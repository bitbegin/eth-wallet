Red [
	Title:	"bip32"
	Author: "bitbegin"
	File: 	%bip32.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %bip39.red
#include %secp256k1.red
#include %bip32-addr.red

bip32key: context [

	from-binary: func [
		bin			[binary!]
		return:		[block! none!]	"[Il Ir] or none"
		/local I Il Ir
	][
		I: checksum/with bin 'SHA512 "Bitcoin seed"
		if not secp256/prikey-valid? Il: copy/part I 32 [return none]
		Ir: copy/part skip I 32 32
		reduce [Il Ir]
	]

	from-entropy: func [
		entropy		[string!]
		return:		[block! none!]	"[Il Ir] or none"
	][
		from-binary Mnemonic/get-binary entropy
	]

	CKD-priv: func [
		kpar		[binary!]
		cpar		[binary!]
		index		[integer!]
		return:		[block! none!]	"[child Ir] or none"
		/local data pub I Il Ir child
	][
		data: make binary! 1 + 32 + 4
		either index < 0 [
			repend data [#{00} kpar to binary! index]
		][
			pub: secp256/serialize-pubkey secp256/create-pubkey kpar true
			repend data [pub to binary! index]
		]
		I: checksum/with data 'SHA512 cpar
		if not secp256/prikey-valid? Il: copy/part I 32 [return none]
		Ir: copy/part skip I 32 32
		if none? child: secp256/privkey-tweak-add kpar Il [return none]
		reduce [child Ir]
	]

	CKD-pub: func [
		kpar		[binary!]
		cpar		[binary!]
		index		[integer!]
		return:		[block! none!]	"[child Ir] or none"
		/local data pub I Il Ir pub2 child
	][
		if i < 0 [do make error! "hardened child!"]
		data: make binary! 33 + 4
		pub: secp256/serialize-pubkey kpar true
		repend data [pub to binary! index]
		I: checksum/with data 'SHA512 cpar
		if not secp256/prikey-valid? Il: copy/part I 32 [return none]
		Ir: copy/part skip I 32 32
		pub2: secp256/create-pubkey Il
		child: secp256/pubkey-combine reduce [pub2 kpar]
		reduce [child Ir]
	]

	finger-print: func [
		pubkey		[binary!]
		return:		[integer!]
		/local hash
	][
		hash: bip32-addr/hash160 secp256/serialize-pubkey pubkey true
		to integer! copy/part hash 4
	]

	derive-key: func [
		mkey		[binary!]
		mchain		[binary!]
		path		[block!]
		private?	[logic!]
		return:		[block!]		"[private? depth fpr index chain key]"
		/local key chain len depth fpr index blk okey
	][
		key: mkey
		chain: mchain
		len: length? path
		if len = 0 [
			unless private? [key: secp256/create-pubkey key]
			return reduce [private? 0 0 0 chain key]
		]
		depth: 0
		foreach index path [
			unless integer? index [do make error! "invalid index"]
			depth: depth + 1
			blk: CKD-priv key chain index
			okey: key
			key: blk/1 chain: blk/2
		]
		fpr: finger-print secp256/create-pubkey okey
		unless private? [key: secp256/create-pubkey key]
		reduce [private? depth fpr index chain key]
	]

	derive: func [
		entropy		[string!]
		path		[block!]
		private?	[logic!]
		return:		[block!]		"[private? depth fpr index chain key]"
		/local blk
	][
		blk: from-entropy entropy
		derive-key blk/1 blk/2 path private?
	]

	derive-bin: func [
		bin			[binary!]
		path		[block!]
		private?	[logic!]
		return:		[block!]		"[private? depth fpr index chain key]"
		/local blk
	][
		blk: from-binary bin
		derive-key blk/1 blk/2 path private?
	]

	encode: func [
		data		[block!]		"[private? depth fpr index chain key]"
		return:		[string!]
		/local bin
	][
		bin: make binary! 78
		repend bin [
			to binary! select bip32-addr/prefix
				either data/1 ['BIP32-PRIKEY]['BIP32-PUBKEY]
			to binary! to char! data/2
			to binary! data/3
			to binary! data/4
			data/5
			either data/1 [
				append copy #{00} data/6
			][
				secp256/serialize-pubkey data/6 true
			]
		]
		bip32-addr/encode58-check bin
	]

	decode: func [
		data		[string!]
		return:		[block!]		"[private? depth fpr index chain key]"
		/local bin ver private? depth fpr index chain key
	][
		bin: bip32-addr/decode58-check data
		if 78 <> length? bin [do make error! "invalid string"]
		ver: to integer! copy/part bin 4
		private?: case [
			ver = select bip32-addr/prefix 'BIP32-PRIKEY [true]
			ver = select bip32-addr/prefix 'BIP32-PUBKEY [false]
			true [do make error! "invalid version"]
		]
		depth: to integer! copy/part skip bin 4 1
		fpr: to integer! copy/part skip bin 5 4
		index: to integer! copy/part skip bin 9 4
		chain: copy/part skip bin 13 32
		key: either private? [
			copy/part skip bin 46 32
		][
			secp256/parse-pubkey copy/part skip bin 45 33
		]
		reduce [private? depth fpr index chain key]
	]
]

;-- test from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
;probe priv: bip32key/decode "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
;probe pub: bip32key/decode "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
;probe secp256/create-pubkey priv/6

bin-entropy: #{000102030405060708090a0b0c0d0e0f}
seeds: Mnemonic/from-binary bin-entropy "123456"
;master: bip32key/from-entropy seeds/2
;probe bip32key/encode reduce [true 0 0 0 master/2 master/1]
;probe bip32key/encode reduce [false 0 0 0 master/2 secp256/create-pubkey master/1]

probe bip32key/encode bip32key/derive seeds/2 [80000000h] true
probe bip32key/encode bip32key/derive seeds/2 [80000000h] false
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h] true
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h] false

probe bip32key/encode bip32key/derive seeds/2 [80000000h 1] true
probe bip32key/encode bip32key/derive seeds/2 [80000000h 1] false
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1] true
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1] false
