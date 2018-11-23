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
		if index < 0 [do make error! "hardened child!"]
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
		key			[binary!]
		chain		[binary!]
		path		[block!]
		depth		[integer!]
		private?	[logic!]
		return:		[block!]		"[private? depth fpr index chain key]"
		/local len fpr index blk okey
	][
		if 0 = len: length? path [
			unless private? [key: secp256/create-pubkey key]
			return reduce [private? 0 0 0 chain key]
		]
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
		bin			[binary!]
		path		[block!]
		private?	[logic!]
		return:		[block!]		"[private? depth fpr index chain key]"
		/local blk
	][
		blk: from-binary bin
		derive-key blk/1 blk/2 path 0 private?
	]

	derive-extkey: func [
		data		[block!]		"[private? depth fpr index chain key]"
		path		[block!]
		rprivate?	[logic!]
		return:		[block!]		"[private? depth fpr index chain key]"
		/local len private? depth index blk okey key chain
	][
		if 0 = len: length? path [
			return data
		]
		private?: data/1 depth: data/2 chain: data/5 key: data/6
		if private? [
			return derive-key key chain path depth rprivate?
		]
		if rprivate? [do make error! "can't derive private key"]
		foreach index path [
			unless integer? index [do make error! "invalid index"]
			depth: depth + 1
			blk: CKD-pub key chain index
			okey: key
			key: blk/1 chain: blk/2
		]
		reduce [false depth finger-print okey index chain key]
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

	pubkey-to-address: func [
		pubkey		[binary!]
		return:		[string!]
		/local ser hash20
	][
		if 64 <> length? pubkey [do make error! "invalid public key"]
		ser: skip secp256/serialize-pubkey pubkey false 1
		encode-address copy/part skip secp256/sha3-256 ser 12 20
	]

	encode-address: func [
		address		[binary!]
		return:		[string!]
		/local str hash ret i c
	][
		hash: enbase/base secp256/sha3-256 str: lowercase enbase/base address 16 2
		ret: make string! 2 + length? str
		i: 0
		foreach c str [
			either all [
				c >= #"0"
				c <= #"9"
			][
				append ret c
			][
				append ret either #"1" = pick hash 4 * i + 1 [uppercase c][lowercase c]
			]
			i: i + 1
		]
		insert ret "0x"
		ret
	]

]
