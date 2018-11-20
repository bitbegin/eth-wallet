Red [
	Title:	"bip32"
	Author: "bitbegin"
	File: 	%bip32.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %bip39.red
#include %secp256k1.red

bip32key: context [

	#define BIP32_HARDEN	80000000h

	from-entropy: func [
		entropy		[string!]
		return:		[block! none!]
		/local I
	][
		if not entropy-valid? entropy [cause-error 'user 'message "invalid entropy!"]
		I: checksum/with Mnemonic/get-binary entropy 'SHA512 "Bitcoin seed"
		if not secp256/prikey-valid? Il: copy/part I 32 [return none]
		Ir: copy/part skip I 32 32
		reduce [Il Ir]
	]

	CKD-priv: func [
		kpar		[binary!]
		cpar		[binary!]
		index		[integer!]
		return:		[block! none!]
		/local data pub I Il Ir priv
	][
		data: make binary! 1 + 32 + 4
		either index < 0 [
			data: reduce [#{00} kpar to binary! index]
		][
			pub: secp256/serialize-pubkey secp256/create-pubkey kpar true
			data: reduce [pub to binary! index]
		]
		I: checksum/with data 'SHA512 cpar
		if not secp256/prikey-valid? Il: copy/part I 32 [return none]
		Ir: copy/part skip I 32 32
		if none? priv: secp256/privkey-tweak-add kpar Il [return none]
		reduce [priv Ir]
	]
]
