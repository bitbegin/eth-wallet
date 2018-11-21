Red [
	Title:	"eth-wallet"
	Author: "bitbegin"
	File: 	%eth-wallet.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %bip32.red

eth-wallet: context [

	private-key: none

	; set the bip32 path of the wallet
	; type: block!
	; e.g [8000002Ch 8000003Ch 80000000h 0 idx]
	bip32-path: []

	init: func [
		"create the master private key"
		seed		[block! none!]		;-- 24-word seed, if none, create a random one
		password	[string!]
		return:		[block!]			;-- return [words entropy seed]
	][
		private-key: either seed [
			Mnemonic/from-words seed password
		][
			Mnemonic/new 'Type24Words password
		]
		private-key/1
	]

	get-address: func [
		idx			[integer! none!]
		return:		[binary!]
		/local path pub
	][
		either idx = none [
			path: copy bip32-path
		][
			path: append copy bip32-path idx
		]
		pub: bip32key/derive private-key/2 path false
		pub/6
	]
]

eth-wallet/init [abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about] "TREZOR"
clear eth-wallet/bip32-path
print eth-wallet/get-address none
