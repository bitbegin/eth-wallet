Red [
	Title:	"eth-wallet"
	Author: "bitbegin"
	File: 	%eth-wallet.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %bip32.red

eth-wallet: context [

	seeds: none

	; set the bip32 path of the wallet
	; type: block!
	; e.g [8000002Ch 8000003Ch 80000000h 0 idx]
	bip32-path: [8000002Ch 8000003Ch 80000000h 0]		;-- default: ETH coin, account 0, change 0

	init: func [
		"create the master private key"
		seed		[block! none!]		;-- 24-word seed, if none, create a random one
		password	[string!]
		return:		[block!]			;-- return [words entropy seed]
	][
		seeds: either seed [
			Mnemonic/from-words seed password
		][
			Mnemonic/new 'Type24Words password
		]
		seeds/1
	]

	get-address: func [
		idx			[integer! none!]
		return:		[hex!]
	][
		to hex! secp256/pubkey-to-address get-public idx
	]

	get-public: func [
		idx			[integer! none!]
		return:		[binary!]
		/local path xpub
	][
		either idx = none [
			path: copy bip32-path
		][
			path: append copy bip32-path idx
		]
		xpub: bip32key/derive seeds/3 path false
		xpub/6
	]

	get-private: func [
		idx			[integer! none!]
		return:		[binary!]
		/local path xprv
	][
		either idx = none [
			path: copy bip32-path
		][
			path: append copy bip32-path idx
		]
		xprv: bip32key/derive seeds/3 path true
		xprv/6
	]
]

eth-wallet/init [abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about] "TREZOR"
;eth-wallet/bip32-path: [8000002Ch 8000003Ch 80000000h 0]
;0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6
print eth-wallet/get-address 0
;0x7AF7283bd1462C3b957e8FAc28Dc19cBbF2FAdfe
print eth-wallet/get-address 1
;0x05f48E30fCb69ADcd2A591Ebc7123be8BE72D7a1
print eth-wallet/get-address 2

;0x62f1d86b246c81bdd8f6c166d56896a4a5e1eddbcaebe06480e5c0bc74c28224
print eth-wallet/get-private 0
;0x49ee230b1605382ac1c40079191bca937fc30e8c2fa845b7de27a96ffcc4ddbf
print eth-wallet/get-private 1
;0xeef2c0702151930b84cffcaa642af58e692956314519114e78f3211a6465f28b
print eth-wallet/get-private 2
