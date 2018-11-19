Red []

#include %bip39.red
#include %secp256k1.red


eth-wallet: context [
	init: func [
		"create the master private key"
		seed		[block! none!]		;-- 24-word seed, if none, create a random one
		password	[string!]
		return: 	[block!]			;-- return [words entropy seed]
	][
		either seed [
			Mnemonic/from-words seed password
		][
			Mnemonic/new 'Type24Words password
		]
	]
]

comment {
	this test case from https://github.com/trezor/python-mnemonic/blob/master/vectors.json

            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
			"xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
}
r: eth-wallet/init [abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about] "TREZOR"
print form r/1
probe Mnemonic/get-binary r/2
print r/3


comment {
			"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
			"void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
			"01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
			"xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
}
;probe eth-wallet/init [beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut] "TREZOR"

r: Mnemonic/from-entropy string-to-entropy "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f" "TREZOR"
print form r/1
probe Mnemonic/get-binary r/2
print r/3