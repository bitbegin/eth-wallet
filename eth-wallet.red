Red []

#include %bip39.red

#system [
	#include %secp256k1.reds

	secp256: context [
		ctx: 0
		reseed: func [
			/local
				seed	[byte-ptr!]
		][
			seed: allocate 32
			crypto/urandom seed 32
			secp256k1_context_randomize ctx seed
			free seed
		]
		init: does [
			ctx: secp256k1_context_create SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY
			reseed
		]
	]

	secp256/init
]

secp256: context [

	;-- routine
	_create-privkey: routine [
		/local
			rand	[byte-ptr!]
	][
		rand: allocate 32
		until [
			crypto/urandom rand 32
			1 = secp256k1_ec_seckey_verify secp256/ctx rand
		]
		stack/set-last as red-value! binary/load rand 32
		free rand
	]

	_create-pubkey: routine [
		prikey		[binary!]
		/local
			klen	[integer!]
			key		[byte-ptr!]
			pubkey	[byte-ptr!]
	][
		klen: binary/rs-length? prikey
		if klen <> 32 [
			fire [TO_ERROR(script invalid-arg)	prikey]
		]
		key: binary/rs-head prikey
		if 1 <> secp256k1_ec_seckey_verify secp256/ctx key [
			fire [TO_ERROR(script invalid-arg)	prikey]
		]
		pubkey: allocate 64
		if 1 <> secp256k1_ec_pubkey_create secp256/ctx pubkey key [
			fire [TO_ERROR(script invalid-arg)	prikey]
		]
		stack/set-last as red-value! binary/load pubkey 64
		free pubkey
	]

	_sign: routine [
		hash		[binary!]
		prikey		[binary!]
		/local
			dlen	[integer!]
			data	[byte-ptr!]
			klen	[integer!]
			key		[byte-ptr!]
			sig		[byte-ptr!]
			blk		[red-block!]
	][
		dlen: binary/rs-length? hash
		if dlen <> 32 [
			fire [TO_ERROR(script invalid-arg)	hash]
		]
		data: binary/rs-head hash
		klen: binary/rs-length? prikey
		if klen <> 32 [
			fire [TO_ERROR(script invalid-arg)	prikey]
		]
		key: binary/rs-head prikey
		sig: allocate 65
		if 1 <> secp256k1_ecdsa_sign_recoverable secp256/ctx sig data key 0 null [
			fire [TO_ERROR(script invalid-arg)	prikey]
		]
		blk: block/push-only* 3
		block/rs-append blk as red-value! integer/push as integer! sig/65
		block/rs-append blk as red-value! binary/load sig 32
		block/rs-append blk as red-value! binary/load sig + 32 32
		stack/set-last as red-value! blk
		free sig
	]

	_verify: routine [
		hash		[binary!]
		signature	[binary!]
		pubkey		[binary!]
		return:		[logic!]
		/local
			dlen	[integer!]
			data	[byte-ptr!]
			slen	[integer!]
			sig		[byte-ptr!]
			klen	[integer!]
			key		[byte-ptr!]
	][
		dlen: binary/rs-length? hash
		if dlen <> 32 [
			fire [TO_ERROR(script invalid-arg)	hash]
		]
		data: binary/rs-head hash
		slen: binary/rs-length? signature
		if slen <> 64 [
			fire [TO_ERROR(script invalid-arg)	signature]
		]
		sig: binary/rs-head signature
		klen: binary/rs-length? pubkey
		if klen <> 64 [
			fire [TO_ERROR(script invalid-arg)	pubkey]
		]
		key: binary/rs-head pubkey
		if 1 = secp256k1_ecdsa_verify secp256/ctx sig data key [return true]
		false
	]

	_recover-pubkey: routine [
		hash		[binary!]
		signature	[binary!]
		/local
			dlen	[integer!]
			data	[byte-ptr!]
			slen	[integer!]
			sig		[byte-ptr!]
			pubkey	[byte-ptr!]
	][
		dlen: binary/rs-length? hash
		if dlen <> 32 [
			fire [TO_ERROR(script invalid-arg)	hash]
		]
		data: binary/rs-head hash
		slen: binary/rs-length? signature
		if slen <> 65 [
			fire [TO_ERROR(script invalid-arg)	signature]
		]
		sig: binary/rs-head signature
		pubkey: allocate 64
		if 1 <> secp256k1_ecdsa_recover secp256/ctx pubkey sig data [
			fire [TO_ERROR(script invalid-arg)	hash]
		]
		stack/set-last as red-value! binary/load pubkey 64
		free pubkey
	]

	;-- api

	create-keypair: func [
		{generate private key and public key pair;
		return a block of two binary!: 32-byte private key and 64-byte public key}
		return: [block!]
		/local
			pri	[binary!]
			pub	[binary!]
	][
		pri: _create-privkey
		pub: _create-pubkey pri
		reduce [pri pub]
	]

	create-privkey: func [
		return:		[binary!]
	][
		_create-privkey
	]

	create-pubkey: func [
		"Compute the public key for a private key"
		private-key [binary!]
		return:		[binary!]		;-- 64-byte binary!
	][
		_create-pubkey private-key
	]

	sign: func [
		hash		[binary!]
		private-key [binary!]
		return:		[block!]		;-- signature: [v r s]
	][
		_sign hash private-key
	]

	verify: func [
		hash		[binary!]
		signature	[block!]
		public-key	[binary!]
		return:		[logic!]
		/local
			sig		[binary!]
	][
		unless all [
			integer? signature/1
			binary? signature/2
			binary? signature/3
			32 = length? signature/2
			32 = length? signature/3
		][
			return false
		]
		sig: make binary! 64
		append sig signature/2
		append sig signature/3
		_verify hash sig public-key
	]

	recover-pubkey: func [
		hash		[binary!]
		signature	[block!]
		return:		[binary!]
		/local
			sig		[binary!]
	][
		unless all [
			integer? signature/1
			binary? signature/2
			binary? signature/3
			32 = length? signature/2
			32 = length? signature/3
		][
			return false
		]
		sig: make binary! 65
		append sig signature/2
		append sig signature/3
		append sig signature/1
		_recover-pubkey hash sig
	]

]

eth-wallet: context [
	init: func [
		"create the master private key"
		seed		[block! none!]		;-- 24-word seed, if none, create a random one
		password	[string!]
		return: 	[block!]			;-- return the 24-word seed
	][
		either seed [
			Mnemonic/from_string seed password
		][
			Mnemonic/new 'Type24Words password
		]
	]
]

comment [
[{point scare range clerk bridge boss faith squeeze garment weapon crush today under expand visit increase blade vague bleak vivid have trial royal wing} #{
3A15B063A7E28D68408AD3FF123E6A346EF64099BE72B8283C2F52DFB4A097B7
FB
} #{
2723568C0D9C9D864A2B1812EC4695A9BDA5A1BCA60690B696E2352E4047B850
B735D72C2A1AE5E8E3DCB4557E7D85707BE740C2BC5BD166EDB50680835C9049
}]
]
probe eth-wallet/init [point scare range clerk bridge boss faith squeeze garment weapon crush today under expand visit increase blade vague bleak vivid have trial royal wing] "123456"


comment {
	this test case from https://github.com/trezor/python-mnemonic/blob/master/vectors.json

			"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
			"void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
			"01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
			"xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
}
;probe eth-wallet/init [beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut] "TREZOR"

probe Mnemonic/from_entropy #{15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419} 'Type24Words "TREZOR"