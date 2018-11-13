Red []

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
			key-len	[integer!]
			key		[byte-ptr!]
			pubkey	[byte-ptr!]
	][
		key-len: binary/rs-length? prikey
		if key-len <> 32 [
			fire [TO_ERROR(script invalid-arg)	prikey]
		]
		key: binary/rs-head prikey
		if 1 <> secp256k1_ec_seckey_verify secp256/ctx key [
			fire [TO_ERROR(script invalid-arg)	prikey]
		]
		pubkey: allocate 64
		assert 1 = secp256k1_ec_pubkey_create secp256/ctx pubkey key
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
]

prikey: #{1C0E092D59767F632C19994E31FD306220823D0EA427C667F59FFD4D8628FBE0}
;-- DER prikey: 04035143501049f1f0155fe843e85cb224fd031ea1bd17f648710c51c53e5a53dab1c43c06c2c5a00408be06b49cf24229089b86bb552b92a91890df0a7cc4c0f8
pubkey: secp256/create-pubkey prikey
print prikey
print pubkey

prikey: secp256/create-privkey
pubkey: secp256/create-pubkey prikey
print prikey
print pubkey

print secp256/create-keypair
