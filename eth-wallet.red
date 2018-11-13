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
		assert 1 = secp256k1_ec_pubkey_create secp256/ctx pubkey key
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

]

prikey: #{1C0E092D59767F632C19994E31FD306220823D0EA427C667F59FFD4D8628FBE0}
;-- DER prikey: 04035143501049f1f0155fe843e85cb224fd031ea1bd17f648710c51c53e5a53dab1c43c06c2c5a00408be06b49cf24229089b86bb552b92a91890df0a7cc4c0f8
pubkey: secp256/create-pubkey prikey
print prikey
print pubkey

msg: "aaa"
hash: checksum msg 'SHA256
sig: secp256/sign hash prikey
probe sig

print secp256/verify hash sig pubkey