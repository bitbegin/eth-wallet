Red [
	Title:	"bip39"
	Author: "bitbegin"
	File: 	%bip39.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

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

	serialize-pubkey: routine [
		pubkey		[binary!]
		compress?	[logic!]
		/local
			klen	[integer!]
			key		[byte-ptr!]
			data	[byte-ptr!]
			dlen	[integer!]
			flags	[integer!]
	][
		klen: binary/rs-length? pubkey
		if klen <> 64 [
			fire [TO_ERROR(script invalid-arg)	pubkey]
		]
		key: binary/rs-head pubkey
		data: allocate 65
		either compress? [
			flags: SECP256K1_EC_COMPRESSED
			dlen: 33
		][
			flags: SECP256K1_EC_UNCOMPRESSED
			dlen: 65
		]
		if 1 <> secp256k1_ec_pubkey_serialize secp256/ctx data :dlen key flags [
			stack/set-last none-value
			free data
			exit
		]
		stack/set-last as red-value! binary/load data dlen
		free data
	]

	parse-pubkey: routine [
		pubkey		[binary!]
		/local
			klen	[integer!]
			key		[byte-ptr!]
			data	[byte-ptr!]
	][
		klen: binary/rs-length? pubkey
		key: binary/rs-head pubkey
		data: allocate 64
		if 1 <> secp256k1_ec_pubkey_parse secp256/ctx data key klen [
			stack/set-last none-value
			free data
			exit
		]
		stack/set-last as red-value! binary/load data 64
		free data
	]

	prikey-valid?: routine [
		private-key [binary!]
		return:		[logic!]
		/local
			klen	[integer!]
			key		[byte-ptr!]
	][
		klen: binary/rs-length? private-key
		if klen <> 32 [
			fire [TO_ERROR(script invalid-arg)	private-key]
		]
		key: binary/rs-head private-key
		1 = secp256k1_ec_seckey_verify secp256/ctx key
	]

	privkey-tweak-add: routine [
		private-key	[binary!]
		tweek		[binary!]
		/local
			klen	[integer!]
			key		[byte-ptr!]
			dlen	[integer!]
			data	[byte-ptr!]
			nkey	[byte-ptr!]
	][
		klen: binary/rs-length? private-key
		if klen <> 32 [
			fire [TO_ERROR(script invalid-arg)	private-key]
		]
		key: binary/rs-head private-key
		dlen: binary/rs-length? tweek
		if dlen <> 32 [
			fire [TO_ERROR(script invalid-arg)	tweek]
		]
		data: binary/rs-head tweek
		nkey: allocate 32 copy-memory nkey key 32
		if 0 = secp256k1_ec_privkey_tweak_add secp256/ctx nkey data [
			stack/set-last none-value
			free nkey
			exit
		]
		stack/set-last as red-value! binary/load nkey 32
		free nkey
	]
	pubkey-combine: routine [
		keys		[block!]
		/local
			len		[integer!]
			ptr		[int-ptr!]
			key		[red-binary!]
			p		[int-ptr!]
			data	[byte-ptr!]
	][
		len: block/rs-length? keys
		if len <= 1 [stack/set-last as red-value! keys exit]
		ptr: as int-ptr! allocate 4 * len
		p: ptr
		key: as red-binary! block/rs-head keys
		loop len [
			if any [
				TYPE_OF(key) <> TYPE_BINARY
				64 <> binary/rs-length? key
			][
				stack/set-last none-value
				free as byte-ptr! ptr
				exit
			]
			p/1: as integer! binary/rs-head key
			key: key + 1
			p: p + 1
		]
		data: allocate 64
		if 0 = secp256k1_ec_pubkey_combine secp256/ctx data ptr len [
			stack/set-last none-value
			free data
			free as byte-ptr! ptr
			exit
		]
		stack/set-last as red-value! binary/load data 64
		free data
		free as byte-ptr! ptr
	]

	_sha3-256: routine [
		bin			[any-type!]
		/local len data hash
	][
		switch TYPE_OF(bin) [
			TYPE_STRING [
				len: -1
				data: as byte-ptr! unicode/to-utf8 as red-string! bin :len
			]
			TYPE_BINARY [
				len: binary/rs-length? as red-binary! bin
				data: binary/rs-head as red-binary! bin
			]
			default [
				print-line TYPE_OF(bin)
				fire [TO_ERROR(script invalid-arg) bin]
			]
		]
		if len < 0 [
			fire [TO_ERROR(script invalid-arg)	bin]
		]
		hash: allocate 32
		SHA3_256 hash data len
		stack/set-last as red-value! binary/load hash 32
		free hash
	]

	sha3-256: func [
		data		[binary! string!]
		return:		[binary!]
	][
		_sha3-256 data
	]

]
