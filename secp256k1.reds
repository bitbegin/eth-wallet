Red/System []

#define SECP256K1_FLAGS_TYPE_CONTEXT		1
#define SECP256K1_FLAGS_TYPE_COMPRESSION	2
#define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY	[1 << 8]
#define SECP256K1_FLAGS_BIT_CONTEXT_SIGN	[1 << 9]
#define SECP256K1_FLAGS_BIT_COMPRESSION		[1 << 8]
#define SECP256K1_CONTEXT_VERIFY			[1 or (1 << 8)]
#define SECP256K1_CONTEXT_SIGN				[1 or (1 << 9)]
#define SECP256K1_CONTEXT_NONE				1

#define SECP256K1_EC_COMPRESSED				[2 or (1 << 8)]
#define SECP256K1_EC_UNCOMPRESSED			2

#import [
	"libsecp256k1.dll" stdcall [
		secp256k1_context_create: "secp256k1_context_create" [
			flags			[integer!]
			return:			[integer!]
		]
		secp256k1_context_clone: "secp256k1_context_clone" [
			return:			[integer!]
		]
		secp256k1_context_destroy: "secp256k1_context_destroy" [
			ctx				[integer!]
		]
		secp256k1_scratch_space_create: "secp256k1_scratch_space_create" [
			ctx				[integer!]
			max_size		[integer!]
			return:			[integer!]
		]
		secp256k1_scratch_space_destroy: "secp256k1_scratch_space_destroy" [
			scratch			[integer!]
		]
		secp256k1_ec_pubkey_parse: "secp256k1_ec_pubkey_parse" [
			ctx				[integer!]
			pubkey64		[byte-ptr!]
			input			[byte-ptr!]
			inputlen		[integer!]
			return:			[integer!]
		]
		secp256k1_ec_pubkey_serialize: "secp256k1_ec_pubkey_serialize" [
			ctx				[integer!]
			output			[byte-ptr!]
			outputlen		[int-ptr!]
			pubkey64		[byte-ptr!]
			flags			[integer!]
			return:			[integer!]
		]
		secp256k1_ecdsa_signature_parse_compact: "secp256k1_ecdsa_signature_parse_compact" [
			ctx				[integer!]
			sig64			[byte-ptr!]
			input64			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ecdsa_signature_parse_der: "secp256k1_ecdsa_signature_parse_der" [
			ctx				[integer!]
			sig64			[byte-ptr!]
			input			[byte-ptr!]
			inputlen		[integer!]
			return:			[integer!]
		]
		secp256k1_ecdsa_signature_serialize_der: "secp256k1_ecdsa_signature_serialize_der" [
			ctx				[integer!]
			output			[byte-ptr!]
			outputlen		[integer!]
			sig64			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ecdsa_signature_serialize_compact: "secp256k1_ecdsa_signature_serialize_compact" [
			ctx				[integer!]
			output64		[byte-ptr!]
			sig64			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ecdsa_verify: "secp256k1_ecdsa_verify" [
			ctx				[integer!]
			sig64			[byte-ptr!]
			msg32			[byte-ptr!]
			pubkey64		[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ecdsa_signature_normalize: "secp256k1_ecdsa_signature_normalize" [
			ctx				[integer!]
			sigout64		[byte-ptr!]
			sigin64			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ecdsa_sign: "secp256k1_ecdsa_sign" [
			ctx				[integer!]
			sig64			[byte-ptr!]
			msg32			[byte-ptr!]
			seckey			[byte-ptr!]
			noncefp			[integer!]
			ndata			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ec_seckey_verify: "secp256k1_ec_seckey_verify" [
			ctx				[integer!]
			seckey32		[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ec_pubkey_create: "secp256k1_ec_pubkey_create" [
			ctx				[integer!]
			pubkey64		[byte-ptr!]
			seckey32		[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ec_privkey_negate: "secp256k1_ec_privkey_negate" [
			ctx				[integer!]
			seckey32		[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ec_pubkey_negate: "secp256k1_ec_pubkey_negate" [
			ctx				[integer!]
			pubkey64		[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ec_privkey_tweak_add: "secp256k1_ec_privkey_tweak_add" [
			ctx				[integer!]
			seckey32		[byte-ptr!]
			tweek32			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ec_pubkey_tweak_add: "secp256k1_ec_pubkey_tweak_add" [
			ctx				[integer!]
			pubkey64		[byte-ptr!]
			tweek32			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ec_privkey_tweak_mul: "secp256k1_ec_privkey_tweak_mul" [
			ctx				[integer!]
			seckey32		[byte-ptr!]
			tweek32			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ec_pubkey_tweak_mul: "secp256k1_ec_pubkey_tweak_mul" [
			ctx				[integer!]
			pubkey64		[byte-ptr!]
			tweek32			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_context_randomize: "secp256k1_context_randomize" [
			ctx				[integer!]
			seed32			[byte-ptr!]
			return:			[integer!]
		]

		secp256k1_ecdsa_recoverable_signature_parse_compact: "secp256k1_ecdsa_recoverable_signature_parse_compact" [
			ctx				[integer!]
			sig65			[byte-ptr!]
			input64			[byte-ptr!]
			recid			[integer!]
			return:			[integer!]
		]
		secp256k1_ecdsa_recoverable_signature_convert: "secp256k1_ecdsa_recoverable_signature_convert" [
			ctx				[integer!]
			sig64			[byte-ptr!]
			sigin65			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ecdsa_recoverable_signature_serialize_compact: "secp256k1_ecdsa_recoverable_signature_serialize_compact" [
			ctx				[integer!]
			output64		[byte-ptr!]
			recid			[int-ptr!]
			sig65			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ecdsa_sign_recoverable: "secp256k1_ecdsa_sign_recoverable" [
			ctx				[integer!]
			sig65			[byte-ptr!]
			msg32			[byte-ptr!]
			seckey32		[byte-ptr!]
			noncefp			[integer!]
			ndata			[byte-ptr!]
			return:			[integer!]
		]
		secp256k1_ecdsa_recover: "secp256k1_ecdsa_recover" [
			ctx				[integer!]
			pubkey64		[byte-ptr!]
			sig65			[byte-ptr!]
			msg32			[byte-ptr!]
			return:			[integer!]
		]
	]
]
