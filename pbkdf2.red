Red [
	Title:	"pbkdf2"
	Author: "bitbegin"
	File: 	%pbkdf2.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#system [
	#include %pbkdf2.reds
	key: allocate 64
	pbkdf2 crypto/ALG_SHA512 as byte-ptr! "password" 8 as byte-ptr! "salt" 4 2048 key 64
	dump-hex key
	pbkdf2 crypto/ALG_SHA1 as byte-ptr! "password" 8 as byte-ptr! "salt" 4 2048 key 20
	dump-hex key
]


alg-digest-size: func [
	"Return the size of a digest result for a given algorithm."
	type	[word!]
	return:	[integer!]
][
	switch type [
		MD5		[16]
		SHA1    [20]
		SHA256  [32]
		SHA384  [48]
		SHA512  [64]
		default	[ 0]
	]
]

pbkdf2: func [
	password	[string! binary!]
	salt		[string! binary!]
	iterations	[integer!]
	key-len		[integer!]
	alg			[word!]
	/local blk-size blk-cnt value sum output i j
][
	blk-size: alg-digest-size alg
	if blk-size = 0 [alg: 'SHA1 blk-size: 20]
	blk-cnt: round/ceiling (key-len / blk-size)
	output: make binary! 512
	repeat i blk-cnt [
		value: append copy salt to-string to-binary i
		value: sum: checksum/with value alg password
		repeat j (iterations - 1) [
			sum: (sum xor (value: checksum/with value alg password))
		]
		append output sum
	]
	copy/part output key-len
]

probe pbkdf2 "password" "salt" 2048 64 'SHA512
probe pbkdf2 "password" "salt" 2048 20 'SHA1
