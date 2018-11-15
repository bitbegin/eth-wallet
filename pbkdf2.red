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
	pbkdf2_hmac_sha512 as byte-ptr! "password" 8 as byte-ptr! "salt" 4 1 key 64
	dump-hex key
]



pbkdf2: func [
	password	[string! binary!]
	salt		[string! binary!]
	iterations	[integer!]
	key-len		[integer!]
	alg			[word!]
	/local blk-size blk-cnt value sum output i j
][
	blk-size: case [
		alg = 'SHA1		[20]
		alg = 'SHA256	[32]
		alg = 'SHA384	[48]
		alg = 'SHA512	[64]
		true [alg: 'SHA1 20]
	]
	print blk-size
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

probe pbkdf2 "password" "salt" 1 64 'SHA512