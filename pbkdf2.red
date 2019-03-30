Red [
	Title:	"pbkdf2"
	Author: "bitbegin"
	File: 	%pbkdf2.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

pbkdf2: context [
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
			default	[return make error! "alg error!"]
		]
	]

	derive: func [
		password	[string! binary!]
		salt		[string! binary!]
		iterations	[integer!]
		key-len		[integer!]
		alg			[word!]
		return:		[binary!]
		/local blk-size output i salt-tail value sum len
	][
		blk-size: alg-digest-size alg
		output: make binary! key-len
		i: 1
		salt-tail: tail salt
		while [key-len > 0][
			value: head change salt-tail to-string to-binary i
			value: sum: checksum/with value alg password
			loop (iterations - 1) [
				sum: (sum xor (value: checksum/with value alg password))
			]
			len: either key-len > blk-size [blk-size][key-len]
			append/part output sum len
			key-len: key-len - len
			i: i + 1
		]
		output
	]
]
