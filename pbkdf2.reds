Red/System [
	Title:	"pbkdf2"
	Author: "bitbegin"
	File: 	%pbkdf2.reds
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

pbkdf2_hmac_sha512: func [
	pass			[byte-ptr!]
	passlen			[integer!]
	salt			[byte-ptr!]
	saltlen			[integer!]
	rounds			[integer!]
	key				[byte-ptr!]
	keylen			[integer!]
	return:			[logic!]
	/local
		asalt		[byte-ptr!]
		obuf		[byte-ptr!]
		d1			[byte-ptr!]
		d2			[byte-ptr!]
		i			[integer!]
		j			[integer!]
		count		[integer!]
		r			[integer!]
		p			[byte-ptr!]
][
	if any [
		rounds < 1
		keylen = 0
		saltlen = 0
		saltlen > (1000 - 4)
	][return false]
	asalt: allocate saltlen + 4
	if asalt = null [return false]
	copy-memory asalt salt saltlen

	count: 1
	obuf: allocate 64
	while [keylen > 0][
		p: asalt + saltlen
		p/1: as byte! (count >>> 24)
		p: p + 1
		p/1: as byte! (count >>> 16)
		p: p + 1
		p/1: as byte! (count >>> 8)
		p: p + 1
		p/1: as byte! count
		d1: crypto/calc-hmac asalt saltlen + 4 pass passlen crypto/ALG_SHA512
		copy-memory obuf d1 64
		loop rounds - 1 [
			d2: crypto/calc-hmac d1 64 pass passlen crypto/ALG_SHA512
			copy-memory d1 d2 64
			j: 1
			while [j <= 64][
				obuf/j: obuf/j xor d1/j
				j: j + 1
			]
			free d2
		]
		free d1
		r: either keylen > 64 [64][keylen]
		copy-memory key obuf r
		key: key + r
		keylen: keylen - r

		count: count + 1
	]
	free asalt
	free obuf

	true
]