Red/System [
	Title:	"pbkdf2"
	Author: "bitbegin"
	File: 	%pbkdf2.reds
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

pbkdf2: func [
	alg				[integer!]
	pass			[byte-ptr!]
	passlen			[integer!]
	salt			[byte-ptr!]
	saltlen			[integer!]
	rounds			[integer!]
	key				[byte-ptr!]
	keylen			[integer!]
	return:			[logic!]
	/local
		digestlen	[integer!]
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
	digestlen: crypto/alg-digest-size alg
	if any [
		digestlen = 0
		rounds < 1
		keylen = 0
		saltlen = 0
		saltlen > (1000 - 4)
	][return false]
	asalt: allocate saltlen + 4
	if asalt = null [return false]
	copy-memory asalt salt saltlen

	count: 1
	obuf: allocate digestlen
	while [keylen > 0][
		p: asalt + saltlen
		p/1: as byte! (count >>> 24)
		p: p + 1
		p/1: as byte! (count >>> 16)
		p: p + 1
		p/1: as byte! (count >>> 8)
		p: p + 1
		p/1: as byte! count
		d1: crypto/calc-hmac asalt saltlen + 4 pass passlen alg
		copy-memory obuf d1 digestlen
		loop rounds - 1 [
			d2: crypto/calc-hmac d1 digestlen pass passlen alg
			copy-memory d1 d2 digestlen
			j: 1
			while [j <= digestlen][
				obuf/j: obuf/j xor d1/j
				j: j + 1
			]
			free d2
		]
		free d1
		r: either keylen > digestlen [digestlen][keylen]
		copy-memory key obuf r
		key: key + r
		keylen: keylen - r

		count: count + 1
	]
	free asalt
	free obuf

	true
]