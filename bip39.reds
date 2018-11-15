Red/System [
	Title:	"bip39"
	Author: "bitbegin"
	File: 	%bip39.reds
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %bip39-english.reds
#include %pbkdf2.reds

generate-seed: func [
	entropy		[byte-ptr!]
	elen		[integer!]
	password	[c-string!]
	key64		[byte-ptr!]
	return:		[logic!]
	/local
		passlen	[integer!]
		saltlen	[integer!]
		salt	[byte-ptr!]
		ret		[logic!]
][
	passlen: length? password
	saltlen: 8 + passlen
	salt: allocate saltlen
	copy-memory salt as byte-ptr! "mnemonic" 8
	copy-memory salt + 8 as byte-ptr! password passlen
	print-line elen
	dump-memory entropy 1 elen / 16 + 1
	print-line saltlen
	dump-memory salt 1 saltlen / 16 + 1
	ret: pbkdf2 crypto/ALG_SHA512 entropy elen salt saltlen 2048 key64 64
	print-line ret
	dump-memory key64 1 16
	free salt
	ret
]


#enum MnemonicType! [
	Type12Words
	Type15Words
	Type18Words
	Type21Words
	Type24Words
]

MnemonicType: context [
	for_word_count: func [
		size		[integer!]
		return:		[MnemonicType!]
	][
		case [
			size = 12 [Type12Words]
			size = 15 [Type15Words]
			size = 18 [Type18Words]
			size = 21 [Type21Words]
			size = 24 [Type24Words]
		]
	]
	for_key_size: func [
		size		[integer!]
		return:		[MnemonicType!]
	][
		case [
			size = 128 [Type12Words]
			size = 160 [Type15Words]
			size = 192 [Type18Words]
			size = 224 [Type21Words]
			size = 256 [Type24Words]
		]
	]
	for_phrase: func [
		str			[c-string!]
		return:		[MnemonicType!]
		/local
			len		[integer!]
			count	[integer!]
	][
		count: 0
		len: length? str
		loop len [
			if str/1 = #" " [count: count + 1]
			str: str + 1
		]
		for_word_count count
	]

	total_bits: func [
		type		[MnemonicType!]
		return:		[integer!]
	][
		case [
			type = Type12Words [132]
			type = Type15Words [165]
			type = Type18Words [198]
			type = Type21Words [231]
			type = Type24Words [264]
		]
	]

	entropy_bits: func [
		type		[MnemonicType!]
		return:		[integer!]
	][
		case [
			type = Type12Words [128]
			type = Type15Words [160]
			type = Type18Words [192]
			type = Type21Words [224]
			type = Type24Words [256]
		]
	]

	checksum_bits: func [
		type		[MnemonicType!]
		return:		[integer!]
	][
		case [
			type = Type12Words [4]
			type = Type15Words [5]
			type = Type18Words [6]
			type = Type21Words [7]
			type = Type24Words [8]
		]
	]

	word_count: func [
		type		[MnemonicType!]
		return:		[integer!]
	][
		case [
			type = Type12Words [12]
			type = Type15Words [15]
			type = Type18Words [18]
			type = Type21Words [21]
			type = Type24Words [24]
		]
	]
]

read-bits: func [
	buf			[byte-ptr!]
	pos			[integer!]
	bits		[integer!]
	return:		[integer!]
	/local
		ret		[integer!]
		readed	[integer!]
		h		[integer!]
		l		[integer!]
		p		[byte-ptr!]
		temp	[integer!]
		mask	[integer!]
][
	ret: 0
	readed: 0
	while [readed < bits][
		h: pos / 8 l: pos % 8
		p: buf + h
		temp: (as integer! p/1) >>> l
		if bits < (readed + (8 - l)) [
			mask: (1 << (bits - readed)) - 1
			temp: temp and mask
		]
		ret: ret + (temp << readed)
		readed: readed + (8 - l)
		pos: pos + (8 - l)
	]
	ret
]

write-bits: func [
	buf			[byte-ptr!]
	pos			[integer!]
	bits		[integer!]
	vl			[integer!]
	/local
		writed	[integer!]
		h		[integer!]
		l		[integer!]
		p		[byte-ptr!]
		temp	[integer!]
		mask	[integer!]
][
	writed: 0
	while [writed < bits][
		h: pos / 8 l: pos % 8
		p: buf + h
		mask: (1 << (8 - l)) - 1
		temp: (vl >>> writed) and mask
		either bits < (writed + (8 - l)) [
			mask: (1 << (bits - writed + l)) - 1
			mask: mask and (not ((1 << l) - 1))
			mask: FFh and not mask
		][
			mask: (1 << l) - 1
		]
		p/1: as byte! ((as integer! p/1) and mask)
		p/1: as byte! ((as integer! p/1) + (temp << l))
		writed: writed + (8 - l)
		pos: pos + (8 - l)
	]
]


Mnemonic!: alias struct! [
	string		[c-string!]
	seed		[byte-ptr!]
	entropy		[byte-ptr!]
	elen		[integer!]
]

Mnemonic: context [

	from_string_entropy: func [
		str			[c-string!]
		return:		[byte-ptr!]
		/local
			type	[MnemonicType!]
			ebits	[integer!]
			cbits	[integer!]
	][
		type: MnemonicType/for_phrase str
		ebits: MnemonicType/entropy_bits type
		cbits: MnemonicType/checksum_bits type
		null
	]

	from_string: func [
		str			[c-string!]
		password	[c-string!]
		return:		[Mnemonic!]
		/local
			seed	[byte-ptr!]
			ret		[Mnemonic!]
	][
		seed: allocate 64
		generate-seed as byte-ptr! str length? str password seed
		ret: as Mnemonic! allocate size? Mnemonic!
		ret/string: str
		ret/seed: seed
		ret
	]

	from_entropy: func [
		entropy		[byte-ptr!]
		elen		[integer!]
		type		[MnemonicType!]
		password	[c-string!]
		return:		[Mnemonic!]
		/local
			ebits	[integer!]
			nwords	[integer!]
			ehash	[byte-ptr!]
			mix		[byte-ptr!]
			str		[byte-ptr!]
			spos	[integer!]
			pos		[integer!]
			vl		[integer!]
			tstr	[c-string!]
			tlen	[integer!]
			temp	[integer!]
			ret		[Mnemonic!]
	][
		ebits: elen * 8
		if ebits <> MnemonicType/entropy_bits type [
			fire [TO_ERROR(script invalid-arg) integer/push elen]
		]
		nwords: MnemonicType/word_count type
		ehash: crypto/get-digest entropy elen crypto/ALG_SHA256
		mix: allocate elen + 4
		copy-memory mix entropy elen
		copy-memory mix + elen ehash 4
		free ehash free entropy
		str: allocate nwords * 12
		spos: 0
		pos: 0
		loop nwords [
			vl: 1 + read-bits mix pos 11
			tstr: as c-string! BIP39_WORDLIST_ENGLISH/vl
			tlen: length? tstr
			copy-memory str + spos as byte-ptr! tstr tlen
			spos: spos + tlen + 1
			str/spos: #" "
			pos: pos + 11
		]
		spos: spos + 1
		str/spos: null-byte
		free mix
		from_string as c-string! str password
	]

	new: func [
		type		[MnemonicType!]
		password	[c-string!]
		return:		[Mnemonic!]
		/local
			elen	[integer!]
			entropy	[byte-ptr!]
	][
		elen: (MnemonicType/entropy_bits type) / 8
		entropy: allocate elen
		crypto/urandom entropy elen
		from_entropy entropy elen type password
	]
]
