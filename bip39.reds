Red/System [
	Title:	"bip39"
	Author: "bitbegin"
	File: 	%bip39.reds
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %bip39-english.reds

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

read-11bits: func [
	buf			[byte-ptr!]
	pos			[integer!]
	return:		[integer!]
	/local
		h		[integer!]
		l		[integer!]
		ret		[integer!]
		p		[byte-ptr!]
		temp	[integer!]
][
	h: pos / 8 l: pos % 8
	p: buf + h
	temp: as integer! p/1
	ret: temp >>> l
	p: p + 1
	temp: (as integer! p/1) >>> l
	ret: ret + ((temp and 07h) << 8)
	ret
]

Mnemonic!: alias struct! [
	string		[c-string!]
	seed		[byte-ptr!]
	slen		[integer!]
	entropy		[byte-ptr!]
	elen		[integer!]
]

Mnemonic: context [
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
			vl: 1 + read-11bits mix pos
			tstr: as c-string! BIP39_WORDLIST_ENGLISH/vl
			tlen: length? tstr
			copy-memory str + spos as byte-ptr! tstr tlen
			spos: spos + tlen + 1
			str/spos: #" "
			pos: pos + 11
		]
		spos: spos + 1
		str/spos: null-byte
		ret: as Mnemonic! allocate size? Mnemonic!
		ret/string: as c-string! str
		ret
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
