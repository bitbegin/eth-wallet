Red [
	Title:	"bip39"
	Author: "bitbegin"
	File: 	%bip39.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %pbkdf2.red

urandom: routine [
	len			[integer!]
	/local
		data	[byte-ptr!]
][
	data: allocate len
	crypto/urandom data len
	stack/set-last as red-value! binary/load data len
	free data
]

word-list: context [
	BIP39_WORDLIST_ENGLISH: load %bip39-english.txt
	word-nums: length? BIP39_WORDLIST_ENGLISH

	get-index: func [
		word		[word!]
		return:		[integer! none!]
		/local f
	][
		if f: find BIP39_WORDLIST_ENGLISH word [return (index? f) - 1]
		none
	]
	get-word: func [
		index		[integer!]
		return:		[word! none!]
	][
		if any [
			index < 0
			index >= word-nums
		][none]
		pick BIP39_WORDLIST_ENGLISH index + 1
	]
]

derive-seed: func [
	entropy			[string!]
	password		[string!]
	return:			[binary!]
	/local salt
][
	salt: copy "mnemonic"
	append salt password
	pbkdf2/derive entropy salt 2048 64 'SHA512
]

MnemonicType: context [
	word-nums: 5
	config: [
		;type			word	ebits	cbits	tbits
		Type12Words		12		128		4		132
		Type15Words		15		160		5		165
		Type18Words		18		192		6		198
		Type21Words		21		224		7		231
		Type24Words		24		256		8		264
	]
	for_word_count: func [
		size		[integer!]
		return:		[word! none!]
		/local i
	][
		i: 2
		loop word-nums [
			if config/(i) = size [return config/(i - 1)]
			i: i + 5
		]
		none
	]
	for_key_size: func [
		size		[integer!]
		return:		[word!]
		/local i
	][
		i: 3
		loop word-nums [
			if config/(i) = size [return config/(i - 2)]
			i: i + 5
		]
		none
	]

	total_bits: func [
		type		[word!]
		return:		[integer! none!]
		/local i
	][
		i: 1
		loop word-nums [
			if config/(i) = type [return config/(i + 4)]
			i: i + 5
		]
		none
	]
	entropy_bits: func [
		type		[word!]
		return:		[integer! none!]
		/local i
	][
		i: 1
		loop word-nums [
			if config/(i) = type [return config/(i + 2)]
			i: i + 5
		]
		none
	]
	checksum_bits: func [
		type		[word!]
		return:		[integer! none!]
		/local i
	][
		i: 1
		loop word-nums [
			if config/(i) = type [return config/(i + 3)]
			i: i + 5
		]
		none
	]
	word_count: func [
		type		[word!]
		return:		[integer! none!]
		/local i
	][
		i: 1
		loop word-nums [
			if config/(i) = type [return config/(i + 1)]
			i: i + 5
		]
		none
	]
]

string-to-entropy: func [
	str			[string!]
	return:		[string!]
][
	enbase/base debase/base str 16 2
]

binary-to-entropy: func [
	bin			[binary!]
	return:		[string!]
][
	enbase/base bin 2
]

entropy-to-string: func [
	entropy		[string!]
	return:		[string!]
][
	enbase/base debase/base entropy 2 16
]

entropy-to-binary: func [
	entropy		[string!]
	return:		[binary!]
][
	debase/base entropy 2
]

Mnemonic: context [

	words-to-entropy: func [
		blk			[block!]
		return:		[string!]
		/local num type ebits cbits entropy elen epos w vl raw ehash rhash
	][
		num: length? blk
		type: MnemonicType/for_word_count num
		ebits: MnemonicType/entropy_bits type
		cbits: MnemonicType/checksum_bits type
		elen: ebits / 8
		entropy: make string! ebits + cbits
		foreach w blk [
			;bit-access/write-bits entropy epos 11 (word-list/get-index to word! w) - 1
			vl: skip binary-to-entropy to binary! word-list/get-index w 21
			append entropy vl
		]
		raw: entropy-to-binary copy/part entropy ebits
		rhash: copy/part skip entropy ebits cbits
		ehash: copy/part binary-to-entropy checksum raw 'SHA256 cbits
		if rhash <> ehash [
			return make error! "invalid entropy!"
		]
		entropy
	]

	from-words: func [
		blk			[block!]
		password	[string!]
		return:		[block!]		;-- [words entropy seed]
		/local seed entropy
	][
		entropy: words-to-entropy blk
		seed: derive-seed form blk password
		reduce [blk entropy seed]
	]

	from-entropy: func [
		entropy		[string!]
		type		[word!]
		password	[string!]
		return:		[block!]		;-- [words entropy seed]
		/local cbits nwords bentropy ehash blk vl
	][
		if (length? entropy) <> MnemonicType/entropy_bits type [
			return make error! "invalid type!"
		]
		cbits: MnemonicType/checksum_bits type
		nwords: MnemonicType/word_count type
		bentropy: entropy-to-binary entropy
		ehash: binary-to-entropy checksum bentropy 'SHA256
		append/part entropy ehash cbits
		blk: make block! nwords
		loop nwords [
			insert/dup vl: copy/part entropy 11 "0" 5
			vl: to integer! entropy-to-binary vl
			append blk word-list/get-word vl
			entropy: skip entropy 11
		]
		from-words blk password
	]

	new: func [
		type		[word!]
		password	[string!]
		return:		[block!]		;-- [words entropy seed]
		/local elen bentropy entropy
	][
		elen: (MnemonicType/entropy_bits type) / 8
		bentropy: urandom elen
		entropy: binary-to-entropy bentropy
		from-entropy entropy type password
	]
]
