Red [
	Title:	"bip39"
	Author: "bitbegin"
	File: 	%bip39.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %pbkdf2.red
#include %bit-access.red

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
		if f: find BIP39_WORDLIST_ENGLISH word [return index? f]
		none
	]
	get-word: func [
		index		[integer!]
		return:		[word! none!]
	][
		if any [
			index = 0
			index < 0
			index > word-nums
		][none]
		pick BIP39_WORDLIST_ENGLISH index
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
	for_word_count: func [
		size		[integer!]
		return:		[word!]
	][
		case [
			size = 12 ['Type12Words]
			size = 15 ['Type15Words]
			size = 18 ['Type18Words]
			size = 21 ['Type21Words]
			size = 24 ['Type24Words]
		]
	]
	for_key_size: func [
		size		[integer!]
		return:		[word!]
	][
		case [
			size = 128 ['Type12Words]
			size = 160 ['Type15Words]
			size = 192 ['Type18Words]
			size = 224 ['Type21Words]
			size = 256 ['Type24Words]
		]
	]
	for_phrase: func [
		str			[string!]
		return:		[word!]
		/local count
	][
		count: length? split str " "
		for_word_count count
	]
	total_bits: func [
		type		[word!]
		return:		[integer!]
	][
		case [
			type = 'Type12Words [132]
			type = 'Type15Words [165]
			type = 'Type18Words [198]
			type = 'Type21Words [231]
			type = 'Type24Words [264]
		]
	]
	entropy_bits: func [
		type		[word!]
		return:		[integer!]
	][
		case [
			type = 'Type12Words [128]
			type = 'Type15Words [160]
			type = 'Type18Words [192]
			type = 'Type21Words [224]
			type = 'Type24Words [256]
		]
	]
	checksum_bits: func [
		type		[word!]
		return:		[integer!]
	][
		case [
			type = 'Type12Words [4]
			type = 'Type15Words [5]
			type = 'Type18Words [6]
			type = 'Type21Words [7]
			type = 'Type24Words [8]
		]
	]
	word_count: func [
		type		[word!]
		return:		[integer!]
	][
		case [
			type = 'Type12Words [12]
			type = 'Type15Words [15]
			type = 'Type18Words [18]
			type = 'Type21Words [21]
			type = 'Type24Words [24]
		]
	]
]

Mnemonic: context [
	from_string_entropy: func [
		str			[string!]
		return:		[binary!]
		/local words num type ebits cbits entropy elen epos w raw ehash
	][
		words: split str " "
		num: length? words
		type: MnemonicType/for_word_count num
		ebits: MnemonicType/entropy_bits type
		cbits: MnemonicType/checksum_bits type
		elen: ebits / 8
		entropy: make binary! elen + 1
		epos: 0
		foreach w words [
			bit-access/write-bits entropy epos 11 (word-list/get-index to word! w) - 1
			epos: epos + 11
		]
		raw: copy/part entropy elen
		ehash: checksum raw 'SHA256
		if (pick entropy elen + 1) <> (ehash/1 and (1 << cbits - 1)) [
			return make error! "invalid entropy!"
		]
		entropy
	]

	from_string: func [
		str			[string!]
		password	[string!]
		return:		[block!]		;-- [string entropy seed]
		/local seed entropy
	][
		entropy: from_string_entropy str
		seed: derive-seed str password
		reduce [str entropy seed]
	]

	from_entropy: func [
		entropy		[binary!]
		type		[word!]
		password	[string!]
		return:		[block!]		;-- [string entropy seed]
		/local elen cbits nwords ehash str vl epos
	][
		elen: length? entropy
		if (elen * 8) <> MnemonicType/entropy_bits type [
			return make error! "invalid type!"
		]
		cbits: MnemonicType/checksum_bits type
		nwords: MnemonicType/word_count type
		ehash: checksum entropy 'SHA256
		append entropy ehash/1 and (1 << cbits - 1)
		str: make string! nwords * 12
		epos: 0
		loop nwords [
			vl: 1 + bit-access/read-bits entropy epos 11
			append str to string! word-list/get-word vl
			append str " "
			epos: epos + 11
		]
		remove back tail str
		from_string str password
	]

	new: func [
		type		[word!]
		password	[string!]
		return:		[block!]		;-- [string entropy seed]
		/local elen entropy
	][
		elen: (MnemonicType/entropy_bits type) / 8
		entropy: urandom elen
		from_entropy entropy type password
	]
]

bip39: context [


]

probe Mnemonic/new 'Type24Words "123456"
