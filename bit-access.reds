Red/System [
	Title:	"bit-access"
	Author: "bitbegin"
	File: 	%bit-access.reds
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

bit-access: context [
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
]
