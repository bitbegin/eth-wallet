Red [
	Title:	"bit-access"
	Author: "bitbegin"
	File: 	%bit-access.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

bit-access: context [
	read-bits: func [
		buf			[binary!]
		pos			[integer!]
		bits		[integer!]
		return:		[integer!]
		/local ret readed h l temp mask
	][
		ret: 0
		readed: 0
		while [readed < bits][
			h: pos / 8 l: pos % 8
			temp: pick buf h + 1
			temp: temp >>> l
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
		buf			[binary!]
		pos			[integer!]
		bits		[integer!]
		vl			[integer!]
		/local writed h l temp mask temp2
	][
		writed: 0
		while [writed < bits][
			h: pos / 8 l: pos % 8
			mask: (1 << (8 - l)) - 1
			temp: (vl >>> writed) and mask
			either bits < (writed + (8 - l)) [
				mask: (1 << (bits - writed + l)) - 1
				mask: mask and (complement ((1 << l) - 1))
				mask: FFh and complement mask
			][
				mask: (1 << l) - 1
			]
			temp2: pick buf h + 1
			either temp2 = none [
				append buf temp << l
			][
				temp2: temp2 and mask
				poke buf h + 1 (temp2 + (temp << l))
			]
			writed: writed + (8 - l)
			pos: pos + (8 - l)
		]
	]
]
