Red/System [
	Title:	"bits-test"
	Author: "bitbegin"
	File: 	%bits-test.reds
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]


test-bits: func [
	str			[c-string!]
	str2		[c-string!]
	bits		[integer!]
	return:		[logic!]
	/local
		len		[integer!]
		pos		[integer!]
		v		[integer!]
][
	len: length? str
	assert len > 80
	assert bits <= 32

	pos: 0
	loop 20 [
		v: read-bits as byte-ptr! str pos bits
		write-bits as byte-ptr! str pos bits v
	]
	if 0 = compare-memory as byte-ptr! str as byte-ptr! str2 len [return true]
	false
]

test-string: "abcdefghijklmnopqrstuvwxyz1234ABCDEFGHIJKLMNOPQRSTUVWXYZ5678abcdefghijklmnopqrstuvwxyz1234"
test-string2: "abcdefghijklmnopqrstuvwxyz1234ABCDEFGHIJKLMNOPQRSTUVWXYZ5678abcdefghijklmnopqrstuvwxyz1234 - new one"

i: 0
loop 33 [
	print ["^/read/write: " i " bits test: "]
	print-line test-bits test-string test-string2 i
	i: i + 1
]
