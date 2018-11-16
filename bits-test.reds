Red/System [
	Title:	"bits-test"
	Author: "bitbegin"
	File: 	%bits-test.reds
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %bits.reds

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

print-line "read/write 11 bits: "
a: allocate 33
i: 1
loop 33 [
	a/i: as byte! i
	i: i + 1
]

b: as int-ptr! allocate 24 * 4
tpos: 0
i: 1
loop 24 [
	b/i: read-bits a tpos 11
	i: i + 1
	tpos: tpos + 11
]

c: allocate 33
tpos: 0
i: 1
loop 24 [
	write-bits c tpos 11 b/i
	i: i + 1
	tpos: tpos + 11
]
print-line either 0 = compare-memory a c 33 [true][false]