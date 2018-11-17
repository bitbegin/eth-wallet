Red [
	Title:	"bit-access-test"
	Author: "bitbegin"
	File: 	%bit-access-test.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

#include %bit-access.red

a: make binary! 33
i: 0
loop 33 [
	append a i
	i: i + 1
]

b: make block! 24
tpos: 0
loop 24 [
	append b bit-access/read-bits a tpos 11
	tpos: tpos + 11
]

c: make binary! 33
tpos: 0
i: 1
loop 24 [
	bit-access/write-bits c tpos 11 pick b i
	i: i + 1
	tpos: tpos + 11
]

print a = c