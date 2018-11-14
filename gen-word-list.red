Red [
	Title:	"gen-word-list"
	Author: "bitbegin"
	File: 	%gen-word-list.red
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

output: %bip39-english.reds
write output {Red/System [
	Title:	"bip39-english"
	Author: "bitbegin"
	File: 	%bip39-english.reds
	Tabs: 	4
	License: "BSD-3 - https://github.com/red/red/blob/master/BSD-3-License.txt"
]

}
write/append output "BIP39_WORDLIST_ENGLISH: [^/"

list: load %bip39-english.txt

foreach c list [
	write/append output mold mold c
	write/append output " "
]
write/append output "^/]"
