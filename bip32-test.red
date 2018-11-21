Red []

#include %bip32.red

;-- test from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
probe priv: bip32key/decode "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
probe pub: bip32key/decode "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
probe secp256/create-pubkey priv/6

bin-entropy: #{000102030405060708090a0b0c0d0e0f}
seeds: Mnemonic/from-binary bin-entropy "123456"
master: bip32key/from-entropy seeds/2
probe bip32key/encode reduce [true 0 0 0 master/2 master/1]
probe bip32key/encode reduce [false 0 0 0 master/2 secp256/create-pubkey master/1]

print [80000000h]
probe bip32key/encode bip32key/derive seeds/2 [80000000h] true
probe bip32key/encode bip32key/derive seeds/2 [80000000h] false
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h] true
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h] false

print [80000000h 1]
probe bip32key/encode bip32key/derive seeds/2 [80000000h 1] true
probe bip32key/encode bip32key/derive seeds/2 [80000000h 1] false
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1] true
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1] false

print [80000000h 1 80000002h]
probe bip32key/encode bip32key/derive seeds/2 [80000000h 1 80000002h] true
probe bip32key/encode bip32key/derive seeds/2 [80000000h 1 80000002h] false
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1 80000002h] true
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1 80000002h] false

print [80000000h 1 80000002h 2]
probe bip32key/encode bip32key/derive seeds/2 [80000000h 1 80000002h 2] true
probe bip32key/encode bip32key/derive seeds/2 [80000000h 1 80000002h 2] false
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1 80000002h 2] true
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1 80000002h 2] false

print [80000000h 1 80000002h 2 1000000000]
probe bip32key/encode bip32key/derive seeds/2 [80000000h 1 80000002h 2 1000000000] true
probe bip32key/encode bip32key/derive seeds/2 [80000000h 1 80000002h 2 1000000000] false
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1 80000002h 2 1000000000] true
probe bip32key/encode bip32key/derive-bin bin-entropy [80000000h 1 80000002h 2 1000000000] false

print ["ext pubkey: " 1000000000]
probe bip32key/encode bip32key/derive-extkey bip32key/decode "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV" [1000000000] false
print ["ext privkey: " 1000000000]
probe bip32key/encode bip32key/derive-extkey bip32key/decode "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334" [1000000000] false
print ["ext privkey: " 1000000000]
probe bip32key/encode bip32key/derive-extkey bip32key/decode "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334" [1000000000] true
