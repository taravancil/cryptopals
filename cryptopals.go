package main

import (
	stdBytes "bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/taravancil/cryptopals/blocks"
	"github.com/taravancil/cryptopals/bytes"
	"github.com/taravancil/cryptopals/crypto"
	"github.com/taravancil/cryptopals/profile"
	"github.com/taravancil/cryptopals/utils"
)

var s = rand.NewSource(time.Now().UnixNano())
var r = rand.New(s)

type Challenge struct {
	actual, expected Result
}

type Result interface{}

func main() {
	var done = []func() (Result, Result){c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19}

	for i, chal := range done {
		var c Challenge
		c.actual, c.expected = chal()
		if equal(c.actual, c.expected) {
			fmt.Printf("\u2714 Challenge %d passed!\n", i+1)
			fmt.Printf("%v\n\n", c.actual)
		} else {
			fmt.Printf("\u2716 Challenge %d FAILED\n", i+1)
			fmt.Printf("Expected: %v\nGot: %v\n\n", c.expected, c.actual)
		}
	}
}

// Convert hex to base64
func c1() (actual, expected Result) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	result, err := bytes.HexToBase64(input)
	if err != nil {
		log.Fatal(err)
	}

	return result, expected
}

// XOR two equal-length buffers
func c2() (actual, expected Result) {
	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"

	expected = "746865206b696420646f6e277420706c6179"

	out1, err := hex.DecodeString(in1)
	if err != nil {
		log.Fatal(err)
	}
	out2, err := hex.DecodeString(in2)
	if err != nil {
		log.Fatal(err)
	}

	xored, err := bytes.Xor(out1, out2)
	if err != nil {
		log.Fatal(err)
	}

	return hex.EncodeToString(xored), expected
}

/* Single-byte XOR cipher
* Given a string that has been XOR'd against a single character, find
* the key and decrypt the string.
 */
func c3() (actual, expected Result) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	expected = string([]byte{99, 79, 79, 75, 73, 78, 71, 0, 109, 99, 7, 83, 0, 76, 73, 75, 69, 0, 65, 0, 80, 79, 85, 78, 68, 0, 79, 70, 0, 66, 65, 67, 79, 78})

	ciphertext, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}

	// Assume the most popular byte in the ciphertext is the key
	key, err := bytes.Popular(ciphertext, 1)
	if err != nil {
		log.Fatal(err)
	}

	result, err := bytes.XorRepeatingKey(ciphertext, key)
	if err != nil {
		log.Fatal(err)
	}

	return string(result), expected
}

// Detect single-character XOR
func c4() (actual, expected Result) {
	expected = string([]byte{110, 79, 87, 0, 84, 72, 65, 84, 0, 84, 72, 69, 0, 80, 65, 82, 84, 89, 0, 73, 83, 0, 74, 85, 77, 80, 73, 78, 71, 42})

	input, err := ioutil.ReadFile("input/4.txt")
	if err != nil {
		panic(err)
	}

	lines := strings.Split(string(input), "\n")
	var bestScore = 0.0
	var plaintext string

	// Find the most popular byte in each line
	for i := 0; i < len(lines)-1; i++ {
		line, err := hex.DecodeString(lines[i])
		if err != nil {
			log.Println(err)
			continue
		}

		key, err := bytes.Popular(line, 1)
		if err != nil {
			log.Println(err)
			continue
		}

		decrypted, err := bytes.XorRepeatingKey(line, key)
		if err != nil {
			log.Println(err)
			continue
		}

		// Score each string for how likely it is English
		decryptedStr := string(decrypted)
		score := utils.EnglishScore(decryptedStr)
		if score > bestScore {
			bestScore = score
			plaintext = decryptedStr
		}
	}
	return plaintext, expected
}

// Implement repeating-key XOR
func c5() (actual, expected Result) {
	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	key := []byte("ICE")

	encrypted, err := bytes.XorRepeatingKey(input, key)
	if err != nil {
		log.Fatal(err)
	}

	encryptedStr := hex.EncodeToString(encrypted)
	return encryptedStr, expected
}

// Break repeating-key XOR
func c6() (actual, expected Result) {
	input, _ := ioutil.ReadFile("input/6.txt")
	output, _ := utils.ReadAndStripFile("output/6.txt")
	expected = string(output)

	inputStr := string(input)
	ciphertext, err := base64.StdEncoding.DecodeString(inputStr)
	if err != nil {
		log.Fatal(err)
	}

	// Find the 3 most likely keysizes in the range 2-40
	keysizes, err := crypto.FindKeysizes(ciphertext, 3, 2, 40)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := crypto.BreakXorRepeating(ciphertext, keysizes)
	if err != nil {
		log.Fatal(err)
	}
	return string(utils.Strip(plaintext)), expected
}

/* Implement AES in ECB mode, then decrypt a ciphertext encrypted under
* a known key.
 */
func c7() (actual, expected Result) {
	input, _ := ioutil.ReadFile("input/7.txt")
	output, _ := utils.ReadAndStripFile("output/7.txt")
	expected = string(output)

	key := []byte("YELLOW SUBMARINE")
	text := string(input)

	ciphertext, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := crypto.EcbDecrypt(ciphertext, key)
	if err != nil {
		log.Fatal(err)
	}

	return string(utils.Strip(plaintext)), expected
}

// Detect AES in ECB mode
func c8() (actual, expected Result) {
	input, _ := ioutil.ReadFile("input/8.txt")
	expected = 132

	hexStrings := strings.Split(string(input), "\n")
	ciphertexts := make([][]byte, len(hexStrings)-1)

	for i := 0; i < len(ciphertexts); i++ {
		ciphertexts[i], _ = hex.DecodeString(hexStrings[i])
		ecb, err := bytes.HasRepeatedBlock(ciphertexts[i], aes.BlockSize)
		if err != nil {
			log.Fatal(err)
		}
		if ecb {
			return i, expected
		}
	}
	return -1, expected
}

// Implement PKCS#7 padding
func c9() (actual, expected Result) {
	input := "YELLOW SUBMARINE"
	expected = "YELLOW SUBMARINE\x04\x04\x04\x04"

	padded, err := blocks.Pkcs7([]byte(input), 20)
	if err != nil {
		log.Fatal(err)
	}
	return string(padded), expected
}

// Implement AES CBC mode
func c10() (actual, expected Result) {
	input, _ := ioutil.ReadFile("input/10.txt")
	output, _ := utils.ReadAndStripFile("output/10.txt")
	expected = string(output)

	key := []byte("YELLOW SUBMARINE")
	iv := stdBytes.Repeat([]byte("\x00"), aes.BlockSize)
	ciphertext, _ := base64.StdEncoding.DecodeString(string(input))
	plaintext, _ := crypto.CbcDecrypt(ciphertext, key, iv)

	return string(utils.Strip(plaintext)), expected
}

/* Implement an ECB/CBC detection oracle
* Write a function that accepts input, appends 5-10 bytes before and
* after the input, then encrypts it under a random AES key. It should
* randomly choose to encrypt under CBC or ECB mode. Detect which.
 */
func c11() (actual, expected Result) {
	plaintext := []byte("Put your good face on, not foolin' no one. You're a jackrabbit underneath.")

	encrypter, actualMode, err := crypto.RandomAesMode()
	if err != nil {
		log.Println(err)
	}

	mode := crypto.AesOracle(plaintext, encrypter)

	switch actualMode {
	case "CBC":
		expected = "CBC"
	case "ECB":
		expected = "ECB"
	}
	return mode, expected
}

/* Byte-at-a-time ECB decryption
* Create a modified oracle function that decrypts an unknown string encrypted
* under ECB-mode with a consistent, but unknown key.
* AES-128-ECB(known-string || unknown-string, key)
 */
func c12() (actual, expected Result) {
	expected = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01"

	if crypto.GlobalAesKey == nil {
		crypto.GlobalAesKey = crypto.NewAesKey()
	}
	key := crypto.GlobalAesKey

	blocksize := crypto.DetectBlocksize(key)
	secretBlocks := len(crypto.AppendSecretEncryptEcb([]byte(""), key, false)) / blocksize

	var secret []byte

	createDict := func(plaintext []byte, block int) map[int][]byte {
		dict := make(map[int][]byte)
		for b := 0; b <= 255; b++ {
			extra := []byte{byte(b)}
			plaintext := append(plaintext, extra[0])
			ciphertext := crypto.AppendSecretEncryptEcb(plaintext, key, false)
			dict[b] = ciphertext[block*blocksize : blocksize*(block+1)]
		}
		return dict
	}

	for n := 0; n < secretBlocks; n++ {
		for i := 0; i < blocksize; i++ {
			short := stdBytes.Repeat([]byte("A"), blocksize-(i+1))
			plaintext := append(short, secret...)
			dict := createDict(plaintext, n)
			secretCiphertext := crypto.AppendSecretEncryptEcb(short, key, false)

			for char, lookup := range dict {
				if string(secretCiphertext[n*blocksize:blocksize*(n+1)]) == string(lookup) {
					char := []byte{byte(char)}
					secret = append(secret, char...)
				}
			}
		}
	}
	return string(secret), expected
}

/* ECB cut and paste
* Make a profile_for function that takes an email address and returns
* a user object encoded cookie-style (email=foo@bar.com&uid=10).
* Encrypt the encoded profile with AES ECB, and *supply* this to the
* "attacker". Find a way to create a valid admin profile.
 */
func c13() (actual, expected Result) {
	expected = "email=XXXXXXXXXXXXXX&uid=1&role=admin"
	key, _ := bytes.Random(aes.BlockSize)

	// A 14 byte-long email address will put role= at the end of the second block
	attackEmail := string(stdBytes.Repeat([]byte("X"), 14))
	// admin padded w/ 10 bytes will put admin at the beginning of the second block
	attackEmail2 := string(stdBytes.Repeat([]byte("X"), 10)) + "admin"

	profile1 := profile.New(attackEmail)
	profile2 := profile.New(attackEmail2)

	encrypted1, err := profile.Encrypt([]byte(profile1), key)
	if err != nil {
		log.Println(err)
	}
	encrypted2, err := profile.Encrypt([]byte(profile2), key)
	if err != nil {
		log.Println(err)
	}

	// Use first two blocks of encrypted1 and thirdBlock of encrypted2 to
	// create the attack ciphertext
	adminProfile := encrypted1[0:32]
	thirdBlock := encrypted2[16:32]
	adminProfile = append(adminProfile, thirdBlock...)

	decrypted, err := profile.Decrypt(adminProfile, key)
	if err != nil {
		log.Fatal(err)
	}

	// Parse the modified ciphertext and encode the admin profile
	parsed := profile.Parse(string(decrypted))
	encoded := profile.Encode(parsed)

	return encoded, expected
}

/* Byte-at-a-time ECB decryption
* Same goal as #12, but prepend a random # of random bytes to input.
* AES-128-ECB(random-#-bytes || input, key)
 */
func c14() (actual, expected Result) {
	expected = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01"

	if len(crypto.GlobalAesKey) == 0 {
		crypto.GlobalAesKey = crypto.NewAesKey()
	}
	key := crypto.GlobalAesKey

	blocksize := crypto.DetectBlocksize(key)

	createDict := func(plaintext []byte, prefixLength, block int) map[int][]byte {
		dict := make(map[int][]byte)
		for b := 0; b <= 255; b++ {
			extra := []byte{byte(b)}
			plaintext := append(plaintext, extra[0])
			ciphertext := crypto.AppendSecretEncryptEcb(plaintext, key, true)
			dict[b] = ciphertext[(block*blocksize)+prefixLength : (blocksize*(block+1))+prefixLength]
		}
		return dict
	}

	findPrefixLength := func(blocksize int, key []byte) int {
		// If we send 2-3 blocks of repeating bytes, we will see a repeating block
		for i := blocksize * 2; i <= blocksize*3; i++ {
			encrypted := crypto.AppendSecretEncryptEcb(stdBytes.Repeat([]byte("A"), i), key, true)
			numBlocks := len(encrypted) / blocksize

			// Loop through blocks to find a repeat
			for j := 0; j < numBlocks-1; j++ {
				firstBlock := encrypted[j*blocksize : (j+1)*blocksize]
				secondBlock := encrypted[(j+1)*blocksize : (j+2)*blocksize]

				// Repeating block indicates we added enough bytes to make an even block
				if string(firstBlock) == string(secondBlock) {
					return (j+2)*blocksize - i
				}
			}
		}
		return 0
	}

	// Knowing the length of the random prefix bytes, pad input to make a full block
	var secretBlocks int
	prefix := findPrefixLength(blocksize, key)
	// TODO: There must be a better way to account for prefix/16 rounding down and
	// giving 1 too few blocks
	if prefix%blocksize <= 5 {
		secretBlocks += 1
	}
	pad := blocksize - (prefix % blocksize) // prefix + pad = full block
	prefix += pad

	// Figure out how many blocks to solve
	totalBlocks := len(crypto.AppendSecretEncryptEcb([]byte(""), key, true)) / blocksize
	secretBlocks += totalBlocks - (prefix / 16)
	var secret []byte

	for n := 0; n < secretBlocks; n++ {
		for i := 0; i < blocksize; i++ {
			// Send A*pad to pad the prefix to a full block, + A*blocksize-1,
			// blocksize-2, ... until that block of the secret is solved
			short := stdBytes.Repeat([]byte("A"), pad+blocksize-(i+1))
			plaintext := append(short, secret...)

			// Create a dictionary of ciphertexts for every character
			dict := createDict(plaintext, prefix, n)
			secretCiphertext := crypto.AppendSecretEncryptEcb(short, key, true)

			for char, lookup := range dict {
				targetBlock := secretCiphertext[prefix+(n*blocksize) : prefix+(blocksize*(n+1))]
				if string(targetBlock) == string(lookup) {
					char := []byte{byte(char)}
					secret = append(secret, char...)
				}
			}
		}
	}
	return string(secret), expected
}

// Write a function for validating PKCS#7 padding
func c15() (actual, expected Result) {
	strings := map[string]string{
		"ICE ICE BABY\x04\x04\x04\x04": "ICE ICE BABY",
		"ICE ICE BABY\x05\x05\x05\x05": "invalid padding: not all padding bytes the same",
		"ICE ICE BABY\x01\x02\x03\x04": "invalid padding: not all padding bytes the same",
		"ICE ICE BABY":                 "invalid padding: len(ICE ICE BABY) is not a multiple of 16",
	}

	for str, ok := range strings {
		var result string

		stripped, err := blocks.StripIfValidPkcs7([]byte(str))
		if err != nil {
			result = err.Error()
		} else {
			result = string(stripped)
		}
		if result != ok {
			return false, true
		}
	}
	return true, true
}

/* CBC bitflipping attack
* Create a function, that given an input, prepends:
* "comment1=cooking%20MCs;userdata="
* and appends:
* ";comment2=%20like%20a%20pound%20of%20bacon"
* , quotes out the ; and =, and pads and encrypts it under AES CBC.
* Another function should decrypt the string and return true if
* ";admin=true;" exists in the string. Modify the ciphertext to
* make the second funcion return true.
 */
func c16() (actual, expected Result) {
	key := crypto.NewAesKey()

	input := "XadminXtrue"
	inputBytes := []byte(input)
	str := profile.ProcessComment(input)

	iv, _ := bytes.Random(aes.BlockSize)
	encrypted, err := crypto.CbcEncrypt([]byte(str), key, iv)
	if err != nil {
		panic(err)
	}

	// Flip the targeted bytes ("X"s in the input string)
	encrypted[16] = encrypted[16] ^ 59 ^ inputBytes[0]
	encrypted[22] = encrypted[22] ^ 61 ^ inputBytes[6]

	hasAdmin := profile.HasAdmin(encrypted, key, iv)
	return hasAdmin, true
}

/* CBC padding oracle
* Write a CBC padding oracle that decrypts a ciphertext and detects
* if the plaintext is padded properly with PKCS#7. Choose a random line
* from 17.txt, encrypt it, then decrypt it using the oracle.
 */
func c17() (actual, expected Result) {
	input, _ := ioutil.ReadFile("input/17.txt")
	strs := strings.Split(string(input), "\n")
	str := strs[r.Intn(10)]
	decodedStr, _ := base64.StdEncoding.DecodeString(str)

	if crypto.GlobalAesKey == nil {
		crypto.GlobalAesKey = crypto.NewAesKey()
	}
	key := crypto.GlobalAesKey
	iv, _ := bytes.Random(aes.BlockSize)

	ciphertext, err := crypto.CbcEncrypt([]byte(decodedStr), key, iv)
	if err != nil {
		log.Fatal(err)
	}

	blocks, err := bytes.SplitIntoBlocks(ciphertext, aes.BlockSize)
	if err != nil {
		log.Fatal(err)
	}

	var plaintext []byte

	for n := 0; n < len(blocks); n++ {
		block := blocks[n]
		controlled := make([]byte, aes.BlockSize)
		plaintextBlock := make([]byte, aes.BlockSize)
		intermediate := make([]byte, aes.BlockSize)
		prevBlock := make([]byte, aes.BlockSize)

		if n == 0 {
			prevBlock = iv
		} else {
			prevBlock = blocks[n-1]
		}

		for i := aes.BlockSize - 1; i >= 0; i-- {
			paddingLen := aes.BlockSize - i
			paddingByte := byte(paddingLen)

			// Set the last paddingLen bytes of controlled to so that when decrypted,
			// each will be a valid padding byte.
			for j := 0; j < paddingLen; j++ {
				controlled[i+j] = paddingByte ^ intermediate[i+j]
			}

			for b := 0; b <= 256; b++ {
				controlled[i] = byte(b)
				controlled := append(controlled, block...)
				valid, _ := crypto.CbcPaddingOracle(controlled, iv)
				if valid {
					// The padding is valid and we control the ith byte of the
					// block XORed with the intermediate state. XOR is an inverse
					// operation so finding the ith byte of the intermediate state
					// is as simple as:
					intermediate[i] = paddingByte ^ controlled[i]
					break
				}
			}
			plaintextBlock[i] = prevBlock[i] ^ intermediate[i]
		}
		plaintext = append(plaintext, plaintextBlock...)
	}

	decrypted, _ := crypto.CbcDecrypt(ciphertext, key, iv)
	return string(plaintext), string(decrypted)
}

// Implement AES in CTR mode
func c18() (actual, expected Result) {
	plaintext := []byte("A-B-C. A-always, B-be, C-counting. Always be counting!")
	key := []byte("YELLOW SUBMARINE")

	ciphertext := make([]byte, len(plaintext))
	plaintext2 := make([]byte, len(plaintext))

	nonce := 0
	// Encrypt...
	stream, err := crypto.Ctr(uint64(nonce), key)
	if err != nil {
		log.Fatal(err)
	}
	stream.XORKeyStream(ciphertext, plaintext)

	// Decrypt with a new key stream
	stream, err = crypto.Ctr(uint64(nonce), key)
	if err != nil {
		log.Fatal(err)
	}
	stream.XORKeyStream(plaintext2, ciphertext)

	return string(plaintext2), string(plaintext)
}

func equal(actual, expected Result) bool {
	if actual != expected {
		return false
	}
	return true
}
