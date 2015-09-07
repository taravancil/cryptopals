package crypto

import (
	stdBytes "bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"math/rand"
	"time"

	"github.com/taravancil/cryptopals/blocks"
	"github.com/taravancil/cryptopals/bytes"
)

var GlobalAesKey []byte

type ecb struct {
	b         cipher.Block
	blockSize int
}

type cbc struct {
	b         cipher.Block
	blockSize int
}

type ecbDecrypter ecb

type ecbEncrypter ecb

func NewECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(NewECB(b))
}

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(NewECB(b))
}

func (d *ecbDecrypter) BlockSize() int {
	return d.blockSize
}

func (d *ecbEncrypter) BlockSize() int {
	return d.blockSize
}

func (d *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%d.blockSize != 0 {
		panic("ciphertext not full blocks")
	}
	for len(src) > 0 {
		d.b.Decrypt(dst, src[:d.blockSize])
		src = src[d.blockSize:]
		dst = dst[d.blockSize:]
	}
}

func (d *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%d.blockSize != 0 {
		panic("plaintext not full blocks")
	}
	for len(src) > 0 {
		d.b.Encrypt(dst, src[:d.blockSize])
		src = src[d.blockSize:]
		dst = dst[d.blockSize:]
	}
}

func EcbEncrypt(plaintext, key []byte) ([]byte, error) {
	plaintext, _ = blocks.Pkcs7(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	encrypter := NewECBEncrypter(block)
	encrypter.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func EcbDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	decrypter := NewECBDecrypter(block)
	decrypter.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

func CbcEncrypt(plaintext, key, iv []byte) ([]byte, error) {
	plaintext, _ = blocks.Pkcs7(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func CbcDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// Ctr is as utility function for setting up a keystream for AES in
// CTR mode
func Ctr(iv, key []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewCTR(block, iv), nil
}

// NewAesKey generates a random AES key
func NewAesKey() []byte {
	key, _ := bytes.Random(aes.BlockSize)
	return key
}

var seed = rand.NewSource(time.Now().UnixNano())
var r = rand.New(seed)

func RandomAesMode() (cipher.BlockMode, string, error) {
	block, err := aes.NewCipher(NewAesKey())
	if err != nil {
		return nil, "", err
	}
	mode := r.Intn(2)
	if mode == 1 {
		iv, _ := bytes.Random(aes.BlockSize)
		encrypter := cipher.NewCBCEncrypter(block, iv)
		return encrypter, "CBC", nil
	}
	encrypter := NewECBEncrypter(block)
	return encrypter, "ECB", nil
}

// AesOracle prepends and appends 5-10 random bytes to a plaintext,
// encrypts the plaintext under a predetermined BlockMode, then
// returns the detected BlockMode
func AesOracle(plaintext []byte, encrypter cipher.BlockMode) string {
	// Generate random bytes to prepend/append to plaintext
	prependBytes, _ := bytes.Random(r.Intn(5) + 5)
	appendBytes, _ := bytes.Random(r.Intn(5) + 5)

	plaintext = append(prependBytes, plaintext...)
	plaintext = append(plaintext, appendBytes...)
	plaintext, _ = blocks.Pkcs7(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(plaintext))
	modifiedCiphertext := make([]byte, len(plaintext))

	// Modify the first block of the plaintext
	modified := plaintext
	modified[0] = byte(255)
	encrypter.CryptBlocks(ciphertext, plaintext)
	encrypter.CryptBlocks(modifiedCiphertext, modified)

	// If the second block in the modified ciphertext is affected by a
	// change in the first block of the plaintext, return CBC mode
	if ciphertext[16] != modifiedCiphertext[16] {
		return "CBC"
	}
	return "ECB"
}

// DetectBlocksize detects the blocksize of a ciphertext encrypted
// under AES ECB mode
func DetectBlocksize(key []byte) int {
	ciphertext, _ := EcbEncrypt([]byte("A"), key)
	length := len(ciphertext)
	var newLength int
	i := 2

	// Continuously encrypt more bytes. When the length of the
	// encrypted bytes is > the length enc(single-byte || padding),
	// we have multiple blocks of ciphertext, so the blocksize
	// is the difference between the two lengths.
	for {
		ciphertext, _ = EcbEncrypt(stdBytes.Repeat([]byte("A"), i), key)
		newLength = len(ciphertext)
		if newLength > length {
			return newLength - length
		}
		i++
	}
}

var prefixBytes []byte

func AppendSecretEncryptEcb(plaintext, key []byte, prefix bool) []byte {
	if prefix == true {
		if len(prefixBytes) == 0 {
			prefixBytes, _ = bytes.Random(r.Intn(99) + 1)
		}
		plaintext = append(prefixBytes, plaintext...)
	}

	secret, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	plaintext = append(plaintext, secret...)
	ciphertext, _ := EcbEncrypt(plaintext, key)
	return ciphertext
}

// CbcValidPadding decrypts a CBC-encrypted ciphertext and detects if the plaintext was padded correctly.
func CbcPaddingOracle(ciphertext, iv []byte) (bool, error) {
	plaintext, err := CbcDecrypt(ciphertext, GlobalAesKey, iv)
	if err != nil {
		return false, err
	}

	valid, _, _ := blocks.ValidPkcs7(plaintext)
	if valid {
		return true, nil
	}
	return false, nil
}
