package profile

import (
	"strconv"
	"strings"

	"github.com/taravancil/cryptopals/crypto"
)

// Parse parses a string and returns the corresponding profile object
func Parse(s string) map[string]string {
	m := make(map[string]string)
	objs := strings.Split(s, "&")

	// We expect 3 keys in the profile object
	objs = objs[0:3]

	for _, val := range objs {
		l := strings.Split(val, "=")
		m[l[0]] = l[1]
	}
	return m
}

// Encode encodes a profile object into the corresponding string
func Encode(m map[string]string) string {
	var cookie string

	// The cookie needs to be encoded in order, so make a slice of the keys
	keys := []string{"email", "uid", "role"}
	for _, key := range keys {
		cookie += key + "=" + m[key] + "&"
	}
	// Trim the trailing ampersand
	return strings.TrimSuffix(cookie, "&")
}

// New returns an encoded profile string given an email address. & and =
// are stripped from the input.
func New(email string) string {
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)

	m := make(map[string]string)
	m["email"] = email
	m["uid"] = "1"
	m["role"] = "user"
	return Encode(m)
}

// Encrypt encrypts an encoded profile under AES ECB
func Encrypt(profile, key []byte) ([]byte, error) {
	encrypted, err := crypto.EcbEncrypt(profile, key)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// Decrypt decrypts a encoded profile encrypted under AES ECB
func Decrypt(profile, key []byte) ([]byte, error) {
	decrypted, err := crypto.EcbDecrypt(profile, key)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func QuoteForbidden(f []string, s string) string {
	for _, char := range f {
		s = strings.Replace(s, char, strconv.Quote(char), -1)
	}
	return s
}

func ProcessComment(s string) string {
	s = QuoteForbidden([]string{"=", ";"}, s)

	prependStr := "comment1=cooking%20MCs;userdata="
	appendStr := ";comment2=%20like%20a%20pound%20of%20bacon"
	return prependStr + s + appendStr
}

func HasAdmin(ciphertext, key, iv []byte) bool {
	decrypted, _ := crypto.CbcDecrypt(ciphertext, key, iv)
	tuples := strings.Split(string(decrypted), ";")
	for _, val := range tuples {
		s := strings.Split(val, "=")
		if s[0] == "admin" && s[1] == "true" {
			return true
		}
	}
	return false
}
