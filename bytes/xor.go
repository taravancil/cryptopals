package bytes

import (
	"errors"
)

// Xor returns the results of XORing two equal-length byte slices
func Xor(b1, b2 []byte) ([]byte, error) {
	b1Len := len(b1)
	b2Len := len(b2)

	if b1Len < 1 {
		return nil, errors.New("empty slice")
	}
	if b2Len < 1 {
		return nil, errors.New("empty slice")
	}
	if b1Len != b2Len {
		return nil, errors.New("length mismatch")
	}

	xored := make([]byte, len(b1))
	for i := range xored {
		xored[i] = b1[i] ^ b2[i]
	}
	return xored, nil
}

// XorRepeating returns the result of applying a repeating XOR key to a byte slice
func XorRepeatingKey(b, key []byte) ([]byte, error) {
	keyLen := len(key)
	if len(b) == 0 {
		return nil, errors.New("cannot XOR an empty slice")
	}
	if keyLen == 0 {
		return nil, errors.New("invalid key")
	}

	xored := make([]byte, len(b))
	j := 0

	for i := range b {
		// Return to first byte in key at the end of a repeat
		if j == keyLen {
			j = 0
		}
		xored[i] = b[i] ^ key[j]
		j++
	}
	return xored, nil
}
