// Package blocks provides utility functions for working with blocks
package blocks

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Pkcs7 pads an input slice with PKCS7 to the specified blocksize
func Pkcs7(b []byte, blocksize int) ([]byte, error) {
	if blocksize < 1 {
		return b, fmt.Errorf("invalid blocksize %d", blocksize)
	}

	// The number of padding bytes
	num := blocksize - len(b)%blocksize

	padding := bytes.Repeat([]byte{byte(num)}, num)
	return append(b, padding...), nil
}

// StripIfValidPkcs7 returns a stripped version of a slice padded with PKCS7
// padding if the padding is valid. Else returns an error.
func StripIfValidPkcs7(b []byte) ([]byte, error) {
	valid, n, err := ValidPkcs7(b)
	if !valid {
		return b, err
	}

	// Strip padding
	length := len(b)
	return b[:length-n], nil
}

// ValidPkcs7 determines if a slice has proper PKCS7 padding and returns the number of padding bytes.
func ValidPkcs7(b []byte) (bool, int, error) {
	length := len(b)
	if length < 1 {
		return false, 0, errors.New("empty slice")
	}

	if length%aes.BlockSize != 0 {
		return false, 0, fmt.Errorf("invalid padding: len(%s) is not a multiple of %d", string(b), aes.BlockSize)
	}

	last := b[length-1 : length]
	pad, n := binary.Uvarint(last)

	if n <= 0 || pad == 0 {
		return false, 0, errors.New("no padding")
	}

	if pad > aes.BlockSize {
		return false, 0, errors.New("last byte exceeds blocksize")
	}

	// Check that padding is as long as pad
	padding := make([]byte, pad)
	padding = b[length-int(pad):]
	if len(padding) != int(pad) {
		return false, 0, fmt.Errorf("invalid padding: expected %d bytes of padding, got %d", pad, len(padding))
	}

	// All bytes in padding should be the same
	temp := padding[0]
	for _, val := range padding {
		if val != temp {
			return false, 0, errors.New("invalid padding: not all padding bytes the same")
		}
		temp = val
	}
	return true, int(pad), nil
}
