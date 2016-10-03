package bytes

import (
	"testing"
)

func TestHexToBase64(t *testing.T) {
	hexStr := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	base64Str := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	result, err := HexToBase64(hexStr)
	if err != nil {
		t.Error(err)

	}
	if result != base64Str {
		t.Error("expected %s, got %s", base64Str, result)
	}

	result, err = HexToBase64("")
	if err.Error() != "empty input string" {
		t.Error("should fail given an empty string")
	}
}

func TestPopular(t *testing.T) {
	b := []byte{1, 2, 2, 3, 3, 3}
	empty := []byte{}

	result, _ := Popular(b, 1)
	if result[0] != 3 {
		t.Fail()
	}

	result, _ = Popular(b, 2)
	if result[0] != 3 {
		t.Fail()
	}
	if result[1] != 2 {
		t.Fail()
	}

	// Test slice with 1 byte
	result, _ = Popular([]byte{1}, 1)
	if result[0] != 1 {
		t.Fail()
	}

	_, err := Popular(b, 0)
	if err.Error() != "invalid argument" {
		t.Error("should fail if 0 passed to n")
	}

	_, err = Popular(empty, 1)
	if err.Error() != "invalid argument" {
		t.Error("should fail if passed an empty slice")
	}

	_, err = Popular(b, 7)
	if err.Error() != ("n exceeds length of slice") {
		t.Error("should fail if n > len(b)")
	}
}

func TestSplitIntoBlocks(t *testing.T) {
	// Test evenly split slice
	blocks, err := SplitIntoBlocks([]byte{1, 1, 1, 1}, 1)
	if err != nil {
		t.Error(err)
	}
	if len(blocks) != 4 {
		t.Fail()
	}
	if len(blocks[0]) != 1 {
		t.Fail()
	}

	// Test slice that needs padding
	blocks, _ = SplitIntoBlocks([]byte{1, 2, 3, 4, 5}, 2)
	if len(blocks) != 3 {
		t.Fail()
	}
	if len(blocks[2]) != 2 {
		t.Fail()
	}
	// Test that padding is added to last block
	if blocks[2][1] != 0 {
		t.Error("last byte should be a zero")
	}
}

func TestHammingDistance(t *testing.T) {
	dist, _ := HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if dist != 37 {
		t.Fail()
	}
}
