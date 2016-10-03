package bytes

import (
	"encoding/hex"
	"testing"
)

func TestXor(t *testing.T) {
	b := []byte("12345678")
	mismatch := []byte("1234567")
	empty := []byte("")

	result, err := Xor(b, b)
	if err != nil {
		t.Fail()
	}
	for _, val := range result {
		if val != 0 {
			t.Fail()
		}
	}

	_, err = Xor(b, mismatch)
	if err.Error() != "length mismatch" {
		t.Error("Xor should fail on length mismatch")
	}

	_, err = Xor(b, empty)
	if err.Error() != "empty slice" {
		t.Error("Xor should fail on empty slice")
	}
}

func TestXorRepeatingKey(t *testing.T) {
	b, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expected := []byte{99, 79, 79, 75, 73, 78, 71, 0, 109, 99, 7, 83, 0, 76, 73, 75, 69, 0, 65, 0, 80, 79, 85, 78, 68, 0, 79, 70, 0, 66, 65, 67, 79, 78}
	empty := []byte("")
	key := []byte("x")

	// Test single-byte key
	xored, err := XorRepeatingKey(b, key)
	if err != nil {
		t.Error(err)
	}
	if string(xored) != string(expected) {
		t.Fail()
	}

	// Test multi-byte key
	b = []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key = []byte("ICE")
	expectedStr := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	xored, err = XorRepeatingKey(b, key)
	if err != nil {
		t.Fail()
	}
	if hex.EncodeToString(xored) != expectedStr {
		t.Fail()
	}
	_, err = XorRepeatingKey(b, empty)
	if err.Error() != "invalid key" {
		t.Error("should fail given an empty key")
	}
	_, err = XorRepeatingKey(empty, key)
	if err.Error() != "cannot XOR an empty slice" {
		t.Error("should fail on empty slice")
	}
}
