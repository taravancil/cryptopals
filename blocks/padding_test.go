package blocks

import (
	"testing"
)

func TestPkcs7(t *testing.T) {
	b := []byte("ICE ICE BABY")
	expected := []byte("ICE ICE BABY\x04\x04\x04\x04")

	_, err := Pkcs7(b, 0)
	if err == nil {
		t.Error("should fail given an invalid blocksize")
	}

	padded, err := Pkcs7(b, 16)
	if err != nil {
		t.Error(err)
	}
	if len(padded) != len(expected) {
		t.Error("expected %s, got %s", string(expected), string(padded))
	}
}

func TestStripIfValidPkcs7(t *testing.T) {
	invalid := []byte("ICE ICE BABY\x05\x05\x05\x05")
	empty := []byte("")
	valid := []byte("ICE ICE BABY\x04\x04\x04\x04")

	// A block with invalid padding should yield an unstripped block
	same, _ := StripIfValidPkcs7(invalid)
	if string(same) != string(invalid) {
		t.Errorf("%s != %s", string(same), string(invalid))
	}

	_, err := StripIfValidPkcs7(empty)
	if err.Error() != "empty slice" {
		t.Error("should fail given an empty slice")
	}

	stripped, err := StripIfValidPkcs7(valid)
	if err != nil {
		t.Error(err)
	}
	if string(stripped) != "ICE ICE BABY" {
		t.Errorf("expcted %s, got %s", "ICE ICE BABY", string(stripped))
	}
}

func TestValidPkcs7(t *testing.T) {
	valid, n, err := ValidPkcs7([]byte("ICE ICE BABY\x04\x04\x04\x04"))
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Fail()
	}
	if n != 4 {
		t.Fail()
	}

	_, _, err = ValidPkcs7([]byte("ICE ICE BABY\x05\x05\x05\x05"))
	// TODO: this still fails, but with the "padding bytes not the same" error.
	// Figure out how to not grab extra byte and fail with "wrong # of pads" error.
	if err == nil {
		t.Fail()
	}

	_, _, err = ValidPkcs7([]byte("ICE ICE BABY\x01\x02\x03\x04"))
	if err.Error() != "invalid padding: not all padding bytes the same" {
		t.Fail()
	}

	_, _, err = ValidPkcs7([]byte("ICE ICE BABY"))
	if err.Error() != "invalid padding: len(ICE ICE BABY) is not a multiple of 16" {
		t.Fail()
	}
}
