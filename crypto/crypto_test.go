package crypto

import (
	"testing"

	"github.com/taravancil/cryptopals/bytes"
)

func TestFindKeysizes(t *testing.T) {
	input := []byte("And you're going to do it all anew. Better run for the hills.")
	tooShort := []byte("Too short")
	empty := []byte("")
	key := []byte("YELLOW")
	size := len(key)
	n := 3

	// Invalid inputs
	encrypted, _ := bytes.XorRepeatingKey(tooShort, key)
	_, err := FindKeysizes(encrypted, n, 3, 10)
	if err.Error() != "input not long enough for analysis" {
		t.Error("should fail if ciphertext is not 4x as long as maxSize")
	}
	_, err = FindKeysizes(empty, n, 3, 10)
	if err.Error() != "empty input ciphertext" {
		t.Error("should fail given a nil ciphertext")
	}
	_, err = FindKeysizes(encrypted, n, 10, 3)
	if err.Error() != "minSize > maxSize" {
		t.Error("should fail if minSize > maxSize")
	}
	_, err = FindKeysizes(encrypted, 0, 3, 10)
	if err.Error() != "n must be > 0" {
		t.Error("should fail if n == 0")
	}

	// Valid input
	encrypted, err = bytes.XorRepeatingKey(input, key)
	keysizes, err := FindKeysizes(encrypted, n, 3, 10)
	if err != nil {
		t.Error(err)
	}
	if len(keysizes) != n {
		t.Error("expected %d keysizes, got %d", n, len(keysizes))
	}

	guessed := false
	for i := range keysizes {
		if keysizes[i] == size {
			guessed = true
		}
	}
	if !guessed {
		t.Error("guessed wrong key length")
	}
}
