package crypto

import (
	"testing"
)

func TestAesOracle(t *testing.T) {
	plaintext := []byte("Like your mother and your father too. All grown up but they're just like you.")

	encrypter, actualMode, err := RandomAesMode()
	if err != nil {
		t.Error(err)
	}
	guessedMode := AesOracle(plaintext, encrypter)
	if actualMode != guessedMode {
		t.Errorf("expected %s, got %s", actualMode, guessedMode)
	}
}
