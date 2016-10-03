package utils

import (
	"testing"
)

func TestEnglishScore(t *testing.T) {
	eng := "This is an English language sentence and should be scored highly compared to other non-English-like strings."
	notEng := "<^D?Fs^G@hLU^X"

	if EnglishScore(eng) < EnglishScore(notEng) {
		t.Fail()
	}

	score := EnglishScore("")
	if score != 0.0 {
		t.Errorf("expected %f, got %f", 0.0, score)
	}
}

func TestStrip(t *testing.T) {
	controlChars := []byte{0, 127, 31}
	ok := []byte("Don't strip any of these")

	stripped := Strip(controlChars)
	if len(stripped) != 0 {
		t.Errorf("expected an empty string, got %b", stripped)
	}

	stripped = Strip(ok)
	if len(stripped) != len(ok) {
		t.Errorf("expected %s, got %s", string(ok), string(stripped))
	}
}
