package utils

import (
	"io/ioutil"
	"math"
	"strings"
)

var ENGLISH_FREQUENCIES = map[string]float64{
	"E": .1202,
	"T": .0910,
	"A": .0812,
	"O": .0768,
	"I": .0731,
	"N": .0695,
	"S": .0628,
	"R": .0602,
	"H": .0592,
	"D": .0432,
	"L": .0398,
	"U": .0288,
	"C": .0271,
	"M": .0261,
	"F": .0230,
	"Y": .0211,
	"W": .0209,
	"G": .0203,
	"P": .0182,
	"B": .0149,
	"V": .0111,
	"K": .0069,
	"X": .0017,
	"Q": .0011,
	"J": .0010,
	"Z": .0007,
}

// EnglishScore returns a numerical representation of the likelihood
// that a given text is written in English. A higher score correlates
// with a higher likelihood.
func EnglishScore(s string) float64 {
	if len(s) < 1 {
		return 0.0
	}

	s = strings.ToUpper(s)
	var sum, score float64
	frequencies := map[string]float64{
		"E": 0,
		"T": 0,
		"A": 0,
		"O": 0,
		"I": 0,
		"N": 0,
		"S": 0,
		"R": 0,
		"H": 0,
		"D": 0,
		"L": 0,
		"U": 0,
		"C": 0,
		"M": 0,
		"F": 0,
		"Y": 0,
		"W": 0,
		"G": 0,
		"P": 0,
		"B": 0,
		"V": 0,
		"K": 0,
		"X": 0,
		"Q": 0,
		"J": 0,
		"Z": 0,
	}

	for letter := range frequencies {
		count := float64(strings.Count(s, letter))
		frequencies[letter] = count
		sum += count
	}
	for letter := range frequencies {
		frequencies[letter] /= sum
		score += math.Sqrt(frequencies[letter] * ENGLISH_FREQUENCIES[letter])
	}
	return score
}

// ReadAndStripFile reads a file with ioutil and returns a version of
// the bytes read from the file with all ASCII control characters
// stripped.
func ReadAndStripFile(filename string) ([]byte, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	stripped := Strip(b)

	return stripped, nil
}

// Strip removes all ASCII control characters (< 32 || == 127)
func Strip(b []byte) []byte {
	if len(b) < 1 {
		return b
	}

	keep := make([]byte, len(b))
	n := 0 // Number of bytes to keep

	for i := 0; i < len(b); i++ {
		temp := b[i]
		if temp >= 32 && temp != 127 {
			keep[n] = temp
			n++
		}
	}
	return keep[:n]
}
