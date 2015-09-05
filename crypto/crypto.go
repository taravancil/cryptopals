package crypto

import (
	"errors"

	"github.com/taravancil/cryptopals/blocks"
	"github.com/taravancil/cryptopals/bytes"
	"github.com/taravancil/cryptopals/utils"
)

func BreakXorRepeating(ciphertext []byte, keysizes []int) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	if len(keysizes) == 0 {
		return nil, errors.New("no keysizes given")
	}

	var bestScore = 0.0
	var plaintext []byte

	for _, size := range keysizes {
		split, _ := bytes.SplitIntoBlocks(ciphertext, size)
		transposed, err := blocks.Transpose(split)
		if err != nil {
			return nil, err
		}

		key := make([]byte, size)
		for i, block := range transposed {
			popular, _ := bytes.Popular(block, 1)
			key[i] = popular[0]
		}

		decrypted, _ := bytes.XorRepeatingKey(ciphertext, key)
		score := utils.EnglishScore(string(decrypted))

		if score > bestScore {
			plaintext = decrypted
			bestScore = score
		}
	}
	return plaintext, nil
}

// FindKeysizes returns a slice of n possible keysizes in a given range
func FindKeysizes(b []byte, n, minSize, maxSize int) ([]int, error) {
	if len(b) == 0 {
		return nil, errors.New("empty input ciphertext")
	}
	if minSize > maxSize {
		return nil, errors.New("minSize > maxSize")
	}
	if n == 0 {
		return nil, errors.New("n must be > 0")
	}

	if maxSize*4 > len(b) {
		return nil, errors.New("input not long enough for analysis")
	}

	// Initialize the set of minDistances with a large value
	minDist := make([]float64, n)
	for i := range minDist {
		minDist[i] = 1000.00
	}
	keysizes := make([]int, n)

	for size := minSize; size <= maxSize; size++ {
		// Get 4 blocks
		blocks := make([][]byte, 4)
		for i := 0; i < 4; i++ {
			blocks[i] = b[size*i : size*(i+1)]
		}

		// Calculate Hamming distance for each pair of blocks
		var sum int
		pairs := [][]int{{0, 1}, {0, 2}, {0, 3}, {1, 2}, {1, 3}, {2, 3}}

		for i := range pairs {
			temp, err := bytes.HammingDistance(blocks[pairs[i][0]], blocks[pairs[i][1]])
			if err != nil {
				return nil, err
			}
			sum += temp
		}

		// Normalize Hamming distances: avg/keysize
		normalizedDist := (float64(sum) / float64(len(pairs))) / float64(size)

		// If the normalized Hamming distance for the guessed keysize is
		// smaller than any of the values in minDist, add the keysize and distance
		// to the slice of possible keysizes
		for i := 0; i < n; i++ {
			if normalizedDist < minDist[i] {
				// If this isn't the last iteration of the loop, push the stored
				// keysize and minDist to the next position
				if n-i != 1 {
					keysizes[i+1] = keysizes[i]
					minDist[i+1] = minDist[i]
				}
				// If it is the last iteration, just replace the values
				keysizes[i] = size
				minDist[i] = normalizedDist
				break
			}
		}
	}
	return keysizes, nil
}
