package blocks

import (
	"testing"
)

func TestTranspose(t *testing.T) {
	var empty [][]byte

	// An empty slice should fail
	_, err := Transpose(empty)
	if err == nil {
		t.Fail()
	}

	blocks := make([][]byte, 2)
	for i := range blocks {
		blocks[i] = []byte{1, 2}
	}

	transposed, err := Transpose(blocks)
	if err != nil {
		t.Fail()
	}
	if len(transposed) != len(blocks[0]) {
		t.Fail()
	}
	if len(transposed[0]) != len(blocks) {
		t.Fail()
	}
	if transposed[0][0] != 1 {
		t.Fail()
	}
	if transposed[1][1] != 2 {
		t.Fail()
	}
}
