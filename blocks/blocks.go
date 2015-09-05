package blocks

import "errors"

func Transpose(b [][]byte) ([][]byte, error) {
	if b == nil {
		return nil, errors.New("cannot transpose empty [][]")
	}

	transposed := make([][]byte, len(b[0]))
	for i := range transposed {
		temp := make([]byte, len(b))
		for k := range b {
			temp[k] = b[k][i]
		}
		transposed[i] = temp
	}
	return transposed, nil
}
