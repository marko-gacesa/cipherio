package cipherio

import (
	"fmt"
	"testing"
)

func TestRequiredBlockSize(t *testing.T) {
	const blockSize = 10
	tests := []struct {
		input int
		exp   int
	}{
		{input: 0, exp: 0},
		{input: blockSize, exp: blockSize},
		{input: blockSize - 1, exp: blockSize},
		{input: blockSize + 1, exp: 2 * blockSize},
		{input: 5*blockSize - 1, exp: 5 * blockSize},
		{input: 7*blockSize + 1, exp: 8 * blockSize},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("size=%d,input=%d,exp=%d", blockSize, test.input, test.exp), func(t *testing.T) {
			if want, got := test.exp, RequiredBlockSize(test.input, blockSize); want != got {
				t.Errorf("failed, got=%d want=%d", got, want)
			}
		})
	}
}

func TestFitToBlock(t *testing.T) {
	const blockSize = 10
	tests := []struct {
		size     int
		expected int
	}{
		{size: 0, expected: 0},
		{size: 1, expected: blockSize},
		{size: blockSize, expected: blockSize},
		{size: 2*blockSize - 1, expected: 2 * blockSize},
		{size: 3*blockSize + 1, expected: 4 * blockSize},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("size=%d,exp=%d", test.size, test.expected), func(t *testing.T) {
			result := FitToBlock(make([]byte, test.size), blockSize)
			if want, got := test.expected, len(result); want != got {
				t.Errorf("failed. expected result=%d, got=%d", want, got)
				return
			}
		})
	}
}
