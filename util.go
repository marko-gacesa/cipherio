package cipherio

import (
	"crypto/cipher"
	"crypto/rand"
)

// RequiredBlockSize returns size required to store dataSize bytes.
// The returned size will be divisible by blockSize.
func RequiredBlockSize(dataSize, blockSize int) int {
	if dataSize <= 0 {
		return 0
	}
	return ((dataSize-1)/blockSize + 1) * blockSize
}

// FitToBlock fits the provided data to a blockSize memory chunk.
func FitToBlock(data []byte, blockSize int) []byte {
	l := len(data)
	if l == 0 {
		return nil
	}

	size := RequiredBlockSize(l, blockSize)
	if l == size {
		return data
	}

	a := make([]byte, size)
	copy(a, data)

	return a
}

// RandIV returns block-sized slice of crypto-random bytes that can be used
// as initialization vector for the provided cipher.Block.
func RandIV(block cipher.Block) []byte {
	iv := make([]byte, block.BlockSize())
	_, err := rand.Read(iv)
	if err != nil {
		panic(err)
	}

	return iv
}
