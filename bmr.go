package cipherio

import (
	"crypto/cipher"
	"io"
)

// NewBlockModeReader creates a new BlockModeReader for decrypting messages from streams.
// The provided decrypter is expected to be a cipher.BlockMode created with a call to
// cipher.NewCBCDecrypter.
func NewBlockModeReader(decrypter cipher.BlockMode, input io.Reader) *BlockModeReader {
	return &BlockModeReader{
		blockMode: decrypter,
		input:     input,
		buffer:    make([]byte, decrypter.BlockSize()),
	}
}

// BlockModeReader is used for reading messages encrypted with cipher.BlockMode.
// BlockModeReader implements io.Reader interface.
type BlockModeReader struct {
	blockMode cipher.BlockMode
	input     io.Reader
	buffer    []byte
	bufferLen int
	err       error
}

// Read reads data from the underlying reader and decrypts it on the fly.
// It assumes that messages are encrypted by cipher.BlockMode.
// The provided buffer must not be smaller than the block size.
// Read will return number of bytes stored into the provided buffer.
// Total number of bytes read from the underlying reader must be divisible by the block size,
// otherwise error io.ErrUnexpectedEOF will be returned.
func (r *BlockModeReader) Read(data []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	blockSize := r.blockMode.BlockSize()
	if len(data) < blockSize {
		return 0, io.ErrShortBuffer
	}

	var read int

	buffer := r.buffer

	copy(data, buffer[:r.bufferLen])

	n, err := r.input.Read(data[r.bufferLen:])

	blockCnt := (r.bufferLen + n) / blockSize
	blockRem := (r.bufferLen + n) % blockSize

	read = blockCnt * blockSize

	copy(buffer, data[read:read+blockRem])
	r.bufferLen = blockRem

	r.blockMode.CryptBlocks(data[:read], data[:read])

	if err != nil && err != io.EOF {
		r.err = err
	} else if err == io.EOF {
		if blockRem > 0 {
			r.err = io.ErrUnexpectedEOF
		} else {
			r.err = io.EOF
		}
	}

	return read, r.err
}

// BlockSize returns block size of the cipher.BlockMode provided during creation of the BlockModeReader.
func (r *BlockModeReader) BlockSize() int {
	return r.blockMode.BlockSize()
}
