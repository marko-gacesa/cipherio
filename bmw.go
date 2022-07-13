package cipherio

import (
	"crypto/cipher"
	"errors"
	"io"
)

const blockModeWriterBufferSizeMultiplier = 64 // if used with AES, it will hold 64 blocks, 1024 bytes

// NewBlockModeWriter creates a new BlockModeWriter. The provided encrypter is expected
// to be a cipher.BlockMode created with a call to cipher.NewCBCEncrypter. Data written to
// to the writer will be sent as encrypted data to the writer passed as a parameter.
func NewBlockModeWriter(encrypter cipher.BlockMode, output io.Writer) *BlockModeWriter {
	return &BlockModeWriter{
		blockMode: encrypter,
		output:    output,
		buffer:    make([]byte, encrypter.BlockSize()*blockModeWriterBufferSizeMultiplier),
	}
}

// BlockModeWriter is used for writing encrypted messages to the underlying io.Writer.
// BlockModeWriter implements io.WriteCloser interface.
type BlockModeWriter struct {
	blockMode cipher.BlockMode
	output    io.Writer
	buffer    []byte
	bufferLen int
	err       error
	closed    bool
	padLen    int
}

// Write encrypts messages and sends them to the underlying io.Writer.
// It will not modify the slice data.
func (w *BlockModeWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	if w.closed {
		return 0, errors.New("writer closed")
	}

	var written int

	buffer := w.buffer
	size := len(buffer)

	for d := data; len(d) != 0; {
		if n := size - w.bufferLen; len(d) > n {
			copy(buffer[w.bufferLen:], d[:n])
			written += n
			d = d[n:]
			w.bufferLen = size
		} else {
			copy(buffer[w.bufferLen:], d)
			written += len(d)
			w.bufferLen = w.bufferLen + len(d)
			d = nil
		}

		if w.bufferLen == size {
			w.bufferLen = 0

			w.blockMode.CryptBlocks(buffer, buffer)

			_, err := w.output.Write(buffer)
			if err != nil {
				w.err = err
				return written, err
			}
		}
	}

	return written, nil
}

// Close closes the BlockModeWriter by flushing any unwritten data to the underlying
// io.Writer. It doesn't close the underlying io.Writer.
func (w *BlockModeWriter) Close() error {
	if w.closed || w.err != nil {
		return w.err
	}

	w.closed = true

	if w.bufferLen == 0 {
		return nil
	}

	size := RequiredBlockSize(w.bufferLen, w.blockMode.BlockSize())
	buffer := w.buffer[:size]
	for i := w.bufferLen; i < size; i++ {
		buffer[i] = 0
	}

	w.padLen = size - w.bufferLen

	w.blockMode.CryptBlocks(buffer, buffer)

	_, w.err = w.output.Write(buffer) // should return an error if returned size is different than the buffer size

	return w.err
}

// Pad returns number of additional bytes written to the underlying writer
// that are not part of the message. If data sent to the writer isn't divisible
// by block size, it is extended by zeroes so that the encrypter can finish.
// The number returned is always from 0 to BlockSize-1.
// Pad has to be called after the BlockModeWriter is closed.
func (w *BlockModeWriter) Pad() int {
	if w.closed {
		return w.padLen
	}
	return -1
}

// BlockSize returns block size of the cipher.BlockMode provided during creation of the BlockModeWriter.
func (w *BlockModeWriter) BlockSize() int {
	return w.blockMode.BlockSize()
}
