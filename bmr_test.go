package cipherio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"testing"
)

func TestBlockModeReader(t *testing.T) {
	const message = "a-short-message-with-several-words-that-is-exactly-64-bytes-long"
	const testKey = "16-byte-long-key"

	block, _ := aes.NewCipher([]byte(testKey))
	iv := RandIV(block)

	type attempt struct {
		size    int
		expN    int
		expErr  error
		expData string
	}

	tests := []struct {
		name     string
		message  string
		attempts []attempt
	}{
		{
			name:    "empty",
			message: "",
			attempts: []attempt{
				{size: 64, expN: 0, expErr: io.EOF, expData: ""},
			},
		},
		{
			name:    "all-at-once",
			message: message,
			attempts: []attempt{
				{size: 64, expN: 64, expErr: nil, expData: message},
				{size: 64, expN: 0, expErr: io.EOF, expData: ""},
				{size: 64, expN: 0, expErr: io.EOF, expData: ""}, // a repeated attempt
			},
		},
		{
			name:    "in-block-sized-chunks",
			message: message,
			attempts: []attempt{
				{size: 16, expN: 16, expErr: nil, expData: message[:16]},
				{size: 16, expN: 16, expErr: nil, expData: message[16:32]},
				{size: 16, expN: 16, expErr: nil, expData: message[32:48]},
				{size: 16, expN: 16, expErr: nil, expData: message[48:]},
				{size: 16, expN: 0, expErr: io.EOF, expData: ""},
			},
		},
		{
			name:    "in-irregular-sized-chunks",
			message: message,
			attempts: []attempt{
				{size: 30, expN: 16, expErr: nil, expData: message[:16]},   // read 30, returned 16, buffered 14
				{size: 40, expN: 32, expErr: nil, expData: message[16:48]}, // read 26 (=40-14), returned 32, buffered 8
				{size: 20, expN: 16, expErr: nil, expData: message[48:]},   // tried to read 12 (=20-8), but got 8, returned 16, buffered 0
				{size: 40, expN: 0, expErr: io.EOF, expData: ""},
			},
		},
		{
			name:    "buffer-too-small",
			message: message,
			attempts: []attempt{
				{size: 15, expN: 0, expErr: io.ErrShortBuffer, expData: ""},
			},
		},
		{
			name:    "non-block-sized",
			message: "this-message-is-not-blocked-sized-and-should-produce-an-error",
			attempts: []attempt{
				{size: 40, expN: 32, expErr: nil, expData: "this-message-is-not-blocked-size"},
				{size: 40, expN: 16, expErr: nil, expData: "d-and-should-pro"},
				{size: 40, expN: 0, expErr: io.ErrUnexpectedEOF, expData: ""},
				{size: 40, expN: 0, expErr: io.ErrUnexpectedEOF, expData: ""}, // a repeated attempt
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encrypter := cipher.NewCBCEncrypter(block, iv)
			decrypter := cipher.NewCBCDecrypter(block, iv)

			m := make([]byte, RequiredBlockSize(len(test.message), aes.BlockSize))
			copy(m, test.message)
			encrypter.CryptBlocks(m, m)

			b := NewBlockModeReader(decrypter, bytes.NewReader(m[:len(test.message)]))

			for i, a := range test.attempts {
				data := make([]byte, a.size)
				n, err := b.Read(data)
				if n != a.expN || err != a.expErr || string(data[:n]) != a.expData {
					t.Errorf("failed [attepmt=%d]: expected=[n=%d,err=%v,data=%s] got=[n=%d,err=%v,data=%s]",
						i, a.expN, a.expErr, a.expData, n, err, data[:n])
				}
			}
		})
	}
}
