package cipherio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"
)

func TestBlockModeWriter(t *testing.T) {
	const testKey = "the_16_bytes_key"
	tests := []struct {
		name   string
		chunks []string
		expPad int
	}{
		{
			name:   "empty",
			chunks: []string{},
			expPad: 0,
		},
		{
			name:   "buffer-len-minus-one",
			chunks: []string{strings.Repeat("1", aes.BlockSize*blockModeWriterBufferSizeMultiplier-1)},
			expPad: 1,
		},
		{
			name:   "buffer-len",
			chunks: []string{strings.Repeat("1", aes.BlockSize*blockModeWriterBufferSizeMultiplier)},
			expPad: 0,
		},
		{
			name:   "buffer-len-plus-one",
			chunks: []string{strings.Repeat("1", aes.BlockSize*blockModeWriterBufferSizeMultiplier+1)},
			expPad: aes.BlockSize - 1,
		},
		{
			name: "irregular-chunks",
			chunks: []string{
				strings.Repeat("1", aes.BlockSize*blockModeWriterBufferSizeMultiplier-7),
				strings.Repeat("2", aes.BlockSize*blockModeWriterBufferSizeMultiplier-13),
				strings.Repeat("3", 4),
				strings.Repeat("4", aes.BlockSize*blockModeWriterBufferSizeMultiplier),
			},
			expPad: (7 + 13 + (aes.BlockSize - 4)) % aes.BlockSize,
		},
		{
			name: "one-big-chunk",
			chunks: []string{
				strings.Repeat("1", aes.BlockSize*blockModeWriterBufferSizeMultiplier*4+13),
			},
			expPad: aes.BlockSize - 13,
		},
	}

	block, _ := aes.NewCipher([]byte(testKey))
	iv := RandIV(block)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encrypter := cipher.NewCBCEncrypter(block, iv)
			decrypter := cipher.NewCBCDecrypter(block, iv)

			var err error

			buffer := bytes.NewBuffer(nil)
			expectedBuilder := &strings.Builder{}

			w := NewBlockModeWriter(encrypter, buffer)
			for _, chunk := range test.chunks {
				var n int

				n, err = w.Write([]byte(chunk))
				if err != nil {
					t.Errorf("failed to write: %s", err)
					return
				}
				if n != len(chunk) {
					t.Errorf("returned size mismatch: expected=%d got=%d", len(chunk), n)
				}

				expectedBuilder.WriteString(chunk)
			}
			err = w.Close()
			if err != nil {
				t.Errorf("failed to close: %s", err)
				return
			}

			encrypted := buffer.Bytes()
			expected := expectedBuilder.String()

			decrypter.CryptBlocks(encrypted, encrypted)

			decrypted := string(encrypted[:len(expected)])

			if expected != decrypted {
				t.Errorf("decrypted message mismatch: expected=%s, got=%s", expected, decrypted)
				return
			}

			if padLen := w.Pad(); test.expPad != padLen {
				t.Errorf("pad length mismatch: expected=%d, got=%d", test.expPad, padLen)
				return
			}
		})
	}
}
