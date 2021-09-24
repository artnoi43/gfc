package gfclib

// This file provides default encryption mode for gfc.
// This mode is chosen because it has message authentication
// built-in and because it is generally faster.
// For very large files, you may want to use CTR.
// See https://golang.org/src/crypto/cipher/gcm.go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

const (
	lenNonce int = 12 // use 96-bit nonce
)

func GCM_encrypt(rbuf *bytes.Buffer, aesKey []byte) *bytes.Buffer {
	key, salt := getKeySalt(aesKey, nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, lenNonce)
	rand.Read(nonce)

	// Use buffer, so we can convert to hex easily
	// if needed so with io.Writer interface.
	// To encrypt, we use Seal(dst, nonce, plaintext, data []byte) []byte

	obuf := new(bytes.Buffer)
	obuf.Write(gcm.Seal(nil, nonce, rbuf.Bytes(), nil))
	obuf.Write(append(nonce, salt...))

	// salt is appended last, hence output format is
	// "ciphertext + nonce + salt".
	// This allow us to easily extract salt
	// for key derivation later when decrypting.

	return obuf
}

func GCM_decrypt(rbuf *bytes.Buffer, aesKey []byte) *bytes.Buffer {

	data := rbuf.Bytes()
	lenData := len(data)

	salt := data[lenData-lenSalt:]
	key, _ := getKeySalt(aesKey, salt)

	nonce := make([]byte, lenNonce)
	nonce = data[lenData-lenNonce-lenSalt : lenData-lenSalt]
	data = data[:lenData-lenNonce-lenSalt]

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	/* To decrypt, we use Open(dst, nonce, ciphertext, data []byte) ([]byte, error) */
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		panic(err)
	}

	return bytes.NewBuffer(plaintext)
}
