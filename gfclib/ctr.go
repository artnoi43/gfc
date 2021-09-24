package gfclib

// This file provides AES256-CTR encryption for gfc.
// CTR converts a block cipher into a stream cipher by
// repeatedly encrypting an incrementing counter and
// xoring the resulting stream of data with the input.
// In gfc, this mode does not authenticate decrypted message
// so I recommend you use GCM (default mode for gfc).
// See https://golang.org/src/crypto/cipher/ctr.go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func CTR_encrypt(rbuf *bytes.Buffer, aesKey []byte) *bytes.Buffer {

	key, salt := getKeySalt(aesKey, nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, block.BlockSize())
	rand.Read(iv)

	stream := cipher.NewCTR(block, iv)
	obuf := new(bytes.Buffer)
	buf := make([]byte, 1024)
	for {
		n, err := rbuf.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			obuf.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
	}

	obuf.Write(append(iv, salt...))
	return obuf
}

func CTR_decrypt(rbuf *bytes.Buffer, aesKey []byte) *bytes.Buffer {

	data := rbuf.Bytes()
	lenData := len(data)

	salt := data[lenData-lenSalt:]
	key, _ := getKeySalt(aesKey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	lenIV := block.BlockSize()
	iv := make([]byte, lenIV)
	iv = data[lenData-lenIV-lenSalt : lenData-lenSalt]
	lenMsg := lenData - lenIV - lenSalt

	stream := cipher.NewCTR(block, iv)
	buf := make([]byte, 1024)
	obuf := new(bytes.Buffer)
	for {
		n, err := rbuf.Read(buf)
		if n > 0 {
			if n > lenMsg {
				n = lenMsg
			}
			lenMsg -= n
			stream.XORKeyStream(buf, buf[:n])
			obuf.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
	}

	return obuf
}
