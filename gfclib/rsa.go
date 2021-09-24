package gfclib

// This file is used to asymmetrically encrypt AES keys
// so that we can use public key cryptography with long plaintext messages

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"os"
)

var (
	hash = sha512.New()
	salt = rand.Reader
)

func RSA_encrypt(plaintext *bytes.Buffer, pubKey []byte) *bytes.Buffer {
	block, _ := pem.Decode([]byte(pubKey))
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		os.Stderr.Write([]byte("Failed to parse public key\n"))
		panic(err)
	}
	pub := pubInterface.(*rsa.PublicKey)

	ciphertext, err := rsa.EncryptOAEP(hash, salt, pub, plaintext.Bytes(), nil)
	if err != nil {
		os.Stderr.Write([]byte("Failed to encrypt string\n"))
		panic(err)
	}
	return bytes.NewBuffer(ciphertext)
}

func RSA_decrypt(ciphertext *bytes.Buffer, priKey []byte) *bytes.Buffer {
	block, _ := pem.Decode([]byte(priKey))
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		os.Stderr.Write([]byte("Failed to parse private key\n"))
		panic(err)
	}

	plaintext, err := rsa.DecryptOAEP(hash, salt, pri, ciphertext.Bytes(), nil)
	if err != nil {
		os.Stderr.Write([]byte("Failed to decrypt string\n"))
		panic(err)
	}
	return bytes.NewBuffer(plaintext)
}
