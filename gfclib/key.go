package gfclib

// key.go is for encryption key derivation.
// This file defines KeyFile struct and its methods,

import (
	"crypto/rand"
	"crypto/sha256"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	rounds     int = 1 << 20 // PBKDF2 rounds
	lenSalt    int = 32
	lenKeyFile int = 32
)

type KeyFile struct {
	File
}

func (F *KeyFile) ReadKey() (keyContent []byte) {
	if err := F.open(); err != nil {
		os.Stderr.Write([]byte("Could not open file for reading: " + (F.Name) + "\n"))
		os.Exit(1)
	}

	defer F.fp.Close()

	keyContent, err = os.ReadFile(F.Name)
	if err != nil {
		os.Stderr.Write([]byte("Could not read file to []byte\n"))
		os.Exit(2)
	}
	return keyContent
}

func getPass() []byte {
	os.Stdout.Write([]byte("Passphrase (will not echo)\n"))
	passphrase, _ := term.ReadPassword(0)
	return passphrase
}

/* Derive 256-bit key and salt using PBKDF2 */
func hashKeySalt(passphrase []byte, salt []byte) ([]byte, []byte) {

	if salt == nil {
		salt = make([]byte, lenSalt)
		rand.Read(salt)
	}
	return pbkdf2.Key(passphrase, salt, rounds, lenSalt, sha256.New), salt
}

func getKeySalt(aesKey []byte, salt []byte) ([]byte, []byte) {
	if aesKey == nil {
		/* Passphrase */
		key, salt := hashKeySalt(getPass(), salt)
		return key, salt

	} else {
		/* Keyfile */
		switch len(aesKey) {
		case lenKeyFile:
			if salt == nil {
				salt = make([]byte, lenSalt)
				rand.Read(salt)
			}
		default:
			os.Stderr.Write([]byte("Invalid key length\n"))
			os.Exit(1)
		}
		return aesKey, salt
	}
}
