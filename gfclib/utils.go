package gfclib

// Non-encryption names are defined in this file
// It contains mostly I/O related structs and functions

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
)

var (
	b64Encoding = base64.StdEncoding
	err         error
)

type File struct {
	fp   *os.File
	Name string
}

func (F *File) open() error {
	if F.fp, err = os.Open(F.Name); err != nil {
		return err
	}
	return nil
}

func (F *File) create() error {
	if F.fp, err = os.Create(F.Name); err != nil {
		return err
	}
	return nil
}

func (F *File) ReadFile() (rbuf *bytes.Buffer) {
	if err := F.open(); err != nil {
		os.Stderr.Write([]byte(
			"Could not open file for reading: " + F.Name + "\n"))
		os.Exit(1)
	}

	defer F.fp.Close()
	rbuf = new(bytes.Buffer)
	rbuf.ReadFrom(F.fp)
	return rbuf
}

func (F *File) WriteFile(obuf *bytes.Buffer) {
	if err := F.create(); err != nil {
		os.Stderr.Write([]byte(
			"Could not open file for writing: " + F.Name + "\n"))
		os.Exit(1)
	}

	defer F.fp.Close()
	obuf.WriteTo(F.fp)
}

func DecodeInput(encoding int, raw *bytes.Buffer) (decoded *bytes.Buffer) {
	var decoder io.Reader
	switch encoding {
	case 0:
		decoder = base64.NewDecoder(b64Encoding, raw)
	case 1:
		decoder = hex.NewDecoder(raw)
	default:
		os.Stderr.Write([]byte("Unknown decoding\n"))
		os.Exit(2)
	}
	decoded = new(bytes.Buffer)
	decoded.ReadFrom(decoder)
	return decoded
}

func EncodeOutput(encoding int, raw *bytes.Buffer) (encoded *bytes.Buffer) {
	// Need empty interface because base64.NewEncoder returns io.WriteCloser,
	// while hex.NewEncoder returns io.Writer
	var encoder interface{}
	encoded = new(bytes.Buffer)
	switch encoding {
	case 0:
		encoder = base64.NewEncoder(b64Encoding, encoded)
		// Base64 encodings operate in 4-byte blocks; when finished writing,
		// the caller must Close the returned encoder to flush any partially written blocks.
		defer encoder.(io.WriteCloser).Close()
	case 1:
		encoder = hex.NewEncoder(encoded)
	default:
		os.Stderr.Write([]byte("Unknown encoding\n"))
		os.Exit(2)
	}
	raw.WriteTo(encoder.(io.Writer))
	return encoded
}
