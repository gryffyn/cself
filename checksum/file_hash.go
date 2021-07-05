// Package checksum computes checksums, like MD5 or SHA256, for large files
package checksum

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"os"

	"github.com/OneOfOne/xxhash"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"lukechampine.com/blake3"
)

// MD5sum returns MD5 checksum of filename
func MD5sum(filename string) (string, error) {
	return sum(md5.New(), filename)
}

// SHA256sum returns SHA-256 checksum of filename
func SHA256sum(filename string) (string, error) {
	return sum(sha256.New(), filename)
}

// SHA1sum returns SHA-1 checksum of filename
func SHA1sum(filename string) (string, error) {
	return sum(sha1.New(), filename)
}

// SHA512sum returns SHA-512 checksum of filename
func SHA512sum(filename string) (string, error) {
	return sum(sha512.New(), filename)
}

// SHA3sum returns SHA-3 checksum of filename
func SHA3sum(filename string) (string, error) {
	return sum(sha3.New224(), filename)
}

// Blake512sum returns BLAKE2b-512 checksum of filename
func Blake512sum(filename string) (string, error) {
	h, _ := blake2b.New512(nil)
	return sum(h, filename)
}

// Blake256sum returns BLAKE2b-256 checksum of filename
func Blake256sum(filename string) (string, error) {
	h, _ := blake2b.New256(nil)
	return sum(h, filename)
}

// Blake3256sum returns BLAKE3 checksum of filename
func Blake3256sum(filename string) (string, error) {
	h := blake3.New(32, nil)
	return sum(h, filename)
}

// Blake3512sum returns BLAKE3 checksum of filename
func Blake3512sum(filename string) (string, error) {
	h := blake3.New(64, nil)
	return sum(h, filename)
}

// Xxh32sum returns XXH32 checksum of filename
func Xxh32sum(filename string) (string, error) {
	return sum(xxhash.NewHash32(), filename)
}

// Xxh64sum returns XXH64 checksum of filename
func Xxh64sum(filename string) (string, error) {
	return sum(xxhash.NewHash64(), filename)
}

// sum calculates the hash based on a provided hash provider
func sum(hashAlgorithm hash.Hash, filename string) (string, error) {
	if info, err := os.Stat(filename); err != nil || info.IsDir() {
		return "", err
	}

	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	return sumReader(hashAlgorithm, bufio.NewReader(file))
}
