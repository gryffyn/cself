package checksum

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"github.com/OneOfOne/xxhash"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"lukechampine.com/blake3"
)

const bufferSize = 65536

// MD5sumReader returns MD5 checksum of content in reader
func MD5sumReader(reader io.Reader) (string, error) {
	return sumReader(md5.New(), reader)
}

// SHA256sumReader returns SHA256 checksum of content in reader
func SHA256sumReader(reader io.Reader) (string, error) {
	return sumReader(sha256.New(), reader)
}

// SHA1sumReader returns SHA-1 checksum of content in reader
func SHA1sumReader(reader io.Reader) (string, error) {
	return sumReader(sha1.New(), reader)
}

// SHA512sumReader returns SHA-512 checksum of content in reader
func SHA512sumReader(reader io.Reader) (string, error) {
	return sumReader(sha512.New(), reader)
}

// SHA3sumReader returns SHA-3 checksum of content in reader
func SHA3sumReader(reader io.Reader) (string, error) {
	return sumReader(sha3.New224(), reader)
}

// Blake512sumReader returns BLAKE2b-512 checksum of content in reader
func Blake512sumReader(reader io.Reader) (string, error) {
	h, _ := blake2b.New512(nil)
	return sumReader(h, reader)
}

// Blake256sumReader returns BLAKE2b-256 checksum of content in reader
func Blake256sumReader(reader io.Reader) (string, error) {
	h, _ := blake2b.New256(nil)
	return sumReader(h, reader)
}

// Blake3256sumReader returns BLAKE3 checksum of content in reader
func Blake3256sumReader(reader io.Reader) (string, error) {
	h := blake3.New(32, nil)
	return sumReader(h, reader)
}

// Blake3512sumReader returns BLAKE3 checksum of content in reader
func Blake3512sumReader(reader io.Reader) (string, error) {
	h := blake3.New(64, nil)
	return sumReader(h, reader)
}

// Xxh32sumReader returns XXH32 checksum of content in reader
func Xxh32sumReader(reader io.Reader) (string, error) {
	return sumReader(xxhash.NewHash32(), reader)
}

// Xxh64sumReader returns XXH64 checksum of content in reader
func Xxh64sumReader(reader io.Reader) (string, error) {
	return sumReader(xxhash.NewHash64(), reader)
}

// sumReader calculates the hash based on a provided hash provider
func sumReader(hashAlgorithm hash.Hash, reader io.Reader) (string, error) {
	buf := make([]byte, bufferSize)
	for {
		switch n, err := reader.Read(buf); err {
		case nil:
			hashAlgorithm.Write(buf[:n])
		case io.EOF:
			return fmt.Sprintf("%x", hashAlgorithm.Sum(nil)), nil
		default:
			return "", err
		}
	}
}
