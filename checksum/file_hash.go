// Package checksum computes checksums, like MD5 or SHA256, for large files
package checksum

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"

	"github.com/OneOfOne/xxhash"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"lukechampine.com/blake3"
)

// MD5sum returns MD5 checksum of filename
// bytes:
func MD5sum(filename string) (string, error) {
	return sum(md5.New(), filename)
}

// SHA1sum returns SHA-1 checksum of filename
// bytes:
func SHA1sum(filename string) (string, error) {
	return sum(sha1.New(), filename)
}

// SHA2sum returns SHA-2 checksum of filename
// bytes: 224, 256, 384, 512
func SHA2sum(filename string, bytes int) (string, error) {
	var h hash.Hash
	switch bytes {
	case 0:
		h = sha256.New()
	case 224:
		h = sha256.New224()
	case 256:
		h = sha256.New()
	case 384:
		h = sha512.New384()
	case 512:
		h = sha512.New()
	default:
		return "", fmt.Errorf("invalid number of bytes: %d", bytes)
	}
	return sum(h, filename)
}

// SHA3sum returns SHA-3 checksum of filename
// bytes: 224, 256, 384, 512
func SHA3sum(filename string, bytes int) (string, error) {
	var h hash.Hash
	switch bytes {
	case 0:
		h = sha3.New224()
	case 224:
		h = sha3.New224()
	case 256:
		h = sha3.New256()
	case 384:
		h = sha3.New384()
	case 512:
		h = sha3.New512()
	default:
		return "", fmt.Errorf("invalid number of bytes: %d", bytes)
	}
	return sum(h, filename)
}

// BLAKE2Bsum returns BLAKE2b checksum of filename
// bytes: 256, 384, 512
func BLAKE2Bsum(filename string, bytes int) (string, error) {
	var h hash.Hash
	switch bytes {
	case 0:
		h, _ = blake2b.New256(nil)
	case 256:
		h, _ = blake2b.New256(nil)
	case 384:
		h, _ = blake2b.New384(nil)
	case 512:
		h, _ = blake2b.New512(nil)
	default:
		return "", fmt.Errorf("invalid number of bytes: %d", bytes)
	}
	return sum(h, filename)
}

// BLAKE3sum returns BLAKE3 checksum of filename
// bytes: 256, 384, 512
func BLAKE3sum(filename string, bytes int) (string, error) {
	var h hash.Hash
	switch bytes {
	case 0:
		h = blake3.New(32, nil)
	case 256:
		h = blake3.New(32, nil)
	case 384:
		h = blake3.New(48, nil)
	case 512:
		h = blake3.New(64, nil)
	default:
		return "", fmt.Errorf("invalid number of bytes: %d", bytes)
	}
	return sum(h, filename)
}

// XXHsum returns XXH(32/64) checksum of filename
// bytes: 32, 64
func XXHsum(filename string, bytes int) (string, error) {
	var h hash.Hash
	switch bytes {
	case 0:
		h = xxhash.NewHash32()
	case 32:
		h = xxhash.NewHash32()
	case 64:
		h = xxhash.NewHash64()
	default:
		return "", fmt.Errorf("invalid number of bytes: %d", bytes)
	}
	return sum(h, filename)
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
