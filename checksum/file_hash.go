// Package checksum computes checksums, like MD5 or SHA256, for large files
package checksum

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"os"
	"strings"

	"git.gryffyn.io/gryffyn/go-chksum3"
	"github.com/OneOfOne/xxhash"
	"github.com/sigurn/crc8"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"lukechampine.com/blake3"
)

// MD5sum returns MD5 checksum of filename
// bits: 128
func MD5sum(filename string, _ int, _ string) (string, error) {
	return sum(md5.New(), 128, filename)
}

// SHA1sum returns SHA-1 checksum of filename
// bits: 160
func SHA1sum(filename string, _ int, _ string) (string, error) {
	return sum(sha1.New(), 160, filename)
}

func CRC8Sum(reader io.Reader, _ int, poly string) (string, error) {
	m := map[string]crc8.Params{
		"CDMA2000": crc8.CRC8_CDMA2000,
		"DARC":     crc8.CRC8_DARC,
		"DVB_S2":   crc8.CRC8_DVB_S2,
		"EBU":      crc8.CRC8_EBU,
		"I_CODE":   crc8.CRC8_I_CODE,
		"ITU":      crc8.CRC8_ITU,
		"MAXIM":    crc8.CRC8_MAXIM,
		"ROHC":     crc8.CRC8_ROHC,
		"WCDMA":    crc8.CRC8_WCDMA,
	}
	data, err := io.ReadAll(reader)
	return string(crc8.Checksum(data, crc8.MakeTable(m[strings.ToUpper(poly)]))), err
}

// LESum returns 8 or 32 bit little-endian checksum of content in filename
// bits: 32
func LESum(filename string, bits int, _ string) (string, error) {
	switch bits {
	case 8:
		return sum(chksum3.New8(), 8, filename)
	case 32:
		return sum(chksum3.New32(), 32, filename)
	default:
		return "", errors.New("invalid byte size: must be '8' or '32'")
	}
}

// CRC32sum returns CRC32 checksum of content in filename
// bits: 32
func CRC32sum(filename string, _ int, poly string) (string, error) {
	switch poly {
	case "c":
		return sum(crc32.New(crc32.MakeTable(crc32.Castagnoli)), 32, filename)
	case "k":
		return sum(crc32.New(crc32.MakeTable(crc32.Koopman)), 32, filename)
	default:
		return sum(crc32.NewIEEE(), 32, filename)
	}
}

// CRC64sum returns CRC64 checksum of content in filename
// bits: 64
func CRC64sum(filename string, _ int, poly string) (string, error) {
	switch poly {
	case "e":
		return sum(crc64.New(crc64.MakeTable(crc64.ECMA)), 64, filename)
	default:
		return sum(crc64.New(crc64.MakeTable(crc64.ISO)), 64, filename)
	}
}

// SHA2sum returns SHA-2 checksum of filename
// bits: 224, 256, 384, 512
func SHA2sum(filename string, bits int, _ string) (string, error) {
	var h hash.Hash
	switch bits {
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
		return "", fmt.Errorf("invalid number of bits: %d", bits)
	}
	return sum(h, bits, filename)
}

// SHA3sum returns SHA-3 checksum of filename
// bits: 224, 256, 384, 512
func SHA3sum(filename string, bits int, _ string) (string, error) {
	var h hash.Hash
	switch bits {
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
		return "", fmt.Errorf("invalid number of bits: %d", bits)
	}
	return sum(h, bits, filename)
}

// BLAKE2Bsum returns BLAKE2b checksum of filename
// bits: 256, 384, 512
func BLAKE2Bsum(filename string, bits int, _ string) (string, error) {
	var h hash.Hash
	switch bits {
	case 0:
		h, _ = blake2b.New256(nil)
	case 256:
		h, _ = blake2b.New256(nil)
	case 384:
		h, _ = blake2b.New384(nil)
	case 512:
		h, _ = blake2b.New512(nil)
	default:
		return "", fmt.Errorf("invalid number of bits: %d", bits)
	}
	return sum(h, bits, filename)
}

// BLAKE3sum returns BLAKE3 checksum of filename
// bits: 256, 384, 512
func BLAKE3sum(filename string, bits int, _ string) (string, error) {
	var h hash.Hash
	switch bits {
	case 0:
		h = blake3.New(32, nil)
	case 256:
		h = blake3.New(32, nil)
	case 384:
		h = blake3.New(48, nil)
	case 512:
		h = blake3.New(64, nil)
	default:
		return "", fmt.Errorf("invalid number of bits: %d", bits)
	}
	return sum(h, bits, filename)
}

// XXHsum returns XXH(32/64) checksum of filename
// bits: 32, 64
func XXHsum(filename string, bits int, _ string) (string, error) {
	var h hash.Hash
	switch bits {
	case 0:
		h = xxhash.NewHash32()
	case 32:
		h = xxhash.NewHash32()
	case 64:
		h = xxhash.NewHash64()
	default:
		return "", fmt.Errorf("invalid number of bits: %d", bits)
	}
	return sum(h, bits, filename)
}

// FNVsum returns XXH checksum of content in reader
// bits: 32, 64, 128
func FNVsum(filename string, bits int, _ string) (string, error) {
	var h hash.Hash
	switch bits {
	case 0:
		h = fnv.New32()
	case 64:
		h = fnv.New64()
	case 128:
		h = fnv.New128()
	default:
		return "", fmt.Errorf("invalid number of bits: %d", bits)
	}
	return sum(h, bits, filename)
}

// FNVasum returns XXH checksum of content in reader
// bits: 32, 64, 128
func FNVasum(filename string, bits int, _ string) (string, error) {
	var h hash.Hash
	switch bits {
	case 0:
		h = fnv.New32a()
	case 64:
		h = fnv.New64a()
	case 128:
		h = fnv.New128a()
	default:
		return "", fmt.Errorf("invalid number of bits: %d", bits)
	}
	return sum(h, bits, filename)
}

// Adler32sum returns XXH checksum of content in reader
// bits: 32
func Adler32sum(filename string, _ int, _ string) (string, error) {
	return sum(adler32.New(), 32, filename)
}

// sum calculates the hash based on a provided hash provider
func sum(hashAlgorithm hash.Hash, bits int, filename string) (string, error) {
	if info, err := os.Stat(filename); err != nil || info.IsDir() {
		return "", err
	}

	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	return sumReader(hashAlgorithm, bits, bufio.NewReader(file))
}
