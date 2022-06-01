package checksum

import (
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
	"strings"

	"git.gryffyn.io/gryffyn/go-chksum3"
	"github.com/OneOfOne/xxhash"
	"github.com/sigurn/crc8"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"lukechampine.com/blake3"
)

const bufferSize int = 65536

// MD5sumReader returns MD5 checksum of content in reader
// bytes: 128
func MD5sumReader(reader io.Reader, _ int, _ string) (string, error) {
	return sumReader(md5.New(), 128, reader)
}

// SHA1sumReader returns SHA-1 checksum of content in reader
// bytes: 160
func SHA1sumReader(reader io.Reader, _ int, _ string) (string, error) {
	return sumReader(sha1.New(), 160, reader)
}

// LESumReader returns 8 or 32 bit little-endian checksum of content in reader
// bits: 32
func LESumReader(reader io.Reader, bytes int, _ string) (string, error) {
	switch bytes {
	case 8:
		return sumReader(chksum3.New8(), 8, reader)
	case 32:
		return sumReader(chksum3.New32(), 32, reader)
	default:
		return "", errors.New("invalid byte size: must be '8' or '32'")
	}
}

func CRC8Reader(reader io.Reader, _ int, poly string) (string, error) {
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

// CRC32Reader returns CRC32 checksum of content in reader
// bytes:
func CRC32Reader(reader io.Reader, _ int, poly string) (string, error) {
	var tbl *crc32.Table
	switch poly {
	case "c":
		tbl = crc32.MakeTable(crc32.Castagnoli)
	case "k":
		tbl = crc32.MakeTable(crc32.Koopman)
	default:
		return sumReader(crc32.NewIEEE(), 32, reader)
	}
	return sumReader(crc32.New(tbl), 32, reader)
}

// CRC64Reader returns CRC64 checksum of content in reader
// bytes:
func CRC64Reader(reader io.Reader, _ int, poly string) (string, error) {
	switch poly {
	case "e":
		return sumReader(crc64.New(crc64.MakeTable(crc64.ECMA)), 64, reader)
	default:
		return sumReader(crc64.New(crc64.MakeTable(crc64.ISO)), 64, reader)
	}
}

// SHA2sumReader returns SHA-2 checksum of content in reader
// bytes: 224, 256, 384, 512
func SHA2sumReader(reader io.Reader, bytes int, _ string) (string, error) {
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
	return sumReader(h, bytes, reader)
}

// SHA3sumReader returns SHA-3 checksum of content in reader
// bytes: 224, 256, 384, 512
func SHA3sumReader(reader io.Reader, bytes int, _ string) (string, error) {
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
	return sumReader(h, bytes, reader)
}

// BLAKE2BsumReader returns BLAKE2b checksum of content in reader
// bytes: 256, 384, 512
func BLAKE2BsumReader(reader io.Reader, bytes int, _ string) (string, error) {
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
	return sumReader(h, bytes, reader)
}

// BLAKE3sumReader returns BLAKE3 checksum of content in reader
// bytes: 256, 384, 512
func BLAKE3sumReader(reader io.Reader, bytes int, _ string) (string, error) {
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
	return sumReader(h, bytes, reader)
}

// XXHsumReader returns XXH checksum of content in reader
// bytes: 32, 64
func XXHsumReader(reader io.Reader, bytes int, _ string) (string, error) {
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
	return sumReader(h, bytes, reader)
}

// FNVsumReader returns XXH checksum of content in reader
// bytes: 32, 64, 128
func FNVsumReader(reader io.Reader, bytes int, _ string) (string, error) {
	var h hash.Hash
	switch bytes {
	case 0:
		h = fnv.New32()
	case 64:
		h = fnv.New64()
	case 128:
		h = fnv.New128()
	default:
		return "", fmt.Errorf("invalid number of bytes: %d", bytes)
	}
	return sumReader(h, bytes, reader)
}

// FNVasumReader returns XXH checksum of content in reader
// bytes: 32, 64, 128
func FNVasumReader(reader io.Reader, bytes int, _ string) (string, error) {
	var h hash.Hash
	switch bytes {
	case 0:
		h = fnv.New32a()
	case 64:
		h = fnv.New64a()
	case 128:
		h = fnv.New128a()
	default:
		return "", fmt.Errorf("invalid number of bytes: %d", bytes)
	}
	return sumReader(h, bytes, reader)
}

// Adler32sumReader returns XXH checksum of content in reader
// bytes: 32
func Adler32sumReader(reader io.Reader, _ int, _ string) (string, error) {
	return sumReader(adler32.New(), 32, reader)
}

// sumReader calculates the hash based on a provided hash provider
func sumReader(hashAlgorithm hash.Hash, bits int, reader io.Reader) (string, error) {
	buf := make([]byte, bufferSize)
	for {
		switch n, err := reader.Read(buf); err {
		case nil:
			_, err := hashAlgorithm.Write(buf[:n])
			if err != nil {
				return "", err
			}
		case io.EOF:
			bytelen := fmt.Sprintf("%%%dx", bits/4)
			return fmt.Sprintf(bytelen, hashAlgorithm.Sum(nil)), nil
		default:
			return "", err
		}
	}
}
