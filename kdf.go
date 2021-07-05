package checksum

import (
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"io"
	"math"
	"runtime"

	gsk "github.com/gryffyn/go-scrypt-kdf"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type Params struct {
	time   uint32
	memory uint32
	iter   uint32
	hmac   func() hash.Hash
	scrypt gsk.Params
	cost   int
}

func (p *Params) setDefault() {
	if p.time == 0 {
		p.time = 3
	}
	if p.cost == 0 {
		p.cost = 10
	}
	if p.memory == 0 {
		p.time = 32 * 1024
	}
	if p.iter == 0 {
		p.iter = 10000
	}
	if p.hmac == nil {
		p.hmac = sha256.New
	}
	if p.scrypt.P == 0 {
		p.scrypt = gsk.DefaultParams
	}
}

// Argon2i returns MD5 checksum of content in reader
func Argon2i(reader io.Reader, params Params) (string, error) {
	pw, salt, threads, err := genKDFParams(reader)
	params.setDefault()
	key := argon2.Key(pw, salt, params.time, params.memory, threads, 32)
	return string(key), err
}

// Argon2id returns MD5 checksum of content in reader
func Argon2id(reader io.Reader, params Params) (string, error) {
	pw, salt, threads, err := genKDFParams(reader)
	params.setDefault()
	key := argon2.IDKey(pw, salt, params.time, params.memory, threads, 32)
	return string(key), err
}

// PBKDF2 returns MD5 checksum of content in reader
func PBKDF2(reader io.Reader, params Params) (string, error) {
	pw, salt, _, err := genKDFParams(reader)
	params.setDefault()
	key := pbkdf2.Key(pw, salt, int(params.iter), 32, params.hmac)
	return string(key), err
}

// ScryptT returns MD5 checksum of content in reader
func ScryptT(reader io.Reader, params Params) (string, error) {
	pw, err := io.ReadAll(reader)
	params.setDefault()
	key, err := gsk.Kdf(pw, params.scrypt)
	return string(key), err
}

// Scrypt returns MD5 checksum of content in reader
func Scrypt(reader io.Reader, params Params) (string, error) {
	pw, salt, _, err := genKDFParams(reader)
	params.setDefault()
	s := params.scrypt
	key, err := scrypt.Key(pw, salt, int(math.Round(math.Pow(2, float64(s.LogN)))), int(s.R), int(s.P), 32)
	return string(key), err
}

// Bcrypt returns MD5 checksum of content in reader
func Bcrypt(reader io.Reader, params Params) (string, error) {
	pw, err := io.ReadAll(reader)
	params.setDefault()
	key, err := bcrypt.GenerateFromPassword(pw, params.cost)
	return string(key), err
}

func genKDFParams(reader io.Reader) ([]byte, []byte, uint8, error) {
	pw, err := io.ReadAll(reader)
	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return []byte{}, []byte{}, 0, err
	}
	threads := runtime.NumCPU()
	if threads > 255 {
		threads = 255
	}
	return []byte(pw), salt, uint8(threads), err
}
