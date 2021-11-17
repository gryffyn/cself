// Package kdf computes key derivation and stretching algorithms like bcrypt and argon2
package kdf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math"
	"reflect"
	"runtime"
	"strings"

	gsk "github.com/gryffyn/go-scrypt-kdf"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type Params struct {
	Time   uint32
	Memory uint32
	Iter   uint32
	Hmac   func() hash.Hash
	Scrypt gsk.Params
	Info   string
	Salt   string
	Cost   int
}

var DefaultParams = Params{
	Time:   3,
	Memory: 32 * 1024,
	Iter:   10000,
	Hmac:   sha256.New,
	Scrypt: gsk.DefaultParams,
	Cost:   10,
}

var SaltLen = 32
var KeyLen = 32

// ARGON2I returns ARGON2I hash of content in reader
// formats: raw, unix
func ARGON2I(reader io.Reader, params Params, format string) ([]byte, error) {
	pw, threads, err := genKDFParams(reader)
	salt, err := genSalt(&params)
	key := argon2.Key(pw, salt, params.Time, params.Memory, threads, uint32(KeyLen))

	if format != "raw" {
		// Base64 encode the salt and hashed password.
		b64Salt := base64.RawStdEncoding.EncodeToString(salt)
		b64Hash := base64.RawStdEncoding.EncodeToString(key)
		// Return a string using the standard encoded hash representation.
		encodedHash := fmt.Sprintf("$argon2i$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.Memory,
			params.Time, threads, b64Salt, b64Hash)
		return []byte(encodedHash), err
	}

	return []byte(hex.EncodeToString(key)), err
}

// ARGON2ID returns ARGON2ID hash of content in reader
// formats: raw, unix
func ARGON2ID(reader io.Reader, params Params, format string) ([]byte, error) {
	pw, threads, err := genKDFParams(reader)
	salt, err := genSalt(&params)
	key := argon2.IDKey(pw, salt, params.Time, params.Memory, threads, uint32(KeyLen))

	if format != "raw" {
		// Base64 encode the salt and hashed password.
		b64Salt := base64.RawStdEncoding.EncodeToString(salt)
		b64Hash := base64.RawStdEncoding.EncodeToString(key)
		// Return a string using the standard encoded hash representation.
		encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.Memory,
			params.Time, threads, b64Salt, b64Hash)
		return []byte(encodedHash), err
	}

	return []byte(hex.EncodeToString(key)), err
}

// PBKDF2 returns PBKDF2 hash of content in reader
// formats: raw, unix
func PBKDF2(reader io.Reader, params Params, format string) ([]byte, error) {
	pw, _, err := genKDFParams(reader)
	salt, err := genSalt(&params)
	key := pbkdf2.Key(pw, salt, int(params.Iter), KeyLen, params.Hmac)

	if format != "raw" {
		// Base64 encode the salt and hashed password.
		b64Salt := base64.RawStdEncoding.EncodeToString(salt)
		b64Hash := base64.RawStdEncoding.EncodeToString(key)
		// Return a string using the standard encoded hash representation.
		encodedHash := fmt.Sprintf("$pbkdf2-%s$i=%d$%s$%s", getHashFunc(params.Hmac), params.Iter, b64Salt, b64Hash)
		return []byte(encodedHash), err
	}

	return key, err
}

// HKDF returns an extended key using provided parameters.
// formats: raw, hex
func HKDF(reader io.Reader, params Params, format string) ([]byte, error) {
	pw, err := io.ReadAll(reader)
	salt, err := genSaltHKDF()
	nhkdf := hkdf.New(params.Hmac, pw, []byte(params.Salt), append(salt, []byte(params.Info)...))
	key := make([]byte, KeyLen)
	_, err = io.ReadFull(nhkdf, key)

	if format == "hex" {
		return []byte(hex.EncodeToString(key)), err
	}

	return key, err
}

// SCRYPT returns SCRYPT hash of content in reader
// formats: raw, tarsnap
func SCRYPT(reader io.Reader, params Params, format string) ([]byte, error) {
	if format == "tarsnap" {
		pw, err := io.ReadAll(reader)
		key, err := gsk.Kdf(pw, params.Scrypt)
		return []byte(hex.EncodeToString(key)), err
	}
	pw, _, err := genKDFParams(reader)
	salt, err := genSalt(&params)
	s := params.Scrypt
	n := int(math.Round(math.Pow(2, float64(s.LogN))))
	key, err := scrypt.Key(pw, salt, n, int(s.R), int(s.P), KeyLen)
	if format == "unix" {
		// Base64 encode the salt and hashed password.
		b64Salt := base64.RawStdEncoding.EncodeToString(salt)
		b64Hash := base64.RawStdEncoding.EncodeToString(key)
		// Return a string using the standard encoded hash representation.
		encodedHash := fmt.Sprintf("$scrypt$N=%d,r=%d,p=%d$%s$%s", n, int(s.R), int(s.P), b64Salt, b64Hash)
		return []byte(encodedHash), err
	}
	return []byte(hex.EncodeToString(key)), err
}

// BCRYPT returns BCRYPT hash of content in reader
// formats: unix
func BCRYPT(reader io.Reader, params Params, format string) ([]byte, error) {
	pw, err := io.ReadAll(reader)
	key, err := bcrypt.GenerateFromPassword(pw, params.Cost)
	return key, err
}

// CRYPT returns crypt-sha512 hash of content in reader
// formats: unix
func CRYPT(reader io.Reader, params Params, format string) ([]byte, error) {
	pw, err := io.ReadAll(reader)
	salt := make([]byte, SaltLen)
	_, err = rand.Read(salt)
	if err != nil {
		return []byte(""), err
	}
	cs := sha512_crypt.New()
	hs := hex.EncodeToString(salt)
	key, err := cs.Generate(pw, []byte("$6$"+hs[:16]))
	return []byte(key), err
}

func genKDFParams(reader io.Reader) ([]byte, uint8, error) {
	pw, err := io.ReadAll(reader)
	salt := make([]byte, SaltLen)
	_, err = rand.Read(salt)
	if err != nil {
		return []byte{}, 0, err
	}
	threads := runtime.NumCPU()
	if threads > 255 {
		threads = 255
	}
	return pw, uint8(threads), err
}

func genSaltHKDF() ([]byte, error) {
	salt := make([]byte, SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return []byte{}, err
	}
	return salt, err
}

func genSalt(params *Params) ([]byte, error) {
	if params.Salt != "" {
		return []byte(params.Salt), nil
	} else {
		return genSaltHKDF()
	}
}

func getHashFunc(i interface{}) string {
	fn := runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
	fn = strings.TrimPrefix(fn, "crypto/")
	fn = strings.TrimSuffix(fn, ".New")
	return fn
}
