package checksum_test

import (
	"strings"
	"testing"

	"git.gryffyn.io/gryffyn/cself/checksum"
)

func TestSHA256sumReader(t *testing.T) {
	if sha256sum, err := checksum.SHA2sumReader(strings.NewReader("some data"),
		256, ""); err != nil || sha256sum != "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee" {
		t.Error("SHA256sum(reader) failed", sha256sum, err)
	}
}

func TestMd5sumReader(t *testing.T) {
	if md5sum, err := checksum.MD5sumReader(strings.NewReader("some data"), 0, ""); err != nil || md5sum != "1e50210a0202497fb79bc38b6ade6c34" {
		t.Error("Md5sum(reader) failed", md5sum, err)
	}
}

func TestSHA1sumReader(t *testing.T) {
	if sum, err := checksum.SHA1sumReader(strings.NewReader(
		"some data"), 0, ""); err != nil || sum != "baf34551fecb48acc3da868eb85e1b6dac9de356" {
		t.Error("SHA1sum(reader) failed", sum, err)
	}
}

func TestSHA512sumReader(t *testing.T) {
	if sum, err := checksum.SHA2sumReader(strings.NewReader(
		"some data"), 512, ""); err != nil || sum != "e1645e7492f032fb62c674db75500be7b260bfc0daa965821ddb3f8a49b5d33788ee3f046744e2b95afb5c3d8f2500c549ca89d79fc6890885d28e055007424f" {
		t.Error("SHA512sum(reader) failed", sum, err)
	}
}

func TestSHA3sumReader(t *testing.T) {
	if sum, err := checksum.SHA3sumReader(strings.NewReader(
		"some data"), 224, ""); err != nil || sum != "5fd9df158fd7eb737893332c5e19906d8d1352a6932dbf10c0200b53" {
		t.Error("SHA3sum(reader) failed", sum, err)
	}
}

func TestBlake256sumReader(t *testing.T) {
	if sum, err := checksum.BLAKE2BsumReader(strings.NewReader(
		"some data"), 256, ""); err != nil || sum != "101e81939178f84a6e896fe1c2638f6f9e16711d942c4efec6f28d7519c17b57" {
		t.Error("BLAKE2b256sum(reader) failed", sum, err)
	}
}

func TestBlake512sumReader(t *testing.T) {
	if sum, err := checksum.BLAKE2BsumReader(strings.NewReader(
		"some data"), 512, ""); err != nil || sum != "44e34bbaadd8719e6d65a67803b8fba0d91eb0669f432314fb933932fa601a2fd23f86f9eb39fc30b20cc5bb884a8d4d8edd1748babd8a28038e5d2c85757feb" {
		t.Error("BLAKE2b512sum(reader) failed", sum, err)
	}
}

func TestBlake3256sumReader(t *testing.T) {
	if sum, err := checksum.BLAKE3sumReader(strings.NewReader(
		"some data"), 256, ""); err != nil || sum != "b224a1da2bf5e72b337dc6dde457a05265a06dec8875be379e2ad2be5edb3bf2" {
		t.Error("BLAKE3-256sum(reader) failed", sum, err)
	}
}

func TestBlake3512sumReader(t *testing.T) {
	if sum, err := checksum.BLAKE3sumReader(strings.NewReader(
		"some data"), 512, ""); err != nil || sum != "b224a1da2bf5e72b337dc6dde457a05265a06dec8875be379e2ad2be5edb3bf21b55688951738e3a7155d6398eb56c6bc35d5bca5f139d98eb7409be51d1be32" {
		t.Error("BLAKE3-512sum(reader) failed", sum, err)
	}
}

func TestXxh32sumReader(t *testing.T) {
	if sum, err := checksum.XXHsumReader(strings.NewReader(
		"some data"), 32, ""); err != nil || sum != "ec6c369a" {
		t.Error("XXH-32sum(reader) failed", sum, err)
	}
}

func TestXxh64sumReader(t *testing.T) {
	if sum, err := checksum.XXHsumReader(strings.NewReader(
		"some data"), 64, ""); err != nil || sum != "2c908fdf96771c8f" {
		t.Error("XXH-64sum(reader) failed", sum, err)
	}
}

func TestFNVsumReader(t *testing.T) {
	if sum, err := checksum.FNVsumReader(strings.NewReader(
		"some data"), 0, ""); err != nil || sum != "dd9de553" {
		t.Error("FNVsum(reader) failed", sum, err)
	}
}

func TestFNVasumReader(t *testing.T) {
	if sum, err := checksum.FNVasumReader(strings.NewReader(
		"some data"), 0, ""); err != nil || sum != "89ed702b" {
		t.Error("FNVasum(reader) failed", sum, err)
	}
}

func TestAdler32sumReader(t *testing.T) {
	if sum, err := checksum.Adler32sumReader(strings.NewReader(
		"some data"), 64, ""); err != nil || sum != "1181036f" {
		t.Error("Adler32sum(reader) failed", sum, err)
	}
}


