package checksum_test

import (
	"io/ioutil"
	"os"
	"testing"

	"git.neveris.one/gryffyn/cself/checksum"
)

func prepareFile() (string, error) {
	file, err := ioutil.TempFile("/tmp", "gochecksum")
	if err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(file.Name(), []byte("some data"), 0600); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func TestSHA256sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.SHA256sum(file); err != nil || sum != "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee" {
		t.Error("SHA256sum(file) failed", sum, err)
	}
}

func TestMd5sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.MD5sum(file); err != nil || sum != "1e50210a0202497fb79bc38b6ade6c34" {
		t.Error("Md5sum(file) failed", sum, err)
	}
}

func TestSHA1sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.SHA1sum(file); err != nil || sum != "baf34551fecb48acc3da868eb85e1b6dac9de356" {
		t.Error("SHA1sum(file) failed", sum, err)
	}
}

func TestSHA512sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.SHA512sum(file); err != nil || sum != "e1645e7492f032fb62c674db75500be7b260bfc0daa965821ddb3f8a49b5d33788ee3f046744e2b95afb5c3d8f2500c549ca89d79fc6890885d28e055007424f" {
		t.Error("SHA512sum(file) failed", sum, err)
	}
}

func TestSHA3sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.SHA3sum(file); err != nil || sum != "5fd9df158fd7eb737893332c5e19906d8d1352a6932dbf10c0200b53" {
		t.Error("SHA3sum(file) failed", sum, err)
	}
}

func TestBlake256sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.Blake256sum(file); err != nil || sum != "101e81939178f84a6e896fe1c2638f6f9e16711d942c4efec6f28d7519c17b57" {
		t.Error("BLAKE2b256sum(file) failed", sum, err)
	}
}

func TestBlake512sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.Blake512sum(file); err != nil || sum != "44e34bbaadd8719e6d65a67803b8fba0d91eb0669f432314fb933932fa601a2fd23f86f9eb39fc30b20cc5bb884a8d4d8edd1748babd8a28038e5d2c85757feb" {
		t.Error("BLAKE2b512sum(file) failed", sum, err)
	}
}

func TestBlake3256sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.Blake3256sum(file); err != nil || sum != "b224a1da2bf5e72b337dc6dde457a05265a06dec8875be379e2ad2be5edb3bf2" {
		t.Error("BLAKE3-256sum(file) failed", sum, err)
	}
}

func TestBlake3512sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.Blake3512sum(file); err != nil || sum != "b224a1da2bf5e72b337dc6dde457a05265a06dec8875be379e2ad2be5edb3bf21b55688951738e3a7155d6398eb56c6bc35d5bca5f139d98eb7409be51d1be32" {
		t.Error("BLAKE3-512sum(file) failed", sum, err)
	}
}

func TestXxh32sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.Xxh32sum(file); err != nil || sum != "ec6c369a" {
		t.Error("XXH32sum(file) failed", sum, err)
	}
}

func TestXxh64sumFile(t *testing.T) {
	file, err := prepareFile()
	if err != nil {
		t.Logf("could not create test file: %s", err)
		t.FailNow()
	}
	defer func() {
		err := os.Remove(file)
		if err != nil {
			t.Logf("could not remove test file: %s", err)
		}
	}()

	if sum, err := checksum.Xxh64sum(file); err != nil || sum != "2c908fdf96771c8f" {
		t.Error("XXH64sum(file) failed", sum, err)
	}
}
