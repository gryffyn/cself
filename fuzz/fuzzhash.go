package fuzz

import (
	"errors"

	"github.com/eciavatta/sdhash"
	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"
)

type FuzzHash struct {
	String string
	Diff   int
}

func SSDEEPsumReader(bytes []byte) (string, error) {
	return ssdeep.FuzzyBytes(bytes)
}

func TLSHsumReader(bytes []byte) (string, error) {
	t1, err := tlsh.HashBytes(bytes)
	if t1 != nil {
		return t1.String(), err
	} else {
		return "", errors.New("failed to compute hash")
	}
}

func SDHASHsumReader(bytes []byte) (string, error) {
	s1, err := sdhash.CreateSdbfFromBytes(bytes)
	var s1h sdhash.Sdbf
	if s1 != nil {
		s1h = s1.Compute()
	} else {
		return "", errors.New("failed to compute hash")
	}
	return s1h.String(), err
}

// SumReader calculates the hash based on a provided hash provider
func SumReader(name string, bytes []byte, compare bool, h2 string) (FuzzHash, error) {
	var f FuzzHash
	var err error
	if compare {
		f.Diff, err = getReader(name, compare).(func([]byte, string) (int, error))(bytes, h2)
	} else {
		f.String, err = getReader(name, compare).(func([]byte) (string, error))(bytes)
	}
	return f, err
}

func getReader(name string, compare bool) interface{} {
	fuzzHash := map[string]func([]byte) (string, error){
		"tlsh":   TLSHsumReader,
		"ssdeep": SSDEEPsumReader,
		"sdhash": SDHASHsumReader,
	}
	fuzzHashC := map[string]func([]byte, string) (int, error){
		"tlsh":   TLSHsumReaderCompare,
		"ssdeep": SSDEEPsumReaderCompare,
		"sdhash": SDHASHsumReaderCompare,
	}
	if compare {
		return fuzzHashC[name]
	}
	return fuzzHash[name]
}
