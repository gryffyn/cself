package fuzz

import (
	"errors"

	"github.com/eciavatta/sdhash"
	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"
)

func SSDEEPsum(filename string) (string, error) {
	return ssdeep.FuzzyFilename(filename)
}

func TLSHsum(filename string) (string, error) {
	t1, err := tlsh.HashFilename(filename)
	if t1 != nil {
		return t1.String(), err
	} else {
		return "", errors.New("failed to compute hash")
	}
}

func SDHASHsum(filename string) (string, error) {
	s1, err := sdhash.CreateSdbfFromFilename(filename)
	var s1h sdhash.Sdbf
	if s1 != nil {
		s1h = s1.Compute()
	} else {
		return "", errors.New("failed to compute hash")
	}
	return s1h.String(), err
}

// Sum calculates the hash based on a provided hash provider
func Sum(name, filename string, compare bool, h2 string) (FuzzHash, error) {
	var f FuzzHash
	var err error
	if compare {
		f.Diff, err = getSum(name, compare).(func(string, string) (int, error))(filename, h2)
	} else {
		f.String, err = getSum(name, compare).(func(string) (string, error))(filename)
	}
	return f, err
}

func getSum(name string, compare bool) interface{} {
	fuzzHash := map[string]func(string) (string, error){
		"tlsh":   TLSHsum,
		"ssdeep": SSDEEPsum,
		"sdhash": SDHASHsum,
	}
	fuzzHashC := map[string]func(string, string) (int, error){
		"tlsh":   TLSHsumCompare,
		"ssdeep": SSDEEPsumCompare,
		"sdhash": SDHASHsumCompare,
	}
	if compare {
		return fuzzHashC[name]
	}
	return fuzzHash[name]
}
