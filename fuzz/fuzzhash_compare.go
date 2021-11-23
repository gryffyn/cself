package fuzz

import (
	"errors"

	"github.com/eciavatta/sdhash"
	"github.com/glaslos/ssdeep"
	"github.com/gryffyn/tlsh"
)

func SSDEEPsumReaderCompare(bytes []byte, h2 string) (int, error) {
	s1, err := ssdeep.FuzzyBytes(bytes)
	d, err := ssdeep.Distance(s1, h2)
	return d, err
}

func TLSHsumReaderCompare(bytes []byte, h2 string) (int, error) {
	t1, err := tlsh.HashBytes(bytes)
	t2, err := tlsh.ParseStringToTlsh(h2)
	if t1 != nil {
		return t1.Diff(t2), err
	} else { return 0, errors.New("failed to compare hash") }
}

func SDHASHsumReaderCompare(bytes []byte, h2 string) (int, error) {
	s1, err := sdhash.CreateSdbfFromBytes(bytes)
	var s1h sdhash.Sdbf
	if s1 != nil {
		s1h = s1.Compute()
	} else { return 0, errors.New("failed to compare hash") }
	s2h, err := sdhash.ParseSdbfFromString(h2)
	return s1h.Compare(s2h), err
}

/*
// sumReader calculates the hash based on a provided hash provider
func sumCompare(f func([]byte, string)(int, error), bytes []byte, h2 string) (int, error) {
	return f(bytes, h2)
}
 */
