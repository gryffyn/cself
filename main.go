package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"strings"

	"git.gryffyn.io/gryffyn/cself/checksum"
	"git.gryffyn.io/gryffyn/cself/fuzz"
	"git.gryffyn.io/gryffyn/cself/kdf"
	gsk "github.com/gryffyn/go-scrypt-kdf"
	"github.com/urfave/cli/v2"
)

func main() {
	hashes := map[string]interface{}{
		"md5":     checksum.MD5sum,
		"sha1":    checksum.SHA1sum,
		"sha2":    checksum.SHA2sum,
		"sha3":    checksum.SHA3sum,
		"blake2b": checksum.BLAKE2Bsum,
		"blake3":  checksum.BLAKE3sum,
		"le":      checksum.LESum,
		"xxh":     checksum.XXHsum,
		"crc32":   checksum.CRC32sum,
		"crc64":   checksum.CRC64sum,
		"fnv":     checksum.FNVsum,
		"fnva":    checksum.FNVasum,
		"adler32": checksum.Adler32sum,
	}
	hashesReader := map[string]interface{}{
		"md5":     checksum.MD5sumReader,
		"sha1":    checksum.SHA1sumReader,
		"sha2":    checksum.SHA2sumReader,
		"sha3":    checksum.SHA3sumReader,
		"blake2b": checksum.BLAKE2BsumReader,
		"blake3":  checksum.BLAKE3sumReader,
		"le":      checksum.LESumReader,
		"xxh":     checksum.XXHsumReader,
		"crc32":   checksum.CRC32Reader,
		"crc64":   checksum.CRC64Reader,
		"fnv":     checksum.FNVsumReader,
		"fnva":    checksum.FNVasumReader,
		"adler32": checksum.Adler32sumReader,
	}
	kdfs := map[string]func(reader io.Reader, params kdf.Params, format string) ([]byte, error){
		"argon2i":  kdf.ARGON2I,
		"argon2id": kdf.ARGON2ID,
		"pbkdf2":   kdf.PBKDF2,
		"scrypt":   kdf.SCRYPT,
		"bcrypt":   kdf.BCRYPT,
		"crypt":    kdf.CRYPT,
		"hkdf":     kdf.HKDF,
	}

	app := cli.App{
		Name:            "cself",
		Usage:           "generate hashes for files, passwords, and stdin",
		UsageText:       "cself [COMMAND] [OPTIONS]",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			{
				Name:            "list-alg",
				Aliases:         []string{"l"},
				Usage:           "list algorithms",
				HideHelpCommand: true,
				UsageText:       "cself list-alg [OPTIONS]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "type",
						Aliases:  []string{"t"},
						Usage:    "type of algorithms to show (hash, kdf, fuzzy)",
						Required: false,
					},
				},
				Action: func(c *cli.Context) error {
					switch t := c.String("type"); t {
					case "hash":
						fmt.Println("Hashes:")
						for k := range hashes {
							fmt.Println(k)
						}
					case "kdf":
						fmt.Println("KDFs:")
						for k := range kdfs {
							fmt.Println(k)
						}
					case "fuzzy":
						fmt.Println("Fuzzy:\ntlsh\nssdeep\nsdhash")
					default:
						fmt.Println("Hashes:")
						for k := range hashes {
							fmt.Println(k)
						}
						fmt.Println("\nKDFs:")
						for k := range kdfs {
							fmt.Println(k)
						}
						fmt.Println("\nFuzzy:\ntlsh\nssdeep\nsdhash")
					}
					return nil
				},
			},
			{
				Name:            "hash",
				Aliases:         []string{"h"},
				Usage:           "hash mode",
				HideHelpCommand: true,
				UsageText:       "cself hash [OPTIONS] file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "a",
						Value:    "sha2",
						Usage:    "hash algorithm",
						Required: false,
					},
					&cli.StringFlag{
						Name:     "poly",
						Usage:    "polynomial for CRC",
						Required: false,
					},
					&cli.IntFlag{
						Name:     "bytes",
						Aliases:  []string{"b"},
						Usage:    "Byte length for hash function ex. 256",
						Required: false,
					},
					// TODO: multihash
					/*
						&cli.BoolFlag{
							Name:     "multihash",
							Aliases:  []string{"m"},
							Usage:    "Outputs in multihash format",
							Required: false,
						},
					*/
				},
				Action: func(c *cli.Context) error {
					var err error
					var output string
					hashfunc := c.String("a")
					if isPipe() {
						if fn, ok := hashesReader[hashfunc]; ok {
							output, err = fn.(func(io.Reader, int, string) (string, error))(bufio.NewReader(os.Stdin),
								c.Int("bytes"), c.String("poly"))
							if err == nil {
								fmt.Println(output + "  -")
							}
						} else {
							fmt.Println("Hash function '" + hashfunc + "' not found.")
						}
					} else {
						if c.Args().Get(0) != "" {
							if fn, ok := hashes[hashfunc]; ok {
								output, err = fn.(func(string, int, string) (string, error))(c.Args().Get(0),
									c.Int("bytes"), c.String("poly"))
								if err == nil {
									fmt.Println(output + "  " + c.Args().Get(0))
								}
							} else {
								fmt.Println("Hash function '" + hashfunc + "' not found.")
							}
						} else {
							cli.ShowAppHelpAndExit(c, 0)
						}
					}
					return err
				},
			},
			{
				Name:            "fuzzyhash",
				Aliases:         []string{"f"},
				Usage:           "fuzzy hash mode",
				HideHelpCommand: true,
				UsageText:       "cself fuzzyhash [OPTIONS] file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "algorithm",
						Aliases:  []string{"a"},
						Value:    "ssdeep",
						Usage:    "algorithm",
						Required: false,
					},
					&cli.StringFlag{
						Name:     "input-hash",
						Aliases:  []string{"i"},
						Usage:    "hash input to compare to",
						Required: false,
					},
					&cli.IntFlag{
						Name:     "threshold",
						Aliases:  []string{"t"},
						Usage:    "match threshold",
						Value:    0,
						Required: false,
					},
					// TODO: file to file comparison
					/*
						&cli.StringFlag{
							Name:     "compare-file",
							Aliases:  []string{"c"},
							Usage:    "file to compare input to",
							Required: false,
						},
					*/
				},
				Action: func(c *cli.Context) error {
					var err error
					var compare bool
					hashfunc := c.String("algorithm")
					if c.String("input-hash") != "" {
						compare = true
					}
					if isPipe() {
						bytes, err := io.ReadAll(bufio.NewReader(os.Stdin))
						fh, err := fuzz.SumReader(hashfunc, bytes, compare, c.String("input-hash"))
						if err != nil {
							log.Fatalln(err)
						}
						if compare {
							if fh.Diff > c.Int("threshold") {
								fmt.Printf("MATCH (%d)  -\n", fh.Diff)
							} else {
								fmt.Printf("NO MATCH")
							}
						} else {
							fmt.Printf("%s  -\n", strings.TrimSpace(fh.String))
						}
					} else {
						if c.Args().Get(0) != "" {
							fh, err := fuzz.Sum(hashfunc, c.Args().First(), compare, c.String("input-hash"))
							if err != nil {
								log.Fatalln(err)
							}
							if compare {
								if fh.Diff > c.Int("threshold") {
									fmt.Printf("MATCH (%d)  %s\n", fh.Diff, c.Args().First())
								} else {
									fmt.Printf("NO MATCH")
								}
							} else {
								fmt.Printf("%s  %s\n", strings.TrimSpace(fh.String), c.Args().Get(0))
							}
						} else {
							cli.ShowAppHelpAndExit(c, 0)
						}
					}
					return err
				},
			},
			{
				Name:            "kdf",
				Aliases:         []string{"k"},
				Usage:           "kdf mode",
				HideHelpCommand: true,
				UsageText:       "cself kdf [OPTIONS] password",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "a",
						Value:    "argon2id",
						Usage:    "kdf algorithm",
						Required: false,
					},
					&cli.IntFlag{
						Name:     "saltlen",
						Usage:    "length of random salt",
						Value:    32,
						Required: false,
					},
					&cli.StringFlag{
						Name:     "salt",
						Usage:    "salt value (default: random bytes)",
						Required: false,
					},
					&cli.StringFlag{
						Name:     "info",
						Usage:    "HKDF - info value to append to random bytes",
						Required: false,
					},
					&cli.IntFlag{
						Name:     "keylen",
						Usage:    "Output key length",
						Value:    32,
						Required: false,
					},
					&cli.IntFlag{
						Name:     "time",
						Aliases:  []string{"t"},
						Usage:    "Argon2 - time",
						Value:    3,
						Required: false,
					},
					&cli.IntFlag{
						Name:     "memory",
						Aliases:  []string{"m"},
						Usage:    "Argon2 - memory",
						Value:    32 * 1024,
						Required: false,
					},
					&cli.IntFlag{
						Name:     "iter",
						Aliases:  []string{"i"},
						Usage:    "PBKDF2 - iterations",
						Value:    10000,
						Required: false,
					},
					&cli.StringFlag{
						Name:     "hmac",
						Usage:    "PBKDF2/HKDF - HMAC function",
						Value:    "sha256",
						Required: false,
					},
					&cli.IntFlag{
						Name:     "logN",
						Aliases:  []string{"l"},
						Usage:    "SCRYPT - logN",
						Value:    15,
						Required: false,
					},
					&cli.IntFlag{
						Name:     "R",
						Usage:    "SCRYPT - R",
						Value:    8,
						Required: false,
					},
					&cli.IntFlag{
						Name:     "P",
						Usage:    "SCRYPT - P",
						Value:    1,
						Required: false,
					},
					&cli.IntFlag{
						Name:     "cost",
						Aliases:  []string{"c"},
						Usage:    "BCRYPT - cost",
						Value:    10,
						Required: false,
					},
					&cli.StringFlag{
						Name:     "format",
						Aliases:  []string{"f"},
						Value:    "unix",
						Usage:    "output format - raw, unix, hex, or tarsnap",
						Required: false,
					},
				},
				Action: func(c *cli.Context) error {
					var err error
					var output []byte
					if c.Int("saltlen") != 32 {
						kdf.SaltLen = c.Int("saltlen")
					}
					if c.Int("keylen") != 32 {
						kdf.KeyLen = c.Int("keylen")
					}
					hmacFuncs := map[string]func() hash.Hash{
						"sha1":   sha1.New,
						"sha256": sha256.New,
						"sha512": sha512.New,
					}
					params := kdf.Params{
						Time:   uint32(c.Int("time")),
						Memory: uint32(c.Int("memory")),
						Iter:   uint32(c.Int("iter")),
						Hmac:   hmacFuncs[c.String("hmac")],
						Scrypt: gsk.Params{
							LogN: uint8(c.Int("logN")),
							R:    uint32(c.Int("R")),
							P:    uint32(c.Int("P")),
						},
						Info: c.String("info"),
						Salt: c.String("salt"),
						Cost: c.Int("cost"),
					}
					hashfunc := c.String("a")
					if isPipe() {
						if fn, ok := kdfs[hashfunc]; ok {
							output, err = fn(bufio.NewReader(os.Stdin), params, c.String("format"))
							if err == nil {
								if hashfunc != "hkdf" {
									fmt.Println(string(output))
								} else {
									fmt.Println(output)
								}
							} else {
								log.Fatalln(err)
							}
						} else {
							fmt.Println("Hash function '" + hashfunc + "' not found.")
						}
					} else {
						if fn, ok := kdfs[hashfunc]; ok {
							r := strings.NewReader(c.Args().Get(0))
							output, err = fn(r, params, c.String("format"))
							if err == nil {
								if hashfunc != "hkdf" || c.String("format") == "hex" {
									fmt.Println(string(output))
								} else {
									fmt.Println(output)
								}
							} else {
								log.Fatalln(err)
							}
						} else {
							fmt.Println("Hash function '" + hashfunc + "' not found.")
						}
					}
					return err
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func isPipe() bool {
	fileInfo, _ := os.Stdin.Stat()
	return fileInfo.Mode()&os.ModeCharDevice == 0
}
