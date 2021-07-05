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

	"git.neveris.one/gryffyn/cself/checksum"
	"git.neveris.one/gryffyn/cself/kdf"
	gsk "github.com/gryffyn/go-scrypt-kdf"
	"github.com/urfave/cli/v2"
)

func main() {
	hashes := map[string]func(string) (string, error){
		"md5":        checksum.MD5sum,
		"sha256":     checksum.SHA256sum,
		"sha512":     checksum.SHA512sum,
		"sha1":       checksum.SHA1sum,
		"sha3":       checksum.SHA3sum,
		"blake2-256": checksum.Blake256sum,
		"blake2":     checksum.Blake512sum,
		"blake2-512": checksum.Blake512sum,
		"blake3-256": checksum.Blake3256sum,
		"blake3":     checksum.Blake256sum,
		"blake3-512": checksum.Blake3512sum,
		"xxhash-32":  checksum.Xxh32sum,
		"xxhash-64":  checksum.Xxh64sum,
		"xxhash":     checksum.Xxh64sum,
	}

	hashesReader := map[string]func(io.Reader) (string, error){
		"md5":        checksum.MD5sumReader,
		"sha256":     checksum.SHA256sumReader,
		"sha512":     checksum.SHA512sumReader,
		"sha1":       checksum.SHA1sumReader,
		"sha3":       checksum.SHA3sumReader,
		"blake2-256": checksum.Blake256sumReader,
		"blake2":     checksum.Blake512sumReader,
		"blake2-512": checksum.Blake512sumReader,
		"blake3-256": checksum.Blake3256sumReader,
		"blake3":     checksum.Blake256sumReader,
		"blake3-512": checksum.Blake3512sumReader,
		"xxhash-32":  checksum.Xxh32sumReader,
		"xxhash-64":  checksum.Xxh64sumReader,
		"xxhash":     checksum.Xxh64sumReader,
	}

	kdfs := map[string]func(reader io.Reader, params kdf.Params, format bool) (string, error){
		"argon2i":  kdf.Argon2i,
		"argon2id": kdf.Argon2id,
		"pbkdf2":   kdf.PBKDF2,
		"scryptt":  kdf.ScryptT,
		"scrypt":   kdf.Scrypt,
		"bcrypt":   kdf.Bcrypt,
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
						Usage:    "type of algorithms to show (hash or kdf)",
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
					default:
						fmt.Println("Hashes:")
						for k := range hashes {
							fmt.Println(k)
						}
						fmt.Println("\nKDFs:")
						for k := range kdfs {
							fmt.Println(k)
						}
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
						Value:    "sha256",
						Usage:    "hash algorithm",
						Required: false,
					},
				},
				Action: func(c *cli.Context) error {
					var err error
					var output string
					hashfunc := c.String("a")
					if isPipe() {
						if fn, ok := hashesReader[hashfunc]; ok {
							output, err = fn(bufio.NewReader(os.Stdin))
							fmt.Println(output + "  -")
						} else {
							fmt.Println("Hash function '" + hashfunc + "' not found.")
						}

					} else {
						if fn, ok := hashes[hashfunc]; ok {
							output, err = fn(c.Args().Get(0))
							fmt.Println(output + "  " + c.Args().Get(0))
						} else {
							fmt.Println("Hash function '" + hashfunc + "' not found.")
						}
					}
					return err
				},
			},
			{
				Name:            "kdf",
				Aliases:         []string{"h"},
				Usage:           "hash mode",
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
						Usage:    "PBKDF2 - HMAC function",
						Value:    "sha256",
						Required: false,
					},
					&cli.IntFlag{
						Name:     "logN",
						Aliases:  []string{"l"},
						Usage:    "Scrypt - logN",
						Value:    15,
						Required: false,
					},
					&cli.IntFlag{
						Name:     "R",
						Usage:    "Scrypt - R",
						Value:    8,
						Required: false,
					},
					&cli.IntFlag{
						Name:     "P",
						Usage:    "Scrypt - P",
						Value:    1,
						Required: false,
					},
					&cli.IntFlag{
						Name:     "cost",
						Aliases:  []string{"c"},
						Usage:    "Bcrypt - cost",
						Value:    10,
						Required: false,
					},

					&cli.BoolFlag{
						Name:     "raw",
						Aliases:  []string{"r"},
						Value:    false,
						Usage:    "raw output of KDF",
						Required: false,
					},
				},
				Action: func(c *cli.Context) error {
					var err error
					var output string
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
						Cost: c.Int("cost"),
					}
					hashfunc := c.String("a")
					if isPipe() {
						if fn, ok := kdfs[hashfunc]; ok {
							output, err = fn(bufio.NewReader(os.Stdin), params, !c.Bool("raw"))
							fmt.Println(output)
						} else {
							fmt.Println("Hash function '" + hashfunc + "' not found.")
						}
					} else {
						if fn, ok := kdfs[hashfunc]; ok {
							r := strings.NewReader(c.Args().Get(0))
							output, err = fn(r, params, !c.Bool("raw"))
							fmt.Println(output)
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
