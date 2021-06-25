package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"

	"git.neveris.one/gryffyn/checksum"
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

	app := cli.App{
		Name:            "cself",
		Usage:           "generate hashes for files or stdin",
		UsageText:       "cself [OPTIONS] file",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			{
				Name:    "list-hashes",
				Aliases: []string{"l"},
				Usage:   "list hashes",
				Action: func(c *cli.Context) error {
					fmt.Println("Hashes:")
					for k := range hashes {
						fmt.Println(k)
					}
					return nil
				},
			},
		},
	}

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:     "hash",
			Value:    "sha256",
			Usage:    "hash algorithm",
			Required: false,
		},
	}

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "list-hashes",
			Usage: "list hash algorithms",
		},
	}

	app.Action = func(c *cli.Context) error {
		var err error
		var output string
		hashfunc := c.String("hash")
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
