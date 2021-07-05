# cself
[![PkgGoDev](https://pkg.go.dev/badge/git.neveris.one/gryffyn/cself)](https://pkg.go.dev/git.neveris.one/gryffyn/cself)
[![Build Status](https://ci.neveris.one/api/badges/gryffyn/cself/status.svg)](https://ci.neveris.one/gryffyn/cself)

Fork of [checksum](https://github.com/codingsince1985/checksum).

Computes checksum (such as SHA256) from files or `stdin` in Go. Uses chunking to support large files.

Computes key from KDFs (such as Argon2id) with either given parameters or sane defaults.

## Usage
### binary

```
§ cself -h
NAME:
   cself - generate hashes for files, passwords, and stdin

USAGE:
   cself [COMMAND] [OPTIONS]

COMMANDS:
   list-alg, l  list algorithms
   hash, h      hash mode
   kdf, h       hash mode

GLOBAL OPTIONS:
   --help, -h  show help (default: false)
```

### library
```go
package main

import (
	"fmt"
	"git.neveris.one/gryffyn/cself/checksum"
)

func main() {
	file := "~/Downloads/ubuntu-gnome-16.04-desktop-amd64.iso"
	md5, _ := checksum.MD5sum(file)
	fmt.Println(md5)
	sha256, _ := checksum.SHA256sum(file)
	fmt.Println(sha256)
}
```

## Algorithms
### Hash functions
```
md5
sha1
sha256
sha512
sha3-224
xxhash-32
xxhash-64
blake2b-256
blake2b-512
blake3-256
blake3-512
```

### KDFs
```
argon2i
argon2id
scrypt (tarsnap format)
scrypt
pbkdf2
bcrypt
```

## Defaults

See `cself kdf -h`.

# License

`checksum` is distributed under the terms of the MIT license. See LICENSE for details.
