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
	sha256, _ := checksum.SHA2sum(file, 256)
	fmt.Println(sha256)
}
```

## Algorithms
### Hash functions
#### CRC's
```
crc32-IEEE
     -Koopman ('k')
     -Castagnoli ('c')
crc64-ISO
     -ECMA ('e')
```
#### Cryptographic Hashes
```
md5
sha1
sha2-224
    -256
    -384
    -512 
sha3-224
    -256
    -384
    -512 
blake2b-256
       -384
       -512
blake3-256
      -384
      -512
```
#### Fuzzy hashes
```
tlsh
ssdeep
sdhash
```
#### Other
```
adler32
fnv-32
   -32a
   -64
   -64a
   -128
   -128a
xxhash-32
      -64
```


### KDFs
```
argon2i
argon2id
scrypt
pbkdf2
bcrypt
crypt-sha512
hkdf
```

## Defaults

See `cself kdf -h`.

## FAQ
* What does `cself` mean?
  * no clue

# License

`checksum` is distributed under the terms of the MIT license. See LICENSE for details.
