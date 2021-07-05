checksum
==
[![PkgGoDev](https://pkg.go.dev/badge/git.neveris.one/gryffyn/checksum)](https://pkg.go.dev/git.neveris.one/gryffyn/checksum)
[![Build Status](https://ci.neveris.one/api/badges/gryffyn/checksum/status.svg)](https://ci.neveris.one/gryffyn/checksum)

Fork of [checksum](https://github.com/codingsince1985/checksum).

Compute message digest, like MD5 and SHA256, in golang for potentially large files.

Usage
--
```go
package main

import (
	"fmt"
	"git.neveris.one/gryffyn/checksum"
)

func main() {
	file := "~/Downloads/ubuntu-gnome-16.04-desktop-amd64.iso"
	md5, _ := checksum.MD5sum(file)
	fmt.Println(md5)
	sha256, _ := checksum.SHA256sum(file)
	fmt.Println(sha256)
}
```

Algorithms
--
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
argon2
argon2id
scrypt (tarsnap format)
scrypt
pbkdf2
bcrypt
```

License
==
`checksum` is distributed under the terms of the MIT license. See LICENSE for details.
