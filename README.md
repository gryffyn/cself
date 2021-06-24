checksum
==

Fork of [checksum](https://github.com/codingsince1985/checksum).

Compute message digest, like MD5 and SHA256, in golang for potentially large files.

Usage
--
```go
package main

import (
	"fmt"
	"github.com/gryffyn/checksum"
)

func main() {
	file := "/home/jerry/Downloads/ubuntu-gnome-16.04-desktop-amd64.iso"
	md5, _ := checksum.MD5sum(file)
	fmt.Println(md5)
	sha256, _ := checksum.SHA256sum(file)
	fmt.Println(sha256)
}
```

License
==
checksum is distributed under the terms of the MIT license. See LICENSE for details.
