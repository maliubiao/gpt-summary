Response:
The user wants to understand the functionality of a Go code snippet. This snippet appears to be generated code by `go-bindata`, which embeds files into the Go binary.

Therefore, the main function is to provide access to the embedded data files.

Let's break down the code:
1. **`// Code generated by go-bindata.`**: This confirms that the file is auto-generated.
2. **`// sources:`**: This lists the source files that were embedded.
3. **`package zxcvbn_data`**: Defines the package for this code.
4. **`import (...)`**: Imports necessary packages for handling data, compression, and file information.
5. **`bindataRead(data []byte, name string)`**:  This function likely decompresses the embedded data (which is gzip compressed).
6. **`type asset struct { ... }`**:  Defines a structure to hold the byte data and file info of an embedded asset.
7. **`type bindataFileInfo struct { ... }`**: Implements the `os.FileInfo` interface for the embedded files.
8. **`var _dataDvorakJson = []byte(...)`**:  This declares a byte slice containing the compressed data for `data/Dvorak.json`. The `_` prefix suggests it's an internal variable.
9. **`func dataDvorakJsonBytes() ([]byte, error)`**: A function to get the decompressed bytes of `data/Dvorak.json`.
10. **`func dataDvorakJson() (*asset, error)`**: A function to get an `asset` struct for `data/Dvorak.json`, including file info.
11. **Similar structures and functions exist for other files listed in the `// sources:` comment.**

Therefore, the primary function of this code is to embed static data files into the Go binary and provide functions to access this data.
这段Go语言代码是由 `go-bindata` 工具生成的，它的主要功能是将一些静态数据文件（例如 JSON 文件）打包并嵌入到 Go 程序的二进制文件中。这样，程序在运行时就不需要依赖外部的数据文件，所有必要的数据都包含在可执行文件中。

**具体功能归纳如下：**

1. **嵌入数据文件：**  代码中可以看到类似 `var _dataDvorakJson = []byte("\x1f\x8b\x08\x00...")` 的变量声明，这些变量存储了被压缩后的数据文件的内容。例如，`_dataDvorakJson` 存储了 `data/Dvorak.json` 文件的压缩数据。
2. **提供读取嵌入数据的方法：**  代码中定义了 `dataDvorakJsonBytes()` 和 `dataDvorakJson()` 这样的函数，用于读取嵌入的 `data/Dvorak.json` 文件。
    * `dataDvorakJsonBytes()` 函数返回解压缩后的原始字节切片 (`[]byte`)。
    * `dataDvorakJson()` 函数返回一个 `asset` 类型的指针，该类型包含了解压缩后的字节数据以及一个实现了 `os.FileInfo` 接口的 `info` 字段，提供了关于嵌入文件的元数据（例如文件名、大小、修改时间）。
3. **数据解压缩：** `bindataRead` 函数负责解压缩嵌入的字节数据。它使用 `gzip.NewReader` 来创建一个 gzip 解压缩读取器，然后将压缩后的数据读取到 `bytes.Buffer` 中，最终返回解压缩后的字节切片。
4. **提供文件元数据：** `bindataFileInfo` 结构体实现了 `os.FileInfo` 接口，为嵌入的文件提供名称、大小、模式、修改时间等信息，虽然这些信息在嵌入时就已经确定。

**可以推理出这是 `go-bindata` 工具实现的嵌入静态资源的功能。**

**Go 代码示例：**

假设我们想在程序中使用嵌入的 `data/English.json` 文件。

```go
package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/alecthomas/gometalinter/_linters/src/github.com/nbutton23/zxcvbn-go/data" // 假设你的项目结构是这样的
)

func main() {
	englishData, err := zxcvbn_data.DataEnglishJsonBytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(englishData[:100])) // 打印前100个字符
}
```

**假设的输入与输出：**

* **输入：** 无，因为数据已经嵌入到程序中。
* **输出：**  会打印出 `data/English.json` 文件的前 100 个字符内容（解压后）。由于 `data/English.json` 的内容很长，这里只展示一部分可能的结果：

```
{"adjacency_graphs": {"keypad": ["123", "147", "2135", "258", "3216", "369", "4175", "456", "52468", "5468", "6359", "6549", "7418", "789", "85790", "8790", "9683", "987"], "mac_keypad": ["123", "147", "25", "326", "4175", "52468", "6359", "748", "8570", "960", "089"], "qwerty": ["`1234567890-=", "1qaz", "12qs", "23wqde", "34erfc", "45tgbv", "56yhn", "67ujm", "78ik,", "89ol.", "90p;/", "0-=[", "-_=+", "qwertyuiop[]\\", "aqwsz", "qwertya", "wersdf", "ertdfg", "rtyfgh", "tyughj", "yuihjk", "uiojkl", "iopkl;", "op[]l'", "pasdlz", "asdfgzx", "sdfghxcv", "dfghjvcb", "fghjknvb", "ghjkmnb", "hjklm,n", "jkl;m.", "kl;'/,", "zax", "xcv", "vbn", "bnm", "m,."]}, "frequency_lists": {"english": ["the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "say", "her", "she", "or", "an", "will", "my", "one", "all", "would", "there", "their", "what", "so", "up", "out", "if", "about", "who", "get", "which", "go", "when", "me", "make", "can", "like", "time", "no", "just", "him", "know", "take", "people", "into", "year", "your", "good", "some", "could", "them", "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think", "also", "back", "after", "use", "two", "how", "our", "work", "first", "well", "way", "even", "new", "want", "because", "any", "these", "give", "day", "most", "us"]}}
```

**命令行参数处理：**

`go-bindata` 是一个独立的命令行工具，它不涉及这段 Go 代码的运行时参数处理。 `go-bindata` 的命令行参数用于指定输入文件、输出文件、包名等配置。例如：

```bash
go-bindata -pkg=zxcvbn_data data/Dvorak.json data/English.json ...
```

这个命令会读取 `data/` 目录下的 JSON 文件，并将它们嵌入到名为 `zxcvbn_data` 的 Go 包中，生成类似于你提供的代码。

**使用者易犯错的点：**

1. **直接修改生成的文件：**  注释 `DO NOT EDIT!` 已经明确指出不要手动编辑此文件。任何修改都会在下次运行 `go-bindata` 时被覆盖。如果需要修改嵌入的数据，应该修改原始的数据文件，然后重新运行 `go-bindata`。
2. **路径问题：**  在代码中使用嵌入数据时，需要使用 `go-bindata` 生成的代码中提供的函数名，这些函数名通常基于原始文件的路径和名称生成。如果文件路径或名称发生变化，需要重新生成代码并更新调用方式。
3. **理解 `asset` 类型的使用：** 虽然可以直接使用 `...Bytes()` 函数获取字节数据，但 `...()` 函数返回的 `asset` 类型包含了 `os.FileInfo`，如果需要获取嵌入文件的元数据，则需要使用 `asset` 类型。

总结一下，这段代码的主要功能是**将静态数据文件嵌入到 Go 程序中，并提供方便的接口来访问这些数据，避免了程序运行时对外部数据文件的依赖。** 它是 `go-bindata` 工具的输出结果，实现了资源嵌入的功能。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/nbutton23/zxcvbn-go/data/bindata.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共43部分，请归纳一下它的功能

"""
// Code generated by go-bindata.
// sources:
// data/Dvorak.json
// data/English.json
// data/FemaleNames.json
// data/Keypad.json
// data/L33t.json
// data/MacKeypad.json
// data/MaleNames.json
// data/Passwords.json
// data/Qwerty.json
// data/Surnames.json
// DO NOT EDIT!

package zxcvbn_data

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _dataDvorakJson = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb4\x98\x57\x57\x1b\x41\x0c\x85\xdf\xf9\x15\xb0\x74\x30\xbd\xf7\xde\x7b\x6f\xa6\x77\x30\xbd\x17\xf3\xdb\x33\x26\x39\x99\xef\x9e\x78\x96\x7d\x88\x5e\x72\xc6\x61\xf9\xa4\x95\xae\x34\xd7\x7c\x14\x14\x16\x46\x63\xf7\xfb\xb7\x67\x51\x67\x61\xee\x83\xfb\x58\xef\x8e\x5b\xdf\x47\xf7\xa1\xa3\x22\x4a\xfd\x39\x5f\x3f\x65\x32\xf9\xce\xd1\xd6\xc7\xdf\x67\xa2\xcc\xb4\x3f\xdf\x2f\x46\xdf\xc7\xed\xdf\xff\x13\x35\x10\xbc\xf7\xf5\x33\xb8\xb1\xdf\xc3\xca\xd3\x91\xfc\x82\x90\x1b\x49\x6e\x28\xfa\x99\xdc\x54\xec\xc9\xa9\x6e\x8d\x22\xe4\x26\x92\x91\x4f\x90\xdc\x5c\xe2\x69\xb5\xbd\x12\x45\xc0\xcd\x04\x23\x9d\x20\xb8\xa5\xd4\xc3\x6e\xe7\x25\x88\x80\x5b\x08\x46\x36\x41\x70\xeb\x8e\x87\xbd\x6d\x48\x10\x01\xb7\x12\x8c\x6c\x82\xe0\xb6\x32\x0f\x3b\x19\x95\x20\x02\x6e\x23\x18\xd9\x04\xc1\xed\x55\x1e\x76\x3a\x26\x41\x04\xdc\x4e\x30\xb2\x09\x82\xa1\xf6\xe8\x70\x48\x82\x08\xb8\x83\x60\x64\x13\x04\xd7\x57\xca\x58\x30\x88\x80\x8b\xcc\x46\xc4\xfd\xcc\xa3\x05\x81\x79\x11\x1c\xe7\x62\x7f\x20\x4c\x2e\xb6\x1a\x91\x12\xab\x11\x29\xb5\x1a\x91\x32\x2b\x25\x97\x5b\x35\xaf\xc2\x4a\xc9\x95\x56\xb7\x48\x95\xd5\x50\x57\x13\x5c\xd7\xe7\x1f\xdc\xce\xe6\x0d\x12\xa5\xd3\x9f\xf9\x7f\x50\xb3\xab\xe4\x14\xc9\x9c\x52\x69\x19\xef\x24\x8e\xc5\xcd\x9c\xb4\x52\xc8\x35\x24\x3f\x2c\xf9\x07\x99\x7f\x4f\xf5\xcf\x45\x7a\xdf\x54\x70\x2d\xc1\x14\x13\xb3\xe4\x20\x73\xde\x8e\x47\x24\x7b\x01\xd7\x11\xcc\x3e\xb3\xff\xa8\x38\xb3\xcf\x15\x36\x85\xb7\x15\x70\x67\x68\x44\x20\x7f\xa9\xe5\xdd\x42\xb0\x2c\x02\xee\xb2\x02\x77\x9b\xc9\xa2\xc7\x4c\xca\xbd\x56\xba\xe8\xb3\xd2\x45\xbf\x99\x37\x1c\x08\x09\x43\x7a\x49\x04\x7b\xd6\xd5\x19\xde\xca\x83\xcc\xf9\x75\xdd\xff\xd2\xd1\xb0\x3f\x9f\x8d\xfb\xf3\xd5\x4c\x32\xc9\x0d\x11\xcc\x0b\x87\x17\x11\x17\x26\x57\xfc\xe3\xb2\x04\x17\xf0\x30\xc1\xe7\x13\xf9\x8d\x1f\x03\x32\xfb\x83\x41\x7f\x76\x6f\x2b\xe0\x11\x82\x59\x3f\xce\x02\x45\xf6\xb4\xe2\xcf\x17\x93\x32\x95\x02\x1e\x25\x98\x97\x3a\x2f\x7b\x5a\x58\x66\xcf\x3e\xb8\xb7\x15\xf0\x18\xc1\x7c\x7d\xc2\x58\x6f\x5e\x4a\x2c\x8b\x0b\x22\xe0\x71\x82\x99\x01\x33\x23\x8c\x0d\x83\x42\x72\xf5\x16\xf0\x04\xc1\xac\x1f\xcb\xc2\x37\x61\x70\xca\xf3\x72\x4a\xc1\x93\x04\x63\x2d\xca\x26\x60\x40\x07\x48\xa4\xe3\x29\x82\xd9\x65\xc2\x28\x43\x64\x19\x0b\x9e\x26\x98\xe2\xa7\xef\xe1\x4a\xe2\x76\xe5\x05\x7c\x3d\xab\xa5\x98\x21\x98\x82\x67\xc7\xd9\xb0\x97\xb5\x64\x19\xcf\x12\x4c\x00\xb3\xe7\x42\x65\x96\xcf\xab\x12\x50\xc0\x73\x04\xf3\xae\xe3\x46\xe3\x14\xb2\xa9\x6c\xb6\xdb\x74\x02\x9e\x27\x98\x00\xde\x1b\xf4\xf2\x94\x21\x1b\xec\x02\x0a\x78\x81\x60\xec\x57\xd9\x1b\xcc\x12\xca\x89\xad\xf1\x22\xc1\x9c\x30\xae\x4a\x2a\x84\xf5\x76\x4a\x60\x83\x05\xbc\x44\x30\x1f\x24\x80\x12\xe3\x4d\xe7\x3c\x1b\x1b\x29\xe0\x65\x82\x29\x31\x66\x4f\x85\x30\x38\xa4\x97\xdb\x1b\x02\x5e\x21\x98\xb5\xe4\x0e\x66\xc3\x38\x85\x18\xef\x5c\xed\x05\xbc\x4a\x30\x33\x60\x66\xd4\x2e\x5e\x3f\xb6\x79\x6b\x04\x73\x0d\x72\x58\x18\x04\x43\x11\x0b\x5e\x27\x98\xaf\xc6\x57\xe6\xaa\xc4\xd8\xc7\x82\x37\x08\x66\x5d\x39\x14\xbc\xa6\xb8\x9b\x19\xdc\x0d\x8b\x80\x37\x09\xe6\xec\xb3\xae\x90\x58\xc8\x23\xfd\x93\xf1\x16\xc1\x18\x84\xa0\xc9\xa2\x93\xa3\xbe\x9d\xee\x05\x9c\x4e\x93\x9c\xe0\x9b\x4c\xe2\x94\xb7\x09\xc6\x46\x4f\x02\x13\xf3\xe9\xd2\x17\xf0\x8e\xd5\xdf\xc9\x76\xad\xbe\xec\xed\x05\x8c\x6c\x10\x10\x63\xa3\x05\xbc\x6f\xe6\x90\x0f\xac\x1c\xf2\xa1\x95\x43\x3e\xb2\x72\xc8\xc7\x56\x0e\xf9\xc4\xca\x21\x9f\x5a\x39\xe4\x33\x2b\x87\x7c\x6e\xe5\x90\x2f\xac\x1c\xf2\xa5\x95\x43\xce\x58\x39\xe4\x2b\x2b\x87\x7c\x6d\xe5\x90\x6f\xac\x1c\xf2\xad\x95\x43\xbe\xb3\x72\xc8\xf7\x56\x0e\xf9\xc1\xca\x21\x3f\x5a\x39\xe4\x27\x2b\x87\xfc\x6c\xe5\x90\x5f\xac\x1c\xf2\xab\x95\x43\x7e\xb3\x72\xc8\xef\x56\x0e\xf9\xc3\xca\x21\x7f\x5a\x19\xe4\xac\x95\x41\xfe\xfa\xef\x76\xd3\xfd\x9b\x2d\xc8\x16\xfc\x0a\x00\x00\xff\xff\xd5\xc4\xca\x21\xce\x20\x00\x00")

func dataDvorakJsonBytes() ([]byte, error) {
	return bindataRead(
		_dataDvorakJson,
		"data/Dvorak.json",
	)
}

func dataDvorakJson() (*asset, error) {
	bytes, err := dataDvorakJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "data/Dvorak.json", size: 8398, mode: os.FileMode(420), modTime: time.Unix(1452717629, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _dataEnglishJson = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x5c\xbd\x4b\x9a\xe3\xca\x0e\x34\xb6\x15\x7f\x9a\xf4\xe4\xae\xc0\x6b\xf0\x0e\x3c\x4a\x92\x29\x31\x4b\x24\x93\x87\x0f\xa9\xd4\xde\xbc\x81\x88\x40\x52\xfd\x0f\xee\xed\xea\x3e\x55\x2a\x32\x1f\x78\x04\x02\x81\xff\xef\xf6\xff\x94\xfd\xb8\xfd\xdf\xff\xef\xff\x75\xfb\xd4\xf3\xf6\xbf\x5b\xb1\xff\x1d\xd5\xff\x6f\xcc\xf6\xff\xc9\xff\xb7\x0c\xf8\x7b\x3a\xfc\xbf\xfb\xff\xd5\xbb\xfd\xdf\xec\xff\xfd\xad\x7f\xdd\xfd\xff\x16\x7c\x1b\xbe\x7e\x2e\xf5\xed\xff\xf4\x67\xb6\xff\xbf\xd7\xcd\xfe\x7f\xf1\x4f\x1d\xd3\xcb\x7f\x6c\xfe\xd8\xff\x0d\x75\xf9\xe3\x3f\xfc\x73\xee\x07\xfe\xfb\x81\x7f\xb4\xff\xeb\xfc\x7b\xaa\x7f\x9c\x3d\x94\xff\xec\x3b\xf9\x87\xbe\x33\x1e\xe0\x0f\xbe\x2e\xc7\x68\x7f\xec\xf8\xf6\xd3\x7f\x32\x4d\x13\xbe\x07\x7f\xa4\xcd\xbf\x17\xaf\x50\xfd\xfb\x52\x57\xf1\x4d\x5b\x79\x8c\x07\x3f\xf7\x0f\xbe\xe5\x91\x0f\x7c\x23\xfe\xc2\xef\x79\xd4\xb2\x3c\xec\xcf\xa9\x3c\xfd\x1f\x3f\x39\xf9\x27\x94\x3b\xbf\xcf\x7f\x29\x3e\xb7\x4f\xfe\x80\xe7\x8a\xc7\x5b\x0e\xbe\xfb\xf2\xd4\x52\xe1\x21\xb9\x08\x0f\xbc\x78\xf1\x95\xc0\x62\x8d\xfa\x57\xfe\x88\x7e\xf3\xe2\xff\x3f\x94\x01\x6b\xea\xab\xb3\x67\xfc\x92\x8a\x65\x7e\xd4\xca\x3d\xc8\xfe\x9f\xb6\x6c\xef\xea\x5f\x70\x55\xea\x39\xf9\x7f\x9c\x6a\x7d\xe2\xa7\x33\xf6\xa1\x70\x7f\x0a\x96\xa3\x3e\x93\x7f\x7f\x97\xfa\x27\x9f\x1c\x0b\x3f\x67\xbc\xc2\xc1\x25\x2b\x7f\xf0\xc7\x7d\xab\x33\xde\xf4\x83\xd5\xd4\x3a\xe2\x75\x7a\xfd\x26\x7b\x4c\x7e\xc0\x27\xef\x78\xb5\x1d\x7b\x86\xdf\x8b\xad\xde\xed\xa9\x7d\x31\x1e\x78\x1e\xee\x68\x9f\xce\x3d\xeb\xbf\xe1\x20\xe8\x85\xfc\x87\x76\x3c\x1d\x1e\xff\x48\x58\x74\x3c\xd8\x1b\xff\x7c\xee\xd8\x8b\xe3\x98\x70\x72\xf8\xdf\x97\x9c\x07\xac\xcb\xb2\x24\xfc\xf5\x85\x9d\x79\x67\xee\xea\x51\x2b\xf7\x09\xcf\x5d\xfe\xe0\xd0\xed\x27\xff\xdb\x98\xfd\x05\xe7\xca\x85\xe7\x0f\xf2\x98\xed\x75\xdb\x3e\x5c\xc3\x2d\x4e\x37\x3e\x61\xca\xb1\xbf\xfe\x4a\x09\x3f\x9f\x3e\x38\xa6\x43\x7d\x2f\xf8\xeb\x82\xb7\xf2\xef\x3e\xfd\xbc\xd8\xe7\x62\xc9\x3f\xb1\xcb\xf8\xa0\x7d\xd4\x1a\xa6\xe5\x13\x1f\xb7\x27\x6c\xfb\x7c\xf6\x23\xff\x03\xde\xf7\xee\x1f\x6e\xaf\x85\x45\xbd\xdf\xf1\x9b\xf8\xfd\x76\xbc\x70\xcc\x1e\xe5\xc5\xa3\x33\xf1\x77\xd4\x93\x67\x7b\xcc\x93\x1f\xca\xe3\x8d\x6b\x9c\x26\xff\xde\x35\xd7\x75\xe2\x49\xf2\xdf\xb5\x1f\x3c\x17\xef\x84\xfb\x5c\x16\x5c\xf9\x7b\xc1\x4d\xb7\x8b\x18\x2f\xfa\x48\x71\xa9\x97\x87\xd6\x01\xaf\x31\xd4\xbc\xf3\x08\xf4\xbc\x76\x47\xc5\x5b\x3d\xec\x68\x1e\xd8\xee\x3b\x97\xb7\xcb\xc7\x81\x05\xd6\x06\x2d\xba\x7f\xfe\x0e\xfe\x0b\xb8\xc5\xf7\xb2\xed\xfc\xb1\xa9\x64\xbe\xd4\xc1\xab\x76\xcf\x79\xd2\x4f\xb7\xf5\x7a\xd7\xcd\x5f\xc9\xaf\x30\xbe\xd7\x1e\x1b\x27\x8a\x07\x2b\xdd\xf9\x0b\xa7\xb4\xeb\x82\xe1\xd8\x0d\xf8\x45\xcf\x9c\x57\x3d\xbe\x2f\x0a\xed\xc6\x56\xcf\x85\x8b\x52\x57\x5d\x32\x9e\xa2\xf2\x07\xef\x74\xfa\x4f\x16\xbd\x6f\x9a\xec\x91\x79\x22\xf7\x23\xf3\x94\x2e\x07\x0e\xe3\xbc\xf1\xbb\x71\x27\x70\x06\x6c\x4f\xf0\xcb\xbb\x02\x7b\x82\x1b\x3f\xa6\x75\xcd\x4b\x1e\x62\x23\x79\x85\xf9\xe1\xc7\xf6\xe1\x2b\x3e\xb9\x13\xef\xad\x6a\xc7\x37\xdf\x5c\x6d\x27\xbf\x65\x4e\x03\x2f\xc2\x1b\x0b\xc7\x7f\x7c\x9c\x79\xe7\x95\xc4\xd6\x70\x0b\x70\xd3\x66\xdc\xea\x2d\xcf\x79\xee\xb0\x3e\x66\xf8\x0e\xad\x67\xfe\xa3\x3d\xb4\x7f\xe3\xb2\x0f\xf8\x99\x29\xd3\x5a\xaf\x53\xea\xfd\x4f\x5b\xa6\x6c\x1b\x45\x7f\x00\xb3\xa3\x35\xe9\x8f\x53\x16\x69\xcc\x69\xc3\xef\xc4\xb9\x5f\x0a\x7e\xee\x9e\xf4\xb1\x79\xa2\x09\x38\x92\xec\x3f\x2e\x59\xd2\xd2\xda\x37\x15\xff\x2e\x33\x33\x1b\xbe\x6f\xd6\x61\x99\xb9\x1a\x59\x57\x2a\x2f\xb1\x18\x1b\x7f\x25\x9e\xbe\x4f\x73\x98\x17\x7e\xae\x9f\x0f\x1a\x3f\x5c\xd0\x7b\x9a\xcb\xc4\xcb\x5d\x27\x9a\x98\x38\x64\x76\x73\x76\xfd\x84\xfd\xe2\xc9\xef\x5a\x19\x32\x5c\xdf\xfe\xc4\xea\xe2\x28\xcd\xf4\x53\x66\x92\xb9\x6e\xb5\x99\xdd\x38\x97\x34\x02\xef\xb1\xe0\x26\x9b\xe3\xd8\x7c\x33\xb6\x8a\xb5\x9f\xf2\xdd\x7f\xfc\xc9\x1d\x3b\x6a\x5c\x05\xb7\xe6\x78\x70\x18\x90\xba\x62\x57\xf5\x32\xfc\xe3\x9d\xe1\x5e\x4e\xd8\xe5\x79\xd6\x21\xf2\x77\x59\x37\xdb\x45\x78\x8b\x04\x9f\x52\x36\x7c\x54\xa1\x97\x82\x9f\xb9\x6f\x25\x63\xf9\xd2\x64\xbf\x69\xe0\x37\xeb\x98\x2d\xf9\x97\x0b\xbf\xc1\xd9\xfc\xd4\x0e\x9f\x59\xbb\x89\x26\xb2\x2c\xe7\x81\x0d\xd4\x0d\xb1\x9b\x37\xf1\xe0\x9a\xa3\xe3\x47\xb8\x43\xe7\xf6\xf9\xd6\x0f\x78\x85\x05\xbe\x63\x4e\xba\xfa\xf3\x47\x8b\xda\x5f\x47\x26\xff\xda\xa1\xe1\x89\x49\x2f\x19\x9b\x51\xbf\x3c\x75\xfa\x0f\x7e\x51\x78\x3e\x71\x0c\xc7\x73\x83\x91\xa8\xb0\xab\x15\xfe\xdf\xd6\x1a\x9b\x69\xdb\x45\x7f\x70\x1c\xd8\xb7\x89\x67\x60\x2f\x0b\x4e\x60\xfe\xed\xcf\x38\x7a\xf8\x90\x27\xed\xdf\xc8\x47\xf6\xa3\x82\xf7\xaa\x34\x13\x3d\x0e\x71\x2c\xd7\xb9\x98\xb5\xbc\x31\xe4\x60\x84\xe0\x57\x1e\xd7\x8c\x47\xc0\xfe\x0a\x2f\xf4\x81\x97\xd8\xe9\x08\x07\x6e\xeb\x41\xaf\x5c\xf9\x1c\x0f\x3e\x96\x1b\x4d\x9a\x8c\xba\x2d\x72\x02\xe7\xba\x9a\xb1\x18\xda\x8e\xed\x5c\x52\x1a\xa6\x13\x0e\x60\xae\x38\x80\x27\xbf\xed\x2d\x67\xb5\xe7\xbe\x62\x77\x56\xbe\xda\x44\xb7\x70\x6c\x27\x23\xa4\x7e\xac\x15\x8e\x9d\x97\xd8\x0c\x33\x63\x1e\xfb\x06\x98\x87\xd3\x16\x89\x56\x23\x27\x9c\xdb\xcb\x53\xe3\x48\x7a\x28\xe7\xff\xf5\xce\x73\x6b\xb7\x4d\xc7\x9d\x2e\xca\xae\x13\x5c\x02\x7f\xa6\x37\x93\x86\x5f\xb3\x9d\xf0\x8a\xf5\xc5\xab\xf6\xe1\x8b\xaf\x66\x3f\xf0\xa1\xdd\x27\x2e\x6b\x57\xb1\xc8\xc3\xa6\x23\x84\x25\xa4\x2b\x9c\x0b\x1e\x6b\x4e\x9b\xad\x08\xde\xd0\x3c\x20\x5e\x31\xe9\x64\xa5\x30\x86\x19\xaf\x64\xbf\x87\x0e\x65\xa6\x17\x5d\x47\xfe\x5a\xdb\x49\xfe\xda\x21\xcd\x0b\xee\x2c\x16\xd2\xaf\x2e\x42\x97\x8d\x9f\xd2\x27\xbc\xc3\x71\x6e\x38\x76\x65\x87\x91\xa9\xb6\x49\x1b\xae\xd2\xb3\x60\x57\x6c\xe1\x68\x08\xc6\xcc\x70\xca\xde\xf9\x81\x53\x86\x6d\xf0\x87\xe3\xb3\x28\xc4\xb8\x73\x43\xcc\x9a\xd2\x23\xd1\x1e\x99\x71\xd6\xbd\x49\xdc\x4c\xbd\xca\x87\x16\xd4\xe3\x1c\xfc\xb2\xeb\x15\xd3\xc2\x87\x0d\xb3\x65\x66\x99\xf7\x84\xbf\x0f\x61\xe6\x4e\xe7\xd4\xe5\x74\x1e\xe5\x7e\xfa\xbe\x3f\x68\xc4\x6d\xfb\xf1\xd0\x5b\xfa\xfb\xd1\x61\xc1\xe9\x61\x40\xcf\x9b\x96\xee\x1b\x63\x11\x73\xdb\x6f\x1e\xe3\x32\xaf\x75\x3b\x18\xdf\x6e\xb4\x83\x77\x6c\xed\xb3\xe8\x10\xf2\x06\x1c\xd8\xb1\xc7\x94\x9a\xa5\x56\x48\xcb\x07\xda\xdd\x5b\xe2\xbd\x60\x53\xf6\xf8\x26\xed\x7e\x57\x68\x59\x4f\x06\x29\x76\xa6\x7c\x51\x72\xd1\x9b\xce\x1b\x0f\x60\xd6\xd1\x1b\x92\x87\x3a\x8c\xf8\x18\x4c\x67\xdc\x47\x33\xd7\x38\x27\x70\x54\x58\xab\x9c\x10\xfd\x58\x4c\x5b\x18\x06\x54\x06\xa8\x38\x2e\xfd\x44\xf7\x3c\xd2\xa3\xd9\xfe\xf8\xb3\xfc\x67\x3e\xf4\x28\x38\x2e\x87\xce\xdd\x3d\x31\x09\x41\x28\xe5\xa1\xe7\xce\x37\x61\x38\x19\xde\xc8\x22\x6e\xc4\x46\xe5\x7e\xb7\x70\x6f\x09\x33\x93\x69\x14\xf7\xb5\x98\xf3\xe6\xc1\xd0\x5b\x9b\x45\x96\x0f\x78\xe7\x61\x90\x1d\x18\x19\x94\x74\x34\x6b\x45\xb7\xe6\x9e\xb1\x7b\xe1\x7c\x3d\x2d\xa0\x9f\xe7\xbf\x56\x58\x82\x8f\x2f\x1a\xfc\x83\xc7\x75\x5a\xaa\xb2\x2c\x58\x0b\xc4\x72\xb1\x7f\xb8\x1d\xe3\xb9\x77\x49\xae\x41\xa6\x65\xc5\x89\xb2\x83\xf6\x66\xf4\xc5\xb0\xd8\xc2\x4f\x3a\xf2\xcc\x80\xdf\x3c\x18\xd2\x01\xb3\xbd\x30\x4f\xe3\x65\xd7\xc7\x04\x4b\xbf\x97\xa1\x39\xd4\x1b\x82\x0f\xae\xc7\x3e\x31\x00\xdb\x68\xd8\xde\x57\x5c\xec\x76\x99\x26\x91\x19\x81\x7b\x1c\xfc\x87\xca\x87\x5d\x0b\xee\x1a\x32\x0b\x2d\x34\x7c\x54\x97\xf9\x02\x48\x04\x07\x5e\x85\x89\x3b\x63\xf7\x83\x2e\x95\x0f\xf1\xb5\xd9\xf8\xe0\xbc\x95\x7a\xf2\xb2\x8c\x0c\x30\x6c\x7d\xf8\xdc\x63\xc1\x8e\x26\xd9\x5f\xbb\x0a\xc8\xac\xaa\x1f\x2b\x5e\xaa\xbb\x36\x6e\xe5\x9d\xee\xb1\x69\xff\x9d\x05\xbf\x7f\x39\x15\x63\x8d\x8a\xac\x76\x3e\xbc\xa5\xae\x13\x6f\x24\xdc\x3a\x43\xe5\xa5\xea\x34\x3c\x18\x94\xba\xeb\x62\x56\xc0\xa4\x25\xe7\x19\x87\xbf\x2c\x0a\xb1\xdc\xbe\x33\x68\x0c\xb3\x78\xae\x3a\xcf\x69\xc3\x77\xcc\x99\x7e\x12\x9e\xa7\xdb\x22\x2f\xf0\x8f\xc2\x12\xd2\xc6\xa6\x3b\xd7\x4a\xee\x17\xbb\xb9\xc9\xe1\x86\x6d\xf2\x08\x90\xff\xd9\xd2\x42\xee\xe0\x58\x69\x3a\x5f\x5c\xf8\x5d\xe6\xc9\xec\xbd\x3c\x59\x3f\xd1\x82\xd9\x12\x31\xe1\xe2\x4f\xdc\xf3\x84\x9f\x2f\xbf\x58\x36\xbf\x20\xb8\x2d\x1b\x73\xe6\xd4\xed\x75\x32\xcb\x40\xd7\x5f\xdf\x4c\x33\xd2\xa0\x8b\x52\xb4\x18\x0b\x03\xc3\x4c\x83\xc4\x10\x01\xbb\xb9\xe6\xbe\xe0\x7a\x75\x7c\xf9\x89\x19\xb3\x9d\xf9\x3f\xbc\x88\x71\xc1\x26\x5c\x29\xdb\xc5\xe9\x46\xbf\xa1\x7b\xc2\x87\xb6\x35\xd2\x3d\x54\xc8\x73\x4f\xe7\x44\x97\x4f\x7b\xa3\x98\xbf\xf2\x98\x76\xc8\x0d\x66\x5b\x9a\x71\xd7\x51\xe3\xc3\xc0\xec\x4c\x8c\x1f\x7e\x72\xe4\x50\x4f\x5e\x9b\xcd\x8c\xe1\x8c\x4c\x51\x5b\x6f\x46\x54\x59\xe8\x11\x27\x30\xe1\x29\x2c\x24\xd8\x0b\x4d\x81\x6d\xf7\x2e\x44\x60\xa5\x77\x33\x93\xa6\x6c\xb9\x02\xe3\xf0\x93\x8d\x6f\xb5\xdf\x4f\xc8\xa6\x1e\x3a\x33\x8f\xb6\xcb\xf6\xa8\x1b\xc2\x81\x76\xf5\xe0\x5e\xd3\x43\x7e\x72\x2a\x7f\x71\x77\xcc\xd6\xdb\x93\x30\xee\x5c\x26\xc6\x07\x7b\xfe\xe5\x26\x20\x4b\x34\x33\xc8\x2c\xc6\x9e\x01\xbe\x95\x87\x71\xf7\xb4\x63\xe0\x8d\x3d\x94\x71\x9b\xe1\xd4\x69\x61\x6e\xb4\x0c\xfc\x16\x7a\x4e\x19\x34\x33\xfd\xda\xfe\xfc\x6b\x57\x17\x89\xa7\xbb\x38\x3d\x78\x36\x2f\x54\x98\xea\xee\xe5\x81\xc5\xaf\x70\x2d\x5b\x36\x8f\x6b\xf6\x7a\x1f\xcb\xaa\x93\x89\xdf\x92\x10\x05\x4f\xf1\xf3\x63\xa5\x0d\xf3\x18\x41\xe9\xfd\xfd\xd4\x03\xbe\x2d\xf1\x80\xeb\x3e\x69\x64\xe2\xde\x7a\x24\x80\xc7\xf3\x18\x08\x9b\x58\x19\x99\x3c\x19\x99\x98\x33\x85\xa5\x09\x97\xe1\xff\x56\xbb\x97\xdb\x15\xa6\x1a\x55\x8e\x68\xe5\xeb\x78\xdc\x17\xc7\x6b\xce\xf1\x18\x9e\xdd\xb9\x13\xdb\x0f\xf3\xbe\xbc\xaa\x3d\x03\xcb\x3b\xad\x8b\x3b\x59\xd8\x00\x9e\xe9\x45\x9e\x75\xe3\xa5\x90\x5b\x44\xb0\xe0\xa9\x2b\x13\x7b\x8b\x27\x68\x4e\x13\xa3\xc4\x49\x9f\x3c\x6c\x48\x72\x7b\x0b\x59\x2b\x8d\x02\xf6\xb8\x2f\x07\xa3\xb0\x0c\x70\xc3\x1c\xe6\x41\x8f\x73\x78\xf2\x81\x98\x78\xe2\xee\xed\xe7\xb6\x6e\x74\xa6\x05\x37\xd8\x7c\x85\xa7\x8d\x8c\xdc\x56\xfa\x57\x8f\xac\xf4\xeb\xe1\x59\x7f\xfb\xbc\x02\x5a\x43\xe8\xf0\xf9\x23\x78\x70\x50\xb0\x78\x28\xd8\xb1\xeb\xbc\xf9\x3d\x86\x15\xcd\xba\xd3\xda\x72\x4b\x31\xe5\x95\x3b\x1c\x4d\x26\xf0\x8c\xe2\xcb\xac\x0c\x63\x8c\x5c\x92\xc1\x8e\xad\x02\x63\x60\x5b\xe9\x32\x10\x71\x98\xd3\x5f\xc1\x28\x58\x08\x07\x51\x16\x9e\x39\xbe\xf0\x16\xc9\x6a\x59\x5e\x75\xa2\x95\xb3\x57\x84\x75\x58\x4b\xee\x15\x33\x63\x4d\x91\x74\x0d\xf6\x94\xbc\x09\x34\x47\x0a\xd7\xea\xab\xf0\x68\x21\xb3\xe8\x15\x20\x59\x88\xb3\x30\x6d\xd5\x9d\x32\xdf\x6e\x3f\x46\x17\x08\xd7\x78\x17\x8e\xe9\x3f\x20\x30\x80\x6b\x37\x98\x75\x97\xad\xaa\x8c\xbf\xf1\x3e\x85\x19\xec\x82\x75\x67\x7c\x9d\x26\x3d\x00\xdf\x93\xa9\x4e\x1a\x66\x04\x0b\x4a\xef\x70\xf3\x4f\xd9\x9d\x91\x0f\x99\x5f\xc8\x73\x86\x6c\xce\xa6\xe8\x2e\xfa\xe9\x22\xb8\x6b\x89\xc3\x1c\x5b\xe0\x71\x35\x8e\x66\x46\x1c\x6f\x3e\xe6\xc9\x84\x7d\x67\x6e\xe2\x3e\x8c\x40\x42\x9d\x26\x66\xc1\x47\xe1\x9d\x77\x48\x4b\xa9\xe3\xc9\x7c\x19\xbe\x5f\x5e\x84\xdf\xb2\xf8\x37\xdf\x10\x7f\xe1\xb0\x4e\xa7\x27\xa6\x8b\xa5\x7a\x3c\x81\x48\x95\x78\x9f\xfc\xb4\x96\x39\x3d\xe8\xf2\xef\x5c\x8e\x3e\xc9\xe5\x75\x93\x12\xe9\x63\x63\x86\x60\xe7\x48\xbf\xea\x9e\x5e\x58\xb2\xe4\x91\xb0\xc2\x13\x47\x1e\x70\xe8\xb3\x99\x44\x9a\x5d\xf7\x66\x48\x19\xec\x04\x2c\xba\x58\xb8\x8b\x5b\xda\x4b\x66\x9a\x38\xa5\x5f\xbc\xbc\x5d\x6e\xac\x4e\xea\xfb\xb0\x9d\x6f\x1a\x68\x5b\x74\x3a\xb0\x99\xd7\xc4\x02\x98\x9d\x26\xd7\x97\x4c\x0f\x64\x89\x59\x15\x1a\x97\x3d\xd4\x96\x75\xe5\x73\x2c\xdd\xbe\xe2\xec\x0b\x11\x9e\x2b\xd3\x3b\xbb\x30\x8f\x85\xde\x70\x36\x1f\x87\xef\x6d\xe9\xcc\x96\x19\xad\xec\xa3\x50\x3a\xde\xee\x8d\x3e\x86\x0e\x9a\x01\x4e\x12\x62\x40\x9b\x70\x30\x5e\xb9\xdb\xe6\xe1\x9e\x9a\x95\xc6\x99\xf5\x00\x52\x21\xd1\xc6\x50\xc7\x31\xb3\x95\x9b\xa6\xe0\x63\x13\x74\xbb\xdd\x14\xae\x5e\x6f\x47\x7b\xf5\x93\x98\x4d\xdb\x0f\x5c\x60\x97\x47\xae\xd3\xb9\xf0\x8e\xb8\x7f\x2c\xf8\x98\x2c\xab\xf5\xb0\xed\x33\x2f\xc4\x14\xfa\xa0\x0f\x1e\xeb\xca\x9f\xb7\x2c\x2f\x77\x11\x8a\xef\x8c\x68\xed\x15\xb1\xbc\x6b\x5a\xe9\xb6\x1b\x7e\xb6\x0a\x06\x38\x72\x5c\xc7\x1b\x5c\x49\xc3\x49\x6c\xaf\x4e\x38\xab\x07\x51\x91\xae\x98\x11\x21\x2e\xb0\x0b\x8f\x85\x9d\x25\x26\x51\x22\xf8\xb6\x35\x26\xa0\xec\xd1\x3f\x4e\x37\x0d\xef\x9d\x07\x8f\xae\x20\x62\x8d\xbe\xec\xb2\x65\xa7\x45\x5d\x82\x93\x96\xac\x40\x8f\x89\xe7\x4b\x0e\xcb\xac\x91\xac\x1b\x20\x37\xfe\x5e\x47\x1f\x75\x8e\xf0\x81\x16\xcd\xbe\x08\x18\xfb\xc9\xc3\xcf\xf5\xc4\x6e\xcc\xa4\xef\xfb\xd7\xa9\xd2\xdd\x33\xfb\xee\xbb\x60\x21\x2b\x43\x47\x07\x28\xe4\xec\xb6\x2a\xd4\x21\x7c\x6f\xc7\x48\x15\x86\xbe\x30\xfe\x5a\x64\x08\x2c\x85\x72\x84\xb5\x3d\x37\xd3\x25\x22\x72\xcb\x95\xbf\x21\x29\xb9\x23\xf4\xdb\x60\xd7\xf1\x79\x2b\xef\x88\xbb\x13\xde\x1b\xdf\xd9\x66\x61\x62\x5d\xdc\x69\x32\xeb\xe0\x99\x92\xff\x41\x9a\x8a\x7f\x71\x50\x57\xf0\x67\xb9\x33\x2c\x54\x36\xb2\x9e\x71\xdb\xcd\x78\xc2\xb3\x73\x21\x2b\x2a\x49\xa7\x2e\x5e\x2c\xf3\xa4\x4f\x59\xdc\xd0\xc1\x64\x9e\x42\x1b\xde\x9f\xdc\x4c\xc5\xad\xc5\x22\x37\xa6\x18\x3b\xce\xf4\xef\x8d\xf0\x5b\x3b\x46\xf7\x89\xae\xd0\xbc\x7c\xa0\x9f\x0d\xc4\x46\xdc\xe5\x21\x16\x17\xc0\x7d\xe7\x88\x53\xf8\x8b\xad\x20\x54\xfe\x73\xf2\x08\x5b\x74\x6f\xbf\x0d\x36\x74\xa7\x35\xb1\x74\x0a\x05\x34\x45\x87\x8c\x34\x88\xa0\xfb\xc1\x0e\x23\xa4\x57\x37\x6b\x44\x07\xd2\x4d\x2d\xcc\x20\x5e\xe1\x29\x06\x83\xaf\xc5\x7e\xe5\x1e\x3f\xe9\x2f\x85\x5f\x63\xbe\xf2\x86\x22\x8f\x9d\x1c\x5e\x80\x89\x31\x9e\x9d\x9a\x9e\x01\xae\xbc\xc4\x7e\x30\x72\xda\xf2\xca\xec\x22\x92\x60\x62\x41\x45\xf0\x3a\x2e\xc8\x2e\x6f\xd3\x25\x9c\xad\xc8\x4e\x86\x7a\x76\xc7\x2d\x70\x75\x41\x4c\x0d\xed\xee\xeb\xca\x83\x4e\xfc\xde\x5f\x60\x53\xf6\x76\xde\xef\x78\x84\xa9\x1d\x83\x7e\x9c\x2a\x7e\x2f\x53\x9c\x7d\x1c\xf1\x68\x3d\xb1\x8a\x89\x7f\xcc\xca\x60\x7e\xaa\x42\x33\xfc\xab\xd9\x1e\x16\xdc\x6c\x67\xcc\x4b\x32\xd8\x2f\x17\xe4\xb5\x0c\x58\xc3\x2d\x07\x48\x14\xa1\xed\xc3\x2e\xf2\xc1\x25\x7a\xea\x3e\xd8\x7b\x45\x0e\xee\x09\x34\xf3\x08\xcb\x2b\x26\xfc\xd6\x27\xfd\x95\x39\x21\x5a\x52\x33\x7e\x93\x5c\xc5\xac\xe3\xbd\x9e\xdd\x54\xfa\x1b\xc1\x4e\xc6\x24\xfb\x44\xfb\xa6\xec\x15\x8b\xdf\xf3\xba\x4d\xb4\xcc\x1e\x5a\xe9\xda\xba\x57\xc6\x51\x18\x5e\x3c\xe3\x1e\x75\x12\x15\x5e\x89\xf3\x58\x4e\x2c\x1b\x7a\xc2\xe6\xf8\x25\x60\xc0\xdb\xde\xf9\xdc\x03\xdb\x77\x0b\x4f\x97\xd7\xd5\x9d\x89\xb3\xb9\xdd\xe5\x2a\x96\x32\x87\x5e\x6a\xcf\x63\x3d\x54\x7f\xf6\xed\xa4\xd7\xee\x11\x6e\xc1\x8d\xaa\xf8\x51\x88\x40\xd9\x65\xc6\x59\x6a\xf5\x08\xa4\x4f\xb2\x89\x40\x1e\x36\x9e\x21\x5f\x42\xee\x39\x22\x00\x9c\x33\x54\x7b\x16\x02\x95\x5d\xc5\x96\xa4\xb5\x4e\xf5\xc1\x34\x66\x57\x8e\x6d\xd6\x91\x3f\x99\xfa\x8d\xcf\xbe\x57\x1d\x95\xb4\xc9\x51\x98\x69\x93\x2f\x88\x2a\x2d\x8e\xe9\x48\x67\x39\x64\x0f\x88\x4b\xd4\x43\xe2\xb5\x17\xd5\x9e\xce\x07\xe3\x20\x7b\x72\x05\xed\x63\x6d\x31\x04\x3d\x7d\x7a\xd3\x19\xaf\x0e\x04\x32\xef\xf0\x10\x3e\x60\xf4\xe5\xa1\x9d\xb0\xab\xc5\xa0\x93\xdb\xea\xa0\x02\xde\x8a\x39\x33\x76\x62\x08\xfc\xbe\x1e\xdc\x58\xbb\xc1\x0f\x0b\x5c\x4f\x65\x42\x78\xb1\x92\x61\xea\x16\x65\x79\x9e\xa3\xda\x9f\xaf\xb2\x07\xd6\x16\xbe\xa4\xff\x33\xd7\x45\x3b\xc0\xa0\x0d\x11\xad\xee\x24\x33\xca\x44\xcf\x48\x57\x62\xbe\xfc\xcd\xeb\x72\x27\xb4\xec\xa5\x06\x3e\xf3\xcc\x87\x76\xa8\x81\xff\xb0\x66\x25\xda\x33\xdd\xa4\xb2\x42\x6c\x81\xec\x11\xf0\x6b\x25\x86\x8c\x33\x6c\x0b\x36\xe2\xbd\xf6\xb0\xf2\x07\x2d\x5c\xd8\xea\x5f\x1c\x50\x8b\x8f\x33\x2b\xaf\x7f\x92\x58\x06\x04\xb8\xb9\x44\xe7\x16\xa7\x89\xb8\x37\x51\x2a\xbe\xb1\xf2\x5c\xa6\x26\x16\x20\x14\x19\xaa\x27\xcd\x1a\x6e\x9b\x3f\x90\xad\x69\x87\xb5\xf3\x7f\x20\x22\x51\xf6\xfe\xdc\x77\x9d\x5f\x45\xf6\xb8\xed\x77\x1e\x66\xf3\x6e\xb6\x01\xda\xf8\x7b\x52\x81\x47\xae\xcc\xce\x70\x65\xdd\x7c\xc5\x29\x1e\xcc\x57\xb3\x90\xff\xd0\x95\x31\x5b\xbb\xb1\xbe\x61\x06\x95\x60\x73\x52\x4e\x4a\x78\x68\xb7\xcb\x45\x4c\x90\xaf\x95\xb6\x99\x86\x51\x7b\x88\x25\x9d\xca\x8b\xd9\x47\x5f\x01\x69\x31\x05\x5d\xf9\x52\xb6\x31\xc5\x7c\x2a\xee\x6a\x6f\xf1\x5f\xe0\x0b\x85\x19\xca\xb0\x9d\x04\x64\x0e\xb3\xd7\xac\xe4\x38\xe6\x2f\x52\x07\x9e\x45\x15\xd0\x87\x80\xa8\x21\x7f\x85\xd0\x0b\x23\xf3\xfd\xf9\x09\x28\x1d\x3f\x69\xb6\x19\x7e\xd2\x16\x9e\x17\xd1\x7e\x0d\xf3\xe0\x4a\x78\xd2\x83\xd5\x9d\xb7\x83\xf9\x66\xfe\xb5\x57\xc7\x2f\x27\x3e\xae\x00\x81\xab\xf1\x88\x9a\xed\x5b\x15\x56\x8b\x86\x51\xf8\x71\xa8\x8e\xfe\x97\xe5\x27\x00\x65\x9e\xcc\xfa\x27\x7d\x56\x6d\x4a\xec\xe6\xa3\xc2\xea\x55\x58\x93\x73\x61\x0e\xec\x88\x77\x43\x5d\x3a\x95\x08\xde\x76\xa9\x85\x8b\x1c\xc2\x3f\x12\x4f\xf8\xcf\x39\xfb\x66\x9a\xa1\xd1\xfd\xdd\x6a\x65\xb1\x8b\x88\x06\x0e\x3a\x1d\xb0\xbf\x23\x03\x89\x4d\x50\xba\x1b\x0c\x12\x6d\x84\xf1\xd2\x99\xdb\xa6\xde\x98\xdd\xd2\x54\xbe\x05\xbf\x46\xca\xf1\xa0\xcf\x1a\xe2\x77\xee\xb4\x11\x9b\x17\x20\x0f\x78\x0c\x5f\x5e\x5a\xdd\xf9\xee\xf8\xbd\xce\x63\xe1\x45\x43\xe5\x82\xa1\x5a\xa1\xb7\x7e\xe9\xf2\xc0\xa4\x63\x3d\x3d\xe8\xe4\xfe\x02\x26\x87\x0d\x3e\x99\x72\x4e\x0d\xf3\xde\x67\x96\xdf\xa6\x14\x15\x59\x1a\xdc\x47\x1d\xfe\x10\xb2\x27\x72\xee\x3c\x0a\xd5\xd2\xf1\xef\xb8\x50\x6f\xa2\x08\xf9\xb7\x2f\x82\x7e\x99\x19\x98\xc5\x0d\xa7\xaf\x98\x86\x05\x5b\xbf\xc8\xa8\x2a\xc3\xea\xf1\xe9\x95\x30\xfe\xba\x0f\xe4\x01\x74\xa8\x10\xe1\x85\xdf\x7f\x6d\x09\x5c\x8f\x39\xd1\x03\x85\xd8\x85\xc7\x81\xd7\xcf\xff\x43\x72\x04\x06\xff\xe9\x1e\x30\x09\x13\x5c\x41\x0f\x4a\x60\x70\x75\x1d\xbb\x25\xea\xa4\xaa\x74\x47\x32\x06\x1d\x89\x98\x49\xaa\xa7\xf9\x72\xeb\x09\xbc\x82\xce\xeb\x9c\x59\x15\x21\x32\x6a\x66\x4e\xe4\x8d\x24\x6c\x38\xc2\x74\xbc\xb7\x2a\xc3\x85\xfe\xd7\xb1\x3b\xe2\x1a\x87\x2a\x75\x66\x14\x56\x7c\xfa\xc9\xbd\xf6\xaa\x27\x39\x3c\x99\xb5\xab\xad\xe8\xa2\xbf\xb4\xc4\x5b\xc5\x6f\xd9\xcc\x22\x55\xbc\x05\x3f\x68\xcc\x48\xbc\x2c\xff\xe3\x96\xcc\xd9\x5e\x66\xe9\x09\x09\x45\x86\x07\x63\x81\x6a\x11\x21\x2e\xfc\x13\x42\x9e\xaa\xd3\x34\x05\xe6\x40\xc3\xfd\x22\x18\xce\xd2\x8c\x67\x53\x74\x22\x27\xd3\xb8\x3a\xb0\x08\xe8\xd6\x3f\xac\xfc\xe3\x94\x5f\x31\xeb\x87\xb3\xf6\x20\x34\xd6\x47\xe0\x0b\x00\x6c\x48\x3c\x5d\xc0\x37\xf1\x14\x69\xe5\xc3\x44\xbe\x22\x0c\x9d\x05\x32\xb7\x4e\x34\x32\xb6\x1e\x3d\xeb\x41\xb6\x41\x74\xc1\x15\xc1\x21\x2f\x1c\x52\x25\xbe\x2a\x68\x5d\x16\xed\x30\xc2\x64\x21\x8e\x16\x60\xc9\x2a\x44\xa8\xbc\x1a\x54\x27\x12\xbe\xc4\x5c\xd8\x12\xcf\xb6\x65\x47\x3b\x2f\x3e\x16\xca\xcd\x16\xf8\x62\x66\xcc\x19\xe4\x03\xfe\x0e\x5a\x8f\x25\x95\x83\x8c\x82\xfe\xed\xae\xeb\x25\xbb\xcb\x60\x03\xf7\x31\x92\xf0\x70\x72\x55\xe5\x1b\xfd\xfd\x38\x09\x9c\xdb\x6b\x92\x15\x13\x95\x17\xb3\x10\x5c\xbb\x33\x2a\xcf\x53\x7e\x60\x15\x5f\xe5\x59\xb0\x78\x83\x2e\x03\xbc\x3a\x49\x3b\xcf\x3a\x25\xbe\x88\x9d\x8c\xc4\x07\x9b\x6e\x51\x58\x55\x4c\x70\xb0\x92\xf7\x20\xf2\xb3\x90\xc9\x40\x0b\x77\x43\x34\x68\x0e\x05\x26\x5e\xd5\xf3\xc9\xd6\x20\x90\x2a\x2c\xf4\x23\xd3\xa3\xc1\xe2\xdf\xeb\x04\xcb\x4b\xc3\xe2\x67\xbf\x2c\x38\x39\xf7\xda\x9f\xbc\x67\xe4\x22\x58\x80\x89\x73\x9a\x11\x46\x7a\x2e\xa3\xa2\x7f\x3f\x29\xa2\x73\x7e\xc3\x9b\x57\x15\x11\xdd\xb9\x1d\xaa\x19\xc4\xfd\x4c\x02\x3a\xcc\xe1\xb3\x20\x86\x0a\x18\xbe\xc9\xc3\x54\xde\x6f\x40\x4b\xf8\x4e\x5d\x25\x3e\xda\x40\x63\x6c\x21\x0f\x5d\x8a\x6d\xec\x22\x67\x18\xb9\x4d\x9e\x57\x46\x07\xf2\x5a\x24\x4d\xbe\x69\x40\x7c\x99\x71\x43\xde\x34\x0a\x4e\x1c\xd0\x2d\xa2\xb3\xf3\x6a\x47\x20\x66\x01\x94\x09\xec\xde\xcf\xee\x87\xc9\xb4\x33\x7f\x80\x08\xd4\x99\xd9\x25\xf6\x74\x16\xec\x48\x87\xc3\x88\x2c\x91\xdc\x61\x0b\x75\x17\x93\xc0\xae\xc2\x43\xd4\x1a\xa0\xa0\xad\x22\xd2\xe3\x52\x9e\x0e\xfd\x99\x7b\x8c\x64\xcf\x8c\x7b\xd4\xd1\x11\x1e\xad\x49\xb7\xc6\x2d\x2c\xbd\x66\xfe\x54\xb9\xe7\x1c\xd4\xbc\x95\xa1\xa2\x83\x36\x11\xd1\x4d\x42\xfe\x19\xba\x00\x06\x64\x90\xa0\x5c\xdd\x0c\x0e\xfe\xe1\xde\x60\x73\xaf\x07\x64\x56\x1f\x7a\x87\xd0\x18\x2d\xda\xba\xf1\x08\xa4\xa5\xd7\x42\x65\x77\x52\xbe\xf5\xf6\xda\xca\x3e\x68\x42\x3d\xe9\xbf\x29\x84\xc7\x27\x0d\xf8\x8c\x44\x52\xe0\xf1\x76\xa7\xe7\xbf\xdc\xa2\x00\x5a\x66\x95\x3e\x68\x8e\xea\x9d\xd8\x93\x87\x7b\xac\x8f\xdb\x21\xca\x58\xe2\x45\x8e\xa1\xd8\x95\x83\x61\x71\x6c\x15\x36\x01\xc4\x16\xd4\xef\x70\x63\x76\x4b\x04\xf9\x48\x03\xd7\x0a\x9c\xb7\x56\x04\xb1\xd8\x8c\x1b\x75\xce\x64\x6c\x59\x0e\xb3\xf1\x37\xd4\xa8\x18\xe4\xbd\x27\x8e\x85\xdb\xb6\x47\x6d\x3e\x9d\x1b\x91\x40\xcf\x05\x04\xfd\x21\x7d\xf3\xef\x64\xbe\x9a\x86\xc0\x83\x9c\xcd\xc2\x83\x6b\x16\x2c\x18\x5e\x7b\xcf\x9b\x02\xa8\xa2\xd5\x27\x36\x82\x1d\x76\xe7\xf9\x44\x66\xca\xe9\xe4\xeb\x20\x4f\xa7\x52\x14\xa3\xc1\xc3\xdc\x38\x5d\xa4\x62\xe1\x32\x31\xb2\xda\xcf\x80\x7e\x7a\x0f\x2d\x89\x3c\x6f\x28\xdc\x9e\x73\x77\x13\xee\x7a\x47\x00\x73\xb7\xa3\xce\x9c\xf7\x41\x96\xeb\x08\x4a\xa7\xb8\x5b\x48\x27\x68\x34\xea\x9f\x5e\xe6\x91\x70\x25\x0f\x80\xdd\x6c\x9e\x13\x54\x57\x69\xf1\xbc\x4c\x71\x63\x14\xa3\xdc\x64\x62\x6a\x55\x36\x65\x93\x5d\x80\x9a\x79\xe9\x68\xe6\xeb\xc4\xe8\x79\x2a\x81\x90\xbe\x5b\x98\xa7\x9b\xe7\xc8\x81\x40\x38\x0b\xe2\x88\x2b\x3a\xc7\xb4\xc5\x4f\xab\x87\x78\x0a\xcb\xd2\xcc\x64\xd0\x56\xe6\xc9\xca\x91\x79\x24\x86\x19\xa2\xeb\xcd\x69\xc3\x81\x49\xf7\x3b\x81\x8a\x97\xc2\x95\x1c\x0c\x58\x62\x64\x3c\xbc\xa7\xd0\x4c\xde\x0a\xcf\xb5\x6f\x0a\xef\x02\xfc\x27\x4a\xb9\xa9\x50\x1c\xb9\x14\xc3\x40\x82\x7e\xfe\xe2\x13\xb6\xdd\xae\xb8\x1d\x21\x40\x5f\x53\x9f\xfe\xe2\x95\xcd\xf0\xcd\x6b\x7a\x2c\x72\xd5\x8b\xdb\x07\x92\x23\x3c\x51\x25\x0d\xca\x92\xd3\xe0\x10\x79\x95\x00\x56\xe6\x15\xe0\x6e\xe0\xdb\xa3\xce\x75\xd4\x28\xf8\xd6\x67\x1c\x60\xf3\xc9\xab\x2a\x87\x00\x45\x6f\xf0\x4c\xbe\x05\x24\xa7\x82\x8c\x88\x75\xae\xef\xa5\x21\x62\x7c\x88\x1b\x6a\xeb\x84\xcb\x65\x72\x27\x85\x32\x76\x60\x08\x50\x25\x50\xa8\x76\xf8\x96\xe1\x3c\x14\x50\xc1\x57\x10\x8e\xd8\x62\x6b\x87\x7c\x57\x9d\xf9\xd9\xea\x19\xf9\x41\xf4\xc0\x31\x24\xb9\x4d\xa2\xc4\xeb\xe6\x40\x1b\x2f\x8f\xaf\xde\x20\xa2\x75\xc7\xd3\x69\x81\x45\x23\x14\xe3\x01\xcd\xc8\x47\x85\xa8\xd8\x8f\x72\xbf\x3c\x3c\x90\xc3\x8f\x7a\x65\x37\xd1\x3b\x9c\x0f\x3e\xbf\x45\x7a\xeb\xb5\x8e\xbb\xee\x6d\x64\xf7\xbb\xc2\xd6\x4e\xd0\x7e\x4f\x0c\xc3\x9f\x97\x18\x26\x00\x6f\x06\xf3\x01\xd4\x5b\xc8\x9c\x3b\x9d\x57\xfb\x39\x33\xb1\x49\x25\x8b\x25\x90\xc3\x81\x39\x3e\x9d\x07\xaf\x01\xd2\x38\x73\xc0\x07\x2b\xd7\x0e\xf5\x90\x13\xef\x96\x43\xbb\x17\x41\x08\x31\x98\xa3\x06\x13\x17\xee\x90\xa5\xae\x53\xf5\x11\x07\x05\xb9\x52\x1e\x6c\xc8\x53\x6c\xf5\x6e\x87\xa9\xd4\xb0\x98\x49\xf6\x03\x48\x3c\x76\xe3\x17\xc7\xda\x32\xbc\xe2\x9f\x84\x47\x7d\xd9\x63\xf3\x6e\xc1\x89\x37\xce\xe9\x9e\xe6\x82\xd5\xc2\x91\xaa\xc1\xbd\xc5\x37\x01\xdf\xec\xb2\x80\xa0\xe5\xd1\xd6\x95\xbb\x68\xdf\x83\x0f\x57\x46\x27\xe6\x95\xd6\x9b\x1f\x93\x10\x3e\xce\xd7\x06\xae\x1e\x33\x89\x78\xb5\xb1\x68\xcc\x5f\xd5\x18\xcd\x2a\xd9\xb7\x4a\x21\x7d\x6e\xab\x8d\x35\x2a\xad\xd3\x4d\x09\x57\x38\x19\x75\xbf\x29\x53\x8a\xd4\xc8\xd6\x4a\xdc\x24\xcb\xc1\x68\x9d\xba\x0a\x2b\xaa\x56\x07\xf3\xd6\xf9\x15\x75\x06\xcb\x34\xcc\xcb\xf2\xd0\x4f\x55\x5c\xbb\x17\xed\xce\x98\x07\xda\x0d\x42\xa4\x8c\xf3\x56\xa5\x8c\x3a\xdf\x7a\x26\xbb\x2d\xd3\xd9\xb2\x33\x3b\x17\xb4\x80\x93\x02\xb3\xad\x15\x67\xca\xec\x30\x43\x44\x0c\x66\x1f\x9c\xb9\x17\x24\xa0\x2a\xaa\x06\xcc\x0d\x43\x1e\xd4\x2f\x08\xab\x04\x85\xdc\x19\x1c\xcc\x2e\x16\x7e\x0a\x3c\x2a\x2d\xf7\xc8\xb2\x9e\x19\x7e\x7c\xd0\x4f\x92\x15\x18\xc9\x79\x11\x8c\xd2\xf8\x08\x7c\xf4\x97\x57\x3f\x1e\x0d\x1f\xef\x58\x92\x63\x6e\x74\x53\xf5\x2b\x36\x91\x4c\x4a\x3b\x85\xac\x72\x6c\x65\x96\xff\x7e\x34\x33\x01\x9a\x24\x0c\x74\xb1\x15\x9a\xaf\x83\x5b\x49\x9d\x6a\x81\xe2\xfd\x34\x5f\xc7\x17\xae\x57\xaa\x10\xd0\x8c\xae\x7b\x0b\xc7\xbd\x54\xb9\x3c\x78\xce\x09\x55\x5a\x74\x4c\x72\x6f\xc2\xc9\xdb\x05\x6b\x34\xfe\x1c\x2d\x80\xff\x15\xbf\xc4\xa1\xdc\x96\x1e\x1c\x39\x5c\xfc\xf5\x9d\x23\xdd\xa5\x7f\x5f\x8b\x96\x18\xe2\x56\x3b\x1c\x34\x08\x20\xf2\x2b\xa2\xb4\x54\x66\xd3\x69\xb0\x3d\xb7\x7d\x1c\x2b\xe2\x1a\xb7\x39\xb3\x38\xe6\x9b\x18\x08\x7f\x93\x18\x0f\x9e\x0f\xdb\xc9\x21\x5c\x9c\x45\xce\xb6\xb3\xca\xbc\xd1\x2e\x21\xec\xa2\x65\x6e\xfb\x78\x0b\xda\x28\xdf\x23\x62\x72\x3f\x8d\x8f\x85\x36\x84\xf1\x1c\xa1\x41\xad\xd8\x3d\xab\x56\xfc\x48\x8f\xf0\x2b\x02\x9e\xdd\xbf\xd1\x6c\x97\x25\xb2\xee\x70\x3e\xe7\xa6\xda\xf1\x73\x21\x7f\x15\x14\x3c\x22\x52\x89\xbc\x2b\xb2\xc5\x89\x0c\x30\x3d\x1f\x59\x8e\x76\x16\x07\xd3\xac\x6d\x68\xd5\x3b\x9c\xd5\xec\x2c\x66\xec\x3b\x92\x33\x9a\x51\x78\xd6\x87\xd3\x6d\xf9\xd2\x76\x4f\x11\xd7\x9e\xdb\x4b\xcc\x0d\x07\x5d\x64\x95\xb6\x38\x97\xa8\x1f\xea\xd5\x18\x57\x10\x60\x12\xa3\x30\x18\xfc\x7a\xbf\x7c\xda\x0e\xab\xfb\x48\xd6\x8a\x5d\x05\x8d\xf1\xa3\xe0\x6d\x73\xdb\x42\xa4\x7b\xfc\xec\x02\x00\xd3\xcb\x42\xb5\x76\xd1\xab\x19\x2a\x1e\xe3\xcc\x12\xa6\xb3\xf8\x79\x64\x56\x6e\xb3\x19\x03\xc4\xd9\x65\x77\xa6\x83\xbc\x75\x12\x65\x09\x2e\xa6\x5d\x71\xd2\xf4\x6e\xc8\x5e\x0e\x2e\xa8\x67\xd0\x2c\x67\x20\x27\x94\x1b\x75\x87\x2d\x74\xf4\x50\x79\xee\x60\x6e\x73\x30\xdb\xb7\x23\xc6\xcb\x6d\x1e\x9c\x39\x98\x08\x7d\x43\x5e\xb5\x44\xb3\xaa\x71\x64\xad\xf0\xd3\x7e\x4e\x5c\xfb\x05\xeb\x8a\xb7\x35\x67\xc7\xda\xa9\x20\x7f\xb7\x1a\x7f\x5a\x69\x54\xb7\xcc\xe2\xf4\x87\x70\xd2\xb3\xd9\x1b\x10\x92\x96\x56\x1f\xdb\x6a\x2f\xf2\x46\x89\x38\xab\x4b\x4a\xa5\x8e\x0f\x57\xd3\x99\x22\x00\x0f\x26\x46\x73\xbb\x5f\xdc\x24\x9f\xb7\x05\x3d\x22\x91\xf4\xce\x20\xcd\x89\x89\x2c\xee\x9f\x0b\xb3\x02\x6d\x8d\xf7\x0a\x71\x31\x97\x70\xde\x66\x01\xe1\x46\x82\x69\x4b\x54\x2d\x3d\x87\x14\x11\x05\x83\xe6\xbc\xc9\xa9\x46\x81\xd8\x41\xc5\x30\x72\x85\x79\x38\x00\xe1\xe0\x4f\xf4\x07\xe1\x4e\xe1\x45\x8e\xd6\xe2\xa2\x96\xad\x3f\x67\x7f\x03\x5d\x53\xf9\x5a\x1e\x05\xff\xa4\x20\x12\xa0\x89\xcb\x19\xd2\x3a\xa1\xbd\x62\x29\xda\xbe\x1b\x13\xbe\xc0\x5a\x0f\xdd\xff\xab\xb3\x44\x46\x70\x22\xf1\x03\xf9\x25\xa8\x78\x3c\x6a\xa2\x53\x88\x21\x3f\xc6\x39\x99\x89\x62\xd9\x6f\x67\x80\x4b\x27\x22\x4f\x3f\x7f\xdc\x62\x7e\x6e\xaa\x26\xd1\xf5\x58\x12\x73\x4e\x64\xf9\x17\x2e\xd0\x2b\x33\xd1\xd0\xa3\xf0\xec\x81\x2e\x97\xc4\x0b\x22\x40\x9a\xf6\xe6\x0d\xf7\xc0\xcc\xef\xe6\xe1\x19\xc5\x23\xfb\x13\xc4\x9a\x88\x21\xdd\xe3\x26\x58\xc8\xf3\x09\x2b\x22\xd7\x9f\x64\x32\x08\xef\x34\xb6\x43\xda\x3a\x2e\xef\x7b\x24\x24\x74\xf0\x3b\xd5\x50\x32\xa0\x9d\x68\x6f\x4c\xfc\xbd\x95\xce\x2c\x66\xcc\x17\xb3\x2e\xc2\xb0\xf8\xca\xbe\x29\xf0\x30\xaf\xa5\x25\x02\x50\x41\x62\xe2\xcd\x4d\xaf\xca\x6e\xb4\x80\xc2\xee\x41\x61\x06\xf7\x4d\x2e\x95\x95\x5c\x36\x95\x45\x5d\x84\x26\xe1\xa6\xde\x0e\x1c\x6b\x95\x0d\xa2\xa2\x35\x12\x66\xdb\xf0\xbb\xc8\x2e\x02\xb0\xf0\x05\xac\x37\x9b\xb5\xab\x9a\xb8\x7b\x4e\xab\x2e\xa2\x06\x48\xbe\x74\xc6\x19\x6f\x02\xed\x6b\x1e\x89\x2e\x8e\xe9\xb1\x45\x3a\x79\x4a\x45\xf7\x93\xbb\xa1\xa8\x53\x20\xde\xb2\xd0\xc2\xdd\xed\x1c\x46\x5a\xa3\xf6\x1e\xc7\x22\xbd\xb5\x4b\x19\xd5\x1e\xf1\x35\x37\x86\xe9\x9b\x1d\x4d\xe2\xe6\x2a\x1f\x32\x82\xc9\x2c\x75\x99\xa7\x7a\x28\x6a\xe8\x82\x48\x08\x5a\x17\x17\xa3\x55\x85\xdc\xea\x91\xf2\x51\xc9\xbf\xda\xc4\x14\x35\x73\x37\x85\x6b\x2b\x44\x3e\x09\xdf\xfa\x15\x72\xdf\x0e\xdb\x64\x51\x5e\x3a\x18\x73\x6c\x39\xff\xe5\x5d\x0b\x68\x9d\x34\x91\xbd\x8f\x0a\xd7\x4a\x0b\x9a\xf5\x16\x29\xf8\x20\x7b\x12\xb1\x21\x2b\x4c\x5c\x71\xc6\xce\xe5\xdf\x02\xc2\x9a\xb9\x32\x8b\x6c\xc0\x76\xc1\x94\x30\x76\xec\x98\x7d\xe7\x08\xbe\x1d\x14\x51\xf9\x31\xd0\xf4\x63\x6b\xc4\x37\x70\x9f\x18\x8c\x6d\x9b\x60\x7b\xe4\x61\xb0\xb2\x28\xc2\x04\x74\x60\x67\x6a\x5e\x55\x91\x51\x37\x86\x6d\x6d\xe6\xae\x32\x64\x71\x58\x9f\x89\x04\xd2\xc5\x62\xe6\x9e\x15\xc7\xcd\xdd\x2b\x3e\x65\xc9\x1e\xfe\xa9\x1d\xa2\x8b\x6a\x32\xa2\xee\x1b\x7b\x03\x58\x62\x73\x16\x24\xdf\xec\x37\xe2\x19\x33\x21\x20\xd6\x3b\x50\xbf\xc9\xaf\x01\x6a\xcf\xc1\x91\x42\xd9\x99\xf4\xf9\x87\xda\xca\x96\xfc\x99\x59\x9b\x7e\x93\x95\xcc\x02\x87\x5d\xc0\x67\x14\x70\xbf\xfd\x56\x25\xca\xf2\xfb\x15\xd7\xcb\x96\x78\x1c\xc3\x33\x6f\xb9\x38\xd9\xaf\x73\x62\xe7\x31\x0e\x0e\x4a\x24\x44\x21\x97\x86\xbc\xa3\x7e\xd0\xd8\xaf\x3c\xff\xf9\xf8\xaa\x0a\xdd\xd4\x44\x24\x72\xc3\x08\xd4\x77\xad\x8a\xa5\x67\x5b\x56\xb4\xee\x4e\x66\x52\x2e\x58\x59\xa7\x9c\xe5\x54\x92\x12\x1e\x8b\x1a\x5d\x9c\x3e\x07\xa4\xca\x2d\x99\x6d\xd4\x48\x2b\x7a\xef\xd0\x55\x9e\x54\xa1\x39\x48\x22\x31\x2b\x17\x3e\x24\xb7\x12\x66\x04\x3c\xbc\x2c\xa8\xf1\xaa\x0a\x5a\x96\x20\x9a\x33\xc3\x55\x5d\x74\xae\x03\x40\x64\x52\x24\xc2\x7c\x0c\x30\x44\x0f\x82\x59\x76\xa6\x93\x90\xae\x3b\x49\x53\x9e\xe1\x92\xe6\xe1\x79\xca\xad\x01\x1b\xa2\x3e\xa8\x48\xc6\xb4\x75\x7f\x06\xab\x83\x16\x4b\x09\xf3\x29\xee\xfd\x78\x8a\x6a\xd1\x8a\x8a\x40\x55\xdc\x6d\xa8\x60\x88\x55\x15\xe1\x0f\xc7\x8d\x9f\xeb\x2e\xf0\xc6\xd8\x63\x51\x75\x05\xc7\x08\xb9\x0d\xac\xac\x2a\x0b\xd8\x8a\x45\xa9\xad\x02\x4e\x7a\xba\x5d\xe7\xb2\xc5\x30\xdb\x29\x96\
"""




```