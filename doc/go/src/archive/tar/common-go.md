Response:
我的目标是对给定的 Go 源代码片段 `go/src/archive/tar/common.go` 进行分析，并用中文回答其功能。具体来说，我需要：

1. **列举功能**: 提取代码中的关键组件和它们的作用。
2. **推理 Go 功能并举例**:  识别代码所实现的 Go 语言特性，并用代码示例说明。
3. **代码推理 (带输入输出)**: 如果涉及到一些逻辑处理，提供假设的输入和输出，展示代码的运行结果。
4. **命令行参数处理**:  如果代码涉及到命令行参数的处理，详细介绍。
5. **易犯错误**:  指出使用者可能犯的错误。

**开始分析和思考：**

* **包声明和导入**:  `package tar` 表明这是一个处理 tar 归档文件的包。导入的包包括标准库的 `errors`, `fmt`, `io/fs`, `maps`, `math`, `path`, `reflect`, `strconv`, `strings`, 和内部包 `internal/godebug`。这些导入暗示了错误处理、格式化、文件系统操作、映射、数学计算、路径操作、反射、字符串转换和调试功能。

* **常量和变量**:
    * `tarinsecurepath`:  看起来是一个用于调试的标志，可能与处理不安全路径有关。
    * `ErrHeader` 等错误变量:  定义了包中可能出现的错误类型。
    * `TypeReg` 等 `Type` 常量:  定义了 tar 文件头中 `Typeflag` 字段的各种取值，代表不同的文件类型。
    * `paxPath` 等 `pax` 常量:  定义了 PAX 扩展头部的关键字。
    * `basicKeys`:  一个 map，存储了基本的 PAX 关键字，表明代码对 PAX 格式有一定的支持。

* **`headerError` 类型**:  自定义错误类型，用于表示头部的编码错误。

* **`Header` 结构体**:  这是核心结构体，代表 tar 归档文件中的单个文件头。它包含了文件名、链接名、大小、权限、UID/GID、用户名/组名、时间戳、设备号、扩展属性和 PAX 记录等信息。  `Format` 字段表明支持不同的 tar 格式 (USTAR, PAX, GNU)。

* **`sparseEntry`, `sparseDatas`, `sparseHoles`**: 这部分定义了用于表示稀疏文件的结构体。稀疏文件是指文件中包含很多空洞的文件，可以节省存储空间。代码中同时用 `sparseDatas` (数据块) 和 `sparseHoles` (空洞块) 两种方式来表示，并在内部进行转换。

* **函数**:
    * `validateSparseEntries`:  验证稀疏文件描述信息的有效性。
    * `alignSparseEntries`:  对齐稀疏文件的偏移量和长度，可能与不同的 tar 工具的兼容性有关。
    * `invertSparseEntries`:  在 `sparseDatas` 和 `sparseHoles` 之间转换。
    * `fileState` 接口: 定义了跟踪文件剩余逻辑和物理字节数的方法，用于处理流式读取和写入。
    * `Header.allowedFormats`:  确定给定的 `Header` 可以被编码成哪些 tar 格式，并返回需要添加到 PAX 扩展头的信息。这是一个核心函数，涉及格式兼容性检查。
    * `Header.FileInfo`:  将 `Header` 转换为 `fs.FileInfo` 接口，方便与 Go 的文件系统抽象交互。
    * `headerFileInfo`:  实现了 `fs.FileInfo` 接口。
    * `FileInfoHeader`:  根据 `fs.FileInfo` 创建 `Header`，是创建 tar 文件头的常用方法。
    * `FileInfoNames`:  一个扩展的 `fs.FileInfo` 接口，允许直接指定用户名和组名，避免系统调用。
    * `isHeaderOnlyType`:  判断给定的类型是否为只包含头部的类型。

**整理思路，形成答案框架:**

1. **包的功能概述**:  `archive/tar` 包用于读写 tar 归档文件，支持多种 tar 格式。
2. **核心数据结构 `Header`**:  详细描述 `Header` 结构体的各个字段及其含义。
3. **稀疏文件支持**:  解释 `sparseDatas` 和 `sparseHoles` 的作用，以及相关函数。
4. **tar 格式处理**: 重点介绍 `Header.allowedFormats` 函数，以及 USTAR, PAX, GNU 格式的区别和兼容性问题。
5. **与 `fs` 包的集成**: 说明 `Header.FileInfo` 和 `FileInfoHeader` 的作用，以及 `FileInfoNames` 接口。
6. **易犯错误**:  根据代码中的错误提示和设计，推测用户可能犯的错误。

**开始撰写答案，并填充细节。**  在撰写过程中，我需要将代码中的信息转化为易于理解的中文描述，并根据需要提供代码示例。例如，在解释 `Header.allowedFormats` 时，可以举例说明某些字段在不同格式下的限制。  对于稀疏文件的处理，可以提供简单的 `sparseDatas` 和 `sparseHoles` 相互转换的例子。  在讲解易犯错误时，可以结合 `tarinsecurepath` 的作用，说明路径安全问题。

经过以上思考和分析，我最终得到了一个比较完善的答案。
这段Go语言代码是 `archive/tar` 包的核心部分，主要定义了 tar 归档文件的头部（Header）结构以及相关的常量和辅助函数。它实现了对不同 tar 格式的支持，并提供了与 Go 标准库 `io/fs` 包的集成。

**主要功能列举：**

1. **定义 Tar 文件头结构 (`Header`)**:  `Header` 结构体定义了 tar 归档中每个文件的元数据信息，例如文件名、大小、权限、修改时间、用户/组ID/名称、链接目标等。

2. **定义 Tar 文件类型常量 (`TypeReg`, `TypeDir`, 等)**:  定义了 `Typeflag` 字段的各种取值，用于标识当前条目是普通文件、目录、符号链接、硬链接、设备文件、FIFO 等。

3. **定义 PAX 扩展头部关键字常量 (`paxPath`, `paxSize`, 等)**:  定义了 PAX 扩展头部中可能出现的各种键值对的键名，用于存储超出传统 tar 头部限制的信息。

4. **定义错误类型 (`ErrHeader`, `ErrWriteTooLong`, 等)**:  定义了在 tar 包操作中可能出现的各种错误。

5. **定义稀疏文件结构 (`sparseEntry`, `sparseDatas`, `sparseHoles`)**:  定义了用于表示稀疏文件的结构体，允许归档和恢复只包含实际数据的部分，节省存储空间。

6. **提供校验稀疏文件数据的方法 (`validateSparseEntries`)**:  用于验证稀疏文件数据是否合法。

7. **提供对齐稀疏文件数据的方法 (`alignSparseEntries`)**:  用于将稀疏文件的偏移量和长度对齐到块大小的倍数，可能用于兼容某些特定的 tar 工具。

8. **提供转换稀疏文件数据表示的方法 (`invertSparseEntries`)**:  用于在数据块 (`sparseDatas`) 和空洞块 (`sparseHoles`) 两种稀疏文件表示方式之间进行转换。

9. **提供确定 Header 兼容格式的方法 (`Header.allowedFormats`)**:  根据 `Header` 中的字段，判断该头部可以被编码成哪些 tar 格式 (USTAR, PAX, GNU)，并返回需要额外存储在 PAX 扩展头部的字段。

10. **提供将 Header 转换为 `fs.FileInfo` 接口的方法 (`Header.FileInfo`)**:  使得 `Header` 可以像 Go 标准库中的文件信息一样使用。

11. **提供从 `fs.FileInfo` 创建 Header 的方法 (`FileInfoHeader`)**:  方便地从文件系统信息创建 tar 文件头。

12. **定义扩展的 `fs.FileInfo` 接口 (`FileInfoNames`)**:  允许在创建 Header 时直接指定用户名和组名，避免潜在的系统调用开销。

13. **提供判断 Typeflag 是否为头部类型的方法 (`isHeaderOnlyType`)**:  判断给定的 `Typeflag` 是否表示一个只包含头部，没有数据体的条目。

**推理 Go 语言功能的实现并举例：**

这个代码片段主要体现了以下 Go 语言功能的应用：

* **结构体 (Struct)**: `Header`, `sparseEntry` 等结构体用于组织和表示 tar 归档文件的元数据和稀疏文件信息。

* **常量 (Const)**:  定义了各种文件类型、PAX 关键字和模式位等常量，提高代码可读性和维护性。

* **错误处理 (Error Handling)**:  使用 `errors.New` 定义了自定义的错误类型，并通过返回值进行错误传递。

* **接口 (Interface)**:  `fileState` 接口定义了处理文件状态的方法，而 `fs.FileInfo` 和 `FileInfoNames` 接口则实现了与 Go 标准库文件系统抽象的集成。

* **方法 (Method)**:  `Header` 结构体定义了多个方法，例如 `allowedFormats` 和 `FileInfo`，用于操作和处理 `Header` 数据。

* **类型别名 (Type Alias)**: `headerError`, `sparseDatas`, `sparseHoles` 使用类型别名，为代码提供更清晰的语义。

**Go 代码示例 (推理 `Header.allowedFormats` 的功能)：**

假设我们有一个 `Header` 实例，其中文件名过长，无法用 USTAR 格式编码，但可以用 PAX 格式编码。

```go
package main

import (
	"archive/tar"
	"fmt"
	"time"
)

func main() {
	header := tar.Header{
		Name:    "this_is_a_very_long_file_name_that_exceeds_the_limit_of_ustar_format.txt",
		Size:    1024,
		Mode:    0644,
		ModTime: time.Now(),
	}

	format, paxHdrs, err := header.allowedFormats()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Allowed Formats:", format)
		fmt.Println("PAX Headers:", paxHdrs)
	}
}
```

**假设输出：**

```
Allowed Formats: PAX
PAX Headers: map[path:this_is_a_very_long_file_name_that_exceeds_the_limit_of_ustar_format.txt]
```

**代码推理：**

* **输入**: 一个 `Header` 结构体，`Name` 字段非常长。
* **`allowedFormats` 函数的执行**: 该函数会检查 `Name` 字段的长度，发现它超过了 USTAR 格式的限制。
* **输出**:
    * `format` 将会是 `PAX`，因为 PAX 格式支持更长的文件名。
    * `paxHdrs` 将会包含一个键值对 `"path": "this_is_a_very_long_file_name_that_exceeds_the_limit_of_ustar_format.txt"`，表示文件名需要存储在 PAX 扩展头部。
    * `err` 将会是 `nil`，因为该头部可以用 PAX 格式编码。

**命令行参数的具体处理：**

这段代码本身没有直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数或其他专门处理命令行的部分。`archive/tar` 包主要负责 tar 文件的读写操作，而不是命令行解析。

**使用者易犯错的点：**

1. **路径安全性 (`tarinsecurepath`)**:  `tarinsecurepath` 变量暗示了在处理 tar 文件中的路径时可能存在安全风险。使用者容易犯的错误是解压来自不可信来源的 tar 文件，其中可能包含恶意构造的路径，例如包含 `..` 从而覆盖系统关键文件。虽然代码中定义了这个变量，但具体的安全检查逻辑可能在其他部分。

   **例子：**  假设一个恶意的 tar 文件包含一个名为 `../../../etc/passwd` 的文件。如果解压程序不进行路径检查，则可能覆盖系统密码文件。

2. **对不同 tar 格式的理解不足**:  使用者可能不清楚 USTAR, PAX, GNU 等不同 tar 格式的限制和特性，导致创建的 tar 文件在某些工具中无法正常解析。例如，USTAR 格式对文件名长度、用户/组名长度等都有严格限制，如果超出这些限制，需要使用 PAX 或 GNU 格式。

   **例子：**  尝试创建一个包含非常长文件名的 tar 文件，并期望用只支持 USTAR 的老旧工具解压，会失败。

3. **稀疏文件的处理**:  使用者可能不了解稀疏文件的概念，或者在创建稀疏文件的 tar 包时，`Header` 中的 `Size` 与实际写入的数据不一致，导致解压时出现问题。

   **例子：**  创建一个声明大小为 1GB 的稀疏文件 tar 包，但只写入了少量数据，解压时可能需要特殊的处理来填充空洞。

4. **修改从 `Reader.Next()` 获取的 `Header`**:  代码注释中提到，从 `Reader.Next()` 获取的 `Header` 不应该直接修改后传回 `Writer.WriteHeader`，而应该创建一个新的 `Header` 并复制需要的字段。这是因为 `Reader` 返回的 `Header` 可能包含一些内部状态信息，直接修改可能会导致不可预测的行为。

**总结：**

`go/src/archive/tar/common.go` 文件是 `archive/tar` 包的基础，它定义了核心的数据结构和常量，并提供了一些关键的辅助功能，例如格式兼容性检查和与文件系统抽象的集成。理解这个文件的内容对于正确使用 `archive/tar` 包至关重要。

### 提示词
```
这是路径为go/src/archive/tar/common.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tar implements access to tar archives.
//
// Tape archives (tar) are a file format for storing a sequence of files that
// can be read and written in a streaming manner.
// This package aims to cover most variations of the format,
// including those produced by GNU and BSD tar tools.
package tar

import (
	"errors"
	"fmt"
	"internal/godebug"
	"io/fs"
	"maps"
	"math"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// BUG: Use of the Uid and Gid fields in Header could overflow on 32-bit
// architectures. If a large value is encountered when decoding, the result
// stored in Header will be the truncated version.

var tarinsecurepath = godebug.New("tarinsecurepath")

var (
	ErrHeader          = errors.New("archive/tar: invalid tar header")
	ErrWriteTooLong    = errors.New("archive/tar: write too long")
	ErrFieldTooLong    = errors.New("archive/tar: header field too long")
	ErrWriteAfterClose = errors.New("archive/tar: write after close")
	ErrInsecurePath    = errors.New("archive/tar: insecure file path")
	errMissData        = errors.New("archive/tar: sparse file references non-existent data")
	errUnrefData       = errors.New("archive/tar: sparse file contains unreferenced data")
	errWriteHole       = errors.New("archive/tar: write non-NUL byte in sparse hole")
)

type headerError []string

func (he headerError) Error() string {
	const prefix = "archive/tar: cannot encode header"
	var ss []string
	for _, s := range he {
		if s != "" {
			ss = append(ss, s)
		}
	}
	if len(ss) == 0 {
		return prefix
	}
	return fmt.Sprintf("%s: %v", prefix, strings.Join(ss, "; and "))
}

// Type flags for Header.Typeflag.
const (
	// Type '0' indicates a regular file.
	TypeReg = '0'

	// Deprecated: Use TypeReg instead.
	TypeRegA = '\x00'

	// Type '1' to '6' are header-only flags and may not have a data body.
	TypeLink    = '1' // Hard link
	TypeSymlink = '2' // Symbolic link
	TypeChar    = '3' // Character device node
	TypeBlock   = '4' // Block device node
	TypeDir     = '5' // Directory
	TypeFifo    = '6' // FIFO node

	// Type '7' is reserved.
	TypeCont = '7'

	// Type 'x' is used by the PAX format to store key-value records that
	// are only relevant to the next file.
	// This package transparently handles these types.
	TypeXHeader = 'x'

	// Type 'g' is used by the PAX format to store key-value records that
	// are relevant to all subsequent files.
	// This package only supports parsing and composing such headers,
	// but does not currently support persisting the global state across files.
	TypeXGlobalHeader = 'g'

	// Type 'S' indicates a sparse file in the GNU format.
	TypeGNUSparse = 'S'

	// Types 'L' and 'K' are used by the GNU format for a meta file
	// used to store the path or link name for the next file.
	// This package transparently handles these types.
	TypeGNULongName = 'L'
	TypeGNULongLink = 'K'
)

// Keywords for PAX extended header records.
const (
	paxNone     = "" // Indicates that no PAX key is suitable
	paxPath     = "path"
	paxLinkpath = "linkpath"
	paxSize     = "size"
	paxUid      = "uid"
	paxGid      = "gid"
	paxUname    = "uname"
	paxGname    = "gname"
	paxMtime    = "mtime"
	paxAtime    = "atime"
	paxCtime    = "ctime"   // Removed from later revision of PAX spec, but was valid
	paxCharset  = "charset" // Currently unused
	paxComment  = "comment" // Currently unused

	paxSchilyXattr = "SCHILY.xattr."

	// Keywords for GNU sparse files in a PAX extended header.
	paxGNUSparse          = "GNU.sparse."
	paxGNUSparseNumBlocks = "GNU.sparse.numblocks"
	paxGNUSparseOffset    = "GNU.sparse.offset"
	paxGNUSparseNumBytes  = "GNU.sparse.numbytes"
	paxGNUSparseMap       = "GNU.sparse.map"
	paxGNUSparseName      = "GNU.sparse.name"
	paxGNUSparseMajor     = "GNU.sparse.major"
	paxGNUSparseMinor     = "GNU.sparse.minor"
	paxGNUSparseSize      = "GNU.sparse.size"
	paxGNUSparseRealSize  = "GNU.sparse.realsize"
)

// basicKeys is a set of the PAX keys for which we have built-in support.
// This does not contain "charset" or "comment", which are both PAX-specific,
// so adding them as first-class features of Header is unlikely.
// Users can use the PAXRecords field to set it themselves.
var basicKeys = map[string]bool{
	paxPath: true, paxLinkpath: true, paxSize: true, paxUid: true, paxGid: true,
	paxUname: true, paxGname: true, paxMtime: true, paxAtime: true, paxCtime: true,
}

// A Header represents a single header in a tar archive.
// Some fields may not be populated.
//
// For forward compatibility, users that retrieve a Header from Reader.Next,
// mutate it in some ways, and then pass it back to Writer.WriteHeader
// should do so by creating a new Header and copying the fields
// that they are interested in preserving.
type Header struct {
	// Typeflag is the type of header entry.
	// The zero value is automatically promoted to either TypeReg or TypeDir
	// depending on the presence of a trailing slash in Name.
	Typeflag byte

	Name     string // Name of file entry
	Linkname string // Target name of link (valid for TypeLink or TypeSymlink)

	Size  int64  // Logical file size in bytes
	Mode  int64  // Permission and mode bits
	Uid   int    // User ID of owner
	Gid   int    // Group ID of owner
	Uname string // User name of owner
	Gname string // Group name of owner

	// If the Format is unspecified, then Writer.WriteHeader rounds ModTime
	// to the nearest second and ignores the AccessTime and ChangeTime fields.
	//
	// To use AccessTime or ChangeTime, specify the Format as PAX or GNU.
	// To use sub-second resolution, specify the Format as PAX.
	ModTime    time.Time // Modification time
	AccessTime time.Time // Access time (requires either PAX or GNU support)
	ChangeTime time.Time // Change time (requires either PAX or GNU support)

	Devmajor int64 // Major device number (valid for TypeChar or TypeBlock)
	Devminor int64 // Minor device number (valid for TypeChar or TypeBlock)

	// Xattrs stores extended attributes as PAX records under the
	// "SCHILY.xattr." namespace.
	//
	// The following are semantically equivalent:
	//  h.Xattrs[key] = value
	//  h.PAXRecords["SCHILY.xattr."+key] = value
	//
	// When Writer.WriteHeader is called, the contents of Xattrs will take
	// precedence over those in PAXRecords.
	//
	// Deprecated: Use PAXRecords instead.
	Xattrs map[string]string

	// PAXRecords is a map of PAX extended header records.
	//
	// User-defined records should have keys of the following form:
	//	VENDOR.keyword
	// Where VENDOR is some namespace in all uppercase, and keyword may
	// not contain the '=' character (e.g., "GOLANG.pkg.version").
	// The key and value should be non-empty UTF-8 strings.
	//
	// When Writer.WriteHeader is called, PAX records derived from the
	// other fields in Header take precedence over PAXRecords.
	PAXRecords map[string]string

	// Format specifies the format of the tar header.
	//
	// This is set by Reader.Next as a best-effort guess at the format.
	// Since the Reader liberally reads some non-compliant files,
	// it is possible for this to be FormatUnknown.
	//
	// If the format is unspecified when Writer.WriteHeader is called,
	// then it uses the first format (in the order of USTAR, PAX, GNU)
	// capable of encoding this Header (see Format).
	Format Format
}

// sparseEntry represents a Length-sized fragment at Offset in the file.
type sparseEntry struct{ Offset, Length int64 }

func (s sparseEntry) endOffset() int64 { return s.Offset + s.Length }

// A sparse file can be represented as either a sparseDatas or a sparseHoles.
// As long as the total size is known, they are equivalent and one can be
// converted to the other form and back. The various tar formats with sparse
// file support represent sparse files in the sparseDatas form. That is, they
// specify the fragments in the file that has data, and treat everything else as
// having zero bytes. As such, the encoding and decoding logic in this package
// deals with sparseDatas.
//
// However, the external API uses sparseHoles instead of sparseDatas because the
// zero value of sparseHoles logically represents a normal file (i.e., there are
// no holes in it). On the other hand, the zero value of sparseDatas implies
// that the file has no data in it, which is rather odd.
//
// As an example, if the underlying raw file contains the 10-byte data:
//
//	var compactFile = "abcdefgh"
//
// And the sparse map has the following entries:
//
//	var spd sparseDatas = []sparseEntry{
//		{Offset: 2,  Length: 5},  // Data fragment for 2..6
//		{Offset: 18, Length: 3},  // Data fragment for 18..20
//	}
//	var sph sparseHoles = []sparseEntry{
//		{Offset: 0,  Length: 2},  // Hole fragment for 0..1
//		{Offset: 7,  Length: 11}, // Hole fragment for 7..17
//		{Offset: 21, Length: 4},  // Hole fragment for 21..24
//	}
//
// Then the content of the resulting sparse file with a Header.Size of 25 is:
//
//	var sparseFile = "\x00"*2 + "abcde" + "\x00"*11 + "fgh" + "\x00"*4
type (
	sparseDatas []sparseEntry
	sparseHoles []sparseEntry
)

// validateSparseEntries reports whether sp is a valid sparse map.
// It does not matter whether sp represents data fragments or hole fragments.
func validateSparseEntries(sp []sparseEntry, size int64) bool {
	// Validate all sparse entries. These are the same checks as performed by
	// the BSD tar utility.
	if size < 0 {
		return false
	}
	var pre sparseEntry
	for _, cur := range sp {
		switch {
		case cur.Offset < 0 || cur.Length < 0:
			return false // Negative values are never okay
		case cur.Offset > math.MaxInt64-cur.Length:
			return false // Integer overflow with large length
		case cur.endOffset() > size:
			return false // Region extends beyond the actual size
		case pre.endOffset() > cur.Offset:
			return false // Regions cannot overlap and must be in order
		}
		pre = cur
	}
	return true
}

// alignSparseEntries mutates src and returns dst where each fragment's
// starting offset is aligned up to the nearest block edge, and each
// ending offset is aligned down to the nearest block edge.
//
// Even though the Go tar Reader and the BSD tar utility can handle entries
// with arbitrary offsets and lengths, the GNU tar utility can only handle
// offsets and lengths that are multiples of blockSize.
func alignSparseEntries(src []sparseEntry, size int64) []sparseEntry {
	dst := src[:0]
	for _, s := range src {
		pos, end := s.Offset, s.endOffset()
		pos += blockPadding(+pos) // Round-up to nearest blockSize
		if end != size {
			end -= blockPadding(-end) // Round-down to nearest blockSize
		}
		if pos < end {
			dst = append(dst, sparseEntry{Offset: pos, Length: end - pos})
		}
	}
	return dst
}

// invertSparseEntries converts a sparse map from one form to the other.
// If the input is sparseHoles, then it will output sparseDatas and vice-versa.
// The input must have been already validated.
//
// This function mutates src and returns a normalized map where:
//   - adjacent fragments are coalesced together
//   - only the last fragment may be empty
//   - the endOffset of the last fragment is the total size
func invertSparseEntries(src []sparseEntry, size int64) []sparseEntry {
	dst := src[:0]
	var pre sparseEntry
	for _, cur := range src {
		if cur.Length == 0 {
			continue // Skip empty fragments
		}
		pre.Length = cur.Offset - pre.Offset
		if pre.Length > 0 {
			dst = append(dst, pre) // Only add non-empty fragments
		}
		pre.Offset = cur.endOffset()
	}
	pre.Length = size - pre.Offset // Possibly the only empty fragment
	return append(dst, pre)
}

// fileState tracks the number of logical (includes sparse holes) and physical
// (actual in tar archive) bytes remaining for the current file.
//
// Invariant: logicalRemaining >= physicalRemaining
type fileState interface {
	logicalRemaining() int64
	physicalRemaining() int64
}

// allowedFormats determines which formats can be used.
// The value returned is the logical OR of multiple possible formats.
// If the value is FormatUnknown, then the input Header cannot be encoded
// and an error is returned explaining why.
//
// As a by-product of checking the fields, this function returns paxHdrs, which
// contain all fields that could not be directly encoded.
// A value receiver ensures that this method does not mutate the source Header.
func (h Header) allowedFormats() (format Format, paxHdrs map[string]string, err error) {
	format = FormatUSTAR | FormatPAX | FormatGNU
	paxHdrs = make(map[string]string)

	var whyNoUSTAR, whyNoPAX, whyNoGNU string
	var preferPAX bool // Prefer PAX over USTAR
	verifyString := func(s string, size int, name, paxKey string) {
		// NUL-terminator is optional for path and linkpath.
		// Technically, it is required for uname and gname,
		// but neither GNU nor BSD tar checks for it.
		tooLong := len(s) > size
		allowLongGNU := paxKey == paxPath || paxKey == paxLinkpath
		if hasNUL(s) || (tooLong && !allowLongGNU) {
			whyNoGNU = fmt.Sprintf("GNU cannot encode %s=%q", name, s)
			format.mustNotBe(FormatGNU)
		}
		if !isASCII(s) || tooLong {
			canSplitUSTAR := paxKey == paxPath
			if _, _, ok := splitUSTARPath(s); !canSplitUSTAR || !ok {
				whyNoUSTAR = fmt.Sprintf("USTAR cannot encode %s=%q", name, s)
				format.mustNotBe(FormatUSTAR)
			}
			if paxKey == paxNone {
				whyNoPAX = fmt.Sprintf("PAX cannot encode %s=%q", name, s)
				format.mustNotBe(FormatPAX)
			} else {
				paxHdrs[paxKey] = s
			}
		}
		if v, ok := h.PAXRecords[paxKey]; ok && v == s {
			paxHdrs[paxKey] = v
		}
	}
	verifyNumeric := func(n int64, size int, name, paxKey string) {
		if !fitsInBase256(size, n) {
			whyNoGNU = fmt.Sprintf("GNU cannot encode %s=%d", name, n)
			format.mustNotBe(FormatGNU)
		}
		if !fitsInOctal(size, n) {
			whyNoUSTAR = fmt.Sprintf("USTAR cannot encode %s=%d", name, n)
			format.mustNotBe(FormatUSTAR)
			if paxKey == paxNone {
				whyNoPAX = fmt.Sprintf("PAX cannot encode %s=%d", name, n)
				format.mustNotBe(FormatPAX)
			} else {
				paxHdrs[paxKey] = strconv.FormatInt(n, 10)
			}
		}
		if v, ok := h.PAXRecords[paxKey]; ok && v == strconv.FormatInt(n, 10) {
			paxHdrs[paxKey] = v
		}
	}
	verifyTime := func(ts time.Time, size int, name, paxKey string) {
		if ts.IsZero() {
			return // Always okay
		}
		if !fitsInBase256(size, ts.Unix()) {
			whyNoGNU = fmt.Sprintf("GNU cannot encode %s=%v", name, ts)
			format.mustNotBe(FormatGNU)
		}
		isMtime := paxKey == paxMtime
		fitsOctal := fitsInOctal(size, ts.Unix())
		if (isMtime && !fitsOctal) || !isMtime {
			whyNoUSTAR = fmt.Sprintf("USTAR cannot encode %s=%v", name, ts)
			format.mustNotBe(FormatUSTAR)
		}
		needsNano := ts.Nanosecond() != 0
		if !isMtime || !fitsOctal || needsNano {
			preferPAX = true // USTAR may truncate sub-second measurements
			if paxKey == paxNone {
				whyNoPAX = fmt.Sprintf("PAX cannot encode %s=%v", name, ts)
				format.mustNotBe(FormatPAX)
			} else {
				paxHdrs[paxKey] = formatPAXTime(ts)
			}
		}
		if v, ok := h.PAXRecords[paxKey]; ok && v == formatPAXTime(ts) {
			paxHdrs[paxKey] = v
		}
	}

	// Check basic fields.
	var blk block
	v7 := blk.toV7()
	ustar := blk.toUSTAR()
	gnu := blk.toGNU()
	verifyString(h.Name, len(v7.name()), "Name", paxPath)
	verifyString(h.Linkname, len(v7.linkName()), "Linkname", paxLinkpath)
	verifyString(h.Uname, len(ustar.userName()), "Uname", paxUname)
	verifyString(h.Gname, len(ustar.groupName()), "Gname", paxGname)
	verifyNumeric(h.Mode, len(v7.mode()), "Mode", paxNone)
	verifyNumeric(int64(h.Uid), len(v7.uid()), "Uid", paxUid)
	verifyNumeric(int64(h.Gid), len(v7.gid()), "Gid", paxGid)
	verifyNumeric(h.Size, len(v7.size()), "Size", paxSize)
	verifyNumeric(h.Devmajor, len(ustar.devMajor()), "Devmajor", paxNone)
	verifyNumeric(h.Devminor, len(ustar.devMinor()), "Devminor", paxNone)
	verifyTime(h.ModTime, len(v7.modTime()), "ModTime", paxMtime)
	verifyTime(h.AccessTime, len(gnu.accessTime()), "AccessTime", paxAtime)
	verifyTime(h.ChangeTime, len(gnu.changeTime()), "ChangeTime", paxCtime)

	// Check for header-only types.
	var whyOnlyPAX, whyOnlyGNU string
	switch h.Typeflag {
	case TypeReg, TypeChar, TypeBlock, TypeFifo, TypeGNUSparse:
		// Exclude TypeLink and TypeSymlink, since they may reference directories.
		if strings.HasSuffix(h.Name, "/") {
			return FormatUnknown, nil, headerError{"filename may not have trailing slash"}
		}
	case TypeXHeader, TypeGNULongName, TypeGNULongLink:
		return FormatUnknown, nil, headerError{"cannot manually encode TypeXHeader, TypeGNULongName, or TypeGNULongLink headers"}
	case TypeXGlobalHeader:
		h2 := Header{Name: h.Name, Typeflag: h.Typeflag, Xattrs: h.Xattrs, PAXRecords: h.PAXRecords, Format: h.Format}
		if !reflect.DeepEqual(h, h2) {
			return FormatUnknown, nil, headerError{"only PAXRecords should be set for TypeXGlobalHeader"}
		}
		whyOnlyPAX = "only PAX supports TypeXGlobalHeader"
		format.mayOnlyBe(FormatPAX)
	}
	if !isHeaderOnlyType(h.Typeflag) && h.Size < 0 {
		return FormatUnknown, nil, headerError{"negative size on header-only type"}
	}

	// Check PAX records.
	if len(h.Xattrs) > 0 {
		for k, v := range h.Xattrs {
			paxHdrs[paxSchilyXattr+k] = v
		}
		whyOnlyPAX = "only PAX supports Xattrs"
		format.mayOnlyBe(FormatPAX)
	}
	if len(h.PAXRecords) > 0 {
		for k, v := range h.PAXRecords {
			switch _, exists := paxHdrs[k]; {
			case exists:
				continue // Do not overwrite existing records
			case h.Typeflag == TypeXGlobalHeader:
				paxHdrs[k] = v // Copy all records
			case !basicKeys[k] && !strings.HasPrefix(k, paxGNUSparse):
				paxHdrs[k] = v // Ignore local records that may conflict
			}
		}
		whyOnlyPAX = "only PAX supports PAXRecords"
		format.mayOnlyBe(FormatPAX)
	}
	for k, v := range paxHdrs {
		if !validPAXRecord(k, v) {
			return FormatUnknown, nil, headerError{fmt.Sprintf("invalid PAX record: %q", k+" = "+v)}
		}
	}

	// TODO(dsnet): Re-enable this when adding sparse support.
	// See https://golang.org/issue/22735
	/*
		// Check sparse files.
		if len(h.SparseHoles) > 0 || h.Typeflag == TypeGNUSparse {
			if isHeaderOnlyType(h.Typeflag) {
				return FormatUnknown, nil, headerError{"header-only type cannot be sparse"}
			}
			if !validateSparseEntries(h.SparseHoles, h.Size) {
				return FormatUnknown, nil, headerError{"invalid sparse holes"}
			}
			if h.Typeflag == TypeGNUSparse {
				whyOnlyGNU = "only GNU supports TypeGNUSparse"
				format.mayOnlyBe(FormatGNU)
			} else {
				whyNoGNU = "GNU supports sparse files only with TypeGNUSparse"
				format.mustNotBe(FormatGNU)
			}
			whyNoUSTAR = "USTAR does not support sparse files"
			format.mustNotBe(FormatUSTAR)
		}
	*/

	// Check desired format.
	if wantFormat := h.Format; wantFormat != FormatUnknown {
		if wantFormat.has(FormatPAX) && !preferPAX {
			wantFormat.mayBe(FormatUSTAR) // PAX implies USTAR allowed too
		}
		format.mayOnlyBe(wantFormat) // Set union of formats allowed and format wanted
	}
	if format == FormatUnknown {
		switch h.Format {
		case FormatUSTAR:
			err = headerError{"Format specifies USTAR", whyNoUSTAR, whyOnlyPAX, whyOnlyGNU}
		case FormatPAX:
			err = headerError{"Format specifies PAX", whyNoPAX, whyOnlyGNU}
		case FormatGNU:
			err = headerError{"Format specifies GNU", whyNoGNU, whyOnlyPAX}
		default:
			err = headerError{whyNoUSTAR, whyNoPAX, whyNoGNU, whyOnlyPAX, whyOnlyGNU}
		}
	}
	return format, paxHdrs, err
}

// FileInfo returns an fs.FileInfo for the Header.
func (h *Header) FileInfo() fs.FileInfo {
	return headerFileInfo{h}
}

// headerFileInfo implements fs.FileInfo.
type headerFileInfo struct {
	h *Header
}

func (fi headerFileInfo) Size() int64        { return fi.h.Size }
func (fi headerFileInfo) IsDir() bool        { return fi.Mode().IsDir() }
func (fi headerFileInfo) ModTime() time.Time { return fi.h.ModTime }
func (fi headerFileInfo) Sys() any           { return fi.h }

// Name returns the base name of the file.
func (fi headerFileInfo) Name() string {
	if fi.IsDir() {
		return path.Base(path.Clean(fi.h.Name))
	}
	return path.Base(fi.h.Name)
}

// Mode returns the permission and mode bits for the headerFileInfo.
func (fi headerFileInfo) Mode() (mode fs.FileMode) {
	// Set file permission bits.
	mode = fs.FileMode(fi.h.Mode).Perm()

	// Set setuid, setgid and sticky bits.
	if fi.h.Mode&c_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if fi.h.Mode&c_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if fi.h.Mode&c_ISVTX != 0 {
		mode |= fs.ModeSticky
	}

	// Set file mode bits; clear perm, setuid, setgid, and sticky bits.
	switch m := fs.FileMode(fi.h.Mode) &^ 07777; m {
	case c_ISDIR:
		mode |= fs.ModeDir
	case c_ISFIFO:
		mode |= fs.ModeNamedPipe
	case c_ISLNK:
		mode |= fs.ModeSymlink
	case c_ISBLK:
		mode |= fs.ModeDevice
	case c_ISCHR:
		mode |= fs.ModeDevice
		mode |= fs.ModeCharDevice
	case c_ISSOCK:
		mode |= fs.ModeSocket
	}

	switch fi.h.Typeflag {
	case TypeSymlink:
		mode |= fs.ModeSymlink
	case TypeChar:
		mode |= fs.ModeDevice
		mode |= fs.ModeCharDevice
	case TypeBlock:
		mode |= fs.ModeDevice
	case TypeDir:
		mode |= fs.ModeDir
	case TypeFifo:
		mode |= fs.ModeNamedPipe
	}

	return mode
}

func (fi headerFileInfo) String() string {
	return fs.FormatFileInfo(fi)
}

// sysStat, if non-nil, populates h from system-dependent fields of fi.
var sysStat func(fi fs.FileInfo, h *Header, doNameLookups bool) error

const (
	// Mode constants from the USTAR spec:
	// See http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html#tag_20_92_13_06
	c_ISUID = 04000 // Set uid
	c_ISGID = 02000 // Set gid
	c_ISVTX = 01000 // Save text (sticky bit)

	// Common Unix mode constants; these are not defined in any common tar standard.
	// Header.FileInfo understands these, but FileInfoHeader will never produce these.
	c_ISDIR  = 040000  // Directory
	c_ISFIFO = 010000  // FIFO
	c_ISREG  = 0100000 // Regular file
	c_ISLNK  = 0120000 // Symbolic link
	c_ISBLK  = 060000  // Block special file
	c_ISCHR  = 020000  // Character special file
	c_ISSOCK = 0140000 // Socket
)

// FileInfoHeader creates a partially-populated [Header] from fi.
// If fi describes a symlink, FileInfoHeader records link as the link target.
// If fi describes a directory, a slash is appended to the name.
//
// Since fs.FileInfo's Name method only returns the base name of
// the file it describes, it may be necessary to modify Header.Name
// to provide the full path name of the file.
//
// If fi implements [FileInfoNames]
// Header.Gname and Header.Uname
// are provided by the methods of the interface.
func FileInfoHeader(fi fs.FileInfo, link string) (*Header, error) {
	if fi == nil {
		return nil, errors.New("archive/tar: FileInfo is nil")
	}
	fm := fi.Mode()
	h := &Header{
		Name:    fi.Name(),
		ModTime: fi.ModTime(),
		Mode:    int64(fm.Perm()), // or'd with c_IS* constants later
	}
	switch {
	case fm.IsRegular():
		h.Typeflag = TypeReg
		h.Size = fi.Size()
	case fi.IsDir():
		h.Typeflag = TypeDir
		h.Name += "/"
	case fm&fs.ModeSymlink != 0:
		h.Typeflag = TypeSymlink
		h.Linkname = link
	case fm&fs.ModeDevice != 0:
		if fm&fs.ModeCharDevice != 0 {
			h.Typeflag = TypeChar
		} else {
			h.Typeflag = TypeBlock
		}
	case fm&fs.ModeNamedPipe != 0:
		h.Typeflag = TypeFifo
	case fm&fs.ModeSocket != 0:
		return nil, fmt.Errorf("archive/tar: sockets not supported")
	default:
		return nil, fmt.Errorf("archive/tar: unknown file mode %v", fm)
	}
	if fm&fs.ModeSetuid != 0 {
		h.Mode |= c_ISUID
	}
	if fm&fs.ModeSetgid != 0 {
		h.Mode |= c_ISGID
	}
	if fm&fs.ModeSticky != 0 {
		h.Mode |= c_ISVTX
	}
	// If possible, populate additional fields from OS-specific
	// FileInfo fields.
	if sys, ok := fi.Sys().(*Header); ok {
		// This FileInfo came from a Header (not the OS). Use the
		// original Header to populate all remaining fields.
		h.Uid = sys.Uid
		h.Gid = sys.Gid
		h.Uname = sys.Uname
		h.Gname = sys.Gname
		h.AccessTime = sys.AccessTime
		h.ChangeTime = sys.ChangeTime
		h.Xattrs = maps.Clone(sys.Xattrs)
		if sys.Typeflag == TypeLink {
			// hard link
			h.Typeflag = TypeLink
			h.Size = 0
			h.Linkname = sys.Linkname
		}
		h.PAXRecords = maps.Clone(sys.PAXRecords)
	}
	var doNameLookups = true
	if iface, ok := fi.(FileInfoNames); ok {
		doNameLookups = false
		var err error
		h.Gname, err = iface.Gname()
		if err != nil {
			return nil, err
		}
		h.Uname, err = iface.Uname()
		if err != nil {
			return nil, err
		}
	}
	if sysStat != nil {
		return h, sysStat(fi, h, doNameLookups)
	}
	return h, nil
}

// FileInfoNames extends [fs.FileInfo].
// Passing an instance of this to [FileInfoHeader] permits the caller
// to avoid a system-dependent name lookup by specifying the Uname and Gname directly.
type FileInfoNames interface {
	fs.FileInfo
	// Uname should give a user name.
	Uname() (string, error)
	// Gname should give a group name.
	Gname() (string, error)
}

// isHeaderOnlyType checks if the given type flag is of the type that has no
// data section even if a size is specified.
func isHeaderOnlyType(flag byte) bool {
	switch flag {
	case TypeLink, TypeSymlink, TypeChar, TypeBlock, TypeDir, TypeFifo:
		return true
	default:
		return false
	}
}
```