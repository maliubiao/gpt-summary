Response:
我的思考过程如下：

1. **理解目标：** 目标是分析 `go/src/archive/zip/struct.go` 文件的功能，并用 Go 代码示例进行说明，同时指出易错点。

2. **初步浏览和结构识别：**  首先快速浏览代码，识别关键的结构体（`FileHeader`、`directoryEnd`），常量定义（各种签名、长度、版本号、压缩方法），以及一些辅助函数。  我注意到文件头部的注释提供了包的整体描述，这很重要。

3. **核心功能识别：** 从包的注释和结构体的名称可以判断，这个文件是 `archive/zip` 包的核心组成部分，负责定义 ZIP 文件的内部数据结构。  `FileHeader` 明显是描述 ZIP 文件中每个文件的元数据的，而 `directoryEnd` 看起来与 ZIP 文件的结尾信息有关。  常量部分则定义了 ZIP 格式的各种标识。

4. **`FileHeader` 的详细分析：**  `FileHeader` 结构体字段很多，需要逐个分析其含义。我注意到注释中提到了 ZIP 规范，这暗示了该结构体是与 ZIP 规范紧密对应的。  我尤其关注了 `Name`, `Comment`, `Modified`, `CompressedSize`, `UncompressedSize`, `Extra` 等重要字段，并意识到 `CompressedSize64` 和 `UncompressedSize64` 是为了支持 ZIP64 格式。

5. **辅助函数的分析：**  关注 `FileInfo()`, `headerFileInfo`, `FileInfoHeader()` 这组函数，它们明显是为了将 `FileHeader` 与 Go 的 `io/fs` 包的接口关联起来。  `timeZone()`, `msDosTimeToTime()`, `timeToMsDosTime()` 这组函数是处理 ZIP 文件中时间戳的转换。  `ModTime()` 和 `SetModTime()` 是过时的 API，应该使用 `Modified` 字段。 `Mode()` 和 `SetMode()` 涉及到文件权限和模式的转换，这部分需要关注 Unix 和 MS-DOS 两种模式的处理。 `isZip64()` 和 `hasDataDescriptor()` 是辅助判断的函数。 `msdosModeToFileMode()`，`fileModeToUnixMode()`，`unixModeToFileMode()` 则是具体的模式转换逻辑。

6. **Go 代码示例构思：**  为了说明 `FileHeader` 的使用，我考虑了几个场景：
    * **创建 `FileHeader`:** 使用 `FileInfoHeader` 从 `os.FileInfo` 创建，并修改部分字段。
    * **访问 `FileHeader` 的信息:** 使用 `FileInfo()` 方法获取 `fs.FileInfo` 并访问其属性。
    * **设置和获取时间：**  展示 `Modified` 字段的使用。
    * **设置和获取权限：** 展示 `Mode()` 和 `SetMode()` 的使用。
    * **ZIP64 的概念：**  虽然没有直接的例子，但在解释 `CompressedSize` 和 `CompressedSize64` 的区别时提到了。

7. **推理 Go 语言功能实现：**  根据分析，这个文件是 `archive/zip` 包中定义 ZIP 文件格式的关键部分。它定义了表示 ZIP 文件内部结构的 Go 数据类型，使得 Go 能够读取和写入 ZIP 文件。

8. **易错点分析：**  我回顾了 `FileHeader` 的字段和函数，特别是那些有“Deprecated”标记的字段，以及关于字符编码和路径分隔符的说明。  我认为以下几点是用户容易犯错的：
    * **使用过时的字段:** 比如 `ModifiedDate` 和 `ModifiedTime`。
    * **字符编码问题:**  `NonUTF8` 标志的使用场景。
    * **路径格式:**  必须使用相对路径和正斜杠。
    * **ZIP64 的理解:**  当文件大小超过 4GB 时，需要注意使用 64 位的字段。

9. **命令行参数处理：**  这个文件本身不直接处理命令行参数，它是 `archive/zip` 包的一部分，而该包会被其他处理 ZIP 文件的程序使用。 我需要说明这一点。

10. **组织答案和润色：**  将以上分析组织成清晰的中文回答，包括功能列表、Go 代码示例、代码推理、命令行参数处理说明和易错点。  对答案进行润色，确保表达准确易懂。  我特别注意在代码示例中添加必要的注释，解释输入和输出。

通过以上思考过程，我逐步分析了 `struct.go` 文件的功能，并生成了最终的答案。  关键在于理解 ZIP 格式的原理，以及 Go 语言中 `archive/zip` 包的设计思路。


这是 Go 语言标准库 `archive/zip` 包中 `struct.go` 文件的一部分，它定义了 ZIP 归档文件的内部数据结构和相关常量。 它的主要功能是：

**1. 定义 ZIP 文件格式的数据结构:**

*   **`FileHeader`**:  定义了 ZIP 文件中每个文件的头部信息，包括文件名、压缩方法、修改时间、CRC32 校验和、压缩和未压缩大小等。这个结构体是读取和写入 ZIP 文件的核心数据表示。
*   **`directoryEnd`**: 定义了 ZIP 归档文件目录的末尾记录，包含目录中文件记录的总数、目录的大小和偏移量等信息。
*   **常量**: 定义了 ZIP 文件格式中使用的各种签名（用于标识不同的数据结构，例如文件头、目录头等）、压缩方法（如 `Store` 和 `Deflate`）、版本号以及一些限制值。

**2. 提供与 `io/fs` 包集成的功能:**

*   **`FileHeader.FileInfo()`**:  将 `FileHeader` 转换为 `fs.FileInfo` 接口的实现，允许将 ZIP 文件中的文件视为文件系统中的文件进行操作，例如获取文件名、大小、修改时间、权限等。
*   **`FileInfoHeader()`**:  从 `fs.FileInfo` 创建一个 `FileHeader` 结构体，方便将文件系统中的文件添加到 ZIP 归档文件中。

**3. 提供处理时间和文件模式的功能:**

*   **`msDosTimeToTime()` 和 `timeToMsDosTime()`**: 在 MS-DOS 格式的时间和 Go 的 `time.Time` 类型之间进行转换。ZIP 格式早期使用 MS-DOS 的时间格式。
*   **`ModTime()` 和 `SetModTime()`**:  （已过时）用于获取和设置 MS-DOS 格式的修改时间。 推荐使用 `Modified` 字段。
*   **`Mode()` 和 `SetMode()`**: 获取和设置文件的权限和模式信息，支持 Unix 和 MS-DOS 两种文件系统模式的转换。

**4. 提供判断 ZIP64 和数据描述符的功能:**

*   **`isZip64()`**: 判断文件的大小是否超过 32 位限制，需要使用 ZIP64 扩展。
*   **`hasDataDescriptor()`**: 判断文件头是否使用了数据描述符来记录压缩后和未压缩后的大小以及 CRC32 校验和。

**它是什么 Go 语言功能的实现：**

这个文件是 Go 语言标准库中处理 ZIP 归档的核心实现。它定义了表示 ZIP 文件内部结构的数据类型，使得 Go 程序可以读取、创建和修改 ZIP 文件。 这涉及到文件格式解析、数据编码和解码等底层操作。

**Go 代码举例说明:**

假设我们有一个名为 `test.txt` 的文件，我们想将其添加到 ZIP 归档中。

```go
package main

import (
	"archive/zip"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

func main() {
	// 创建一个临时的 ZIP 文件
	zipFile, err := os.Create("example.zip")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer zipFile.Close()

	// 创建 ZIP 写入器
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// 读取要添加到 ZIP 的文件信息
	fileInfo, err := os.Stat("test.txt")
	if err != nil {
		fmt.Println(err)
		return
	}

	// 使用 FileInfoHeader 创建 FileHeader
	header, err := zip.FileInfoHeader(fileInfo)
	if err != nil {
		fmt.Println(err)
		return
	}
	header.Name = "inner/test.txt" // 设置 ZIP 文件中的路径
	header.Method = zip.Deflate    // 设置压缩方法

	// 创建 ZIP 文件中的文件
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 读取要添加到 ZIP 的文件的内容
	fileContent, err := ioutil.ReadFile("test.txt")
	if err != nil {
		fmt.Println(err)
		return
	}

	// 将文件内容写入 ZIP 文件
	_, err = writer.Write(fileContent)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("ZIP 文件创建成功！")
}
```

**假设输入与输出:**

*   **假设输入:** 当前目录下存在一个名为 `test.txt` 的文本文件，内容为 "Hello, ZIP!".
*   **预期输出:** 在当前目录下创建一个名为 `example.zip` 的 ZIP 归档文件，其中包含一个名为 `inner/test.txt` 的文件，内容为 "Hello, ZIP!"，并且使用了 Deflate 压缩。程序会打印 "ZIP 文件创建成功！"。

**代码推理:**

1. `os.Create("example.zip")` 创建了一个新的 ZIP 文件。
2. `zip.NewWriter(zipFile)` 创建了一个用于写入 ZIP 文件的 `zip.Writer`。
3. `os.Stat("test.txt")` 获取 `test.txt` 的文件信息。
4. `zip.FileInfoHeader(fileInfo)` 使用文件信息创建了一个 `FileHeader` 结构体，其中包含了文件名、大小、修改时间等信息。
5. `header.Name = "inner/test.txt"` 修改了 `FileHeader` 中的文件名，指定了在 ZIP 文件中的路径。
6. `header.Method = zip.Deflate` 设置了压缩方法为 Deflate。
7. `zipWriter.CreateHeader(header)` 使用创建的 `FileHeader` 在 ZIP 文件中创建了一个新的文件入口。
8. `ioutil.ReadFile("test.txt")` 读取了 `test.txt` 的内容。
9. `writer.Write(fileContent)` 将 `test.txt` 的内容写入到 ZIP 文件中。

**命令行参数的具体处理:**

这个 `struct.go` 文件本身并不直接处理命令行参数。 命令行参数的处理通常发生在调用 `archive/zip` 包的程序中。 例如，一个用于创建 ZIP 文件的命令行工具可能会使用 `flag` 包或 `os.Args` 来解析用户提供的输入文件和输出文件路径。

**使用者易犯错的点:**

*   **使用过时的字段:**  `ModifiedTime` 和 `ModifiedDate` 字段已经过时，应该使用 `Modified` 字段来处理时间信息。直接操作这两个字段可能会导致时间信息的处理不一致。
*   **字符编码问题:**  `Name` 和 `Comment` 字段的字符编码需要注意。 默认情况下，Go 的 `zip` 包会尝试使用 UTF-8 编码。如果文件名或注释使用了其他编码，并且 `NonUTF8` 标志没有正确设置，可能会导致解压时出现乱码。
*   **路径分隔符:**  ZIP 文件内部使用正斜杠 `/` 作为路径分隔符，即使在 Windows 系统上也是如此。创建 `FileHeader` 时，需要确保 `Name` 字段使用正斜杠。
*   **ZIP64 的理解:**  对于大于 4GB 的文件，需要使用 ZIP64 扩展。 虽然 Go 的 `zip` 包会自动处理大部分 ZIP64 的情况，但理解 `CompressedSize64` 和 `UncompressedSize64` 的作用以及何时会用到它们是很重要的。如果手动创建 `FileHeader`，需要注意在必要时设置这些 64 位字段。

例如，一个常见的错误是直接使用 `ModifiedDate` 和 `ModifiedTime` 而不是 `Modified` 字段来设置或获取文件修改时间，这可能会导致时区信息的丢失或不准确。应该始终使用 `Modified` 字段，因为它能更好地处理时区信息。

```go
// 错误的示例：直接使用 ModifiedDate 和 ModifiedTime
header := &zip.FileHeader{
    Name: "my_file.txt",
    ModifiedDate: uint16(time.Now().YearDay()), // 这种方式不包含完整的日期和时间信息
    ModifiedTime: uint16(time.Now().Second()/2 + time.Now().Minute()<<5 + time.Now().Hour()<<11),
}

// 正确的示例：使用 Modified 字段
header := &zip.FileHeader{
    Name:     "my_file.txt",
    Modified: time.Now(),
}
```

Prompt: 
```
这是路径为go/src/archive/zip/struct.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package zip provides support for reading and writing ZIP archives.

See the [ZIP specification] for details.

This package does not support disk spanning.

A note about ZIP64:

To be backwards compatible the FileHeader has both 32 and 64 bit Size
fields. The 64 bit fields will always contain the correct value and
for normal archives both fields will be the same. For files requiring
the ZIP64 format the 32 bit fields will be 0xffffffff and the 64 bit
fields must be used instead.

[ZIP specification]: https://support.pkware.com/pkzip/appnote
*/
package zip

import (
	"io/fs"
	"path"
	"time"
)

// Compression methods.
const (
	Store   uint16 = 0 // no compression
	Deflate uint16 = 8 // DEFLATE compressed
)

const (
	fileHeaderSignature      = 0x04034b50
	directoryHeaderSignature = 0x02014b50
	directoryEndSignature    = 0x06054b50
	directory64LocSignature  = 0x07064b50
	directory64EndSignature  = 0x06064b50
	dataDescriptorSignature  = 0x08074b50 // de-facto standard; required by OS X Finder
	fileHeaderLen            = 30         // + filename + extra
	directoryHeaderLen       = 46         // + filename + extra + comment
	directoryEndLen          = 22         // + comment
	dataDescriptorLen        = 16         // four uint32: descriptor signature, crc32, compressed size, size
	dataDescriptor64Len      = 24         // two uint32: signature, crc32 | two uint64: compressed size, size
	directory64LocLen        = 20         //
	directory64EndLen        = 56         // + extra

	// Constants for the first byte in CreatorVersion.
	creatorFAT    = 0
	creatorUnix   = 3
	creatorNTFS   = 11
	creatorVFAT   = 14
	creatorMacOSX = 19

	// Version numbers.
	zipVersion20 = 20 // 2.0
	zipVersion45 = 45 // 4.5 (reads and writes zip64 archives)

	// Limits for non zip64 files.
	uint16max = (1 << 16) - 1
	uint32max = (1 << 32) - 1

	// Extra header IDs.
	//
	// IDs 0..31 are reserved for official use by PKWARE.
	// IDs above that range are defined by third-party vendors.
	// Since ZIP lacked high precision timestamps (nor an official specification
	// of the timezone used for the date fields), many competing extra fields
	// have been invented. Pervasive use effectively makes them "official".
	//
	// See http://mdfs.net/Docs/Comp/Archiving/Zip/ExtraField
	zip64ExtraID       = 0x0001 // Zip64 extended information
	ntfsExtraID        = 0x000a // NTFS
	unixExtraID        = 0x000d // UNIX
	extTimeExtraID     = 0x5455 // Extended timestamp
	infoZipUnixExtraID = 0x5855 // Info-ZIP Unix extension
)

// FileHeader describes a file within a ZIP file.
// See the [ZIP specification] for details.
//
// [ZIP specification]: https://support.pkware.com/pkzip/appnote
type FileHeader struct {
	// Name is the name of the file.
	//
	// It must be a relative path, not start with a drive letter (such as "C:"),
	// and must use forward slashes instead of back slashes. A trailing slash
	// indicates that this file is a directory and should have no data.
	Name string

	// Comment is any arbitrary user-defined string shorter than 64KiB.
	Comment string

	// NonUTF8 indicates that Name and Comment are not encoded in UTF-8.
	//
	// By specification, the only other encoding permitted should be CP-437,
	// but historically many ZIP readers interpret Name and Comment as whatever
	// the system's local character encoding happens to be.
	//
	// This flag should only be set if the user intends to encode a non-portable
	// ZIP file for a specific localized region. Otherwise, the Writer
	// automatically sets the ZIP format's UTF-8 flag for valid UTF-8 strings.
	NonUTF8 bool

	CreatorVersion uint16
	ReaderVersion  uint16
	Flags          uint16

	// Method is the compression method. If zero, Store is used.
	Method uint16

	// Modified is the modified time of the file.
	//
	// When reading, an extended timestamp is preferred over the legacy MS-DOS
	// date field, and the offset between the times is used as the timezone.
	// If only the MS-DOS date is present, the timezone is assumed to be UTC.
	//
	// When writing, an extended timestamp (which is timezone-agnostic) is
	// always emitted. The legacy MS-DOS date field is encoded according to the
	// location of the Modified time.
	Modified time.Time

	// ModifiedTime is an MS-DOS-encoded time.
	//
	// Deprecated: Use Modified instead.
	ModifiedTime uint16

	// ModifiedDate is an MS-DOS-encoded date.
	//
	// Deprecated: Use Modified instead.
	ModifiedDate uint16

	// CRC32 is the CRC32 checksum of the file content.
	CRC32 uint32

	// CompressedSize is the compressed size of the file in bytes.
	// If either the uncompressed or compressed size of the file
	// does not fit in 32 bits, CompressedSize is set to ^uint32(0).
	//
	// Deprecated: Use CompressedSize64 instead.
	CompressedSize uint32

	// UncompressedSize is the uncompressed size of the file in bytes.
	// If either the uncompressed or compressed size of the file
	// does not fit in 32 bits, UncompressedSize is set to ^uint32(0).
	//
	// Deprecated: Use UncompressedSize64 instead.
	UncompressedSize uint32

	// CompressedSize64 is the compressed size of the file in bytes.
	CompressedSize64 uint64

	// UncompressedSize64 is the uncompressed size of the file in bytes.
	UncompressedSize64 uint64

	Extra         []byte
	ExternalAttrs uint32 // Meaning depends on CreatorVersion
}

// FileInfo returns an fs.FileInfo for the [FileHeader].
func (h *FileHeader) FileInfo() fs.FileInfo {
	return headerFileInfo{h}
}

// headerFileInfo implements [fs.FileInfo].
type headerFileInfo struct {
	fh *FileHeader
}

func (fi headerFileInfo) Name() string { return path.Base(fi.fh.Name) }
func (fi headerFileInfo) Size() int64 {
	if fi.fh.UncompressedSize64 > 0 {
		return int64(fi.fh.UncompressedSize64)
	}
	return int64(fi.fh.UncompressedSize)
}
func (fi headerFileInfo) IsDir() bool { return fi.Mode().IsDir() }
func (fi headerFileInfo) ModTime() time.Time {
	if fi.fh.Modified.IsZero() {
		return fi.fh.ModTime()
	}
	return fi.fh.Modified.UTC()
}
func (fi headerFileInfo) Mode() fs.FileMode { return fi.fh.Mode() }
func (fi headerFileInfo) Type() fs.FileMode { return fi.fh.Mode().Type() }
func (fi headerFileInfo) Sys() any          { return fi.fh }

func (fi headerFileInfo) Info() (fs.FileInfo, error) { return fi, nil }

func (fi headerFileInfo) String() string {
	return fs.FormatFileInfo(fi)
}

// FileInfoHeader creates a partially-populated [FileHeader] from an
// fs.FileInfo.
// Because fs.FileInfo's Name method returns only the base name of
// the file it describes, it may be necessary to modify the Name field
// of the returned header to provide the full path name of the file.
// If compression is desired, callers should set the FileHeader.Method
// field; it is unset by default.
func FileInfoHeader(fi fs.FileInfo) (*FileHeader, error) {
	size := fi.Size()
	fh := &FileHeader{
		Name:               fi.Name(),
		UncompressedSize64: uint64(size),
	}
	fh.SetModTime(fi.ModTime())
	fh.SetMode(fi.Mode())
	if fh.UncompressedSize64 > uint32max {
		fh.UncompressedSize = uint32max
	} else {
		fh.UncompressedSize = uint32(fh.UncompressedSize64)
	}
	return fh, nil
}

type directoryEnd struct {
	diskNbr            uint32 // unused
	dirDiskNbr         uint32 // unused
	dirRecordsThisDisk uint64 // unused
	directoryRecords   uint64
	directorySize      uint64
	directoryOffset    uint64 // relative to file
	commentLen         uint16
	comment            string
}

// timeZone returns a *time.Location based on the provided offset.
// If the offset is non-sensible, then this uses an offset of zero.
func timeZone(offset time.Duration) *time.Location {
	const (
		minOffset   = -12 * time.Hour  // E.g., Baker island at -12:00
		maxOffset   = +14 * time.Hour  // E.g., Line island at +14:00
		offsetAlias = 15 * time.Minute // E.g., Nepal at +5:45
	)
	offset = offset.Round(offsetAlias)
	if offset < minOffset || maxOffset < offset {
		offset = 0
	}
	return time.FixedZone("", int(offset/time.Second))
}

// msDosTimeToTime converts an MS-DOS date and time into a time.Time.
// The resolution is 2s.
// See: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime
func msDosTimeToTime(dosDate, dosTime uint16) time.Time {
	return time.Date(
		// date bits 0-4: day of month; 5-8: month; 9-15: years since 1980
		int(dosDate>>9+1980),
		time.Month(dosDate>>5&0xf),
		int(dosDate&0x1f),

		// time bits 0-4: second/2; 5-10: minute; 11-15: hour
		int(dosTime>>11),
		int(dosTime>>5&0x3f),
		int(dosTime&0x1f*2),
		0, // nanoseconds

		time.UTC,
	)
}

// timeToMsDosTime converts a time.Time to an MS-DOS date and time.
// The resolution is 2s.
// See: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-filetimetodosdatetime
func timeToMsDosTime(t time.Time) (fDate uint16, fTime uint16) {
	fDate = uint16(t.Day() + int(t.Month())<<5 + (t.Year()-1980)<<9)
	fTime = uint16(t.Second()/2 + t.Minute()<<5 + t.Hour()<<11)
	return
}

// ModTime returns the modification time in UTC using the legacy
// [ModifiedDate] and [ModifiedTime] fields.
//
// Deprecated: Use [Modified] instead.
func (h *FileHeader) ModTime() time.Time {
	return msDosTimeToTime(h.ModifiedDate, h.ModifiedTime)
}

// SetModTime sets the [Modified], [ModifiedTime], and [ModifiedDate] fields
// to the given time in UTC.
//
// Deprecated: Use [Modified] instead.
func (h *FileHeader) SetModTime(t time.Time) {
	t = t.UTC() // Convert to UTC for compatibility
	h.Modified = t
	h.ModifiedDate, h.ModifiedTime = timeToMsDosTime(t)
}

const (
	// Unix constants. The specification doesn't mention them,
	// but these seem to be the values agreed on by tools.
	s_IFMT   = 0xf000
	s_IFSOCK = 0xc000
	s_IFLNK  = 0xa000
	s_IFREG  = 0x8000
	s_IFBLK  = 0x6000
	s_IFDIR  = 0x4000
	s_IFCHR  = 0x2000
	s_IFIFO  = 0x1000
	s_ISUID  = 0x800
	s_ISGID  = 0x400
	s_ISVTX  = 0x200

	msdosDir      = 0x10
	msdosReadOnly = 0x01
)

// Mode returns the permission and mode bits for the [FileHeader].
func (h *FileHeader) Mode() (mode fs.FileMode) {
	switch h.CreatorVersion >> 8 {
	case creatorUnix, creatorMacOSX:
		mode = unixModeToFileMode(h.ExternalAttrs >> 16)
	case creatorNTFS, creatorVFAT, creatorFAT:
		mode = msdosModeToFileMode(h.ExternalAttrs)
	}
	if len(h.Name) > 0 && h.Name[len(h.Name)-1] == '/' {
		mode |= fs.ModeDir
	}
	return mode
}

// SetMode changes the permission and mode bits for the [FileHeader].
func (h *FileHeader) SetMode(mode fs.FileMode) {
	h.CreatorVersion = h.CreatorVersion&0xff | creatorUnix<<8
	h.ExternalAttrs = fileModeToUnixMode(mode) << 16

	// set MSDOS attributes too, as the original zip does.
	if mode&fs.ModeDir != 0 {
		h.ExternalAttrs |= msdosDir
	}
	if mode&0200 == 0 {
		h.ExternalAttrs |= msdosReadOnly
	}
}

// isZip64 reports whether the file size exceeds the 32 bit limit
func (h *FileHeader) isZip64() bool {
	return h.CompressedSize64 >= uint32max || h.UncompressedSize64 >= uint32max
}

func (h *FileHeader) hasDataDescriptor() bool {
	return h.Flags&0x8 != 0
}

func msdosModeToFileMode(m uint32) (mode fs.FileMode) {
	if m&msdosDir != 0 {
		mode = fs.ModeDir | 0777
	} else {
		mode = 0666
	}
	if m&msdosReadOnly != 0 {
		mode &^= 0222
	}
	return mode
}

func fileModeToUnixMode(mode fs.FileMode) uint32 {
	var m uint32
	switch mode & fs.ModeType {
	default:
		m = s_IFREG
	case fs.ModeDir:
		m = s_IFDIR
	case fs.ModeSymlink:
		m = s_IFLNK
	case fs.ModeNamedPipe:
		m = s_IFIFO
	case fs.ModeSocket:
		m = s_IFSOCK
	case fs.ModeDevice:
		m = s_IFBLK
	case fs.ModeDevice | fs.ModeCharDevice:
		m = s_IFCHR
	}
	if mode&fs.ModeSetuid != 0 {
		m |= s_ISUID
	}
	if mode&fs.ModeSetgid != 0 {
		m |= s_ISGID
	}
	if mode&fs.ModeSticky != 0 {
		m |= s_ISVTX
	}
	return m | uint32(mode&0777)
}

func unixModeToFileMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0777)
	switch m & s_IFMT {
	case s_IFBLK:
		mode |= fs.ModeDevice
	case s_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case s_IFDIR:
		mode |= fs.ModeDir
	case s_IFIFO:
		mode |= fs.ModeNamedPipe
	case s_IFLNK:
		mode |= fs.ModeSymlink
	case s_IFREG:
		// nothing to do
	case s_IFSOCK:
		mode |= fs.ModeSocket
	}
	if m&s_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if m&s_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if m&s_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

"""



```