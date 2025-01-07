Response:
Let's break down the thought process for analyzing this Go code snippet for `archive/zip/reader.go`.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, including inferring its purpose, giving Go code examples, detailing command-line handling (if any), and highlighting common pitfalls.

2. **Identify the Core Package and File:** The code resides in `go/src/archive/zip/reader.go`. This immediately tells us it's part of the standard Go library and deals with reading ZIP archives. The `reader.go` suffix suggests it focuses on the reading aspect.

3. **Scan for Key Data Structures:** Look for prominent structs. `Reader`, `ReadCloser`, and `File` stand out. These likely represent the main ways to interact with ZIP archives.

4. **Analyze the `Reader` Struct:**
   - `r io.ReaderAt`:  Indicates the underlying source is read randomly, suggesting the ability to jump around the ZIP file.
   - `File []*File`: A slice of `File` structs, representing the individual files within the archive.
   - `Comment string`: Stores the ZIP archive's comment.
   - `decompressors map[uint16]Decompressor`: Hints at support for different compression methods.
   - `baseOffset int64`: Suggests handling of ZIP files embedded within other files (like self-extracting archives or JARs with a script prefix).
   - `fileListOnce sync.Once`, `fileList []fileListEntry`:  Points to an internal mechanism for managing and accessing the file list, likely for methods like `Open`.

5. **Analyze the `ReadCloser` Struct:**
   - `f *os.File`:  Indicates that this reader is tied to an actual file on the filesystem and needs to be closed.
   - `Reader`: Embeds the `Reader`, meaning it inherits its functionality.

6. **Analyze the `File` Struct:**
   - `FileHeader`:  Suggests this struct holds the metadata about a single file in the ZIP.
   - `zip *Reader`: A back-reference to the parent `Reader`.
   - `zipr io.ReaderAt`:  Similar to the `Reader`, allowing random access to the underlying data.
   - `headerOffset int64`:  The location of this file's header within the ZIP.
   - `zip64 bool`: Indicates support for large ZIP files (beyond the limitations of the original ZIP format).

7. **Examine Key Functions and Their Purpose:**
   - `OpenReader(name string) (*ReadCloser, error)`:  Opens a ZIP file from the filesystem. The comment about `zipinsecurepath` is crucial for security considerations.
   - `NewReader(r io.ReaderAt, size int64) (*Reader, error)`: Creates a `Reader` from an `io.ReaderAt`, offering flexibility beyond just filesystem files.
   - `Reader.init(...)`:  The core initialization logic, responsible for parsing the ZIP structure.
   - `Reader.RegisterDecompressor(...)`:  Allows adding custom decompression algorithms.
   - `File.Open() (io.ReadCloser, error)`:  Provides access to the *content* of a specific file within the ZIP, handling decompression and checksumming.
   - `File.OpenRaw() (io.Reader, error)`:  Provides raw, uncompressed access to the file's data.
   - `Reader.Open(name string) (fs.File, error)`: Implements the `fs.FS` interface, allowing interaction with the ZIP as a virtual filesystem.

8. **Infer Go Feature Implementation:** Based on the structures and functions, it's clear this code implements the functionality to *read* ZIP archives in Go. The `fs.FS` interface implementation is a significant feature to highlight.

9. **Construct Go Code Examples:** Create simple, illustrative examples using the key functions like `OpenReader` and accessing file contents. Include examples for listing files and reading a specific file's content.

10. **Analyze for Command-Line Parameters:** Carefully examine the code for any direct handling of `os.Args` or similar mechanisms. In this case, there are no explicit command-line argument parsing elements within this code snippet. However, the `OpenReader` function takes a filename as an argument, which could *originate* from a command line.

11. **Identify Potential Pitfalls:** Look for areas where users might make mistakes. The `zipinsecurepath` handling is a major point. Also, the need to `Close()` `ReadCloser` and potential issues with large ZIP files (zip64) are worth mentioning. The distinction between `Open` and `OpenRaw` is another potential source of confusion.

12. **Structure the Answer in Chinese:**  Translate the findings into clear and concise Chinese, addressing all parts of the original request. Use appropriate terminology for Go concepts.

13. **Review and Refine:** Read through the answer to ensure accuracy, completeness, and clarity. Check that the code examples are correct and easy to understand. Make sure the explanation of potential pitfalls is well-articulated.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the low-level parsing of ZIP headers.
* **Correction:**  Realize the higher-level functionality provided by `Reader.Open` implementing `fs.FS` is also very important and should be prominently featured.
* **Initial thought:**  Assume all decompression is handled implicitly.
* **Correction:** Note the `RegisterDecompressor` function and mention the default decompression methods. Highlight the existence of `OpenRaw` for uncompressed access.
* **Initial thought:** Overlook the `zipinsecurepath` aspect.
* **Correction:**  Recognize the security implications and explain the behavior controlled by the environment variable. This is a critical detail.
* **Initial thought:**  Not provide any code examples.
* **Correction:**  Add clear, runnable code examples to demonstrate the usage of the key functions. This greatly improves understanding.

By following this structured approach, including self-correction, we arrive at a comprehensive and accurate answer to the request.
这段代码是 Go 语言 `archive/zip` 标准库中用于 **读取 ZIP 归档文件** 的一部分实现。它提供了将 ZIP 文件作为可读取的数据源进行操作的功能。

以下是它的主要功能：

1. **打开和读取 ZIP 文件:**
   - 提供了 `OpenReader` 函数，可以打开指定路径的 ZIP 文件，并返回一个 `ReadCloser` 结构体，用于后续读取操作。
   - 提供了 `NewReader` 函数，可以从一个 `io.ReaderAt` 接口读取 ZIP 文件数据，这使得可以从内存或其他数据源读取 ZIP 文件，而不仅仅是文件系统中的文件。

2. **访问 ZIP 文件中的文件:**
   - `Reader` 结构体包含一个 `File` 类型的切片，每个 `File` 结构体代表 ZIP 归档中的一个文件。
   - `File` 结构体包含了文件的元数据信息（存储在 `FileHeader` 中），例如文件名、大小、修改时间、压缩方法等。
   - `File` 结构体的 `Open` 方法可以打开 ZIP 归档中的单个文件，返回一个 `io.ReadCloser` 用于读取该文件的内容。  `Open` 方法会自动处理文件的解压缩和校验和验证。
   - `File` 结构体的 `OpenRaw` 方法也可以打开 ZIP 归档中的单个文件，但返回一个 `io.Reader`，提供对压缩后数据的直接访问，不进行解压缩。

3. **处理不同的压缩算法:**
   - `Reader` 结构体维护一个 `decompressors` 映射，用于存储不同压缩方法的解压器。
   - `RegisterDecompressor` 方法允许用户注册自定义的解压器，以便支持标准库中未包含的压缩算法。
   - `decompressor` 方法用于查找给定压缩方法的解压器。

4. **校验和验证:**
   - 在通过 `File.Open` 读取文件内容时，会自动进行 CRC32 校验和验证，以确保数据的完整性。如果校验和不匹配，会返回 `ErrChecksum` 错误。

5. **处理 ZIP64 扩展:**
   - 代码中包含了对 ZIP64 扩展的支持，这意味着它可以处理大于 4GB 的 ZIP 文件以及包含超过 65535 个文件的 ZIP 归档。

6. **安全路径处理 (通过 `zipinsecurepath` GODEBUG):**
   - 代码引入了一个通过 `zipinsecurepath` GODEBUG 环境变量控制的安全特性。
   - 如果 `zipinsecurepath=0`，且 ZIP 文件中包含非本地路径（例如以 `\` 开头或包含 `..`）或包含反斜杠的文件名，`OpenReader` 和 `NewReader` 会返回 `ErrInsecurePath` 错误。
   - 这是一个安全措施，旨在防止 ZIP 炸弹等安全漏洞。

7. **实现 `fs.FS` 接口:**
   - `Reader` 结构体实现了 `fs.FS` 接口，这意味着可以将 ZIP 归档视为一个虚拟的文件系统进行操作。
   - `Open` 方法（注意与 `File` 的 `Open` 方法区分）用于打开 ZIP 归档中的文件或目录，返回一个 `fs.File` 接口。对于目录，返回一个可以读取目录项的结构体。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言中用于 **读取 ZIP 归档文件** 功能的核心实现。它利用了 Go 的 `io` 包提供的接口（如 `io.ReaderAt`, `io.ReadCloser`）和错误处理机制，以及 `encoding/binary` 包进行二进制数据的解析。  它还展示了如何使用 GODEBUG 环境变量来控制程序行为，以及如何实现 `fs.FS` 接口来提供文件系统的抽象。

**Go 代码举例说明:**

假设我们有一个名为 `example.zip` 的 ZIP 文件，其中包含两个文件：`file1.txt` 和一个名为 `subdir` 的子目录，`subdir` 中包含 `file2.txt`。

```go
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

func main() {
	// 打开 ZIP 文件
	r, err := zip.OpenReader("example.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	// 遍历 ZIP 文件中的所有文件
	fmt.Println("Files in the ZIP archive:")
	for _, f := range r.File {
		fmt.Printf("  %s", f.Name)
		if f.FileInfo().IsDir() {
			fmt.Println("/")
		} else {
			fmt.Println()
		}
	}

	// 读取特定文件的内容
	fileName := "file1.txt"
	fmt.Printf("\nContent of %s:\n", fileName)
	file, err := r.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(content))

	// 使用 fs.FS 接口列出子目录的内容
	subdirName := "subdir"
	fmt.Printf("\nContents of directory %s:\n", subdirName)
	dirEntry, err := r.Open(subdirName)
	if err != nil {
		log.Fatal(err)
	}
	defer dirEntry.Close()

	dir, ok := dirEntry.(fs.ReadDirFile)
	if !ok {
		log.Fatalf("%s is not a directory", subdirName)
	}

	dirEntries, err := dir.ReadDir(-1) // 读取所有目录项
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range dirEntries {
		fmt.Println(" ", entry.Name())
	}
}
```

**假设的输入与输出:**

**输入 (example.zip):**

包含以下文件：

- `file1.txt`，内容为 "Hello from file1.txt"
- `subdir/file2.txt`，内容为 "Content in file2.txt"

**输出:**

```
Files in the ZIP archive:
  file1.txt
  subdir/
  subdir/file2.txt

Content of file1.txt:
Hello from file1.txt

Contents of directory subdir:
  file2.txt
```

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。但是，`OpenReader` 函数接收一个字符串参数 `name`，这个 `name` 通常是从命令行参数中获取的文件路径。例如，如果用户通过命令行执行 `myprogram example.zip`，那么 `example.zip` 就会作为参数传递给 `OpenReader`。

**使用者易犯错的点:**

1. **忘记关闭 `ReadCloser`:** `OpenReader` 返回的 `ReadCloser` 和 `File.Open` 返回的 `io.ReadCloser` 都需要在不再使用时关闭，以释放底层的文件句柄。忘记关闭会导致资源泄漏。

   ```go
   r, err := zip.OpenReader("my.zip")
   if err != nil {
       // ... 处理错误
   }
   // 忘记了 r.Close()
   ```

   **应该这样做:**

   ```go
   r, err := zip.OpenReader("my.zip")
   if err != nil {
       // ... 处理错误
   }
   defer r.Close() // 确保在函数退出时关闭
   ```

2. **错误地处理路径分隔符:**  ZIP 文件内部使用正斜杠 `/` 作为路径分隔符，即使在 Windows 系统上也是如此。用户可能会混淆使用反斜杠 `\`，尤其是在手动创建 ZIP 文件时。

   ```go
   // 假设 ZIP 文件中有一个文件名为 "path\to\file.txt" (错误)
   file, err := r.Open("path\\to\\file.txt") // 错误地使用了反斜杠
   if err != nil {
       // ... 可能会返回 "file does not exist" 错误
   }
   ```

   **应该这样做:**

   ```go
   // 假设 ZIP 文件中有一个文件名为 "path/to/file.txt"
   file, err := r.Open("path/to/file.txt")
   if err != nil {
       // ...
   }
   ```

3. **忽略 `ErrInsecurePath` 错误:**  如果设置了 `GODEBUG=zipinsecurepath=0`，并且 ZIP 文件包含不安全的路径，`OpenReader` 或 `NewReader` 会返回 `ErrInsecurePath`。  简单地忽略这个错误可能会导致安全风险。使用者应该根据具体应用场景判断是否需要处理这种不安全的路径。

   ```go
   os.Setenv("GODEBUG", "zipinsecurepath=0")
   r, err := zip.OpenReader("potentially_malicious.zip")
   if err != nil {
       // 可能错误地忽略了 ErrInsecurePath
       log.Println("Error opening zip:", err)
   }
   if err == zip.ErrInsecurePath {
       log.Println("Insecure path detected!")
       // 应该考虑拒绝打开该 ZIP 文件或进行额外的安全检查
   }
   defer r.Close()
   ```

4. **假设文件总是以标准方式压缩:**  虽然 `archive/zip` 提供了对常见压缩算法的支持，但如果 ZIP 文件使用了自定义或不受支持的压缩算法，默认情况下会返回 `ErrAlgorithm` 错误。用户需要注册自定义的解压器才能处理这些情况。

   ```go
   r, err := zip.OpenReader("custom_compressed.zip")
   if err != nil {
       log.Fatal(err) // 可能会得到 ErrAlgorithm
   }
   defer r.Close()

   // 要处理自定义压缩，需要注册解压器
   // zip.RegisterDecompressor(...)
   ```

理解这些功能和潜在的陷阱可以帮助开发者更有效地使用 `archive/zip` 包来处理 ZIP 归档文件。

Prompt: 
```
这是路径为go/src/archive/zip/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"bufio"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"internal/godebug"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

var zipinsecurepath = godebug.New("zipinsecurepath")

var (
	ErrFormat       = errors.New("zip: not a valid zip file")
	ErrAlgorithm    = errors.New("zip: unsupported compression algorithm")
	ErrChecksum     = errors.New("zip: checksum error")
	ErrInsecurePath = errors.New("zip: insecure file path")
)

// A Reader serves content from a ZIP archive.
type Reader struct {
	r             io.ReaderAt
	File          []*File
	Comment       string
	decompressors map[uint16]Decompressor

	// Some JAR files are zip files with a prefix that is a bash script.
	// The baseOffset field is the start of the zip file proper.
	baseOffset int64

	// fileList is a list of files sorted by ename,
	// for use by the Open method.
	fileListOnce sync.Once
	fileList     []fileListEntry
}

// A ReadCloser is a [Reader] that must be closed when no longer needed.
type ReadCloser struct {
	f *os.File
	Reader
}

// A File is a single file in a ZIP archive.
// The file information is in the embedded [FileHeader].
// The file content can be accessed by calling [File.Open].
type File struct {
	FileHeader
	zip          *Reader
	zipr         io.ReaderAt
	headerOffset int64 // includes overall ZIP archive baseOffset
	zip64        bool  // zip64 extended information extra field presence
}

// OpenReader will open the Zip file specified by name and return a ReadCloser.
//
// If any file inside the archive uses a non-local name
// (as defined by [filepath.IsLocal]) or a name containing backslashes
// and the GODEBUG environment variable contains `zipinsecurepath=0`,
// OpenReader returns the reader with an ErrInsecurePath error.
// A future version of Go may introduce this behavior by default.
// Programs that want to accept non-local names can ignore
// the ErrInsecurePath error and use the returned reader.
func OpenReader(name string) (*ReadCloser, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	r := new(ReadCloser)
	if err = r.init(f, fi.Size()); err != nil && err != ErrInsecurePath {
		f.Close()
		return nil, err
	}
	r.f = f
	return r, err
}

// NewReader returns a new [Reader] reading from r, which is assumed to
// have the given size in bytes.
//
// If any file inside the archive uses a non-local name
// (as defined by [filepath.IsLocal]) or a name containing backslashes
// and the GODEBUG environment variable contains `zipinsecurepath=0`,
// NewReader returns the reader with an [ErrInsecurePath] error.
// A future version of Go may introduce this behavior by default.
// Programs that want to accept non-local names can ignore
// the [ErrInsecurePath] error and use the returned reader.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	if size < 0 {
		return nil, errors.New("zip: size cannot be negative")
	}
	zr := new(Reader)
	var err error
	if err = zr.init(r, size); err != nil && err != ErrInsecurePath {
		return nil, err
	}
	return zr, err
}

func (r *Reader) init(rdr io.ReaderAt, size int64) error {
	end, baseOffset, err := readDirectoryEnd(rdr, size)
	if err != nil {
		return err
	}
	r.r = rdr
	r.baseOffset = baseOffset
	// Since the number of directory records is not validated, it is not
	// safe to preallocate r.File without first checking that the specified
	// number of files is reasonable, since a malformed archive may
	// indicate it contains up to 1 << 128 - 1 files. Since each file has a
	// header which will be _at least_ 30 bytes we can safely preallocate
	// if (data size / 30) >= end.directoryRecords.
	if end.directorySize < uint64(size) && (uint64(size)-end.directorySize)/30 >= end.directoryRecords {
		r.File = make([]*File, 0, end.directoryRecords)
	}
	r.Comment = end.comment
	rs := io.NewSectionReader(rdr, 0, size)
	if _, err = rs.Seek(r.baseOffset+int64(end.directoryOffset), io.SeekStart); err != nil {
		return err
	}
	buf := bufio.NewReader(rs)

	// The count of files inside a zip is truncated to fit in a uint16.
	// Gloss over this by reading headers until we encounter
	// a bad one, and then only report an ErrFormat or UnexpectedEOF if
	// the file count modulo 65536 is incorrect.
	for {
		f := &File{zip: r, zipr: rdr}
		err = readDirectoryHeader(f, buf)
		if err == ErrFormat || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
		f.headerOffset += r.baseOffset
		r.File = append(r.File, f)
	}
	if uint16(len(r.File)) != uint16(end.directoryRecords) { // only compare 16 bits here
		// Return the readDirectoryHeader error if we read
		// the wrong number of directory entries.
		return err
	}
	if zipinsecurepath.Value() == "0" {
		for _, f := range r.File {
			if f.Name == "" {
				// Zip permits an empty file name field.
				continue
			}
			// The zip specification states that names must use forward slashes,
			// so consider any backslashes in the name insecure.
			if !filepath.IsLocal(f.Name) || strings.Contains(f.Name, `\`) {
				zipinsecurepath.IncNonDefault()
				return ErrInsecurePath
			}
		}
	}
	return nil
}

// RegisterDecompressor registers or overrides a custom decompressor for a
// specific method ID. If a decompressor for a given method is not found,
// [Reader] will default to looking up the decompressor at the package level.
func (r *Reader) RegisterDecompressor(method uint16, dcomp Decompressor) {
	if r.decompressors == nil {
		r.decompressors = make(map[uint16]Decompressor)
	}
	r.decompressors[method] = dcomp
}

func (r *Reader) decompressor(method uint16) Decompressor {
	dcomp := r.decompressors[method]
	if dcomp == nil {
		dcomp = decompressor(method)
	}
	return dcomp
}

// Close closes the Zip file, rendering it unusable for I/O.
func (rc *ReadCloser) Close() error {
	return rc.f.Close()
}

// DataOffset returns the offset of the file's possibly-compressed
// data, relative to the beginning of the zip file.
//
// Most callers should instead use [File.Open], which transparently
// decompresses data and verifies checksums.
func (f *File) DataOffset() (offset int64, err error) {
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return
	}
	return f.headerOffset + bodyOffset, nil
}

// Open returns a [ReadCloser] that provides access to the [File]'s contents.
// Multiple files may be read concurrently.
func (f *File) Open() (io.ReadCloser, error) {
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(f.Name, "/") {
		// The ZIP specification (APPNOTE.TXT) specifies that directories, which
		// are technically zero-byte files, must not have any associated file
		// data. We previously tried failing here if f.CompressedSize64 != 0,
		// but it turns out that a number of implementations (namely, the Java
		// jar tool) don't properly set the storage method on directories
		// resulting in a file with compressed size > 0 but uncompressed size ==
		// 0. We still want to fail when a directory has associated uncompressed
		// data, but we are tolerant of cases where the uncompressed size is
		// zero but compressed size is not.
		if f.UncompressedSize64 != 0 {
			return &dirReader{ErrFormat}, nil
		} else {
			return &dirReader{io.EOF}, nil
		}
	}
	size := int64(f.CompressedSize64)
	r := io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset, size)
	dcomp := f.zip.decompressor(f.Method)
	if dcomp == nil {
		return nil, ErrAlgorithm
	}
	var rc io.ReadCloser = dcomp(r)
	var desr io.Reader
	if f.hasDataDescriptor() {
		desr = io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset+size, dataDescriptorLen)
	}
	rc = &checksumReader{
		rc:   rc,
		hash: crc32.NewIEEE(),
		f:    f,
		desr: desr,
	}
	return rc, nil
}

// OpenRaw returns a [Reader] that provides access to the [File]'s contents without
// decompression.
func (f *File) OpenRaw() (io.Reader, error) {
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return nil, err
	}
	r := io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset, int64(f.CompressedSize64))
	return r, nil
}

type dirReader struct {
	err error
}

func (r *dirReader) Read([]byte) (int, error) {
	return 0, r.err
}

func (r *dirReader) Close() error {
	return nil
}

type checksumReader struct {
	rc    io.ReadCloser
	hash  hash.Hash32
	nread uint64 // number of bytes read so far
	f     *File
	desr  io.Reader // if non-nil, where to read the data descriptor
	err   error     // sticky error
}

func (r *checksumReader) Stat() (fs.FileInfo, error) {
	return headerFileInfo{&r.f.FileHeader}, nil
}

func (r *checksumReader) Read(b []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err = r.rc.Read(b)
	r.hash.Write(b[:n])
	r.nread += uint64(n)
	if r.nread > r.f.UncompressedSize64 {
		return 0, ErrFormat
	}
	if err == nil {
		return
	}
	if err == io.EOF {
		if r.nread != r.f.UncompressedSize64 {
			return 0, io.ErrUnexpectedEOF
		}
		if r.desr != nil {
			if err1 := readDataDescriptor(r.desr, r.f); err1 != nil {
				if err1 == io.EOF {
					err = io.ErrUnexpectedEOF
				} else {
					err = err1
				}
			} else if r.hash.Sum32() != r.f.CRC32 {
				err = ErrChecksum
			}
		} else {
			// If there's not a data descriptor, we still compare
			// the CRC32 of what we've read against the file header
			// or TOC's CRC32, if it seems like it was set.
			if r.f.CRC32 != 0 && r.hash.Sum32() != r.f.CRC32 {
				err = ErrChecksum
			}
		}
	}
	r.err = err
	return
}

func (r *checksumReader) Close() error { return r.rc.Close() }

// findBodyOffset does the minimum work to verify the file has a header
// and returns the file body offset.
func (f *File) findBodyOffset() (int64, error) {
	var buf [fileHeaderLen]byte
	if _, err := f.zipr.ReadAt(buf[:], f.headerOffset); err != nil {
		return 0, err
	}
	b := readBuf(buf[:])
	if sig := b.uint32(); sig != fileHeaderSignature {
		return 0, ErrFormat
	}
	b = b[22:] // skip over most of the header
	filenameLen := int(b.uint16())
	extraLen := int(b.uint16())
	return int64(fileHeaderLen + filenameLen + extraLen), nil
}

// readDirectoryHeader attempts to read a directory header from r.
// It returns io.ErrUnexpectedEOF if it cannot read a complete header,
// and ErrFormat if it doesn't find a valid header signature.
func readDirectoryHeader(f *File, r io.Reader) error {
	var buf [directoryHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	b := readBuf(buf[:])
	if sig := b.uint32(); sig != directoryHeaderSignature {
		return ErrFormat
	}
	f.CreatorVersion = b.uint16()
	f.ReaderVersion = b.uint16()
	f.Flags = b.uint16()
	f.Method = b.uint16()
	f.ModifiedTime = b.uint16()
	f.ModifiedDate = b.uint16()
	f.CRC32 = b.uint32()
	f.CompressedSize = b.uint32()
	f.UncompressedSize = b.uint32()
	f.CompressedSize64 = uint64(f.CompressedSize)
	f.UncompressedSize64 = uint64(f.UncompressedSize)
	filenameLen := int(b.uint16())
	extraLen := int(b.uint16())
	commentLen := int(b.uint16())
	b = b[4:] // skipped start disk number and internal attributes (2x uint16)
	f.ExternalAttrs = b.uint32()
	f.headerOffset = int64(b.uint32())
	d := make([]byte, filenameLen+extraLen+commentLen)
	if _, err := io.ReadFull(r, d); err != nil {
		return err
	}
	f.Name = string(d[:filenameLen])
	f.Extra = d[filenameLen : filenameLen+extraLen]
	f.Comment = string(d[filenameLen+extraLen:])

	// Determine the character encoding.
	utf8Valid1, utf8Require1 := detectUTF8(f.Name)
	utf8Valid2, utf8Require2 := detectUTF8(f.Comment)
	switch {
	case !utf8Valid1 || !utf8Valid2:
		// Name and Comment definitely not UTF-8.
		f.NonUTF8 = true
	case !utf8Require1 && !utf8Require2:
		// Name and Comment use only single-byte runes that overlap with UTF-8.
		f.NonUTF8 = false
	default:
		// Might be UTF-8, might be some other encoding; preserve existing flag.
		// Some ZIP writers use UTF-8 encoding without setting the UTF-8 flag.
		// Since it is impossible to always distinguish valid UTF-8 from some
		// other encoding (e.g., GBK or Shift-JIS), we trust the flag.
		f.NonUTF8 = f.Flags&0x800 == 0
	}

	needUSize := f.UncompressedSize == ^uint32(0)
	needCSize := f.CompressedSize == ^uint32(0)
	needHeaderOffset := f.headerOffset == int64(^uint32(0))

	// Best effort to find what we need.
	// Other zip authors might not even follow the basic format,
	// and we'll just ignore the Extra content in that case.
	var modified time.Time
parseExtras:
	for extra := readBuf(f.Extra); len(extra) >= 4; { // need at least tag and size
		fieldTag := extra.uint16()
		fieldSize := int(extra.uint16())
		if len(extra) < fieldSize {
			break
		}
		fieldBuf := extra.sub(fieldSize)

		switch fieldTag {
		case zip64ExtraID:
			f.zip64 = true

			// update directory values from the zip64 extra block.
			// They should only be consulted if the sizes read earlier
			// are maxed out.
			// See golang.org/issue/13367.
			if needUSize {
				needUSize = false
				if len(fieldBuf) < 8 {
					return ErrFormat
				}
				f.UncompressedSize64 = fieldBuf.uint64()
			}
			if needCSize {
				needCSize = false
				if len(fieldBuf) < 8 {
					return ErrFormat
				}
				f.CompressedSize64 = fieldBuf.uint64()
			}
			if needHeaderOffset {
				needHeaderOffset = false
				if len(fieldBuf) < 8 {
					return ErrFormat
				}
				f.headerOffset = int64(fieldBuf.uint64())
			}
		case ntfsExtraID:
			if len(fieldBuf) < 4 {
				continue parseExtras
			}
			fieldBuf.uint32()        // reserved (ignored)
			for len(fieldBuf) >= 4 { // need at least tag and size
				attrTag := fieldBuf.uint16()
				attrSize := int(fieldBuf.uint16())
				if len(fieldBuf) < attrSize {
					continue parseExtras
				}
				attrBuf := fieldBuf.sub(attrSize)
				if attrTag != 1 || attrSize != 24 {
					continue // Ignore irrelevant attributes
				}

				const ticksPerSecond = 1e7    // Windows timestamp resolution
				ts := int64(attrBuf.uint64()) // ModTime since Windows epoch
				secs := ts / ticksPerSecond
				nsecs := (1e9 / ticksPerSecond) * (ts % ticksPerSecond)
				epoch := time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC)
				modified = time.Unix(epoch.Unix()+secs, nsecs)
			}
		case unixExtraID, infoZipUnixExtraID:
			if len(fieldBuf) < 8 {
				continue parseExtras
			}
			fieldBuf.uint32()              // AcTime (ignored)
			ts := int64(fieldBuf.uint32()) // ModTime since Unix epoch
			modified = time.Unix(ts, 0)
		case extTimeExtraID:
			if len(fieldBuf) < 5 || fieldBuf.uint8()&1 == 0 {
				continue parseExtras
			}
			ts := int64(fieldBuf.uint32()) // ModTime since Unix epoch
			modified = time.Unix(ts, 0)
		}
	}

	msdosModified := msDosTimeToTime(f.ModifiedDate, f.ModifiedTime)
	f.Modified = msdosModified
	if !modified.IsZero() {
		f.Modified = modified.UTC()

		// If legacy MS-DOS timestamps are set, we can use the delta between
		// the legacy and extended versions to estimate timezone offset.
		//
		// A non-UTC timezone is always used (even if offset is zero).
		// Thus, FileHeader.Modified.Location() == time.UTC is useful for
		// determining whether extended timestamps are present.
		// This is necessary for users that need to do additional time
		// calculations when dealing with legacy ZIP formats.
		if f.ModifiedTime != 0 || f.ModifiedDate != 0 {
			f.Modified = modified.In(timeZone(msdosModified.Sub(modified)))
		}
	}

	// Assume that uncompressed size 2³²-1 could plausibly happen in
	// an old zip32 file that was sharding inputs into the largest chunks
	// possible (or is just malicious; search the web for 42.zip).
	// If needUSize is true still, it means we didn't see a zip64 extension.
	// As long as the compressed size is not also 2³²-1 (implausible)
	// and the header is not also 2³²-1 (equally implausible),
	// accept the uncompressed size 2³²-1 as valid.
	// If nothing else, this keeps archive/zip working with 42.zip.
	_ = needUSize

	if needCSize || needHeaderOffset {
		return ErrFormat
	}

	return nil
}

func readDataDescriptor(r io.Reader, f *File) error {
	var buf [dataDescriptorLen]byte
	// The spec says: "Although not originally assigned a
	// signature, the value 0x08074b50 has commonly been adopted
	// as a signature value for the data descriptor record.
	// Implementers should be aware that ZIP files may be
	// encountered with or without this signature marking data
	// descriptors and should account for either case when reading
	// ZIP files to ensure compatibility."
	//
	// dataDescriptorLen includes the size of the signature but
	// first read just those 4 bytes to see if it exists.
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	off := 0
	maybeSig := readBuf(buf[:4])
	if maybeSig.uint32() != dataDescriptorSignature {
		// No data descriptor signature. Keep these four
		// bytes.
		off += 4
	}
	if _, err := io.ReadFull(r, buf[off:12]); err != nil {
		return err
	}
	b := readBuf(buf[:12])
	if b.uint32() != f.CRC32 {
		return ErrChecksum
	}

	// The two sizes that follow here can be either 32 bits or 64 bits
	// but the spec is not very clear on this and different
	// interpretations has been made causing incompatibilities. We
	// already have the sizes from the central directory so we can
	// just ignore these.

	return nil
}

func readDirectoryEnd(r io.ReaderAt, size int64) (dir *directoryEnd, baseOffset int64, err error) {
	// look for directoryEndSignature in the last 1k, then in the last 65k
	var buf []byte
	var directoryEndOffset int64
	for i, bLen := range []int64{1024, 65 * 1024} {
		if bLen > size {
			bLen = size
		}
		buf = make([]byte, int(bLen))
		if _, err := r.ReadAt(buf, size-bLen); err != nil && err != io.EOF {
			return nil, 0, err
		}
		if p := findSignatureInBlock(buf); p >= 0 {
			buf = buf[p:]
			directoryEndOffset = size - bLen + int64(p)
			break
		}
		if i == 1 || bLen == size {
			return nil, 0, ErrFormat
		}
	}

	// read header into struct
	b := readBuf(buf[4:]) // skip signature
	d := &directoryEnd{
		diskNbr:            uint32(b.uint16()),
		dirDiskNbr:         uint32(b.uint16()),
		dirRecordsThisDisk: uint64(b.uint16()),
		directoryRecords:   uint64(b.uint16()),
		directorySize:      uint64(b.uint32()),
		directoryOffset:    uint64(b.uint32()),
		commentLen:         b.uint16(),
	}
	l := int(d.commentLen)
	if l > len(b) {
		return nil, 0, errors.New("zip: invalid comment length")
	}
	d.comment = string(b[:l])

	// These values mean that the file can be a zip64 file
	if d.directoryRecords == 0xffff || d.directorySize == 0xffff || d.directoryOffset == 0xffffffff {
		p, err := findDirectory64End(r, directoryEndOffset)
		if err == nil && p >= 0 {
			directoryEndOffset = p
			err = readDirectory64End(r, p, d)
		}
		if err != nil {
			return nil, 0, err
		}
	}

	maxInt64 := uint64(1<<63 - 1)
	if d.directorySize > maxInt64 || d.directoryOffset > maxInt64 {
		return nil, 0, ErrFormat
	}

	baseOffset = directoryEndOffset - int64(d.directorySize) - int64(d.directoryOffset)

	// Make sure directoryOffset points to somewhere in our file.
	if o := baseOffset + int64(d.directoryOffset); o < 0 || o >= size {
		return nil, 0, ErrFormat
	}

	// If the directory end data tells us to use a non-zero baseOffset,
	// but we would find a valid directory entry if we assume that the
	// baseOffset is 0, then just use a baseOffset of 0.
	// We've seen files in which the directory end data gives us
	// an incorrect baseOffset.
	if baseOffset > 0 {
		off := int64(d.directoryOffset)
		rs := io.NewSectionReader(r, off, size-off)
		if readDirectoryHeader(&File{}, rs) == nil {
			baseOffset = 0
		}
	}

	return d, baseOffset, nil
}

// findDirectory64End tries to read the zip64 locator just before the
// directory end and returns the offset of the zip64 directory end if
// found.
func findDirectory64End(r io.ReaderAt, directoryEndOffset int64) (int64, error) {
	locOffset := directoryEndOffset - directory64LocLen
	if locOffset < 0 {
		return -1, nil // no need to look for a header outside the file
	}
	buf := make([]byte, directory64LocLen)
	if _, err := r.ReadAt(buf, locOffset); err != nil {
		return -1, err
	}
	b := readBuf(buf)
	if sig := b.uint32(); sig != directory64LocSignature {
		return -1, nil
	}
	if b.uint32() != 0 { // number of the disk with the start of the zip64 end of central directory
		return -1, nil // the file is not a valid zip64-file
	}
	p := b.uint64()      // relative offset of the zip64 end of central directory record
	if b.uint32() != 1 { // total number of disks
		return -1, nil // the file is not a valid zip64-file
	}
	return int64(p), nil
}

// readDirectory64End reads the zip64 directory end and updates the
// directory end with the zip64 directory end values.
func readDirectory64End(r io.ReaderAt, offset int64, d *directoryEnd) (err error) {
	buf := make([]byte, directory64EndLen)
	if _, err := r.ReadAt(buf, offset); err != nil {
		return err
	}

	b := readBuf(buf)
	if sig := b.uint32(); sig != directory64EndSignature {
		return ErrFormat
	}

	b = b[12:]                        // skip dir size, version and version needed (uint64 + 2x uint16)
	d.diskNbr = b.uint32()            // number of this disk
	d.dirDiskNbr = b.uint32()         // number of the disk with the start of the central directory
	d.dirRecordsThisDisk = b.uint64() // total number of entries in the central directory on this disk
	d.directoryRecords = b.uint64()   // total number of entries in the central directory
	d.directorySize = b.uint64()      // size of the central directory
	d.directoryOffset = b.uint64()    // offset of start of central directory with respect to the starting disk number

	return nil
}

func findSignatureInBlock(b []byte) int {
	for i := len(b) - directoryEndLen; i >= 0; i-- {
		// defined from directoryEndSignature in struct.go
		if b[i] == 'P' && b[i+1] == 'K' && b[i+2] == 0x05 && b[i+3] == 0x06 {
			// n is length of comment
			n := int(b[i+directoryEndLen-2]) | int(b[i+directoryEndLen-1])<<8
			if n+directoryEndLen+i > len(b) {
				// Truncated comment.
				// Some parsers (such as Info-ZIP) ignore the truncated comment
				// rather than treating it as a hard error.
				return -1
			}
			return i
		}
	}
	return -1
}

type readBuf []byte

func (b *readBuf) uint8() uint8 {
	v := (*b)[0]
	*b = (*b)[1:]
	return v
}

func (b *readBuf) uint16() uint16 {
	v := binary.LittleEndian.Uint16(*b)
	*b = (*b)[2:]
	return v
}

func (b *readBuf) uint32() uint32 {
	v := binary.LittleEndian.Uint32(*b)
	*b = (*b)[4:]
	return v
}

func (b *readBuf) uint64() uint64 {
	v := binary.LittleEndian.Uint64(*b)
	*b = (*b)[8:]
	return v
}

func (b *readBuf) sub(n int) readBuf {
	b2 := (*b)[:n]
	*b = (*b)[n:]
	return b2
}

// A fileListEntry is a File and its ename.
// If file == nil, the fileListEntry describes a directory without metadata.
type fileListEntry struct {
	name  string
	file  *File
	isDir bool
	isDup bool
}

type fileInfoDirEntry interface {
	fs.FileInfo
	fs.DirEntry
}

func (f *fileListEntry) stat() (fileInfoDirEntry, error) {
	if f.isDup {
		return nil, errors.New(f.name + ": duplicate entries in zip file")
	}
	if !f.isDir {
		return headerFileInfo{&f.file.FileHeader}, nil
	}
	return f, nil
}

// Only used for directories.
func (f *fileListEntry) Name() string      { _, elem, _ := split(f.name); return elem }
func (f *fileListEntry) Size() int64       { return 0 }
func (f *fileListEntry) Mode() fs.FileMode { return fs.ModeDir | 0555 }
func (f *fileListEntry) Type() fs.FileMode { return fs.ModeDir }
func (f *fileListEntry) IsDir() bool       { return true }
func (f *fileListEntry) Sys() any          { return nil }

func (f *fileListEntry) ModTime() time.Time {
	if f.file == nil {
		return time.Time{}
	}
	return f.file.FileHeader.Modified.UTC()
}

func (f *fileListEntry) Info() (fs.FileInfo, error) { return f, nil }

func (f *fileListEntry) String() string {
	return fs.FormatDirEntry(f)
}

// toValidName coerces name to be a valid name for fs.FS.Open.
func toValidName(name string) string {
	name = strings.ReplaceAll(name, `\`, `/`)
	p := path.Clean(name)

	p = strings.TrimPrefix(p, "/")

	for strings.HasPrefix(p, "../") {
		p = p[len("../"):]
	}

	return p
}

func (r *Reader) initFileList() {
	r.fileListOnce.Do(func() {
		// files and knownDirs map from a file/directory name
		// to an index into the r.fileList entry that we are
		// building. They are used to mark duplicate entries.
		files := make(map[string]int)
		knownDirs := make(map[string]int)

		// dirs[name] is true if name is known to be a directory,
		// because it appears as a prefix in a path.
		dirs := make(map[string]bool)

		for _, file := range r.File {
			isDir := len(file.Name) > 0 && file.Name[len(file.Name)-1] == '/'
			name := toValidName(file.Name)
			if name == "" {
				continue
			}

			if idx, ok := files[name]; ok {
				r.fileList[idx].isDup = true
				continue
			}
			if idx, ok := knownDirs[name]; ok {
				r.fileList[idx].isDup = true
				continue
			}

			for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
				dirs[dir] = true
			}

			idx := len(r.fileList)
			entry := fileListEntry{
				name:  name,
				file:  file,
				isDir: isDir,
			}
			r.fileList = append(r.fileList, entry)
			if isDir {
				knownDirs[name] = idx
			} else {
				files[name] = idx
			}
		}
		for dir := range dirs {
			if _, ok := knownDirs[dir]; !ok {
				if idx, ok := files[dir]; ok {
					r.fileList[idx].isDup = true
				} else {
					entry := fileListEntry{
						name:  dir,
						file:  nil,
						isDir: true,
					}
					r.fileList = append(r.fileList, entry)
				}
			}
		}

		slices.SortFunc(r.fileList, func(a, b fileListEntry) int {
			return fileEntryCompare(a.name, b.name)
		})
	})
}

func fileEntryCompare(x, y string) int {
	xdir, xelem, _ := split(x)
	ydir, yelem, _ := split(y)
	if xdir != ydir {
		return strings.Compare(xdir, ydir)
	}
	return strings.Compare(xelem, yelem)
}

// Open opens the named file in the ZIP archive,
// using the semantics of fs.FS.Open:
// paths are always slash separated, with no
// leading / or ../ elements.
func (r *Reader) Open(name string) (fs.File, error) {
	r.initFileList()

	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	e := r.openLookup(name)
	if e == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if e.isDir {
		return &openDir{e, r.openReadDir(name), 0}, nil
	}
	rc, err := e.file.Open()
	if err != nil {
		return nil, err
	}
	return rc.(fs.File), nil
}

func split(name string) (dir, elem string, isDir bool) {
	name, isDir = strings.CutSuffix(name, "/")
	i := strings.LastIndexByte(name, '/')
	if i < 0 {
		return ".", name, isDir
	}
	return name[:i], name[i+1:], isDir
}

var dotFile = &fileListEntry{name: "./", isDir: true}

func (r *Reader) openLookup(name string) *fileListEntry {
	if name == "." {
		return dotFile
	}

	dir, elem, _ := split(name)
	files := r.fileList
	i, _ := slices.BinarySearchFunc(files, dir, func(a fileListEntry, dir string) (ret int) {
		idir, ielem, _ := split(a.name)
		if dir != idir {
			return strings.Compare(idir, dir)
		}
		return strings.Compare(ielem, elem)
	})
	if i < len(files) {
		fname := files[i].name
		if fname == name || len(fname) == len(name)+1 && fname[len(name)] == '/' && fname[:len(name)] == name {
			return &files[i]
		}
	}
	return nil
}

func (r *Reader) openReadDir(dir string) []fileListEntry {
	files := r.fileList
	i, _ := slices.BinarySearchFunc(files, dir, func(a fileListEntry, dir string) int {
		idir, _, _ := split(a.name)
		if dir != idir {
			return strings.Compare(idir, dir)
		}
		// find the first entry with dir
		return +1
	})
	j, _ := slices.BinarySearchFunc(files, dir, func(a fileListEntry, dir string) int {
		jdir, _, _ := split(a.name)
		if dir != jdir {
			return strings.Compare(jdir, dir)
		}
		// find the last entry with dir
		return -1
	})
	return files[i:j]
}

type openDir struct {
	e      *fileListEntry
	files  []fileListEntry
	offset int
}

func (d *openDir) Close() error               { return nil }
func (d *openDir) Stat() (fs.FileInfo, error) { return d.e.stat() }

func (d *openDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.e.name, Err: errors.New("is a directory")}
}

func (d *openDir) ReadDir(count int) ([]fs.DirEntry, error) {
	n := len(d.files) - d.offset
	if count > 0 && n > count {
		n = count
	}
	if n == 0 {
		if count <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	list := make([]fs.DirEntry, n)
	for i := range list {
		s, err := d.files[d.offset+i].stat()
		if err != nil {
			return nil, err
		}
		list[i] = s
	}
	d.offset += n
	return list, nil
}

"""



```