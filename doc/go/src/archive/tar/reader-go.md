Response:
My thought process for answering the request about `go/src/archive/tar/reader.go` goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of the provided Go code snippet, which is part of the `tar` package's `reader.go`. They also want examples, explanations of specific Go features used, handling of command-line arguments (if any), and common pitfalls for users.

2. **Identify the Primary Goal:** The code is about reading and processing tar archives. The central structure is the `Reader` type.

3. **Break Down Functionality by Type and Method:** I'll go through the key types and their associated methods to understand their roles:
    * **`Reader` struct:**  This is the main entry point for reading a tar archive. It holds the underlying `io.Reader`, padding information, the current file's reader (`curr`), and an error tracker.
    * **`NewReader(r io.Reader) *Reader`:** This is the constructor for the `Reader`. It takes an `io.Reader` as input, which represents the source of the tar archive data.
    * **`Next() (*Header, error)`:** This is crucial. It advances the reader to the next entry in the tar archive. It also handles meta-files (like PAX headers, GNU long names), checks for insecure paths, and returns the header information. This needs careful explanation.
    * **`Read(b []byte) (int, error)`:** This method allows reading the *content* of the current file entry after `Next()` has been called. It needs to address how it handles regular files and sparse files.
    * **`fileReader` interface:** This interface abstracts the reading of file data, allowing different implementations for regular and sparse files.
    * **`regFileReader` struct:** This implements `fileReader` for regular files, simply reading from the underlying `io.Reader`.
    * **`sparseFileReader` struct:** This implements `fileReader` for sparse files, handling the "holes" in the file data. This is a more complex part and requires a good explanation with an example.
    * **Helper functions (e.g., `readHeader`, `parsePAX`, `readSpecialFile`, `discard`, `mustReadFull`, `tryReadFull`):** These support the main reading logic by parsing headers, handling PAX extensions, reading special files, skipping data, and ensuring full reads.

4. **Infer Go Features in Use:** As I examine the code, I'll note the Go language features being employed:
    * **Interfaces (`io.Reader`, `io.Seeker`, `fileReader`):** For abstraction and polymorphism.
    * **Structs:** To define data structures like `Reader`, `Header`, `regFileReader`, `sparseFileReader`.
    * **Methods on structs:** To implement the behavior of these types.
    * **Error handling:** Using the `error` interface and sticky errors.
    * **`io` package:** For basic input/output operations.
    * **`bytes` package:** For comparing byte slices.
    * **`strings` package:** For string manipulation.
    * **`strconv` package:** For converting strings to numbers.
    * **`time` package:** For handling timestamps.
    * **Constants:** For defining special values like zero blocks and maximum file sizes.
    * **Conditional logic (switch, if/else):** For handling different header types and formats.
    * **Loops (for):** For iterating through archive entries and PAX records.
    * **Maps:** For storing PAX headers.
    * **Slices:** For representing byte arrays and sparse data structures.
    * **Type assertions:**  (Although not explicitly used with `.(type)` in the provided snippet, the `fileReader` interface implies potential type assertions elsewhere in the broader `tar` package).
    * **Embedded structs (within `Header`):** (Not explicitly shown in this snippet, but common in the `tar` package).

5. **Address Specific Requirements:**

    * **Functionality Listing:** Create a concise bulleted list of the key functions.
    * **Go Feature Examples:**  Choose a few representative Go features and provide small, illustrative code examples demonstrating their usage in the context of the `tar` package. The `io.Reader` interface and the `Reader` struct with its methods are good candidates.
    * **Code Reasoning (with Input/Output):** The sparse file handling is the most complex part. I need to create a scenario where a sparse file is encountered in the tar archive and explain how `sparseFileReader` handles reading data, potentially skipping over the holes. I'll need to invent a simple sparse file representation and show how the output would look.
    * **Command-Line Arguments:**  Scan the code for any direct handling of `os.Args` or similar. If none are found, explicitly state that the code *doesn't* directly handle command-line arguments. Mention that the surrounding tooling (like the `tar` command-line utility) would handle that. The mention of `GODEBUG` for insecure paths is important here.
    * **Common Mistakes:** Think about what users might do wrong when working with the `tar` package's reader. Not calling `Next()` before `Read()`, not handling `io.EOF` correctly, and issues with sparse files are potential areas.
    * **Language:** The response must be in Chinese.

6. **Structure the Answer:** Organize the information logically:

    * Start with a high-level overview of the code's purpose.
    * List the key functionalities.
    * Provide examples of Go feature usage.
    * Explain the code reasoning with the sparse file example.
    * Address command-line argument handling.
    * Discuss common mistakes.
    * Conclude with a summary.

7. **Refine and Review:**  Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any ambiguities or missing information. Make sure the Chinese is natural and grammatically correct. For instance, I initially might forget to explicitly mention the `GODEBUG` environment variable's influence on path security, so I'd review and add that in. I also want to ensure my sparse file example is simple and understandable.

By following these steps, I can systematically analyze the code and construct a comprehensive and accurate answer to the user's request. The focus is on understanding the code's purpose, breaking it down into manageable parts, illustrating key concepts with examples, and addressing all the specific requirements of the prompt.
这段代码是 Go 语言 `archive/tar` 标准库中 `reader.go` 文件的一部分，它实现了对 tar 归档文件的读取功能。

以下是它的一些主要功能：

* **顺序读取 tar 归档文件内容:**  `Reader` 结构体提供了对 tar 归档文件内容的顺序访问。你可以把它想象成一个迭代器，每次调用 `Next()` 方法都会移动到归档中的下一个文件或目录。
* **解析 tar 文件头 (Header):**  `Next()` 方法负责读取并解析 tar 归档中每个条目的头部信息。这个头部包含了文件名、大小、权限、修改时间等元数据。解析过程会处理不同的 tar 格式 (USTAR, PAX, GNU)。
* **提供文件数据的 `io.Reader` 接口:**  在成功调用 `Next()` 后，`Reader` 实例可以像一个 `io.Reader` 一样使用，用于读取当前条目的文件数据。读取的字节数由 `Header.Size` 决定。
* **处理不同类型的 tar 条目:** 代码能够处理不同类型的 tar 条目，例如普通文件 (`TypeReg`)、目录 (`TypeDir`)、符号链接 (`TypeSymlink`)、硬链接 (`TypeLink`) 等。对于某些特殊类型（例如链接、目录），`Read()` 方法会立即返回 `io.EOF`。
* **处理 PAX 扩展头部:** 代码支持 PAX (POSIX.1-2001 extended tar format) 扩展头部，这些头部可以提供超出传统 USTAR 格式限制的元数据，例如更长的文件名、更大的文件大小以及扩展属性。
* **处理 GNU 长文件名和长链接名头部:** 代码支持 GNU 扩展头部，用于存储超过 USTAR 格式限制的长文件名和长链接名。
* **处理 GNU 稀疏文件:** 代码支持读取 GNU 稀疏格式的 tar 文件，这种格式允许文件中包含“空洞”，从而节省存储空间。读取稀疏文件时，空洞部分会被读取为 NUL 字节。
* **错误处理:**  `Reader` 结构体内部维护一个持久的错误状态 `err`。每个导出的方法都会确保这个错误状态是粘性的，也就是说，一旦发生错误，后续的操作也会返回该错误。

**它是什么 go 语言功能的实现？**

这段代码主要实现了 **tar 归档文件的读取和解析** 功能。

**Go 代码示例：**

假设我们有一个名为 `mytar.tar` 的 tar 归档文件，我们可以使用以下 Go 代码读取它的内容：

```go
package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
)

func main() {
	file, err := os.Open("mytar.tar")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	tr := tar.NewReader(file)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // 已经到达 tar 文件的末尾
		}
		if err != nil {
			panic(err)
		}

		fmt.Printf("Filename: %s\n", header.Name)
		fmt.Printf("Size: %d bytes\n", header.Size)
		fmt.Printf("Type: %c\n", header.Typeflag)

		// 如果是普通文件，则读取其内容
		if header.Typeflag == tar.TypeReg {
			fmt.Println("Content:")
			if _, err := io.CopyN(os.Stdout, tr, header.Size); err != nil {
				panic(err)
			}
			fmt.Println()
		}
		fmt.Println("---")
	}
}
```

**假设的输入与输出：**

假设 `mytar.tar` 文件包含两个文件：

1. `file1.txt`，内容为 "Hello, world!\n"
2. `dir1/file2.txt`，内容为 "This is another file.\n"

运行上面的 Go 代码，预期的输出如下：

```
Filename: file1.txt
Size: 14 bytes
Type: 0
Content:
Hello, world!

---
Filename: dir1/file2.txt
Size: 22 bytes
Type: 0
Content:
This is another file.

---
```

**命令行参数的具体处理：**

这段代码本身 **没有直接处理命令行参数**。 `archive/tar` 库主要提供的是读取和写入 tar 文件的功能，它不关心文件从哪里来或到哪里去。命令行参数的处理通常由使用 `archive/tar` 库的上层应用程序来完成，例如 `tar` 命令行工具。

然而，代码中提到了 `GODEBUG` 环境变量中的 `tarinsecurepath=0`。这是一个影响程序行为的环境变量，而不是命令行参数。

* **`GODEBUG=tarinsecurepath=0`:** 如果设置了这个环境变量，并且 `Next()` 方法遇到一个非本地路径 (由 `filepath.IsLocal` 判断)，它会返回一个包含 `ErrInsecurePath` 错误的 header。这是一种安全机制，用于防止读取包含恶意路径的 tar 文件，这些路径可能导致意外的文件系统操作。

**使用者易犯错的点：**

* **未调用 `Next()` 就尝试 `Read()`:**  在读取一个文件的内容之前，必须先调用 `Next()` 方法来定位到该文件。如果直接对 `NewReader()` 返回的 `Reader` 实例调用 `Read()`，将会读取到的是 tar 文件的头部信息，而不是第一个文件的内容。

   ```go
   // 错误示例
   file, _ := os.Open("mytar.tar")
   tr := tar.NewReader(file)
   buf := make([]byte, 100)
   n, err := tr.Read(buf) // 错误！此时还没有调用 Next()
   ```

* **没有正确处理 `io.EOF`:**  `Next()` 方法在到达 tar 文件末尾时会返回 `io.EOF` 错误。循环读取 tar 文件时，需要检查并正确处理这个错误，以避免无限循环。

   ```go
   // 常见错误
   for {
       header, err := tr.Next()
       if err != nil { // 没有检查 err == io.EOF
           panic(err)
       }
       // ... 处理 header 和文件内容
   }
   ```

* **假设所有文件都是普通文件:** tar 文件可以包含不同类型的文件和目录。用户应该检查 `Header.Typeflag` 来确定当前条目的类型，并采取相应的处理措施。例如，读取符号链接的内容是没有意义的。

* **忽略 `ErrInsecurePath` 错误 (当 `GODEBUG=tarinsecurepath=0` 时):** 如果程序设置了 `GODEBUG=tarinsecurepath=0` 并且遇到了包含非本地路径的 tar 文件，`Next()` 会返回 `ErrInsecurePath`。盲目忽略这个错误可能会导致安全风险。用户应该根据自己的需求决定是否接受这些非本地路径。

这段代码是 Go 语言 `archive/tar` 包中核心的读取逻辑，它使得 Go 程序能够方便地解析和提取 tar 归档文件的内容。理解其工作原理对于正确使用 `archive/tar` 包至关重要。

### 提示词
```
这是路径为go/src/archive/tar/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package tar

import (
	"bytes"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Reader provides sequential access to the contents of a tar archive.
// Reader.Next advances to the next file in the archive (including the first),
// and then Reader can be treated as an io.Reader to access the file's data.
type Reader struct {
	r    io.Reader
	pad  int64      // Amount of padding (ignored) after current file entry
	curr fileReader // Reader for current file entry
	blk  block      // Buffer to use as temporary local storage

	// err is a persistent error.
	// It is only the responsibility of every exported method of Reader to
	// ensure that this error is sticky.
	err error
}

type fileReader interface {
	io.Reader
	fileState

	WriteTo(io.Writer) (int64, error)
}

// NewReader creates a new [Reader] reading from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r, curr: &regFileReader{r, 0}}
}

// Next advances to the next entry in the tar archive.
// The Header.Size determines how many bytes can be read for the next file.
// Any remaining data in the current file is automatically discarded.
// At the end of the archive, Next returns the error io.EOF.
//
// If Next encounters a non-local name (as defined by [filepath.IsLocal])
// and the GODEBUG environment variable contains `tarinsecurepath=0`,
// Next returns the header with an [ErrInsecurePath] error.
// A future version of Go may introduce this behavior by default.
// Programs that want to accept non-local names can ignore
// the [ErrInsecurePath] error and use the returned header.
func (tr *Reader) Next() (*Header, error) {
	if tr.err != nil {
		return nil, tr.err
	}
	hdr, err := tr.next()
	tr.err = err
	if err == nil && !filepath.IsLocal(hdr.Name) {
		if tarinsecurepath.Value() == "0" {
			tarinsecurepath.IncNonDefault()
			err = ErrInsecurePath
		}
	}
	return hdr, err
}

func (tr *Reader) next() (*Header, error) {
	var paxHdrs map[string]string
	var gnuLongName, gnuLongLink string

	// Externally, Next iterates through the tar archive as if it is a series of
	// files. Internally, the tar format often uses fake "files" to add meta
	// data that describes the next file. These meta data "files" should not
	// normally be visible to the outside. As such, this loop iterates through
	// one or more "header files" until it finds a "normal file".
	format := FormatUSTAR | FormatPAX | FormatGNU
	for {
		// Discard the remainder of the file and any padding.
		if err := discard(tr.r, tr.curr.physicalRemaining()); err != nil {
			return nil, err
		}
		if _, err := tryReadFull(tr.r, tr.blk[:tr.pad]); err != nil {
			return nil, err
		}
		tr.pad = 0

		hdr, rawHdr, err := tr.readHeader()
		if err != nil {
			return nil, err
		}
		if err := tr.handleRegularFile(hdr); err != nil {
			return nil, err
		}
		format.mayOnlyBe(hdr.Format)

		// Check for PAX/GNU special headers and files.
		switch hdr.Typeflag {
		case TypeXHeader, TypeXGlobalHeader:
			format.mayOnlyBe(FormatPAX)
			paxHdrs, err = parsePAX(tr)
			if err != nil {
				return nil, err
			}
			if hdr.Typeflag == TypeXGlobalHeader {
				mergePAX(hdr, paxHdrs)
				return &Header{
					Name:       hdr.Name,
					Typeflag:   hdr.Typeflag,
					Xattrs:     hdr.Xattrs,
					PAXRecords: hdr.PAXRecords,
					Format:     format,
				}, nil
			}
			continue // This is a meta header affecting the next header
		case TypeGNULongName, TypeGNULongLink:
			format.mayOnlyBe(FormatGNU)
			realname, err := readSpecialFile(tr)
			if err != nil {
				return nil, err
			}

			var p parser
			switch hdr.Typeflag {
			case TypeGNULongName:
				gnuLongName = p.parseString(realname)
			case TypeGNULongLink:
				gnuLongLink = p.parseString(realname)
			}
			continue // This is a meta header affecting the next header
		default:
			// The old GNU sparse format is handled here since it is technically
			// just a regular file with additional attributes.

			if err := mergePAX(hdr, paxHdrs); err != nil {
				return nil, err
			}
			if gnuLongName != "" {
				hdr.Name = gnuLongName
			}
			if gnuLongLink != "" {
				hdr.Linkname = gnuLongLink
			}
			if hdr.Typeflag == TypeRegA {
				if strings.HasSuffix(hdr.Name, "/") {
					hdr.Typeflag = TypeDir // Legacy archives use trailing slash for directories
				} else {
					hdr.Typeflag = TypeReg
				}
			}

			// The extended headers may have updated the size.
			// Thus, setup the regFileReader again after merging PAX headers.
			if err := tr.handleRegularFile(hdr); err != nil {
				return nil, err
			}

			// Sparse formats rely on being able to read from the logical data
			// section; there must be a preceding call to handleRegularFile.
			if err := tr.handleSparseFile(hdr, rawHdr); err != nil {
				return nil, err
			}

			// Set the final guess at the format.
			if format.has(FormatUSTAR) && format.has(FormatPAX) {
				format.mayOnlyBe(FormatUSTAR)
			}
			hdr.Format = format
			return hdr, nil // This is a file, so stop
		}
	}
}

// handleRegularFile sets up the current file reader and padding such that it
// can only read the following logical data section. It will properly handle
// special headers that contain no data section.
func (tr *Reader) handleRegularFile(hdr *Header) error {
	nb := hdr.Size
	if isHeaderOnlyType(hdr.Typeflag) {
		nb = 0
	}
	if nb < 0 {
		return ErrHeader
	}

	tr.pad = blockPadding(nb)
	tr.curr = &regFileReader{r: tr.r, nb: nb}
	return nil
}

// handleSparseFile checks if the current file is a sparse format of any type
// and sets the curr reader appropriately.
func (tr *Reader) handleSparseFile(hdr *Header, rawHdr *block) error {
	var spd sparseDatas
	var err error
	if hdr.Typeflag == TypeGNUSparse {
		spd, err = tr.readOldGNUSparseMap(hdr, rawHdr)
	} else {
		spd, err = tr.readGNUSparsePAXHeaders(hdr)
	}

	// If sp is non-nil, then this is a sparse file.
	// Note that it is possible for len(sp) == 0.
	if err == nil && spd != nil {
		if isHeaderOnlyType(hdr.Typeflag) || !validateSparseEntries(spd, hdr.Size) {
			return ErrHeader
		}
		sph := invertSparseEntries(spd, hdr.Size)
		tr.curr = &sparseFileReader{tr.curr, sph, 0}
	}
	return err
}

// readGNUSparsePAXHeaders checks the PAX headers for GNU sparse headers.
// If they are found, then this function reads the sparse map and returns it.
// This assumes that 0.0 headers have already been converted to 0.1 headers
// by the PAX header parsing logic.
func (tr *Reader) readGNUSparsePAXHeaders(hdr *Header) (sparseDatas, error) {
	// Identify the version of GNU headers.
	var is1x0 bool
	major, minor := hdr.PAXRecords[paxGNUSparseMajor], hdr.PAXRecords[paxGNUSparseMinor]
	switch {
	case major == "0" && (minor == "0" || minor == "1"):
		is1x0 = false
	case major == "1" && minor == "0":
		is1x0 = true
	case major != "" || minor != "":
		return nil, nil // Unknown GNU sparse PAX version
	case hdr.PAXRecords[paxGNUSparseMap] != "":
		is1x0 = false // 0.0 and 0.1 did not have explicit version records, so guess
	default:
		return nil, nil // Not a PAX format GNU sparse file.
	}
	hdr.Format.mayOnlyBe(FormatPAX)

	// Update hdr from GNU sparse PAX headers.
	if name := hdr.PAXRecords[paxGNUSparseName]; name != "" {
		hdr.Name = name
	}
	size := hdr.PAXRecords[paxGNUSparseSize]
	if size == "" {
		size = hdr.PAXRecords[paxGNUSparseRealSize]
	}
	if size != "" {
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			return nil, ErrHeader
		}
		hdr.Size = n
	}

	// Read the sparse map according to the appropriate format.
	if is1x0 {
		return readGNUSparseMap1x0(tr.curr)
	}
	return readGNUSparseMap0x1(hdr.PAXRecords)
}

// mergePAX merges paxHdrs into hdr for all relevant fields of Header.
func mergePAX(hdr *Header, paxHdrs map[string]string) (err error) {
	for k, v := range paxHdrs {
		if v == "" {
			continue // Keep the original USTAR value
		}
		var id64 int64
		switch k {
		case paxPath:
			hdr.Name = v
		case paxLinkpath:
			hdr.Linkname = v
		case paxUname:
			hdr.Uname = v
		case paxGname:
			hdr.Gname = v
		case paxUid:
			id64, err = strconv.ParseInt(v, 10, 64)
			hdr.Uid = int(id64) // Integer overflow possible
		case paxGid:
			id64, err = strconv.ParseInt(v, 10, 64)
			hdr.Gid = int(id64) // Integer overflow possible
		case paxAtime:
			hdr.AccessTime, err = parsePAXTime(v)
		case paxMtime:
			hdr.ModTime, err = parsePAXTime(v)
		case paxCtime:
			hdr.ChangeTime, err = parsePAXTime(v)
		case paxSize:
			hdr.Size, err = strconv.ParseInt(v, 10, 64)
		default:
			if strings.HasPrefix(k, paxSchilyXattr) {
				if hdr.Xattrs == nil {
					hdr.Xattrs = make(map[string]string)
				}
				hdr.Xattrs[k[len(paxSchilyXattr):]] = v
			}
		}
		if err != nil {
			return ErrHeader
		}
	}
	hdr.PAXRecords = paxHdrs
	return nil
}

// parsePAX parses PAX headers.
// If an extended header (type 'x') is invalid, ErrHeader is returned.
func parsePAX(r io.Reader) (map[string]string, error) {
	buf, err := readSpecialFile(r)
	if err != nil {
		return nil, err
	}
	sbuf := string(buf)

	// For GNU PAX sparse format 0.0 support.
	// This function transforms the sparse format 0.0 headers into format 0.1
	// headers since 0.0 headers were not PAX compliant.
	var sparseMap []string

	paxHdrs := make(map[string]string)
	for len(sbuf) > 0 {
		key, value, residual, err := parsePAXRecord(sbuf)
		if err != nil {
			return nil, ErrHeader
		}
		sbuf = residual

		switch key {
		case paxGNUSparseOffset, paxGNUSparseNumBytes:
			// Validate sparse header order and value.
			if (len(sparseMap)%2 == 0 && key != paxGNUSparseOffset) ||
				(len(sparseMap)%2 == 1 && key != paxGNUSparseNumBytes) ||
				strings.Contains(value, ",") {
				return nil, ErrHeader
			}
			sparseMap = append(sparseMap, value)
		default:
			paxHdrs[key] = value
		}
	}
	if len(sparseMap) > 0 {
		paxHdrs[paxGNUSparseMap] = strings.Join(sparseMap, ",")
	}
	return paxHdrs, nil
}

// readHeader reads the next block header and assumes that the underlying reader
// is already aligned to a block boundary. It returns the raw block of the
// header in case further processing is required.
//
// The err will be set to io.EOF only when one of the following occurs:
//   - Exactly 0 bytes are read and EOF is hit.
//   - Exactly 1 block of zeros is read and EOF is hit.
//   - At least 2 blocks of zeros are read.
func (tr *Reader) readHeader() (*Header, *block, error) {
	// Two blocks of zero bytes marks the end of the archive.
	if _, err := io.ReadFull(tr.r, tr.blk[:]); err != nil {
		return nil, nil, err // EOF is okay here; exactly 0 bytes read
	}
	if bytes.Equal(tr.blk[:], zeroBlock[:]) {
		if _, err := io.ReadFull(tr.r, tr.blk[:]); err != nil {
			return nil, nil, err // EOF is okay here; exactly 1 block of zeros read
		}
		if bytes.Equal(tr.blk[:], zeroBlock[:]) {
			return nil, nil, io.EOF // normal EOF; exactly 2 block of zeros read
		}
		return nil, nil, ErrHeader // Zero block and then non-zero block
	}

	// Verify the header matches a known format.
	format := tr.blk.getFormat()
	if format == FormatUnknown {
		return nil, nil, ErrHeader
	}

	var p parser
	hdr := new(Header)

	// Unpack the V7 header.
	v7 := tr.blk.toV7()
	hdr.Typeflag = v7.typeFlag()[0]
	hdr.Name = p.parseString(v7.name())
	hdr.Linkname = p.parseString(v7.linkName())
	hdr.Size = p.parseNumeric(v7.size())
	hdr.Mode = p.parseNumeric(v7.mode())
	hdr.Uid = int(p.parseNumeric(v7.uid()))
	hdr.Gid = int(p.parseNumeric(v7.gid()))
	hdr.ModTime = time.Unix(p.parseNumeric(v7.modTime()), 0)

	// Unpack format specific fields.
	if format > formatV7 {
		ustar := tr.blk.toUSTAR()
		hdr.Uname = p.parseString(ustar.userName())
		hdr.Gname = p.parseString(ustar.groupName())
		hdr.Devmajor = p.parseNumeric(ustar.devMajor())
		hdr.Devminor = p.parseNumeric(ustar.devMinor())

		var prefix string
		switch {
		case format.has(FormatUSTAR | FormatPAX):
			hdr.Format = format
			ustar := tr.blk.toUSTAR()
			prefix = p.parseString(ustar.prefix())

			// For Format detection, check if block is properly formatted since
			// the parser is more liberal than what USTAR actually permits.
			notASCII := func(r rune) bool { return r >= 0x80 }
			if bytes.IndexFunc(tr.blk[:], notASCII) >= 0 {
				hdr.Format = FormatUnknown // Non-ASCII characters in block.
			}
			nul := func(b []byte) bool { return int(b[len(b)-1]) == 0 }
			if !(nul(v7.size()) && nul(v7.mode()) && nul(v7.uid()) && nul(v7.gid()) &&
				nul(v7.modTime()) && nul(ustar.devMajor()) && nul(ustar.devMinor())) {
				hdr.Format = FormatUnknown // Numeric fields must end in NUL
			}
		case format.has(formatSTAR):
			star := tr.blk.toSTAR()
			prefix = p.parseString(star.prefix())
			hdr.AccessTime = time.Unix(p.parseNumeric(star.accessTime()), 0)
			hdr.ChangeTime = time.Unix(p.parseNumeric(star.changeTime()), 0)
		case format.has(FormatGNU):
			hdr.Format = format
			var p2 parser
			gnu := tr.blk.toGNU()
			if b := gnu.accessTime(); b[0] != 0 {
				hdr.AccessTime = time.Unix(p2.parseNumeric(b), 0)
			}
			if b := gnu.changeTime(); b[0] != 0 {
				hdr.ChangeTime = time.Unix(p2.parseNumeric(b), 0)
			}

			// Prior to Go1.8, the Writer had a bug where it would output
			// an invalid tar file in certain rare situations because the logic
			// incorrectly believed that the old GNU format had a prefix field.
			// This is wrong and leads to an output file that mangles the
			// atime and ctime fields, which are often left unused.
			//
			// In order to continue reading tar files created by former, buggy
			// versions of Go, we skeptically parse the atime and ctime fields.
			// If we are unable to parse them and the prefix field looks like
			// an ASCII string, then we fallback on the pre-Go1.8 behavior
			// of treating these fields as the USTAR prefix field.
			//
			// Note that this will not use the fallback logic for all possible
			// files generated by a pre-Go1.8 toolchain. If the generated file
			// happened to have a prefix field that parses as valid
			// atime and ctime fields (e.g., when they are valid octal strings),
			// then it is impossible to distinguish between a valid GNU file
			// and an invalid pre-Go1.8 file.
			//
			// See https://golang.org/issues/12594
			// See https://golang.org/issues/21005
			if p2.err != nil {
				hdr.AccessTime, hdr.ChangeTime = time.Time{}, time.Time{}
				ustar := tr.blk.toUSTAR()
				if s := p.parseString(ustar.prefix()); isASCII(s) {
					prefix = s
				}
				hdr.Format = FormatUnknown // Buggy file is not GNU
			}
		}
		if len(prefix) > 0 {
			hdr.Name = prefix + "/" + hdr.Name
		}
	}
	return hdr, &tr.blk, p.err
}

// readOldGNUSparseMap reads the sparse map from the old GNU sparse format.
// The sparse map is stored in the tar header if it's small enough.
// If it's larger than four entries, then one or more extension headers are used
// to store the rest of the sparse map.
//
// The Header.Size does not reflect the size of any extended headers used.
// Thus, this function will read from the raw io.Reader to fetch extra headers.
// This method mutates blk in the process.
func (tr *Reader) readOldGNUSparseMap(hdr *Header, blk *block) (sparseDatas, error) {
	// Make sure that the input format is GNU.
	// Unfortunately, the STAR format also has a sparse header format that uses
	// the same type flag but has a completely different layout.
	if blk.getFormat() != FormatGNU {
		return nil, ErrHeader
	}
	hdr.Format.mayOnlyBe(FormatGNU)

	var p parser
	hdr.Size = p.parseNumeric(blk.toGNU().realSize())
	if p.err != nil {
		return nil, p.err
	}
	s := blk.toGNU().sparse()
	spd := make(sparseDatas, 0, s.maxEntries())
	for {
		for i := 0; i < s.maxEntries(); i++ {
			// This termination condition is identical to GNU and BSD tar.
			if s.entry(i).offset()[0] == 0x00 {
				break // Don't return, need to process extended headers (even if empty)
			}
			offset := p.parseNumeric(s.entry(i).offset())
			length := p.parseNumeric(s.entry(i).length())
			if p.err != nil {
				return nil, p.err
			}
			spd = append(spd, sparseEntry{Offset: offset, Length: length})
		}

		if s.isExtended()[0] > 0 {
			// There are more entries. Read an extension header and parse its entries.
			if _, err := mustReadFull(tr.r, blk[:]); err != nil {
				return nil, err
			}
			s = blk.toSparse()
			continue
		}
		return spd, nil // Done
	}
}

// readGNUSparseMap1x0 reads the sparse map as stored in GNU's PAX sparse format
// version 1.0. The format of the sparse map consists of a series of
// newline-terminated numeric fields. The first field is the number of entries
// and is always present. Following this are the entries, consisting of two
// fields (offset, length). This function must stop reading at the end
// boundary of the block containing the last newline.
//
// Note that the GNU manual says that numeric values should be encoded in octal
// format. However, the GNU tar utility itself outputs these values in decimal.
// As such, this library treats values as being encoded in decimal.
func readGNUSparseMap1x0(r io.Reader) (sparseDatas, error) {
	var (
		cntNewline int64
		buf        bytes.Buffer
		blk        block
	)

	// feedTokens copies data in blocks from r into buf until there are
	// at least cnt newlines in buf. It will not read more blocks than needed.
	feedTokens := func(n int64) error {
		for cntNewline < n {
			if _, err := mustReadFull(r, blk[:]); err != nil {
				return err
			}
			buf.Write(blk[:])
			for _, c := range blk {
				if c == '\n' {
					cntNewline++
				}
			}
		}
		return nil
	}

	// nextToken gets the next token delimited by a newline. This assumes that
	// at least one newline exists in the buffer.
	nextToken := func() string {
		cntNewline--
		tok, _ := buf.ReadString('\n')
		return strings.TrimRight(tok, "\n")
	}

	// Parse for the number of entries.
	// Use integer overflow resistant math to check this.
	if err := feedTokens(1); err != nil {
		return nil, err
	}
	numEntries, err := strconv.ParseInt(nextToken(), 10, 0) // Intentionally parse as native int
	if err != nil || numEntries < 0 || int(2*numEntries) < int(numEntries) {
		return nil, ErrHeader
	}

	// Parse for all member entries.
	// numEntries is trusted after this since a potential attacker must have
	// committed resources proportional to what this library used.
	if err := feedTokens(2 * numEntries); err != nil {
		return nil, err
	}
	spd := make(sparseDatas, 0, numEntries)
	for i := int64(0); i < numEntries; i++ {
		offset, err1 := strconv.ParseInt(nextToken(), 10, 64)
		length, err2 := strconv.ParseInt(nextToken(), 10, 64)
		if err1 != nil || err2 != nil {
			return nil, ErrHeader
		}
		spd = append(spd, sparseEntry{Offset: offset, Length: length})
	}
	return spd, nil
}

// readGNUSparseMap0x1 reads the sparse map as stored in GNU's PAX sparse format
// version 0.1. The sparse map is stored in the PAX headers.
func readGNUSparseMap0x1(paxHdrs map[string]string) (sparseDatas, error) {
	// Get number of entries.
	// Use integer overflow resistant math to check this.
	numEntriesStr := paxHdrs[paxGNUSparseNumBlocks]
	numEntries, err := strconv.ParseInt(numEntriesStr, 10, 0) // Intentionally parse as native int
	if err != nil || numEntries < 0 || int(2*numEntries) < int(numEntries) {
		return nil, ErrHeader
	}

	// There should be two numbers in sparseMap for each entry.
	sparseMap := strings.Split(paxHdrs[paxGNUSparseMap], ",")
	if len(sparseMap) == 1 && sparseMap[0] == "" {
		sparseMap = sparseMap[:0]
	}
	if int64(len(sparseMap)) != 2*numEntries {
		return nil, ErrHeader
	}

	// Loop through the entries in the sparse map.
	// numEntries is trusted now.
	spd := make(sparseDatas, 0, numEntries)
	for len(sparseMap) >= 2 {
		offset, err1 := strconv.ParseInt(sparseMap[0], 10, 64)
		length, err2 := strconv.ParseInt(sparseMap[1], 10, 64)
		if err1 != nil || err2 != nil {
			return nil, ErrHeader
		}
		spd = append(spd, sparseEntry{Offset: offset, Length: length})
		sparseMap = sparseMap[2:]
	}
	return spd, nil
}

// Read reads from the current file in the tar archive.
// It returns (0, io.EOF) when it reaches the end of that file,
// until [Next] is called to advance to the next file.
//
// If the current file is sparse, then the regions marked as a hole
// are read back as NUL-bytes.
//
// Calling Read on special types like [TypeLink], [TypeSymlink], [TypeChar],
// [TypeBlock], [TypeDir], and [TypeFifo] returns (0, [io.EOF]) regardless of what
// the [Header.Size] claims.
func (tr *Reader) Read(b []byte) (int, error) {
	if tr.err != nil {
		return 0, tr.err
	}
	n, err := tr.curr.Read(b)
	if err != nil && err != io.EOF {
		tr.err = err
	}
	return n, err
}

// writeTo writes the content of the current file to w.
// The bytes written matches the number of remaining bytes in the current file.
//
// If the current file is sparse and w is an io.WriteSeeker,
// then writeTo uses Seek to skip past holes defined in Header.SparseHoles,
// assuming that skipped regions are filled with NULs.
// This always writes the last byte to ensure w is the right size.
//
// TODO(dsnet): Re-export this when adding sparse file support.
// See https://golang.org/issue/22735
func (tr *Reader) writeTo(w io.Writer) (int64, error) {
	if tr.err != nil {
		return 0, tr.err
	}
	n, err := tr.curr.WriteTo(w)
	if err != nil {
		tr.err = err
	}
	return n, err
}

// regFileReader is a fileReader for reading data from a regular file entry.
type regFileReader struct {
	r  io.Reader // Underlying Reader
	nb int64     // Number of remaining bytes to read
}

func (fr *regFileReader) Read(b []byte) (n int, err error) {
	if int64(len(b)) > fr.nb {
		b = b[:fr.nb]
	}
	if len(b) > 0 {
		n, err = fr.r.Read(b)
		fr.nb -= int64(n)
	}
	switch {
	case err == io.EOF && fr.nb > 0:
		return n, io.ErrUnexpectedEOF
	case err == nil && fr.nb == 0:
		return n, io.EOF
	default:
		return n, err
	}
}

func (fr *regFileReader) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, struct{ io.Reader }{fr})
}

// logicalRemaining implements fileState.logicalRemaining.
func (fr regFileReader) logicalRemaining() int64 {
	return fr.nb
}

// physicalRemaining implements fileState.physicalRemaining.
func (fr regFileReader) physicalRemaining() int64 {
	return fr.nb
}

// sparseFileReader is a fileReader for reading data from a sparse file entry.
type sparseFileReader struct {
	fr  fileReader  // Underlying fileReader
	sp  sparseHoles // Normalized list of sparse holes
	pos int64       // Current position in sparse file
}

func (sr *sparseFileReader) Read(b []byte) (n int, err error) {
	finished := int64(len(b)) >= sr.logicalRemaining()
	if finished {
		b = b[:sr.logicalRemaining()]
	}

	b0 := b
	endPos := sr.pos + int64(len(b))
	for endPos > sr.pos && err == nil {
		var nf int // Bytes read in fragment
		holeStart, holeEnd := sr.sp[0].Offset, sr.sp[0].endOffset()
		if sr.pos < holeStart { // In a data fragment
			bf := b[:min(int64(len(b)), holeStart-sr.pos)]
			nf, err = tryReadFull(sr.fr, bf)
		} else { // In a hole fragment
			bf := b[:min(int64(len(b)), holeEnd-sr.pos)]
			nf, err = tryReadFull(zeroReader{}, bf)
		}
		b = b[nf:]
		sr.pos += int64(nf)
		if sr.pos >= holeEnd && len(sr.sp) > 1 {
			sr.sp = sr.sp[1:] // Ensure last fragment always remains
		}
	}

	n = len(b0) - len(b)
	switch {
	case err == io.EOF:
		return n, errMissData // Less data in dense file than sparse file
	case err != nil:
		return n, err
	case sr.logicalRemaining() == 0 && sr.physicalRemaining() > 0:
		return n, errUnrefData // More data in dense file than sparse file
	case finished:
		return n, io.EOF
	default:
		return n, nil
	}
}

func (sr *sparseFileReader) WriteTo(w io.Writer) (n int64, err error) {
	ws, ok := w.(io.WriteSeeker)
	if ok {
		if _, err := ws.Seek(0, io.SeekCurrent); err != nil {
			ok = false // Not all io.Seeker can really seek
		}
	}
	if !ok {
		return io.Copy(w, struct{ io.Reader }{sr})
	}

	var writeLastByte bool
	pos0 := sr.pos
	for sr.logicalRemaining() > 0 && !writeLastByte && err == nil {
		var nf int64 // Size of fragment
		holeStart, holeEnd := sr.sp[0].Offset, sr.sp[0].endOffset()
		if sr.pos < holeStart { // In a data fragment
			nf = holeStart - sr.pos
			nf, err = io.CopyN(ws, sr.fr, nf)
		} else { // In a hole fragment
			nf = holeEnd - sr.pos
			if sr.physicalRemaining() == 0 {
				writeLastByte = true
				nf--
			}
			_, err = ws.Seek(nf, io.SeekCurrent)
		}
		sr.pos += nf
		if sr.pos >= holeEnd && len(sr.sp) > 1 {
			sr.sp = sr.sp[1:] // Ensure last fragment always remains
		}
	}

	// If the last fragment is a hole, then seek to 1-byte before EOF, and
	// write a single byte to ensure the file is the right size.
	if writeLastByte && err == nil {
		_, err = ws.Write([]byte{0})
		sr.pos++
	}

	n = sr.pos - pos0
	switch {
	case err == io.EOF:
		return n, errMissData // Less data in dense file than sparse file
	case err != nil:
		return n, err
	case sr.logicalRemaining() == 0 && sr.physicalRemaining() > 0:
		return n, errUnrefData // More data in dense file than sparse file
	default:
		return n, nil
	}
}

func (sr sparseFileReader) logicalRemaining() int64 {
	return sr.sp[len(sr.sp)-1].endOffset() - sr.pos
}
func (sr sparseFileReader) physicalRemaining() int64 {
	return sr.fr.physicalRemaining()
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}

// mustReadFull is like io.ReadFull except it returns
// io.ErrUnexpectedEOF when io.EOF is hit before len(b) bytes are read.
func mustReadFull(r io.Reader, b []byte) (int, error) {
	n, err := tryReadFull(r, b)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// tryReadFull is like io.ReadFull except it returns
// io.EOF when it is hit before len(b) bytes are read.
func tryReadFull(r io.Reader, b []byte) (n int, err error) {
	for len(b) > n && err == nil {
		var nn int
		nn, err = r.Read(b[n:])
		n += nn
	}
	if len(b) == n && err == io.EOF {
		err = nil
	}
	return n, err
}

// readSpecialFile is like io.ReadAll except it returns
// ErrFieldTooLong if more than maxSpecialFileSize is read.
func readSpecialFile(r io.Reader) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, maxSpecialFileSize+1))
	if len(buf) > maxSpecialFileSize {
		return nil, ErrFieldTooLong
	}
	return buf, err
}

// discard skips n bytes in r, reporting an error if unable to do so.
func discard(r io.Reader, n int64) error {
	// If possible, Seek to the last byte before the end of the data section.
	// Do this because Seek is often lazy about reporting errors; this will mask
	// the fact that the stream may be truncated. We can rely on the
	// io.CopyN done shortly afterwards to trigger any IO errors.
	var seekSkipped int64 // Number of bytes skipped via Seek
	if sr, ok := r.(io.Seeker); ok && n > 1 {
		// Not all io.Seeker can actually Seek. For example, os.Stdin implements
		// io.Seeker, but calling Seek always returns an error and performs
		// no action. Thus, we try an innocent seek to the current position
		// to see if Seek is really supported.
		pos1, err := sr.Seek(0, io.SeekCurrent)
		if pos1 >= 0 && err == nil {
			// Seek seems supported, so perform the real Seek.
			pos2, err := sr.Seek(n-1, io.SeekCurrent)
			if pos2 < 0 || err != nil {
				return err
			}
			seekSkipped = pos2 - pos1
		}
	}

	copySkipped, err := io.CopyN(io.Discard, r, n-seekSkipped)
	if err == io.EOF && seekSkipped+copySkipped < n {
		err = io.ErrUnexpectedEOF
	}
	return err
}
```