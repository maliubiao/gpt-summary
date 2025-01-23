Response:
我的思考过程如下：

1. **理解目标：**  提问要求分析 `go/src/archive/zip/writer.go` 的一部分代码，列举功能，推理实现，举代码示例，说明命令行参数（如果适用），以及指出易错点。

2. **代码结构概览：**  快速浏览代码，识别关键类型和函数。我注意到 `Writer` 结构体是核心，它包含了写入 zip 文件的必要信息，如输出流、目录信息等。  `NewWriter` 是构造函数，`Close` 完成写入，`Create` 和 `CreateHeader` 用于添加文件。

3. **功能分解与解释：**  逐步分析代码，提取主要功能点。
    * **创建 ZIP 文件：** `NewWriter` 负责初始化 `Writer`，绑定输出流。
    * **设置 ZIP 文件偏移量：** `SetOffset` 允许在已有文件末尾追加 ZIP 数据。
    * **刷新缓冲区：** `Flush` 将缓冲区内容写入底层 writer。
    * **设置注释：** `SetComment` 设置 ZIP 文件的注释。
    * **完成 ZIP 文件写入 (核心功能)：** `Close` 函数负责写入中央目录、ZIP64 扩展信息（如果需要）、以及文件尾记录。它遍历已添加的文件信息，构造中央目录项。
    * **添加文件 (简单方式)：** `Create` 提供了一种便捷的方式添加文件，默认使用 Deflate 压缩。
    * **添加文件 (自定义头部)：** `CreateHeader` 允许用户提供 `FileHeader` 结构体，更精细地控制文件元数据。  这里需要特别注意对 UTF-8 标志的处理。
    * **添加原始数据 (不压缩)：** `CreateRaw` 允许直接写入未经压缩的数据，适用于已经压缩过的数据。
    * **复制现有文件：** `Copy`  高效地复制来自 `zip.Reader` 的文件，避免重新压缩。
    * **注册自定义压缩器：** `RegisterCompressor` 允许用户扩展支持的压缩算法。
    * **添加文件系统内容：** `AddFS` 遍历文件系统，将文件和目录添加到 ZIP 文件中。
    * **内部辅助函数：** `detectUTF8`, `prepare`, `writeHeader`, `writeDataDescriptor`, `compressor` 等是内部使用的辅助函数，用于完成特定任务。 `fileWriter` 和 `dirWriter` 用于管理文件和目录的写入。

4. **Go 语言功能推理与示例：**  重点关注 `Writer` 的主要方法，尤其是 `Create` 和 `CreateHeader`。
    * **`Create` 示例：**  展示如何使用 `Create` 添加一个简单的文本文件。
    * **`CreateHeader` 示例：**  展示如何使用 `CreateHeader` 添加文件，并设置文件名和修改时间。  需要解释 `FileHeader` 的使用，以及如何设置时间。
    * **`CreateRaw` 示例：** 展示如何使用 `CreateRaw` 添加一个已经压缩的文件。

5. **代码推理 (细节分析)：**  选择 `Close` 函数作为代码推理的重点，因为它涉及了 ZIP 文件的核心结构。
    * **输入假设：**  假设已经通过 `Create` 或 `CreateHeader` 添加了几个文件。
    * **输出描述：** 描述 `Close` 函数会写入中央目录，包括每个文件的信息（名称、大小、偏移量等），并根据文件大小和数量决定是否写入 ZIP64 扩展信息。
    * **代码片段解释：**  选取 `Close` 函数中写入中央目录项和文件尾记录的关键代码片段，解释其作用。

6. **命令行参数：**  检查代码，没有直接处理命令行参数的部分。`archive/zip` 包通常作为库使用，其功能集成到其他程序中，由上层程序处理命令行参数。

7. **易犯错的点：**  思考使用 `zip.Writer` 时常见的错误。
    * **忘记 `Close()`：** 这是最常见的问题，会导致 ZIP 文件不完整。
    * **在 `Close()` 之后写入：**  `Writer` 关闭后不能再写入。
    * **文件名路径问题：** ZIP 文件名应使用相对路径和正斜杠。
    * **修改 `FileHeader`：** 在调用 `CreateHeader` 后修改 `FileHeader` 会导致不可预测的结果。

8. **组织答案：**  将以上分析结果组织成清晰的中文回答，包括功能列表、Go 代码示例、代码推理、命令行参数说明（没有则说明）、以及易犯错的点。 使用代码块格式化代码，增强可读性。

9. **审阅和完善：**  仔细检查答案，确保准确性和完整性。 例如，确认代码示例是否正确，解释是否清晰。  检查有没有遗漏重要的功能或细节。

通过以上步骤，我能够系统地分析给定的 Go 代码片段，并生成符合提问要求的详细解答。
这段 `go/src/archive/zip/writer.go` 代码是 Go 语言 `archive/zip` 标准库中用于 **创建 ZIP 归档文件** 的核心部分。 它实现了 `Writer` 类型，用于向一个 `io.Writer` 写入 ZIP 格式的数据。

以下是它的主要功能：

1. **创建新的 ZIP 文件写入器：**  `NewWriter(w io.Writer)` 函数创建一个新的 `Writer` 实例，它会将 ZIP 数据写入提供的 `io.Writer`。 这允许将 ZIP 文件写入内存缓冲区、文件或其他实现了 `io.Writer` 接口的对象。

2. **设置 ZIP 数据的起始偏移量：** `SetOffset(n int64)` 函数允许指定 ZIP 数据在底层 `io.Writer` 中的起始位置。 这通常用于将 ZIP 数据追加到已有的文件中，例如可执行文件。  必须在写入任何数据之前调用。

3. **刷新写入缓冲区：** `Flush()` 方法将内部的 `bufio.Writer` 缓冲区中的数据刷新到底层的 `io.Writer`。 通常不需要手动调用，`Close()` 方法会自动执行。

4. **设置 ZIP 文件的注释：** `SetComment(comment string)` 方法用于设置 ZIP 文件的结尾注释。  必须在调用 `Close()` 之前调用。

5. **完成 ZIP 文件的写入 (关闭写入器)：** `Close()` 方法是核心，它执行以下操作：
   - 刷新最后一个添加的文件的写入器（如果有）。
   - 写入 ZIP 文件的中央目录。 中央目录包含了每个文件的元数据信息，例如名称、大小、压缩方法、CRC32 校验和等。
   - 如果需要，写入 ZIP64 扩展信息（用于支持大于 4GB 的文件或超过 65535 个文件）。
   - 写入 ZIP 文件的结尾记录。
   - 刷新底层的 `io.Writer`。

6. **添加新文件到 ZIP 归档 (使用默认压缩)：** `Create(name string)` 方法创建一个新的文件条目，并返回一个 `io.Writer`，用于写入该文件的内容。  默认使用 Deflate 压缩算法。  文件名必须是相对路径，并使用正斜杠。

7. **添加新文件到 ZIP 归档 (自定义头部信息)：** `CreateHeader(fh *FileHeader)` 方法与 `Create` 类似，但允许提供一个 `FileHeader` 结构体来更精细地控制文件的元数据，例如修改时间、压缩方法、外部属性等。 `Writer` 会拥有 `FileHeader` 的所有权，调用者不应再修改。

8. **添加未经压缩的原始数据到 ZIP 归档：** `CreateRaw(fh *FileHeader)` 方法允许添加已经压缩或不需要压缩的数据。  调用者需要自行负责数据的压缩和设置 `FileHeader` 中的 `CompressedSize` 和 `UncompressedSize` 等字段。

9. **复制已存在的文件条目：** `Copy(f *File)` 方法用于复制来自 `zip.Reader` 的文件条目。它直接复制原始数据，避免了重新压缩和解压缩，效率很高。

10. **注册自定义压缩器：** `RegisterCompressor(method uint16, comp Compressor)` 方法允许注册或覆盖特定压缩方法 ID 的自定义压缩器。

11. **添加文件系统中的文件和目录：** `AddFS(fsys fs.FS)` 方法遍历指定的文件系统，并将文件和目录添加到 ZIP 归档中。 目录结构会被保留，文件默认使用 Deflate 压缩。

**Go 语言功能实现示例：**

以下代码示例演示了如何使用 `zip.Writer` 创建一个包含两个文件的 ZIP 归档：

```go
package main

import (
	"archive/zip"
	"io"
	"log"
	"os"
	"time"
)

func main() {
	// 创建一个文件用于写入 ZIP 归档
	file, err := os.Create("myzipfile.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// 创建一个 zip.Writer
	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	// 添加第一个文件
	file1Writer, err := zipWriter.Create("file1.txt")
	if err != nil {
		log.Fatal(err)
	}
	_, err = file1Writer.Write([]byte("This is the content of file1."))
	if err != nil {
		log.Fatal(err)
	}

	// 添加第二个文件并设置修改时间
	header := &zip.FileHeader{
		Name:     "file2.txt",
		Modified: time.Now().Add(-time.Hour * 24), // 设置为昨天
		Method:   zip.Deflate,
	}
	file2Writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		log.Fatal(err)
	}
	_, err = file2Writer.Write([]byte("This is the content of file2 with a custom modification time."))
	if err != nil {
		log.Fatal(err)
	}

	// 设置 ZIP 文件的注释
	err = zipWriter.SetComment("This is a sample ZIP file.")
	if err != nil {
		log.Fatal(err)
	}

	// Close zipWriter 完成写入
	err = zipWriter.Close()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("ZIP file created successfully!")
}
```

**假设的输入与输出 (代码推理)：**

假设我们已经通过 `Create` 或 `CreateHeader` 向 `zipWriter` 添加了两个文件，分别为 `file1.txt` 和 `file2.txt`。

当调用 `zipWriter.Close()` 时，它会执行以下步骤（简化描述）：

1. **写入 `file1.txt` 的中央目录项：**
   - 写入中央目录头部签名。
   - 写入创建者版本、读取者版本、标志位、压缩方法等信息。
   - 写入 `file1.txt` 的修改时间、CRC32 校验和、压缩后大小、原始大小。
   - 写入文件名长度和 `file1.txt` 的文件名。
   - 写入额外字段长度和内容（如果存在）。
   - 写入注释长度和内容（如果存在）。
   - 写入起始磁盘号、内部文件属性、外部文件属性、本地头部偏移量。

2. **写入 `file2.txt` 的中央目录项：**  与 `file1.txt` 类似，但会写入 `file2.txt` 的相应信息。

3. **写入 ZIP 文件结尾记录：**
   - 写入结尾记录签名。
   - 写入磁盘号、起始磁盘号、当前磁盘上的中央目录条目数、总中央目录条目数。
   - 写入中央目录的大小。
   - 写入中央目录的起始偏移量。
   - 写入注释长度和 ZIP 文件的注释 "This is a sample ZIP file."。

**命令行参数处理：**

这段代码本身并没有直接处理命令行参数。 `archive/zip` 包通常作为库使用，它的功能会被集成到需要创建 ZIP 文件的应用程序中。 这些应用程序可能会使用 `flag` 包或其他库来处理命令行参数，例如指定输出 ZIP 文件的路径或要添加到 ZIP 归档中的文件。

例如，一个简单的命令行工具可能接受以下参数：

```
myziptool -output myarchive.zip file1.txt dir1/file2.txt
```

该工具会使用 `archive/zip` 包来创建 `myarchive.zip`，并将 `file1.txt` 和 `dir1/file2.txt` 添加到其中。

**使用者易犯错的点：**

1. **忘记调用 `Close()`：**  如果不调用 `Close()` 方法，中央目录和结尾记录不会被写入，导致 ZIP 文件不完整或无法读取。

   ```go
   zipWriter := zip.NewWriter(file)
   // ... 添加文件 ...
   // 忘记调用 zipWriter.Close() !!!
   ```

2. **在 `Close()` 之后继续写入：**  一旦 `Close()` 被调用，`Writer` 就不能再写入任何数据。

   ```go
   zipWriter := zip.NewWriter(file)
   // ... 添加文件 ...
   zipWriter.Close()
   fileWriter, _ := zipWriter.Create("another_file.txt") // 这会出错
   ```

3. **文件名路径问题：**  ZIP 文件名应该使用相对路径，并且使用正斜杠 `/` 作为路径分隔符，即使在 Windows 系统上也是如此。 使用绝对路径或反斜杠可能会导致兼容性问题。

   ```go
   zipWriter.Create("C:\\My Documents\\file.txt") // 错误：应使用相对路径和正斜杠
   zipWriter.Create("my/documents/file.txt")     // 正确
   ```

4. **在调用 `CreateHeader` 后修改 `FileHeader`：**  `Writer` 会取得传递给 `CreateHeader` 的 `FileHeader` 的所有权，并在内部使用和修改它。  在调用 `CreateHeader` 之后修改 `FileHeader` 的字段可能会导致数据不一致或写入错误。

   ```go
   header := &zip.FileHeader{Name: "myFile.txt"}
   fileWriter, _ := zipWriter.CreateHeader(header)
   header.Method = zip.Store //  不应该在 CreateHeader 后修改 header
   ```

理解这些功能和潜在的错误能够帮助开发者更有效地使用 Go 语言的 `archive/zip` 包来创建 ZIP 归档文件。

### 提示词
```
这是路径为go/src/archive/zip/writer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"bufio"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"strings"
	"unicode/utf8"
)

var (
	errLongName  = errors.New("zip: FileHeader.Name too long")
	errLongExtra = errors.New("zip: FileHeader.Extra too long")
)

// Writer implements a zip file writer.
type Writer struct {
	cw          *countWriter
	dir         []*header
	last        *fileWriter
	closed      bool
	compressors map[uint16]Compressor
	comment     string

	// testHookCloseSizeOffset if non-nil is called with the size
	// of offset of the central directory at Close.
	testHookCloseSizeOffset func(size, offset uint64)
}

type header struct {
	*FileHeader
	offset uint64
	raw    bool
}

// NewWriter returns a new [Writer] writing a zip file to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{cw: &countWriter{w: bufio.NewWriter(w)}}
}

// SetOffset sets the offset of the beginning of the zip data within the
// underlying writer. It should be used when the zip data is appended to an
// existing file, such as a binary executable.
// It must be called before any data is written.
func (w *Writer) SetOffset(n int64) {
	if w.cw.count != 0 {
		panic("zip: SetOffset called after data was written")
	}
	w.cw.count = n
}

// Flush flushes any buffered data to the underlying writer.
// Calling Flush is not normally necessary; calling Close is sufficient.
func (w *Writer) Flush() error {
	return w.cw.w.(*bufio.Writer).Flush()
}

// SetComment sets the end-of-central-directory comment field.
// It can only be called before [Writer.Close].
func (w *Writer) SetComment(comment string) error {
	if len(comment) > uint16max {
		return errors.New("zip: Writer.Comment too long")
	}
	w.comment = comment
	return nil
}

// Close finishes writing the zip file by writing the central directory.
// It does not close the underlying writer.
func (w *Writer) Close() error {
	if w.last != nil && !w.last.closed {
		if err := w.last.close(); err != nil {
			return err
		}
		w.last = nil
	}
	if w.closed {
		return errors.New("zip: writer closed twice")
	}
	w.closed = true

	// write central directory
	start := w.cw.count
	for _, h := range w.dir {
		var buf [directoryHeaderLen]byte
		b := writeBuf(buf[:])
		b.uint32(uint32(directoryHeaderSignature))
		b.uint16(h.CreatorVersion)
		b.uint16(h.ReaderVersion)
		b.uint16(h.Flags)
		b.uint16(h.Method)
		b.uint16(h.ModifiedTime)
		b.uint16(h.ModifiedDate)
		b.uint32(h.CRC32)
		if h.isZip64() || h.offset >= uint32max {
			// the file needs a zip64 header. store maxint in both
			// 32 bit size fields (and offset later) to signal that the
			// zip64 extra header should be used.
			b.uint32(uint32max) // compressed size
			b.uint32(uint32max) // uncompressed size

			// append a zip64 extra block to Extra
			var buf [28]byte // 2x uint16 + 3x uint64
			eb := writeBuf(buf[:])
			eb.uint16(zip64ExtraID)
			eb.uint16(24) // size = 3x uint64
			eb.uint64(h.UncompressedSize64)
			eb.uint64(h.CompressedSize64)
			eb.uint64(h.offset)
			h.Extra = append(h.Extra, buf[:]...)
		} else {
			b.uint32(h.CompressedSize)
			b.uint32(h.UncompressedSize)
		}

		b.uint16(uint16(len(h.Name)))
		b.uint16(uint16(len(h.Extra)))
		b.uint16(uint16(len(h.Comment)))
		b = b[4:] // skip disk number start and internal file attr (2x uint16)
		b.uint32(h.ExternalAttrs)
		if h.offset > uint32max {
			b.uint32(uint32max)
		} else {
			b.uint32(uint32(h.offset))
		}
		if _, err := w.cw.Write(buf[:]); err != nil {
			return err
		}
		if _, err := io.WriteString(w.cw, h.Name); err != nil {
			return err
		}
		if _, err := w.cw.Write(h.Extra); err != nil {
			return err
		}
		if _, err := io.WriteString(w.cw, h.Comment); err != nil {
			return err
		}
	}
	end := w.cw.count

	records := uint64(len(w.dir))
	size := uint64(end - start)
	offset := uint64(start)

	if f := w.testHookCloseSizeOffset; f != nil {
		f(size, offset)
	}

	if records >= uint16max || size >= uint32max || offset >= uint32max {
		var buf [directory64EndLen + directory64LocLen]byte
		b := writeBuf(buf[:])

		// zip64 end of central directory record
		b.uint32(directory64EndSignature)
		b.uint64(directory64EndLen - 12) // length minus signature (uint32) and length fields (uint64)
		b.uint16(zipVersion45)           // version made by
		b.uint16(zipVersion45)           // version needed to extract
		b.uint32(0)                      // number of this disk
		b.uint32(0)                      // number of the disk with the start of the central directory
		b.uint64(records)                // total number of entries in the central directory on this disk
		b.uint64(records)                // total number of entries in the central directory
		b.uint64(size)                   // size of the central directory
		b.uint64(offset)                 // offset of start of central directory with respect to the starting disk number

		// zip64 end of central directory locator
		b.uint32(directory64LocSignature)
		b.uint32(0)           // number of the disk with the start of the zip64 end of central directory
		b.uint64(uint64(end)) // relative offset of the zip64 end of central directory record
		b.uint32(1)           // total number of disks

		if _, err := w.cw.Write(buf[:]); err != nil {
			return err
		}

		// store max values in the regular end record to signal
		// that the zip64 values should be used instead
		records = uint16max
		size = uint32max
		offset = uint32max
	}

	// write end record
	var buf [directoryEndLen]byte
	b := writeBuf(buf[:])
	b.uint32(uint32(directoryEndSignature))
	b = b[4:]                        // skip over disk number and first disk number (2x uint16)
	b.uint16(uint16(records))        // number of entries this disk
	b.uint16(uint16(records))        // number of entries total
	b.uint32(uint32(size))           // size of directory
	b.uint32(uint32(offset))         // start of directory
	b.uint16(uint16(len(w.comment))) // byte size of EOCD comment
	if _, err := w.cw.Write(buf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w.cw, w.comment); err != nil {
		return err
	}

	return w.cw.w.(*bufio.Writer).Flush()
}

// Create adds a file to the zip file using the provided name.
// It returns a [Writer] to which the file contents should be written.
// The file contents will be compressed using the [Deflate] method.
// The name must be a relative path: it must not start with a drive
// letter (e.g. C:) or leading slash, and only forward slashes are
// allowed. To create a directory instead of a file, add a trailing
// slash to the name. Duplicate names will not overwrite previous entries
// and are appended to the zip file.
// The file's contents must be written to the [io.Writer] before the next
// call to [Writer.Create], [Writer.CreateHeader], or [Writer.Close].
func (w *Writer) Create(name string) (io.Writer, error) {
	header := &FileHeader{
		Name:   name,
		Method: Deflate,
	}
	return w.CreateHeader(header)
}

// detectUTF8 reports whether s is a valid UTF-8 string, and whether the string
// must be considered UTF-8 encoding (i.e., not compatible with CP-437, ASCII,
// or any other common encoding).
func detectUTF8(s string) (valid, require bool) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		// Officially, ZIP uses CP-437, but many readers use the system's
		// local character encoding. Most encoding are compatible with a large
		// subset of CP-437, which itself is ASCII-like.
		//
		// Forbid 0x7e and 0x5c since EUC-KR and Shift-JIS replace those
		// characters with localized currency and overline characters.
		if r < 0x20 || r > 0x7d || r == 0x5c {
			if !utf8.ValidRune(r) || (r == utf8.RuneError && size == 1) {
				return false, false
			}
			require = true
		}
	}
	return true, require
}

// prepare performs the bookkeeping operations required at the start of
// CreateHeader and CreateRaw.
func (w *Writer) prepare(fh *FileHeader) error {
	if w.last != nil && !w.last.closed {
		if err := w.last.close(); err != nil {
			return err
		}
	}
	if len(w.dir) > 0 && w.dir[len(w.dir)-1].FileHeader == fh {
		// See https://golang.org/issue/11144 confusion.
		return errors.New("archive/zip: invalid duplicate FileHeader")
	}
	return nil
}

// CreateHeader adds a file to the zip archive using the provided [FileHeader]
// for the file metadata. [Writer] takes ownership of fh and may mutate
// its fields. The caller must not modify fh after calling [Writer.CreateHeader].
//
// This returns a [Writer] to which the file contents should be written.
// The file's contents must be written to the io.Writer before the next
// call to [Writer.Create], [Writer.CreateHeader], [Writer.CreateRaw], or [Writer.Close].
func (w *Writer) CreateHeader(fh *FileHeader) (io.Writer, error) {
	if err := w.prepare(fh); err != nil {
		return nil, err
	}

	// The ZIP format has a sad state of affairs regarding character encoding.
	// Officially, the name and comment fields are supposed to be encoded
	// in CP-437 (which is mostly compatible with ASCII), unless the UTF-8
	// flag bit is set. However, there are several problems:
	//
	//	* Many ZIP readers still do not support UTF-8.
	//	* If the UTF-8 flag is cleared, several readers simply interpret the
	//	name and comment fields as whatever the local system encoding is.
	//
	// In order to avoid breaking readers without UTF-8 support,
	// we avoid setting the UTF-8 flag if the strings are CP-437 compatible.
	// However, if the strings require multibyte UTF-8 encoding and is a
	// valid UTF-8 string, then we set the UTF-8 bit.
	//
	// For the case, where the user explicitly wants to specify the encoding
	// as UTF-8, they will need to set the flag bit themselves.
	utf8Valid1, utf8Require1 := detectUTF8(fh.Name)
	utf8Valid2, utf8Require2 := detectUTF8(fh.Comment)
	switch {
	case fh.NonUTF8:
		fh.Flags &^= 0x800
	case (utf8Require1 || utf8Require2) && (utf8Valid1 && utf8Valid2):
		fh.Flags |= 0x800
	}

	fh.CreatorVersion = fh.CreatorVersion&0xff00 | zipVersion20 // preserve compatibility byte
	fh.ReaderVersion = zipVersion20

	// If Modified is set, this takes precedence over MS-DOS timestamp fields.
	if !fh.Modified.IsZero() {
		// Contrary to the FileHeader.SetModTime method, we intentionally
		// do not convert to UTC, because we assume the user intends to encode
		// the date using the specified timezone. A user may want this control
		// because many legacy ZIP readers interpret the timestamp according
		// to the local timezone.
		//
		// The timezone is only non-UTC if a user directly sets the Modified
		// field directly themselves. All other approaches sets UTC.
		fh.ModifiedDate, fh.ModifiedTime = timeToMsDosTime(fh.Modified)

		// Use "extended timestamp" format since this is what Info-ZIP uses.
		// Nearly every major ZIP implementation uses a different format,
		// but at least most seem to be able to understand the other formats.
		//
		// This format happens to be identical for both local and central header
		// if modification time is the only timestamp being encoded.
		var mbuf [9]byte // 2*SizeOf(uint16) + SizeOf(uint8) + SizeOf(uint32)
		mt := uint32(fh.Modified.Unix())
		eb := writeBuf(mbuf[:])
		eb.uint16(extTimeExtraID)
		eb.uint16(5)  // Size: SizeOf(uint8) + SizeOf(uint32)
		eb.uint8(1)   // Flags: ModTime
		eb.uint32(mt) // ModTime
		fh.Extra = append(fh.Extra, mbuf[:]...)
	}

	var (
		ow io.Writer
		fw *fileWriter
	)
	h := &header{
		FileHeader: fh,
		offset:     uint64(w.cw.count),
	}

	if strings.HasSuffix(fh.Name, "/") {
		// Set the compression method to Store to ensure data length is truly zero,
		// which the writeHeader method always encodes for the size fields.
		// This is necessary as most compression formats have non-zero lengths
		// even when compressing an empty string.
		fh.Method = Store
		fh.Flags &^= 0x8 // we will not write a data descriptor

		// Explicitly clear sizes as they have no meaning for directories.
		fh.CompressedSize = 0
		fh.CompressedSize64 = 0
		fh.UncompressedSize = 0
		fh.UncompressedSize64 = 0

		ow = dirWriter{}
	} else {
		fh.Flags |= 0x8 // we will write a data descriptor

		fw = &fileWriter{
			zipw:      w.cw,
			compCount: &countWriter{w: w.cw},
			crc32:     crc32.NewIEEE(),
		}
		comp := w.compressor(fh.Method)
		if comp == nil {
			return nil, ErrAlgorithm
		}
		var err error
		fw.comp, err = comp(fw.compCount)
		if err != nil {
			return nil, err
		}
		fw.rawCount = &countWriter{w: fw.comp}
		fw.header = h
		ow = fw
	}
	w.dir = append(w.dir, h)
	if err := writeHeader(w.cw, h); err != nil {
		return nil, err
	}
	// If we're creating a directory, fw is nil.
	w.last = fw
	return ow, nil
}

func writeHeader(w io.Writer, h *header) error {
	const maxUint16 = 1<<16 - 1
	if len(h.Name) > maxUint16 {
		return errLongName
	}
	if len(h.Extra) > maxUint16 {
		return errLongExtra
	}

	var buf [fileHeaderLen]byte
	b := writeBuf(buf[:])
	b.uint32(uint32(fileHeaderSignature))
	b.uint16(h.ReaderVersion)
	b.uint16(h.Flags)
	b.uint16(h.Method)
	b.uint16(h.ModifiedTime)
	b.uint16(h.ModifiedDate)
	// In raw mode (caller does the compression), the values are either
	// written here or in the trailing data descriptor based on the header
	// flags.
	if h.raw && !h.hasDataDescriptor() {
		b.uint32(h.CRC32)
		b.uint32(uint32(min(h.CompressedSize64, uint32max)))
		b.uint32(uint32(min(h.UncompressedSize64, uint32max)))
	} else {
		// When this package handle the compression, these values are
		// always written to the trailing data descriptor.
		b.uint32(0) // crc32
		b.uint32(0) // compressed size
		b.uint32(0) // uncompressed size
	}
	b.uint16(uint16(len(h.Name)))
	b.uint16(uint16(len(h.Extra)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, h.Name); err != nil {
		return err
	}
	_, err := w.Write(h.Extra)
	return err
}

// CreateRaw adds a file to the zip archive using the provided [FileHeader] and
// returns a [Writer] to which the file contents should be written. The file's
// contents must be written to the io.Writer before the next call to [Writer.Create],
// [Writer.CreateHeader], [Writer.CreateRaw], or [Writer.Close].
//
// In contrast to [Writer.CreateHeader], the bytes passed to Writer are not compressed.
//
// CreateRaw's argument is stored in w. If the argument is a pointer to the embedded
// [FileHeader] in a [File] obtained from a [Reader] created from in-memory data,
// then w will refer to all of that memory.
func (w *Writer) CreateRaw(fh *FileHeader) (io.Writer, error) {
	if err := w.prepare(fh); err != nil {
		return nil, err
	}

	fh.CompressedSize = uint32(min(fh.CompressedSize64, uint32max))
	fh.UncompressedSize = uint32(min(fh.UncompressedSize64, uint32max))

	h := &header{
		FileHeader: fh,
		offset:     uint64(w.cw.count),
		raw:        true,
	}
	w.dir = append(w.dir, h)
	if err := writeHeader(w.cw, h); err != nil {
		return nil, err
	}

	if strings.HasSuffix(fh.Name, "/") {
		w.last = nil
		return dirWriter{}, nil
	}

	fw := &fileWriter{
		header: h,
		zipw:   w.cw,
	}
	w.last = fw
	return fw, nil
}

// Copy copies the file f (obtained from a [Reader]) into w. It copies the raw
// form directly bypassing decompression, compression, and validation.
func (w *Writer) Copy(f *File) error {
	r, err := f.OpenRaw()
	if err != nil {
		return err
	}
	// Copy the FileHeader so w doesn't store a pointer to the data
	// of f's entire archive. See #65499.
	fh := f.FileHeader
	fw, err := w.CreateRaw(&fh)
	if err != nil {
		return err
	}
	_, err = io.Copy(fw, r)
	return err
}

// RegisterCompressor registers or overrides a custom compressor for a specific
// method ID. If a compressor for a given method is not found, [Writer] will
// default to looking up the compressor at the package level.
func (w *Writer) RegisterCompressor(method uint16, comp Compressor) {
	if w.compressors == nil {
		w.compressors = make(map[uint16]Compressor)
	}
	w.compressors[method] = comp
}

// AddFS adds the files from fs.FS to the archive.
// It walks the directory tree starting at the root of the filesystem
// adding each file to the zip using deflate while maintaining the directory structure.
func (w *Writer) AddFS(fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return errors.New("zip: cannot add non-regular file")
		}
		h, err := FileInfoHeader(info)
		if err != nil {
			return err
		}
		h.Name = name
		h.Method = Deflate
		fw, err := w.CreateHeader(h)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := fsys.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(fw, f)
		return err
	})
}

func (w *Writer) compressor(method uint16) Compressor {
	comp := w.compressors[method]
	if comp == nil {
		comp = compressor(method)
	}
	return comp
}

type dirWriter struct{}

func (dirWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	return 0, errors.New("zip: write to directory")
}

type fileWriter struct {
	*header
	zipw      io.Writer
	rawCount  *countWriter
	comp      io.WriteCloser
	compCount *countWriter
	crc32     hash.Hash32
	closed    bool
}

func (w *fileWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("zip: write to closed file")
	}
	if w.raw {
		return w.zipw.Write(p)
	}
	w.crc32.Write(p)
	return w.rawCount.Write(p)
}

func (w *fileWriter) close() error {
	if w.closed {
		return errors.New("zip: file closed twice")
	}
	w.closed = true
	if w.raw {
		return w.writeDataDescriptor()
	}
	if err := w.comp.Close(); err != nil {
		return err
	}

	// update FileHeader
	fh := w.header.FileHeader
	fh.CRC32 = w.crc32.Sum32()
	fh.CompressedSize64 = uint64(w.compCount.count)
	fh.UncompressedSize64 = uint64(w.rawCount.count)

	if fh.isZip64() {
		fh.CompressedSize = uint32max
		fh.UncompressedSize = uint32max
		fh.ReaderVersion = zipVersion45 // requires 4.5 - File uses ZIP64 format extensions
	} else {
		fh.CompressedSize = uint32(fh.CompressedSize64)
		fh.UncompressedSize = uint32(fh.UncompressedSize64)
	}

	return w.writeDataDescriptor()
}

func (w *fileWriter) writeDataDescriptor() error {
	if !w.hasDataDescriptor() {
		return nil
	}
	// Write data descriptor. This is more complicated than one would
	// think, see e.g. comments in zipfile.c:putextended() and
	// https://bugs.openjdk.org/browse/JDK-7073588.
	// The approach here is to write 8 byte sizes if needed without
	// adding a zip64 extra in the local header (too late anyway).
	var buf []byte
	if w.isZip64() {
		buf = make([]byte, dataDescriptor64Len)
	} else {
		buf = make([]byte, dataDescriptorLen)
	}
	b := writeBuf(buf)
	b.uint32(dataDescriptorSignature) // de-facto standard, required by OS X
	b.uint32(w.CRC32)
	if w.isZip64() {
		b.uint64(w.CompressedSize64)
		b.uint64(w.UncompressedSize64)
	} else {
		b.uint32(w.CompressedSize)
		b.uint32(w.UncompressedSize)
	}
	_, err := w.zipw.Write(buf)
	return err
}

type countWriter struct {
	w     io.Writer
	count int64
}

func (w *countWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.count += int64(n)
	return n, err
}

type nopCloser struct {
	io.Writer
}

func (w nopCloser) Close() error {
	return nil
}

type writeBuf []byte

func (b *writeBuf) uint8(v uint8) {
	(*b)[0] = v
	*b = (*b)[1:]
}

func (b *writeBuf) uint16(v uint16) {
	binary.LittleEndian.PutUint16(*b, v)
	*b = (*b)[2:]
}

func (b *writeBuf) uint32(v uint32) {
	binary.LittleEndian.PutUint32(*b, v)
	*b = (*b)[4:]
}

func (b *writeBuf) uint64(v uint64) {
	binary.LittleEndian.PutUint64(*b, v)
	*b = (*b)[8:]
}
```