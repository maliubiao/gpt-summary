Response:
我的思考过程如下：

1. **理解核心目标：** 提问是关于 Go 语言 `archive/tar` 包中 `writer.go` 文件的功能，以及如何使用它。目标是解释其作用，并提供代码示例。

2. **通读代码，识别关键结构体和方法：**  快速浏览代码，关注以下关键点：
    * `Writer` 结构体：这是核心结构体，负责 tar 文件的写入。
    * `NewWriter` 函数：创建 `Writer` 实例。
    * `WriteHeader` 方法：写入 tar 文件的头部信息。
    * `Write` 方法：写入文件内容。
    * `Flush` 方法：刷新缓冲区。
    * `Close` 方法：关闭 tar 文件。
    * `AddFS` 方法：添加文件系统到 tar 归档。
    * 各种 `write...Header` 方法 (`writeUSTARHeader`, `writePAXHeader`, `writeGNUHeader`)：处理不同 tar 格式的头部写入。
    * `fileWriter` 接口及其实现 (`regFileWriter`, `sparseFileWriter`)：处理文件内容的写入，包括常规文件和稀疏文件（尽管代码中有注释说明稀疏文件的部分功能被注释掉了）。

3. **提取主要功能点：**  基于对代码的理解，列出 `Writer` 的主要功能：
    * 创建 tar 归档文件。
    * 写入文件头部信息，包括文件名、大小、权限等。
    * 写入文件内容。
    * 支持不同的 tar 格式 (USTAR, PAX, GNU)。
    * 支持添加整个文件系统到 tar 归档。
    * 处理文件内容的填充 (padding)。
    * 关闭 tar 归档文件并写入尾部信息。

4. **选择合适的 Go 语言功能进行示例说明：**  `archive/tar` 包的核心功能就是创建和写入 tar 归档文件。  因此，使用 `Writer` 来创建一个简单的 tar 文件是最直接的例子。

5. **构建代码示例：**  编写一个示例，演示如何使用 `Writer` 创建一个包含单个文件的 tar 归档。  需要包含以下步骤：
    * 导入必要的包 (`archive/tar`, `os`, `io`).
    * 创建一个 `os.File` 用于写入 tar 文件。
    * 使用 `tar.NewWriter` 创建 `Writer` 实例。
    * 创建一个 `tar.Header` 结构体，设置文件名和大小。
    * 使用 `writer.WriteHeader` 写入头部。
    * 使用 `writer.Write` 写入文件内容。
    * 使用 `writer.Close` 关闭 `Writer`。

6. **添加假设的输入和输出：**  对于代码示例，明确说明假设的输入（例如，要压缩的文件名和内容）以及预期的输出（一个包含该文件的 tar 归档）。

7. **解释 `AddFS` 的功能：**  重点解释 `AddFS` 方法可以方便地将整个文件系统或目录添加到 tar 归档中。

8. **分析命令行参数处理：**  `archive/tar` 包本身并不直接处理命令行参数。它的作用是提供底层的 tar 文件读写能力。  命令行参数的处理通常由调用 `archive/tar` 的应用程序来完成。因此，需要说明这一点。

9. **识别易犯错误点：**  思考使用 `Writer` 时可能出现的常见错误：
    * 在 `WriteHeader` 之前尝试 `Write`。
    * 写入的数据量超过 `Header.Size`。
    * 没有正确关闭 `Writer`。
    * `Header` 中的文件名或路径不正确。

10. **组织答案并使用中文：**  将以上分析结果组织成清晰的中文回答，包括功能列表、代码示例、输入输出说明、`AddFS` 的解释、命令行参数处理的说明以及易犯错误点的列举。

**自检和完善：**  重新阅读问题和答案，确保答案完整、准确、易懂，并覆盖了问题的所有要点。 检查代码示例是否可以运行，输入输出是否合理。 确认中文表达是否自然流畅。  例如，我最初可能只关注了 `WriteHeader` 和 `Write`，后来意识到 `AddFS` 也是一个重要的功能点，需要单独说明。  对于错误点，需要给出具体的例子，而不仅仅是抽象的描述。
这段Go语言代码是 `archive/tar` 包中 `writer.go` 文件的一部分，它实现了 **创建（写入）tar 归档文件** 的功能。

以下是它的主要功能：

1. **创建 `tar.Writer` 实例:** `NewWriter(w io.Writer)` 函数用于创建一个新的 `Writer`，它会将 tar 归档的数据写入提供的 `io.Writer` (例如，一个文件)。

2. **写入文件头部信息 (`WriteHeader`):**  `WriteHeader(hdr *Header)` 方法接收一个 `tar.Header` 结构体指针，该结构体包含了要写入的文件的元数据信息（如文件名、大小、权限、修改时间等）。这个方法会将这些信息格式化并写入到 tar 归档中，为后续写入文件内容做准备。  它还会处理不同 tar 格式（USTAR, PAX, GNU）的头部信息。

3. **写入文件内容 (`Write`):**  `Write(b []byte)` 方法实现了 `io.Writer` 接口，用于将文件的实际内容写入到 tar 归档中。写入的数据量不能超过在 `WriteHeader` 中指定的 `Header.Size`。

4. **刷新缓冲区 (`Flush`):** `Flush()` 方法用于确保当前文件的所有数据和填充都被写入到下层的 `io.Writer`。虽然不一定需要显式调用，但在某些情况下可以确保数据及时写入。

5. **添加整个文件系统 (`AddFS`):** `AddFS(fsys fs.FS)` 方法允许将整个文件系统（或其子集）添加到 tar 归档中。它会遍历文件系统，为每个文件和目录创建相应的头部信息并写入内容。

6. **关闭 tar 归档 (`Close`):** `Close()` 方法会完成 tar 归档的写入，包括写入末尾的两个零数据块作为结束标志，并确保所有数据都被刷新。

**它可以被理解为实现了 Go 语言中创建和写入 tar 归档文件的核心逻辑。**

**Go 代码示例：**

以下代码示例展示了如何使用 `tar.Writer` 创建一个包含两个文件的 tar 归档。

```go
package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	// 创建一个用于写入 tar 文件的文件
	file, err := os.Create("mytar.tar")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 创建一个 tar.Writer 实例
	tw := tar.NewWriter(file)
	defer tw.Close()

	// --- 添加第一个文件 ---
	header := &tar.Header{
		Name:    "file1.txt",
		Size:    int64(len("Hello, Tar!\n")),
		Mode:    0600,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		panic(err)
	}
	_, err = io.Copy(tw, strings.NewReader("Hello, Tar!\n"))
	if err != nil {
		panic(err)
	}

	// --- 添加第二个文件 ---
	header = &tar.Header{
		Name:    "subdir/file2.txt",
		Size:    int64(len("This is another file.\n")),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		panic(err)
	}
	_, err = io.Copy(tw, strings.NewReader("This is another file.\n"))
	if err != nil {
		panic(err)
	}

	fmt.Println("Tar file created successfully!")
}
```

**假设的输入与输出：**

**输入：** 无（此示例直接在代码中定义了要写入的内容）

**输出：** 会在当前目录下生成一个名为 `mytar.tar` 的文件，该文件包含了两个文件：

* `file1.txt`，内容为 "Hello, Tar!\n"
* `subdir/file2.txt`，内容为 "This is another file.\n"

**代码推理：**

代码首先创建了一个 `tar.Writer` 并将其关联到一个输出文件。然后，它为每个要添加到 tar 归档中的文件创建了一个 `tar.Header` 结构体，设置了文件名、大小、权限等信息。`WriteHeader` 方法将头部信息写入归档，然后 `io.Copy` 将文件内容写入。最后，`Close` 方法完成归档。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。`archive/tar` 包是提供 tar 文件读写功能的库，具体的命令行参数处理通常由使用该库的应用程序来完成。

例如，一个命令行 tar 工具可能会使用 `flag` 包来解析命令行参数，如 `-c` (创建归档), `-f` (指定归档文件名), 以及要添加到归档的文件列表。然后，它会使用 `archive/tar` 包的 `Writer` 来实现创建归档的功能。

**使用者易犯错的点：**

1. **在调用 `WriteHeader` 之前调用 `Write`:**  必须先调用 `WriteHeader` 来声明要写入的文件及其元数据，然后才能使用 `Write` 写入文件内容。

   ```go
   // 错误示例
   tw := tar.NewWriter(file)
   _, err = tw.Write([]byte("some data")) // 错误！必须先 WriteHeader
   if err != nil {
       panic(err)
   }
   ```

2. **写入的数据量超过 `Header.Size`:** 在 `WriteHeader` 中指定的 `Header.Size` 决定了可以写入的字节数。如果 `Write` 写入的数据超过了这个大小，会返回 `ErrWriteTooLong` 错误。

   ```go
   header := &tar.Header{
       Name: "smallfile.txt",
       Size: 10, // 声明文件大小为 10 字节
       Mode: 0600,
       ModTime: time.Now(),
   }
   tw.WriteHeader(header)
   _, err = tw.Write([]byte("This is more than 10 bytes")) // 错误！
   if err != nil {
       fmt.Println(err) // 输出：archive/tar: write too long
   }
   ```

3. **没有正确关闭 `Writer`:**  忘记调用 `tw.Close()` 会导致 tar 归档没有正确结束，可能导致归档文件不完整或无法读取。

4. **`Header` 中的文件名或路径不正确:**  确保 `Header.Name` 设置为正确的文件名和路径，特别是当创建包含子目录的归档时。

这段代码的核心职责是提供创建 tar 归档的能力，使用者需要理解 tar 文件的结构和 `tar.Header` 的作用才能正确使用它。

Prompt: 
```
这是路径为go/src/archive/tar/writer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tar

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"time"
)

// Writer provides sequential writing of a tar archive.
// [Writer.WriteHeader] begins a new file with the provided [Header],
// and then Writer can be treated as an io.Writer to supply that file's data.
type Writer struct {
	w    io.Writer
	pad  int64      // Amount of padding to write after current file entry
	curr fileWriter // Writer for current file entry
	hdr  Header     // Shallow copy of Header that is safe for mutations
	blk  block      // Buffer to use as temporary local storage

	// err is a persistent error.
	// It is only the responsibility of every exported method of Writer to
	// ensure that this error is sticky.
	err error
}

// NewWriter creates a new Writer writing to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w, curr: &regFileWriter{w, 0}}
}

type fileWriter interface {
	io.Writer
	fileState

	ReadFrom(io.Reader) (int64, error)
}

// Flush finishes writing the current file's block padding.
// The current file must be fully written before Flush can be called.
//
// This is unnecessary as the next call to [Writer.WriteHeader] or [Writer.Close]
// will implicitly flush out the file's padding.
func (tw *Writer) Flush() error {
	if tw.err != nil {
		return tw.err
	}
	if nb := tw.curr.logicalRemaining(); nb > 0 {
		return fmt.Errorf("archive/tar: missed writing %d bytes", nb)
	}
	if _, tw.err = tw.w.Write(zeroBlock[:tw.pad]); tw.err != nil {
		return tw.err
	}
	tw.pad = 0
	return nil
}

// WriteHeader writes hdr and prepares to accept the file's contents.
// The Header.Size determines how many bytes can be written for the next file.
// If the current file is not fully written, then this returns an error.
// This implicitly flushes any padding necessary before writing the header.
func (tw *Writer) WriteHeader(hdr *Header) error {
	if err := tw.Flush(); err != nil {
		return err
	}
	tw.hdr = *hdr // Shallow copy of Header

	// Avoid usage of the legacy TypeRegA flag, and automatically promote
	// it to use TypeReg or TypeDir.
	if tw.hdr.Typeflag == TypeRegA {
		if strings.HasSuffix(tw.hdr.Name, "/") {
			tw.hdr.Typeflag = TypeDir
		} else {
			tw.hdr.Typeflag = TypeReg
		}
	}

	// Round ModTime and ignore AccessTime and ChangeTime unless
	// the format is explicitly chosen.
	// This ensures nominal usage of WriteHeader (without specifying the format)
	// does not always result in the PAX format being chosen, which
	// causes a 1KiB increase to every header.
	if tw.hdr.Format == FormatUnknown {
		tw.hdr.ModTime = tw.hdr.ModTime.Round(time.Second)
		tw.hdr.AccessTime = time.Time{}
		tw.hdr.ChangeTime = time.Time{}
	}

	allowedFormats, paxHdrs, err := tw.hdr.allowedFormats()
	switch {
	case allowedFormats.has(FormatUSTAR):
		tw.err = tw.writeUSTARHeader(&tw.hdr)
		return tw.err
	case allowedFormats.has(FormatPAX):
		tw.err = tw.writePAXHeader(&tw.hdr, paxHdrs)
		return tw.err
	case allowedFormats.has(FormatGNU):
		tw.err = tw.writeGNUHeader(&tw.hdr)
		return tw.err
	default:
		return err // Non-fatal error
	}
}

func (tw *Writer) writeUSTARHeader(hdr *Header) error {
	// Check if we can use USTAR prefix/suffix splitting.
	var namePrefix string
	if prefix, suffix, ok := splitUSTARPath(hdr.Name); ok {
		namePrefix, hdr.Name = prefix, suffix
	}

	// Pack the main header.
	var f formatter
	blk := tw.templateV7Plus(hdr, f.formatString, f.formatOctal)
	f.formatString(blk.toUSTAR().prefix(), namePrefix)
	blk.setFormat(FormatUSTAR)
	if f.err != nil {
		return f.err // Should never happen since header is validated
	}
	return tw.writeRawHeader(blk, hdr.Size, hdr.Typeflag)
}

func (tw *Writer) writePAXHeader(hdr *Header, paxHdrs map[string]string) error {
	realName, realSize := hdr.Name, hdr.Size

	// TODO(dsnet): Re-enable this when adding sparse support.
	// See https://golang.org/issue/22735
	/*
		// Handle sparse files.
		var spd sparseDatas
		var spb []byte
		if len(hdr.SparseHoles) > 0 {
			sph := append([]sparseEntry{}, hdr.SparseHoles...) // Copy sparse map
			sph = alignSparseEntries(sph, hdr.Size)
			spd = invertSparseEntries(sph, hdr.Size)

			// Format the sparse map.
			hdr.Size = 0 // Replace with encoded size
			spb = append(strconv.AppendInt(spb, int64(len(spd)), 10), '\n')
			for _, s := range spd {
				hdr.Size += s.Length
				spb = append(strconv.AppendInt(spb, s.Offset, 10), '\n')
				spb = append(strconv.AppendInt(spb, s.Length, 10), '\n')
			}
			pad := blockPadding(int64(len(spb)))
			spb = append(spb, zeroBlock[:pad]...)
			hdr.Size += int64(len(spb)) // Accounts for encoded sparse map

			// Add and modify appropriate PAX records.
			dir, file := path.Split(realName)
			hdr.Name = path.Join(dir, "GNUSparseFile.0", file)
			paxHdrs[paxGNUSparseMajor] = "1"
			paxHdrs[paxGNUSparseMinor] = "0"
			paxHdrs[paxGNUSparseName] = realName
			paxHdrs[paxGNUSparseRealSize] = strconv.FormatInt(realSize, 10)
			paxHdrs[paxSize] = strconv.FormatInt(hdr.Size, 10)
			delete(paxHdrs, paxPath) // Recorded by paxGNUSparseName
		}
	*/
	_ = realSize

	// Write PAX records to the output.
	isGlobal := hdr.Typeflag == TypeXGlobalHeader
	if len(paxHdrs) > 0 || isGlobal {
		// Write each record to a buffer.
		var buf strings.Builder
		// Sort keys for deterministic ordering.
		for _, k := range slices.Sorted(maps.Keys(paxHdrs)) {
			rec, err := formatPAXRecord(k, paxHdrs[k])
			if err != nil {
				return err
			}
			buf.WriteString(rec)
		}

		// Write the extended header file.
		var name string
		var flag byte
		if isGlobal {
			name = realName
			if name == "" {
				name = "GlobalHead.0.0"
			}
			flag = TypeXGlobalHeader
		} else {
			dir, file := path.Split(realName)
			name = path.Join(dir, "PaxHeaders.0", file)
			flag = TypeXHeader
		}
		data := buf.String()
		if len(data) > maxSpecialFileSize {
			return ErrFieldTooLong
		}
		if err := tw.writeRawFile(name, data, flag, FormatPAX); err != nil || isGlobal {
			return err // Global headers return here
		}
	}

	// Pack the main header.
	var f formatter // Ignore errors since they are expected
	fmtStr := func(b []byte, s string) { f.formatString(b, toASCII(s)) }
	blk := tw.templateV7Plus(hdr, fmtStr, f.formatOctal)
	blk.setFormat(FormatPAX)
	if err := tw.writeRawHeader(blk, hdr.Size, hdr.Typeflag); err != nil {
		return err
	}

	// TODO(dsnet): Re-enable this when adding sparse support.
	// See https://golang.org/issue/22735
	/*
		// Write the sparse map and setup the sparse writer if necessary.
		if len(spd) > 0 {
			// Use tw.curr since the sparse map is accounted for in hdr.Size.
			if _, err := tw.curr.Write(spb); err != nil {
				return err
			}
			tw.curr = &sparseFileWriter{tw.curr, spd, 0}
		}
	*/
	return nil
}

func (tw *Writer) writeGNUHeader(hdr *Header) error {
	// Use long-link files if Name or Linkname exceeds the field size.
	const longName = "././@LongLink"
	if len(hdr.Name) > nameSize {
		data := hdr.Name + "\x00"
		if err := tw.writeRawFile(longName, data, TypeGNULongName, FormatGNU); err != nil {
			return err
		}
	}
	if len(hdr.Linkname) > nameSize {
		data := hdr.Linkname + "\x00"
		if err := tw.writeRawFile(longName, data, TypeGNULongLink, FormatGNU); err != nil {
			return err
		}
	}

	// Pack the main header.
	var f formatter // Ignore errors since they are expected
	var spd sparseDatas
	var spb []byte
	blk := tw.templateV7Plus(hdr, f.formatString, f.formatNumeric)
	if !hdr.AccessTime.IsZero() {
		f.formatNumeric(blk.toGNU().accessTime(), hdr.AccessTime.Unix())
	}
	if !hdr.ChangeTime.IsZero() {
		f.formatNumeric(blk.toGNU().changeTime(), hdr.ChangeTime.Unix())
	}
	// TODO(dsnet): Re-enable this when adding sparse support.
	// See https://golang.org/issue/22735
	/*
		if hdr.Typeflag == TypeGNUSparse {
			sph := append([]sparseEntry{}, hdr.SparseHoles...) // Copy sparse map
			sph = alignSparseEntries(sph, hdr.Size)
			spd = invertSparseEntries(sph, hdr.Size)

			// Format the sparse map.
			formatSPD := func(sp sparseDatas, sa sparseArray) sparseDatas {
				for i := 0; len(sp) > 0 && i < sa.MaxEntries(); i++ {
					f.formatNumeric(sa.Entry(i).Offset(), sp[0].Offset)
					f.formatNumeric(sa.Entry(i).Length(), sp[0].Length)
					sp = sp[1:]
				}
				if len(sp) > 0 {
					sa.IsExtended()[0] = 1
				}
				return sp
			}
			sp2 := formatSPD(spd, blk.GNU().Sparse())
			for len(sp2) > 0 {
				var spHdr block
				sp2 = formatSPD(sp2, spHdr.Sparse())
				spb = append(spb, spHdr[:]...)
			}

			// Update size fields in the header block.
			realSize := hdr.Size
			hdr.Size = 0 // Encoded size; does not account for encoded sparse map
			for _, s := range spd {
				hdr.Size += s.Length
			}
			copy(blk.V7().Size(), zeroBlock[:]) // Reset field
			f.formatNumeric(blk.V7().Size(), hdr.Size)
			f.formatNumeric(blk.GNU().RealSize(), realSize)
		}
	*/
	blk.setFormat(FormatGNU)
	if err := tw.writeRawHeader(blk, hdr.Size, hdr.Typeflag); err != nil {
		return err
	}

	// Write the extended sparse map and setup the sparse writer if necessary.
	if len(spd) > 0 {
		// Use tw.w since the sparse map is not accounted for in hdr.Size.
		if _, err := tw.w.Write(spb); err != nil {
			return err
		}
		tw.curr = &sparseFileWriter{tw.curr, spd, 0}
	}
	return nil
}

type (
	stringFormatter func([]byte, string)
	numberFormatter func([]byte, int64)
)

// templateV7Plus fills out the V7 fields of a block using values from hdr.
// It also fills out fields (uname, gname, devmajor, devminor) that are
// shared in the USTAR, PAX, and GNU formats using the provided formatters.
//
// The block returned is only valid until the next call to
// templateV7Plus or writeRawFile.
func (tw *Writer) templateV7Plus(hdr *Header, fmtStr stringFormatter, fmtNum numberFormatter) *block {
	tw.blk.reset()

	modTime := hdr.ModTime
	if modTime.IsZero() {
		modTime = time.Unix(0, 0)
	}

	v7 := tw.blk.toV7()
	v7.typeFlag()[0] = hdr.Typeflag
	fmtStr(v7.name(), hdr.Name)
	fmtStr(v7.linkName(), hdr.Linkname)
	fmtNum(v7.mode(), hdr.Mode)
	fmtNum(v7.uid(), int64(hdr.Uid))
	fmtNum(v7.gid(), int64(hdr.Gid))
	fmtNum(v7.size(), hdr.Size)
	fmtNum(v7.modTime(), modTime.Unix())

	ustar := tw.blk.toUSTAR()
	fmtStr(ustar.userName(), hdr.Uname)
	fmtStr(ustar.groupName(), hdr.Gname)
	fmtNum(ustar.devMajor(), hdr.Devmajor)
	fmtNum(ustar.devMinor(), hdr.Devminor)

	return &tw.blk
}

// writeRawFile writes a minimal file with the given name and flag type.
// It uses format to encode the header format and will write data as the body.
// It uses default values for all of the other fields (as BSD and GNU tar does).
func (tw *Writer) writeRawFile(name, data string, flag byte, format Format) error {
	tw.blk.reset()

	// Best effort for the filename.
	name = toASCII(name)
	if len(name) > nameSize {
		name = name[:nameSize]
	}
	name = strings.TrimRight(name, "/")

	var f formatter
	v7 := tw.blk.toV7()
	v7.typeFlag()[0] = flag
	f.formatString(v7.name(), name)
	f.formatOctal(v7.mode(), 0)
	f.formatOctal(v7.uid(), 0)
	f.formatOctal(v7.gid(), 0)
	f.formatOctal(v7.size(), int64(len(data))) // Must be < 8GiB
	f.formatOctal(v7.modTime(), 0)
	tw.blk.setFormat(format)
	if f.err != nil {
		return f.err // Only occurs if size condition is violated
	}

	// Write the header and data.
	if err := tw.writeRawHeader(&tw.blk, int64(len(data)), flag); err != nil {
		return err
	}
	_, err := io.WriteString(tw, data)
	return err
}

// writeRawHeader writes the value of blk, regardless of its value.
// It sets up the Writer such that it can accept a file of the given size.
// If the flag is a special header-only flag, then the size is treated as zero.
func (tw *Writer) writeRawHeader(blk *block, size int64, flag byte) error {
	if err := tw.Flush(); err != nil {
		return err
	}
	if _, err := tw.w.Write(blk[:]); err != nil {
		return err
	}
	if isHeaderOnlyType(flag) {
		size = 0
	}
	tw.curr = &regFileWriter{tw.w, size}
	tw.pad = blockPadding(size)
	return nil
}

// AddFS adds the files from fs.FS to the archive.
// It walks the directory tree starting at the root of the filesystem
// adding each file to the tar archive while maintaining the directory structure.
func (tw *Writer) AddFS(fsys fs.FS) error {
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
		// TODO(#49580): Handle symlinks when fs.ReadLinkFS is available.
		if !d.IsDir() && !info.Mode().IsRegular() {
			return errors.New("tar: cannot add non-regular file")
		}
		h, err := FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = name
		if err := tw.WriteHeader(h); err != nil {
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
		_, err = io.Copy(tw, f)
		return err
	})
}

// splitUSTARPath splits a path according to USTAR prefix and suffix rules.
// If the path is not splittable, then it will return ("", "", false).
func splitUSTARPath(name string) (prefix, suffix string, ok bool) {
	length := len(name)
	if length <= nameSize || !isASCII(name) {
		return "", "", false
	} else if length > prefixSize+1 {
		length = prefixSize + 1
	} else if name[length-1] == '/' {
		length--
	}

	i := strings.LastIndex(name[:length], "/")
	nlen := len(name) - i - 1 // nlen is length of suffix
	plen := i                 // plen is length of prefix
	if i <= 0 || nlen > nameSize || nlen == 0 || plen > prefixSize {
		return "", "", false
	}
	return name[:i], name[i+1:], true
}

// Write writes to the current file in the tar archive.
// Write returns the error [ErrWriteTooLong] if more than
// Header.Size bytes are written after [Writer.WriteHeader].
//
// Calling Write on special types like [TypeLink], [TypeSymlink], [TypeChar],
// [TypeBlock], [TypeDir], and [TypeFifo] returns (0, [ErrWriteTooLong]) regardless
// of what the [Header.Size] claims.
func (tw *Writer) Write(b []byte) (int, error) {
	if tw.err != nil {
		return 0, tw.err
	}
	n, err := tw.curr.Write(b)
	if err != nil && err != ErrWriteTooLong {
		tw.err = err
	}
	return n, err
}

// readFrom populates the content of the current file by reading from r.
// The bytes read must match the number of remaining bytes in the current file.
//
// If the current file is sparse and r is an io.ReadSeeker,
// then readFrom uses Seek to skip past holes defined in Header.SparseHoles,
// assuming that skipped regions are all NULs.
// This always reads the last byte to ensure r is the right size.
//
// TODO(dsnet): Re-export this when adding sparse file support.
// See https://golang.org/issue/22735
func (tw *Writer) readFrom(r io.Reader) (int64, error) {
	if tw.err != nil {
		return 0, tw.err
	}
	n, err := tw.curr.ReadFrom(r)
	if err != nil && err != ErrWriteTooLong {
		tw.err = err
	}
	return n, err
}

// Close closes the tar archive by flushing the padding, and writing the footer.
// If the current file (from a prior call to [Writer.WriteHeader]) is not fully written,
// then this returns an error.
func (tw *Writer) Close() error {
	if tw.err == ErrWriteAfterClose {
		return nil
	}
	if tw.err != nil {
		return tw.err
	}

	// Trailer: two zero blocks.
	err := tw.Flush()
	for i := 0; i < 2 && err == nil; i++ {
		_, err = tw.w.Write(zeroBlock[:])
	}

	// Ensure all future actions are invalid.
	tw.err = ErrWriteAfterClose
	return err // Report IO errors
}

// regFileWriter is a fileWriter for writing data to a regular file entry.
type regFileWriter struct {
	w  io.Writer // Underlying Writer
	nb int64     // Number of remaining bytes to write
}

func (fw *regFileWriter) Write(b []byte) (n int, err error) {
	overwrite := int64(len(b)) > fw.nb
	if overwrite {
		b = b[:fw.nb]
	}
	if len(b) > 0 {
		n, err = fw.w.Write(b)
		fw.nb -= int64(n)
	}
	switch {
	case err != nil:
		return n, err
	case overwrite:
		return n, ErrWriteTooLong
	default:
		return n, nil
	}
}

func (fw *regFileWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{fw}, r)
}

// logicalRemaining implements fileState.logicalRemaining.
func (fw regFileWriter) logicalRemaining() int64 {
	return fw.nb
}

// physicalRemaining implements fileState.physicalRemaining.
func (fw regFileWriter) physicalRemaining() int64 {
	return fw.nb
}

// sparseFileWriter is a fileWriter for writing data to a sparse file entry.
type sparseFileWriter struct {
	fw  fileWriter  // Underlying fileWriter
	sp  sparseDatas // Normalized list of data fragments
	pos int64       // Current position in sparse file
}

func (sw *sparseFileWriter) Write(b []byte) (n int, err error) {
	overwrite := int64(len(b)) > sw.logicalRemaining()
	if overwrite {
		b = b[:sw.logicalRemaining()]
	}

	b0 := b
	endPos := sw.pos + int64(len(b))
	for endPos > sw.pos && err == nil {
		var nf int // Bytes written in fragment
		dataStart, dataEnd := sw.sp[0].Offset, sw.sp[0].endOffset()
		if sw.pos < dataStart { // In a hole fragment
			bf := b[:min(int64(len(b)), dataStart-sw.pos)]
			nf, err = zeroWriter{}.Write(bf)
		} else { // In a data fragment
			bf := b[:min(int64(len(b)), dataEnd-sw.pos)]
			nf, err = sw.fw.Write(bf)
		}
		b = b[nf:]
		sw.pos += int64(nf)
		if sw.pos >= dataEnd && len(sw.sp) > 1 {
			sw.sp = sw.sp[1:] // Ensure last fragment always remains
		}
	}

	n = len(b0) - len(b)
	switch {
	case err == ErrWriteTooLong:
		return n, errMissData // Not possible; implies bug in validation logic
	case err != nil:
		return n, err
	case sw.logicalRemaining() == 0 && sw.physicalRemaining() > 0:
		return n, errUnrefData // Not possible; implies bug in validation logic
	case overwrite:
		return n, ErrWriteTooLong
	default:
		return n, nil
	}
}

func (sw *sparseFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
	rs, ok := r.(io.ReadSeeker)
	if ok {
		if _, err := rs.Seek(0, io.SeekCurrent); err != nil {
			ok = false // Not all io.Seeker can really seek
		}
	}
	if !ok {
		return io.Copy(struct{ io.Writer }{sw}, r)
	}

	var readLastByte bool
	pos0 := sw.pos
	for sw.logicalRemaining() > 0 && !readLastByte && err == nil {
		var nf int64 // Size of fragment
		dataStart, dataEnd := sw.sp[0].Offset, sw.sp[0].endOffset()
		if sw.pos < dataStart { // In a hole fragment
			nf = dataStart - sw.pos
			if sw.physicalRemaining() == 0 {
				readLastByte = true
				nf--
			}
			_, err = rs.Seek(nf, io.SeekCurrent)
		} else { // In a data fragment
			nf = dataEnd - sw.pos
			nf, err = io.CopyN(sw.fw, rs, nf)
		}
		sw.pos += nf
		if sw.pos >= dataEnd && len(sw.sp) > 1 {
			sw.sp = sw.sp[1:] // Ensure last fragment always remains
		}
	}

	// If the last fragment is a hole, then seek to 1-byte before EOF, and
	// read a single byte to ensure the file is the right size.
	if readLastByte && err == nil {
		_, err = mustReadFull(rs, []byte{0})
		sw.pos++
	}

	n = sw.pos - pos0
	switch {
	case err == io.EOF:
		return n, io.ErrUnexpectedEOF
	case err == ErrWriteTooLong:
		return n, errMissData // Not possible; implies bug in validation logic
	case err != nil:
		return n, err
	case sw.logicalRemaining() == 0 && sw.physicalRemaining() > 0:
		return n, errUnrefData // Not possible; implies bug in validation logic
	default:
		return n, ensureEOF(rs)
	}
}

func (sw sparseFileWriter) logicalRemaining() int64 {
	return sw.sp[len(sw.sp)-1].endOffset() - sw.pos
}

func (sw sparseFileWriter) physicalRemaining() int64 {
	return sw.fw.physicalRemaining()
}

// zeroWriter may only be written with NULs, otherwise it returns errWriteHole.
type zeroWriter struct{}

func (zeroWriter) Write(b []byte) (int, error) {
	for i, c := range b {
		if c != 0 {
			return i, errWriteHole
		}
	}
	return len(b), nil
}

// ensureEOF checks whether r is at EOF, reporting ErrWriteTooLong if not so.
func ensureEOF(r io.Reader) error {
	n, err := tryReadFull(r, []byte{0})
	switch {
	case n > 0:
		return ErrWriteTooLong
	case err == io.EOF:
		return nil
	default:
		return err
	}
}

"""



```