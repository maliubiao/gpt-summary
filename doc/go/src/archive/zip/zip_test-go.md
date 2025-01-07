Response:
Let's break down the thought process for analyzing the Go `zip_test.go` file.

1. **Understand the Goal:** The core request is to understand the *functionality* of the provided Go code snippet. Specifically, it's a test file (`_test.go`). This immediately suggests the primary purpose is testing the `archive/zip` package.

2. **Initial Scan for Keywords and Structure:** I'll quickly scan the code for common testing patterns and relevant keywords.

    * **`package zip`:**  Confirms it's testing the `zip` package.
    * **`import (...)`:** Lists the imported packages. `testing` is the key one for understanding testing functions. Other imports like `bytes`, `strings`, `io`, `time` give hints about the types of operations being tested (byte manipulation, string handling, input/output, time handling). `internal/testenv` suggests environment-specific tests.
    * **`func Test...`:**  Identifies test functions. Each `Test...` function name usually indicates a specific aspect being tested.
    * **`t *testing.T`:** The standard argument for test functions, allowing for error reporting.
    * **`NewWriter`, `NewReader`, `CreateHeader`, `FileHeader`:** These are core types and functions from the `archive/zip` package itself. They are key to understanding the interactions being tested.
    * **Constants like `Store`, `Deflate`:** These suggest testing different compression methods.

3. **Categorize the Tests:**  As I scan the `Test...` functions, I start grouping them by the functionality they seem to be targeting:

    * **Basic File Handling:** `TestOver65kFiles` (testing large number of files), `TestModTime` (testing modification time).
    * **Header Manipulation:** `TestFileHeaderRoundTrip`, `TestFileHeaderRoundTrip64`, `TestFileHeaderRoundTripModified`, `TestFileHeaderRoundTripWithoutModified` (testing different aspects of `FileHeader`). The "RoundTrip" pattern often indicates testing serialization/deserialization or data integrity after operations.
    * **Zip64 Specifics:**  `TestZip64`, `TestZip64EdgeCase`, `TestZip64DirectoryOffset`, `TestZip64ManyRecords`, `TestZip64LargeDirectory`, `testZip64DirectoryRecordLength` (clearly focused on handling large zip files and the Zip64 extension).
    * **Error Handling/Invalid Input:** `TestHeaderInvalidTagAndSize`, `TestHeaderTooShort`, `TestHeaderTooLongErr`, `TestHeaderIgnoredSize`.
    * **Special Cases:** `TestZeroLengthHeader`.
    * **Benchmarking:** `BenchmarkZip64Test`, `BenchmarkZip64TestSizes` (measuring performance).
    * **Helper Functions/Data Structures:**  `rleBuffer`, `TestRLEBuffer`, `suffixSaver`, `generatesZip64`, `suffixIsZip64` (these aren't directly testing `archive/zip` features, but are utilities used *in* the tests).

4. **Analyze Individual Test Functions (Deep Dive):**  For each category, I examine a few representative tests in more detail:

    * **`TestOver65kFiles`:**  Clearly tests the ability to create and read zip files with more than 65,535 files (the limit for standard ZIP). It uses `CreateHeader` in a loop and then reads the archive.
    * **`TestModTime`:**  Simple test for setting and getting the modification time using `SetModTime` and `ModTime`.
    * **`TestFileHeaderRoundTrip`:** Shows how a `FileHeader` can be created, its `FileInfo()` obtained, and then a new `FileHeader` created *from* that `FileInfo` using `FileInfoHeader`. It verifies the values are preserved. This tests the consistency of information across different ways of representing file metadata.
    * **`TestZip64`:** Demonstrates creating a very large zip file (`1 << 32` bytes) and checking if it can be read back correctly, especially looking at the `UncompressedSize` and `UncompressedSize64` fields. The helper function `testZip64` is used.
    * **`TestHeaderTooLongErr`:** Illustrates how the writer handles overly long filenames and extra data, expecting specific errors (`errLongName`, `errLongExtra`).

5. **Infer Go Feature Implementation:** Based on the tests, I can infer which Go language features are being implemented by the `archive/zip` package:

    * **Creating ZIP Archives:**  `NewWriter`, `CreateHeader`, `Write`, `Close`.
    * **Reading ZIP Archives:** `NewReader`, accessing `File` slice, `Open` on a `File`, reading from the `io.ReadCloser`.
    * **Handling File Metadata:**  `FileHeader` struct, `SetModTime`, `ModTime`, `FileInfo`, `FileInfoHeader`.
    * **Compression:** Implicitly through `Method` field with values like `Store` and `Deflate`.
    * **Zip64 Support:**  Explicitly tested by many `TestZip64...` functions, indicating handling of large files and archives that exceed the limitations of the original ZIP format.

6. **Code Examples (Illustrative):** I'll create simple, focused code examples to demonstrate the key functionalities, drawing directly from the test cases. For instance, the file creation and reading example is a direct simplification of the patterns seen in tests like `TestOver65kFiles`.

7. **Command-line Arguments:**  I'll carefully review the code for any interactions with command-line flags. In this case, `testing.Short()` and `testenv.Builder()` are used to control test execution based on the testing environment, but there's no direct interaction with user-provided command-line arguments for the *zip package itself*. Therefore, I'll focus on explaining these testing flags.

8. **Common Mistakes:** I'll think about common pitfalls when working with ZIP archives, particularly in Go. For instance, not closing the `Writer` or the `io.ReadCloser` obtained from `Open()` is a frequent error leading to incomplete or corrupted archives. Incorrectly handling file paths or permissions could also be mentioned.

9. **Structure and Refine:**  Finally, I'll organize the information clearly using headings, bullet points, and code blocks. I'll ensure the language is precise and easy to understand, avoiding jargon where possible. I'll double-check that I've addressed all parts of the original request. For example, ensuring I have provided code examples, explained any relevant command-line arguments (even if they are test-related), and highlighted potential user errors.
这段代码是Go语言标准库 `archive/zip` 包的一部分，专门用于 **测试该 zip 包的读取和写入功能**。它包含了一系列测试函数，用来验证 zip 包的各种特性是否按预期工作。

下面我将详细列举其功能，并用 Go 代码举例说明：

**主要功能点:**

1. **测试创建包含大量文件的 ZIP 压缩包:**
   - `TestOver65kFiles` 函数测试了创建包含超过 65535 个文件的 zip 压缩包的功能。这是为了验证 zip64 扩展的正确性，因为标准的 zip 格式对文件数量有限制。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "archive/zip"
         "fmt"
         "log"
         "os"
         "strings"
     )

     func main() {
         buf := new(strings.Builder)
         w := zip.NewWriter(buf)
         const nFiles = (1 << 16) + 42 // 65535 + 42

         for i := 0; i < nFiles; i++ {
             header := &zip.FileHeader{
                 Name:   fmt.Sprintf("%d.txt", i),
                 Method: zip.Store, // 不压缩，加速测试
             }
             _, err := w.CreateHeader(header)
             if err != nil {
                 log.Fatalf("创建文件 %d 失败: %v", i, err)
             }
         }

         if err := w.Close(); err != nil {
             log.Fatalf("关闭 Writer 失败: %v", err)
         }

         // 验证创建的 zip 内容 (这里只是简单打印长度)
         fmt.Printf("创建的 ZIP 文件大小: %d\n", buf.Len())
     }
     ```
     - **假设输入:** 无，代码内部生成文件名。
     - **预期输出:**  创建的 ZIP 文件大小，且不应报错。

2. **测试文件修改时间 (Modification Time) 的处理:**
   - `TestModTime` 函数测试了 `FileHeader` 结构体的 `SetModTime` 和 `ModTime` 方法，确保设置和获取的文件修改时间一致。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "archive/zip"
         "fmt"
         "time"
     )

     func main() {
         testTime := time.Date(2023, 10, 27, 10, 30, 0, 0, time.UTC)
         fh := new(zip.FileHeader)
         fh.SetModTime(testTime)
         outTime := fh.ModTime()

         if !outTime.Equal(testTime) {
             fmt.Printf("修改时间不匹配: 期望 %s, 实际 %s\n", testTime, outTime)
         } else {
             fmt.Println("修改时间测试通过")
         }
     }
     ```
     - **假设输入:**  预定义的 `testTime`。
     - **预期输出:** "修改时间测试通过"。

3. **测试 `FileHeader` 信息的完整性 (Round Trip):**
   - `TestFileHeaderRoundTrip`, `TestFileHeaderRoundTrip64`, `TestFileHeaderRoundTripModified`, `TestFileHeaderRoundTripWithoutModified` 等函数测试了 `FileHeader` 结构体在经过 `FileInfo()` 和 `FileInfoHeader()` 方法转换后，关键信息（如文件名、未压缩大小、修改时间等）是否保持不变。这验证了元数据处理的正确性。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "archive/zip"
         "fmt"
         "os"
         "time"
     )

     func main() {
         originalFH := &zip.FileHeader{
             Name:             "test.txt",
             UncompressedSize: 12345,
             Modified:         time.Now(),
         }

         fileInfo := originalFH.FileInfo()
         newFH, err := zip.FileInfoHeader(fileInfo)
         if err != nil {
             fmt.Println("获取 FileInfoHeader 失败:", err)
             return
         }

         if originalFH.Name != newFH.Name || originalFH.UncompressedSize != newFH.UncompressedSize {
             fmt.Println("FileInfoHeader 转换后信息不一致")
         } else {
             fmt.Println("FileInfoHeader 转换测试通过")
         }
     }
     ```
     - **假设输入:**  初始化的 `FileHeader`。
     - **预期输出:** "FileInfoHeader 转换测试通过"。

4. **测试 Zip64 扩展功能:**
   - `TestZip64`, `TestZip64EdgeCase`, `TestZip64DirectoryOffset`, `TestZip64ManyRecords`, `TestZip64LargeDirectory`, `testZip64DirectoryRecordLength` 等一系列函数专门测试了对大型文件（超过 4GB）或包含大量条目的 zip 压缩包的处理，这需要用到 Zip64 扩展。这些测试验证了在各种需要使用 Zip64 的场景下，`archive/zip` 包能否正确生成和解析 zip 文件。
   - 这些测试通常会创建超过 4GB 的文件或者包含大量文件的 zip 包，并检查生成的 zip 文件结构是否符合 Zip64 规范。

5. **测试处理损坏或不符合规范的 Header 信息:**
   - `TestHeaderInvalidTagAndSize`, `TestHeaderTooShort`, `TestHeaderTooLongErr`, `TestHeaderIgnoredSize` 等函数测试了当 zip 文件的 Header 信息不完整、包含无效标签或长度超出限制时，`archive/zip` 包的健壮性，看是否能够正确处理或返回错误。

6. **性能基准测试:**
   - `BenchmarkZip64Test`, `BenchmarkZip64TestSizes` 是性能基准测试，用于衡量创建大型 zip 文件的性能。这些测试不会直接验证功能，而是评估代码的运行效率。

**代码推理与示例 (以 `TestZip64` 为例):**

- **假设输入:**  `size` 变量指定创建的虚拟文件大小 (例如 `1 << 32` 字节，即 4GB)。
- **内部流程:**
    1. 创建一个 `rleBuffer` 作为内存中的 zip 文件缓冲区。
    2. 使用 `NewWriter` 创建 zip writer。
    3. 使用 `CreateHeader` 创建一个名为 "huge.txt" 的文件条目，并设置为不压缩 (`Store`)。
    4. 循环写入指定大小的数据到该文件条目。
    5. 写入 "END\n" 字符串。
    6. 关闭 zip writer。
    7. 使用 `NewReader` 从缓冲区读取 zip 文件。
    8. 打开读取到的文件条目。
    9. 循环读取文件内容，并与预期大小进行比较。
    10. 检查 `FileHeader` 中的 `UncompressedSize` 和 `UncompressedSize64` 字段是否正确反映了文件大小（对于超过 4GB 的文件，`UncompressedSize` 应该为 `uint32max`，而 `UncompressedSize64` 应该为实际大小）。
- **预期输出:**  测试通过，不会有 `t.Fatal` 或 `t.Errorf` 输出。

**命令行参数的具体处理:**

这段测试代码本身并不直接处理用户提供的命令行参数。Go 的测试框架 `testing` 提供了一些标准命令行参数来控制测试行为，例如：

- `-test.short`:  运行短测试，跳过耗时的测试（代码中 `if testing.Short() { t.Skip(...) }` 就使用了这个）。
- `-test.v`:  显示更详细的测试输出。
- `-test.run <regexp>`:  只运行匹配正则表达式的测试函数。
- `-test.bench <regexp>`:  只运行匹配正则表达式的基准测试函数。

这些参数是在运行 `go test` 命令时使用的，例如：

```bash
go test -test.short ./archive/zip
go test -test.v -test.run TestZip64 ./archive/zip
go test -test.bench BenchmarkZip64Test ./archive/zip
```

**使用者易犯错的点 (基于测试内容推断):**

虽然这段代码是测试代码，但可以从中推断出使用 `archive/zip` 包时可能出现的错误：

1. **处理超过 4GB 的文件或大量文件时未考虑 Zip64:**  如果程序需要处理大型 zip 文件，必须确保 `archive/zip` 包能正确处理 Zip64 扩展，否则可能会导致数据丢失或无法读取。测试中的 `TestZip64` 系列就强调了这一点。
2. **修改文件后未正确更新 `FileHeader` 的元数据:** 例如，如果手动修改了文件的修改时间，需要确保 `FileHeader` 中的相关字段也同步更新，否则生成的 zip 文件元数据可能不正确。`TestModTime` 和 `TestFileHeaderRoundTrip` 等测试确保了元数据处理的正确性。
3. **假设 `FileInfoHeader` 返回的 `FileHeader` 与原始 `FileHeader` 完全相同:** 虽然大部分信息会保留，但某些情况下可能会有差异，例如 `Modified` 字段的处理。`TestFileHeaderRoundTripModified` 和 `TestFileHeaderRoundTripWithoutModified` 关注了这一点。
4. **未正确处理或验证 `Extra` 字段:**  `Extra` 字段用于存储额外的、标准 zip 格式未定义的元数据。如果应用程序依赖于特定的 `Extra` 字段，需要确保正确地写入和读取。测试中的 `TestHeaderInvalidTagAndSize` 等测试了对 `Extra` 字段的解析。
5. **在创建包含大量文件的 zip 包时，性能可能成为问题:**  `BenchmarkZip64Test` 表明创建大型 zip 文件可能需要较长时间。开发者需要根据实际情况考虑性能优化。
6. **依赖于特定的压缩方法而未进行兼容性处理:**  `Method` 字段指定了压缩方法 (例如 `Store` 或 `Deflate`)。接收 zip 文件的程序需要支持相应的解压方法。

总而言之，这段测试代码覆盖了 `archive/zip` 包在读取和写入 zip 文件时的各种场景，包括基本的文件操作、元数据处理、Zip64 扩展、错误处理以及性能测试。通过分析这些测试，可以更好地理解 `archive/zip` 包的功能和使用方式，并避免一些常见的错误。

Prompt: 
```
这是路径为go/src/archive/zip/zip_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests that involve both reading and writing.

package zip

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"hash"
	"internal/testenv"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOver65kFiles(t *testing.T) {
	if testing.Short() && testenv.Builder() == "" {
		t.Skip("skipping in short mode")
	}
	buf := new(strings.Builder)
	w := NewWriter(buf)
	const nFiles = (1 << 16) + 42
	for i := 0; i < nFiles; i++ {
		_, err := w.CreateHeader(&FileHeader{
			Name:   fmt.Sprintf("%d.dat", i),
			Method: Store, // Deflate is too slow when it is compiled with -race flag
		})
		if err != nil {
			t.Fatalf("creating file %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Writer.Close: %v", err)
	}
	s := buf.String()
	zr, err := NewReader(strings.NewReader(s), int64(len(s)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if got := len(zr.File); got != nFiles {
		t.Fatalf("File contains %d files, want %d", got, nFiles)
	}
	for i := 0; i < nFiles; i++ {
		want := fmt.Sprintf("%d.dat", i)
		if zr.File[i].Name != want {
			t.Fatalf("File(%d) = %q, want %q", i, zr.File[i].Name, want)
		}
	}
}

func TestModTime(t *testing.T) {
	var testTime = time.Date(2009, time.November, 10, 23, 45, 58, 0, time.UTC)
	fh := new(FileHeader)
	fh.SetModTime(testTime)
	outTime := fh.ModTime()
	if !outTime.Equal(testTime) {
		t.Errorf("times don't match: got %s, want %s", outTime, testTime)
	}
}

func testHeaderRoundTrip(fh *FileHeader, wantUncompressedSize uint32, wantUncompressedSize64 uint64, t *testing.T) {
	fi := fh.FileInfo()
	fh2, err := FileInfoHeader(fi)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fh2.Name, fh.Name; got != want {
		t.Errorf("Name: got %s, want %s\n", got, want)
	}
	if got, want := fh2.UncompressedSize, wantUncompressedSize; got != want {
		t.Errorf("UncompressedSize: got %d, want %d\n", got, want)
	}
	if got, want := fh2.UncompressedSize64, wantUncompressedSize64; got != want {
		t.Errorf("UncompressedSize64: got %d, want %d\n", got, want)
	}
	if got, want := fh2.ModifiedTime, fh.ModifiedTime; got != want {
		t.Errorf("ModifiedTime: got %d, want %d\n", got, want)
	}
	if got, want := fh2.ModifiedDate, fh.ModifiedDate; got != want {
		t.Errorf("ModifiedDate: got %d, want %d\n", got, want)
	}

	if sysfh, ok := fi.Sys().(*FileHeader); !ok && sysfh != fh {
		t.Errorf("Sys didn't return original *FileHeader")
	}
}

func TestFileHeaderRoundTrip(t *testing.T) {
	fh := &FileHeader{
		Name:             "foo.txt",
		UncompressedSize: 987654321,
		ModifiedTime:     1234,
		ModifiedDate:     5678,
	}
	testHeaderRoundTrip(fh, fh.UncompressedSize, uint64(fh.UncompressedSize), t)
}

func TestFileHeaderRoundTrip64(t *testing.T) {
	fh := &FileHeader{
		Name:               "foo.txt",
		UncompressedSize64: 9876543210,
		ModifiedTime:       1234,
		ModifiedDate:       5678,
	}
	testHeaderRoundTrip(fh, uint32max, fh.UncompressedSize64, t)
}

func TestFileHeaderRoundTripModified(t *testing.T) {
	fh := &FileHeader{
		Name:             "foo.txt",
		UncompressedSize: 987654321,
		Modified:         time.Now().Local(),
		ModifiedTime:     1234,
		ModifiedDate:     5678,
	}
	fi := fh.FileInfo()
	fh2, err := FileInfoHeader(fi)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fh2.Modified, fh.Modified.UTC(); got != want {
		t.Errorf("Modified: got %s, want %s\n", got, want)
	}
	if got, want := fi.ModTime(), fh.Modified.UTC(); got != want {
		t.Errorf("Modified: got %s, want %s\n", got, want)
	}
}

func TestFileHeaderRoundTripWithoutModified(t *testing.T) {
	fh := &FileHeader{
		Name:             "foo.txt",
		UncompressedSize: 987654321,
		ModifiedTime:     1234,
		ModifiedDate:     5678,
	}
	fi := fh.FileInfo()
	fh2, err := FileInfoHeader(fi)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fh2.ModTime(), fh.ModTime(); got != want {
		t.Errorf("Modified: got %s, want %s\n", got, want)
	}
	if got, want := fi.ModTime(), fh.ModTime(); got != want {
		t.Errorf("Modified: got %s, want %s\n", got, want)
	}
}

type repeatedByte struct {
	off int64
	b   byte
	n   int64
}

// rleBuffer is a run-length-encoded byte buffer.
// It's an io.Writer (like a bytes.Buffer) and also an io.ReaderAt,
// allowing random-access reads.
type rleBuffer struct {
	buf []repeatedByte
}

func (r *rleBuffer) Size() int64 {
	if len(r.buf) == 0 {
		return 0
	}
	last := &r.buf[len(r.buf)-1]
	return last.off + last.n
}

func (r *rleBuffer) Write(p []byte) (n int, err error) {
	var rp *repeatedByte
	if len(r.buf) > 0 {
		rp = &r.buf[len(r.buf)-1]
		// Fast path, if p is entirely the same byte repeated.
		if lastByte := rp.b; len(p) > 0 && p[0] == lastByte {
			if bytes.Count(p, []byte{lastByte}) == len(p) {
				rp.n += int64(len(p))
				return len(p), nil
			}
		}
	}

	for _, b := range p {
		if rp == nil || rp.b != b {
			r.buf = append(r.buf, repeatedByte{r.Size(), b, 1})
			rp = &r.buf[len(r.buf)-1]
		} else {
			rp.n++
		}
	}
	return len(p), nil
}

func memset(a []byte, b byte) {
	if len(a) == 0 {
		return
	}
	// Double, until we reach power of 2 >= len(a), same as bytes.Repeat,
	// but without allocation.
	a[0] = b
	for i, l := 1, len(a); i < l; i *= 2 {
		copy(a[i:], a[:i])
	}
}

func (r *rleBuffer) ReadAt(p []byte, off int64) (n int, err error) {
	if len(p) == 0 {
		return
	}
	skipParts, _ := slices.BinarySearchFunc(r.buf, off, func(rb repeatedByte, off int64) int {
		return cmp.Compare(rb.off+rb.n, off)
	})
	parts := r.buf[skipParts:]
	if len(parts) > 0 {
		skipBytes := off - parts[0].off
		for _, part := range parts {
			repeat := int(min(part.n-skipBytes, int64(len(p)-n)))
			memset(p[n:n+repeat], part.b)
			n += repeat
			if n == len(p) {
				return
			}
			skipBytes = 0
		}
	}
	if n != len(p) {
		err = io.ErrUnexpectedEOF
	}
	return
}

// Just testing the rleBuffer used in the Zip64 test above. Not used by the zip code.
func TestRLEBuffer(t *testing.T) {
	b := new(rleBuffer)
	var all []byte
	writes := []string{"abcdeee", "eeeeeee", "eeeefghaaiii"}
	for _, w := range writes {
		b.Write([]byte(w))
		all = append(all, w...)
	}
	if len(b.buf) != 10 {
		t.Fatalf("len(b.buf) = %d; want 10", len(b.buf))
	}

	for i := 0; i < len(all); i++ {
		for j := 0; j < len(all)-i; j++ {
			buf := make([]byte, j)
			n, err := b.ReadAt(buf, int64(i))
			if err != nil || n != len(buf) {
				t.Errorf("ReadAt(%d, %d) = %d, %v; want %d, nil", i, j, n, err, len(buf))
			}
			if !bytes.Equal(buf, all[i:i+j]) {
				t.Errorf("ReadAt(%d, %d) = %q; want %q", i, j, buf, all[i:i+j])
			}
		}
	}
}

// fakeHash32 is a dummy Hash32 that always returns 0.
type fakeHash32 struct {
	hash.Hash32
}

func (fakeHash32) Write(p []byte) (int, error) { return len(p), nil }
func (fakeHash32) Sum32() uint32               { return 0 }

func TestZip64(t *testing.T) {
	if testing.Short() {
		t.Skip("slow test; skipping")
	}
	t.Parallel()
	const size = 1 << 32 // before the "END\n" part
	buf := testZip64(t, size)
	testZip64DirectoryRecordLength(buf, t)
}

func TestZip64EdgeCase(t *testing.T) {
	if testing.Short() {
		t.Skip("slow test; skipping")
	}
	t.Parallel()
	// Test a zip file with uncompressed size 0xFFFFFFFF.
	// That's the magic marker for a 64-bit file, so even though
	// it fits in a 32-bit field we must use the 64-bit field.
	// Go 1.5 and earlier got this wrong,
	// writing an invalid zip file.
	const size = 1<<32 - 1 - int64(len("END\n")) // before the "END\n" part
	buf := testZip64(t, size)
	testZip64DirectoryRecordLength(buf, t)
}

// Tests that we generate a zip64 file if the directory at offset
// 0xFFFFFFFF, but not before.
func TestZip64DirectoryOffset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	t.Parallel()
	const filename = "huge.txt"
	gen := func(wantOff uint64) func(*Writer) {
		return func(w *Writer) {
			w.testHookCloseSizeOffset = func(size, off uint64) {
				if off != wantOff {
					t.Errorf("central directory offset = %d (%x); want %d", off, off, wantOff)
				}
			}
			f, err := w.CreateHeader(&FileHeader{
				Name:   filename,
				Method: Store,
			})
			if err != nil {
				t.Fatal(err)
			}
			f.(*fileWriter).crc32 = fakeHash32{}
			size := wantOff - fileHeaderLen - uint64(len(filename)) - dataDescriptorLen
			if _, err := io.CopyN(f, zeros{}, int64(size)); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("uint32max-2_NoZip64", func(t *testing.T) {
		t.Parallel()
		if generatesZip64(t, gen(0xfffffffe)) {
			t.Error("unexpected zip64")
		}
	})
	t.Run("uint32max-1_Zip64", func(t *testing.T) {
		t.Parallel()
		if !generatesZip64(t, gen(0xffffffff)) {
			t.Error("expected zip64")
		}
	})
}

// At 16k records, we need to generate a zip64 file.
func TestZip64ManyRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	t.Parallel()
	gen := func(numRec int) func(*Writer) {
		return func(w *Writer) {
			for i := 0; i < numRec; i++ {
				_, err := w.CreateHeader(&FileHeader{
					Name:   "a.txt",
					Method: Store,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	// 16k-1 records shouldn't make a zip64:
	t.Run("uint16max-1_NoZip64", func(t *testing.T) {
		t.Parallel()
		if generatesZip64(t, gen(0xfffe)) {
			t.Error("unexpected zip64")
		}
	})
	// 16k records should make a zip64:
	t.Run("uint16max_Zip64", func(t *testing.T) {
		t.Parallel()
		if !generatesZip64(t, gen(0xffff)) {
			t.Error("expected zip64")
		}
	})
}

// suffixSaver is an io.Writer & io.ReaderAt that remembers the last 0
// to 'keep' bytes of data written to it. Call Suffix to get the
// suffix bytes.
type suffixSaver struct {
	keep  int
	buf   []byte
	start int
	size  int64
}

func (ss *suffixSaver) Size() int64 { return ss.size }

var errDiscardedBytes = errors.New("ReadAt of discarded bytes")

func (ss *suffixSaver) ReadAt(p []byte, off int64) (n int, err error) {
	back := ss.size - off
	if back > int64(ss.keep) {
		return 0, errDiscardedBytes
	}
	suf := ss.Suffix()
	n = copy(p, suf[len(suf)-int(back):])
	if n != len(p) {
		err = io.EOF
	}
	return
}

func (ss *suffixSaver) Suffix() []byte {
	if len(ss.buf) < ss.keep {
		return ss.buf
	}
	buf := make([]byte, ss.keep)
	n := copy(buf, ss.buf[ss.start:])
	copy(buf[n:], ss.buf[:])
	return buf
}

func (ss *suffixSaver) Write(p []byte) (n int, err error) {
	n = len(p)
	ss.size += int64(len(p))
	if len(ss.buf) < ss.keep {
		space := ss.keep - len(ss.buf)
		add := len(p)
		if add > space {
			add = space
		}
		ss.buf = append(ss.buf, p[:add]...)
		p = p[add:]
	}
	for len(p) > 0 {
		n := copy(ss.buf[ss.start:], p)
		p = p[n:]
		ss.start += n
		if ss.start == ss.keep {
			ss.start = 0
		}
	}
	return
}

// generatesZip64 reports whether f wrote a zip64 file.
// f is also responsible for closing w.
func generatesZip64(t *testing.T, f func(w *Writer)) bool {
	ss := &suffixSaver{keep: 10 << 20}
	w := NewWriter(ss)
	f(w)
	return suffixIsZip64(t, ss)
}

type sizedReaderAt interface {
	io.ReaderAt
	Size() int64
}

func suffixIsZip64(t *testing.T, zip sizedReaderAt) bool {
	d := make([]byte, 1024)
	if _, err := zip.ReadAt(d, zip.Size()-int64(len(d))); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}

	sigOff := findSignatureInBlock(d)
	if sigOff == -1 {
		t.Errorf("failed to find signature in block")
		return false
	}

	dirOff, err := findDirectory64End(zip, zip.Size()-int64(len(d))+int64(sigOff))
	if err != nil {
		t.Fatalf("findDirectory64End: %v", err)
	}
	if dirOff == -1 {
		return false
	}

	d = make([]byte, directory64EndLen)
	if _, err := zip.ReadAt(d, dirOff); err != nil {
		t.Fatalf("ReadAt(off=%d): %v", dirOff, err)
	}

	b := readBuf(d)
	if sig := b.uint32(); sig != directory64EndSignature {
		return false
	}

	size := b.uint64()
	if size != directory64EndLen-12 {
		t.Errorf("expected length of %d, got %d", directory64EndLen-12, size)
	}
	return true
}

// Zip64 is required if the total size of the records is uint32max.
func TestZip64LargeDirectory(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("too slow on wasm")
	}
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	t.Parallel()
	// gen returns a func that writes a zip with a wantLen bytes
	// of central directory.
	gen := func(wantLen int64) func(*Writer) {
		return func(w *Writer) {
			w.testHookCloseSizeOffset = func(size, off uint64) {
				if size != uint64(wantLen) {
					t.Errorf("Close central directory size = %d; want %d", size, wantLen)
				}
			}

			uint16string := strings.Repeat(".", uint16max)
			remain := wantLen
			for remain > 0 {
				commentLen := int(uint16max) - directoryHeaderLen - 1
				thisRecLen := directoryHeaderLen + int(uint16max) + commentLen
				if int64(thisRecLen) > remain {
					remove := thisRecLen - int(remain)
					commentLen -= remove
					thisRecLen -= remove
				}
				remain -= int64(thisRecLen)
				f, err := w.CreateHeader(&FileHeader{
					Name:    uint16string,
					Comment: uint16string[:commentLen],
				})
				if err != nil {
					t.Fatalf("CreateHeader: %v", err)
				}
				f.(*fileWriter).crc32 = fakeHash32{}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		}
	}
	t.Run("uint32max-1_NoZip64", func(t *testing.T) {
		t.Parallel()
		if generatesZip64(t, gen(uint32max-1)) {
			t.Error("unexpected zip64")
		}
	})
	t.Run("uint32max_HasZip64", func(t *testing.T) {
		t.Parallel()
		if !generatesZip64(t, gen(uint32max)) {
			t.Error("expected zip64")
		}
	})
}

func testZip64(t testing.TB, size int64) *rleBuffer {
	const chunkSize = 1024
	chunks := int(size / chunkSize)
	// write size bytes plus "END\n" to a zip file
	buf := new(rleBuffer)
	w := NewWriter(buf)
	f, err := w.CreateHeader(&FileHeader{
		Name:   "huge.txt",
		Method: Store,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.(*fileWriter).crc32 = fakeHash32{}
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = '.'
	}
	for i := 0; i < chunks; i++ {
		_, err := f.Write(chunk)
		if err != nil {
			t.Fatal("write chunk:", err)
		}
	}
	if frag := int(size % chunkSize); frag > 0 {
		_, err := f.Write(chunk[:frag])
		if err != nil {
			t.Fatal("write chunk:", err)
		}
	}
	end := []byte("END\n")
	_, err = f.Write(end)
	if err != nil {
		t.Fatal("write end:", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// read back zip file and check that we get to the end of it
	r, err := NewReader(buf, buf.Size())
	if err != nil {
		t.Fatal("reader:", err)
	}
	f0 := r.File[0]
	rc, err := f0.Open()
	if err != nil {
		t.Fatal("opening:", err)
	}
	rc.(*checksumReader).hash = fakeHash32{}
	for i := 0; i < chunks; i++ {
		_, err := io.ReadFull(rc, chunk)
		if err != nil {
			t.Fatal("read:", err)
		}
	}
	if frag := int(size % chunkSize); frag > 0 {
		_, err := io.ReadFull(rc, chunk[:frag])
		if err != nil {
			t.Fatal("read:", err)
		}
	}
	gotEnd, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal("read end:", err)
	}
	if !bytes.Equal(gotEnd, end) {
		t.Errorf("End of zip64 archive %q, want %q", gotEnd, end)
	}
	err = rc.Close()
	if err != nil {
		t.Fatal("closing:", err)
	}
	if size+int64(len("END\n")) >= 1<<32-1 {
		if got, want := f0.UncompressedSize, uint32(uint32max); got != want {
			t.Errorf("UncompressedSize %#x, want %#x", got, want)
		}
	}

	if got, want := f0.UncompressedSize64, uint64(size)+uint64(len(end)); got != want {
		t.Errorf("UncompressedSize64 %#x, want %#x", got, want)
	}

	return buf
}

// Issue 9857
func testZip64DirectoryRecordLength(buf *rleBuffer, t *testing.T) {
	if !suffixIsZip64(t, buf) {
		t.Fatal("not a zip64")
	}
}

func testValidHeader(h *FileHeader, t *testing.T) {
	var buf bytes.Buffer
	z := NewWriter(&buf)

	f, err := z.CreateHeader(h)
	if err != nil {
		t.Fatalf("error creating header: %v", err)
	}
	if _, err := f.Write([]byte("hi")); err != nil {
		t.Fatalf("error writing content: %v", err)
	}
	if err := z.Close(); err != nil {
		t.Fatalf("error closing zip writer: %v", err)
	}

	b := buf.Bytes()
	zf, err := NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("got %v, expected nil", err)
	}
	zh := zf.File[0].FileHeader
	if zh.Name != h.Name || zh.Method != h.Method || zh.UncompressedSize64 != uint64(len("hi")) {
		t.Fatalf("got %q/%d/%d expected %q/%d/%d", zh.Name, zh.Method, zh.UncompressedSize64, h.Name, h.Method, len("hi"))
	}
}

// Issue 4302.
func TestHeaderInvalidTagAndSize(t *testing.T) {
	const timeFormat = "20060102T150405.000.txt"

	ts := time.Now()
	filename := ts.Format(timeFormat)

	h := FileHeader{
		Name:   filename,
		Method: Deflate,
		Extra:  []byte(ts.Format(time.RFC3339Nano)), // missing tag and len, but Extra is best-effort parsing
	}
	h.SetModTime(ts)

	testValidHeader(&h, t)
}

func TestHeaderTooShort(t *testing.T) {
	h := FileHeader{
		Name:   "foo.txt",
		Method: Deflate,
		Extra:  []byte{zip64ExtraID}, // missing size and second half of tag, but Extra is best-effort parsing
	}
	testValidHeader(&h, t)
}

func TestHeaderTooLongErr(t *testing.T) {
	var headerTests = []struct {
		name    string
		extra   []byte
		wanterr error
	}{
		{
			name:    strings.Repeat("x", 1<<16),
			extra:   []byte{},
			wanterr: errLongName,
		},
		{
			name:    "long_extra",
			extra:   bytes.Repeat([]byte{0xff}, 1<<16),
			wanterr: errLongExtra,
		},
	}

	// write a zip file
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	for _, test := range headerTests {
		h := &FileHeader{
			Name:  test.name,
			Extra: test.extra,
		}
		_, err := w.CreateHeader(h)
		if err != test.wanterr {
			t.Errorf("error=%v, want %v", err, test.wanterr)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHeaderIgnoredSize(t *testing.T) {
	h := FileHeader{
		Name:   "foo.txt",
		Method: Deflate,
		Extra:  []byte{zip64ExtraID & 0xFF, zip64ExtraID >> 8, 24, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}, // bad size but shouldn't be consulted
	}
	testValidHeader(&h, t)
}

// Issue 4393. It is valid to have an extra data header
// which contains no body.
func TestZeroLengthHeader(t *testing.T) {
	h := FileHeader{
		Name:   "extadata.txt",
		Method: Deflate,
		Extra: []byte{
			85, 84, 5, 0, 3, 154, 144, 195, 77, // tag 21589 size 5
			85, 120, 0, 0, // tag 30805 size 0
		},
	}
	testValidHeader(&h, t)
}

// Just benchmarking how fast the Zip64 test above is. Not related to
// our zip performance, since the test above disabled CRC32 and flate.
func BenchmarkZip64Test(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testZip64(b, 1<<26)
	}
}

func BenchmarkZip64TestSizes(b *testing.B) {
	for _, size := range []int64{1 << 12, 1 << 20, 1 << 26} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					testZip64(b, size)
				}
			})
		})
	}
}

func TestSuffixSaver(t *testing.T) {
	const keep = 10
	ss := &suffixSaver{keep: keep}
	ss.Write([]byte("abc"))
	if got := string(ss.Suffix()); got != "abc" {
		t.Errorf("got = %q; want abc", got)
	}
	ss.Write([]byte("defghijklmno"))
	if got := string(ss.Suffix()); got != "fghijklmno" {
		t.Errorf("got = %q; want fghijklmno", got)
	}
	if got, want := ss.Size(), int64(len("abc")+len("defghijklmno")); got != want {
		t.Errorf("Size = %d; want %d", got, want)
	}
	buf := make([]byte, ss.Size())
	for off := int64(0); off < ss.Size(); off++ {
		for size := 1; size <= int(ss.Size()-off); size++ {
			readBuf := buf[:size]
			n, err := ss.ReadAt(readBuf, off)
			if off < ss.Size()-keep {
				if err != errDiscardedBytes {
					t.Errorf("off %d, size %d = %v, %v (%q); want errDiscardedBytes", off, size, n, err, readBuf[:n])
				}
				continue
			}
			want := "abcdefghijklmno"[off : off+int64(size)]
			got := string(readBuf[:n])
			if err != nil || got != want {
				t.Errorf("off %d, size %d = %v, %v (%q); want %q", off, size, n, err, got, want)
			}
		}
	}

}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

"""



```