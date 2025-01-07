Response:
Let's break down the thought process for analyzing this Go code snippet and generating the desired comprehensive answer.

**1. Initial Understanding: What is this code doing?**

The first step is to quickly scan the code and identify the core purpose. The package name `zip` and the file name `writer_test.go` immediately suggest this is testing functionality related to writing ZIP archives in Go. Keywords like `WriteTest`, `NewWriter`, `Create`, `Close`, and `NewReader` reinforce this idea.

**2. Identifying Key Functionality through Test Cases:**

The most direct way to understand what the `zip.Writer` does is to examine the test functions. Each test function focuses on a specific aspect of the writer's capabilities. I'd go through each test function and summarize its purpose:

* **`TestWriter`**:  Basic writing of files with different names, data, compression methods, and file modes. It also tests reading back the written zip.
* **`TestWriterComment`**:  Testing the ability to set and retrieve comments for the ZIP archive. It also covers error handling for excessively long comments.
* **`TestWriterUTF8`**: Testing the handling of UTF-8 encoded filenames and comments, including a case with non-UTF-8 encoding. This reveals the writer's ability to set flags indicating UTF-8 encoding.
* **`TestWriterTime`**:  Verifies that file modification times are correctly written to the ZIP archive. It compares the output with a known good "golden" file.
* **`TestWriterOffset`**: Shows how to set an offset within the output buffer before writing the ZIP data. This is useful for appending to existing data.
* **`TestWriterFlush`**: Tests the `Flush` method, confirming it forces buffered data to be written.
* **`TestWriterDir`**:  Focuses on how the writer handles directories, particularly that writing data to a directory entry is disallowed.
* **`TestWriterDirAttributes`**: Examines the specific attributes written for directory entries, such as compression method, sizes, and the absence of a data descriptor.
* **`TestWriterCopy`**:  Demonstrates the `Copy` method, which efficiently copies compressed data from an existing ZIP file.
* **`TestWriterCreateRaw`**:  Tests the `CreateRaw` method, which allows for finer control over the file header, including setting pre-computed CRC32, compressed size, and uncompressed size.
* **`TestWriterAddFS`**:  Shows how to add files and directories from a `fs.FS` interface to the ZIP archive.
* **`TestIssue61875`**:  Specifically tests and identifies a potential error scenario when adding certain file types (like symlinks and devices) from an `fs.FS`.

**3. Categorizing and Summarizing Functionality:**

Based on the test functions, I would categorize the `zip.Writer`'s functionalities:

* **Basic File Writing:** Creating and writing file entries with names, data, compression methods (Store and Deflate), and file modes.
* **Metadata Handling:**
    * Setting and retrieving ZIP archive comments.
    * Handling UTF-8 encoding for filenames and comments.
    * Setting file modification times.
* **Advanced Features:**
    * Setting an offset for writing within the output.
    * Flushing buffered data.
    * Handling directory entries (creation and attribute setting).
    * Copying entries from existing ZIP files.
    * Creating raw file entries with custom header information.
    * Adding files and directories from a `fs.FS` interface.

**4. Inferring Go Language Features:**

From the usage patterns in the tests, I can identify the relevant Go language features being utilized:

* **`bytes.Buffer`**: Used as an in-memory buffer to store the ZIP archive data during writing.
* **`io.Writer` Interface**: The `zip.Writer` implements `io.Writer`, allowing it to write to any destination that satisfies this interface (like `bytes.Buffer`, `os.File`, etc.).
* **`compress/flate` Package**: Used for Deflate compression.
* **`hash/crc32` Package**: Used for calculating CRC32 checksums.
* **`encoding/binary` Package**: Used for reading and writing binary data (like header signatures).
* **`testing` Package**:  The foundation for the unit tests.
* **`io/fs` Package**: Used for interacting with file system abstractions, particularly in the `AddFS` test.
* **File Modes (`fs.FileMode`, `os.ModeDir`, `fs.ModeSymlink`, etc.)**: Demonstrates how to set file permissions and types within the ZIP archive.
* **Time Handling (`time.Time`)**: Shows how to set the modification time of files.

**5. Code Examples and Reasoning:**

For each identified feature, I'd construct simple, illustrative Go code examples. These examples should be clear and concise, showcasing the core functionality. Crucially, I'd include:

* **Assumptions/Inputs**: What data or parameters are being used.
* **Expected Outputs**: What the code is expected to produce.
* **Reasoning**: Explaining *why* the code works the way it does, linking it back to the underlying `zip` package behavior.

**6. Command-Line Arguments (If Applicable):**

In this specific code, there aren't direct command-line argument handling examples. If there were, I would analyze how the arguments are parsed (e.g., using the `flag` package) and explain the purpose and syntax of each argument.

**7. Common Mistakes:**

I'd review the test cases for scenarios that could lead to errors or unexpected behavior. For instance, the `TestWriterComment` function highlights the mistake of trying to set a comment that's too long. The `TestIssue61875` shows a case where adding certain file types via `AddFS` can cause issues.

**8. Structuring the Answer:**

Finally, I'd organize the information logically, using clear headings and bullet points to make it easy to read and understand. The requested order of information from the prompt (functionality, Go features, code examples, etc.) would be followed. The language used would be clear and concise, avoiding jargon where possible or explaining it when necessary.

**(Self-Correction/Refinement during the process):**

* **Initially, I might focus too much on the individual test cases.**  It's important to step back and synthesize the information to identify the *broader* functionalities of the `zip.Writer`.
* **I need to ensure the code examples are self-contained and runnable (conceptually, at least).**  Including necessary imports and basic setup is important.
* **The "reasoning" for the code examples is crucial.**  Simply providing code isn't enough; explaining *why* it works is key to understanding.
* **The common mistakes section should be based on actual issues revealed by the tests, not just general assumptions.**

By following these steps, and iterating/refining as needed, I can generate a comprehensive and accurate answer to the user's request.
这段代码是 Go 语言 `archive/zip` 包中 `writer_test.go` 文件的一部分，它主要用于测试 `zip.Writer` 结构体的功能。`zip.Writer` 结构体用于创建 ZIP 归档文件。

以下是这段代码的主要功能：

1. **测试基本的 ZIP 文件写入功能:**
   - 测试创建包含不同文件和目录的 ZIP 文件。
   - 测试写入不同大小的数据，包括小数据和大数据。
   - 测试使用不同的压缩方法（Store 和 Deflate）。
   - 测试设置文件的权限模式 (file mode)。

2. **测试 ZIP 文件注释功能:**
   - 测试设置和读取 ZIP 文件的全局注释。
   - 测试处理不同长度的注释，包括允许的最大长度和超出最大长度的情况。

3. **测试 UTF-8 编码支持:**
   - 测试在 ZIP 文件中使用 UTF-8 编码的文件名和注释。
   - 测试 `NonUTF8` 标志的使用，用于指示文件名或注释是否为非 UTF-8 编码。

4. **测试文件修改时间:**
   - 测试将文件的修改时间写入 ZIP 文件。
   - 通过与预期的 ZIP 文件内容进行比较来验证时间戳的正确性。

5. **测试写入偏移量:**
   - 测试在已存在数据的 `io.Writer` 中，通过设置偏移量来创建新的 ZIP 文件。这允许在现有数据后追加 ZIP 内容。

6. **测试 `Flush` 方法:**
   - 测试 `Flush` 方法是否能强制将缓冲区中的数据写入底层的 `io.Writer`。

7. **测试目录处理:**
   - 测试创建目录条目。
   - 测试不允许向目录条目写入数据。
   - 测试目录条目的特定属性，例如压缩大小和未压缩大小应为 0，并且不应包含数据描述符。

8. **测试 `Copy` 方法:**
   - 测试 `Copy` 方法，它可以将现有 ZIP 文件中的条目直接复制到新的 ZIP 文件中，而无需重新压缩。

9. **测试 `CreateRaw` 方法:**
   - 测试 `CreateRaw` 方法，它允许更精细地控制文件头的内容，例如预先计算的 CRC32 校验和、压缩后的大小和未压缩的大小。

10. **测试从 `fs.FS` 接口添加文件:**
    - 测试 `AddFS` 方法，它可以将 `io/fs` 包定义的 `FS` 接口中的文件和目录添加到 ZIP 文件中。

11. **错误处理测试:**
    - 测试在某些特定情况下是否会产生预期的错误，例如尝试添加某些特殊类型的文件 (如设备文件和符号链接) 从 `fs.FS` 时。

**推理 `zip.Writer` 的 Go 语言功能实现：**

`zip.Writer` 的核心功能是根据用户提供的文件信息（名称、数据、压缩方法等）构建符合 ZIP 文件格式的数据结构，并将其写入底层的 `io.Writer`。

**Go 代码示例 (基于 `TestWriter`):**

```go
package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"log"
)

func main() {
	// 假设我们要创建一个包含两个文件的 ZIP 文件

	// 第一个文件
	fileName1 := "hello.txt"
	fileContent1 := []byte("Hello, ZIP!")

	// 第二个文件
	fileName2 := "world.txt"
	fileContent2 := []byte("World of compression.")

	// 创建一个 buffer 用于存储 ZIP 文件内容
	buf := new(bytes.Buffer)

	// 创建一个 zip.Writer 实例
	zipWriter := zip.NewWriter(buf)

	// 添加第一个文件
	header1 := &zip.FileHeader{
		Name:     fileName1,
		Method:   zip.Deflate, // 使用 Deflate 压缩
		Modified: time.Now(),
	}
	writer1, err := zipWriter.CreateHeader(header1)
	if err != nil {
		log.Fatal(err)
	}
	_, err = writer1.Write(fileContent1)
	if err != nil {
		log.Fatal(err)
	}

	// 添加第二个文件
	header2 := &zip.FileHeader{
		Name:     fileName2,
		Method:   zip.Store, // 不压缩
		Modified: time.Now(),
	}
	writer2, err := zipWriter.CreateHeader(header2)
	if err != nil {
		log.Fatal(err)
	}
	_, err = writer2.Write(fileContent2)
	if err != nil {
		log.Fatal(err)
	}

	// 完成 ZIP 文件的写入
	err = zipWriter.Close()
	if err != nil {
		log.Fatal(err)
	}

	// 打印生成的 ZIP 文件内容 (用于演示)
	fmt.Printf("Generated ZIP file:\n%X\n", buf.Bytes())

	// 可以使用 zip.NewReader 从 buf 中读取 ZIP 文件内容进行验证
}
```

**假设的输入与输出 (基于上面的代码示例):**

**输入:**  `fileName1 = "hello.txt"`, `fileContent1 = []byte("Hello, ZIP!")`, `fileName2 = "world.txt"`, `fileContent2 = []byte("World of compression.")`

**输出:** (实际输出的字节序列会很长，并且会因为时间戳和压缩结果而略有不同，这里只展示一个简化的概念)

```
Generated ZIP file:
504B0304... // 本地文件头 - hello.txt (Deflate)
... // 压缩后的 "Hello, ZIP!" 数据
504B0304... // 本地文件头 - world.txt (Store)
... // "World of compression." 数据
504B0102... // 中央目录文件头 - hello.txt
504B0102... // 中央目录文件头 - world.txt
504B0506... // 中央目录结束记录
```

**代码推理:**

- `zip.NewWriter(buf)` 创建一个新的 `zip.Writer`，它将数据写入 `buf` 这个 `bytes.Buffer`。
- `zipWriter.CreateHeader(header)` 创建一个新的文件条目，`header` 包含了文件的元数据（名称、压缩方法、修改时间等）。
- `writer.Write(data)` 将文件的实际内容写入到 ZIP 归档中。如果压缩方法是 `zip.Deflate`，`zip.Writer` 会使用 `compress/flate` 包进行压缩。
- `zipWriter.Close()` 完成 ZIP 文件的写入，包括写入中央目录和中央目录结束记录。中央目录包含了 ZIP 文件中所有文件的索引信息，使得 ZIP 解压器可以快速定位和提取文件。

**命令行参数的具体处理:**

这段测试代码本身并不直接处理命令行参数。它是一个单元测试文件，用于测试 `archive/zip` 包的功能。如果要在命令行中使用 `archive/zip` 包创建 ZIP 文件，你需要编写一个独立的 Go 程序，并使用 `flag` 包或者其他方式来处理命令行参数，例如指定要压缩的文件和输出的 ZIP 文件名。

例如，一个简单的命令行 ZIP 创建工具可能如下所示：

```go
package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	output := flag.String("out", "archive.zip", "Output ZIP file name")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("Usage: zip-creator [options] <file1> <file2> ...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	outFile, err := os.Create(*output)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		os.Exit(1)
	}
	defer outFile.Close()

	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	for _, filename := range flag.Args() {
		file, err := os.Open(filename)
		if err != nil {
			fmt.Println("Error opening file:", filename, err)
			continue
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			fmt.Println("Error getting file info:", filename, err)
			continue
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			fmt.Println("Error creating header for:", filename, err)
			continue
		}

		// 使用相对于当前目录的路径作为 ZIP 文件中的文件名
		header.Name = filename

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			fmt.Println("Error creating zip entry for:", filename, err)
			continue
		}

		_, err = io.Copy(writer, file)
		if err != nil {
			fmt.Println("Error copying data for:", filename, err)
			continue
		}
	}

	fmt.Println("Successfully created:", *output)
}
```

在这个例子中：

- `-out` 参数使用 `flag.String` 定义，用于指定输出的 ZIP 文件名，默认为 `archive.zip`。
- `flag.Parse()` 解析命令行参数。
- `flag.Args()` 返回所有非 flag 参数，这里是需要添加到 ZIP 文件中的文件名。

用户可以通过以下命令运行：

```bash
go run your_zip_creator.go -out myarchive.zip file1.txt file2.jpg directory/
```

**使用者易犯错的点:**

1. **忘记 `Close()` `zip.Writer`:**  如果不调用 `Close()` 方法，ZIP 文件的中央目录和结束记录不会被写入，导致 ZIP 文件不完整或无法被正确解压。

   ```go
   buf := new(bytes.Buffer)
   zw := zip.NewWriter(buf)
   zw.Create("myfile.txt")
   // ... 写入数据 ...
   // 忘记 zw.Close()
   ```

2. **向目录条目写入数据:**  `zip.Writer` 允许创建目录条目，但是尝试向目录条目写入任何数据都会导致错误。

   ```go
   zw := zip.NewWriter(buf)
   w, _ := zw.Create("mydir/")
   _, err := w.Write([]byte("this will cause an error")) // 错误！
   ```

3. **假设所有的 `io.Writer` 都是立即写入的:**  `zip.Writer` 内部会对数据进行缓冲，特别是在使用压缩时。如果不调用 `Flush()` 或 `Close()`，数据可能不会立即写入到下层的 `io.Writer` 中。虽然通常情况下 `Close()` 会处理所有未写入的数据，但在某些需要逐步写入的场景下（例如网络传输），可能会导致问题。

4. **不理解压缩方法的影响:**  使用 `zip.Store` 方法不会进行压缩，而 `zip.Deflate` 会进行压缩。选择错误的压缩方法可能会导致 ZIP 文件过大或者解压速度慢。

5. **处理文件名中的路径:**  当使用 `AddFS` 或手动创建条目时，需要注意 ZIP 文件中存储的文件名路径。如果直接使用绝对路径，可能会导致在不同的系统上解压时出现问题。通常建议使用相对于某个根目录的相对路径。

这段测试代码覆盖了 `zip.Writer` 的许多关键功能，通过阅读和理解这些测试用例，可以更好地掌握 `archive/zip` 包的使用方法。

Prompt: 
```
这是路径为go/src/archive/zip/writer_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// TODO(adg): a more sophisticated test suite

type WriteTest struct {
	Name   string
	Data   []byte
	Method uint16
	Mode   fs.FileMode
}

var writeTests = []WriteTest{
	{
		Name:   "foo",
		Data:   []byte("Rabbits, guinea pigs, gophers, marsupial rats, and quolls."),
		Method: Store,
		Mode:   0666,
	},
	{
		Name:   "bar",
		Data:   nil, // large data set in the test
		Method: Deflate,
		Mode:   0644,
	},
	{
		Name:   "setuid",
		Data:   []byte("setuid file"),
		Method: Deflate,
		Mode:   0755 | fs.ModeSetuid,
	},
	{
		Name:   "setgid",
		Data:   []byte("setgid file"),
		Method: Deflate,
		Mode:   0755 | fs.ModeSetgid,
	},
	{
		Name:   "symlink",
		Data:   []byte("../link/target"),
		Method: Deflate,
		Mode:   0755 | fs.ModeSymlink,
	},
	{
		Name:   "device",
		Data:   []byte("device file"),
		Method: Deflate,
		Mode:   0755 | fs.ModeDevice,
	},
	{
		Name:   "chardevice",
		Data:   []byte("char device file"),
		Method: Deflate,
		Mode:   0755 | fs.ModeDevice | fs.ModeCharDevice,
	},
}

func TestWriter(t *testing.T) {
	largeData := make([]byte, 1<<17)
	if _, err := rand.Read(largeData); err != nil {
		t.Fatal("rand.Read failed:", err)
	}
	writeTests[1].Data = largeData
	defer func() {
		writeTests[1].Data = nil
	}()

	// write a zip file
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	for _, wt := range writeTests {
		testCreate(t, w, &wt)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// read it back
	r, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for i, wt := range writeTests {
		testReadFile(t, r.File[i], &wt)
	}
}

// TestWriterComment is test for EOCD comment read/write.
func TestWriterComment(t *testing.T) {
	tests := []struct {
		comment string
		ok      bool
	}{
		{"hi, hello", true},
		{"hi, こんにちわ", true},
		{strings.Repeat("a", uint16max), true},
		{strings.Repeat("a", uint16max+1), false},
	}

	for _, test := range tests {
		// write a zip file
		buf := new(bytes.Buffer)
		w := NewWriter(buf)
		if err := w.SetComment(test.comment); err != nil {
			if test.ok {
				t.Fatalf("SetComment: unexpected error %v", err)
			}
			continue
		} else {
			if !test.ok {
				t.Fatalf("SetComment: unexpected success, want error")
			}
		}

		if err := w.Close(); test.ok == (err != nil) {
			t.Fatal(err)
		}

		if w.closed != test.ok {
			t.Fatalf("Writer.closed: got %v, want %v", w.closed, test.ok)
		}

		// skip read test in failure cases
		if !test.ok {
			continue
		}

		// read it back
		r, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		if r.Comment != test.comment {
			t.Fatalf("Reader.Comment: got %v, want %v", r.Comment, test.comment)
		}
	}
}

func TestWriterUTF8(t *testing.T) {
	utf8Tests := []struct {
		name    string
		comment string
		nonUTF8 bool
		flags   uint16
	}{
		{
			name:    "hi, hello",
			comment: "in the world",
			flags:   0x8,
		},
		{
			name:    "hi, こんにちわ",
			comment: "in the world",
			flags:   0x808,
		},
		{
			name:    "hi, こんにちわ",
			comment: "in the world",
			nonUTF8: true,
			flags:   0x8,
		},
		{
			name:    "hi, hello",
			comment: "in the 世界",
			flags:   0x808,
		},
		{
			name:    "hi, こんにちわ",
			comment: "in the 世界",
			flags:   0x808,
		},
		{
			name:    "the replacement rune is �",
			comment: "the replacement rune is �",
			flags:   0x808,
		},
		{
			// Name is Japanese encoded in Shift JIS.
			name:    "\x93\xfa\x96{\x8c\xea.txt",
			comment: "in the 世界",
			flags:   0x008, // UTF-8 must not be set
		},
	}

	// write a zip file
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	for _, test := range utf8Tests {
		h := &FileHeader{
			Name:    test.name,
			Comment: test.comment,
			NonUTF8: test.nonUTF8,
			Method:  Deflate,
		}
		w, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte{})
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// read it back
	r, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range utf8Tests {
		flags := r.File[i].Flags
		if flags != test.flags {
			t.Errorf("CreateHeader(name=%q comment=%q nonUTF8=%v): flags=%#x, want %#x", test.name, test.comment, test.nonUTF8, flags, test.flags)
		}
	}
}

func TestWriterTime(t *testing.T) {
	var buf bytes.Buffer
	h := &FileHeader{
		Name:     "test.txt",
		Modified: time.Date(2017, 10, 31, 21, 11, 57, 0, timeZone(-7*time.Hour)),
	}
	w := NewWriter(&buf)
	if _, err := w.CreateHeader(h); err != nil {
		t.Fatalf("unexpected CreateHeader error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("unexpected Close error: %v", err)
	}

	want, err := os.ReadFile("testdata/time-go.zip")
	if err != nil {
		t.Fatalf("unexpected ReadFile error: %v", err)
	}
	if got := buf.Bytes(); !bytes.Equal(got, want) {
		fmt.Printf("%x\n%x\n", got, want)
		t.Error("contents of time-go.zip differ")
	}
}

func TestWriterOffset(t *testing.T) {
	largeData := make([]byte, 1<<17)
	if _, err := rand.Read(largeData); err != nil {
		t.Fatal("rand.Read failed:", err)
	}
	writeTests[1].Data = largeData
	defer func() {
		writeTests[1].Data = nil
	}()

	// write a zip file
	buf := new(bytes.Buffer)
	existingData := []byte{1, 2, 3, 1, 2, 3, 1, 2, 3}
	n, _ := buf.Write(existingData)
	w := NewWriter(buf)
	w.SetOffset(int64(n))

	for _, wt := range writeTests {
		testCreate(t, w, &wt)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// read it back
	r, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for i, wt := range writeTests {
		testReadFile(t, r.File[i], &wt)
	}
}

func TestWriterFlush(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(struct{ io.Writer }{&buf})
	_, err := w.Create("foo")
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 0 {
		t.Fatalf("Unexpected %d bytes already in buffer", buf.Len())
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("No bytes written after Flush")
	}
}

func TestWriterDir(t *testing.T) {
	w := NewWriter(io.Discard)
	dw, err := w.Create("dir/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dw.Write(nil); err != nil {
		t.Errorf("Write(nil) to directory: got %v, want nil", err)
	}
	if _, err := dw.Write([]byte("hello")); err == nil {
		t.Error(`Write("hello") to directory: got nil error, want non-nil`)
	}
}

func TestWriterDirAttributes(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if _, err := w.CreateHeader(&FileHeader{
		Name:               "dir/",
		Method:             Deflate,
		CompressedSize64:   1234,
		UncompressedSize64: 5678,
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()

	var sig [4]byte
	binary.LittleEndian.PutUint32(sig[:], uint32(fileHeaderSignature))

	idx := bytes.Index(b, sig[:])
	if idx == -1 {
		t.Fatal("file header not found")
	}
	b = b[idx:]

	if !bytes.Equal(b[6:10], []byte{0, 0, 0, 0}) { // FileHeader.Flags: 0, FileHeader.Method: 0
		t.Errorf("unexpected method and flags: %v", b[6:10])
	}

	if !bytes.Equal(b[14:26], make([]byte, 12)) { // FileHeader.{CRC32,CompressSize,UncompressedSize} all zero.
		t.Errorf("unexpected crc, compress and uncompressed size to be 0 was: %v", b[14:26])
	}

	binary.LittleEndian.PutUint32(sig[:], uint32(dataDescriptorSignature))
	if bytes.Contains(b, sig[:]) {
		t.Error("there should be no data descriptor")
	}
}

func TestWriterCopy(t *testing.T) {
	// make a zip file
	buf := new(bytes.Buffer)
	w := NewWriter(buf)
	for _, wt := range writeTests {
		testCreate(t, w, &wt)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// read it back
	src, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for i, wt := range writeTests {
		testReadFile(t, src.File[i], &wt)
	}

	// make a new zip file copying the old compressed data.
	buf2 := new(bytes.Buffer)
	dst := NewWriter(buf2)
	for _, f := range src.File {
		if err := dst.Copy(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}

	// read the new one back
	r, err := NewReader(bytes.NewReader(buf2.Bytes()), int64(buf2.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for i, wt := range writeTests {
		testReadFile(t, r.File[i], &wt)
	}
}

func TestWriterCreateRaw(t *testing.T) {
	files := []struct {
		name             string
		content          []byte
		method           uint16
		flags            uint16
		crc32            uint32
		uncompressedSize uint64
		compressedSize   uint64
	}{
		{
			name:    "small store w desc",
			content: []byte("gophers"),
			method:  Store,
			flags:   0x8,
		},
		{
			name:    "small deflate wo desc",
			content: bytes.Repeat([]byte("abcdefg"), 2048),
			method:  Deflate,
		},
	}

	// write a zip file
	archive := new(bytes.Buffer)
	w := NewWriter(archive)

	for i := range files {
		f := &files[i]
		f.crc32 = crc32.ChecksumIEEE(f.content)
		size := uint64(len(f.content))
		f.uncompressedSize = size
		f.compressedSize = size

		var compressedContent []byte
		if f.method == Deflate {
			var buf bytes.Buffer
			w, err := flate.NewWriter(&buf, flate.BestSpeed)
			if err != nil {
				t.Fatalf("flate.NewWriter err = %v", err)
			}
			_, err = w.Write(f.content)
			if err != nil {
				t.Fatalf("flate Write err = %v", err)
			}
			err = w.Close()
			if err != nil {
				t.Fatalf("flate Writer.Close err = %v", err)
			}
			compressedContent = buf.Bytes()
			f.compressedSize = uint64(len(compressedContent))
		}

		h := &FileHeader{
			Name:               f.name,
			Method:             f.method,
			Flags:              f.flags,
			CRC32:              f.crc32,
			CompressedSize64:   f.compressedSize,
			UncompressedSize64: f.uncompressedSize,
		}
		w, err := w.CreateRaw(h)
		if err != nil {
			t.Fatal(err)
		}
		if compressedContent != nil {
			_, err = w.Write(compressedContent)
		} else {
			_, err = w.Write(f.content)
		}
		if err != nil {
			t.Fatalf("%s Write got %v; want nil", f.name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// read it back
	r, err := NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range files {
		got := r.File[i]
		if got.Name != want.name {
			t.Errorf("got Name %s; want %s", got.Name, want.name)
		}
		if got.Method != want.method {
			t.Errorf("%s: got Method %#x; want %#x", want.name, got.Method, want.method)
		}
		if got.Flags != want.flags {
			t.Errorf("%s: got Flags %#x; want %#x", want.name, got.Flags, want.flags)
		}
		if got.CRC32 != want.crc32 {
			t.Errorf("%s: got CRC32 %#x; want %#x", want.name, got.CRC32, want.crc32)
		}
		if got.CompressedSize64 != want.compressedSize {
			t.Errorf("%s: got CompressedSize64 %d; want %d", want.name, got.CompressedSize64, want.compressedSize)
		}
		if got.UncompressedSize64 != want.uncompressedSize {
			t.Errorf("%s: got UncompressedSize64 %d; want %d", want.name, got.UncompressedSize64, want.uncompressedSize)
		}

		r, err := got.Open()
		if err != nil {
			t.Errorf("%s: Open err = %v", got.Name, err)
			continue
		}

		buf, err := io.ReadAll(r)
		if err != nil {
			t.Errorf("%s: ReadAll err = %v", got.Name, err)
			continue
		}

		if !bytes.Equal(buf, want.content) {
			t.Errorf("%v: ReadAll returned unexpected bytes", got.Name)
		}
	}
}

func testCreate(t *testing.T, w *Writer, wt *WriteTest) {
	header := &FileHeader{
		Name:   wt.Name,
		Method: wt.Method,
	}
	if wt.Mode != 0 {
		header.SetMode(wt.Mode)
	}
	f, err := w.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(wt.Data)
	if err != nil {
		t.Fatal(err)
	}
}

func testReadFile(t *testing.T, f *File, wt *WriteTest) {
	if f.Name != wt.Name {
		t.Fatalf("File name: got %q, want %q", f.Name, wt.Name)
	}
	testFileMode(t, f, wt.Mode)
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("opening %s: %v", f.Name, err)
	}
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading %s: %v", f.Name, err)
	}
	err = rc.Close()
	if err != nil {
		t.Fatalf("closing %s: %v", f.Name, err)
	}
	if !bytes.Equal(b, wt.Data) {
		t.Errorf("File contents %q, want %q", b, wt.Data)
	}
}

func BenchmarkCompressedZipGarbage(b *testing.B) {
	bigBuf := bytes.Repeat([]byte("a"), 1<<20)

	runOnce := func(buf *bytes.Buffer) {
		buf.Reset()
		zw := NewWriter(buf)
		for j := 0; j < 3; j++ {
			w, _ := zw.CreateHeader(&FileHeader{
				Name:   "foo",
				Method: Deflate,
			})
			w.Write(bigBuf)
		}
		zw.Close()
	}

	b.ReportAllocs()
	// Run once and then reset the timer.
	// This effectively discards the very large initial flate setup cost,
	// as well as the initialization of bigBuf.
	runOnce(&bytes.Buffer{})
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		var buf bytes.Buffer
		for pb.Next() {
			runOnce(&buf)
		}
	})
}

func writeTestsToFS(tests []WriteTest) fs.FS {
	fsys := fstest.MapFS{}
	for _, wt := range tests {
		fsys[wt.Name] = &fstest.MapFile{
			Data: wt.Data,
			Mode: wt.Mode,
		}
	}
	return fsys
}

func TestWriterAddFS(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)
	tests := []WriteTest{
		{Name: "emptyfolder", Mode: 0o755 | os.ModeDir},
		{Name: "file.go", Data: []byte("hello"), Mode: 0644},
		{Name: "subfolder/another.go", Data: []byte("world"), Mode: 0644},
		// Notably missing here is the "subfolder" directory. This makes sure even
		// if we don't have a subfolder directory listed.
	}
	err := w.AddFS(writeTestsToFS(tests))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Add subfolder into fsys to match what we'll read from the tar.
	tests = append(tests[:2:2], WriteTest{Name: "subfolder", Mode: 0o555 | os.ModeDir}, tests[2])

	// read it back
	r, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for i, wt := range tests {
		testReadFile(t, r.File[i], &wt)
	}
}

func TestIssue61875(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)
	tests := []WriteTest{
		{
			Name:   "symlink",
			Data:   []byte("../link/target"),
			Method: Deflate,
			Mode:   0755 | fs.ModeSymlink,
		},
		{
			Name:   "device",
			Data:   []byte(""),
			Method: Deflate,
			Mode:   0755 | fs.ModeDevice,
		},
	}
	err := w.AddFS(writeTestsToFS(tests))
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

"""



```