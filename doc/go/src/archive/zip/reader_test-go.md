Response:
Let's break down the thought process for analyzing the provided Go code snippet and generating the comprehensive answer.

1. **Understanding the Goal:** The request asks for a description of the code's functionality, identification of the Go features it uses, illustrative examples, handling of command-line arguments (if any), common pitfalls, and a summary of its purpose. Crucially, it specifies that this is *part* of a larger file.

2. **Initial Code Scan (Keywords and Structure):**  I immediately look for key Go keywords and structural elements to get a high-level understanding:
    * `package zip`:  Indicates this code belongs to the `archive/zip` package, so it's related to ZIP file manipulation.
    * `import`:  Lists imported packages (`bytes`, `encoding/binary`, etc.). This gives hints about what the code interacts with (byte buffers, binary data, file systems, testing).
    * `type ZipTest struct`, `type ZipTestFile struct`: Defines custom data structures, suggesting this code is involved in defining and processing test cases related to ZIP files.
    * `var tests = []ZipTest{ ... }`:  A global variable holding a slice of `ZipTest` structs. This strongly implies that the core purpose is testing ZIP reading functionality.
    * `func TestReader(t *testing.T)`: A standard Go testing function. Confirms the primary purpose is testing.
    * `func readTestZip(t *testing.T, zt ZipTest)`:  A helper function likely responsible for executing a single ZIP test case.
    * `func readTestFile(...)`: Another helper, probably for verifying the contents and metadata of individual files within a ZIP archive.

3. **Dissecting the `ZipTest` and `ZipTestFile` Structs:** These are central to understanding the testing mechanism.
    * `ZipTest`: Represents a single ZIP archive test case. Key fields are:
        * `Name`:  The filename of the test ZIP.
        * `Source`:  A function to generate the ZIP data in memory (alternative to reading from a file).
        * `Comment`:  The expected comment in the ZIP.
        * `File`:  A slice of `ZipTestFile` structs, describing the expected contents of the ZIP.
        * `Obscured`: Indicates if the test data is encoded (for compatibility with certain systems).
        * `Error`: The expected error when opening the ZIP.
    * `ZipTestFile`:  Describes an expected file within a ZIP. Important fields:
        * `Name`: The filename within the ZIP.
        * `Mode`:  The expected file mode/permissions.
        * `Content`: The expected uncompressed content of the file as a byte slice.
        * `File`:  The filename in the `testdata` directory containing the expected content (alternative to `Content`).
        * `Size`: The expected uncompressed size (for very large files, to avoid loading content).
        * `ContentErr`: The expected error when reading the file's content.

4. **Tracing the Test Execution Flow:**
    * `TestReader`: Iterates through the `tests` slice, running `readTestZip` for each test case.
    * `readTestZip`:
        * Loads the ZIP data, either from a file (`testdata` directory) or by calling the `Source` function.
        * Creates a `zip.Reader` using `NewReader` or `OpenReader`.
        * Checks for the expected error when opening the ZIP.
        * Compares the ZIP comment.
        * Iterates through the expected files (`zt.File`) and calls `readTestFile` to verify each one.
        * Includes a section to test concurrent reads of the files in the ZIP.
    * `readTestFile`:
        * Verifies the filename, modification time, and file mode.
        * Opens the file using `f.OpenRaw()` to check the raw data segment.
        * Opens the file for reading using `f.Open()`.
        * For large files, just checks the size.
        * Otherwise, reads the entire content and compares it against the expected content (either directly in `ft.Content` or loaded from a file).
        * Checks for the expected `ContentErr`.

5. **Identifying Go Features:** Based on the code analysis, the prominent Go features used are:
    * **Structs:** `ZipTest`, `ZipTestFile` for organizing test data.
    * **Slices:** `[]ZipTest`, `[]ZipTestFile` to hold multiple test cases and file descriptions.
    * **Functions as Values:** The `Source func() (io.ReaderAt, int64)` in `ZipTest`.
    * **Error Handling:**  Checking for expected errors using `if err != zt.Error`.
    * **File System Interaction:** `os.ReadFile`, `filepath.Join`.
    * **Input/Output (io):** `io.ReaderAt`, `io.Reader`, `io.Copy`, `bytes.NewReader`.
    * **Time Handling:** `time.Time`.
    * **Testing Framework:** `testing.T`, `t.Run`, `t.Errorf`, `t.Fatalf`.
    * **Concurrency:** `go func()`, `chan bool` in the concurrent read test.
    * **Encoding/Decoding:** `encoding/binary`, `encoding/hex` (used in helper functions not directly in the core `TestReader` logic but part of the file).
    * **Deferred Calls:** `defer rc.Close()`, `defer os.Remove(tf)` for resource cleanup.
    * **File Modes:** `fs.FileMode`, `os.ModeSymlink`, `os.ModeDir`.

6. **Inferring Functionality and Providing Examples:** The core functionality is clearly testing the reading of ZIP archives. Examples were constructed to show:
    * Reading basic ZIP files.
    * Handling ZIP files with errors (like `ErrFormat`).
    * Verifying file metadata (name, modification time, mode).
    * Checking file content.
    * Testing large file handling.

7. **Command-Line Arguments:**  The code snippet itself doesn't directly process command-line arguments. The `testing` package handles running tests, but the test data is embedded or loaded from files.

8. **Common Pitfalls:**  Based on the test cases and the nature of ZIP files, the potential pitfalls were identified:
    * Incorrectly specifying expected file content or metadata.
    * Forgetting to update test data when the ZIP reading logic changes.
    * Not accounting for time zone differences.
    * Issues related to UTF-8 encoding of filenames.

9. **Summarizing Functionality:** The final step was to synthesize the observations into a concise summary stating that the code tests the `archive/zip` package's ability to correctly read and interpret ZIP files, covering various scenarios and potential error conditions.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe it's about *writing* ZIP files. However, the focus on `Reader`, `NewReader`, and `OpenReader` quickly shifted the focus to reading.
* **Realization:** The `ZipTest` structure is the *key* to understanding the testing methodology. Spending time to understand its fields is crucial.
* **Observation:**  The `Source` field indicates the ability to generate ZIP data programmatically, which is a powerful testing technique.
* **Focus:** Initially, I might have focused too much on individual functions. Stepping back and looking at the overall structure (test cases, helper functions) provided a better understanding of the purpose.
* **Detail:**  Noticing the `Obscured` field and its comment about Apple notarization added a layer of understanding about real-world considerations in testing.

By following these steps, combining careful code examination with an understanding of Go's testing conventions and ZIP file structure, I was able to generate the detailed and comprehensive answer.
这段代码是 Go 语言 `archive/zip` 包中 `reader_test.go` 文件的一部分，它定义了一系列的结构体和测试用例，用于测试 ZIP 文件的读取功能。

**它的主要功能可以归纳为:**

1. **定义测试用例结构:**
   - 定义了 `ZipTest` 结构体，用于描述一个完整的 ZIP 文件测试用例，包括 ZIP 文件的名称、注释、包含的文件列表、是否被混淆（用于特定场景）以及期望的错误。
   - 定义了 `ZipTestFile` 结构体，用于描述 ZIP 文件中单个文件的预期信息，包括文件名、文件模式、是否非 UTF-8 编码、修改时间、期望的内容（可以直接指定字节数组，也可以指定测试数据目录下的文件）、以及读取内容时期望出现的错误。

2. **构建测试用例数据:**
   - 声明了一个全局变量 `tests`，它是一个 `ZipTest` 结构体的切片。
   - `tests` 中包含了多个 `ZipTest` 实例，每个实例对应一个具体的 ZIP 文件测试场景。这些测试场景覆盖了各种情况，例如：
     - 正常的 ZIP 文件
     - 带有尾部垃圾数据的 ZIP 文件
     - 带有前缀数据的 ZIP 文件
     - 包含错误大小信息的 ZIP 文件
     - 包含错误基础信息的 ZIP 文件
     - 嵌套的 ZIP 文件
     - 包含符号链接的 ZIP 文件
     - 空的 ZIP 文件或非 ZIP 文件
     - 不同操作系统或工具创建的 ZIP 文件 (Windows XP, Linux, Go, 7-Zip, Info-ZIP, OS X, WinRAR, WinZip)
     - 包含数据描述符的 ZIP 文件
     - CRC32 校验错误的 ZIP 文件
     - ZIP64 格式的 ZIP 文件
     - 包含 UTF-8 编码文件名的 ZIP 文件
     - 包含不同时间戳信息的 ZIP 文件
     - 包含重复目录项的 ZIP 文件
     - 包含截断注释的 ZIP 文件

3. **执行测试:**
   - 定义了 `TestReader(t *testing.T)` 函数，这是一个标准的 Go 测试函数。
   - `TestReader` 函数遍历 `tests` 切片中的每一个 `ZipTest` 实例，并为每个实例创建一个子测试 (`t.Run`)。
   - 在每个子测试中，调用 `readTestZip` 函数来执行具体的 ZIP 文件读取测试。

4. **实现具体的读取测试逻辑:**
   - `readTestZip(t *testing.T, zt ZipTest)` 函数负责打开 ZIP 文件并进行各种断言。它会：
     - 根据 `ZipTest` 结构体中的 `Source` 字段或文件名打开 ZIP 文件。
     - 检查打开 ZIP 文件时是否出现了预期的错误。
     - 检查 ZIP 文件的注释是否与预期一致。
     - 遍历 `ZipTest` 结构体中定义的文件列表，并对 ZIP 文件中的每个文件调用 `readTestFile` 函数进行更详细的检查。
     - 执行并发读取测试，模拟多个 goroutine 同时读取 ZIP 文件中的内容。

5. **验证单个文件的读取情况:**
   - `readTestFile(t *testing.T, zt ZipTest, ft ZipTestFile, f *File, raw []byte)` 函数负责验证 ZIP 文件中单个文件的信息和内容。它会：
     - 检查文件名是否与预期一致。
     - 检查修改时间是否与预期一致。
     - 检查文件模式是否与预期一致。
     - 检查解压后的大小是否与预期一致。
     - 通过 `f.OpenRaw()` 检查原始数据段是否正确。
     - 通过 `f.Open()` 打开文件并读取内容。
     - 对于大文件，只检查大小，避免实际解压。
     - 将读取到的内容与预期的内容进行比较，或者检查是否出现了预期的错误。

**可以推理出它是什么 go 语言功能的实现：**

这段代码是 `archive/zip` 包中 **ZIP 文件读取器 (Reader)** 的测试实现。它测试了 `archive/zip` 包提供的用于读取 ZIP 文件的各种功能，例如打开 ZIP 文件、读取文件元数据（文件名、大小、修改时间、权限等）、以及读取文件内容。

**Go 代码举例说明:**

假设我们要测试一个名为 "mytest.zip" 的 ZIP 文件，它包含一个名为 "hello.txt" 的文件，内容为 "Hello, world!\n"。我们可以添加如下的 `ZipTest` 实例到 `tests` 切片中：

```go
{
	Name: "mytest.zip",
	File: []ZipTestFile{
		{
			Name:    "hello.txt",
			Content: []byte("Hello, world!\n"),
			Mode:    0644, // 假设权限是 0644
		},
	},
}
```

为了让这个测试用例跑起来，你需要在 `testdata` 目录下创建一个名为 "mytest.zip" 的文件，并将包含 "hello.txt" 的 ZIP 文件放进去。

**代码推理与假设输入输出:**

假设我们有以下 `ZipTestFile` 定义：

```go
{
    Name:     "test.txt",
    Content:  []byte("This is a test.\n"),
    Modified: time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC),
    Mode:     0644,
}
```

并且 ZIP 文件中确实存在一个名为 "test.txt" 的文件，其内容为 "This is a test.\n"，修改时间为 2023 年 10 月 27 日 10:00:00 UTC，权限为 0644。

`readTestFile` 函数在被调用时，将会进行如下检查：

- **输入 (假设 `f` 代表 ZIP 文件中的 "test.txt"):**
  - `f.Name` 的值为 "test.txt"
  - `f.Modified` 的值接近 `time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC)`
  - `f.Mode()` 的值为 `0644`
  - 通过 `f.Open()` 读取到的内容为 "This is a test.\n"

- **输出 (断言结果):**
  - 断言 `f.Name == ft.Name` 将会成功，因为 "test.txt" == "test.txt"。
  - 断言 `equalTimeAndZone(f.Modified, ft.Modified)` 将会成功，因为时间戳匹配。
  - 断言 `f.Mode() == ft.Mode` 将会成功，因为 `0644 == 0644`。
  - 断言读取到的内容与 `ft.Content` 相等将会成功，因为 "This is a test.\n" == "This is a test.\n"。

**命令行参数:**

这段代码本身是一个测试文件，不涉及命令行参数的具体处理。Go 的测试是通过 `go test` 命令来运行的。你可以通过 `go test ./go/src/archive/zip` 来运行 `archive/zip` 包下的所有测试，包括 `reader_test.go`。

**功能归纳:**

总而言之，这段 `reader_test.go` 代码的主要功能是 **通过定义一系列的测试用例，来全面地测试 `archive/zip` 包中 ZIP 文件读取器的正确性和健壮性**。它覆盖了各种合法的和非法的 ZIP 文件格式，以及不同操作系统和工具生成的 ZIP 文件，确保 `archive/zip` 包能够可靠地读取各种 ZIP 档案。

### 提示词
```
这是路径为go/src/archive/zip/reader_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"internal/obscuretestdata"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type ZipTest struct {
	Name     string
	Source   func() (r io.ReaderAt, size int64) // if non-nil, used instead of testdata/<Name> file
	Comment  string
	File     []ZipTestFile
	Obscured bool  // needed for Apple notarization (golang.org/issue/34986)
	Error    error // the error that Opening this file should return
}

type ZipTestFile struct {
	Name     string
	Mode     fs.FileMode
	NonUTF8  bool
	ModTime  time.Time
	Modified time.Time

	// Information describing expected zip file content.
	// First, reading the entire content should produce the error ContentErr.
	// Second, if ContentErr==nil, the content should match Content.
	// If content is large, an alternative to setting Content is to set File,
	// which names a file in the testdata/ directory containing the
	// uncompressed expected content.
	// If content is very large, an alternative to setting Content or File
	// is to set Size, which will then be checked against the header-reported size
	// but will bypass the decompressing of the actual data.
	// This last option is used for testing very large (multi-GB) compressed files.
	ContentErr error
	Content    []byte
	File       string
	Size       uint64
}

var tests = []ZipTest{
	{
		Name:    "test.zip",
		Comment: "This is a zipfile comment.",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte("This is a test text file.\n"),
				Modified: time.Date(2010, 9, 5, 12, 12, 1, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
			{
				Name:     "gophercolor16x16.png",
				File:     "gophercolor16x16.png",
				Modified: time.Date(2010, 9, 5, 15, 52, 58, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
		},
	},
	{
		Name:    "test-trailing-junk.zip",
		Comment: "This is a zipfile comment.",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte("This is a test text file.\n"),
				Modified: time.Date(2010, 9, 5, 12, 12, 1, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
			{
				Name:     "gophercolor16x16.png",
				File:     "gophercolor16x16.png",
				Modified: time.Date(2010, 9, 5, 15, 52, 58, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
		},
	},
	{
		Name:    "test-prefix.zip",
		Comment: "This is a zipfile comment.",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte("This is a test text file.\n"),
				Modified: time.Date(2010, 9, 5, 12, 12, 1, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
			{
				Name:     "gophercolor16x16.png",
				File:     "gophercolor16x16.png",
				Modified: time.Date(2010, 9, 5, 15, 52, 58, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
		},
	},
	{
		Name:    "test-baddirsz.zip",
		Comment: "This is a zipfile comment.",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte("This is a test text file.\n"),
				Modified: time.Date(2010, 9, 5, 12, 12, 1, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
			{
				Name:     "gophercolor16x16.png",
				File:     "gophercolor16x16.png",
				Modified: time.Date(2010, 9, 5, 15, 52, 58, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
		},
	},
	{
		Name:    "test-badbase.zip",
		Comment: "This is a zipfile comment.",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte("This is a test text file.\n"),
				Modified: time.Date(2010, 9, 5, 12, 12, 1, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
			{
				Name:     "gophercolor16x16.png",
				File:     "gophercolor16x16.png",
				Modified: time.Date(2010, 9, 5, 15, 52, 58, 0, timeZone(+10*time.Hour)),
				Mode:     0644,
			},
		},
	},
	{
		Name:   "r.zip",
		Source: returnRecursiveZip,
		File: []ZipTestFile{
			{
				Name:     "r/r.zip",
				Content:  rZipBytes(),
				Modified: time.Date(2010, 3, 4, 0, 24, 16, 0, time.UTC),
				Mode:     0666,
			},
		},
	},
	{
		Name: "symlink.zip",
		File: []ZipTestFile{
			{
				Name:     "symlink",
				Content:  []byte("../target"),
				Modified: time.Date(2012, 2, 3, 19, 56, 48, 0, timeZone(-2*time.Hour)),
				Mode:     0777 | fs.ModeSymlink,
			},
		},
	},
	{
		Name: "readme.zip",
	},
	{
		Name:  "readme.notzip",
		Error: ErrFormat,
	},
	{
		Name: "dd.zip",
		File: []ZipTestFile{
			{
				Name:     "filename",
				Content:  []byte("This is a test textfile.\n"),
				Modified: time.Date(2011, 2, 2, 13, 6, 20, 0, time.UTC),
				Mode:     0666,
			},
		},
	},
	{
		// created in windows XP file manager.
		Name: "winxp.zip",
		File: []ZipTestFile{
			{
				Name:     "hello",
				Content:  []byte("world \r\n"),
				Modified: time.Date(2011, 12, 8, 10, 4, 24, 0, time.UTC),
				Mode:     0666,
			},
			{
				Name:     "dir/bar",
				Content:  []byte("foo \r\n"),
				Modified: time.Date(2011, 12, 8, 10, 4, 50, 0, time.UTC),
				Mode:     0666,
			},
			{
				Name:     "dir/empty/",
				Content:  []byte{},
				Modified: time.Date(2011, 12, 8, 10, 8, 6, 0, time.UTC),
				Mode:     fs.ModeDir | 0777,
			},
			{
				Name:     "readonly",
				Content:  []byte("important \r\n"),
				Modified: time.Date(2011, 12, 8, 10, 6, 8, 0, time.UTC),
				Mode:     0444,
			},
		},
	},
	{
		// created by Zip 3.0 under Linux
		Name: "unix.zip",
		File: []ZipTestFile{
			{
				Name:     "hello",
				Content:  []byte("world \r\n"),
				Modified: time.Date(2011, 12, 8, 10, 4, 24, 0, timeZone(0)),
				Mode:     0666,
			},
			{
				Name:     "dir/bar",
				Content:  []byte("foo \r\n"),
				Modified: time.Date(2011, 12, 8, 10, 4, 50, 0, timeZone(0)),
				Mode:     0666,
			},
			{
				Name:     "dir/empty/",
				Content:  []byte{},
				Modified: time.Date(2011, 12, 8, 10, 8, 6, 0, timeZone(0)),
				Mode:     fs.ModeDir | 0777,
			},
			{
				Name:     "readonly",
				Content:  []byte("important \r\n"),
				Modified: time.Date(2011, 12, 8, 10, 6, 8, 0, timeZone(0)),
				Mode:     0444,
			},
		},
	},
	{
		// created by Go, before we wrote the "optional" data
		// descriptor signatures (which are required by macOS).
		// Use obscured file to avoid Apple’s notarization service
		// rejecting the toolchain due to an inability to unzip this archive.
		// See golang.org/issue/34986
		Name:     "go-no-datadesc-sig.zip.base64",
		Obscured: true,
		File: []ZipTestFile{
			{
				Name:     "foo.txt",
				Content:  []byte("foo\n"),
				Modified: time.Date(2012, 3, 8, 16, 59, 10, 0, timeZone(-8*time.Hour)),
				Mode:     0644,
			},
			{
				Name:     "bar.txt",
				Content:  []byte("bar\n"),
				Modified: time.Date(2012, 3, 8, 16, 59, 12, 0, timeZone(-8*time.Hour)),
				Mode:     0644,
			},
		},
	},
	{
		// created by Go, after we wrote the "optional" data
		// descriptor signatures (which are required by macOS)
		Name: "go-with-datadesc-sig.zip",
		File: []ZipTestFile{
			{
				Name:     "foo.txt",
				Content:  []byte("foo\n"),
				Modified: time.Date(1979, 11, 30, 0, 0, 0, 0, time.UTC),
				Mode:     0666,
			},
			{
				Name:     "bar.txt",
				Content:  []byte("bar\n"),
				Modified: time.Date(1979, 11, 30, 0, 0, 0, 0, time.UTC),
				Mode:     0666,
			},
		},
	},
	{
		Name:   "Bad-CRC32-in-data-descriptor",
		Source: returnCorruptCRC32Zip,
		File: []ZipTestFile{
			{
				Name:       "foo.txt",
				Content:    []byte("foo\n"),
				Modified:   time.Date(1979, 11, 30, 0, 0, 0, 0, time.UTC),
				Mode:       0666,
				ContentErr: ErrChecksum,
			},
			{
				Name:     "bar.txt",
				Content:  []byte("bar\n"),
				Modified: time.Date(1979, 11, 30, 0, 0, 0, 0, time.UTC),
				Mode:     0666,
			},
		},
	},
	// Tests that we verify (and accept valid) crc32s on files
	// with crc32s in their file header (not in data descriptors)
	{
		Name: "crc32-not-streamed.zip",
		File: []ZipTestFile{
			{
				Name:     "foo.txt",
				Content:  []byte("foo\n"),
				Modified: time.Date(2012, 3, 8, 16, 59, 10, 0, timeZone(-8*time.Hour)),
				Mode:     0644,
			},
			{
				Name:     "bar.txt",
				Content:  []byte("bar\n"),
				Modified: time.Date(2012, 3, 8, 16, 59, 12, 0, timeZone(-8*time.Hour)),
				Mode:     0644,
			},
		},
	},
	// Tests that we verify (and reject invalid) crc32s on files
	// with crc32s in their file header (not in data descriptors)
	{
		Name:   "crc32-not-streamed.zip",
		Source: returnCorruptNotStreamedZip,
		File: []ZipTestFile{
			{
				Name:       "foo.txt",
				Content:    []byte("foo\n"),
				Modified:   time.Date(2012, 3, 8, 16, 59, 10, 0, timeZone(-8*time.Hour)),
				Mode:       0644,
				ContentErr: ErrChecksum,
			},
			{
				Name:     "bar.txt",
				Content:  []byte("bar\n"),
				Modified: time.Date(2012, 3, 8, 16, 59, 12, 0, timeZone(-8*time.Hour)),
				Mode:     0644,
			},
		},
	},
	{
		Name: "zip64.zip",
		File: []ZipTestFile{
			{
				Name:     "README",
				Content:  []byte("This small file is in ZIP64 format.\n"),
				Modified: time.Date(2012, 8, 10, 14, 33, 32, 0, time.UTC),
				Mode:     0644,
			},
		},
	},
	// Another zip64 file with different Extras fields. (golang.org/issue/7069)
	{
		Name: "zip64-2.zip",
		File: []ZipTestFile{
			{
				Name:     "README",
				Content:  []byte("This small file is in ZIP64 format.\n"),
				Modified: time.Date(2012, 8, 10, 14, 33, 32, 0, timeZone(-4*time.Hour)),
				Mode:     0644,
			},
		},
	},
	// Largest possible non-zip64 file, with no zip64 header.
	{
		Name:   "big.zip",
		Source: returnBigZipBytes,
		File: []ZipTestFile{
			{
				Name:     "big.file",
				Content:  nil,
				Size:     1<<32 - 1,
				Modified: time.Date(1979, 11, 30, 0, 0, 0, 0, time.UTC),
				Mode:     0666,
			},
		},
	},
	{
		Name: "utf8-7zip.zip",
		File: []ZipTestFile{
			{
				Name:     "世界",
				Content:  []byte{},
				Mode:     0666,
				Modified: time.Date(2017, 11, 6, 13, 9, 27, 867862500, timeZone(-8*time.Hour)),
			},
		},
	},
	{
		Name: "utf8-infozip.zip",
		File: []ZipTestFile{
			{
				Name:    "世界",
				Content: []byte{},
				Mode:    0644,
				// Name is valid UTF-8, but format does not have UTF-8 flag set.
				// We don't do UTF-8 detection for multi-byte runes due to
				// false-positives with other encodings (e.g., Shift-JIS).
				// Format says encoding is not UTF-8, so we trust it.
				NonUTF8:  true,
				Modified: time.Date(2017, 11, 6, 13, 9, 27, 0, timeZone(-8*time.Hour)),
			},
		},
	},
	{
		Name: "utf8-osx.zip",
		File: []ZipTestFile{
			{
				Name:    "世界",
				Content: []byte{},
				Mode:    0644,
				// Name is valid UTF-8, but format does not have UTF-8 set.
				NonUTF8:  true,
				Modified: time.Date(2017, 11, 6, 13, 9, 27, 0, timeZone(-8*time.Hour)),
			},
		},
	},
	{
		Name: "utf8-winrar.zip",
		File: []ZipTestFile{
			{
				Name:     "世界",
				Content:  []byte{},
				Mode:     0666,
				Modified: time.Date(2017, 11, 6, 13, 9, 27, 867862500, timeZone(-8*time.Hour)),
			},
		},
	},
	{
		Name: "utf8-winzip.zip",
		File: []ZipTestFile{
			{
				Name:     "世界",
				Content:  []byte{},
				Mode:     0666,
				Modified: time.Date(2017, 11, 6, 13, 9, 27, 867000000, timeZone(-8*time.Hour)),
			},
		},
	},
	{
		Name: "time-7zip.zip",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte{},
				Size:     1<<32 - 1,
				Modified: time.Date(2017, 10, 31, 21, 11, 57, 244817900, timeZone(-7*time.Hour)),
				Mode:     0666,
			},
		},
	},
	{
		Name: "time-infozip.zip",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte{},
				Size:     1<<32 - 1,
				Modified: time.Date(2017, 10, 31, 21, 11, 57, 0, timeZone(-7*time.Hour)),
				Mode:     0644,
			},
		},
	},
	{
		Name: "time-osx.zip",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte{},
				Size:     1<<32 - 1,
				Modified: time.Date(2017, 10, 31, 21, 11, 57, 0, timeZone(-7*time.Hour)),
				Mode:     0644,
			},
		},
	},
	{
		Name: "time-win7.zip",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte{},
				Size:     1<<32 - 1,
				Modified: time.Date(2017, 10, 31, 21, 11, 58, 0, time.UTC),
				Mode:     0666,
			},
		},
	},
	{
		Name: "time-winrar.zip",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte{},
				Size:     1<<32 - 1,
				Modified: time.Date(2017, 10, 31, 21, 11, 57, 244817900, timeZone(-7*time.Hour)),
				Mode:     0666,
			},
		},
	},
	{
		Name: "time-winzip.zip",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte{},
				Size:     1<<32 - 1,
				Modified: time.Date(2017, 10, 31, 21, 11, 57, 244000000, timeZone(-7*time.Hour)),
				Mode:     0666,
			},
		},
	},
	{
		Name: "time-go.zip",
		File: []ZipTestFile{
			{
				Name:     "test.txt",
				Content:  []byte{},
				Size:     1<<32 - 1,
				Modified: time.Date(2017, 10, 31, 21, 11, 57, 0, timeZone(-7*time.Hour)),
				Mode:     0666,
			},
		},
	},
	{
		Name: "time-22738.zip",
		File: []ZipTestFile{
			{
				Name:     "file",
				Content:  []byte{},
				Mode:     0666,
				Modified: time.Date(1999, 12, 31, 19, 0, 0, 0, timeZone(-5*time.Hour)),
				ModTime:  time.Date(1999, 12, 31, 19, 0, 0, 0, time.UTC),
			},
		},
	},
	{
		Name: "dupdir.zip",
		File: []ZipTestFile{
			{
				Name:     "a/",
				Content:  []byte{},
				Mode:     fs.ModeDir | 0666,
				Modified: time.Date(2021, 12, 29, 0, 0, 0, 0, timeZone(0)),
			},
			{
				Name:     "a/b",
				Content:  []byte{},
				Mode:     0666,
				Modified: time.Date(2021, 12, 29, 0, 0, 0, 0, timeZone(0)),
			},
			{
				Name:     "a/b/",
				Content:  []byte{},
				Mode:     fs.ModeDir | 0666,
				Modified: time.Date(2021, 12, 29, 0, 0, 0, 0, timeZone(0)),
			},
			{
				Name:     "a/b/c",
				Content:  []byte{},
				Mode:     0666,
				Modified: time.Date(2021, 12, 29, 0, 0, 0, 0, timeZone(0)),
			},
		},
	},
	// Issue 66869: Don't skip over an EOCDR with a truncated comment.
	// The test file sneakily hides a second EOCDR before the first one;
	// previously we would extract one file ("file") from this archive,
	// while most other tools would reject the file or extract a different one ("FILE").
	{
		Name:  "comment-truncated.zip",
		Error: ErrFormat,
	},
}

func TestReader(t *testing.T) {
	for _, zt := range tests {
		t.Run(zt.Name, func(t *testing.T) {
			readTestZip(t, zt)
		})
	}
}

func readTestZip(t *testing.T, zt ZipTest) {
	var z *Reader
	var err error
	var raw []byte
	if zt.Source != nil {
		rat, size := zt.Source()
		z, err = NewReader(rat, size)
		raw = make([]byte, size)
		if _, err := rat.ReadAt(raw, 0); err != nil {
			t.Errorf("ReadAt error=%v", err)
			return
		}
	} else {
		path := filepath.Join("testdata", zt.Name)
		if zt.Obscured {
			tf, err := obscuretestdata.DecodeToTempFile(path)
			if err != nil {
				t.Errorf("obscuretestdata.DecodeToTempFile(%s): %v", path, err)
				return
			}
			defer os.Remove(tf)
			path = tf
		}
		var rc *ReadCloser
		rc, err = OpenReader(path)
		if err == nil {
			defer rc.Close()
			z = &rc.Reader
		}
		var err2 error
		raw, err2 = os.ReadFile(path)
		if err2 != nil {
			t.Errorf("ReadFile(%s) error=%v", path, err2)
			return
		}
	}
	if err != zt.Error {
		t.Errorf("error=%v, want %v", err, zt.Error)
		return
	}

	// bail if file is not zip
	if err == ErrFormat {
		return
	}

	// bail here if no Files expected to be tested
	// (there may actually be files in the zip, but we don't care)
	if zt.File == nil {
		return
	}

	if z.Comment != zt.Comment {
		t.Errorf("comment=%q, want %q", z.Comment, zt.Comment)
	}
	if len(z.File) != len(zt.File) {
		t.Fatalf("file count=%d, want %d", len(z.File), len(zt.File))
	}

	// test read of each file
	for i, ft := range zt.File {
		readTestFile(t, zt, ft, z.File[i], raw)
	}
	if t.Failed() {
		return
	}

	// test simultaneous reads
	n := 0
	done := make(chan bool)
	for i := 0; i < 5; i++ {
		for j, ft := range zt.File {
			go func(j int, ft ZipTestFile) {
				readTestFile(t, zt, ft, z.File[j], raw)
				done <- true
			}(j, ft)
			n++
		}
	}
	for ; n > 0; n-- {
		<-done
	}
}

func equalTimeAndZone(t1, t2 time.Time) bool {
	name1, offset1 := t1.Zone()
	name2, offset2 := t2.Zone()
	return t1.Equal(t2) && name1 == name2 && offset1 == offset2
}

func readTestFile(t *testing.T, zt ZipTest, ft ZipTestFile, f *File, raw []byte) {
	if f.Name != ft.Name {
		t.Errorf("name=%q, want %q", f.Name, ft.Name)
	}
	if !ft.Modified.IsZero() && !equalTimeAndZone(f.Modified, ft.Modified) {
		t.Errorf("%s: Modified=%s, want %s", f.Name, f.Modified, ft.Modified)
	}
	if !ft.ModTime.IsZero() && !equalTimeAndZone(f.ModTime(), ft.ModTime) {
		t.Errorf("%s: ModTime=%s, want %s", f.Name, f.ModTime(), ft.ModTime)
	}

	testFileMode(t, f, ft.Mode)

	size := uint64(f.UncompressedSize)
	if size == uint32max {
		size = f.UncompressedSize64
	} else if size != f.UncompressedSize64 {
		t.Errorf("%v: UncompressedSize=%#x does not match UncompressedSize64=%#x", f.Name, size, f.UncompressedSize64)
	}

	// Check that OpenRaw returns the correct byte segment
	rw, err := f.OpenRaw()
	if err != nil {
		t.Errorf("%v: OpenRaw error=%v", f.Name, err)
		return
	}
	start, err := f.DataOffset()
	if err != nil {
		t.Errorf("%v: DataOffset error=%v", f.Name, err)
		return
	}
	got, err := io.ReadAll(rw)
	if err != nil {
		t.Errorf("%v: OpenRaw ReadAll error=%v", f.Name, err)
		return
	}
	end := uint64(start) + f.CompressedSize64
	want := raw[start:end]
	if !bytes.Equal(got, want) {
		t.Logf("got %q", got)
		t.Logf("want %q", want)
		t.Errorf("%v: OpenRaw returned unexpected bytes", f.Name)
		return
	}

	r, err := f.Open()
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	// For very large files, just check that the size is correct.
	// The content is expected to be all zeros.
	// Don't bother uncompressing: too big.
	if ft.Content == nil && ft.File == "" && ft.Size > 0 {
		if size != ft.Size {
			t.Errorf("%v: uncompressed size %#x, want %#x", ft.Name, size, ft.Size)
		}
		r.Close()
		return
	}

	var b bytes.Buffer
	_, err = io.Copy(&b, r)
	if err != ft.ContentErr {
		t.Errorf("copying contents: %v (want %v)", err, ft.ContentErr)
	}
	if err != nil {
		return
	}
	r.Close()

	if g := uint64(b.Len()); g != size {
		t.Errorf("%v: read %v bytes but f.UncompressedSize == %v", f.Name, g, size)
	}

	var c []byte
	if ft.Content != nil {
		c = ft.Content
	} else if c, err = os.ReadFile("testdata/" + ft.File); err != nil {
		t.Error(err)
		return
	}

	if b.Len() != len(c) {
		t.Errorf("%s: len=%d, want %d", f.Name, b.Len(), len(c))
		return
	}

	for i, b := range b.Bytes() {
		if b != c[i] {
			t.Errorf("%s: content[%d]=%q want %q", f.Name, i, b, c[i])
			return
		}
	}
}

func testFileMode(t *testing.T, f *File, want fs.FileMode) {
	mode := f.Mode()
	if want == 0 {
		t.Errorf("%s mode: got %v, want none", f.Name, mode)
	} else if mode != want {
		t.Errorf("%s mode: want %v, got %v", f.Name, want, mode)
	}
}

func TestInvalidFiles(t *testing.T) {
	const size = 1024 * 70 // 70kb
	b := make([]byte, size)

	// zeroes
	_, err := NewReader(bytes.NewReader(b), size)
	if err != ErrFormat {
		t.Errorf("zeroes: error=%v, want %v", err, ErrFormat)
	}

	// repeated directoryEndSignatures
	sig := make([]byte, 4)
	binary.LittleEndian.PutUint32(sig, directoryEndSignature)
	for i := 0; i < size-4; i += 4 {
		copy(b[i:i+4], sig)
	}
	_, err = NewReader(bytes.NewReader(b), size)
	if err != ErrFormat {
		t.Errorf("sigs: error=%v, want %v", err, ErrFormat)
	}

	// negative size
	_, err = NewReader(bytes.NewReader([]byte("foobar")), -1)
	if err == nil {
		t.Errorf("archive/zip.NewReader: expected error when negative size is passed")
	}
}

func messWith(fileName string, corrupter func(b []byte)) (r io.ReaderAt, size int64) {
	data, err := os.ReadFile(filepath.Join("testdata", fileName))
	if err != nil {
		panic("Error reading " + fileName + ": " + err.Error())
	}
	corrupter(data)
	return bytes.NewReader(data), int64(len(data))
}

func returnCorruptCRC32Zip() (r io.ReaderAt, size int64) {
	return messWith("go-with-datadesc-sig.zip", func(b []byte) {
		// Corrupt one of the CRC32s in the data descriptor:
		b[0x2d]++
	})
}

func returnCorruptNotStreamedZip() (r io.ReaderAt, size int64) {
	return messWith("crc32-not-streamed.zip", func(b []byte) {
		// Corrupt foo.txt's final crc32 byte, in both
		// the file header and TOC. (0x7e -> 0x7f)
		b[0x11]++
		b[0x9d]++

		// TODO(bradfitz): add a new test that only corrupts
		// one of these values, and verify that that's also an
		// error. Currently, the reader code doesn't verify the
		// fileheader and TOC's crc32 match if they're both
		// non-zero and only the second line above, the TOC,
		// is what matters.
	})
}

// rZipBytes returns the bytes of a recursive zip file, without
// putting it on disk and triggering certain virus scanners.
func rZipBytes() []byte {
	s := `
0000000 50 4b 03 04 14 00 00 00 08 00 08 03 64 3c f9 f4
0000010 89 64 48 01 00 00 b8 01 00 00 07 00 00 00 72 2f
0000020 72 2e 7a 69 70 00 25 00 da ff 50 4b 03 04 14 00
0000030 00 00 08 00 08 03 64 3c f9 f4 89 64 48 01 00 00
0000040 b8 01 00 00 07 00 00 00 72 2f 72 2e 7a 69 70 00
0000050 2f 00 d0 ff 00 25 00 da ff 50 4b 03 04 14 00 00
0000060 00 08 00 08 03 64 3c f9 f4 89 64 48 01 00 00 b8
0000070 01 00 00 07 00 00 00 72 2f 72 2e 7a 69 70 00 2f
0000080 00 d0 ff c2 54 8e 57 39 00 05 00 fa ff c2 54 8e
0000090 57 39 00 05 00 fa ff 00 05 00 fa ff 00 14 00 eb
00000a0 ff c2 54 8e 57 39 00 05 00 fa ff 00 05 00 fa ff
00000b0 00 14 00 eb ff 42 88 21 c4 00 00 14 00 eb ff 42
00000c0 88 21 c4 00 00 14 00 eb ff 42 88 21 c4 00 00 14
00000d0 00 eb ff 42 88 21 c4 00 00 14 00 eb ff 42 88 21
00000e0 c4 00 00 00 00 ff ff 00 00 00 ff ff 00 34 00 cb
00000f0 ff 42 88 21 c4 00 00 00 00 ff ff 00 00 00 ff ff
0000100 00 34 00 cb ff 42 e8 21 5e 0f 00 00 00 ff ff 0a
0000110 f0 66 64 12 61 c0 15 dc e8 a0 48 bf 48 af 2a b3
0000120 20 c0 9b 95 0d c4 67 04 42 53 06 06 06 40 00 06
0000130 00 f9 ff 6d 01 00 00 00 00 42 e8 21 5e 0f 00 00
0000140 00 ff ff 0a f0 66 64 12 61 c0 15 dc e8 a0 48 bf
0000150 48 af 2a b3 20 c0 9b 95 0d c4 67 04 42 53 06 06
0000160 06 40 00 06 00 f9 ff 6d 01 00 00 00 00 50 4b 01
0000170 02 14 00 14 00 00 00 08 00 08 03 64 3c f9 f4 89
0000180 64 48 01 00 00 b8 01 00 00 07 00 00 00 00 00 00
0000190 00 00 00 00 00 00 00 00 00 00 00 72 2f 72 2e 7a
00001a0 69 70 50 4b 05 06 00 00 00 00 01 00 01 00 35 00
00001b0 00 00 6d 01 00 00 00 00`
	s = regexp.MustCompile(`[0-9a-f]{7}`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func returnRecursiveZip() (r io.ReaderAt, size int64) {
	b := rZipBytes()
	return bytes.NewReader(b), int64(len(b))
}

// biggestZipBytes returns the bytes of a zip file biggest.zip
// that contains a zip file bigger.zip that contains a zip file
// big.zip that contains big.file, which contains 2³²-1 zeros.
// The big.zip file is interesting because it has no zip64 header,
// much like the innermost zip files in the well-known 42.zip.
//
// biggest.zip was generated by changing isZip64 to use > uint32max
// instead of >= uint32max and then running this program:
//
//	package main
//
//	import (
//		"archive/zip"
//		"bytes"
//		"io"
//		"log"
//		"os"
//	)
//
//	type zeros struct{}
//
//	func (zeros) Read(b []byte) (int, error) {
//		clear(b)
//		return len(b), nil
//	}
//
//	func main() {
//		bigZip := makeZip("big.file", io.LimitReader(zeros{}, 1<<32-1))
//		if err := os.WriteFile("/tmp/big.zip", bigZip, 0666); err != nil {
//			log.Fatal(err)
//		}
//
//		biggerZip := makeZip("big.zip", bytes.NewReader(bigZip))
//		if err := os.WriteFile("/tmp/bigger.zip", biggerZip, 0666); err != nil {
//			log.Fatal(err)
//		}
//
//		biggestZip := makeZip("bigger.zip", bytes.NewReader(biggerZip))
//		if err := os.WriteFile("/tmp/biggest.zip", biggestZip, 0666); err != nil {
//			log.Fatal(err)
//		}
//	}
//
//	func makeZip(name string, r io.Reader) []byte {
//		var buf bytes.Buffer
//		w := zip.NewWriter(&buf)
//		wf, err := w.Create(name)
//		if err != nil {
//			log.Fatal(err)
//		}
//		if _, err = io.Copy(wf, r); err != nil {
//			log.Fatal(err)
//		}
//		if err := w.Close(); err != nil {
//			log.Fatal(err)
//		}
//		return buf.Bytes()
//	}
//
// The 4 GB of zeros compresses to 4 MB, which compresses to 20 kB,
// which compresses to 1252 bytes (in the hex dump below).
//
// It's here in hex for the same reason as rZipBytes above: to avoid
// problems with on-disk virus scanners or other zip processors.
func biggestZipBytes() []byte {
	s := `
0000000 50 4b 03 04 14 00 08 00 08 00 00 00 00 00 00 00
0000010 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 62 69
0000020 67 67 65 72 2e 7a 69 70 ec dc 6b 4c 53 67 18 07
0000030 f0 16 c5 ca 65 2e cb b8 94 20 61 1f 44 33 c7 cd
0000040 c0 86 4a b5 c0 62 8a 61 05 c6 cd 91 b2 54 8c 1b
0000050 63 8b 03 9c 1b 95 52 5a e3 a0 19 6c b2 05 59 44
0000060 64 9d 73 83 71 11 46 61 14 b9 1d 14 09 4a c3 60
0000070 2e 4c 6e a5 60 45 02 62 81 95 b6 94 9e 9e 77 e7
0000080 d0 43 b6 f8 71 df 96 3c e7 a4 69 ce bf cf e9 79
0000090 ce ef 79 3f bf f1 31 db b6 bb 31 76 92 e7 f3 07
00000a0 8b fc 9c ca cc 08 cc cb cc 5e d2 1c 88 d9 7e bb
00000b0 4f bb 3a 3f 75 f1 5d 7f 8f c2 68 67 77 8f 25 ff
00000c0 84 e2 93 2d ef a4 95 3d 71 4e 2c b9 b0 87 c3 be
00000d0 3d f8 a7 60 24 61 c5 ef ae 9e c8 6c 6d 4e 69 c8
00000e0 67 65 34 f8 37 76 2d 76 5c 54 f3 95 65 49 c7 0f
00000f0 18 71 4b 7e 5b 6a d1 79 47 61 41 b0 4e 2a 74 45
0000100 43 58 12 b2 5a a5 c6 7d 68 55 88 d4 98 75 18 6d
0000110 08 d1 1f 8f 5a 9e 96 ee 45 cf a4 84 4e 4b e8 50
0000120 a7 13 d9 06 de 52 81 97 36 b2 d7 b8 fc 2b 5f 55
0000130 23 1f 32 59 cf 30 27 fb e2 8a b9 de 45 dd 63 9c
0000140 4b b5 8b 96 4c 7a 62 62 cc a1 a7 cf fa f1 fe dd
0000150 54 62 11 bf 36 78 b3 c7 b1 b5 f2 61 4d 4e dd 66
0000160 32 2e e6 70 34 5f f4 c9 e6 6c 43 6f da 6b c6 c3
0000170 09 2c ce 09 57 7f d2 7e b4 23 ba 7c 1b 99 bc 22
0000180 3e f1 de 91 2f e3 9c 1b 82 cc c2 84 39 aa e6 de
0000190 b4 69 fc cc cb 72 a6 61 45 f0 d3 1d 26 19 7c 8d
00001a0 29 c8 66 02 be 77 6a f9 3d 34 79 17 19 c8 96 24
00001b0 a3 ac e4 dd 3b 1a 8e c6 fe 96 38 6b bf 67 5a 23
00001c0 f4 16 f4 e6 8a b4 fc c2 cd bf 95 66 1d bb 35 aa
00001d0 92 7d 66 d8 08 8d a5 1f 54 2a af 09 cf 61 ff d2
00001e0 85 9d 8f b6 d7 88 07 4a 86 03 db 64 f3 d9 92 73
00001f0 df ec a7 fc 23 4c 8d 83 79 63 2a d9 fd 8d b3 c8
0000200 8f 7e d4 19 85 e6 8d 1c 76 f0 8b 58 32 fd 9a d6
0000210 85 e2 48 ad c3 d5 60 6f 7e 22 dd ef 09 49 7c 7f
0000220 3a 45 c3 71 b7 df f3 4c 63 fb b5 d9 31 5f 6e d6
0000230 24 1d a4 4a fe 32 a7 5c 16 48 5c 3e 08 6b 8a d3
0000240 25 1d a2 12 a5 59 24 ea 20 5f 52 6d ad 94 db 6b
0000250 94 b9 5d eb 4b a7 5c 44 bb 1e f2 3c 6b cf 52 c9
0000260 e9 e5 ba 06 b9 c4 e5 0a d0 00 0d d0 00 0d d0 00
0000270 0d d0 00 0d d0 00 0d d0 00 0d d0 00 0d d0 00 0d
0000280 d0 00 0d d0 00 0d d0 00 0d d0 00 0d d0 00 0d d0
0000290 00 0d d0 00 0d d0 00 0d d0 00 0d d0 00 0d d0 00
00002a0 0d d0 00 cd ff 9e 46 86 fa a7 7d 3a 43 d7 8e 10
00002b0 52 e9 be e6 6e cf eb 9e 85 4d 65 ce cc 30 c1 44
00002c0 c0 4e af bc 9c 6c 4b a0 d7 54 ff 1d d5 5c 89 fb
00002d0 b5 34 7e c4 c2 9e f5 a0 f6 5b 7e 6e ca 73 c7 ef
00002e0 5d be de f9 e8 81 eb a5 0a a5 63 54 2c d7 1c d1
00002f0 89 17 85 f8 16 94 f2 8a b2 a3 f5 b6 6d df 75 cd
0000300 90 dd 64 bd 5d 55 4e f2 55 19 1b b7 cc ef 1b ea
0000310 2e 05 9c f4 aa 1e a8 cd a6 82 c7 59 0f 5e 9d e0
0000320 bb fc 6c d6 99 23 eb 36 ad c6 c5 e1 d8 e1 e2 3e
0000330 d9 90 5a f7 91 5d 6f bc 33 6d 98 47 d2 7c 2e 2f
0000340 99 a4 25 72 85 49 2c be 0b 5b af 8f e5 6e 81 a6
0000350 a3 5a 6f 39 53 3a ab 7a 8b 1e 26 f7 46 6c 7d 26
0000360 53 b3 22 31 94 d3 83 f2 18 4d f5 92 33 27 53 97
0000370 0f d3 e6 55 9c a6 c5 31 87 6f d3 f3 ae 39 6f 56
0000380 10 7b ab 7e d0 b4 ca f2 b8 05 be 3f 0e 6e 5a 75
0000390 ab 0c f5 37 0e ba 8e 75 71 7a aa ed 7a dd 6a 63
00003a0 be 9b a0 97 27 6a 6f e7 d3 8b c4 7c ec d3 91 56
00003b0 d9 ac 5e bf 16 42 2f 00 1f 93 a2 23 87 bd e2 59
00003c0 a0 de 1a 66 c8 62 eb 55 8f 91 17 b4 61 42 7a 50
00003d0 40 03 34 40 03 34 40 03 34 40 03 34 40 03 34 40
00003e0 03 34 40 03 34 40 03 34 40 03 34 40 03 34 40 03
00003f0 34 40 03 34 40 03 34 ff 85 86 90 8b ea 67 90 0d
0000400 e1 42 1b d2 61 d6 79 ec fd 3e 44 28 a4 51 6c 5c
0000410 fc d2 72 ca ba 82 18 46 16 61 cd 93 a9 0f d1 24
0000420 17 99 e2 2c 71 16 84 0c c8 7a 13 0f 9a 5e c5 f0
0000430 79 64 e2 12 4d c8 82 a1 81 19 2d aa 44 6d 87 54
0000440 84 71 c1 f6 d4 ca 25 8c 77 b9 08 c7 c8 5e 10 8a
0000450 8f 61 ed 8c ba 30 1f 79 9a c7 60 34 2b b9 8c f8
0000460 18 a6 83 1b e3 9f ad 79 fe fd 1b 8b f1 fc 41 6f
0000470 d4 13 1f e3 b8 83 ba 64 92 e7 eb e4 77 05 8f ba
0000480 fa 3b 00 00 ff ff 50 4b 07 08 a6 18 b1 91 5e 04
0000490 00 00 e4 47 00 00 50 4b 01 02 14 00 14 00 08 00
00004a0 08 00 00 00 00 00 a6 18 b1 91 5e 04 00 00 e4 47
00004b0 00 00 0a 00 00 00 00 00 00 00 00 00 00 00 00 00
00004c0 00 00 00 00 62 69 67 67 65 72 2e 7a 69 70 50 4b
00004d0 05 06 00 00 00 00 01 00 01 00 38 00 00 00 96 04
00004e0 00 00 00 00`
	s = regexp.MustCompile(`[0-9a-f]{7}`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func returnBigZipBytes() (r io.ReaderAt, size int64) {
	b := biggestZipBytes()
	for i := 0; i < 2; i++ {
		r, err := NewReader(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			panic(err)
		}
		f, err := r.File[0].Open()
		if err != nil {
			panic(err)
		}
		b, err = io.ReadAll(f)
		if err != nil {
			panic(err)
		}
	}
	return bytes.NewReader(b), int64(len(b))
}

func TestIssue8186(t *testing.T) {
	// Directory headers & data found in the TOC of a JAR file.
	dirEnts := []string{
		"PK\x01\x02\n\x00\n\x00\x00\b\x00\x004\x9d3?\xaa\x1b\x06\xf0\x81\x02\x00\x00\x81\x02\x00\x00-\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00res/drawable-xhdpi-v4/ic_actionbar_accept.png\xfe\xca\x00\x00\x00",
		"PK\x01\x02\n\x00\n\x00\x00\b\x00\x004\x9d3?\x90K\x89\xc7t\n\x00\x00t\n\x00\x00\x0e\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd1\x02\x00\x00resources.arsc\x00\x00\x00",
		"PK\x01\x02\x14\x00\x14\x00\b\b\b\x004\x9d3?\xff$\x18\xed3\x03\x00\x00\xb4\b\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00t\r\x00\x00AndroidManifest.xml",
		"PK\x01\x02\x14\x00\x14\x00\b\b\b\x004\x9d3?\x14\xc5K\xab\x192\x02\x00\xc8\xcd\x04\x00\v\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x10\x00\x00classes.dex",
		"PK\x01\x02\x14\x00\x14\x00\b\b\b\x004\x9d3?E\x96\nD\xac\x01\x00\x00P\x03\x00\x00&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:C\x02\x00res/layout/actionbar_set_wallpaper.xml",
		"PK\x01\x02\x14\x00\x14\x00\b\b\b\x004\x9d3?Ļ\x14\xe3\xd8\x01\x00\x00\xd8\x03\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:E\x02\x00res/layout/wallpaper_cropper.xml",
		"PK\x01\x02\x14\x00\x14\x00\b\b\b\x004\x9d3?}\xc1\x15\x9eZ\x01\x00\x00!\x02\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`G\x02\x00META-INF/MANIFEST.MF",
		"PK\x01\x02\x14\x00\x14\x00\b\b\b\x004\x9d3?\xe6\x98Ьo\x01\x00\x00\x84\x02\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfcH\x02\x00META-INF/CERT.SF",
		"PK\x01\x02\x14\x00\x14\x00\b\b\b\x004\x9d3?\xbfP\x96b\x86\x04\x00\x00\xb2\x06\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa9J\x02\x00META-INF/CERT.RSA",
	}
	for i, s := range dirEnts {
		var f File
		err := readDirectoryHeader(&f, strings.NewReader(s))
		if err != nil {
			t.Errorf("error reading #%d: %v", i, err)
		}
	}
}

// Verify we return ErrUnexpectedEOF when length is short.
func TestIssue10957(t *testing.T) {
	data := []byte("PK\x03\x040000000PK\x01\x0200000" +
		"0000000000000000000\x00" +
		"\x00\x00\x00\x00\x00000000000000PK\x01" +
		"\x020000000000000000000" +
		"00000\v\x00\x00\x00\x00\x00000000000" +
		"00000000000000PK\x01\x0200" +
		"00000000000000000000" +
		"00\v\x00\x00\x00\x00\x00000000000000" +
		"00000000000PK\x01\x020000<" +
		"0\x00\x0000000000000000\v\x00\v" +
		"\x00\x00\x00\x00\x0000000000\x00\x00\x00\x00000" +
		"00000000PK\x01\x0200000000" +
		"0000000000000000\v\x00\x00\x00" +
		"\x00\x0000PK\x05\x06000000\x05\x00\xfd\x00\x00\x00" +
		"\v\x00\x00\x00\x00\x00")
	z, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range z.File {
		r, err := f.Open()
		if err != nil {
			continue
		}
		if f.UncompressedSize64 < 1e6 {
			n, err := io.Copy(io.Discard, r)
			if i == 3 && err != io.ErrUnexpectedEOF {
				t.Errorf("File[3] error = %v; want io.ErrUnexpectedEOF", err)
			}
			if err == nil && uint64(n) != f.UncompressedSize64 {
				t.Errorf("file %d: bad size: copied=%d; want=%d", i, n, f.UncompressedSize64)
			}
		}
		r.Close()
	}
}

// Verify that this particular malformed zip file is rejected.
func TestIssue10956(t *testing.T) {
	data := []byte("PK\x06\x06PK\x06\a0000\x00\x00\x0
```