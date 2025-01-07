Response:
Let's break down the thought process to analyze the provided Go code for `tar_test.go`.

1. **Identify the Core Purpose:** The file name `tar_test.go` immediately suggests this code is for testing the `archive/tar` package in Go's standard library. This means its primary function is to verify the correct behavior of the `tar` package's functionalities.

2. **Scan for Key Test Functions:** Look for functions starting with `Test...`. These are the entry points for the different test cases. The names of these functions often hint at what they are testing. In this case, we see:
    * `TestSparseEntries`: Suggests testing the handling of sparse files within tar archives.
    * `TestFileInfoHeader`: Likely testing the creation of tar headers from `os.FileInfo`.
    * `TestFileInfoHeaderDir`: Similar to the above but specifically for directories.
    * `TestFileInfoHeaderSymlink`: Testing header creation for symbolic links.
    * `TestRoundTrip`:  A classic test to see if data can be written to and read back from a tar archive without modification.
    * `TestHeaderRoundTrip`: Focuses on testing the header information itself, ensuring it's correctly serialized and deserialized.
    * `TestHeaderAllowedFormats`:  Examines which tar formats (USTAR, PAX, GNU) can accommodate specific header attributes.
    * `TestFileInfoHeaderUseFileInfoNames`:  Likely tests how the `FileInfoHeader` function interacts with custom types that satisfy the `fs.FileInfo` interface.

3. **Analyze Helper Structures and Functions:**  Look for types and functions that support the test functions.
    * `testError`: A custom error type, probably used for clearer error reporting within the tests.
    * `fileOps` and `testFile`: These seem to be designed for testing file I/O operations in a controlled manner. The `testFile` type keeps track of expected read/write/seek operations.
    * `sparseEntry`:  Used specifically for the `TestSparseEntries` function, representing regions of data in sparse files.
    * `validateSparseEntries`, `alignSparseEntries`, `invertSparseEntries`:  Helper functions within the `TestSparseEntries` block, suggesting various aspects of sparse entry validation and manipulation are being tested.
    * `headerRoundTripTest`:  A struct used to organize test cases for `TestHeaderRoundTrip`.
    * `fileInfoNames`:  A struct implementing `fs.FileInfo`, used in `TestFileInfoHeaderUseFileInfoNames` to simulate custom file information.

4. **Examine Individual Test Cases:**  Dive deeper into each `Test...` function to understand the specific scenarios being tested.
    * **`TestSparseEntries`:** The `vectors` slice contains test cases with different sparse entry configurations, sizes, and expected outcomes for validation, alignment, and inversion.
    * **`TestFileInfoHeader` family:** These tests use `os.Stat` and `os.Lstat` to get file information and then call `FileInfoHeader` to create tar headers. They compare the generated header fields with expected values.
    * **`TestRoundTrip`:** This test creates a tar archive in memory, writes a header and data, and then reads it back, comparing the original and read data and header.
    * **`TestHeaderRoundTrip`:** This test has a `vectors` slice defining different header configurations and their corresponding `fs.FileMode`. It verifies that converting a header to `FileInfo` and back to a header preserves the relevant information.
    * **`TestHeaderAllowedFormats`:**  This test checks if the `allowedFormats` method on the `Header` struct correctly identifies which tar formats can represent a given header and if it generates the expected PAX headers.
    * **`TestFileInfoHeaderUseFileInfoNames`:** This test uses the custom `fileInfoNames` type to check if `FileInfoHeader` correctly uses the `Uname` and `Gname` methods from the `fs.FileInfo` interface.

5. **Look for Benchmarks:** The `Benchmark` function tests the performance of the `tar` writer and reader. It defines different tar archive structures (USTAR, GNU, PAX) and measures the time it takes to write and read them.

6. **Infer Go Language Features:** Based on the code, identify the Go features being demonstrated and tested:
    * **Standard Library Usage:** Heavy use of `io`, `bytes`, `os`, `path/filepath`, `time`, `reflect`, `testing`.
    * **Interfaces:**  Demonstrates and tests the interaction with the `fs.FileInfo` interface.
    * **Structs and Methods:**  Extensive use of structs to represent data and methods to operate on that data (e.g., `Header`, `testFile`).
    * **Slices:** Used extensively for test vectors and storing file operations.
    * **Error Handling:** Using the `error` interface and custom error types.
    * **Benchmarking:**  Utilizing the `testing.B` type for performance measurements.
    * **Conditional Compilation (`internal/testenv`):**  The `testenv.MustHaveSymlink(t)` call indicates the use of build constraints or internal testing utilities.

7. **Identify Potential Pitfalls:** Based on the tests and the functionality being tested, think about common mistakes users might make. For example, the tests around header formats highlight that not all header information can be represented in all tar formats.

8. **Structure the Answer:** Organize the findings into logical sections (functionality, Go features, code examples, command-line arguments, common mistakes). Use clear and concise language. Provide code examples where applicable, keeping them simple and illustrative.

By following this thought process, you can systematically analyze the code and generate a comprehensive answer that covers the key aspects of its functionality, the Go language features it demonstrates, and potential user pitfalls.
这段代码是 Go 语言 `archive/tar` 标准库的一部分，它的主要功能是 **测试 `tar` 包的各项功能**。更具体地说，它包含了针对 `tar` 包中读取和写入 tar 档案的功能的各种单元测试。

下面我将详细列举它的功能，并用 Go 代码举例说明一些关键的实现，以及进行一些代码推理。

**1. 测试稀疏文件条目 (Sparse Entries)**

这段代码测试了 `tar` 包中处理稀疏文件条目的功能。稀疏文件是指文件中包含大量零字节的区域，为了节省空间，tar 格式允许记录这些非零字节的区域。

* **`TestSparseEntries(t *testing.T)` 函数：**  这个函数定义了一系列测试用例 (`vectors`)，每个用例包含不同的稀疏条目配置 (`in`) 和文件大小 (`size`)。
* **`sparseEntry` 结构体：**  代表一个稀疏文件的非零数据块，包含起始偏移量和长度。
* **`validateSparseEntries`， `alignSparseEntries`， `invertSparseEntries` 函数：** 这些函数（虽然没有在提供的代码片段中完整展示，但根据测试用例可以推断出其功能）分别用于验证稀疏条目的合法性，将稀疏条目按块大小对齐，以及计算稀疏文件的“空洞”区域。

**代码推理和示例：**

假设我们有一个大小为 5000 字节的文件，其中从 1000 字节到 4999 字节是有效数据，其余部分是空洞。我们可以用一个稀疏条目 `{1000, 4000}` 来表示。

```go
package main

import (
	"archive/tar"
	"fmt"
	"reflect"
	"testing"
)

func validateSparseEntries(in []tar.SparseEntry, size int64) bool {
	// 假设的 validateSparseEntries 实现，实际实现可能更复杂
	if size < 0 {
		return false
	}
	var currentOffset int64 = 0
	for _, entry := range in {
		if entry.Offset < currentOffset || entry.Offset+entry.Length > size || entry.Offset < 0 || entry.Length < 0 {
			return false
		}
		currentOffset = entry.Offset + entry.Length
	}
	return currentOffset <= size
}

func main() {
	// 测试用例
	input := []tar.SparseEntry{{Offset: 1000, Length: 4000}}
	fileSize := int64(5000)

	isValid := validateSparseEntries(input, fileSize)
	fmt.Println("稀疏条目是否合法:", isValid) // 输出: 稀疏条目是否合法: true

	// 使用 testing 包进行断言（在实际的 tar_test.go 中）
	// t := &testing.T{}
	// if !validateSparseEntries(input, fileSize) {
	// 	t.Errorf("稀疏条目验证失败")
	// }
}
```

**假设的输入与输出：**

* **输入:** `in = []tar.SparseEntry{{Offset: 1000, Length: 4000}}`, `size = 5000`
* **输出 (validateSparseEntries):** `true` (因为偏移量和长度都在文件大小范围内)

**2. 测试从 `os.FileInfo` 创建 Tar 头部信息 (Header)**

代码测试了 `FileInfoHeader` 函数，该函数根据 `os.FileInfo` 接口的实现来创建一个 `tar.Header` 结构体。

* **`TestFileInfoHeader(t *testing.T)`， `TestFileInfoHeaderDir(t *testing.T)`， `TestFileInfoHeaderSymlink(t *testing.T)` 函数：** 这些函数分别测试了从普通文件、目录和符号链接的 `os.FileInfo` 创建头部信息的情况。

**代码示例：**

```go
package main

import (
	"archive/tar"
	"fmt"
	"os"
	"testing"
)

func main() {
	t := &testing.T{} // 模拟 testing.T

	// 假设存在一个名为 "testdata/small.txt" 的文件
	fileInfo, err := os.Stat("testdata/small.txt")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	header, err := tar.FileInfoHeader(fileInfo, "")
	if err != nil {
		fmt.Println("FileInfoHeader Error:", err)
		return
	}

	fmt.Printf("文件名: %s\n", header.Name)
	fmt.Printf("文件大小: %d\n", header.Size)
	fmt.Printf("文件权限: %o\n", header.Mode)

	// 在实际的测试中会进行更严格的断言
	if header.Name != "small.txt" {
		t.Errorf("文件名不匹配，期望: %s, 实际: %s", "small.txt", header.Name)
	}
	// ... 其他断言
}
```

**假设的输入与输出：**

* **假设 `testdata/small.txt` 存在，内容为 "hello"，权限为 0644。**
* **输出 (部分):**
  ```
  文件名: small.txt
  文件大小: 5
  文件权限: 644
  ```

**3. 测试 Tar 档案的读写循环 (Round Trip)**

`TestRoundTrip` 函数测试了将数据写入 tar 档案，然后再读取出来的过程，以验证写入和读取功能的正确性。

**代码示例：**

```go
package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"
)

func main() {
	t := &testing.T{} // 模拟 testing.T

	data := []byte("some file contents")
	var buffer bytes.Buffer
	tarWriter := tar.NewWriter(&buffer)

	header := &tar.Header{
		Name:    "file.txt",
		Size:    int64(len(data)),
		ModTime: time.Now().Round(time.Second),
		Format:  tar.FormatPAX,
		Typeflag: tar.TypeReg,
	}

	err := tarWriter.WriteHeader(header)
	if err != nil {
		fmt.Println("WriteHeader Error:", err)
		return
	}

	_, err = tarWriter.Write(data)
	if err != nil {
		fmt.Println("Write Error:", err)
		return
	}

	err = tarWriter.Close()
	if err != nil {
		fmt.Println("Close Error:", err)
		return
	}

	// 读取档案
	tarReader := tar.NewReader(&buffer)
	readHeader, err := tarReader.Next()
	if err != nil {
		fmt.Println("Next Error:", err)
		return
	}

	readData, err := io.ReadAll(tarReader)
	if err != nil {
		fmt.Println("ReadAll Error:", err)
		return
	}

	fmt.Println("读取到的文件名:", readHeader.Name)
	fmt.Println("读取到的内容:", string(readData))

	// 在实际测试中进行断言
	if !reflect.DeepEqual(readHeader, header) {
		t.Errorf("头部信息不匹配")
	}
	if !bytes.Equal(readData, data) {
		t.Errorf("数据内容不匹配")
	}
}
```

**假设的输入与输出：**

* **输入:**  创建一个包含名为 "file.txt"，内容为 "some file contents" 的 tar 档案。
* **输出 (部分):**
  ```
  读取到的文件名: file.txt
  读取到的内容: some file contents
  ```

**4. 测试 Tar 头部信息的循环 (Header Round Trip)**

`TestHeaderRoundTrip` 函数测试了 `tar.Header` 结构体的序列化和反序列化过程，确保头部信息在转换过程中不会丢失或损坏。

**5. 测试头部信息允许的格式 (Allowed Formats)**

`TestHeaderAllowedFormats` 函数测试了 `Header` 结构体的 `allowedFormats` 方法，该方法用于确定哪些 tar 格式（如 USTAR, PAX, GNU）可以表示给定的头部信息。这涉及到检查头部信息的字段是否超出了特定格式的限制。

**6. 基准测试 (Benchmark)**

`Benchmark` 函数用于测试 `tar` 包的读写性能，通过多次执行读写操作来测量性能指标。

**7. `testFile` 结构体和相关方法**

* **`testFile` 结构体：**  这是一个自定义的 `io.ReadWriteSeeker` 实现，用于模拟文件操作，并在操作过程中记录和校验执行的操作序列。
* **`Read`， `Write`， `Seek` 方法：** 这些方法实现了 `io.ReadWriteSeeker` 接口，但它们不是直接对真实文件进行操作，而是根据预定义的 `ops` (操作序列) 进行模拟，用于更精确地控制测试过程。

**代码推理和示例：**

`testFile` 的目的是为了确保 `tar` 包在读写过程中执行了预期的文件操作。例如，我们可以创建一个 `testFile` 实例，期望它先读取一定数量的字节，然后 Seek 到某个位置，再写入一些数据。

```go
package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"strings"
)

type fileOps []interface{} // 允许字符串 (Read/Write 数据) 或 int64 (Seek 偏移量)

type testFile struct {
	ops fileOps
	pos int64
}

func (f *testFile) Read(b []byte) (int, error) {
	if len(f.ops) == 0 {
		return 0, io.EOF
	}
	s, ok := f.ops[0].(string)
	if !ok {
		return 0, errors.New("unexpected Read operation")
	}
	n := copy(b, s)
	if len(s) > n {
		f.ops[0] = s[n:]
	} else {
		f.ops = f.ops[1:]
	}
	f.pos += int64(n)
	return n, nil
}

func (f *testFile) Write(b []byte) (int, error) {
	// ... (类似 Read 的实现，用于校验写入内容)
	if len(f.ops) == 0 {
		return 0, errors.New("unexpected Write operation")
	}
	s, ok := f.ops[0].(string)
	if !ok {
		return 0, errors.New("unexpected Write operation")
	}
	if !strings.HasPrefix(s, string(b)) {
		return 0, fmt.Errorf("got Write(%q), want prefix %q", b, s)
	}
	n := len(b)
	if len(s) > n {
		f.ops[0] = s[n:]
	} else {
		f.ops = f.ops[1:]
	}
	f.pos += int64(n)
	return n, nil
}

func (f *testFile) Seek(offset int64, whence int) (int64, error) {
	if len(f.ops) == 0 {
		return 0, errors.New("unexpected Seek operation")
	}
	expectedOffset, ok := f.ops[0].(int64)
	if !ok || whence != io.SeekCurrent || offset != expectedOffset {
		return 0, fmt.Errorf("got Seek(%d, %d), want Seek(%d, %d)", offset, whence, expectedOffset, io.SeekCurrent)
	}
	f.pos += offset
	f.ops = f.ops[1:]
	return f.pos, nil
}

func main() {
	// 期望先读取 "hello"，然后 Seek 到偏移量 5
	tf := &testFile{ops: fileOps{"hello", int64(5)}}

	buffer := make([]byte, 5)
	n, err := tf.Read(buffer)
	fmt.Printf("读取了 %d 字节: %s, 错误: %v\n", n, string(buffer[:n]), err)

	newPos, err := tf.Seek(5, io.SeekCurrent)
	fmt.Printf("Seeked to position: %d, 错误: %v\n", newPos, err)
}
```

**假设的输入与输出：**

* **输入:** 创建 `testFile`，期望先读取 "hello"，然后 Seek(5, io.SeekCurrent)。
* **输出:**
  ```
  读取了 5 字节: hello, 错误: <nil>
  Seeked to position: 5, 错误: <nil>
  ```

**命令行参数的具体处理：**

这段代码主要是单元测试，并不直接处理命令行参数。`go test` 命令会执行这些测试，可以通过一些标志（flags）来控制测试的执行，例如：

* `-v`:  显示详细的测试输出。
* `-run <regexp>`:  只运行名称匹配正则表达式的测试。
* `-bench <regexp>`:  运行基准测试。

**使用者易犯错的点：**

虽然这段代码是测试代码，但从中可以推断出使用 `archive/tar` 包时的一些常见错误：

1. **不正确的头部信息设置：**  例如，文件名、大小、权限等信息不正确，可能导致解压失败或文件内容错误。
2. **处理稀疏文件不当：**  如果创建或解压稀疏文件时没有正确处理稀疏条目，可能会导致文件大小不一致或数据丢失。
3. **不兼容的 Tar 格式：**  不同的 Tar 格式（USTAR, PAX, GNU）对头部信息的限制不同。如果头部信息超出了目标格式的限制，可能会导致信息丢失或解析错误。`TestHeaderAllowedFormats` 就在测试这方面的问题。例如，文件名过长在 USTAR 格式中会被截断，但在 PAX 格式中可以通过扩展头部来存储。
4. **修改已经写入的 `tar.Writer`：**  在调用 `WriteHeader` 之后，不能随意修改 `Header` 结构体的内容，因为这可能会导致写入的头部信息与实际数据不符。
5. **忘记调用 `tar.Writer.Close()`：**  这会导致部分数据没有被刷新到输出流中，造成 Tar 档案不完整。
6. **读取 Tar 档案时未处理 `io.EOF` 错误：**  `tar.Reader.Next()` 在读取完所有头部信息后会返回 `io.EOF`，需要正确处理这个错误以结束读取循环。

总而言之，这段 `tar_test.go` 代码通过各种测试用例，细致地验证了 `archive/tar` 包的各项功能，确保了在不同场景下 `tar` 包的正确性和健壮性。理解这些测试用例也有助于我们更好地理解和使用 `archive/tar` 包。

Prompt: 
```
这是路径为go/src/archive/tar/tar_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tar

import (
	"bytes"
	"errors"
	"fmt"
	"internal/testenv"
	"io"
	"io/fs"
	"maps"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

type testError struct{ error }

type fileOps []any // []T where T is (string | int64)

// testFile is an io.ReadWriteSeeker where the IO operations performed
// on it must match the list of operations in ops.
type testFile struct {
	ops fileOps
	pos int64
}

func (f *testFile) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(f.ops) == 0 {
		return 0, io.EOF
	}
	s, ok := f.ops[0].(string)
	if !ok {
		return 0, errors.New("unexpected Read operation")
	}

	n := copy(b, s)
	if len(s) > n {
		f.ops[0] = s[n:]
	} else {
		f.ops = f.ops[1:]
	}
	f.pos += int64(len(b))
	return n, nil
}

func (f *testFile) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(f.ops) == 0 {
		return 0, errors.New("unexpected Write operation")
	}
	s, ok := f.ops[0].(string)
	if !ok {
		return 0, errors.New("unexpected Write operation")
	}

	if !strings.HasPrefix(s, string(b)) {
		return 0, testError{fmt.Errorf("got Write(%q), want Write(%q)", b, s)}
	}
	if len(s) > len(b) {
		f.ops[0] = s[len(b):]
	} else {
		f.ops = f.ops[1:]
	}
	f.pos += int64(len(b))
	return len(b), nil
}

func (f *testFile) Seek(pos int64, whence int) (int64, error) {
	if pos == 0 && whence == io.SeekCurrent {
		return f.pos, nil
	}
	if len(f.ops) == 0 {
		return 0, errors.New("unexpected Seek operation")
	}
	s, ok := f.ops[0].(int64)
	if !ok {
		return 0, errors.New("unexpected Seek operation")
	}

	if s != pos || whence != io.SeekCurrent {
		return 0, testError{fmt.Errorf("got Seek(%d, %d), want Seek(%d, %d)", pos, whence, s, io.SeekCurrent)}
	}
	f.pos += s
	f.ops = f.ops[1:]
	return f.pos, nil
}

func TestSparseEntries(t *testing.T) {
	vectors := []struct {
		in   []sparseEntry
		size int64

		wantValid    bool          // Result of validateSparseEntries
		wantAligned  []sparseEntry // Result of alignSparseEntries
		wantInverted []sparseEntry // Result of invertSparseEntries
	}{{
		in: []sparseEntry{}, size: 0,
		wantValid:    true,
		wantInverted: []sparseEntry{{0, 0}},
	}, {
		in: []sparseEntry{}, size: 5000,
		wantValid:    true,
		wantInverted: []sparseEntry{{0, 5000}},
	}, {
		in: []sparseEntry{{0, 5000}}, size: 5000,
		wantValid:    true,
		wantAligned:  []sparseEntry{{0, 5000}},
		wantInverted: []sparseEntry{{5000, 0}},
	}, {
		in: []sparseEntry{{1000, 4000}}, size: 5000,
		wantValid:    true,
		wantAligned:  []sparseEntry{{1024, 3976}},
		wantInverted: []sparseEntry{{0, 1000}, {5000, 0}},
	}, {
		in: []sparseEntry{{0, 3000}}, size: 5000,
		wantValid:    true,
		wantAligned:  []sparseEntry{{0, 2560}},
		wantInverted: []sparseEntry{{3000, 2000}},
	}, {
		in: []sparseEntry{{3000, 2000}}, size: 5000,
		wantValid:    true,
		wantAligned:  []sparseEntry{{3072, 1928}},
		wantInverted: []sparseEntry{{0, 3000}, {5000, 0}},
	}, {
		in: []sparseEntry{{2000, 2000}}, size: 5000,
		wantValid:    true,
		wantAligned:  []sparseEntry{{2048, 1536}},
		wantInverted: []sparseEntry{{0, 2000}, {4000, 1000}},
	}, {
		in: []sparseEntry{{0, 2000}, {8000, 2000}}, size: 10000,
		wantValid:    true,
		wantAligned:  []sparseEntry{{0, 1536}, {8192, 1808}},
		wantInverted: []sparseEntry{{2000, 6000}, {10000, 0}},
	}, {
		in: []sparseEntry{{0, 2000}, {2000, 2000}, {4000, 0}, {4000, 3000}, {7000, 1000}, {8000, 0}, {8000, 2000}}, size: 10000,
		wantValid:    true,
		wantAligned:  []sparseEntry{{0, 1536}, {2048, 1536}, {4096, 2560}, {7168, 512}, {8192, 1808}},
		wantInverted: []sparseEntry{{10000, 0}},
	}, {
		in: []sparseEntry{{0, 0}, {1000, 0}, {2000, 0}, {3000, 0}, {4000, 0}, {5000, 0}}, size: 5000,
		wantValid:    true,
		wantInverted: []sparseEntry{{0, 5000}},
	}, {
		in: []sparseEntry{{1, 0}}, size: 0,
		wantValid: false,
	}, {
		in: []sparseEntry{{-1, 0}}, size: 100,
		wantValid: false,
	}, {
		in: []sparseEntry{{0, -1}}, size: 100,
		wantValid: false,
	}, {
		in: []sparseEntry{{0, 0}}, size: -100,
		wantValid: false,
	}, {
		in: []sparseEntry{{math.MaxInt64, 3}, {6, -5}}, size: 35,
		wantValid: false,
	}, {
		in: []sparseEntry{{1, 3}, {6, -5}}, size: 35,
		wantValid: false,
	}, {
		in: []sparseEntry{{math.MaxInt64, math.MaxInt64}}, size: math.MaxInt64,
		wantValid: false,
	}, {
		in: []sparseEntry{{3, 3}}, size: 5,
		wantValid: false,
	}, {
		in: []sparseEntry{{2, 0}, {1, 0}, {0, 0}}, size: 3,
		wantValid: false,
	}, {
		in: []sparseEntry{{1, 3}, {2, 2}}, size: 10,
		wantValid: false,
	}}

	for i, v := range vectors {
		gotValid := validateSparseEntries(v.in, v.size)
		if gotValid != v.wantValid {
			t.Errorf("test %d, validateSparseEntries() = %v, want %v", i, gotValid, v.wantValid)
		}
		if !v.wantValid {
			continue
		}
		gotAligned := alignSparseEntries(append([]sparseEntry{}, v.in...), v.size)
		if !slices.Equal(gotAligned, v.wantAligned) {
			t.Errorf("test %d, alignSparseEntries():\ngot  %v\nwant %v", i, gotAligned, v.wantAligned)
		}
		gotInverted := invertSparseEntries(append([]sparseEntry{}, v.in...), v.size)
		if !slices.Equal(gotInverted, v.wantInverted) {
			t.Errorf("test %d, inverseSparseEntries():\ngot  %v\nwant %v", i, gotInverted, v.wantInverted)
		}
	}
}

func TestFileInfoHeader(t *testing.T) {
	fi, err := os.Stat("testdata/small.txt")
	if err != nil {
		t.Fatal(err)
	}
	h, err := FileInfoHeader(fi, "")
	if err != nil {
		t.Fatalf("FileInfoHeader: %v", err)
	}
	if g, e := h.Name, "small.txt"; g != e {
		t.Errorf("Name = %q; want %q", g, e)
	}
	if g, e := h.Mode, int64(fi.Mode().Perm()); g != e {
		t.Errorf("Mode = %#o; want %#o", g, e)
	}
	if g, e := h.Size, int64(5); g != e {
		t.Errorf("Size = %v; want %v", g, e)
	}
	if g, e := h.ModTime, fi.ModTime(); !g.Equal(e) {
		t.Errorf("ModTime = %v; want %v", g, e)
	}
	// FileInfoHeader should error when passing nil FileInfo
	if _, err := FileInfoHeader(nil, ""); err == nil {
		t.Fatalf("Expected error when passing nil to FileInfoHeader")
	}
}

func TestFileInfoHeaderDir(t *testing.T) {
	fi, err := os.Stat("testdata")
	if err != nil {
		t.Fatal(err)
	}
	h, err := FileInfoHeader(fi, "")
	if err != nil {
		t.Fatalf("FileInfoHeader: %v", err)
	}
	if g, e := h.Name, "testdata/"; g != e {
		t.Errorf("Name = %q; want %q", g, e)
	}
	// Ignoring c_ISGID for golang.org/issue/4867
	if g, e := h.Mode&^c_ISGID, int64(fi.Mode().Perm()); g != e {
		t.Errorf("Mode = %#o; want %#o", g, e)
	}
	if g, e := h.Size, int64(0); g != e {
		t.Errorf("Size = %v; want %v", g, e)
	}
	if g, e := h.ModTime, fi.ModTime(); !g.Equal(e) {
		t.Errorf("ModTime = %v; want %v", g, e)
	}
}

func TestFileInfoHeaderSymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)

	tmpdir := t.TempDir()

	link := filepath.Join(tmpdir, "link")
	target := tmpdir
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}

	h, err := FileInfoHeader(fi, target)
	if err != nil {
		t.Fatal(err)
	}
	if g, e := h.Name, fi.Name(); g != e {
		t.Errorf("Name = %q; want %q", g, e)
	}
	if g, e := h.Linkname, target; g != e {
		t.Errorf("Linkname = %q; want %q", g, e)
	}
	if g, e := h.Typeflag, byte(TypeSymlink); g != e {
		t.Errorf("Typeflag = %v; want %v", g, e)
	}
}

func TestRoundTrip(t *testing.T) {
	data := []byte("some file contents")

	var b bytes.Buffer
	tw := NewWriter(&b)
	hdr := &Header{
		Name:       "file.txt",
		Uid:        1 << 21, // Too big for 8 octal digits
		Size:       int64(len(data)),
		ModTime:    time.Now().Round(time.Second),
		PAXRecords: map[string]string{"uid": "2097152"},
		Format:     FormatPAX,
		Typeflag:   TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tw.WriteHeader: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("tw.Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}

	// Read it back.
	tr := NewReader(&b)
	rHdr, err := tr.Next()
	if err != nil {
		t.Fatalf("tr.Next: %v", err)
	}
	if !reflect.DeepEqual(rHdr, hdr) {
		t.Errorf("Header mismatch.\n got %+v\nwant %+v", rHdr, hdr)
	}
	rData, err := io.ReadAll(tr)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(rData, data) {
		t.Errorf("Data mismatch.\n got %q\nwant %q", rData, data)
	}
}

type headerRoundTripTest struct {
	h  *Header
	fm fs.FileMode
}

func TestHeaderRoundTrip(t *testing.T) {
	vectors := []headerRoundTripTest{{
		// regular file.
		h: &Header{
			Name:     "test.txt",
			Mode:     0644,
			Size:     12,
			ModTime:  time.Unix(1360600916, 0),
			Typeflag: TypeReg,
		},
		fm: 0644,
	}, {
		// symbolic link.
		h: &Header{
			Name:     "link.txt",
			Mode:     0777,
			Size:     0,
			ModTime:  time.Unix(1360600852, 0),
			Typeflag: TypeSymlink,
		},
		fm: 0777 | fs.ModeSymlink,
	}, {
		// character device node.
		h: &Header{
			Name:     "dev/null",
			Mode:     0666,
			Size:     0,
			ModTime:  time.Unix(1360578951, 0),
			Typeflag: TypeChar,
		},
		fm: 0666 | fs.ModeDevice | fs.ModeCharDevice,
	}, {
		// block device node.
		h: &Header{
			Name:     "dev/sda",
			Mode:     0660,
			Size:     0,
			ModTime:  time.Unix(1360578954, 0),
			Typeflag: TypeBlock,
		},
		fm: 0660 | fs.ModeDevice,
	}, {
		// directory.
		h: &Header{
			Name:     "dir/",
			Mode:     0755,
			Size:     0,
			ModTime:  time.Unix(1360601116, 0),
			Typeflag: TypeDir,
		},
		fm: 0755 | fs.ModeDir,
	}, {
		// fifo node.
		h: &Header{
			Name:     "dev/initctl",
			Mode:     0600,
			Size:     0,
			ModTime:  time.Unix(1360578949, 0),
			Typeflag: TypeFifo,
		},
		fm: 0600 | fs.ModeNamedPipe,
	}, {
		// setuid.
		h: &Header{
			Name:     "bin/su",
			Mode:     0755 | c_ISUID,
			Size:     23232,
			ModTime:  time.Unix(1355405093, 0),
			Typeflag: TypeReg,
		},
		fm: 0755 | fs.ModeSetuid,
	}, {
		// setguid.
		h: &Header{
			Name:     "group.txt",
			Mode:     0750 | c_ISGID,
			Size:     0,
			ModTime:  time.Unix(1360602346, 0),
			Typeflag: TypeReg,
		},
		fm: 0750 | fs.ModeSetgid,
	}, {
		// sticky.
		h: &Header{
			Name:     "sticky.txt",
			Mode:     0600 | c_ISVTX,
			Size:     7,
			ModTime:  time.Unix(1360602540, 0),
			Typeflag: TypeReg,
		},
		fm: 0600 | fs.ModeSticky,
	}, {
		// hard link.
		h: &Header{
			Name:     "hard.txt",
			Mode:     0644,
			Size:     0,
			Linkname: "file.txt",
			ModTime:  time.Unix(1360600916, 0),
			Typeflag: TypeLink,
		},
		fm: 0644,
	}, {
		// More information.
		h: &Header{
			Name:     "info.txt",
			Mode:     0600,
			Size:     0,
			Uid:      1000,
			Gid:      1000,
			ModTime:  time.Unix(1360602540, 0),
			Uname:    "slartibartfast",
			Gname:    "users",
			Typeflag: TypeReg,
		},
		fm: 0600,
	}}

	for i, v := range vectors {
		fi := v.h.FileInfo()
		h2, err := FileInfoHeader(fi, "")
		if err != nil {
			t.Error(err)
			continue
		}
		if strings.Contains(fi.Name(), "/") {
			t.Errorf("FileInfo of %q contains slash: %q", v.h.Name, fi.Name())
		}
		name := path.Base(v.h.Name)
		if fi.IsDir() {
			name += "/"
		}
		if got, want := h2.Name, name; got != want {
			t.Errorf("i=%d: Name: got %v, want %v", i, got, want)
		}
		if got, want := h2.Size, v.h.Size; got != want {
			t.Errorf("i=%d: Size: got %v, want %v", i, got, want)
		}
		if got, want := h2.Uid, v.h.Uid; got != want {
			t.Errorf("i=%d: Uid: got %d, want %d", i, got, want)
		}
		if got, want := h2.Gid, v.h.Gid; got != want {
			t.Errorf("i=%d: Gid: got %d, want %d", i, got, want)
		}
		if got, want := h2.Uname, v.h.Uname; got != want {
			t.Errorf("i=%d: Uname: got %q, want %q", i, got, want)
		}
		if got, want := h2.Gname, v.h.Gname; got != want {
			t.Errorf("i=%d: Gname: got %q, want %q", i, got, want)
		}
		if got, want := h2.Linkname, v.h.Linkname; got != want {
			t.Errorf("i=%d: Linkname: got %v, want %v", i, got, want)
		}
		if got, want := h2.Typeflag, v.h.Typeflag; got != want {
			t.Logf("%#v %#v", v.h, fi.Sys())
			t.Errorf("i=%d: Typeflag: got %q, want %q", i, got, want)
		}
		if got, want := h2.Mode, v.h.Mode; got != want {
			t.Errorf("i=%d: Mode: got %o, want %o", i, got, want)
		}
		if got, want := fi.Mode(), v.fm; got != want {
			t.Errorf("i=%d: fi.Mode: got %o, want %o", i, got, want)
		}
		if got, want := h2.AccessTime, v.h.AccessTime; got != want {
			t.Errorf("i=%d: AccessTime: got %v, want %v", i, got, want)
		}
		if got, want := h2.ChangeTime, v.h.ChangeTime; got != want {
			t.Errorf("i=%d: ChangeTime: got %v, want %v", i, got, want)
		}
		if got, want := h2.ModTime, v.h.ModTime; got != want {
			t.Errorf("i=%d: ModTime: got %v, want %v", i, got, want)
		}
		if sysh, ok := fi.Sys().(*Header); !ok || sysh != v.h {
			t.Errorf("i=%d: Sys didn't return original *Header", i)
		}
	}
}

func TestHeaderAllowedFormats(t *testing.T) {
	vectors := []struct {
		header  *Header           // Input header
		paxHdrs map[string]string // Expected PAX headers that may be needed
		formats Format            // Expected formats that can encode the header
	}{{
		header:  &Header{},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{Size: 077777777777},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{Size: 077777777777, Format: FormatUSTAR},
		formats: FormatUSTAR,
	}, {
		header:  &Header{Size: 077777777777, Format: FormatPAX},
		formats: FormatUSTAR | FormatPAX,
	}, {
		header:  &Header{Size: 077777777777, Format: FormatGNU},
		formats: FormatGNU,
	}, {
		header:  &Header{Size: 077777777777 + 1},
		paxHdrs: map[string]string{paxSize: "8589934592"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{Size: 077777777777 + 1, Format: FormatPAX},
		paxHdrs: map[string]string{paxSize: "8589934592"},
		formats: FormatPAX,
	}, {
		header:  &Header{Size: 077777777777 + 1, Format: FormatGNU},
		paxHdrs: map[string]string{paxSize: "8589934592"},
		formats: FormatGNU,
	}, {
		header:  &Header{Mode: 07777777},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{Mode: 07777777 + 1},
		formats: FormatGNU,
	}, {
		header:  &Header{Devmajor: -123},
		formats: FormatGNU,
	}, {
		header:  &Header{Devmajor: 1<<56 - 1},
		formats: FormatGNU,
	}, {
		header:  &Header{Devmajor: 1 << 56},
		formats: FormatUnknown,
	}, {
		header:  &Header{Devmajor: -1 << 56},
		formats: FormatGNU,
	}, {
		header:  &Header{Devmajor: -1<<56 - 1},
		formats: FormatUnknown,
	}, {
		header:  &Header{Name: "用戶名", Devmajor: -1 << 56},
		formats: FormatGNU,
	}, {
		header:  &Header{Size: math.MaxInt64},
		paxHdrs: map[string]string{paxSize: "9223372036854775807"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{Size: math.MinInt64},
		paxHdrs: map[string]string{paxSize: "-9223372036854775808"},
		formats: FormatUnknown,
	}, {
		header:  &Header{Uname: "0123456789abcdef0123456789abcdef"},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{Uname: "0123456789abcdef0123456789abcdefx"},
		paxHdrs: map[string]string{paxUname: "0123456789abcdef0123456789abcdefx"},
		formats: FormatPAX,
	}, {
		header:  &Header{Name: "foobar"},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{Name: strings.Repeat("a", nameSize)},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{Name: strings.Repeat("a", nameSize+1)},
		paxHdrs: map[string]string{paxPath: strings.Repeat("a", nameSize+1)},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{Linkname: "用戶名"},
		paxHdrs: map[string]string{paxLinkpath: "用戶名"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{Linkname: strings.Repeat("用戶名\x00", nameSize)},
		paxHdrs: map[string]string{paxLinkpath: strings.Repeat("用戶名\x00", nameSize)},
		formats: FormatUnknown,
	}, {
		header:  &Header{Linkname: "\x00hello"},
		paxHdrs: map[string]string{paxLinkpath: "\x00hello"},
		formats: FormatUnknown,
	}, {
		header:  &Header{Uid: 07777777},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{Uid: 07777777 + 1},
		paxHdrs: map[string]string{paxUid: "2097152"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{Xattrs: nil},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{Xattrs: map[string]string{"foo": "bar"}},
		paxHdrs: map[string]string{paxSchilyXattr + "foo": "bar"},
		formats: FormatPAX,
	}, {
		header:  &Header{Xattrs: map[string]string{"foo": "bar"}, Format: FormatGNU},
		paxHdrs: map[string]string{paxSchilyXattr + "foo": "bar"},
		formats: FormatUnknown,
	}, {
		header:  &Header{Xattrs: map[string]string{"用戶名": "\x00hello"}},
		paxHdrs: map[string]string{paxSchilyXattr + "用戶名": "\x00hello"},
		formats: FormatPAX,
	}, {
		header:  &Header{Xattrs: map[string]string{"foo=bar": "baz"}},
		formats: FormatUnknown,
	}, {
		header:  &Header{Xattrs: map[string]string{"foo": ""}},
		paxHdrs: map[string]string{paxSchilyXattr + "foo": ""},
		formats: FormatPAX,
	}, {
		header:  &Header{ModTime: time.Unix(0, 0)},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{ModTime: time.Unix(077777777777, 0)},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{ModTime: time.Unix(077777777777+1, 0)},
		paxHdrs: map[string]string{paxMtime: "8589934592"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{ModTime: time.Unix(math.MaxInt64, 0)},
		paxHdrs: map[string]string{paxMtime: "9223372036854775807"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{ModTime: time.Unix(math.MaxInt64, 0), Format: FormatUSTAR},
		paxHdrs: map[string]string{paxMtime: "9223372036854775807"},
		formats: FormatUnknown,
	}, {
		header:  &Header{ModTime: time.Unix(-1, 0)},
		paxHdrs: map[string]string{paxMtime: "-1"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{ModTime: time.Unix(1, 500)},
		paxHdrs: map[string]string{paxMtime: "1.0000005"},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{ModTime: time.Unix(1, 0)},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{ModTime: time.Unix(1, 0), Format: FormatPAX},
		formats: FormatUSTAR | FormatPAX,
	}, {
		header:  &Header{ModTime: time.Unix(1, 500), Format: FormatUSTAR},
		paxHdrs: map[string]string{paxMtime: "1.0000005"},
		formats: FormatUSTAR,
	}, {
		header:  &Header{ModTime: time.Unix(1, 500), Format: FormatPAX},
		paxHdrs: map[string]string{paxMtime: "1.0000005"},
		formats: FormatPAX,
	}, {
		header:  &Header{ModTime: time.Unix(1, 500), Format: FormatGNU},
		paxHdrs: map[string]string{paxMtime: "1.0000005"},
		formats: FormatGNU,
	}, {
		header:  &Header{ModTime: time.Unix(-1, 500)},
		paxHdrs: map[string]string{paxMtime: "-0.9999995"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{ModTime: time.Unix(-1, 500), Format: FormatGNU},
		paxHdrs: map[string]string{paxMtime: "-0.9999995"},
		formats: FormatGNU,
	}, {
		header:  &Header{AccessTime: time.Unix(0, 0)},
		paxHdrs: map[string]string{paxAtime: "0"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{AccessTime: time.Unix(0, 0), Format: FormatUSTAR},
		paxHdrs: map[string]string{paxAtime: "0"},
		formats: FormatUnknown,
	}, {
		header:  &Header{AccessTime: time.Unix(0, 0), Format: FormatPAX},
		paxHdrs: map[string]string{paxAtime: "0"},
		formats: FormatPAX,
	}, {
		header:  &Header{AccessTime: time.Unix(0, 0), Format: FormatGNU},
		paxHdrs: map[string]string{paxAtime: "0"},
		formats: FormatGNU,
	}, {
		header:  &Header{AccessTime: time.Unix(-123, 0)},
		paxHdrs: map[string]string{paxAtime: "-123"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{AccessTime: time.Unix(-123, 0), Format: FormatPAX},
		paxHdrs: map[string]string{paxAtime: "-123"},
		formats: FormatPAX,
	}, {
		header:  &Header{ChangeTime: time.Unix(123, 456)},
		paxHdrs: map[string]string{paxCtime: "123.000000456"},
		formats: FormatPAX | FormatGNU,
	}, {
		header:  &Header{ChangeTime: time.Unix(123, 456), Format: FormatUSTAR},
		paxHdrs: map[string]string{paxCtime: "123.000000456"},
		formats: FormatUnknown,
	}, {
		header:  &Header{ChangeTime: time.Unix(123, 456), Format: FormatGNU},
		paxHdrs: map[string]string{paxCtime: "123.000000456"},
		formats: FormatGNU,
	}, {
		header:  &Header{ChangeTime: time.Unix(123, 456), Format: FormatPAX},
		paxHdrs: map[string]string{paxCtime: "123.000000456"},
		formats: FormatPAX,
	}, {
		header:  &Header{Name: "foo/", Typeflag: TypeDir},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}, {
		header:  &Header{Name: "foo/", Typeflag: TypeReg},
		formats: FormatUnknown,
	}, {
		header:  &Header{Name: "foo/", Typeflag: TypeSymlink},
		formats: FormatUSTAR | FormatPAX | FormatGNU,
	}}

	for i, v := range vectors {
		formats, paxHdrs, err := v.header.allowedFormats()
		if formats != v.formats {
			t.Errorf("test %d, allowedFormats(): got %v, want %v", i, formats, v.formats)
		}
		if formats&FormatPAX > 0 && !maps.Equal(paxHdrs, v.paxHdrs) && !(len(paxHdrs) == 0 && len(v.paxHdrs) == 0) {
			t.Errorf("test %d, allowedFormats():\ngot  %v\nwant %s", i, paxHdrs, v.paxHdrs)
		}
		if (formats != FormatUnknown) && (err != nil) {
			t.Errorf("test %d, unexpected error: %v", i, err)
		}
		if (formats == FormatUnknown) && (err == nil) {
			t.Errorf("test %d, got nil-error, want non-nil error", i)
		}
	}
}

func Benchmark(b *testing.B) {
	type file struct {
		hdr  *Header
		body []byte
	}

	vectors := []struct {
		label string
		files []file
	}{{
		"USTAR",
		[]file{{
			&Header{Name: "bar", Mode: 0640, Size: int64(3)},
			[]byte("foo"),
		}, {
			&Header{Name: "world", Mode: 0640, Size: int64(5)},
			[]byte("hello"),
		}},
	}, {
		"GNU",
		[]file{{
			&Header{Name: "bar", Mode: 0640, Size: int64(3), Devmajor: -1},
			[]byte("foo"),
		}, {
			&Header{Name: "world", Mode: 0640, Size: int64(5), Devmajor: -1},
			[]byte("hello"),
		}},
	}, {
		"PAX",
		[]file{{
			&Header{Name: "bar", Mode: 0640, Size: int64(3), Xattrs: map[string]string{"foo": "bar"}},
			[]byte("foo"),
		}, {
			&Header{Name: "world", Mode: 0640, Size: int64(5), Xattrs: map[string]string{"foo": "bar"}},
			[]byte("hello"),
		}},
	}}

	b.Run("Writer", func(b *testing.B) {
		for _, v := range vectors {
			b.Run(v.label, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					// Writing to io.Discard because we want to
					// test purely the writer code and not bring in disk performance into this.
					tw := NewWriter(io.Discard)
					for _, file := range v.files {
						if err := tw.WriteHeader(file.hdr); err != nil {
							b.Errorf("unexpected WriteHeader error: %v", err)
						}
						if _, err := tw.Write(file.body); err != nil {
							b.Errorf("unexpected Write error: %v", err)
						}
					}
					if err := tw.Close(); err != nil {
						b.Errorf("unexpected Close error: %v", err)
					}
				}
			})
		}
	})

	b.Run("Reader", func(b *testing.B) {
		for _, v := range vectors {
			var buf bytes.Buffer
			var r bytes.Reader

			// Write the archive to a byte buffer.
			tw := NewWriter(&buf)
			for _, file := range v.files {
				tw.WriteHeader(file.hdr)
				tw.Write(file.body)
			}
			tw.Close()
			b.Run(v.label, func(b *testing.B) {
				b.ReportAllocs()
				// Read from the byte buffer.
				for i := 0; i < b.N; i++ {
					r.Reset(buf.Bytes())
					tr := NewReader(&r)
					if _, err := tr.Next(); err != nil {
						b.Errorf("unexpected Next error: %v", err)
					}
					if _, err := io.Copy(io.Discard, tr); err != nil {
						b.Errorf("unexpected Copy error : %v", err)
					}
				}
			})
		}
	})

}

var _ fileInfoNames = fileInfoNames{}

type fileInfoNames struct{}

func (f *fileInfoNames) Name() string {
	return "tmp"
}

func (f *fileInfoNames) Size() int64 {
	return 0
}

func (f *fileInfoNames) Mode() fs.FileMode {
	return 0777
}

func (f *fileInfoNames) ModTime() time.Time {
	return time.Time{}
}

func (f *fileInfoNames) IsDir() bool {
	return false
}

func (f *fileInfoNames) Sys() any {
	return nil
}

func (f *fileInfoNames) Uname() (string, error) {
	return "Uname", nil
}

func (f *fileInfoNames) Gname() (string, error) {
	return "Gname", nil
}

func TestFileInfoHeaderUseFileInfoNames(t *testing.T) {
	info := &fileInfoNames{}
	header, err := FileInfoHeader(info, "")
	if err != nil {
		t.Fatal(err)
	}
	if header.Uname != "Uname" {
		t.Fatalf("header.Uname: got %s, want %s", header.Uname, "Uname")
	}
	if header.Gname != "Gname" {
		t.Fatalf("header.Gname: got %s, want %s", header.Gname, "Gname")
	}
}

"""



```