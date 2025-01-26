Response:
Let's break down the thought process to answer the user's request about the `formdata_test.go` file.

**1. Understanding the Goal:**

The primary goal is to explain the functionality of the provided Go test file (`formdata_test.go`). This involves identifying what aspects of the `mime/multipart` package are being tested and how. The user also wants specific examples and identification of potential pitfalls.

**2. Initial Analysis of the Code Structure:**

* **Package Declaration:** `package multipart` indicates this is a test file for the `mime/multipart` package.
* **Imports:** The imports give clues about the functionalities being tested: `bytes`, `fmt`, `io`, `math`, `net/textproto`, `os`, `strings`, `testing`. These suggest testing things like reading data, handling strings, dealing with files, and using specific network protocols.
* **Test Functions:**  Functions starting with `Test` are standard Go test functions. The names of these functions provide hints about what's being tested (e.g., `TestReadForm`, `TestReadFormWithNamelessFile`, `TestReadFormMaxMemoryOverflow`).
* **Helper Functions:** Functions like `testFile` are utility functions used within the tests.
* **Constants:**  Constants like `fileaContents`, `textaValue`, and `boundary` likely represent sample data used in the tests.
* **Message Constants:** `message`, `messageWithFileWithoutName`, etc., look like pre-defined multipart message strings.
* **Benchmark Function:** `BenchmarkReadForm` indicates performance testing is also present.

**3. Analyzing Individual Test Functions (and Helper Functions):**

* **`TestReadForm`:** This seems to be the core test. It creates a `Reader`, calls `ReadForm`, and then checks the values and files within the returned `Form`. The use of `f.Value` and `f.File` is significant, hinting at the structure of the `Form` type. `testFile` is used to verify file content and filename. The assertion `if _, ok := fd.(*os.File); ok` is crucial – it indicates that *initially*, files are *not* necessarily stored as `os.File` objects (likely kept in memory up to a certain size).
* **`TestReadFormWithNamelessFile`:** This specifically tests the scenario where a file part in the multipart form doesn't have a filename.
* **`TestReadFormWitFileNameMaxMemoryOverflow` and `TestReadFormMaxMemoryOverflow`:**  These test how `ReadForm` behaves when provided with a very large `maxMemory` value (specifically `math.MaxInt64`). They likely aim to ensure no integer overflow issues occur.
* **`TestReadFormWithTextContentType`:** This addresses a specific issue (`#24041`) related to handling parts with a `text/plain` content type.
* **`testFile`:** This helper function verifies the filename, size, and content of a file part obtained from the `Form`.
* **`TestReadForm_NoReadAfterEOF`:** Tests the robustness of the reader by ensuring it doesn't try to read after encountering an error or EOF.
* **`failOnReadAfterErrorReader`:** This is a custom `io.Reader` used by `TestReadForm_NoReadAfterEOF` to enforce the "no read after error" condition.
* **`TestReadForm_NonFileMaxMemory`:**  This is important. It checks that the `maxMemory` limit applies to *both* file and non-file data. The loop with increasing `maxMemory` suggests testing the threshold where data is moved to disk.
* **`TestReadForm_MetadataTooLarge`:**  Focuses on limiting memory usage based on the *metadata* of the form (field names, headers), not just the content. This is a crucial security and resource management aspect.
* **`TestReadForm_ManyFiles_Combined` and `TestReadForm_ManyFiles_Distinct`:**  These test how the system handles multiple files. The `GODEBUG` environment variable interaction (`multipartfiles=distinct`) is a key point here, indicating a configurable behavior for storing uploaded files (in memory vs. separate disk files).
* **`testReadFormManyFiles`:** The helper function for the multiple files tests.
* **`TestReadFormLimits`:** This test suite explores various limits related to the number of values, files, and headers in a multipart form. The use of `GODEBUG` again suggests configurable limits.
* **`TestReadFormEndlessHeaderLine`:** This tests how the parser handles excessively long header lines, preventing potential denial-of-service attacks.
* **`neverendingReader`:** A utility reader for the "endless header line" test.
* **`BenchmarkReadForm`:**  Measures the performance of `ReadForm` under different conditions (handling fields vs. files, different `maxMemory` values).

**4. Identifying Core Functionality and Providing Examples:**

Based on the analysis, the primary function being tested is `ReadForm`. The examples need to demonstrate its usage, how to access the parsed data (values and files), and how the `maxMemory` parameter affects behavior.

* **Example 1 (Basic Form):** Showcases a simple form with text fields and a file.
* **Example 2 (Max Memory):** Illustrates how `maxMemory` determines whether a file is kept in memory or written to disk.

**5. Identifying Potential Mistakes:**

The analysis reveals several areas where users might make mistakes:

* **Assuming files are always `*os.File`:** The tests show that small files might be kept in memory initially.
* **Not understanding `maxMemory`:** Users might not realize its impact on memory usage and temporary file creation.
* **Ignoring error handling:**  The tests emphasize checking errors from `ReadForm` and file operations.
* **Not cleaning up temporary files:** The `defer f.RemoveAll()` calls highlight the importance of releasing resources.

**6. Explaining Command-Line Arguments (if applicable):**

In this specific test file, there are no direct command-line arguments being parsed. However, the use of the `GODEBUG` environment variable is a crucial point to explain, as it modifies the behavior related to file handling and limits.

**7. Structuring the Answer:**

The final answer should be structured logically, covering:

* **Overall Functionality:** A high-level description of what the test file does.
* **Detailed Functionality (Test by Test):** Explain the purpose of each test function.
* **Go Language Feature:** Identify `multipart.Reader.ReadForm` as the key feature being tested.
* **Code Examples:** Provide illustrative Go code snippets.
* **Input and Output:** Explain the input to the examples and the expected output.
* **Command-Line Parameters (GODEBUG):** Detail how the `GODEBUG` variable influences behavior.
* **Common Mistakes:** List and explain potential pitfalls for users.

By following these steps, we can systematically analyze the test file and provide a comprehensive and informative answer to the user's request. The process involves reading the code, understanding the imports and function names, and inferring the intent behind each test case. The focus should be on translating the code's actions into clear explanations and practical examples for the user.这个 `formdata_test.go` 文件是 Go 语言 `mime/multipart` 包的一部分，专门用于测试处理 `multipart/form-data` 格式的功能。 它主要测试了 `Reader` 类型的 `ReadForm` 方法。

以下是该文件测试的主要功能点：

1. **`ReadForm` 方法的基本功能:**
   - 测试 `ReadForm` 方法能否正确解析包含文本字段和文件字段的 `multipart/form-data` 请求体。
   - 验证解析出的文本字段的值是否正确。
   - 验证解析出的文件字段的元数据（文件名、大小）是否正确。
   - 验证解析出的文件字段的内容是否正确。
   - 检查文件在内存中和磁盘上的处理方式。

2. **处理不带文件名的文件字段:**
   - 测试当 `multipart/form-data` 中包含没有 `filename` 属性的文件字段时，`ReadForm` 方法是否能正确处理。

3. **`ReadForm` 方法的 `maxMemory` 参数:**
   - 测试 `ReadForm` 方法的 `maxMemory` 参数如何限制内存使用。
   - 验证当 `maxMemory` 设置较小时，文件内容会被写入临时文件。
   - 验证当 `maxMemory` 设置足够大时，文件内容可以保留在内存中。
   - 特别测试了 `maxMemory` 设置为 `math.MaxInt64` 时的行为，以防止潜在的溢出问题。
   - 测试 `maxMemory` 参数对非文件字段的限制。

4. **处理带有 `text/plain` Content-Type 的文本字段:**
   - 测试 `ReadForm` 方法是否能正确处理 `Content-Type` 为 `text/plain` 的文本字段。

5. **防止读取 EOF 后的数据:**
   - 测试当读取器遇到 EOF 后，`ReadForm` 方法不会尝试继续读取。

6. **限制非文件数据的内存使用:**
   - 验证 `maxMemory` 限制也适用于非文件表单数据，防止大量文本数据占用过多内存。

7. **限制元数据大小:**
   - 测试 `ReadForm` 方法如何限制表单的元数据（字段名、MIME 头）的大小，防止恶意请求占用过多内存。

8. **处理大量文件:**
   - 测试当 `multipart/form-data` 中包含大量文件时，`ReadForm` 方法的处理情况。
   - 测试通过设置 `GODEBUG=multipartfiles=distinct` 环境变量，可以使每个文件都存储在独立的磁盘文件中。

9. **限制表单中的字段和头部数量:**
   - 测试通过 `GODEBUG` 环境变量（如 `multipartmaxparts` 和 `multipartmaxheaders`）可以限制表单中允许的最大字段和头部数量。

10. **处理无限长的头部行:**
    - 测试 `ReadForm` 方法在遇到无限长的头部行时的处理，防止潜在的资源耗尽。

11. **性能测试:**
    - 提供了 `BenchmarkReadForm` 基准测试，用于评估 `ReadForm` 方法在处理不同类型的表单数据时的性能。

**推理 `ReadForm` 方法的实现 (Go 代码示例):**

`ReadForm` 方法的主要功能是解析 `multipart/form-data` 的请求体，将其中的字段和文件提取出来。它需要处理边界 (boundary) 来分隔不同的 part，并解析每个 part 的头部信息 (Content-Disposition, Content-Type 等)。

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
)

func main() {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// 添加文本字段
	writer.WriteField("name", "张三")
	writer.WriteField("age", "30")

	// 添加文件字段
	fileContent := "This is the content of the file."
	part, err := writer.CreateFormFile("uploadfile", "example.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	io.Copy(part, strings.NewReader(fileContent))

	writer.Close()

	// 创建一个模拟的 HTTP 请求
	req, err := http.NewRequest("POST", "/upload", body)
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// 创建一个 multipart.Reader
	reader := multipart.NewReader(req.Body, writer.Boundary())

	// 调用 ReadForm 方法，设置最大内存限制为 1MB
	form, err := reader.ReadForm(1 * 1024 * 1024)
	if err != nil {
		fmt.Println("ReadForm error:", err)
		return
	}
	defer form.RemoveAll()

	// 打印解析出的文本字段
	fmt.Println("Name:", form.Value["name"][0])
	fmt.Println("Age:", form.Value["age"][0])

	// 打印解析出的文件信息
	fileHeaders := form.File["uploadfile"]
	if len(fileHeaders) > 0 {
		fileHeader := fileHeaders[0]
		fmt.Println("Uploaded File Name:", fileHeader.Filename)
		fmt.Println("Uploaded File Size:", fileHeader.Size)

		file, err := fileHeader.Open()
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer file.Close()

		fileContentBuf := new(strings.Builder)
		io.Copy(fileContentBuf, file)
		fmt.Println("Uploaded File Content:", fileContentBuf.String())

		// 检查文件是否被写入了临时文件（如果 maxMemory 较小）
		if _, ok := file.(*os.File); ok {
			fmt.Println("File was saved to a temporary file.")
		} else {
			fmt.Println("File was kept in memory.")
		}
	}
}
```

**假设的输入与输出:**

**输入 (模拟的 HTTP 请求体):**

```
--<boundary>
Content-Disposition: form-data; name="name"

张三
--<boundary>
Content-Disposition: form-data; name="age"

30
--<boundary>
Content-Disposition: form-data; name="uploadfile"; filename="example.txt"
Content-Type: text/plain

This is the content of the file.
--<boundary>--
```

**输出:**

```
Name: 张三
Age: 30
Uploaded File Name: example.txt
Uploaded File Size: 31
Uploaded File Content: This is the content of the file.
File was kept in memory. (如果 ReadForm 的 maxMemory 设置足够大)
或者
File was saved to a temporary file. (如果 ReadForm 的 maxMemory 设置较小)
```

**命令行参数的具体处理:**

该测试文件本身不直接处理命令行参数。但是，它使用了 `testing` 包提供的功能来进行测试，可以通过 `go test` 命令运行。

此外，它还演示了如何使用 `GODEBUG` 环境变量来影响 `multipart` 包的行为，例如：

- `GODEBUG=multipartfiles=distinct`:  使上传的每个文件都存储在独立的磁盘文件中，即使 `maxMemory` 足够大。
- `GODEBUG=multipartmaxparts=100`: 设置表单中允许的最大 part 数量为 100。
- `GODEBUG=multipartmaxheaders=100`: 设置每个 part 允许的最大头部数量为 100。

这些 `GODEBUG` 环境变量是在运行测试时设置的，例如：

```bash
GODEBUG=multipartfiles=distinct go test ./mime/multipart
```

**使用者易犯错的点:**

1. **假设文件总是 `*os.File` 类型:**  当 `maxMemory` 设置较大时，小文件可能不会被写入磁盘，而是保留在内存中，此时通过 `FileHeader.Open()` 返回的 `io.ReadCloser` 可能不是 `*os.File` 类型。使用者应该使用 `io.ReadCloser` 接口进行操作，而不是假定具体的类型。

   **错误示例:**

   ```go
   file, _ := fileHeader.Open()
   defer file.Close()
   osFile := file.(*os.File) // 如果文件在内存中，这里会 panic
   // ... 使用 osFile 进行操作 ...
   ```

   **正确示例:**

   ```go
   file, _ := fileHeader.Open()
   defer file.Close()
   // ... 使用 file (io.ReadCloser) 进行操作 ...
   ```

2. **没有正确处理 `ReadForm` 的 `maxMemory` 参数:**  使用者可能没有意识到 `maxMemory` 参数的重要性，或者设置了一个不合适的值，导致内存使用过高或频繁地创建临时文件。应该根据应用的实际需求合理设置 `maxMemory`。

3. **忘记调用 `form.RemoveAll()` 清理临时文件:** 如果 `ReadForm` 因为 `maxMemory` 的限制将文件写入了临时目录，那么在使用完 `form` 后，必须调用 `form.RemoveAll()` 来删除这些临时文件和目录，否则会造成资源泄漏。

   **错误示例:**

   ```go
   form, err := reader.ReadForm(1024)
   if err != nil {
       // ... 处理错误 ...
       return
   }
   // ... 使用 form ...
   // 忘记调用 form.RemoveAll()
   ```

   **正确示例:**

   ```go
   form, err := reader.ReadForm(1024)
   if err != nil {
       // ... 处理错误 ...
       return
   }
   defer form.RemoveAll()
   // ... 使用 form ...
   ```

4. **没有处理 `ReadForm` 可能返回的错误:**  `ReadForm` 在解析过程中可能会遇到错误，例如请求体格式不正确、超过 `maxMemory` 限制等。使用者应该检查并处理这些错误。

总而言之，`formdata_test.go` 文件通过各种测试用例，全面地验证了 `mime/multipart` 包中 `ReadForm` 方法的正确性和健壮性，涵盖了基本功能、边界情况、性能以及资源管理等方面。理解这些测试用例可以帮助开发者更好地理解和使用 `multipart` 包，避免常见的错误。

Prompt: 
```
这是路径为go/src/mime/multipart/formdata_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package multipart

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/textproto"
	"os"
	"strings"
	"testing"
)

func TestReadForm(t *testing.T) {
	b := strings.NewReader(strings.ReplaceAll(message, "\n", "\r\n"))
	r := NewReader(b, boundary)
	f, err := r.ReadForm(25)
	if err != nil {
		t.Fatal("ReadForm:", err)
	}
	defer f.RemoveAll()
	if g, e := f.Value["texta"][0], textaValue; g != e {
		t.Errorf("texta value = %q, want %q", g, e)
	}
	if g, e := f.Value["textb"][0], textbValue; g != e {
		t.Errorf("texta value = %q, want %q", g, e)
	}
	fd := testFile(t, f.File["filea"][0], "filea.txt", fileaContents)
	if _, ok := fd.(*os.File); ok {
		t.Error("file is *os.File, should not be")
	}
	fd.Close()
	fd = testFile(t, f.File["fileb"][0], "fileb.txt", filebContents)
	if _, ok := fd.(*os.File); !ok {
		t.Errorf("file has unexpected underlying type %T", fd)
	}
	fd.Close()
}

func TestReadFormWithNamelessFile(t *testing.T) {
	b := strings.NewReader(strings.ReplaceAll(messageWithFileWithoutName, "\n", "\r\n"))
	r := NewReader(b, boundary)
	f, err := r.ReadForm(25)
	if err != nil {
		t.Fatal("ReadForm:", err)
	}
	defer f.RemoveAll()

	if g, e := f.Value["hiddenfile"][0], filebContents; g != e {
		t.Errorf("hiddenfile value = %q, want %q", g, e)
	}
}

// Issue 58384: Handle ReadForm(math.MaxInt64)
func TestReadFormWitFileNameMaxMemoryOverflow(t *testing.T) {
	b := strings.NewReader(strings.ReplaceAll(messageWithFileName, "\n", "\r\n"))
	r := NewReader(b, boundary)
	f, err := r.ReadForm(math.MaxInt64)
	if err != nil {
		t.Fatalf("ReadForm(MaxInt64): %v", err)
	}
	defer f.RemoveAll()

	fd := testFile(t, f.File["filea"][0], "filea.txt", fileaContents)
	if _, ok := fd.(*os.File); ok {
		t.Error("file is *os.File, should not be")
	}
	fd.Close()
}

// Issue 40430: Handle ReadForm(math.MaxInt64)
func TestReadFormMaxMemoryOverflow(t *testing.T) {
	b := strings.NewReader(strings.ReplaceAll(messageWithTextContentType, "\n", "\r\n"))
	r := NewReader(b, boundary)
	f, err := r.ReadForm(math.MaxInt64)
	if err != nil {
		t.Fatalf("ReadForm(MaxInt64): %v", err)
	}
	if f == nil {
		t.Fatal("ReadForm(MaxInt64): missing form")
	}
	defer f.RemoveAll()

	if g, e := f.Value["texta"][0], textaValue; g != e {
		t.Errorf("texta value = %q, want %q", g, e)
	}
}

func TestReadFormWithTextContentType(t *testing.T) {
	// From https://github.com/golang/go/issues/24041
	b := strings.NewReader(strings.ReplaceAll(messageWithTextContentType, "\n", "\r\n"))
	r := NewReader(b, boundary)
	f, err := r.ReadForm(25)
	if err != nil {
		t.Fatal("ReadForm:", err)
	}
	defer f.RemoveAll()

	if g, e := f.Value["texta"][0], textaValue; g != e {
		t.Errorf("texta value = %q, want %q", g, e)
	}
}

func testFile(t *testing.T, fh *FileHeader, efn, econtent string) File {
	if fh.Filename != efn {
		t.Errorf("filename = %q, want %q", fh.Filename, efn)
	}
	if fh.Size != int64(len(econtent)) {
		t.Errorf("size = %d, want %d", fh.Size, len(econtent))
	}
	f, err := fh.Open()
	if err != nil {
		t.Fatal("opening file:", err)
	}
	b := new(strings.Builder)
	_, err = io.Copy(b, f)
	if err != nil {
		t.Fatal("copying contents:", err)
	}
	if g := b.String(); g != econtent {
		t.Errorf("contents = %q, want %q", g, econtent)
	}
	return f
}

const (
	fileaContents = "This is a test file."
	filebContents = "Another test file."
	textaValue    = "foo"
	textbValue    = "bar"
	boundary      = `MyBoundary`
)

const messageWithFileWithoutName = `
--MyBoundary
Content-Disposition: form-data; name="hiddenfile"; filename=""
Content-Type: text/plain

` + filebContents + `
--MyBoundary--
`

const messageWithFileName = `
--MyBoundary
Content-Disposition: form-data; name="filea"; filename="filea.txt"
Content-Type: text/plain

` + fileaContents + `
--MyBoundary--
`

const messageWithTextContentType = `
--MyBoundary
Content-Disposition: form-data; name="texta"
Content-Type: text/plain

` + textaValue + `
--MyBoundary
`

const message = `
--MyBoundary
Content-Disposition: form-data; name="filea"; filename="filea.txt"
Content-Type: text/plain

` + fileaContents + `
--MyBoundary
Content-Disposition: form-data; name="fileb"; filename="fileb.txt"
Content-Type: text/plain

` + filebContents + `
--MyBoundary
Content-Disposition: form-data; name="texta"

` + textaValue + `
--MyBoundary
Content-Disposition: form-data; name="textb"

` + textbValue + `
--MyBoundary--
`

func TestReadForm_NoReadAfterEOF(t *testing.T) {
	maxMemory := int64(32) << 20
	boundary := `---------------------------8d345eef0d38dc9`
	body := `
-----------------------------8d345eef0d38dc9
Content-Disposition: form-data; name="version"

171
-----------------------------8d345eef0d38dc9--`

	mr := NewReader(&failOnReadAfterErrorReader{t: t, r: strings.NewReader(body)}, boundary)

	f, err := mr.ReadForm(maxMemory)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %#v", f)
}

// failOnReadAfterErrorReader is an io.Reader wrapping r.
// It fails t if any Read is called after a failing Read.
type failOnReadAfterErrorReader struct {
	t      *testing.T
	r      io.Reader
	sawErr error
}

func (r *failOnReadAfterErrorReader) Read(p []byte) (n int, err error) {
	if r.sawErr != nil {
		r.t.Fatalf("unexpected Read on Reader after previous read saw error %v", r.sawErr)
	}
	n, err = r.r.Read(p)
	r.sawErr = err
	return
}

// TestReadForm_NonFileMaxMemory asserts that the ReadForm maxMemory limit is applied
// while processing non-file form data as well as file form data.
func TestReadForm_NonFileMaxMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	n := 10 << 20
	largeTextValue := strings.Repeat("1", n)
	message := `--MyBoundary
Content-Disposition: form-data; name="largetext"

` + largeTextValue + `
--MyBoundary--
`
	testBody := strings.ReplaceAll(message, "\n", "\r\n")
	// Try parsing the form with increasing maxMemory values.
	// Changes in how we account for non-file form data may cause the exact point
	// where we change from rejecting the form as too large to accepting it to vary,
	// but we should see both successes and failures.
	const failWhenMaxMemoryLessThan = 128
	for maxMemory := int64(0); maxMemory < failWhenMaxMemoryLessThan*2; maxMemory += 16 {
		b := strings.NewReader(testBody)
		r := NewReader(b, boundary)
		f, err := r.ReadForm(maxMemory)
		if err != nil {
			continue
		}
		if g := f.Value["largetext"][0]; g != largeTextValue {
			t.Errorf("largetext mismatch: got size: %v, expected size: %v", len(g), len(largeTextValue))
		}
		f.RemoveAll()
		if maxMemory < failWhenMaxMemoryLessThan {
			t.Errorf("ReadForm(%v): no error, expect to hit memory limit when maxMemory < %v", maxMemory, failWhenMaxMemoryLessThan)
		}
		return
	}
	t.Errorf("ReadForm(x) failed for x < 1024, expect success")
}

// TestReadForm_MetadataTooLarge verifies that we account for the size of field names,
// MIME headers, and map entry overhead while limiting the memory consumption of parsed forms.
func TestReadForm_MetadataTooLarge(t *testing.T) {
	for _, test := range []struct {
		name string
		f    func(*Writer)
	}{{
		name: "large name",
		f: func(fw *Writer) {
			name := strings.Repeat("a", 10<<20)
			w, _ := fw.CreateFormField(name)
			w.Write([]byte("value"))
		},
	}, {
		name: "large MIME header",
		f: func(fw *Writer) {
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", `form-data; name="a"`)
			h.Set("X-Foo", strings.Repeat("a", 10<<20))
			w, _ := fw.CreatePart(h)
			w.Write([]byte("value"))
		},
	}, {
		name: "many parts",
		f: func(fw *Writer) {
			for i := 0; i < 110000; i++ {
				w, _ := fw.CreateFormField("f")
				w.Write([]byte("v"))
			}
		},
	}} {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			fw := NewWriter(&buf)
			test.f(fw)
			if err := fw.Close(); err != nil {
				t.Fatal(err)
			}
			fr := NewReader(&buf, fw.Boundary())
			_, err := fr.ReadForm(0)
			if err != ErrMessageTooLarge {
				t.Errorf("fr.ReadForm() = %v, want ErrMessageTooLarge", err)
			}
		})
	}
}

// TestReadForm_ManyFiles_Combined tests that a multipart form containing many files only
// results in a single on-disk file.
func TestReadForm_ManyFiles_Combined(t *testing.T) {
	const distinct = false
	testReadFormManyFiles(t, distinct)
}

// TestReadForm_ManyFiles_Distinct tests that setting GODEBUG=multipartfiles=distinct
// results in every file in a multipart form being placed in a distinct on-disk file.
func TestReadForm_ManyFiles_Distinct(t *testing.T) {
	t.Setenv("GODEBUG", "multipartfiles=distinct")
	const distinct = true
	testReadFormManyFiles(t, distinct)
}

func testReadFormManyFiles(t *testing.T, distinct bool) {
	var buf bytes.Buffer
	fw := NewWriter(&buf)
	const numFiles = 10
	for i := 0; i < numFiles; i++ {
		name := fmt.Sprint(i)
		w, err := fw.CreateFormFile(name, name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(name))
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	fr := NewReader(&buf, fw.Boundary())
	fr.tempDir = t.TempDir()
	form, err := fr.ReadForm(0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < numFiles; i++ {
		name := fmt.Sprint(i)
		if got := len(form.File[name]); got != 1 {
			t.Fatalf("form.File[%q] has %v entries, want 1", name, got)
		}
		fh := form.File[name][0]
		file, err := fh.Open()
		if err != nil {
			t.Fatalf("form.File[%q].Open() = %v", name, err)
		}
		if distinct {
			if _, ok := file.(*os.File); !ok {
				t.Fatalf("form.File[%q].Open: %T, want *os.File", name, file)
			}
		}
		got, err := io.ReadAll(file)
		file.Close()
		if string(got) != name || err != nil {
			t.Fatalf("read form.File[%q]: %q, %v; want %q, nil", name, string(got), err, name)
		}
	}
	dir, err := os.Open(fr.tempDir)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	names, err := dir.Readdirnames(0)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := 1
	if distinct {
		wantNames = numFiles
	}
	if len(names) != wantNames {
		t.Fatalf("temp dir contains %v files; want 1", len(names))
	}
	if err := form.RemoveAll(); err != nil {
		t.Fatalf("form.RemoveAll() = %v", err)
	}
	names, err = dir.Readdirnames(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("temp dir contains %v files; want 0", len(names))
	}
}

func TestReadFormLimits(t *testing.T) {
	for _, test := range []struct {
		values           int
		files            int
		extraKeysPerFile int
		wantErr          error
		godebug          string
	}{
		{values: 1000},
		{values: 1001, wantErr: ErrMessageTooLarge},
		{values: 500, files: 500},
		{values: 501, files: 500, wantErr: ErrMessageTooLarge},
		{files: 1000},
		{files: 1001, wantErr: ErrMessageTooLarge},
		{files: 1, extraKeysPerFile: 9998}, // plus Content-Disposition and Content-Type
		{files: 1, extraKeysPerFile: 10000, wantErr: ErrMessageTooLarge},
		{godebug: "multipartmaxparts=100", values: 100},
		{godebug: "multipartmaxparts=100", values: 101, wantErr: ErrMessageTooLarge},
		{godebug: "multipartmaxheaders=100", files: 2, extraKeysPerFile: 48},
		{godebug: "multipartmaxheaders=100", files: 2, extraKeysPerFile: 50, wantErr: ErrMessageTooLarge},
	} {
		name := fmt.Sprintf("values=%v/files=%v/extraKeysPerFile=%v", test.values, test.files, test.extraKeysPerFile)
		if test.godebug != "" {
			name += fmt.Sprintf("/godebug=%v", test.godebug)
		}
		t.Run(name, func(t *testing.T) {
			if test.godebug != "" {
				t.Setenv("GODEBUG", test.godebug)
			}
			var buf bytes.Buffer
			fw := NewWriter(&buf)
			for i := 0; i < test.values; i++ {
				w, _ := fw.CreateFormField(fmt.Sprintf("field%v", i))
				fmt.Fprintf(w, "value %v", i)
			}
			for i := 0; i < test.files; i++ {
				h := make(textproto.MIMEHeader)
				h.Set("Content-Disposition",
					fmt.Sprintf(`form-data; name="file%v"; filename="file%v"`, i, i))
				h.Set("Content-Type", "application/octet-stream")
				for j := 0; j < test.extraKeysPerFile; j++ {
					h.Set(fmt.Sprintf("k%v", j), "v")
				}
				w, _ := fw.CreatePart(h)
				fmt.Fprintf(w, "value %v", i)
			}
			if err := fw.Close(); err != nil {
				t.Fatal(err)
			}
			fr := NewReader(bytes.NewReader(buf.Bytes()), fw.Boundary())
			form, err := fr.ReadForm(1 << 10)
			if err == nil {
				defer form.RemoveAll()
			}
			if err != test.wantErr {
				t.Errorf("ReadForm = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestReadFormEndlessHeaderLine(t *testing.T) {
	for _, test := range []struct {
		name   string
		prefix string
	}{{
		name:   "name",
		prefix: "X-",
	}, {
		name:   "value",
		prefix: "X-Header: ",
	}, {
		name:   "continuation",
		prefix: "X-Header: foo\r\n  ",
	}} {
		t.Run(test.name, func(t *testing.T) {
			const eol = "\r\n"
			s := `--boundary` + eol
			s += `Content-Disposition: form-data; name="a"` + eol
			s += `Content-Type: text/plain` + eol
			s += test.prefix
			fr := io.MultiReader(
				strings.NewReader(s),
				neverendingReader('X'),
			)
			r := NewReader(fr, "boundary")
			_, err := r.ReadForm(1 << 20)
			if err != ErrMessageTooLarge {
				t.Fatalf("ReadForm(1 << 20): %v, want ErrMessageTooLarge", err)
			}
		})
	}
}

type neverendingReader byte

func (r neverendingReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func BenchmarkReadForm(b *testing.B) {
	for _, test := range []struct {
		name string
		form func(fw *Writer, count int)
	}{{
		name: "fields",
		form: func(fw *Writer, count int) {
			for i := 0; i < count; i++ {
				w, _ := fw.CreateFormField(fmt.Sprintf("field%v", i))
				fmt.Fprintf(w, "value %v", i)
			}
		},
	}, {
		name: "files",
		form: func(fw *Writer, count int) {
			for i := 0; i < count; i++ {
				w, _ := fw.CreateFormFile(fmt.Sprintf("field%v", i), fmt.Sprintf("file%v", i))
				fmt.Fprintf(w, "value %v", i)
			}
		},
	}} {
		b.Run(test.name, func(b *testing.B) {
			for _, maxMemory := range []int64{
				0,
				1 << 20,
			} {
				var buf bytes.Buffer
				fw := NewWriter(&buf)
				test.form(fw, 10)
				if err := fw.Close(); err != nil {
					b.Fatal(err)
				}
				b.Run(fmt.Sprintf("maxMemory=%v", maxMemory), func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						fr := NewReader(bytes.NewReader(buf.Bytes()), fw.Boundary())
						form, err := fr.ReadForm(maxMemory)
						if err != nil {
							b.Fatal(err)
						}
						form.RemoveAll()
					}

				})
			}
		})
	}
}

"""



```