Response:
Let's break down the thought process for analyzing this Go test file.

1. **Understand the Goal:** The core request is to understand the functionality of the provided Go code snippet, which is a test file (`buffer_test.go`) for the `bytes` package, specifically the `Buffer` type.

2. **Identify the Core Subject:** The filename `buffer_test.go` and the import of the `bytes` package strongly indicate that the tests are focused on the `bytes.Buffer` type.

3. **Initial Scan for Keywords and Patterns:** Quickly scan the code for common testing patterns and relevant methods related to `bytes.Buffer`. Look for:
    * `func Test...`:  This is the standard Go testing function signature. Each such function likely tests a specific feature or aspect of `bytes.Buffer`.
    * `bytes.NewBuffer`, `bytes.NewBufferString`:  These are constructor functions for creating `Buffer` instances.
    * `buf.Write`, `buf.WriteString`, `buf.WriteByte`, `buf.WriteRune`: Methods for writing data to the buffer.
    * `buf.Read`, `buf.ReadByte`, `buf.ReadRune`, `buf.ReadBytes`, `buf.ReadString`: Methods for reading data from the buffer.
    * `buf.Reset`, `buf.Truncate`, `buf.Len`, `buf.Cap`, `buf.Bytes`, `buf.String`:  Other important `Buffer` methods for management and access.
    * `io.Reader`, `io.Writer`, `io.EOF`: Interfaces and constants related to input/output operations, suggesting the `Buffer` implements these interfaces.
    * Helper functions like `check`, `fillString`, `fillBytes`, `empty`: These are likely used to simplify repetitive test setup and assertion logic.

4. **Categorize Tests:** Group the test functions based on the functionality they seem to be testing. For example:
    * **Creation/Initialization:** `TestNewBuffer`, `TestNewBufferString`, `TestNewBufferShallow`.
    * **Basic Operations:** `TestBasicOperations` (covers Reset, Truncate, Write, WriteByte, ReadByte).
    * **Writing:** `TestLargeStringWrites`, `TestLargeByteWrites`, `TestWriteAppend`, `TestWriteRune`, `TestWriteInvalidRune`.
    * **Reading:** `TestLargeStringReads`, `TestLargeByteReads`, `TestReadFrom`, `TestReadBytes`, `TestReadString`, `TestNext`.
    * **Combined Read/Write:** `TestMixedReadsAndWrites`.
    * **Capacity/Growth:** `TestCapWithPreallocatedSlice`, `TestCapWithSliceAndWrittenData`, `TestGrow`, `TestGrowOverflow`, `TestBufferGrowth`.
    * **Edge Cases:** `TestNil`, `TestReadFromPanicReader`, `TestReadFromNegativeReader`, `TestReadEmptyAtEOF`, `TestUnreadByte`, `TestRuneIO`.
    * **Benchmarking:** `Benchmark...` functions measure performance.

5. **Analyze Key Helper Functions:** Understand the purpose of the helper functions like `check`, `fillString`, `fillBytes`, and `empty`. These provide insights into how the tests are structured and what aspects of the `Buffer` are being verified. For example:
    * `check`: Verifies that the internal state of the `Buffer` (length, string representation, byte representation) is consistent.
    * `fillString`/`fillBytes`:  Repeatedly writes data to the buffer.
    * `empty`: Repeatedly reads data from the buffer until it's empty.

6. **Infer Functionality:** Based on the test names and the operations performed within them, infer the functionality of `bytes.Buffer`. It's clearly designed for in-memory byte manipulation, supporting:
    * Appending and reading byte slices and strings.
    * Reading and writing runes (UTF-8 characters).
    * Managing its internal buffer (growing, resetting, truncating).
    * Implementing `io.Reader` and `io.Writer` interfaces.

7. **Code Examples (Conceptual):** Start thinking about simple Go code examples that demonstrate the key functionalities. This doesn't require running the code at this stage, just visualizing how `bytes.Buffer` would be used.

8. **Command-Line Arguments (If Applicable):**  In this specific test file, there aren't explicit command-line argument processing scenarios. However, note the use of `testing.Short()`, which influences the loop limits in some tests. This is a standard Go testing mechanism.

9. **Common Mistakes:** Based on the types of tests being performed (especially edge cases and error handling), consider potential pitfalls for users:
    * Incorrectly assuming the buffer's initial capacity.
    * Not handling `io.EOF` when reading.
    * Potential issues with `UnreadByte` and `UnreadRune` if used incorrectly.
    * Off-by-one errors when working with buffer lengths and indices.

10. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt:
    * **功能列举:** List the identified functionalities in clear, concise points.
    * **功能实现推理:** Focus on the core purpose of `bytes.Buffer` as an in-memory buffer and its implementation of `io.Reader` and `io.Writer`. Provide code examples.
    * **代码推理 (with Input/Output):**  Illustrate specific methods with simple examples and expected results.
    * **命令行参数:** Explain the use of `testing.Short()`.
    * **易犯错的点:**  List potential mistakes with examples.

11. **Refine and Review:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Make sure the language is natural and easy to understand. Check if the examples are helpful and correct.

Self-Correction/Refinement during the process:

* **Initial thought:** "This is just about testing basic byte operations."  **Correction:** Realized it also covers Unicode (runes), `io` interfaces, and performance aspects.
* **Early examples:** Might have initially focused on very complex examples. **Correction:**  Simplified the examples to focus on single functionalities.
* **Missed detail:** Initially overlooked the significance of `testing.Short()`. **Correction:** Added a section explaining its purpose in the test suite.

By following this structured approach, combined with careful reading and interpretation of the code, we can accurately understand and explain the functionality of the `bytes/buffer_test.go` file.
这段代码是Go语言标准库 `bytes` 包中 `Buffer` 类型的测试代码。它的主要功能是：

**1. 测试 `bytes.Buffer` 类型的各种功能和方法的正确性。**

   `bytes.Buffer` 是一个实现了可读写 `[]byte` 切片功能的类型，可以将其看作一个动态大小的字节数组。测试代码覆盖了 `Buffer` 的创建、写入、读取、容量管理等核心功能。

**2. 验证 `bytes.Buffer` 是否符合 `io.Reader` 和 `io.Writer` 接口。**

   通过测试 `Read` 和 `Write` 方法以及相关的接口方法，确保 `Buffer` 可以像标准输入输出流一样工作。

**3. 测试 `bytes.Buffer` 的性能特性。**

   代码中包含了一些基准测试 (`Benchmark...`)，用于评估 `Buffer` 在不同场景下的性能表现，例如 `WriteByte`、`WriteRune` 和批量写入等。

**以下是用 Go 代码举例说明 `bytes.Buffer` 功能的实现：**

```go
package main

import (
	"bytes"
	"fmt"
	"io"
)

func main() {
	// 1. 创建 Buffer
	var buf bytes.Buffer // 创建一个空的 Buffer
	buf2 := bytes.NewBufferString("hello ") // 使用字符串初始化 Buffer
	buf3 := bytes.NewBuffer([]byte("world")) // 使用字节切片初始化 Buffer

	fmt.Println("Initial buffers:")
	fmt.Println("buf:", buf.String())   // 输出: buf:
	fmt.Println("buf2:", buf2.String())  // 输出: buf2: hello
	fmt.Println("buf3:", buf3.String())  // 输出: buf3: world

	// 2. 写入数据
	buf.WriteString("Go ")
	buf.Write([]byte("language "))
	buf.WriteByte('!')
	buf.WriteRune('😄')

	fmt.Println("\nAfter writing to buf:", buf.String()) // 输出: After writing to buf: Go language !😄

	// 3. 读取数据
	readBuf := make([]byte, 10)
	n, err := buf.Read(readBuf)
	if err != nil && err != io.EOF {
		fmt.Println("Error reading:", err)
	}
	fmt.Printf("Read %d bytes from buf: %s\n", n, string(readBuf[:n])) // 输出: Read 10 bytes from buf: Go languag

	b, err := buf.ReadByte()
	if err == nil {
		fmt.Printf("Read one byte: %c\n", b) // 输出: Read one byte: e
	}

	r, _, err := buf.ReadRune()
	if err == nil {
		fmt.Printf("Read one rune: %c\n", r) // 输出: Read one rune:
	}

	// 4. 其他操作
	fmt.Println("\nRemaining content in buf:", buf.String()) // 输出: Remaining content in buf:  !😄
	fmt.Println("Length of buf:", buf.Len())              // 输出: Length of buf: 5
	fmt.Println("Capacity of buf:", buf.Cap())           // 输出: Capacity of buf: 64 (或者其他值，取决于内部增长)

	buf.Reset() // 清空 Buffer
	fmt.Println("\nAfter Reset, buf:", buf.String())       // 输出: After Reset, buf:
}
```

**代码推理示例 (涉及 `ReadBytes` 方法):**

**假设输入:** `buf` 中包含字符串 "apple,banana,orange"

**测试代码:**

```go
package main

import (
	"bytes"
	"fmt"
)

func main() {
	buf := bytes.NewBufferString("apple,banana,orange")
	delimiter := byte(',')
	for {
		line, err := buf.ReadBytes(delimiter)
		if err != nil {
			fmt.Println("Error or EOF:", err)
			break
		}
		fmt.Printf("Read line: %s", line)
	}
}
```

**输出:**

```
Read line: apple,
Read line: banana,
Error or EOF: EOF
```

**解释:** `ReadBytes(',')` 方法会读取 `buf` 中的内容直到遇到逗号 `,` 字符，并将包括逗号在内的内容返回。循环会持续读取直到遇到文件末尾 (EOF)。

**命令行参数的具体处理:**

这段测试代码本身不直接处理命令行参数。它的运行依赖于 Go 的测试框架。你可以使用 `go test` 命令来运行该测试文件，并可以通过一些 `go test` 的参数来控制测试行为，例如：

*   `go test`: 运行当前目录下的所有测试文件。
*   `go test -v`: 显示详细的测试输出。
*   `go test -run <正则表达式>`:  运行名称匹配正则表达式的测试函数。例如，`go test -run TestNewBuffer` 只会运行 `TestNewBuffer` 函数。
*   `go test -bench <正则表达式>`: 运行名称匹配正则表达式的基准测试函数。例如，`go test -bench BenchmarkWriteByte`。
*   `go test -short`:  运行标记为 "short" 的测试（这段代码中有使用 `testing.Short()` 来跳过一些耗时的测试）。

**使用者易犯错的点举例:**

1. **未处理 `Read` 方法返回的错误:**  `Read` 方法在读取到文件末尾时会返回 `io.EOF` 错误。使用者可能没有正确处理这个错误，导致程序出现意外行为。

    ```go
    package main

    import (
    	"bytes"
    	"fmt"
    	"io"
    )

    func main() {
    	buf := bytes.NewBufferString("hello")
    	readBuf := make([]byte, 10)
    	n, err := buf.Read(readBuf)
    	fmt.Printf("Read %d bytes: %s, error: %v\n", n, string(readBuf[:n]), err) // 输出：Read 5 bytes: hello, error: EOF

    	n, err = buf.Read(readBuf) // 再次读取
    	fmt.Printf("Read %d bytes: %s, error: %v\n", n, string(readBuf[:n]), err) // 输出：Read 0 bytes: , error: EOF
    }
    ```

    **错误点:**  第二次 `Read` 返回 `io.EOF`，`n` 为 0，表示没有读取到任何数据。如果代码没有判断 `err == io.EOF`，可能会继续使用 `readBuf` 中的旧数据，导致逻辑错误。

2. **混淆 `Len()` 和 `Cap()`:**  `Len()` 返回 `Buffer` 中实际存储数据的长度，而 `Cap()` 返回 `Buffer` 底层字节切片的容量。初学者可能会误以为 `Cap()` 是剩余可写入的空间。

    ```go
    package main

    import (
    	"bytes"
    	"fmt"
    )

    func main() {
    	buf := bytes.NewBuffer(make([]byte, 5, 10)) // 初始长度 5，容量 10
    	buf.WriteString("abc")
    	fmt.Println("Len:", buf.Len()) // 输出：Len: 8
    	fmt.Println("Cap:", buf.Cap()) // 输出：Cap: 10
    }
    ```

    **错误点:**  虽然容量是 10，但 `Len()` 是 8，表示已经写入了 8 个字节。直接使用 `buf.Bytes()[buf.Cap():]` 会导致越界访问。

总而言之，`go/src/bytes/buffer_test.go` 是 `bytes` 包中 `Buffer` 类型功能和正确性的重要保障，它通过各种测试用例覆盖了 `Buffer` 的核心行为和边缘情况。理解这些测试用例有助于更深入地理解 `bytes.Buffer` 的工作原理和正确使用方式。

### 提示词
```
这是路径为go/src/bytes/buffer_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package bytes_test

import (
	. "bytes"
	"fmt"
	"internal/testenv"
	"io"
	"math/rand"
	"strconv"
	"testing"
	"unicode/utf8"
)

const N = 10000       // make this bigger for a larger (and slower) test
var testString string // test data for write tests
var testBytes []byte  // test data; same as testString but as a slice.

type negativeReader struct{}

func (r *negativeReader) Read([]byte) (int, error) { return -1, nil }

func init() {
	testBytes = make([]byte, N)
	for i := 0; i < N; i++ {
		testBytes[i] = 'a' + byte(i%26)
	}
	testString = string(testBytes)
}

// Verify that contents of buf match the string s.
func check(t *testing.T, testname string, buf *Buffer, s string) {
	bytes := buf.Bytes()
	str := buf.String()
	if buf.Len() != len(bytes) {
		t.Errorf("%s: buf.Len() == %d, len(buf.Bytes()) == %d", testname, buf.Len(), len(bytes))
	}

	if buf.Len() != len(str) {
		t.Errorf("%s: buf.Len() == %d, len(buf.String()) == %d", testname, buf.Len(), len(str))
	}

	if buf.Len() != len(s) {
		t.Errorf("%s: buf.Len() == %d, len(s) == %d", testname, buf.Len(), len(s))
	}

	if string(bytes) != s {
		t.Errorf("%s: string(buf.Bytes()) == %q, s == %q", testname, string(bytes), s)
	}
}

// Fill buf through n writes of string fus.
// The initial contents of buf corresponds to the string s;
// the result is the final contents of buf returned as a string.
func fillString(t *testing.T, testname string, buf *Buffer, s string, n int, fus string) string {
	check(t, testname+" (fill 1)", buf, s)
	for ; n > 0; n-- {
		m, err := buf.WriteString(fus)
		if m != len(fus) {
			t.Errorf(testname+" (fill 2): m == %d, expected %d", m, len(fus))
		}
		if err != nil {
			t.Errorf(testname+" (fill 3): err should always be nil, found err == %s", err)
		}
		s += fus
		check(t, testname+" (fill 4)", buf, s)
	}
	return s
}

// Fill buf through n writes of byte slice fub.
// The initial contents of buf corresponds to the string s;
// the result is the final contents of buf returned as a string.
func fillBytes(t *testing.T, testname string, buf *Buffer, s string, n int, fub []byte) string {
	check(t, testname+" (fill 1)", buf, s)
	for ; n > 0; n-- {
		m, err := buf.Write(fub)
		if m != len(fub) {
			t.Errorf(testname+" (fill 2): m == %d, expected %d", m, len(fub))
		}
		if err != nil {
			t.Errorf(testname+" (fill 3): err should always be nil, found err == %s", err)
		}
		s += string(fub)
		check(t, testname+" (fill 4)", buf, s)
	}
	return s
}

func TestNewBuffer(t *testing.T) {
	buf := NewBuffer(testBytes)
	check(t, "NewBuffer", buf, testString)
}

var buf Buffer

// Calling NewBuffer and immediately shallow copying the Buffer struct
// should not result in any allocations.
// This can be used to reset the underlying []byte of an existing Buffer.
func TestNewBufferShallow(t *testing.T) {
	testenv.SkipIfOptimizationOff(t)
	n := testing.AllocsPerRun(1000, func() {
		buf = *NewBuffer(testBytes)
	})
	if n > 0 {
		t.Errorf("allocations occurred while shallow copying")
	}
	check(t, "NewBuffer", &buf, testString)
}

func TestNewBufferString(t *testing.T) {
	buf := NewBufferString(testString)
	check(t, "NewBufferString", buf, testString)
}

// Empty buf through repeated reads into fub.
// The initial contents of buf corresponds to the string s.
func empty(t *testing.T, testname string, buf *Buffer, s string, fub []byte) {
	check(t, testname+" (empty 1)", buf, s)

	for {
		n, err := buf.Read(fub)
		if n == 0 {
			break
		}
		if err != nil {
			t.Errorf(testname+" (empty 2): err should always be nil, found err == %s", err)
		}
		s = s[n:]
		check(t, testname+" (empty 3)", buf, s)
	}

	check(t, testname+" (empty 4)", buf, "")
}

func TestBasicOperations(t *testing.T) {
	var buf Buffer

	for i := 0; i < 5; i++ {
		check(t, "TestBasicOperations (1)", &buf, "")

		buf.Reset()
		check(t, "TestBasicOperations (2)", &buf, "")

		buf.Truncate(0)
		check(t, "TestBasicOperations (3)", &buf, "")

		n, err := buf.Write(testBytes[0:1])
		if want := 1; err != nil || n != want {
			t.Errorf("Write: got (%d, %v), want (%d, %v)", n, err, want, nil)
		}
		check(t, "TestBasicOperations (4)", &buf, "a")

		buf.WriteByte(testString[1])
		check(t, "TestBasicOperations (5)", &buf, "ab")

		n, err = buf.Write(testBytes[2:26])
		if want := 24; err != nil || n != want {
			t.Errorf("Write: got (%d, %v), want (%d, %v)", n, err, want, nil)
		}
		check(t, "TestBasicOperations (6)", &buf, testString[0:26])

		buf.Truncate(26)
		check(t, "TestBasicOperations (7)", &buf, testString[0:26])

		buf.Truncate(20)
		check(t, "TestBasicOperations (8)", &buf, testString[0:20])

		empty(t, "TestBasicOperations (9)", &buf, testString[0:20], make([]byte, 5))
		empty(t, "TestBasicOperations (10)", &buf, "", make([]byte, 100))

		buf.WriteByte(testString[1])
		c, err := buf.ReadByte()
		if want := testString[1]; err != nil || c != want {
			t.Errorf("ReadByte: got (%q, %v), want (%q, %v)", c, err, want, nil)
		}
		c, err = buf.ReadByte()
		if err != io.EOF {
			t.Errorf("ReadByte: got (%q, %v), want (%q, %v)", c, err, byte(0), io.EOF)
		}
	}
}

func TestLargeStringWrites(t *testing.T) {
	var buf Buffer
	limit := 30
	if testing.Short() {
		limit = 9
	}
	for i := 3; i < limit; i += 3 {
		s := fillString(t, "TestLargeWrites (1)", &buf, "", 5, testString)
		empty(t, "TestLargeStringWrites (2)", &buf, s, make([]byte, len(testString)/i))
	}
	check(t, "TestLargeStringWrites (3)", &buf, "")
}

func TestLargeByteWrites(t *testing.T) {
	var buf Buffer
	limit := 30
	if testing.Short() {
		limit = 9
	}
	for i := 3; i < limit; i += 3 {
		s := fillBytes(t, "TestLargeWrites (1)", &buf, "", 5, testBytes)
		empty(t, "TestLargeByteWrites (2)", &buf, s, make([]byte, len(testString)/i))
	}
	check(t, "TestLargeByteWrites (3)", &buf, "")
}

func TestLargeStringReads(t *testing.T) {
	var buf Buffer
	for i := 3; i < 30; i += 3 {
		s := fillString(t, "TestLargeReads (1)", &buf, "", 5, testString[:len(testString)/i])
		empty(t, "TestLargeReads (2)", &buf, s, make([]byte, len(testString)))
	}
	check(t, "TestLargeStringReads (3)", &buf, "")
}

func TestLargeByteReads(t *testing.T) {
	var buf Buffer
	for i := 3; i < 30; i += 3 {
		s := fillBytes(t, "TestLargeReads (1)", &buf, "", 5, testBytes[:len(testBytes)/i])
		empty(t, "TestLargeReads (2)", &buf, s, make([]byte, len(testString)))
	}
	check(t, "TestLargeByteReads (3)", &buf, "")
}

func TestMixedReadsAndWrites(t *testing.T) {
	var buf Buffer
	s := ""
	for i := 0; i < 50; i++ {
		wlen := rand.Intn(len(testString))
		if i%2 == 0 {
			s = fillString(t, "TestMixedReadsAndWrites (1)", &buf, s, 1, testString[0:wlen])
		} else {
			s = fillBytes(t, "TestMixedReadsAndWrites (1)", &buf, s, 1, testBytes[0:wlen])
		}

		rlen := rand.Intn(len(testString))
		fub := make([]byte, rlen)
		n, _ := buf.Read(fub)
		s = s[n:]
	}
	empty(t, "TestMixedReadsAndWrites (2)", &buf, s, make([]byte, buf.Len()))
}

func TestCapWithPreallocatedSlice(t *testing.T) {
	buf := NewBuffer(make([]byte, 10))
	n := buf.Cap()
	if n != 10 {
		t.Errorf("expected 10, got %d", n)
	}
}

func TestCapWithSliceAndWrittenData(t *testing.T) {
	buf := NewBuffer(make([]byte, 0, 10))
	buf.Write([]byte("test"))
	n := buf.Cap()
	if n != 10 {
		t.Errorf("expected 10, got %d", n)
	}
}

func TestNil(t *testing.T) {
	var b *Buffer
	if b.String() != "<nil>" {
		t.Errorf("expected <nil>; got %q", b.String())
	}
}

func TestReadFrom(t *testing.T) {
	var buf Buffer
	for i := 3; i < 30; i += 3 {
		s := fillBytes(t, "TestReadFrom (1)", &buf, "", 5, testBytes[:len(testBytes)/i])
		var b Buffer
		b.ReadFrom(&buf)
		empty(t, "TestReadFrom (2)", &b, s, make([]byte, len(testString)))
	}
}

type panicReader struct{ panic bool }

func (r panicReader) Read(p []byte) (int, error) {
	if r.panic {
		panic("oops")
	}
	return 0, io.EOF
}

// Make sure that an empty Buffer remains empty when
// it is "grown" before a Read that panics
func TestReadFromPanicReader(t *testing.T) {

	// First verify non-panic behaviour
	var buf Buffer
	i, err := buf.ReadFrom(panicReader{})
	if err != nil {
		t.Fatal(err)
	}
	if i != 0 {
		t.Fatalf("unexpected return from bytes.ReadFrom (1): got: %d, want %d", i, 0)
	}
	check(t, "TestReadFromPanicReader (1)", &buf, "")

	// Confirm that when Reader panics, the empty buffer remains empty
	var buf2 Buffer
	defer func() {
		recover()
		check(t, "TestReadFromPanicReader (2)", &buf2, "")
	}()
	buf2.ReadFrom(panicReader{panic: true})
}

func TestReadFromNegativeReader(t *testing.T) {
	var b Buffer
	defer func() {
		switch err := recover().(type) {
		case nil:
			t.Fatal("bytes.Buffer.ReadFrom didn't panic")
		case error:
			// this is the error string of errNegativeRead
			wantError := "bytes.Buffer: reader returned negative count from Read"
			if err.Error() != wantError {
				t.Fatalf("recovered panic: got %v, want %v", err.Error(), wantError)
			}
		default:
			t.Fatalf("unexpected panic value: %#v", err)
		}
	}()

	b.ReadFrom(new(negativeReader))
}

func TestWriteTo(t *testing.T) {
	var buf Buffer
	for i := 3; i < 30; i += 3 {
		s := fillBytes(t, "TestWriteTo (1)", &buf, "", 5, testBytes[:len(testBytes)/i])
		var b Buffer
		buf.WriteTo(&b)
		empty(t, "TestWriteTo (2)", &b, s, make([]byte, len(testString)))
	}
}

func TestWriteAppend(t *testing.T) {
	var got Buffer
	var want []byte
	for i := 0; i < 1000; i++ {
		b := got.AvailableBuffer()
		b = strconv.AppendInt(b, int64(i), 10)
		want = strconv.AppendInt(want, int64(i), 10)
		got.Write(b)
	}
	if !Equal(got.Bytes(), want) {
		t.Fatalf("Bytes() = %q, want %q", got, want)
	}

	// With a sufficiently sized buffer, there should be no allocations.
	n := testing.AllocsPerRun(100, func() {
		got.Reset()
		for i := 0; i < 1000; i++ {
			b := got.AvailableBuffer()
			b = strconv.AppendInt(b, int64(i), 10)
			got.Write(b)
		}
	})
	if n > 0 {
		t.Errorf("allocations occurred while appending")
	}
}

func TestRuneIO(t *testing.T) {
	const NRune = 1000
	// Built a test slice while we write the data
	b := make([]byte, utf8.UTFMax*NRune)
	var buf Buffer
	n := 0
	for r := rune(0); r < NRune; r++ {
		size := utf8.EncodeRune(b[n:], r)
		nbytes, err := buf.WriteRune(r)
		if err != nil {
			t.Fatalf("WriteRune(%U) error: %s", r, err)
		}
		if nbytes != size {
			t.Fatalf("WriteRune(%U) expected %d, got %d", r, size, nbytes)
		}
		n += size
	}
	b = b[0:n]

	// Check the resulting bytes
	if !Equal(buf.Bytes(), b) {
		t.Fatalf("incorrect result from WriteRune: %q not %q", buf.Bytes(), b)
	}

	p := make([]byte, utf8.UTFMax)
	// Read it back with ReadRune
	for r := rune(0); r < NRune; r++ {
		size := utf8.EncodeRune(p, r)
		nr, nbytes, err := buf.ReadRune()
		if nr != r || nbytes != size || err != nil {
			t.Fatalf("ReadRune(%U) got %U,%d not %U,%d (err=%s)", r, nr, nbytes, r, size, err)
		}
	}

	// Check that UnreadRune works
	buf.Reset()

	// check at EOF
	if err := buf.UnreadRune(); err == nil {
		t.Fatal("UnreadRune at EOF: got no error")
	}
	if _, _, err := buf.ReadRune(); err == nil {
		t.Fatal("ReadRune at EOF: got no error")
	}
	if err := buf.UnreadRune(); err == nil {
		t.Fatal("UnreadRune after ReadRune at EOF: got no error")
	}

	// check not at EOF
	buf.Write(b)
	for r := rune(0); r < NRune; r++ {
		r1, size, _ := buf.ReadRune()
		if err := buf.UnreadRune(); err != nil {
			t.Fatalf("UnreadRune(%U) got error %q", r, err)
		}
		r2, nbytes, err := buf.ReadRune()
		if r1 != r2 || r1 != r || nbytes != size || err != nil {
			t.Fatalf("ReadRune(%U) after UnreadRune got %U,%d not %U,%d (err=%s)", r, r2, nbytes, r, size, err)
		}
	}
}

func TestWriteInvalidRune(t *testing.T) {
	// Invalid runes, including negative ones, should be written as
	// utf8.RuneError.
	for _, r := range []rune{-1, utf8.MaxRune + 1} {
		var buf Buffer
		buf.WriteRune(r)
		check(t, fmt.Sprintf("TestWriteInvalidRune (%d)", r), &buf, "\uFFFD")
	}
}

func TestNext(t *testing.T) {
	b := []byte{0, 1, 2, 3, 4}
	tmp := make([]byte, 5)
	for i := 0; i <= 5; i++ {
		for j := i; j <= 5; j++ {
			for k := 0; k <= 6; k++ {
				// 0 <= i <= j <= 5; 0 <= k <= 6
				// Check that if we start with a buffer
				// of length j at offset i and ask for
				// Next(k), we get the right bytes.
				buf := NewBuffer(b[0:j])
				n, _ := buf.Read(tmp[0:i])
				if n != i {
					t.Fatalf("Read %d returned %d", i, n)
				}
				bb := buf.Next(k)
				want := k
				if want > j-i {
					want = j - i
				}
				if len(bb) != want {
					t.Fatalf("in %d,%d: len(Next(%d)) == %d", i, j, k, len(bb))
				}
				for l, v := range bb {
					if v != byte(l+i) {
						t.Fatalf("in %d,%d: Next(%d)[%d] = %d, want %d", i, j, k, l, v, l+i)
					}
				}
			}
		}
	}
}

var readBytesTests = []struct {
	buffer   string
	delim    byte
	expected []string
	err      error
}{
	{"", 0, []string{""}, io.EOF},
	{"a\x00", 0, []string{"a\x00"}, nil},
	{"abbbaaaba", 'b', []string{"ab", "b", "b", "aaab"}, nil},
	{"hello\x01world", 1, []string{"hello\x01"}, nil},
	{"foo\nbar", 0, []string{"foo\nbar"}, io.EOF},
	{"alpha\nbeta\ngamma\n", '\n', []string{"alpha\n", "beta\n", "gamma\n"}, nil},
	{"alpha\nbeta\ngamma", '\n', []string{"alpha\n", "beta\n", "gamma"}, io.EOF},
}

func TestReadBytes(t *testing.T) {
	for _, test := range readBytesTests {
		buf := NewBufferString(test.buffer)
		var err error
		for _, expected := range test.expected {
			var bytes []byte
			bytes, err = buf.ReadBytes(test.delim)
			if string(bytes) != expected {
				t.Errorf("expected %q, got %q", expected, bytes)
			}
			if err != nil {
				break
			}
		}
		if err != test.err {
			t.Errorf("expected error %v, got %v", test.err, err)
		}
	}
}

func TestReadString(t *testing.T) {
	for _, test := range readBytesTests {
		buf := NewBufferString(test.buffer)
		var err error
		for _, expected := range test.expected {
			var s string
			s, err = buf.ReadString(test.delim)
			if s != expected {
				t.Errorf("expected %q, got %q", expected, s)
			}
			if err != nil {
				break
			}
		}
		if err != test.err {
			t.Errorf("expected error %v, got %v", test.err, err)
		}
	}
}

func BenchmarkReadString(b *testing.B) {
	const n = 32 << 10

	data := make([]byte, n)
	data[n-1] = 'x'
	b.SetBytes(int64(n))
	for i := 0; i < b.N; i++ {
		buf := NewBuffer(data)
		_, err := buf.ReadString('x')
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestGrow(t *testing.T) {
	x := []byte{'x'}
	y := []byte{'y'}
	tmp := make([]byte, 72)
	for _, growLen := range []int{0, 100, 1000, 10000, 100000} {
		for _, startLen := range []int{0, 100, 1000, 10000, 100000} {
			xBytes := Repeat(x, startLen)

			buf := NewBuffer(xBytes)
			// If we read, this affects buf.off, which is good to test.
			readBytes, _ := buf.Read(tmp)
			yBytes := Repeat(y, growLen)
			allocs := testing.AllocsPerRun(100, func() {
				buf.Grow(growLen)
				buf.Write(yBytes)
			})
			// Check no allocation occurs in write, as long as we're single-threaded.
			if allocs != 0 {
				t.Errorf("allocation occurred during write")
			}
			// Check that buffer has correct data.
			if !Equal(buf.Bytes()[0:startLen-readBytes], xBytes[readBytes:]) {
				t.Errorf("bad initial data at %d %d", startLen, growLen)
			}
			if !Equal(buf.Bytes()[startLen-readBytes:startLen-readBytes+growLen], yBytes) {
				t.Errorf("bad written data at %d %d", startLen, growLen)
			}
		}
	}
}

func TestGrowOverflow(t *testing.T) {
	defer func() {
		if err := recover(); err != ErrTooLarge {
			t.Errorf("after too-large Grow, recover() = %v; want %v", err, ErrTooLarge)
		}
	}()

	buf := NewBuffer(make([]byte, 1))
	const maxInt = int(^uint(0) >> 1)
	buf.Grow(maxInt)
}

// Was a bug: used to give EOF reading empty slice at EOF.
func TestReadEmptyAtEOF(t *testing.T) {
	b := new(Buffer)
	slice := make([]byte, 0)
	n, err := b.Read(slice)
	if err != nil {
		t.Errorf("read error: %v", err)
	}
	if n != 0 {
		t.Errorf("wrong count; got %d want 0", n)
	}
}

func TestUnreadByte(t *testing.T) {
	b := new(Buffer)

	// check at EOF
	if err := b.UnreadByte(); err == nil {
		t.Fatal("UnreadByte at EOF: got no error")
	}
	if _, err := b.ReadByte(); err == nil {
		t.Fatal("ReadByte at EOF: got no error")
	}
	if err := b.UnreadByte(); err == nil {
		t.Fatal("UnreadByte after ReadByte at EOF: got no error")
	}

	// check not at EOF
	b.WriteString("abcdefghijklmnopqrstuvwxyz")

	// after unsuccessful read
	if n, err := b.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d,%v; want 0,nil", n, err)
	}
	if err := b.UnreadByte(); err == nil {
		t.Fatal("UnreadByte after Read(nil): got no error")
	}

	// after successful read
	if _, err := b.ReadBytes('m'); err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if err := b.UnreadByte(); err != nil {
		t.Fatalf("UnreadByte: %v", err)
	}
	c, err := b.ReadByte()
	if err != nil {
		t.Fatalf("ReadByte: %v", err)
	}
	if c != 'm' {
		t.Errorf("ReadByte = %q; want %q", c, 'm')
	}
}

// Tests that we occasionally compact. Issue 5154.
func TestBufferGrowth(t *testing.T) {
	var b Buffer
	buf := make([]byte, 1024)
	b.Write(buf[0:1])
	var cap0 int
	for i := 0; i < 5<<10; i++ {
		b.Write(buf)
		b.Read(buf)
		if i == 0 {
			cap0 = b.Cap()
		}
	}
	cap1 := b.Cap()
	// (*Buffer).grow allows for 2x capacity slop before sliding,
	// so set our error threshold at 3x.
	if cap1 > cap0*3 {
		t.Errorf("buffer cap = %d; too big (grew from %d)", cap1, cap0)
	}
}

func BenchmarkWriteByte(b *testing.B) {
	const n = 4 << 10
	b.SetBytes(n)
	buf := NewBuffer(make([]byte, n))
	for i := 0; i < b.N; i++ {
		buf.Reset()
		for i := 0; i < n; i++ {
			buf.WriteByte('x')
		}
	}
}

func BenchmarkWriteRune(b *testing.B) {
	const n = 4 << 10
	const r = '☺'
	b.SetBytes(int64(n * utf8.RuneLen(r)))
	buf := NewBuffer(make([]byte, n*utf8.UTFMax))
	for i := 0; i < b.N; i++ {
		buf.Reset()
		for i := 0; i < n; i++ {
			buf.WriteRune(r)
		}
	}
}

// From Issue 5154.
func BenchmarkBufferNotEmptyWriteRead(b *testing.B) {
	buf := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		var b Buffer
		b.Write(buf[0:1])
		for i := 0; i < 5<<10; i++ {
			b.Write(buf)
			b.Read(buf)
		}
	}
}

// Check that we don't compact too often. From Issue 5154.
func BenchmarkBufferFullSmallReads(b *testing.B) {
	buf := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		var b Buffer
		b.Write(buf)
		for b.Len()+20 < b.Cap() {
			b.Write(buf[:10])
		}
		for i := 0; i < 5<<10; i++ {
			b.Read(buf[:1])
			b.Write(buf[:1])
		}
	}
}

func BenchmarkBufferWriteBlock(b *testing.B) {
	block := make([]byte, 1024)
	for _, n := range []int{1 << 12, 1 << 16, 1 << 20} {
		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var bb Buffer
				for bb.Len() < n {
					bb.Write(block)
				}
			}
		})
	}
}

func BenchmarkBufferAppendNoCopy(b *testing.B) {
	var bb Buffer
	bb.Grow(16 << 20)
	b.SetBytes(int64(bb.Available()))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bb.Reset()
		b := bb.AvailableBuffer()
		b = b[:cap(b)] // use max capacity to simulate a large append operation
		bb.Write(b)    // should be nearly infinitely fast
	}
}
```