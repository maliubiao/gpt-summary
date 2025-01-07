Response:
Let's break down the thought process for analyzing the Go code snippet and generating the Chinese response.

1. **Understand the Goal:** The request is to analyze a Go test file (`reader_test.go`) and explain its functionality, focusing on the `bytes.Reader` type and its methods. The response needs to be in Chinese and include code examples, input/output, and potential pitfalls.

2. **Initial Scan and Identification:**  The first step is to quickly scan the code to identify key elements. I see:
    * `package bytes_test`: This tells me it's a test file for the `bytes` package.
    * `import`:  Highlights the dependencies, particularly the `bytes` package itself, `fmt`, `io`, `sync`, and `testing`. This indicates we're dealing with byte manipulation, input/output operations, concurrency, and of course, testing.
    * Function names like `TestReader`, `TestReadAt`, `TestReaderWriteTo`, `TestReaderLen`, etc.:  These strongly suggest that the code is testing various methods of the `bytes.Reader` type.

3. **Focus on `bytes.Reader`:** The filename `reader_test.go` and the test function names clearly point to the `bytes.Reader` as the central subject. I need to understand what this type does. Recalling my Go knowledge, `bytes.Reader` is designed to read data from an in-memory byte slice.

4. **Analyze Individual Test Functions:** Now, I'll examine each test function to understand the specific functionality being tested:

    * **`TestReader`:** This test seems to cover the core `Read` and `Seek` methods. The `tests` slice defines various scenarios with different `seek` offsets, read lengths (`n`), and expected outputs. This is crucial for understanding how `Seek` and `Read` interact.

    * **`TestReadAfterBigSeek`:** This focuses on handling seeking beyond the end of the underlying byte slice. The expected outcome is `io.EOF`.

    * **`TestReaderAt`:**  This tests the `ReadAt` method, which allows reading from a specific offset without affecting the internal read pointer. The test cases include reading within bounds, out of bounds, and with a negative offset.

    * **`TestReaderAtConcurrent`:** The name and the `sync.WaitGroup` clearly indicate this is a concurrency test for `ReadAt`. It aims to ensure that `ReadAt` is safe for concurrent use and doesn't have race conditions (it doesn't modify internal state).

    * **`TestEmptyReaderConcurrent`:** Another concurrency test, this one focuses on the `Read` method of an empty `bytes.Reader`.

    * **`TestReaderWriteTo`:** This tests the `WriteTo` method, which writes the remaining content of the reader to a given `io.Writer`.

    * **`TestReaderLen`:**  This tests the `Len` method, which returns the number of unread bytes in the reader.

    * **`TestUnreadRuneError`:** This test focuses on the behavior of `UnreadRune` after other read operations (like `Read`, `ReadByte`). It highlights the constraint that `UnreadRune` can only be called once after a successful `ReadRune`.

    * **`TestReaderDoubleUnreadRune`:** This specifically tests calling `UnreadByte` twice in a row, demonstrating that it results in an error.

    * **`TestReaderCopyNothing`:** This test compares the behavior of `io.Copy` with and without the `WriteTo` method present on the reader when the reader is empty.

    * **`TestReaderLenSize`:** This clarifies the difference between `Len` (remaining bytes) and `Size` (total bytes).

    * **`TestReaderReset`:** This tests the `Reset` method, which allows reusing the `Reader` with a new byte slice.

    * **`TestReaderZero`:** This tests the behavior of various methods on a zero-initialized `Reader`.

5. **Synthesize and Structure the Response (in Chinese):**  Now that I understand the individual tests, I need to structure the information logically in Chinese.

    * **Overall Functionality:** Start with a high-level explanation of the purpose of the `reader_test.go` file and the `bytes.Reader`.
    * **Method-Specific Explanations:**  For each significant method (`Read`, `Seek`, `ReadAt`, `WriteTo`, `Len`, `Size`, `Reset`, `UnreadRune`, `UnreadByte`), explain its function and provide a simple Go code example demonstrating its usage. Include the assumed input and expected output for clarity.
    * **Concurrency Aspects:**  Specifically mention the concurrency tests and their significance in verifying the thread-safety of `ReadAt` and `Read` on empty readers.
    * **Potential Pitfalls:**  Highlight the common errors like calling `UnreadRune` or `UnreadByte` multiple times or seeking to negative positions. Provide examples of these errors.
    * **Command-line Arguments:**  Since the code doesn't directly process command-line arguments, explicitly state that this aspect isn't covered.

6. **Refine and Review:**  Finally, review the Chinese response for clarity, accuracy, and completeness. Ensure that the code examples are correct and the explanations are easy to understand. Make sure the terminology is consistent and the flow is logical. For instance, ensure the explanation of `Seek` covers the different `io.Seek...` constants.

By following these steps, I can systematically analyze the Go test code and generate a comprehensive and accurate Chinese explanation as requested. The key is to break down the problem into smaller, manageable parts, understand the purpose of each part, and then synthesize the information in a clear and structured way.
这段代码是 Go 语言标准库 `bytes` 包中 `Reader` 类型的测试代码，位于 `go/src/bytes/reader_test.go` 文件中。它的主要功能是 **测试 `bytes.Reader` 类型的各种方法，以确保其行为符合预期。**

`bytes.Reader` 实现了 `io.Reader`, `io.Seeker`, `io.ReaderAt`, `io.WriterTo`, `io.ByteScanner`, 和 `io.RuneScanner` 接口，这意味着它可以被用来从一个字节切片中读取数据，并且支持查找、在指定偏移量读取、写入到其他 `io.Writer` 以及读取单个字节或 Rune（Unicode 码点）。

下面列举一下测试代码中测试的主要功能点，并用 Go 代码举例说明：

**1. 基本的 `Read` 和 `Seek` 功能测试:**

   - 测试从 `Reader` 中读取指定数量的字节。
   - 测试使用 `Seek` 方法改变 `Reader` 内部的读取位置。
   - 测试 `Seek` 方法的不同起始位置 (`io.SeekStart`, `io.SeekCurrent`, `io.SeekEnd`)。
   - 测试 `Seek` 方法的错误处理，例如负数偏移量。
   - 测试读取超出 `Reader` 长度的情况，预期返回 `io.EOF` 错误。

   **Go 代码示例：**

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "io"
   )

   func main() {
       r := bytes.NewReader([]byte("Hello, World!"))
       buf := make([]byte, 5)

       // 从头开始读取 5 个字节
       n, err := r.Read(buf)
       fmt.Printf("Read %d bytes: %s, error: %v\n", n, string(buf[:n]), err) // 输出: Read 5 bytes: Hello, error: <nil>

       // 从当前位置继续读取 3 个字节
       n, err = r.Read(buf[:3])
       fmt.Printf("Read %d bytes: %s, error: %v\n", n, string(buf[:n]), err) // 输出: Read 3 bytes: , Wo, error: <nil>

       // Seek 到偏移量 7 (从头开始)
       _, err = r.Seek(7, io.SeekStart)
       if err != nil {
           fmt.Println("Seek error:", err)
       }

       // 从新的位置读取剩余的字节
       remaining, _ := io.ReadAll(r)
       fmt.Printf("Remaining: %s\n", string(remaining)) // 输出: Remaining: rld!
   }
   ```

   **假设输入与输出：**  如上面代码中的注释所示。

**2. 大偏移量 `Seek` 后的读取测试:**

   - 测试当 `Seek` 到一个很大的偏移量后，后续的 `Read` 操作是否会正确返回 `io.EOF`。

   **Go 代码示例：**

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "io"
   )

   func main() {
       r := bytes.NewReader([]byte("abcdefg"))
       _, err := r.Seek(1<<31+5, io.SeekStart) // Seek 到一个很大的偏移量
       if err != nil {
           fmt.Println("Seek error:", err)
       }

       buf := make([]byte, 10)
       n, err := r.Read(buf)
       fmt.Printf("Read %d bytes, error: %v\n", n, err) // 输出: Read 0 bytes, error: EOF
   }
   ```

   **假设输入与输出：**  `Read 0 bytes, error: EOF`

**3. `ReadAt` 功能测试:**

   - 测试 `ReadAt` 方法，该方法允许从指定的偏移量读取数据，而不改变 `Reader` 内部的读取位置。
   - 测试 `ReadAt` 的边界情况和错误处理，例如负数偏移量或超出长度的偏移量。

   **Go 代码示例：**

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "io"
   )

   func main() {
       r := bytes.NewReader([]byte("0123456789"))
       buf := make([]byte, 5)

       // 从偏移量 2 开始读取 5 个字节
       n, err := r.ReadAt(buf, 2)
       fmt.Printf("ReadAt %d bytes: %s, error: %v\n", n, string(buf[:n]), err) // 输出: ReadAt 5 bytes: 23456, error: <nil>

       // 再次从偏移量 2 开始读取，证明内部读取位置没有改变
       n, err = r.ReadAt(buf, 2)
       fmt.Printf("ReadAt %d bytes: %s, error: %v\n", n, string(buf[:n]), err) // 输出: ReadAt 5 bytes: 23456, error: <nil>

       // 从超出长度的偏移量读取
       n, err = r.ReadAt(buf, 15)
       fmt.Printf("ReadAt %d bytes, error: %v\n", n, err) // 输出: ReadAt 0 bytes, error: EOF

       // 从负数偏移量读取
       n, err = r.ReadAt(buf, -1)
       fmt.Printf("ReadAt %d bytes, error: %v\n", n, err) // 输出: ReadAt 0 bytes, error: bytes.Reader.ReadAt: negative offset
   }
   ```

   **假设输入与输出：** 如上面代码中的注释所示。

**4. `ReadAt` 的并发安全性测试:**

   - 使用 `sync.WaitGroup` 启动多个 Goroutine 并发调用 `ReadAt` 方法，以检测是否存在竞态条件，验证 `ReadAt` 是否是并发安全的（不会修改内部状态）。

**5. 空 `Reader` 的并发 `Read` 测试:**

   - 测试多个 Goroutine 并发地从一个空的 `Reader` 中读取，验证其行为是否正确。

**6. `WriteTo` 功能测试:**

   - 测试 `WriteTo` 方法，该方法将 `Reader` 中剩余的数据写入到指定的 `io.Writer` 中。
   - 测试写入后 `Reader` 的内部状态（读取位置应该移动到末尾）。

   **Go 代码示例：**

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "strings"
   )

   func main() {
       r := bytes.NewReader([]byte("This is a test"))
       var buf strings.Builder

       n, err := r.WriteTo(&buf)
       fmt.Printf("Written %d bytes, error: %v\n", n, err)        // 输出: Written 14 bytes, error: <nil>
       fmt.Println("Written content:", buf.String())             // 输出: Written content: This is a test
       fmt.Println("Remaining bytes in reader:", r.Len()) // 输出: Remaining bytes in reader: 0
   }
   ```

   **假设输入与输出：** 如上面代码中的注释所示。

**7. `Len` 功能测试:**

   - 测试 `Len` 方法，该方法返回 `Reader` 中未读取的字节数。
   - 测试在进行 `Read` 操作后 `Len` 方法的返回值是否正确更新。

   **Go 代码示例：**

   ```go
   package main

   import (
       "bytes"
       "fmt"
   )

   func main() {
       r := bytes.NewReader([]byte("abcdef"))
       fmt.Println("Initial length:", r.Len()) // 输出: Initial length: 6

       buf := make([]byte, 3)
       r.Read(buf)
       fmt.Println("Length after read:", r.Len()) // 输出: Length after read: 3
   }
   ```

   **假设输入与输出：** 如上面代码中的注释所示。

**8. `UnreadRune` 的错误处理测试:**

   - 测试在调用 `ReadRune` 之后，可以成功调用一次 `UnreadRune`。
   - 测试在其他读取操作（例如 `Read`, `ReadByte`）后调用 `UnreadRune` 会返回错误。
   - 测试连续调用两次 `UnreadRune` 会返回错误。

   **Go 代码示例：**

   ```go
   package main

   import (
       "bytes"
       "fmt"
   )

   func main() {
       r := bytes.NewReader([]byte("你好world"))

       _, _, err := r.ReadRune()
       if err != nil {
           fmt.Println("ReadRune error:", err)
       }

       err = r.UnreadRune()
       fmt.Println("UnreadRune error (after ReadRune):", err) // 输出: UnreadRune error (after ReadRune): <nil>

       _, err = r.ReadByte()
       if err != nil {
           fmt.Println("ReadByte error:", err)
       }

       err = r.UnreadRune()
       fmt.Println("UnreadRune error (after ReadByte):", err) // 输出: UnreadRune error (after ReadByte): bytes.Reader.UnreadRune: previous operation was not a successful ReadRune

       err = r.UnreadByte()
       if err != nil {
           fmt.Println("UnreadByte error:", err)
       }

       err = r.UnreadByte()
       fmt.Println("UnreadByte error (second time):", err) // 输出: UnreadByte error (second time): bytes.Buffer.UnreadByte: previous operation was not a successful read
   }
   ```

   **假设输入与输出：** 如上面代码中的注释所示。

**9. `Copy` 空 `Reader` 的行为测试:**

   - 测试当使用 `io.Copy` 从一个空的 `Reader` 复制数据时，无论 `Reader` 是否实现了 `WriteTo` 接口，结果都应该相同。

**10. `Len` 和 `Size` 的区别测试:**

    - 测试 `Len` 方法返回剩余未读取的字节数，而 `Size` 方法返回 `Reader` 的总大小，即使在读取了一些数据后，`Size` 的值也不会改变。

    **Go 代码示例：**

    ```go
    package main

    import (
        "bytes"
        "fmt"
        "io"
    )

    func main() {
        r := bytes.NewReader([]byte("abcdef"))
        fmt.Println("Initial Len:", r.Len())  // 输出: Initial Len: 6
        fmt.Println("Initial Size:", r.Size()) // 输出: Initial Size: 6

        io.CopyN(io.Discard, r, 3) // 读取 3 个字节
        fmt.Println("Len after read:", r.Len())   // 输出: Len after read: 3
        fmt.Println("Size after read:", r.Size())  // 输出: Size after read: 6
    }
    ```

    **假设输入与输出：** 如上面代码中的注释所示。

**11. `Reset` 功能测试:**

    - 测试 `Reset` 方法，该方法允许将 `Reader` 重置为读取一个新的字节切片。
    - 测试重置后 `UnreadRune` 等方法的行为。

    **Go 代码示例：**

    ```go
    package main

    import (
        "bytes"
        "fmt"
        "io"
    )

    func main() {
        r := bytes.NewReader([]byte("hello"))
        r.ReadByte() // 读取一个字节

        fmt.Println("Len before reset:", r.Len()) // 输出: Len before reset: 4

        r.Reset([]byte("world"))
        fmt.Println("Len after reset:", r.Len())  // 输出: Len after reset: 5

        content, _ := io.ReadAll(r)
        fmt.Println("Content after reset:", string(content)) // 输出: Content after reset: world
    }
    ```

    **假设输入与输出：** 如上面代码中的注释所示。

**12. 零值 `Reader` 的行为测试:**

    - 测试一个未初始化的 `Reader` (零值) 的各种方法调用，例如 `Len`, `Read`, `ReadAt`, `Seek` 等，确保其行为是安全的，通常会返回 `io.EOF` 或其他合理的默认值。

**命令行参数的具体处理:**

这段代码是单元测试，**不涉及任何命令行参数的处理**。单元测试通常在 Go 的测试框架下运行，通过 `go test` 命令执行。

**使用者易犯错的点:**

1. **多次调用 `UnreadRune` 或 `UnreadByte`:**  在成功调用 `ReadRune` 或 `ReadByte` 后，只能成功调用一次对应的 `Unread` 方法。多次调用会导致错误。

    ```go
    package main

    import (
        "bytes"
        "fmt"
    )

    func main() {
        r := bytes.NewReader([]byte("ab"))
        r.ReadByte()
        r.UnreadByte()
        err := r.UnreadByte() // 错误：上一个操作不是成功的读取
        fmt.Println(err)      // 输出: bytes.Buffer.UnreadByte: previous operation was not a successful read
    }
    ```

2. **对 `Seek` 的理解不准确:**  需要理解 `Seek` 方法的起始位置参数 (`io.SeekStart`, `io.SeekCurrent`, `io.SeekEnd`) 和偏移量的含义。负数偏移量或超出边界的偏移量会导致错误或意想不到的结果。

    ```go
    package main

    import (
        "bytes"
        "fmt"
        "io"
    )

    func main() {
        r := bytes.NewReader([]byte("abc"))
        _, err := r.Seek(-1, io.SeekStart) // 错误：负数偏移量
        fmt.Println(err)                   // 输出: bytes.Reader.Seek: negative position
    }
    ```

这段测试代码通过各种场景覆盖了 `bytes.Reader` 的核心功能和边界情况，是确保 `bytes.Reader` 行为正确的重要组成部分。

Prompt: 
```
这是路径为go/src/bytes/reader_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bytes_test

import (
	. "bytes"
	"fmt"
	"io"
	"sync"
	"testing"
)

func TestReader(t *testing.T) {
	r := NewReader([]byte("0123456789"))
	tests := []struct {
		off     int64
		seek    int
		n       int
		want    string
		wantpos int64
		readerr error
		seekerr string
	}{
		{seek: io.SeekStart, off: 0, n: 20, want: "0123456789"},
		{seek: io.SeekStart, off: 1, n: 1, want: "1"},
		{seek: io.SeekCurrent, off: 1, wantpos: 3, n: 2, want: "34"},
		{seek: io.SeekStart, off: -1, seekerr: "bytes.Reader.Seek: negative position"},
		{seek: io.SeekStart, off: 1 << 33, wantpos: 1 << 33, readerr: io.EOF},
		{seek: io.SeekCurrent, off: 1, wantpos: 1<<33 + 1, readerr: io.EOF},
		{seek: io.SeekStart, n: 5, want: "01234"},
		{seek: io.SeekCurrent, n: 5, want: "56789"},
		{seek: io.SeekEnd, off: -1, n: 1, wantpos: 9, want: "9"},
	}

	for i, tt := range tests {
		pos, err := r.Seek(tt.off, tt.seek)
		if err == nil && tt.seekerr != "" {
			t.Errorf("%d. want seek error %q", i, tt.seekerr)
			continue
		}
		if err != nil && err.Error() != tt.seekerr {
			t.Errorf("%d. seek error = %q; want %q", i, err.Error(), tt.seekerr)
			continue
		}
		if tt.wantpos != 0 && tt.wantpos != pos {
			t.Errorf("%d. pos = %d, want %d", i, pos, tt.wantpos)
		}
		buf := make([]byte, tt.n)
		n, err := r.Read(buf)
		if err != tt.readerr {
			t.Errorf("%d. read = %v; want %v", i, err, tt.readerr)
			continue
		}
		got := string(buf[:n])
		if got != tt.want {
			t.Errorf("%d. got %q; want %q", i, got, tt.want)
		}
	}
}

func TestReadAfterBigSeek(t *testing.T) {
	r := NewReader([]byte("0123456789"))
	if _, err := r.Seek(1<<31+5, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if n, err := r.Read(make([]byte, 10)); n != 0 || err != io.EOF {
		t.Errorf("Read = %d, %v; want 0, EOF", n, err)
	}
}

func TestReaderAt(t *testing.T) {
	r := NewReader([]byte("0123456789"))
	tests := []struct {
		off     int64
		n       int
		want    string
		wanterr any
	}{
		{0, 10, "0123456789", nil},
		{1, 10, "123456789", io.EOF},
		{1, 9, "123456789", nil},
		{11, 10, "", io.EOF},
		{0, 0, "", nil},
		{-1, 0, "", "bytes.Reader.ReadAt: negative offset"},
	}
	for i, tt := range tests {
		b := make([]byte, tt.n)
		rn, err := r.ReadAt(b, tt.off)
		got := string(b[:rn])
		if got != tt.want {
			t.Errorf("%d. got %q; want %q", i, got, tt.want)
		}
		if fmt.Sprintf("%v", err) != fmt.Sprintf("%v", tt.wanterr) {
			t.Errorf("%d. got error = %v; want %v", i, err, tt.wanterr)
		}
	}
}

func TestReaderAtConcurrent(t *testing.T) {
	// Test for the race detector, to verify ReadAt doesn't mutate
	// any state.
	r := NewReader([]byte("0123456789"))
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var buf [1]byte
			r.ReadAt(buf[:], int64(i))
		}(i)
	}
	wg.Wait()
}

func TestEmptyReaderConcurrent(t *testing.T) {
	// Test for the race detector, to verify a Read that doesn't yield any bytes
	// is okay to use from multiple goroutines. This was our historic behavior.
	// See golang.org/issue/7856
	r := NewReader([]byte{})
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			var buf [1]byte
			r.Read(buf[:])
		}()
		go func() {
			defer wg.Done()
			r.Read(nil)
		}()
	}
	wg.Wait()
}

func TestReaderWriteTo(t *testing.T) {
	for i := 0; i < 30; i += 3 {
		var l int
		if i > 0 {
			l = len(testString) / i
		}
		s := testString[:l]
		r := NewReader(testBytes[:l])
		var b Buffer
		n, err := r.WriteTo(&b)
		if expect := int64(len(s)); n != expect {
			t.Errorf("got %v; want %v", n, expect)
		}
		if err != nil {
			t.Errorf("for length %d: got error = %v; want nil", l, err)
		}
		if b.String() != s {
			t.Errorf("got string %q; want %q", b.String(), s)
		}
		if r.Len() != 0 {
			t.Errorf("reader contains %v bytes; want 0", r.Len())
		}
	}
}

func TestReaderLen(t *testing.T) {
	const data = "hello world"
	r := NewReader([]byte(data))
	if got, want := r.Len(), 11; got != want {
		t.Errorf("r.Len(): got %d, want %d", got, want)
	}
	if n, err := r.Read(make([]byte, 10)); err != nil || n != 10 {
		t.Errorf("Read failed: read %d %v", n, err)
	}
	if got, want := r.Len(), 1; got != want {
		t.Errorf("r.Len(): got %d, want %d", got, want)
	}
	if n, err := r.Read(make([]byte, 1)); err != nil || n != 1 {
		t.Errorf("Read failed: read %d %v; want 1, nil", n, err)
	}
	if got, want := r.Len(), 0; got != want {
		t.Errorf("r.Len(): got %d, want %d", got, want)
	}
}

var UnreadRuneErrorTests = []struct {
	name string
	f    func(*Reader)
}{
	{"Read", func(r *Reader) { r.Read([]byte{0}) }},
	{"ReadByte", func(r *Reader) { r.ReadByte() }},
	{"UnreadRune", func(r *Reader) { r.UnreadRune() }},
	{"Seek", func(r *Reader) { r.Seek(0, io.SeekCurrent) }},
	{"WriteTo", func(r *Reader) { r.WriteTo(&Buffer{}) }},
}

func TestUnreadRuneError(t *testing.T) {
	for _, tt := range UnreadRuneErrorTests {
		reader := NewReader([]byte("0123456789"))
		if _, _, err := reader.ReadRune(); err != nil {
			// should not happen
			t.Fatal(err)
		}
		tt.f(reader)
		err := reader.UnreadRune()
		if err == nil {
			t.Errorf("Unreading after %s: expected error", tt.name)
		}
	}
}

func TestReaderDoubleUnreadRune(t *testing.T) {
	buf := NewBuffer([]byte("groucho"))
	if _, _, err := buf.ReadRune(); err != nil {
		// should not happen
		t.Fatal(err)
	}
	if err := buf.UnreadByte(); err != nil {
		// should not happen
		t.Fatal(err)
	}
	if err := buf.UnreadByte(); err == nil {
		t.Fatal("UnreadByte: expected error, got nil")
	}
}

// verify that copying from an empty reader always has the same results,
// regardless of the presence of a WriteTo method.
func TestReaderCopyNothing(t *testing.T) {
	type nErr struct {
		n   int64
		err error
	}
	type justReader struct {
		io.Reader
	}
	type justWriter struct {
		io.Writer
	}
	discard := justWriter{io.Discard} // hide ReadFrom

	var with, withOut nErr
	with.n, with.err = io.Copy(discard, NewReader(nil))
	withOut.n, withOut.err = io.Copy(discard, justReader{NewReader(nil)})
	if with != withOut {
		t.Errorf("behavior differs: with = %#v; without: %#v", with, withOut)
	}
}

// tests that Len is affected by reads, but Size is not.
func TestReaderLenSize(t *testing.T) {
	r := NewReader([]byte("abc"))
	io.CopyN(io.Discard, r, 1)
	if r.Len() != 2 {
		t.Errorf("Len = %d; want 2", r.Len())
	}
	if r.Size() != 3 {
		t.Errorf("Size = %d; want 3", r.Size())
	}
}

func TestReaderReset(t *testing.T) {
	r := NewReader([]byte("世界"))
	if _, _, err := r.ReadRune(); err != nil {
		t.Errorf("ReadRune: unexpected error: %v", err)
	}

	const want = "abcdef"
	r.Reset([]byte(want))
	if err := r.UnreadRune(); err == nil {
		t.Errorf("UnreadRune: expected error, got nil")
	}
	buf, err := io.ReadAll(r)
	if err != nil {
		t.Errorf("ReadAll: unexpected error: %v", err)
	}
	if got := string(buf); got != want {
		t.Errorf("ReadAll: got %q, want %q", got, want)
	}
}

func TestReaderZero(t *testing.T) {
	if l := (&Reader{}).Len(); l != 0 {
		t.Errorf("Len: got %d, want 0", l)
	}

	if n, err := (&Reader{}).Read(nil); n != 0 || err != io.EOF {
		t.Errorf("Read: got %d, %v; want 0, io.EOF", n, err)
	}

	if n, err := (&Reader{}).ReadAt(nil, 11); n != 0 || err != io.EOF {
		t.Errorf("ReadAt: got %d, %v; want 0, io.EOF", n, err)
	}

	if b, err := (&Reader{}).ReadByte(); b != 0 || err != io.EOF {
		t.Errorf("ReadByte: got %d, %v; want 0, io.EOF", b, err)
	}

	if ch, size, err := (&Reader{}).ReadRune(); ch != 0 || size != 0 || err != io.EOF {
		t.Errorf("ReadRune: got %d, %d, %v; want 0, 0, io.EOF", ch, size, err)
	}

	if offset, err := (&Reader{}).Seek(11, io.SeekStart); offset != 11 || err != nil {
		t.Errorf("Seek: got %d, %v; want 11, nil", offset, err)
	}

	if s := (&Reader{}).Size(); s != 0 {
		t.Errorf("Size: got %d, want 0", s)
	}

	if (&Reader{}).UnreadByte() == nil {
		t.Errorf("UnreadByte: got nil, want error")
	}

	if (&Reader{}).UnreadRune() == nil {
		t.Errorf("UnreadRune: got nil, want error")
	}

	if n, err := (&Reader{}).WriteTo(io.Discard); n != 0 || err != nil {
		t.Errorf("WriteTo: got %d, %v; want 0, nil", n, err)
	}
}

"""



```