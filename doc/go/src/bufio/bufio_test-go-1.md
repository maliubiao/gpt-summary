Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `bufio_test.go` file. This code focuses on testing the `bufio` package's `Writer` and `Reader` types.

Here's a breakdown of how to approach this:

1. **Identify the core components:** The code heavily utilizes `bufio.NewWriter`, `bufio.NewWriterSize`, `bufio.NewReader`, and `bufio.NewReaderSize`. This indicates the focus is on testing buffered writing and reading.

2. **Categorize the tests:**  Observe the names of the test functions (e.g., `TestWriterBuffered`, `TestNegativeRead`, `TestReaderReset`). This helps in understanding the specific aspects being tested.

3. **Analyze individual test cases:**  Examine the logic within each test function. Look for patterns like:
    - Setting up a `bufio.Writer` or `bufio.Reader` with different sizes.
    - Performing write or read operations with varying amounts of data.
    - Checking the number of underlying `Write` calls.
    - Testing error handling scenarios (e.g., negative read count, write errors, `io.ErrNoProgress`).
    - Testing the `Reset` functionality for both `Reader` and `Writer`.
    - Testing `Discard` functionality of `Reader`.
    - Testing `ReadFrom` functionality for `Writer`.

4. **Identify helper types:** Notice the custom types like `writeCountingDiscard`, `negativeReader`, `errorThenGoodReader`, `onlyReader`, `onlyWriter`, `scriptedReader`, `eofReader`, `writerWithReadFromError`, and `writeErrorOnlyWriter`. These are used to simulate specific behaviors of underlying readers/writers for testing purposes.

5. **Summarize the functionality of each test category:** Group the tests based on the feature they are testing. For example, tests related to `Writer` buffering, `Reader` error handling, `Reset` functionality, etc.

6. **Infer the tested Go features:** Based on the tested functionalities, deduce the underlying Go features being exercised. This includes buffered I/O, error handling with `io.Reader` and `io.Writer`, and interfaces like `io.ReaderFrom` and `io.WriterTo`.

7. **Address specific requirements:**  The prompt asks for code examples (already present in the test functions), input/output assumptions (inherent in the test cases), command-line arguments (not applicable here), and common mistakes (some tests implicitly highlight potential errors).

8. **Synthesize a concise summary:** Combine the findings into a comprehensive yet understandable summary of the code's purpose.

**Applying this to the provided snippet:**

- The code continues testing the buffering behavior of `bufio.Writer`.
- It focuses on ensuring that writes to a `bufio.Writer` don't necessarily translate to immediate writes to the underlying writer.
- It checks the behavior of `Flush` in ensuring all buffered data is written.
- It tests edge cases like negative read counts and error handling during reads.
- It examines the `Reset` functionality for both `Reader` and `Writer`, verifying that they can be reused with new underlying readers/writers.
- It includes tests for `ReadFrom` functionality of `Writer`, especially when the buffer is partially full.
- It tests the `Discard` method of `Reader`, verifying its ability to skip a specified number of bytes.
- It includes benchmark tests for `io.Copy` and `WriteTo` with and without underlying interface implementations for optimization.

By following these steps, we can arrive at the detailed summary provided in the final answer.
这是 `go/src/bufio/bufio_test.go` 文件的一部分，主要功能是**测试 `bufio` 包中 `Writer` 类型的缓冲写入功能**。这是该测试文件的第二部分，延续了第一部分的测试内容，并涵盖了更多关于 `bufio.Writer` 和 `bufio.Reader` 的功能测试。

**具体功能归纳如下：**

1. **测试 `Writer` 的缓冲机制：**
   - 验证当写入的数据量小于 `Writer` 的缓冲区大小时，不会立即写入底层 `io.Writer`。
   - 通过 `Flush()` 方法强制将缓冲区中的数据写入底层 `io.Writer`。
   - 测试使用 `WriteString` 和 `io.Copy` 进行写入时的缓冲行为。

2. **测试 `Writer` 的 `ReadFrom` 方法：**
   - 验证 `Writer` 的 `ReadFrom` 方法能够从 `io.Reader` 中读取数据并写入到其缓冲区。
   - 特别测试了当 `Writer` 缓冲区已满或部分填充时 `ReadFrom` 的行为。
   - 测试了 `ReadFrom` 在遇到错误 `io.ErrNoProgress` 时的处理。
   - 测试了当 `Writer` 已经缓冲了数据时调用 `ReadFrom` 的行为，确保先填充缓冲区再执行 `ReadFrom`。

3. **测试 `Reader` 的 `Discard` 方法：**
   - 验证 `Reader` 的 `Discard` 方法能够跳过指定数量的字节。
   - 测试了 `Discard` 在不同情况下的行为，包括跳过部分缓冲区、跳过所有数据、跳过超过剩余数据量的情况以及处理底层 `Reader` 返回错误的情况。

4. **测试 `Reader` 和 `Writer` 的 `Reset` 方法：**
   - 验证 `Reader` 和 `Writer` 的 `Reset` 方法可以将缓冲区关联到新的 `io.Reader` 或 `io.Writer`。
   - 测试了在 `Reset` 之后，旧缓冲区的内容是否被丢弃。

5. **测试 `Reader` 的负数读取返回值时的 panic 行为：**
   - 验证当底层的 `io.Reader` 的 `Read` 方法返回负数时，`bufio.Reader` 会触发 panic，并包含正确的错误信息。

6. **测试 `Reader` 清除错误状态的功能：**
   - 验证当底层的 `io.Reader` 返回错误后，后续的读取操作是否能正常进行。

7. **测试 `Reader` 读取零字节时的行为：**
   - 验证 `Read` 方法在传入零长度的切片时不会发生错误。

8. **测试当底层 `Writer` 的 `ReadFrom` 方法返回错误时，`bufio.Writer` 的行为。**

9. **性能基准测试：**
   - 包含了针对 `bufio.Reader` 和 `bufio.Writer` 的 `io.Copy` 和 `WriteTo` 方法的性能基准测试，分别针对底层 `io.Reader` 或 `io.Writer` 是否实现了 `io.WriterTo` 或 `io.ReaderFrom` 接口的情况进行了测试。
   - 包含了 `bufio.Reader` 的 `ReadString` 方法的性能基准测试。
   - 包含了空读写操作和 `Flush` 操作的性能基准测试。

**可以推理出它是什么 go 语言功能的实现：**

这部分代码主要测试了 `bufio` 包提供的带缓冲的 I/O 操作功能。`bufio.Writer` 通过在内存中维护一个缓冲区，减少了直接调用底层 `io.Writer` 的次数，从而提高了写入效率。`bufio.Reader` 类似地通过缓冲读取，减少了对底层 `io.Reader` 的读取次数。

**Go 代码举例说明 `Writer` 的缓冲机制：**

```go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

type countingWriter struct {
	count int
	buf   bytes.Buffer
}

func (cw *countingWriter) Write(p []byte) (n int, err error) {
	cw.count++
	return cw.buf.Write(p)
}

func main() {
	var cw countingWriter
	bufWriter := bufio.NewWriterSize(&cw, 10) // 创建一个缓冲区大小为 10 的 Writer

	n, err := bufWriter.WriteString("hello")
	fmt.Printf("写入 %d 字节，底层 Write 调用次数: %d\n", n, cw.count) // 输出: 写入 5 字节，底层 Write 调用次数: 0

	n, err = bufWriter.WriteString(" world")
	fmt.Printf("写入 %d 字节，底层 Write 调用次数: %d\n", n, cw.count) // 输出: 写入 6 字节，底层 Write 调用次数: 1

	err = bufWriter.Flush() // 刷新缓冲区
	fmt.Printf("刷新缓冲区后，底层 Write 调用次数: %d, 写入内容: %q, 错误: %v\n", cw.count, cw.buf.String(), err)
	// 输出: 刷新缓冲区后，底层 Write 调用次数: 1, 写入内容: "hello world", 错误: <nil>
}
```

**假设的输入与输出（针对 `TestWriterBuffered` 的部分逻辑）：**

假设我们创建了一个缓冲区大小为 1000 的 `bufio.Writer`，并向其中写入数据。

```go
	var w0 writeCountingDiscard
	b0 := NewWriterSize(&w0, 1000)

	// 假设输入 "x" 重复 1000 次
	b0.WriteString(strings.Repeat("x", 1000))
	// 输出：w0 仍然为 0，因为数据还在缓冲区中，未刷新到底层 writer

	// 假设输入 "x" 重复 200 次，总共 1200 次
	b0.WriteString(strings.Repeat("x", 200))
	// 输出：w0 仍然为 0，因为总共 1200 字节，缓冲区大小 1000，仍然可以缓冲

	// 假设通过 io.Copy 写入 30 个 "x"
	io.Copy(b0, onlyReader{strings.NewReader(strings.Repeat("x", 30))})
	// 输出：w0 仍然为 0

	// 假设通过 io.Copy 写入 9 个 "x"，总共 1239 个 "x"
	io.Copy(b0, onlyReader{strings.NewReader(strings.Repeat("x", 9))})
	// 输出：w0 变为 1，因为超过缓冲区大小，触发了一次底层 Write 操作
```

**命令行参数的具体处理：**

这段代码是测试代码，不涉及命令行参数的处理。`bufio` 包本身也不直接处理命令行参数。

**使用者易犯错的点：**

1. **忘记 `Flush()`：**  `bufio.Writer` 只有在缓冲区满或者显式调用 `Flush()` 方法时才会将数据写入底层 `io.Writer`。如果程序在写入后直接退出，可能会丢失缓冲区中的数据。

   ```go
   package main

   import (
       "bufio"
       "fmt"
       "os"
   )

   func main() {
       writer := bufio.NewWriter(os.Stdout)
       writer.WriteString("Hello, ")
       // 忘记调用 writer.Flush()
       fmt.Println("World!") // 这行会立即输出
   }
   ```

   上面的例子中，"Hello, " 很可能不会立即输出到终端，因为 `bufio.Writer` 的缓冲区还没有被刷新。应该在程序结束前调用 `writer.Flush()`。

2. **假设写入操作会立即反映到底层 `io.Writer`：** 开发者可能会错误地认为每次调用 `WriteString` 或 `Write` 都会立即写入到文件或网络连接，这在 `bufio.Writer` 中是不成立的，需要理解缓冲的概念。

总的来说，这段代码详细测试了 `bufio` 包中 `Writer` 和 `Reader` 的各项功能，特别是关注了缓冲机制、错误处理以及与其他 I/O 接口的交互，确保了 `bufio` 包的正确性和健壮性。

### 提示词
```
这是路径为go/src/bufio/bufio_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
"x", 1000))
	if w0 != 0 {
		t.Fatalf("write 1000 'x's: got %d writes, want 0", w0)
	}
	b0.WriteString(strings.Repeat("x", 200))
	if w0 != 0 {
		t.Fatalf("write 1200 'x's: got %d writes, want 0", w0)
	}
	io.Copy(b0, onlyReader{strings.NewReader(strings.Repeat("x", 30))})
	if w0 != 0 {
		t.Fatalf("write 1230 'x's: got %d writes, want 0", w0)
	}
	io.Copy(b0, onlyReader{strings.NewReader(strings.Repeat("x", 9))})
	if w0 != 1 {
		t.Fatalf("write 1239 'x's: got %d writes, want 1", w0)
	}

	var w1 writeCountingDiscard
	b1 := NewWriterSize(&w1, 1234)
	b1.WriteString(strings.Repeat("x", 1200))
	b1.Flush()
	if w1 != 1 {
		t.Fatalf("flush 1200 'x's: got %d writes, want 1", w1)
	}
	b1.WriteString(strings.Repeat("x", 89))
	if w1 != 1 {
		t.Fatalf("write 1200 + 89 'x's: got %d writes, want 1", w1)
	}
	io.Copy(b1, onlyReader{strings.NewReader(strings.Repeat("x", 700))})
	if w1 != 1 {
		t.Fatalf("write 1200 + 789 'x's: got %d writes, want 1", w1)
	}
	io.Copy(b1, onlyReader{strings.NewReader(strings.Repeat("x", 600))})
	if w1 != 2 {
		t.Fatalf("write 1200 + 1389 'x's: got %d writes, want 2", w1)
	}
	b1.Flush()
	if w1 != 3 {
		t.Fatalf("flush 1200 + 1389 'x's: got %d writes, want 3", w1)
	}
}

// A writeCountingDiscard is like io.Discard and counts the number of times
// Write is called on it.
type writeCountingDiscard int

func (w *writeCountingDiscard) Write(p []byte) (int, error) {
	*w++
	return len(p), nil
}

type negativeReader int

func (r *negativeReader) Read([]byte) (int, error) { return -1, nil }

func TestNegativeRead(t *testing.T) {
	// should panic with a description pointing at the reader, not at itself.
	// (should NOT panic with slice index error, for example.)
	b := NewReader(new(negativeReader))
	defer func() {
		switch err := recover().(type) {
		case nil:
			t.Fatal("read did not panic")
		case error:
			if !strings.Contains(err.Error(), "reader returned negative count from Read") {
				t.Fatalf("wrong panic: %v", err)
			}
		default:
			t.Fatalf("unexpected panic value: %T(%v)", err, err)
		}
	}()
	b.Read(make([]byte, 100))
}

var errFake = errors.New("fake error")

type errorThenGoodReader struct {
	didErr bool
	nread  int
}

func (r *errorThenGoodReader) Read(p []byte) (int, error) {
	r.nread++
	if !r.didErr {
		r.didErr = true
		return 0, errFake
	}
	return len(p), nil
}

func TestReaderClearError(t *testing.T) {
	r := &errorThenGoodReader{}
	b := NewReader(r)
	buf := make([]byte, 1)
	if _, err := b.Read(nil); err != nil {
		t.Fatalf("1st nil Read = %v; want nil", err)
	}
	if _, err := b.Read(buf); err != errFake {
		t.Fatalf("1st Read = %v; want errFake", err)
	}
	if _, err := b.Read(nil); err != nil {
		t.Fatalf("2nd nil Read = %v; want nil", err)
	}
	if _, err := b.Read(buf); err != nil {
		t.Fatalf("3rd Read with buffer = %v; want nil", err)
	}
	if r.nread != 2 {
		t.Errorf("num reads = %d; want 2", r.nread)
	}
}

// Test for golang.org/issue/5947
func TestWriterReadFromWhileFull(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriterSize(buf, 10)

	// Fill buffer exactly.
	n, err := w.Write([]byte("0123456789"))
	if n != 10 || err != nil {
		t.Fatalf("Write returned (%v, %v), want (10, nil)", n, err)
	}

	// Use ReadFrom to read in some data.
	n2, err := w.ReadFrom(strings.NewReader("abcdef"))
	if n2 != 6 || err != nil {
		t.Fatalf("ReadFrom returned (%v, %v), want (6, nil)", n2, err)
	}
}

type emptyThenNonEmptyReader struct {
	r io.Reader
	n int
}

func (r *emptyThenNonEmptyReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return r.r.Read(p)
	}
	r.n--
	return 0, nil
}

// Test for golang.org/issue/7611
func TestWriterReadFromUntilEOF(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriterSize(buf, 5)

	// Partially fill buffer
	n, err := w.Write([]byte("0123"))
	if n != 4 || err != nil {
		t.Fatalf("Write returned (%v, %v), want (4, nil)", n, err)
	}

	// Use ReadFrom to read in some data.
	r := &emptyThenNonEmptyReader{r: strings.NewReader("abcd"), n: 3}
	n2, err := w.ReadFrom(r)
	if n2 != 4 || err != nil {
		t.Fatalf("ReadFrom returned (%v, %v), want (4, nil)", n2, err)
	}
	w.Flush()
	if got, want := buf.String(), "0123abcd"; got != want {
		t.Fatalf("buf.Bytes() returned %q, want %q", got, want)
	}
}

func TestWriterReadFromErrNoProgress(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriterSize(buf, 5)

	// Partially fill buffer
	n, err := w.Write([]byte("0123"))
	if n != 4 || err != nil {
		t.Fatalf("Write returned (%v, %v), want (4, nil)", n, err)
	}

	// Use ReadFrom to read in some data.
	r := &emptyThenNonEmptyReader{r: strings.NewReader("abcd"), n: 100}
	n2, err := w.ReadFrom(r)
	if n2 != 0 || err != io.ErrNoProgress {
		t.Fatalf("buf.Bytes() returned (%v, %v), want (0, io.ErrNoProgress)", n2, err)
	}
}

type readFromWriter struct {
	buf           []byte
	writeBytes    int
	readFromBytes int
}

func (w *readFromWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	w.writeBytes += len(p)
	return len(p), nil
}

func (w *readFromWriter) ReadFrom(r io.Reader) (int64, error) {
	b, err := io.ReadAll(r)
	w.buf = append(w.buf, b...)
	w.readFromBytes += len(b)
	return int64(len(b)), err
}

// Test that calling (*Writer).ReadFrom with a partially-filled buffer
// fills the buffer before switching over to ReadFrom.
func TestWriterReadFromWithBufferedData(t *testing.T) {
	const bufsize = 16

	input := createTestInput(64)
	rfw := &readFromWriter{}
	w := NewWriterSize(rfw, bufsize)

	const writeSize = 8
	if n, err := w.Write(input[:writeSize]); n != writeSize || err != nil {
		t.Errorf("w.Write(%v bytes) = %v, %v; want %v, nil", writeSize, n, err, writeSize)
	}
	n, err := w.ReadFrom(bytes.NewReader(input[writeSize:]))
	if wantn := len(input[writeSize:]); int(n) != wantn || err != nil {
		t.Errorf("io.Copy(w, %v bytes) = %v, %v; want %v, nil", wantn, n, err, wantn)
	}
	if err := w.Flush(); err != nil {
		t.Errorf("w.Flush() = %v, want nil", err)
	}

	if got, want := rfw.writeBytes, bufsize; got != want {
		t.Errorf("wrote %v bytes with Write, want %v", got, want)
	}
	if got, want := rfw.readFromBytes, len(input)-bufsize; got != want {
		t.Errorf("wrote %v bytes with ReadFrom, want %v", got, want)
	}
}

func TestReadZero(t *testing.T) {
	for _, size := range []int{100, 2} {
		t.Run(fmt.Sprintf("bufsize=%d", size), func(t *testing.T) {
			r := io.MultiReader(strings.NewReader("abc"), &emptyThenNonEmptyReader{r: strings.NewReader("def"), n: 1})
			br := NewReaderSize(r, size)
			want := func(s string, wantErr error) {
				p := make([]byte, 50)
				n, err := br.Read(p)
				if err != wantErr || n != len(s) || string(p[:n]) != s {
					t.Fatalf("read(%d) = %q, %v, want %q, %v", len(p), string(p[:n]), err, s, wantErr)
				}
				t.Logf("read(%d) = %q, %v", len(p), string(p[:n]), err)
			}
			want("abc", nil)
			want("", nil)
			want("def", nil)
			want("", io.EOF)
		})
	}
}

func TestReaderReset(t *testing.T) {
	checkAll := func(r *Reader, want string) {
		t.Helper()
		all, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if string(all) != want {
			t.Errorf("ReadAll returned %q, want %q", all, want)
		}
	}

	r := NewReader(strings.NewReader("foo foo"))
	buf := make([]byte, 3)
	r.Read(buf)
	if string(buf) != "foo" {
		t.Errorf("buf = %q; want foo", buf)
	}

	r.Reset(strings.NewReader("bar bar"))
	checkAll(r, "bar bar")

	*r = Reader{} // zero out the Reader
	r.Reset(strings.NewReader("bar bar"))
	checkAll(r, "bar bar")

	// Wrap a reader and then Reset to that reader.
	r.Reset(strings.NewReader("recur"))
	r2 := NewReader(r)
	checkAll(r2, "recur")
	r.Reset(strings.NewReader("recur2"))
	r2.Reset(r)
	checkAll(r2, "recur2")
}

func TestWriterReset(t *testing.T) {
	var buf1, buf2, buf3, buf4, buf5 strings.Builder
	w := NewWriter(&buf1)
	w.WriteString("foo")

	w.Reset(&buf2) // and not flushed
	w.WriteString("bar")
	w.Flush()
	if buf1.String() != "" {
		t.Errorf("buf1 = %q; want empty", buf1.String())
	}
	if buf2.String() != "bar" {
		t.Errorf("buf2 = %q; want bar", buf2.String())
	}

	*w = Writer{}  // zero out the Writer
	w.Reset(&buf3) // and not flushed
	w.WriteString("bar")
	w.Flush()
	if buf1.String() != "" {
		t.Errorf("buf1 = %q; want empty", buf1.String())
	}
	if buf3.String() != "bar" {
		t.Errorf("buf3 = %q; want bar", buf3.String())
	}

	// Wrap a writer and then Reset to that writer.
	w.Reset(&buf4)
	w2 := NewWriter(w)
	w2.WriteString("recur")
	w2.Flush()
	if buf4.String() != "recur" {
		t.Errorf("buf4 = %q, want %q", buf4.String(), "recur")
	}
	w.Reset(&buf5)
	w2.Reset(w)
	w2.WriteString("recur2")
	w2.Flush()
	if buf5.String() != "recur2" {
		t.Errorf("buf5 = %q, want %q", buf5.String(), "recur2")
	}
}

func TestReaderDiscard(t *testing.T) {
	tests := []struct {
		name     string
		r        io.Reader
		bufSize  int // 0 means 16
		peekSize int

		n int // input to Discard

		want    int   // from Discard
		wantErr error // from Discard

		wantBuffered int
	}{
		{
			name:         "normal case",
			r:            strings.NewReader("abcdefghijklmnopqrstuvwxyz"),
			peekSize:     16,
			n:            6,
			want:         6,
			wantBuffered: 10,
		},
		{
			name:         "discard causing read",
			r:            strings.NewReader("abcdefghijklmnopqrstuvwxyz"),
			n:            6,
			want:         6,
			wantBuffered: 10,
		},
		{
			name:         "discard all without peek",
			r:            strings.NewReader("abcdefghijklmnopqrstuvwxyz"),
			n:            26,
			want:         26,
			wantBuffered: 0,
		},
		{
			name:         "discard more than end",
			r:            strings.NewReader("abcdefghijklmnopqrstuvwxyz"),
			n:            27,
			want:         26,
			wantErr:      io.EOF,
			wantBuffered: 0,
		},
		// Any error from filling shouldn't show up until we
		// get past the valid bytes. Here we return 5 valid bytes at the same time
		// as an error, but test that we don't see the error from Discard.
		{
			name: "fill error, discard less",
			r: newScriptedReader(func(p []byte) (n int, err error) {
				if len(p) < 5 {
					panic("unexpected small read")
				}
				return 5, errors.New("5-then-error")
			}),
			n:            4,
			want:         4,
			wantErr:      nil,
			wantBuffered: 1,
		},
		{
			name: "fill error, discard equal",
			r: newScriptedReader(func(p []byte) (n int, err error) {
				if len(p) < 5 {
					panic("unexpected small read")
				}
				return 5, errors.New("5-then-error")
			}),
			n:            5,
			want:         5,
			wantErr:      nil,
			wantBuffered: 0,
		},
		{
			name: "fill error, discard more",
			r: newScriptedReader(func(p []byte) (n int, err error) {
				if len(p) < 5 {
					panic("unexpected small read")
				}
				return 5, errors.New("5-then-error")
			}),
			n:            6,
			want:         5,
			wantErr:      errors.New("5-then-error"),
			wantBuffered: 0,
		},
		// Discard of 0 shouldn't cause a read:
		{
			name:         "discard zero",
			r:            newScriptedReader(), // will panic on Read
			n:            0,
			want:         0,
			wantErr:      nil,
			wantBuffered: 0,
		},
		{
			name:         "discard negative",
			r:            newScriptedReader(), // will panic on Read
			n:            -1,
			want:         0,
			wantErr:      ErrNegativeCount,
			wantBuffered: 0,
		},
	}
	for _, tt := range tests {
		br := NewReaderSize(tt.r, tt.bufSize)
		if tt.peekSize > 0 {
			peekBuf, err := br.Peek(tt.peekSize)
			if err != nil {
				t.Errorf("%s: Peek(%d): %v", tt.name, tt.peekSize, err)
				continue
			}
			if len(peekBuf) != tt.peekSize {
				t.Errorf("%s: len(Peek(%d)) = %v; want %v", tt.name, tt.peekSize, len(peekBuf), tt.peekSize)
				continue
			}
		}
		discarded, err := br.Discard(tt.n)
		if ge, we := fmt.Sprint(err), fmt.Sprint(tt.wantErr); discarded != tt.want || ge != we {
			t.Errorf("%s: Discard(%d) = (%v, %v); want (%v, %v)", tt.name, tt.n, discarded, ge, tt.want, we)
			continue
		}
		if bn := br.Buffered(); bn != tt.wantBuffered {
			t.Errorf("%s: after Discard, Buffered = %d; want %d", tt.name, bn, tt.wantBuffered)
		}
	}

}

func TestReaderSize(t *testing.T) {
	if got, want := NewReader(nil).Size(), DefaultBufSize; got != want {
		t.Errorf("NewReader's Reader.Size = %d; want %d", got, want)
	}
	if got, want := NewReaderSize(nil, 1234).Size(), 1234; got != want {
		t.Errorf("NewReaderSize's Reader.Size = %d; want %d", got, want)
	}
}

func TestWriterSize(t *testing.T) {
	if got, want := NewWriter(nil).Size(), DefaultBufSize; got != want {
		t.Errorf("NewWriter's Writer.Size = %d; want %d", got, want)
	}
	if got, want := NewWriterSize(nil, 1234).Size(), 1234; got != want {
		t.Errorf("NewWriterSize's Writer.Size = %d; want %d", got, want)
	}
}

// An onlyReader only implements io.Reader, no matter what other methods the underlying implementation may have.
type onlyReader struct {
	io.Reader
}

// An onlyWriter only implements io.Writer, no matter what other methods the underlying implementation may have.
type onlyWriter struct {
	io.Writer
}

// A scriptedReader is an io.Reader that executes its steps sequentially.
type scriptedReader []func(p []byte) (n int, err error)

func (sr *scriptedReader) Read(p []byte) (n int, err error) {
	if len(*sr) == 0 {
		panic("too many Read calls on scripted Reader. No steps remain.")
	}
	step := (*sr)[0]
	*sr = (*sr)[1:]
	return step(p)
}

func newScriptedReader(steps ...func(p []byte) (n int, err error)) io.Reader {
	sr := scriptedReader(steps)
	return &sr
}

// eofReader returns the number of bytes read and io.EOF for the read that consumes the last of the content.
type eofReader struct {
	buf []byte
}

func (r *eofReader) Read(p []byte) (int, error) {
	read := copy(p, r.buf)
	r.buf = r.buf[read:]

	switch read {
	case 0, len(r.buf):
		// As allowed in the documentation, this will return io.EOF
		// in the same call that consumes the last of the data.
		// https://godoc.org/io#Reader
		return read, io.EOF
	}

	return read, nil
}

func TestPartialReadEOF(t *testing.T) {
	src := make([]byte, 10)
	eofR := &eofReader{buf: src}
	r := NewReader(eofR)

	// Start by reading 5 of the 10 available bytes.
	dest := make([]byte, 5)
	read, err := r.Read(dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := len(dest); read != n {
		t.Fatalf("read %d bytes; wanted %d bytes", read, n)
	}

	// The Reader should have buffered all the content from the io.Reader.
	if n := len(eofR.buf); n != 0 {
		t.Fatalf("got %d bytes left in bufio.Reader source; want 0 bytes", n)
	}
	// To prove the point, check that there are still 5 bytes available to read.
	if n := r.Buffered(); n != 5 {
		t.Fatalf("got %d bytes buffered in bufio.Reader; want 5 bytes", n)
	}

	// This is the second read of 0 bytes.
	read, err = r.Read([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if read != 0 {
		t.Fatalf("read %d bytes; want 0 bytes", read)
	}
}

type writerWithReadFromError struct{}

func (w writerWithReadFromError) ReadFrom(r io.Reader) (int64, error) {
	return 0, errors.New("writerWithReadFromError error")
}

func (w writerWithReadFromError) Write(b []byte) (n int, err error) {
	return 10, nil
}

func TestWriterReadFromMustSetUnderlyingError(t *testing.T) {
	var wr = NewWriter(writerWithReadFromError{})
	if _, err := wr.ReadFrom(strings.NewReader("test2")); err == nil {
		t.Fatal("expected ReadFrom returns error, got nil")
	}
	if _, err := wr.Write([]byte("123")); err == nil {
		t.Fatal("expected Write returns error, got nil")
	}
}

type writeErrorOnlyWriter struct{}

func (w writeErrorOnlyWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("writeErrorOnlyWriter error")
}

// Ensure that previous Write errors are immediately returned
// on any ReadFrom. See golang.org/issue/35194.
func TestWriterReadFromMustReturnUnderlyingError(t *testing.T) {
	var wr = NewWriter(writeErrorOnlyWriter{})
	s := "test1"
	wantBuffered := len(s)
	if _, err := wr.WriteString(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := wr.Flush(); err == nil {
		t.Error("expected flush error, got nil")
	}
	if _, err := wr.ReadFrom(strings.NewReader("test2")); err == nil {
		t.Fatal("expected error, got nil")
	}
	if buffered := wr.Buffered(); buffered != wantBuffered {
		t.Fatalf("Buffered = %v; want %v", buffered, wantBuffered)
	}
}

func BenchmarkReaderCopyOptimal(b *testing.B) {
	// Optimal case is where the underlying reader implements io.WriterTo
	srcBuf := bytes.NewBuffer(make([]byte, 8192))
	src := NewReader(srcBuf)
	dstBuf := new(bytes.Buffer)
	dst := onlyWriter{dstBuf}
	for i := 0; i < b.N; i++ {
		srcBuf.Reset()
		src.Reset(srcBuf)
		dstBuf.Reset()
		io.Copy(dst, src)
	}
}

func BenchmarkReaderCopyUnoptimal(b *testing.B) {
	// Unoptimal case is where the underlying reader doesn't implement io.WriterTo
	srcBuf := bytes.NewBuffer(make([]byte, 8192))
	src := NewReader(onlyReader{srcBuf})
	dstBuf := new(bytes.Buffer)
	dst := onlyWriter{dstBuf}
	for i := 0; i < b.N; i++ {
		srcBuf.Reset()
		src.Reset(onlyReader{srcBuf})
		dstBuf.Reset()
		io.Copy(dst, src)
	}
}

func BenchmarkReaderCopyNoWriteTo(b *testing.B) {
	srcBuf := bytes.NewBuffer(make([]byte, 8192))
	srcReader := NewReader(srcBuf)
	src := onlyReader{srcReader}
	dstBuf := new(bytes.Buffer)
	dst := onlyWriter{dstBuf}
	for i := 0; i < b.N; i++ {
		srcBuf.Reset()
		srcReader.Reset(srcBuf)
		dstBuf.Reset()
		io.Copy(dst, src)
	}
}

func BenchmarkReaderWriteToOptimal(b *testing.B) {
	const bufSize = 16 << 10
	buf := make([]byte, bufSize)
	r := bytes.NewReader(buf)
	srcReader := NewReaderSize(onlyReader{r}, 1<<10)
	if _, ok := io.Discard.(io.ReaderFrom); !ok {
		b.Fatal("io.Discard doesn't support ReaderFrom")
	}
	for i := 0; i < b.N; i++ {
		r.Seek(0, io.SeekStart)
		srcReader.Reset(onlyReader{r})
		n, err := srcReader.WriteTo(io.Discard)
		if err != nil {
			b.Fatal(err)
		}
		if n != bufSize {
			b.Fatalf("n = %d; want %d", n, bufSize)
		}
	}
}

func BenchmarkReaderReadString(b *testing.B) {
	r := strings.NewReader("       foo       foo        42        42        42        42        42        42        42        42       4.2       4.2       4.2       4.2\n")
	buf := NewReader(r)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Seek(0, io.SeekStart)
		buf.Reset(r)

		_, err := buf.ReadString('\n')
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriterCopyOptimal(b *testing.B) {
	// Optimal case is where the underlying writer implements io.ReaderFrom
	srcBuf := bytes.NewBuffer(make([]byte, 8192))
	src := onlyReader{srcBuf}
	dstBuf := new(bytes.Buffer)
	dst := NewWriter(dstBuf)
	for i := 0; i < b.N; i++ {
		srcBuf.Reset()
		dstBuf.Reset()
		dst.Reset(dstBuf)
		io.Copy(dst, src)
	}
}

func BenchmarkWriterCopyUnoptimal(b *testing.B) {
	srcBuf := bytes.NewBuffer(make([]byte, 8192))
	src := onlyReader{srcBuf}
	dstBuf := new(bytes.Buffer)
	dst := NewWriter(onlyWriter{dstBuf})
	for i := 0; i < b.N; i++ {
		srcBuf.Reset()
		dstBuf.Reset()
		dst.Reset(onlyWriter{dstBuf})
		io.Copy(dst, src)
	}
}

func BenchmarkWriterCopyNoReadFrom(b *testing.B) {
	srcBuf := bytes.NewBuffer(make([]byte, 8192))
	src := onlyReader{srcBuf}
	dstBuf := new(bytes.Buffer)
	dstWriter := NewWriter(dstBuf)
	dst := onlyWriter{dstWriter}
	for i := 0; i < b.N; i++ {
		srcBuf.Reset()
		dstBuf.Reset()
		dstWriter.Reset(dstBuf)
		io.Copy(dst, src)
	}
}

func BenchmarkReaderEmpty(b *testing.B) {
	b.ReportAllocs()
	str := strings.Repeat("x", 16<<10)
	for i := 0; i < b.N; i++ {
		br := NewReader(strings.NewReader(str))
		n, err := io.Copy(io.Discard, br)
		if err != nil {
			b.Fatal(err)
		}
		if n != int64(len(str)) {
			b.Fatal("wrong length")
		}
	}
}

func BenchmarkWriterEmpty(b *testing.B) {
	b.ReportAllocs()
	str := strings.Repeat("x", 1<<10)
	bs := []byte(str)
	for i := 0; i < b.N; i++ {
		bw := NewWriter(io.Discard)
		bw.Flush()
		bw.WriteByte('a')
		bw.Flush()
		bw.WriteRune('B')
		bw.Flush()
		bw.Write(bs)
		bw.Flush()
		bw.WriteString(str)
		bw.Flush()
	}
}

func BenchmarkWriterFlush(b *testing.B) {
	b.ReportAllocs()
	bw := NewWriter(io.Discard)
	str := strings.Repeat("x", 50)
	for i := 0; i < b.N; i++ {
		bw.WriteString(str)
		bw.Flush()
	}
}
```