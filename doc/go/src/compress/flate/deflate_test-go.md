Response:
Let's break down the thought process for analyzing this Go code and generating the comprehensive answer.

**1. Initial Understanding & Goal Identification:**

The first step is to recognize that this code is part of the Go standard library's `compress/flate` package, specifically the test file `deflate_test.go`. The primary purpose of a test file is to verify the correctness of the associated implementation (in this case, the `deflate.go` file, though not provided).

The prompt asks for:

* **Functionality Listing:** What does this test file *do*?
* **Go Feature Implementation (Inference):** What `flate` functionality is being tested?
* **Code Examples:** Illustrate the inferred functionality with Go code (including assumptions about inputs and outputs).
* **Command-Line Arguments:**  Are there any?
* **Common Mistakes:** What are potential pitfalls for users of the `flate` package?

**2. Scanning for Key Structures and Functions:**

I'd start by quickly scanning the code for important elements:

* **`package flate`:** Confirms the package under test.
* **`import` statements:**  Shows dependencies used for testing (e.g., `bytes`, `io`, `testing`). The `internal/testenv` is a hint that some tests might be environment-dependent.
* **`struct` definitions (`deflateTest`, `deflateInflateTest`, `reverseBitsTest`):** These clearly define test cases, indicating what aspects of the `flate` package are being targeted.
* **Global variable declarations (`deflateTests`, `deflateInflateTests`, `reverseBitsTests`):** These are slices of the test case structs, providing concrete test data.
* **Function declarations starting with `Test...` (e.g., `TestDeflate`, `TestDeflateInflate`):** These are the actual test functions executed by the `go test` command.
* **Helper functions (e.g., `largeDataChunk`, `testSync`, `testToFromWithLimit`):**  These support the main test functions, often encapsulating common setup or assertion logic.

**3. Analyzing Individual Test Functions and Test Data:**

Now, I'd go through each `Test...` function and its associated test data:

* **`TestBulkHash4`:** This tests a low-level function `bulkHash4`. The test data (`deflateTests`) and the logic suggest it's related to calculating hash values for sequences of bytes, likely used for finding matching substrings during compression.
* **`TestDeflate`:** This is a core test. It uses `deflateTests`, which contains input bytes, compression levels, and expected output bytes. This directly tests the compression functionality (`NewWriter`, `Write`, `Close`).
* **`TestWriterClose`:** Focuses on the behavior of the `Writer` when `Close` is called, specifically preventing further writes and flushes.
* **`TestVeryLongSparseChunk`:** Tests compression of a large, mostly zero-filled input, likely to check edge cases in the compression algorithm. The `sparseReader` provides the specific input pattern.
* **`testSync`:**  This function seems to test the interaction between writing and reading concurrently, using a `syncBuffer`. It involves flushing and closing the writer at different points.
* **`testToFromWithLevelAndLimit`, `testToFromWithLimit`, `TestDeflateInflate`:**  These test the complete deflate/inflate cycle. `deflateInflateTests` provides the input data. The "limit" part suggests checks on the compressed size.
* **`TestReverseBits`:** Tests a bit manipulation function, likely a utility within the compression algorithm.
* **`TestDeflateInflateString`, `deflateInflateStringTests`:**  Similar to `TestDeflateInflate`, but uses data from external files, providing more realistic test cases.
* **`TestReaderDict`, `TestWriterDict`:** These tests specifically address the dictionary feature of the `flate` package, where a pre-defined dictionary can improve compression for repetitive data.
* **`TestRegression2508`:**  Indicates a fix for a specific issue, likely involving a large number of writes.
* **`TestWriterReset`:** Tests the `Reset` method of the `Writer`, allowing reuse of the writer with a new output.
* **`TestBestSpeed`:**  Focuses on the `BestSpeed` compression level and tests various write sizes and flush behaviors.
* **`TestWriterPersistentWriteError`, `TestWriterPersistentFlushError`, `TestWriterPersistentCloseError`:** These tests the error handling of the `Writer`, ensuring that errors from the underlying `io.Writer` are correctly propagated and persist.
* **`TestBestSpeedMatch`, `TestBestSpeedMaxMatchOffset`, `TestBestSpeedShiftOffsets`:** These seem to test internal details of the "best speed" compression implementation, specifically the matching logic.
* **`TestMaxStackSize`:**  This checks for potential stack overflow issues when compressing large inputs, using `debug.SetMaxStack`.

**4. Inferring Functionality and Generating Examples:**

Based on the test names, the structures, and the operations performed within the tests (like `NewWriter`, `Write`, `NewReader`, `ReadAll`), I would start inferring the core functionalities:

* **Compression:**  `NewWriter` creates a compressor, `Write` feeds data, `Close` finishes the stream.
* **Decompression:** `NewReader` creates a decompressor, `ReadAll` reads the decompressed data.
* **Compression Levels:** The tests use different integer levels, hinting at different trade-offs between speed and compression ratio.
* **Dictionary Support:** The `...Dict` tests clearly show the ability to provide a dictionary.

Then, I'd construct basic Go examples demonstrating these, making assumptions about input and expected output where needed.

**5. Identifying Command-Line Arguments and Common Mistakes:**

By examining the imports and the test functions, I can see that this specific test file doesn't directly handle command-line arguments. However, the `testing` package is used, which inherently interacts with `go test` flags like `-short`.

For common mistakes, I'd focus on:

* **Forgetting to `Close` the writer:** This is a common resource management issue.
* **Incorrectly using compression levels:**  Not understanding the trade-offs.
* **Not handling errors:**  Checking the return values of `Write`, `Close`, `Read`, etc.

**6. Structuring the Answer:**

Finally, I'd organize the findings into a clear and structured answer, addressing each point in the prompt:

* **功能列举:**  List the functionalities identified.
* **Go语言功能实现推理:** Explain the inferred functionalities and provide code examples with input/output assumptions.
* **命令行参数:** State that this specific file doesn't handle them but mention the `testing` package's interaction with `go test` flags.
* **易犯错的点:**  List the common mistakes with illustrative examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe the `deflateTests` directly show the compressed format."  **Correction:**  Realized that these are *test cases*, and the `flate` package handles the actual compression logic. The output in `deflateTests` is the *expected* compressed output for specific inputs and levels.
* **Initial thought:** "The `limit` in some tests is a strict size constraint." **Correction:**  It seems more like a way to verify the compression ratio at different levels, perhaps not a hard limit enforced by the compressor itself.
* **Considered adding details about the DEFLATE algorithm:** **Decision:** Kept the focus on what the *test file* does and what functionalities it verifies, rather than diving deep into the compression algorithm itself.

This iterative process of scanning, analyzing, inferring, and refining helps to generate a comprehensive and accurate answer to the prompt.
这个 `go/src/compress/flate/deflate_test.go` 文件是 Go 语言 `compress/flate` 包的一部分，专门用于测试 `flate` 包中关于 DEFLATE 压缩算法的实现。它的主要功能是：

1. **单元测试 `flate.Writer` (压缩器) 的功能:**
   - 测试不同压缩级别 (`level`) 下的压缩输出是否符合预期。
   - 测试空输入、单个字节输入、多个字节输入以及重复字节输入的压缩效果。
   - 测试 `Writer` 的 `Close` 方法的行为，例如关闭后是否还能写入数据。
   - 测试 `Writer` 的 `Flush` 方法的行为，确保数据被刷新到输出。
   - 测试 `Writer` 的 `Reset` 方法，用于重置 `Writer` 的状态以进行新的压缩。
   - 测试使用预定义字典 (`dict`) 进行压缩的功能。
   - 测试 `BestSpeed` 压缩级别的特定行为和性能。
   - 测试 `Writer` 在底层 `io.Writer` 发生错误时的持久性错误处理。

2. **单元测试 `flate.Reader` (解压缩器) 的功能:**
   - 测试解压缩器是否能正确地将由 `flate.Writer` 压缩的数据解压缩回原始数据。
   - 测试使用预定义字典 (`dict`) 进行解压缩的功能。
   - 测试解压缩大型、稀疏的数据块。

3. **测试压缩和解压缩的完整流程 (Deflate 和 Inflate):**
   - 通过压缩后再解压缩的方式，验证数据的完整性。
   - 使用不同的压缩级别进行测试。
   - 使用来自文件的实际文本数据进行更全面的测试。

4. **测试内部辅助函数:**
   - 测试 `reverseBits` 函数，该函数用于反转比特位，是 DEFLATE 算法的一部分。
   - 测试 `bulkHash4` 函数，这很可能是一个用于快速计算哈希值的内部函数，用于查找重复的字符串。
   - 测试 `matchLen` 函数，用于在 `BestSpeed` 模式下查找匹配的长度。

**它可以推理出 `compress/flate` 包实现了 DEFLATE 压缩算法。**

DEFLATE 是一种广泛使用的无损数据压缩算法，它结合了 LZ77 算法和哈夫曼编码。`flate` 包提供了 `Writer` 用于压缩数据，`Reader` 用于解压缩数据，并允许用户指定压缩级别以平衡压缩率和速度。

**Go 代码举例说明 (压缩和解压缩):**

```go
package main

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"log"
)

func main() {
	// 原始数据
	originalData := []byte("This is some text to compress.")

	// 创建一个 bytes.Buffer 用于存储压缩后的数据
	var compressedBuffer bytes.Buffer

	// 创建一个 flate.Writer 进行压缩，使用默认压缩级别
	compressor, err := flate.NewWriter(&compressedBuffer, flate.DefaultCompression)
	if err != nil {
		log.Fatal(err)
	}

	// 将原始数据写入压缩器
	_, err = compressor.Write(originalData)
	if err != nil {
		log.Fatal(err)
	}

	// 关闭压缩器，确保所有数据都被刷新
	err = compressor.Close()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("原始数据: %s\n", originalData)
	fmt.Printf("压缩后数据 (字节): %v\n", compressedBuffer.Bytes())

	// 创建一个 flate.Reader 用于解压缩
	decompressor := flate.NewReader(&compressedBuffer)
	if decompressor == nil {
		log.Fatal("Failed to create flate.Reader")
	}

	// 读取所有解压缩后的数据
	decompressedData, err := io.ReadAll(decompressor)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("解压缩后数据: %s\n", decompressedData)

	// 验证解压缩后的数据是否与原始数据一致
	if bytes.Equal(originalData, decompressedData) {
		fmt.Println("解压缩成功，数据一致！")
	} else {
		fmt.Println("解压缩失败，数据不一致！")
	}
}
```

**假设的输入与输出:**

对于上面的代码示例：

**假设输入:** `originalData := []byte("This is some text to compress.")`

**可能的输出:**

```
原始数据: This is some text to compress.
压缩后数据 (字节): [31 139 8 0 0 9 110 136 0 255 116 72 105 115 32 105 115 32 115 111 109 101 32 116 101 120 116 32 116 111 32 99 111 109 112 114 101 115 115 46 3 0 19 221 41 179 30 0 0 0]
解压缩后数据: This is some text to compress.
解压缩成功，数据一致！
```

**代码推理：**

- `NewWriter(&compressedBuffer, flate.DefaultCompression)` 创建了一个将压缩数据写入 `compressedBuffer` 的压缩器。`flate.DefaultCompression` 是一个预定义的常量，表示默认的压缩级别。
- `compressor.Write(originalData)` 将原始数据写入压缩器，压缩器内部会按照 DEFLATE 算法进行处理。
- `compressor.Close()` 关闭压缩器，这会刷新任何剩余的压缩数据并添加必要的结束标记到输出流中。
- `NewReader(&compressedBuffer)` 创建了一个从 `compressedBuffer` 读取压缩数据的解压缩器。
- `io.ReadAll(decompressor)` 从解压缩器读取所有数据，解压缩器会将压缩的数据还原为原始数据。
- `bytes.Equal(originalData, decompressedData)` 用于比较原始数据和解压缩后的数据，以验证压缩和解压缩的正确性.

**命令行参数的具体处理:**

这个测试文件本身并不直接处理命令行参数。但是，它是一个 Go 测试文件，可以通过 `go test` 命令来运行。`go test` 命令本身有很多参数，例如：

- `-v`:  显示更详细的测试输出。
- `-run <regexp>`:  只运行名称匹配正则表达式的测试。
- `-bench <regexp>`: 运行性能测试。
- `-short`:  运行时间较短的测试（在这个文件中，一些耗时的测试会被跳过）。
- `-cpuprofile <file>`:  将 CPU profile 写入文件。
- `-memprofile <file>`:  将内存 profile 写入文件。

例如，要运行 `deflate_test.go` 文件中的所有测试并显示详细输出，可以在命令行中执行：

```bash
go test -v go/src/compress/flate/deflate_test.go
```

要只运行名称包含 "Deflate" 的测试，可以执行：

```bash
go test -v -run Deflate go/src/compress/flate/deflate_test.go
```

**使用者易犯错的点:**

1. **忘记关闭 `flate.Writer`:**  `flate.Writer` 在 `Close()` 方法中会刷新剩余的数据并写入结束标志。如果不调用 `Close()`，可能会导致压缩后的数据不完整或无法被正确解压缩。

   ```go
   // 错误示例：忘记关闭 Writer
   func compressDataBad(data []byte) []byte {
       var b bytes.Buffer
       w, _ := flate.NewWriter(&b, flate.DefaultCompression)
       w.Write(data)
       return b.Bytes() // 可能会丢失部分数据
   }

   // 正确示例：确保关闭 Writer
   func compressDataGood(data []byte) ([]byte, error) {
       var b bytes.Buffer
       w, err := flate.NewWriter(&b, flate.DefaultCompression)
       if err != nil {
           return nil, err
       }
       if _, err := w.Write(data); err != nil {
           return nil, err
       }
       if err := w.Close(); err != nil {
           return nil, err
       }
       return b.Bytes(), nil
   }
   ```

2. **没有处理 `flate.NewWriter` 和 `flate.NewReader` 的错误:** 这些函数可能会返回错误，例如内存分配失败等。应该检查并处理这些错误。

   ```go
   // 错误示例：忽略 NewWriter 的错误
   func createCompressorBad(w io.Writer) *flate.Writer {
       compressor, _ := flate.NewWriter(w, flate.DefaultCompression)
       return compressor // 如果 NewWriter 失败，compressor 可能为 nil
   }

   // 正确示例：检查并处理错误
   func createCompressorGood(w io.Writer) (*flate.Writer, error) {
       compressor, err := flate.NewWriter(w, flate.DefaultCompression)
       if err != nil {
           return nil, err
       }
       return compressor, nil
   }
   ```

3. **对压缩级别理解不足:**  `flate` 包支持不同的压缩级别（0 到 9，以及 `NoCompression`, `BestSpeed`, `BestCompression`, `DefaultCompression`, `HuffmanOnly`）。不同的级别在压缩率和速度之间有不同的权衡。不了解这些级别可能导致选择不适合场景的级别。例如，在需要快速压缩的场景下使用 `BestCompression` 可能会导致性能问题。

   ```go
   // 例如，如果需要最快的压缩速度，应该使用 BestSpeed
   compressor, _ := flate.NewWriter(&b, flate.BestSpeed)

   // 如果需要最高的压缩率，应该使用 BestCompression
   compressor, _ := flate.NewWriter(&b, flate.BestCompression)
   ```

4. **在并发环境中使用同一个 `flate.Writer` 或 `flate.Reader` 而不进行适当的同步:**  `flate.Writer` 和 `flate.Reader` 的实现并非线程安全。在多个 goroutine 中同时使用同一个实例可能会导致数据竞争和未定义的行为。如果需要在并发环境中使用，应该使用互斥锁或其他同步机制来保护访问。

   ```go
   var compressedBuffer bytes.Buffer
   var mu sync.Mutex

   func compressConcurrently(data []byte) {
       mu.Lock()
       defer mu.Unlock()
       w, _ := flate.NewWriter(&compressedBuffer, flate.DefaultCompression)
       w.Write(data)
       w.Close()
   }
   ```

Prompt: 
```
这是路径为go/src/compress/flate/deflate_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package flate

import (
	"bytes"
	"errors"
	"fmt"
	"internal/testenv"
	"io"
	"math/rand"
	"os"
	"reflect"
	"runtime/debug"
	"sync"
	"testing"
)

type deflateTest struct {
	in    []byte
	level int
	out   []byte
}

type deflateInflateTest struct {
	in []byte
}

type reverseBitsTest struct {
	in       uint16
	bitCount uint8
	out      uint16
}

var deflateTests = []*deflateTest{
	{[]byte{}, 0, []byte{1, 0, 0, 255, 255}},
	{[]byte{0x11}, -1, []byte{18, 4, 4, 0, 0, 255, 255}},
	{[]byte{0x11}, DefaultCompression, []byte{18, 4, 4, 0, 0, 255, 255}},
	{[]byte{0x11}, 4, []byte{18, 4, 4, 0, 0, 255, 255}},

	{[]byte{0x11}, 0, []byte{0, 1, 0, 254, 255, 17, 1, 0, 0, 255, 255}},
	{[]byte{0x11, 0x12}, 0, []byte{0, 2, 0, 253, 255, 17, 18, 1, 0, 0, 255, 255}},
	{[]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 0,
		[]byte{0, 8, 0, 247, 255, 17, 17, 17, 17, 17, 17, 17, 17, 1, 0, 0, 255, 255},
	},
	{[]byte{}, 2, []byte{1, 0, 0, 255, 255}},
	{[]byte{0x11}, 2, []byte{18, 4, 4, 0, 0, 255, 255}},
	{[]byte{0x11, 0x12}, 2, []byte{18, 20, 2, 4, 0, 0, 255, 255}},
	{[]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 2, []byte{18, 132, 2, 64, 0, 0, 0, 255, 255}},
	{[]byte{}, 9, []byte{1, 0, 0, 255, 255}},
	{[]byte{0x11}, 9, []byte{18, 4, 4, 0, 0, 255, 255}},
	{[]byte{0x11, 0x12}, 9, []byte{18, 20, 2, 4, 0, 0, 255, 255}},
	{[]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 9, []byte{18, 132, 2, 64, 0, 0, 0, 255, 255}},
}

var deflateInflateTests = []*deflateInflateTest{
	{[]byte{}},
	{[]byte{0x11}},
	{[]byte{0x11, 0x12}},
	{[]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}},
	{[]byte{0x11, 0x10, 0x13, 0x41, 0x21, 0x21, 0x41, 0x13, 0x87, 0x78, 0x13}},
	{largeDataChunk()},
}

var reverseBitsTests = []*reverseBitsTest{
	{1, 1, 1},
	{1, 2, 2},
	{1, 3, 4},
	{1, 4, 8},
	{1, 5, 16},
	{17, 5, 17},
	{257, 9, 257},
	{29, 5, 23},
}

func largeDataChunk() []byte {
	result := make([]byte, 100000)
	for i := range result {
		result[i] = byte(i * i & 0xFF)
	}
	return result
}

func TestBulkHash4(t *testing.T) {
	for _, x := range deflateTests {
		y := x.out
		if len(y) < minMatchLength {
			continue
		}
		y = append(y, y...)
		for j := 4; j < len(y); j++ {
			y := y[:j]
			dst := make([]uint32, len(y)-minMatchLength+1)
			for i := range dst {
				dst[i] = uint32(i + 100)
			}
			bulkHash4(y, dst)
			for i, got := range dst {
				want := hash4(y[i:])
				if got != want && got == uint32(i)+100 {
					t.Errorf("Len:%d Index:%d, want 0x%08x but not modified", len(y), i, want)
				} else if got != want {
					t.Errorf("Len:%d Index:%d, got 0x%08x want:0x%08x", len(y), i, got, want)
				}
			}
		}
	}
}

func TestDeflate(t *testing.T) {
	for _, h := range deflateTests {
		var buf bytes.Buffer
		w, err := NewWriter(&buf, h.level)
		if err != nil {
			t.Errorf("NewWriter: %v", err)
			continue
		}
		w.Write(h.in)
		w.Close()
		if !bytes.Equal(buf.Bytes(), h.out) {
			t.Errorf("Deflate(%d, %x) = \n%#v, want \n%#v", h.level, h.in, buf.Bytes(), h.out)
		}
	}
}

func TestWriterClose(t *testing.T) {
	b := new(bytes.Buffer)
	zw, err := NewWriter(b, 6)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	if c, err := zw.Write([]byte("Test")); err != nil || c != 4 {
		t.Fatalf("Write to not closed writer: %s, %d", err, c)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	afterClose := b.Len()

	if c, err := zw.Write([]byte("Test")); err == nil || c != 0 {
		t.Fatalf("Write to closed writer: %v, %d", err, c)
	}

	if err := zw.Flush(); err == nil {
		t.Fatalf("Flush to closed writer: %s", err)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if afterClose != b.Len() {
		t.Fatalf("Writer wrote data after close. After close: %d. After writes on closed stream: %d", afterClose, b.Len())
	}
}

// A sparseReader returns a stream consisting of 0s followed by 1<<16 1s.
// This tests missing hash references in a very large input.
type sparseReader struct {
	l   int64
	cur int64
}

func (r *sparseReader) Read(b []byte) (n int, err error) {
	if r.cur >= r.l {
		return 0, io.EOF
	}
	n = len(b)
	cur := r.cur + int64(n)
	if cur > r.l {
		n -= int(cur - r.l)
		cur = r.l
	}
	for i := range b[0:n] {
		if r.cur+int64(i) >= r.l-1<<16 {
			b[i] = 1
		} else {
			b[i] = 0
		}
	}
	r.cur = cur
	return
}

func TestVeryLongSparseChunk(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sparse chunk during short test")
	}
	w, err := NewWriter(io.Discard, 1)
	if err != nil {
		t.Errorf("NewWriter: %v", err)
		return
	}
	if _, err = io.Copy(w, &sparseReader{l: 23e8}); err != nil {
		t.Errorf("Compress failed: %v", err)
		return
	}
}

type syncBuffer struct {
	buf    bytes.Buffer
	mu     sync.RWMutex
	closed bool
	ready  chan bool
}

func newSyncBuffer() *syncBuffer {
	return &syncBuffer{ready: make(chan bool, 1)}
}

func (b *syncBuffer) Read(p []byte) (n int, err error) {
	for {
		b.mu.RLock()
		n, err = b.buf.Read(p)
		b.mu.RUnlock()
		if n > 0 || b.closed {
			return
		}
		<-b.ready
	}
}

func (b *syncBuffer) signal() {
	select {
	case b.ready <- true:
	default:
	}
}

func (b *syncBuffer) Write(p []byte) (n int, err error) {
	n, err = b.buf.Write(p)
	b.signal()
	return
}

func (b *syncBuffer) WriteMode() {
	b.mu.Lock()
}

func (b *syncBuffer) ReadMode() {
	b.mu.Unlock()
	b.signal()
}

func (b *syncBuffer) Close() error {
	b.closed = true
	b.signal()
	return nil
}

func testSync(t *testing.T, level int, input []byte, name string) {
	if len(input) == 0 {
		return
	}

	t.Logf("--testSync %d, %d, %s", level, len(input), name)
	buf := newSyncBuffer()
	buf1 := new(bytes.Buffer)
	buf.WriteMode()
	w, err := NewWriter(io.MultiWriter(buf, buf1), level)
	if err != nil {
		t.Errorf("NewWriter: %v", err)
		return
	}
	r := NewReader(buf)

	// Write half the input and read back.
	for i := 0; i < 2; i++ {
		var lo, hi int
		if i == 0 {
			lo, hi = 0, (len(input)+1)/2
		} else {
			lo, hi = (len(input)+1)/2, len(input)
		}
		t.Logf("#%d: write %d-%d", i, lo, hi)
		if _, err := w.Write(input[lo:hi]); err != nil {
			t.Errorf("testSync: write: %v", err)
			return
		}
		if i == 0 {
			if err := w.Flush(); err != nil {
				t.Errorf("testSync: flush: %v", err)
				return
			}
		} else {
			if err := w.Close(); err != nil {
				t.Errorf("testSync: close: %v", err)
			}
		}
		buf.ReadMode()
		out := make([]byte, hi-lo+1)
		m, err := io.ReadAtLeast(r, out, hi-lo)
		t.Logf("#%d: read %d", i, m)
		if m != hi-lo || err != nil {
			t.Errorf("testSync/%d (%d, %d, %s): read %d: %d, %v (%d left)", i, level, len(input), name, hi-lo, m, err, buf.buf.Len())
			return
		}
		if !bytes.Equal(input[lo:hi], out[:hi-lo]) {
			t.Errorf("testSync/%d: read wrong bytes: %x vs %x", i, input[lo:hi], out[:hi-lo])
			return
		}
		// This test originally checked that after reading
		// the first half of the input, there was nothing left
		// in the read buffer (buf.buf.Len() != 0) but that is
		// not necessarily the case: the write Flush may emit
		// some extra framing bits that are not necessary
		// to process to obtain the first half of the uncompressed
		// data. The test ran correctly most of the time, because
		// the background goroutine had usually read even
		// those extra bits by now, but it's not a useful thing to
		// check.
		buf.WriteMode()
	}
	buf.ReadMode()
	out := make([]byte, 10)
	if n, err := r.Read(out); n > 0 || err != io.EOF {
		t.Errorf("testSync (%d, %d, %s): final Read: %d, %v (hex: %x)", level, len(input), name, n, err, out[0:n])
	}
	if buf.buf.Len() != 0 {
		t.Errorf("testSync (%d, %d, %s): extra data at end", level, len(input), name)
	}
	r.Close()

	// stream should work for ordinary reader too
	r = NewReader(buf1)
	out, err = io.ReadAll(r)
	if err != nil {
		t.Errorf("testSync: read: %s", err)
		return
	}
	r.Close()
	if !bytes.Equal(input, out) {
		t.Errorf("testSync: decompress(compress(data)) != data: level=%d input=%s", level, name)
	}
}

func testToFromWithLevelAndLimit(t *testing.T, level int, input []byte, name string, limit int) {
	var buffer bytes.Buffer
	w, err := NewWriter(&buffer, level)
	if err != nil {
		t.Errorf("NewWriter: %v", err)
		return
	}
	w.Write(input)
	w.Close()
	if limit > 0 && buffer.Len() > limit {
		t.Errorf("level: %d, len(compress(data)) = %d > limit = %d", level, buffer.Len(), limit)
		return
	}
	if limit > 0 {
		t.Logf("level: %d, size:%.2f%%, %d b\n", level, float64(buffer.Len()*100)/float64(limit), buffer.Len())
	}
	r := NewReader(&buffer)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Errorf("read: %s", err)
		return
	}
	r.Close()
	if !bytes.Equal(input, out) {
		t.Errorf("decompress(compress(data)) != data: level=%d input=%s", level, name)
		return
	}
	testSync(t, level, input, name)
}

func testToFromWithLimit(t *testing.T, input []byte, name string, limit [11]int) {
	for i := 0; i < 10; i++ {
		testToFromWithLevelAndLimit(t, i, input, name, limit[i])
	}
	// Test HuffmanCompression
	testToFromWithLevelAndLimit(t, -2, input, name, limit[10])
}

func TestDeflateInflate(t *testing.T) {
	t.Parallel()
	for i, h := range deflateInflateTests {
		if testing.Short() && len(h.in) > 10000 {
			continue
		}
		testToFromWithLimit(t, h.in, fmt.Sprintf("#%d", i), [11]int{})
	}
}

func TestReverseBits(t *testing.T) {
	for _, h := range reverseBitsTests {
		if v := reverseBits(h.in, h.bitCount); v != h.out {
			t.Errorf("reverseBits(%v,%v) = %v, want %v",
				h.in, h.bitCount, v, h.out)
		}
	}
}

type deflateInflateStringTest struct {
	filename string
	label    string
	limit    [11]int
}

var deflateInflateStringTests = []deflateInflateStringTest{
	{
		"../testdata/e.txt",
		"2.718281828...",
		[...]int{100018, 50650, 50960, 51150, 50930, 50790, 50790, 50790, 50790, 50790, 43683},
	},
	{
		"../../testdata/Isaac.Newton-Opticks.txt",
		"Isaac.Newton-Opticks",
		[...]int{567248, 218338, 198211, 193152, 181100, 175427, 175427, 173597, 173422, 173422, 325240},
	},
}

func TestDeflateInflateString(t *testing.T) {
	t.Parallel()
	if testing.Short() && testenv.Builder() == "" {
		t.Skip("skipping in short mode")
	}
	for _, test := range deflateInflateStringTests {
		gold, err := os.ReadFile(test.filename)
		if err != nil {
			t.Error(err)
		}
		testToFromWithLimit(t, gold, test.label, test.limit)
		if testing.Short() {
			break
		}
	}
}

func TestReaderDict(t *testing.T) {
	const (
		dict = "hello world"
		text = "hello again world"
	)
	var b bytes.Buffer
	w, err := NewWriter(&b, 5)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	w.Write([]byte(dict))
	w.Flush()
	b.Reset()
	w.Write([]byte(text))
	w.Close()

	r := NewReaderDict(&b, []byte(dict))
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello again world" {
		t.Fatalf("read returned %q want %q", string(data), text)
	}
}

func TestWriterDict(t *testing.T) {
	const (
		dict = "hello world"
		text = "hello again world"
	)
	var b bytes.Buffer
	w, err := NewWriter(&b, 5)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	w.Write([]byte(dict))
	w.Flush()
	b.Reset()
	w.Write([]byte(text))
	w.Close()

	var b1 bytes.Buffer
	w, _ = NewWriterDict(&b1, 5, []byte(dict))
	w.Write([]byte(text))
	w.Close()

	if !bytes.Equal(b1.Bytes(), b.Bytes()) {
		t.Fatalf("writer wrote %q want %q", b1.Bytes(), b.Bytes())
	}
}

// See https://golang.org/issue/2508
func TestRegression2508(t *testing.T) {
	if testing.Short() {
		t.Logf("test disabled with -short")
		return
	}
	w, err := NewWriter(io.Discard, 1)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	buf := make([]byte, 1024)
	for i := 0; i < 131072; i++ {
		if _, err := w.Write(buf); err != nil {
			t.Fatalf("writer failed: %v", err)
		}
	}
	w.Close()
}

func TestWriterReset(t *testing.T) {
	t.Parallel()
	for level := 0; level <= 9; level++ {
		if testing.Short() && level > 1 {
			break
		}
		w, err := NewWriter(io.Discard, level)
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}
		buf := []byte("hello world")
		n := 1024
		if testing.Short() {
			n = 10
		}
		for i := 0; i < n; i++ {
			w.Write(buf)
		}
		w.Reset(io.Discard)

		wref, err := NewWriter(io.Discard, level)
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}

		// DeepEqual doesn't compare functions.
		w.d.fill, wref.d.fill = nil, nil
		w.d.step, wref.d.step = nil, nil
		w.d.bulkHasher, wref.d.bulkHasher = nil, nil
		w.d.bestSpeed, wref.d.bestSpeed = nil, nil
		// hashMatch is always overwritten when used.
		copy(w.d.hashMatch[:], wref.d.hashMatch[:])
		if len(w.d.tokens) != 0 {
			t.Errorf("level %d Writer not reset after Reset. %d tokens were present", level, len(w.d.tokens))
		}
		// As long as the length is 0, we don't care about the content.
		w.d.tokens = wref.d.tokens

		// We don't care if there are values in the window, as long as it is at d.index is 0
		w.d.window = wref.d.window
		if !reflect.DeepEqual(w, wref) {
			t.Errorf("level %d Writer not reset after Reset", level)
		}
	}

	levels := []int{0, 1, 2, 5, 9}
	for _, level := range levels {
		t.Run(fmt.Sprint(level), func(t *testing.T) {
			testResetOutput(t, level, nil)
		})
	}

	t.Run("dict", func(t *testing.T) {
		for _, level := range levels {
			t.Run(fmt.Sprint(level), func(t *testing.T) {
				testResetOutput(t, level, nil)
			})
		}
	})
}

func testResetOutput(t *testing.T, level int, dict []byte) {
	writeData := func(w *Writer) {
		msg := []byte("now is the time for all good gophers")
		w.Write(msg)
		w.Flush()

		hello := []byte("hello world")
		for i := 0; i < 1024; i++ {
			w.Write(hello)
		}

		fill := bytes.Repeat([]byte("x"), 65000)
		w.Write(fill)
	}

	buf := new(bytes.Buffer)
	var w *Writer
	var err error
	if dict == nil {
		w, err = NewWriter(buf, level)
	} else {
		w, err = NewWriterDict(buf, level, dict)
	}
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	writeData(w)
	w.Close()
	out1 := buf.Bytes()

	buf2 := new(bytes.Buffer)
	w.Reset(buf2)
	writeData(w)
	w.Close()
	out2 := buf2.Bytes()

	if len(out1) != len(out2) {
		t.Errorf("got %d, expected %d bytes", len(out2), len(out1))
		return
	}
	if !bytes.Equal(out1, out2) {
		mm := 0
		for i, b := range out1[:len(out2)] {
			if b != out2[i] {
				t.Errorf("mismatch index %d: %#02x, expected %#02x", i, out2[i], b)
			}
			mm++
			if mm == 10 {
				t.Fatal("Stopping")
			}
		}
	}
	t.Logf("got %d bytes", len(out1))
}

// TestBestSpeed tests that round-tripping through deflate and then inflate
// recovers the original input. The Write sizes are near the thresholds in the
// compressor.encSpeed method (0, 16, 128), as well as near maxStoreBlockSize
// (65535).
func TestBestSpeed(t *testing.T) {
	t.Parallel()
	abc := make([]byte, 128)
	for i := range abc {
		abc[i] = byte(i)
	}
	abcabc := bytes.Repeat(abc, 131072/len(abc))
	var want []byte

	testCases := [][]int{
		{65536, 0},
		{65536, 1},
		{65536, 1, 256},
		{65536, 1, 65536},
		{65536, 14},
		{65536, 15},
		{65536, 16},
		{65536, 16, 256},
		{65536, 16, 65536},
		{65536, 127},
		{65536, 128},
		{65536, 128, 256},
		{65536, 128, 65536},
		{65536, 129},
		{65536, 65536, 256},
		{65536, 65536, 65536},
	}

	for i, tc := range testCases {
		if i >= 3 && testing.Short() {
			break
		}
		for _, firstN := range []int{1, 65534, 65535, 65536, 65537, 131072} {
			tc[0] = firstN
		outer:
			for _, flush := range []bool{false, true} {
				buf := new(bytes.Buffer)
				want = want[:0]

				w, err := NewWriter(buf, BestSpeed)
				if err != nil {
					t.Errorf("i=%d, firstN=%d, flush=%t: NewWriter: %v", i, firstN, flush, err)
					continue
				}
				for _, n := range tc {
					want = append(want, abcabc[:n]...)
					if _, err := w.Write(abcabc[:n]); err != nil {
						t.Errorf("i=%d, firstN=%d, flush=%t: Write: %v", i, firstN, flush, err)
						continue outer
					}
					if !flush {
						continue
					}
					if err := w.Flush(); err != nil {
						t.Errorf("i=%d, firstN=%d, flush=%t: Flush: %v", i, firstN, flush, err)
						continue outer
					}
				}
				if err := w.Close(); err != nil {
					t.Errorf("i=%d, firstN=%d, flush=%t: Close: %v", i, firstN, flush, err)
					continue
				}

				r := NewReader(buf)
				got, err := io.ReadAll(r)
				if err != nil {
					t.Errorf("i=%d, firstN=%d, flush=%t: ReadAll: %v", i, firstN, flush, err)
					continue
				}
				r.Close()

				if !bytes.Equal(got, want) {
					t.Errorf("i=%d, firstN=%d, flush=%t: corruption during deflate-then-inflate", i, firstN, flush)
					continue
				}
			}
		}
	}
}

var errIO = errors.New("IO error")

// failWriter fails with errIO exactly at the nth call to Write.
type failWriter struct{ n int }

func (w *failWriter) Write(b []byte) (int, error) {
	w.n--
	if w.n == -1 {
		return 0, errIO
	}
	return len(b), nil
}

func TestWriterPersistentWriteError(t *testing.T) {
	t.Parallel()
	d, err := os.ReadFile("../../testdata/Isaac.Newton-Opticks.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	d = d[:10000] // Keep this test short

	zw, err := NewWriter(nil, DefaultCompression)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Sweep over the threshold at which an error is returned.
	// The variable i makes it such that the ith call to failWriter.Write will
	// return errIO. Since failWriter errors are not persistent, we must ensure
	// that flate.Writer errors are persistent.
	for i := 0; i < 1000; i++ {
		fw := &failWriter{i}
		zw.Reset(fw)

		_, werr := zw.Write(d)
		cerr := zw.Close()
		ferr := zw.Flush()
		if werr != errIO && werr != nil {
			t.Errorf("test %d, mismatching Write error: got %v, want %v", i, werr, errIO)
		}
		if cerr != errIO && fw.n < 0 {
			t.Errorf("test %d, mismatching Close error: got %v, want %v", i, cerr, errIO)
		}
		if ferr != errIO && fw.n < 0 {
			t.Errorf("test %d, mismatching Flush error: got %v, want %v", i, ferr, errIO)
		}
		if fw.n >= 0 {
			// At this point, the failure threshold was sufficiently high enough
			// that we wrote the whole stream without any errors.
			return
		}
	}
}
func TestWriterPersistentFlushError(t *testing.T) {
	zw, err := NewWriter(&failWriter{0}, DefaultCompression)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	flushErr := zw.Flush()
	closeErr := zw.Close()
	_, writeErr := zw.Write([]byte("Test"))
	checkErrors([]error{closeErr, flushErr, writeErr}, errIO, t)
}

func TestWriterPersistentCloseError(t *testing.T) {
	// If underlying writer return error on closing stream we should persistent this error across all writer calls.
	zw, err := NewWriter(&failWriter{0}, DefaultCompression)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	closeErr := zw.Close()
	flushErr := zw.Flush()
	_, writeErr := zw.Write([]byte("Test"))
	checkErrors([]error{closeErr, flushErr, writeErr}, errIO, t)

	// After closing writer we should persistent "write after close" error across Flush and Write calls, but return nil
	// on next Close calls.
	var b bytes.Buffer
	zw.Reset(&b)
	err = zw.Close()
	if err != nil {
		t.Fatalf("First call to close returned error: %s", err)
	}
	err = zw.Close()
	if err != nil {
		t.Fatalf("Second call to close returned error: %s", err)
	}

	flushErr = zw.Flush()
	_, writeErr = zw.Write([]byte("Test"))
	checkErrors([]error{flushErr, writeErr}, errWriterClosed, t)
}

func checkErrors(got []error, want error, t *testing.T) {
	t.Helper()
	for _, err := range got {
		if err != want {
			t.Errorf("Error doesn't match\nWant: %s\nGot: %s", want, got)
		}
	}
}

func TestBestSpeedMatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		previous, current []byte
		t, s, want        int32
	}{{
		previous: []byte{0, 0, 0, 1, 2},
		current:  []byte{3, 4, 5, 0, 1, 2, 3, 4, 5},
		t:        -3,
		s:        3,
		want:     6,
	}, {
		previous: []byte{0, 0, 0, 1, 2},
		current:  []byte{2, 4, 5, 0, 1, 2, 3, 4, 5},
		t:        -3,
		s:        3,
		want:     3,
	}, {
		previous: []byte{0, 0, 0, 1, 1},
		current:  []byte{3, 4, 5, 0, 1, 2, 3, 4, 5},
		t:        -3,
		s:        3,
		want:     2,
	}, {
		previous: []byte{0, 0, 0, 1, 2},
		current:  []byte{2, 2, 2, 2, 1, 2, 3, 4, 5},
		t:        -1,
		s:        0,
		want:     4,
	}, {
		previous: []byte{0, 0, 0, 1, 2, 3, 4, 5, 2, 2},
		current:  []byte{2, 2, 2, 2, 1, 2, 3, 4, 5},
		t:        -7,
		s:        4,
		want:     5,
	}, {
		previous: []byte{9, 9, 9, 9, 9},
		current:  []byte{2, 2, 2, 2, 1, 2, 3, 4, 5},
		t:        -1,
		s:        0,
		want:     0,
	}, {
		previous: []byte{9, 9, 9, 9, 9},
		current:  []byte{9, 2, 2, 2, 1, 2, 3, 4, 5},
		t:        0,
		s:        1,
		want:     0,
	}, {
		previous: []byte{},
		current:  []byte{9, 2, 2, 2, 1, 2, 3, 4, 5},
		t:        -5,
		s:        1,
		want:     0,
	}, {
		previous: []byte{},
		current:  []byte{9, 2, 2, 2, 1, 2, 3, 4, 5},
		t:        -1,
		s:        1,
		want:     0,
	}, {
		previous: []byte{},
		current:  []byte{2, 2, 2, 2, 1, 2, 3, 4, 5},
		t:        0,
		s:        1,
		want:     3,
	}, {
		previous: []byte{3, 4, 5},
		current:  []byte{3, 4, 5},
		t:        -3,
		s:        0,
		want:     3,
	}, {
		previous: make([]byte, 1000),
		current:  make([]byte, 1000),
		t:        -1000,
		s:        0,
		want:     maxMatchLength - 4,
	}, {
		previous: make([]byte, 200),
		current:  make([]byte, 500),
		t:        -200,
		s:        0,
		want:     maxMatchLength - 4,
	}, {
		previous: make([]byte, 200),
		current:  make([]byte, 500),
		t:        0,
		s:        1,
		want:     maxMatchLength - 4,
	}, {
		previous: make([]byte, maxMatchLength-4),
		current:  make([]byte, 500),
		t:        -(maxMatchLength - 4),
		s:        0,
		want:     maxMatchLength - 4,
	}, {
		previous: make([]byte, 200),
		current:  make([]byte, 500),
		t:        -200,
		s:        400,
		want:     100,
	}, {
		previous: make([]byte, 10),
		current:  make([]byte, 500),
		t:        200,
		s:        400,
		want:     100,
	}}
	for i, c := range cases {
		e := deflateFast{prev: c.previous}
		got := e.matchLen(c.s, c.t, c.current)
		if got != c.want {
			t.Errorf("Test %d: match length, want %d, got %d", i, c.want, got)
		}
	}
}

func TestBestSpeedMaxMatchOffset(t *testing.T) {
	t.Parallel()
	const abc, xyz = "abcdefgh", "stuvwxyz"
	for _, matchBefore := range []bool{false, true} {
		for _, extra := range []int{0, inputMargin - 1, inputMargin, inputMargin + 1, 2 * inputMargin} {
			for offsetAdj := -5; offsetAdj <= +5; offsetAdj++ {
				report := func(desc string, err error) {
					t.Errorf("matchBefore=%t, extra=%d, offsetAdj=%d: %s%v",
						matchBefore, extra, offsetAdj, desc, err)
				}

				offset := maxMatchOffset + offsetAdj

				// Make src to be a []byte of the form
				//	"%s%s%s%s%s" % (abc, zeros0, xyzMaybe, abc, zeros1)
				// where:
				//	zeros0 is approximately maxMatchOffset zeros.
				//	xyzMaybe is either xyz or the empty string.
				//	zeros1 is between 0 and 30 zeros.
				// The difference between the two abc's will be offset, which
				// is maxMatchOffset plus or minus a small adjustment.
				src := make([]byte, offset+len(abc)+extra)
				copy(src, abc)
				if !matchBefore {
					copy(src[offset-len(xyz):], xyz)
				}
				copy(src[offset:], abc)

				buf := new(bytes.Buffer)
				w, err := NewWriter(buf, BestSpeed)
				if err != nil {
					report("NewWriter: ", err)
					continue
				}
				if _, err := w.Write(src); err != nil {
					report("Write: ", err)
					continue
				}
				if err := w.Close(); err != nil {
					report("Writer.Close: ", err)
					continue
				}

				r := NewReader(buf)
				dst, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					report("ReadAll: ", err)
					continue
				}

				if !bytes.Equal(dst, src) {
					report("", fmt.Errorf("bytes differ after round-tripping"))
					continue
				}
			}
		}
	}
}

func TestBestSpeedShiftOffsets(t *testing.T) {
	// Test if shiftoffsets properly preserves matches and resets out-of-range matches
	// seen in https://github.com/golang/go/issues/4142
	enc := newDeflateFast()

	// testData may not generate internal matches.
	testData := make([]byte, 32)
	rng := rand.New(rand.NewSource(0))
	for i := range testData {
		testData[i] = byte(rng.Uint32())
	}

	// Encode the testdata with clean state.
	// Second part should pick up matches from the first block.
	wantFirstTokens := len(enc.encode(nil, testData))
	wantSecondTokens := len(enc.encode(nil, testData))

	if wantFirstTokens <= wantSecondTokens {
		t.Fatalf("test needs matches between inputs to be generated")
	}
	// Forward the current indicator to before wraparound.
	enc.cur = bufferReset - int32(len(testData))

	// Part 1 before wrap, should match clean state.
	got := len(enc.encode(nil, testData))
	if wantFirstTokens != got {
		t.Errorf("got %d, want %d tokens", got, wantFirstTokens)
	}

	// Verify we are about to wrap.
	if enc.cur != bufferReset {
		t.Errorf("got %d, want e.cur to be at bufferReset (%d)", enc.cur, bufferReset)
	}

	// Part 2 should match clean state as well even if wrapped.
	got = len(enc.encode(nil, testData))
	if wantSecondTokens != got {
		t.Errorf("got %d, want %d token", got, wantSecondTokens)
	}

	// Verify that we wrapped.
	if enc.cur >= bufferReset {
		t.Errorf("want e.cur to be < bufferReset (%d), got %d", bufferReset, enc.cur)
	}

	// Forward the current buffer, leaving the matches at the bottom.
	enc.cur = bufferReset
	enc.shiftOffsets()

	// Ensure that no matches were picked up.
	got = len(enc.encode(nil, testData))
	if wantFirstTokens != got {
		t.Errorf("got %d, want %d tokens", got, wantFirstTokens)
	}
}

func TestMaxStackSize(t *testing.T) {
	// This test must not run in parallel with other tests as debug.SetMaxStack
	// affects all goroutines.
	n := debug.SetMaxStack(1 << 16)
	defer debug.SetMaxStack(n)

	var wg sync.WaitGroup
	defer wg.Wait()

	b := make([]byte, 1<<20)
	for level := HuffmanOnly; level <= BestCompression; level++ {
		// Run in separate goroutine to increase probability of stack regrowth.
		wg.Add(1)
		go func(level int) {
			defer wg.Done()
			zw, err := NewWriter(io.Discard, level)
			if err != nil {
				t.Errorf("level %d, NewWriter() = %v, want nil", level, err)
			}
			if n, err := zw.Write(b); n != len(b) || err != nil {
				t.Errorf("level %d, Write() = (%d, %v), want (%d, nil)", level, n, err, len(b))
			}
			if err := zw.Close(); err != nil {
				t.Errorf("level %d, Close() = %v, want nil", level, err)
			}
			zw.Reset(io.Discard)
		}(level)
	}
}

"""



```