Response:
Let's break down the thought process for analyzing the `bytes.Buffer` code and generating the detailed response.

1. **Understand the Core Purpose:** The initial comment "// Simple byte buffer for marshaling data." and the type definition `type Buffer struct` immediately tell us this is about managing a dynamically sized byte array in memory. The `Read` and `Write` methods mentioned in the documentation further reinforce its role as an in-memory buffer implementing the `io.Reader` and `io.Writer` interfaces (though not explicitly stated in the provided snippet).

2. **Identify Key Data Structures:**  The `Buffer` struct has three main fields: `buf`, `off`, and `lastRead`. Understanding these is crucial:
    * `buf`: The underlying byte slice. This holds the actual data.
    * `off`: The offset, indicating the starting point for reading. This means the data conceptually "in the buffer" is `buf[off:]`.
    * `lastRead`:  Keeps track of the last read operation. This is important for the `UnreadByte` and `UnreadRune` functionality.

3. **Categorize Functionality:**  Go through each function and group them based on their primary action:
    * **Information/Access:** `Bytes()`, `AvailableBuffer()`, `String()`, `Len()`, `Cap()`, `Available()` - These provide information about the buffer's state.
    * **Modification (Write):** `Write()`, `WriteString()`, `WriteByte()`, `WriteRune()`, `Grow()`, `ReadFrom()` - These functions add data to the buffer.
    * **Modification (Read):** `Read()`, `Next()`, `ReadByte()`, `ReadRune()`, `ReadBytes()`, `ReadString()` - These functions retrieve data from the buffer.
    * **Modification (Other):** `Truncate()`, `Reset()`, `UnreadByte()`, `UnreadRune()`, `WriteTo()` - These functions modify the buffer in various ways, including resetting, truncating, or writing its contents elsewhere.
    * **Creation:** `NewBuffer()`, `NewBufferString()` - These create new `Buffer` instances.
    * **Internal Helpers:** `empty()`, `tryGrowByReslice()`, `grow()`, `growSlice()` -  These are internal functions supporting the core functionality.

4. **Explain Each Function's Purpose:** For each function, describe its role in simple, clear terms. Focus on what it does, its inputs, and its outputs. For example, for `Write()`, explain that it appends data, grows if needed, and always returns `nil` for the error.

5. **Identify Core Go Language Concepts Illustrated:**  Look for key Go features demonstrated by the code. The `bytes.Buffer` clearly showcases:
    * **Structs and Methods:**  The `Buffer` struct and its associated methods are a fundamental part of Go's object-oriented programming.
    * **Slices:** The core of the `Buffer` is the `[]byte` slice, demonstrating dynamic sizing and memory management.
    * **Interfaces (`io.Reader`, `io.Writer`):** Although not explicitly shown in the snippet, the function names (`Read`, `Write`, `ReadFrom`, `WriteTo`) strongly suggest implementation of these interfaces.
    * **Error Handling:** The code uses `error` as a return type and defines custom errors like `ErrTooLarge`.
    * **String Conversion:**  The `String()` method and `WriteString()` functions show how byte slices and strings interact.
    * **UTF-8 Handling:** `ReadRune()` and `WriteRune()` demonstrate support for Unicode.
    * **Memory Management (Implicit):** The `grow` and `growSlice` functions highlight the dynamic memory allocation behind slices.

6. **Provide Code Examples (Crucial for Understanding):** For the core functionality (read and write), provide concise and illustrative code examples. Include:
    * **Setup:** Creating a `Buffer`.
    * **Action:** Performing the read or write operation.
    * **Output/Verification:**  Printing the buffer contents or the result of the operation.
    * **Assumptions/Inputs:** Clearly state any assumptions made about the input data.

7. **Address Potential Pitfalls (Important for Users):** Think about common mistakes developers might make when using `bytes.Buffer`. Key examples include:
    * **Modifying the slice returned by `Bytes()`:**  Highlight that this can have unintended side effects.
    * **Assuming capacity is always sufficient:** Explain the `ErrTooLarge` panic.
    * **Misunderstanding the `off` pointer:**  Explain how `Reset()` affects the read position.

8. **Command-Line Arguments (Not Applicable):** This code doesn't directly interact with command-line arguments, so explicitly state that.

9. **Structure and Language:** Organize the answer logically with clear headings and bullet points. Use precise and accurate language. Explain technical terms where necessary. The goal is to be informative and easy to understand.

10. **Review and Refine:**  Read through the entire answer to ensure accuracy, clarity, and completeness. Are there any ambiguities?  Is the language consistent? Could anything be explained better?

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Focus heavily on individual function explanations.
* **Correction:** Realize the importance of grouping functions by category and explaining the overall purpose of `bytes.Buffer`.
* **Initial Thought:** Briefly mention `io.Reader` and `io.Writer`.
* **Correction:** Emphasize this aspect more as it's a key feature and implication of the function names.
* **Initial Thought:** Provide only basic code examples.
* **Correction:** Add more comprehensive examples demonstrating both read and write operations and how to check the buffer's content.
* **Initial Thought:**  List all functions without context.
* **Correction:** Prioritize the most commonly used functions and explain their relevance. Mention internal helpers as supporting functions.
* **Initial Thought:**  Assume the user is an expert Go developer.
* **Correction:** Explain concepts clearly and avoid jargon where possible. Target a broader audience of Go developers.
这段代码是 Go 语言标准库 `bytes` 包中 `Buffer` 类型的一部分实现。`Buffer` 类型提供了一个可变大小的字节缓冲区，实现了 `io.Reader` 和 `io.Writer` 接口，可以用于高效地构建和操作字节序列。

以下是 `bytes.Buffer` 的主要功能：

1. **作为字节序列的容器:**  `Buffer` 可以存储任意数量的字节，类似于动态数组。
2. **实现 `io.Reader` 接口:** 这意味着你可以像从文件中读取数据一样从 `Buffer` 中读取字节。
3. **实现 `io.Writer` 接口:** 这意味着你可以像写入文件一样向 `Buffer` 中写入字节。
4. **动态增长:** 当写入的数据超过当前缓冲区容量时，`Buffer` 会自动扩展其内部存储空间。
5. **高效的字符串构建:**  虽然 `strings.Builder` 更适合专门用于构建字符串，但 `Buffer` 也可以用来高效地拼接字符串片段，避免不必要的内存分配和复制。
6. **支持常见的读写操作:**  提供了 `Read`、`Write`、`ReadByte`、`WriteByte`、`ReadRune`、`WriteRune` 等方法进行基本的字节和字符读写。
7. **支持查找和截断:** 提供了 `Truncate` 方法来截断缓冲区的内容。
8. **支持回退操作:** 提供了 `UnreadByte` 和 `UnreadRune` 方法来撤销最近的读取操作。
9. **支持写入到 `io.Writer` 和从 `io.Reader` 读取:** 提供了 `WriteTo` 和 `ReadFrom` 方法，方便与其他实现了 `io.Writer` 和 `io.Reader` 接口的类型进行交互。

**`bytes.Buffer` 是 Go 语言中实现内存缓冲区的核心组件之一。**

**Go 代码举例说明:**

假设我们需要从不同的来源读取一些数据，并将它们合并到一个缓冲区中，然后再将缓冲区的内容作为一个整体进行处理。

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

func main() {
	var buf bytes.Buffer

	// 从字符串写入
	buf.WriteString("Hello, ")

	// 从字节切片写入
	data := []byte("world!")
	buf.Write(data)

	// 从另一个 io.Reader 写入
	reader := strings.NewReader(" Welcome!")
	io.Copy(&buf, reader)

	// 读取缓冲区的内容
	result := buf.String()
	fmt.Println(result) // 输出: Hello, world! Welcome!

	// 从缓冲区读取数据
	readBuf := make([]byte, 5)
	n, err := buf.Read(readBuf)
	if err != nil && err != io.EOF {
		fmt.Println("读取错误:", err)
	} else {
		fmt.Printf("读取了 %d 个字节: %s\n", n, string(readBuf[:n])) // 输出: 读取了 5 个字节: Hello
	}

	// 再次读取，会从上次读取的位置开始
	n, err = buf.Read(readBuf)
	if err != nil && err != io.EOF {
		fmt.Println("读取错误:", err)
	} else {
		fmt.Printf("读取了 %d 个字节: %s\n", n, string(readBuf[:n])) // 输出: 读取了 5 个字节: , wor
	}
}
```

**假设的输入与输出:**

在上面的例子中，我们没有直接的外部输入，数据来源是硬编码的字符串和字节切片。

**输出:**

```
Hello, world! Welcome!
读取了 5 个字节: Hello
读取了 5 个字节: , wor
```

**代码推理:**

1. **创建缓冲区:** `var buf bytes.Buffer` 创建了一个空的 `Buffer`。
2. **写入数据:** `WriteString`、`Write` 和 `io.Copy` 方法将不同来源的数据追加到缓冲区 `buf` 的末尾。`io.Copy` 将 `reader` 中的数据读取并写入到 `buf` 中。
3. **读取缓冲区内容:** `buf.String()` 方法返回缓冲区中未读取部分的字符串表示。
4. **从缓冲区读取:** `buf.Read(readBuf)` 方法从缓冲区 `buf` 中读取最多 `len(readBuf)` 个字节到 `readBuf` 中。返回值 `n` 是实际读取的字节数，`err` 是可能出现的错误。第一次读取后，`Buffer` 的内部读取偏移量会移动，所以第二次读取会从上次读取的位置开始。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。`bytes.Buffer` 主要用于内存中的数据操作，而不是与命令行交互。如果需要从命令行读取数据并存储到 `bytes.Buffer` 中，你需要使用其他包，例如 `os` 包来获取命令行参数，然后将参数内容写入 `Buffer`。

**使用者易犯错的点:**

1. **修改 `Bytes()` 方法返回的切片:** `Bytes()` 方法返回的是缓冲区内部字节切片的一个切片。直接修改这个返回的切片会直接影响 `Buffer` 的内容，这可能会导致意想不到的结果。

   ```go
   package main

   import "bytes"
   import "fmt"

   func main() {
       var buf bytes.Buffer
       buf.WriteString("hello")
       b := buf.Bytes()
       b[0] = 'J'
       fmt.Println(buf.String()) // 输出: Jello
   }
   ```
   在这个例子中，修改 `b[0]` 直接改变了 `buf` 的内容。

2. **混淆 `Len()` 和 `Cap()`:**
   - `Len()` 返回缓冲区中未读取部分的字节数。
   - `Cap()` 返回缓冲区底层字节切片的总容量。

   ```go
   package main

   import "bytes"
   import "fmt"

   func main() {
       buf := bytes.NewBuffer(make([]byte, 10, 100)) // 初始长度 10，容量 100
       buf.WriteString("world")
       fmt.Println("Len:", buf.Len())   // 输出: Len: 15
       fmt.Println("Cap:", buf.Cap())   // 输出: Cap: 100
       fmt.Println("Available:", buf.Available()) // 输出: Available: 85
   }
   ```
   初学者可能会误认为 `Len()` 返回的是已写入的总字节数，而忽略了读取偏移量 `off` 的存在。

3. **未考虑缓冲区增长可能导致的 `ErrTooLarge` panic:** 当缓冲区需要增长但无法分配足够的内存时，某些写入操作（如 `Write`、`WriteString` 等）会 panic 并抛出 `ErrTooLarge`。

   ```go
   package main

   import "bytes"
   import "fmt"

   func main() {
       var buf bytes.Buffer
       largeData := make([]byte, 1<<31) // 2GB
       _, err := buf.Write(largeData)
       if err != nil {
           fmt.Println("写入错误:", err)
       }
       // 运行上面的代码可能会导致 panic: bytes.Buffer: too large
   }
   ```
   需要注意控制写入缓冲区的数据量，避免超出系统可用内存。

4. **在并发环境中使用 `Buffer` 需要注意同步:** `bytes.Buffer` 本身不是并发安全的。如果在多个 goroutine 中同时读写同一个 `Buffer`，可能会导致数据竞争和其他未定义行为。需要使用互斥锁或其他同步机制来保护 `Buffer` 的访问。

总而言之，`bytes.Buffer` 是一个强大且常用的工具，用于在内存中处理字节数据。理解其内部机制和潜在的陷阱可以帮助开发者更有效地使用它。

### 提示词
```
这是路径为go/src/bytes/buffer.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package bytes

// Simple byte buffer for marshaling data.

import (
	"errors"
	"io"
	"unicode/utf8"
)

// smallBufferSize is an initial allocation minimal capacity.
const smallBufferSize = 64

// A Buffer is a variable-sized buffer of bytes with [Buffer.Read] and [Buffer.Write] methods.
// The zero value for Buffer is an empty buffer ready to use.
type Buffer struct {
	buf      []byte // contents are the bytes buf[off : len(buf)]
	off      int    // read at &buf[off], write at &buf[len(buf)]
	lastRead readOp // last read operation, so that Unread* can work correctly.
}

// The readOp constants describe the last action performed on
// the buffer, so that UnreadRune and UnreadByte can check for
// invalid usage. opReadRuneX constants are chosen such that
// converted to int they correspond to the rune size that was read.
type readOp int8

// Don't use iota for these, as the values need to correspond with the
// names and comments, which is easier to see when being explicit.
const (
	opRead      readOp = -1 // Any other read operation.
	opInvalid   readOp = 0  // Non-read operation.
	opReadRune1 readOp = 1  // Read rune of size 1.
	opReadRune2 readOp = 2  // Read rune of size 2.
	opReadRune3 readOp = 3  // Read rune of size 3.
	opReadRune4 readOp = 4  // Read rune of size 4.
)

// ErrTooLarge is passed to panic if memory cannot be allocated to store data in a buffer.
var ErrTooLarge = errors.New("bytes.Buffer: too large")
var errNegativeRead = errors.New("bytes.Buffer: reader returned negative count from Read")

const maxInt = int(^uint(0) >> 1)

// Bytes returns a slice of length b.Len() holding the unread portion of the buffer.
// The slice is valid for use only until the next buffer modification (that is,
// only until the next call to a method like [Buffer.Read], [Buffer.Write], [Buffer.Reset], or [Buffer.Truncate]).
// The slice aliases the buffer content at least until the next buffer modification,
// so immediate changes to the slice will affect the result of future reads.
func (b *Buffer) Bytes() []byte { return b.buf[b.off:] }

// AvailableBuffer returns an empty buffer with b.Available() capacity.
// This buffer is intended to be appended to and
// passed to an immediately succeeding [Buffer.Write] call.
// The buffer is only valid until the next write operation on b.
func (b *Buffer) AvailableBuffer() []byte { return b.buf[len(b.buf):] }

// String returns the contents of the unread portion of the buffer
// as a string. If the [Buffer] is a nil pointer, it returns "<nil>".
//
// To build strings more efficiently, see the [strings.Builder] type.
func (b *Buffer) String() string {
	if b == nil {
		// Special case, useful in debugging.
		return "<nil>"
	}
	return string(b.buf[b.off:])
}

// empty reports whether the unread portion of the buffer is empty.
func (b *Buffer) empty() bool { return len(b.buf) <= b.off }

// Len returns the number of bytes of the unread portion of the buffer;
// b.Len() == len(b.Bytes()).
func (b *Buffer) Len() int { return len(b.buf) - b.off }

// Cap returns the capacity of the buffer's underlying byte slice, that is, the
// total space allocated for the buffer's data.
func (b *Buffer) Cap() int { return cap(b.buf) }

// Available returns how many bytes are unused in the buffer.
func (b *Buffer) Available() int { return cap(b.buf) - len(b.buf) }

// Truncate discards all but the first n unread bytes from the buffer
// but continues to use the same allocated storage.
// It panics if n is negative or greater than the length of the buffer.
func (b *Buffer) Truncate(n int) {
	if n == 0 {
		b.Reset()
		return
	}
	b.lastRead = opInvalid
	if n < 0 || n > b.Len() {
		panic("bytes.Buffer: truncation out of range")
	}
	b.buf = b.buf[:b.off+n]
}

// Reset resets the buffer to be empty,
// but it retains the underlying storage for use by future writes.
// Reset is the same as [Buffer.Truncate](0).
func (b *Buffer) Reset() {
	b.buf = b.buf[:0]
	b.off = 0
	b.lastRead = opInvalid
}

// tryGrowByReslice is an inlineable version of grow for the fast-case where the
// internal buffer only needs to be resliced.
// It returns the index where bytes should be written and whether it succeeded.
func (b *Buffer) tryGrowByReslice(n int) (int, bool) {
	if l := len(b.buf); n <= cap(b.buf)-l {
		b.buf = b.buf[:l+n]
		return l, true
	}
	return 0, false
}

// grow grows the buffer to guarantee space for n more bytes.
// It returns the index where bytes should be written.
// If the buffer can't grow it will panic with ErrTooLarge.
func (b *Buffer) grow(n int) int {
	m := b.Len()
	// If buffer is empty, reset to recover space.
	if m == 0 && b.off != 0 {
		b.Reset()
	}
	// Try to grow by means of a reslice.
	if i, ok := b.tryGrowByReslice(n); ok {
		return i
	}
	if b.buf == nil && n <= smallBufferSize {
		b.buf = make([]byte, n, smallBufferSize)
		return 0
	}
	c := cap(b.buf)
	if n <= c/2-m {
		// We can slide things down instead of allocating a new
		// slice. We only need m+n <= c to slide, but
		// we instead let capacity get twice as large so we
		// don't spend all our time copying.
		copy(b.buf, b.buf[b.off:])
	} else if c > maxInt-c-n {
		panic(ErrTooLarge)
	} else {
		// Add b.off to account for b.buf[:b.off] being sliced off the front.
		b.buf = growSlice(b.buf[b.off:], b.off+n)
	}
	// Restore b.off and len(b.buf).
	b.off = 0
	b.buf = b.buf[:m+n]
	return m
}

// Grow grows the buffer's capacity, if necessary, to guarantee space for
// another n bytes. After Grow(n), at least n bytes can be written to the
// buffer without another allocation.
// If n is negative, Grow will panic.
// If the buffer can't grow it will panic with [ErrTooLarge].
func (b *Buffer) Grow(n int) {
	if n < 0 {
		panic("bytes.Buffer.Grow: negative count")
	}
	m := b.grow(n)
	b.buf = b.buf[:m]
}

// Write appends the contents of p to the buffer, growing the buffer as
// needed. The return value n is the length of p; err is always nil. If the
// buffer becomes too large, Write will panic with [ErrTooLarge].
func (b *Buffer) Write(p []byte) (n int, err error) {
	b.lastRead = opInvalid
	m, ok := b.tryGrowByReslice(len(p))
	if !ok {
		m = b.grow(len(p))
	}
	return copy(b.buf[m:], p), nil
}

// WriteString appends the contents of s to the buffer, growing the buffer as
// needed. The return value n is the length of s; err is always nil. If the
// buffer becomes too large, WriteString will panic with [ErrTooLarge].
func (b *Buffer) WriteString(s string) (n int, err error) {
	b.lastRead = opInvalid
	m, ok := b.tryGrowByReslice(len(s))
	if !ok {
		m = b.grow(len(s))
	}
	return copy(b.buf[m:], s), nil
}

// MinRead is the minimum slice size passed to a [Buffer.Read] call by
// [Buffer.ReadFrom]. As long as the [Buffer] has at least MinRead bytes beyond
// what is required to hold the contents of r, [Buffer.ReadFrom] will not grow the
// underlying buffer.
const MinRead = 512

// ReadFrom reads data from r until EOF and appends it to the buffer, growing
// the buffer as needed. The return value n is the number of bytes read. Any
// error except io.EOF encountered during the read is also returned. If the
// buffer becomes too large, ReadFrom will panic with [ErrTooLarge].
func (b *Buffer) ReadFrom(r io.Reader) (n int64, err error) {
	b.lastRead = opInvalid
	for {
		i := b.grow(MinRead)
		b.buf = b.buf[:i]
		m, e := r.Read(b.buf[i:cap(b.buf)])
		if m < 0 {
			panic(errNegativeRead)
		}

		b.buf = b.buf[:i+m]
		n += int64(m)
		if e == io.EOF {
			return n, nil // e is EOF, so return nil explicitly
		}
		if e != nil {
			return n, e
		}
	}
}

// growSlice grows b by n, preserving the original content of b.
// If the allocation fails, it panics with ErrTooLarge.
func growSlice(b []byte, n int) []byte {
	defer func() {
		if recover() != nil {
			panic(ErrTooLarge)
		}
	}()
	// TODO(http://golang.org/issue/51462): We should rely on the append-make
	// pattern so that the compiler can call runtime.growslice. For example:
	//	return append(b, make([]byte, n)...)
	// This avoids unnecessary zero-ing of the first len(b) bytes of the
	// allocated slice, but this pattern causes b to escape onto the heap.
	//
	// Instead use the append-make pattern with a nil slice to ensure that
	// we allocate buffers rounded up to the closest size class.
	c := len(b) + n // ensure enough space for n elements
	if c < 2*cap(b) {
		// The growth rate has historically always been 2x. In the future,
		// we could rely purely on append to determine the growth rate.
		c = 2 * cap(b)
	}
	b2 := append([]byte(nil), make([]byte, c)...)
	i := copy(b2, b)
	return b2[:i]
}

// WriteTo writes data to w until the buffer is drained or an error occurs.
// The return value n is the number of bytes written; it always fits into an
// int, but it is int64 to match the [io.WriterTo] interface. Any error
// encountered during the write is also returned.
func (b *Buffer) WriteTo(w io.Writer) (n int64, err error) {
	b.lastRead = opInvalid
	if nBytes := b.Len(); nBytes > 0 {
		m, e := w.Write(b.buf[b.off:])
		if m > nBytes {
			panic("bytes.Buffer.WriteTo: invalid Write count")
		}
		b.off += m
		n = int64(m)
		if e != nil {
			return n, e
		}
		// all bytes should have been written, by definition of
		// Write method in io.Writer
		if m != nBytes {
			return n, io.ErrShortWrite
		}
	}
	// Buffer is now empty; reset.
	b.Reset()
	return n, nil
}

// WriteByte appends the byte c to the buffer, growing the buffer as needed.
// The returned error is always nil, but is included to match [bufio.Writer]'s
// WriteByte. If the buffer becomes too large, WriteByte will panic with
// [ErrTooLarge].
func (b *Buffer) WriteByte(c byte) error {
	b.lastRead = opInvalid
	m, ok := b.tryGrowByReslice(1)
	if !ok {
		m = b.grow(1)
	}
	b.buf[m] = c
	return nil
}

// WriteRune appends the UTF-8 encoding of Unicode code point r to the
// buffer, returning its length and an error, which is always nil but is
// included to match [bufio.Writer]'s WriteRune. The buffer is grown as needed;
// if it becomes too large, WriteRune will panic with [ErrTooLarge].
func (b *Buffer) WriteRune(r rune) (n int, err error) {
	// Compare as uint32 to correctly handle negative runes.
	if uint32(r) < utf8.RuneSelf {
		b.WriteByte(byte(r))
		return 1, nil
	}
	b.lastRead = opInvalid
	m, ok := b.tryGrowByReslice(utf8.UTFMax)
	if !ok {
		m = b.grow(utf8.UTFMax)
	}
	b.buf = utf8.AppendRune(b.buf[:m], r)
	return len(b.buf) - m, nil
}

// Read reads the next len(p) bytes from the buffer or until the buffer
// is drained. The return value n is the number of bytes read. If the
// buffer has no data to return, err is [io.EOF] (unless len(p) is zero);
// otherwise it is nil.
func (b *Buffer) Read(p []byte) (n int, err error) {
	b.lastRead = opInvalid
	if b.empty() {
		// Buffer is empty, reset to recover space.
		b.Reset()
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	n = copy(p, b.buf[b.off:])
	b.off += n
	if n > 0 {
		b.lastRead = opRead
	}
	return n, nil
}

// Next returns a slice containing the next n bytes from the buffer,
// advancing the buffer as if the bytes had been returned by [Buffer.Read].
// If there are fewer than n bytes in the buffer, Next returns the entire buffer.
// The slice is only valid until the next call to a read or write method.
func (b *Buffer) Next(n int) []byte {
	b.lastRead = opInvalid
	m := b.Len()
	if n > m {
		n = m
	}
	data := b.buf[b.off : b.off+n]
	b.off += n
	if n > 0 {
		b.lastRead = opRead
	}
	return data
}

// ReadByte reads and returns the next byte from the buffer.
// If no byte is available, it returns error [io.EOF].
func (b *Buffer) ReadByte() (byte, error) {
	if b.empty() {
		// Buffer is empty, reset to recover space.
		b.Reset()
		return 0, io.EOF
	}
	c := b.buf[b.off]
	b.off++
	b.lastRead = opRead
	return c, nil
}

// ReadRune reads and returns the next UTF-8-encoded
// Unicode code point from the buffer.
// If no bytes are available, the error returned is io.EOF.
// If the bytes are an erroneous UTF-8 encoding, it
// consumes one byte and returns U+FFFD, 1.
func (b *Buffer) ReadRune() (r rune, size int, err error) {
	if b.empty() {
		// Buffer is empty, reset to recover space.
		b.Reset()
		return 0, 0, io.EOF
	}
	c := b.buf[b.off]
	if c < utf8.RuneSelf {
		b.off++
		b.lastRead = opReadRune1
		return rune(c), 1, nil
	}
	r, n := utf8.DecodeRune(b.buf[b.off:])
	b.off += n
	b.lastRead = readOp(n)
	return r, n, nil
}

// UnreadRune unreads the last rune returned by [Buffer.ReadRune].
// If the most recent read or write operation on the buffer was
// not a successful [Buffer.ReadRune], UnreadRune returns an error.  (In this regard
// it is stricter than [Buffer.UnreadByte], which will unread the last byte
// from any read operation.)
func (b *Buffer) UnreadRune() error {
	if b.lastRead <= opInvalid {
		return errors.New("bytes.Buffer: UnreadRune: previous operation was not a successful ReadRune")
	}
	if b.off >= int(b.lastRead) {
		b.off -= int(b.lastRead)
	}
	b.lastRead = opInvalid
	return nil
}

var errUnreadByte = errors.New("bytes.Buffer: UnreadByte: previous operation was not a successful read")

// UnreadByte unreads the last byte returned by the most recent successful
// read operation that read at least one byte. If a write has happened since
// the last read, if the last read returned an error, or if the read read zero
// bytes, UnreadByte returns an error.
func (b *Buffer) UnreadByte() error {
	if b.lastRead == opInvalid {
		return errUnreadByte
	}
	b.lastRead = opInvalid
	if b.off > 0 {
		b.off--
	}
	return nil
}

// ReadBytes reads until the first occurrence of delim in the input,
// returning a slice containing the data up to and including the delimiter.
// If ReadBytes encounters an error before finding a delimiter,
// it returns the data read before the error and the error itself (often [io.EOF]).
// ReadBytes returns err != nil if and only if the returned data does not end in
// delim.
func (b *Buffer) ReadBytes(delim byte) (line []byte, err error) {
	slice, err := b.readSlice(delim)
	// return a copy of slice. The buffer's backing array may
	// be overwritten by later calls.
	line = append(line, slice...)
	return line, err
}

// readSlice is like ReadBytes but returns a reference to internal buffer data.
func (b *Buffer) readSlice(delim byte) (line []byte, err error) {
	i := IndexByte(b.buf[b.off:], delim)
	end := b.off + i + 1
	if i < 0 {
		end = len(b.buf)
		err = io.EOF
	}
	line = b.buf[b.off:end]
	b.off = end
	b.lastRead = opRead
	return line, err
}

// ReadString reads until the first occurrence of delim in the input,
// returning a string containing the data up to and including the delimiter.
// If ReadString encounters an error before finding a delimiter,
// it returns the data read before the error and the error itself (often [io.EOF]).
// ReadString returns err != nil if and only if the returned data does not end
// in delim.
func (b *Buffer) ReadString(delim byte) (line string, err error) {
	slice, err := b.readSlice(delim)
	return string(slice), err
}

// NewBuffer creates and initializes a new [Buffer] using buf as its
// initial contents. The new [Buffer] takes ownership of buf, and the
// caller should not use buf after this call. NewBuffer is intended to
// prepare a [Buffer] to read existing data. It can also be used to set
// the initial size of the internal buffer for writing. To do that,
// buf should have the desired capacity but a length of zero.
//
// In most cases, new([Buffer]) (or just declaring a [Buffer] variable) is
// sufficient to initialize a [Buffer].
func NewBuffer(buf []byte) *Buffer { return &Buffer{buf: buf} }

// NewBufferString creates and initializes a new [Buffer] using string s as its
// initial contents. It is intended to prepare a buffer to read an existing
// string.
//
// In most cases, new([Buffer]) (or just declaring a [Buffer] variable) is
// sufficient to initialize a [Buffer].
func NewBufferString(s string) *Buffer {
	return &Buffer{buf: []byte(s)}
}
```