Response:
Let's break down the thought process for analyzing the provided `io.go` code.

1. **Understand the Request:** The core request is to explain the functionality of the given Go code snippet, which is a part of the `io` package. The request also asks for examples, code reasoning, handling of command-line arguments (though this is less relevant for this particular file), and common mistakes. Crucially, the answer should be in Chinese.

2. **Identify the Core Purpose:** The comment at the beginning of the file clearly states the purpose of the `io` package: providing basic interfaces for I/O primitives. It acts as an abstraction layer over lower-level I/O implementations. This is the central theme.

3. **Categorize the Content:**  The code primarily defines interfaces and some associated constants and errors. This immediately suggests a structured approach to the analysis:

    * **Constants:** Identify and explain the purpose of constants like `SeekStart`, `SeekCurrent`, `SeekEnd`.
    * **Errors:**  List and describe the meaning of the various `Err...` and `EOF` variables. Emphasize their role in signaling specific I/O conditions.
    * **Interfaces:** This is the bulk of the code. Go through each interface (`Reader`, `Writer`, `Closer`, `Seeker`, and the combined interfaces like `ReadWriter`, `ReadCloser`, etc.) and explain what methods they define and their intended behavior. Pay attention to the comments within the interface definitions, as they provide crucial details about the expected semantics of the methods.
    * **Concrete Types/Functions:**  Note the definitions of concrete types like `LimitedReader`, `SectionReader`, `OffsetWriter`, and `teeReader`, and functions like `LimitReader`, `NewSectionReader`, `NewOffsetWriter`, `TeeReader`, `WriteString`, `ReadAtLeast`, `ReadFull`, `CopyN`, `Copy`, `CopyBuffer`, `NopCloser`, and `ReadAll`. Explain their specific functions and how they utilize the defined interfaces. Pay special attention to the `Copy` and `CopyBuffer` functions as they have different implementations based on whether the source or destination implements `WriterTo` or `ReaderFrom`.

4. **Explain Each Interface and its Functionality:**  For each interface:

    * **Name:** State the interface name.
    * **Purpose:**  Describe the core responsibility of the interface.
    * **Methods:** List the methods defined by the interface and explain what each method does, its parameters, and return values. Refer to the comments in the code for accurate descriptions. Highlight key aspects of the method's behavior (e.g., `Read` might return fewer bytes than requested, `Write` must return a non-nil error if fewer bytes are written).

5. **Explain the Concrete Types and Functions:** For each concrete type and function:

    * **Name:** State the name.
    * **Purpose:** Describe its specific task.
    * **How it uses interfaces:** Explain which interfaces it implements or interacts with.
    * **Example (where applicable):**  Provide simple Go code examples to illustrate how to use these types and functions. Include example inputs and expected outputs to clarify the behavior. For instance, demonstrating `LimitReader` with a string reader and showing how it limits the number of bytes read.

6. **Address Specific Instructions:**

    * **Go Language Feature:** The primary Go language feature demonstrated here is **interfaces**. The `io` package heavily relies on interfaces to provide abstraction and polymorphism. Explain this concept clearly.
    * **Code Reasoning with Examples:** Provide examples as mentioned above, focusing on demonstrating the behavior of key interfaces and functions. The `LimitReader` and `SectionReader` examples are good choices due to their clear and specific functionality.
    * **Command-Line Arguments:** Acknowledge that this specific file doesn't directly handle command-line arguments. This shows attention to detail.
    * **Common Mistakes:** Think about common pitfalls when working with I/O in Go. For example, neglecting to check the error return from `Read` and `Write`, or misunderstanding the behavior of `EOF`. Provide concrete examples of these mistakes.

7. **Structure and Language:** Organize the answer logically. Use clear and concise Chinese. Employ headings and bullet points to enhance readability. Ensure the terminology is accurate and consistent.

8. **Review and Refine:** After drafting the initial response, review it carefully. Check for clarity, accuracy, and completeness. Make sure all parts of the original request have been addressed. For instance, double-check the descriptions of the error variables and the nuances of the `Read` and `Write` methods. Ensure the examples are correct and easy to understand. Ensure that the Chinese is natural and grammatically sound.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus only on the interfaces.
* **Correction:** Realize that concrete types and functions like `LimitReader` and `Copy` are equally important for understanding the package's functionality.
* **Initial thought:** Provide very complex examples.
* **Correction:** Simplify the examples to clearly illustrate the core concepts without unnecessary complexity. Focus on minimal, working examples.
* **Initial thought:**  Just list the errors.
* **Correction:** Explain *why* these errors are important and what situations cause them. Emphasize the special nature of `EOF`.
* **Initial thought:** Forget to mention the overall purpose stated in the package comment.
* **Correction:** Start by clearly stating the package's role as an abstraction layer.

By following this structured thinking and incorporating self-correction, a comprehensive and accurate explanation of the `io.go` code can be produced.
这段代码是 Go 语言标准库 `io` 包的一部分，它定义了进行基本 I/O 操作所需的接口和一些相关的常量与错误。

**功能列举:**

1. **定义了 I/O 相关的基本接口:**
   - `Reader`: 定义了 `Read` 方法，用于从输入源读取数据。
   - `Writer`: 定义了 `Write` 方法，用于向输出目的地写入数据。
   - `Closer`: 定义了 `Close` 方法，用于关闭 I/O 流。
   - `Seeker`: 定义了 `Seek` 方法，用于设置读写位置。
   - 以及组合接口，如 `ReadWriter`, `ReadCloser`, `WriteCloser`, `ReadWriteCloser`, `ReadSeeker`, `ReadSeekCloser`, `WriteSeeker`, `ReadWriteSeeker`，它们组合了上述基本接口。
   - `ReaderFrom`: 定义了 `ReadFrom` 方法，允许从一个 `Reader` 读取数据。
   - `WriterTo`: 定义了 `WriteTo` 方法，允许将数据写入一个 `Writer`。
   - `ReaderAt`: 定义了 `ReadAt` 方法，允许在指定偏移量读取数据。
   - `WriterAt`: 定义了 `WriteAt` 方法，允许在指定偏移量写入数据。
   - `ByteReader`: 定义了 `ReadByte` 方法，用于读取单个字节。
   - `ByteScanner`: 继承自 `ByteReader`，并添加了 `UnreadByte` 方法，用于撤销最近一次的 `ReadByte` 操作。
   - `ByteWriter`: 定义了 `WriteByte` 方法，用于写入单个字节。
   - `RuneReader`: 定义了 `ReadRune` 方法，用于读取一个 Unicode 字符。
   - `RuneScanner`: 继承自 `RuneReader`，并添加了 `UnreadRune` 方法，用于撤销最近一次的 `ReadRune` 操作。
   - `StringWriter`: 定义了 `WriteString` 方法，用于写入字符串。

2. **定义了 I/O 操作相关的常量:**
   - `SeekStart`: 用于 `Seek` 方法，表示相对于文件起始位置进行偏移。
   - `SeekCurrent`: 用于 `Seek` 方法，表示相对于当前读写位置进行偏移。
   - `SeekEnd`: 用于 `Seek` 方法，表示相对于文件末尾位置进行偏移。

3. **定义了常见的 I/O 错误:**
   - `ErrShortWrite`: 表示 `Write` 方法接受的字节数少于请求的字节数，但没有返回明确的错误。
   - `errInvalidWrite`: 表示 `Write` 方法返回了一个不可能的写入计数。
   - `ErrShortBuffer`: 表示 `Read` 方法需要的缓冲区比提供的缓冲区更长。
   - `EOF`: 表示读取到文件末尾。
   - `ErrUnexpectedEOF`: 表示在读取固定大小的数据块时遇到了文件末尾。
   - `ErrNoProgress`: 表示多次调用 `Read` 方法都没有返回任何数据或错误，通常表示 `Reader` 的实现有问题。
   - `errWhence`:  用于 `Seek` 方法，表示无效的 `whence` 参数。
   - `errOffset`: 用于 `Seek` 方法，表示无效的偏移量。

4. **提供了一些实用的 I/O 操作函数:**
   - `WriteString`: 将字符串写入 `Writer`。
   - `ReadAtLeast`: 从 `Reader` 中至少读取指定数量的字节到缓冲区。
   - `ReadFull`: 从 `Reader` 中读取指定长度的字节到缓冲区。
   - `CopyN`: 从 `Reader` 复制指定数量的字节到 `Writer`。
   - `Copy`: 从 `Reader` 复制数据到 `Writer` 直到遇到 EOF 或错误。
   - `CopyBuffer`: 与 `Copy` 类似，但使用提供的缓冲区。
   - `LimitReader`: 返回一个 `Reader`，它从另一个 `Reader` 读取数据，但在读取指定数量的字节后返回 EOF。
   - `NewSectionReader`: 返回一个 `SectionReader`，它可以从 `ReaderAt` 的指定偏移量和长度读取数据。
   - `NewOffsetWriter`: 返回一个 `OffsetWriter`，它会将写入操作映射到 `WriterAt` 的指定偏移量。
   - `TeeReader`: 返回一个 `Reader`，它在从另一个 `Reader` 读取数据的同时，将读取到的数据写入一个 `Writer`。
   - `Discard`: 一个实现了 `Writer` 接口的变量，所有写入操作都会成功，但不做任何实际操作（相当于 `/dev/null` 或 `NUL`）。
   - `NopCloser`: 返回一个 `ReadCloser`，其 `Close` 方法是一个空操作。
   - `ReadAll`: 从 `Reader` 读取所有数据直到遇到错误或 EOF。

**它是什么 Go 语言功能的实现:**

这段代码主要实现了 Go 语言的 **接口 (interface)** 功能，用于定义 I/O 操作的抽象。通过定义接口，`io` 包可以与各种不同的底层 I/O 实现进行交互，而无需知道它们的具体实现细节。这体现了面向对象编程中的 **多态性**。

**Go 代码举例说明:**

假设我们有一个实现了 `io.Reader` 接口的自定义类型 `MyReader`:

```go
package main

import (
	"fmt"
	"io"
	"strings"
)

// MyReader 是一个简单的实现了 io.Reader 的类型
type MyReader struct {
	data string
	pos  int
}

func NewMyReader(data string) *MyReader {
	return &MyReader{data: data}
}

func (r *MyReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func main() {
	reader := NewMyReader("Hello, Go!")
	buffer := make([]byte, 5)

	for {
		n, err := reader.Read(buffer)
		fmt.Printf("Read %d bytes: %q, error: %v\n", n, buffer[:n], err)
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
	}
}

// 假设的输出:
// Read 5 bytes: "Hello", error: <nil>
// Read 3 bytes: ", Go", error: <nil>
// Read 1 bytes: "!", error: <nil>
// Read 0 bytes: "", error: EOF
```

在这个例子中，`MyReader` 实现了 `io.Reader` 接口的 `Read` 方法。`main` 函数中使用 `MyReader` 的实例，并调用其 `Read` 方法来读取数据。`io` 包定义的 `Reader` 接口允许我们以统一的方式处理不同的输入源。

**代码推理 (结合假设输入与输出):**

假设我们使用 `io.LimitReader` 来限制一个字符串读取器读取的字节数：

```go
package main

import (
	"fmt"
	"io"
	"strings"
)

func main() {
	reader := strings.NewReader("This is a long string.")
	limitedReader := io.LimitReader(reader, 10) // 限制读取 10 个字节

	buffer := make([]byte, 20)
	n, err := limitedReader.Read(buffer)

	fmt.Printf("Read %d bytes: %q, error: %v\n", n, buffer[:n], err)

	n, err = limitedReader.Read(buffer) // 再次读取

	fmt.Printf("Read %d bytes: %q, error: %v\n", n, buffer[:n], err)
}

// 假设的输出:
// Read 10 bytes: "This is a ", error: <nil>
// Read 0 bytes: "", error: EOF
```

**推理:**

1. 我们创建了一个从字符串读取数据的 `strings.Reader`。
2. 我们使用 `io.LimitReader` 将其包装起来，限制最多读取 10 个字节。
3. 第一次调用 `limitedReader.Read`，它成功读取了 "This is a " (10个字节)。
4. 第二次调用 `limitedReader.Read`，由于已经读取了限制的字节数，它返回了 `io.EOF`，表示没有更多数据可读。

**命令行参数的具体处理:**

`io` 包本身主要关注 I/O 的抽象和基本操作，它并不直接处理命令行参数。命令行参数的处理通常由 `os` 包和 `flag` 包来完成。`io` 包提供的接口和函数可以与从命令行参数指定的文件或其他输入源创建的 `os.File` 等类型一起使用。

**使用者易犯错的点:**

1. **忽略 `Read` 和 `Write` 方法的返回值:**  `Read` 和 `Write` 方法会返回实际读取或写入的字节数以及可能发生的错误。使用者容易犯的错误是只检查错误，而不处理已经读取或写入的字节。这可能导致数据丢失或处理不完整。

   ```go
   // 错误示例: 没有处理 n 的情况
   n, err := reader.Read(buf)
   if err != nil {
       // ... 处理错误
   }
   // 假设 buf 中只有部分数据被读取，后续操作可能会出错

   // 正确示例:
   n, err := reader.Read(buf)
   if err != nil && err != io.EOF {
       // ... 处理错误
   }
   // 使用 buf[:n] 中读取到的数据
   processData(buf[:n])
   ```

2. **不正确地处理 `io.EOF`:** `io.EOF` 并非一个真正的错误，它表示已经到达输入流的末尾。使用者应该将其作为正常情况处理，而不是当作错误来对待。

   ```go
   // 错误示例: 将 io.EOF 当作错误处理
   n, err := reader.Read(buf)
   if err != nil {
       fmt.Println("读取出错:", err) // 可能会错误地报告 EOF
   }

   // 正确示例:
   n, err := reader.Read(buf)
   if err == io.EOF {
       fmt.Println("读取完成")
   } else if err != nil {
       fmt.Println("发生其他读取错误:", err)
   }
   ```

3. **在循环读取时没有正确判断 `Read` 返回 0 和 `nil`:**  `Read` 方法返回 `n == 0` 和 `err == nil` 通常表示没有任何数据被读取，但这并不意味着到达了 EOF。这可能发生在非阻塞的 I/O 操作中。

   ```go
   // 容易混淆的情况
   n, err := reader.Read(buf)
   if err == io.EOF {
       // ... 认为读取结束
   } else if n > 0 {
       // ... 处理读取到的数据
   }
   // 可能会忽略 n == 0 且 err == nil 的情况

   // 更健壮的处理方式
   for {
       n, err := reader.Read(buf)
       if err == io.EOF {
           break
       }
       if err != nil {
           // ... 处理其他错误
           break
       }
       if n > 0 {
           // ... 处理读取到的数据
       }
       // 可以添加一些逻辑来处理 n == 0 且 err == nil 的情况，
       // 例如，在非阻塞 I/O 中进行重试或等待
   }
   ```

这段 `io.go` 代码是 Go 语言 I/O 操作的基础，理解其定义的功能和接口对于进行任何形式的输入输出操作都至关重要。

### 提示词
```
这是路径为go/src/io/io.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package io provides basic interfaces to I/O primitives.
// Its primary job is to wrap existing implementations of such primitives,
// such as those in package os, into shared public interfaces that
// abstract the functionality, plus some other related primitives.
//
// Because these interfaces and primitives wrap lower-level operations with
// various implementations, unless otherwise informed clients should not
// assume they are safe for parallel execution.
package io

import (
	"errors"
	"sync"
)

// Seek whence values.
const (
	SeekStart   = 0 // seek relative to the origin of the file
	SeekCurrent = 1 // seek relative to the current offset
	SeekEnd     = 2 // seek relative to the end
)

// ErrShortWrite means that a write accepted fewer bytes than requested
// but failed to return an explicit error.
var ErrShortWrite = errors.New("short write")

// errInvalidWrite means that a write returned an impossible count.
var errInvalidWrite = errors.New("invalid write result")

// ErrShortBuffer means that a read required a longer buffer than was provided.
var ErrShortBuffer = errors.New("short buffer")

// EOF is the error returned by Read when no more input is available.
// (Read must return EOF itself, not an error wrapping EOF,
// because callers will test for EOF using ==.)
// Functions should return EOF only to signal a graceful end of input.
// If the EOF occurs unexpectedly in a structured data stream,
// the appropriate error is either [ErrUnexpectedEOF] or some other error
// giving more detail.
var EOF = errors.New("EOF")

// ErrUnexpectedEOF means that EOF was encountered in the
// middle of reading a fixed-size block or data structure.
var ErrUnexpectedEOF = errors.New("unexpected EOF")

// ErrNoProgress is returned by some clients of a [Reader] when
// many calls to Read have failed to return any data or error,
// usually the sign of a broken [Reader] implementation.
var ErrNoProgress = errors.New("multiple Read calls return no data or error")

// Reader is the interface that wraps the basic Read method.
//
// Read reads up to len(p) bytes into p. It returns the number of bytes
// read (0 <= n <= len(p)) and any error encountered. Even if Read
// returns n < len(p), it may use all of p as scratch space during the call.
// If some data is available but not len(p) bytes, Read conventionally
// returns what is available instead of waiting for more.
//
// When Read encounters an error or end-of-file condition after
// successfully reading n > 0 bytes, it returns the number of
// bytes read. It may return the (non-nil) error from the same call
// or return the error (and n == 0) from a subsequent call.
// An instance of this general case is that a Reader returning
// a non-zero number of bytes at the end of the input stream may
// return either err == EOF or err == nil. The next Read should
// return 0, EOF.
//
// Callers should always process the n > 0 bytes returned before
// considering the error err. Doing so correctly handles I/O errors
// that happen after reading some bytes and also both of the
// allowed EOF behaviors.
//
// If len(p) == 0, Read should always return n == 0. It may return a
// non-nil error if some error condition is known, such as EOF.
//
// Implementations of Read are discouraged from returning a
// zero byte count with a nil error, except when len(p) == 0.
// Callers should treat a return of 0 and nil as indicating that
// nothing happened; in particular it does not indicate EOF.
//
// Implementations must not retain p.
type Reader interface {
	Read(p []byte) (n int, err error)
}

// Writer is the interface that wraps the basic Write method.
//
// Write writes len(p) bytes from p to the underlying data stream.
// It returns the number of bytes written from p (0 <= n <= len(p))
// and any error encountered that caused the write to stop early.
// Write must return a non-nil error if it returns n < len(p).
// Write must not modify the slice data, even temporarily.
//
// Implementations must not retain p.
type Writer interface {
	Write(p []byte) (n int, err error)
}

// Closer is the interface that wraps the basic Close method.
//
// The behavior of Close after the first call is undefined.
// Specific implementations may document their own behavior.
type Closer interface {
	Close() error
}

// Seeker is the interface that wraps the basic Seek method.
//
// Seek sets the offset for the next Read or Write to offset,
// interpreted according to whence:
// [SeekStart] means relative to the start of the file,
// [SeekCurrent] means relative to the current offset, and
// [SeekEnd] means relative to the end
// (for example, offset = -2 specifies the penultimate byte of the file).
// Seek returns the new offset relative to the start of the
// file or an error, if any.
//
// Seeking to an offset before the start of the file is an error.
// Seeking to any positive offset may be allowed, but if the new offset exceeds
// the size of the underlying object the behavior of subsequent I/O operations
// is implementation-dependent.
type Seeker interface {
	Seek(offset int64, whence int) (int64, error)
}

// ReadWriter is the interface that groups the basic Read and Write methods.
type ReadWriter interface {
	Reader
	Writer
}

// ReadCloser is the interface that groups the basic Read and Close methods.
type ReadCloser interface {
	Reader
	Closer
}

// WriteCloser is the interface that groups the basic Write and Close methods.
type WriteCloser interface {
	Writer
	Closer
}

// ReadWriteCloser is the interface that groups the basic Read, Write and Close methods.
type ReadWriteCloser interface {
	Reader
	Writer
	Closer
}

// ReadSeeker is the interface that groups the basic Read and Seek methods.
type ReadSeeker interface {
	Reader
	Seeker
}

// ReadSeekCloser is the interface that groups the basic Read, Seek and Close
// methods.
type ReadSeekCloser interface {
	Reader
	Seeker
	Closer
}

// WriteSeeker is the interface that groups the basic Write and Seek methods.
type WriteSeeker interface {
	Writer
	Seeker
}

// ReadWriteSeeker is the interface that groups the basic Read, Write and Seek methods.
type ReadWriteSeeker interface {
	Reader
	Writer
	Seeker
}

// ReaderFrom is the interface that wraps the ReadFrom method.
//
// ReadFrom reads data from r until EOF or error.
// The return value n is the number of bytes read.
// Any error except EOF encountered during the read is also returned.
//
// The [Copy] function uses [ReaderFrom] if available.
type ReaderFrom interface {
	ReadFrom(r Reader) (n int64, err error)
}

// WriterTo is the interface that wraps the WriteTo method.
//
// WriteTo writes data to w until there's no more data to write or
// when an error occurs. The return value n is the number of bytes
// written. Any error encountered during the write is also returned.
//
// The Copy function uses WriterTo if available.
type WriterTo interface {
	WriteTo(w Writer) (n int64, err error)
}

// ReaderAt is the interface that wraps the basic ReadAt method.
//
// ReadAt reads len(p) bytes into p starting at offset off in the
// underlying input source. It returns the number of bytes
// read (0 <= n <= len(p)) and any error encountered.
//
// When ReadAt returns n < len(p), it returns a non-nil error
// explaining why more bytes were not returned. In this respect,
// ReadAt is stricter than Read.
//
// Even if ReadAt returns n < len(p), it may use all of p as scratch
// space during the call. If some data is available but not len(p) bytes,
// ReadAt blocks until either all the data is available or an error occurs.
// In this respect ReadAt is different from Read.
//
// If the n = len(p) bytes returned by ReadAt are at the end of the
// input source, ReadAt may return either err == EOF or err == nil.
//
// If ReadAt is reading from an input source with a seek offset,
// ReadAt should not affect nor be affected by the underlying
// seek offset.
//
// Clients of ReadAt can execute parallel ReadAt calls on the
// same input source.
//
// Implementations must not retain p.
type ReaderAt interface {
	ReadAt(p []byte, off int64) (n int, err error)
}

// WriterAt is the interface that wraps the basic WriteAt method.
//
// WriteAt writes len(p) bytes from p to the underlying data stream
// at offset off. It returns the number of bytes written from p (0 <= n <= len(p))
// and any error encountered that caused the write to stop early.
// WriteAt must return a non-nil error if it returns n < len(p).
//
// If WriteAt is writing to a destination with a seek offset,
// WriteAt should not affect nor be affected by the underlying
// seek offset.
//
// Clients of WriteAt can execute parallel WriteAt calls on the same
// destination if the ranges do not overlap.
//
// Implementations must not retain p.
type WriterAt interface {
	WriteAt(p []byte, off int64) (n int, err error)
}

// ByteReader is the interface that wraps the ReadByte method.
//
// ReadByte reads and returns the next byte from the input or
// any error encountered. If ReadByte returns an error, no input
// byte was consumed, and the returned byte value is undefined.
//
// ReadByte provides an efficient interface for byte-at-time
// processing. A [Reader] that does not implement  ByteReader
// can be wrapped using bufio.NewReader to add this method.
type ByteReader interface {
	ReadByte() (byte, error)
}

// ByteScanner is the interface that adds the UnreadByte method to the
// basic ReadByte method.
//
// UnreadByte causes the next call to ReadByte to return the last byte read.
// If the last operation was not a successful call to ReadByte, UnreadByte may
// return an error, unread the last byte read (or the byte prior to the
// last-unread byte), or (in implementations that support the [Seeker] interface)
// seek to one byte before the current offset.
type ByteScanner interface {
	ByteReader
	UnreadByte() error
}

// ByteWriter is the interface that wraps the WriteByte method.
type ByteWriter interface {
	WriteByte(c byte) error
}

// RuneReader is the interface that wraps the ReadRune method.
//
// ReadRune reads a single encoded Unicode character
// and returns the rune and its size in bytes. If no character is
// available, err will be set.
type RuneReader interface {
	ReadRune() (r rune, size int, err error)
}

// RuneScanner is the interface that adds the UnreadRune method to the
// basic ReadRune method.
//
// UnreadRune causes the next call to ReadRune to return the last rune read.
// If the last operation was not a successful call to ReadRune, UnreadRune may
// return an error, unread the last rune read (or the rune prior to the
// last-unread rune), or (in implementations that support the [Seeker] interface)
// seek to the start of the rune before the current offset.
type RuneScanner interface {
	RuneReader
	UnreadRune() error
}

// StringWriter is the interface that wraps the WriteString method.
type StringWriter interface {
	WriteString(s string) (n int, err error)
}

// WriteString writes the contents of the string s to w, which accepts a slice of bytes.
// If w implements [StringWriter], [StringWriter.WriteString] is invoked directly.
// Otherwise, [Writer.Write] is called exactly once.
func WriteString(w Writer, s string) (n int, err error) {
	if sw, ok := w.(StringWriter); ok {
		return sw.WriteString(s)
	}
	return w.Write([]byte(s))
}

// ReadAtLeast reads from r into buf until it has read at least min bytes.
// It returns the number of bytes copied and an error if fewer bytes were read.
// The error is EOF only if no bytes were read.
// If an EOF happens after reading fewer than min bytes,
// ReadAtLeast returns [ErrUnexpectedEOF].
// If min is greater than the length of buf, ReadAtLeast returns [ErrShortBuffer].
// On return, n >= min if and only if err == nil.
// If r returns an error having read at least min bytes, the error is dropped.
func ReadAtLeast(r Reader, buf []byte, min int) (n int, err error) {
	if len(buf) < min {
		return 0, ErrShortBuffer
	}
	for n < min && err == nil {
		var nn int
		nn, err = r.Read(buf[n:])
		n += nn
	}
	if n >= min {
		err = nil
	} else if n > 0 && err == EOF {
		err = ErrUnexpectedEOF
	}
	return
}

// ReadFull reads exactly len(buf) bytes from r into buf.
// It returns the number of bytes copied and an error if fewer bytes were read.
// The error is EOF only if no bytes were read.
// If an EOF happens after reading some but not all the bytes,
// ReadFull returns [ErrUnexpectedEOF].
// On return, n == len(buf) if and only if err == nil.
// If r returns an error having read at least len(buf) bytes, the error is dropped.
func ReadFull(r Reader, buf []byte) (n int, err error) {
	return ReadAtLeast(r, buf, len(buf))
}

// CopyN copies n bytes (or until an error) from src to dst.
// It returns the number of bytes copied and the earliest
// error encountered while copying.
// On return, written == n if and only if err == nil.
//
// If dst implements [ReaderFrom], the copy is implemented using it.
func CopyN(dst Writer, src Reader, n int64) (written int64, err error) {
	written, err = Copy(dst, LimitReader(src, n))
	if written == n {
		return n, nil
	}
	if written < n && err == nil {
		// src stopped early; must have been EOF.
		err = EOF
	}
	return
}

// Copy copies from src to dst until either EOF is reached
// on src or an error occurs. It returns the number of bytes
// copied and the first error encountered while copying, if any.
//
// A successful Copy returns err == nil, not err == EOF.
// Because Copy is defined to read from src until EOF, it does
// not treat an EOF from Read as an error to be reported.
//
// If src implements [WriterTo],
// the copy is implemented by calling src.WriteTo(dst).
// Otherwise, if dst implements [ReaderFrom],
// the copy is implemented by calling dst.ReadFrom(src).
func Copy(dst Writer, src Reader) (written int64, err error) {
	return copyBuffer(dst, src, nil)
}

// CopyBuffer is identical to Copy except that it stages through the
// provided buffer (if one is required) rather than allocating a
// temporary one. If buf is nil, one is allocated; otherwise if it has
// zero length, CopyBuffer panics.
//
// If either src implements [WriterTo] or dst implements [ReaderFrom],
// buf will not be used to perform the copy.
func CopyBuffer(dst Writer, src Reader, buf []byte) (written int64, err error) {
	if buf != nil && len(buf) == 0 {
		panic("empty buffer in CopyBuffer")
	}
	return copyBuffer(dst, src, buf)
}

// copyBuffer is the actual implementation of Copy and CopyBuffer.
// if buf is nil, one is allocated.
func copyBuffer(dst Writer, src Reader, buf []byte) (written int64, err error) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	if wt, ok := src.(WriterTo); ok {
		return wt.WriteTo(dst)
	}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	if rf, ok := dst.(ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = make([]byte, size)
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errInvalidWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// LimitReader returns a Reader that reads from r
// but stops with EOF after n bytes.
// The underlying implementation is a *LimitedReader.
func LimitReader(r Reader, n int64) Reader { return &LimitedReader{r, n} }

// A LimitedReader reads from R but limits the amount of
// data returned to just N bytes. Each call to Read
// updates N to reflect the new amount remaining.
// Read returns EOF when N <= 0 or when the underlying R returns EOF.
type LimitedReader struct {
	R Reader // underlying reader
	N int64  // max bytes remaining
}

func (l *LimitedReader) Read(p []byte) (n int, err error) {
	if l.N <= 0 {
		return 0, EOF
	}
	if int64(len(p)) > l.N {
		p = p[0:l.N]
	}
	n, err = l.R.Read(p)
	l.N -= int64(n)
	return
}

// NewSectionReader returns a [SectionReader] that reads from r
// starting at offset off and stops with EOF after n bytes.
func NewSectionReader(r ReaderAt, off int64, n int64) *SectionReader {
	var remaining int64
	const maxint64 = 1<<63 - 1
	if off <= maxint64-n {
		remaining = n + off
	} else {
		// Overflow, with no way to return error.
		// Assume we can read up to an offset of 1<<63 - 1.
		remaining = maxint64
	}
	return &SectionReader{r, off, off, remaining, n}
}

// SectionReader implements Read, Seek, and ReadAt on a section
// of an underlying [ReaderAt].
type SectionReader struct {
	r     ReaderAt // constant after creation
	base  int64    // constant after creation
	off   int64
	limit int64 // constant after creation
	n     int64 // constant after creation
}

func (s *SectionReader) Read(p []byte) (n int, err error) {
	if s.off >= s.limit {
		return 0, EOF
	}
	if max := s.limit - s.off; int64(len(p)) > max {
		p = p[0:max]
	}
	n, err = s.r.ReadAt(p, s.off)
	s.off += int64(n)
	return
}

var errWhence = errors.New("Seek: invalid whence")
var errOffset = errors.New("Seek: invalid offset")

func (s *SectionReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	default:
		return 0, errWhence
	case SeekStart:
		offset += s.base
	case SeekCurrent:
		offset += s.off
	case SeekEnd:
		offset += s.limit
	}
	if offset < s.base {
		return 0, errOffset
	}
	s.off = offset
	return offset - s.base, nil
}

func (s *SectionReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= s.Size() {
		return 0, EOF
	}
	off += s.base
	if max := s.limit - off; int64(len(p)) > max {
		p = p[0:max]
		n, err = s.r.ReadAt(p, off)
		if err == nil {
			err = EOF
		}
		return n, err
	}
	return s.r.ReadAt(p, off)
}

// Size returns the size of the section in bytes.
func (s *SectionReader) Size() int64 { return s.limit - s.base }

// Outer returns the underlying [ReaderAt] and offsets for the section.
//
// The returned values are the same that were passed to [NewSectionReader]
// when the [SectionReader] was created.
func (s *SectionReader) Outer() (r ReaderAt, off int64, n int64) {
	return s.r, s.base, s.n
}

// An OffsetWriter maps writes at offset base to offset base+off in the underlying writer.
type OffsetWriter struct {
	w    WriterAt
	base int64 // the original offset
	off  int64 // the current offset
}

// NewOffsetWriter returns an [OffsetWriter] that writes to w
// starting at offset off.
func NewOffsetWriter(w WriterAt, off int64) *OffsetWriter {
	return &OffsetWriter{w, off, off}
}

func (o *OffsetWriter) Write(p []byte) (n int, err error) {
	n, err = o.w.WriteAt(p, o.off)
	o.off += int64(n)
	return
}

func (o *OffsetWriter) WriteAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, errOffset
	}

	off += o.base
	return o.w.WriteAt(p, off)
}

func (o *OffsetWriter) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	default:
		return 0, errWhence
	case SeekStart:
		offset += o.base
	case SeekCurrent:
		offset += o.off
	}
	if offset < o.base {
		return 0, errOffset
	}
	o.off = offset
	return offset - o.base, nil
}

// TeeReader returns a [Reader] that writes to w what it reads from r.
// All reads from r performed through it are matched with
// corresponding writes to w. There is no internal buffering -
// the write must complete before the read completes.
// Any error encountered while writing is reported as a read error.
func TeeReader(r Reader, w Writer) Reader {
	return &teeReader{r, w}
}

type teeReader struct {
	r Reader
	w Writer
}

func (t *teeReader) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 {
		if n, err := t.w.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return
}

// Discard is a [Writer] on which all Write calls succeed
// without doing anything.
var Discard Writer = discard{}

type discard struct{}

// discard implements ReaderFrom as an optimization so Copy to
// io.Discard can avoid doing unnecessary work.
var _ ReaderFrom = discard{}

func (discard) Write(p []byte) (int, error) {
	return len(p), nil
}

func (discard) WriteString(s string) (int, error) {
	return len(s), nil
}

var blackHolePool = sync.Pool{
	New: func() any {
		b := make([]byte, 8192)
		return &b
	},
}

func (discard) ReadFrom(r Reader) (n int64, err error) {
	bufp := blackHolePool.Get().(*[]byte)
	readSize := 0
	for {
		readSize, err = r.Read(*bufp)
		n += int64(readSize)
		if err != nil {
			blackHolePool.Put(bufp)
			if err == EOF {
				return n, nil
			}
			return
		}
	}
}

// NopCloser returns a [ReadCloser] with a no-op Close method wrapping
// the provided [Reader] r.
// If r implements [WriterTo], the returned [ReadCloser] will implement [WriterTo]
// by forwarding calls to r.
func NopCloser(r Reader) ReadCloser {
	if _, ok := r.(WriterTo); ok {
		return nopCloserWriterTo{r}
	}
	return nopCloser{r}
}

type nopCloser struct {
	Reader
}

func (nopCloser) Close() error { return nil }

type nopCloserWriterTo struct {
	Reader
}

func (nopCloserWriterTo) Close() error { return nil }

func (c nopCloserWriterTo) WriteTo(w Writer) (n int64, err error) {
	return c.Reader.(WriterTo).WriteTo(w)
}

// ReadAll reads from r until an error or EOF and returns the data it read.
// A successful call returns err == nil, not err == EOF. Because ReadAll is
// defined to read from src until EOF, it does not treat an EOF from Read
// as an error to be reported.
func ReadAll(r Reader) ([]byte, error) {
	b := make([]byte, 0, 512)
	for {
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == EOF {
				err = nil
			}
			return b, err
		}

		if len(b) == cap(b) {
			// Add more capacity (let append pick how much).
			b = append(b, 0)[:len(b)]
		}
	}
}
```