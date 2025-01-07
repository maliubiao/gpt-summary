Response:
Let's break down the thought process to answer the request about the `encoding/binary` package in Go, based on the provided source code.

**1. Understanding the Goal:**

The primary goal is to analyze the provided Go source code (`go/src/encoding/binary/binary.go`) and explain its functionality, provide usage examples, and identify potential pitfalls for users.

**2. Initial Reading and High-Level Understanding:**

First, I skim through the code and the package comment. Key takeaways from the comment:

*   It deals with translating between numbers and byte sequences.
*   It handles fixed-size values (basic types, arrays, structs of basic types).
*   It includes variable-length encoding for integers (varints - though this code snippet doesn't include the varint functions).
*   It prioritizes simplicity over performance and suggests `encoding/gob` or `google.golang.org/protobuf` for high-performance needs.

**3. Identifying Core Functionalities (By Examining Top-Level Functions and Types):**

I start by looking at the exported identifiers (those starting with uppercase letters). This gives a good overview of the package's capabilities:

*   `ByteOrder` interface: This immediately suggests the concept of byte order (endianness).
*   `LittleEndian`, `BigEndian`, `NativeEndian`: Concrete implementations of `ByteOrder`, confirming the endianness handling.
*   `Read`, `Write`, `Decode`, `Encode`, `Append`, `Size`: These are the main functions for reading/writing binary data. The paired `Read`/`Write` likely work with `io.Reader`/`io.Writer`, while `Decode`/`Encode` operate on byte slices. `Append` seems to be a variant of `Encode` that appends to an existing slice. `Size` determines the binary size of a value.

**4. Dissecting `ByteOrder` and Endianness:**

The `ByteOrder` interface and its implementations are straightforward. I see methods for converting between byte slices and 16, 32, and 64-bit unsigned integers, and corresponding `Put` methods for the reverse operation. This confirms the package's core function of handling different byte orderings.

**5. Analyzing `Read`, `Write`, `Decode`, `Encode`, and `Append`:**

*   **Commonalities:** These functions all take a `ByteOrder` argument, indicating that endianness is always considered. They also operate on `data` of type `any`, suggesting they can handle various data types.
*   **`Read` and `Write`:** These take an `io.Reader` or `io.Writer`, respectively, implying they are used for streaming or file-based binary I/O. The comment for `Read` mentions handling booleans and skipping blank fields in structs. The error handling (`io.EOF`, `io.ErrUnexpectedEOF`) is also important.
*   **`Decode` and `Encode`:** These take and return byte slices, indicating they are for in-memory binary conversions. They return the number of bytes processed and an error if the buffer is too small.
*   **`Append`:** This function appends the binary representation to an existing byte slice.

**6. Looking for "Fast Paths" and Reflection:**

The code includes comments about "fast paths" for basic types and slices within `Read`, `Write`, `Decode`, and `Encode`. This suggests that the package optimizes for common cases. The code also mentions falling back to "reflect-based decoding/encoding," which indicates that the package can handle more complex data structures (like structs) using Go's reflection capabilities.

**7. Understanding `Size` and `dataSize`:**

`Size` provides a way to determine the size of the binary representation of data *before* actually encoding it. `dataSize` is an internal helper function that calculates the size, especially for structs and slices, potentially using reflection.

**8. Identifying Potential User Errors (Based on Code and Comments):**

*   The comments in `Read` warn about requiring non-blank struct fields to be exported. This is a common reflection gotcha.
*   The error `errBufferTooSmall` in `Decode` and `Encode` indicates a need for sufficient buffer size.
*   The package documentation explicitly mentions its simplicity and suggests alternatives for performance-critical scenarios, which could be a point of error for users with high-performance requirements.
*   The reliance on fixed-size values is a key constraint. Users trying to serialize dynamically sized data without understanding this might run into issues.

**9. Crafting Examples:**

Based on the identified functionalities, I construct code examples demonstrating:

*   Basic type encoding/decoding with different endianness.
*   Encoding/decoding slices.
*   Encoding/decoding structs, highlighting the exported field requirement.

**10. Command-Line Arguments (Not Applicable):**

The code snippet doesn't show any command-line argument processing, so I explicitly state that.

**11. Structuring the Answer:**

Finally, I organize the information into a clear and logical structure, addressing each point of the original request:

*   List of functionalities.
*   Code examples with assumptions and outputs.
*   Explanation of the Go language feature implemented (binary serialization).
*   Discussion of potential user errors with examples.
*   Confirmation that command-line arguments aren't relevant.

**Self-Correction/Refinement During the Process:**

*   Initially, I might focus too much on the `ByteOrder` implementations. I need to remember that the core purpose is the serialization itself.
*   I might overlook the significance of the "fast path" and reflection mechanisms. It's important to highlight that the package handles both simple and more complex types.
*   When creating examples, I need to ensure they are clear, concise, and demonstrate the specific functionality being explained. I should include both `Encode`/`Decode` and `Write`/`Read` examples to cover the different use cases.
*   I need to double-check the comments in the code to accurately reflect the intended behavior and potential pitfalls.

By following these steps, I can systematically analyze the provided code and generate a comprehensive and accurate answer to the user's request.
好的，让我们来分析一下 `go/src/encoding/binary/binary.go` 这个 Go 语言文件。

**功能列举：**

1. **定义了字节序 (Byte Order) 接口和实现：**  定义了 `ByteOrder` 接口，用于描述如何将字节序列转换为 16、32 或 64 位的无符号整数，以及反向操作。提供了两种常用的实现：
    *   `LittleEndian` (小端字节序)
    *   `BigEndian` (大端字节序)
    *   `NativeEndian` (本地字节序，但在提供的代码中未完整实现，仅有 `String()` 和 `GoString()` 方法)

2. **提供了读写固定大小二进制数据的方法：**  
    *   `Read(r io.Reader, order ByteOrder, data any) error`: 从 `io.Reader` 中读取二进制数据，并根据指定的字节序将其解码到 `data` 中。`data` 必须是指向固定大小值的指针或固定大小值的切片。
    *   `Write(w io.Writer, order ByteOrder, data any) error`: 将 `data` 的二进制表示写入到 `io.Writer` 中，并根据指定的字节序进行编码。`data` 必须是固定大小的值、固定大小值的切片或指向这些数据的指针。
    *   `Decode(buf []byte, order ByteOrder, data any) (int, error)`:  从字节切片 `buf` 中解码二进制数据到 `data` 中。返回消耗的字节数和可能发生的错误。
    *   `Encode(buf []byte, order ByteOrder, data any) (int, error)`: 将 `data` 编码为二进制数据写入到字节切片 `buf` 中。返回写入的字节数和可能发生的错误。
    *   `Append(buf []byte, order ByteOrder, data any) ([]byte, error)`: 将 `data` 的二进制表示追加到字节切片 `buf` 中。

3. **提供了获取数据二进制大小的方法：**
    *   `Size(v any) int`: 返回将值 `v` 编码后所需的字节数。`v` 必须是固定大小的值、固定大小值的切片或指向这些数据的指针。

4. **内部实现了基于反射的通用编解码逻辑：**  当处理结构体或数组等复杂类型时，会使用 Go 的反射机制来遍历字段并进行编解码。

5. **针对基本类型和切片提供了快速编解码路径：**  为了提升性能，对 `bool`, `int8`, `uint8`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `float32`, `float64` 及其切片类型提供了优化的编解码实现。

**它是什么 Go 语言功能的实现？**

这个文件实现了 **二进制数据的序列化和反序列化** 功能，也常被称为 **编码 (Encoding) 和解码 (Decoding)**。它允许你将 Go 语言中的基本数据类型和由它们组成的复合类型（如结构体、数组和切片）转换为字节序列，以及将字节序列转换回 Go 语言中的数据。  这个包主要关注固定大小的数据类型的处理，并提供了对不同字节序的支持。

**Go 代码举例说明：**

```go
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

func main() {
	// 假设的输入数据
	var pi float64 = 3.1415926
	var count uint32 = 100
	message := "Hello"

	// 使用小端字节序进行编码
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, pi)
	if err != nil {
		log.Fatal("binary.Write failed:", err)
	}
	err = binary.Write(buf, binary.LittleEndian, count)
	if err != nil {
		log.Fatal("binary.Write failed:", err)
	}
	err = binary.Write(buf, binary.LittleEndian, []byte(message))
	if err != nil {
		log.Fatal("binary.Write failed:", err)
	}

	encodedData := buf.Bytes()
	fmt.Printf("编码后的数据 (小端): %v\n", encodedData)

	// 使用小端字节序进行解码
	reader := bytes.NewReader(encodedData)
	var decodedPi float64
	err = binary.Read(reader, binary.LittleEndian, &decodedPi)
	if err != nil {
		log.Fatal("binary.Read failed:", err)
	}

	var decodedCount uint32
	err = binary.Read(reader, binary.LittleEndian, &decodedCount)
	if err != nil {
		log.Fatal("binary.Read failed:", err)
	}

	decodedMessage := make([]byte, len(message))
	err = binary.Read(reader, binary.LittleEndian, decodedMessage)
	if err != nil {
		log.Fatal("binary.Read failed:", err)
	}

	fmt.Printf("解码后的数据 (小端):\n")
	fmt.Printf("  Pi: %f\n", decodedPi)
	fmt.Printf("  Count: %d\n", decodedCount)
	fmt.Printf("  Message: %s\n", decodedMessage)

	// 使用大端字节序进行编码
	bufBigEndian := new(bytes.Buffer)
	err = binary.Write(bufBigEndian, binary.BigEndian, pi)
	if err != nil {
		log.Fatal("binary.Write failed:", err)
	}
	err = binary.Write(bufBigEndian, binary.BigEndian, count)
	if err != nil {
		log.Fatal("binary.Write failed:", err)
	}
	err = binary.Write(bufBigEndian, binary.BigEndian, []byte(message))
	if err != nil {
		log.Fatal("binary.Write failed:", err)
	}

	encodedDataBigEndian := bufBigEndian.Bytes()
	fmt.Printf("编码后的数据 (大端): %v\n", encodedDataBigEndian)

	// 使用大端字节序进行解码
	readerBigEndian := bytes.NewReader(encodedDataBigEndian)
	var decodedPiBigEndian float64
	err = binary.Read(readerBigEndian, binary.BigEndian, &decodedPiBigEndian)
	if err != nil {
		log.Fatal("binary.Read failed:", err)
	}

	var decodedCountBigEndian uint32
	err = binary.Read(readerBigEndian, binary.BigEndian, &decodedCountBigEndian)
	if err != nil {
		log.Fatal("binary.Read failed:", err)
	}

	decodedMessageBigEndian := make([]byte, len(message))
	err = binary.Read(readerBigEndian, binary.BigEndian, decodedMessageBigEndian)
	if err != nil {
		log.Fatal("binary.Read failed:", err)
	}

	fmt.Printf("解码后的数据 (大端):\n")
	fmt.Printf("  Pi: %f\n", decodedPiBigEndian)
	fmt.Printf("  Count: %d\n", decodedCountBigEndian)
	fmt.Printf("  Message: %s\n", decodedMessageBigEndian)
}
```

**假设的输入与输出：**

假设我们有 `pi = 3.1415926`, `count = 100`, `message = "Hello"`。

**小端字节序的输出可能如下 (字节的具体值取决于浮点数的二进制表示):**

```
编码后的数据 (小端): [21 244 92 215 14 73 9 64 100 0 0 0 72 101 108 108 111]
解码后的数据 (小端):
  Pi: 3.141593
  Count: 100
  Message: Hello
```

**大端字节序的输出可能如下 (字节的具体值取决于浮点数的二进制表示):**

```
编码后的数据 (大端): [64 9 73 14 215 92 244 21 0 0 0 100 72 101 108 108 111]
解码后的数据 (大端):
  Pi: 3.141593
  Count: 100
  Message: Hello
```

**代码推理：**

*   我们首先创建了一个 `bytes.Buffer` 用于存储编码后的数据。
*   然后，我们使用 `binary.Write` 函数，并指定了 `binary.LittleEndian` 将 `pi`、`count` 和 `message` 的字节表示写入到缓冲区。注意，字符串 "Hello" 被转换成了字节切片。
*   接着，我们打印了编码后的字节切片。
*   为了解码，我们创建了一个 `bytes.NewReader` 从编码后的字节切片读取数据。
*   我们使用 `binary.Read` 函数，同样指定了 `binary.LittleEndian`，并将读取到的字节解码回对应的变量。
*   最后，我们打印了解码后的值。
*   重复了使用 `binary.BigEndian` 的过程来演示大端字节序的处理。

**命令行参数的具体处理：**

从提供的代码片段来看，`encoding/binary` 包本身并不直接处理命令行参数。它的主要职责是进行二进制数据的编解码。命令行参数的处理通常由 `os` 包和 `flag` 包来完成。

**使用者易犯错的点：**

1. **字节序混淆：**  如果在编码时使用了小端字节序，而在解码时使用了大端字节序，或者反过来，会导致解码出的数据错误。  例如，上面的例子中，如果编码时用 `binary.LittleEndian`，解码时用 `binary.BigEndian`，那么 `decodedPi` 和 `decodedCount` 的值将会是错误的。

    ```go
    // 错误示例：编码用小端，解码用大端
    // ... (编码部分使用 binary.LittleEndian) ...

    reader := bytes.NewReader(encodedData)
    var wrongDecodedPi float64
    err = binary.Read(reader, binary.BigEndian, &wrongDecodedPi) // 错误的使用
    if err != nil {
        log.Fatal("binary.Read failed:", err)
    }
    fmt.Printf("错误解码的 Pi: %f\n", wrongDecodedPi)
    ```

2. **数据类型不匹配：**  在 `Read` 和 `Decode` 时，提供的 `data` 变量的类型必须与编码时写入的数据类型严格匹配，否则会导致错误或不可预测的结果。例如，尝试将编码后的 `uint32` 解码到 `uint16` 变量中就会有问题。

    ```go
    // 错误示例：数据类型不匹配
    // ... (编码部分写入 uint32 类型的 count) ...

    var wrongDecodedCount uint16 // 类型不匹配
    err = binary.Read(reader, binary.LittleEndian, &wrongDecodedCount)
    if err != nil {
        log.Fatal("binary.Read failed:", err)
    }
    fmt.Printf("错误解码的 Count: %d\n", wrongDecodedCount)
    ```

3. **处理结构体时，未导出的字段不会被编解码：**  `binary` 包在处理结构体时，只会编解码导出的字段（首字母大写）。未导出的字段会被忽略。

    ```go
    type MyData struct {
        PublicField  uint32
        privateField uint32 // 不会被编解码
    }

    data := MyData{PublicField: 10, privateField: 20}
    buf := new(bytes.Buffer)
    binary.Write(buf, binary.LittleEndian, data)

    var decodedData MyData
    reader := bytes.NewReader(buf.Bytes())
    binary.Read(reader, binary.LittleEndian, &decodedData)

    fmt.Printf("解码后的 PublicField: %d\n", decodedData.PublicField)
    fmt.Printf("解码后的 privateField (保持默认值): %d\n", decodedData.privateField) // 可能是 0
    ```

4. **读取数据时缓冲区过小：**  在使用 `Decode` 函数时，如果提供的 `buf` 切片长度小于待解码数据所需的长度，会返回 `errBufferTooSmall` 错误。

    ```go
    var num uint32 = 12345
    buf := make([]byte, 2) // 缓冲区太小，无法容纳 uint32 (4字节)
    _, err := binary.Encode(buf, binary.LittleEndian, num)
    if errors.Is(err, binary.ErrBufferTooSmall) {
        fmt.Println("缓冲区太小错误")
    }
    ```

5. **结构体字段的内存布局影响：**  结构体在内存中的布局可能受到编译器优化的影响（例如字段对齐）。虽然 `binary` 包会尝试按照字段顺序进行编解码，但在跨平台或编译器版本变化的情况下，最好明确控制结构体的内存布局，例如使用 `struct{}` 类型的匿名成员来填充，或者避免依赖于特定的内存布局。

总而言之，`encoding/binary` 包提供了一种简单但强大的方式来处理二进制数据。理解字节序、数据类型匹配以及结构体字段的导出规则是正确使用这个包的关键。

Prompt: 
```
这是路径为go/src/encoding/binary/binary.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package binary implements simple translation between numbers and byte
// sequences and encoding and decoding of varints.
//
// Numbers are translated by reading and writing fixed-size values.
// A fixed-size value is either a fixed-size arithmetic
// type (bool, int8, uint8, int16, float32, complex64, ...)
// or an array or struct containing only fixed-size values.
//
// The varint functions encode and decode single integer values using
// a variable-length encoding; smaller values require fewer bytes.
// For a specification, see
// https://developers.google.com/protocol-buffers/docs/encoding.
//
// This package favors simplicity over efficiency. Clients that require
// high-performance serialization, especially for large data structures,
// should look at more advanced solutions such as the [encoding/gob]
// package or [google.golang.org/protobuf] for protocol buffers.
package binary

import (
	"errors"
	"io"
	"math"
	"reflect"
	"slices"
	"sync"
)

var errBufferTooSmall = errors.New("buffer too small")

// A ByteOrder specifies how to convert byte slices into
// 16-, 32-, or 64-bit unsigned integers.
//
// It is implemented by [LittleEndian], [BigEndian], and [NativeEndian].
type ByteOrder interface {
	Uint16([]byte) uint16
	Uint32([]byte) uint32
	Uint64([]byte) uint64
	PutUint16([]byte, uint16)
	PutUint32([]byte, uint32)
	PutUint64([]byte, uint64)
	String() string
}

// AppendByteOrder specifies how to append 16-, 32-, or 64-bit unsigned integers
// into a byte slice.
//
// It is implemented by [LittleEndian], [BigEndian], and [NativeEndian].
type AppendByteOrder interface {
	AppendUint16([]byte, uint16) []byte
	AppendUint32([]byte, uint32) []byte
	AppendUint64([]byte, uint64) []byte
	String() string
}

// LittleEndian is the little-endian implementation of [ByteOrder] and [AppendByteOrder].
var LittleEndian littleEndian

// BigEndian is the big-endian implementation of [ByteOrder] and [AppendByteOrder].
var BigEndian bigEndian

type littleEndian struct{}

func (littleEndian) Uint16(b []byte) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[0]) | uint16(b[1])<<8
}

func (littleEndian) PutUint16(b []byte, v uint16) {
	_ = b[1] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func (littleEndian) AppendUint16(b []byte, v uint16) []byte {
	return append(b,
		byte(v),
		byte(v>>8),
	)
}

func (littleEndian) Uint32(b []byte) uint32 {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func (littleEndian) PutUint32(b []byte, v uint32) {
	_ = b[3] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func (littleEndian) AppendUint32(b []byte, v uint32) []byte {
	return append(b,
		byte(v),
		byte(v>>8),
		byte(v>>16),
		byte(v>>24),
	)
}

func (littleEndian) Uint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func (littleEndian) PutUint64(b []byte, v uint64) {
	_ = b[7] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

func (littleEndian) AppendUint64(b []byte, v uint64) []byte {
	return append(b,
		byte(v),
		byte(v>>8),
		byte(v>>16),
		byte(v>>24),
		byte(v>>32),
		byte(v>>40),
		byte(v>>48),
		byte(v>>56),
	)
}

func (littleEndian) String() string { return "LittleEndian" }

func (littleEndian) GoString() string { return "binary.LittleEndian" }

type bigEndian struct{}

func (bigEndian) Uint16(b []byte) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[1]) | uint16(b[0])<<8
}

func (bigEndian) PutUint16(b []byte, v uint16) {
	_ = b[1] // early bounds check to guarantee safety of writes below
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func (bigEndian) AppendUint16(b []byte, v uint16) []byte {
	return append(b,
		byte(v>>8),
		byte(v),
	)
}

func (bigEndian) Uint32(b []byte) uint32 {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

func (bigEndian) PutUint32(b []byte, v uint32) {
	_ = b[3] // early bounds check to guarantee safety of writes below
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func (bigEndian) AppendUint32(b []byte, v uint32) []byte {
	return append(b,
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

func (bigEndian) Uint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

func (bigEndian) PutUint64(b []byte, v uint64) {
	_ = b[7] // early bounds check to guarantee safety of writes below
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func (bigEndian) AppendUint64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56),
		byte(v>>48),
		byte(v>>40),
		byte(v>>32),
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

func (bigEndian) String() string { return "BigEndian" }

func (bigEndian) GoString() string { return "binary.BigEndian" }

func (nativeEndian) String() string { return "NativeEndian" }

func (nativeEndian) GoString() string { return "binary.NativeEndian" }

// Read reads structured binary data from r into data.
// Data must be a pointer to a fixed-size value or a slice
// of fixed-size values.
// Bytes read from r are decoded using the specified byte order
// and written to successive fields of the data.
// When decoding boolean values, a zero byte is decoded as false, and
// any other non-zero byte is decoded as true.
// When reading into structs, the field data for fields with
// blank (_) field names is skipped; i.e., blank field names
// may be used for padding.
// When reading into a struct, all non-blank fields must be exported
// or Read may panic.
//
// The error is [io.EOF] only if no bytes were read.
// If an [io.EOF] happens after reading some but not all the bytes,
// Read returns [io.ErrUnexpectedEOF].
func Read(r io.Reader, order ByteOrder, data any) error {
	// Fast path for basic types and slices.
	if n, _ := intDataSize(data); n != 0 {
		bs := make([]byte, n)
		if _, err := io.ReadFull(r, bs); err != nil {
			return err
		}

		if decodeFast(bs, order, data) {
			return nil
		}
	}

	// Fallback to reflect-based decoding.
	v := reflect.ValueOf(data)
	size := -1
	switch v.Kind() {
	case reflect.Pointer:
		v = v.Elem()
		size = dataSize(v)
	case reflect.Slice:
		size = dataSize(v)
	}
	if size < 0 {
		return errors.New("binary.Read: invalid type " + reflect.TypeOf(data).String())
	}

	d := &decoder{order: order, buf: make([]byte, size)}
	if _, err := io.ReadFull(r, d.buf); err != nil {
		return err
	}
	d.value(v)
	return nil
}

// Decode decodes binary data from buf into data according to
// the given byte order.
// It returns an error if buf is too small, otherwise the number of
// bytes consumed from buf.
func Decode(buf []byte, order ByteOrder, data any) (int, error) {
	if n, _ := intDataSize(data); n != 0 {
		if len(buf) < n {
			return 0, errBufferTooSmall
		}

		if decodeFast(buf, order, data) {
			return n, nil
		}
	}

	// Fallback to reflect-based decoding.
	v := reflect.ValueOf(data)
	size := -1
	switch v.Kind() {
	case reflect.Pointer:
		v = v.Elem()
		size = dataSize(v)
	case reflect.Slice:
		size = dataSize(v)
	}
	if size < 0 {
		return 0, errors.New("binary.Decode: invalid type " + reflect.TypeOf(data).String())
	}

	if len(buf) < size {
		return 0, errBufferTooSmall
	}
	d := &decoder{order: order, buf: buf[:size]}
	d.value(v)
	return size, nil
}

func decodeFast(bs []byte, order ByteOrder, data any) bool {
	switch data := data.(type) {
	case *bool:
		*data = bs[0] != 0
	case *int8:
		*data = int8(bs[0])
	case *uint8:
		*data = bs[0]
	case *int16:
		*data = int16(order.Uint16(bs))
	case *uint16:
		*data = order.Uint16(bs)
	case *int32:
		*data = int32(order.Uint32(bs))
	case *uint32:
		*data = order.Uint32(bs)
	case *int64:
		*data = int64(order.Uint64(bs))
	case *uint64:
		*data = order.Uint64(bs)
	case *float32:
		*data = math.Float32frombits(order.Uint32(bs))
	case *float64:
		*data = math.Float64frombits(order.Uint64(bs))
	case []bool:
		for i, x := range bs { // Easier to loop over the input for 8-bit values.
			data[i] = x != 0
		}
	case []int8:
		for i, x := range bs {
			data[i] = int8(x)
		}
	case []uint8:
		copy(data, bs)
	case []int16:
		for i := range data {
			data[i] = int16(order.Uint16(bs[2*i:]))
		}
	case []uint16:
		for i := range data {
			data[i] = order.Uint16(bs[2*i:])
		}
	case []int32:
		for i := range data {
			data[i] = int32(order.Uint32(bs[4*i:]))
		}
	case []uint32:
		for i := range data {
			data[i] = order.Uint32(bs[4*i:])
		}
	case []int64:
		for i := range data {
			data[i] = int64(order.Uint64(bs[8*i:]))
		}
	case []uint64:
		for i := range data {
			data[i] = order.Uint64(bs[8*i:])
		}
	case []float32:
		for i := range data {
			data[i] = math.Float32frombits(order.Uint32(bs[4*i:]))
		}
	case []float64:
		for i := range data {
			data[i] = math.Float64frombits(order.Uint64(bs[8*i:]))
		}
	default:
		return false
	}
	return true
}

// Write writes the binary representation of data into w.
// Data must be a fixed-size value or a slice of fixed-size
// values, or a pointer to such data.
// Boolean values encode as one byte: 1 for true, and 0 for false.
// Bytes written to w are encoded using the specified byte order
// and read from successive fields of the data.
// When writing structs, zero values are written for fields
// with blank (_) field names.
func Write(w io.Writer, order ByteOrder, data any) error {
	// Fast path for basic types and slices.
	if n, bs := intDataSize(data); n != 0 {
		if bs == nil {
			bs = make([]byte, n)
			encodeFast(bs, order, data)
		}

		_, err := w.Write(bs)
		return err
	}

	// Fallback to reflect-based encoding.
	v := reflect.Indirect(reflect.ValueOf(data))
	size := dataSize(v)
	if size < 0 {
		return errors.New("binary.Write: some values are not fixed-sized in type " + reflect.TypeOf(data).String())
	}

	buf := make([]byte, size)
	e := &encoder{order: order, buf: buf}
	e.value(v)
	_, err := w.Write(buf)
	return err
}

// Encode encodes the binary representation of data into buf according to
// the given byte order.
// It returns an error if buf is too small, otherwise the number of
// bytes written into buf.
func Encode(buf []byte, order ByteOrder, data any) (int, error) {
	// Fast path for basic types and slices.
	if n, _ := intDataSize(data); n != 0 {
		if len(buf) < n {
			return 0, errBufferTooSmall
		}

		encodeFast(buf, order, data)
		return n, nil
	}

	// Fallback to reflect-based encoding.
	v := reflect.Indirect(reflect.ValueOf(data))
	size := dataSize(v)
	if size < 0 {
		return 0, errors.New("binary.Encode: some values are not fixed-sized in type " + reflect.TypeOf(data).String())
	}

	if len(buf) < size {
		return 0, errBufferTooSmall
	}
	e := &encoder{order: order, buf: buf}
	e.value(v)
	return size, nil
}

// Append appends the binary representation of data to buf.
// buf may be nil, in which case a new buffer will be allocated.
// See [Write] on which data are acceptable.
// It returns the (possibly extended) buffer containing data or an error.
func Append(buf []byte, order ByteOrder, data any) ([]byte, error) {
	// Fast path for basic types and slices.
	if n, _ := intDataSize(data); n != 0 {
		buf, pos := ensure(buf, n)
		encodeFast(pos, order, data)
		return buf, nil
	}

	// Fallback to reflect-based encoding.
	v := reflect.Indirect(reflect.ValueOf(data))
	size := dataSize(v)
	if size < 0 {
		return nil, errors.New("binary.Append: some values are not fixed-sized in type " + reflect.TypeOf(data).String())
	}

	buf, pos := ensure(buf, size)
	e := &encoder{order: order, buf: pos}
	e.value(v)
	return buf, nil
}

func encodeFast(bs []byte, order ByteOrder, data any) {
	switch v := data.(type) {
	case *bool:
		if *v {
			bs[0] = 1
		} else {
			bs[0] = 0
		}
	case bool:
		if v {
			bs[0] = 1
		} else {
			bs[0] = 0
		}
	case []bool:
		for i, x := range v {
			if x {
				bs[i] = 1
			} else {
				bs[i] = 0
			}
		}
	case *int8:
		bs[0] = byte(*v)
	case int8:
		bs[0] = byte(v)
	case []int8:
		for i, x := range v {
			bs[i] = byte(x)
		}
	case *uint8:
		bs[0] = *v
	case uint8:
		bs[0] = v
	case []uint8:
		copy(bs, v)
	case *int16:
		order.PutUint16(bs, uint16(*v))
	case int16:
		order.PutUint16(bs, uint16(v))
	case []int16:
		for i, x := range v {
			order.PutUint16(bs[2*i:], uint16(x))
		}
	case *uint16:
		order.PutUint16(bs, *v)
	case uint16:
		order.PutUint16(bs, v)
	case []uint16:
		for i, x := range v {
			order.PutUint16(bs[2*i:], x)
		}
	case *int32:
		order.PutUint32(bs, uint32(*v))
	case int32:
		order.PutUint32(bs, uint32(v))
	case []int32:
		for i, x := range v {
			order.PutUint32(bs[4*i:], uint32(x))
		}
	case *uint32:
		order.PutUint32(bs, *v)
	case uint32:
		order.PutUint32(bs, v)
	case []uint32:
		for i, x := range v {
			order.PutUint32(bs[4*i:], x)
		}
	case *int64:
		order.PutUint64(bs, uint64(*v))
	case int64:
		order.PutUint64(bs, uint64(v))
	case []int64:
		for i, x := range v {
			order.PutUint64(bs[8*i:], uint64(x))
		}
	case *uint64:
		order.PutUint64(bs, *v)
	case uint64:
		order.PutUint64(bs, v)
	case []uint64:
		for i, x := range v {
			order.PutUint64(bs[8*i:], x)
		}
	case *float32:
		order.PutUint32(bs, math.Float32bits(*v))
	case float32:
		order.PutUint32(bs, math.Float32bits(v))
	case []float32:
		for i, x := range v {
			order.PutUint32(bs[4*i:], math.Float32bits(x))
		}
	case *float64:
		order.PutUint64(bs, math.Float64bits(*v))
	case float64:
		order.PutUint64(bs, math.Float64bits(v))
	case []float64:
		for i, x := range v {
			order.PutUint64(bs[8*i:], math.Float64bits(x))
		}
	}
}

// Size returns how many bytes [Write] would generate to encode the value v, which
// must be a fixed-size value or a slice of fixed-size values, or a pointer to such data.
// If v is neither of these, Size returns -1.
func Size(v any) int {
	switch data := v.(type) {
	case bool, int8, uint8:
		return 1
	case *bool:
		if data == nil {
			return -1
		}
		return 1
	case *int8:
		if data == nil {
			return -1
		}
		return 1
	case *uint8:
		if data == nil {
			return -1
		}
		return 1
	case []bool:
		return len(data)
	case []int8:
		return len(data)
	case []uint8:
		return len(data)
	case int16, uint16:
		return 2
	case *int16:
		if data == nil {
			return -1
		}
		return 2
	case *uint16:
		if data == nil {
			return -1
		}
		return 2
	case []int16:
		return 2 * len(data)
	case []uint16:
		return 2 * len(data)
	case int32, uint32:
		return 4
	case *int32:
		if data == nil {
			return -1
		}
		return 4
	case *uint32:
		if data == nil {
			return -1
		}
		return 4
	case []int32:
		return 4 * len(data)
	case []uint32:
		return 4 * len(data)
	case int64, uint64:
		return 8
	case *int64:
		if data == nil {
			return -1
		}
		return 8
	case *uint64:
		if data == nil {
			return -1
		}
		return 8
	case []int64:
		return 8 * len(data)
	case []uint64:
		return 8 * len(data)
	case float32:
		return 4
	case *float32:
		if data == nil {
			return -1
		}
		return 4
	case float64:
		return 8
	case *float64:
		if data == nil {
			return -1
		}
		return 8
	case []float32:
		return 4 * len(data)
	case []float64:
		return 8 * len(data)
	}
	return dataSize(reflect.Indirect(reflect.ValueOf(v)))
}

var structSize sync.Map // map[reflect.Type]int

// dataSize returns the number of bytes the actual data represented by v occupies in memory.
// For compound structures, it sums the sizes of the elements. Thus, for instance, for a slice
// it returns the length of the slice times the element size and does not count the memory
// occupied by the header. If the type of v is not acceptable, dataSize returns -1.
func dataSize(v reflect.Value) int {
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		t := v.Type().Elem()
		if size, ok := structSize.Load(t); ok {
			return size.(int) * v.Len()
		}

		size := sizeof(t)
		if size >= 0 {
			if t.Kind() == reflect.Struct {
				structSize.Store(t, size)
			}
			return size * v.Len()
		}

	case reflect.Struct:
		t := v.Type()
		if size, ok := structSize.Load(t); ok {
			return size.(int)
		}
		size := sizeof(t)
		structSize.Store(t, size)
		return size

	default:
		if v.IsValid() {
			return sizeof(v.Type())
		}
	}

	return -1
}

// sizeof returns the size >= 0 of variables for the given type or -1 if the type is not acceptable.
func sizeof(t reflect.Type) int {
	switch t.Kind() {
	case reflect.Array:
		if s := sizeof(t.Elem()); s >= 0 {
			return s * t.Len()
		}

	case reflect.Struct:
		sum := 0
		for i, n := 0, t.NumField(); i < n; i++ {
			s := sizeof(t.Field(i).Type)
			if s < 0 {
				return -1
			}
			sum += s
		}
		return sum

	case reflect.Bool,
		reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return int(t.Size())
	}

	return -1
}

type coder struct {
	order  ByteOrder
	buf    []byte
	offset int
}

type decoder coder
type encoder coder

func (d *decoder) bool() bool {
	x := d.buf[d.offset]
	d.offset++
	return x != 0
}

func (e *encoder) bool(x bool) {
	if x {
		e.buf[e.offset] = 1
	} else {
		e.buf[e.offset] = 0
	}
	e.offset++
}

func (d *decoder) uint8() uint8 {
	x := d.buf[d.offset]
	d.offset++
	return x
}

func (e *encoder) uint8(x uint8) {
	e.buf[e.offset] = x
	e.offset++
}

func (d *decoder) uint16() uint16 {
	x := d.order.Uint16(d.buf[d.offset : d.offset+2])
	d.offset += 2
	return x
}

func (e *encoder) uint16(x uint16) {
	e.order.PutUint16(e.buf[e.offset:e.offset+2], x)
	e.offset += 2
}

func (d *decoder) uint32() uint32 {
	x := d.order.Uint32(d.buf[d.offset : d.offset+4])
	d.offset += 4
	return x
}

func (e *encoder) uint32(x uint32) {
	e.order.PutUint32(e.buf[e.offset:e.offset+4], x)
	e.offset += 4
}

func (d *decoder) uint64() uint64 {
	x := d.order.Uint64(d.buf[d.offset : d.offset+8])
	d.offset += 8
	return x
}

func (e *encoder) uint64(x uint64) {
	e.order.PutUint64(e.buf[e.offset:e.offset+8], x)
	e.offset += 8
}

func (d *decoder) int8() int8 { return int8(d.uint8()) }

func (e *encoder) int8(x int8) { e.uint8(uint8(x)) }

func (d *decoder) int16() int16 { return int16(d.uint16()) }

func (e *encoder) int16(x int16) { e.uint16(uint16(x)) }

func (d *decoder) int32() int32 { return int32(d.uint32()) }

func (e *encoder) int32(x int32) { e.uint32(uint32(x)) }

func (d *decoder) int64() int64 { return int64(d.uint64()) }

func (e *encoder) int64(x int64) { e.uint64(uint64(x)) }

func (d *decoder) value(v reflect.Value) {
	switch v.Kind() {
	case reflect.Array:
		l := v.Len()
		for i := 0; i < l; i++ {
			d.value(v.Index(i))
		}

	case reflect.Struct:
		t := v.Type()
		l := v.NumField()
		for i := 0; i < l; i++ {
			// Note: Calling v.CanSet() below is an optimization.
			// It would be sufficient to check the field name,
			// but creating the StructField info for each field is
			// costly (run "go test -bench=ReadStruct" and compare
			// results when making changes to this code).
			if v := v.Field(i); v.CanSet() || t.Field(i).Name != "_" {
				d.value(v)
			} else {
				d.skip(v)
			}
		}

	case reflect.Slice:
		l := v.Len()
		for i := 0; i < l; i++ {
			d.value(v.Index(i))
		}

	case reflect.Bool:
		v.SetBool(d.bool())

	case reflect.Int8:
		v.SetInt(int64(d.int8()))
	case reflect.Int16:
		v.SetInt(int64(d.int16()))
	case reflect.Int32:
		v.SetInt(int64(d.int32()))
	case reflect.Int64:
		v.SetInt(d.int64())

	case reflect.Uint8:
		v.SetUint(uint64(d.uint8()))
	case reflect.Uint16:
		v.SetUint(uint64(d.uint16()))
	case reflect.Uint32:
		v.SetUint(uint64(d.uint32()))
	case reflect.Uint64:
		v.SetUint(d.uint64())

	case reflect.Float32:
		v.SetFloat(float64(math.Float32frombits(d.uint32())))
	case reflect.Float64:
		v.SetFloat(math.Float64frombits(d.uint64()))

	case reflect.Complex64:
		v.SetComplex(complex(
			float64(math.Float32frombits(d.uint32())),
			float64(math.Float32frombits(d.uint32())),
		))
	case reflect.Complex128:
		v.SetComplex(complex(
			math.Float64frombits(d.uint64()),
			math.Float64frombits(d.uint64()),
		))
	}
}

func (e *encoder) value(v reflect.Value) {
	switch v.Kind() {
	case reflect.Array:
		l := v.Len()
		for i := 0; i < l; i++ {
			e.value(v.Index(i))
		}

	case reflect.Struct:
		t := v.Type()
		l := v.NumField()
		for i := 0; i < l; i++ {
			// see comment for corresponding code in decoder.value()
			if v := v.Field(i); v.CanSet() || t.Field(i).Name != "_" {
				e.value(v)
			} else {
				e.skip(v)
			}
		}

	case reflect.Slice:
		l := v.Len()
		for i := 0; i < l; i++ {
			e.value(v.Index(i))
		}

	case reflect.Bool:
		e.bool(v.Bool())

	case reflect.Int8:
		e.int8(int8(v.Int()))
	case reflect.Int16:
		e.int16(int16(v.Int()))
	case reflect.Int32:
		e.int32(int32(v.Int()))
	case reflect.Int64:
		e.int64(v.Int())

	case reflect.Uint8:
		e.uint8(uint8(v.Uint()))
	case reflect.Uint16:
		e.uint16(uint16(v.Uint()))
	case reflect.Uint32:
		e.uint32(uint32(v.Uint()))
	case reflect.Uint64:
		e.uint64(v.Uint())

	case reflect.Float32:
		e.uint32(math.Float32bits(float32(v.Float())))
	case reflect.Float64:
		e.uint64(math.Float64bits(v.Float()))

	case reflect.Complex64:
		x := v.Complex()
		e.uint32(math.Float32bits(float32(real(x))))
		e.uint32(math.Float32bits(float32(imag(x))))
	case reflect.Complex128:
		x := v.Complex()
		e.uint64(math.Float64bits(real(x)))
		e.uint64(math.Float64bits(imag(x)))
	}
}

func (d *decoder) skip(v reflect.Value) {
	d.offset += dataSize(v)
}

func (e *encoder) skip(v reflect.Value) {
	n := dataSize(v)
	clear(e.buf[e.offset : e.offset+n])
	e.offset += n
}

// intDataSize returns the size of the data required to represent the data when encoded,
// and optionally a byte slice containing the encoded data if no conversion is necessary.
// It returns zero, nil if the type cannot be implemented by the fast path in Read or Write.
func intDataSize(data any) (int, []byte) {
	switch data := data.(type) {
	case bool, int8, uint8, *bool, *int8, *uint8:
		return 1, nil
	case []bool:
		return len(data), nil
	case []int8:
		return len(data), nil
	case []uint8:
		return len(data), data
	case int16, uint16, *int16, *uint16:
		return 2, nil
	case []int16:
		return 2 * len(data), nil
	case []uint16:
		return 2 * len(data), nil
	case int32, uint32, *int32, *uint32:
		return 4, nil
	case []int32:
		return 4 * len(data), nil
	case []uint32:
		return 4 * len(data), nil
	case int64, uint64, *int64, *uint64:
		return 8, nil
	case []int64:
		return 8 * len(data), nil
	case []uint64:
		return 8 * len(data), nil
	case float32, *float32:
		return 4, nil
	case float64, *float64:
		return 8, nil
	case []float32:
		return 4 * len(data), nil
	case []float64:
		return 8 * len(data), nil
	}
	return 0, nil
}

// ensure grows buf to length len(buf) + n and returns the grown buffer
// and a slice starting at the original length of buf (that is, buf2[len(buf):]).
func ensure(buf []byte, n int) (buf2, pos []byte) {
	l := len(buf)
	buf = slices.Grow(buf, n)[:l+n]
	return buf, buf[l:]
}

"""



```