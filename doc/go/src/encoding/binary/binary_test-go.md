Response:
Let's break down the thought process for analyzing the provided Go code and generating the answer.

**1. Understanding the Request:**

The core request is to analyze a Go test file (`binary_test.go`) and determine its functionality. Key aspects to cover are:

* **Core Functionality:** What Go feature is being tested?
* **Code Examples:** Illustrate the functionality with Go code, including input and output.
* **Command-Line Arguments:**  Are there any relevant command-line arguments (unlikely for a test file, but good to check).
* **Common Mistakes:** What are potential pitfalls for users?
* **Language:** The answer must be in Chinese.

**2. Initial Code Scan and Keywords:**

I first scanned the code for prominent keywords and patterns:

* `package binary`: This immediately suggests the code is testing the `encoding/binary` package in Go's standard library.
* `import (...)`:  The imports confirm the testing context (`testing`) and the target package (`binary`). `bytes`, `io`, `math`, `reflect`, etc., hint at operations involving byte streams, input/output, mathematical conversions, and reflection.
* `type Struct`, `type T`, `var s`, `var big`, `var little`: These variable declarations define test data and expected outcomes. `big` and `little` strongly suggest testing for different byte orders (big-endian and little-endian).
* `func Test...`:  This is the standard prefix for Go test functions.
* `LittleEndian`, `BigEndian`: These are key constants from the `encoding/binary` package, confirming the focus on byte order.
* `Write`, `Read`, `Encode`, `Decode`, `Size`, `Append`: These are the primary functions being tested in the `encoding/binary` package.
* `checkResult`: This is a helper function for comparing actual results with expected results in the tests.

**3. Identifying the Core Functionality:**

Based on the keywords and the structure of the test functions, it becomes clear that `binary_test.go` is primarily testing the functionalities of the `encoding/binary` package. This package is responsible for converting between Go data types and byte sequences, with explicit control over byte order (endianness).

**4. Analyzing Key Test Functions:**

I then focused on the main test functions to understand how they verify the `encoding/binary` package's behavior:

* `TestLittleEndianRead/Write`, `TestBigEndianRead/Write`: These functions test the `Read` and `Write` functions with both little-endian and big-endian byte orders, using the predefined `s`, `big`, and `little` variables for comparison.
* `TestReadSlice`, `TestWriteSlice`: These test the handling of slices.
* `TestReadBool`, `TestReadBoolSlice`: These verify the encoding/decoding of boolean values.
* `TestSliceRoundTrip`: This function performs a more comprehensive test, writing and then reading back slices of various integer types to ensure data integrity.
* `TestWriteT`: This function checks how the `Write` function handles types that are not directly supported (like `int` or slices of `int`). It expects errors.
* `TestBlankFields`: This tests the behavior with structs containing padding or blank fields (`_`).
* `TestSize...`: These functions test the `Size` function, which determines the byte size of a data type.
* `TestUnexportedRead`: This tests the behavior when trying to read into a struct with unexported fields (it should panic).
* `TestReadErrorMsg`: Checks the error messages produced by `Read` and `Decode`.
* `TestReadTruncated`: Tests the behavior when reading from a byte stream that is shorter than expected.
* `TestByteOrder`:  Directly tests the `PutUint*` and `Uint*` methods of the `ByteOrder` interface.
* `TestEarlyBoundsChecks`: Checks for panics when using `Uint64` and `PutUint64` with insufficient slice lengths.
* `TestReadInvalidDestination`:  Tests reading into invalid destination types.
* `TestNoFixedSize`: Checks how the functions handle types with non-fixed sizes.
* `Benchmark...`: These functions are for performance testing (benchmarking).

**5. Constructing Code Examples:**

Based on the identified functionalities, I constructed Go code examples demonstrating the usage of `Read`, `Write`, `Encode`, and `Decode` with different data types and byte orders. The key here was to select simple and clear examples that illustrate the core concepts. I included input byte slices and expected output values.

**6. Addressing Other Requirements:**

* **Command-Line Arguments:**  I realized that `binary_test.go` itself doesn't directly process command-line arguments. However, the `go test` command used to run the tests can accept arguments (e.g., `-v` for verbose output). I included a brief explanation of this.
* **Common Mistakes:**  I identified common pitfalls such as:
    * Incorrect byte order.
    * Providing a buffer of insufficient size to `Decode`.
    * Trying to read into a struct with unexported fields.
    * Not checking for errors after `Read` or `Decode`.
* **Language:** Throughout the process, I kept the target language (Chinese) in mind, translating concepts and explanations appropriately.

**7. Structuring the Answer:**

Finally, I organized the information into a clear and logical structure, addressing each point of the request:

* **功能:**  Start with a high-level description of the file's purpose.
* **Go语言功能的实现:**  Identify the core Go feature being tested (`encoding/binary`).
* **代码举例:** Provide illustrative code examples with input and output.
* **命令行参数:** Explain the role of `go test` arguments.
* **使用者易犯错的点:**  List common mistakes with examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the test file tests specific edge cases of network protocols. **Correction:**  While byte order is important in networking, the primary focus is on the general `encoding/binary` package functionality.
* **Initial thought:**  Focus heavily on every single test function. **Correction:** Prioritize the most illustrative tests (`Read`, `Write` with different types and endianness) and provide a summary of the other tests.
* **Ensuring clarity in Chinese:** Double-check the terminology and phrasing in Chinese to ensure it's accurate and easy to understand. For example, making sure to use the correct terms for "big-endian" and "little-endian."

By following these steps, I was able to analyze the provided Go code and generate a comprehensive and accurate answer in Chinese that addressed all the requirements of the prompt.
这个 `go/src/encoding/binary/binary_test.go` 文件是 Go 语言标准库中 `encoding/binary` 包的测试文件。它的主要功能是验证 `encoding/binary` 包提供的各种功能是否按预期工作。

具体来说，这个测试文件覆盖了以下几个方面的功能：

1. **基本数据类型的读写 (Read/Write):** 测试了将各种基本数据类型（如 `int8`, `int16`, `int32`, `int64`, `uint8`, `uint16`, `uint32`, `uint64`, `float32`, `float64`, `bool`）以特定的字节顺序（大端和小端）写入字节流，并能正确地从字节流中读取出来。

2. **结构体的读写 (Read/Write):** 测试了将结构体数据以特定的字节顺序写入字节流，并能正确地从字节流中读取回结构体。这包括了包含不同类型字段的结构体。

3. **切片的读写 (Read/Write):** 测试了将切片数据以特定的字节顺序写入字节流，并能正确地从字节流中读取回切片。

4. **字节顺序 (ByteOrder):**  测试了 `LittleEndian` (小端) 和 `BigEndian` (大端) 两种字节顺序的正确性。验证了使用不同的字节顺序读写数据时，字节的排列顺序是否符合预期。

5. **编码和解码 (Encode/Decode):** 测试了 `Encode` 和 `Decode` 函数，这两个函数的功能与 `Write` 和 `Read` 类似，但是它们直接操作字节切片。

6. **追加数据 (Append):** 测试了 `Append` 函数，用于将数据以指定字节顺序追加到字节切片中。

7. **计算数据大小 (Size):** 测试了 `Size` 函数，用于计算给定数据类型或值的字节大小。

8. **处理结构体中的空白字段:** 测试了当结构体中包含空白字段 (`_`) 时，读写操作的行为。

9. **错误处理:** 测试了各种可能出现的错误情况，例如读取超出字节流末尾的数据，或者尝试读取到不兼容的类型中。

10. **性能测试 (Benchmarks):**  包含了各种性能测试用例，用于衡量 `encoding/binary` 包中不同操作的性能。

**`encoding/binary` 包的功能推理和代码举例:**

`encoding/binary` 包主要用于在 Go 语言中实现 **二进制数据的序列化和反序列化**。它允许你将 Go 的数据结构转换为字节流，以便存储到文件中或通过网络传输，并且能够将这些字节流转换回 Go 的数据结构。 关键在于它可以让你控制字节的排列顺序（大端或小端），这在处理跨平台或网络协议时非常重要。

**Go 代码举例:**

假设我们想将一个包含整数和浮点数的结构体写入到一个字节切片中，并再将其读取回来。

```go
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Data struct {
	ID   uint32
	Value float64
}

func main() {
	// 创建一个 Data 结构体
	originalData := Data{ID: 12345, Value: 3.14159}

	// 创建一个字节缓冲区
	buf := new(bytes.Buffer)

	// 使用小端字节序将结构体写入缓冲区
	err := binary.Write(buf, binary.LittleEndian, &originalData)
	if err != nil {
		fmt.Println("写入错误:", err)
		return
	}

	// 打印写入的字节
	fmt.Printf("写入的字节 (小端): %v\n", buf.Bytes())

	// 创建一个新的 Data 结构体用于读取
	var readData Data

	// 使用小端字节序从缓冲区读取数据
	reader := bytes.NewReader(buf.Bytes())
	err = binary.Read(reader, binary.LittleEndian, &readData)
	if err != nil {
		fmt.Println("读取错误:", err)
		return
	}

	// 打印读取到的数据
	fmt.Printf("读取到的数据: %+v\n", readData)

	// 使用大端字节序进行相同的操作
	bufBigEndian := new(bytes.Buffer)
	err = binary.Write(bufBigEndian, binary.BigEndian, &originalData)
	if err != nil {
		fmt.Println("写入错误 (大端):", err)
		return
	}
	fmt.Printf("写入的字节 (大端): %v\n", bufBigEndian.Bytes())

	var readDataBigEndian Data
	readerBigEndian := bytes.NewReader(bufBigEndian.Bytes())
	err = binary.Read(readerBigEndian, binary.BigEndian, &readDataBigEndian)
	if err != nil {
		fmt.Println("读取错误 (大端):", err)
		return
	}
	fmt.Printf("读取到的数据 (大端): %+v\n", readDataBigEndian)
}
```

**假设的输入与输出:**

上面的代码没有直接的“输入”，它创建了一个 `originalData` 变量作为要序列化的数据。

**输出 (可能因机器字节序而异，这里假设一个通用的输出):**

```
写入的字节 (小端): [49 30 0 0 18 39 ad 77 15 f8 2d 40]
读取到的数据: {ID:12345 Value:3.14159}
写入的字节 (大端): [0 0 30 49 64 15 77 ad 39 18 09 40]
读取到的数据 (大端): {ID:12345 Value:3.14159}
```

**代码推理:**

* `binary.Write(buf, binary.LittleEndian, &originalData)`：这行代码使用小端字节序将 `originalData` 结构体的内容写入到 `buf` 这个 `bytes.Buffer` 中。结构体的字段会按照它们在结构体中定义的顺序被序列化为字节。
* `binary.Read(reader, binary.LittleEndian, &readData)`：这行代码使用小端字节序从 `reader` 中读取字节流，并将这些字节反序列化到 `readData` 结构体中。字节流会被解析并赋值给 `readData` 的相应字段。
* 可以观察到，大端和小端写入的字节序列是不同的，这体现了字节顺序的作用。

**命令行参数:**

这个测试文件本身并不处理特定的命令行参数。但是，当你使用 `go test` 命令来运行这个测试文件时，你可以使用 `go test` 的一些标准参数，例如：

* `go test -v`:  显示更详细的测试输出，包括每个测试函数的运行结果。
* `go test -run <正则表达式>`:  只运行名称匹配指定正则表达式的测试函数。
* `go test -bench <正则表达式>`:  运行性能测试。

例如，要运行 `binary_test.go` 文件中的所有测试，可以在终端中执行：

```bash
go test go/src/encoding/binary/binary_test.go
```

要运行特定的测试函数（例如名称包含 "LittleEndianRead" 的测试），可以执行：

```bash
go test -run LittleEndianRead go/src/encoding/binary/binary_test.go
```

要运行性能测试，可以执行：

```bash
go test -bench . go/src/encoding/binary/binary_test.go
```

**使用者易犯错的点:**

1. **字节顺序错误:** 最常见的错误是读写数据时使用了错误的字节顺序。如果发送端使用大端序写入数据，而接收端使用小端序读取，或者反过来，会导致数据解析错误。

   ```go
   // 错误示例：写入时使用小端，读取时使用大端
   buf := new(bytes.Buffer)
   data := uint32(0x12345678)
   binary.Write(buf, binary.LittleEndian, data)

   var readData uint32
   reader := bytes.NewReader(buf.Bytes())
   binary.Read(reader, binary.BigEndian, &readData)
   fmt.Printf("错误读取的结果: 0x%X\n", readData) // 输出可能不是 0x12345678
   ```

2. **缓冲区大小不足:** 在使用 `binary.Decode` 将数据解码到切片时，如果提供的切片容量不足以容纳所有数据，可能会导致解码失败或数据丢失。

   ```go
   // 错误示例：解码到容量不足的切片
   data := []uint32{1, 2, 3, 4, 5}
   buf := new(bytes.Buffer)
   binary.Write(buf, binary.LittleEndian, data)

   slice := make([]uint32, 3) // 切片容量小于实际数据量
   _, err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, slice)
   if err != nil {
       fmt.Println("读取错误:", err) // 可能会报错或只读取部分数据
   }
   fmt.Println("读取到的切片:", slice)
   ```

3. **尝试读取到不兼容的类型:**  尝试将一种类型的数据读取到另一种不兼容的类型中会导致错误。

   ```go
   // 错误示例：尝试将 int32 的字节读取到 float32 中
   buf := new(bytes.Buffer)
   intValue := int32(10)
   binary.Write(buf, binary.LittleEndian, intValue)

   var floatValue float32
   reader := bytes.NewReader(buf.Bytes())
   err := binary.Read(reader, binary.LittleEndian, &floatValue)
   if err != nil {
       fmt.Println("读取错误:", err) // 会报错
   }
   ```

理解这些功能和潜在的错误可以帮助开发者更好地使用 `encoding/binary` 包来处理二进制数据。

Prompt: 
```
这是路径为go/src/encoding/binary/binary_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package binary

import (
	"bytes"
	"fmt"
	"internal/asan"
	"io"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

type Struct struct {
	Int8       int8
	Int16      int16
	Int32      int32
	Int64      int64
	Uint8      uint8
	Uint16     uint16
	Uint32     uint32
	Uint64     uint64
	Float32    float32
	Float64    float64
	Complex64  complex64
	Complex128 complex128
	Array      [4]uint8
	Bool       bool
	BoolArray  [4]bool
}

type T struct {
	Int     int
	Uint    uint
	Uintptr uintptr
	Array   [4]int
}

var s = Struct{
	0x01,
	0x0203,
	0x04050607,
	0x08090a0b0c0d0e0f,
	0x10,
	0x1112,
	0x13141516,
	0x1718191a1b1c1d1e,

	math.Float32frombits(0x1f202122),
	math.Float64frombits(0x232425262728292a),
	complex(
		math.Float32frombits(0x2b2c2d2e),
		math.Float32frombits(0x2f303132),
	),
	complex(
		math.Float64frombits(0x333435363738393a),
		math.Float64frombits(0x3b3c3d3e3f404142),
	),

	[4]uint8{0x43, 0x44, 0x45, 0x46},

	true,
	[4]bool{true, false, true, false},
}

var big = []byte{
	1,
	2, 3,
	4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16,
	17, 18,
	19, 20, 21, 22,
	23, 24, 25, 26, 27, 28, 29, 30,

	31, 32, 33, 34,
	35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,

	67, 68, 69, 70,

	1,
	1, 0, 1, 0,
}

var little = []byte{
	1,
	3, 2,
	7, 6, 5, 4,
	15, 14, 13, 12, 11, 10, 9, 8,
	16,
	18, 17,
	22, 21, 20, 19,
	30, 29, 28, 27, 26, 25, 24, 23,

	34, 33, 32, 31,
	42, 41, 40, 39, 38, 37, 36, 35,
	46, 45, 44, 43, 50, 49, 48, 47,
	58, 57, 56, 55, 54, 53, 52, 51, 66, 65, 64, 63, 62, 61, 60, 59,

	67, 68, 69, 70,

	1,
	1, 0, 1, 0,
}

var src = []byte{1, 2, 3, 4, 5, 6, 7, 8}
var res = []int32{0x01020304, 0x05060708}
var putbuf = []byte{0, 0, 0, 0, 0, 0, 0, 0}

func checkResult(t *testing.T, dir string, order ByteOrder, err error, have, want any) {
	t.Helper()
	if err != nil {
		t.Errorf("%v %v: %v", dir, order, err)
		return
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("%v %v:\n\thave %+v\n\twant %+v", dir, order, have, want)
	}
}

var encoders = []struct {
	name string
	fn   func(order ByteOrder, data any) ([]byte, error)
}{
	{
		"Write",
		func(order ByteOrder, data any) ([]byte, error) {
			buf := new(bytes.Buffer)
			err := Write(buf, order, data)
			return buf.Bytes(), err
		},
	},
	{
		"Encode",
		func(order ByteOrder, data any) ([]byte, error) {
			size := Size(data)

			var buf []byte
			if size > 0 {
				buf = make([]byte, Size(data))
			}

			n, err := Encode(buf, order, data)
			if err == nil && n != size {
				return nil, fmt.Errorf("returned size %d instead of %d", n, size)
			}
			return buf, err
		},
	}, {
		"Append",
		func(order ByteOrder, data any) ([]byte, error) {
			return Append(nil, order, data)
		},
	},
}

var decoders = []struct {
	name string
	fn   func(order ByteOrder, data any, buf []byte) error
}{
	{
		"Read",
		func(order ByteOrder, data any, buf []byte) error {
			return Read(bytes.NewReader(buf), order, data)
		},
	},
	{
		"Decode",
		func(order ByteOrder, data any, buf []byte) error {
			n, err := Decode(buf, order, data)
			if err == nil && n != Size(data) {
				return fmt.Errorf("returned size %d instead of %d", n, Size(data))
			}
			return err
		},
	},
}

func testRead(t *testing.T, order ByteOrder, b []byte, s1 any) {
	t.Helper()
	for _, dec := range decoders {
		t.Run(dec.name, func(t *testing.T) {
			var s2 Struct
			err := dec.fn(order, &s2, b)
			checkResult(t, dec.name, order, err, s2, s1)
		})
	}
}

func testWrite(t *testing.T, order ByteOrder, b []byte, s1 any) {
	t.Helper()
	for _, enc := range encoders {
		t.Run(enc.name, func(t *testing.T) {
			buf, err := enc.fn(order, s1)
			checkResult(t, enc.name, order, err, buf, b)
		})
	}
}

func TestLittleEndianRead(t *testing.T)     { testRead(t, LittleEndian, little, s) }
func TestLittleEndianWrite(t *testing.T)    { testWrite(t, LittleEndian, little, s) }
func TestLittleEndianPtrWrite(t *testing.T) { testWrite(t, LittleEndian, little, &s) }

func TestBigEndianRead(t *testing.T)     { testRead(t, BigEndian, big, s) }
func TestBigEndianWrite(t *testing.T)    { testWrite(t, BigEndian, big, s) }
func TestBigEndianPtrWrite(t *testing.T) { testWrite(t, BigEndian, big, &s) }

func TestReadSlice(t *testing.T) {
	t.Run("Read", func(t *testing.T) {
		slice := make([]int32, 2)
		err := Read(bytes.NewReader(src), BigEndian, slice)
		checkResult(t, "ReadSlice", BigEndian, err, slice, res)
	})

	t.Run("Decode", func(t *testing.T) {
		slice := make([]int32, 2)
		_, err := Decode(src, BigEndian, slice)
		checkResult(t, "ReadSlice", BigEndian, err, slice, res)
	})
}

func TestWriteSlice(t *testing.T) {
	testWrite(t, BigEndian, src, res)
}

func TestReadBool(t *testing.T) {
	for _, dec := range decoders {
		t.Run(dec.name, func(t *testing.T) {
			var res bool
			var err error
			err = dec.fn(BigEndian, &res, []byte{0})
			checkResult(t, dec.name, BigEndian, err, res, false)
			res = false
			err = dec.fn(BigEndian, &res, []byte{1})
			checkResult(t, dec.name, BigEndian, err, res, true)
			res = false
			err = dec.fn(BigEndian, &res, []byte{2})
			checkResult(t, dec.name, BigEndian, err, res, true)
		})
	}

}

func TestReadBoolSlice(t *testing.T) {
	for _, dec := range decoders {
		t.Run(dec.name, func(t *testing.T) {
			slice := make([]bool, 4)
			err := dec.fn(BigEndian, slice, []byte{0, 1, 2, 255})
			checkResult(t, dec.name, BigEndian, err, slice, []bool{false, true, true, true})
		})
	}
}

// Addresses of arrays are easier to manipulate with reflection than are slices.
var intArrays = []any{
	&[100]int8{},
	&[100]int16{},
	&[100]int32{},
	&[100]int64{},
	&[100]uint8{},
	&[100]uint16{},
	&[100]uint32{},
	&[100]uint64{},
}

func TestSliceRoundTrip(t *testing.T) {
	for _, enc := range encoders {
		for _, dec := range decoders {
			t.Run(fmt.Sprintf("%s,%s", enc.name, dec.name), func(t *testing.T) {
				for _, array := range intArrays {
					src := reflect.ValueOf(array).Elem()
					t.Run(src.Index(0).Type().Name(), func(t *testing.T) {
						unsigned := false
						switch src.Index(0).Kind() {
						case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
							unsigned = true
						}
						for i := 0; i < src.Len(); i++ {
							if unsigned {
								src.Index(i).SetUint(uint64(i * 0x07654321))
							} else {
								src.Index(i).SetInt(int64(i * 0x07654321))
							}
						}
						srcSlice := src.Slice(0, src.Len())
						buf, err := enc.fn(BigEndian, srcSlice.Interface())
						if err != nil {
							t.Fatal(err)
						}
						dst := reflect.New(src.Type()).Elem()
						dstSlice := dst.Slice(0, dst.Len())
						err = dec.fn(BigEndian, dstSlice.Interface(), buf)
						if err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(src.Interface(), dst.Interface()) {
							t.Log(dst)
							t.Fatal(src)
						}
					})
				}
			})
		}
	}
}

func TestWriteT(t *testing.T) {
	for _, enc := range encoders {
		t.Run(enc.name, func(t *testing.T) {
			ts := T{}
			if _, err := enc.fn(BigEndian, ts); err == nil {
				t.Errorf("WriteT: have err == nil, want non-nil")
			}

			tv := reflect.Indirect(reflect.ValueOf(ts))
			for i, n := 0, tv.NumField(); i < n; i++ {
				typ := tv.Field(i).Type().String()
				if typ == "[4]int" {
					typ = "int" // the problem is int, not the [4]
				}
				if _, err := enc.fn(BigEndian, tv.Field(i).Interface()); err == nil {
					t.Errorf("WriteT.%v: have err == nil, want non-nil", tv.Field(i).Type())
				} else if !strings.Contains(err.Error(), typ) {
					t.Errorf("WriteT: have err == %q, want it to mention %s", err, typ)
				}
			}
		})
	}
}

type BlankFields struct {
	A uint32
	_ int32
	B float64
	_ [4]int16
	C byte
	_ [7]byte
	_ struct {
		f [8]float32
	}
}

type BlankFieldsProbe struct {
	A  uint32
	P0 int32
	B  float64
	P1 [4]int16
	C  byte
	P2 [7]byte
	P3 struct {
		F [8]float32
	}
}

func TestBlankFields(t *testing.T) {
	for _, enc := range encoders {
		t.Run(enc.name, func(t *testing.T) {
			b1 := BlankFields{A: 1234567890, B: 2.718281828, C: 42}
			buf, err := enc.fn(LittleEndian, &b1)
			if err != nil {
				t.Error(err)
			}

			// zero values must have been written for blank fields
			var p BlankFieldsProbe
			if err := Read(bytes.NewReader(buf), LittleEndian, &p); err != nil {
				t.Error(err)
			}

			// quick test: only check first value of slices
			if p.P0 != 0 || p.P1[0] != 0 || p.P2[0] != 0 || p.P3.F[0] != 0 {
				t.Errorf("non-zero values for originally blank fields: %#v", p)
			}

			// write p and see if we can probe only some fields
			buf, err = enc.fn(LittleEndian, &p)
			if err != nil {
				t.Error(err)
			}

			// read should ignore blank fields in b2
			var b2 BlankFields
			if err := Read(bytes.NewReader(buf), LittleEndian, &b2); err != nil {
				t.Error(err)
			}
			if b1.A != b2.A || b1.B != b2.B || b1.C != b2.C {
				t.Errorf("%#v != %#v", b1, b2)
			}
		})
	}
}

func TestSizeStructCache(t *testing.T) {
	// Reset the cache, otherwise multiple test runs fail.
	structSize = sync.Map{}

	count := func() int {
		var i int
		structSize.Range(func(_, _ any) bool {
			i++
			return true
		})
		return i
	}

	var total int
	added := func() int {
		delta := count() - total
		total += delta
		return delta
	}

	type foo struct {
		A uint32
	}

	type bar struct {
		A Struct
		B foo
		C Struct
	}

	testcases := []struct {
		val  any
		want int
	}{
		{new(foo), 1},
		{new([1]foo), 0},
		{make([]foo, 1), 0},
		{new(bar), 1},
		{new(bar), 0},
		{new(struct{ A Struct }), 1},
		{new(struct{ A Struct }), 0},
		{new([1]struct{ A Struct }), 0},
		{make([]struct{ A Struct }, 1), 0},
	}

	for _, tc := range testcases {
		if Size(tc.val) == -1 {
			t.Fatalf("Can't get the size of %T", tc.val)
		}

		if n := added(); n != tc.want {
			t.Errorf("Sizing %T added %d entries to the cache, want %d", tc.val, n, tc.want)
		}
	}
}

func TestSizeInvalid(t *testing.T) {
	testcases := []any{
		int(0),
		new(int),
		(*int)(nil),
		[1]uint{},
		new([1]uint),
		(*[1]uint)(nil),
		[]int{},
		[]int(nil),
		new([]int),
		(*[]int)(nil),
		(*int8)(nil),
		(*uint8)(nil),
		(*int16)(nil),
		(*uint16)(nil),
		(*int32)(nil),
		(*uint32)(nil),
		(*int64)(nil),
		(*uint64)(nil),
		(*float32)(nil),
		(*float64)(nil),
		(*complex64)(nil),
		(*complex128)(nil),
	}
	for _, tc := range testcases {
		if got := Size(tc); got != -1 {
			t.Errorf("Size(%T) = %d, want -1", tc, got)
		}
	}
}

// An attempt to read into a struct with an unexported field will
// panic. This is probably not the best choice, but at this point
// anything else would be an API change.

type Unexported struct {
	a int32
}

func TestUnexportedRead(t *testing.T) {
	var buf bytes.Buffer
	u1 := Unexported{a: 1}
	if err := Write(&buf, LittleEndian, &u1); err != nil {
		t.Fatal(err)
	}

	for _, dec := range decoders {
		t.Run(dec.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("did not panic")
				}
			}()
			var u2 Unexported
			dec.fn(LittleEndian, &u2, buf.Bytes())
		})
	}

}

func TestReadErrorMsg(t *testing.T) {
	for _, dec := range decoders {
		t.Run(dec.name, func(t *testing.T) {
			read := func(data any) {
				err := dec.fn(LittleEndian, data, nil)
				want := fmt.Sprintf("binary.%s: invalid type %s", dec.name, reflect.TypeOf(data).String())
				if err == nil {
					t.Errorf("%T: got no error; want %q", data, want)
					return
				}
				if got := err.Error(); got != want {
					t.Errorf("%T: got %q; want %q", data, got, want)
				}
			}
			read(0)
			s := new(struct{})
			read(&s)
			p := &s
			read(&p)
		})
	}
}

func TestReadTruncated(t *testing.T) {
	const data = "0123456789abcdef"

	var b1 = make([]int32, 4)
	var b2 struct {
		A, B, C, D byte
		E          int32
		F          float64
	}

	for i := 0; i <= len(data); i++ {
		var errWant error
		switch i {
		case 0:
			errWant = io.EOF
		case len(data):
			errWant = nil
		default:
			errWant = io.ErrUnexpectedEOF
		}

		if err := Read(strings.NewReader(data[:i]), LittleEndian, &b1); err != errWant {
			t.Errorf("Read(%d) with slice: got %v, want %v", i, err, errWant)
		}
		if err := Read(strings.NewReader(data[:i]), LittleEndian, &b2); err != errWant {
			t.Errorf("Read(%d) with struct: got %v, want %v", i, err, errWant)
		}
	}
}

func testUint64SmallSliceLengthPanics() (panicked bool) {
	defer func() {
		panicked = recover() != nil
	}()
	b := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	LittleEndian.Uint64(b[:4])
	return false
}

func testPutUint64SmallSliceLengthPanics() (panicked bool) {
	defer func() {
		panicked = recover() != nil
	}()
	b := [8]byte{}
	LittleEndian.PutUint64(b[:4], 0x0102030405060708)
	return false
}

func TestByteOrder(t *testing.T) {
	type byteOrder interface {
		ByteOrder
		AppendByteOrder
	}
	buf := make([]byte, 8)
	for _, order := range []byteOrder{LittleEndian, BigEndian} {
		const offset = 3
		for _, value := range []uint64{
			0x0000000000000000,
			0x0123456789abcdef,
			0xfedcba9876543210,
			0xffffffffffffffff,
			0xaaaaaaaaaaaaaaaa,
			math.Float64bits(math.Pi),
			math.Float64bits(math.E),
		} {
			want16 := uint16(value)
			order.PutUint16(buf[:2], want16)
			if got := order.Uint16(buf[:2]); got != want16 {
				t.Errorf("PutUint16: Uint16 = %v, want %v", got, want16)
			}
			buf = order.AppendUint16(buf[:offset], want16)
			if got := order.Uint16(buf[offset:]); got != want16 {
				t.Errorf("AppendUint16: Uint16 = %v, want %v", got, want16)
			}
			if len(buf) != offset+2 {
				t.Errorf("AppendUint16: len(buf) = %d, want %d", len(buf), offset+2)
			}

			want32 := uint32(value)
			order.PutUint32(buf[:4], want32)
			if got := order.Uint32(buf[:4]); got != want32 {
				t.Errorf("PutUint32: Uint32 = %v, want %v", got, want32)
			}
			buf = order.AppendUint32(buf[:offset], want32)
			if got := order.Uint32(buf[offset:]); got != want32 {
				t.Errorf("AppendUint32: Uint32 = %v, want %v", got, want32)
			}
			if len(buf) != offset+4 {
				t.Errorf("AppendUint32: len(buf) = %d, want %d", len(buf), offset+4)
			}

			want64 := uint64(value)
			order.PutUint64(buf[:8], want64)
			if got := order.Uint64(buf[:8]); got != want64 {
				t.Errorf("PutUint64: Uint64 = %v, want %v", got, want64)
			}
			buf = order.AppendUint64(buf[:offset], want64)
			if got := order.Uint64(buf[offset:]); got != want64 {
				t.Errorf("AppendUint64: Uint64 = %v, want %v", got, want64)
			}
			if len(buf) != offset+8 {
				t.Errorf("AppendUint64: len(buf) = %d, want %d", len(buf), offset+8)
			}
		}
	}
}

func TestEarlyBoundsChecks(t *testing.T) {
	if testUint64SmallSliceLengthPanics() != true {
		t.Errorf("binary.LittleEndian.Uint64 expected to panic for small slices, but didn't")
	}
	if testPutUint64SmallSliceLengthPanics() != true {
		t.Errorf("binary.LittleEndian.PutUint64 expected to panic for small slices, but didn't")
	}
}

func TestReadInvalidDestination(t *testing.T) {
	testReadInvalidDestination(t, BigEndian)
	testReadInvalidDestination(t, LittleEndian)
}

func testReadInvalidDestination(t *testing.T, order ByteOrder) {
	destinations := []any{
		int8(0),
		int16(0),
		int32(0),
		int64(0),

		uint8(0),
		uint16(0),
		uint32(0),
		uint64(0),

		bool(false),
	}

	for _, dst := range destinations {
		err := Read(bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8}), order, dst)
		want := fmt.Sprintf("binary.Read: invalid type %T", dst)
		if err == nil || err.Error() != want {
			t.Fatalf("for type %T: got %q; want %q", dst, err, want)
		}
	}
}

func TestNoFixedSize(t *testing.T) {
	type Person struct {
		Age    int
		Weight float64
		Height float64
	}

	person := Person{
		Age:    27,
		Weight: 67.3,
		Height: 177.8,
	}

	for _, enc := range encoders {
		t.Run(enc.name, func(t *testing.T) {
			_, err := enc.fn(LittleEndian, &person)
			if err == nil {
				t.Fatalf("binary.%s: unexpected success as size of type *binary.Person is not fixed", enc.name)
			}
			errs := fmt.Sprintf("binary.%s: some values are not fixed-sized in type *binary.Person", enc.name)
			if err.Error() != errs {
				t.Fatalf("got %q, want %q", err, errs)
			}
		})
	}
}

func TestAppendAllocs(t *testing.T) {
	if asan.Enabled {
		t.Skip("test allocates more with -asan; see #70079")
	}
	buf := make([]byte, 0, Size(&s))
	var err error
	allocs := testing.AllocsPerRun(1, func() {
		_, err = Append(buf, LittleEndian, &s)
	})
	if err != nil {
		t.Fatal("Append failed:", err)
	}
	if allocs != 0 {
		t.Fatalf("Append allocated %v times instead of not allocating at all", allocs)
	}
}

var sizableTypes = []any{
	bool(false),
	int8(0),
	int16(0),
	int32(0),
	int64(0),
	uint8(0),
	uint16(0),
	uint32(0),
	uint64(0),
	float32(0),
	float64(0),
	complex64(0),
	complex128(0),
	Struct{},
	&Struct{},
	[]Struct{},
	([]Struct)(nil),
	[1]Struct{},
}

func TestSizeAllocs(t *testing.T) {
	if asan.Enabled {
		t.Skip("test allocates more with -asan; see #70079")
	}
	for _, data := range sizableTypes {
		t.Run(fmt.Sprintf("%T", data), func(t *testing.T) {
			// Size uses a sync.Map behind the scenes. The slow lookup path of
			// that does allocate, so we need a couple of runs here to be
			// allocation free.
			allocs := testing.AllocsPerRun(10, func() {
				_ = Size(data)
			})
			if allocs != 0 {
				t.Fatalf("Expected no allocations, got %v", allocs)
			}
		})
	}
}

type byteSliceReader struct {
	remain []byte
}

func (br *byteSliceReader) Read(p []byte) (int, error) {
	n := copy(p, br.remain)
	br.remain = br.remain[n:]
	return n, nil
}

func BenchmarkReadSlice1000Int32s(b *testing.B) {
	bsr := &byteSliceReader{}
	slice := make([]int32, 1000)
	buf := make([]byte, len(slice)*4)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bsr.remain = buf
		Read(bsr, BigEndian, slice)
	}
}

func BenchmarkReadStruct(b *testing.B) {
	bsr := &byteSliceReader{}
	var buf bytes.Buffer
	Write(&buf, BigEndian, &s)
	b.SetBytes(int64(dataSize(reflect.ValueOf(s))))
	t := s
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bsr.remain = buf.Bytes()
		Read(bsr, BigEndian, &t)
	}
	b.StopTimer()
	if b.N > 0 && !reflect.DeepEqual(s, t) {
		b.Fatalf("struct doesn't match:\ngot  %v;\nwant %v", t, s)
	}
}

func BenchmarkWriteStruct(b *testing.B) {
	b.SetBytes(int64(Size(&s)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Write(io.Discard, BigEndian, &s)
	}
}

func BenchmarkAppendStruct(b *testing.B) {
	buf := make([]byte, 0, Size(&s))
	b.SetBytes(int64(cap(buf)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Encode(buf, BigEndian, &s)
	}
}

func BenchmarkWriteSlice1000Structs(b *testing.B) {
	slice := make([]Struct, 1000)
	buf := new(bytes.Buffer)
	var w io.Writer = buf
	b.SetBytes(int64(Size(slice)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		Write(w, BigEndian, slice)
	}
	b.StopTimer()
}

func BenchmarkAppendSlice1000Structs(b *testing.B) {
	slice := make([]Struct, 1000)
	buf := make([]byte, 0, Size(slice))
	b.SetBytes(int64(cap(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Append(buf, BigEndian, slice)
	}
	b.StopTimer()
}

func BenchmarkReadSlice1000Structs(b *testing.B) {
	bsr := &byteSliceReader{}
	slice := make([]Struct, 1000)
	buf := make([]byte, Size(slice))
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bsr.remain = buf
		Read(bsr, BigEndian, slice)
	}
}

func BenchmarkReadInts(b *testing.B) {
	var ls Struct
	bsr := &byteSliceReader{}
	var r io.Reader = bsr
	b.SetBytes(2 * (1 + 2 + 4 + 8))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bsr.remain = big
		Read(r, BigEndian, &ls.Int8)
		Read(r, BigEndian, &ls.Int16)
		Read(r, BigEndian, &ls.Int32)
		Read(r, BigEndian, &ls.Int64)
		Read(r, BigEndian, &ls.Uint8)
		Read(r, BigEndian, &ls.Uint16)
		Read(r, BigEndian, &ls.Uint32)
		Read(r, BigEndian, &ls.Uint64)
	}
	b.StopTimer()
	want := s
	want.Float32 = 0
	want.Float64 = 0
	want.Complex64 = 0
	want.Complex128 = 0
	want.Array = [4]uint8{0, 0, 0, 0}
	want.Bool = false
	want.BoolArray = [4]bool{false, false, false, false}
	if b.N > 0 && !reflect.DeepEqual(ls, want) {
		b.Fatalf("struct doesn't match:\ngot  %v;\nwant %v", ls, want)
	}
}

func BenchmarkWriteInts(b *testing.B) {
	buf := new(bytes.Buffer)
	var w io.Writer = buf
	b.SetBytes(2 * (1 + 2 + 4 + 8))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		Write(w, BigEndian, s.Int8)
		Write(w, BigEndian, s.Int16)
		Write(w, BigEndian, s.Int32)
		Write(w, BigEndian, s.Int64)
		Write(w, BigEndian, s.Uint8)
		Write(w, BigEndian, s.Uint16)
		Write(w, BigEndian, s.Uint32)
		Write(w, BigEndian, s.Uint64)
	}
	b.StopTimer()
	if b.N > 0 && !bytes.Equal(buf.Bytes(), big[:30]) {
		b.Fatalf("first half doesn't match: %x %x", buf.Bytes(), big[:30])
	}
}

func BenchmarkAppendInts(b *testing.B) {
	buf := make([]byte, 0, 256)
	b.SetBytes(2 * (1 + 2 + 4 + 8))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = buf[:0]
		buf, _ = Append(buf, BigEndian, s.Int8)
		buf, _ = Append(buf, BigEndian, s.Int16)
		buf, _ = Append(buf, BigEndian, s.Int32)
		buf, _ = Append(buf, BigEndian, s.Int64)
		buf, _ = Append(buf, BigEndian, s.Uint8)
		buf, _ = Append(buf, BigEndian, s.Uint16)
		buf, _ = Append(buf, BigEndian, s.Uint32)
		buf, _ = Append(buf, BigEndian, s.Uint64)
	}
	b.StopTimer()
	if b.N > 0 && !bytes.Equal(buf, big[:30]) {
		b.Fatalf("first half doesn't match: %x %x", buf, big[:30])
	}
}

func BenchmarkWriteSlice1000Int32s(b *testing.B) {
	slice := make([]int32, 1000)
	buf := new(bytes.Buffer)
	var w io.Writer = buf
	b.SetBytes(4 * 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		Write(w, BigEndian, slice)
	}
	b.StopTimer()
}

func BenchmarkAppendSlice1000Int32s(b *testing.B) {
	slice := make([]int32, 1000)
	buf := make([]byte, 0, Size(slice))
	b.SetBytes(int64(cap(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Append(buf, BigEndian, slice)
	}
	b.StopTimer()
}

func BenchmarkPutUint16(b *testing.B) {
	b.SetBytes(2)
	for i := 0; i < b.N; i++ {
		BigEndian.PutUint16(putbuf[:2], uint16(i))
	}
}

func BenchmarkAppendUint16(b *testing.B) {
	b.SetBytes(2)
	for i := 0; i < b.N; i++ {
		putbuf = BigEndian.AppendUint16(putbuf[:0], uint16(i))
	}
}

func BenchmarkPutUint32(b *testing.B) {
	b.SetBytes(4)
	for i := 0; i < b.N; i++ {
		BigEndian.PutUint32(putbuf[:4], uint32(i))
	}
}

func BenchmarkAppendUint32(b *testing.B) {
	b.SetBytes(4)
	for i := 0; i < b.N; i++ {
		putbuf = BigEndian.AppendUint32(putbuf[:0], uint32(i))
	}
}

func BenchmarkPutUint64(b *testing.B) {
	b.SetBytes(8)
	for i := 0; i < b.N; i++ {
		BigEndian.PutUint64(putbuf[:8], uint64(i))
	}
}

func BenchmarkAppendUint64(b *testing.B) {
	b.SetBytes(8)
	for i := 0; i < b.N; i++ {
		putbuf = BigEndian.AppendUint64(putbuf[:0], uint64(i))
	}
}

func BenchmarkLittleEndianPutUint16(b *testing.B) {
	b.SetBytes(2)
	for i := 0; i < b.N; i++ {
		LittleEndian.PutUint16(putbuf[:2], uint16(i))
	}
}

func BenchmarkLittleEndianAppendUint16(b *testing.B) {
	b.SetBytes(2)
	for i := 0; i < b.N; i++ {
		putbuf = LittleEndian.AppendUint16(putbuf[:0], uint16(i))
	}
}

func BenchmarkLittleEndianPutUint32(b *testing.B) {
	b.SetBytes(4)
	for i := 0; i < b.N; i++ {
		LittleEndian.PutUint32(putbuf[:4], uint32(i))
	}
}

func BenchmarkLittleEndianAppendUint32(b *testing.B) {
	b.SetBytes(4)
	for i := 0; i < b.N; i++ {
		putbuf = LittleEndian.AppendUint32(putbuf[:0], uint32(i))
	}
}

func BenchmarkLittleEndianPutUint64(b *testing.B) {
	b.SetBytes(8)
	for i := 0; i < b.N; i++ {
		LittleEndian.PutUint64(putbuf[:8], uint64(i))
	}
}

func BenchmarkLittleEndianAppendUint64(b *testing.B) {
	b.SetBytes(8)
	for i := 0; i < b.N; i++ {
		putbuf = LittleEndian.AppendUint64(putbuf[:0], uint64(i))
	}
}

func BenchmarkReadFloats(b *testing.B) {
	var ls Struct
	bsr := &byteSliceReader{}
	var r io.Reader = bsr
	b.SetBytes(4 + 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bsr.remain = big[30:]
		Read(r, BigEndian, &ls.Float32)
		Read(r, BigEndian, &ls.Float64)
	}
	b.StopTimer()
	want := s
	want.Int8 = 0
	want.Int16 = 0
	want.Int32 = 0
	want.Int64 = 0
	want.Uint8 = 0
	want.Uint16 = 0
	want.Uint32 = 0
	want.Uint64 = 0
	want.Complex64 = 0
	want.Complex128 = 0
	want.Array = [4]uint8{0, 0, 0, 0}
	want.Bool = false
	want.BoolArray = [4]bool{false, false, false, false}
	if b.N > 0 && !reflect.DeepEqual(ls, want) {
		b.Fatalf("struct doesn't match:\ngot  %v;\nwant %v", ls, want)
	}
}

func BenchmarkWriteFloats(b *testing.B) {
	buf := new(bytes.Buffer)
	var w io.Writer = buf
	b.SetBytes(4 + 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		Write(w, BigEndian, s.Float32)
		Write(w, BigEndian, s.Float64)
	}
	b.StopTimer()
	if b.N > 0 && !bytes.Equal(buf.Bytes(), big[30:30+4+8]) {
		b.Fatalf("first half doesn't match: %x %x", buf.Bytes(), big[30:30+4+8])
	}
}

func BenchmarkReadSlice1000Float32s(b *testing.B) {
	bsr := &byteSliceReader{}
	slice := make([]float32, 1000)
	buf := make([]byte, len(slice)*4)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bsr.remain = buf
		Read(bsr, BigEndian, slice)
	}
}

func BenchmarkWriteSlice1000Float32s(b *testing.B) {
	slice := make([]float32, 1000)
	buf := new(bytes.Buffer)
	var w io.Writer = buf
	b.SetBytes(4 * 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		Write(w, BigEndian, slice)
	}
	b.StopTimer()
}

func BenchmarkReadSlice1000Uint8s(b *testing.B) {
	bsr := &byteSliceReader{}
	slice := make([]uint8, 1000)
	buf := make([]byte, len(slice))
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bsr.remain = buf
		Read(bsr, BigEndian, slice)
	}
}

func BenchmarkWriteSlice1000Uint8s(b *testing.B) {
	slice := make([]uint8, 1000)
	buf := new(bytes.Buffer)
	var w io.Writer = buf
	b.SetBytes(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		Write(w, BigEndian, slice)
	}
}

func BenchmarkSize(b *testing.B) {
	for _, data := range sizableTypes {
		b.Run(fmt.Sprintf("%T", data), func(b *testing.B) {
			for range b.N {
				_ = Size(data)
			}
		})
	}
}

func TestNativeEndian(t *testing.T) {
	const val = 0x12345678
	i := uint32(val)
	s := unsafe.Slice((*byte)(unsafe.Pointer(&i)), unsafe.Sizeof(i))
	if v := NativeEndian.Uint32(s); v != val {
		t.Errorf("NativeEndian.Uint32 returned %#x, expected %#x", v, val)
	}
}

"""



```