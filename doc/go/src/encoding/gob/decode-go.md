Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the provided Go code snippet's functionality. It also hints at identifying the larger Go feature this code is part of and providing examples.

2. **Identify the Core Package:** The `package gob` declaration immediately tells me this code is part of the `encoding/gob` package. This is crucial context.

3. **Scan for Key Data Structures and Functions:** I'll quickly skim the code looking for prominent types, functions, and variables. This helps establish the overall structure and purpose. I notice:
    * `decoderState`, `decBuffer`:  These look like they manage the state and buffer during the decoding process.
    * `decodeUint`, `decodeInt`: These clearly handle reading encoded integers.
    * `decOp`, `decInstr`, `decEngine`: These suggest a kind of instruction-based decoding mechanism.
    * Functions like `decBool`, `decInt8`, `decString`: These are specific decoders for different Go types.
    * `decodeSingle`, `decodeStruct`, `decodeArray`, `decodeMap`, `decodeSlice`, `decodeInterface`: These look like top-level decoding functions for various Go data structures.
    * `ignore...` functions: These probably handle skipping data when the decoder doesn't have a destination.
    * `decOpFor`, `decIgnoreOpFor`: These suggest the logic for selecting the correct decoding operation based on the data type.

4. **Infer the High-Level Functionality:** Based on the package name and the identified elements, I can infer that this code is responsible for *decoding* data encoded using the `encoding/gob` package. The presence of different decoding functions for various types reinforces this. The `ignore...` functions suggest the ability to skip over data when needed, which is common in deserialization scenarios.

5. **Focus on the Request's Specific Points:**
    * **List the functions:**  I'll go back and list the major functions, grouping them by related purpose (e.g., decoding primitives, handling structs, etc.).
    * **Infer the Go feature:** The `encoding/gob` package's purpose is to provide a way to serialize and deserialize Go data structures. This snippet is clearly the *deserialization* part.
    * **Provide a Go code example:**  To illustrate `encoding/gob`, I'll create a simple struct, encode it using `gob.NewEncoder`, and then demonstrate the decoding process using `gob.NewDecoder`. This provides a clear practical context. I need to include the necessary `import "encoding/gob"` and  `import "bytes"` statements.
    * **Code inference (with input/output):**  The `decodeUint` function is a good example for this. I can illustrate how it reads a variable-length encoded unsigned integer from the buffer. I'll provide an example input byte slice and the expected output `uint64` value.
    * **Command-line arguments:**  Based on the code, I see no direct interaction with command-line arguments. The `gob` package typically works with `io.Reader` and `io.Writer`. So, I'll state that there are no direct command-line argument processing in this particular snippet.
    * **Common mistakes:**  A common mistake when using `encoding/gob` is forgetting to register custom types with `gob.Register`. This is essential for decoding interfaces and custom struct types correctly. I'll provide an example of this error and how to fix it.

6. **Structure the Answer:** I'll organize the answer into clear sections based on the request's points. Using headings and bullet points will make the information easy to read.

7. **Refine and Elaborate:** I'll review my initial thoughts and add more details where needed. For instance, explaining the variable-length encoding scheme used in `decodeUint` adds valuable information. I'll also make sure the code examples are correct and runnable. I need to explain the `decoderState` and `decBuffer` roles more clearly.

8. **Address the "Part 1" Instruction:** Finally, I'll specifically address the "Part 1, 共 2 部分，请归纳一下它的功能" by summarizing the overall function of the code snippet at the end.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate response that addresses all aspects of the user's request. The key is to start with the high-level context and then delve into the specifics, using the provided code as the primary source of information.
好的，让我们来分析一下这段Go语言代码的功能。

**功能归纳 (第1部分)**

这段代码是 `encoding/gob` 包中负责解码 (deserialization) 功能的核心部分。它定义了解码器 (`Decoder`) 的内部状态、缓冲区管理以及各种数据类型的解码操作。 主要功能可以归纳为：

1. **解码器状态管理:**
   - 定义了 `decoderState` 结构体，用于跟踪解码过程中的状态，包括当前的解码器实例、缓冲区、读取的字段编号等。
   - 提供了 `newDecoderState` 和 `freeDecoderState` 方法来管理 `decoderState` 对象的创建和回收，使用了 free list 来提高效率。

2. **解码缓冲区管理:**
   - 定义了 `decBuffer` 结构体，实现了一个简单的只读字节缓冲区，用于从输入流中读取数据。
   - 提供了 `Read`、`ReadByte`、`Drop`、`Len`、`Bytes`、`SetBytes` 和 `Reset` 等方法来操作缓冲区。

3. **基础数据类型解码:**
   - 实现了 `decodeUintReader` 和 `decodeUint` 函数，用于从 `io.Reader` 或 `decBuffer` 中读取变长的无符号整数。这是 `gob` 编码格式的基础。
   - 实现了 `decodeInt` 函数，用于解码有符号整数。
   - 实现了 `getLength` 函数，用于读取表示数据长度的无符号整数，并进行一些安全检查。

4. **解码操作的抽象:**
   - 定义了 `decOp` 类型，表示一个解码操作的函数签名。
   - 定义了 `decInstr` 结构体，表示一个解码指令，包含了解码操作、字段编号、目标类型的字段索引以及溢出错误信息。

5. **特定类型解码函数:**
   - 实现了针对不同 Go 基础类型的解码函数，例如 `decBool`、`decInt8`、`decUint8`、`decInt16` 等，它们都接收一个 `decInstr` 和 `decoderState`，并更新 `reflect.Value` 表示的目标值。
   - 特别地，针对浮点数 (`decFloat32`, `decFloat64`) 和复数 (`decComplex64`, `decComplex128`)，解码时会进行字节反转，这是 `gob` 编码格式的特点，以提高某些情况下的压缩率。
   - 针对 `[]byte` (`decUint8Slice`) 和 `string` (`decString`)，解码时会先读取长度，然后读取实际的数据。

6. **解码引擎:**
   - 定义了 `decEngine` 结构体，它包含一个 `decInstr` 数组，表示解码的指令序列。
   - 实现了 `decodeSingle` 和 `decodeStruct` 函数，用于解码顶层的非结构体值和结构体值。结构体的解码是基于字段编号的增量 (delta) 进行的。

7. **忽略数据:**
   - 提供了 `ignoreUint`、`ignoreTwoUints`、`ignoreUint8Array`、`ignoreStruct` 和 `ignoreSingle` 等函数，用于在没有目标值时跳过编码的数据。

8. **数组和切片解码:**
   - 实现了 `decodeArrayHelper`、`decodeArray` 和 `decodeSlice` 函数，用于解码数组和切片。解码时会先读取长度信息。

9. **Map 解码:**
   - 实现了 `decodeMap` 函数，用于解码 map。解码时会先读取 map 的长度，然后逐个解码键值对。

10. **接口解码:**
    - 实现了 `decodeInterface` 函数，用于解码接口类型。接口在编码时会包含具体类型的名称和值。

11. **实现了 `GobDecoder` 接口的类型解码:**
    - 实现了 `decodeGobDecoder` 函数，用于解码实现了 `encoding/gob.GobDecoder`、`encoding.BinaryUnmarshaler` 或 `encoding.TextUnmarshaler` 接口的类型。这些类型会将其数据编码为字节切片。

**它是什么go语言功能的实现？**

这段代码是 Go 语言标准库 `encoding/gob` 包中 **解码 (deserialization)** 功能的具体实现。 `encoding/gob` 提供了一种将 Go 数据结构进行序列化和反序列化的机制，类似于 Java 的 `ObjectOutputStream`/`ObjectInputStream` 或 Python 的 `pickle` 模块。

**Go 代码举例说明:**

```go
package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
)

// 定义一个需要编码和解码的结构体
type Person struct {
	Name string
	Age  int
}

func main() {
	// 创建一个 Person 实例
	p := Person{Name: "Alice", Age: 30}

	// 编码
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(p)
	if err != nil {
		log.Fatal("encode error:", err)
	}

	fmt.Printf("Encoded data: %x\n", buf.Bytes())

	// 解码
	var decodedPerson Person
	dec := gob.NewDecoder(&buf)
	err = dec.Decode(&decodedPerson)
	if err != nil {
		log.Fatal("decode error:", err)
	}

	fmt.Printf("Decoded person: %+v\n", decodedPerson)
}
```

**假设的输入与输出 (针对 `decodeUint`):**

**假设输入 (字节切片):** `[]byte{0x82, 0x01, 0x02}`

**推理过程:**

1. `decodeUint` 读取第一个字节 `0x82`。
2. 由于该字节大于 `0x7f`，表示这是一个多字节的无符号整数。
3. 计算 `-int8(0x82)`，得到 `-(-126)`，即 `126`。但是，根据 `gob` 的编码规则，当高位被设置时，表示后续的字节数，取反后得到字节数，所以 `-int8(0x82)` 实际上是 `-130`，取负号并减去 256 (因为 int8 是有符号的)，得到 `2`。这表示后面有 2 个字节表示实际的数值。
4. 读取接下来的 2 个字节 `0x01` 和 `0x02`。
5. 将这两个字节组合成一个 `uint64`： `(0 << 8) | 0x01 = 1`,  `(1 << 8) | 0x02 = 258`。
6. 因此，解码后的 `uint64` 值为 `258`。

**预期输出:** `uint64(258)`

**涉及命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。`encoding/gob` 包通常与其他包（如 `net/rpc` 或自定义的网络/文件处理代码）结合使用，那些代码可能会处理命令行参数以确定要序列化或反序列化的数据来源和目标。

**使用者易犯错的点 (虽然代码本身不直接涉及，但与 `gob` 包的使用相关):**

1. **忘记注册自定义类型:** 当使用接口类型或者需要解码到具体的结构体时，必须使用 `gob.Register()` 注册这些类型。否则，解码器无法知道如何构造这些类型的实例。

   ```go
   package main

   import (
   	"bytes"
   	"encoding/gob"
   	"fmt"
   	"log"
   )

   type MyData struct {
   	Value int
   }

   type Container struct {
   	Data interface{} // 使用 interface{}
   }

   func main() {
   	// 假设我们忘记注册 MyData 类型
   	// gob.Register(MyData{})

   	var buf bytes.Buffer
   	enc := gob.NewEncoder(&buf)
   	err := enc.Encode(Container{Data: MyData{Value: 10}})
   	if err != nil {
   		log.Fatal("encode error:", err)
   	}

   	var decodedContainer Container
   	dec := gob.NewDecoder(&buf)
   	err = dec.Decode(&decodedContainer)
   	if err != nil {
   		log.Fatal("decode error:", err)
   	}

   	fmt.Printf("Decoded container: %+v\n", decodedContainer) // Data 的类型可能是 map[string]interface{}
   }
   ```

   **修正方法:** 在 `main` 函数或其他初始化代码中添加 `gob.Register(MyData{})`。

总而言之，这段代码是 `encoding/gob` 包解码功能的核心实现，负责将 `gob` 格式的字节流转换回 Go 语言的数据结构。它处理了各种基本类型、复合类型（如数组、切片、map、结构体和接口）的解码，并提供了一种机制来处理实现了特定接口的自定义类型。

### 提示词
```
这是路径为go/src/encoding/gob/decode.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run decgen.go -output dec_helpers.go

package gob

import (
	"encoding"
	"errors"
	"internal/saferio"
	"io"
	"math"
	"math/bits"
	"reflect"
)

var (
	errBadUint = errors.New("gob: encoded unsigned integer out of range")
	errBadType = errors.New("gob: unknown type id or corrupted data")
	errRange   = errors.New("gob: bad data: field numbers out of bounds")
)

type decHelper func(state *decoderState, v reflect.Value, length int, ovfl error) bool

// decoderState is the execution state of an instance of the decoder. A new state
// is created for nested objects.
type decoderState struct {
	dec *Decoder
	// The buffer is stored with an extra indirection because it may be replaced
	// if we load a type during decode (when reading an interface value).
	b        *decBuffer
	fieldnum int           // the last field number read.
	next     *decoderState // for free list
}

// decBuffer is an extremely simple, fast implementation of a read-only byte buffer.
// It is initialized by calling Size and then copying the data into the slice returned by Bytes().
type decBuffer struct {
	data   []byte
	offset int // Read offset.
}

func (d *decBuffer) Read(p []byte) (int, error) {
	n := copy(p, d.data[d.offset:])
	if n == 0 && len(p) != 0 {
		return 0, io.EOF
	}
	d.offset += n
	return n, nil
}

func (d *decBuffer) Drop(n int) {
	if n > d.Len() {
		panic("drop")
	}
	d.offset += n
}

func (d *decBuffer) ReadByte() (byte, error) {
	if d.offset >= len(d.data) {
		return 0, io.EOF
	}
	c := d.data[d.offset]
	d.offset++
	return c, nil
}

func (d *decBuffer) Len() int {
	return len(d.data) - d.offset
}

func (d *decBuffer) Bytes() []byte {
	return d.data[d.offset:]
}

// SetBytes sets the buffer to the bytes, discarding any existing data.
func (d *decBuffer) SetBytes(data []byte) {
	d.data = data
	d.offset = 0
}

func (d *decBuffer) Reset() {
	d.data = d.data[0:0]
	d.offset = 0
}

// We pass the bytes.Buffer separately for easier testing of the infrastructure
// without requiring a full Decoder.
func (dec *Decoder) newDecoderState(buf *decBuffer) *decoderState {
	d := dec.freeList
	if d == nil {
		d = new(decoderState)
		d.dec = dec
	} else {
		dec.freeList = d.next
	}
	d.b = buf
	return d
}

func (dec *Decoder) freeDecoderState(d *decoderState) {
	d.next = dec.freeList
	dec.freeList = d
}

func overflow(name string) error {
	return errors.New(`value for "` + name + `" out of range`)
}

// decodeUintReader reads an encoded unsigned integer from an io.Reader.
// Used only by the Decoder to read the message length.
func decodeUintReader(r io.Reader, buf []byte) (x uint64, width int, err error) {
	width = 1
	n, err := io.ReadFull(r, buf[0:width])
	if n == 0 {
		return
	}
	b := buf[0]
	if b <= 0x7f {
		return uint64(b), width, nil
	}
	n = -int(int8(b))
	if n > uint64Size {
		err = errBadUint
		return
	}
	width, err = io.ReadFull(r, buf[0:n])
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return
	}
	// Could check that the high byte is zero but it's not worth it.
	for _, b := range buf[0:width] {
		x = x<<8 | uint64(b)
	}
	width++ // +1 for length byte
	return
}

// decodeUint reads an encoded unsigned integer from state.r.
// Does not check for overflow.
func (state *decoderState) decodeUint() (x uint64) {
	b, err := state.b.ReadByte()
	if err != nil {
		error_(err)
	}
	if b <= 0x7f {
		return uint64(b)
	}
	n := -int(int8(b))
	if n > uint64Size {
		error_(errBadUint)
	}
	buf := state.b.Bytes()
	if len(buf) < n {
		errorf("invalid uint data length %d: exceeds input size %d", n, len(buf))
	}
	// Don't need to check error; it's safe to loop regardless.
	// Could check that the high byte is zero but it's not worth it.
	for _, b := range buf[0:n] {
		x = x<<8 | uint64(b)
	}
	state.b.Drop(n)
	return x
}

// decodeInt reads an encoded signed integer from state.r.
// Does not check for overflow.
func (state *decoderState) decodeInt() int64 {
	x := state.decodeUint()
	if x&1 != 0 {
		return ^int64(x >> 1)
	}
	return int64(x >> 1)
}

// getLength decodes the next uint and makes sure it is a possible
// size for a data item that follows, which means it must fit in a
// non-negative int and fit in the buffer.
func (state *decoderState) getLength() (int, bool) {
	n := int(state.decodeUint())
	if n < 0 || state.b.Len() < n || tooBig <= n {
		return 0, false
	}
	return n, true
}

// decOp is the signature of a decoding operator for a given type.
type decOp func(i *decInstr, state *decoderState, v reflect.Value)

// The 'instructions' of the decoding machine
type decInstr struct {
	op    decOp
	field int   // field number of the wire type
	index []int // field access indices for destination type
	ovfl  error // error message for overflow/underflow (for arrays, of the elements)
}

// ignoreUint discards a uint value with no destination.
func ignoreUint(i *decInstr, state *decoderState, v reflect.Value) {
	state.decodeUint()
}

// ignoreTwoUints discards a uint value with no destination. It's used to skip
// complex values.
func ignoreTwoUints(i *decInstr, state *decoderState, v reflect.Value) {
	state.decodeUint()
	state.decodeUint()
}

// Since the encoder writes no zeros, if we arrive at a decoder we have
// a value to extract and store. The field number has already been read
// (it's how we knew to call this decoder).
// Each decoder is responsible for handling any indirections associated
// with the data structure. If any pointer so reached is nil, allocation must
// be done.

// decAlloc takes a value and returns a settable value that can
// be assigned to. If the value is a pointer, decAlloc guarantees it points to storage.
// The callers to the individual decoders are expected to have used decAlloc.
// The individual decoders don't need it.
func decAlloc(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}
	return v
}

// decBool decodes a uint and stores it as a boolean in value.
func decBool(i *decInstr, state *decoderState, value reflect.Value) {
	value.SetBool(state.decodeUint() != 0)
}

// decInt8 decodes an integer and stores it as an int8 in value.
func decInt8(i *decInstr, state *decoderState, value reflect.Value) {
	v := state.decodeInt()
	if v < math.MinInt8 || math.MaxInt8 < v {
		error_(i.ovfl)
	}
	value.SetInt(v)
}

// decUint8 decodes an unsigned integer and stores it as a uint8 in value.
func decUint8(i *decInstr, state *decoderState, value reflect.Value) {
	v := state.decodeUint()
	if math.MaxUint8 < v {
		error_(i.ovfl)
	}
	value.SetUint(v)
}

// decInt16 decodes an integer and stores it as an int16 in value.
func decInt16(i *decInstr, state *decoderState, value reflect.Value) {
	v := state.decodeInt()
	if v < math.MinInt16 || math.MaxInt16 < v {
		error_(i.ovfl)
	}
	value.SetInt(v)
}

// decUint16 decodes an unsigned integer and stores it as a uint16 in value.
func decUint16(i *decInstr, state *decoderState, value reflect.Value) {
	v := state.decodeUint()
	if math.MaxUint16 < v {
		error_(i.ovfl)
	}
	value.SetUint(v)
}

// decInt32 decodes an integer and stores it as an int32 in value.
func decInt32(i *decInstr, state *decoderState, value reflect.Value) {
	v := state.decodeInt()
	if v < math.MinInt32 || math.MaxInt32 < v {
		error_(i.ovfl)
	}
	value.SetInt(v)
}

// decUint32 decodes an unsigned integer and stores it as a uint32 in value.
func decUint32(i *decInstr, state *decoderState, value reflect.Value) {
	v := state.decodeUint()
	if math.MaxUint32 < v {
		error_(i.ovfl)
	}
	value.SetUint(v)
}

// decInt64 decodes an integer and stores it as an int64 in value.
func decInt64(i *decInstr, state *decoderState, value reflect.Value) {
	v := state.decodeInt()
	value.SetInt(v)
}

// decUint64 decodes an unsigned integer and stores it as a uint64 in value.
func decUint64(i *decInstr, state *decoderState, value reflect.Value) {
	v := state.decodeUint()
	value.SetUint(v)
}

// Floating-point numbers are transmitted as uint64s holding the bits
// of the underlying representation. They are sent byte-reversed, with
// the exponent end coming out first, so integer floating point numbers
// (for example) transmit more compactly. This routine does the
// unswizzling.
func float64FromBits(u uint64) float64 {
	v := bits.ReverseBytes64(u)
	return math.Float64frombits(v)
}

// float32FromBits decodes an unsigned integer, treats it as a 32-bit floating-point
// number, and returns it. It's a helper function for float32 and complex64.
// It returns a float64 because that's what reflection needs, but its return
// value is known to be accurately representable in a float32.
func float32FromBits(u uint64, ovfl error) float64 {
	v := float64FromBits(u)
	av := v
	if av < 0 {
		av = -av
	}
	// +Inf is OK in both 32- and 64-bit floats. Underflow is always OK.
	if math.MaxFloat32 < av && av <= math.MaxFloat64 {
		error_(ovfl)
	}
	return v
}

// decFloat32 decodes an unsigned integer, treats it as a 32-bit floating-point
// number, and stores it in value.
func decFloat32(i *decInstr, state *decoderState, value reflect.Value) {
	value.SetFloat(float32FromBits(state.decodeUint(), i.ovfl))
}

// decFloat64 decodes an unsigned integer, treats it as a 64-bit floating-point
// number, and stores it in value.
func decFloat64(i *decInstr, state *decoderState, value reflect.Value) {
	value.SetFloat(float64FromBits(state.decodeUint()))
}

// decComplex64 decodes a pair of unsigned integers, treats them as a
// pair of floating point numbers, and stores them as a complex64 in value.
// The real part comes first.
func decComplex64(i *decInstr, state *decoderState, value reflect.Value) {
	real := float32FromBits(state.decodeUint(), i.ovfl)
	imag := float32FromBits(state.decodeUint(), i.ovfl)
	value.SetComplex(complex(real, imag))
}

// decComplex128 decodes a pair of unsigned integers, treats them as a
// pair of floating point numbers, and stores them as a complex128 in value.
// The real part comes first.
func decComplex128(i *decInstr, state *decoderState, value reflect.Value) {
	real := float64FromBits(state.decodeUint())
	imag := float64FromBits(state.decodeUint())
	value.SetComplex(complex(real, imag))
}

// decUint8Slice decodes a byte slice and stores in value a slice header
// describing the data.
// uint8 slices are encoded as an unsigned count followed by the raw bytes.
func decUint8Slice(i *decInstr, state *decoderState, value reflect.Value) {
	n, ok := state.getLength()
	if !ok {
		errorf("bad %s slice length: %d", value.Type(), n)
	}
	if value.Cap() < n {
		safe := saferio.SliceCap[byte](uint64(n))
		if safe < 0 {
			errorf("%s slice too big: %d elements", value.Type(), n)
		}
		value.Set(reflect.MakeSlice(value.Type(), safe, safe))
		ln := safe
		i := 0
		for i < n {
			if i >= ln {
				// We didn't allocate the entire slice,
				// due to using saferio.SliceCap.
				// Grow the slice for one more element.
				// The slice is full, so this should
				// bump up the capacity.
				value.Grow(1)
			}
			// Copy into s up to the capacity or n,
			// whichever is less.
			ln = value.Cap()
			if ln > n {
				ln = n
			}
			value.SetLen(ln)
			sub := value.Slice(i, ln)
			if _, err := state.b.Read(sub.Bytes()); err != nil {
				errorf("error decoding []byte at %d: %s", i, err)
			}
			i = ln
		}
	} else {
		value.SetLen(n)
		if _, err := state.b.Read(value.Bytes()); err != nil {
			errorf("error decoding []byte: %s", err)
		}
	}
}

// decString decodes byte array and stores in value a string header
// describing the data.
// Strings are encoded as an unsigned count followed by the raw bytes.
func decString(i *decInstr, state *decoderState, value reflect.Value) {
	n, ok := state.getLength()
	if !ok {
		errorf("bad %s slice length: %d", value.Type(), n)
	}
	// Read the data.
	data := state.b.Bytes()
	if len(data) < n {
		errorf("invalid string length %d: exceeds input size %d", n, len(data))
	}
	s := string(data[:n])
	state.b.Drop(n)
	value.SetString(s)
}

// ignoreUint8Array skips over the data for a byte slice value with no destination.
func ignoreUint8Array(i *decInstr, state *decoderState, value reflect.Value) {
	n, ok := state.getLength()
	if !ok {
		errorf("slice length too large")
	}
	bn := state.b.Len()
	if bn < n {
		errorf("invalid slice length %d: exceeds input size %d", n, bn)
	}
	state.b.Drop(n)
}

// Execution engine

// The encoder engine is an array of instructions indexed by field number of the incoming
// decoder. It is executed with random access according to field number.
type decEngine struct {
	instr    []decInstr
	numInstr int // the number of active instructions
}

// decodeSingle decodes a top-level value that is not a struct and stores it in value.
// Such values are preceded by a zero, making them have the memory layout of a
// struct field (although with an illegal field number).
func (dec *Decoder) decodeSingle(engine *decEngine, value reflect.Value) {
	state := dec.newDecoderState(&dec.buf)
	defer dec.freeDecoderState(state)
	state.fieldnum = singletonField
	if state.decodeUint() != 0 {
		errorf("decode: corrupted data: non-zero delta for singleton")
	}
	instr := &engine.instr[singletonField]
	instr.op(instr, state, value)
}

// decodeStruct decodes a top-level struct and stores it in value.
// Indir is for the value, not the type. At the time of the call it may
// differ from ut.indir, which was computed when the engine was built.
// This state cannot arise for decodeSingle, which is called directly
// from the user's value, not from the innards of an engine.
func (dec *Decoder) decodeStruct(engine *decEngine, value reflect.Value) {
	state := dec.newDecoderState(&dec.buf)
	defer dec.freeDecoderState(state)
	state.fieldnum = -1
	for state.b.Len() > 0 {
		delta := int(state.decodeUint())
		if delta < 0 {
			errorf("decode: corrupted data: negative delta")
		}
		if delta == 0 { // struct terminator is zero delta fieldnum
			break
		}
		if state.fieldnum >= len(engine.instr)-delta { // subtract to compare without overflow
			error_(errRange)
		}
		fieldnum := state.fieldnum + delta
		instr := &engine.instr[fieldnum]
		var field reflect.Value
		if instr.index != nil {
			// Otherwise the field is unknown to us and instr.op is an ignore op.
			field = value.FieldByIndex(instr.index)
			if field.Kind() == reflect.Pointer {
				field = decAlloc(field)
			}
		}
		instr.op(instr, state, field)
		state.fieldnum = fieldnum
	}
}

var noValue reflect.Value

// ignoreStruct discards the data for a struct with no destination.
func (dec *Decoder) ignoreStruct(engine *decEngine) {
	state := dec.newDecoderState(&dec.buf)
	defer dec.freeDecoderState(state)
	state.fieldnum = -1
	for state.b.Len() > 0 {
		delta := int(state.decodeUint())
		if delta < 0 {
			errorf("ignore decode: corrupted data: negative delta")
		}
		if delta == 0 { // struct terminator is zero delta fieldnum
			break
		}
		fieldnum := state.fieldnum + delta
		if fieldnum >= len(engine.instr) {
			error_(errRange)
		}
		instr := &engine.instr[fieldnum]
		instr.op(instr, state, noValue)
		state.fieldnum = fieldnum
	}
}

// ignoreSingle discards the data for a top-level non-struct value with no
// destination. It's used when calling Decode with a nil value.
func (dec *Decoder) ignoreSingle(engine *decEngine) {
	state := dec.newDecoderState(&dec.buf)
	defer dec.freeDecoderState(state)
	state.fieldnum = singletonField
	delta := int(state.decodeUint())
	if delta != 0 {
		errorf("decode: corrupted data: non-zero delta for singleton")
	}
	instr := &engine.instr[singletonField]
	instr.op(instr, state, noValue)
}

// decodeArrayHelper does the work for decoding arrays and slices.
func (dec *Decoder) decodeArrayHelper(state *decoderState, value reflect.Value, elemOp decOp, length int, ovfl error, helper decHelper) {
	if helper != nil && helper(state, value, length, ovfl) {
		return
	}
	instr := &decInstr{elemOp, 0, nil, ovfl}
	isPtr := value.Type().Elem().Kind() == reflect.Pointer
	ln := value.Len()
	for i := 0; i < length; i++ {
		if state.b.Len() == 0 {
			errorf("decoding array or slice: length exceeds input size (%d elements)", length)
		}
		if i >= ln {
			// This is a slice that we only partially allocated.
			// Grow it up to length.
			value.Grow(1)
			cp := value.Cap()
			if cp > length {
				cp = length
			}
			value.SetLen(cp)
			ln = cp
		}
		v := value.Index(i)
		if isPtr {
			v = decAlloc(v)
		}
		elemOp(instr, state, v)
	}
}

// decodeArray decodes an array and stores it in value.
// The length is an unsigned integer preceding the elements. Even though the length is redundant
// (it's part of the type), it's a useful check and is included in the encoding.
func (dec *Decoder) decodeArray(state *decoderState, value reflect.Value, elemOp decOp, length int, ovfl error, helper decHelper) {
	if n := state.decodeUint(); n != uint64(length) {
		errorf("length mismatch in decodeArray")
	}
	dec.decodeArrayHelper(state, value, elemOp, length, ovfl, helper)
}

// decodeIntoValue is a helper for map decoding.
func decodeIntoValue(state *decoderState, op decOp, isPtr bool, value reflect.Value, instr *decInstr) reflect.Value {
	v := value
	if isPtr {
		v = decAlloc(value)
	}

	op(instr, state, v)
	return value
}

// decodeMap decodes a map and stores it in value.
// Maps are encoded as a length followed by key:value pairs.
// Because the internals of maps are not visible to us, we must
// use reflection rather than pointer magic.
func (dec *Decoder) decodeMap(mtyp reflect.Type, state *decoderState, value reflect.Value, keyOp, elemOp decOp, ovfl error) {
	n := int(state.decodeUint())
	if value.IsNil() {
		value.Set(reflect.MakeMapWithSize(mtyp, n))
	}
	keyIsPtr := mtyp.Key().Kind() == reflect.Pointer
	elemIsPtr := mtyp.Elem().Kind() == reflect.Pointer
	keyInstr := &decInstr{keyOp, 0, nil, ovfl}
	elemInstr := &decInstr{elemOp, 0, nil, ovfl}
	keyP := reflect.New(mtyp.Key())
	elemP := reflect.New(mtyp.Elem())
	for i := 0; i < n; i++ {
		key := decodeIntoValue(state, keyOp, keyIsPtr, keyP.Elem(), keyInstr)
		elem := decodeIntoValue(state, elemOp, elemIsPtr, elemP.Elem(), elemInstr)
		value.SetMapIndex(key, elem)
		keyP.Elem().SetZero()
		elemP.Elem().SetZero()
	}
}

// ignoreArrayHelper does the work for discarding arrays and slices.
func (dec *Decoder) ignoreArrayHelper(state *decoderState, elemOp decOp, length int) {
	instr := &decInstr{elemOp, 0, nil, errors.New("no error")}
	for i := 0; i < length; i++ {
		if state.b.Len() == 0 {
			errorf("decoding array or slice: length exceeds input size (%d elements)", length)
		}
		elemOp(instr, state, noValue)
	}
}

// ignoreArray discards the data for an array value with no destination.
func (dec *Decoder) ignoreArray(state *decoderState, elemOp decOp, length int) {
	if n := state.decodeUint(); n != uint64(length) {
		errorf("length mismatch in ignoreArray")
	}
	dec.ignoreArrayHelper(state, elemOp, length)
}

// ignoreMap discards the data for a map value with no destination.
func (dec *Decoder) ignoreMap(state *decoderState, keyOp, elemOp decOp) {
	n := int(state.decodeUint())
	keyInstr := &decInstr{keyOp, 0, nil, errors.New("no error")}
	elemInstr := &decInstr{elemOp, 0, nil, errors.New("no error")}
	for i := 0; i < n; i++ {
		keyOp(keyInstr, state, noValue)
		elemOp(elemInstr, state, noValue)
	}
}

// decodeSlice decodes a slice and stores it in value.
// Slices are encoded as an unsigned length followed by the elements.
func (dec *Decoder) decodeSlice(state *decoderState, value reflect.Value, elemOp decOp, ovfl error, helper decHelper) {
	u := state.decodeUint()
	typ := value.Type()
	size := uint64(typ.Elem().Size())
	nBytes := u * size
	n := int(u)
	// Take care with overflow in this calculation.
	if n < 0 || uint64(n) != u || nBytes > tooBig || (size > 0 && nBytes/size != u) {
		// We don't check n against buffer length here because if it's a slice
		// of interfaces, there will be buffer reloads.
		errorf("%s slice too big: %d elements of %d bytes", typ.Elem(), u, size)
	}
	if value.Cap() < n {
		safe := saferio.SliceCapWithSize(size, uint64(n))
		if safe < 0 {
			errorf("%s slice too big: %d elements of %d bytes", typ.Elem(), u, size)
		}
		value.Set(reflect.MakeSlice(typ, safe, safe))
	} else {
		value.SetLen(n)
	}
	dec.decodeArrayHelper(state, value, elemOp, n, ovfl, helper)
}

// ignoreSlice skips over the data for a slice value with no destination.
func (dec *Decoder) ignoreSlice(state *decoderState, elemOp decOp) {
	dec.ignoreArrayHelper(state, elemOp, int(state.decodeUint()))
}

// decodeInterface decodes an interface value and stores it in value.
// Interfaces are encoded as the name of a concrete type followed by a value.
// If the name is empty, the value is nil and no value is sent.
func (dec *Decoder) decodeInterface(ityp reflect.Type, state *decoderState, value reflect.Value) {
	// Read the name of the concrete type.
	nr := state.decodeUint()
	if nr > 1<<31 { // zero is permissible for anonymous types
		errorf("invalid type name length %d", nr)
	}
	if nr > uint64(state.b.Len()) {
		errorf("invalid type name length %d: exceeds input size", nr)
	}
	n := int(nr)
	name := state.b.Bytes()[:n]
	state.b.Drop(n)
	// Allocate the destination interface value.
	if len(name) == 0 {
		// Copy the nil interface value to the target.
		value.SetZero()
		return
	}
	if len(name) > 1024 {
		errorf("name too long (%d bytes): %.20q...", len(name), name)
	}
	// The concrete type must be registered.
	typi, ok := nameToConcreteType.Load(string(name))
	if !ok {
		errorf("name not registered for interface: %q", name)
	}
	typ := typi.(reflect.Type)

	// Read the type id of the concrete value.
	concreteId := dec.decodeTypeSequence(true)
	if concreteId < 0 {
		error_(dec.err)
	}
	// Byte count of value is next; we don't care what it is (it's there
	// in case we want to ignore the value by skipping it completely).
	state.decodeUint()
	// Read the concrete value.
	v := allocValue(typ)
	dec.decodeValue(concreteId, v)
	if dec.err != nil {
		error_(dec.err)
	}
	// Assign the concrete value to the interface.
	// Tread carefully; it might not satisfy the interface.
	if !typ.AssignableTo(ityp) {
		errorf("%s is not assignable to type %s", typ, ityp)
	}
	// Copy the interface value to the target.
	value.Set(v)
}

// ignoreInterface discards the data for an interface value with no destination.
func (dec *Decoder) ignoreInterface(state *decoderState) {
	// Read the name of the concrete type.
	n, ok := state.getLength()
	if !ok {
		errorf("bad interface encoding: name too large for buffer")
	}
	bn := state.b.Len()
	if bn < n {
		errorf("invalid interface value length %d: exceeds input size %d", n, bn)
	}
	state.b.Drop(n)
	id := dec.decodeTypeSequence(true)
	if id < 0 {
		error_(dec.err)
	}
	// At this point, the decoder buffer contains a delimited value. Just toss it.
	n, ok = state.getLength()
	if !ok {
		errorf("bad interface encoding: data length too large for buffer")
	}
	state.b.Drop(n)
}

// decodeGobDecoder decodes something implementing the GobDecoder interface.
// The data is encoded as a byte slice.
func (dec *Decoder) decodeGobDecoder(ut *userTypeInfo, state *decoderState, value reflect.Value) {
	// Read the bytes for the value.
	n, ok := state.getLength()
	if !ok {
		errorf("GobDecoder: length too large for buffer")
	}
	b := state.b.Bytes()
	if len(b) < n {
		errorf("GobDecoder: invalid data length %d: exceeds input size %d", n, len(b))
	}
	b = b[:n]
	state.b.Drop(n)
	var err error
	// We know it's one of these.
	switch ut.externalDec {
	case xGob:
		err = value.Interface().(GobDecoder).GobDecode(b)
	case xBinary:
		err = value.Interface().(encoding.BinaryUnmarshaler).UnmarshalBinary(b)
	case xText:
		err = value.Interface().(encoding.TextUnmarshaler).UnmarshalText(b)
	}
	if err != nil {
		error_(err)
	}
}

// ignoreGobDecoder discards the data for a GobDecoder value with no destination.
func (dec *Decoder) ignoreGobDecoder(state *decoderState) {
	// Read the bytes for the value.
	n, ok := state.getLength()
	if !ok {
		errorf("GobDecoder: length too large for buffer")
	}
	bn := state.b.Len()
	if bn < n {
		errorf("GobDecoder: invalid data length %d: exceeds input size %d", n, bn)
	}
	state.b.Drop(n)
}

// Index by Go types.
var decOpTable = [...]decOp{
	reflect.Bool:       decBool,
	reflect.Int8:       decInt8,
	reflect.Int16:      decInt16,
	reflect.Int32:      decInt32,
	reflect.Int64:      decInt64,
	reflect.Uint8:      decUint8,
	reflect.Uint16:     decUint16,
	reflect.Uint32:     decUint32,
	reflect.Uint64:     decUint64,
	reflect.Float32:    decFloat32,
	reflect.Float64:    decFloat64,
	reflect.Complex64:  decComplex64,
	reflect.Complex128: decComplex128,
	reflect.String:     decString,
}

// Indexed by gob types.  tComplex will be added during type.init().
var decIgnoreOpMap = map[typeId]decOp{
	tBool:    ignoreUint,
	tInt:     ignoreUint,
	tUint:    ignoreUint,
	tFloat:   ignoreUint,
	tBytes:   ignoreUint8Array,
	tString:  ignoreUint8Array,
	tComplex: ignoreTwoUints,
}

// decOpFor returns the decoding op for the base type under rt and
// the indirection count to reach it.
func (dec *Decoder) decOpFor(wireId typeId, rt reflect.Type, name string, inProgress map[reflect.Type]*decOp) *decOp {
	ut := userType(rt)
	// If the type implements GobEncoder, we handle it without further processing.
	if ut.externalDec != 0 {
		return dec.gobDecodeOpFor(ut)
	}

	// If this type is already in progress, it's a recursive type (e.g. map[string]*T).
	// Return the pointer to the op we're already building.
	if opPtr := inProgress[rt]; opPtr != nil {
		return opPtr
	}
	typ := ut.base
	var op decOp
	k := typ.Kind()
	if int(k) < len(decOpTable) {
		op = decOpTable[k]
	}
	if op == nil {
		inProgress[rt] = &op
		// Special cases
		switch t := typ; t.Kind() {
		case reflect.Array:
			name = "element of " + name
			elemId := dec.wireType[wireId].ArrayT.Elem
			elemOp := dec.decOpFor(elemId, t.Elem(), name, inProgress)
			ovfl := overflow(name)
			helper := decArrayHelper[t.Elem().Kind()]
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				state.dec.decodeArray(state, value, *elemOp, t.Len(), ovfl, helper)
			}

		case reflect.Map:
			keyId := dec.wireType[wireId].MapT.Key
			elemId := dec.wireType[wireId].MapT.Elem
			keyOp := dec.decOpFor(keyId, t.Key(), "key of "+name, inProgress)
			elemOp := dec.decOpFor(elemId, t.Elem(), "element of "+name, inProgress)
			ovfl := overflow(name)
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				state.dec.decodeMap(t, state, value, *keyOp, *elemOp, ovfl)
			}

		case reflect.Slice:
			name = "element of " + name
			if t.Elem().Kind() == reflect.Uint8 {
				op = decUint8Slice
				break
			}
			var elemId typeId
			if tt := builtinIdToType(wireId); tt != nil {
				elemId = tt.(*sliceType).Elem
			} else {
				elemId = dec.wireType[wireId].SliceT.Elem
			}
			elemOp := dec.decOpFor(elemId, t.Elem(), name, inProgress)
			ovfl := overflow(name)
			helper := decSliceHelper[t.Elem().Kind()]
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				state.dec.decodeSlice(state, value, *elemOp, ovfl, helper)
			}

		case reflect.Struct:
			// Generate a closure that calls out to the engine for the nested type.
			ut := userType(typ)
			enginePtr, err := dec.getDecEnginePtr(wireId, ut)
			if err != nil {
				error_(err)
			}
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				// indirect through enginePtr to delay evaluation for recursive structs.
				dec.decodeStruct(*enginePtr, value)
			}
		case reflect.Interface:
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				state.dec.decodeInterface(t, state, value)
			}
		}
	}
	if op == nil {
		errorf("decode can't handle type %s", rt)
	}
	return &op
}

var maxIgnoreNestingDepth = 10000

// decIgnoreOpFor returns the decoding op for a field that has no destination.
func (dec *Decoder) decIgnoreOpFor(wireId typeId, inProgress map[typeId]*decOp) *decOp {
	// Track how deep we've recursed trying to skip nested ignored fields.
	dec.ignoreDepth++
	defer func() { dec.ignoreDepth-- }()
	if dec.ignoreDepth > maxIgnoreNestingDepth {
		error_(errors.New("invalid nesting depth"))
	}
	// If this type is already in progress, it's a recursive type (e.g. map[string]*T).
	// Return the pointer to the op we're already building.
	if opPtr := inProgress[wireId]; opPtr != nil {
		return opPtr
	}
	op, ok := decIgnoreOpMap[wireId]
	if !ok {
		inProgress[wireId] = &op
		if wireId == tInterface {
			// Special case because it's a method: the ignored item might
			// define types and we need to record their state in the decoder.
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				state.dec.ignoreInterface(state)
			}
			return &op
		}
		// Special cases
		wire := dec.wireType[wireId]
		switch {
		case wire == nil:
			errorf("bad data: undefined type %s", wireId.string())
		case wire.ArrayT != nil:
			elemId := wire.ArrayT.Elem
			elemOp := dec.decIgnoreOpFor(elemId, inProgress)
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				state.dec.ignoreArray(state, *elemOp, wire.ArrayT.Len)
			}

		case wire.MapT != nil:
			keyId := dec.wireType[wireId].MapT.Key
			elemId := dec.wireType[wireId].MapT.Elem
			keyOp := dec.decIgnoreOpFor(keyId, inProgress)
			elemOp := dec.decIgnoreOpFor(elemId, inProgress)
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				state.dec.ignoreMap(state, *keyOp, *elemOp)
			}

		case wire.SliceT != nil:
			elemId := wire.SliceT.Elem
			elemOp := dec.decIgnoreOpFor(elemId, inProgress)
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				state.dec.ignoreSlice(state, *elemOp)
			}

		case wire.StructT != nil:
			// Generate a closure that calls out to the engine for the nested type.
			enginePtr, err := dec.getIgnoreEnginePtr(wireId)
			if err != nil {
				error_(err)
			}
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				// indirect through enginePtr to delay evaluation for recursive structs
				state.dec.ignoreStruct(*enginePtr)
			}

		case wire.GobEncoderT != nil, wire.BinaryMarshalerT != nil, wire.TextMarshalerT != nil:
			op = func(i *decInstr, state *decoderState, value reflect.Value) {
				state.dec.ignoreGobDecoder(state)
			}
		}
	}
	if op == nil {
		errorf("bad data: ignore can't handle type %s", wireId.string())
	}
	return &op
}

// gobDecodeOpFor returns the op for a type that is known to implement
// GobDecoder.
func (dec *Decoder) gobDecodeOpFor(ut *userTypeInfo) *decOp {
	rcvrType := ut.user
	if ut.decIndir == -1 {
		rcvrType = reflect.PointerTo(rcvrType)
	} else if ut.decIndir > 0 {
		for i := int8(0); i < ut.decIndir; i++ {
			rcvrType = rcvrType.Elem()
		}
	}
	var op decOp
	op = func(i *decInstr, state *decoderState, value reflect.Value) {
		// We now have the base type. We need its address if the receiver is a pointer.
		if value.Kind() != reflect.Pointer && rcvrType.Kind() == reflect.Pointer {
			value = value.Addr()
		}
		state.dec.decodeGobDecoder(ut, state, value)
	}
	return &op
}

// compatibleType asks: Are these two gob Types compatible?
// Answers the question for basic types, arrays, maps and slices, plus
// GobEncoder/Decoder pairs.
// Structs are considered ok; fields will be checked later.
func (dec *Decoder) compatibleType(fr reflect.Type, fw typeId, inProgress map[reflect.Type]typeId) bool {
	if rhs, ok := inProgress[fr]; ok {
		return rhs == fw
	}
	inProgress[fr] = fw
	ut := userType(fr)
	wire, ok := dec.wireType[fw]
	// If wire was encoded with an encoding method, fr must have that method.
	// And if not, it must not.
	// At most one of the booleans in ut is set.
	// We could possibly relax this constraint in the future in order to
	// choose the decoding method using the data in the wireType.
	// The parentheses look odd but are correct.
	if (ut.externalDec == xGob) != (ok && wire.GobEncoderT != nil) ||
		(ut.externalDec == xBinary) != (ok && wire.BinaryMarshalerT != nil) ||
		(ut.externalDec == xText) != (ok && wire.TextMarshalerT != nil) {
		return false
	}
	if ut.externalDec != 0 { // This test trumps all others.
		return true
	}
	switch t := ut.base; t.Kind() {
	default:
		// chan, etc: cannot handle.
		return false
	case reflect.Bool:
		return fw == tBool
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fw == tInt
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return fw == tUint
	case reflect.Float32, reflect.Float64:
		return fw == tFloat
	case reflect.Complex64, reflect.Complex128:
		return fw == tComplex
	c
```