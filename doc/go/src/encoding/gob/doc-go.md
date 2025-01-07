Response:
My thought process to answer the request about `go/src/encoding/gob/doc.go` goes like this:

1. **Understand the Core Question:** The request asks for the functionality of the `gob` package as described in its documentation. It also wants examples, explanations of specific features (like command-line arguments - which are unlikely here but I need to check), common mistakes, and everything in Chinese.

2. **Identify the Key Information Source:** The provided text is the documentation for the `gob` package. My primary task is to extract and explain the information within this document.

3. **Break Down the Documentation:** I'll go section by section in the documentation and identify the key functionalities and concepts being discussed. This will help structure my answer.

4. **"Package gob manages streams of gobs..."**: This opening sentence is crucial. It tells me the core purpose: serializing Go values for transmission between an encoder and a decoder. Keywords here are "binary values," "Encoder," and "Decoder."

5. **"A typical use is transporting arguments and results of remote procedure calls (RPCs)..."**: This provides a concrete use case, which is good for understanding its purpose.

6. **"The implementation compiles a custom codec..."**: This explains the efficiency aspect. It's worth noting that this compilation happens per data type and is amortized over a stream of values.

7. **"# Basics"**:  This section introduces core concepts:
    * **Self-describing stream:**  Type information is included.
    * **Pointers are flattened:** Values are transmitted, not pointer addresses.
    * **Nil pointers are not permitted:**  This is a limitation.
    * **Recursive types work, recursive values are problematic:** Another important detail about limitations.
    * **Encoder and Decoder roles:** How to use the package.

8. **"# Types and Values"**: This is a very detailed section about type compatibility:
    * **Loose type matching for structs:** Focus on field names. Missing or extra fields are tolerated.
    * **Type compatibility rules:**  Signedness, basic types, common field names are crucial.
    * **Integer encoding:**  Signed and unsigned integers, no size distinctions (int8, int16, etc.).
    * **Floating-point encoding:** Always 64-bit.
    * **Struct, array, and slice handling:** How they are encoded and decoded. Exported fields are important for structs.
    * **String and byte array optimization:** Special handling for efficiency.
    * **Slice decoding behavior:**  In-place extension or allocation.
    * **Memory allocation:** Decoder handles allocation when needed.
    * **Function and channel limitations:**  Cannot be encoded directly.
    * **GobEncoder/BinaryMarshaler and GobDecoder/BinaryUnmarshaler interfaces:** Support for custom serialization.

9. **"# Encoding Details"**: This section delves into the lower-level wire format:
    * **Unsigned integer encoding:**  Variable-length encoding.
    * **Boolean encoding:** As an unsigned integer.
    * **Signed integer encoding:**  Bit manipulation for sign representation.
    * **Floating-point encoding:** `math.Float64bits` and byte reversal.
    * **String and byte slice encoding:** Length prefix.
    * **Array and slice encoding:** Length prefix and recursive encoding.
    * **Map encoding:** Length prefix and key-value pairs.
    * **Struct encoding:** Field number deltas and a terminator.
    * **Interface encoding:** Type name registration and dynamic value encoding.
    * **Top-level non-struct encoding:** Treated as a single-field struct.
    * **Type definitions:** Sending type information with negative IDs.
    * **Predefined type IDs:**  A list of built-in types.
    * **Message framing:** Length prefix for each message.

10. **"# Security"**: Important disclaimer about security considerations when dealing with untrusted input.

11. **"Grammar"**: Formal description of the gob stream structure.

12. **Example**: A detailed walkthrough of encoding a `Point` struct. This is excellent for illustration.

13. **Identify Potential Go Examples:**  The documentation itself provides hints for examples. I need to translate those hints into runnable Go code. The struct example is a great starting point. Encoding and decoding basic types are also good.

14. **Consider Command-Line Arguments:** Based on the documentation, the `gob` package itself doesn't directly interact with command-line arguments. It's a serialization library. This needs to be stated clearly.

15. **Think About Common Mistakes:**  Based on the documentation, common errors could involve:
    * Trying to encode nil pointers directly.
    * Expecting exact type matching for structs.
    * Forgetting that only exported struct fields are encoded.
    * Security risks with untrusted input.

16. **Structure the Answer in Chinese:**  Now I need to synthesize all the gathered information and present it in a clear and structured way in Chinese, addressing all parts of the original request. I'll follow the structure of the request:
    * Functionality overview.
    * Go code examples (with assumptions for input/output).
    * Explanation of the code examples.
    * Discussion of command-line arguments (or lack thereof).
    * Common mistakes.

17. **Refine and Review:** Finally, I'll review my answer for accuracy, clarity, and completeness, ensuring it directly addresses all aspects of the user's request. I'll double-check the Chinese translation for correctness and natural flow. For the code examples, I'll ensure they compile and demonstrate the points I'm making.

This systematic approach allows me to extract the relevant information from the documentation, provide illustrative examples, and address the user's request comprehensively. The detailed analysis of each section of the documentation is key to producing a thorough and accurate answer.`go/src/encoding/gob/doc.go` 文件是 Go 语言 `encoding/gob` 包的文档，它详细描述了 `gob` 包的功能和使用方法。 总结来说，`gob` 包的主要功能是：

**主要功能:**

1. **gob 流管理:**  `gob` 包用于管理 gob 流，这是一种用于在 `Encoder` (发送器) 和 `Decoder` (接收器) 之间交换二进制值的机制。
2. **远程过程调用 (RPC) 的数据传输:**  `gob` 的一个典型应用是传输远程过程调用 (RPC) 的参数和结果，例如 `net/rpc` 包提供的功能。
3. **高效的编解码:**  `gob` 为流中的每种数据类型编译一个自定义的编解码器，当使用单个 `Encoder` 发送一系列值时效率最高，可以分摊编译成本。
4. **自描述流:** gob 流是自描述的。流中的每个数据项都带有其类型规范，类型基于一组预定义的类型。
5. **指针处理:** 指针本身不被传输，但指针指向的值会被传输 (值会被扁平化)。不允许使用 `nil` 指针。
6. **递归类型的支持:**  `gob` 支持递归类型，但递归值 (包含循环的数据) 可能会有问题。
7. **类型和值的转换:** 源和目标的值/类型不需要完全对应。对于结构体，源中存在但接收变量中不存在的字段将被忽略。接收变量中存在但传输类型或值中缺少的字段在目标中将被忽略。如果两个字段名称相同，它们的类型必须兼容。`Encoder` 和 `Decoder` 会处理必要的间接引用和解引用，以在 gobs 和实际的 Go 值之间进行转换。
8. **基本数据类型的支持:** 支持 `bool`、整数 (有符号和无符号，不区分 `int8`、`int16` 等)、浮点数 (始终使用 IEEE 754 64 位精度)、字符串和字节数组。
9. **复合数据类型的支持:** 支持结构体、数组和切片。结构体只编码和解码导出的字段。
10. **切片的动态分配:** 当解码切片时，如果现有切片有容量，则会在原地扩展切片；否则，会分配一个新的数组。
11. **内存管理:** 通常，如果需要分配内存，解码器会分配内存。否则，它会使用从流中读取的值更新目标变量。它不会先初始化目标变量。
12. **函数和通道的限制:** 函数和通道不会在 gob 中发送。尝试编码此类顶层值会失败。结构体中 `chan` 或 `func` 类型的字段就像未导出的字段一样被忽略。
13. **自定义编码和解码:** `gob` 可以通过调用相应的 `GobEncoder`/`encoding.BinaryMarshaler` 方法来编码实现这些接口的值，也可以通过调用 `GobDecoder`/`encoding.BinaryUnmarshaler` 方法来解码。

**gob 是什么 Go 语言功能的实现:**

`gob` 包实现了 **序列化** 和 **反序列化** 的功能，可以将 Go 语言的数据结构编码成二进制流进行传输或存储，然后再将其解码回原来的数据结构。  它特别注重 Go 语言的类型系统，能够安全有效地传输 Go 语言的值。

**Go 代码示例:**

```go
package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
)

// 定义一个需要编码的结构体
type Person struct {
	Name string
	Age  int
}

func main() {
	// 创建一个 Person 实例
	p1 := Person{"Alice", 30}

	// 创建一个 buffer 来存储编码后的数据
	var buf bytes.Buffer

	// 创建一个 gob 编码器
	enc := gob.NewEncoder(&buf)

	// 假设的输入：p1

	// 编码 Person 实例
	err := enc.Encode(p1)
	if err != nil {
		log.Fatal("encode error:", err)
	}

	// 假设的输出：buf 包含编码后的二进制数据，例如：
	// 1a ff 81 03 01 01 06 50 65 72 73 6f 6e 01 ff 82 00 01 01 04 4e 61 6d 65 01 06 00 01 01 03 41 67 65 01 04 00 00 0c ff 82 01 05 41 6c 69 63 65 1e 00

	fmt.Printf("Encoded data: %x\n", buf.Bytes())

	// 创建一个 gob 解码器
	dec := gob.NewDecoder(&buf)

	// 创建一个用于存储解码后数据的 Person 实例
	var p2 Person

	// 解码数据到 p2
	err = dec.Decode(&p2)
	if err != nil {
		log.Fatal("decode error:", err)
	}

	// 假设的输出：p2 的值为 {Alice 30}
	fmt.Printf("Decoded Person: %+v\n", p2)
}
```

**代码推理:**

1. **编码 (Encode):**
   - 我们创建了一个 `Person` 类型的实例 `p1`。
   - 创建了一个 `bytes.Buffer` 用于存储编码后的数据。
   - 使用 `gob.NewEncoder(&buf)` 创建了一个编码器，并将 `buf` 作为写入目标。
   - 调用 `enc.Encode(p1)` 将 `p1` 编码成 gob 数据并写入 `buf`。
   - 假设的输出 `buf` 中包含了 `p1` 的二进制表示，其中包含了类型信息和值信息。具体的二进制内容会根据 `gob` 的编码规则而定。

2. **解码 (Decode):**
   - 使用 `gob.NewDecoder(&buf)` 创建了一个解码器，并将包含编码数据的 `buf` 作为读取来源。
   - 创建了一个 `Person` 类型的变量 `p2`，用于接收解码后的数据。
   - 调用 `dec.Decode(&p2)` 从 `buf` 中读取 gob 数据并解码到 `p2` 中。
   - 假设的输出 `p2` 的值将与原始的 `p1` 值相同，因为解码器会根据编码数据中的类型信息和值信息重建 `Person` 对象。

**命令行参数的具体处理:**

`encoding/gob` 包本身不直接处理命令行参数。它是一个用于序列化和反序列化的库，通常与其他包（例如 `net/rpc` 用于网络通信，或者自定义的程序）结合使用。命令行参数的处理通常发生在应用程序的主函数中，并根据参数的值来决定是否使用 `gob` 进行数据的编码和解码。

**使用者易犯错的点:**

1. **未导出字段:** `gob` 只会编码和解码结构体中导出的字段（以大写字母开头的字段）。如果尝试编码包含未导出字段的结构体，这些字段会被忽略，解码后它们将保持其零值。

   ```go
   package main

   import (
       "bytes"
       "encoding/gob"
       "fmt"
       "log"
   )

   type Data struct {
       PublicField  string
       privateField int // 未导出字段
   }

   func main() {
       d1 := Data{"public", 10}

       var buf bytes.Buffer
       enc := gob.NewEncoder(&buf)
       err := enc.Encode(d1)
       if err != nil {
           log.Fatal(err)
       }

       var d2 Data
       dec := gob.NewDecoder(&buf)
       err = dec.Decode(&d2)
       if err != nil {
           log.Fatal(err)
       }

       fmt.Printf("Original: %+v\n", d1) // Output: Original: {PublicField:public privateField:10}
       fmt.Printf("Decoded: %+v\n", d2)  // Output: Decoded: {PublicField:public privateField:0}
   }
   ```
   在这个例子中，`privateField` 没有被编码和解码，所以 `d2.privateField` 的值是其零值 `0`。

2. **类型不匹配:**  虽然 `gob` 在结构体字段匹配时有一定的灵活性（通过字段名匹配），但基本类型必须兼容。尝试将编码后的有符号整数解码到无符号整数变量，或者将浮点数解码到整数变量，会导致解码错误。

   ```go
   package main

   import (
       "bytes"
       "encoding/gob"
       "fmt"
       "log"
   )

   func main() {
       var buf bytes.Buffer
       enc := gob.NewEncoder(&buf)
       err := enc.Encode(int32(10))
       if err != nil {
           log.Fatal(err)
       }

       var u uint32
       dec := gob.NewDecoder(&buf)
       err = dec.Decode(&u)
       if err != nil {
           log.Fatal(err) // 这里会发生解码错误，因为 int32 和 uint32 类型不兼容
       }

       fmt.Println(u)
   }
   ```

3. **尝试编码函数或通道:**  `gob` 不能直接编码函数或通道类型。尝试这样做会导致编码错误。

   ```go
   package main

   import (
       "bytes"
       "encoding/gob"
       "log"
   )

   func myFunc() {}

   func main() {
       var buf bytes.Buffer
       enc := gob.NewEncoder(&buf)
       err := enc.Encode(myFunc) // 这里会发生编码错误
       if err != nil {
           log.Fatal(err)
       }
   }
   ```

4. **处理 `nil` 指针不当:** 虽然 `gob` 会解引用指针指向的值，但尝试直接编码 `nil` 指针会导致错误。你需要确保要编码的值是实际存在的。

理解 `gob` 包的功能和限制对于正确使用它进行数据序列化至关重要。

Prompt: 
```
这是路径为go/src/encoding/gob/doc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package gob manages streams of gobs - binary values exchanged between an
[Encoder] (transmitter) and a [Decoder] (receiver). A typical use is transporting
arguments and results of remote procedure calls (RPCs) such as those provided by
[net/rpc].

The implementation compiles a custom codec for each data type in the stream and
is most efficient when a single [Encoder] is used to transmit a stream of values,
amortizing the cost of compilation.

# Basics

A stream of gobs is self-describing. Each data item in the stream is preceded by
a specification of its type, expressed in terms of a small set of predefined
types. Pointers are not transmitted, but the things they point to are
transmitted; that is, the values are flattened. Nil pointers are not permitted,
as they have no value. Recursive types work fine, but
recursive values (data with cycles) are problematic. This may change.

To use gobs, create an [Encoder] and present it with a series of data items as
values or addresses that can be dereferenced to values. The [Encoder] makes sure
all type information is sent before it is needed. At the receive side, a
[Decoder] retrieves values from the encoded stream and unpacks them into local
variables.

# Types and Values

The source and destination values/types need not correspond exactly. For structs,
fields (identified by name) that are in the source but absent from the receiving
variable will be ignored. Fields that are in the receiving variable but missing
from the transmitted type or value will be ignored in the destination. If a field
with the same name is present in both, their types must be compatible. Both the
receiver and transmitter will do all necessary indirection and dereferencing to
convert between gobs and actual Go values. For instance, a gob type that is
schematically,

	struct { A, B int }

can be sent from or received into any of these Go types:

	struct { A, B int }	// the same
	*struct { A, B int }	// extra indirection of the struct
	struct { *A, **B int }	// extra indirection of the fields
	struct { A, B int64 }	// different concrete value type; see below

It may also be received into any of these:

	struct { A, B int }	// the same
	struct { B, A int }	// ordering doesn't matter; matching is by name
	struct { A, B, C int }	// extra field (C) ignored
	struct { B int }	// missing field (A) ignored; data will be dropped
	struct { B, C int }	// missing field (A) ignored; extra field (C) ignored.

Attempting to receive into these types will draw a decode error:

	struct { A int; B uint }	// change of signedness for B
	struct { A int; B float }	// change of type for B
	struct { }			// no field names in common
	struct { C, D int }		// no field names in common

Integers are transmitted two ways: arbitrary precision signed integers or
arbitrary precision unsigned integers. There is no int8, int16 etc.
discrimination in the gob format; there are only signed and unsigned integers. As
described below, the transmitter sends the value in a variable-length encoding;
the receiver accepts the value and stores it in the destination variable.
Floating-point numbers are always sent using IEEE 754 64-bit precision (see
below).

Signed integers may be received into any signed integer variable: int, int16, etc.;
unsigned integers may be received into any unsigned integer variable; and floating
point values may be received into any floating point variable. However,
the destination variable must be able to represent the value or the decode
operation will fail.

Structs, arrays and slices are also supported. Structs encode and decode only
exported fields. Strings and arrays of bytes are supported with a special,
efficient representation (see below). When a slice is decoded, if the existing
slice has capacity the slice will be extended in place; if not, a new array is
allocated. Regardless, the length of the resulting slice reports the number of
elements decoded.

In general, if allocation is required, the decoder will allocate memory. If not,
it will update the destination variables with values read from the stream. It does
not initialize them first, so if the destination is a compound value such as a
map, struct, or slice, the decoded values will be merged elementwise into the
existing variables.

Functions and channels will not be sent in a gob. Attempting to encode such a value
at the top level will fail. A struct field of chan or func type is treated exactly
like an unexported field and is ignored.

Gob can encode a value of any type implementing the [GobEncoder] or
[encoding.BinaryMarshaler] interfaces by calling the corresponding method,
in that order of preference.

Gob can decode a value of any type implementing the [GobDecoder] or
[encoding.BinaryUnmarshaler] interfaces by calling the corresponding method,
again in that order of preference.

# Encoding Details

This section documents the encoding, details that are not important for most
users. Details are presented bottom-up.

An unsigned integer is sent one of two ways. If it is less than 128, it is sent
as a byte with that value. Otherwise it is sent as a minimal-length big-endian
(high byte first) byte stream holding the value, preceded by one byte holding the
byte count, negated. Thus 0 is transmitted as (00), 7 is transmitted as (07) and
256 is transmitted as (FE 01 00).

A boolean is encoded within an unsigned integer: 0 for false, 1 for true.

A signed integer, i, is encoded within an unsigned integer, u. Within u, bits 1
upward contain the value; bit 0 says whether they should be complemented upon
receipt. The encode algorithm looks like this:

	var u uint
	if i < 0 {
		u = (^uint(i) << 1) | 1 // complement i, bit 0 is 1
	} else {
		u = (uint(i) << 1) // do not complement i, bit 0 is 0
	}
	encodeUnsigned(u)

The low bit is therefore analogous to a sign bit, but making it the complement bit
instead guarantees that the largest negative integer is not a special case. For
example, -129=^128=(^256>>1) encodes as (FE 01 01).

Floating-point numbers are always sent as a representation of a float64 value.
That value is converted to a uint64 using [math.Float64bits]. The uint64 is then
byte-reversed and sent as a regular unsigned integer. The byte-reversal means the
exponent and high-precision part of the mantissa go first. Since the low bits are
often zero, this can save encoding bytes. For instance, 17.0 is encoded in only
three bytes (FE 31 40).

Strings and slices of bytes are sent as an unsigned count followed by that many
uninterpreted bytes of the value.

All other slices and arrays are sent as an unsigned count followed by that many
elements using the standard gob encoding for their type, recursively.

Maps are sent as an unsigned count followed by that many key, element
pairs. Empty but non-nil maps are sent, so if the receiver has not allocated
one already, one will always be allocated on receipt unless the transmitted map
is nil and not at the top level.

In slices and arrays, as well as maps, all elements, even zero-valued elements,
are transmitted, even if all the elements are zero.

Structs are sent as a sequence of (field number, field value) pairs. The field
value is sent using the standard gob encoding for its type, recursively. If a
field has the zero value for its type (except for arrays; see above), it is omitted
from the transmission. The field number is defined by the type of the encoded
struct: the first field of the encoded type is field 0, the second is field 1,
etc. When encoding a value, the field numbers are delta encoded for efficiency
and the fields are always sent in order of increasing field number; the deltas are
therefore unsigned. The initialization for the delta encoding sets the field
number to -1, so an unsigned integer field 0 with value 7 is transmitted as unsigned
delta = 1, unsigned value = 7 or (01 07). Finally, after all the fields have been
sent a terminating mark denotes the end of the struct. That mark is a delta=0
value, which has representation (00).

Interface types are not checked for compatibility; all interface types are
treated, for transmission, as members of a single "interface" type, analogous to
int or []byte - in effect they're all treated as interface{}. Interface values
are transmitted as a string identifying the concrete type being sent (a name
that must be pre-defined by calling [Register]), followed by a byte count of the
length of the following data (so the value can be skipped if it cannot be
stored), followed by the usual encoding of concrete (dynamic) value stored in
the interface value. (A nil interface value is identified by the empty string
and transmits no value.) Upon receipt, the decoder verifies that the unpacked
concrete item satisfies the interface of the receiving variable.

If a value is passed to [Encoder.Encode] and the type is not a struct (or pointer to struct,
etc.), for simplicity of processing it is represented as a struct of one field.
The only visible effect of this is to encode a zero byte after the value, just as
after the last field of an encoded struct, so that the decode algorithm knows when
the top-level value is complete.

The representation of types is described below. When a type is defined on a given
connection between an [Encoder] and [Decoder], it is assigned a signed integer type
id. When [Encoder.Encode](v) is called, it makes sure there is an id assigned for
the type of v and all its elements and then it sends the pair (typeid, encoded-v)
where typeid is the type id of the encoded type of v and encoded-v is the gob
encoding of the value v.

To define a type, the encoder chooses an unused, positive type id and sends the
pair (-type id, encoded-type) where encoded-type is the gob encoding of a wireType
description, constructed from these types:

	type wireType struct {
		ArrayT           *arrayType
		SliceT           *sliceType
		StructT          *structType
		MapT             *mapType
		GobEncoderT      *gobEncoderType
		BinaryMarshalerT *gobEncoderType
		TextMarshalerT   *gobEncoderType
	}
	type arrayType struct {
		CommonType
		Elem typeId
		Len  int
	}
	type CommonType struct {
		Name string // the name of the struct type
		Id  int    // the id of the type, repeated so it's inside the type
	}
	type sliceType struct {
		CommonType
		Elem typeId
	}
	type structType struct {
		CommonType
		Field []fieldType // the fields of the struct.
	}
	type fieldType struct {
		Name string // the name of the field.
		Id   int    // the type id of the field, which must be already defined
	}
	type mapType struct {
		CommonType
		Key  typeId
		Elem typeId
	}
	type gobEncoderType struct {
		CommonType
	}

If there are nested type ids, the types for all inner type ids must be defined
before the top-level type id is used to describe an encoded-v.

For simplicity in setup, the connection is defined to understand these types a
priori, as well as the basic gob types int, uint, etc. Their ids are:

	bool        1
	int         2
	uint        3
	float       4
	[]byte      5
	string      6
	complex     7
	interface   8
	// gap for reserved ids.
	WireType    16
	ArrayType   17
	CommonType  18
	SliceType   19
	StructType  20
	FieldType   21
	// 22 is slice of fieldType.
	MapType     23

Finally, each message created by a call to Encode is preceded by an encoded
unsigned integer count of the number of bytes remaining in the message. After
the initial type name, interface values are wrapped the same way; in effect, the
interface value acts like a recursive invocation of Encode.

In summary, a gob stream looks like

	(byteCount (-type id, encoding of a wireType)* (type id, encoding of a value))*

where * signifies zero or more repetitions and the type id of a value must
be predefined or be defined before the value in the stream.

Compatibility: Any future changes to the package will endeavor to maintain
compatibility with streams encoded using previous versions. That is, any released
version of this package should be able to decode data written with any previously
released version, subject to issues such as security fixes. See the Go compatibility
document for background: https://golang.org/doc/go1compat

See "Gobs of data" for a design discussion of the gob wire format:
https://blog.golang.org/gobs-of-data

# Security

This package is not designed to be hardened against adversarial inputs, and is
outside the scope of https://go.dev/security/policy. In particular, the [Decoder]
does only basic sanity checking on decoded input sizes, and its limits are not
configurable. Care should be taken when decoding gob data from untrusted
sources, which may consume significant resources.
*/
package gob

/*
Grammar:

Tokens starting with a lower case letter are terminals; int(n)
and uint(n) represent the signed/unsigned encodings of the value n.

GobStream:
	DelimitedMessage*
DelimitedMessage:
	uint(lengthOfMessage) Message
Message:
	TypeSequence TypedValue
TypeSequence
	(TypeDefinition DelimitedTypeDefinition*)?
DelimitedTypeDefinition:
	uint(lengthOfTypeDefinition) TypeDefinition
TypedValue:
	int(typeId) Value
TypeDefinition:
	int(-typeId) encodingOfWireType
Value:
	SingletonValue | StructValue
SingletonValue:
	uint(0) FieldValue
FieldValue:
	builtinValue | ArrayValue | MapValue | SliceValue | StructValue | InterfaceValue
InterfaceValue:
	NilInterfaceValue | NonNilInterfaceValue
NilInterfaceValue:
	uint(0)
NonNilInterfaceValue:
	ConcreteTypeName TypeSequence InterfaceContents
ConcreteTypeName:
	uint(lengthOfName) [already read=n] name
InterfaceContents:
	int(concreteTypeId) DelimitedValue
DelimitedValue:
	uint(length) Value
ArrayValue:
	uint(n) FieldValue*n [n elements]
MapValue:
	uint(n) (FieldValue FieldValue)*n  [n (key, value) pairs]
SliceValue:
	uint(n) FieldValue*n [n elements]
StructValue:
	(uint(fieldDelta) FieldValue)*
*/

/*
For implementers and the curious, here is an encoded example. Given
	type Point struct {X, Y int}
and the value
	p := Point{22, 33}
the bytes transmitted that encode p will be:
	1f ff 81 03 01 01 05 50 6f 69 6e 74 01 ff 82 00
	01 02 01 01 58 01 04 00 01 01 59 01 04 00 00 00
	07 ff 82 01 2c 01 42 00
They are determined as follows.

Since this is the first transmission of type Point, the type descriptor
for Point itself must be sent before the value. This is the first type
we've sent on this Encoder, so it has type id 65 (0 through 64 are
reserved).

	1f	// This item (a type descriptor) is 31 bytes long.
	ff 81	// The negative of the id for the type we're defining, -65.
		// This is one byte (indicated by FF = -1) followed by
		// ^-65<<1 | 1. The low 1 bit signals to complement the
		// rest upon receipt.

	// Now we send a type descriptor, which is itself a struct (wireType).
	// The type of wireType itself is known (it's built in, as is the type of
	// all its components), so we just need to send a *value* of type wireType
	// that represents type "Point".
	// Here starts the encoding of that value.
	// Set the field number implicitly to -1; this is done at the beginning
	// of every struct, including nested structs.
	03	// Add 3 to field number; now 2 (wireType.structType; this is a struct).
		// structType starts with an embedded CommonType, which appears
		// as a regular structure here too.
	01	// add 1 to field number (now 0); start of embedded CommonType.
	01	// add 1 to field number (now 0, the name of the type)
	05	// string is (unsigned) 5 bytes long
	50 6f 69 6e 74	// wireType.structType.CommonType.name = "Point"
	01	// add 1 to field number (now 1, the id of the type)
	ff 82	// wireType.structType.CommonType._id = 65
	00	// end of embedded wiretype.structType.CommonType struct
	01	// add 1 to field number (now 1, the field array in wireType.structType)
	02	// There are two fields in the type (len(structType.field))
	01	// Start of first field structure; add 1 to get field number 0: field[0].name
	01	// 1 byte
	58	// structType.field[0].name = "X"
	01	// Add 1 to get field number 1: field[0].id
	04	// structType.field[0].typeId is 2 (signed int).
	00	// End of structType.field[0]; start structType.field[1]; set field number to -1.
	01	// Add 1 to get field number 0: field[1].name
	01	// 1 byte
	59	// structType.field[1].name = "Y"
	01	// Add 1 to get field number 1: field[1].id
	04	// struct.Type.field[1].typeId is 2 (signed int).
	00	// End of structType.field[1]; end of structType.field.
	00	// end of wireType.structType structure
	00	// end of wireType structure

Now we can send the Point value. Again the field number resets to -1:

	07	// this value is 7 bytes long
	ff 82	// the type number, 65 (1 byte (-FF) followed by 65<<1)
	01	// add one to field number, yielding field 0
	2c	// encoding of signed "22" (0x2c = 44 = 22<<1); Point.x = 22
	01	// add one to field number, yielding field 1
	42	// encoding of signed "33" (0x42 = 66 = 33<<1); Point.y = 33
	00	// end of structure

The type encoding is long and fairly intricate but we send it only once.
If p is transmitted a second time, the type is already known so the
output will be just:

	07 ff 82 01 2c 01 42 00

A single non-struct value at top level is transmitted like a field with
delta tag 0. For instance, a signed integer with value 3 presented as
the argument to Encode will emit:

	03 04 00 06

Which represents:

	03	// this value is 3 bytes long
	04	// the type number, 2, represents an integer
	00	// tag delta 0
	06	// value 3

*/

"""



```