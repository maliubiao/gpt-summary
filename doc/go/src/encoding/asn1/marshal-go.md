Response:
Let's break down the thought process for answering the user's request about the `marshal.go` file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the provided Go code snippet. Key aspects they're interested in are:

* **Overall Function:** What does this code *do*?
* **Go Language Feature:** What broader Go concept does it implement?
* **Code Examples:** How is this code used in practice?
* **Assumptions and I/O:**  For code examples, what are the inputs and expected outputs?
* **Command-Line Arguments:** Does this code involve command-line arguments?
* **Common Mistakes:** Are there any pitfalls for users?
* **Answer Language:** Chinese.

**2. Initial Code Analysis (Skimming and Identifying Key Types/Functions):**

My first pass involves scanning the code for recognizable patterns and keywords:

* **Package Declaration:** `package asn1` immediately suggests it's related to Abstract Syntax Notation One (ASN.1).
* **`encoder` interface:**  This is a central abstraction, indicating a process of preparing data for output. The `Len()` and `Encode()` methods confirm this.
* **Various `...Encoder` types:**  `byteEncoder`, `bytesEncoder`, `stringEncoder`, `multiEncoder`, `setEncoder`, `taggedEncoder`, `int64Encoder`, `oidEncoder`, `bitStringEncoder`. These suggest different ways of encoding various data types into ASN.1.
* **`make...` functions:**  `makeBigInt`, `makeObjectIdentifier`, `makePrintableString`, `makeIA5String`, `makeNumericString`, `makeUTF8String`, `makeUTCTime`, `makeGeneralizedTime`, `makeBody`, `makeField`. These are likely factory functions for creating the various `encoder` implementations.
* **`Marshal` and `MarshalWithParams` functions:**  These are the entry points for the marshaling process, taking a Go value and producing a byte slice.
* **Constants/Variables:** `byte00Encoder`, `byteFFEncoder`. These seem like pre-defined encoders for specific byte values.
* **Imports:** `bytes`, `errors`, `fmt`, `math/big`, `reflect`, `slices`, `time`, `unicode/utf8`. These imports provide clues about the code's dependencies and functionality (e.g., `reflect` for introspection, `time` for time handling).
* **Comments:**  The comments provide valuable context, especially the one explaining the ordering for `setEncoder`.

**3. Inferring the Core Functionality:**

Based on the keywords, types, and function names, the central function is clearly **marshaling Go data structures into ASN.1 encoded byte sequences**. This is the primary goal of the code.

**4. Identifying the Go Language Feature:**

The use of `reflect` is a strong indicator that this code implements **serialization/deserialization** (specifically, serialization or marshaling in this case). It's inspecting the structure of Go types at runtime to convert them into a different format.

**5. Planning the Code Example:**

To illustrate the functionality, a simple struct with various data types that ASN.1 can represent would be ideal. I'd want to include:

* Basic types: `int`, `string`, `bool`
* A time type (`time.Time`) to demonstrate the UTCTime/GeneralizedTime handling.
* A slice to showcase sequence encoding.
* Potentially an `ObjectIdentifier` for more specific ASN.1 features.

I also need to consider the `Marshal` function. The example should demonstrate calling `Marshal` and inspecting the output. Since the output is a byte slice, I'll need a way to represent it (e.g., using hexadecimal representation for clarity).

**6. Addressing Other Requirements:**

* **Assumptions and I/O:**  For the code example, I'll explicitly state the input Go struct and the expected ASN.1 output (which I'll manually derive or simulate based on my understanding of ASN.1 encoding).
* **Command-Line Arguments:**  A quick scan reveals no direct command-line argument processing in this snippet. So the answer will be "no direct handling."
* **Common Mistakes:** The comments and the logic related to tags, lengths, and specific string/time types suggest potential errors in tagging or choosing the correct ASN.1 string type. I'll formulate an example where a user might incorrectly assume a string will always be UTF8.

**7. Structuring the Answer (in Chinese):**

I'll organize the answer according to the user's request:

* **功能列举:**  List the core functionalities identified.
* **Go 语言功能实现:** Explain that it's implementing ASN.1 marshaling using reflection.
* **Go 代码举例:** Provide the planned code example with input and output, explaining the process.
* **命令行参数:** State that there's no direct command-line parameter handling.
* **使用者易犯错的点:**  Explain the potential mistake with string types and provide a counter-example.

**8. Refining and Detailing the Answer:**

During this stage, I'll flesh out the details of each section in Chinese, ensuring clarity and accuracy. For the code example, I'll write the Go code and then attempt to manually derive or use an online ASN.1 encoder to verify the expected output (or at least a conceptual representation of the output). I'll pay attention to the specific rules mentioned in the code comments, such as the sorting of SET elements.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have thought about including a complex example with custom tags. However, for a basic explanation, a simpler example covering the core data types is more effective. I also need to remember the user requested the answer in Chinese, so double-checking the terminology and phrasing is crucial. I need to ensure I'm not just translating English concepts literally but expressing them naturally in Chinese. I also need to make sure the "common mistake" example is clear and easy to understand.

By following these steps, combining code analysis, logical deduction, and careful planning, I can construct a comprehensive and accurate answer to the user's request.
这段代码是 Go 语言 `encoding/asn1` 包中负责将 Go 语言数据结构 **编码 (Marshal)** 成 ASN.1 (Abstract Syntax Notation One) 格式的一部分。

**核心功能列举:**

1. **定义了 `encoder` 接口:**  这是一个核心接口，定义了任何能够被编码成 ASN.1 的元素的行为。所有具体的编码器都必须实现 `Len()` (返回编码后的字节长度) 和 `Encode(dst []byte)` (将编码后的数据写入 `dst` 字节切片) 方法。
2. **实现了多种基础类型的编码器:**
   - `byteEncoder`: 用于编码单个字节。
   - `bytesEncoder`: 用于编码字节切片。
   - `stringEncoder`: 用于编码字符串。
   - `int64Encoder`: 用于编码 int64 类型的整数。
   - `bitStringEncoder`: 用于编码 ASN.1 BIT STRING 类型。
   - `oidEncoder`: 用于编码 ASN.1 OBJECT IDENTIFIER 类型。
3. **实现了复合类型的编码器:**
   - `multiEncoder`:  将多个 `encoder` 组合在一起，按顺序编码。
   - `setEncoder`: 将多个 `encoder` 组合在一起，并按照 ASN.1 DER 规则进行排序后再编码 (用于 SET OF 类型)。
   - `taggedEncoder`:  为其他 `encoder` 添加 ASN.1 Tag 和 Length 信息。
4. **提供了 `make...` 系列函数:** 这些函数根据 Go 语言的类型和值，创建相应的 `encoder` 实例。例如：
   - `makeBigInt`: 创建用于编码 `*big.Int` 的 `encoder`。
   - `makeObjectIdentifier`: 创建用于编码 `[]int` 表示的 OID 的 `encoder`。
   - `makePrintableString`, `makeIA5String`, `makeNumericString`, `makeUTF8String`: 创建用于编码不同 ASN.1 字符串类型的 `encoder`。
   - `makeUTCTime`, `makeGeneralizedTime`: 创建用于编码 `time.Time` 的 `encoder`。
   - `makeBody`:  根据 `reflect.Value` 和 `fieldParameters` 创建数据体的 `encoder`。
   - `makeField`:  处理 Go 结构体字段，根据标签 (tag) 信息创建合适的 `encoder`。
5. **实现了 `Marshal` 和 `MarshalWithParams` 函数:** 这是将 Go 语言数据结构编码成 ASN.1 字节序列的入口点。 `MarshalWithParams` 允许指定顶层元素的字段参数。

**它是什么 Go 语言功能的实现：序列化 (Serialization) 或编组 (Marshaling)**

这段代码实现了将 Go 语言数据结构 **序列化** 或 **编组** 成 ASN.1 格式的功能。 序列化是将内存中的数据结构转换为可以存储或传输的格式的过程。ASN.1 是一种标准的数据序列化格式，常用于网络协议和安全领域。

**Go 代码举例说明:**

```go
package main

import (
	"encoding/asn1"
	"fmt"
	"time"
)

type Person struct {
	Name    string `asn1:"utf8"`
	Age     int
	IsAdult bool `asn1:"optional"`
	Birthday time.Time `asn1:"generalized"`
}

func main() {
	person := Person{
		Name:    "张三",
		Age:     30,
		Birthday: time.Date(1993, 10, 27, 10, 0, 0, 0, time.UTC),
	}

	// 将 person 结构体编码成 ASN.1 格式
	asn1Bytes, err := asn1.Marshal(person)
	if err != nil {
		fmt.Println("编码错误:", err)
		return
	}

	fmt.Printf("ASN.1 编码后的字节: %X\n", asn1Bytes)

	// 假设的解码过程 (这里只是为了演示，实际解码需要使用 Unmarshal)
	// 实际的 ASN.1 字节序列会包含 Tag 和 Length 信息，
	// 这里的输出只是数据部分的近似表示，用于理解编码过程
	// (具体的 ASN.1 编码结果会因编码器实现细节而略有不同)
	// 理论上，编码顺序和类型会影响最终的字节序列

	// 字符串 "张三" (UTF8 编码)
	// 年龄 30
	// Birthday 时间的 GeneralizedTime 格式
}
```

**假设的输入与输出:**

**输入 (Go 结构体 `person`):**

```go
Person{
	Name:    "张三",
	Age:     30,
	Birthday: time.Date(1993, 10, 27, 10, 0, 0, 0, time.UTC),
}
```

**可能的输出 (ASN.1 编码后的字节，十六进制表示):**

```
ASN.1 编码后的字节: 30100C08E5BCA0E4B889E4B88902011E180F3139393331303237313030305A
```

**解释 (粗略分析，实际结果会更复杂):**

* `30 10`:  这是一个 SEQUENCE 类型的构造，长度为 16 字节 (0x10)。
* `0C 08`:  接下来是 UTF8String 类型 (0x0C)，长度为 8 字节 (0x08)。
* `E5 BC A0 E4 B8 89 E4 B8 89`:  "张三" 的 UTF8 编码。
* `02 01`:  INTEGER 类型 (0x02)，长度为 1 字节 (0x01)。
* `1E`:  数字 30 的十六进制表示。
* `18 0F`:  GeneralizedTime 类型 (0x18)，长度为 15 字节 (0x0F)。
* `31 39 39 33 31 30 32 37 31 30 30 30 5A`: "19931027100000Z" 的 ASCII 表示 (GeneralizedTime 格式)。

**请注意:**  这只是一个简化的例子，实际的 ASN.1 编码会更复杂，涉及到 Tag、Length 和 Value 的具体编码规则。 使用 `asn1.Unmarshal` 可以将 ASN.1 字节序列解码回 Go 语言结构体。

**命令行参数的具体处理:**

这段代码本身 **不直接处理命令行参数**。 它的功能是将 Go 语言的数据结构编码成 ASN.1 格式。  如果需要在命令行中使用 ASN.1 编码，通常会编写一个使用此包的命令行工具，该工具会负责解析命令行参数并调用 `asn1.Marshal` 进行编码。

**使用者易犯错的点:**

1. **对 ASN.1 Tag 的理解不足:**  `asn1` 标签用于指定 Go 结构体字段对应的 ASN.1 类型和选项。错误地使用标签 (例如，指定了错误的类型) 会导致编码错误。
   ```go
   type Example struct {
       Value string `asn1:"ia5"` // 期望是 IA5String，但如果字符串包含非 ASCII 字符会出错
   }
   ```
2. **时间类型的处理:**  `time.Time` 默认会被编码成 UTCTime，但 UTCTime 的年份范围有限制 (1950-2049)。如果时间超出此范围，需要使用 `generalized` 标签强制使用 GeneralizedTime。
   ```go
   type Event struct {
       Timestamp time.Time // 默认编码为 UTCTime，如果年份不在 1950-2049 会出错
   }

   type EventGeneralized struct {
       Timestamp time.Time `asn1:"generalized"` // 强制使用 GeneralizedTime，支持更广的年份范围
   }
   ```
3. **字符串类型的选择:** ASN.1 有多种字符串类型 (PrintableString, IA5String, UTF8String 等)。选择错误的字符串类型可能导致编码后的数据不符合规范或无法被正确解析。
   ```go
   type Text struct {
       Content string `asn1:"printable"` // 如果 Content 包含非 Printable 字符会出错
   }
   ```
4. **`omitempty` 的使用:**  `omitempty` 标签用于在切片或映射为空时省略该字段的编码。不了解其作用可能导致编码结果与预期不符。
   ```go
   type Data struct {
       Items []string `asn1:"omitempty"`
   }

   data1 := Data{Items: []string{"a", "b"}}
   data2 := Data{Items: []string{}}

   // data1 会编码 Items 字段
   // data2 不会编码 Items 字段
   ```

总而言之，这段代码是 Go 语言 `encoding/asn1` 包中实现 ASN.1 编码的核心部分，它定义了编码器的接口和各种类型的编码实现，并通过反射机制将 Go 语言数据结构转换为 ASN.1 字节序列。理解 ASN.1 的基本概念和 `asn1` 标签的使用是正确使用这个包的关键。

### 提示词
```
这是路径为go/src/encoding/asn1/marshal.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package asn1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"time"
	"unicode/utf8"
)

var (
	byte00Encoder encoder = byteEncoder(0x00)
	byteFFEncoder encoder = byteEncoder(0xff)
)

// encoder represents an ASN.1 element that is waiting to be marshaled.
type encoder interface {
	// Len returns the number of bytes needed to marshal this element.
	Len() int
	// Encode encodes this element by writing Len() bytes to dst.
	Encode(dst []byte)
}

type byteEncoder byte

func (c byteEncoder) Len() int {
	return 1
}

func (c byteEncoder) Encode(dst []byte) {
	dst[0] = byte(c)
}

type bytesEncoder []byte

func (b bytesEncoder) Len() int {
	return len(b)
}

func (b bytesEncoder) Encode(dst []byte) {
	if copy(dst, b) != len(b) {
		panic("internal error")
	}
}

type stringEncoder string

func (s stringEncoder) Len() int {
	return len(s)
}

func (s stringEncoder) Encode(dst []byte) {
	if copy(dst, s) != len(s) {
		panic("internal error")
	}
}

type multiEncoder []encoder

func (m multiEncoder) Len() int {
	var size int
	for _, e := range m {
		size += e.Len()
	}
	return size
}

func (m multiEncoder) Encode(dst []byte) {
	var off int
	for _, e := range m {
		e.Encode(dst[off:])
		off += e.Len()
	}
}

type setEncoder []encoder

func (s setEncoder) Len() int {
	var size int
	for _, e := range s {
		size += e.Len()
	}
	return size
}

func (s setEncoder) Encode(dst []byte) {
	// Per X690 Section 11.6: The encodings of the component values of a
	// set-of value shall appear in ascending order, the encodings being
	// compared as octet strings with the shorter components being padded
	// at their trailing end with 0-octets.
	//
	// First we encode each element to its TLV encoding and then use
	// octetSort to get the ordering expected by X690 DER rules before
	// writing the sorted encodings out to dst.
	l := make([][]byte, len(s))
	for i, e := range s {
		l[i] = make([]byte, e.Len())
		e.Encode(l[i])
	}

	// Since we are using bytes.Compare to compare TLV encodings we
	// don't need to right pad s[i] and s[j] to the same length as
	// suggested in X690. If len(s[i]) < len(s[j]) the length octet of
	// s[i], which is the first determining byte, will inherently be
	// smaller than the length octet of s[j]. This lets us skip the
	// padding step.
	slices.SortFunc(l, bytes.Compare)

	var off int
	for _, b := range l {
		copy(dst[off:], b)
		off += len(b)
	}
}

type taggedEncoder struct {
	// scratch contains temporary space for encoding the tag and length of
	// an element in order to avoid extra allocations.
	scratch [8]byte
	tag     encoder
	body    encoder
}

func (t *taggedEncoder) Len() int {
	return t.tag.Len() + t.body.Len()
}

func (t *taggedEncoder) Encode(dst []byte) {
	t.tag.Encode(dst)
	t.body.Encode(dst[t.tag.Len():])
}

type int64Encoder int64

func (i int64Encoder) Len() int {
	n := 1

	for i > 127 {
		n++
		i >>= 8
	}

	for i < -128 {
		n++
		i >>= 8
	}

	return n
}

func (i int64Encoder) Encode(dst []byte) {
	n := i.Len()

	for j := 0; j < n; j++ {
		dst[j] = byte(i >> uint((n-1-j)*8))
	}
}

func base128IntLength(n int64) int {
	if n == 0 {
		return 1
	}

	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}

	return l
}

func appendBase128Int(dst []byte, n int64) []byte {
	l := base128IntLength(n)

	for i := l - 1; i >= 0; i-- {
		o := byte(n >> uint(i*7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}

		dst = append(dst, o)
	}

	return dst
}

func makeBigInt(n *big.Int) (encoder, error) {
	if n == nil {
		return nil, StructuralError{"empty integer"}
	}

	if n.Sign() < 0 {
		// A negative number has to be converted to two's-complement
		// form. So we'll invert and subtract 1. If the
		// most-significant-bit isn't set then we'll need to pad the
		// beginning with 0xff in order to keep the number negative.
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bytes := nMinus1.Bytes()
		for i := range bytes {
			bytes[i] ^= 0xff
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			return multiEncoder([]encoder{byteFFEncoder, bytesEncoder(bytes)}), nil
		}
		return bytesEncoder(bytes), nil
	} else if n.Sign() == 0 {
		// Zero is written as a single 0 zero rather than no bytes.
		return byte00Encoder, nil
	} else {
		bytes := n.Bytes()
		if len(bytes) > 0 && bytes[0]&0x80 != 0 {
			// We'll have to pad this with 0x00 in order to stop it
			// looking like a negative number.
			return multiEncoder([]encoder{byte00Encoder, bytesEncoder(bytes)}), nil
		}
		return bytesEncoder(bytes), nil
	}
}

func appendLength(dst []byte, i int) []byte {
	n := lengthLength(i)

	for ; n > 0; n-- {
		dst = append(dst, byte(i>>uint((n-1)*8)))
	}

	return dst
}

func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

func appendTagAndLength(dst []byte, t tagAndLength) []byte {
	b := uint8(t.class) << 6
	if t.isCompound {
		b |= 0x20
	}
	if t.tag >= 31 {
		b |= 0x1f
		dst = append(dst, b)
		dst = appendBase128Int(dst, int64(t.tag))
	} else {
		b |= uint8(t.tag)
		dst = append(dst, b)
	}

	if t.length >= 128 {
		l := lengthLength(t.length)
		dst = append(dst, 0x80|byte(l))
		dst = appendLength(dst, t.length)
	} else {
		dst = append(dst, byte(t.length))
	}

	return dst
}

type bitStringEncoder BitString

func (b bitStringEncoder) Len() int {
	return len(b.Bytes) + 1
}

func (b bitStringEncoder) Encode(dst []byte) {
	dst[0] = byte((8 - b.BitLength%8) % 8)
	if copy(dst[1:], b.Bytes) != len(b.Bytes) {
		panic("internal error")
	}
}

type oidEncoder []int

func (oid oidEncoder) Len() int {
	l := base128IntLength(int64(oid[0]*40 + oid[1]))
	for i := 2; i < len(oid); i++ {
		l += base128IntLength(int64(oid[i]))
	}
	return l
}

func (oid oidEncoder) Encode(dst []byte) {
	dst = appendBase128Int(dst[:0], int64(oid[0]*40+oid[1]))
	for i := 2; i < len(oid); i++ {
		dst = appendBase128Int(dst, int64(oid[i]))
	}
}

func makeObjectIdentifier(oid []int) (e encoder, err error) {
	if len(oid) < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
		return nil, StructuralError{"invalid object identifier"}
	}

	return oidEncoder(oid), nil
}

func makePrintableString(s string) (e encoder, err error) {
	for i := 0; i < len(s); i++ {
		// The asterisk is often used in PrintableString, even though
		// it is invalid. If a PrintableString was specifically
		// requested then the asterisk is permitted by this code.
		// Ampersand is allowed in parsing due a handful of CA
		// certificates, however when making new certificates
		// it is rejected.
		if !isPrintable(s[i], allowAsterisk, rejectAmpersand) {
			return nil, StructuralError{"PrintableString contains invalid character"}
		}
	}

	return stringEncoder(s), nil
}

func makeIA5String(s string) (e encoder, err error) {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return nil, StructuralError{"IA5String contains invalid character"}
		}
	}

	return stringEncoder(s), nil
}

func makeNumericString(s string) (e encoder, err error) {
	for i := 0; i < len(s); i++ {
		if !isNumeric(s[i]) {
			return nil, StructuralError{"NumericString contains invalid character"}
		}
	}

	return stringEncoder(s), nil
}

func makeUTF8String(s string) encoder {
	return stringEncoder(s)
}

func appendTwoDigits(dst []byte, v int) []byte {
	return append(dst, byte('0'+(v/10)%10), byte('0'+v%10))
}

func appendFourDigits(dst []byte, v int) []byte {
	return append(dst,
		byte('0'+(v/1000)%10),
		byte('0'+(v/100)%10),
		byte('0'+(v/10)%10),
		byte('0'+v%10))
}

func outsideUTCRange(t time.Time) bool {
	year := t.Year()
	return year < 1950 || year >= 2050
}

func makeUTCTime(t time.Time) (e encoder, err error) {
	dst := make([]byte, 0, 18)

	dst, err = appendUTCTime(dst, t)
	if err != nil {
		return nil, err
	}

	return bytesEncoder(dst), nil
}

func makeGeneralizedTime(t time.Time) (e encoder, err error) {
	dst := make([]byte, 0, 20)

	dst, err = appendGeneralizedTime(dst, t)
	if err != nil {
		return nil, err
	}

	return bytesEncoder(dst), nil
}

func appendUTCTime(dst []byte, t time.Time) (ret []byte, err error) {
	year := t.Year()

	switch {
	case 1950 <= year && year < 2000:
		dst = appendTwoDigits(dst, year-1900)
	case 2000 <= year && year < 2050:
		dst = appendTwoDigits(dst, year-2000)
	default:
		return nil, StructuralError{"cannot represent time as UTCTime"}
	}

	return appendTimeCommon(dst, t), nil
}

func appendGeneralizedTime(dst []byte, t time.Time) (ret []byte, err error) {
	year := t.Year()
	if year < 0 || year > 9999 {
		return nil, StructuralError{"cannot represent time as GeneralizedTime"}
	}

	dst = appendFourDigits(dst, year)

	return appendTimeCommon(dst, t), nil
}

func appendTimeCommon(dst []byte, t time.Time) []byte {
	_, month, day := t.Date()

	dst = appendTwoDigits(dst, int(month))
	dst = appendTwoDigits(dst, day)

	hour, min, sec := t.Clock()

	dst = appendTwoDigits(dst, hour)
	dst = appendTwoDigits(dst, min)
	dst = appendTwoDigits(dst, sec)

	_, offset := t.Zone()

	switch {
	case offset/60 == 0:
		return append(dst, 'Z')
	case offset > 0:
		dst = append(dst, '+')
	case offset < 0:
		dst = append(dst, '-')
	}

	offsetMinutes := offset / 60
	if offsetMinutes < 0 {
		offsetMinutes = -offsetMinutes
	}

	dst = appendTwoDigits(dst, offsetMinutes/60)
	dst = appendTwoDigits(dst, offsetMinutes%60)

	return dst
}

func stripTagAndLength(in []byte) []byte {
	_, offset, err := parseTagAndLength(in, 0)
	if err != nil {
		return in
	}
	return in[offset:]
}

func makeBody(value reflect.Value, params fieldParameters) (e encoder, err error) {
	switch value.Type() {
	case flagType:
		return bytesEncoder(nil), nil
	case timeType:
		t := value.Interface().(time.Time)
		if params.timeType == TagGeneralizedTime || outsideUTCRange(t) {
			return makeGeneralizedTime(t)
		}
		return makeUTCTime(t)
	case bitStringType:
		return bitStringEncoder(value.Interface().(BitString)), nil
	case objectIdentifierType:
		return makeObjectIdentifier(value.Interface().(ObjectIdentifier))
	case bigIntType:
		return makeBigInt(value.Interface().(*big.Int))
	}

	switch v := value; v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			return byteFFEncoder, nil
		}
		return byte00Encoder, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int64Encoder(v.Int()), nil
	case reflect.Struct:
		t := v.Type()

		for i := 0; i < t.NumField(); i++ {
			if !t.Field(i).IsExported() {
				return nil, StructuralError{"struct contains unexported fields"}
			}
		}

		startingField := 0

		n := t.NumField()
		if n == 0 {
			return bytesEncoder(nil), nil
		}

		// If the first element of the structure is a non-empty
		// RawContents, then we don't bother serializing the rest.
		if t.Field(0).Type == rawContentsType {
			s := v.Field(0)
			if s.Len() > 0 {
				bytes := s.Bytes()
				/* The RawContents will contain the tag and
				 * length fields but we'll also be writing
				 * those ourselves, so we strip them out of
				 * bytes */
				return bytesEncoder(stripTagAndLength(bytes)), nil
			}

			startingField = 1
		}

		switch n1 := n - startingField; n1 {
		case 0:
			return bytesEncoder(nil), nil
		case 1:
			return makeField(v.Field(startingField), parseFieldParameters(t.Field(startingField).Tag.Get("asn1")))
		default:
			m := make([]encoder, n1)
			for i := 0; i < n1; i++ {
				m[i], err = makeField(v.Field(i+startingField), parseFieldParameters(t.Field(i+startingField).Tag.Get("asn1")))
				if err != nil {
					return nil, err
				}
			}

			return multiEncoder(m), nil
		}
	case reflect.Slice:
		sliceType := v.Type()
		if sliceType.Elem().Kind() == reflect.Uint8 {
			return bytesEncoder(v.Bytes()), nil
		}

		var fp fieldParameters

		switch l := v.Len(); l {
		case 0:
			return bytesEncoder(nil), nil
		case 1:
			return makeField(v.Index(0), fp)
		default:
			m := make([]encoder, l)

			for i := 0; i < l; i++ {
				m[i], err = makeField(v.Index(i), fp)
				if err != nil {
					return nil, err
				}
			}

			if params.set {
				return setEncoder(m), nil
			}
			return multiEncoder(m), nil
		}
	case reflect.String:
		switch params.stringType {
		case TagIA5String:
			return makeIA5String(v.String())
		case TagPrintableString:
			return makePrintableString(v.String())
		case TagNumericString:
			return makeNumericString(v.String())
		default:
			return makeUTF8String(v.String()), nil
		}
	}

	return nil, StructuralError{"unknown Go type"}
}

func makeField(v reflect.Value, params fieldParameters) (e encoder, err error) {
	if !v.IsValid() {
		return nil, fmt.Errorf("asn1: cannot marshal nil value")
	}
	// If the field is an interface{} then recurse into it.
	if v.Kind() == reflect.Interface && v.Type().NumMethod() == 0 {
		return makeField(v.Elem(), params)
	}

	if v.Kind() == reflect.Slice && v.Len() == 0 && params.omitEmpty {
		return bytesEncoder(nil), nil
	}

	if params.optional && params.defaultValue != nil && canHaveDefaultValue(v.Kind()) {
		defaultValue := reflect.New(v.Type()).Elem()
		defaultValue.SetInt(*params.defaultValue)

		if reflect.DeepEqual(v.Interface(), defaultValue.Interface()) {
			return bytesEncoder(nil), nil
		}
	}

	// If no default value is given then the zero value for the type is
	// assumed to be the default value. This isn't obviously the correct
	// behavior, but it's what Go has traditionally done.
	if params.optional && params.defaultValue == nil {
		if reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface()) {
			return bytesEncoder(nil), nil
		}
	}

	if v.Type() == rawValueType {
		rv := v.Interface().(RawValue)
		if len(rv.FullBytes) != 0 {
			return bytesEncoder(rv.FullBytes), nil
		}

		t := new(taggedEncoder)

		t.tag = bytesEncoder(appendTagAndLength(t.scratch[:0], tagAndLength{rv.Class, rv.Tag, len(rv.Bytes), rv.IsCompound}))
		t.body = bytesEncoder(rv.Bytes)

		return t, nil
	}

	matchAny, tag, isCompound, ok := getUniversalType(v.Type())
	if !ok || matchAny {
		return nil, StructuralError{fmt.Sprintf("unknown Go type: %v", v.Type())}
	}

	if params.timeType != 0 && tag != TagUTCTime {
		return nil, StructuralError{"explicit time type given to non-time member"}
	}

	if params.stringType != 0 && tag != TagPrintableString {
		return nil, StructuralError{"explicit string type given to non-string member"}
	}

	switch tag {
	case TagPrintableString:
		if params.stringType == 0 {
			// This is a string without an explicit string type. We'll use
			// a PrintableString if the character set in the string is
			// sufficiently limited, otherwise we'll use a UTF8String.
			for _, r := range v.String() {
				if r >= utf8.RuneSelf || !isPrintable(byte(r), rejectAsterisk, rejectAmpersand) {
					if !utf8.ValidString(v.String()) {
						return nil, errors.New("asn1: string not valid UTF-8")
					}
					tag = TagUTF8String
					break
				}
			}
		} else {
			tag = params.stringType
		}
	case TagUTCTime:
		if params.timeType == TagGeneralizedTime || outsideUTCRange(v.Interface().(time.Time)) {
			tag = TagGeneralizedTime
		}
	}

	if params.set {
		if tag != TagSequence {
			return nil, StructuralError{"non sequence tagged as set"}
		}
		tag = TagSet
	}

	// makeField can be called for a slice that should be treated as a SET
	// but doesn't have params.set set, for instance when using a slice
	// with the SET type name suffix. In this case getUniversalType returns
	// TagSet, but makeBody doesn't know about that so will treat the slice
	// as a sequence. To work around this we set params.set.
	if tag == TagSet && !params.set {
		params.set = true
	}

	t := new(taggedEncoder)

	t.body, err = makeBody(v, params)
	if err != nil {
		return nil, err
	}

	bodyLen := t.body.Len()

	class := ClassUniversal
	if params.tag != nil {
		if params.application {
			class = ClassApplication
		} else if params.private {
			class = ClassPrivate
		} else {
			class = ClassContextSpecific
		}

		if params.explicit {
			t.tag = bytesEncoder(appendTagAndLength(t.scratch[:0], tagAndLength{ClassUniversal, tag, bodyLen, isCompound}))

			tt := new(taggedEncoder)

			tt.body = t

			tt.tag = bytesEncoder(appendTagAndLength(tt.scratch[:0], tagAndLength{
				class:      class,
				tag:        *params.tag,
				length:     bodyLen + t.tag.Len(),
				isCompound: true,
			}))

			return tt, nil
		}

		// implicit tag.
		tag = *params.tag
	}

	t.tag = bytesEncoder(appendTagAndLength(t.scratch[:0], tagAndLength{class, tag, bodyLen, isCompound}))

	return t, nil
}

// Marshal returns the ASN.1 encoding of val.
//
// In addition to the struct tags recognized by Unmarshal, the following can be
// used:
//
//	ia5:         causes strings to be marshaled as ASN.1, IA5String values
//	omitempty:   causes empty slices to be skipped
//	printable:   causes strings to be marshaled as ASN.1, PrintableString values
//	utf8:        causes strings to be marshaled as ASN.1, UTF8String values
//	utc:         causes time.Time to be marshaled as ASN.1, UTCTime values
//	generalized: causes time.Time to be marshaled as ASN.1, GeneralizedTime values
func Marshal(val any) ([]byte, error) {
	return MarshalWithParams(val, "")
}

// MarshalWithParams allows field parameters to be specified for the
// top-level element. The form of the params is the same as the field tags.
func MarshalWithParams(val any, params string) ([]byte, error) {
	e, err := makeField(reflect.ValueOf(val), parseFieldParameters(params))
	if err != nil {
		return nil, err
	}
	b := make([]byte, e.Len())
	e.Encode(b)
	return b, nil
}
```