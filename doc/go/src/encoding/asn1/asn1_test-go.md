Response:
Let's break down the thought process for analyzing this Go code snippet for the `encoding/asn1` package.

**1. Initial Scan and Keyword Recognition:**

* **Package Name:** `asn1`. This immediately tells me the code is related to Abstract Syntax Notation One, a standard for data serialization.
* **Import Statements:** `bytes`, `encoding/hex`, `fmt`, `math`, `math/big`, `reflect`, `strings`, `testing`, `time`. These imports indicate the code will involve byte manipulation, hexadecimal encoding, formatted output, mathematical operations (including big integers), reflection (for examining types at runtime), string manipulation, testing, and time handling.
* **`type` declarations:** `boolTest`, `int64Test`, `int32Test`, `bitStringTest`, `bitStringRightAlignTest`, `objectIdentifierTest`, `timeTest`, `tagAndLengthTest`, `parseFieldParametersTest`, `TestObjectIdentifierStruct`, `TestContextSpecificTags`, `TestContextSpecificTags2`, `TestContextSpecificTags3`, `TestElementsAfterString`, `TestBigInt`, `TestSet`, `Certificate`, `TBSCertificate`, `AlgorithmIdentifier`, `RDNSequence`, `RelativeDistinguishedNameSET`, `AttributeTypeAndValue`, `Validity`, `PublicKeyInfo`, `rawStructTest`, `oiEqualTest`. The sheer number of custom types strongly suggests this is a *testing* file. These types are likely designed to hold test data or represent structures relevant to ASN.1 encoding/decoding.
* **`var` declarations ending in `TestData` or `Tests`:** `boolTestData`, `int64TestData`, `int32TestData`, `bigIntTests`, `bitStringTestData`, `bitStringRightAlignTests`, `objectIdentifierTestData`, `utcTestData`, `generalizedTimeTestData`, `tagAndLengthData`, `parseFieldParametersTestData`, `unmarshalTestData`, `oiEqualTests`, `derEncodedSelfSignedCert`, `derEncodedSelfSignedCertBytes`, `derEncodedPaypalNULCertBytes`. This reinforces the idea that this is a testing file, providing various inputs and expected outputs for different ASN.1 types and parsing functions.
* **`func Test...`:**  `TestParseBool`, `TestParseInt64`, `TestParseInt32`, `TestParseBigInt`, `TestBitString`, `TestBitStringAt`, `TestBitStringRightAlign`, `TestObjectIdentifier`, `TestUTCTime`, `TestGeneralizedTime`, `TestParseTagAndLength`, `TestParseFieldParameters`, `TestUnmarshal`, `TestUnmarshalWithNilOrNonPointer`, `TestCertificate`, `TestCertificateWithNUL`, `TestRawStructs`, `TestObjectIdentifierEqual`. These are clearly the individual test functions.

**2. Deeper Dive into Functionality by Test Function:**

* **`TestParseBool`:** Tests the `parseBool` function, taking byte slices as input and expecting a boolean output. The test cases suggest different byte representations of booleans (0x00 for false, 0xff for true).
* **`TestParseInt64`, `TestParseInt32`:** Similar to `TestParseBool`, these test functions for `parseInt64` and `parseInt32` deal with parsing byte slices into integer types. The test data includes positive, negative, and boundary values.
* **`TestParseBigInt`:** Tests `parseBigInt`, indicating support for arbitrarily large integers. The test cases involve byte representations of positive and negative large numbers. The code also seems to test the reverse operation (`makeBigInt` and `Encode`).
* **`TestBitString`:** Tests `parseBitString`. Bit strings have both byte data and a bit length. The test cases cover various byte sequences and bit lengths.
* **`TestBitStringAt`, `TestBitStringRightAlign`:** These test specific functionalities of the `BitString` type, accessing individual bits and right-aligning the bit representation.
* **`TestObjectIdentifier`:** Tests `parseObjectIdentifier`. Object Identifiers (OIDs) are hierarchical identifiers represented by sequences of integers. The test data includes valid and invalid OID byte sequences. The `String()` method of `ObjectIdentifier` is also tested.
* **`TestUTCTime`, `TestGeneralizedTime`:** These test parsing of different ASN.1 time formats into `time.Time` values. The test data includes valid and invalid time strings, considering timezones.
* **`TestParseTagAndLength`:** Tests `parseTagAndLength`, a crucial function for parsing the structure of ASN.1 encoded data. It extracts the tag (type), class, and length of a data element. The test cases cover different tag numbers and length encodings.
* **`TestParseFieldParameters`:** Tests `parseFieldParameters`. This function likely parses struct field tags (using reflection) to extract ASN.1 specific options like `optional`, `explicit`, `tag`, `default`, and string/time type hints.
* **`TestUnmarshal`:** This is a major test function. It uses `Unmarshal` to decode ASN.1 byte sequences into Go structs. The `unmarshalTestData` shows examples of decoding various ASN.1 types (integers, strings, bit strings, object identifiers, booleans, nested structures, big integers, sets) into corresponding Go types.
* **`TestUnmarshalWithNilOrNonPointer`:**  Specifically tests error handling when `Unmarshal` is called with invalid recipient types (nil or non-pointer).
* **`TestCertificate`, `TestCertificateWithNUL`:** These test the `Unmarshal` function with more complex data structures representing X.509 certificates. The "NUL-hack" test is designed to verify correct handling of invalid characters.
* **`TestRawStructs`:** Tests the `RawContent` type, which allows capturing the raw ASN.1 encoding of a section of data.
* **`TestObjectIdentifierEqual`:** Tests the `Equal` method of the `ObjectIdentifier` type.

**3. Inferring the Go Language Feature:**

Based on the prevalence of `Unmarshal`, the various data types, and the focus on parsing byte sequences into structured data, it's clear that this code is implementing **ASN.1 encoding and decoding** functionality in Go. The `encoding/asn1` package provides tools to work with this standard.

**4. Summarizing the Functionality (for Part 1):**

This section of the `go/src/encoding/asn1/asn1_test.go` file focuses on testing the **decoding (unmarshaling)** functionality of the `encoding/asn1` package in Go. It includes tests for:

* **Parsing basic ASN.1 types:** Boolean, Integer (int32, int64, big.Int), Bit String, Object Identifier.
* **Parsing ASN.1 time types:**  UTCTime and GeneralizedTime.
* **Parsing the tag and length of ASN.1 encoded values.**
* **Parsing struct field tags to extract ASN.1 encoding directives.**
* **Unmarshaling ASN.1 byte sequences into Go structs,** covering various ASN.1 types and structures, including nested structures and sets.
* **Handling errors during unmarshaling,** such as invalid input or incorrect recipient types.
* **Specific tests for unmarshaling X.509 certificates.**
* **Testing the `RawContent` type for capturing raw ASN.1 data.**
* **Testing the equality of Object Identifiers.**

Essentially, this part of the test suite verifies that the `encoding/asn1` package can correctly decode ASN.1 encoded data into Go data structures.

This methodical approach allows for a comprehensive understanding of the code's purpose and the specific features it tests. It utilizes the structure of Go test files and the naming conventions to quickly identify the core functionalities being validated.
好的，让我们来分析一下 `go/src/encoding/asn1/asn1_test.go` 的这部分代码的功能。

**功能归纳 (针对提供的第 1 部分代码):**

这段代码是 Go 语言标准库 `encoding/asn1` 包的测试代码的一部分，专门用于测试 **ASN.1 数据的解码 (Unmarshal) 功能**。 它包含了各种测试用例，用于验证 `asn1` 包能否正确地将 ASN.1 编码的字节流解析成 Go 语言中的各种数据类型。

**更具体的功能点包括：**

1. **基本数据类型的解析测试:**
   - `TestParseBool`: 测试将 ASN.1 布尔类型编码的字节解析为 Go 的 `bool` 类型。
   - `TestParseInt64`, `TestParseInt32`: 测试将 ASN.1 整数类型编码的字节解析为 Go 的 `int64` 和 `int32` 类型。
   - `TestParseBigInt`: 测试将 ASN.1 任意精度整数类型编码的字节解析为 Go 的 `big.Int` 类型。
   - `TestBitString`: 测试将 ASN.1 比特串类型编码的字节解析为 Go 的 `asn1.BitString` 类型。
   - `TestObjectIdentifier`: 测试将 ASN.1 对象标识符 (Object Identifier) 类型编码的字节解析为 Go 的 `asn1.ObjectIdentifier` 类型。

2. **时间类型的解析测试:**
   - `TestUTCTime`: 测试将 ASN.1 UTC 时间类型编码的字符串解析为 Go 的 `time.Time` 类型。
   - `TestGeneralizedTime`: 测试将 ASN.1 通用时间类型编码的字符串解析为 Go 的 `time.Time` 类型。

3. **底层结构解析测试:**
   - `TestParseTagAndLength`: 测试解析 ASN.1 编码中表示标签 (Tag) 和长度 (Length) 的字节。

4. **结构体字段参数解析测试:**
   - `TestParseFieldParameters`: 测试解析 Go 结构体字段标签 (tag)，以提取 ASN.1 相关的参数，例如 `optional`, `explicit`, `tag`, `default` 等。这对于 `Unmarshal` 函数根据结构体定义进行解码至关重要。

5. **`Unmarshal` 函数的核心功能测试:**
   - `TestUnmarshal`:  这是最重要的测试，它使用 `asn1.Unmarshal` 函数将 ASN.1 编码的字节流直接解码到各种 Go 结构体和基本类型中。 这些测试用例覆盖了多种 ASN.1 数据类型和组合方式。
   - `TestUnmarshalWithNilOrNonPointer`: 测试 `Unmarshal` 函数在接收到 `nil` 或非指针类型的参数时是否能正确处理并返回错误。

6. **复杂数据结构的解析测试:**
   - `TestCertificate`, `TestCertificateWithNUL`:  使用 X.509 证书作为更复杂的 ASN.1 数据结构进行测试，验证 `Unmarshal` 函数处理嵌套结构和特定 ASN.1 规则的能力。`TestCertificateWithNUL` 专门测试了对包含非法字符的编码的处理。
   - `TestRawStructs`: 测试使用 `asn1.RawContent` 类型来捕获原始的 ASN.1 编码片段。

7. **辅助功能测试:**
   - `TestBitStringAt`: 测试 `asn1.BitString` 类型的 `At` 方法，用于访问特定位置的比特。
   - `TestBitStringRightAlign`: 测试 `asn1.BitString` 类型的 `RightAlign` 方法，用于将比特串右对齐。
   - `TestObjectIdentifierEqual`: 测试 `asn1.ObjectIdentifier` 类型的 `Equal` 方法，用于比较两个对象标识符是否相等。

**代码功能背后的 Go 语言功能实现推理:**

这段代码测试的是 Go 语言标准库 `encoding/asn1` 包提供的 **ASN.1 数据编码和解码功能**。 `encoding/asn1` 包使用反射 (reflection) 机制来实现通用 ASN.1 数据的编解码。

**Go 代码举例说明 (Unmarshal 功能):**

假设我们有以下 ASN.1 编码的字节流，它表示一个整数和一个字符串：

```
ber := []byte{0x30, 0x09, 0x02, 0x01, 0x0A, 0x16, 0x04, 0x74, 0x65, 0x73, 0x74}
```

这个字节流的含义是：
- `0x30`:  SEQUENCE (复合类型)
- `0x09`:  SEQUENCE 的长度为 9 字节
- `0x02`:  INTEGER 标签
- `0x01`:  INTEGER 的长度为 1 字节
- `0x0A`:  INTEGER 的值为 10
- `0x16`:  PrintableString 标签
- `0x04`:  PrintableString 的长度为 4 字节
- `0x74, 0x65, 0x73, 0x74`: PrintableString 的值为 "test"

我们可以定义一个 Go 结构体来接收这个 ASN.1 数据：

```go
type MyData struct {
	ID   int
	Name string
}
```

然后使用 `asn1.Unmarshal` 进行解码：

```go
package main

import (
	"encoding/asn1"
	"fmt"
)

type MyData struct {
	ID   int
	Name string
}

func main() {
	ber := []byte{0x30, 0x09, 0x02, 0x01, 0x0A, 0x16, 0x04, 0x74, 0x65, 0x73, 0x74}
	var data MyData
	_, err := asn1.Unmarshal(ber, &data)
	if err != nil {
		fmt.Println("Unmarshal error:", err)
		return
	}
	fmt.Printf("ID: %d, Name: %s\n", data.ID, data.Name) // 输出: ID: 10, Name: test
}
```

**假设的输入与输出 (针对 `TestParseBool`):**

**输入:** `[]byte{0xff}`
**输出:** `true`, `nil` (没有错误)

**输入:** `[]byte{0x00, 0x00}`
**输出:** `false`, `非 nil 的 error` (因为布尔类型应该只有一个字节)

**命令行参数的具体处理:**

这段代码是测试代码，本身不涉及命令行参数的处理。`go test` 命令会执行这些测试用例，但 `asn1` 包的解码功能本身不依赖于命令行参数。

**使用者易犯错的点 (针对 `Unmarshal`):**

1. **Go 结构体字段类型与 ASN.1 数据类型不匹配:**  如果 Go 结构体字段的类型与 ASN.1 数据的类型不兼容，`Unmarshal` 会返回错误。例如，尝试将一个 ASN.1 INTEGER 解码到一个 `string` 字段。

   ```go
   type IncorrectData struct {
       ID string // 错误：应该使用 int 类型
   }
   ```

2. **Go 结构体字段标签 (tag) 设置错误:**  `Unmarshal` 依赖于结构体字段的标签来确定如何解码 ASN.1 数据。标签设置错误会导致解码失败或得到意外的结果。

   ```go
   type TagErrorData struct {
       ID int `asn1:" неправильный_tag"` // 错误的标签语法
   }
   ```

3. **尝试解码到非指针类型:** `Unmarshal` 函数的第二个参数必须是指针类型，以便修改其指向的值。如果传递的是非指针类型，会返回错误。这在 `TestUnmarshalWithNilOrNonPointer` 中有测试。

   ```go
   var data MyData
   _, err := asn1.Unmarshal(ber, data) // 错误：data 应该是指针 &data
   ```

4. **忽略 `Unmarshal` 的返回值:** `Unmarshal` 返回剩余未解析的字节和一个错误。忽略错误会导致无法发现解码问题。

**总结一下它的功能 (针对提供的第 1 部分代码):**

提供的 Go 代码是 `encoding/asn1` 包的测试用例，主要用于验证 **ASN.1 数据的解码 (Unmarshal)** 功能的正确性。它涵盖了对各种 ASN.1 基本类型、时间类型、底层结构以及复杂数据结构的解码测试，并通过不同的测试函数针对特定的解码场景和错误情况进行了验证。 这些测试用例确保了 `encoding/asn1` 包能够可靠地将 ASN.1 编码的数据转换为 Go 语言中的数据结构。

Prompt: 
```
这是路径为go/src/encoding/asn1/asn1_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

type boolTest struct {
	in  []byte
	ok  bool
	out bool
}

var boolTestData = []boolTest{
	{[]byte{0x00}, true, false},
	{[]byte{0xff}, true, true},
	{[]byte{0x00, 0x00}, false, false},
	{[]byte{0xff, 0xff}, false, false},
	{[]byte{0x01}, false, false},
}

func TestParseBool(t *testing.T) {
	for i, test := range boolTestData {
		ret, err := parseBool(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did fail? %v, expected: %v)", i, err == nil, test.ok)
		}
		if test.ok && ret != test.out {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ret, test.out)
		}
	}
}

type int64Test struct {
	in  []byte
	ok  bool
	out int64
}

var int64TestData = []int64Test{
	{[]byte{0x00}, true, 0},
	{[]byte{0x7f}, true, 127},
	{[]byte{0x00, 0x80}, true, 128},
	{[]byte{0x01, 0x00}, true, 256},
	{[]byte{0x80}, true, -128},
	{[]byte{0xff, 0x7f}, true, -129},
	{[]byte{0xff}, true, -1},
	{[]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, true, -9223372036854775808},
	{[]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, false, 0},
	{[]byte{}, false, 0},
	{[]byte{0x00, 0x7f}, false, 0},
	{[]byte{0xff, 0xf0}, false, 0},
}

func TestParseInt64(t *testing.T) {
	for i, test := range int64TestData {
		ret, err := parseInt64(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did fail? %v, expected: %v)", i, err == nil, test.ok)
		}
		if test.ok && ret != test.out {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ret, test.out)
		}
	}
}

type int32Test struct {
	in  []byte
	ok  bool
	out int32
}

var int32TestData = []int32Test{
	{[]byte{0x00}, true, 0},
	{[]byte{0x7f}, true, 127},
	{[]byte{0x00, 0x80}, true, 128},
	{[]byte{0x01, 0x00}, true, 256},
	{[]byte{0x80}, true, -128},
	{[]byte{0xff, 0x7f}, true, -129},
	{[]byte{0xff}, true, -1},
	{[]byte{0x80, 0x00, 0x00, 0x00}, true, -2147483648},
	{[]byte{0x80, 0x00, 0x00, 0x00, 0x00}, false, 0},
	{[]byte{}, false, 0},
	{[]byte{0x00, 0x7f}, false, 0},
	{[]byte{0xff, 0xf0}, false, 0},
}

func TestParseInt32(t *testing.T) {
	for i, test := range int32TestData {
		ret, err := parseInt32(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did fail? %v, expected: %v)", i, err == nil, test.ok)
		}
		if test.ok && ret != test.out {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ret, test.out)
		}
	}
}

var bigIntTests = []struct {
	in     []byte
	ok     bool
	base10 string
}{
	{[]byte{0xff}, true, "-1"},
	{[]byte{0x00}, true, "0"},
	{[]byte{0x01}, true, "1"},
	{[]byte{0x00, 0xff}, true, "255"},
	{[]byte{0xff, 0x00}, true, "-256"},
	{[]byte{0x01, 0x00}, true, "256"},
	{[]byte{}, false, ""},
	{[]byte{0x00, 0x7f}, false, ""},
	{[]byte{0xff, 0xf0}, false, ""},
}

func TestParseBigInt(t *testing.T) {
	for i, test := range bigIntTests {
		ret, err := parseBigInt(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did fail? %v, expected: %v)", i, err == nil, test.ok)
		}
		if test.ok {
			if ret.String() != test.base10 {
				t.Errorf("#%d: bad result from %x, got %s want %s", i, test.in, ret.String(), test.base10)
			}
			e, err := makeBigInt(ret)
			if err != nil {
				t.Errorf("%d: err=%q", i, err)
				continue
			}
			result := make([]byte, e.Len())
			e.Encode(result)
			if !bytes.Equal(result, test.in) {
				t.Errorf("#%d: got %x from marshaling %s, want %x", i, result, ret, test.in)
			}
		}
	}
}

type bitStringTest struct {
	in        []byte
	ok        bool
	out       []byte
	bitLength int
}

var bitStringTestData = []bitStringTest{
	{[]byte{}, false, []byte{}, 0},
	{[]byte{0x00}, true, []byte{}, 0},
	{[]byte{0x07, 0x00}, true, []byte{0x00}, 1},
	{[]byte{0x07, 0x01}, false, []byte{}, 0},
	{[]byte{0x07, 0x40}, false, []byte{}, 0},
	{[]byte{0x08, 0x00}, false, []byte{}, 0},
}

func TestBitString(t *testing.T) {
	for i, test := range bitStringTestData {
		ret, err := parseBitString(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did fail? %v, expected: %v)", i, err == nil, test.ok)
		}
		if err == nil {
			if test.bitLength != ret.BitLength || !bytes.Equal(ret.Bytes, test.out) {
				t.Errorf("#%d: Bad result: %v (expected %v %v)", i, ret, test.out, test.bitLength)
			}
		}
	}
}

func TestBitStringAt(t *testing.T) {
	bs := BitString{[]byte{0x82, 0x40}, 16}
	if bs.At(0) != 1 {
		t.Error("#1: Failed")
	}
	if bs.At(1) != 0 {
		t.Error("#2: Failed")
	}
	if bs.At(6) != 1 {
		t.Error("#3: Failed")
	}
	if bs.At(9) != 1 {
		t.Error("#4: Failed")
	}
	if bs.At(-1) != 0 {
		t.Error("#5: Failed")
	}
	if bs.At(17) != 0 {
		t.Error("#6: Failed")
	}
}

type bitStringRightAlignTest struct {
	in    []byte
	inlen int
	out   []byte
}

var bitStringRightAlignTests = []bitStringRightAlignTest{
	{[]byte{0x80}, 1, []byte{0x01}},
	{[]byte{0x80, 0x80}, 9, []byte{0x01, 0x01}},
	{[]byte{}, 0, []byte{}},
	{[]byte{0xce}, 8, []byte{0xce}},
	{[]byte{0xce, 0x47}, 16, []byte{0xce, 0x47}},
	{[]byte{0x34, 0x50}, 12, []byte{0x03, 0x45}},
}

func TestBitStringRightAlign(t *testing.T) {
	for i, test := range bitStringRightAlignTests {
		bs := BitString{test.in, test.inlen}
		out := bs.RightAlign()
		if !bytes.Equal(out, test.out) {
			t.Errorf("#%d got: %x want: %x", i, out, test.out)
		}
	}
}

type objectIdentifierTest struct {
	in  []byte
	ok  bool
	out ObjectIdentifier // has base type[]int
}

var objectIdentifierTestData = []objectIdentifierTest{
	{[]byte{}, false, []int{}},
	{[]byte{85}, true, []int{2, 5}},
	{[]byte{85, 0x02}, true, []int{2, 5, 2}},
	{[]byte{85, 0x02, 0xc0, 0x00}, true, []int{2, 5, 2, 0x2000}},
	{[]byte{0x81, 0x34, 0x03}, true, []int{2, 100, 3}},
	{[]byte{85, 0x02, 0xc0, 0x80, 0x80, 0x80, 0x80}, false, []int{}},
}

func TestObjectIdentifier(t *testing.T) {
	for i, test := range objectIdentifierTestData {
		ret, err := parseObjectIdentifier(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did fail? %v, expected: %v)", i, err == nil, test.ok)
		}
		if err == nil {
			if !reflect.DeepEqual(test.out, ret) {
				t.Errorf("#%d: Bad result: %v (expected %v)", i, ret, test.out)
			}
		}
	}

	if s := ObjectIdentifier([]int{1, 2, 3, 4}).String(); s != "1.2.3.4" {
		t.Errorf("bad ObjectIdentifier.String(). Got %s, want 1.2.3.4", s)
	}
}

type timeTest struct {
	in  string
	ok  bool
	out time.Time
}

var utcTestData = []timeTest{
	{"910506164540-0700", true, time.Date(1991, 05, 06, 16, 45, 40, 0, time.FixedZone("", -7*60*60))},
	{"910506164540+0730", true, time.Date(1991, 05, 06, 16, 45, 40, 0, time.FixedZone("", 7*60*60+30*60))},
	{"910506234540Z", true, time.Date(1991, 05, 06, 23, 45, 40, 0, time.UTC)},
	{"9105062345Z", true, time.Date(1991, 05, 06, 23, 45, 0, 0, time.UTC)},
	{"5105062345Z", true, time.Date(1951, 05, 06, 23, 45, 0, 0, time.UTC)},
	{"a10506234540Z", false, time.Time{}},
	{"91a506234540Z", false, time.Time{}},
	{"9105a6234540Z", false, time.Time{}},
	{"910506a34540Z", false, time.Time{}},
	{"910506334a40Z", false, time.Time{}},
	{"91050633444aZ", false, time.Time{}},
	{"910506334461Z", false, time.Time{}},
	{"910506334400Za", false, time.Time{}},
	/* These are invalid times. However, the time package normalises times
	 * and they were accepted in some versions. See #11134. */
	{"000100000000Z", false, time.Time{}},
	{"101302030405Z", false, time.Time{}},
	{"100002030405Z", false, time.Time{}},
	{"100100030405Z", false, time.Time{}},
	{"100132030405Z", false, time.Time{}},
	{"100231030405Z", false, time.Time{}},
	{"100102240405Z", false, time.Time{}},
	{"100102036005Z", false, time.Time{}},
	{"100102030460Z", false, time.Time{}},
	{"-100102030410Z", false, time.Time{}},
	{"10-0102030410Z", false, time.Time{}},
	{"10-0002030410Z", false, time.Time{}},
	{"1001-02030410Z", false, time.Time{}},
	{"100102-030410Z", false, time.Time{}},
	{"10010203-0410Z", false, time.Time{}},
	{"1001020304-10Z", false, time.Time{}},
}

func TestUTCTime(t *testing.T) {
	for i, test := range utcTestData {
		ret, err := parseUTCTime([]byte(test.in))
		if err != nil {
			if test.ok {
				t.Errorf("#%d: parseUTCTime(%q) = error %v", i, test.in, err)
			}
			continue
		}
		if !test.ok {
			t.Errorf("#%d: parseUTCTime(%q) succeeded, should have failed", i, test.in)
			continue
		}
		const format = "Jan _2 15:04:05 -0700 2006" // ignore zone name, just offset
		have := ret.Format(format)
		want := test.out.Format(format)
		if have != want {
			t.Errorf("#%d: parseUTCTime(%q) = %s, want %s", i, test.in, have, want)
		}
	}
}

var generalizedTimeTestData = []timeTest{
	{"20100102030405Z", true, time.Date(2010, 01, 02, 03, 04, 05, 0, time.UTC)},
	{"20100102030405", false, time.Time{}},
	{"20100102030405.123456Z", true, time.Date(2010, 01, 02, 03, 04, 05, 123456e3, time.UTC)},
	{"20100102030405.123456", false, time.Time{}},
	{"20100102030405.Z", false, time.Time{}},
	{"20100102030405.", false, time.Time{}},
	{"20100102030405+0607", true, time.Date(2010, 01, 02, 03, 04, 05, 0, time.FixedZone("", 6*60*60+7*60))},
	{"20100102030405-0607", true, time.Date(2010, 01, 02, 03, 04, 05, 0, time.FixedZone("", -6*60*60-7*60))},
	/* These are invalid times. However, the time package normalises times
	 * and they were accepted in some versions. See #11134. */
	{"00000100000000Z", false, time.Time{}},
	{"20101302030405Z", false, time.Time{}},
	{"20100002030405Z", false, time.Time{}},
	{"20100100030405Z", false, time.Time{}},
	{"20100132030405Z", false, time.Time{}},
	{"20100231030405Z", false, time.Time{}},
	{"20100102240405Z", false, time.Time{}},
	{"20100102036005Z", false, time.Time{}},
	{"20100102030460Z", false, time.Time{}},
	{"-20100102030410Z", false, time.Time{}},
	{"2010-0102030410Z", false, time.Time{}},
	{"2010-0002030410Z", false, time.Time{}},
	{"201001-02030410Z", false, time.Time{}},
	{"20100102-030410Z", false, time.Time{}},
	{"2010010203-0410Z", false, time.Time{}},
	{"201001020304-10Z", false, time.Time{}},
}

func TestGeneralizedTime(t *testing.T) {
	for i, test := range generalizedTimeTestData {
		ret, err := parseGeneralizedTime([]byte(test.in))
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did fail? %v, expected: %v)", i, err == nil, test.ok)
		}
		if err == nil {
			if !reflect.DeepEqual(test.out, ret) {
				t.Errorf("#%d: Bad result: %q → %v (expected %v)", i, test.in, ret, test.out)
			}
		}
	}
}

type tagAndLengthTest struct {
	in  []byte
	ok  bool
	out tagAndLength
}

var tagAndLengthData = []tagAndLengthTest{
	{[]byte{0x80, 0x01}, true, tagAndLength{2, 0, 1, false}},
	{[]byte{0xa0, 0x01}, true, tagAndLength{2, 0, 1, true}},
	{[]byte{0x02, 0x00}, true, tagAndLength{0, 2, 0, false}},
	{[]byte{0xfe, 0x00}, true, tagAndLength{3, 30, 0, true}},
	{[]byte{0x1f, 0x1f, 0x00}, true, tagAndLength{0, 31, 0, false}},
	{[]byte{0x1f, 0x81, 0x00, 0x00}, true, tagAndLength{0, 128, 0, false}},
	{[]byte{0x1f, 0x81, 0x80, 0x01, 0x00}, true, tagAndLength{0, 0x4001, 0, false}},
	{[]byte{0x00, 0x81, 0x80}, true, tagAndLength{0, 0, 128, false}},
	{[]byte{0x00, 0x82, 0x01, 0x00}, true, tagAndLength{0, 0, 256, false}},
	{[]byte{0x00, 0x83, 0x01, 0x00}, false, tagAndLength{}},
	{[]byte{0x1f, 0x85}, false, tagAndLength{}},
	{[]byte{0x30, 0x80}, false, tagAndLength{}},
	// Superfluous zeros in the length should be an error.
	{[]byte{0xa0, 0x82, 0x00, 0xff}, false, tagAndLength{}},
	// Lengths up to the maximum size of an int should work.
	{[]byte{0xa0, 0x84, 0x7f, 0xff, 0xff, 0xff}, true, tagAndLength{2, 0, 0x7fffffff, true}},
	// Lengths that would overflow an int should be rejected.
	{[]byte{0xa0, 0x84, 0x80, 0x00, 0x00, 0x00}, false, tagAndLength{}},
	// Long length form may not be used for lengths that fit in short form.
	{[]byte{0xa0, 0x81, 0x7f}, false, tagAndLength{}},
	// Tag numbers which would overflow int32 are rejected. (The value below is 2^31.)
	{[]byte{0x1f, 0x88, 0x80, 0x80, 0x80, 0x00, 0x00}, false, tagAndLength{}},
	// Tag numbers that fit in an int32 are valid. (The value below is 2^31 - 1.)
	{[]byte{0x1f, 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0x00}, true, tagAndLength{tag: math.MaxInt32}},
	// Long tag number form may not be used for tags that fit in short form.
	{[]byte{0x1f, 0x1e, 0x00}, false, tagAndLength{}},
}

func TestParseTagAndLength(t *testing.T) {
	for i, test := range tagAndLengthData {
		tagAndLength, _, err := parseTagAndLength(test.in, 0)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did pass? %v, expected: %v)", i, err == nil, test.ok)
		}
		if err == nil && !reflect.DeepEqual(test.out, tagAndLength) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, tagAndLength, test.out)
		}
	}
}

type parseFieldParametersTest struct {
	in  string
	out fieldParameters
}

func newInt(n int) *int { return &n }

func newInt64(n int64) *int64 { return &n }

func newString(s string) *string { return &s }

func newBool(b bool) *bool { return &b }

var parseFieldParametersTestData []parseFieldParametersTest = []parseFieldParametersTest{
	{"", fieldParameters{}},
	{"ia5", fieldParameters{stringType: TagIA5String}},
	{"generalized", fieldParameters{timeType: TagGeneralizedTime}},
	{"utc", fieldParameters{timeType: TagUTCTime}},
	{"printable", fieldParameters{stringType: TagPrintableString}},
	{"numeric", fieldParameters{stringType: TagNumericString}},
	{"optional", fieldParameters{optional: true}},
	{"explicit", fieldParameters{explicit: true, tag: new(int)}},
	{"application", fieldParameters{application: true, tag: new(int)}},
	{"private", fieldParameters{private: true, tag: new(int)}},
	{"optional,explicit", fieldParameters{optional: true, explicit: true, tag: new(int)}},
	{"default:42", fieldParameters{defaultValue: newInt64(42)}},
	{"tag:17", fieldParameters{tag: newInt(17)}},
	{"optional,explicit,default:42,tag:17", fieldParameters{optional: true, explicit: true, defaultValue: newInt64(42), tag: newInt(17)}},
	{"optional,explicit,default:42,tag:17,rubbish1", fieldParameters{optional: true, explicit: true, application: false, defaultValue: newInt64(42), tag: newInt(17), stringType: 0, timeType: 0, set: false, omitEmpty: false}},
	{"set", fieldParameters{set: true}},
}

func TestParseFieldParameters(t *testing.T) {
	for i, test := range parseFieldParametersTestData {
		f := parseFieldParameters(test.in)
		if !reflect.DeepEqual(f, test.out) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, f, test.out)
		}
	}
}

type TestObjectIdentifierStruct struct {
	OID ObjectIdentifier
}

type TestContextSpecificTags struct {
	A int `asn1:"tag:1"`
}

type TestContextSpecificTags2 struct {
	A int `asn1:"explicit,tag:1"`
	B int
}

type TestContextSpecificTags3 struct {
	S string `asn1:"tag:1,utf8"`
}

type TestElementsAfterString struct {
	S    string
	A, B int
}

type TestBigInt struct {
	X *big.Int
}

type TestSet struct {
	Ints []int `asn1:"set"`
}

var unmarshalTestData = []struct {
	in  []byte
	out any
}{
	{[]byte{0x02, 0x01, 0x42}, newInt(0x42)},
	{[]byte{0x05, 0x00}, &RawValue{0, 5, false, []byte{}, []byte{0x05, 0x00}}},
	{[]byte{0x30, 0x08, 0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d}, &TestObjectIdentifierStruct{[]int{1, 2, 840, 113549}}},
	{[]byte{0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0}, &BitString{[]byte{110, 93, 192}, 18}},
	{[]byte{0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03}, &[]int{1, 2, 3}},
	{[]byte{0x02, 0x01, 0x10}, newInt(16)},
	{[]byte{0x13, 0x04, 't', 'e', 's', 't'}, newString("test")},
	{[]byte{0x16, 0x04, 't', 'e', 's', 't'}, newString("test")},
	// Ampersand is allowed in PrintableString due to mistakes by major CAs.
	{[]byte{0x13, 0x05, 't', 'e', 's', 't', '&'}, newString("test&")},
	{[]byte{0x16, 0x04, 't', 'e', 's', 't'}, &RawValue{0, 22, false, []byte("test"), []byte("\x16\x04test")}},
	{[]byte{0x04, 0x04, 1, 2, 3, 4}, &RawValue{0, 4, false, []byte{1, 2, 3, 4}, []byte{4, 4, 1, 2, 3, 4}}},
	{[]byte{0x30, 0x03, 0x81, 0x01, 0x01}, &TestContextSpecificTags{1}},
	{[]byte{0x30, 0x08, 0xa1, 0x03, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}, &TestContextSpecificTags2{1, 2}},
	{[]byte{0x30, 0x03, 0x81, 0x01, '@'}, &TestContextSpecificTags3{"@"}},
	{[]byte{0x01, 0x01, 0x00}, newBool(false)},
	{[]byte{0x01, 0x01, 0xff}, newBool(true)},
	{[]byte{0x30, 0x0b, 0x13, 0x03, 0x66, 0x6f, 0x6f, 0x02, 0x01, 0x22, 0x02, 0x01, 0x33}, &TestElementsAfterString{"foo", 0x22, 0x33}},
	{[]byte{0x30, 0x05, 0x02, 0x03, 0x12, 0x34, 0x56}, &TestBigInt{big.NewInt(0x123456)}},
	{[]byte{0x30, 0x0b, 0x31, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03}, &TestSet{Ints: []int{1, 2, 3}}},
	{[]byte{0x12, 0x0b, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ' '}, newString("0123456789 ")},
}

func TestUnmarshal(t *testing.T) {
	for i, test := range unmarshalTestData {
		pv := reflect.New(reflect.TypeOf(test.out).Elem())
		val := pv.Interface()
		_, err := Unmarshal(test.in, val)
		if err != nil {
			t.Errorf("Unmarshal failed at index %d %v", i, err)
		}
		if !reflect.DeepEqual(val, test.out) {
			t.Errorf("#%d:\nhave %#v\nwant %#v", i, val, test.out)
		}
	}
}

func TestUnmarshalWithNilOrNonPointer(t *testing.T) {
	tests := []struct {
		b    []byte
		v    any
		want string
	}{
		{b: []byte{0x05, 0x00}, v: nil, want: "asn1: Unmarshal recipient value is nil"},
		{b: []byte{0x05, 0x00}, v: RawValue{}, want: "asn1: Unmarshal recipient value is non-pointer asn1.RawValue"},
		{b: []byte{0x05, 0x00}, v: (*RawValue)(nil), want: "asn1: Unmarshal recipient value is nil *asn1.RawValue"},
	}

	for _, test := range tests {
		_, err := Unmarshal(test.b, test.v)
		if err == nil {
			t.Errorf("Unmarshal expecting error, got nil")
			continue
		}
		if g, w := err.Error(), test.want; g != w {
			t.Errorf("InvalidUnmarshalError mismatch\nGot:  %q\nWant: %q", g, w)
		}
	}
}

type Certificate struct {
	TBSCertificate     TBSCertificate
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     BitString
}

type TBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       RawValue
	SignatureAlgorithm AlgorithmIdentifier
	Issuer             RDNSequence
	Validity           Validity
	Subject            RDNSequence
	PublicKey          PublicKeyInfo
}

type AlgorithmIdentifier struct {
	Algorithm ObjectIdentifier
}

type RDNSequence []RelativeDistinguishedNameSET

type RelativeDistinguishedNameSET []AttributeTypeAndValue

type AttributeTypeAndValue struct {
	Type  ObjectIdentifier
	Value any
}

type Validity struct {
	NotBefore, NotAfter time.Time
}

type PublicKeyInfo struct {
	Algorithm AlgorithmIdentifier
	PublicKey BitString
}

func TestCertificate(t *testing.T) {
	// This is a minimal, self-signed certificate that should parse correctly.
	var cert Certificate
	if _, err := Unmarshal(derEncodedSelfSignedCertBytes, &cert); err != nil {
		t.Errorf("Unmarshal failed: %v", err)
	}
	if !reflect.DeepEqual(cert, derEncodedSelfSignedCert) {
		t.Errorf("Bad result:\ngot: %+v\nwant: %+v", cert, derEncodedSelfSignedCert)
	}
}

func TestCertificateWithNUL(t *testing.T) {
	// This is the paypal NUL-hack certificate. It should fail to parse because
	// NUL isn't a permitted character in a PrintableString.

	var cert Certificate
	if _, err := Unmarshal(derEncodedPaypalNULCertBytes, &cert); err == nil {
		t.Error("Unmarshal succeeded, should not have")
	}
}

type rawStructTest struct {
	Raw RawContent
	A   int
}

func TestRawStructs(t *testing.T) {
	var s rawStructTest
	input := []byte{0x30, 0x03, 0x02, 0x01, 0x50}

	rest, err := Unmarshal(input, &s)
	if len(rest) != 0 {
		t.Errorf("incomplete parse: %x", rest)
		return
	}
	if err != nil {
		t.Error(err)
		return
	}
	if s.A != 0x50 {
		t.Errorf("bad value for A: got %d want %d", s.A, 0x50)
	}
	if !bytes.Equal([]byte(s.Raw), input) {
		t.Errorf("bad value for Raw: got %x want %x", s.Raw, input)
	}
}

type oiEqualTest struct {
	first  ObjectIdentifier
	second ObjectIdentifier
	same   bool
}

var oiEqualTests = []oiEqualTest{
	{
		ObjectIdentifier{1, 2, 3},
		ObjectIdentifier{1, 2, 3},
		true,
	},
	{
		ObjectIdentifier{1},
		ObjectIdentifier{1, 2, 3},
		false,
	},
	{
		ObjectIdentifier{1, 2, 3},
		ObjectIdentifier{10, 11, 12},
		false,
	},
}

func TestObjectIdentifierEqual(t *testing.T) {
	for _, o := range oiEqualTests {
		if s := o.first.Equal(o.second); s != o.same {
			t.Errorf("ObjectIdentifier.Equal: got: %t want: %t", s, o.same)
		}
	}
}

var derEncodedSelfSignedCert = Certificate{
	TBSCertificate: TBSCertificate{
		Version:            0,
		SerialNumber:       RawValue{Class: 0, Tag: 2, IsCompound: false, Bytes: []uint8{0x0, 0x8c, 0xc3, 0x37, 0x92, 0x10, 0xec, 0x2c, 0x98}, FullBytes: []byte{2, 9, 0x0, 0x8c, 0xc3, 0x37, 0x92, 0x10, 0xec, 0x2c, 0x98}},
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}},
		Issuer: RDNSequence{
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 6}, Value: "XX"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 8}, Value: "Some-State"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 7}, Value: "City"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 10}, Value: "Internet Widgits Pty Ltd"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 3}, Value: "false.example.com"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "false@example.com"}},
		},
		Validity: Validity{
			NotBefore: time.Date(2009, 10, 8, 00, 25, 53, 0, time.UTC),
			NotAfter:  time.Date(2010, 10, 8, 00, 25, 53, 0, time.UTC),
		},
		Subject: RDNSequence{
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 6}, Value: "XX"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 8}, Value: "Some-State"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 7}, Value: "City"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 10}, Value: "Internet Widgits Pty Ltd"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{2, 5, 4, 3}, Value: "false.example.com"}},
			RelativeDistinguishedNameSET{AttributeTypeAndValue{Type: ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "false@example.com"}},
		},
		PublicKey: PublicKeyInfo{
			Algorithm: AlgorithmIdentifier{Algorithm: ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}},
			PublicKey: BitString{
				Bytes: []uint8{
					0x30, 0x48, 0x2, 0x41, 0x0, 0xcd, 0xb7,
					0x63, 0x9c, 0x32, 0x78, 0xf0, 0x6, 0xaa, 0x27, 0x7f, 0x6e, 0xaf, 0x42,
					0x90, 0x2b, 0x59, 0x2d, 0x8c, 0xbc, 0xbe, 0x38, 0xa1, 0xc9, 0x2b, 0xa4,
					0x69, 0x5a, 0x33, 0x1b, 0x1d, 0xea, 0xde, 0xad, 0xd8, 0xe9, 0xa5, 0xc2,
					0x7e, 0x8c, 0x4c, 0x2f, 0xd0, 0xa8, 0x88, 0x96, 0x57, 0x72, 0x2a, 0x4f,
					0x2a, 0xf7, 0x58, 0x9c, 0xf2, 0xc7, 0x70, 0x45, 0xdc, 0x8f, 0xde, 0xec,
					0x35, 0x7d, 0x2, 0x3, 0x1, 0x0, 0x1,
				},
				BitLength: 592,
			},
		},
	},
	SignatureAlgorithm: AlgorithmIdentifier{Algorithm: ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}},
	SignatureValue: BitString{
		Bytes: []uint8{
			0xa6, 0x7b, 0x6, 0xec, 0x5e, 0xce,
			0x92, 0x77, 0x2c, 0xa4, 0x13, 0xcb, 0xa3, 0xca, 0x12, 0x56, 0x8f, 0xdc, 0x6c,
			0x7b, 0x45, 0x11, 0xcd, 0x40, 0xa7, 0xf6, 0x59, 0x98, 0x4, 0x2, 0xdf, 0x2b,
			0x99, 0x8b, 0xb9, 0xa4, 0xa8, 0xcb, 0xeb, 0x34, 0xc0, 0xf0, 0xa7, 0x8c, 0xf8,
			0xd9, 0x1e, 0xde, 0x14, 0xa5, 0xed, 0x76, 0xbf, 0x11, 0x6f, 0xe3, 0x60, 0xaa,
			0xfa, 0x88, 0x21, 0x49, 0x4, 0x35,
		},
		BitLength: 512,
	},
}

var derEncodedSelfSignedCertBytes = []byte{
	0x30, 0x82, 0x02, 0x18, 0x30,
	0x82, 0x01, 0xc2, 0x02, 0x09, 0x00, 0x8c, 0xc3, 0x37, 0x92, 0x10, 0xec, 0x2c,
	0x98, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x05, 0x05, 0x00, 0x30, 0x81, 0x92, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
	0x04, 0x06, 0x13, 0x02, 0x58, 0x58, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
	0x04, 0x08, 0x13, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74,
	0x65, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x04, 0x43,
	0x69, 0x74, 0x79, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
	0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64,
	0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31,
	0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x11, 0x66, 0x61, 0x6c,
	0x73, 0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
	0x6d, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x09, 0x01, 0x16, 0x11, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x40, 0x65, 0x78,
	0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d,
	0x30, 0x39, 0x31, 0x30, 0x30, 0x38, 0x30, 0x30, 0x32, 0x35, 0x35, 0x33, 0x5a,
	0x17, 0x0d, 0x31, 0x30, 0x31, 0x30, 0x30, 0x38, 0x30, 0x30, 0x32, 0x35, 0x35,
	0x33, 0x5a, 0x30, 0x81, 0x92, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
	0x06, 0x13, 0x02, 0x58, 0x58, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
	0x08, 0x13, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x04, 0x43, 0x69,
	0x74, 0x79, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x18,
	0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
	0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x1a,
	0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x11, 0x66, 0x61, 0x6c, 0x73,
	0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	0x31, 0x20, 0x30, 0x1e, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
	0x09, 0x01, 0x16, 0x11, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x40, 0x65, 0x78, 0x61,
	0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x5c, 0x30, 0x0d, 0x06,
	0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
	0x4b, 0x00, 0x30, 0x48, 0x02, 0x41, 0x00, 0xcd, 0xb7, 0x63, 0x9c, 0x32, 0x78,
	0xf0, 0x06, 0xaa, 0x27, 0x7f, 0x6e, 0xaf, 0x42, 0x90, 0x2b, 0x59, 0x2d, 0x8c,
	0xbc, 0xbe, 0x38, 0xa1, 0xc9, 0x2b, 0xa4, 0x69, 0x5a, 0x33, 0x1b, 0x1d, 0xea,
	0xde, 0xad, 0xd8, 0xe9, 0xa5, 0xc2, 0x7e, 0x8c, 0x4c, 0x2f, 0xd0, 0xa8, 0x88,
	0x96, 0x57, 0x72, 0x2a, 0x4f, 0x2a, 0xf7, 0x58, 0x9c, 0xf2, 0xc7, 0x70, 0x45,
	0xdc, 0x8f, 0xde, 0xec, 0x35, 0x7d, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d,
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00,
	0x03, 0x41, 0x00, 0xa6, 0x7b, 0x06, 0xec, 0x5e, 0xce, 0x92, 0x77, 0x2c, 0xa4,
	0x13, 0xcb, 0xa3, 0xca, 0x12, 0x56, 0x8f, 0xdc, 0x6c, 0x7b, 0x45, 0x11, 0xcd,
	0x40, 0xa7, 0xf6, 0x59, 0x98, 0x04, 0x02, 0xdf, 0x2b, 0x99, 0x8b, 0xb9, 0xa4,
	0xa8, 0xcb, 0xeb, 0x34, 0xc0, 0xf0, 0xa7, 0x8c, 0xf8, 0xd9, 0x1e, 0xde, 0x14,
	0xa5, 0xed, 0x76, 0xbf, 0x11, 0x6f, 0xe3, 0x60, 0xaa, 0xfa, 0x88, 0x21, 0x49,
	0x04, 0x35,
}

var derEncodedPaypalNULCertBytes = []byte{
	0x30, 0x82, 0x06, 0x44, 0x30,
	0x82, 0x05, 0xad, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x00, 0xf0, 0x9b,
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
	0x05, 0x00, 0x30, 0x82, 0x01, 0x12, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
	0x04, 0x06, 0x13, 0x02, 0x45, 0x53, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
	0x04, 0x08, 0x13, 0x09, 0x42, 0x61, 0x72, 0x63, 0x65, 0x6c, 0x6f, 0x6e, 0x61,
	0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x09, 0x42, 0x61,
	0x72, 0x63, 0x65, 0x6c, 0x6f, 0x6e, 0x61, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03,
	0x55, 0x04, 0x0a, 0x13, 0x20, 0x49, 0x50, 0x53, 0x20, 0x43, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74,
	0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x73, 0x2e, 0x6c, 0x2e, 0x31, 0x2e,
	0x30, 0x2c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x14, 0x25, 0x67, 0x65, 0x6e, 0x65,
	0x72, 0x61, 0x6c, 0x40, 0x69, 0x70, 0x73, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d,
	0x20, 0x43, 0x2e, 0x49, 0x2e, 0x46, 0x2e, 0x20, 0x20, 0x42, 0x2d, 0x42, 0x36,
	0x32, 0x32, 0x31, 0x30, 0x36, 0x39, 0x35, 0x31, 0x2e, 0x30, 0x2c, 0x06, 0x03,
	0x55, 0x04, 0x0b, 0x13, 0x25, 0x69, 0x70, 0x73, 0x43, 0x41, 0x20, 0x43, 0x4c,
	0x41, 0x53, 0x45, 0x41, 0x31, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
	0x69, 0x74, 0x79, 0x31, 0x2e, 0x30, 0x2c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
	0x25, 0x69, 0x70, 0x73, 0x43, 0x41, 0x20, 0x43, 0x4c, 0x41, 0x53, 0x45, 0x41,
	0x31, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31,
	0x20, 0x30, 0x1e, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
	0x01, 0x16, 0x11, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c, 0x40, 0x69, 0x70,
	0x73, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x39,
	0x30, 0x32, 0x32, 0x34, 0x32, 0x33, 0x30, 0x34, 0x31, 0x37, 0x5a, 0x17, 0x0d,
	0x31, 0x31, 0x30, 0x32, 0x32, 0x34, 0x32, 0x33, 0x30, 0x34, 0x31, 0x37, 0x5a,
	0x30, 0x81, 0x94, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13,
	0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x16,
	0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0d, 0x53, 0x61, 0x6e, 0x20,
	0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x31, 0x11, 0x30, 0x0f,
	0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69,
	0x74, 0x79, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0b,
	0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x55, 0x6e, 0x69, 0x74, 0x31, 0x2f,
	0x30, 0x2d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x26, 0x77, 0x77, 0x77, 0x2e,
	0x70, 0x61, 0x79, 0x70, 0x61, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x73, 0x73,
	0x6c, 0x2e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x63, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x63, 0x63, 0x30, 0x81, 0x9f, 0x30, 0x0d,
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
	0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xd2, 0x69,
	0xfa, 0x6f, 0x3a, 0x00, 0xb4, 0x21, 0x1b, 0xc8, 0xb1, 0x02, 0xd7, 0x3f, 0x19,
	0xb2, 0xc4, 0x6d, 0xb4, 0x54, 0xf8, 0x8b, 0x8a, 0xcc, 0xdb, 0x72, 0xc2, 0x9e,
	0x3c, 0x60, 0xb9, 0xc6, 0x91, 0x3d, 0x82, 0xb7, 0x7d, 0x99, 0xff, 0xd1, 0x29,
	0x84, 0xc1, 0x73, 0x53, 0x9c, 0x82, 0xdd, 0xfc, 0x24, 0x8c, 0x77, 0xd5, 0x41,
	0xf3, 0xe8, 0x1e, 0x42, 0xa1, 0xad, 0x2d, 0x9e, 0xff, 0x5b, 0x10, 0x26, 0xce,
	0x9d, 0x57, 0x17, 0x73, 0x16, 0x23, 0x38, 0xc8, 0xd6, 0xf1, 0xba, 0xa3, 0x96,
	0x5b, 0x16, 0x67, 0x4a, 0x4f, 0x73, 0x97, 0x3a, 0x4d, 0x14, 0xa4, 0xf4, 0xe2,
	0x3f, 0x8b, 0x05, 0x83, 0x42, 0xd1, 0xd0, 0xdc, 0x2f, 0x7a, 0xe5, 0xb6, 0x10,
	0xb2, 0x11, 0xc0, 0xdc, 0x21, 0x2a, 0x90, 0xff, 0xae, 0x97, 0x71, 0x5a, 0x49,
	0x81, 0xac, 0x40, 0xf3, 0x3b, 0xb8, 0x59, 0xb2, 0x4f, 0x02, 0x03, 0x01, 0x00,
	0x01, 0xa3, 0x82, 0x03, 0x21, 0x30, 0x82, 0x03, 0x1d, 0x30, 0x09, 0x06, 0x03,
	0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x11, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x06, 0x40,
	0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x03, 0xf8,
	0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08,
	0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x1d, 0x06, 0x03, 0x55,
	0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x61, 0x8f, 0x61, 0x34, 0x43, 0x55, 0x14,
	0x7f, 0x27, 0x09, 0xce, 0x4c, 0x8b, 0xea, 0x9b, 0x7b, 0x19, 0x25, 0xbc, 0x6e,
	0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
	0x0e, 0x07, 0x60, 0xd4, 0x39, 0xc9, 0x1b, 0x5b, 0x5d, 0x90, 0x7b, 0x23, 0xc8,
	0xd2, 0x34, 0x9d, 0x4a, 0x9a, 0x46, 0x39, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d,
	0x11, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x1d, 0x12, 0x04,
	0x15, 0x30, 0x13, 0x81, 0x11, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c, 0x40,
	0x69, 0x70, 0x73, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x72, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x0d, 0x04, 0x65, 0x16, 0x63,
	0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20,
	0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4e,
	0x4f, 0x54, 0x20, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x41, 0x54, 0x45, 0x44, 0x2e,
	0x20, 0x43, 0x4c, 0x41, 0x53, 0x45, 0x41, 0x31, 0x20, 0x53, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x20, 0x69, 0x73, 0x73, 0x75, 0x65, 
"""




```