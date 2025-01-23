Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Goal:**

The request asks for an analysis of the `scan_test.go` file, specifically focusing on its functionality and purpose. It also asks for examples, error-prone areas, and a summary. The "Part 1 of 2" suggests we're dealing with a larger context, but we should focus on the provided snippet.

**2. High-Level Examination:**

The first step is to skim the code and identify key elements. I notice:

* **Package Declaration:** `package fmt_test` - This immediately tells me it's a testing file for the `fmt` package in Go.
* **Imports:** A variety of standard Go libraries are imported (`bufio`, `bytes`, `errors`, `fmt`, `io`, `math`, `reflect`, `regexp`, `strings`, `testing`, `testing/iotest`, `unicode/utf8`). This suggests testing various input/output scenarios, error handling, reflection, string manipulation, and Unicode support.
* **Struct Definitions:** `ScanTest`, `ScanfTest`, `ScanfMultiTest`. These likely represent different test cases for different scanning functions. The fields `text`, `in`, `out`, and `format` hint at input strings, input variables, expected output values, and format strings used in scanning.
* **Global Variable Declarations:**  A long list of variables like `boolVal`, `intVal`, `stringVal`, etc., and their renamed counterparts. These are likely used as destination variables for the scanning functions being tested. The `renamed` prefix suggests testing custom types.
* **Custom Scanner Types:** `Xs` and `IntString` along with their `Scan` methods. This strongly indicates the file tests the `fmt` package's ability to handle custom scanning logic.
* **Test Data Structures:** `scanTests`, `scanfTests`, `multiTests`, `overflowTests`, `eofTests`. These are slices of the previously defined structs, containing the actual test cases.
* **Test Functions:** Functions like `TestScan`, `TestScanln`, `TestScanf`, `TestScanOverflow`, `TestNaN`, `TestInf`, `TestScanfMulti`, `TestScanMultiple`, etc. These clearly define the individual test scenarios.
* **Helper Functions:** `testScan`, `testScanfMulti`, `verifyNaN`, `verifyInf`, `makeInts`, `testScanInts`. These are used to streamline the execution and verification of the tests.
* **Specific Test Cases:**  Looking closer at the data within the test slices reveals a wide range of inputs, including different number formats (decimal, hexadecimal, octal, binary), floating-point formats, complex numbers, strings, byte slices, boolean values, and edge cases like overflow, NaN, and infinity.

**3. Inferring Functionality (Deductive Reasoning):**

Based on the observed elements, I can infer the following primary functions of this code:

* **Testing `fmt.Scan`, `fmt.Scanln`, and `fmt.Sscan`, `fmt.Sscanln`:** The presence of `ScanTest` and the `TestScan` and `TestScanln` functions strongly suggest testing the basic scanning functions that read from an `io.Reader`.
* **Testing `fmt.Scanf` and `fmt.Sscanf`:** The `ScanfTest` and `ScanfMultiTest` structs and the `TestScanf` and `TestScanfMulti` functions clearly indicate testing the formatted scanning capabilities. The `%` verbs in the `format` fields confirm this.
* **Testing Custom Scanner Implementations:** The `Xs` and `IntString` types with their `Scan` methods and the inclusion of these types in the test data demonstrate testing the `fmt` package's support for custom types that implement the `fmt.Scanner` interface.
* **Testing Error Handling:** The `overflowTests`, checks for `io.EOF`, and the `multiTests` with an `err` field indicate thorough testing of various error conditions, such as input mismatch, overflow, and unexpected EOF.
* **Testing Edge Cases and Specific Scenarios:** The code covers scenarios like reading NaN and infinity, handling different whitespace, dealing with empty input, and verifying the correct number of items scanned.
* **Testing with Different `io.Reader` Implementations:**  The `readers` slice and the way `testScan` and `testScanfMulti` iterate through them show that the tests are designed to work with various types of readers, including string readers, one-byte readers, and error-injecting readers.

**4. Code Examples (Illustrative Examples):**

To provide concrete examples, I select some representative test cases and translate them into executable Go code. This involves picking a `ScanTest` and a `ScanfTest` and demonstrating how the corresponding `fmt.Scan` and `fmt.Scanf` functions would be used. I also include an example of using a custom scanner.

**5. Identifying Error-Prone Areas:**

By analyzing the test cases, especially those related to `Scanf`, I can identify common pitfalls for users:

* **Whitespace Sensitivity with `Scanf`:** The tests with explicit spaces in the format string highlight how `Scanf` expects the input to match the format precisely, including whitespace.
* **Mismatched Format Verbs and Data Types:** The error cases in `multiTests` demonstrate what happens when the format string doesn't align with the types of the variables being scanned into.
* **Ignoring Return Values:**  Users might forget to check the number of items scanned or the error returned by the `Scan` functions.

**6. Summarizing Functionality:**

Finally, I synthesize the observations into a concise summary that encapsulates the main purpose of the `scan_test.go` file. This involves highlighting its role in testing the input scanning capabilities of the `fmt` package, covering basic and formatted scanning, custom types, and various error scenarios.

**Self-Correction/Refinement:**

During the process, I might notice some details I initially overlooked. For example:

* **The `testing/iotest` package:** This reinforces the focus on robust I/O testing.
* **The use of `reflect.DeepEqual`:** This indicates the tests are comparing the *values* of the scanned variables, not just their types.

I would then refine my analysis to incorporate these observations, ensuring a more complete and accurate description of the code's functionality. The prompt asking for "Part 1" implies there's likely a subsequent part focusing on more specific aspects or perhaps benchmark tests, but for this initial analysis, focusing on the present code is sufficient.
这个 `go/src/fmt/scan_test.go` 文件的第 1 部分主要功能是定义和执行一系列的单元测试，用于验证 Go 语言 `fmt` 包中用于扫描（读取和解析输入）的功能，例如 `fmt.Scan`、`fmt.Scanln`、`fmt.Sscan`、`fmt.Sscanln`、`fmt.Fscan`、`fmt.Fscanln` 以及其格式化版本 `fmt.Scanf`、`fmt.Sscanf`、`fmt.Fscanf` 的正确性。

**功能归纳：**

1. **定义测试用例结构体:**  定义了 `ScanTest`, `ScanfTest`, 和 `ScanfMultiTest` 这几个结构体，用于组织不同类型的扫描测试用例。
    * `ScanTest`: 用于测试非格式化扫描函数，包含输入文本 (`text`)，接收扫描结果的变量指针 (`in`)，以及期望的输出值 (`out`)。
    * `ScanfTest`: 用于测试格式化扫描函数，包含格式字符串 (`format`)，输入文本 (`text`)，接收扫描结果的变量指针 (`in`)，以及期望的输出值 (`out`)。
    * `ScanfMultiTest`: 用于测试可以扫描多个值的格式化扫描函数，包含格式字符串 (`format`)，输入文本 (`text`)，接收扫描结果的多个变量指针切片 (`in`)，期望的输出值切片 (`out`)，以及预期的错误字符串 (`err`)。

2. **声明测试用变量:** 声明了一系列不同类型的全局变量（例如 `boolVal`, `intVal`, `stringVal` 等），以及它们的 "renamed" 版本（例如 `renamedBoolVal`, `renamedIntVal`）。这些变量在测试用例中作为 `Scan` 函数的目标接收输入值。 "renamed" 版本可能是为了测试扫描器对自定义类型的支持。

3. **实现自定义扫描器:** 定义了 `Xs` 和 `IntString` 两个自定义类型，并实现了 `fmt.Scanner` 接口的 `Scan` 方法。这允许测试 `fmt` 包是否能够正确地使用用户自定义的扫描逻辑。
    * `Xs`:  可以扫描连续重复的特定字符。
    * `IntString`: 可以先扫描一个整数，然后紧接着扫描一个字符串。

4. **定义测试用例数据:** 创建了 `scanTests`, `scanfTests`, `multiTests`, `overflowTests`, 和 `eofTests` 这些切片，其中包含了大量的具体测试用例。每个用例都指定了输入、格式（对于 `scanf`），以及期望的输出。
    * `scanTests`: 包含各种基本类型和自定义类型的非格式化扫描测试用例。
    * `scanfTests`: 包含各种基本类型和自定义类型的格式化扫描测试用例，测试了不同的格式化动词（如 `%d`, `%s`, `%t` 等）。
    * `multiTests`: 包含需要扫描多个值的格式化扫描测试用例，也包含了预期会出错的用例。
    * `overflowTests`: 包含预期会发生溢出的扫描测试用例，用于验证错误处理。
    * `eofTests`: 包含测试在输入结束时扫描行为的用例。

5. **定义不同的 `io.Reader`:**  创建了一个 `readers` 切片，包含了不同的 `io.Reader` 实现，例如 `strings.Reader`, `iotest.OneByteReader`, `iotest.DataErrReader` 等。这旨在测试扫描功能在不同类型的输入流下的表现。

**可以推理出它是什么go语言功能的实现：**

这段代码主要测试 `fmt` 包中用于从输入源解析数据的 `Scan` 系列函数。这些函数允许程序从字符串、标准输入或其他 `io.Reader` 中读取数据，并将其解析为 Go 语言的各种类型。

**Go 代码举例说明:**

假设有以下 `scanTests` 中的一个用例：

```go
{"21\n", &intVal, 21},
```

这个用例测试了将字符串 "21\n" 扫描到一个 `int` 类型的变量中。对应的 Go 代码示例：

```go
package main

import "fmt"

func main() {
	var intVal int
	n, err := fmt.Scan("21\n", &intVal)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if n != 1 {
		fmt.Println("Scanned items:", n)
		return
	}
	fmt.Println("Scanned value:", intVal) // Output: Scanned value: 21
}
```

再例如，对于 `scanfTests` 中的一个用例：

```go
{"%d", "72\n", &intVal, 72},
```

这个用例测试了使用格式字符串 `%d` 将字符串 "72\n" 扫描到一个 `int` 类型的变量中。对应的 Go 代码示例：

```go
package main

import "fmt"

func main() {
	var intVal int
	n, err := fmt.Sscanf("72\n", "%d", &intVal)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if n != 1 {
		fmt.Println("Scanned items:", n)
		return
	}
	fmt.Println("Scanned value:", intVal) // Output: Scanned value: 72
}
```

对于自定义扫描器 `Xs` 的用例：

```go
{"  vvv ", &xVal, Xs("vvv")},
```

对应的 Go 代码示例：

```go
package main

import (
	"fmt"
	"errors"
	"regexp"
)

// Xs accepts any non-empty run of the verb character
type Xs string

func (x *Xs) Scan(state fmt.ScanState, verb rune) error {
	tok, err := state.Token(true, func(r rune) bool { return r == verb })
	if err != nil {
		return err
	}
	s := string(tok)
	if !regexp.MustCompile("^" + string(verb) + "+$").MatchString(s) {
		return errors.New("syntax error for xs")
	}
	*x = Xs(s)
	return nil
}

func main() {
	var xVal Xs
	n, err := fmt.Scan("  vvv ", &xVal)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if n != 1 {
		fmt.Println("Scanned items:", n)
		return
	}
	fmt.Println("Scanned value:", xVal) // Output: Scanned value: vvv
}
```

**假设的输入与输出:**

上面的 Go 代码示例中已经包含了假设的输入和输出。

**命令行参数的具体处理:**

这段代码本身是单元测试代码，并不直接处理命令行参数。`fmt.Scan` 系列函数可以从标准输入读取数据，但这部分测试代码是通过提供字符串作为输入来模拟各种场景，而没有涉及到命令行参数的解析。

**使用者易犯错的点:**

这段代码的测试用例可以帮助我们理解使用 `fmt.Scan` 系列函数时容易犯的错误：

* **`Scanln` 的换行符要求:**  `fmt.Scanln` 及其变体要求输入在扫描完所有参数后必须有一个换行符。如果没有换行符，或者中间有额外的换行符，可能会导致错误。  测试函数 `TestScanlnNoNewline` 和 `TestScanlnWithMiddleNewline` 就是验证这一点。
* **`Scanf` 的格式字符串匹配:** `fmt.Scanf` 及其变体要求输入严格匹配格式字符串。例如，格式字符串中包含空格，输入中也必须有对应的空格。测试用例中有很多关于空格处理的例子，例如 `{"X %d", "X27", &intVal, nil}` 就展示了格式字符串中需要空格，但输入中没有，导致扫描失败。
* **数据类型不匹配:** 如果提供的输入无法转换为目标变量的类型，扫描会失败。例如，尝试将字符串 "abc" 扫描到 `int` 类型的变量会出错。
* **忽略返回值:**  `fmt.Scan` 系列函数会返回成功扫描的参数数量和遇到的错误。使用者容易忽略对返回值的检查，导致程序在发生错误时没有得到正确的处理。
* **自定义扫描器的实现错误:**  如果自定义类型的 `Scan` 方法实现不正确，例如没有正确地读取输入或者返回了错误的错误，`fmt` 包可能无法正确地使用它。

**这是第1部分，共2部分，请归纳一下它的功能**

总结来说，`go/src/fmt/scan_test.go` 文件的第 1 部分主要功能是：

**为 `fmt` 包的扫描功能定义了全面的单元测试用例，覆盖了基本类型的扫描、格式化扫描、自定义类型扫描、错误处理以及各种边界情况。它旨在确保 `fmt.Scan` 及其相关函数能够正确地从不同类型的输入源解析数据到 Go 语言的变量中。**

接下来的第 2 部分很可能会包含更多的测试用例，或者可能包含性能测试（benchmark）。

### 提示词
```
这是路径为go/src/fmt/scan_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package fmt_test

import (
	"bufio"
	"bytes"
	"errors"
	. "fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"
)

type ScanTest struct {
	text string
	in   any
	out  any
}

type ScanfTest struct {
	format string
	text   string
	in     any
	out    any
}

type ScanfMultiTest struct {
	format string
	text   string
	in     []any
	out    []any
	err    string
}

var (
	boolVal              bool
	intVal               int
	int8Val              int8
	int16Val             int16
	int32Val             int32
	int64Val             int64
	uintVal              uint
	uint8Val             uint8
	uint16Val            uint16
	uint32Val            uint32
	uint64Val            uint64
	uintptrVal           uintptr
	float32Val           float32
	float64Val           float64
	stringVal            string
	bytesVal             []byte
	runeVal              rune
	complex64Val         complex64
	complex128Val        complex128
	renamedBoolVal       renamedBool
	renamedIntVal        renamedInt
	renamedInt8Val       renamedInt8
	renamedInt16Val      renamedInt16
	renamedInt32Val      renamedInt32
	renamedInt64Val      renamedInt64
	renamedUintVal       renamedUint
	renamedUint8Val      renamedUint8
	renamedUint16Val     renamedUint16
	renamedUint32Val     renamedUint32
	renamedUint64Val     renamedUint64
	renamedUintptrVal    renamedUintptr
	renamedStringVal     renamedString
	renamedBytesVal      renamedBytes
	renamedFloat32Val    renamedFloat32
	renamedFloat64Val    renamedFloat64
	renamedComplex64Val  renamedComplex64
	renamedComplex128Val renamedComplex128
)

// Xs accepts any non-empty run of the verb character
type Xs string

func (x *Xs) Scan(state ScanState, verb rune) error {
	tok, err := state.Token(true, func(r rune) bool { return r == verb })
	if err != nil {
		return err
	}
	s := string(tok)
	if !regexp.MustCompile("^" + string(verb) + "+$").MatchString(s) {
		return errors.New("syntax error for xs")
	}
	*x = Xs(s)
	return nil
}

var xVal Xs

// IntString accepts an integer followed immediately by a string.
// It tests the embedding of a scan within a scan.
type IntString struct {
	i int
	s string
}

func (s *IntString) Scan(state ScanState, verb rune) error {
	if _, err := Fscan(state, &s.i); err != nil {
		return err
	}

	tok, err := state.Token(true, nil)
	if err != nil {
		return err
	}
	s.s = string(tok)
	return nil
}

var intStringVal IntString

var scanTests = []ScanTest{
	// Basic types
	{"T\n", &boolVal, true},  // boolean test vals toggle to be sure they are written
	{"F\n", &boolVal, false}, // restored to zero value
	{"21\n", &intVal, 21},
	{"2_1\n", &intVal, 21},
	{"0\n", &intVal, 0},
	{"000\n", &intVal, 0},
	{"0x10\n", &intVal, 0x10},
	{"0x_1_0\n", &intVal, 0x10},
	{"-0x10\n", &intVal, -0x10},
	{"0377\n", &intVal, 0377},
	{"0_3_7_7\n", &intVal, 0377},
	{"0o377\n", &intVal, 0377},
	{"0o_3_7_7\n", &intVal, 0377},
	{"-0377\n", &intVal, -0377},
	{"-0o377\n", &intVal, -0377},
	{"0\n", &uintVal, uint(0)},
	{"000\n", &uintVal, uint(0)},
	{"0x10\n", &uintVal, uint(0x10)},
	{"0377\n", &uintVal, uint(0377)},
	{"22\n", &int8Val, int8(22)},
	{"23\n", &int16Val, int16(23)},
	{"24\n", &int32Val, int32(24)},
	{"25\n", &int64Val, int64(25)},
	{"127\n", &int8Val, int8(127)},
	{"-21\n", &intVal, -21},
	{"-22\n", &int8Val, int8(-22)},
	{"-23\n", &int16Val, int16(-23)},
	{"-24\n", &int32Val, int32(-24)},
	{"-25\n", &int64Val, int64(-25)},
	{"-128\n", &int8Val, int8(-128)},
	{"+21\n", &intVal, +21},
	{"+22\n", &int8Val, int8(+22)},
	{"+23\n", &int16Val, int16(+23)},
	{"+24\n", &int32Val, int32(+24)},
	{"+25\n", &int64Val, int64(+25)},
	{"+127\n", &int8Val, int8(+127)},
	{"26\n", &uintVal, uint(26)},
	{"27\n", &uint8Val, uint8(27)},
	{"28\n", &uint16Val, uint16(28)},
	{"29\n", &uint32Val, uint32(29)},
	{"30\n", &uint64Val, uint64(30)},
	{"31\n", &uintptrVal, uintptr(31)},
	{"255\n", &uint8Val, uint8(255)},
	{"32767\n", &int16Val, int16(32767)},
	{"2.3\n", &float64Val, 2.3},
	{"2.3e1\n", &float32Val, float32(2.3e1)},
	{"2.3e2\n", &float64Val, 2.3e2},
	{"2.3p2\n", &float64Val, 2.3 * 4},
	{"2.3p+2\n", &float64Val, 2.3 * 4},
	{"2.3p+66\n", &float64Val, 2.3 * (1 << 66)},
	{"2.3p-66\n", &float64Val, 2.3 / (1 << 66)},
	{"0x2.3p-66\n", &float64Val, float64(0x23) / (1 << 70)},
	{"2_3.4_5\n", &float64Val, 23.45},
	{"2.35\n", &stringVal, "2.35"},
	{"2345678\n", &bytesVal, []byte("2345678")},
	{"(3.4e1-2i)\n", &complex128Val, 3.4e1 - 2i},
	{"-3.45e1-3i\n", &complex64Val, complex64(-3.45e1 - 3i)},
	{"-.45e1-1e2i\n", &complex128Val, complex128(-.45e1 - 100i)},
	{"-.4_5e1-1E2i\n", &complex128Val, complex128(-.45e1 - 100i)},
	{"0x1.0p1+0x1.0P2i\n", &complex128Val, complex128(2 + 4i)},
	{"-0x1p1-0x1p2i\n", &complex128Val, complex128(-2 - 4i)},
	{"-0x1ep-1-0x1p2i\n", &complex128Val, complex128(-15 - 4i)},
	{"-0x1_Ep-1-0x1p0_2i\n", &complex128Val, complex128(-15 - 4i)},
	{"hello\n", &stringVal, "hello"},

	// Carriage-return followed by newline. (We treat \r\n as \n always.)
	{"hello\r\n", &stringVal, "hello"},
	{"27\r\n", &uint8Val, uint8(27)},

	// Renamed types
	{"true\n", &renamedBoolVal, renamedBool(true)},
	{"F\n", &renamedBoolVal, renamedBool(false)},
	{"101\n", &renamedIntVal, renamedInt(101)},
	{"102\n", &renamedIntVal, renamedInt(102)},
	{"103\n", &renamedUintVal, renamedUint(103)},
	{"104\n", &renamedUintVal, renamedUint(104)},
	{"105\n", &renamedInt8Val, renamedInt8(105)},
	{"106\n", &renamedInt16Val, renamedInt16(106)},
	{"107\n", &renamedInt32Val, renamedInt32(107)},
	{"108\n", &renamedInt64Val, renamedInt64(108)},
	{"109\n", &renamedUint8Val, renamedUint8(109)},
	{"110\n", &renamedUint16Val, renamedUint16(110)},
	{"111\n", &renamedUint32Val, renamedUint32(111)},
	{"112\n", &renamedUint64Val, renamedUint64(112)},
	{"113\n", &renamedUintptrVal, renamedUintptr(113)},
	{"114\n", &renamedStringVal, renamedString("114")},
	{"115\n", &renamedBytesVal, renamedBytes([]byte("115"))},

	// Custom scanners.
	{"  vvv ", &xVal, Xs("vvv")},
	{" 1234hello", &intStringVal, IntString{1234, "hello"}},

	// Fixed bugs
	{"2147483648\n", &int64Val, int64(2147483648)}, // was: integer overflow
}

var scanfTests = []ScanfTest{
	{"%v", "TRUE\n", &boolVal, true},
	{"%t", "false\n", &boolVal, false},
	{"%v", "-71\n", &intVal, -71},
	{"%v", "-7_1\n", &intVal, -71},
	{"%v", "0b111\n", &intVal, 7},
	{"%v", "0b_1_1_1\n", &intVal, 7},
	{"%v", "0377\n", &intVal, 0377},
	{"%v", "0_3_7_7\n", &intVal, 0377},
	{"%v", "0o377\n", &intVal, 0377},
	{"%v", "0o_3_7_7\n", &intVal, 0377},
	{"%v", "0x44\n", &intVal, 0x44},
	{"%v", "0x_4_4\n", &intVal, 0x44},
	{"%d", "72\n", &intVal, 72},
	{"%c", "a\n", &runeVal, 'a'},
	{"%c", "\u5072\n", &runeVal, '\u5072'},
	{"%c", "\u1234\n", &runeVal, '\u1234'},
	{"%d", "73\n", &int8Val, int8(73)},
	{"%d", "+74\n", &int16Val, int16(74)},
	{"%d", "75\n", &int32Val, int32(75)},
	{"%d", "76\n", &int64Val, int64(76)},
	{"%b", "1001001\n", &intVal, 73},
	{"%o", "075\n", &intVal, 075},
	{"%x", "a75\n", &intVal, 0xa75},
	{"%v", "71\n", &uintVal, uint(71)},
	{"%d", "72\n", &uintVal, uint(72)},
	{"%d", "7_2\n", &uintVal, uint(7)}, // only %v takes underscores
	{"%d", "73\n", &uint8Val, uint8(73)},
	{"%d", "74\n", &uint16Val, uint16(74)},
	{"%d", "75\n", &uint32Val, uint32(75)},
	{"%d", "76\n", &uint64Val, uint64(76)},
	{"%d", "77\n", &uintptrVal, uintptr(77)},
	{"%b", "1001001\n", &uintVal, uint(73)},
	{"%b", "100_1001\n", &uintVal, uint(4)},
	{"%o", "075\n", &uintVal, uint(075)},
	{"%o", "07_5\n", &uintVal, uint(07)}, // only %v takes underscores
	{"%x", "a75\n", &uintVal, uint(0xa75)},
	{"%x", "A75\n", &uintVal, uint(0xa75)},
	{"%x", "A7_5\n", &uintVal, uint(0xa7)}, // only %v takes underscores
	{"%U", "U+1234\n", &intVal, int(0x1234)},
	{"%U", "U+4567\n", &uintVal, uint(0x4567)},

	{"%e", "2.3\n", &float64Val, 2.3},
	{"%E", "2.3e1\n", &float32Val, float32(2.3e1)},
	{"%f", "2.3e2\n", &float64Val, 2.3e2},
	{"%g", "2.3p2\n", &float64Val, 2.3 * 4},
	{"%G", "2.3p+2\n", &float64Val, 2.3 * 4},
	{"%v", "2.3p+66\n", &float64Val, 2.3 * (1 << 66)},
	{"%f", "2.3p-66\n", &float64Val, 2.3 / (1 << 66)},
	{"%G", "0x2.3p-66\n", &float64Val, float64(0x23) / (1 << 70)},
	{"%E", "2_3.4_5\n", &float64Val, 23.45},

	// Strings
	{"%s", "using-%s\n", &stringVal, "using-%s"},
	{"%x", "7573696e672d2578\n", &stringVal, "using-%x"},
	{"%X", "7573696E672D2558\n", &stringVal, "using-%X"},
	{"%q", `"quoted\twith\\do\u0075bl\x65s"` + "\n", &stringVal, "quoted\twith\\doubles"},
	{"%q", "`quoted with backs`\n", &stringVal, "quoted with backs"},

	// Byte slices
	{"%s", "bytes-%s\n", &bytesVal, []byte("bytes-%s")},
	{"%x", "62797465732d2578\n", &bytesVal, []byte("bytes-%x")},
	{"%X", "62797465732D2558\n", &bytesVal, []byte("bytes-%X")},
	{"%q", `"bytes\rwith\vdo\u0075bl\x65s"` + "\n", &bytesVal, []byte("bytes\rwith\vdoubles")},
	{"%q", "`bytes with backs`\n", &bytesVal, []byte("bytes with backs")},

	// Renamed types
	{"%v\n", "true\n", &renamedBoolVal, renamedBool(true)},
	{"%t\n", "F\n", &renamedBoolVal, renamedBool(false)},
	{"%v", "101\n", &renamedIntVal, renamedInt(101)},
	{"%c", "\u0101\n", &renamedIntVal, renamedInt('\u0101')},
	{"%o", "0146\n", &renamedIntVal, renamedInt(102)},
	{"%v", "103\n", &renamedUintVal, renamedUint(103)},
	{"%d", "104\n", &renamedUintVal, renamedUint(104)},
	{"%d", "105\n", &renamedInt8Val, renamedInt8(105)},
	{"%d", "106\n", &renamedInt16Val, renamedInt16(106)},
	{"%d", "107\n", &renamedInt32Val, renamedInt32(107)},
	{"%d", "108\n", &renamedInt64Val, renamedInt64(108)},
	{"%x", "6D\n", &renamedUint8Val, renamedUint8(109)},
	{"%o", "0156\n", &renamedUint16Val, renamedUint16(110)},
	{"%d", "111\n", &renamedUint32Val, renamedUint32(111)},
	{"%d", "112\n", &renamedUint64Val, renamedUint64(112)},
	{"%d", "113\n", &renamedUintptrVal, renamedUintptr(113)},
	{"%s", "114\n", &renamedStringVal, renamedString("114")},
	{"%q", "\"1155\"\n", &renamedBytesVal, renamedBytes([]byte("1155"))},
	{"%g", "116e1\n", &renamedFloat32Val, renamedFloat32(116e1)},
	{"%g", "-11.7e+1", &renamedFloat64Val, renamedFloat64(-11.7e+1)},
	{"%g", "11+6e1i\n", &renamedComplex64Val, renamedComplex64(11 + 6e1i)},
	{"%g", "-11.+7e+1i", &renamedComplex128Val, renamedComplex128(-11. + 7e+1i)},

	// Interesting formats
	{"here is\tthe value:%d", "here is   the\tvalue:118\n", &intVal, 118},
	{"%% %%:%d", "% %:119\n", &intVal, 119},
	{"%d%%", "42%", &intVal, 42}, // %% at end of string.

	// Corner cases
	{"%x", "FFFFFFFF\n", &uint32Val, uint32(0xFFFFFFFF)},

	// Custom scanner.
	{"%s", "  sss ", &xVal, Xs("sss")},
	{"%2s", "sssss", &xVal, Xs("ss")},

	// Fixed bugs
	{"%d\n", "27\n", &intVal, 27},         // ok
	{"%d\n", "28 \n", &intVal, 28},        // was: "unexpected newline"
	{"%v", "0", &intVal, 0},               // was: "EOF"; 0 was taken as base prefix and not counted.
	{"%v", "0", &uintVal, uint(0)},        // was: "EOF"; 0 was taken as base prefix and not counted.
	{"%c", " ", &uintVal, uint(' ')},      // %c must accept a blank.
	{"%c", "\t", &uintVal, uint('\t')},    // %c must accept any space.
	{"%c", "\n", &uintVal, uint('\n')},    // %c must accept any space.
	{"%d%%", "23%\n", &uintVal, uint(23)}, // %% matches literal %.
	{"%%%d", "%23\n", &uintVal, uint(23)}, // %% matches literal %.

	// space handling
	{"%d", "27", &intVal, 27},
	{"%d", "27 ", &intVal, 27},
	{"%d", " 27", &intVal, 27},
	{"%d", " 27 ", &intVal, 27},

	{"X%d", "X27", &intVal, 27},
	{"X%d", "X27 ", &intVal, 27},
	{"X%d", "X 27", &intVal, 27},
	{"X%d", "X 27 ", &intVal, 27},

	{"X %d", "X27", &intVal, nil},  // expected space in input to match format
	{"X %d", "X27 ", &intVal, nil}, // expected space in input to match format
	{"X %d", "X 27", &intVal, 27},
	{"X %d", "X 27 ", &intVal, 27},

	{"%dX", "27X", &intVal, 27},
	{"%dX", "27 X", &intVal, nil}, // input does not match format
	{"%dX", " 27X", &intVal, 27},
	{"%dX", " 27 X", &intVal, nil}, // input does not match format

	{"%d X", "27X", &intVal, nil}, // expected space in input to match format
	{"%d X", "27 X", &intVal, 27},
	{"%d X", " 27X", &intVal, nil}, // expected space in input to match format
	{"%d X", " 27 X", &intVal, 27},

	{"X %d X", "X27X", &intVal, nil},  // expected space in input to match format
	{"X %d X", "X27 X", &intVal, nil}, // expected space in input to match format
	{"X %d X", "X 27X", &intVal, nil}, // expected space in input to match format
	{"X %d X", "X 27 X", &intVal, 27},

	{"X %s X", "X27X", &stringVal, nil},  // expected space in input to match format
	{"X %s X", "X27 X", &stringVal, nil}, // expected space in input to match format
	{"X %s X", "X 27X", &stringVal, nil}, // unexpected EOF
	{"X %s X", "X 27 X", &stringVal, "27"},

	{"X%sX", "X27X", &stringVal, nil},   // unexpected EOF
	{"X%sX", "X27 X", &stringVal, nil},  // input does not match format
	{"X%sX", "X 27X", &stringVal, nil},  // unexpected EOF
	{"X%sX", "X 27 X", &stringVal, nil}, // input does not match format

	{"X%s", "X27", &stringVal, "27"},
	{"X%s", "X27 ", &stringVal, "27"},
	{"X%s", "X 27", &stringVal, "27"},
	{"X%s", "X 27 ", &stringVal, "27"},

	{"X%dX", "X27X", &intVal, 27},
	{"X%dX", "X27 X", &intVal, nil}, // input does not match format
	{"X%dX", "X 27X", &intVal, 27},
	{"X%dX", "X 27 X", &intVal, nil}, // input does not match format

	{"X%dX", "X27X", &intVal, 27},
	{"X%dX", "X27X ", &intVal, 27},
	{"X%dX", " X27X", &intVal, nil},  // input does not match format
	{"X%dX", " X27X ", &intVal, nil}, // input does not match format

	{"X%dX\n", "X27X", &intVal, 27},
	{"X%dX \n", "X27X ", &intVal, 27},
	{"X%dX\n", "X27X\n", &intVal, 27},
	{"X%dX\n", "X27X \n", &intVal, 27},

	{"X%dX \n", "X27X", &intVal, 27},
	{"X%dX \n", "X27X ", &intVal, 27},
	{"X%dX \n", "X27X\n", &intVal, 27},
	{"X%dX \n", "X27X \n", &intVal, 27},

	{"X%c", "X\n", &runeVal, '\n'},
	{"X%c", "X \n", &runeVal, ' '},
	{"X %c", "X!", &runeVal, nil},  // expected space in input to match format
	{"X %c", "X\n", &runeVal, nil}, // newline in input does not match format
	{"X %c", "X !", &runeVal, '!'},
	{"X %c", "X \n", &runeVal, '\n'},

	{" X%dX", "X27X", &intVal, nil},  // expected space in input to match format
	{" X%dX", "X27X ", &intVal, nil}, // expected space in input to match format
	{" X%dX", " X27X", &intVal, 27},
	{" X%dX", " X27X ", &intVal, 27},

	{"X%dX ", "X27X", &intVal, 27},
	{"X%dX ", "X27X ", &intVal, 27},
	{"X%dX ", " X27X", &intVal, nil},  // input does not match format
	{"X%dX ", " X27X ", &intVal, nil}, // input does not match format

	{" X%dX ", "X27X", &intVal, nil},  // expected space in input to match format
	{" X%dX ", "X27X ", &intVal, nil}, // expected space in input to match format
	{" X%dX ", " X27X", &intVal, 27},
	{" X%dX ", " X27X ", &intVal, 27},

	{"%d\nX", "27\nX", &intVal, 27},
	{"%dX\n X", "27X\n X", &intVal, 27},
}

var overflowTests = []ScanTest{
	{"128", &int8Val, 0},
	{"32768", &int16Val, 0},
	{"-129", &int8Val, 0},
	{"-32769", &int16Val, 0},
	{"256", &uint8Val, 0},
	{"65536", &uint16Val, 0},
	{"1e100", &float32Val, 0},
	{"1e500", &float64Val, 0},
	{"(1e100+0i)", &complex64Val, 0},
	{"(1+1e100i)", &complex64Val, 0},
	{"(1-1e500i)", &complex128Val, 0},
}

var truth bool
var i, j, k int
var f float64
var s, t string
var c complex128
var x, y Xs
var z IntString
var r1, r2, r3 rune

var multiTests = []ScanfMultiTest{
	{"", "", []any{}, []any{}, ""},
	{"%d", "23", args(&i), args(23), ""},
	{"%2s%3s", "22333", args(&s, &t), args("22", "333"), ""},
	{"%2d%3d", "44555", args(&i, &j), args(44, 555), ""},
	{"%2d.%3d", "66.777", args(&i, &j), args(66, 777), ""},
	{"%d, %d", "23, 18", args(&i, &j), args(23, 18), ""},
	{"%3d22%3d", "33322333", args(&i, &j), args(333, 333), ""},
	{"%6vX=%3fY", "3+2iX=2.5Y", args(&c, &f), args((3 + 2i), 2.5), ""},
	{"%d%s", "123abc", args(&i, &s), args(123, "abc"), ""},
	{"%c%c%c", "2\u50c2X", args(&r1, &r2, &r3), args('2', '\u50c2', 'X'), ""},
	{"%5s%d", " 1234567 ", args(&s, &i), args("12345", 67), ""},
	{"%5s%d", " 12 34 567 ", args(&s, &i), args("12", 34), ""},

	// Custom scanners.
	{"%e%f", "eefffff", args(&x, &y), args(Xs("ee"), Xs("fffff")), ""},
	{"%4v%s", "12abcd", args(&z, &s), args(IntString{12, "ab"}, "cd"), ""},

	// Errors
	{"%t", "23 18", args(&i), nil, "bad verb"},
	{"%d %d %d", "23 18", args(&i, &j), args(23, 18), "too few operands"},
	{"%d %d", "23 18 27", args(&i, &j, &k), args(23, 18), "too many operands"},
	{"%c", "\u0100", args(&int8Val), nil, "overflow"},
	{"X%d", "10X", args(&intVal), nil, "input does not match format"},
	{"%d%", "42%", args(&intVal), args(42), "missing verb: % at end of format string"},
	{"%d% ", "42%", args(&intVal), args(42), "too few operands for format '% '"}, // Slightly odd error, but correct.
	{"%%%d", "xxx 42", args(&intVal), args(42), "missing literal %"},
	{"%%%d", "x42", args(&intVal), args(42), "missing literal %"},
	{"%%%d", "42", args(&intVal), args(42), "missing literal %"},

	// Bad UTF-8: should see every byte.
	{"%c%c%c", "\xc2X\xc2", args(&r1, &r2, &r3), args(utf8.RuneError, 'X', utf8.RuneError), ""},

	// Fixed bugs
	{"%v%v", "FALSE23", args(&truth, &i), args(false, 23), ""},
}

var readers = []struct {
	name string
	f    func(string) io.Reader
}{
	{"StringReader", func(s string) io.Reader {
		return strings.NewReader(s)
	}},
	{"ReaderOnly", func(s string) io.Reader {
		return struct{ io.Reader }{strings.NewReader(s)}
	}},
	{"OneByteReader", func(s string) io.Reader {
		return iotest.OneByteReader(strings.NewReader(s))
	}},
	{"DataErrReader", func(s string) io.Reader {
		return iotest.DataErrReader(strings.NewReader(s))
	}},
}

func testScan(t *testing.T, f func(string) io.Reader, scan func(r io.Reader, a ...any) (int, error)) {
	for _, test := range scanTests {
		r := f(test.text)
		n, err := scan(r, test.in)
		if err != nil {
			m := ""
			if n > 0 {
				m = Sprintf(" (%d fields ok)", n)
			}
			t.Errorf("got error scanning %q: %s%s", test.text, err, m)
			continue
		}
		if n != 1 {
			t.Errorf("count error on entry %q: got %d", test.text, n)
			continue
		}
		// The incoming value may be a pointer
		v := reflect.ValueOf(test.in)
		if p := v; p.Kind() == reflect.Pointer {
			v = p.Elem()
		}
		val := v.Interface()
		if !reflect.DeepEqual(val, test.out) {
			t.Errorf("scanning %q: expected %#v got %#v, type %T", test.text, test.out, val, val)
		}
	}
}

func TestScan(t *testing.T) {
	for _, r := range readers {
		t.Run(r.name, func(t *testing.T) {
			testScan(t, r.f, Fscan)
		})
	}
}

func TestScanln(t *testing.T) {
	for _, r := range readers {
		t.Run(r.name, func(t *testing.T) {
			testScan(t, r.f, Fscanln)
		})
	}
}

func TestScanf(t *testing.T) {
	for _, test := range scanfTests {
		n, err := Sscanf(test.text, test.format, test.in)
		if err != nil {
			if test.out != nil {
				t.Errorf("Sscanf(%q, %q): unexpected error: %v", test.text, test.format, err)
			}
			continue
		}
		if test.out == nil {
			t.Errorf("Sscanf(%q, %q): unexpected success", test.text, test.format)
			continue
		}
		if n != 1 {
			t.Errorf("Sscanf(%q, %q): parsed %d field, want 1", test.text, test.format, n)
			continue
		}
		// The incoming value may be a pointer
		v := reflect.ValueOf(test.in)
		if p := v; p.Kind() == reflect.Pointer {
			v = p.Elem()
		}
		val := v.Interface()
		if !reflect.DeepEqual(val, test.out) {
			t.Errorf("Sscanf(%q, %q): parsed value %T(%#v), want %T(%#v)", test.text, test.format, val, val, test.out, test.out)
		}
	}
}

func TestScanOverflow(t *testing.T) {
	// different machines and different types report errors with different strings.
	re := regexp.MustCompile("overflow|too large|out of range|not representable")
	for _, test := range overflowTests {
		_, err := Sscan(test.text, test.in)
		if err == nil {
			t.Errorf("expected overflow scanning %q", test.text)
			continue
		}
		if !re.MatchString(err.Error()) {
			t.Errorf("expected overflow error scanning %q: %s", test.text, err)
		}
	}
}

func verifyNaN(str string, t *testing.T) {
	var f float64
	var f32 float32
	var f64 float64
	text := str + " " + str + " " + str
	n, err := Fscan(strings.NewReader(text), &f, &f32, &f64)
	if err != nil {
		t.Errorf("got error scanning %q: %s", text, err)
	}
	if n != 3 {
		t.Errorf("count error scanning %q: got %d", text, n)
	}
	if !math.IsNaN(float64(f)) || !math.IsNaN(float64(f32)) || !math.IsNaN(f64) {
		t.Errorf("didn't get NaNs scanning %q: got %g %g %g", text, f, f32, f64)
	}
}

func TestNaN(t *testing.T) {
	for _, s := range []string{"nan", "NAN", "NaN"} {
		verifyNaN(s, t)
	}
}

func verifyInf(str string, t *testing.T) {
	var f float64
	var f32 float32
	var f64 float64
	text := str + " " + str + " " + str
	n, err := Fscan(strings.NewReader(text), &f, &f32, &f64)
	if err != nil {
		t.Errorf("got error scanning %q: %s", text, err)
	}
	if n != 3 {
		t.Errorf("count error scanning %q: got %d", text, n)
	}
	sign := 1
	if str[0] == '-' {
		sign = -1
	}
	if !math.IsInf(float64(f), sign) || !math.IsInf(float64(f32), sign) || !math.IsInf(f64, sign) {
		t.Errorf("didn't get right Infs scanning %q: got %g %g %g", text, f, f32, f64)
	}
}

func TestInf(t *testing.T) {
	for _, s := range []string{"inf", "+inf", "-inf", "INF", "-INF", "+INF", "Inf", "-Inf", "+Inf"} {
		verifyInf(s, t)
	}
}

func testScanfMulti(t *testing.T, f func(string) io.Reader) {
	sliceType := reflect.TypeOf(make([]any, 1))
	for _, test := range multiTests {
		r := f(test.text)
		n, err := Fscanf(r, test.format, test.in...)
		if err != nil {
			if test.err == "" {
				t.Errorf("got error scanning (%q, %q): %q", test.format, test.text, err)
			} else if !strings.Contains(err.Error(), test.err) {
				t.Errorf("got wrong error scanning (%q, %q): %q; expected %q", test.format, test.text, err, test.err)
			}
			continue
		}
		if test.err != "" {
			t.Errorf("expected error %q error scanning (%q, %q)", test.err, test.format, test.text)
		}
		if n != len(test.out) {
			t.Errorf("count error on entry (%q, %q): expected %d got %d", test.format, test.text, len(test.out), n)
			continue
		}
		// Convert the slice of pointers into a slice of values
		resultVal := reflect.MakeSlice(sliceType, n, n)
		for i := 0; i < n; i++ {
			v := reflect.ValueOf(test.in[i]).Elem()
			resultVal.Index(i).Set(v)
		}
		result := resultVal.Interface()
		if !reflect.DeepEqual(result, test.out) {
			t.Errorf("scanning (%q, %q): expected %#v got %#v", test.format, test.text, test.out, result)
		}
	}
}

func TestScanfMulti(t *testing.T) {
	for _, r := range readers {
		t.Run(r.name, func(t *testing.T) {
			testScanfMulti(t, r.f)
		})
	}
}

func TestScanMultiple(t *testing.T) {
	var a int
	var s string
	n, err := Sscan("123abc", &a, &s)
	if n != 2 {
		t.Errorf("Sscan count error: expected 2: got %d", n)
	}
	if err != nil {
		t.Errorf("Sscan expected no error; got %s", err)
	}
	if a != 123 || s != "abc" {
		t.Errorf("Sscan wrong values: got (%d %q) expected (123 \"abc\")", a, s)
	}
	n, err = Sscan("asdf", &s, &a)
	if n != 1 {
		t.Errorf("Sscan count error: expected 1: got %d", n)
	}
	if err == nil {
		t.Errorf("Sscan expected error; got none: %s", err)
	}
	if s != "asdf" {
		t.Errorf("Sscan wrong values: got %q expected \"asdf\"", s)
	}
}

// Empty strings are not valid input when scanning a string.
func TestScanEmpty(t *testing.T) {
	var s1, s2 string
	n, err := Sscan("abc", &s1, &s2)
	if n != 1 {
		t.Errorf("Sscan count error: expected 1: got %d", n)
	}
	if err == nil {
		t.Error("Sscan <one item> expected error; got none")
	}
	if s1 != "abc" {
		t.Errorf("Sscan wrong values: got %q expected \"abc\"", s1)
	}
	n, err = Sscan("", &s1, &s2)
	if n != 0 {
		t.Errorf("Sscan count error: expected 0: got %d", n)
	}
	if err == nil {
		t.Error("Sscan <empty> expected error; got none")
	}
	// Quoted empty string is OK.
	n, err = Sscanf(`""`, "%q", &s1)
	if n != 1 {
		t.Errorf("Sscanf count error: expected 1: got %d", n)
	}
	if err != nil {
		t.Errorf("Sscanf <empty> expected no error with quoted string; got %s", err)
	}
}

func TestScanNotPointer(t *testing.T) {
	r := strings.NewReader("1")
	var a int
	_, err := Fscan(r, a)
	if err == nil {
		t.Error("expected error scanning non-pointer")
	} else if !strings.Contains(err.Error(), "pointer") {
		t.Errorf("expected pointer error scanning non-pointer, got: %s", err)
	}
}

func TestScanlnNoNewline(t *testing.T) {
	var a int
	_, err := Sscanln("1 x\n", &a)
	if err == nil {
		t.Error("expected error scanning string missing newline")
	} else if !strings.Contains(err.Error(), "newline") {
		t.Errorf("expected newline error scanning string missing newline, got: %s", err)
	}
}

func TestScanlnWithMiddleNewline(t *testing.T) {
	r := strings.NewReader("123\n456\n")
	var a, b int
	_, err := Fscanln(r, &a, &b)
	if err == nil {
		t.Error("expected error scanning string with extra newline")
	} else if !strings.Contains(err.Error(), "newline") {
		t.Errorf("expected newline error scanning string with extra newline, got: %s", err)
	}
}

// eofCounter is a special Reader that counts reads at end of file.
type eofCounter struct {
	reader   *strings.Reader
	eofCount int
}

func (ec *eofCounter) Read(b []byte) (n int, err error) {
	n, err = ec.reader.Read(b)
	if n == 0 {
		ec.eofCount++
	}
	return
}

// TestEOF verifies that when we scan, we see at most EOF once per call to a
// Scan function, and then only when it's really an EOF.
func TestEOF(t *testing.T) {
	ec := &eofCounter{strings.NewReader("123\n"), 0}
	var a int
	n, err := Fscanln(ec, &a)
	if err != nil {
		t.Error("unexpected error", err)
	}
	if n != 1 {
		t.Error("expected to scan one item, got", n)
	}
	if ec.eofCount != 0 {
		t.Error("expected zero EOFs", ec.eofCount)
		ec.eofCount = 0 // reset for next test
	}
	n, err = Fscanln(ec, &a)
	if err == nil {
		t.Error("expected error scanning empty string")
	}
	if n != 0 {
		t.Error("expected to scan zero items, got", n)
	}
	if ec.eofCount != 1 {
		t.Error("expected one EOF, got", ec.eofCount)
	}
}

// TestEOFAtEndOfInput verifies that we see an EOF error if we run out of input.
// This was a buglet: we used to get "expected integer".
func TestEOFAtEndOfInput(t *testing.T) {
	var i, j int
	n, err := Sscanf("23", "%d %d", &i, &j)
	if n != 1 || i != 23 {
		t.Errorf("Sscanf expected one value of 23; got %d %d", n, i)
	}
	if err != io.EOF {
		t.Errorf("Sscanf expected EOF; got %q", err)
	}
	n, err = Sscan("234", &i, &j)
	if n != 1 || i != 234 {
		t.Errorf("Sscan expected one value of 234; got %d %d", n, i)
	}
	if err != io.EOF {
		t.Errorf("Sscan expected EOF; got %q", err)
	}
	// Trailing space is tougher.
	n, err = Sscan("234 ", &i, &j)
	if n != 1 || i != 234 {
		t.Errorf("Sscan expected one value of 234; got %d %d", n, i)
	}
	if err != io.EOF {
		t.Errorf("Sscan expected EOF; got %q", err)
	}
}

var eofTests = []struct {
	format string
	v      any
}{
	{"%s", &stringVal},
	{"%q", &stringVal},
	{"%x", &stringVal},
	{"%v", &stringVal},
	{"%v", &bytesVal},
	{"%v", &intVal},
	{"%v", &uintVal},
	{"%v", &boolVal},
	{"%v", &float32Val},
	{"%v", &complex64Val},
	{"%v", &renamedStringVal},
	{"%v", &renamedBytesVal},
	{"%v", &renamedIntVal},
	{"%v", &renamedUintVal},
	{"%v", &renamedBoolVal},
	{"%v", &renamedFloat32Val},
	{"%v", &renamedComplex64Val},
}

func TestEOFAllTypes(t *testing.T) {
	for i, test := range eofTests {
		if _, err := Sscanf("", test.format, test.v); err != io.EOF {
			t.Errorf("#%d: %s %T not eof on empty string: %s", i, test.format, test.v, err)
		}
		if _, err := Sscanf("   ", test.format, test.v); err != io.EOF {
			t.Errorf("#%d: %s %T not eof on trailing blanks: %s", i, test.format, test.v, err)
		}
	}
}

// TestUnreadRuneWithBufio verifies that, at least when using bufio, successive
// calls to Fscan do not lose runes.
func TestUnreadRuneWithBufio(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("123αb"))
	var i int
	var a string
	n, err := Fscanf(r, "%d", &i)
	if n != 1 || err != nil {
		t.Errorf("reading int expected one item, no errors; got %d %q", n, err)
	}
	if i != 123 {
		t.Errorf("expected 123; got %d", i)
	}
	n, err = Fscanf(r, "%s", &a)
	if n != 1 || err != nil {
		t.Errorf("reading string expected one item, no errors; got %d %q", n, err)
	}
	if a != "αb" {
		t.Errorf("expected αb; got %q", a)
	}
}

type TwoLines string

// Scan attempts to read two lines into the object. Scanln should prevent this
// because it stops at newline; Scan and Scanf should be fine.
func (t *TwoLines) Scan(state ScanState, verb rune) error {
	chars := make([]rune, 0, 100)
	for nlCount := 0; nlCount < 2; {
		c, _, err := state.ReadRune()
		if err != nil {
			return err
		}
		chars = append(chars, c)
		if c == '\n' {
			nlCount++
		}
	}
	*t = TwoLines(string(chars))
	return nil
}

func TestMultiLine(t *testing.T) {
	input := "abc\ndef\n"
	// Sscan should work
	var tscan TwoLines
	n, err := Sscan(input, &tscan)
	if n != 1 {
		t.Errorf("Sscan: expected 1 item; got %d", n)
	}
	if err != nil {
		t.Errorf("Sscan: expected no error; got %s", err)
	}
	if string(tscan) != input {
		t.Errorf("Sscan: expected %q; got %q", input, tscan)
	}
	// Sscanf should work
	var tscanf TwoLines
	n, err = Sscanf(input, "%s", &tscanf)
	if n != 1 {
		t.Errorf("Sscanf: expected 1 item; got %d", n)
	}
	if err != nil {
		t.Errorf("Sscanf: expected no error; got %s", err)
	}
	if string(tscanf) != input {
		t.Errorf("Sscanf: expected %q; got %q", input, tscanf)
	}
	// Sscanln should not work
	var tscanln TwoLines
	n, err = Sscanln(input, &tscanln)
	if n != 0 {
		t.Errorf("Sscanln: expected 0 items; got %d: %q", n, tscanln)
	}
	if err == nil {
		t.Error("Sscanln: expected error; got none")
	} else if err != io.ErrUnexpectedEOF {
		t.Errorf("Sscanln: expected io.ErrUnexpectedEOF (ha!); got %s", err)
	}
}

// TestLineByLineFscanf tests that Fscanf does not read past newline. Issue
// 3481.
func TestLineByLineFscanf(t *testing.T) {
	r := struct{ io.Reader }{strings.NewReader("1\n2\n")}
	var i, j int
	n, err := Fscanf(r, "%v\n", &i)
	if n != 1 || err != nil {
		t.Fatalf("first read: %d %q", n, err)
	}
	n, err = Fscanf(r, "%v\n", &j)
	if n != 1 || err != nil {
		t.Fatalf("second read: %d %q", n, err)
	}
	if i != 1 || j != 2 {
		t.Errorf("wrong values; wanted 1 2 got %d %d", i, j)
	}
}

// TestScanStateCount verifies the correct byte count is returned. Issue 8512.

// runeScanner implements the Scanner interface for TestScanStateCount.
type runeScanner struct {
	rune rune
	size int
}

func (rs *runeScanner) Scan(state ScanState, verb rune) error {
	r, size, err := state.ReadRune()
	rs.rune = r
	rs.size = size
	return err
}

func TestScanStateCount(t *testing.T) {
	var a, b, c runeScanner
	n, err := Sscanf("12➂", "%c%c%c", &a, &b, &c)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected 3 items consumed, got %d", n)
	}
	if a.rune != '1' || b.rune != '2' || c.rune != '➂' {
		t.Errorf("bad scan rune: %q %q %q should be '1' '2' '➂'", a.rune, b.rune, c.rune)
	}
	if a.size != 1 || b.size != 1 || c.size != 3 {
		t.Errorf("bad scan size: %q %q %q should be 1 1 3", a.size, b.size, c.size)
	}
}

// RecursiveInt accepts a string matching %d.%d.%d....
// and parses it into a linked list.
// It allows us to benchmark recursive descent style scanners.
type RecursiveInt struct {
	i    int
	next *RecursiveInt
}

func (r *RecursiveInt) Scan(state ScanState, verb rune) (err error) {
	_, err = Fscan(state, &r.i)
	if err != nil {
		return
	}
	next := new(RecursiveInt)
	_, err = Fscanf(state, ".%v", next)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			err = nil
		}
		return
	}
	r.next = next
	return
}

// scanInts performs the same scanning task as RecursiveInt.Scan
// but without recurring through scanner, so we can compare
// performance more directly.
func scanInts(r *RecursiveInt, b *bytes.Buffer) (err error) {
	r.next = nil
	_, err = Fscan(b, &r.i)
	if err != nil {
		return
	}
	c, _, err := b.ReadRune()
	if err != nil {
		if err == io.EOF {
			err = nil
		}
		return
	}
	if c != '.' {
		return
	}
	next := new(RecursiveInt)
	err = scanInts(next, b)
	if err == nil {
		r.next = next
	}
	return
}

func makeInts(n int) []byte {
	var buf bytes.Buffer
	Fprintf(&buf, "1")
	for i := 1; i < n; i++ {
		Fprintf(&buf, ".%d", i+1)
	}
	return buf.Bytes()
}

func TestScanInts(t *testing.T) {
	testScanInts(t, scanInts)
	testScanInts(t, func(r *RecursiveInt, b *bytes.Buffer) (err error) {
		_, err = Fscan(b, r)
		return
	})
}

// 800 is small enough to not overflow the stack when using gccgo on a
// platform that does not support split stack.
const intCount = 800

func testScanInts(t *testing.T, scan func(*RecursiveInt, *bytes.Buffer) error) {
	r := new(RecursiveInt)
	ints := makeInts(intCount)
	buf := bytes.NewBuffer(ints)
	err := scan(r, buf)
	if err != nil {
		t.Error("unexpected error", err)
	}
	i := 1
	for ; r != nil; r = r.next {
		if r.i != i {
			t.Fatalf("bad scan: expected %d got %d", i,
```