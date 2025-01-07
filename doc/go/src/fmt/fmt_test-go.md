Response:
Let's break down the thought process for analyzing this Go code snippet and answering the prompt.

**1. Understanding the Goal:**

The request asks for a summary of the functionality of the provided Go code, which is explicitly stated to be part of `go/src/fmt/fmt_test.go`. This immediately suggests the code is a test suite for the `fmt` package. The prompt also asks for specific examples, code inferences, handling of command-line arguments (less likely in a test file, but good to keep in mind), common mistakes (also less likely in the test suite itself, but possible), and a final summary.

**2. Initial Code Scan - Identifying Key Structures:**

A quick skim reveals several important elements:

* **`package fmt_test`:** Confirms it's a test package for `fmt`.
* **`import` statements:**  Shows the dependencies, including the `fmt` package itself (imported as `.` for direct access to its functions), `testing`, `io`, `bytes`, `strings`, `math`, `reflect`, `time`, and `unicode`. These imports hint at the kinds of functionalities being tested (string formatting, input/output, reflection, time formatting, etc.).
* **Type Definitions (`type renamed...`):**  A series of custom types based on built-in types. This strongly suggests testing how `fmt` handles different underlying types, including custom ones.
* **Global Variables (`var NaN`, `var intVar`, `var array`, etc.):** These provide test data of various types.
* **Functions with `Test...` prefix (`func TestFmtInterface(t *testing.T)`)**: This is the standard Go testing convention. Each such function represents a specific test case.
* **Structs (`type A struct`, `type B struct`, etc.):**  These are used for testing formatting of composite data types. Some have `String()` and `Format()` methods, indicating tests for custom formatting behavior.
* **The `fmtTests` slice of structs:** This is the most crucial part. Each element in this slice defines a test case with a format string (`fmt`), a value to format (`val`), and the expected output (`out`). This is a table-driven testing approach.

**3. Focusing on the `fmtTests` Slice:**

This is where the core functionality is being exercised. A closer look at the `fmtTests` slice reveals:

* **Various format verbs:**  `%d`, `%v`, `%s`, `%q`, `%x`, `%c`, `%f`, `%e`, `%g`, `%T`, `%p`, `%U`, etc. This directly corresponds to the different formatting capabilities of the `fmt` package.
* **Different data types being formatted:** Integers, floats, strings, byte slices, arrays, slices, structs, pointers, functions, complex numbers, booleans, nil values, and custom types.
* **Flags and modifiers:**  `+`, `-`, `#`, `0`, space, and precision are all being tested in combination with different verbs.
* **Escaping and quoting:** The tests for `%q` and `#q` are evident.
* **Width and precision:** Many test cases specify width and precision modifiers.

**4. Inferring Functionality and Providing Examples:**

Based on the `fmtTests`, we can start inferring the purpose of different format verbs:

* **`%d`:**  Decimal integer formatting.
* **`%s`:** String formatting.
* **`%q`:** Quoted string formatting.
* **`%x`, `%X`:** Hexadecimal formatting (lowercase and uppercase).
* **`%c`:** Character (rune) formatting.
* **`%f`, `%e`, `%g`:** Floating-point formatting (standard, scientific, and general).
* **`%v`:** Default formatting (often uses `String()` or `GoString()` if available).
* **`%T`:** Type printing.
* **`%p`:** Pointer address printing.
* **`%U`:** Unicode format.
* **`%b`:** Binary formatting.

For each verb, we can then devise simple Go code examples to demonstrate its usage. This involves using `fmt.Sprintf` with the appropriate format string and a sample value, along with the expected output. This addresses the "用go代码举例说明" part of the prompt.

**5. Reasoning about Go Language Features:**

The tests touch upon several core Go features:

* **Interfaces:**  The `Stringer` interface is clearly being tested through the custom types `I`, `P`, and `Fn`. The `%s` verb's behavior with these types is a key aspect. The `Formatter` interface is tested with type `F`.
* **Reflection:** The `reflect` package is imported, and some tests use `reflect.ValueOf`. This suggests testing how `fmt` handles values obtained through reflection.
* **Pointers:**  The `%p` verb and tests involving `&` clearly target pointer formatting.
* **Custom Types:** The `renamed...` types verify how `fmt` handles types based on built-in types.
* **String and Byte Slice Handling:** Numerous tests focus on the nuances of formatting strings and byte slices, including escaping and hexadecimal output.

**6. Considering Command-Line Arguments and Common Mistakes:**

While this is a test file, it doesn't directly handle command-line arguments. However, the *underlying* `fmt` package does. So, for that part of the prompt, we'd think about things like:

* **Incorrect format verb:** Using `%d` for a string, for example.
* **Mismatch between format verb and data type:** This will often lead to default formatting or error messages (which the tests indirectly verify).
* **Incorrect use of flags and modifiers:**  Misunderstanding the effect of `+`, `-`, `#`, `0`, and precision.

**7. Structuring the Answer:**

Organize the answer into logical sections as requested by the prompt:

* **功能列举:** List the core functionalities observed in the tests.
* **Go语言功能实现推理与代码举例:** Explain how the tests relate to specific Go features and provide code examples.
* **代码推理:**  If a test case requires deeper code analysis to understand the output, include that with assumptions and inputs/outputs.
* **命令行参数处理:**  Address this, even if it's primarily about the underlying `fmt` package, not the test file itself.
* **使用者易犯错的点:**  Provide examples of common mistakes when using `fmt`.
* **功能归纳:**  Summarize the overall purpose of the test file.

**8. Refinement and Language:**

Ensure the answer is clear, concise, and uses correct terminology. Since the prompt is in Chinese, the answer should also be in Chinese.

By following these steps, we can systematically analyze the provided Go code snippet and generate a comprehensive and accurate response to the prompt.
这段代码是 Go 语言标准库 `fmt` 包的一部分，具体来说，它是 `go/src/fmt/fmt_test.go` 文件的一部分，用于测试 `fmt` 包的各种格式化输出功能。

**它的主要功能可以归纳为：**

1. **测试 `fmt` 包提供的各种格式化动词（verbs）的功能**: 代码中定义了一个名为 `fmtTests` 的结构体切片，其中包含了大量的测试用例。每个测试用例都指定了一个格式化字符串 (`fmt`)、一个要格式化的值 (`val`) 和预期的输出结果 (`out`)。通过遍历这个切片，使用 `Sprintf` 等函数对值进行格式化，并将实际输出与预期输出进行比较，从而验证 `fmt` 包的格式化功能是否正确。

2. **测试不同数据类型的格式化**: 测试用例涵盖了 Go 语言中各种基本数据类型（如 `int`, `uint`, `float`, `bool`, `string`）以及复合数据类型（如 `array`, `slice`, `struct`, `map`, `chan`, `func`）。同时，也测试了自定义类型（通过 `type renamed...` 定义）。

3. **测试格式化标志（flags）和宽度、精度修饰符的效果**: 测试用例中使用了各种格式化标志（如 `+`, `-`, `#`, `0`, 空格）以及宽度和精度修饰符，以验证它们在不同格式化动词下的行为是否符合预期。

4. **测试实现了 `String()`、`Format()` 和 `GoString()` 方法的类型的格式化**: 代码中定义了一些实现了这些接口的自定义类型（如 `I`, `F`, `G`, `P`, `Fn`），测试了 `fmt` 包在遇到这些类型时，是否会正确调用这些方法进行格式化。

5. **测试特殊值的格式化**:  例如，测试了 `NaN`（非数字）、正负无穷 (`posInf`, `negInf`) 以及 `nil` 值的格式化输出。

6. **测试不同进制的格式化**:  例如，二进制 (`%b`)、八进制 (`%o`, `%O`)、十六进制 (`%x`, `%X`)。

7. **测试 Unicode 字符和字符串的格式化**: 例如，`%c` 用于字符，`%s` 和 `%q` 用于字符串， `%U` 用于 Unicode 格式。

8. **测试指针的格式化**: 使用 `%p` 格式化指针地址。

9. **测试错误处理**: 虽然这段代码主要是测试正确的功能，但通过比较实际输出和预期输出，也可以间接地发现 `fmt` 包在处理一些边缘情况或错误输入时的行为。

**如果你能推理出它是什么go语言功能的实现，请用go代码举例说明:**

基于上述分析，这段代码主要测试了 Go 语言 `fmt` 包提供的**格式化输出**功能。`fmt` 包允许开发者使用各种格式化动词、标志和修饰符，将不同类型的数据转换为易于阅读的字符串表示形式。

**Go 代码示例：**

```go
package main

import "fmt"

func main() {
	age := 30
	name := "Alice"
	height := 1.65

	// 使用不同的格式化动词
	fmt.Printf("我的名字是 %s，年龄是 %d，身高是 %.2f 米。\n", name, age, height)

	// 使用 %v 进行默认格式化
	person := struct {
		Name string
		Age  int
	}{Name: "Bob", Age: 25}
	fmt.Printf("人员信息： %v\n", person)

	// 使用 %#v 输出 Go 语法表示
	fmt.Printf("人员信息（Go语法）： %#v\n", person)

	// 使用 %T 输出类型
	fmt.Printf("age 的类型是：%T\n", age)

	// 使用 %q 输出带引号的字符串
	message := "Hello, Go!"
	fmt.Printf("消息： %q\n", message)

	// 使用 %x 输出十六进制表示
	bytes := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}
	fmt.Printf("字节的十六进制表示： %x\n", bytes)

	// 使用 %p 输出指针地址
	ptr := &age
	fmt.Printf("age 变量的地址： %p\n", ptr)
}
```

**假设的输入与输出：**

上述代码无需额外输入，其输出是固定的。

**输出：**

```
我的名字是 Alice，年龄是 30，身高是 1.65 米。
人员信息： {Bob 25}
人员信息（Go语法）： struct { Name string; Age int }{Name:"Bob", Age:25}
age 的类型是：int
消息： "Hello, Go!"
字节的十六进制表示： 48656c6c6f
age 变量的地址： 0xc000018098  (实际地址会不同)
```

**如果涉及命令行参数的具体处理，请详细介绍一下：**

这段 `fmt_test.go` 代码本身**不涉及**命令行参数的处理。它是一个测试文件，其目的是通过硬编码的测试用例来验证 `fmt` 包的功能。

`fmt` 包本身的一些函数，例如 `Scanf` 系列函数，可以用于从标准输入或实现了 `io.Reader` 接口的对象中读取格式化的数据，这可以间接地与命令行参数关联（例如，通过管道将命令行输出传递给使用 `Scanf` 的程序）。但是，这段测试代码并没有直接演示或测试 `Scanf` 的功能。

**如果有哪些使用者易犯错的点，请举例说明：**

1. **格式化动词与数据类型不匹配：**

   ```go
   age := 30
   name := "Alice"
   fmt.Printf("年龄是 %s，名字是 %d\n", age, name) // 错误： %s 用于字符串，%d 用于整数
   ```

   **输出：**  `%!s(int=30)，名字是 %!d(string=Alice)`  （`fmt` 包会尽可能给出提示）

2. **忽略宽度和精度修饰符的效果：**

   ```go
   price := 12.345
   fmt.Printf("价格： %5.2f\n", price) // 输出宽度为 5，保留 2 位小数
   fmt.Printf("价格： %.2f\n", price)  // 只保留 2 位小数
   ```

   **输出：**
   ```
   价格： 12.35
   价格： 12.35
   ```
   初学者可能不清楚宽度修饰符的作用，只关注精度。

3. **混淆 `%v` 和 `%#v` 的用途：**

   `%v` 提供默认的格式化输出，而 `%#v` 提供 Go 语法表示形式，通常用于调试。不了解它们的区别可能导致输出不符合预期。

   ```go
   type Person struct {
       Name string
       Age  int
   }
   p := Person{"Charlie", 35}
   fmt.Printf("人员信息： %v\n", p)   // 输出： {Charlie 35}
   fmt.Printf("人员信息： %#v\n", p)  // 输出： main.Person{Name:"Charlie", Age:35}
   ```

4. **对实现了 `String()` 方法的类型使用非 `%s` 格式化动词：**

   如果一个类型实现了 `String()` 方法，通常只有 `%s` 会调用该方法。其他动词可能会使用默认的格式化方式。

   ```go
   type MyInt int
   func (m MyInt) String() string {
       return fmt.Sprintf("My integer is: %d", m)
   }

   num := MyInt(10)
   fmt.Printf("数字： %s\n", num)   // 输出： My integer is: 10
   fmt.Printf("数字： %v\n", num)   // 输出： My integer is: 10 (通常和 %s 行为一致)
   fmt.Printf("数字： %d\n", num)   // 输出： 10 (使用默认的整数格式化)
   ```

**请用中文回答。这是第1部分，共2部分，请归纳一下它的功能**

总而言之，这段 `go/src/fmt/fmt_test.go` 的代码片段是 `fmt` 包的核心测试代码，它的主要功能是**系统性地、全面地测试 `fmt` 包提供的各种格式化输出功能是否按照预期工作**。它通过大量的预定义测试用例，覆盖了不同的格式化动词、数据类型、格式化标志和修饰符，以及实现了特定接口的类型，确保 `fmt` 包的可靠性和正确性。 这部分代码是 `fmt` 包质量保证的关键组成部分。

Prompt: 
```
这是路径为go/src/fmt/fmt_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package fmt_test

import (
	"bytes"
	. "fmt"
	"internal/race"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"
)

type (
	renamedBool       bool
	renamedInt        int
	renamedInt8       int8
	renamedInt16      int16
	renamedInt32      int32
	renamedInt64      int64
	renamedUint       uint
	renamedUint8      uint8
	renamedUint16     uint16
	renamedUint32     uint32
	renamedUint64     uint64
	renamedUintptr    uintptr
	renamedString     string
	renamedBytes      []byte
	renamedFloat32    float32
	renamedFloat64    float64
	renamedComplex64  complex64
	renamedComplex128 complex128
)

func TestFmtInterface(t *testing.T) {
	var i1 any
	i1 = "abc"
	s := Sprintf("%s", i1)
	if s != "abc" {
		t.Errorf(`Sprintf("%%s", empty("abc")) = %q want %q`, s, "abc")
	}
}

var (
	NaN    = math.NaN()
	posInf = math.Inf(1)
	negInf = math.Inf(-1)

	intVar = 0

	array  = [5]int{1, 2, 3, 4, 5}
	iarray = [4]any{1, "hello", 2.5, nil}
	slice  = array[:]
	islice = iarray[:]
)

type A struct {
	i int
	j uint
	s string
	x []int
}

type I int

func (i I) String() string { return Sprintf("<%d>", int(i)) }

type B struct {
	I I
	j int
}

type C struct {
	i int
	B
}

type F int

func (f F) Format(s State, c rune) {
	Fprintf(s, "<%c=F(%d)>", c, int(f))
}

type G int

func (g G) GoString() string {
	return Sprintf("GoString(%d)", int(g))
}

type S struct {
	F F // a struct field that Formats
	G G // a struct field that GoStrings
}

type SI struct {
	I any
}

// P is a type with a String method with pointer receiver for testing %p.
type P int

var pValue P

func (p *P) String() string {
	return "String(p)"
}

// Fn is a function type with a String method.
type Fn func() int

func (fn Fn) String() string { return "String(fn)" }

var fnValue Fn

// U is a type with two unexported function fields.
type U struct {
	u  func() string
	fn Fn
}

var barray = [5]renamedUint8{1, 2, 3, 4, 5}
var bslice = barray[:]

type byteStringer byte

func (byteStringer) String() string {
	return "X"
}

var byteStringerSlice = []byteStringer{'h', 'e', 'l', 'l', 'o'}

type byteFormatter byte

func (byteFormatter) Format(f State, _ rune) {
	Fprint(f, "X")
}

var byteFormatterSlice = []byteFormatter{'h', 'e', 'l', 'l', 'o'}

type writeStringFormatter string

func (sf writeStringFormatter) Format(f State, c rune) {
	if sw, ok := f.(io.StringWriter); ok {
		sw.WriteString("***" + string(sf) + "***")
	}
}

var fmtTests = []struct {
	fmt string
	val any
	out string
}{
	{"%d", 12345, "12345"},
	{"%v", 12345, "12345"},
	{"%t", true, "true"},

	// basic string
	{"%s", "abc", "abc"},
	{"%q", "abc", `"abc"`},
	{"%x", "abc", "616263"},
	{"%x", "\xff\xf0\x0f\xff", "fff00fff"},
	{"%X", "\xff\xf0\x0f\xff", "FFF00FFF"},
	{"%x", "", ""},
	{"% x", "", ""},
	{"%#x", "", ""},
	{"%# x", "", ""},
	{"%x", "xyz", "78797a"},
	{"%X", "xyz", "78797A"},
	{"% x", "xyz", "78 79 7a"},
	{"% X", "xyz", "78 79 7A"},
	{"%#x", "xyz", "0x78797a"},
	{"%#X", "xyz", "0X78797A"},
	{"%# x", "xyz", "0x78 0x79 0x7a"},
	{"%# X", "xyz", "0X78 0X79 0X7A"},

	// basic bytes
	{"%s", []byte("abc"), "abc"},
	{"%s", [3]byte{'a', 'b', 'c'}, "abc"},
	{"%s", &[3]byte{'a', 'b', 'c'}, "&abc"},
	{"%q", []byte("abc"), `"abc"`},
	{"%x", []byte("abc"), "616263"},
	{"%x", []byte("\xff\xf0\x0f\xff"), "fff00fff"},
	{"%X", []byte("\xff\xf0\x0f\xff"), "FFF00FFF"},
	{"%x", []byte(""), ""},
	{"% x", []byte(""), ""},
	{"%#x", []byte(""), ""},
	{"%# x", []byte(""), ""},
	{"%x", []byte("xyz"), "78797a"},
	{"%X", []byte("xyz"), "78797A"},
	{"% x", []byte("xyz"), "78 79 7a"},
	{"% X", []byte("xyz"), "78 79 7A"},
	{"%#x", []byte("xyz"), "0x78797a"},
	{"%#X", []byte("xyz"), "0X78797A"},
	{"%# x", []byte("xyz"), "0x78 0x79 0x7a"},
	{"%# X", []byte("xyz"), "0X78 0X79 0X7A"},

	// escaped strings
	{"%q", "", `""`},
	{"%#q", "", "``"},
	{"%q", "\"", `"\""`},
	{"%#q", "\"", "`\"`"},
	{"%q", "`", `"` + "`" + `"`},
	{"%#q", "`", `"` + "`" + `"`},
	{"%q", "\n", `"\n"`},
	{"%#q", "\n", `"\n"`},
	{"%q", `\n`, `"\\n"`},
	{"%#q", `\n`, "`\\n`"},
	{"%q", "abc", `"abc"`},
	{"%#q", "abc", "`abc`"},
	{"%q", "日本語", `"日本語"`},
	{"%+q", "日本語", `"\u65e5\u672c\u8a9e"`},
	{"%#q", "日本語", "`日本語`"},
	{"%#+q", "日本語", "`日本語`"},
	{"%q", "\a\b\f\n\r\t\v\"\\", `"\a\b\f\n\r\t\v\"\\"`},
	{"%+q", "\a\b\f\n\r\t\v\"\\", `"\a\b\f\n\r\t\v\"\\"`},
	{"%#q", "\a\b\f\n\r\t\v\"\\", `"\a\b\f\n\r\t\v\"\\"`},
	{"%#+q", "\a\b\f\n\r\t\v\"\\", `"\a\b\f\n\r\t\v\"\\"`},
	{"%q", "☺", `"☺"`},
	{"% q", "☺", `"☺"`}, // The space modifier should have no effect.
	{"%+q", "☺", `"\u263a"`},
	{"%#q", "☺", "`☺`"},
	{"%#+q", "☺", "`☺`"},
	{"%10q", "⌘", `       "⌘"`},
	{"%+10q", "⌘", `  "\u2318"`},
	{"%-10q", "⌘", `"⌘"       `},
	{"%+-10q", "⌘", `"\u2318"  `},
	{"%010q", "⌘", `0000000"⌘"`},
	{"%+010q", "⌘", `00"\u2318"`},
	{"%-010q", "⌘", `"⌘"       `}, // 0 has no effect when - is present.
	{"%+-010q", "⌘", `"\u2318"  `},
	{"%#8q", "\n", `    "\n"`},
	{"%#+8q", "\r", `    "\r"`},
	{"%#-8q", "\t", "`	`     "},
	{"%#+-8q", "\b", `"\b"    `},
	{"%q", "abc\xffdef", `"abc\xffdef"`},
	{"%+q", "abc\xffdef", `"abc\xffdef"`},
	{"%#q", "abc\xffdef", `"abc\xffdef"`},
	{"%#+q", "abc\xffdef", `"abc\xffdef"`},
	// Runes that are not printable.
	{"%q", "\U0010ffff", `"\U0010ffff"`},
	{"%+q", "\U0010ffff", `"\U0010ffff"`},
	{"%#q", "\U0010ffff", "`􏿿`"},
	{"%#+q", "\U0010ffff", "`􏿿`"},
	// Runes that are not valid.
	{"%q", string(rune(0x110000)), `"�"`},
	{"%+q", string(rune(0x110000)), `"\ufffd"`},
	{"%#q", string(rune(0x110000)), "`�`"},
	{"%#+q", string(rune(0x110000)), "`�`"},

	// characters
	{"%c", uint('x'), "x"},
	{"%c", 0xe4, "ä"},
	{"%c", 0x672c, "本"},
	{"%c", '日', "日"},
	{"%.0c", '⌘', "⌘"}, // Specifying precision should have no effect.
	{"%3c", '⌘', "  ⌘"},
	{"%-3c", '⌘', "⌘  "},
	{"%c", uint64(0x100000000), "\ufffd"},
	// Runes that are not printable.
	{"%c", '\U00000e00', "\u0e00"},
	{"%c", '\U0010ffff', "\U0010ffff"},
	// Runes that are not valid.
	{"%c", -1, "�"},
	{"%c", 0xDC80, "�"},
	{"%c", rune(0x110000), "�"},
	{"%c", int64(0xFFFFFFFFF), "�"},
	{"%c", uint64(0xFFFFFFFFF), "�"},

	// escaped characters
	{"%q", uint(0), `'\x00'`},
	{"%+q", uint(0), `'\x00'`},
	{"%q", '"', `'"'`},
	{"%+q", '"', `'"'`},
	{"%q", '\'', `'\''`},
	{"%+q", '\'', `'\''`},
	{"%q", '`', "'`'"},
	{"%+q", '`', "'`'"},
	{"%q", 'x', `'x'`},
	{"%+q", 'x', `'x'`},
	{"%q", 'ÿ', `'ÿ'`},
	{"%+q", 'ÿ', `'\u00ff'`},
	{"%q", '\n', `'\n'`},
	{"%+q", '\n', `'\n'`},
	{"%q", '☺', `'☺'`},
	{"%+q", '☺', `'\u263a'`},
	{"% q", '☺', `'☺'`},  // The space modifier should have no effect.
	{"%.0q", '☺', `'☺'`}, // Specifying precision should have no effect.
	{"%10q", '⌘', `       '⌘'`},
	{"%+10q", '⌘', `  '\u2318'`},
	{"%-10q", '⌘', `'⌘'       `},
	{"%+-10q", '⌘', `'\u2318'  `},
	{"%010q", '⌘', `0000000'⌘'`},
	{"%+010q", '⌘', `00'\u2318'`},
	{"%-010q", '⌘', `'⌘'       `}, // 0 has no effect when - is present.
	{"%+-010q", '⌘', `'\u2318'  `},
	// Runes that are not printable.
	{"%q", '\U00000e00', `'\u0e00'`},
	{"%q", '\U0010ffff', `'\U0010ffff'`},
	// Runes that are not valid.
	{"%q", int32(-1), `'�'`},
	{"%q", 0xDC80, `'�'`},
	{"%q", rune(0x110000), `'�'`},
	{"%q", int64(0xFFFFFFFFF), `'�'`},
	{"%q", uint64(0xFFFFFFFFF), `'�'`},

	// width
	{"%5s", "abc", "  abc"},
	{"%5s", []byte("abc"), "  abc"},
	{"%2s", "\u263a", " ☺"},
	{"%2s", []byte("\u263a"), " ☺"},
	{"%-5s", "abc", "abc  "},
	{"%-5s", []byte("abc"), "abc  "},
	{"%05s", "abc", "00abc"},
	{"%05s", []byte("abc"), "00abc"},
	{"%5s", "abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"},
	{"%5s", []byte("abcdefghijklmnopqrstuvwxyz"), "abcdefghijklmnopqrstuvwxyz"},
	{"%.5s", "abcdefghijklmnopqrstuvwxyz", "abcde"},
	{"%.5s", []byte("abcdefghijklmnopqrstuvwxyz"), "abcde"},
	{"%.0s", "日本語日本語", ""},
	{"%.0s", []byte("日本語日本語"), ""},
	{"%.5s", "日本語日本語", "日本語日本"},
	{"%.5s", []byte("日本語日本語"), "日本語日本"},
	{"%.10s", "日本語日本語", "日本語日本語"},
	{"%.10s", []byte("日本語日本語"), "日本語日本語"},
	{"%08q", "abc", `000"abc"`},
	{"%08q", []byte("abc"), `000"abc"`},
	{"%-8q", "abc", `"abc"   `},
	{"%-8q", []byte("abc"), `"abc"   `},
	{"%.5q", "abcdefghijklmnopqrstuvwxyz", `"abcde"`},
	{"%.5q", []byte("abcdefghijklmnopqrstuvwxyz"), `"abcde"`},
	{"%.5x", "abcdefghijklmnopqrstuvwxyz", "6162636465"},
	{"%.5x", []byte("abcdefghijklmnopqrstuvwxyz"), "6162636465"},
	{"%.3q", "日本語日本語", `"日本語"`},
	{"%.3q", []byte("日本語日本語"), `"日本語"`},
	{"%.1q", "日本語", `"日"`},
	{"%.1q", []byte("日本語"), `"日"`},
	{"%.1x", "日本語", "e6"},
	{"%.1X", []byte("日本語"), "E6"},
	{"%10.1q", "日本語日本語", `       "日"`},
	{"%10.1q", []byte("日本語日本語"), `       "日"`},
	{"%10v", nil, "     <nil>"},
	{"%-10v", nil, "<nil>     "},

	// integers
	{"%d", uint(12345), "12345"},
	{"%d", int(-12345), "-12345"},
	{"%d", ^uint8(0), "255"},
	{"%d", ^uint16(0), "65535"},
	{"%d", ^uint32(0), "4294967295"},
	{"%d", ^uint64(0), "18446744073709551615"},
	{"%d", int8(-1 << 7), "-128"},
	{"%d", int16(-1 << 15), "-32768"},
	{"%d", int32(-1 << 31), "-2147483648"},
	{"%d", int64(-1 << 63), "-9223372036854775808"},
	{"%.d", 0, ""},
	{"%.0d", 0, ""},
	{"%6.0d", 0, "      "},
	{"%06.0d", 0, "      "},
	{"% d", 12345, " 12345"},
	{"%+d", 12345, "+12345"},
	{"%+d", -12345, "-12345"},
	{"%b", 7, "111"},
	{"%b", -6, "-110"},
	{"%#b", 7, "0b111"},
	{"%#b", -6, "-0b110"},
	{"%b", ^uint32(0), "11111111111111111111111111111111"},
	{"%b", ^uint64(0), "1111111111111111111111111111111111111111111111111111111111111111"},
	{"%b", int64(-1 << 63), zeroFill("-1", 63, "")},
	{"%o", 01234, "1234"},
	{"%o", -01234, "-1234"},
	{"%#o", 01234, "01234"},
	{"%#o", -01234, "-01234"},
	{"%O", 01234, "0o1234"},
	{"%O", -01234, "-0o1234"},
	{"%o", ^uint32(0), "37777777777"},
	{"%o", ^uint64(0), "1777777777777777777777"},
	{"%#X", 0, "0X0"},
	{"%x", 0x12abcdef, "12abcdef"},
	{"%X", 0x12abcdef, "12ABCDEF"},
	{"%x", ^uint32(0), "ffffffff"},
	{"%X", ^uint64(0), "FFFFFFFFFFFFFFFF"},
	{"%.20b", 7, "00000000000000000111"},
	{"%10d", 12345, "     12345"},
	{"%10d", -12345, "    -12345"},
	{"%+10d", 12345, "    +12345"},
	{"%010d", 12345, "0000012345"},
	{"%010d", -12345, "-000012345"},
	{"%20.8d", 1234, "            00001234"},
	{"%20.8d", -1234, "           -00001234"},
	{"%020.8d", 1234, "            00001234"},
	{"%020.8d", -1234, "           -00001234"},
	{"%-20.8d", 1234, "00001234            "},
	{"%-20.8d", -1234, "-00001234           "},
	{"%-#20.8x", 0x1234abc, "0x01234abc          "},
	{"%-#20.8X", 0x1234abc, "0X01234ABC          "},
	{"%-#20.8o", 01234, "00001234            "},

	// Test correct f.intbuf overflow checks.
	{"%068d", 1, zeroFill("", 68, "1")},
	{"%068d", -1, zeroFill("-", 67, "1")},
	{"%#.68x", 42, zeroFill("0x", 68, "2a")},
	{"%.68d", -42, zeroFill("-", 68, "42")},
	{"%+.68d", 42, zeroFill("+", 68, "42")},
	{"% .68d", 42, zeroFill(" ", 68, "42")},
	{"% +.68d", 42, zeroFill("+", 68, "42")},

	// unicode format
	{"%U", 0, "U+0000"},
	{"%U", -1, "U+FFFFFFFFFFFFFFFF"},
	{"%U", '\n', `U+000A`},
	{"%#U", '\n', `U+000A`},
	{"%+U", 'x', `U+0078`},       // Plus flag should have no effect.
	{"%# U", 'x', `U+0078 'x'`},  // Space flag should have no effect.
	{"%#.2U", 'x', `U+0078 'x'`}, // Precisions below 4 should print 4 digits.
	{"%U", '\u263a', `U+263A`},
	{"%#U", '\u263a', `U+263A '☺'`},
	{"%U", '\U0001D6C2', `U+1D6C2`},
	{"%#U", '\U0001D6C2', `U+1D6C2 '𝛂'`},
	{"%#14.6U", '⌘', "  U+002318 '⌘'"},
	{"%#-14.6U", '⌘', "U+002318 '⌘'  "},
	{"%#014.6U", '⌘', "  U+002318 '⌘'"},
	{"%#-014.6U", '⌘', "U+002318 '⌘'  "},
	{"%.68U", uint(42), zeroFill("U+", 68, "2A")},
	{"%#.68U", '日', zeroFill("U+", 68, "65E5") + " '日'"},

	// floats
	{"%+.3e", 0.0, "+0.000e+00"},
	{"%+.3e", 1.0, "+1.000e+00"},
	{"%+.3x", 0.0, "+0x0.000p+00"},
	{"%+.3x", 1.0, "+0x1.000p+00"},
	{"%+.3f", -1.0, "-1.000"},
	{"%+.3F", -1.0, "-1.000"},
	{"%+.3F", float32(-1.0), "-1.000"},
	{"%+07.2f", 1.0, "+001.00"},
	{"%+07.2f", -1.0, "-001.00"},
	{"%-07.2f", 1.0, "1.00   "},
	{"%-07.2f", -1.0, "-1.00  "},
	{"%+-07.2f", 1.0, "+1.00  "},
	{"%+-07.2f", -1.0, "-1.00  "},
	{"%-+07.2f", 1.0, "+1.00  "},
	{"%-+07.2f", -1.0, "-1.00  "},
	{"%+10.2f", +1.0, "     +1.00"},
	{"%+10.2f", -1.0, "     -1.00"},
	{"% .3E", -1.0, "-1.000E+00"},
	{"% .3e", 1.0, " 1.000e+00"},
	{"% .3X", -1.0, "-0X1.000P+00"},
	{"% .3x", 1.0, " 0x1.000p+00"},
	{"%+.3g", 0.0, "+0"},
	{"%+.3g", 1.0, "+1"},
	{"%+.3g", -1.0, "-1"},
	{"% .3g", -1.0, "-1"},
	{"% .3g", 1.0, " 1"},
	{"%b", float32(1.0), "8388608p-23"},
	{"%b", 1.0, "4503599627370496p-52"},
	// Test sharp flag used with floats.
	{"%#g", 1e-323, "1.00000e-323"},
	{"%#g", -1.0, "-1.00000"},
	{"%#g", 1.1, "1.10000"},
	{"%#g", 123456.0, "123456."},
	{"%#g", 1234567.0, "1.234567e+06"},
	{"%#g", 1230000.0, "1.23000e+06"},
	{"%#g", 1000000.0, "1.00000e+06"},
	{"%#.0f", 1.0, "1."},
	{"%#.0e", 1.0, "1.e+00"},
	{"%#.0x", 1.0, "0x1.p+00"},
	{"%#.0g", 1.0, "1."},
	{"%#.0g", 1100000.0, "1.e+06"},
	{"%#.4f", 1.0, "1.0000"},
	{"%#.4e", 1.0, "1.0000e+00"},
	{"%#.4x", 1.0, "0x1.0000p+00"},
	{"%#.4g", 1.0, "1.000"},
	{"%#.4g", 100000.0, "1.000e+05"},
	{"%#.4g", 1.234, "1.234"},
	{"%#.4g", 0.1234, "0.1234"},
	{"%#.4g", 1.23, "1.230"},
	{"%#.4g", 0.123, "0.1230"},
	{"%#.4g", 1.2, "1.200"},
	{"%#.4g", 0.12, "0.1200"},
	{"%#.4g", 10.2, "10.20"},
	{"%#.4g", 0.0, "0.000"},
	{"%#.4g", 0.012, "0.01200"},
	{"%#.0f", 123.0, "123."},
	{"%#.0e", 123.0, "1.e+02"},
	{"%#.0x", 123.0, "0x1.p+07"},
	{"%#.0g", 123.0, "1.e+02"},
	{"%#.4f", 123.0, "123.0000"},
	{"%#.4e", 123.0, "1.2300e+02"},
	{"%#.4x", 123.0, "0x1.ec00p+06"},
	{"%#.4g", 123.0, "123.0"},
	{"%#.4g", 123000.0, "1.230e+05"},
	{"%#9.4g", 1.0, "    1.000"},
	// The sharp flag has no effect for binary float format.
	{"%#b", 1.0, "4503599627370496p-52"},
	// Precision has no effect for binary float format.
	{"%.4b", float32(1.0), "8388608p-23"},
	{"%.4b", -1.0, "-4503599627370496p-52"},
	// Test correct f.intbuf boundary checks.
	{"%.68f", 1.0, zeroFill("1.", 68, "")},
	{"%.68f", -1.0, zeroFill("-1.", 68, "")},
	// float infinites and NaNs
	{"%f", posInf, "+Inf"},
	{"%.1f", negInf, "-Inf"},
	{"% f", NaN, " NaN"},
	{"%20f", posInf, "                +Inf"},
	{"% 20F", posInf, "                 Inf"},
	{"% 20e", negInf, "                -Inf"},
	{"% 20x", negInf, "                -Inf"},
	{"%+20E", negInf, "                -Inf"},
	{"%+20X", negInf, "                -Inf"},
	{"% +20g", negInf, "                -Inf"},
	{"%+-20G", posInf, "+Inf                "},
	{"%20e", NaN, "                 NaN"},
	{"%20x", NaN, "                 NaN"},
	{"% +20E", NaN, "                +NaN"},
	{"% +20X", NaN, "                +NaN"},
	{"% -20g", NaN, " NaN                "},
	{"%+-20G", NaN, "+NaN                "},
	// Zero padding does not apply to infinities and NaN.
	{"%+020e", posInf, "                +Inf"},
	{"%+020x", posInf, "                +Inf"},
	{"%-020f", negInf, "-Inf                "},
	{"%-020E", NaN, "NaN                 "},
	{"%-020X", NaN, "NaN                 "},

	// complex values
	{"%.f", 0i, "(0+0i)"},
	{"% .f", 0i, "( 0+0i)"},
	{"%+.f", 0i, "(+0+0i)"},
	{"% +.f", 0i, "(+0+0i)"},
	{"%+.3e", 0i, "(+0.000e+00+0.000e+00i)"},
	{"%+.3x", 0i, "(+0x0.000p+00+0x0.000p+00i)"},
	{"%+.3f", 0i, "(+0.000+0.000i)"},
	{"%+.3g", 0i, "(+0+0i)"},
	{"%+.3e", 1 + 2i, "(+1.000e+00+2.000e+00i)"},
	{"%+.3x", 1 + 2i, "(+0x1.000p+00+0x1.000p+01i)"},
	{"%+.3f", 1 + 2i, "(+1.000+2.000i)"},
	{"%+.3g", 1 + 2i, "(+1+2i)"},
	{"%.3e", 0i, "(0.000e+00+0.000e+00i)"},
	{"%.3x", 0i, "(0x0.000p+00+0x0.000p+00i)"},
	{"%.3f", 0i, "(0.000+0.000i)"},
	{"%.3F", 0i, "(0.000+0.000i)"},
	{"%.3F", complex64(0i), "(0.000+0.000i)"},
	{"%.3g", 0i, "(0+0i)"},
	{"%.3e", 1 + 2i, "(1.000e+00+2.000e+00i)"},
	{"%.3x", 1 + 2i, "(0x1.000p+00+0x1.000p+01i)"},
	{"%.3f", 1 + 2i, "(1.000+2.000i)"},
	{"%.3g", 1 + 2i, "(1+2i)"},
	{"%.3e", -1 - 2i, "(-1.000e+00-2.000e+00i)"},
	{"%.3x", -1 - 2i, "(-0x1.000p+00-0x1.000p+01i)"},
	{"%.3f", -1 - 2i, "(-1.000-2.000i)"},
	{"%.3g", -1 - 2i, "(-1-2i)"},
	{"% .3E", -1 - 2i, "(-1.000E+00-2.000E+00i)"},
	{"% .3X", -1 - 2i, "(-0X1.000P+00-0X1.000P+01i)"},
	{"%+.3g", 1 + 2i, "(+1+2i)"},
	{"%+.3g", complex64(1 + 2i), "(+1+2i)"},
	{"%#g", 1 + 2i, "(1.00000+2.00000i)"},
	{"%#g", 123456 + 789012i, "(123456.+789012.i)"},
	{"%#g", 1e-10i, "(0.00000+1.00000e-10i)"},
	{"%#g", -1e10 - 1.11e100i, "(-1.00000e+10-1.11000e+100i)"},
	{"%#.0f", 1.23 + 1.0i, "(1.+1.i)"},
	{"%#.0e", 1.23 + 1.0i, "(1.e+00+1.e+00i)"},
	{"%#.0x", 1.23 + 1.0i, "(0x1.p+00+0x1.p+00i)"},
	{"%#.0g", 1.23 + 1.0i, "(1.+1.i)"},
	{"%#.0g", 0 + 100000i, "(0.+1.e+05i)"},
	{"%#.0g", 1230000 + 0i, "(1.e+06+0.i)"},
	{"%#.4f", 1 + 1.23i, "(1.0000+1.2300i)"},
	{"%#.4e", 123 + 1i, "(1.2300e+02+1.0000e+00i)"},
	{"%#.4x", 123 + 1i, "(0x1.ec00p+06+0x1.0000p+00i)"},
	{"%#.4g", 123 + 1.23i, "(123.0+1.230i)"},
	{"%#12.5g", 0 + 100000i, "(      0.0000 +1.0000e+05i)"},
	{"%#12.5g", 1230000 - 0i, "(  1.2300e+06     +0.0000i)"},
	{"%b", 1 + 2i, "(4503599627370496p-52+4503599627370496p-51i)"},
	{"%b", complex64(1 + 2i), "(8388608p-23+8388608p-22i)"},
	// The sharp flag has no effect for binary complex format.
	{"%#b", 1 + 2i, "(4503599627370496p-52+4503599627370496p-51i)"},
	// Precision has no effect for binary complex format.
	{"%.4b", 1 + 2i, "(4503599627370496p-52+4503599627370496p-51i)"},
	{"%.4b", complex64(1 + 2i), "(8388608p-23+8388608p-22i)"},
	// complex infinites and NaNs
	{"%f", complex(posInf, posInf), "(+Inf+Infi)"},
	{"%f", complex(negInf, negInf), "(-Inf-Infi)"},
	{"%f", complex(NaN, NaN), "(NaN+NaNi)"},
	{"%.1f", complex(posInf, posInf), "(+Inf+Infi)"},
	{"% f", complex(posInf, posInf), "( Inf+Infi)"},
	{"% f", complex(negInf, negInf), "(-Inf-Infi)"},
	{"% f", complex(NaN, NaN), "( NaN+NaNi)"},
	{"%8e", complex(posInf, posInf), "(    +Inf    +Infi)"},
	{"%8x", complex(posInf, posInf), "(    +Inf    +Infi)"},
	{"% 8E", complex(posInf, posInf), "(     Inf    +Infi)"},
	{"% 8X", complex(posInf, posInf), "(     Inf    +Infi)"},
	{"%+8f", complex(negInf, negInf), "(    -Inf    -Infi)"},
	{"% +8g", complex(negInf, negInf), "(    -Inf    -Infi)"},
	{"% -8G", complex(NaN, NaN), "( NaN    +NaN    i)"},
	{"%+-8b", complex(NaN, NaN), "(+NaN    +NaN    i)"},
	// Zero padding does not apply to infinities and NaN.
	{"%08f", complex(posInf, posInf), "(    +Inf    +Infi)"},
	{"%-08g", complex(negInf, negInf), "(-Inf    -Inf    i)"},
	{"%-08G", complex(NaN, NaN), "(NaN     +NaN    i)"},

	// old test/fmt_test.go
	{"%e", 1.0, "1.000000e+00"},
	{"%e", 1234.5678e3, "1.234568e+06"},
	{"%e", 1234.5678e-8, "1.234568e-05"},
	{"%e", -7.0, "-7.000000e+00"},
	{"%e", -1e-9, "-1.000000e-09"},
	{"%f", 1234.5678e3, "1234567.800000"},
	{"%f", 1234.5678e-8, "0.000012"},
	{"%f", -7.0, "-7.000000"},
	{"%f", -1e-9, "-0.000000"},
	{"%g", 1234.5678e3, "1.2345678e+06"},
	{"%g", float32(1234.5678e3), "1.2345678e+06"},
	{"%g", 1234.5678e-8, "1.2345678e-05"},
	{"%g", -7.0, "-7"},
	{"%g", -1e-9, "-1e-09"},
	{"%g", float32(-1e-9), "-1e-09"},
	{"%E", 1.0, "1.000000E+00"},
	{"%E", 1234.5678e3, "1.234568E+06"},
	{"%E", 1234.5678e-8, "1.234568E-05"},
	{"%E", -7.0, "-7.000000E+00"},
	{"%E", -1e-9, "-1.000000E-09"},
	{"%G", 1234.5678e3, "1.2345678E+06"},
	{"%G", float32(1234.5678e3), "1.2345678E+06"},
	{"%G", 1234.5678e-8, "1.2345678E-05"},
	{"%G", -7.0, "-7"},
	{"%G", -1e-9, "-1E-09"},
	{"%G", float32(-1e-9), "-1E-09"},
	{"%20.5s", "qwertyuiop", "               qwert"},
	{"%.5s", "qwertyuiop", "qwert"},
	{"%-20.5s", "qwertyuiop", "qwert               "},
	{"%20c", 'x', "                   x"},
	{"%-20c", 'x', "x                   "},
	{"%20.6e", 1.2345e3, "        1.234500e+03"},
	{"%20.6e", 1.2345e-3, "        1.234500e-03"},
	{"%20e", 1.2345e3, "        1.234500e+03"},
	{"%20e", 1.2345e-3, "        1.234500e-03"},
	{"%20.8e", 1.2345e3, "      1.23450000e+03"},
	{"%20f", 1.23456789e3, "         1234.567890"},
	{"%20f", 1.23456789e-3, "            0.001235"},
	{"%20f", 12345678901.23456789, "  12345678901.234568"},
	{"%-20f", 1.23456789e3, "1234.567890         "},
	{"%20.8f", 1.23456789e3, "       1234.56789000"},
	{"%20.8f", 1.23456789e-3, "          0.00123457"},
	{"%g", 1.23456789e3, "1234.56789"},
	{"%g", 1.23456789e-3, "0.00123456789"},
	{"%g", 1.23456789e20, "1.23456789e+20"},

	// arrays
	{"%v", array, "[1 2 3 4 5]"},
	{"%v", iarray, "[1 hello 2.5 <nil>]"},
	{"%v", barray, "[1 2 3 4 5]"},
	{"%v", &array, "&[1 2 3 4 5]"},
	{"%v", &iarray, "&[1 hello 2.5 <nil>]"},
	{"%v", &barray, "&[1 2 3 4 5]"},

	// slices
	{"%v", slice, "[1 2 3 4 5]"},
	{"%v", islice, "[1 hello 2.5 <nil>]"},
	{"%v", bslice, "[1 2 3 4 5]"},
	{"%v", &slice, "&[1 2 3 4 5]"},
	{"%v", &islice, "&[1 hello 2.5 <nil>]"},
	{"%v", &bslice, "&[1 2 3 4 5]"},

	// byte arrays and slices with %b,%c,%d,%o,%U and %v
	{"%b", [3]byte{65, 66, 67}, "[1000001 1000010 1000011]"},
	{"%c", [3]byte{65, 66, 67}, "[A B C]"},
	{"%d", [3]byte{65, 66, 67}, "[65 66 67]"},
	{"%o", [3]byte{65, 66, 67}, "[101 102 103]"},
	{"%U", [3]byte{65, 66, 67}, "[U+0041 U+0042 U+0043]"},
	{"%v", [3]byte{65, 66, 67}, "[65 66 67]"},
	{"%v", [1]byte{123}, "[123]"},
	{"%012v", []byte{}, "[]"},
	{"%#012v", []byte{}, "[]byte{}"},
	{"%6v", []byte{1, 11, 111}, "[     1     11    111]"},
	{"%06v", []byte{1, 11, 111}, "[000001 000011 000111]"},
	{"%-6v", []byte{1, 11, 111}, "[1      11     111   ]"},
	{"%-06v", []byte{1, 11, 111}, "[1      11     111   ]"},
	{"%#v", []byte{1, 11, 111}, "[]byte{0x1, 0xb, 0x6f}"},
	{"%#6v", []byte{1, 11, 111}, "[]byte{   0x1,    0xb,   0x6f}"},
	{"%#06v", []byte{1, 11, 111}, "[]byte{0x000001, 0x00000b, 0x00006f}"},
	{"%#-6v", []byte{1, 11, 111}, "[]byte{0x1   , 0xb   , 0x6f  }"},
	{"%#-06v", []byte{1, 11, 111}, "[]byte{0x1   , 0xb   , 0x6f  }"},
	// f.space should and f.plus should not have an effect with %v.
	{"% v", []byte{1, 11, 111}, "[ 1  11  111]"},
	{"%+v", [3]byte{1, 11, 111}, "[1 11 111]"},
	{"%# -6v", []byte{1, 11, 111}, "[]byte{ 0x1  ,  0xb  ,  0x6f }"},
	{"%#+-6v", [3]byte{1, 11, 111}, "[3]uint8{0x1   , 0xb   , 0x6f  }"},
	// f.space and f.plus should have an effect with %d.
	{"% d", []byte{1, 11, 111}, "[ 1  11  111]"},
	{"%+d", [3]byte{1, 11, 111}, "[+1 +11 +111]"},
	{"%# -6d", []byte{1, 11, 111}, "[ 1      11     111  ]"},
	{"%#+-6d", [3]byte{1, 11, 111}, "[+1     +11    +111  ]"},

	// floates with %v
	{"%v", 1.2345678, "1.2345678"},
	{"%v", float32(1.2345678), "1.2345678"},

	// complexes with %v
	{"%v", 1 + 2i, "(1+2i)"},
	{"%v", complex64(1 + 2i), "(1+2i)"},

	// structs
	{"%v", A{1, 2, "a", []int{1, 2}}, `{1 2 a [1 2]}`},
	{"%+v", A{1, 2, "a", []int{1, 2}}, `{i:1 j:2 s:a x:[1 2]}`},

	// +v on structs with Stringable items
	{"%+v", B{1, 2}, `{I:<1> j:2}`},
	{"%+v", C{1, B{2, 3}}, `{i:1 B:{I:<2> j:3}}`},

	// other formats on Stringable items
	{"%s", I(23), `<23>`},
	{"%q", I(23), `"<23>"`},
	{"%x", I(23), `3c32333e`},
	{"%#x", I(23), `0x3c32333e`},
	{"%# x", I(23), `0x3c 0x32 0x33 0x3e`},
	// Stringer applies only to string formats.
	{"%d", I(23), `23`},
	// Stringer applies to the extracted value.
	{"%s", reflect.ValueOf(I(23)), `<23>`},

	// go syntax
	{"%#v", A{1, 2, "a", []int{1, 2}}, `fmt_test.A{i:1, j:0x2, s:"a", x:[]int{1, 2}}`},
	{"%#v", new(byte), "(*uint8)(0xPTR)"},
	{"%#v", make(chan int), "(chan int)(0xPTR)"},
	{"%#v", uint64(1<<64 - 1), "0xffffffffffffffff"},
	{"%#v", 1000000000, "1000000000"},
	{"%#v", map[string]int{"a": 1}, `map[string]int{"a":1}`},
	{"%#v", map[string]B{"a": {1, 2}}, `map[string]fmt_test.B{"a":fmt_test.B{I:1, j:2}}`},
	{"%#v", []string{"a", "b"}, `[]string{"a", "b"}`},
	{"%#v", SI{}, `fmt_test.SI{I:interface {}(nil)}`},
	{"%#v", []int(nil), `[]int(nil)`},
	{"%#v", []int{}, `[]int{}`},
	{"%#v", array, `[5]int{1, 2, 3, 4, 5}`},
	{"%#v", &array, `&[5]int{1, 2, 3, 4, 5}`},
	{"%#v", iarray, `[4]interface {}{1, "hello", 2.5, interface {}(nil)}`},
	{"%#v", &iarray, `&[4]interface {}{1, "hello", 2.5, interface {}(nil)}`},
	{"%#v", map[int]byte(nil), `map[int]uint8(nil)`},
	{"%#v", map[int]byte{}, `map[int]uint8{}`},
	{"%#v", "foo", `"foo"`},
	{"%#v", barray, `[5]fmt_test.renamedUint8{0x1, 0x2, 0x3, 0x4, 0x5}`},
	{"%#v", bslice, `[]fmt_test.renamedUint8{0x1, 0x2, 0x3, 0x4, 0x5}`},
	{"%#v", []int32(nil), "[]int32(nil)"},
	{"%#v", 1.2345678, "1.2345678"},
	{"%#v", float32(1.2345678), "1.2345678"},

	// functions
	{"%v", TestFmtInterface, "0xPTR"}, // simple function
	{"%v", reflect.ValueOf(TestFmtInterface), "0xPTR"},
	{"%v", G.GoString, "0xPTR"}, // method expression
	{"%v", reflect.ValueOf(G.GoString), "0xPTR"},
	{"%v", G(23).GoString, "0xPTR"}, // method value
	{"%v", reflect.ValueOf(G(23).GoString), "0xPTR"},
	{"%v", reflect.ValueOf(G(23)).Method(0), "0xPTR"},
	{"%v", Fn.String, "0xPTR"}, // method of function type
	{"%v", reflect.ValueOf(Fn.String), "0xPTR"},
	{"%v", fnValue, "String(fn)"}, // variable of function type with String method
	{"%v", reflect.ValueOf(fnValue), "String(fn)"},
	{"%v", [1]Fn{fnValue}, "[String(fn)]"}, // array of function type with String method
	{"%v", reflect.ValueOf([1]Fn{fnValue}), "[String(fn)]"},
	{"%v", fnValue.String, "0xPTR"}, // method value from function type
	{"%v", reflect.ValueOf(fnValue.String), "0xPTR"},
	{"%v", reflect.ValueOf(fnValue).Method(0), "0xPTR"},
	{"%v", U{}.u, "<nil>"}, // unexported function field
	{"%v", reflect.ValueOf(U{}.u), "<nil>"},
	{"%v", reflect.ValueOf(U{}).Field(0), "<nil>"},
	{"%v", U{fn: fnValue}.fn, "String(fn)"}, // unexported field of function type with String method
	{"%v", reflect.ValueOf(U{fn: fnValue}.fn), "String(fn)"},
	{"%v", reflect.ValueOf(U{fn: fnValue}).Field(1), "<nil>"},

	// functions with go syntax
	{"%#v", TestFmtInterface, "(func(*testing.T))(0xPTR)"}, // simple function
	{"%#v", reflect.ValueOf(TestFmtInterface), "(func(*testing.T))(0xPTR)"},
	{"%#v", G.GoString, "(func(fmt_test.G) string)(0xPTR)"}, // method expression
	{"%#v", reflect.ValueOf(G.GoString), "(func(fmt_test.G) string)(0xPTR)"},
	{"%#v", G(23).GoString, "(func() string)(0xPTR)"}, // method value
	{"%#v", reflect.ValueOf(G(23).GoString), "(func() string)(0xPTR)"},
	{"%#v", reflect.ValueOf(G(23)).Method(0), "(func() string)(0xPTR)"},
	{"%#v", Fn.String, "(func(fmt_test.Fn) string)(0xPTR)"}, // method of function type
	{"%#v", reflect.ValueOf(Fn.String), "(func(fmt_test.Fn) string)(0xPTR)"},
	{"%#v", fnValue, "(fmt_test.Fn)(nil)"}, // variable of function type with String method
	{"%#v", reflect.ValueOf(fnValue), "(fmt_test.Fn)(nil)"},
	{"%#v", [1]Fn{fnValue}, "[1]fmt_test.Fn{(fmt_test.Fn)(nil)}"}, // array of function type with String method
	{"%#v", reflect.ValueOf([1]Fn{fnValue}), "[1]fmt_test.Fn{(fmt_test.Fn)(nil)}"},
	{"%#v", fnValue.String, "(func() string)(0xPTR)"}, // method value from function type
	{"%#v", reflect.ValueOf(fnValue.String), "(func() string)(0xPTR)"},
	{"%#v", reflect.ValueOf(fnValue).Method(0), "(func() string)(0xPTR)"},
	{"%#v", U{}.u, "(func() string)(nil)"}, // unexported function field
	{"%#v", reflect.ValueOf(U{}.u), "(func() string)(nil)"},
	{"%#v", reflect.ValueOf(U{}).Field(0), "(func() string)(nil)"},
	{"%#v", U{fn: fnValue}.fn, "(fmt_test.Fn)(nil)"}, // unexported field of function type with String method
	{"%#v", reflect.ValueOf(U{fn: fnValue}.fn), "(fmt_test.Fn)(nil)"},
	{"%#v", reflect.ValueOf(U{fn: fnValue}).Field(1), "(fmt_test.Fn)(nil)"},

	// Whole number floats are printed without decimals. See Issue 27634.
	{"%#v", 1.0, "1"},
	{"%#v", 1000000.0, "1e+06"},
	{"%#v", float32(1.0), "1"},
	{"%#v", float32(1000000.0), "1e+06"},

	// Only print []byte and []uint8 as type []byte if they appear at the top level.
	{"%#v", []byte(nil), "[]byte(nil)"},
	{"%#v", []uint8(nil), "[]byte(nil)"},
	{"%#v", []byte{}, "[]byte{}"},
	{"%#v", []uint8{}, "[]byte{}"},
	{"%#v", reflect.ValueOf([]byte{}), "[]uint8{}"},
	{"%#v", reflect.ValueOf([]uint8{}), "[]uint8{}"},
	{"%#v", &[]byte{}, "&[]uint8{}"},
	{"%#v", &[]byte{}, "&[]uint8{}"},
	{"%#v", [3]byte{}, "[3]uint8{0x0, 0x0, 0x0}"},
	{"%#v", [3]uint8{}, "[3]uint8{0x0, 0x0, 0x0}"},

	// slices with other formats
	{"%#x", []int{1, 2, 15}, `[0x1 0x2 0xf]`},
	{"%x", []int{1, 2, 15}, `[1 2 f]`},
	{"%d", []int{1, 2, 15}, `[1 2 15]`},
	{"%d", []byte{1, 2, 15}, `[1 2 15]`},
	{"%q", []string{"a", "b"}, `["a" "b"]`},
	{"% 02x", []byte{1}, "01"},
	{"% 02x", []byte{1, 2, 3}, "01 02 03"},

	// Padding with byte slices.
	{"%2x", []byte{}, "  "},
	{"%#2x", []byte{}, "  "},
	{"% 02x", []byte{}, "00"},
	{"%# 02x", []byte{}, "00"},
	{"%-2x", []byte{}, "  "},
	{"%-02x", []byte{}, "  "},
	{"%8x", []byte{0xab}, "      ab"},
	{"% 8x", []byte{0xab}, "      ab"},
	{"%#8x", []byte{0xab}, "    0xab"},
	{"%# 8x", []byte{0xab}, "    0xab"},
	{"%08x", []byte{0xab}, "000000ab"},
	{"% 08x", []byte{0xab}, "000000ab"},
	{"%#08x", []byte{0xab}, "00000xab"},
	{"%# 08x", []byte{0xab}, "00000xab"},
	{"%10x", []byte{0xab, 0xcd}, "      abcd"},
	{"% 10x", []byte{0xab, 0xcd}, "     ab cd"},
	{"%#10x", []byte{0xab, 0xcd}, "    0xabcd"},
	{"%# 10x", []byte{0xab, 0xcd}, " 0xab 0xcd"},
	{"%010x", []byte{0xab, 0xcd}, "000000abcd"},
	{"% 010x", []byte{0xab, 0xcd}, "00000ab cd"},
	{"%#010x", []byte{0xab, 0xcd}, "00000xabcd"},
	{"%# 010x", []byte{0xab, 0xcd}, "00xab 0xcd"},
	{"%-10X", []byte{0xab}, "AB        "},
	{"% -010X", []byte{0xab}, "AB        "},
	{"%#-10X", []byte{0xab, 0xcd}, "0XABCD    "},
	{"%# -010X", []byte{0xab, 0xcd}, "0XAB 0XCD "},
	// Same for strings
	{"%2x", "", "  "},
	{"%#2x", "", "  "},
	{"% 02x", "", "00"},
	{"%# 02x", "", "00"},
	{"%-2x", "", "  "},
	{"%-02x", "", "  "},
	{"%8x", "\xab", "      ab"},
	{"% 8x", "\xab", "      ab"},
	{"%#8x", "\xab", "    0xab"},
	{"%# 8x", "\xab", "    0xab"},
	{"%08x", "\xab", "000000ab"},
	{"% 08x", "\xab", "000000ab"},
	{"%#08x", "\xab", "00000xab"},
	{"%# 08x", "\xab", "00000xab"},
	{"%10x", "\xab\xcd", "      abcd"},
	{"% 10x", "\xab\xcd", "     ab cd"},
	{"%#10x", "\xab\xcd", "    0xabcd"},
	{"%# 10x", "\xab\xcd", " 0xab 0xcd"},
	{"%010x", "\xab\xcd", "000000abcd"},
	{"% 010x", "\xab\xcd", "00000ab cd"},
	{"%#010x", "\xab\xcd", "00000xabcd"},
	{"%# 010x", "\xab\xcd", "00xab 0xcd"},
	{"%-10X", "\xab", "AB        "},
	{"% -010X", "\xab", "AB        "},
	{"%#-10X", "\xab\xcd", "0XABCD    "},
	{"%# -010X", "\xab\xcd", "0XAB 0XCD "},

	// renamings
	{"%v", renamedBool(true), "true"},
	{"%d", renamedBool(true), "%!d(fmt_test.renamedBool=true)"},
	{"%o", renamedInt(8), "10"},
	{"%d", renamedInt8(-9), "-9"},
	{"%v", renamedInt16(10), "10"},
	{"%v", renamedInt32(-11), "-11"},
	{"%X", renamedInt64(255), "FF"},
	{"%v", renamedUint(13), "13"},
	{"%o", renamedUint8(14), "16"},
	{"%X", renamedUint16(15), "F"},
	{"%d", renamedUint32(16), "16"},
	{"%X", renamedUint64(17), "11"},
	{"%o", renamedUintptr(18), "22"},
	{"%x", renamedString("thing"), "7468696e67"},
	{"%d", renamedBytes([]byte{1, 2, 15}), `[1 2 15]`},
	{"%q", renamedBytes([]byte("hello")), `"hello"`},
	{"%x", []renamedUint8{'h', 'e', 'l', 'l', 'o'}, "68656c6c6f"},
	{"%X", []renamedUint8{'h', 'e', 'l', 'l', 'o'}, "68656C6C6F"},
	{"%s", []renamedUint8{'h', 'e', 'l', 'l', 'o'}, "hello"},
	{"%q", []renamedUint8{'h', 'e', 'l', 'l', 'o'}, `"hello"`},
	{"%v", renamedFloat32(22), "22"},
	{"%v", renamedFloat64(33), "33"},
	{"%v", renamedComplex64(3 + 4i), "(3+4i)"},
	{"%v", renamedComplex128(4 - 3i), "(4-3i)"},

	// Formatter
	{"%x", F(1), "<x=F(1)>"},
	{"%x", G(2), "2"},
	{"%+v", S{F(4), G(5)}, "{F:<v=F(4)> G:5}"},

	// GoStringer
	{"%#v", G(6), "GoString(6)"},
	{"%#v", S{F(7), G(8)}, "fmt_test.S{F:<v=F(7)>, G:GoString(8)}"},

	// %T
	{"%T", byte(0), "uint8"},
	{"%T", reflect.ValueOf(nil), "reflect.Value"},
	{"%T", (4 - 3i), "complex128"},
	{"%T", renamedComplex128(4 - 3i), "fmt_test.renamedComplex128"},
	{"%T", intVar, "int"},
	{"%6T", &intVar, "  *int"},
	{"%10T", nil, "     <nil>"},
	{"%-10T", nil, "<nil>     "},

	// %p with pointers
	{"%p", (*int)(nil), "0x0"},
	{"%#p", (*int)(nil), "0"},
	{"%p", &intVar, "0xPTR"},
	{"%#p", &intVar, "PTR"},
	{"%p", &array, "0xPTR"},
	{"%p", &slice, "0xPTR"},
	{"%8.2p", (*int)(nil), "    0x00"},
	{"%-20.16p", &intVar, "0xPTR  "},
	// %p on non-pointers
	{"%p", make(chan int), "0xPTR"},
	{"%p", make(map[int]int), "0xPTR"},
	{"%p", func() {}, "0xPTR"},
	{"%p", 27, "%!p(int=27)"},  // not a pointer at all
	{"%p", nil, "%!p(<nil>)"},  // nil on its own has no type ...
	{"%#p", nil, "%!p(<nil>)"}, // ... and hence is not a pointer type.
	// pointers with specified base
	{"%b", &intVar, "PTR_b"},
	{"%d", &intVar, "PTR_d"},
	{"%o", &intVar, "PTR_o"},
	{"%x", &intVar, "PTR_x"},
	{"%X", &intVar, "PTR_X"},
	// %v on pointers
	{"%v", nil, "<nil>"},
	{"%#v", nil, "<nil>"},
	{"%v", (*int)(nil), "<nil>"},
	{"%#v", (*int)(nil), "(*int)(nil)"},
	{"%v", &intVar, "0xPTR"},
	{"%#v", &intVar, "(*int)(0xPTR)"},
	{"%8.2v", (*int)(nil), "   <nil>"},
	{"%-20.16v", &intVar, "0xPTR  "},
	// string method on pointer
	{"%s", &pValue, "String(p)"}, // String method...
	{"%p", &pValue, "0xPTR"},     // ... is not called with %p.

	// %d on Stringer should give integer if possible
	{"%s", time.Time{}.M
"""




```