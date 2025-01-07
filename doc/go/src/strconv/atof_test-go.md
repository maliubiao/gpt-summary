Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of `atof_test.go`, its purpose in the broader context of Go, code examples, potential pitfalls, and answers in Chinese.

2. **Initial Scan and High-Level Understanding:** Quickly read through the code, paying attention to imports, type definitions, and global variables. Keywords like `test`, `atof`, `ParseFloat`, `FormatFloat`, `float64`, `float32`, `ErrSyntax`, and `ErrRange` stand out. This immediately suggests the code is about testing the conversion of strings to floating-point numbers.

3. **Identify the Core Functionality:** The `atofTest` struct and the `atoftests` and `atof32tests` variables are central. These clearly represent test cases for string-to-float conversions. Each test case includes an input string (`in`), the expected output string representation (`out`), and the expected error (`err`). This pattern strongly indicates unit testing.

4. **Infer the Tested Go Feature:** Based on the test cases, the code is testing functions that parse strings into `float64` and `float32` values. The naming convention (`ParseFloat`) and the presence of test cases for different formats (decimal, exponential, hexadecimal) confirm this. The `strconv` package import further solidifies this inference.

5. **Construct Code Examples:** Now, create illustrative Go code that uses the inferred functionality. Focus on the `strconv.ParseFloat` function. Include examples for successful parsing and error scenarios. Crucially, demonstrate both `float64` and `float32` conversions.

6. **Reason about Code Details and Edge Cases:**
    * **Test Case Variety:**  Notice the extensive list of test cases in `atoftests` and `atof32tests`. These cover a wide range of inputs: valid numbers, invalid formats, edge cases like zero, infinity, NaN, very large/small numbers, denormalized numbers, hexadecimal floating-point numbers, and numbers with underscores. This indicates a thorough test suite.
    * **Error Handling:** The presence of `ErrSyntax` and `ErrRange` suggests the `ParseFloat` function returns specific error types. The test cases explicitly check for these errors.
    * **Rounding Behavior:** Some test cases, especially those near the limits of floating-point representation, are designed to verify correct rounding behavior. The comments in the code ("rounded down", "rounded up") are helpful here.
    * **Hexadecimal Floating-Point:** The inclusion of "0x" prefixed test cases signifies support for parsing hexadecimal floating-point numbers.
    * **Special Values:** The tests for "nan", "inf", "-Inf" demonstrate the handling of these special floating-point values.
    * **Underscores:** The tests with underscores indicate that `ParseFloat` (or the underlying implementation being tested) allows underscores as separators in numbers.
    * **`ParseFloatPrefix`:** The `TestParseFloatPrefix` function suggests an additional function that parses the prefix of a string that represents a floating-point number.
    * **Random Testing:** The `atofRandomTests` and benchmark functions point to the use of random input generation for more extensive testing and performance analysis.

7. **Address Specific Requirements:**
    * **Functionality Listing:** Summarize the identified functionalities in clear, concise bullet points.
    * **Go Feature and Code Example:** Provide the `strconv.ParseFloat` explanation and the Go code examples.
    * **Input/Output Reasoning:**  For the code examples, explicitly state the input and expected output.
    * **Command-Line Arguments:** The code doesn't directly handle command-line arguments. State this clearly.
    * **Common Mistakes:**  Think about how developers might misuse `ParseFloat`. The most likely mistake is ignoring the returned error. Another potential issue is assuming a specific level of precision without considering the `bitSize` parameter. The issue with incorrect `bitSize` (like 0 or 10) is specifically addressed in a test case, making it a good example of a potential pitfall.
    * **Chinese Answers:** Ensure all responses are in Chinese.

8. **Refine and Organize:** Review the generated answer for clarity, accuracy, and completeness. Ensure the language is natural and easy to understand. Organize the information logically, following the structure of the original request. For instance, group the functionality descriptions together, the code examples together, etc.

9. **Self-Correction/Refinement during the process:**
    * Initially, I might just focus on the basic conversion functionality. Then, realizing the depth of the test cases, I'd expand to include handling of special values, hexadecimal numbers, and rounding.
    * I might initially forget to mention the `ParseFloatPrefix` function and add it upon closer inspection.
    * Recognizing the benchmarks, I'd include a point about performance testing.
    * I'd double-check the Chinese phrasing to ensure it's accurate and natural.

By following these steps, combining code analysis with understanding the context of unit testing, and addressing the specific requirements of the prompt, we can generate a comprehensive and accurate answer like the example provided.
这段代码是 Go 语言标准库 `strconv` 包中 `atof_test.go` 文件的一部分。它的主要功能是**测试 `strconv` 包中的字符串到浮点数转换功能**，特别是 `ParseFloat` 函数。

更具体地说，它做了以下几件事情：

1. **定义测试用例结构体 `atofTest`**:  这个结构体用于存储单个测试用例的信息，包括：
   - `in`: 输入的字符串。
   - `out`: 期望的 `ParseFloat` 函数转换后的字符串表示形式。
   - `err`: 期望的错误类型（例如 `nil` 表示没有错误, `ErrSyntax` 表示语法错误, `ErrRange` 表示超出范围）。

2. **定义测试用例切片 `atoftests` 和 `atof32tests`**:  这两个切片分别包含了大量的 `atofTest` 结构体实例，用于测试 `ParseFloat` 函数在不同输入情况下的行为。
   - `atoftests` 主要测试将字符串解析为 `float64` 类型。
   - `atof32tests` 主要测试将字符串解析为 `float32` 类型。

3. **覆盖各种输入情况**: 这些测试用例覆盖了各种可能的浮点数字符串表示形式，包括：
   - 正数、负数
   - 整数、小数
   - 科学计数法表示 (例如 "1e23", "1e-100")
   - 十六进制浮点数表示 (例如 "0x1p0", "0x1.fp4")
   - 特殊值 (例如 "nan", "inf", "-Inf")
   - 最大和最小的 `float64` 和 `float32` 值
   - 接近零的极小值 (denormalized numbers)
   - 各种错误输入 (例如 "1x", "1.1.")
   - 带有下划线的数字分隔符 (例如 "1_23.50_0_0e+1_2")

4. **定义辅助测试函数**:
   - `TestParseFloatPrefix`: 测试 `ParseFloatPrefix` 函数，该函数用于解析字符串中浮点数的前缀部分。
   - `testAtof`:  核心测试函数，遍历 `atoftests` 和 `atof32tests` 中的用例，调用 `ParseFloat` 进行转换，并将实际结果与预期结果进行比较。它还会检查将 `float64` 转换为 `float32` 是否会丢失精度。
   - `TestAtof`, `TestAtofSlow`:  调用 `testAtof` 函数，`TestAtof` 使用优化过的快速路径，`TestAtofSlow` 禁用优化。
   - `TestAtofRandom`: 使用随机生成的浮点数及其字符串表示形式进行测试，增加测试的覆盖面。
   - `TestRoundTrip`: 测试 `FormatFloat` 和 `ParseFloat` 的往返转换，确保转换后再解析能得到原始值。
   - `TestRoundTrip32`: 类似于 `TestRoundTrip`，但针对 `float32` 类型。
   - `TestParseFloatIncorrectBitSize`: 测试当 `ParseFloat` 的 `bitSize` 参数传入非 32 或 64 时，函数的行为是否符合预期。

5. **定义性能基准测试函数 (Benchmarks)**:
   - `BenchmarkAtof64Decimal`, `BenchmarkAtof64Float`, `BenchmarkAtof64FloatExp`, `BenchmarkAtof64Big`, `BenchmarkAtof64RandomBits`, `BenchmarkAtof64RandomFloats`, `BenchmarkAtof64RandomLongFloats`, `BenchmarkAtof32Decimal`, `BenchmarkAtof32Float`, `BenchmarkAtof32FloatExp`, `BenchmarkAtof32Random`, `BenchmarkAtof32RandomLong`:  这些函数用于衡量 `ParseFloat` 函数在不同输入情况下的性能。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码主要测试的是 `strconv` 包中的 `ParseFloat` 函数，该函数的功能是将字符串解析为 `float64` 或 `float32` 类型的浮点数。

**Go 代码举例说明 `strconv.ParseFloat` 的使用：**

```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	// 解析字符串为 float64
	float64Value, err := strconv.ParseFloat("3.14159", 64)
	if err != nil {
		fmt.Println("解析 float64 错误:", err)
	} else {
		fmt.Printf("解析得到的 float64 值: %f\n", float64Value) // 输出: 3.141590
	}

	// 解析字符串为 float32
	float32Value, err := strconv.ParseFloat("1.23e-5", 32)
	if err != nil {
		fmt.Println("解析 float32 错误:", err)
	} else {
		fmt.Printf("解析得到的 float32 值: %f\n", float32Value) // 输出: 0.000012
	}

	// 解析失败的情况
	_, err = strconv.ParseFloat("invalid", 64)
	if err != nil {
		fmt.Println("解析错误:", err) // 输出: 解析错误: strconv.ParseFloat: parsing "invalid": invalid syntax
	}

	// 解析超出范围的情况
	_, err = strconv.ParseFloat("1e1000", 64)
	if err != nil {
		fmt.Println("解析错误:", err) // 输出: 解析错误: strconv.ParseFloat: parsing "1e1000": value out of range
	}
}
```

**代码推理，带上假设的输入与输出：**

假设我们有以下测试用例：

```go
test := atofTest{in: "123.45", out: "123.45", err: nil}
```

当 `testAtof` 函数使用这个用例进行测试时，会调用 `strconv.ParseFloat(test.in, 64)`。

**假设输入:** `test.in` 为字符串 `"123.45"`

**预期输出:**
- `ParseFloat` 返回的 `float64` 值应该近似等于 `123.45`。
- `FormatFloat` 将该 `float64` 值格式化后的字符串应该等于 `test.out`，即 `"123.45"`。
- 返回的 `error` 应该等于 `test.err`，即 `nil`。

如果输入是错误的，例如：

```go
test := atofTest{in: "abc", out: "0", err: ErrSyntax}
```

**假设输入:** `test.in` 为字符串 `"abc"`

**预期输出:**
- `ParseFloat` 会返回一个默认的 `float64` 值（通常是 0）。
- 返回的 `error` 应该与 `test.err` 相等，即 `strconv.ErrSyntax`。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它是单元测试代码，通常通过 `go test` 命令来运行。`go test` 命令会查找当前目录及其子目录中以 `_test.go` 结尾的文件，并运行其中的测试函数。

你可以使用 `go test` 的一些参数来控制测试的执行，例如：

- `-v`: 显示更详细的测试输出。
- `-run <正则表达式>`:  只运行匹配正则表达式的测试函数。
- `-bench <正则表达式>`: 只运行匹配正则表达式的基准测试函数。
- `-short`: 运行时间较短的测试，跳过一些耗时的测试（例如这段代码中会跳过一些大量的随机测试）。

例如，要运行 `atof_test.go` 中的所有测试，你可以在终端中进入 `go/src/strconv/` 目录并执行：

```bash
go test -v
```

要只运行名称包含 "Atof" 的测试函数，可以执行：

```bash
go test -v -run Atof
```

要运行基准测试函数，可以执行：

```bash
go test -bench .
```

**使用者易犯错的点：**

1. **忽略错误返回值:** `ParseFloat` 函数会返回一个 `error` 类型的值。如果解析失败，`error` 不为 `nil`。使用者容易忘记检查这个错误，导致程序在遇到非法输入时出现未预期的行为。

   ```go
   // 错误的做法：没有检查错误
   f, _ := strconv.ParseFloat(inputString, 64)
   fmt.Println(f) // 如果 inputString 是 "abc"，f 的值是 0，但没有提示错误

   // 正确的做法：检查错误
   f, err := strconv.ParseFloat(inputString, 64)
   if err != nil {
       fmt.Println("解析错误:", err)
   } else {
       fmt.Println(f)
   }
   ```

2. **`bitSize` 参数的误解:** `bitSize` 参数指定了期望的浮点数精度 (32 代表 `float32`, 64 代表 `float64`)。如果传入其他值，虽然在 Go 1.16 之后会尝试解析，但仍然可能导致精度损失或不符合预期的行为。在旧版本 Go 中，传入非 32 或 64 的值可能会导致 panic。

   ```go
   // 容易出错：错误地使用 bitSize
   f, err := strconv.ParseFloat("3.14159", 0) // 0 会被解释为 64，但容易引起误解
   fmt.Println(f, err)

   // 推荐做法：明确指定 32 或 64
   f64, err := strconv.ParseFloat("3.14159", 64)
   fmt.Println(f64, err)

   f32, err := strconv.ParseFloat("3.14159", 32)
   fmt.Println(f32, err) // 注意 float32 可能损失精度
   ```

这段测试代码通过大量的测试用例，确保了 `strconv.ParseFloat` 函数在各种输入情况下都能正确地工作，并且提供了性能基准测试来衡量其效率。这对于保证 Go 语言标准库的质量至关重要。

Prompt: 
```
这是路径为go/src/strconv/atof_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package strconv_test

import (
	"math"
	"math/rand"
	"reflect"
	. "strconv"
	"strings"
	"sync"
	"testing"
)

type atofTest struct {
	in  string
	out string
	err error
}

var atoftests = []atofTest{
	{"", "0", ErrSyntax},
	{"1", "1", nil},
	{"+1", "1", nil},
	{"1x", "0", ErrSyntax},
	{"1.1.", "0", ErrSyntax},
	{"1e23", "1e+23", nil},
	{"1E23", "1e+23", nil},
	{"100000000000000000000000", "1e+23", nil},
	{"1e-100", "1e-100", nil},
	{"123456700", "1.234567e+08", nil},
	{"99999999999999974834176", "9.999999999999997e+22", nil},
	{"100000000000000000000001", "1.0000000000000001e+23", nil},
	{"100000000000000008388608", "1.0000000000000001e+23", nil},
	{"100000000000000016777215", "1.0000000000000001e+23", nil},
	{"100000000000000016777216", "1.0000000000000003e+23", nil},
	{"-1", "-1", nil},
	{"-0.1", "-0.1", nil},
	{"-0", "-0", nil},
	{"1e-20", "1e-20", nil},
	{"625e-3", "0.625", nil},

	// Hexadecimal floating-point.
	{"0x1p0", "1", nil},
	{"0x1p1", "2", nil},
	{"0x1p-1", "0.5", nil},
	{"0x1ep-1", "15", nil},
	{"-0x1ep-1", "-15", nil},
	{"-0x1_ep-1", "-15", nil},
	{"0x1p-200", "6.223015277861142e-61", nil},
	{"0x1p200", "1.6069380442589903e+60", nil},
	{"0x1fFe2.p0", "131042", nil},
	{"0x1fFe2.P0", "131042", nil},
	{"-0x2p3", "-16", nil},
	{"0x0.fp4", "15", nil},
	{"0x0.fp0", "0.9375", nil},
	{"0x1e2", "0", ErrSyntax},
	{"1p2", "0", ErrSyntax},

	// zeros
	{"0", "0", nil},
	{"0e0", "0", nil},
	{"-0e0", "-0", nil},
	{"+0e0", "0", nil},
	{"0e-0", "0", nil},
	{"-0e-0", "-0", nil},
	{"+0e-0", "0", nil},
	{"0e+0", "0", nil},
	{"-0e+0", "-0", nil},
	{"+0e+0", "0", nil},
	{"0e+01234567890123456789", "0", nil},
	{"0.00e-01234567890123456789", "0", nil},
	{"-0e+01234567890123456789", "-0", nil},
	{"-0.00e-01234567890123456789", "-0", nil},
	{"0x0p+01234567890123456789", "0", nil},
	{"0x0.00p-01234567890123456789", "0", nil},
	{"-0x0p+01234567890123456789", "-0", nil},
	{"-0x0.00p-01234567890123456789", "-0", nil},

	{"0e291", "0", nil}, // issue 15364
	{"0e292", "0", nil}, // issue 15364
	{"0e347", "0", nil}, // issue 15364
	{"0e348", "0", nil}, // issue 15364
	{"-0e291", "-0", nil},
	{"-0e292", "-0", nil},
	{"-0e347", "-0", nil},
	{"-0e348", "-0", nil},
	{"0x0p126", "0", nil},
	{"0x0p127", "0", nil},
	{"0x0p128", "0", nil},
	{"0x0p129", "0", nil},
	{"0x0p130", "0", nil},
	{"0x0p1022", "0", nil},
	{"0x0p1023", "0", nil},
	{"0x0p1024", "0", nil},
	{"0x0p1025", "0", nil},
	{"0x0p1026", "0", nil},
	{"-0x0p126", "-0", nil},
	{"-0x0p127", "-0", nil},
	{"-0x0p128", "-0", nil},
	{"-0x0p129", "-0", nil},
	{"-0x0p130", "-0", nil},
	{"-0x0p1022", "-0", nil},
	{"-0x0p1023", "-0", nil},
	{"-0x0p1024", "-0", nil},
	{"-0x0p1025", "-0", nil},
	{"-0x0p1026", "-0", nil},

	// NaNs
	{"nan", "NaN", nil},
	{"NaN", "NaN", nil},
	{"NAN", "NaN", nil},

	// Infs
	{"inf", "+Inf", nil},
	{"-Inf", "-Inf", nil},
	{"+INF", "+Inf", nil},
	{"-Infinity", "-Inf", nil},
	{"+INFINITY", "+Inf", nil},
	{"Infinity", "+Inf", nil},

	// largest float64
	{"1.7976931348623157e308", "1.7976931348623157e+308", nil},
	{"-1.7976931348623157e308", "-1.7976931348623157e+308", nil},
	{"0x1.fffffffffffffp1023", "1.7976931348623157e+308", nil},
	{"-0x1.fffffffffffffp1023", "-1.7976931348623157e+308", nil},
	{"0x1fffffffffffffp+971", "1.7976931348623157e+308", nil},
	{"-0x1fffffffffffffp+971", "-1.7976931348623157e+308", nil},
	{"0x.1fffffffffffffp1027", "1.7976931348623157e+308", nil},
	{"-0x.1fffffffffffffp1027", "-1.7976931348623157e+308", nil},

	// next float64 - too large
	{"1.7976931348623159e308", "+Inf", ErrRange},
	{"-1.7976931348623159e308", "-Inf", ErrRange},
	{"0x1p1024", "+Inf", ErrRange},
	{"-0x1p1024", "-Inf", ErrRange},
	{"0x2p1023", "+Inf", ErrRange},
	{"-0x2p1023", "-Inf", ErrRange},
	{"0x.1p1028", "+Inf", ErrRange},
	{"-0x.1p1028", "-Inf", ErrRange},
	{"0x.2p1027", "+Inf", ErrRange},
	{"-0x.2p1027", "-Inf", ErrRange},

	// the border is ...158079
	// borderline - okay
	{"1.7976931348623158e308", "1.7976931348623157e+308", nil},
	{"-1.7976931348623158e308", "-1.7976931348623157e+308", nil},
	{"0x1.fffffffffffff7fffp1023", "1.7976931348623157e+308", nil},
	{"-0x1.fffffffffffff7fffp1023", "-1.7976931348623157e+308", nil},
	// borderline - too large
	{"1.797693134862315808e308", "+Inf", ErrRange},
	{"-1.797693134862315808e308", "-Inf", ErrRange},
	{"0x1.fffffffffffff8p1023", "+Inf", ErrRange},
	{"-0x1.fffffffffffff8p1023", "-Inf", ErrRange},
	{"0x1fffffffffffff.8p+971", "+Inf", ErrRange},
	{"-0x1fffffffffffff8p+967", "-Inf", ErrRange},
	{"0x.1fffffffffffff8p1027", "+Inf", ErrRange},
	{"-0x.1fffffffffffff9p1027", "-Inf", ErrRange},

	// a little too large
	{"1e308", "1e+308", nil},
	{"2e308", "+Inf", ErrRange},
	{"1e309", "+Inf", ErrRange},
	{"0x1p1025", "+Inf", ErrRange},

	// way too large
	{"1e310", "+Inf", ErrRange},
	{"-1e310", "-Inf", ErrRange},
	{"1e400", "+Inf", ErrRange},
	{"-1e400", "-Inf", ErrRange},
	{"1e400000", "+Inf", ErrRange},
	{"-1e400000", "-Inf", ErrRange},
	{"0x1p1030", "+Inf", ErrRange},
	{"0x1p2000", "+Inf", ErrRange},
	{"0x1p2000000000", "+Inf", ErrRange},
	{"-0x1p1030", "-Inf", ErrRange},
	{"-0x1p2000", "-Inf", ErrRange},
	{"-0x1p2000000000", "-Inf", ErrRange},

	// denormalized
	{"1e-305", "1e-305", nil},
	{"1e-306", "1e-306", nil},
	{"1e-307", "1e-307", nil},
	{"1e-308", "1e-308", nil},
	{"1e-309", "1e-309", nil},
	{"1e-310", "1e-310", nil},
	{"1e-322", "1e-322", nil},
	// smallest denormal
	{"5e-324", "5e-324", nil},
	{"4e-324", "5e-324", nil},
	{"3e-324", "5e-324", nil},
	// too small
	{"2e-324", "0", nil},
	// way too small
	{"1e-350", "0", nil},
	{"1e-400000", "0", nil},

	// Near denormals and denormals.
	{"0x2.00000000000000p-1010", "1.8227805048890994e-304", nil}, // 0x00e0000000000000
	{"0x1.fffffffffffff0p-1010", "1.8227805048890992e-304", nil}, // 0x00dfffffffffffff
	{"0x1.fffffffffffff7p-1010", "1.8227805048890992e-304", nil}, // rounded down
	{"0x1.fffffffffffff8p-1010", "1.8227805048890994e-304", nil}, // rounded up
	{"0x1.fffffffffffff9p-1010", "1.8227805048890994e-304", nil}, // rounded up

	{"0x2.00000000000000p-1022", "4.450147717014403e-308", nil},  // 0x0020000000000000
	{"0x1.fffffffffffff0p-1022", "4.4501477170144023e-308", nil}, // 0x001fffffffffffff
	{"0x1.fffffffffffff7p-1022", "4.4501477170144023e-308", nil}, // rounded down
	{"0x1.fffffffffffff8p-1022", "4.450147717014403e-308", nil},  // rounded up
	{"0x1.fffffffffffff9p-1022", "4.450147717014403e-308", nil},  // rounded up

	{"0x1.00000000000000p-1022", "2.2250738585072014e-308", nil}, // 0x0010000000000000
	{"0x0.fffffffffffff0p-1022", "2.225073858507201e-308", nil},  // 0x000fffffffffffff
	{"0x0.ffffffffffffe0p-1022", "2.2250738585072004e-308", nil}, // 0x000ffffffffffffe
	{"0x0.ffffffffffffe7p-1022", "2.2250738585072004e-308", nil}, // rounded down
	{"0x1.ffffffffffffe8p-1023", "2.225073858507201e-308", nil},  // rounded up
	{"0x1.ffffffffffffe9p-1023", "2.225073858507201e-308", nil},  // rounded up

	{"0x0.00000003fffff0p-1022", "2.072261e-317", nil},  // 0x00000000003fffff
	{"0x0.00000003456780p-1022", "1.694649e-317", nil},  // 0x0000000000345678
	{"0x0.00000003456787p-1022", "1.694649e-317", nil},  // rounded down
	{"0x0.00000003456788p-1022", "1.694649e-317", nil},  // rounded down (half to even)
	{"0x0.00000003456790p-1022", "1.6946496e-317", nil}, // 0x0000000000345679
	{"0x0.00000003456789p-1022", "1.6946496e-317", nil}, // rounded up

	{"0x0.0000000345678800000000000000000000000001p-1022", "1.6946496e-317", nil}, // rounded up

	{"0x0.000000000000f0p-1022", "7.4e-323", nil}, // 0x000000000000000f
	{"0x0.00000000000060p-1022", "3e-323", nil},   // 0x0000000000000006
	{"0x0.00000000000058p-1022", "3e-323", nil},   // rounded up
	{"0x0.00000000000057p-1022", "2.5e-323", nil}, // rounded down
	{"0x0.00000000000050p-1022", "2.5e-323", nil}, // 0x0000000000000005

	{"0x0.00000000000010p-1022", "5e-324", nil},  // 0x0000000000000001
	{"0x0.000000000000081p-1022", "5e-324", nil}, // rounded up
	{"0x0.00000000000008p-1022", "0", nil},       // rounded down
	{"0x0.00000000000007fp-1022", "0", nil},      // rounded down

	// try to overflow exponent
	{"1e-4294967296", "0", nil},
	{"1e+4294967296", "+Inf", ErrRange},
	{"1e-18446744073709551616", "0", nil},
	{"1e+18446744073709551616", "+Inf", ErrRange},
	{"0x1p-4294967296", "0", nil},
	{"0x1p+4294967296", "+Inf", ErrRange},
	{"0x1p-18446744073709551616", "0", nil},
	{"0x1p+18446744073709551616", "+Inf", ErrRange},

	// Parse errors
	{"1e", "0", ErrSyntax},
	{"1e-", "0", ErrSyntax},
	{".e-1", "0", ErrSyntax},
	{"1\x00.2", "0", ErrSyntax},
	{"0x", "0", ErrSyntax},
	{"0x.", "0", ErrSyntax},
	{"0x1", "0", ErrSyntax},
	{"0x.1", "0", ErrSyntax},
	{"0x1p", "0", ErrSyntax},
	{"0x.1p", "0", ErrSyntax},
	{"0x1p+", "0", ErrSyntax},
	{"0x.1p+", "0", ErrSyntax},
	{"0x1p-", "0", ErrSyntax},
	{"0x.1p-", "0", ErrSyntax},
	{"0x1p+2", "4", nil},
	{"0x.1p+2", "0.25", nil},
	{"0x1p-2", "0.25", nil},
	{"0x.1p-2", "0.015625", nil},

	// https://www.exploringbinary.com/java-hangs-when-converting-2-2250738585072012e-308/
	{"2.2250738585072012e-308", "2.2250738585072014e-308", nil},
	// https://www.exploringbinary.com/php-hangs-on-numeric-value-2-2250738585072011e-308/
	{"2.2250738585072011e-308", "2.225073858507201e-308", nil},

	// A very large number (initially wrongly parsed by the fast algorithm).
	{"4.630813248087435e+307", "4.630813248087435e+307", nil},

	// A different kind of very large number.
	{"22.222222222222222", "22.22222222222222", nil},
	{"2." + strings.Repeat("2", 4000) + "e+1", "22.22222222222222", nil},
	{"0x1.1111111111111p222", "7.18931911124017e+66", nil},
	{"0x2.2222222222222p221", "7.18931911124017e+66", nil},
	{"0x2." + strings.Repeat("2", 4000) + "p221", "7.18931911124017e+66", nil},

	// Exactly halfway between 1 and math.Nextafter(1, 2).
	// Round to even (down).
	{"1.00000000000000011102230246251565404236316680908203125", "1", nil},
	{"0x1.00000000000008p0", "1", nil},
	// Slightly lower; still round down.
	{"1.00000000000000011102230246251565404236316680908203124", "1", nil},
	{"0x1.00000000000007Fp0", "1", nil},
	// Slightly higher; round up.
	{"1.00000000000000011102230246251565404236316680908203126", "1.0000000000000002", nil},
	{"0x1.000000000000081p0", "1.0000000000000002", nil},
	{"0x1.00000000000009p0", "1.0000000000000002", nil},
	// Slightly higher, but you have to read all the way to the end.
	{"1.00000000000000011102230246251565404236316680908203125" + strings.Repeat("0", 10000) + "1", "1.0000000000000002", nil},
	{"0x1.00000000000008" + strings.Repeat("0", 10000) + "1p0", "1.0000000000000002", nil},

	// Halfway between x := math.Nextafter(1, 2) and math.Nextafter(x, 2)
	// Round to even (up).
	{"1.00000000000000033306690738754696212708950042724609375", "1.0000000000000004", nil},
	{"0x1.00000000000018p0", "1.0000000000000004", nil},

	// Halfway between 1090544144181609278303144771584 and 1090544144181609419040633126912
	// (15497564393479157p+46, should round to even 15497564393479156p+46, issue 36657)
	{"1090544144181609348671888949248", "1.0905441441816093e+30", nil},
	// slightly above, rounds up
	{"1090544144181609348835077142190", "1.0905441441816094e+30", nil},

	// Underscores.
	{"1_23.50_0_0e+1_2", "1.235e+14", nil},
	{"-_123.5e+12", "0", ErrSyntax},
	{"+_123.5e+12", "0", ErrSyntax},
	{"_123.5e+12", "0", ErrSyntax},
	{"1__23.5e+12", "0", ErrSyntax},
	{"123_.5e+12", "0", ErrSyntax},
	{"123._5e+12", "0", ErrSyntax},
	{"123.5_e+12", "0", ErrSyntax},
	{"123.5__0e+12", "0", ErrSyntax},
	{"123.5e_+12", "0", ErrSyntax},
	{"123.5e+_12", "0", ErrSyntax},
	{"123.5e_-12", "0", ErrSyntax},
	{"123.5e-_12", "0", ErrSyntax},
	{"123.5e+1__2", "0", ErrSyntax},
	{"123.5e+12_", "0", ErrSyntax},

	{"0x_1_2.3_4_5p+1_2", "74565", nil},
	{"-_0x12.345p+12", "0", ErrSyntax},
	{"+_0x12.345p+12", "0", ErrSyntax},
	{"_0x12.345p+12", "0", ErrSyntax},
	{"0x__12.345p+12", "0", ErrSyntax},
	{"0x1__2.345p+12", "0", ErrSyntax},
	{"0x12_.345p+12", "0", ErrSyntax},
	{"0x12._345p+12", "0", ErrSyntax},
	{"0x12.3__45p+12", "0", ErrSyntax},
	{"0x12.345_p+12", "0", ErrSyntax},
	{"0x12.345p_+12", "0", ErrSyntax},
	{"0x12.345p+_12", "0", ErrSyntax},
	{"0x12.345p_-12", "0", ErrSyntax},
	{"0x12.345p-_12", "0", ErrSyntax},
	{"0x12.345p+1__2", "0", ErrSyntax},
	{"0x12.345p+12_", "0", ErrSyntax},

	{"1e100x", "0", ErrSyntax},
	{"1e1000x", "0", ErrSyntax},
}

var atof32tests = []atofTest{
	// Hex
	{"0x1p-100", "7.888609e-31", nil},
	{"0x1p100", "1.2676506e+30", nil},

	// Exactly halfway between 1 and the next float32.
	// Round to even (down).
	{"1.000000059604644775390625", "1", nil},
	{"0x1.000001p0", "1", nil},
	// Slightly lower.
	{"1.000000059604644775390624", "1", nil},
	{"0x1.0000008p0", "1", nil},
	{"0x1.000000fp0", "1", nil},
	// Slightly higher.
	{"1.000000059604644775390626", "1.0000001", nil},
	{"0x1.000002p0", "1.0000001", nil},
	{"0x1.0000018p0", "1.0000001", nil},
	{"0x1.0000011p0", "1.0000001", nil},
	// Slightly higher, but you have to read all the way to the end.
	{"1.000000059604644775390625" + strings.Repeat("0", 10000) + "1", "1.0000001", nil},
	{"0x1.000001" + strings.Repeat("0", 10000) + "1p0", "1.0000001", nil},

	// largest float32: (1<<128) * (1 - 2^-24)
	{"340282346638528859811704183484516925440", "3.4028235e+38", nil},
	{"-340282346638528859811704183484516925440", "-3.4028235e+38", nil},
	{"0x.ffffffp128", "3.4028235e+38", nil},
	{"-340282346638528859811704183484516925440", "-3.4028235e+38", nil},
	{"-0x.ffffffp128", "-3.4028235e+38", nil},
	// next float32 - too large
	{"3.4028236e38", "+Inf", ErrRange},
	{"-3.4028236e38", "-Inf", ErrRange},
	{"0x1.0p128", "+Inf", ErrRange},
	{"-0x1.0p128", "-Inf", ErrRange},
	// the border is 3.40282356779...e+38
	// borderline - okay
	{"3.402823567e38", "3.4028235e+38", nil},
	{"-3.402823567e38", "-3.4028235e+38", nil},
	{"0x.ffffff7fp128", "3.4028235e+38", nil},
	{"-0x.ffffff7fp128", "-3.4028235e+38", nil},
	// borderline - too large
	{"3.4028235678e38", "+Inf", ErrRange},
	{"-3.4028235678e38", "-Inf", ErrRange},
	{"0x.ffffff8p128", "+Inf", ErrRange},
	{"-0x.ffffff8p128", "-Inf", ErrRange},

	// Denormals: less than 2^-126
	{"1e-38", "1e-38", nil},
	{"1e-39", "1e-39", nil},
	{"1e-40", "1e-40", nil},
	{"1e-41", "1e-41", nil},
	{"1e-42", "1e-42", nil},
	{"1e-43", "1e-43", nil},
	{"1e-44", "1e-44", nil},
	{"6e-45", "6e-45", nil}, // 4p-149 = 5.6e-45
	{"5e-45", "6e-45", nil},

	// Smallest denormal
	{"1e-45", "1e-45", nil}, // 1p-149 = 1.4e-45
	{"2e-45", "1e-45", nil},
	{"3e-45", "3e-45", nil},

	// Near denormals and denormals.
	{"0x0.89aBcDp-125", "1.2643093e-38", nil},  // 0x0089abcd
	{"0x0.8000000p-125", "1.1754944e-38", nil}, // 0x00800000
	{"0x0.1234560p-125", "1.671814e-39", nil},  // 0x00123456
	{"0x0.1234567p-125", "1.671814e-39", nil},  // rounded down
	{"0x0.1234568p-125", "1.671814e-39", nil},  // rounded down
	{"0x0.1234569p-125", "1.671815e-39", nil},  // rounded up
	{"0x0.1234570p-125", "1.671815e-39", nil},  // 0x00123457
	{"0x0.0000010p-125", "1e-45", nil},         // 0x00000001
	{"0x0.00000081p-125", "1e-45", nil},        // rounded up
	{"0x0.0000008p-125", "0", nil},             // rounded down
	{"0x0.0000007p-125", "0", nil},             // rounded down

	// 2^92 = 8388608p+69 = 4951760157141521099596496896 (4.9517602e27)
	// is an exact power of two that needs 8 decimal digits to be correctly
	// parsed back.
	// The float32 before is 16777215p+68 = 4.95175986e+27
	// The halfway is 4.951760009. A bad algorithm that thinks the previous
	// float32 is 8388607p+69 will shorten incorrectly to 4.95176e+27.
	{"4951760157141521099596496896", "4.9517602e+27", nil},
}

type atofSimpleTest struct {
	x float64
	s string
}

var (
	atofOnce               sync.Once
	atofRandomTests        []atofSimpleTest
	benchmarksRandomBits   [1024]string
	benchmarksRandomNormal [1024]string
)

func initAtof() {
	atofOnce.Do(initAtofOnce)
}

func initAtofOnce() {
	// The atof routines return NumErrors wrapping
	// the error and the string. Convert the table above.
	for i := range atoftests {
		test := &atoftests[i]
		if test.err != nil {
			test.err = &NumError{"ParseFloat", test.in, test.err}
		}
	}
	for i := range atof32tests {
		test := &atof32tests[i]
		if test.err != nil {
			test.err = &NumError{"ParseFloat", test.in, test.err}
		}
	}

	// Generate random inputs for tests and benchmarks
	if testing.Short() {
		atofRandomTests = make([]atofSimpleTest, 100)
	} else {
		atofRandomTests = make([]atofSimpleTest, 10000)
	}
	for i := range atofRandomTests {
		n := uint64(rand.Uint32())<<32 | uint64(rand.Uint32())
		x := math.Float64frombits(n)
		s := FormatFloat(x, 'g', -1, 64)
		atofRandomTests[i] = atofSimpleTest{x, s}
	}

	for i := range benchmarksRandomBits {
		bits := uint64(rand.Uint32())<<32 | uint64(rand.Uint32())
		x := math.Float64frombits(bits)
		benchmarksRandomBits[i] = FormatFloat(x, 'g', -1, 64)
	}

	for i := range benchmarksRandomNormal {
		x := rand.NormFloat64()
		benchmarksRandomNormal[i] = FormatFloat(x, 'g', -1, 64)
	}
}

func TestParseFloatPrefix(t *testing.T) {
	for i := range atoftests {
		test := &atoftests[i]
		if test.err != nil {
			continue
		}
		// Adding characters that do not extend a number should not invalidate it.
		// Test a few. The "i" and "init" cases test that we accept "infi", "infinit"
		// correctly as "inf" with suffix.
		for _, suffix := range []string{" ", "q", "+", "-", "<", "=", ">", "(", ")", "i", "init"} {
			in := test.in + suffix
			_, n, err := ParseFloatPrefix(in, 64)
			if err != nil {
				t.Errorf("ParseFloatPrefix(%q, 64): err = %v; want no error", in, err)
			}
			if n != len(test.in) {
				t.Errorf("ParseFloatPrefix(%q, 64): n = %d; want %d", in, n, len(test.in))
			}
		}
	}
}

func testAtof(t *testing.T, opt bool) {
	initAtof()
	oldopt := SetOptimize(opt)
	for i := 0; i < len(atoftests); i++ {
		test := &atoftests[i]
		out, err := ParseFloat(test.in, 64)
		outs := FormatFloat(out, 'g', -1, 64)
		if outs != test.out || !reflect.DeepEqual(err, test.err) {
			t.Errorf("ParseFloat(%v, 64) = %v, %v want %v, %v",
				test.in, out, err, test.out, test.err)
		}

		if float64(float32(out)) == out {
			out, err := ParseFloat(test.in, 32)
			out32 := float32(out)
			if float64(out32) != out {
				t.Errorf("ParseFloat(%v, 32) = %v, not a float32 (closest is %v)", test.in, out, float64(out32))
				continue
			}
			outs := FormatFloat(float64(out32), 'g', -1, 32)
			if outs != test.out || !reflect.DeepEqual(err, test.err) {
				t.Errorf("ParseFloat(%v, 32) = %v, %v want %v, %v  # %v",
					test.in, out32, err, test.out, test.err, out)
			}
		}
	}
	for _, test := range atof32tests {
		out, err := ParseFloat(test.in, 32)
		out32 := float32(out)
		if float64(out32) != out {
			t.Errorf("ParseFloat(%v, 32) = %v, not a float32 (closest is %v)", test.in, out, float64(out32))
			continue
		}
		outs := FormatFloat(float64(out32), 'g', -1, 32)
		if outs != test.out || !reflect.DeepEqual(err, test.err) {
			t.Errorf("ParseFloat(%v, 32) = %v, %v want %v, %v  # %v",
				test.in, out32, err, test.out, test.err, out)
		}
	}
	SetOptimize(oldopt)
}

func TestAtof(t *testing.T) { testAtof(t, true) }

func TestAtofSlow(t *testing.T) { testAtof(t, false) }

func TestAtofRandom(t *testing.T) {
	initAtof()
	for _, test := range atofRandomTests {
		x, _ := ParseFloat(test.s, 64)
		switch {
		default:
			t.Errorf("number %s badly parsed as %b (expected %b)", test.s, x, test.x)
		case x == test.x:
		case math.IsNaN(test.x) && math.IsNaN(x):
		}
	}
	t.Logf("tested %d random numbers", len(atofRandomTests))
}

var roundTripCases = []struct {
	f float64
	s string
}{
	// Issue 2917.
	// This test will break the optimized conversion if the
	// FPU is using 80-bit registers instead of 64-bit registers,
	// usually because the operating system initialized the
	// thread with 80-bit precision and the Go runtime didn't
	// fix the FP control word.
	{8865794286000691 << 39, "4.87402195346389e+27"},
	{8865794286000692 << 39, "4.8740219534638903e+27"},
}

func TestRoundTrip(t *testing.T) {
	for _, tt := range roundTripCases {
		old := SetOptimize(false)
		s := FormatFloat(tt.f, 'g', -1, 64)
		if s != tt.s {
			t.Errorf("no-opt FormatFloat(%b) = %s, want %s", tt.f, s, tt.s)
		}
		f, err := ParseFloat(tt.s, 64)
		if f != tt.f || err != nil {
			t.Errorf("no-opt ParseFloat(%s) = %b, %v want %b, nil", tt.s, f, err, tt.f)
		}
		SetOptimize(true)
		s = FormatFloat(tt.f, 'g', -1, 64)
		if s != tt.s {
			t.Errorf("opt FormatFloat(%b) = %s, want %s", tt.f, s, tt.s)
		}
		f, err = ParseFloat(tt.s, 64)
		if f != tt.f || err != nil {
			t.Errorf("opt ParseFloat(%s) = %b, %v want %b, nil", tt.s, f, err, tt.f)
		}
		SetOptimize(old)
	}
}

// TestRoundTrip32 tries a fraction of all finite positive float32 values.
func TestRoundTrip32(t *testing.T) {
	step := uint32(997)
	if testing.Short() {
		step = 99991
	}
	count := 0
	for i := uint32(0); i < 0xff<<23; i += step {
		f := math.Float32frombits(i)
		if i&1 == 1 {
			f = -f // negative
		}
		s := FormatFloat(float64(f), 'g', -1, 32)

		parsed, err := ParseFloat(s, 32)
		parsed32 := float32(parsed)
		switch {
		case err != nil:
			t.Errorf("ParseFloat(%q, 32) gave error %s", s, err)
		case float64(parsed32) != parsed:
			t.Errorf("ParseFloat(%q, 32) = %v, not a float32 (nearest is %v)", s, parsed, parsed32)
		case parsed32 != f:
			t.Errorf("ParseFloat(%q, 32) = %b (expected %b)", s, parsed32, f)
		}
		count++
	}
	t.Logf("tested %d float32's", count)
}

// Issue 42297: a lot of code in the wild accidentally calls ParseFloat(s, 10)
// or ParseFloat(s, 0), so allow bitSize values other than 32 and 64.
func TestParseFloatIncorrectBitSize(t *testing.T) {
	const s = "1.5e308"
	const want = 1.5e308

	for _, bitSize := range []int{0, 10, 100, 128} {
		f, err := ParseFloat(s, bitSize)
		if err != nil {
			t.Fatalf("ParseFloat(%q, %d) gave error %s", s, bitSize, err)
		}
		if f != want {
			t.Fatalf("ParseFloat(%q, %d) = %g (expected %g)", s, bitSize, f, want)
		}
	}
}

func BenchmarkAtof64Decimal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseFloat("33909", 64)
	}
}

func BenchmarkAtof64Float(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseFloat("339.7784", 64)
	}
}

func BenchmarkAtof64FloatExp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseFloat("-5.09e75", 64)
	}
}

func BenchmarkAtof64Big(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseFloat("123456789123456789123456789", 64)
	}
}

func BenchmarkAtof64RandomBits(b *testing.B) {
	initAtof()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseFloat(benchmarksRandomBits[i%1024], 64)
	}
}

func BenchmarkAtof64RandomFloats(b *testing.B) {
	initAtof()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseFloat(benchmarksRandomNormal[i%1024], 64)
	}
}

func BenchmarkAtof64RandomLongFloats(b *testing.B) {
	initAtof()
	samples := make([]string, len(atofRandomTests))
	for i, t := range atofRandomTests {
		samples[i] = FormatFloat(t.x, 'g', 20, 64)
	}
	b.ResetTimer()
	idx := 0
	for i := 0; i < b.N; i++ {
		ParseFloat(samples[idx], 64)
		idx++
		if idx == len(samples) {
			idx = 0
		}
	}
}

func BenchmarkAtof32Decimal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseFloat("33909", 32)
	}
}

func BenchmarkAtof32Float(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseFloat("339.778", 32)
	}
}

func BenchmarkAtof32FloatExp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseFloat("12.3456e32", 32)
	}
}

func BenchmarkAtof32Random(b *testing.B) {
	n := uint32(997)
	var float32strings [4096]string
	for i := range float32strings {
		n = (99991*n + 42) % (0xff << 23)
		float32strings[i] = FormatFloat(float64(math.Float32frombits(n)), 'g', -1, 32)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseFloat(float32strings[i%4096], 32)
	}
}

func BenchmarkAtof32RandomLong(b *testing.B) {
	n := uint32(997)
	var float32strings [4096]string
	for i := range float32strings {
		n = (99991*n + 42) % (0xff << 23)
		float32strings[i] = FormatFloat(float64(math.Float32frombits(n)), 'g', 20, 32)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseFloat(float32strings[i%4096], 32)
	}
}

"""



```