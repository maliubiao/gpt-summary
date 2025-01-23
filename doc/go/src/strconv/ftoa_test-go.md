Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Functionality:** The file name `ftoa_test.go` immediately suggests that this code is for testing the "float to ASCII" (or string) conversion functionality. The package name `strconv_test` confirms it's part of the `strconv` package's testing suite.

2. **Examine the Test Structure:**  The presence of `import "testing"` is a strong indicator of a Go test file. Look for functions starting with `Test` and `Benchmark`. These are the standard entry points for tests and benchmarks.

3. **Analyze the `ftoaTest` struct:** This struct, containing `f`, `fmt`, `prec`, and `s`, is clearly designed to hold test cases. It represents a floating-point number (`f`), a formatting character (`fmt`), a precision value (`prec`), and the expected string representation (`s`). This is a common pattern in Go testing for parameterizing tests.

4. **Understand the Test Data (`ftoatests`):** The `ftoatests` variable is a slice of `ftoaTest` structs. Scanning through the data reveals various floating-point numbers, format specifiers ('e', 'f', 'g', 'x', 'X', 'b', '?'), and precision values (positive integers, -1, and 0). The corresponding string values are the expected outputs. This gives concrete examples of the behavior being tested.

5. **Focus on the `TestFtoa` Function:** This is a primary test function. It iterates through `ftoatests`. Inside the loop, it calls `FormatFloat` (the function being tested) and `AppendFloat`. It compares the generated output with the expected output (`test.s`). The checks for both 64-bit and 32-bit floats are important.

6. **Investigate the `TestFtoaPowersOfTwo` Function:** This test focuses on a specific set of inputs: powers of two. The goal is likely to verify the correct handling of these edge cases and ensure accurate round-tripping (converting to a string and back).

7. **Understand the `TestFtoaRandom` Function:** This test uses random floating-point numbers to provide broader coverage and stress the `FormatFloat` function with more diverse inputs. It also checks the impact of the `SetOptimize` function (although the details of `SetOptimize` aren't directly visible in this snippet).

8. **Examine `TestFormatFloatInvalidBitSize`:** This test uses `defer panic()` to check that `FormatFloat` panics (errors) when given an invalid `bitSize`. This is good practice for testing error handling.

9. **Analyze the Benchmark Functions (`BenchmarkFormatFloat` and `BenchmarkAppendFloat`):** These functions measure the performance of `FormatFloat` and `AppendFloat` with various inputs defined in `ftoaBenches`. The `ftoaBenches` data is similar to `ftoatests` but geared towards performance testing with different categories of numbers (decimal, exponential, etc.).

10. **Infer the Functionality of `FormatFloat` and `AppendFloat`:** Based on the tests, `FormatFloat` converts a floating-point number to its string representation according to the specified format and precision. `AppendFloat` does the same but appends the result to an existing byte slice.

11. **Infer the Meaning of the Format Specifiers:** By observing the input and output pairs in `ftoatests`, we can deduce the meaning of the format specifiers:
    * `'e'`: Scientific notation (e.g., `1.00000e+00`)
    * `'f'`: Decimal notation (e.g., `1.00000`)
    * `'g'`: General format (chooses between 'e' and 'f' based on the magnitude of the number and precision)
    * `'x'`/`'X'`: Hexadecimal floating-point representation (e.g., `0x1p+00`)
    * `'b'`: Binary floating-point representation (mantissa and exponent)
    * `'?'`: Seems to be an invalid format, resulting in a placeholder.

12. **Consider Potential Error Points for Users:**  Thinking about how someone might misuse these functions, precision can be tricky. Setting the precision too low can lead to loss of information due to rounding. Using the wrong format specifier will produce unexpected results. Also, the `bitSize` parameter is important for matching the actual type of the float (32-bit or 64-bit).

13. **Structure the Answer:** Organize the findings into clear sections: Functionality, Go Feature Implementation, Code Example (with assumptions and output), Command-line Arguments (none in this snippet), and Common Mistakes. Use clear and concise language.

By following these steps, one can systematically analyze the provided Go code and deduce its purpose, implementation details, and potential usage considerations. The key is to start with the obvious (file name, imports) and progressively analyze the code structure and data to build a comprehensive understanding.
这段代码是 Go 语言标准库 `strconv` 包中 `ftoa_test.go` 文件的一部分，它主要用于测试将浮点数转换为字符串的功能，具体来说，它测试了 `strconv` 包中的 `FormatFloat` 和 `AppendFloat` 函数。

**功能列举:**

1. **定义测试用例:**  它定义了一个名为 `ftoaTest` 的结构体，用于存储浮点数 (`f`)、格式化标识符 (`fmt`)、精度 (`prec`) 以及期望的字符串输出 (`s`)。
2. **提供大量的测试数据:**  定义了一个名为 `ftoatests` 的切片，其中包含了大量的 `ftoaTest` 结构体实例，覆盖了各种不同的浮点数（正数、负数、零、非常大和非常小的数、特殊值如 NaN 和无穷大）、不同的格式化标识符 ('e', 'f', 'g', 'x', 'X', 'b', '?') 以及不同的精度值。
3. **测试 `FormatFloat` 函数:**  `TestFtoa` 函数遍历 `ftoatests` 中的每一个测试用例，调用 `strconv.FormatFloat` 函数将浮点数转换为字符串，并将结果与预期的字符串进行比较，如果不同则报告错误。它同时测试了 64 位和 32 位浮点数的转换。
4. **测试 `AppendFloat` 函数:** `TestFtoa` 函数还测试了 `strconv.AppendFloat` 函数，该函数的功能与 `FormatFloat` 类似，但它将转换后的字符串追加到一个已有的 byte 切片中。
5. **测试 2 的幂次方:** `TestFtoaPowersOfTwo` 函数专门测试将 2 的不同次幂转换为字符串，并进行反向解析，以确保转换和解析的一致性。
6. **进行随机测试:** `TestFtoaRandom` 函数生成大量的随机浮点数，并使用 `FormatFloat` 函数进行转换，通过对比在是否开启优化的两种情况下的输出，来验证转换的正确性。
7. **测试无效的 bitSize 参数:** `TestFormatFloatInvalidBitSize` 函数测试当 `FormatFloat` 函数接收到无效的 `bitSize` 参数时是否会 panic (引发恐慌)。
8. **性能基准测试:** `BenchmarkFormatFloat` 和 `BenchmarkAppendFloat` 函数用于衡量 `FormatFloat` 和 `AppendFloat` 函数的性能，针对不同类型的浮点数和格式进行了基准测试。

**Go 语言功能实现推理与代码示例:**

这段代码主要测试的是 Go 语言标准库 `strconv` 包中将浮点数转换为字符串的功能。  具体来说，它测试了 `FormatFloat` 函数，该函数根据指定的格式和精度将 `float64` 或 `float32` 类型的值转换为字符串表示。

```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	f := 123.456
	// 使用 'e' 格式，精度为 3
	s := strconv.FormatFloat(f, 'e', 3, 64)
	fmt.Println(s) // 输出: 1.235e+02

	// 使用 'f' 格式，精度为 2
	s = strconv.FormatFloat(f, 'f', 2, 64)
	fmt.Println(s) // 输出: 123.46

	// 使用 'g' 格式，自动选择最佳表示，精度为 -1 (默认精度)
	s = strconv.FormatFloat(f, 'g', -1, 64)
	fmt.Println(s) // 输出: 123.456

	// 使用 'x' 格式，十六进制表示
	s = strconv.FormatFloat(f, 'x', -1, 64)
	fmt.Println(s) // 输出: 0x1.ed70a3d70a3d7p+06

	// AppendFloat 的使用
	b := []byte("The value is: ")
	b = strconv.AppendFloat(b, f, 'f', 2, 64)
	fmt.Println(string(b)) // 输出: The value is: 123.46
}
```

**假设的输入与输出:**

在上面的代码示例中：

* **输入 `f` 为 `123.456`**
* **对于 `strconv.FormatFloat(f, 'e', 3, 64)`:**  `'e'` 表示科学计数法，精度为 3，所以输出为 `1.235e+02` (注意这里会根据精度进行四舍五入)。
* **对于 `strconv.FormatFloat(f, 'f', 2, 64)`:** `'f'` 表示小数形式，精度为 2，所以输出为 `123.46`。
* **对于 `strconv.FormatFloat(f, 'g', -1, 64)`:** `'g'` 表示通用格式，根据数值大小选择最佳表示，精度为默认，输出为 `123.456`。
* **对于 `strconv.FormatFloat(f, 'x', -1, 64)`:** `'x'` 表示十六进制浮点数表示，输出为 `0x1.ed70a3d70a3d7p+06`。
* **对于 `strconv.AppendFloat(b, f, 'f', 2, 64)`:** 将浮点数以 `'f'` 格式，精度为 2 追加到 byte 切片 `b`，最终 `b` 转换为字符串输出为 `The value is: 123.46`。

**命令行参数:**

这段代码是测试代码，本身不涉及命令行参数的处理。它是通过 `go test` 命令来运行的。

**使用者易犯错的点:**

1. **对 `fmt` 参数的理解不足:**  `fmt` 参数决定了浮点数的输出格式，常见的有：
    * `'e'` (或 `'E'`): 科学计数法 (例如: `1.234e+08`)
    * `'f'`:  小数点形式，没有指数 (例如: `123456700.00`)
    * `'g'` (或 `'G'`):  根据数值大小自动选择 `'e'` 或 `'f'` 格式
    * `'x'` (或 `'X'`): 十六进制表示 (例如: `0x1.2d687cccccccdp+20`)
    * `'b'`:  二进制表示 (例如: `-4503599627370496p-52`)
    * 使用不合适的 `fmt` 可能导致输出不是预期的格式。

    **示例:**

    ```go
    package main

    import (
        "fmt"
        "strconv"
    )

    func main() {
        f := 1234567.8
        s := strconv.FormatFloat(f, 'f', -1, 64) // 期望看到科学计数法，但用了 'f'
        fmt.Println(s) // 输出: 1234567.8
    }
    ```

2. **对 `prec` 参数的理解不足:** `prec` 参数控制输出的精度。
    * 对于 `'f'` 格式，它指定小数点后要显示多少位数字。
    * 对于 `'e'` 和 `'g'` 格式，它指定总共要显示多少位有效数字（不包括指数部分）。
    * 当 `prec` 为负数时，表示使用必要的最小位数来表示该值。

    **示例:**

    ```go
    package main

    import (
        "fmt"
        "strconv"
    )

    func main() {
        f := 1.23456789
        s := strconv.FormatFloat(f, 'f', 3, 64) // 期望看到更多小数位
        fmt.Println(s) // 输出: 1.235 (被截断并四舍五入了)
    }
    ```

3. **忽略 `bitSize` 参数的重要性:** `bitSize` 参数指定了浮点数的精度，可以是 32 (for `float32`) 或 64 (for `float64`)。如果 `bitSize` 与传入的浮点数类型不匹配，可能会导致意想不到的结果或精度损失。虽然在大多数情况下 Go 会自动处理，但了解其含义有助于避免潜在问题。

4. **误用精度为 0:** 当使用 `'f'` 格式且精度为 0 时，浮点数会被四舍五入到最接近的整数。这可能不是用户期望的行为。

    **示例:**

    ```go
    package main

    import (
        "fmt"
        "strconv"
    )

    func main() {
        f1 := 1.5
        s1 := strconv.FormatFloat(f1, 'f', 0, 64)
        fmt.Println(s1) // 输出: 2

        f2 := 1.4
        s2 := strconv.FormatFloat(f2, 'f', 0, 64)
        fmt.Println(s2) // 输出: 1
    }
    ```

总之，理解 `FormatFloat` 函数的各个参数及其含义，并根据需要选择合适的格式和精度，是避免错误的关键。

### 提示词
```
这是路径为go/src/strconv/ftoa_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package strconv_test

import (
	"math"
	"math/rand"
	. "strconv"
	"testing"
)

type ftoaTest struct {
	f    float64
	fmt  byte
	prec int
	s    string
}

func fdiv(a, b float64) float64 { return a / b }

const (
	below1e23 = 99999999999999974834176
	above1e23 = 100000000000000008388608
)

var ftoatests = []ftoaTest{
	{1, 'e', 5, "1.00000e+00"},
	{1, 'f', 5, "1.00000"},
	{1, 'g', 5, "1"},
	{1, 'g', -1, "1"},
	{1, 'x', -1, "0x1p+00"},
	{1, 'x', 5, "0x1.00000p+00"},
	{20, 'g', -1, "20"},
	{20, 'x', -1, "0x1.4p+04"},
	{1234567.8, 'g', -1, "1.2345678e+06"},
	{1234567.8, 'x', -1, "0x1.2d687cccccccdp+20"},
	{200000, 'g', -1, "200000"},
	{200000, 'x', -1, "0x1.86ap+17"},
	{200000, 'X', -1, "0X1.86AP+17"},
	{2000000, 'g', -1, "2e+06"},
	{1e10, 'g', -1, "1e+10"},

	// g conversion and zero suppression
	{400, 'g', 2, "4e+02"},
	{40, 'g', 2, "40"},
	{4, 'g', 2, "4"},
	{.4, 'g', 2, "0.4"},
	{.04, 'g', 2, "0.04"},
	{.004, 'g', 2, "0.004"},
	{.0004, 'g', 2, "0.0004"},
	{.00004, 'g', 2, "4e-05"},
	{.000004, 'g', 2, "4e-06"},

	{0, 'e', 5, "0.00000e+00"},
	{0, 'f', 5, "0.00000"},
	{0, 'g', 5, "0"},
	{0, 'g', -1, "0"},
	{0, 'x', 5, "0x0.00000p+00"},

	{-1, 'e', 5, "-1.00000e+00"},
	{-1, 'f', 5, "-1.00000"},
	{-1, 'g', 5, "-1"},
	{-1, 'g', -1, "-1"},

	{12, 'e', 5, "1.20000e+01"},
	{12, 'f', 5, "12.00000"},
	{12, 'g', 5, "12"},
	{12, 'g', -1, "12"},

	{123456700, 'e', 5, "1.23457e+08"},
	{123456700, 'f', 5, "123456700.00000"},
	{123456700, 'g', 5, "1.2346e+08"},
	{123456700, 'g', -1, "1.234567e+08"},

	{1.2345e6, 'e', 5, "1.23450e+06"},
	{1.2345e6, 'f', 5, "1234500.00000"},
	{1.2345e6, 'g', 5, "1.2345e+06"},

	// Round to even
	{1.2345e6, 'e', 3, "1.234e+06"},
	{1.2355e6, 'e', 3, "1.236e+06"},
	{1.2345, 'f', 3, "1.234"},
	{1.2355, 'f', 3, "1.236"},
	{1234567890123456.5, 'e', 15, "1.234567890123456e+15"},
	{1234567890123457.5, 'e', 15, "1.234567890123458e+15"},
	{108678236358137.625, 'g', -1, "1.0867823635813762e+14"},

	{1e23, 'e', 17, "9.99999999999999916e+22"},
	{1e23, 'f', 17, "99999999999999991611392.00000000000000000"},
	{1e23, 'g', 17, "9.9999999999999992e+22"},

	{1e23, 'e', -1, "1e+23"},
	{1e23, 'f', -1, "100000000000000000000000"},
	{1e23, 'g', -1, "1e+23"},

	{below1e23, 'e', 17, "9.99999999999999748e+22"},
	{below1e23, 'f', 17, "99999999999999974834176.00000000000000000"},
	{below1e23, 'g', 17, "9.9999999999999975e+22"},

	{below1e23, 'e', -1, "9.999999999999997e+22"},
	{below1e23, 'f', -1, "99999999999999970000000"},
	{below1e23, 'g', -1, "9.999999999999997e+22"},

	{above1e23, 'e', 17, "1.00000000000000008e+23"},
	{above1e23, 'f', 17, "100000000000000008388608.00000000000000000"},
	{above1e23, 'g', 17, "1.0000000000000001e+23"},

	{above1e23, 'e', -1, "1.0000000000000001e+23"},
	{above1e23, 'f', -1, "100000000000000010000000"},
	{above1e23, 'g', -1, "1.0000000000000001e+23"},

	{fdiv(5e-304, 1e20), 'g', -1, "5e-324"},   // avoid constant arithmetic
	{fdiv(-5e-304, 1e20), 'g', -1, "-5e-324"}, // avoid constant arithmetic

	{32, 'g', -1, "32"},
	{32, 'g', 0, "3e+01"},

	{100, 'x', -1, "0x1.9p+06"},
	{100, 'y', -1, "%y"},

	{math.NaN(), 'g', -1, "NaN"},
	{-math.NaN(), 'g', -1, "NaN"},
	{math.Inf(0), 'g', -1, "+Inf"},
	{math.Inf(-1), 'g', -1, "-Inf"},
	{-math.Inf(0), 'g', -1, "-Inf"},

	{-1, 'b', -1, "-4503599627370496p-52"},

	// fixed bugs
	{0.9, 'f', 1, "0.9"},
	{0.09, 'f', 1, "0.1"},
	{0.0999, 'f', 1, "0.1"},
	{0.05, 'f', 1, "0.1"},
	{0.05, 'f', 0, "0"},
	{0.5, 'f', 1, "0.5"},
	{0.5, 'f', 0, "0"},
	{1.5, 'f', 0, "2"},

	// https://www.exploringbinary.com/java-hangs-when-converting-2-2250738585072012e-308/
	{2.2250738585072012e-308, 'g', -1, "2.2250738585072014e-308"},
	// https://www.exploringbinary.com/php-hangs-on-numeric-value-2-2250738585072011e-308/
	{2.2250738585072011e-308, 'g', -1, "2.225073858507201e-308"},

	// Issue 2625.
	{383260575764816448, 'f', 0, "383260575764816448"},
	{383260575764816448, 'g', -1, "3.8326057576481645e+17"},

	// Issue 29491.
	{498484681984085570, 'f', -1, "498484681984085570"},
	{-5.8339553793802237e+23, 'g', -1, "-5.8339553793802237e+23"},

	// Issue 52187
	{123.45, '?', 0, "%?"},
	{123.45, '?', 1, "%?"},
	{123.45, '?', -1, "%?"},

	// rounding
	{2.275555555555555, 'x', -1, "0x1.23456789abcdep+01"},
	{2.275555555555555, 'x', 0, "0x1p+01"},
	{2.275555555555555, 'x', 2, "0x1.23p+01"},
	{2.275555555555555, 'x', 16, "0x1.23456789abcde000p+01"},
	{2.275555555555555, 'x', 21, "0x1.23456789abcde00000000p+01"},
	{2.2755555510520935, 'x', -1, "0x1.2345678p+01"},
	{2.2755555510520935, 'x', 6, "0x1.234568p+01"},
	{2.275555431842804, 'x', -1, "0x1.2345668p+01"},
	{2.275555431842804, 'x', 6, "0x1.234566p+01"},
	{3.999969482421875, 'x', -1, "0x1.ffffp+01"},
	{3.999969482421875, 'x', 4, "0x1.ffffp+01"},
	{3.999969482421875, 'x', 3, "0x1.000p+02"},
	{3.999969482421875, 'x', 2, "0x1.00p+02"},
	{3.999969482421875, 'x', 1, "0x1.0p+02"},
	{3.999969482421875, 'x', 0, "0x1p+02"},
}

func TestFtoa(t *testing.T) {
	for i := 0; i < len(ftoatests); i++ {
		test := &ftoatests[i]
		s := FormatFloat(test.f, test.fmt, test.prec, 64)
		if s != test.s {
			t.Error("testN=64", test.f, string(test.fmt), test.prec, "want", test.s, "got", s)
		}
		x := AppendFloat([]byte("abc"), test.f, test.fmt, test.prec, 64)
		if string(x) != "abc"+test.s {
			t.Error("AppendFloat testN=64", test.f, string(test.fmt), test.prec, "want", "abc"+test.s, "got", string(x))
		}
		if float64(float32(test.f)) == test.f && test.fmt != 'b' {
			s := FormatFloat(test.f, test.fmt, test.prec, 32)
			if s != test.s {
				t.Error("testN=32", test.f, string(test.fmt), test.prec, "want", test.s, "got", s)
			}
			x := AppendFloat([]byte("abc"), test.f, test.fmt, test.prec, 32)
			if string(x) != "abc"+test.s {
				t.Error("AppendFloat testN=32", test.f, string(test.fmt), test.prec, "want", "abc"+test.s, "got", string(x))
			}
		}
	}
}

func TestFtoaPowersOfTwo(t *testing.T) {
	for exp := -2048; exp <= 2048; exp++ {
		f := math.Ldexp(1, exp)
		if !math.IsInf(f, 0) {
			s := FormatFloat(f, 'e', -1, 64)
			if x, _ := ParseFloat(s, 64); x != f {
				t.Errorf("failed roundtrip %v => %s => %v", f, s, x)
			}
		}
		f32 := float32(f)
		if !math.IsInf(float64(f32), 0) {
			s := FormatFloat(float64(f32), 'e', -1, 32)
			if x, _ := ParseFloat(s, 32); float32(x) != f32 {
				t.Errorf("failed roundtrip %v => %s => %v", f32, s, float32(x))
			}
		}
	}
}

func TestFtoaRandom(t *testing.T) {
	N := int(1e4)
	if testing.Short() {
		N = 100
	}
	t.Logf("testing %d random numbers with fast and slow FormatFloat", N)
	for i := 0; i < N; i++ {
		bits := uint64(rand.Uint32())<<32 | uint64(rand.Uint32())
		x := math.Float64frombits(bits)

		shortFast := FormatFloat(x, 'g', -1, 64)
		SetOptimize(false)
		shortSlow := FormatFloat(x, 'g', -1, 64)
		SetOptimize(true)
		if shortSlow != shortFast {
			t.Errorf("%b printed as %s, want %s", x, shortFast, shortSlow)
		}

		prec := rand.Intn(12) + 5
		shortFast = FormatFloat(x, 'e', prec, 64)
		SetOptimize(false)
		shortSlow = FormatFloat(x, 'e', prec, 64)
		SetOptimize(true)
		if shortSlow != shortFast {
			t.Errorf("%b printed as %s, want %s", x, shortFast, shortSlow)
		}
	}
}

func TestFormatFloatInvalidBitSize(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic due to invalid bitSize")
		}
	}()
	_ = FormatFloat(3.14, 'g', -1, 100)
}

var ftoaBenches = []struct {
	name    string
	float   float64
	fmt     byte
	prec    int
	bitSize int
}{
	{"Decimal", 33909, 'g', -1, 64},
	{"Float", 339.7784, 'g', -1, 64},
	{"Exp", -5.09e75, 'g', -1, 64},
	{"NegExp", -5.11e-95, 'g', -1, 64},
	{"LongExp", 1.234567890123456e-78, 'g', -1, 64},

	{"Big", 123456789123456789123456789, 'g', -1, 64},
	{"BinaryExp", -1, 'b', -1, 64},

	{"32Integer", 33909, 'g', -1, 32},
	{"32ExactFraction", 3.375, 'g', -1, 32},
	{"32Point", 339.7784, 'g', -1, 32},
	{"32Exp", -5.09e25, 'g', -1, 32},
	{"32NegExp", -5.11e-25, 'g', -1, 32},
	{"32Shortest", 1.234567e-8, 'g', -1, 32},
	{"32Fixed8Hard", math.Ldexp(15961084, -125), 'e', 8, 32},
	{"32Fixed9Hard", math.Ldexp(14855922, -83), 'e', 9, 32},

	{"64Fixed1", 123456, 'e', 3, 64},
	{"64Fixed2", 123.456, 'e', 3, 64},
	{"64Fixed3", 1.23456e+78, 'e', 3, 64},
	{"64Fixed4", 1.23456e-78, 'e', 3, 64},
	{"64Fixed12", 1.23456e-78, 'e', 12, 64},
	{"64Fixed16", 1.23456e-78, 'e', 16, 64},
	// From testdata/testfp.txt
	{"64Fixed12Hard", math.Ldexp(6965949469487146, -249), 'e', 12, 64},
	{"64Fixed17Hard", math.Ldexp(8887055249355788, 665), 'e', 17, 64},
	{"64Fixed18Hard", math.Ldexp(6994187472632449, 690), 'e', 18, 64},

	// Trigger slow path (see issue #15672).
	// The shortest is: 8.034137530808823e+43
	{"Slowpath64", 8.03413753080882349e+43, 'e', -1, 64},
	// This denormal is pathological because the lower/upper
	// halfways to neighboring floats are:
	// 622666234635.321003e-320 ~= 622666234635.321e-320
	// 622666234635.321497e-320 ~= 622666234635.3215e-320
	// making it hard to find the 3rd digit
	{"SlowpathDenormal64", 622666234635.3213e-320, 'e', -1, 64},
}

func BenchmarkFormatFloat(b *testing.B) {
	for _, c := range ftoaBenches {
		b.Run(c.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				FormatFloat(c.float, c.fmt, c.prec, c.bitSize)
			}
		})
	}
}

func BenchmarkAppendFloat(b *testing.B) {
	dst := make([]byte, 30)
	for _, c := range ftoaBenches {
		b.Run(c.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				AppendFloat(dst[:0], c.float, c.fmt, c.prec, c.bitSize)
			}
		})
	}
}
```