Response:
Thinking Process:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code snippet, which is the third part of a testing file (`all_test.go`) for the `math` package.

2. **Identify the Core Activity:**  The code consists primarily of functions named `Test...`. This strongly suggests that the code's main purpose is *testing*.

3. **Examine Individual `Test...` Functions:** Go through each `Test...` function and determine what specific `math` package function it is testing. Note the pattern: `Test<FunctionName>` tests the `math.<FunctionName>` (or a closely related) function.

4. **Categorize the Tested Functions:** Group the tested functions into categories based on their mathematical operations. This helps organize the summary and identify common themes. Examples:
    * Logarithmic functions: `Log10`, `Log1p`, `Log2`
    * Rounding functions: `Round`, `RoundToEven`, `Trunc`, `Ceil`, `Floor`, `Modf`
    * Trigonometric functions: `Sin`, `Cos`, `Tan`, `Sincos`, `Sinh`, `Tanh`
    * Power and exponentiation: `Pow`, `Pow10`, `Sqrt`, `Exp`, `Exp2`
    * Remainder and Modulo: `Remainder`, `Mod`
    * Functions related to floating-point representation: `Signbit`, `Nextafter`, `Ldexp`, `Frexp`, `Float64bits`, `Float64frombits`, `Float32bits`, `Float32frombits`
    * Bessel functions: `Y0`, `Y1`, `Yn`, `J0`, `J1`, `Jn`
    * Special functions: `Erf`, `Erfc`, `Erfinv`, `Erfcinv`, `Gamma`, `Lgamma`
    * Utility functions: `Abs`, `Copysign`, `Dim`, `Max`, `Min`, `Hypot`, `Ilogb`
    * Fused Multiply-Add: `FMA`

5. **Identify Supporting Test Structures:** Notice the presence of arrays like `vf`, `log10`, `modf`, etc., and how they are used within the test functions. These arrays hold pre-calculated expected values for various inputs. Also, note the use of helper functions like `veryclose` and `alike` for comparing floating-point numbers with tolerance.

6. **Recognize Benchmark Functions:**  The code also contains functions named `Benchmark...`. These are for performance testing (benchmarking) of the `math` package functions.

7. **Summarize the Functionality (Focus on Testing):**  Based on the observations, summarize the main purpose of the code: to thoroughly test the implementation of various mathematical functions in the Go `math` package. Highlight the types of tests being performed (testing against known values, testing edge cases, testing accuracy).

8. **Summarize the Benchmark Functionality:** Describe the purpose of the `Benchmark...` functions: to measure the performance of the `math` package functions.

9. **Address Specific Instructions:**  Review the original prompt and ensure all points are covered:
    * **List the functions:** This is done implicitly by describing the tests for each function.
    * **Infer Go language feature:** The code tests the functionality of the `math` package.
    * **Go code example (if inferrable):** Provide an example demonstrating a typical test case structure.
    * **Code reasoning (with input/output):**  Illustrate a test case and the comparison logic.
    * **Command-line arguments:** Not applicable in this specific code.
    * **User errors:** The prompt asks for *易犯错的点* in using the *tested functions*, not in the testing code itself. Since no specific functions are mentioned, this point can be omitted.
    * **Chinese answer:** Ensure the response is in Chinese.
    * **Part 3 Summary:**  This is the current step, summarizing the functionality of the provided code snippet.

10. **Refine and Organize:** Structure the summary logically, using clear headings and bullet points for better readability. Ensure the language is precise and avoids jargon where possible.

11. **Final Review:**  Read through the entire summary to ensure accuracy and completeness. Double-check that all parts of the prompt have been addressed.
这是路径为go/src/math/all_test.go的go语言实现的一部分，它主要负责对Go语言标准库中 `math` 包中的各种数学函数进行单元测试和性能基准测试。

**功能归纳:**

这段代码是 `math` 包测试套件的一部分，具体来说，它主要负责以下功能：

1. **单元测试 (Unit Tests):** 针对 `math` 包中的一系列数学函数（如 `Log10`, `Log1p`, `Log2`, `Modf`, `Nextafter`, `Pow`, `Remainder`, `Round`, `Sin`, `Cos`, `Tan`, `Sqrt`, `FMA` 等）进行详细的正确性测试。 这些测试通过以下方式进行：
    * **使用预定义的测试用例:** 代码中定义了多个数组 (如 `vf`, `log10`, `modf`, `pow`, 等) 和结构体 (如 `fmaC`)，包含了不同的输入值和期望的输出值。
    * **比较实际结果与期望结果:**  每个 `Test...` 函数都会调用 `math` 包中的对应函数，并将返回的实际结果与预定义的期望结果进行比较。
    * **使用近似比较:** 由于浮点数运算的精度问题，测试中使用了 `veryclose` 和 `alike` 等辅助函数进行近似比较，判断实际结果是否在误差允许范围内。
    * **覆盖特殊情况和边界条件:** 测试用例包含了各种正常值、特殊值（如正负无穷、NaN）、边界值等，以确保函数的鲁棒性。

2. **性能基准测试 (Benchmarks):**  这段代码还包含了一系列的 `Benchmark...` 函数，用于衡量 `math` 包中各个函数的性能。
    * **测量执行速度:**  这些基准测试会多次执行目标函数，并报告每次操作的平均耗时。
    * **防止编译器优化:**  使用了全局变量 (`GlobalI`, `GlobalB`, `GlobalF`) 来存储函数返回值，以防止编译器过度优化导致测试结果不准确。

**它是什么go语言功能的实现:**

这段代码主要实现了对 Go 语言标准库中 `math` 包的**单元测试**和**性能基准测试**。

**go代码举例说明 (单元测试):**

假设我们要测试 `math.Log10` 函数的功能，以下是一个基于代码片段的简化示例：

```go
import (
	"math"
	"testing"
)

func almostEqual(a, b float64) bool {
	const epsilon = 1e-9
	return math.Abs(a-b) <= epsilon
}

func TestLog10Example(t *testing.T) {
	testCases := []struct {
		input    float64
		expected float64
	}{
		{100, 2},
		{1, 0},
		{0.1, -1},
	}

	for _, tc := range testCases {
		actual := math.Log10(tc.input)
		if !almostEqual(actual, tc.expected) {
			t.Errorf("Log10(%g) = %g, want %g", tc.input, actual, tc.expected)
		}
	}
}
```

**假设的输入与输出:**

在 `TestLog10Example` 中：

* **输入:**  `testCases` 数组中的 `input` 字段，例如 `100`, `1`, `0.1`。
* **输出:**  `math.Log10(tc.input)` 的返回值。
* **期望输出:** `testCases` 数组中的 `expected` 字段，例如 `2`, `0`, `-1`。

如果实际输出与期望输出不符（在一定的精度范围内），`t.Errorf` 会报告错误。

**go代码举例说明 (性能基准测试):**

假设我们要测试 `math.Sin` 函数的性能：

```go
import (
	"math"
	"testing"
)

var globalSinResult float64 // 用于防止编译器优化

func BenchmarkSinExample(b *testing.B) {
	var result float64
	for i := 0; i < b.N; i++ {
		result = math.Sin(0.5)
	}
	globalSinResult = result
}
```

在这个基准测试中，`BenchmarkSinExample` 函数会被 `go test -bench=.` 命令多次执行，`b.N` 表示执行的迭代次数，Go 会自动调整迭代次数以获得可靠的性能数据。最终会报告 `math.Sin(0.5)` 的平均执行时间。

**涉及命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。 单元测试和基准测试通常通过 `go test` 命令来运行。

例如：

* 运行当前目录下的所有测试： `go test`
* 运行指定的测试文件： `go test ./all_test.go`
* 运行匹配特定模式的测试函数： `go test -run=TestLog10`
* 运行性能基准测试： `go test -bench=.`
* 运行匹配特定模式的基准测试： `go test -bench=BenchmarkSin`

`go test` 命令还支持其他参数，例如 `-v` (显示详细输出), `-cover` (显示代码覆盖率) 等。

**使用者易犯错的点:**

在 *使用 `math` 包中的函数* 时，用户容易犯错的点包括：

* **精度问题:**  浮点数运算存在精度误差，直接使用 `==` 比较两个浮点数可能不可靠。应该使用一个小的误差范围进行比较，就像测试代码中使用的 `veryclose` 或 `alike` 函数。
    ```go
    a := math.Sqrt(2)
    b := 1.41421356237
    // 错误的做法：
    // if a == b { ... }
    // 正确的做法：
    epsilon := 1e-9
    if math.Abs(a-b) < epsilon {
        // ...
    }
    ```
* **输入值超出定义域:**  某些数学函数对输入值有特定的限制。例如，`math.Sqrt` 不能接受负数作为输入（除了 NaN），`math.Log` 不能接受小于等于 0 的数。如果输入超出定义域，函数可能会返回 NaN 或正负无穷，或者导致 panic。
    ```go
    result := math.Sqrt(-1) // result 将是 NaN
    // result := math.Log(0)  // result 将是负无穷
    ```
* **忽略特殊值 (NaN, +/-Inf):** 数学函数的返回值可能包含特殊值，例如 NaN（非数字）和正负无穷。在使用这些返回值进行后续计算时，需要特别注意处理这些特殊情况，避免程序出错。可以使用 `math.IsNaN()` 和 `math.IsInf()` 函数来检查。
    ```go
    result := math.Sqrt(-1)
    if math.IsNaN(result) {
        println("输入无效")
    }
    ```

**总结一下它的功能:**

这段 `go/src/math/all_test.go` 的一部分代码，作为 `math` 包测试套件的一部分，其核心功能是：

1. **全面地测试 `math` 包中各种数学函数的正确性**，确保这些函数在各种输入条件下都能返回预期的结果。
2. **衡量 `math` 包中各个函数的性能**，为性能优化提供数据支持。

它通过单元测试验证函数的行为是否符合预期，并通过性能基准测试评估函数的执行效率。 这对于保证 Go 语言标准库的质量和性能至关重要。

Prompt: 
```
这是路径为go/src/math/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

"""
%g, want %g", E, f, Log10E)
	}
	for i := 0; i < len(vflogSC); i++ {
		if f := Log10(vflogSC[i]); !alike(logSC[i], f) {
			t.Errorf("Log10(%g) = %g, want %g", vflogSC[i], f, logSC[i])
		}
	}
}

func TestLog1p(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 100
		if f := Log1p(a); !veryclose(log1p[i], f) {
			t.Errorf("Log1p(%g) = %g, want %g", a, f, log1p[i])
		}
	}
	a := 9.0
	if f := Log1p(a); f != Ln10 {
		t.Errorf("Log1p(%g) = %g, want %g", a, f, Ln10)
	}
	for i := 0; i < len(vflogSC); i++ {
		if f := Log1p(vflog1pSC[i]); !alike(log1pSC[i], f) {
			t.Errorf("Log1p(%g) = %g, want %g", vflog1pSC[i], f, log1pSC[i])
		}
	}
}

func TestLog2(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := Abs(vf[i])
		if f := Log2(a); !veryclose(log2[i], f) {
			t.Errorf("Log2(%g) = %g, want %g", a, f, log2[i])
		}
	}
	if f := Log2(E); f != Log2E {
		t.Errorf("Log2(%g) = %g, want %g", E, f, Log2E)
	}
	for i := 0; i < len(vflogSC); i++ {
		if f := Log2(vflogSC[i]); !alike(logSC[i], f) {
			t.Errorf("Log2(%g) = %g, want %g", vflogSC[i], f, logSC[i])
		}
	}
	for i := -1074; i <= 1023; i++ {
		f := Ldexp(1, i)
		l := Log2(f)
		if l != float64(i) {
			t.Errorf("Log2(2**%d) = %g, want %d", i, l, i)
		}
	}
}

func TestModf(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f, g := Modf(vf[i]); !veryclose(modf[i][0], f) || !veryclose(modf[i][1], g) {
			t.Errorf("Modf(%g) = %g, %g, want %g, %g", vf[i], f, g, modf[i][0], modf[i][1])
		}
	}
	for i := 0; i < len(vfmodfSC); i++ {
		if f, g := Modf(vfmodfSC[i]); !alike(modfSC[i][0], f) || !alike(modfSC[i][1], g) {
			t.Errorf("Modf(%g) = %g, %g, want %g, %g", vfmodfSC[i], f, g, modfSC[i][0], modfSC[i][1])
		}
	}
}

func TestNextafter32(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		vfi := float32(vf[i])
		if f := Nextafter32(vfi, 10); nextafter32[i] != f {
			t.Errorf("Nextafter32(%g, %g) = %g want %g", vfi, 10.0, f, nextafter32[i])
		}
	}
	for i := 0; i < len(vfnextafter32SC); i++ {
		if f := Nextafter32(vfnextafter32SC[i][0], vfnextafter32SC[i][1]); !alike(float64(nextafter32SC[i]), float64(f)) {
			t.Errorf("Nextafter32(%g, %g) = %g want %g", vfnextafter32SC[i][0], vfnextafter32SC[i][1], f, nextafter32SC[i])
		}
	}
}

func TestNextafter64(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Nextafter(vf[i], 10); nextafter64[i] != f {
			t.Errorf("Nextafter64(%g, %g) = %g want %g", vf[i], 10.0, f, nextafter64[i])
		}
	}
	for i := 0; i < len(vfnextafter64SC); i++ {
		if f := Nextafter(vfnextafter64SC[i][0], vfnextafter64SC[i][1]); !alike(nextafter64SC[i], f) {
			t.Errorf("Nextafter64(%g, %g) = %g want %g", vfnextafter64SC[i][0], vfnextafter64SC[i][1], f, nextafter64SC[i])
		}
	}
}

func TestPow(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Pow(10, vf[i]); !close(pow[i], f) {
			t.Errorf("Pow(10, %g) = %g, want %g", vf[i], f, pow[i])
		}
	}
	for i := 0; i < len(vfpowSC); i++ {
		if f := Pow(vfpowSC[i][0], vfpowSC[i][1]); !alike(powSC[i], f) {
			t.Errorf("Pow(%g, %g) = %g, want %g", vfpowSC[i][0], vfpowSC[i][1], f, powSC[i])
		}
	}
}

func TestPow10(t *testing.T) {
	for i := 0; i < len(vfpow10SC); i++ {
		if f := Pow10(vfpow10SC[i]); !alike(pow10SC[i], f) {
			t.Errorf("Pow10(%d) = %g, want %g", vfpow10SC[i], f, pow10SC[i])
		}
	}
}

func TestRemainder(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Remainder(10, vf[i]); remainder[i] != f {
			t.Errorf("Remainder(10, %g) = %g, want %g", vf[i], f, remainder[i])
		}
	}
	for i := 0; i < len(vffmodSC); i++ {
		if f := Remainder(vffmodSC[i][0], vffmodSC[i][1]); !alike(fmodSC[i], f) {
			t.Errorf("Remainder(%g, %g) = %g, want %g", vffmodSC[i][0], vffmodSC[i][1], f, fmodSC[i])
		}
	}
	// verify precision of result for extreme inputs
	if f := Remainder(5.9790119248836734e+200, 1.1258465975523544); -0.4810497673014966 != f {
		t.Errorf("Remainder(5.9790119248836734e+200, 1.1258465975523544) = %g, want -0.4810497673014966", f)
	}
	// verify that sign is correct when r == 0.
	test := func(x, y float64) {
		if r := Remainder(x, y); r == 0 && Signbit(r) != Signbit(x) {
			t.Errorf("Remainder(x=%f, y=%f) = %f, sign of (zero) result should agree with sign of x", x, y, r)
		}
	}
	for x := 0.0; x <= 3.0; x += 1 {
		for y := 1.0; y <= 3.0; y += 1 {
			test(x, y)
			test(x, -y)
			test(-x, y)
			test(-x, -y)
		}
	}
}

func TestRound(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Round(vf[i]); !alike(round[i], f) {
			t.Errorf("Round(%g) = %g, want %g", vf[i], f, round[i])
		}
	}
	for i := 0; i < len(vfroundSC); i++ {
		if f := Round(vfroundSC[i][0]); !alike(vfroundSC[i][1], f) {
			t.Errorf("Round(%g) = %g, want %g", vfroundSC[i][0], f, vfroundSC[i][1])
		}
	}
}

func TestRoundToEven(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := RoundToEven(vf[i]); !alike(round[i], f) {
			t.Errorf("RoundToEven(%g) = %g, want %g", vf[i], f, round[i])
		}
	}
	for i := 0; i < len(vfroundEvenSC); i++ {
		if f := RoundToEven(vfroundEvenSC[i][0]); !alike(vfroundEvenSC[i][1], f) {
			t.Errorf("RoundToEven(%g) = %g, want %g", vfroundEvenSC[i][0], f, vfroundEvenSC[i][1])
		}
	}
}

func TestSignbit(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Signbit(vf[i]); signbit[i] != f {
			t.Errorf("Signbit(%g) = %t, want %t", vf[i], f, signbit[i])
		}
	}
	for i := 0; i < len(vfsignbitSC); i++ {
		if f := Signbit(vfsignbitSC[i]); signbitSC[i] != f {
			t.Errorf("Signbit(%g) = %t, want %t", vfsignbitSC[i], f, signbitSC[i])
		}
	}
}
func TestSin(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Sin(vf[i]); !veryclose(sin[i], f) {
			t.Errorf("Sin(%g) = %g, want %g", vf[i], f, sin[i])
		}
	}
	for i := 0; i < len(vfsinSC); i++ {
		if f := Sin(vfsinSC[i]); !alike(sinSC[i], f) {
			t.Errorf("Sin(%g) = %g, want %g", vfsinSC[i], f, sinSC[i])
		}
	}
}

func TestSincos(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if s, c := Sincos(vf[i]); !veryclose(sin[i], s) || !veryclose(cos[i], c) {
			t.Errorf("Sincos(%g) = %g, %g want %g, %g", vf[i], s, c, sin[i], cos[i])
		}
	}
}

func TestSinh(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Sinh(vf[i]); !close(sinh[i], f) {
			t.Errorf("Sinh(%g) = %g, want %g", vf[i], f, sinh[i])
		}
	}
	for i := 0; i < len(vfsinhSC); i++ {
		if f := Sinh(vfsinhSC[i]); !alike(sinhSC[i], f) {
			t.Errorf("Sinh(%g) = %g, want %g", vfsinhSC[i], f, sinhSC[i])
		}
	}
}

func TestSqrt(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := Abs(vf[i])
		if f := SqrtGo(a); sqrt[i] != f {
			t.Errorf("SqrtGo(%g) = %g, want %g", a, f, sqrt[i])
		}
		a = Abs(vf[i])
		if f := Sqrt(a); sqrt[i] != f {
			t.Errorf("Sqrt(%g) = %g, want %g", a, f, sqrt[i])
		}
	}
	for i := 0; i < len(vfsqrtSC); i++ {
		if f := SqrtGo(vfsqrtSC[i]); !alike(sqrtSC[i], f) {
			t.Errorf("SqrtGo(%g) = %g, want %g", vfsqrtSC[i], f, sqrtSC[i])
		}
		if f := Sqrt(vfsqrtSC[i]); !alike(sqrtSC[i], f) {
			t.Errorf("Sqrt(%g) = %g, want %g", vfsqrtSC[i], f, sqrtSC[i])
		}
	}
}

func TestTan(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Tan(vf[i]); !veryclose(tan[i], f) {
			t.Errorf("Tan(%g) = %g, want %g", vf[i], f, tan[i])
		}
	}
	// same special cases as Sin
	for i := 0; i < len(vfsinSC); i++ {
		if f := Tan(vfsinSC[i]); !alike(sinSC[i], f) {
			t.Errorf("Tan(%g) = %g, want %g", vfsinSC[i], f, sinSC[i])
		}
	}
}

func TestTanh(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Tanh(vf[i]); !veryclose(tanh[i], f) {
			t.Errorf("Tanh(%g) = %g, want %g", vf[i], f, tanh[i])
		}
	}
	for i := 0; i < len(vftanhSC); i++ {
		if f := Tanh(vftanhSC[i]); !alike(tanhSC[i], f) {
			t.Errorf("Tanh(%g) = %g, want %g", vftanhSC[i], f, tanhSC[i])
		}
	}
}

func TestTrunc(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Trunc(vf[i]); !alike(trunc[i], f) {
			t.Errorf("Trunc(%g) = %g, want %g", vf[i], f, trunc[i])
		}
	}
	for i := 0; i < len(vfceilSC); i++ {
		if f := Trunc(vfceilSC[i]); !alike(truncSC[i], f) {
			t.Errorf("Trunc(%g) = %g, want %g", vfceilSC[i], f, truncSC[i])
		}
	}
}

func TestY0(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := Abs(vf[i])
		if f := Y0(a); !close(y0[i], f) {
			t.Errorf("Y0(%g) = %g, want %g", a, f, y0[i])
		}
	}
	for i := 0; i < len(vfy0SC); i++ {
		if f := Y0(vfy0SC[i]); !alike(y0SC[i], f) {
			t.Errorf("Y0(%g) = %g, want %g", vfy0SC[i], f, y0SC[i])
		}
	}
}

func TestY1(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := Abs(vf[i])
		if f := Y1(a); !soclose(y1[i], f, 2e-14) {
			t.Errorf("Y1(%g) = %g, want %g", a, f, y1[i])
		}
	}
	for i := 0; i < len(vfy0SC); i++ {
		if f := Y1(vfy0SC[i]); !alike(y1SC[i], f) {
			t.Errorf("Y1(%g) = %g, want %g", vfy0SC[i], f, y1SC[i])
		}
	}
}

func TestYn(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := Abs(vf[i])
		if f := Yn(2, a); !close(y2[i], f) {
			t.Errorf("Yn(2, %g) = %g, want %g", a, f, y2[i])
		}
		if f := Yn(-3, a); !close(yM3[i], f) {
			t.Errorf("Yn(-3, %g) = %g, want %g", a, f, yM3[i])
		}
	}
	for i := 0; i < len(vfy0SC); i++ {
		if f := Yn(2, vfy0SC[i]); !alike(y2SC[i], f) {
			t.Errorf("Yn(2, %g) = %g, want %g", vfy0SC[i], f, y2SC[i])
		}
		if f := Yn(-3, vfy0SC[i]); !alike(yM3SC[i], f) {
			t.Errorf("Yn(-3, %g) = %g, want %g", vfy0SC[i], f, yM3SC[i])
		}
	}
	if f := Yn(0, 0); !alike(Inf(-1), f) {
		t.Errorf("Yn(0, 0) = %g, want %g", f, Inf(-1))
	}
}

var PortableFMA = FMA // hide call from compiler intrinsic; falls back to portable code

func TestFMA(t *testing.T) {
	for _, c := range fmaC {
		got := FMA(c.x, c.y, c.z)
		if !alike(got, c.want) {
			t.Errorf("FMA(%g,%g,%g) == %g; want %g", c.x, c.y, c.z, got, c.want)
		}
		got = PortableFMA(c.x, c.y, c.z)
		if !alike(got, c.want) {
			t.Errorf("PortableFMA(%g,%g,%g) == %g; want %g", c.x, c.y, c.z, got, c.want)
		}
	}
}

//go:noinline
func fmsub(x, y, z float64) float64 {
	return FMA(x, y, -z)
}

//go:noinline
func fnmsub(x, y, z float64) float64 {
	return FMA(-x, y, z)
}

//go:noinline
func fnmadd(x, y, z float64) float64 {
	return FMA(-x, y, -z)
}

func TestFMANegativeArgs(t *testing.T) {
	// Some architectures have instructions for fused multiply-subtract and
	// also negated variants of fused multiply-add and subtract. This test
	// aims to check that the optimizations that generate those instructions
	// are applied correctly, if they exist.
	for _, c := range fmaC {
		want := PortableFMA(c.x, c.y, -c.z)
		got := fmsub(c.x, c.y, c.z)
		if !alike(got, want) {
			t.Errorf("FMA(%g, %g, -(%g)) == %g, want %g", c.x, c.y, c.z, got, want)
		}
		want = PortableFMA(-c.x, c.y, c.z)
		got = fnmsub(c.x, c.y, c.z)
		if !alike(got, want) {
			t.Errorf("FMA(-(%g), %g, %g) == %g, want %g", c.x, c.y, c.z, got, want)
		}
		want = PortableFMA(-c.x, c.y, -c.z)
		got = fnmadd(c.x, c.y, c.z)
		if !alike(got, want) {
			t.Errorf("FMA(-(%g), %g, -(%g)) == %g, want %g", c.x, c.y, c.z, got, want)
		}
	}
}

// Check that math functions of high angle values
// return accurate results. [Since (vf[i] + large) - large != vf[i],
// testing for Trig(vf[i] + large) == Trig(vf[i]), where large is
// a multiple of 2*Pi, is misleading.]
func TestLargeCos(t *testing.T) {
	large := float64(100000 * Pi)
	for i := 0; i < len(vf); i++ {
		f1 := cosLarge[i]
		f2 := Cos(vf[i] + large)
		if !close(f1, f2) {
			t.Errorf("Cos(%g) = %g, want %g", vf[i]+large, f2, f1)
		}
	}
}

func TestLargeSin(t *testing.T) {
	large := float64(100000 * Pi)
	for i := 0; i < len(vf); i++ {
		f1 := sinLarge[i]
		f2 := Sin(vf[i] + large)
		if !close(f1, f2) {
			t.Errorf("Sin(%g) = %g, want %g", vf[i]+large, f2, f1)
		}
	}
}

func TestLargeSincos(t *testing.T) {
	large := float64(100000 * Pi)
	for i := 0; i < len(vf); i++ {
		f1, g1 := sinLarge[i], cosLarge[i]
		f2, g2 := Sincos(vf[i] + large)
		if !close(f1, f2) || !close(g1, g2) {
			t.Errorf("Sincos(%g) = %g, %g, want %g, %g", vf[i]+large, f2, g2, f1, g1)
		}
	}
}

func TestLargeTan(t *testing.T) {
	large := float64(100000 * Pi)
	for i := 0; i < len(vf); i++ {
		f1 := tanLarge[i]
		f2 := Tan(vf[i] + large)
		if !close(f1, f2) {
			t.Errorf("Tan(%g) = %g, want %g", vf[i]+large, f2, f1)
		}
	}
}

// Check that trigReduce matches the standard reduction results for input values
// below reduceThreshold.
func TestTrigReduce(t *testing.T) {
	inputs := make([]float64, len(vf))
	// all of the standard inputs
	copy(inputs, vf)
	// all of the large inputs
	large := float64(100000 * Pi)
	for _, v := range vf {
		inputs = append(inputs, v+large)
	}
	// Also test some special inputs, Pi and right below the reduceThreshold
	inputs = append(inputs, Pi, Nextafter(ReduceThreshold, 0))
	for _, x := range inputs {
		// reduce the value to compare
		j, z := TrigReduce(x)
		xred := float64(j)*(Pi/4) + z

		if f, fred := Sin(x), Sin(xred); !close(f, fred) {
			t.Errorf("Sin(trigReduce(%g)) != Sin(%g), got %g, want %g", x, x, fred, f)
		}
		if f, fred := Cos(x), Cos(xred); !close(f, fred) {
			t.Errorf("Cos(trigReduce(%g)) != Cos(%g), got %g, want %g", x, x, fred, f)
		}
		if f, fred := Tan(x), Tan(xred); !close(f, fred) {
			t.Errorf(" Tan(trigReduce(%g)) != Tan(%g), got %g, want %g", x, x, fred, f)
		}
		f, g := Sincos(x)
		fred, gred := Sincos(xred)
		if !close(f, fred) || !close(g, gred) {
			t.Errorf(" Sincos(trigReduce(%g)) != Sincos(%g), got %g, %g, want %g, %g", x, x, fred, gred, f, g)
		}
	}
}

// Check that math constants are accepted by compiler
// and have right value (assumes strconv.ParseFloat works).
// https://golang.org/issue/201

type floatTest struct {
	val  any
	name string
	str  string
}

var floatTests = []floatTest{
	{float64(MaxFloat64), "MaxFloat64", "1.7976931348623157e+308"},
	{float64(SmallestNonzeroFloat64), "SmallestNonzeroFloat64", "5e-324"},
	{float32(MaxFloat32), "MaxFloat32", "3.4028235e+38"},
	{float32(SmallestNonzeroFloat32), "SmallestNonzeroFloat32", "1e-45"},
}

func TestFloatMinMax(t *testing.T) {
	for _, tt := range floatTests {
		s := fmt.Sprint(tt.val)
		if s != tt.str {
			t.Errorf("Sprint(%v) = %s, want %s", tt.name, s, tt.str)
		}
	}
}

func TestFloatMinima(t *testing.T) {
	if q := float32(SmallestNonzeroFloat32 / 2); q != 0 {
		t.Errorf("float32(SmallestNonzeroFloat32 / 2) = %g, want 0", q)
	}
	if q := float64(SmallestNonzeroFloat64 / 2); q != 0 {
		t.Errorf("float64(SmallestNonzeroFloat64 / 2) = %g, want 0", q)
	}
}

var indirectSqrt = Sqrt

// TestFloat32Sqrt checks the correctness of the float32 square root optimization result.
func TestFloat32Sqrt(t *testing.T) {
	for _, v := range sqrt32 {
		want := float32(indirectSqrt(float64(v)))
		got := float32(Sqrt(float64(v)))
		if IsNaN(float64(want)) {
			if !IsNaN(float64(got)) {
				t.Errorf("got=%#v want=NaN, v=%#v", got, v)
			}
			continue
		}
		if got != want {
			t.Errorf("got=%#v want=%#v, v=%#v", got, want, v)
		}
	}
}

// Benchmarks

// Global exported variables are used to store the
// return values of functions measured in the benchmarks.
// Storing the results in these variables prevents the compiler
// from completely optimizing the benchmarked functions away.
var (
	GlobalI int
	GlobalB bool
	GlobalF float64
)

func BenchmarkAcos(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Acos(.5)
	}
	GlobalF = x
}

func BenchmarkAcosh(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Acosh(1.5)
	}
	GlobalF = x
}

func BenchmarkAsin(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Asin(.5)
	}
	GlobalF = x
}

func BenchmarkAsinh(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Asinh(.5)
	}
	GlobalF = x
}

func BenchmarkAtan(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Atan(.5)
	}
	GlobalF = x
}

func BenchmarkAtanh(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Atanh(.5)
	}
	GlobalF = x
}

func BenchmarkAtan2(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Atan2(.5, 1)
	}
	GlobalF = x
}

func BenchmarkCbrt(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Cbrt(10)
	}
	GlobalF = x
}

func BenchmarkCeil(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Ceil(.5)
	}
	GlobalF = x
}

var copysignNeg = -1.0

func BenchmarkCopysign(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Copysign(.5, copysignNeg)
	}
	GlobalF = x
}

func BenchmarkCos(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Cos(.5)
	}
	GlobalF = x
}

func BenchmarkCosh(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Cosh(2.5)
	}
	GlobalF = x
}

func BenchmarkErf(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Erf(.5)
	}
	GlobalF = x
}

func BenchmarkErfc(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Erfc(.5)
	}
	GlobalF = x
}

func BenchmarkErfinv(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Erfinv(.5)
	}
	GlobalF = x
}

func BenchmarkErfcinv(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Erfcinv(.5)
	}
	GlobalF = x
}

func BenchmarkExp(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Exp(.5)
	}
	GlobalF = x
}

func BenchmarkExpGo(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = ExpGo(.5)
	}
	GlobalF = x
}

func BenchmarkExpm1(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Expm1(.5)
	}
	GlobalF = x
}

func BenchmarkExp2(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Exp2(.5)
	}
	GlobalF = x
}

func BenchmarkExp2Go(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Exp2Go(.5)
	}
	GlobalF = x
}

var absPos = .5

func BenchmarkAbs(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Abs(absPos)
	}
	GlobalF = x

}

func BenchmarkDim(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Dim(GlobalF, x)
	}
	GlobalF = x
}

func BenchmarkFloor(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Floor(.5)
	}
	GlobalF = x
}

func BenchmarkMax(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Max(10, 3)
	}
	GlobalF = x
}

func BenchmarkMin(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Min(10, 3)
	}
	GlobalF = x
}

func BenchmarkMod(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Mod(10, 3)
	}
	GlobalF = x
}

func BenchmarkFrexp(b *testing.B) {
	x := 0.0
	y := 0
	for i := 0; i < b.N; i++ {
		x, y = Frexp(8)
	}
	GlobalF = x
	GlobalI = y
}

func BenchmarkGamma(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Gamma(2.5)
	}
	GlobalF = x
}

func BenchmarkHypot(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Hypot(3, 4)
	}
	GlobalF = x
}

func BenchmarkHypotGo(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = HypotGo(3, 4)
	}
	GlobalF = x
}

func BenchmarkIlogb(b *testing.B) {
	x := 0
	for i := 0; i < b.N; i++ {
		x = Ilogb(.5)
	}
	GlobalI = x
}

func BenchmarkJ0(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = J0(2.5)
	}
	GlobalF = x
}

func BenchmarkJ1(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = J1(2.5)
	}
	GlobalF = x
}

func BenchmarkJn(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Jn(2, 2.5)
	}
	GlobalF = x
}

func BenchmarkLdexp(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Ldexp(.5, 2)
	}
	GlobalF = x
}

func BenchmarkLgamma(b *testing.B) {
	x := 0.0
	y := 0
	for i := 0; i < b.N; i++ {
		x, y = Lgamma(2.5)
	}
	GlobalF = x
	GlobalI = y
}

func BenchmarkLog(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Log(.5)
	}
	GlobalF = x
}

func BenchmarkLogb(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Logb(.5)
	}
	GlobalF = x
}

func BenchmarkLog1p(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Log1p(.5)
	}
	GlobalF = x
}

func BenchmarkLog10(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Log10(.5)
	}
	GlobalF = x
}

func BenchmarkLog2(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Log2(.5)
	}
	GlobalF += x
}

func BenchmarkModf(b *testing.B) {
	x := 0.0
	y := 0.0
	for i := 0; i < b.N; i++ {
		x, y = Modf(1.5)
	}
	GlobalF += x
	GlobalF += y
}

func BenchmarkNextafter32(b *testing.B) {
	x := float32(0.0)
	for i := 0; i < b.N; i++ {
		x = Nextafter32(.5, 1)
	}
	GlobalF = float64(x)
}

func BenchmarkNextafter64(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Nextafter(.5, 1)
	}
	GlobalF = x
}

func BenchmarkPowInt(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Pow(2, 2)
	}
	GlobalF = x
}

func BenchmarkPowFrac(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Pow(2.5, 1.5)
	}
	GlobalF = x
}

var pow10pos = int(300)

func BenchmarkPow10Pos(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Pow10(pow10pos)
	}
	GlobalF = x
}

var pow10neg = int(-300)

func BenchmarkPow10Neg(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Pow10(pow10neg)
	}
	GlobalF = x
}

var roundNeg = float64(-2.5)

func BenchmarkRound(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Round(roundNeg)
	}
	GlobalF = x
}

func BenchmarkRoundToEven(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = RoundToEven(roundNeg)
	}
	GlobalF = x
}

func BenchmarkRemainder(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Remainder(10, 3)
	}
	GlobalF = x
}

var signbitPos = 2.5

func BenchmarkSignbit(b *testing.B) {
	x := false
	for i := 0; i < b.N; i++ {
		x = Signbit(signbitPos)
	}
	GlobalB = x
}

func BenchmarkSin(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Sin(.5)
	}
	GlobalF = x
}

func BenchmarkSincos(b *testing.B) {
	x := 0.0
	y := 0.0
	for i := 0; i < b.N; i++ {
		x, y = Sincos(.5)
	}
	GlobalF += x
	GlobalF += y
}

func BenchmarkSinh(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Sinh(2.5)
	}
	GlobalF = x
}

func BenchmarkSqrtIndirect(b *testing.B) {
	x, y := 0.0, 10.0
	f := Sqrt
	for i := 0; i < b.N; i++ {
		x += f(y)
	}
	GlobalF = x
}

func BenchmarkSqrtLatency(b *testing.B) {
	x := 10.0
	for i := 0; i < b.N; i++ {
		x = Sqrt(x)
	}
	GlobalF = x
}

func BenchmarkSqrtIndirectLatency(b *testing.B) {
	x := 10.0
	f := Sqrt
	for i := 0; i < b.N; i++ {
		x = f(x)
	}
	GlobalF = x
}

func BenchmarkSqrtGoLatency(b *testing.B) {
	x := 10.0
	for i := 0; i < b.N; i++ {
		x = SqrtGo(x)
	}
	GlobalF = x
}

func isPrime(i int) bool {
	// Yes, this is a dumb way to write this code,
	// but calling Sqrt repeatedly in this way demonstrates
	// the benefit of using a direct SQRT instruction on systems
	// that have one, whereas the obvious loop seems not to
	// demonstrate such a benefit.
	for j := 2; float64(j) <= Sqrt(float64(i)); j++ {
		if i%j == 0 {
			return false
		}
	}
	return true
}

func BenchmarkSqrtPrime(b *testing.B) {
	x := false
	for i := 0; i < b.N; i++ {
		x = isPrime(100003)
	}
	GlobalB = x
}

func BenchmarkTan(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Tan(.5)
	}
	GlobalF = x
}

func BenchmarkTanh(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Tanh(2.5)
	}
	GlobalF = x
}
func BenchmarkTrunc(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Trunc(.5)
	}
	GlobalF = x
}

func BenchmarkY0(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Y0(2.5)
	}
	GlobalF = x
}

func BenchmarkY1(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Y1(2.5)
	}
	GlobalF = x
}

func BenchmarkYn(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Yn(2, 2.5)
	}
	GlobalF = x
}

func BenchmarkFloat64bits(b *testing.B) {
	y := uint64(0)
	for i := 0; i < b.N; i++ {
		y = Float64bits(roundNeg)
	}
	GlobalI = int(y)
}

var roundUint64 = uint64(5)

func BenchmarkFloat64frombits(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = Float64frombits(roundUint64)
	}
	GlobalF = x
}

var roundFloat32 = float32(-2.5)

func BenchmarkFloat32bits(b *testing.B) {
	y := uint32(0)
	for i := 0; i < b.N; i++ {
		y = Float32bits(roundFloat32)
	}
	GlobalI = int(y)
}

var roundUint32 = uint32(5)

func BenchmarkFloat32frombits(b *testing.B) {
	x := float32(0.0)
	for i := 0; i < b.N; i++ {
		x = Float32frombits(roundUint32)
	}
	GlobalF = float64(x)
}

func BenchmarkFMA(b *testing.B) {
	x := 0.0
	for i := 0; i < b.N; i++ {
		x = FMA(E, Pi, x)
	}
	GlobalF = x
}

"""




```