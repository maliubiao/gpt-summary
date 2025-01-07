Response:
Let's break down the thought process for answering the request about the Go test file.

1. **Understand the Goal:** The core request is to analyze a Go test file (`arith_s390x_test.go`) and explain its purpose, functionality, and potential pitfalls.

2. **Initial Scan and High-Level Understanding:**  Read through the code quickly to get a general idea. Key observations:
    * It's a test file (`_test.go`).
    * It imports the `math` package.
    * There are many functions named `Test...Novec`.
    * Each test function seems to iterate through some data (`vf`, `vfcosSC`, etc.).
    * There are calls to functions like `CosNoVec`, `SinNoVec`, etc.
    * There's a check for `HasVX`.

3. **Identify the Core Functionality:** The `Novec` suffix on the test functions strongly suggests that these tests are specifically for the *non-vectorized* implementations of math functions. The `if !HasVX` checks confirm this – the tests are skipped if vector instructions are not available. This immediately leads to the idea that the `math` package likely has both vectorized and non-vectorized implementations for certain architectures (like s390x).

4. **Analyze Individual Test Functions:**  Pick a few representative test functions and understand their structure:
    * **`TestCosNovec`:** Tests `CosNoVec` by comparing its output with expected values stored in `cos` and `cosSC`. The `veryclose` and `alike` functions likely handle floating-point comparisons with different tolerances.
    * **`TestCoshNovec`:** Similar to `TestCosNovec`, but for `CoshNoVec`.
    * **`TestLargeCosNovec`:** Tests `CosNoVec` with large input values, suggesting potential edge cases related to precision.
    * **`TestLog10Novec`:** Tests `Log10NoVec`, including a specific test case with `E`.
    * **`TestAtan2Novec`:** Tests `Atan2NoVec`, which takes two arguments.

5. **Infer the Purpose of the File:**  Based on the structure and the `Novec` naming convention, the primary function of this test file is to ensure that the non-vectorized implementations of common mathematical functions (`Cos`, `Sin`, `Log`, etc.) in the `math` package work correctly on s390x architecture, *even when vector instructions are available*. This is important for maintaining accuracy and potentially for fallback scenarios.

6. **Deduce the "Go Language Feature":**  The key Go language feature being tested here is the ability to have architecture-specific implementations of functions. The existence of `...Novec` functions implies that there are corresponding vector implementations, likely without the `Novec` suffix (e.g., `Cos`). Go's build system and conditional compilation (though not directly visible in this snippet) enable selecting the appropriate implementation based on the target architecture.

7. **Construct Example Code:**  To illustrate the concept, create a simple Go program that demonstrates calling the `math.Cos` function. Emphasize that on s390x with vector support, this call *might* use the vectorized version, while the tests specifically target the non-vectorized version.

8. **Address Specific Questions:**
    * **Functionality Listing:** Summarize the purpose of each `Test...Novec` function.
    * **Code Example:**  Provide the simple `math.Cos` example.
    * **Input/Output (Hypothetical):** While the test code *has* inputs and outputs, they are within the test data (`vf`, `cos`, etc.). Since we don't have the *definitions* of these variables, we can only provide a *general* example of how `CosNoVec` might be used and what kind of output to expect. *Initially, I considered trying to reverse-engineer the test data, but realized it's unnecessary and could be inaccurate. Focus on the *concept*.*
    * **Command-Line Arguments:**  Standard Go tests don't usually involve specific command-line arguments in the way some other programs do. Mention the common `go test` command and the `-v` flag for verbose output.
    * **User Mistakes:** The most likely mistake is assuming that `math.Cos` and `CosNoVec` are interchangeable. Explain that `CosNoVec` is for a specific purpose (testing the non-vectorized version) and shouldn't be used directly in typical code.

9. **Refine and Organize:** Review the entire answer for clarity, accuracy, and completeness. Ensure it flows logically and addresses all parts of the request. Use clear and concise language. Specifically, make sure the explanation of *why* these tests exist is clear.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the `Novec` functions are slower versions for compatibility?  **Correction:** The code explicitly checks for `HasVX` and skips if it's false, suggesting the `Novec` versions are the *default* when vector instructions aren't available. The tests are ensuring they work even when vectorization *is* possible.
* **Initial thought:** Should I try to guess the values in `vf`, `cos`, etc.? **Correction:**  No, that's not the point of the request. The focus is on the *purpose* and *structure* of the tests. Providing a general example of using `math.Cos` is more helpful.
* **Consideration:** Should I mention the build tags that might be involved? **Decision:** While build tags are relevant to architecture-specific code, they aren't directly visible in the provided snippet. Keep the explanation focused on what the code *shows*.

By following these steps, combining code analysis with logical deduction, and refining the answer, we arrive at the comprehensive explanation provided previously.
这个 `go/src/math/arith_s390x_test.go` 文件是 Go 语言标准库 `math` 包的一部分，专门用于测试在 s390x 架构上的数学函数的**非向量化 (non-vectorized)** 实现。

**功能列举:**

1. **测试非向量化数学函数:** 该文件中的测试函数，例如 `TestCosNovec`, `TestSinNovec`, `TestLogNovec` 等，都带有 `Novec` 后缀，明确指出它们测试的是 `math` 包中不使用向量指令优化的版本。
2. **确保在支持向量指令的机器上的正确性:** 文件开头的注释说明了其目的：即使在支持向量指令的机器上运行测试，也要确保非向量化的例程能够正常工作。这暗示了 `math` 包可能针对 s390x 架构同时提供了向量化和非向量化的实现。
3. **覆盖多种数学函数:** 该文件测试了多种常见的数学函数，包括三角函数 (Cos, Sin, Tan, Cosh, Sinh, Tanh, Acos, Asin, Atan, Atan2)，对数和指数函数 (Log, Log10, Log1p, Exp, Expm1)，幂函数 (Pow)，以及其他特殊函数 (Erf, Erfc, Cbrt, Atanh, Acosh, Asinh)。
4. **测试特殊情况和边界情况:**  除了常规测试用例外，文件中还包含针对大数值的测试 (例如 `TestLargeCosNovec`, `TestLargeSinNovec`, `TestLargeTanNovec`)，以及使用预定义的特殊测试用例 (`vfcosSC`, `vfsinSC` 等) 来验证函数在特定输入下的行为。
5. **使用不同的精度比较方法:**  代码中使用了 `veryclose` 和 `alike` 两种函数来比较浮点数结果。这表明对于不同的函数或不同的输入范围，可能需要不同的精度要求。 `veryclose` 可能是更严格的比较，而 `alike` 可能用于比较一些已知特殊值的相等性。
6. **架构特定测试:**  文件名中的 `s390x` 表明这些测试是针对 IBM System z (s390x) 架构的。代码中使用 `if !HasVX { t.Skipf("no vector support") }` 来跳过在不支持向量扩展 (VX) 的 s390x 机器上的测试，进一步证实了这一点。这说明 `math` 包在 s390x 上可能存在利用向量指令优化的实现。

**推理 Go 语言功能实现 (架构特定实现):**

该文件测试的是 `math` 包中非向量化的实现，这意味着 `math` 包很可能为 s390x 架构提供了**架构特定的函数实现**。Go 语言允许开发者根据不同的操作系统和架构提供不同的代码实现。

**Go 代码举例说明:**

假设 `math` 包内部有以下结构（简化说明）：

```go
package math

//go:build !s390x || !vx

// Cos 计算余弦值 (非向量化实现)
func Cos(x float64) float64 {
	// ... 非向量化的余弦计算逻辑 ...
	return 0.0
}

//go:build s390x && vx

// Cos 计算余弦值 (向量化实现)
func Cos(x float64) float64 {
	// ... 使用向量指令优化的余弦计算逻辑 ...
	return 0.0
}

// CosNoVec 是非向量化的 Cos 函数，用于测试
func CosNoVec(x float64) float64 {
	return cosNovec(x) // 实际调用非向量化实现
}

// cosNovec 实际的非向量化实现 (假设存在)
func cosNovec(x float64) float64 {
	// ... 非向量化的余弦计算逻辑 ...
	return 0.0
}
```

**假设的输入与输出:**

假设 `vf` 数组中包含一些测试用的浮点数，`cos` 数组中包含这些浮点数对应的余弦值的期望结果。

**输入:** `vf = []float64{0, Pi/6, Pi/4, Pi/3, Pi/2}`
**输出 (期望):** `cos = []float64{1, 0.8660254037844386, 0.7071067811865476, 0.5, 0}`

在 `TestCosNovec` 函数中，会遍历 `vf` 数组，并调用 `CosNoVec` 函数，将结果与 `cos` 数组中的期望值进行比较。

```go
func TestCosNovec(t *testing.T) {
	// ... 省略 ...
	vf := []float64{0, Pi / 6, Pi / 4, Pi / 3, Pi / 2}
	cos := []float64{1, 0.8660254037844386, 0.7071067811865476, 0.5, 0}
	for i := 0; i < len(vf); i++ {
		if f := CosNoVec(vf[i]); !veryclose(cos[i], f) {
			t.Errorf("Cos(%g) = %g, want %g", vf[i], f, cos[i])
		}
	}
	// ... 省略 ...
}
```

**命令行参数的具体处理:**

该测试文件本身是一个 Go 测试文件，它主要通过 Go 的测试工具链 `go test` 来运行。通常不需要传递特定的命令行参数来运行这些测试。

常见的 `go test` 命令及其相关参数：

* **`go test ./math`**:  运行 `math` 目录下的所有测试文件。
* **`go test -v ./math`**: 运行 `math` 目录下的所有测试文件，并显示详细的测试输出 (verbose)。这将显示每个测试函数是否通过。
* **`go test -run TestCosNovec ./math`**:  只运行 `math` 目录下名称匹配 `TestCosNovec` 的测试函数。
* **`go test -bench=. ./math`**: 运行 `math` 目录下的基准测试 (benchmark)。虽然这个文件没有基准测试，但这是一个常见的 `go test` 用法。
* **`go test -cpuprofile=cpu.prof -memprofile=mem.prof ./math`**: 运行测试并生成 CPU 和内存性能分析文件，用于性能分析。

**使用者易犯错的点:**

对于 `math/arith_s390x_test.go` 这个特定的测试文件，普通 Go 语言使用者不太会直接与之交互或犯错。它主要是 Go 语言开发人员用来保证 `math` 包在特定架构上的正确性。

但是，可以从更广的角度理解，如果开发者尝试直接使用 `CosNoVec` 这样的函数，可能会犯错：

**错误示例:**

```go
package main

import (
	"fmt"
	"math"
)

func main() {
	// 错误用法：直接使用了测试文件中定义的 CosNoVec
	result := math.CosNoVec(math.Pi / 2)
	fmt.Println(result)
}
```

**说明:**

* `CosNoVec` 是测试文件中定义的辅助函数，它的目的是为了**测试** `math.Cos` 的非向量化实现。
* 普通开发者应该使用 `math.Cos` 函数，Go 语言的构建系统会自动根据目标架构选择合适的实现 (向量化或非向量化)。
* 直接使用 `CosNoVec` 会限制代码只使用非向量化的版本，可能会损失性能。

**总结:**

`go/src/math/arith_s390x_test.go` 是 `math` 包中一个重要的测试文件，它专门用于验证 s390x 架构上数学函数的非向量化实现的正确性。这体现了 Go 语言对不同架构的支持以及对代码质量的严格要求。普通 Go 开发者无需直接关注此文件，但了解其作用有助于理解 Go 标准库的实现细节和测试方法。

Prompt: 
```
这是路径为go/src/math/arith_s390x_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests whether the non vector routines are working, even when the tests are run on a
// vector-capable machine.
package math_test

import (
	. "math"
	"testing"
)

func TestCosNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := CosNoVec(vf[i]); !veryclose(cos[i], f) {
			t.Errorf("Cos(%g) = %g, want %g", vf[i], f, cos[i])
		}
	}
	for i := 0; i < len(vfcosSC); i++ {
		if f := CosNoVec(vfcosSC[i]); !alike(cosSC[i], f) {
			t.Errorf("Cos(%g) = %g, want %g", vfcosSC[i], f, cosSC[i])
		}
	}
}

func TestCoshNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := CoshNoVec(vf[i]); !close(cosh[i], f) {
			t.Errorf("Cosh(%g) = %g, want %g", vf[i], f, cosh[i])
		}
	}
	for i := 0; i < len(vfcoshSC); i++ {
		if f := CoshNoVec(vfcoshSC[i]); !alike(coshSC[i], f) {
			t.Errorf("Cosh(%g) = %g, want %g", vfcoshSC[i], f, coshSC[i])
		}
	}
}
func TestSinNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := SinNoVec(vf[i]); !veryclose(sin[i], f) {
			t.Errorf("Sin(%g) = %g, want %g", vf[i], f, sin[i])
		}
	}
	for i := 0; i < len(vfsinSC); i++ {
		if f := SinNoVec(vfsinSC[i]); !alike(sinSC[i], f) {
			t.Errorf("Sin(%g) = %g, want %g", vfsinSC[i], f, sinSC[i])
		}
	}
}

func TestSinhNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := SinhNoVec(vf[i]); !close(sinh[i], f) {
			t.Errorf("Sinh(%g) = %g, want %g", vf[i], f, sinh[i])
		}
	}
	for i := 0; i < len(vfsinhSC); i++ {
		if f := SinhNoVec(vfsinhSC[i]); !alike(sinhSC[i], f) {
			t.Errorf("Sinh(%g) = %g, want %g", vfsinhSC[i], f, sinhSC[i])
		}
	}
}

// Check that math functions of high angle values
// return accurate results. [Since (vf[i] + large) - large != vf[i],
// testing for Trig(vf[i] + large) == Trig(vf[i]), where large is
// a multiple of 2*Pi, is misleading.]
func TestLargeCosNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	large := float64(100000 * Pi)
	for i := 0; i < len(vf); i++ {
		f1 := cosLarge[i]
		f2 := CosNoVec(vf[i] + large)
		if !close(f1, f2) {
			t.Errorf("Cos(%g) = %g, want %g", vf[i]+large, f2, f1)
		}
	}
}

func TestLargeSinNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	large := float64(100000 * Pi)
	for i := 0; i < len(vf); i++ {
		f1 := sinLarge[i]
		f2 := SinNoVec(vf[i] + large)
		if !close(f1, f2) {
			t.Errorf("Sin(%g) = %g, want %g", vf[i]+large, f2, f1)
		}
	}
}

func TestLargeTanNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	large := float64(100000 * Pi)
	for i := 0; i < len(vf); i++ {
		f1 := tanLarge[i]
		f2 := TanNovec(vf[i] + large)
		if !close(f1, f2) {
			t.Errorf("Tan(%g) = %g, want %g", vf[i]+large, f2, f1)
		}
	}
}

func TestTanNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := TanNovec(vf[i]); !veryclose(tan[i], f) {
			t.Errorf("Tan(%g) = %g, want %g", vf[i], f, tan[i])
		}
	}
	// same special cases as Sin
	for i := 0; i < len(vfsinSC); i++ {
		if f := TanNovec(vfsinSC[i]); !alike(sinSC[i], f) {
			t.Errorf("Tan(%g) = %g, want %g", vfsinSC[i], f, sinSC[i])
		}
	}
}

func TestTanhNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := TanhNoVec(vf[i]); !veryclose(tanh[i], f) {
			t.Errorf("Tanh(%g) = %g, want %g", vf[i], f, tanh[i])
		}
	}
	for i := 0; i < len(vftanhSC); i++ {
		if f := TanhNoVec(vftanhSC[i]); !alike(tanhSC[i], f) {
			t.Errorf("Tanh(%g) = %g, want %g", vftanhSC[i], f, tanhSC[i])
		}
	}

}

func TestLog10Novec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := Abs(vf[i])
		if f := Log10NoVec(a); !veryclose(log10[i], f) {
			t.Errorf("Log10(%g) = %g, want %g", a, f, log10[i])
		}
	}
	if f := Log10NoVec(E); f != Log10E {
		t.Errorf("Log10(%g) = %g, want %g", E, f, Log10E)
	}
	for i := 0; i < len(vflogSC); i++ {
		if f := Log10NoVec(vflogSC[i]); !alike(logSC[i], f) {
			t.Errorf("Log10(%g) = %g, want %g", vflogSC[i], f, logSC[i])
		}
	}
}

func TestLog1pNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 100
		if f := Log1pNovec(a); !veryclose(log1p[i], f) {
			t.Errorf("Log1p(%g) = %g, want %g", a, f, log1p[i])
		}
	}
	a := 9.0
	if f := Log1pNovec(a); f != Ln10 {
		t.Errorf("Log1p(%g) = %g, want %g", a, f, Ln10)
	}
	for i := 0; i < len(vflogSC); i++ {
		if f := Log1pNovec(vflog1pSC[i]); !alike(log1pSC[i], f) {
			t.Errorf("Log1p(%g) = %g, want %g", vflog1pSC[i], f, log1pSC[i])
		}
	}
}

func TestAtanhNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := AtanhNovec(a); !veryclose(atanh[i], f) {
			t.Errorf("Atanh(%g) = %g, want %g", a, f, atanh[i])
		}
	}
	for i := 0; i < len(vfatanhSC); i++ {
		if f := AtanhNovec(vfatanhSC[i]); !alike(atanhSC[i], f) {
			t.Errorf("Atanh(%g) = %g, want %g", vfatanhSC[i], f, atanhSC[i])
		}
	}
}

func TestAcosNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := AcosNovec(a); !close(acos[i], f) {
			t.Errorf("Acos(%g) = %g, want %g", a, f, acos[i])
		}
	}
	for i := 0; i < len(vfacosSC); i++ {
		if f := AcosNovec(vfacosSC[i]); !alike(acosSC[i], f) {
			t.Errorf("Acos(%g) = %g, want %g", vfacosSC[i], f, acosSC[i])
		}
	}
}

func TestAsinNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := AsinNovec(a); !veryclose(asin[i], f) {
			t.Errorf("Asin(%g) = %g, want %g", a, f, asin[i])
		}
	}
	for i := 0; i < len(vfasinSC); i++ {
		if f := AsinNovec(vfasinSC[i]); !alike(asinSC[i], f) {
			t.Errorf("Asin(%g) = %g, want %g", vfasinSC[i], f, asinSC[i])
		}
	}
}

func TestAcoshNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := 1 + Abs(vf[i])
		if f := AcoshNovec(a); !veryclose(acosh[i], f) {
			t.Errorf("Acosh(%g) = %g, want %g", a, f, acosh[i])
		}
	}
	for i := 0; i < len(vfacoshSC); i++ {
		if f := AcoshNovec(vfacoshSC[i]); !alike(acoshSC[i], f) {
			t.Errorf("Acosh(%g) = %g, want %g", vfacoshSC[i], f, acoshSC[i])
		}
	}
}

func TestAsinhNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := AsinhNovec(vf[i]); !veryclose(asinh[i], f) {
			t.Errorf("Asinh(%g) = %g, want %g", vf[i], f, asinh[i])
		}
	}
	for i := 0; i < len(vfasinhSC); i++ {
		if f := AsinhNovec(vfasinhSC[i]); !alike(asinhSC[i], f) {
			t.Errorf("Asinh(%g) = %g, want %g", vfasinhSC[i], f, asinhSC[i])
		}
	}
}

func TestErfNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := ErfNovec(a); !veryclose(erf[i], f) {
			t.Errorf("Erf(%g) = %g, want %g", a, f, erf[i])
		}
	}
	for i := 0; i < len(vferfSC); i++ {
		if f := ErfNovec(vferfSC[i]); !alike(erfSC[i], f) {
			t.Errorf("Erf(%g) = %g, want %g", vferfSC[i], f, erfSC[i])
		}
	}
}

func TestErfcNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := ErfcNovec(a); !veryclose(erfc[i], f) {
			t.Errorf("Erfc(%g) = %g, want %g", a, f, erfc[i])
		}
	}
	for i := 0; i < len(vferfcSC); i++ {
		if f := ErfcNovec(vferfcSC[i]); !alike(erfcSC[i], f) {
			t.Errorf("Erfc(%g) = %g, want %g", vferfcSC[i], f, erfcSC[i])
		}
	}
}

func TestAtanNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := AtanNovec(vf[i]); !veryclose(atan[i], f) {
			t.Errorf("Atan(%g) = %g, want %g", vf[i], f, atan[i])
		}
	}
	for i := 0; i < len(vfatanSC); i++ {
		if f := AtanNovec(vfatanSC[i]); !alike(atanSC[i], f) {
			t.Errorf("Atan(%g) = %g, want %g", vfatanSC[i], f, atanSC[i])
		}
	}
}

func TestAtan2Novec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := Atan2Novec(10, vf[i]); !veryclose(atan2[i], f) {
			t.Errorf("Atan2(10, %g) = %g, want %g", vf[i], f, atan2[i])
		}
	}
	for i := 0; i < len(vfatan2SC); i++ {
		if f := Atan2Novec(vfatan2SC[i][0], vfatan2SC[i][1]); !alike(atan2SC[i], f) {
			t.Errorf("Atan2(%g, %g) = %g, want %g", vfatan2SC[i][0], vfatan2SC[i][1], f, atan2SC[i])
		}
	}
}

func TestCbrtNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := CbrtNovec(vf[i]); !veryclose(cbrt[i], f) {
			t.Errorf("Cbrt(%g) = %g, want %g", vf[i], f, cbrt[i])
		}
	}
	for i := 0; i < len(vfcbrtSC); i++ {
		if f := CbrtNovec(vfcbrtSC[i]); !alike(cbrtSC[i], f) {
			t.Errorf("Cbrt(%g) = %g, want %g", vfcbrtSC[i], f, cbrtSC[i])
		}
	}
}

func TestLogNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := Abs(vf[i])
		if f := LogNovec(a); log[i] != f {
			t.Errorf("Log(%g) = %g, want %g", a, f, log[i])
		}
	}
	if f := LogNovec(10); f != Ln10 {
		t.Errorf("Log(%g) = %g, want %g", 10.0, f, Ln10)
	}
	for i := 0; i < len(vflogSC); i++ {
		if f := LogNovec(vflogSC[i]); !alike(logSC[i], f) {
			t.Errorf("Log(%g) = %g, want %g", vflogSC[i], f, logSC[i])
		}
	}
}

func TestExpNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	testExpNovec(t, Exp, "Exp")
	testExpNovec(t, ExpGo, "ExpGo")
}

func testExpNovec(t *testing.T, Exp func(float64) float64, name string) {
	for i := 0; i < len(vf); i++ {
		if f := ExpNovec(vf[i]); !veryclose(exp[i], f) {
			t.Errorf("%s(%g) = %g, want %g", name, vf[i], f, exp[i])
		}
	}
	for i := 0; i < len(vfexpSC); i++ {
		if f := ExpNovec(vfexpSC[i]); !alike(expSC[i], f) {
			t.Errorf("%s(%g) = %g, want %g", name, vfexpSC[i], f, expSC[i])
		}
	}
}

func TestExpm1Novec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 100
		if f := Expm1Novec(a); !veryclose(expm1[i], f) {
			t.Errorf("Expm1(%g) = %g, want %g", a, f, expm1[i])
		}
	}
	for i := 0; i < len(vf); i++ {
		a := vf[i] * 10
		if f := Expm1Novec(a); !close(expm1Large[i], f) {
			t.Errorf("Expm1(%g) = %g, want %g", a, f, expm1Large[i])
		}
	}
	for i := 0; i < len(vfexpm1SC); i++ {
		if f := Expm1Novec(vfexpm1SC[i]); !alike(expm1SC[i], f) {
			t.Errorf("Expm1(%g) = %g, want %g", vfexpm1SC[i], f, expm1SC[i])
		}
	}
}

func TestPowNovec(t *testing.T) {
	if !HasVX {
		t.Skipf("no vector support")
	}
	for i := 0; i < len(vf); i++ {
		if f := PowNovec(10, vf[i]); !close(pow[i], f) {
			t.Errorf("Pow(10, %g) = %g, want %g", vf[i], f, pow[i])
		}
	}
	for i := 0; i < len(vfpowSC); i++ {
		if f := PowNovec(vfpowSC[i][0], vfpowSC[i][1]); !alike(powSC[i], f) {
			t.Errorf("Pow(%g, %g) = %g, want %g", vfpowSC[i][0], vfpowSC[i][1], f, powSC[i])
		}
	}
}

"""



```