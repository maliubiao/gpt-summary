Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The first step is to recognize that this is a *test file* within the Go compiler (`cmd/compile/internal/ssa`). The file name `rewriteCond_test.go` strongly suggests it's testing the *rewriting of conditional expressions* within the SSA (Static Single Assignment) intermediate representation. This immediately tells us the code isn't about general Go programming but specifically about compiler optimizations.

2. **Identify Key Components:**  Scan the code for important elements:
    * **`package ssa`:** Confirms the location within the compiler.
    * **`import` statements:**  Shows dependencies on `math`, `math/rand`, and `testing`. This indicates it involves numerical tests and benchmarking.
    * **Global Variables:**  The `x64`, `y64`, `x32`, `y32`, `one64`, `one32`, `v64`, `v32`, `uv32`, `uz` variables are clearly test data, representing boundary cases and specific values for different integer types. The names hint at their sizes (64-bit, 32-bit) and purpose (e.g., `one`, `v` for variable).
    * **`crTests` and `crBenches`:** These slices of structs are the heart of the testing and benchmarking setup. They define the individual test and benchmark functions to be executed. The names of the tests (e.g., `AddConst64`, `AddVar32`, `MSubVar64`) give a good idea of what's being tested: arithmetic operations with constants and variables.
    * **`TestCondRewrite` function:**  This is the main test runner, iterating through the `crTests`.
    * **`BenchmarkCondRewrite` function:** This is the main benchmark runner, iterating through `crBenches`.
    * **Individual `test...` functions:** These are the actual test cases. They contain `if` statements with conditional expressions involving the global variables. The `t.Errorf` calls indicate that the tests are verifying the *truthiness* or *falsiness* of these conditions.
    * **Individual `bench...` functions:** These are the benchmark cases. They involve loops with conditional expressions and a `sink` variable to prevent dead-code elimination. The `SoloJump` and `CombJump` names suggest different patterns of conditional jumps being measured.

3. **Infer Functionality (Based on Test Cases):**  The structure of the `test...` functions is crucial. They all follow a similar pattern: perform an arithmetic operation (addition, subtraction, multiplication), and then check the result against zero using various comparison operators (`<`, `<=`, `>`, `>=`). The `t.Errorf` calls are placed in the `else` blocks for conditions that *should* be true and in the `if` blocks for conditions that *should* be false. This strongly suggests the tests are validating the compiler's ability to *correctly evaluate these conditional expressions*, especially around boundary conditions (like `math.MaxInt64`, `math.MinInt64`).

4. **Infer Go Language Feature:** Given that the tests are focused on comparisons after arithmetic operations, and considering the file's location within the compiler, the most likely Go language feature being tested is the **evaluation of conditional expressions in `if` statements** involving integer arithmetic, especially around boundary values and potential overflows/underflows. The comments mentioning "optimization to 'comparing to zero' expressions of if-statements" and "Canonicalize the order of arguments to comparisons" provide explicit confirmation.

5. **Construct Go Code Examples:** Based on the `test...` functions, creating illustrative examples is straightforward. Pick a few of the tested scenarios and write simple Go code snippets that demonstrate the same conditional logic. Include the expected outcome in comments.

6. **Analyze Benchmarks:** The `benchSoloJump` and `benchCombJump` functions are designed to measure performance. The comments explain the expected behavior: `SoloJump` (using `<` and `>=`) should be more efficient due to the possibility of a single jump instruction, while `CombJump` (using `<=` and `>`) might require two jumps. This points to compiler optimizations related to branching.

7. **Consider Command Line Arguments:** Since this is a test file, it will be executed using the `go test` command. The standard `go test` flags (like `-v` for verbose output, `-bench` for running benchmarks, `-run` for running specific tests) will apply. No specific custom command-line arguments are defined within the file itself.

8. **Identify Potential Pitfalls:**  The primary focus of these tests is on compiler correctness. Therefore, common programmer errors related to integer overflow or incorrect comparison logic are relevant. Give concrete examples of how a programmer might write a seemingly correct condition that fails due to these issues, highlighting the importance of the compiler optimizations being tested.

9. **Review and Refine:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check if all parts of the code have been addressed. Ensure the examples are clear and directly relate to the tested scenarios.

This systematic approach, moving from understanding the context to identifying components and inferring functionality, allows for a comprehensive analysis of the provided Go code.这个文件 `go/src/cmd/compile/internal/ssa/rewriteCond_test.go` 是 Go 语言编译器的一部分， 专门用于测试 **SSA (Static Single Assignment) 中条件语句的重写规则 (rewrite rules)**。

更具体地说，它测试了编译器后端在生成机器码之前，对中间表示 SSA 中的条件表达式进行的优化。 这些优化旨在提高生成的机器码的效率，尤其是在处理整数的加减法和乘法运算时，通过将某些比较操作转换为与零的比较来简化分支指令。

**功能列表:**

1. **测试常量加减法的条件重写:** 针对 `int32` 和 `int64` 类型的变量与常量进行加减运算后的条件判断（例如 `x + 11 < 0`）。
2. **测试变量加减法的条件重写:** 针对 `int32` 和 `int64` 类型的变量与变量进行加减运算后的条件判断（例如 `x + v < 0`）。
3. **测试带副作用的条件重写 (Cset):**  验证即使在条件判断内部有赋值操作时，条件重写依然能够正确工作。
4. **测试乘法加法 (multiply-add) 的条件重写:** 针对 `int32` 和 `int64` 类型的 `x + y*1` 形式的条件判断。
5. **测试乘法减法 (multiply-sub) 的条件重写:** 针对 `int32` 和 `int64` 类型的 `x - y*1` 形式的条件判断。
6. **测试带位移操作的加减法条件重写:** 针对 `int32` 类型的变量与带位移操作的变量进行加减运算后的条件判断 (例如 `x + v<<1 < 0`)。
7. **性能基准测试:** 衡量优化后的条件语句与未优化或不同优化方式的性能差异。 `SoloJump` 基准测试针对可以优化为单次跳转的场景，而 `CombJump` 针对可能需要多次跳转的场景。

**它是什么Go语言功能的实现？**

这个文件测试的是 Go 编译器内部的优化功能，更准确地说，是 **SSA 中间表示的转换和优化**。  它并不直接对应于一个用户可见的 Go 语言特性，而是编译器为了生成更高效的目标代码而进行的幕后工作。

**Go 代码举例说明:**

```go
package main

import "fmt"

func main() {
	x := int64(math.MaxInt64 - 2)
	y := int64(math.MinInt64 + 1)

	// 假设编译器会将以下条件重写为与零的比较
	if x + 11 < 0 {
		fmt.Println("This should not be printed")
	} else {
		fmt.Println("x + 11 is not less than 0") // 预期输出
	}

	if y - 11 > 0 {
		fmt.Println("y - 11 is greater than 0") // 预期输出
	} else {
		fmt.Println("This should not be printed")
	}
}
```

**假设的输入与输出:**

在 `testAddConst64` 函数中，我们有以下测试用例：

* **输入:** `x64 = math.MaxInt64 - 2`
* **测试代码:**
  ```go
  if x64+11 < 0 {
  } else {
    t.Errorf("'%#x + 11 < 0' failed", x64)
  }
  ```
* **预期输出:** 由于 `math.MaxInt64 - 2 + 11` 的结果仍然是一个非常大的正数，因此条件 `x64 + 11 < 0` 应该为假，`t.Errorf` 不会被调用。

* **输入:** `y64 = math.MinInt64 + 1`
* **测试代码:**
  ```go
  if y64-11 > 0 {
  } else {
    t.Errorf("'%#x - 11 > 0' failed", y64)
  }
  ```
* **预期输出:** 由于 `math.MinInt64 + 1 - 11` 的结果是一个负数，因此条件 `y64 - 11 > 0` 应该为假，`t.Errorf` 不会被调用。

**命令行参数的具体处理:**

这个文件本身是一个测试文件，并不直接处理命令行参数。  它通过 `go test` 命令来运行。常用的 `go test` 命令参数包括：

* **`-v`**:  显示详细的测试输出。
* **`-run <regexp>`**:  运行名称匹配正则表达式的测试函数。 例如，`go test -run AddConst64` 只会运行 `testAddConst64` 这个测试函数。
* **`-bench <regexp>`**: 运行名称匹配正则表达式的基准测试函数。 例如，`go test -bench SoloJump` 只会运行 `benchSoloJump` 这个基准测试函数。
* **`-count n`**:  运行每个测试或基准测试 `n` 次。
* **`-cpuprofile <file>`**: 将 CPU 性能分析信息写入指定文件。
* **`-memprofile <file>`**: 将内存性能分析信息写入指定文件。

当运行基准测试时，`go test` 会自动进行多次迭代以获得更稳定的性能数据。 `testing.B` 类型提供了一些方法来控制基准测试的行为，例如 `b.N` 表示基准测试循环的次数。

**使用者易犯错的点 (针对条件重写优化的理解):**

对于一般的 Go 开发者来说，直接使用这部分编译器代码的可能性很小。然而，理解这种优化有助于开发者写出更易于编译器优化的代码。

一个潜在的误解是 **过度依赖或臆测编译器的优化行为**。虽然编译器会进行这些优化，但人为地去迎合某种特定的优化模式可能并不总是有效，甚至可能适得其反，降低代码的可读性。

例如，开发者可能会认为将所有的条件判断都写成与零比较的形式会更好，但实际上，Go 编译器会在适当的时候进行这样的转换。  清晰易懂的代码比刻意迎合编译器优化的代码更重要。

另一个潜在的误解是 **认为所有的比较操作都会被优化**。  这里的测试用例主要关注整数的加减法和乘法，以及与常量的比较。对于更复杂的比较操作或涉及浮点数的比较，编译器的优化策略可能会有所不同。

总结来说，`go/src/cmd/compile/internal/ssa/rewriteCond_test.go` 是 Go 编译器内部用于验证条件表达式重写优化是否正确工作的测试文件。它通过大量的测试用例覆盖了各种整数运算和比较的场景，确保编译器能够生成高效且正确的机器码。 理解这些测试背后的原理可以帮助开发者更好地理解编译器的工作方式，但编写代码时应优先考虑代码的清晰度和可维护性。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteCond_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"math"
	"math/rand"
	"testing"
)

var (
	x64   int64  = math.MaxInt64 - 2
	x64b  int64  = math.MaxInt64 - 2
	x64c  int64  = math.MaxInt64 - 2
	y64   int64  = math.MinInt64 + 1
	x32   int32  = math.MaxInt32 - 2
	x32b  int32  = math.MaxInt32 - 2
	x32c  int32  = math.MaxInt32 - 2
	y32   int32  = math.MinInt32 + 1
	one64 int64  = 1
	one32 int32  = 1
	v64   int64  = 11 // ensure it's not 2**n +/- 1
	v64_n int64  = -11
	v32   int32  = 11
	v32_n int32  = -11
	uv32  uint32 = 19
	uz    uint8  = 1 // for lowering to SLL/SRL/SRA
)

var crTests = []struct {
	name string
	tf   func(t *testing.T)
}{
	{"AddConst64", testAddConst64},
	{"AddConst32", testAddConst32},
	{"AddVar64", testAddVar64},
	{"AddVar64Cset", testAddVar64Cset},
	{"AddVar32", testAddVar32},
	{"MAddVar64", testMAddVar64},
	{"MAddVar32", testMAddVar32},
	{"MSubVar64", testMSubVar64},
	{"MSubVar32", testMSubVar32},
	{"AddShift32", testAddShift32},
	{"SubShift32", testSubShift32},
}

var crBenches = []struct {
	name string
	bf   func(b *testing.B)
}{
	{"SoloJump", benchSoloJump},
	{"CombJump", benchCombJump},
}

// Test int32/int64's add/sub/madd/msub operations with boundary values to
// ensure the optimization to 'comparing to zero' expressions of if-statements
// yield expected results.
// 32 rewriting rules are covered. At least two scenarios for "Canonicalize
// the order of arguments to comparisons", which helps with CSE, are covered.
// The tedious if-else structures are necessary to ensure all concerned rules
// and machine code sequences are covered.
// It's for arm64 initially, please see https://github.com/golang/go/issues/38740
func TestCondRewrite(t *testing.T) {
	for _, test := range crTests {
		t.Run(test.name, test.tf)
	}
}

// Profile the aforementioned optimization from two angles:
//
//	SoloJump: generated branching code has one 'jump', for '<' and '>='
//	CombJump: generated branching code has two consecutive 'jump', for '<=' and '>'
//
// We expect that 'CombJump' is generally on par with the non-optimized code, and
// 'SoloJump' demonstrates some improvement.
// It's for arm64 initially, please see https://github.com/golang/go/issues/38740
func BenchmarkCondRewrite(b *testing.B) {
	for _, bench := range crBenches {
		b.Run(bench.name, bench.bf)
	}
}

// var +/- const
func testAddConst64(t *testing.T) {
	if x64+11 < 0 {
	} else {
		t.Errorf("'%#x + 11 < 0' failed", x64)
	}

	if x64+13 <= 0 {
	} else {
		t.Errorf("'%#x + 13 <= 0' failed", x64)
	}

	if y64-11 > 0 {
	} else {
		t.Errorf("'%#x - 11 > 0' failed", y64)
	}

	if y64-13 >= 0 {
	} else {
		t.Errorf("'%#x - 13 >= 0' failed", y64)
	}

	if x64+19 > 0 {
		t.Errorf("'%#x + 19 > 0' failed", x64)
	}

	if x64+23 >= 0 {
		t.Errorf("'%#x + 23 >= 0' failed", x64)
	}

	if y64-19 < 0 {
		t.Errorf("'%#x - 19 < 0' failed", y64)
	}

	if y64-23 <= 0 {
		t.Errorf("'%#x - 23 <= 0' failed", y64)
	}
}

// 32-bit var +/- const
func testAddConst32(t *testing.T) {
	if x32+11 < 0 {
	} else {
		t.Errorf("'%#x + 11 < 0' failed", x32)
	}

	if x32+13 <= 0 {
	} else {
		t.Errorf("'%#x + 13 <= 0' failed", x32)
	}

	if y32-11 > 0 {
	} else {
		t.Errorf("'%#x - 11 > 0' failed", y32)
	}

	if y32-13 >= 0 {
	} else {
		t.Errorf("'%#x - 13 >= 0' failed", y32)
	}

	if x32+19 > 0 {
		t.Errorf("'%#x + 19 > 0' failed", x32)
	}

	if x32+23 >= 0 {
		t.Errorf("'%#x + 23 >= 0' failed", x32)
	}

	if y32-19 < 0 {
		t.Errorf("'%#x - 19 < 0' failed", y32)
	}

	if y32-23 <= 0 {
		t.Errorf("'%#x - 23 <= 0' failed", y32)
	}
}

// var + var
func testAddVar64(t *testing.T) {
	if x64+v64 < 0 {
	} else {
		t.Errorf("'%#x + %#x < 0' failed", x64, v64)
	}

	if x64+v64 <= 0 {
	} else {
		t.Errorf("'%#x + %#x <= 0' failed", x64, v64)
	}

	if y64+v64_n > 0 {
	} else {
		t.Errorf("'%#x + %#x > 0' failed", y64, v64_n)
	}

	if y64+v64_n >= 0 {
	} else {
		t.Errorf("'%#x + %#x >= 0' failed", y64, v64_n)
	}

	if x64+v64 > 0 {
		t.Errorf("'%#x + %#x > 0' failed", x64, v64)
	}

	if x64+v64 >= 0 {
		t.Errorf("'%#x + %#x >= 0' failed", x64, v64)
	}

	if y64+v64_n < 0 {
		t.Errorf("'%#x + %#x < 0' failed", y64, v64_n)
	}

	if y64+v64_n <= 0 {
		t.Errorf("'%#x + %#x <= 0' failed", y64, v64_n)
	}
}

// var + var, cset
func testAddVar64Cset(t *testing.T) {
	var a int
	if x64+v64 < 0 {
		a = 1
	}
	if a != 1 {
		t.Errorf("'%#x + %#x < 0' failed", x64, v64)
	}

	a = 0
	if y64+v64_n >= 0 {
		a = 1
	}
	if a != 1 {
		t.Errorf("'%#x + %#x >= 0' failed", y64, v64_n)
	}

	a = 1
	if x64+v64 >= 0 {
		a = 0
	}
	if a == 0 {
		t.Errorf("'%#x + %#x >= 0' failed", x64, v64)
	}

	a = 1
	if y64+v64_n < 0 {
		a = 0
	}
	if a == 0 {
		t.Errorf("'%#x + %#x < 0' failed", y64, v64_n)
	}
}

// 32-bit var+var
func testAddVar32(t *testing.T) {
	if x32+v32 < 0 {
	} else {
		t.Errorf("'%#x + %#x < 0' failed", x32, v32)
	}

	if x32+v32 <= 0 {
	} else {
		t.Errorf("'%#x + %#x <= 0' failed", x32, v32)
	}

	if y32+v32_n > 0 {
	} else {
		t.Errorf("'%#x + %#x > 0' failed", y32, v32_n)
	}

	if y32+v32_n >= 0 {
	} else {
		t.Errorf("'%#x + %#x >= 0' failed", y32, v32_n)
	}

	if x32+v32 > 0 {
		t.Errorf("'%#x + %#x > 0' failed", x32, v32)
	}

	if x32+v32 >= 0 {
		t.Errorf("'%#x + %#x >= 0' failed", x32, v32)
	}

	if y32+v32_n < 0 {
		t.Errorf("'%#x + %#x < 0' failed", y32, v32_n)
	}

	if y32+v32_n <= 0 {
		t.Errorf("'%#x + %#x <= 0' failed", y32, v32_n)
	}
}

// multiply-add
func testMAddVar64(t *testing.T) {
	if x64+v64*one64 < 0 {
	} else {
		t.Errorf("'%#x + %#x*1 < 0' failed", x64, v64)
	}

	if x64+v64*one64 <= 0 {
	} else {
		t.Errorf("'%#x + %#x*1 <= 0' failed", x64, v64)
	}

	if y64+v64_n*one64 > 0 {
	} else {
		t.Errorf("'%#x + %#x*1 > 0' failed", y64, v64_n)
	}

	if y64+v64_n*one64 >= 0 {
	} else {
		t.Errorf("'%#x + %#x*1 >= 0' failed", y64, v64_n)
	}

	if x64+v64*one64 > 0 {
		t.Errorf("'%#x + %#x*1 > 0' failed", x64, v64)
	}

	if x64+v64*one64 >= 0 {
		t.Errorf("'%#x + %#x*1 >= 0' failed", x64, v64)
	}

	if y64+v64_n*one64 < 0 {
		t.Errorf("'%#x + %#x*1 < 0' failed", y64, v64_n)
	}

	if y64+v64_n*one64 <= 0 {
		t.Errorf("'%#x + %#x*1 <= 0' failed", y64, v64_n)
	}
}

// 32-bit multiply-add
func testMAddVar32(t *testing.T) {
	if x32+v32*one32 < 0 {
	} else {
		t.Errorf("'%#x + %#x*1 < 0' failed", x32, v32)
	}

	if x32+v32*one32 <= 0 {
	} else {
		t.Errorf("'%#x + %#x*1 <= 0' failed", x32, v32)
	}

	if y32+v32_n*one32 > 0 {
	} else {
		t.Errorf("'%#x + %#x*1 > 0' failed", y32, v32_n)
	}

	if y32+v32_n*one32 >= 0 {
	} else {
		t.Errorf("'%#x + %#x*1 >= 0' failed", y32, v32_n)
	}

	if x32+v32*one32 > 0 {
		t.Errorf("'%#x + %#x*1 > 0' failed", x32, v32)
	}

	if x32+v32*one32 >= 0 {
		t.Errorf("'%#x + %#x*1 >= 0' failed", x32, v32)
	}

	if y32+v32_n*one32 < 0 {
		t.Errorf("'%#x + %#x*1 < 0' failed", y32, v32_n)
	}

	if y32+v32_n*one32 <= 0 {
		t.Errorf("'%#x + %#x*1 <= 0' failed", y32, v32_n)
	}
}

// multiply-sub
func testMSubVar64(t *testing.T) {
	if x64-v64_n*one64 < 0 {
	} else {
		t.Errorf("'%#x - %#x*1 < 0' failed", x64, v64_n)
	}

	if x64-v64_n*one64 <= 0 {
	} else {
		t.Errorf("'%#x - %#x*1 <= 0' failed", x64, v64_n)
	}

	if y64-v64*one64 > 0 {
	} else {
		t.Errorf("'%#x - %#x*1 > 0' failed", y64, v64)
	}

	if y64-v64*one64 >= 0 {
	} else {
		t.Errorf("'%#x - %#x*1 >= 0' failed", y64, v64)
	}

	if x64-v64_n*one64 > 0 {
		t.Errorf("'%#x - %#x*1 > 0' failed", x64, v64_n)
	}

	if x64-v64_n*one64 >= 0 {
		t.Errorf("'%#x - %#x*1 >= 0' failed", x64, v64_n)
	}

	if y64-v64*one64 < 0 {
		t.Errorf("'%#x - %#x*1 < 0' failed", y64, v64)
	}

	if y64-v64*one64 <= 0 {
		t.Errorf("'%#x - %#x*1 <= 0' failed", y64, v64)
	}

	if x64-x64b*one64 < 0 {
		t.Errorf("'%#x - %#x*1 < 0' failed", x64, x64b)
	}

	if x64-x64b*one64 >= 0 {
	} else {
		t.Errorf("'%#x - %#x*1 >= 0' failed", x64, x64b)
	}
}

// 32-bit multiply-sub
func testMSubVar32(t *testing.T) {
	if x32-v32_n*one32 < 0 {
	} else {
		t.Errorf("'%#x - %#x*1 < 0' failed", x32, v32_n)
	}

	if x32-v32_n*one32 <= 0 {
	} else {
		t.Errorf("'%#x - %#x*1 <= 0' failed", x32, v32_n)
	}

	if y32-v32*one32 > 0 {
	} else {
		t.Errorf("'%#x - %#x*1 > 0' failed", y32, v32)
	}

	if y32-v32*one32 >= 0 {
	} else {
		t.Errorf("'%#x - %#x*1 >= 0' failed", y32, v32)
	}

	if x32-v32_n*one32 > 0 {
		t.Errorf("'%#x - %#x*1 > 0' failed", x32, v32_n)
	}

	if x32-v32_n*one32 >= 0 {
		t.Errorf("'%#x - %#x*1 >= 0' failed", x32, v32_n)
	}

	if y32-v32*one32 < 0 {
		t.Errorf("'%#x - %#x*1 < 0' failed", y32, v32)
	}

	if y32-v32*one32 <= 0 {
		t.Errorf("'%#x - %#x*1 <= 0' failed", y32, v32)
	}

	if x32-x32b*one32 < 0 {
		t.Errorf("'%#x - %#x*1 < 0' failed", x32, x32b)
	}

	if x32-x32b*one32 >= 0 {
	} else {
		t.Errorf("'%#x - %#x*1 >= 0' failed", x32, x32b)
	}
}

// 32-bit ADDshift, pick up 1~2 scenarios randomly for each condition
func testAddShift32(t *testing.T) {
	if x32+v32<<1 < 0 {
	} else {
		t.Errorf("'%#x + %#x<<%#x < 0' failed", x32, v32, 1)
	}

	if x32+v32>>1 <= 0 {
	} else {
		t.Errorf("'%#x + %#x>>%#x <= 0' failed", x32, v32, 1)
	}

	if x32+int32(uv32>>1) > 0 {
		t.Errorf("'%#x + int32(%#x>>%#x) > 0' failed", x32, uv32, 1)
	}

	if x32+v32<<uz >= 0 {
		t.Errorf("'%#x + %#x<<%#x >= 0' failed", x32, v32, uz)
	}

	if x32+v32>>uz > 0 {
		t.Errorf("'%#x + %#x>>%#x > 0' failed", x32, v32, uz)
	}

	if x32+int32(uv32>>uz) < 0 {
	} else {
		t.Errorf("'%#x + int32(%#x>>%#x) < 0' failed", x32, uv32, uz)
	}
}

// 32-bit SUBshift, pick up 1~2 scenarios randomly for each condition
func testSubShift32(t *testing.T) {
	if y32-v32<<1 > 0 {
	} else {
		t.Errorf("'%#x - %#x<<%#x > 0' failed", y32, v32, 1)
	}

	if y32-v32>>1 < 0 {
		t.Errorf("'%#x - %#x>>%#x < 0' failed", y32, v32, 1)
	}

	if y32-int32(uv32>>1) >= 0 {
	} else {
		t.Errorf("'%#x - int32(%#x>>%#x) >= 0' failed", y32, uv32, 1)
	}

	if y32-v32<<uz < 0 {
		t.Errorf("'%#x - %#x<<%#x < 0' failed", y32, v32, uz)
	}

	if y32-v32>>uz >= 0 {
	} else {
		t.Errorf("'%#x - %#x>>%#x >= 0' failed", y32, v32, uz)
	}

	if y32-int32(uv32>>uz) <= 0 {
		t.Errorf("'%#x - int32(%#x>>%#x) <= 0' failed", y32, uv32, uz)
	}
}

var rnd = rand.New(rand.NewSource(0))
var sink int64

func benchSoloJump(b *testing.B) {
	r1 := x64
	r2 := x64b
	r3 := x64c
	r4 := y64
	d := rnd.Int63n(10)

	// 6 out 10 conditions evaluate to true
	for i := 0; i < b.N; i++ {
		if r1+r2 < 0 {
			d *= 2
			d /= 2
		}

		if r1+r3 >= 0 {
			d *= 2
			d /= 2
		}

		if r1+r2*one64 < 0 {
			d *= 2
			d /= 2
		}

		if r2+r3*one64 >= 0 {
			d *= 2
			d /= 2
		}

		if r1-r2*v64 >= 0 {
			d *= 2
			d /= 2
		}

		if r3-r4*v64 < 0 {
			d *= 2
			d /= 2
		}

		if r1+11 < 0 {
			d *= 2
			d /= 2
		}

		if r1+13 >= 0 {
			d *= 2
			d /= 2
		}

		if r4-17 < 0 {
			d *= 2
			d /= 2
		}

		if r4-19 >= 0 {
			d *= 2
			d /= 2
		}
	}
	sink = d
}

func benchCombJump(b *testing.B) {
	r1 := x64
	r2 := x64b
	r3 := x64c
	r4 := y64
	d := rnd.Int63n(10)

	// 6 out 10 conditions evaluate to true
	for i := 0; i < b.N; i++ {
		if r1+r2 <= 0 {
			d *= 2
			d /= 2
		}

		if r1+r3 > 0 {
			d *= 2
			d /= 2
		}

		if r1+r2*one64 <= 0 {
			d *= 2
			d /= 2
		}

		if r2+r3*one64 > 0 {
			d *= 2
			d /= 2
		}

		if r1-r2*v64 > 0 {
			d *= 2
			d /= 2
		}

		if r3-r4*v64 <= 0 {
			d *= 2
			d /= 2
		}

		if r1+11 <= 0 {
			d *= 2
			d /= 2
		}

		if r1+13 > 0 {
			d *= 2
			d /= 2
		}

		if r4-17 <= 0 {
			d *= 2
			d /= 2
		}

		if r4-19 > 0 {
			d *= 2
			d /= 2
		}
	}
	sink = d
}

"""



```