Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The core request is to understand the functionality of the Go code and explain it clearly. The file name "prove.go" and the `// errorcheck` directive immediately suggest that this code is designed for testing the Go compiler's static analysis capabilities, specifically the "prove" phase.

2. **Identify Key Directives:**
    * `// errorcheck -0 -d=ssa/prove/debug=1`: This is the most crucial directive. It tells the `go test` command to run this file specifically for error checking. `-0` likely signifies no optimization, and `-d=ssa/prove/debug=1` turns on debug output for the SSA prove pass. This tells us the file *isn't* about standard Go functionality, but about testing compiler internals.
    * `//go:build amd64`: This build constraint limits the execution of this code to amd64 architectures. It doesn't directly explain the *purpose* of the code, but is important context.
    * `// ERROR "..."`: These comments are the key to understanding what the `prove` pass is expected to do. They indicate assertions about what the compiler should be able to deduce (prove) at specific points in the code.

3. **Analyze the Code Structure:** The code consists of numerous small functions (like `f0`, `f1`, `f2`, etc.). This structure is typical for unit testing, where each function tests a specific scenario. The `main` function is empty, which further reinforces the idea that this code is meant to be *analyzed*, not *executed* in a traditional sense.

4. **Focus on the `// ERROR` Comments:**  These comments are the most direct clues to the code's purpose. They fall into a few categories:
    * `"Proved IsInBounds$"`: Indicates the compiler should be able to prove that an array/slice access is within bounds.
    * `"Proved IsSliceInBounds$"`:  Indicates the compiler should be able to prove that a slice operation (e.g., slicing) is within bounds.
    * `"Disproved ...$"`: Indicates the compiler should be able to disprove certain conditions (e.g., equality, inequality, less than).
    * `"Induction variable: ...$"`:  Indicates the compiler should recognize loop variables as induction variables and track their bounds.
    * `"Proved ... non-zero$"`:  Indicates the compiler should be able to prove that the result of a function (like `bits.TrailingZeros`) is non-zero under certain conditions.
    * `"Proved ... shifts to zero"`:  Indicates the compiler can deduce that a right shift operation will result in zero.
    * `"Proved slicemask not needed$"`: Indicates the compiler can optimize away the slicemask operation.
    * `"Proved Leq...$"` and `"Proved Less...$"`: Indicates the compiler should be able to prove less-than-or-equal-to and less-than relationships.
    * `"Proved Arg$"`: Indicates the compiler can prove the value of a boolean argument within a conditional.
    * `"Proved IsNonNil$"`: Indicates the compiler can prove a pointer is not nil.
    * `"Proved Mod64 does not need fix-up$"` and `"Proved Div64 does not need fix-up$"`:  Indicates the compiler can optimize modulo and division operations under certain conditions.

5. **Infer the Functionality:** Based on the `// ERROR` comments, the primary function of this code is to test the Go compiler's ability to perform static analysis and prove certain properties about the code. This includes:
    * **Bounds Check Elimination (BCE):**  A significant portion of the tests revolves around proving array/slice accesses are within bounds, allowing the compiler to eliminate redundant bounds checks.
    * **Proving Relational Operators:** Testing the compiler's ability to deduce the truth or falsehood of comparisons (`<`, `>`, `==`, `!=`, `<=`, `>=`).
    * **Induction Variable Analysis:** Verifying the compiler can track the range of loop counters.
    * **Reasoning about Bitwise Operations:**  Checking if the compiler can reason about the results of bitwise operations (shifts, AND, OR, XOR, NOT).
    * **Reasoning about Integer Overflow and Underflow:** Although not explicitly marked with `// ERROR`, some examples implicitly test the compiler's awareness of potential overflows (e.g., `f1c`).
    * **Reasoning about Boolean Logic and Pointer Values:**  Testing the ability to deduce the values of boolean variables and pointer nilness.

6. **Synthesize the Explanation:**  Now, structure the explanation based on the initial request:
    * **Functionality Summary:** Start with a high-level description of the code's purpose – testing the Go compiler's `prove` pass.
    * **Go Feature (Inferred):**  Identify that it's related to static analysis and optimization, specifically Bounds Check Elimination.
    * **Code Examples:**  Select representative functions (like `f0`, `f1`, `f2`, functions demonstrating disproved conditions, and loop analysis) to illustrate the concepts. Explain the expected behavior based on the `// ERROR` comments.
    * **Code Logic (with Assumptions):** For a few key examples, walk through the control flow and explain how the `prove` pass should be able to make deductions. Use simple examples with clear input/output (even though the code isn't meant to be *run* in the typical sense).
    * **Command-Line Arguments:** Explain the `-d=ssa/prove/debug=1` flag and its purpose in enabling debug output for the `prove` pass.
    * **Common Mistakes (Conceptual):**  Since this isn't about user-written code, but compiler testing, the "mistakes" are about misunderstanding what the `prove` pass can and cannot deduce. Give examples of situations where a programmer might *think* a bound check is unnecessary, but the compiler might not be able to prove it. Also, point out the importance of the `// ERROR` comments for interpreting the test results.

7. **Review and Refine:**  Read through the explanation, ensuring it's clear, concise, and accurate. Make sure the examples are easy to understand and directly relate to the concepts being discussed. Check for consistency in terminology.

By following this process of identifying the core goal, analyzing the key directives and code structure, focusing on the error annotations, and then synthesizing the information into a structured explanation, we can effectively understand and explain the functionality of this Go compiler testing code.
这是 Go 语言编译器测试套件的一部分，专门用于测试静态单赋值形式 (SSA) 中 `prove` 阶段的功能。`prove` 阶段的目标是通过静态分析来推断和证明程序中的各种属性，例如数组/切片访问是否在边界内，条件判断是否为真或假等等，从而进行优化，例如消除冗余的边界检查。

**功能归纳:**

该文件 `prove.go` 包含一系列 Go 函数，每个函数都设计用来测试 `prove` 阶段的特定能力。这些测试用例旨在验证编译器是否能够正确地：

1. **证明数组和切片访问的边界安全性 (Bounds Check Elimination - BCE):**  很多函数 (如 `f0`, `f1`, `f1b`, `f3`, `f7`, `f11a`, `f11b`, `f11c`, `f14`, `f17` 等) 旨在测试编译器能否通过分析变量的范围和条件判断，证明数组或切片的索引访问不会超出其有效范围。
2. **推断和证明条件表达式的结果:** 函数如 `f4a`, `f4b`, `f4c`, `f4d`, `f4e`, `f4f`, `f5`, `f8`, `f9`, `f13a`, `f13b`, `f13c`, `f13d`, `f13e`, `f13f`, `f13g`, `f13h`, `f13i`, `f20`, `f21`, `f22` 等测试编译器能否证明某些比较操作的结果 (`==`, `!=`, `<`, `>`, `<=`, `>=`)。
3. **识别和跟踪循环归纳变量:** 函数如 `f2`, `f3`, `f17`, `range1`, `range2`, `signHint1`, `signHint2`, `indexGT0`, `unrollUpExcl`, `unrollUpIncl`, `unrollDownExcl0`, `unrollDownExcl1`, `unrollDownInclStep` 等测试编译器能否识别循环中的归纳变量，并推断其取值范围。
4. **理解和利用位运算的性质:** 函数如 `sh64`, `sh32`, `sh32x64`, `sh16`, `divShiftClean`, `divShiftClean64`, `divShiftClean32`, `rshu`, `divu`, `modu1`, `modu2`, `ctz64`, `ctz32`, `ctz16`, `ctz8`, `bitLen64`, `bitLen32`, `bitLen16`, `bitLen8`, `xor64`, `or64`, `mod64uWithSmallerDividendMax`, `mod64uWithSmallerDivisorMax`, `mod64uWithIdenticalMax`, `mod64sPositiveWithSmallerDividendMax`, `mod64sPositiveWithSmallerDivisorMax`, `mod64sPositiveWithIdenticalMax`, `div64u`, `div64s`, `trunc64to16`, `com64`, `neg64` 等测试编译器能否理解和推断位运算的结果，例如右移是否会变为零，计数前导/尾随零等。
5. **处理类型转换和溢出:** 函数如 `f1c`, `signExtNto64`, `zeroExtNto64`, `signExt32to64Fence`, `zeroExt32to64Fence` 等测试编译器在进行类型转换时能否正确处理符号扩展、零扩展以及潜在的溢出情况。
6. **处理更复杂的控制流和逻辑:**  一些函数组合了多种条件判断和操作，测试编译器在更复杂的场景下的推断能力。
7. **利用已知的变量关系进行推断:** 例如在 `f1` 中，通过 `len(a) <= 5` 的判断，后续的数组访问可以被证明是安全的。
8. **处理 `math` 包和 `bits` 包中的函数:**  许多测试用例使用了 `math` 和 `bits` 包中的函数，以验证编译器对这些特定函数的推理能力。

**Go 语言功能的实现 (推断):**

基于上述分析，可以推断 `go/test/prove.go` 主要测试的是 Go 编译器中 **静态分析和优化** 相关的能力，特别是 **SSA 的 `prove` 阶段**。 这个阶段是编译器进行深层优化的关键部分，通过证明代码的某些属性，可以安全地消除冗余操作，提高程序性能。 许多测试用例集中在 **Bounds Check Elimination (BCE)**，这是 Go 语言编译器一个重要的优化。

**Go 代码举例说明 (BCE):**

```go
package main

func testBCE(arr []int, index int) int {
	if index >= 0 && index < len(arr) {
		return arr[index] // 编译器应该能够证明这里访问是安全的
	}
	return 0
}

func main() {
	myArray := []int{1, 2, 3, 4, 5}
	result := testBCE(myArray, 2)
	println(result) // 输出 3
}
```

在这个例子中，`testBCE` 函数在访问 `arr[index]` 之前，先检查了 `index` 是否在 `arr` 的有效范围内。 `prove` 阶段应该能够识别出这个条件判断，并在编译后的代码中消除 `arr[index]` 的边界检查，因为静态分析已经证明了其安全性。

**代码逻辑介绍 (带假设输入与输出):**

以函数 `f1(a []int) int` 为例：

```go
func f1(a []int) int {
	if len(a) <= 5 {
		return 18
	}
	a[0] = 1 // ERROR "Proved IsInBounds$"
	a[0] = 1 // ERROR "Proved IsInBounds$"
	a[6] = 1
	a[6] = 1 // ERROR "Proved IsInBounds$"
	a[5] = 1 // ERROR "Proved IsInBounds$"
	a[5] = 1 // ERROR "Proved IsInBounds$"
	return 26
}
```

**假设输入:**  `a` 是一个长度为 10 的 `[]int`，例如 `[]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}`。

**代码逻辑:**

1. 函数首先检查切片 `a` 的长度是否小于等于 5。
2. 由于假设输入的 `len(a)` 为 10，条件 `len(a) <= 5` 为假，代码会跳过 `return 18` 的语句。
3. 接下来执行 `a[0] = 1`。由于已知 `len(a)` 大于 5，索引 0 是安全的，`prove` 阶段应该能证明这一点。
4. 同样的，后续的 `a[0] = 1` 也是安全的。
5. 执行 `a[6] = 1`。因为 `len(a)` 为 10，索引 6 是安全的，`prove` 阶段应该能证明。
6. 同样，后续的 `a[6] = 1` 也是安全的。
7. 执行 `a[5] = 1`。索引 5 也是安全的。
8. 最后执行 `return 26`。

**预期输出:**  由于该代码是用于编译器测试，其“输出”体现在 `// ERROR` 注释上。对于输入 `len(a) = 10` 的情况，编译器应该能够在标记 `// ERROR "Proved IsInBounds$"` 的行证明数组访问是安全的。

**命令行参数的具体处理:**

该文件本身不是一个可执行的程序，而是作为 `go test` 的输入。 其中的特殊注释 (如 `// errorcheck`, `//go:build`) 是 `go test` 命令解析和使用的指令。

* **`// errorcheck -0 -d=ssa/prove/debug=1`:**
    * **`// errorcheck`:**  这个指令告诉 `go test` 工具，这个文件是一个错误检查测试。它会编译代码并检查输出中是否包含特定的错误或消息（在这个例子中，是 `// ERROR` 注释）。
    * **`-0`:**  这个标志传递给编译器，指示编译器禁用优化。这可能用于在没有优化的状态下测试 `prove` 阶段的基本功能。
    * **`-d=ssa/prove/debug=1`:** 这个标志传递给编译器，用于启用 `ssa/prove` 包的调试输出。这通常用于开发和调试编译器本身，可以输出 `prove` 阶段的详细信息，帮助理解其推理过程。

因此，要运行这个测试文件，通常会使用如下命令：

```bash
go test -gcflags='-d=ssa/prove/debug=1' go/test/prove.go
```

或者，如果当前目录在包含 `go` 目录的上层，可以直接使用：

```bash
go test -gcflags='-d=ssa/prove/debug=1' ./go/test/prove.go
```

`go test` 工具会编译 `prove.go`，并根据 `// errorcheck` 指令验证编译器的输出是否包含了所有标记为 `// ERROR` 的消息。如果编译器成功地证明了相应的属性，就会输出包含 "Proved..." 的信息，`go test` 会认为测试通过。

**使用者易犯错的点:**

因为这个文件主要是用于 Go 编译器开发和测试，所以 “使用者” 主要指 Go 编译器的开发者。

一个容易犯错的点是 **错误地理解 `prove` 阶段的能力或限制**。 例如：

1. **假设 `prove` 可以推断出所有可能的边界安全。**  `prove` 阶段的分析是静态的，对于一些动态才能确定的情况，例如索引值来自用户输入或复杂的运行时逻辑，`prove` 可能无法证明其安全性，从而无法消除边界检查。
2. **错误地编写 `// ERROR` 注释。**  如果 `// ERROR` 注释的内容与编译器实际输出的信息不匹配（例如，拼写错误、信息不完整），会导致测试失败，即使 `prove` 阶段的推断是正确的。
3. **忽略了 `-0` 标志的影响。** 在禁用优化的情况下测试 `prove` 阶段，可能无法涵盖所有优化场景。某些 `prove` 的能力可能依赖于其他优化阶段的结果。
4. **没有充分理解 SSA 的概念。**  `prove` 阶段工作在 SSA 中间表示上，理解 SSA 的特性（例如，每个变量只赋值一次）对于编写有效的测试用例至关重要。

**举例说明错误理解 `prove` 能力的情况:**

```go
package main

func mightBeOutOfBounds(arr []int, index int) int {
	// 假设 index 可能超出 arr 的范围
	if someExternalCondition() {
		index = len(arr) + 1
	}
	return arr[index] // 开发者可能认为 prove 应该能分析出所有情况，但静态分析可能无法确定 someExternalCondition 的结果
}

//go:noinline
func someExternalCondition() bool {
	// 模拟一些运行时才能确定的条件
	return false
}

func main() {
	myArray := []int{1, 2, 3}
	result := mightBeOutOfBounds(myArray, 0)
	println(result)
}
```

在这个例子中，即使 `someExternalCondition` 在运行时返回 `false`，静态的 `prove` 阶段通常也无法确定 `index` 永远不会超出边界，因此不太可能消除 `arr[index]` 的边界检查。 编译器开发者需要理解这种限制，并编写能够有效测试 `prove` 实际能力的用例。

总而言之，`go/test/prove.go` 是一个精巧的测试套件，用于验证 Go 编译器静态分析和优化能力的核心部分，特别是其在 SSA 中 `prove` 阶段的推理能力。 它通过大量的具体用例，确保编译器能够正确地推断代码的各种属性，从而实现更安全、更高效的 Go 代码。

### 提示词
```
这是路径为go/test/prove.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// errorcheck -0 -d=ssa/prove/debug=1

//go:build amd64

// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"math"
	"math/bits"
)

func f0(a []int) int {
	a[0] = 1
	a[0] = 1 // ERROR "Proved IsInBounds$"
	a[6] = 1
	a[6] = 1 // ERROR "Proved IsInBounds$"
	a[5] = 1 // ERROR "Proved IsInBounds$"
	a[5] = 1 // ERROR "Proved IsInBounds$"
	return 13
}

func f1(a []int) int {
	if len(a) <= 5 {
		return 18
	}
	a[0] = 1 // ERROR "Proved IsInBounds$"
	a[0] = 1 // ERROR "Proved IsInBounds$"
	a[6] = 1
	a[6] = 1 // ERROR "Proved IsInBounds$"
	a[5] = 1 // ERROR "Proved IsInBounds$"
	a[5] = 1 // ERROR "Proved IsInBounds$"
	return 26
}

func f1b(a []int, i int, j uint) int {
	if i >= 0 && i < len(a) {
		return a[i] // ERROR "Proved IsInBounds$"
	}
	if i >= 10 && i < len(a) {
		return a[i] // ERROR "Proved IsInBounds$"
	}
	if i >= 10 && i < len(a) {
		return a[i] // ERROR "Proved IsInBounds$"
	}
	if i >= 10 && i < len(a) {
		return a[i-10] // ERROR "Proved IsInBounds$"
	}
	if j < uint(len(a)) {
		return a[j] // ERROR "Proved IsInBounds$"
	}
	return 0
}

func f1c(a []int, i int64) int {
	c := uint64(math.MaxInt64 + 10) // overflows int
	d := int64(c)
	if i >= d && i < int64(len(a)) {
		// d overflows, should not be handled.
		return a[i]
	}
	return 0
}

func f2(a []int) int {
	for i := range a { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		a[i+1] = i
		a[i+1] = i // ERROR "Proved IsInBounds$"
	}
	return 34
}

func f3(a []uint) int {
	for i := uint(0); i < uint(len(a)); i++ {
		a[i] = i // ERROR "Proved IsInBounds$"
	}
	return 41
}

func f4a(a, b, c int) int {
	if a < b {
		if a == b { // ERROR "Disproved Eq64$"
			return 47
		}
		if a > b { // ERROR "Disproved Less64$"
			return 50
		}
		if a < b { // ERROR "Proved Less64$"
			return 53
		}
		// We can't get to this point and prove knows that, so
		// there's no message for the next (obvious) branch.
		if a != a {
			return 56
		}
		return 61
	}
	return 63
}

func f4b(a, b, c int) int {
	if a <= b {
		if a >= b {
			if a == b { // ERROR "Proved Eq64$"
				return 70
			}
			return 75
		}
		return 77
	}
	return 79
}

func f4c(a, b, c int) int {
	if a <= b {
		if a >= b {
			if a != b { // ERROR "Disproved Neq64$"
				return 73
			}
			return 75
		}
		return 77
	}
	return 79
}

func f4d(a, b, c int) int {
	if a < b {
		if a < c {
			if a < b { // ERROR "Proved Less64$"
				if a < c { // ERROR "Proved Less64$"
					return 87
				}
				return 89
			}
			return 91
		}
		return 93
	}
	return 95
}

func f4e(a, b, c int) int {
	if a < b {
		if b > a { // ERROR "Proved Less64$"
			return 101
		}
		return 103
	}
	return 105
}

func f4f(a, b, c int) int {
	if a <= b {
		if b > a {
			if b == a { // ERROR "Disproved Eq64$"
				return 112
			}
			return 114
		}
		if b >= a { // ERROR "Proved Leq64$"
			if b == a { // ERROR "Proved Eq64$"
				return 118
			}
			return 120
		}
		return 122
	}
	return 124
}

func f5(a, b uint) int {
	if a == b {
		if a <= b { // ERROR "Proved Leq64U$"
			return 130
		}
		return 132
	}
	return 134
}

// These comparisons are compile time constants.
func f6a(a uint8) int {
	if a < a { // ERROR "Disproved Less8U$"
		return 140
	}
	return 151
}

func f6b(a uint8) int {
	if a < a { // ERROR "Disproved Less8U$"
		return 140
	}
	return 151
}

func f6x(a uint8) int {
	if a > a { // ERROR "Disproved Less8U$"
		return 143
	}
	return 151
}

func f6d(a uint8) int {
	if a <= a { // ERROR "Proved Leq8U$"
		return 146
	}
	return 151
}

func f6e(a uint8) int {
	if a >= a { // ERROR "Proved Leq8U$"
		return 149
	}
	return 151
}

func f7(a []int, b int) int {
	if b < len(a) {
		a[b] = 3
		if b < len(a) { // ERROR "Proved Less64$"
			a[b] = 5 // ERROR "Proved IsInBounds$"
		}
	}
	return 161
}

func f8(a, b uint) int {
	if a == b {
		return 166
	}
	if a > b {
		return 169
	}
	if a < b { // ERROR "Proved Less64U$"
		return 172
	}
	return 174
}

func f9(a, b bool) int {
	if a {
		return 1
	}
	if a || b { // ERROR "Disproved Arg$"
		return 2
	}
	return 3
}

func f10(a string) int {
	n := len(a)
	// We optimize comparisons with small constant strings (see cmd/compile/internal/gc/walk.go),
	// so this string literal must be long.
	if a[:n>>1] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		return 0
	}
	return 1
}

func f11a(a []int, i int) {
	useInt(a[i])
	useInt(a[i]) // ERROR "Proved IsInBounds$"
}

func f11b(a []int, i int) {
	useSlice(a[i:])
	useSlice(a[i:]) // ERROR "Proved IsSliceInBounds$"
}

func f11c(a []int, i int) {
	useSlice(a[:i])
	useSlice(a[:i]) // ERROR "Proved IsSliceInBounds$"
}

func f11d(a []int, i int) {
	useInt(a[2*i+7])
	useInt(a[2*i+7]) // ERROR "Proved IsInBounds$"
}

func f12(a []int, b int) {
	useSlice(a[:b])
}

func f13a(a, b, c int, x bool) int {
	if a > 12 {
		if x {
			if a < 12 { // ERROR "Disproved Less64$"
				return 1
			}
		}
		if x {
			if a <= 12 { // ERROR "Disproved Leq64$"
				return 2
			}
		}
		if x {
			if a == 12 { // ERROR "Disproved Eq64$"
				return 3
			}
		}
		if x {
			if a >= 12 { // ERROR "Proved Leq64$"
				return 4
			}
		}
		if x {
			if a > 12 { // ERROR "Proved Less64$"
				return 5
			}
		}
		return 6
	}
	return 0
}

func f13b(a int, x bool) int {
	if a == -9 {
		if x {
			if a < -9 { // ERROR "Disproved Less64$"
				return 7
			}
		}
		if x {
			if a <= -9 { // ERROR "Proved Leq64$"
				return 8
			}
		}
		if x {
			if a == -9 { // ERROR "Proved Eq64$"
				return 9
			}
		}
		if x {
			if a >= -9 { // ERROR "Proved Leq64$"
				return 10
			}
		}
		if x {
			if a > -9 { // ERROR "Disproved Less64$"
				return 11
			}
		}
		return 12
	}
	return 0
}

func f13c(a int, x bool) int {
	if a < 90 {
		if x {
			if a < 90 { // ERROR "Proved Less64$"
				return 13
			}
		}
		if x {
			if a <= 90 { // ERROR "Proved Leq64$"
				return 14
			}
		}
		if x {
			if a == 90 { // ERROR "Disproved Eq64$"
				return 15
			}
		}
		if x {
			if a >= 90 { // ERROR "Disproved Leq64$"
				return 16
			}
		}
		if x {
			if a > 90 { // ERROR "Disproved Less64$"
				return 17
			}
		}
		return 18
	}
	return 0
}

func f13d(a int) int {
	if a < 5 {
		if a < 9 { // ERROR "Proved Less64$"
			return 1
		}
	}
	return 0
}

func f13e(a int) int {
	if a > 9 {
		if a > 5 { // ERROR "Proved Less64$"
			return 1
		}
	}
	return 0
}

func f13f(a, b int64) int64 {
	if b != math.MaxInt64 {
		return 42
	}
	if a > b { // ERROR "Disproved Less64$"
		if a == 0 {
			return 1
		}
	}
	return 0
}

func f13g(a int) int {
	if a < 3 {
		return 5
	}
	if a > 3 {
		return 6
	}
	if a == 3 { // ERROR "Proved Eq64$"
		return 7
	}
	return 8
}

func f13h(a int) int {
	if a < 3 {
		if a > 1 {
			if a == 2 { // ERROR "Proved Eq64$"
				return 5
			}
		}
	}
	return 0
}

func f13i(a uint) int {
	if a == 0 {
		return 1
	}
	if a > 0 { // ERROR "Proved Less64U$"
		return 2
	}
	return 3
}

func f14(p, q *int, a []int) {
	// This crazy ordering usually gives i1 the lowest value ID,
	// j the middle value ID, and i2 the highest value ID.
	// That used to confuse CSE because it ordered the args
	// of the two + ops below differently.
	// That in turn foiled bounds check elimination.
	i1 := *p
	j := *q
	i2 := *p
	useInt(a[i1+j])
	useInt(a[i2+j]) // ERROR "Proved IsInBounds$"
}

func f15(s []int, x int) {
	useSlice(s[x:])
	useSlice(s[:x]) // ERROR "Proved IsSliceInBounds$"
}

func f16(s []int) []int {
	if len(s) >= 10 {
		return s[:10] // ERROR "Proved IsSliceInBounds$"
	}
	return nil
}

func f17(b []int) {
	for i := 0; i < len(b); i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		// This tests for i <= cap, which we can only prove
		// using the derived relation between len and cap.
		// This depends on finding the contradiction, since we
		// don't query this condition directly.
		useSlice(b[:i]) // ERROR "Proved IsSliceInBounds$"
	}
}

func f18(b []int, x int, y uint) {
	_ = b[x]
	_ = b[y]

	if x > len(b) { // ERROR "Disproved Less64$"
		return
	}
	if y > uint(len(b)) { // ERROR "Disproved Less64U$"
		return
	}
	if int(y) > len(b) { // ERROR "Disproved Less64$"
		return
	}
}

func f19() (e int64, err error) {
	// Issue 29502: slice[:0] is incorrectly disproved.
	var stack []int64
	stack = append(stack, 123)
	if len(stack) > 1 {
		panic("too many elements")
	}
	last := len(stack) - 1
	e = stack[last]
	// Buggy compiler prints "Disproved Leq64" for the next line.
	stack = stack[:last]
	return e, nil
}

func sm1(b []int, x int) {
	// Test constant argument to slicemask.
	useSlice(b[2:8]) // ERROR "Proved slicemask not needed$"
	// Test non-constant argument with known limits.
	if cap(b) > 10 {
		useSlice(b[2:])
	}
}

func lim1(x, y, z int) {
	// Test relations between signed and unsigned limits.
	if x > 5 {
		if uint(x) > 5 { // ERROR "Proved Less64U$"
			return
		}
	}
	if y >= 0 && y < 4 {
		if uint(y) > 4 { // ERROR "Disproved Less64U$"
			return
		}
		if uint(y) < 5 { // ERROR "Proved Less64U$"
			return
		}
	}
	if z < 4 {
		if uint(z) > 4 { // Not provable without disjunctions.
			return
		}
	}
}

// fence1–4 correspond to the four fence-post implications.

func fence1(b []int, x, y int) {
	// Test proofs that rely on fence-post implications.
	if x+1 > y {
		if x < y { // ERROR "Disproved Less64$"
			return
		}
	}
	if len(b) < cap(b) {
		// This eliminates the growslice path.
		b = append(b, 1) // ERROR "Disproved Less64U$"
	}
}

func fence2(x, y int) {
	if x-1 < y {
		if x > y { // ERROR "Disproved Less64$"
			return
		}
	}
}

func fence3(b, c []int, x, y int64) {
	if x-1 >= y {
		if x <= y { // Can't prove because x may have wrapped.
			return
		}
	}

	if x != math.MinInt64 && x-1 >= y {
		if x <= y { // ERROR "Disproved Leq64$"
			return
		}
	}

	c[len(c)-1] = 0 // Can't prove because len(c) might be 0

	if n := len(b); n > 0 {
		b[n-1] = 0 // ERROR "Proved IsInBounds$"
	}
}

func fence4(x, y int64) {
	if x >= y+1 {
		if x <= y {
			return
		}
	}
	if y != math.MaxInt64 && x >= y+1 {
		if x <= y { // ERROR "Disproved Leq64$"
			return
		}
	}
}

// Check transitive relations
func trans1(x, y int64) {
	if x > 5 {
		if y > x {
			if y > 2 { // ERROR "Proved Less64$"
				return
			}
		} else if y == x {
			if y > 5 { // ERROR "Proved Less64$"
				return
			}
		}
	}
	if x >= 10 {
		if y > x {
			if y > 10 { // ERROR "Proved Less64$"
				return
			}
		}
	}
}

func trans2(a, b []int, i int) {
	if len(a) != len(b) {
		return
	}

	_ = a[i]
	_ = b[i] // ERROR "Proved IsInBounds$"
}

func trans3(a, b []int, i int) {
	if len(a) > len(b) {
		return
	}

	_ = a[i]
	_ = b[i] // ERROR "Proved IsInBounds$"
}

func trans4(b []byte, x int) {
	// Issue #42603: slice len/cap transitive relations.
	switch x {
	case 0:
		if len(b) < 20 {
			return
		}
		_ = b[:2] // ERROR "Proved IsSliceInBounds$"
	case 1:
		if len(b) < 40 {
			return
		}
		_ = b[:2] // ERROR "Proved IsSliceInBounds$"
	}
}

// Derived from nat.cmp
func natcmp(x, y []uint) (r int) {
	m := len(x)
	n := len(y)
	if m != n || m == 0 {
		return
	}

	i := m - 1
	for i > 0 && // ERROR "Induction variable: limits \(0,\?\], increment 1$"
		x[i] == // ERROR "Proved IsInBounds$"
			y[i] { // ERROR "Proved IsInBounds$"
		i--
	}

	switch {
	case x[i] < // todo, cannot prove this because it's dominated by i<=0 || x[i]==y[i]
		y[i]: // ERROR "Proved IsInBounds$"
		r = -1
	case x[i] > // ERROR "Proved IsInBounds$"
		y[i]: // ERROR "Proved IsInBounds$"
		r = 1
	}
	return
}

func suffix(s, suffix string) bool {
	// todo, we're still not able to drop the bound check here in the general case
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func constsuffix(s string) bool {
	return suffix(s, "abc") // ERROR "Proved IsSliceInBounds$"
}

func atexit(foobar []func()) {
	for i := len(foobar) - 1; i >= 0; i-- { // ERROR "Induction variable: limits \[0,\?\], increment 1"
		f := foobar[i]
		foobar = foobar[:i] // ERROR "IsSliceInBounds"
		f()
	}
}

func make1(n int) []int {
	s := make([]int, n)
	for i := 0; i < n; i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1"
		s[i] = 1 // ERROR "Proved IsInBounds$"
	}
	return s
}

func make2(n int) []int {
	s := make([]int, n)
	for i := range s { // ERROR "Induction variable: limits \[0,\?\), increment 1"
		s[i] = 1 // ERROR "Proved IsInBounds$"
	}
	return s
}

// The range tests below test the index variable of range loops.

// range1 compiles to the "efficiently indexable" form of a range loop.
func range1(b []int) {
	for i, v := range b { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		b[i] = v + 1    // ERROR "Proved IsInBounds$"
		if i < len(b) { // ERROR "Proved Less64$"
			println("x")
		}
		if i >= 0 { // ERROR "Proved Leq64$"
			println("x")
		}
	}
}

// range2 elements are larger, so they use the general form of a range loop.
func range2(b [][32]int) {
	for i, v := range b { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		b[i][0] = v[0] + 1 // ERROR "Proved IsInBounds$"
		if i < len(b) {    // ERROR "Proved Less64$"
			println("x")
		}
		if i >= 0 { // ERROR "Proved Leq64$"
			println("x")
		}
	}
}

// signhint1-2 test whether the hint (int >= 0) is propagated into the loop.
func signHint1(i int, data []byte) {
	if i >= 0 {
		for i < len(data) { // ERROR "Induction variable: limits \[\?,\?\), increment 1$"
			_ = data[i] // ERROR "Proved IsInBounds$"
			i++
		}
	}
}

func signHint2(b []byte, n int) {
	if n < 0 {
		panic("")
	}
	_ = b[25]
	for i := n; i <= 25; i++ { // ERROR "Induction variable: limits \[\?,25\], increment 1$"
		b[i] = 123 // ERROR "Proved IsInBounds$"
	}
}

// indexGT0 tests whether prove learns int index >= 0 from bounds check.
func indexGT0(b []byte, n int) {
	_ = b[n]
	_ = b[25]

	for i := n; i <= 25; i++ { // ERROR "Induction variable: limits \[\?,25\], increment 1$"
		b[i] = 123 // ERROR "Proved IsInBounds$"
	}
}

// Induction variable in unrolled loop.
func unrollUpExcl(a []int) int {
	var i, x int
	for i = 0; i < len(a)-1; i += 2 { // ERROR "Induction variable: limits \[0,\?\), increment 2$"
		x += a[i] // ERROR "Proved IsInBounds$"
		x += a[i+1]
	}
	if i == len(a)-1 {
		x += a[i]
	}
	return x
}

// Induction variable in unrolled loop.
func unrollUpIncl(a []int) int {
	var i, x int
	for i = 0; i <= len(a)-2; i += 2 { // ERROR "Induction variable: limits \[0,\?\], increment 2$"
		x += a[i] // ERROR "Proved IsInBounds$"
		x += a[i+1]
	}
	if i == len(a)-1 {
		x += a[i]
	}
	return x
}

// Induction variable in unrolled loop.
func unrollDownExcl0(a []int) int {
	var i, x int
	for i = len(a) - 1; i > 0; i -= 2 { // ERROR "Induction variable: limits \(0,\?\], increment 2$"
		x += a[i]   // ERROR "Proved IsInBounds$"
		x += a[i-1] // ERROR "Proved IsInBounds$"
	}
	if i == 0 {
		x += a[i]
	}
	return x
}

// Induction variable in unrolled loop.
func unrollDownExcl1(a []int) int {
	var i, x int
	for i = len(a) - 1; i >= 1; i -= 2 { // ERROR "Induction variable: limits \(0,\?\], increment 2$"
		x += a[i]   // ERROR "Proved IsInBounds$"
		x += a[i-1] // ERROR "Proved IsInBounds$"
	}
	if i == 0 {
		x += a[i]
	}
	return x
}

// Induction variable in unrolled loop.
func unrollDownInclStep(a []int) int {
	var i, x int
	for i = len(a); i >= 2; i -= 2 { // ERROR "Induction variable: limits \[2,\?\], increment 2$"
		x += a[i-1] // ERROR "Proved IsInBounds$"
		x += a[i-2] // ERROR "Proved IsInBounds$"
	}
	if i == 1 {
		x += a[i-1]
	}
	return x
}

// Not an induction variable (step too large)
func unrollExclStepTooLarge(a []int) int {
	var i, x int
	for i = 0; i < len(a)-1; i += 3 {
		x += a[i]
		x += a[i+1]
	}
	if i == len(a)-1 {
		x += a[i]
	}
	return x
}

// Not an induction variable (step too large)
func unrollInclStepTooLarge(a []int) int {
	var i, x int
	for i = 0; i <= len(a)-2; i += 3 {
		x += a[i]
		x += a[i+1]
	}
	if i == len(a)-1 {
		x += a[i]
	}
	return x
}

// Not an induction variable (min too small, iterating down)
func unrollDecMin(a []int, b int) int {
	if b != math.MinInt64 {
		return 42
	}
	var i, x int
	for i = len(a); i >= b; i -= 2 { // ERROR "Proved Leq64"
		x += a[i-1]
		x += a[i-2]
	}
	if i == 1 {
		x += a[i-1]
	}
	return x
}

// Not an induction variable (min too small, iterating up -- perhaps could allow, but why bother?)
func unrollIncMin(a []int, b int) int {
	if b != math.MinInt64 {
		return 42
	}
	var i, x int
	for i = len(a); i >= b; i += 2 { // ERROR "Proved Leq64"
		x += a[i-1]
		x += a[i-2]
	}
	if i == 1 {
		x += a[i-1]
	}
	return x
}

// The 4 xxxxExtNto64 functions below test whether prove is looking
// through value-preserving sign/zero extensions of index values (issue #26292).

// Look through all extensions
func signExtNto64(x []int, j8 int8, j16 int16, j32 int32) int {
	if len(x) < 22 {
		return 0
	}
	if j8 >= 0 && j8 < 22 {
		return x[j8] // ERROR "Proved IsInBounds$"
	}
	if j16 >= 0 && j16 < 22 {
		return x[j16] // ERROR "Proved IsInBounds$"
	}
	if j32 >= 0 && j32 < 22 {
		return x[j32] // ERROR "Proved IsInBounds$"
	}
	return 0
}

func zeroExtNto64(x []int, j8 uint8, j16 uint16, j32 uint32) int {
	if len(x) < 22 {
		return 0
	}
	if j8 >= 0 && j8 < 22 {
		return x[j8] // ERROR "Proved IsInBounds$"
	}
	if j16 >= 0 && j16 < 22 {
		return x[j16] // ERROR "Proved IsInBounds$"
	}
	if j32 >= 0 && j32 < 22 {
		return x[j32] // ERROR "Proved IsInBounds$"
	}
	return 0
}

// Process fence-post implications through 32to64 extensions (issue #29964)
func signExt32to64Fence(x []int, j int32) int {
	if x[j] != 0 {
		return 1
	}
	if j > 0 && x[j-1] != 0 { // ERROR "Proved IsInBounds$"
		return 1
	}
	return 0
}

func zeroExt32to64Fence(x []int, j uint32) int {
	if x[j] != 0 {
		return 1
	}
	if j > 0 && x[j-1] != 0 { // ERROR "Proved IsInBounds$"
		return 1
	}
	return 0
}

// Ensure that bounds checks with negative indexes are not incorrectly removed.
func negIndex() {
	n := make([]int, 1)
	for i := -1; i <= 0; i++ { // ERROR "Induction variable: limits \[-1,0\], increment 1$"
		n[i] = 1
	}
}
func negIndex2(n int) {
	a := make([]int, 5)
	b := make([]int, 5)
	c := make([]int, 5)
	for i := -1; i <= 0; i-- {
		b[i] = i
		n++
		if n > 10 {
			break
		}
	}
	useSlice(a)
	useSlice(c)
}

// Check that prove is zeroing these right shifts of positive ints by bit-width - 1.
// e.g (Rsh64x64 <t> n (Const64 <typ.UInt64> [63])) && ft.isNonNegative(n) -> 0
func sh64(n int64) int64 {
	if n < 0 {
		return n
	}
	return n >> 63 // ERROR "Proved Rsh64x64 shifts to zero"
}

func sh32(n int32) int32 {
	if n < 0 {
		return n
	}
	return n >> 31 // ERROR "Proved Rsh32x64 shifts to zero"
}

func sh32x64(n int32) int32 {
	if n < 0 {
		return n
	}
	return n >> uint64(31) // ERROR "Proved Rsh32x64 shifts to zero"
}

func sh16(n int16) int16 {
	if n < 0 {
		return n
	}
	return n >> 15 // ERROR "Proved Rsh16x64 shifts to zero"
}

func sh64noopt(n int64) int64 {
	return n >> 63 // not optimized; n could be negative
}

// These cases are division of a positive signed integer by a power of 2.
// The opt pass doesnt have sufficient information to see that n is positive.
// So, instead, opt rewrites the division with a less-than-optimal replacement.
// Prove, which can see that n is nonnegative, cannot see the division because
// opt, an earlier pass, has already replaced it.
// The fix for this issue allows prove to zero a right shift that was added as
// part of the less-than-optimal reqwrite. That change by prove then allows
// lateopt to clean up all the unnecessary parts of the original division
// replacement. See issue #36159.
func divShiftClean(n int) int {
	if n < 0 {
		return n
	}
	return n / int(8) // ERROR "Proved Rsh64x64 shifts to zero"
}

func divShiftClean64(n int64) int64 {
	if n < 0 {
		return n
	}
	return n / int64(16) // ERROR "Proved Rsh64x64 shifts to zero"
}

func divShiftClean32(n int32) int32 {
	if n < 0 {
		return n
	}
	return n / int32(16) // ERROR "Proved Rsh32x64 shifts to zero"
}

// Bounds check elimination

func sliceBCE1(p []string, h uint) string {
	if len(p) == 0 {
		return ""
	}

	i := h & uint(len(p)-1)
	return p[i] // ERROR "Proved IsInBounds$"
}

func sliceBCE2(p []string, h int) string {
	if len(p) == 0 {
		return ""
	}
	i := h & (len(p) - 1)
	return p[i] // ERROR "Proved IsInBounds$"
}

func and(p []byte) ([]byte, []byte) { // issue #52563
	const blocksize = 16
	fullBlocks := len(p) &^ (blocksize - 1)
	blk := p[:fullBlocks] // ERROR "Proved IsSliceInBounds$"
	rem := p[fullBlocks:] // ERROR "Proved IsSliceInBounds$"
	return blk, rem
}

func rshu(x, y uint) int {
	z := x >> y
	if z <= x { // ERROR "Proved Leq64U$"
		return 1
	}
	return 0
}

func divu(x, y uint) int {
	z := x / y
	if z <= x { // ERROR "Proved Leq64U$"
		return 1
	}
	return 0
}

func modu1(x, y uint) int {
	z := x % y
	if z < y { // ERROR "Proved Less64U$"
		return 1
	}
	return 0
}

func modu2(x, y uint) int {
	z := x % y
	if z <= x { // ERROR "Proved Leq64U$"
		return 1
	}
	return 0
}

func issue57077(s []int) (left, right []int) {
	middle := len(s) / 2
	left = s[:middle]  // ERROR "Proved IsSliceInBounds$"
	right = s[middle:] // ERROR "Proved IsSliceInBounds$"
	return
}

func issue51622(b []byte) int {
	if len(b) >= 3 && b[len(b)-3] == '#' { // ERROR "Proved IsInBounds$"
		return len(b)
	}
	return 0
}

func issue45928(x int) {
	combinedFrac := x / (x | (1 << 31)) // ERROR "Proved Neq64$"
	useInt(combinedFrac)
}

func constantBounds1(i, j uint) int {
	var a [10]int
	if j < 11 && i < j {
		return a[i] // ERROR "Proved IsInBounds$"
	}
	return 0
}

func constantBounds2(i, j uint) int {
	var a [10]int
	if i < j && j < 11 {
		return a[i] // ERROR "Proved IsInBounds"
	}
	return 0
}

func constantBounds3(i, j, k, l uint) int {
	var a [8]int
	if i < j && j < k && k < l && l < 11 {
		return a[i] // ERROR "Proved IsInBounds"
	}
	return 0
}

func equalityPropagation(a [1]int, i, j uint) int {
	if i == j && i == 5 {
		return a[j-5] // ERROR "Proved IsInBounds"
	}
	return 0
}
func inequalityPropagation(a [1]int, i, j uint) int {
	if i != j && j >= 5 && j <= 6 && i == 5 {
		return a[j-6] // ERROR "Proved IsInBounds"
	}
	return 0
}

func issue66826a(a [21]byte) {
	for i := 0; i <= 10; i++ { // ERROR "Induction variable: limits \[0,10\], increment 1$"
		_ = a[2*i] // ERROR "Proved IsInBounds"
	}
}
func issue66826b(a [31]byte, i int) {
	if i < 0 || i > 10 {
		return
	}
	_ = a[3*i] // ERROR "Proved IsInBounds"
}

func f20(a, b bool) int {
	if a == b {
		if a {
			if b { // ERROR "Proved Arg"
				return 1
			}
		}
	}
	return 0
}

func f21(a, b *int) int {
	if a == b {
		if a != nil {
			if b != nil { // ERROR "Proved IsNonNil"
				return 1
			}
		}
	}
	return 0
}

func f22(b bool, x, y int) int {
	b2 := x < y
	if b == b2 {
		if b {
			if x >= y { // ERROR "Disproved Leq64$"
				return 1
			}
		}
	}
	return 0
}

func ctz64(x uint64, ensureBothBranchesCouldHappen bool) int {
	const max = math.MaxUint64
	sz := bits.Len64(max)

	log2half := uint64(max) >> (sz / 2)
	if x >= log2half || x == 0 {
		return 42
	}

	y := bits.TrailingZeros64(x) // ERROR "Proved Ctz64 non-zero$""

	z := sz / 2
	if ensureBothBranchesCouldHappen {
		if y < z { // ERROR "Proved Less64$"
			return -42
		}
	} else {
		if y >= z { // ERROR "Disproved Leq64$"
			return 1337
		}
	}

	return y
}
func ctz32(x uint32, ensureBothBranchesCouldHappen bool) int {
	const max = math.MaxUint32
	sz := bits.Len32(max)

	log2half := uint32(max) >> (sz / 2)
	if x >= log2half || x == 0 {
		return 42
	}

	y := bits.TrailingZeros32(x) // ERROR "Proved Ctz32 non-zero$""

	z := sz / 2
	if ensureBothBranchesCouldHappen {
		if y < z { // ERROR "Proved Less64$"
			return -42
		}
	} else {
		if y >= z { // ERROR "Disproved Leq64$"
			return 1337
		}
	}

	return y
}
func ctz16(x uint16, ensureBothBranchesCouldHappen bool) int {
	const max = math.MaxUint16
	sz := bits.Len16(max)

	log2half := uint16(max) >> (sz / 2)
	if x >= log2half || x == 0 {
		return 42
	}

	y := bits.TrailingZeros16(x) // ERROR "Proved Ctz16 non-zero$""

	z := sz / 2
	if ensureBothBranchesCouldHappen {
		if y < z { // ERROR "Proved Less64$"
			return -42
		}
	} else {
		if y >= z { // ERROR "Disproved Leq64$"
			return 1337
		}
	}

	return y
}
func ctz8(x uint8, ensureBothBranchesCouldHappen bool) int {
	const max = math.MaxUint8
	sz := bits.Len8(max)

	log2half := uint8(max) >> (sz / 2)
	if x >= log2half || x == 0 {
		return 42
	}

	y := bits.TrailingZeros8(x) // ERROR "Proved Ctz8 non-zero$""

	z := sz / 2
	if ensureBothBranchesCouldHappen {
		if y < z { // ERROR "Proved Less64$"
			return -42
		}
	} else {
		if y >= z { // ERROR "Disproved Leq64$"
			return 1337
		}
	}

	return y
}

func bitLen64(x uint64, ensureBothBranchesCouldHappen bool) int {
	const max = math.MaxUint64
	sz := bits.Len64(max)

	if x >= max>>3 {
		return 42
	}
	if x <= max>>6 {
		return 42
	}

	y := bits.Len64(x)

	if ensureBothBranchesCouldHappen {
		if sz-6 <= y && y <= sz-3 { // ERROR "Proved Leq64$"
			return -42
		}
	} else {
		if y < sz-6 || sz-3 < y { // ERROR "Disproved Less64$"
			return 1337
		}
	}
	return y
}
func bitLen32(x uint32, ensureBothBranchesCouldHappen bool) int {
	const max = math.MaxUint32
	sz := bits.Len32(max)

	if x >= max>>3 {
		return 42
	}
	if x <= max>>6 {
		return 42
	}

	y := bits.Len32(x)

	if ensureBothBranchesCouldHappen {
		if sz-6 <= y && y <= sz-3 { // ERROR "Proved Leq64$"
			return -42
		}
	} else {
		if y < sz-6 || sz-3 < y { // ERROR "Disproved Less64$"
			return 1337
		}
	}
	return y
}
func bitLen16(x uint16, ensureBothBranchesCouldHappen bool) int {
	const max = math.MaxUint16
	sz := bits.Len16(max)

	if x >= max>>3 {
		return 42
	}
	if x <= max>>6 {
		return 42
	}

	y := bits.Len16(x)

	if ensureBothBranchesCouldHappen {
		if sz-6 <= y && y <= sz-3 { // ERROR "Proved Leq64$"
			return -42
		}
	} else {
		if y < sz-6 || sz-3 < y { // ERROR "Disproved Less64$"
			return 1337
		}
	}
	return y
}
func bitLen8(x uint8, ensureBothBranchesCouldHappen bool) int {
	const max = math.MaxUint8
	sz := bits.Len8(max)

	if x >= max>>3 {
		return 42
	}
	if x <= max>>6 {
		return 42
	}

	y := bits.Len8(x)

	if ensureBothBranchesCouldHappen {
		if sz-6 <= y && y <= sz-3 { // ERROR "Proved Leq64$"
			return -42
		}
	} else {
		if y < sz-6 || sz-3 < y { // ERROR "Disproved Less64$"
			return 1337
		}
	}
	return y
}

func xor64(a, b uint64, ensureBothBranchesCouldHappen bool) int {
	a &= 0xff
	b &= 0xfff

	z := a ^ b

	if ensureBothBranchesCouldHappen {
		if z > 0xfff { // ERROR "Disproved Less64U$"
			return 42
		}
	} else {
		if z <= 0xfff { // ERROR "Proved Leq64U$"
			return 1337
		}
	}
	return int(z)
}

func or64(a, b uint64, ensureBothBranchesCouldHappen bool) int {
	a &= 0xff
	b &= 0xfff

	z := a | b

	if ensureBothBranchesCouldHappen {
		if z > 0xfff { // ERROR "Disproved Less64U$"
			return 42
		}
	} else {
		if z <= 0xfff { // ERROR "Proved Leq64U$"
			return 1337
		}
	}
	return int(z)
}

func mod64uWithSmallerDividendMax(a, b uint64, ensureBothBranchesCouldHappen bool) int {
	a &= 0xff
	b &= 0xfff

	z := bits.Len64(a % b) // see go.dev/issue/68857 for bits.Len64

	if ensureBothBranchesCouldHappen {
		if z > bits.Len64(0xff) { // ERROR "Disproved Less64$"
			return 42
		}
	} else {
		if z <= bits.Len64(0xff) { // ERROR "Proved Leq64$"
			return 1337
		}
	}
	return z
}
func mod64uWithSmallerDivisorMax(a, b uint64, ensureBothBranchesCouldHappen bool) int {
	a &= 0xfff
	b &= 0x10 // we need bits.Len64(b.umax) != bits.Len64(b.umax-1)

	z := bits.Len64(a % b) // see go.dev/issue/68857 for bits.Len64

	if ensureBothBranchesCouldHappen {
		if z > bits.Len64(0x10-1) { // ERROR "Disproved Less64$"
			return 42
		}
	} else {
		if z <= bits.Len64(0x10-1) { // ERROR "Proved Leq64$"
			return 1337
		}
	}
	return z
}
func mod64uWithIdenticalMax(a, b uint64, ensureBothBranchesCouldHappen bool) int {
	a &= 0x10
	b &= 0x10 // we need bits.Len64(b.umax) != bits.Len64(b.umax-1)

	z := bits.Len64(a % b) // see go.dev/issue/68857 for bits.Len64

	if ensureBothBranchesCouldHappen {
		if z > bits.Len64(0x10-1) { // ERROR "Disproved Less64$"
			return 42
		}
	} else {
		if z <= bits.Len64(0x10-1) { // ERROR "Proved Leq64$"
			return 1337
		}
	}
	return z
}
func mod64sPositiveWithSmallerDividendMax(a, b int64, ensureBothBranchesCouldHappen bool) int64 {
	if a < 0 || b < 0 {
		return 42
	}
	a &= 0xff
	b &= 0xfff

	z := a % b // ERROR "Proved Mod64 does not need fix-up$"

	if ensureBothBranchesCouldHappen {
		if z > 0xff { // ERROR "Disproved Less64$"
			return 42
		}
	} else {
		if z <= 0xff { // ERROR "Proved Leq64$"
			return 1337
		}
	}
	return z
}
func mod64sPositiveWithSmallerDivisorMax(a, b int64, ensureBothBranchesCouldHappen bool) int64 {
	if a < 0 || b < 0 {
		return 42
	}
	a &= 0xfff
	b &= 0xff

	z := a % b // ERROR "Proved Mod64 does not need fix-up$"

	if ensureBothBranchesCouldHappen {
		if z > 0xff-1 { // ERROR "Disproved Less64$"
			return 42
		}
	} else {
		if z <= 0xff-1 { // ERROR "Proved Leq64$"
			return 1337
		}
	}
	return z
}
func mod64sPositiveWithIdenticalMax(a, b int64, ensureBothBranchesCouldHappen bool) int64 {
	if a < 0 || b < 0 {
		return 42
	}
	a &= 0xfff
	b &= 0xfff

	z := a % b // ERROR "Proved Mod64 does not need fix-up$"

	if ensureBothBranchesCouldHappen {
		if z > 0xfff-1 { // ERROR "Disproved Less64$"
			return 42
		}
	} else {
		if z <= 0xfff-1 { // ERROR "Proved Leq64$"
			return 1337
		}
	}
	return z
}

func div64u(a, b uint64, ensureAllBranchesCouldHappen func() bool) uint64 {
	a &= 0xffff
	a |= 0xfff
	b &= 0xff
	b |= 0xf

	z := a / b // ERROR "Proved Neq64$"

	if ensureAllBranchesCouldHappen() && z > 0xffff/0xf { // ERROR "Disproved Less64U$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z <= 0xffff/0xf { // ERROR "Proved Leq64U$"
		return 1337
	}
	if ensureAllBranchesCouldHappen() && z < 0xfff/0xff { // ERROR "Disproved Less64U$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z >= 0xfff/0xff { // ERROR "Proved Leq64U$"
		return 42
	}
	return z
}
func div64s(a, b int64, ensureAllBranchesCouldHappen func() bool) int64 {
	if a < 0 || b < 0 {
		return 42
	}
	a &= 0xffff
	a |= 0xfff
	b &= 0xff
	b |= 0xf

	z := a / b // ERROR "(Proved Div64 does not need fix-up|Proved Neq64)$"

	if ensureAllBranchesCouldHappen() && z > 0xffff/0xf { // ERROR "Disproved Less64$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z <= 0xffff/0xf { // ERROR "Proved Leq64$"
		return 1337
	}
	if ensureAllBranchesCouldHappen() && z < 0xfff/0xff { // ERROR "Disproved Less64$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z >= 0xfff/0xff { // ERROR "Proved Leq64$"
		return 42
	}
	return z
}

func trunc64to16(a uint64, ensureAllBranchesCouldHappen func() bool) uint16 {
	a &= 0xfff
	a |= 0xff

	z := uint16(a)
	if ensureAllBranchesCouldHappen() && z > 0xfff { // ERROR "Disproved Less16U$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z <= 0xfff { // ERROR "Proved Leq16U$"
		return 1337
	}
	if ensureAllBranchesCouldHappen() && z < 0xff { // ERROR "Disproved Less16U$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z >= 0xff { // ERROR "Proved Leq16U$"
		return 1337
	}
	return z
}

func com64(a uint64, ensureAllBranchesCouldHappen func() bool) uint64 {
	a &= 0xffff
	a |= 0xff

	z := ^a

	if ensureAllBranchesCouldHappen() && z > ^uint64(0xff) { // ERROR "Disproved Less64U$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z <= ^uint64(0xff) { // ERROR "Proved Leq64U$"
		return 1337
	}
	if ensureAllBranchesCouldHappen() && z < ^uint64(0xffff) { // ERROR "Disproved Less64U$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z >= ^uint64(0xffff) { // ERROR "Proved Leq64U$"
		return 1337
	}
	return z
}

func neg64(a uint64, ensureAllBranchesCouldHappen func() bool) uint64 {
	var lo, hi uint64 = 0xff, 0xfff
	a &= hi
	a |= lo

	z := -a

	if ensureAllBranchesCouldHappen() && z > -lo { // ERROR "Disproved Less64U$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z <= -lo { // ERROR "Proved Leq64U$"
		return 1337
	}
	if ensureAllBranchesCouldHappen() && z < -hi { // ERROR "Disproved Less64U$"
		return 42
	}
	if ensureAllBranchesCouldHappen() && z >= -hi { // ERROR "Proved Leq64U$"
		return 1337
	}
	return z
}
func neg64mightOverflowDuringNeg(a uint64, ensureAllBranchesCouldHappen func() bool) uint64 {
	var lo, hi uint64 = 0, 0xfff
	a &= hi
	a |= lo

	z := -a

	if ensureAllBranchesCouldHappen() && z > -lo {
		return 42
	}
	if ensureAllBranchesCouldHappen() && z <= -lo {
		return 1337
	}
	if ensureAllBranchesCouldHappen() && z < -hi {
		return 42
	}
	if ensureAllBranchesCouldHappen() && z >= -hi {
		return 1337
	}
	return z
}

func phiMin(a, b []byte) {
	_ = a[:min(len(a), len(b))] // ERROR "Proved IsSliceInBounds"
	_ = b[:min(len(a), len(b))] // ERROR "Proved IsSliceInBounds"
	_ = a[:max(len(a), len(b))]
	_ = b[:max(len(a), len(b))]
	x := len(a)
	if x > len(b) {
		x = len(b)
		useInt(0)
	}
	_ = a[:x] // ERROR "Proved IsSliceInBounds"
	y := len(a)
	if y > len(b) {
		y = len(b)
		useInt(0)
	} else {
		useInt(1)
	}
	_ = b[:y] // ERROR "Proved IsSliceInBounds"
}

func issue16833(a, b []byte) {
	n := copy(a, b)
	_ = a[n:] // ERROR "Proved IsSliceInBounds"
	_ = b[n:] // ERROR "Proved IsSliceInBounds"
	_ = a[:n] // ERROR "Proved IsSliceInBounds"
	_ = b[:n] // ERROR "Proved IsSliceInBounds"
}

func clampedIdx1(x []int, i int) int {
	if len(x) == 0 {
		return 0
	}
	return x[min(max(0, i), len(x)-1)] // ERROR "Proved IsInBounds"
}
func clampedIdx2(x []int, i int) int {
	if len(x) == 0 {
		return 0
	}
	return x[max(min(i, len(x)-1), 0)] // TODO: can't get rid of this bounds check yet
}

//go:noinline
func useInt(a int) {
}

//go:noinline
func useSlice(a []int) {
}

func main() {
}
```