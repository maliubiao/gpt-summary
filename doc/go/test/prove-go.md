Response: My thought process for analyzing the Go code and fulfilling the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, what Go feature it demonstrates, examples, command-line arguments (if any), and common mistakes.

2. **Initial Scan and Keywords:** I quickly scan the code for keywords like `package`, `import`, `func`, `if`, `for`, `range`, and comments. The `// errorcheck`, `//go:build`, and `// Copyright` comments are immediately noticeable. The `ERROR "..."` comments within the function bodies also stand out.

3. **Identify Core Functionality:** The `// errorcheck` directive strongly suggests this code is part of the Go compiler's testing infrastructure. Specifically, it's designed to verify the "prove" phase of static analysis, which aims to prove certain conditions at compile time. The `ERROR` comments indicate expected outputs from the `prove` analysis. The `//go:build amd64` constraint is a platform-specific build tag.

4. **Deduce the "Prove" Feature:**  Based on the `// errorcheck` and `ERROR "Proved ..."` comments, I conclude that this code tests the Go compiler's ability to prove properties about the code. The specific examples overwhelmingly focus on proving:
    * **Bounds Checking Elimination (BCE):**  The "Proved IsInBounds$" and "Proved IsSliceInBounds$" errors indicate the compiler successfully determined that array/slice accesses are within valid ranges, thus the runtime bounds check is unnecessary.
    * **Logical Implications:** The "Proved Less64$", "Proved Leq64$", "Disproved Eq64$", etc., errors show the compiler's ability to deduce and disprove logical relationships between variables.
    * **Induction Variable Analysis:** The "Induction variable: limits ..." errors point to the compiler's capability to analyze loop counter variables and their ranges.
    * **Other Optimizations:** "Proved slicemask not needed$" hints at optimizations related to slice operations.

5. **Categorize and Analyze Functions:** I go through the functions, grouping them by the type of proving being tested:
    * **Basic Bounds Checks (f0, f1, f1b, f1c):** Demonstrating simple array access with and without prior length checks.
    * **Loop Bounds Checks (f2, f3, f17, range1, range2):** Showing how the compiler proves bounds within loops.
    * **Logical Condition Proving (f4a-f4f, f5, f6a-f6e, f8, f9, f13a-f13i, f20, f21, f22):**  Illustrating the compiler's ability to prove and disprove comparisons.
    * **Slice Operations (f11a-f11d, f12, f15, f16, f19, sm1, and, issue57077, issue16833, phiMin):** Focusing on proving the validity of slice creation and access.
    * **Integer Operations and Optimizations (f7, f10, f18, lim1, fence1-4, trans1-4, natcmp, suffix, constsuffix, sh64, sh32, divShiftClean, divu, modu1, modu2, issue45928, rshu, ctz64, bitLen64, xor64, or64, mod64uWithSmallerDividendMax, div64u, com64, neg64, trunc64to16):** Testing proving properties about arithmetic and bitwise operations.
    * **Specific Compiler Issues (f14, issue29502, issue42603, issue52563, issue51622, issue66826a, issue66826b):**  Likely regression tests for previously identified bugs.

6. **Construct Example Code:** For each category or interesting function, I create simplified Go code examples that demonstrate the "prove" functionality. I aim for clarity and conciseness. I include comments to explain the expected proving behavior and potential inputs/outputs where relevant.

7. **Identify Command-Line Arguments:**  The `// errorcheck -0 -d=ssa/prove/debug=1` line reveals the command-line arguments used to invoke the Go compiler for this specific test. I explain these flags: `-0` (disable optimizations), `-d=ssa/prove/debug=1` (enable debug output for the `prove` phase).

8. **Pinpoint Common Mistakes:** I consider how a developer might write similar code and miss the opportunity for the compiler to prove properties. Common mistakes include:
    * **Not checking slice length before access.**
    * **Writing redundant or contradictory conditions in `if` statements.**
    * **Overly complex loop conditions that hinder the compiler's analysis.**

9. **Structure the Output:** I organize the information into clear sections based on the prompt's requirements: Functionality, Go Feature, Examples, Command-Line Arguments, and Common Mistakes. I use code blocks and formatting for readability.

10. **Refine and Review:** I reread the code and my explanation to ensure accuracy, clarity, and completeness. I check that my examples are correct and effectively illustrate the points I'm making. I also double-check if I missed any key aspects of the code or the request.

This systematic approach helps me break down the complex code into manageable parts, understand its purpose, and effectively communicate its functionality and related information. The key is to recognize the testing nature of the code and the significance of the `// errorcheck` and `ERROR` comments.

这段Go语言代码片段是Go编译器测试套件的一部分，专门用于测试**静态单赋值形式 (SSA) 中 `prove` (证明) 阶段的功能**。`prove` 阶段是Go编译器进行静态分析和优化的一个重要环节，它的目标是在编译时**证明**某些代码属性为真，从而实现诸如**边界检查消除 (BCE)** 等优化。

以下是代码的功能点的详细解释：

**1. 边界检查消除 (BCE) 的测试:**

   - 代码中大量使用了形如 `a[i]` 的数组或切片访问，并在后续的代码中重复访问相同的元素。
   - 注释 `// ERROR "Proved IsInBounds$"` 表明编译器应该能够证明这些访问操作是在数组或切片的有效索引范围内，从而在最终的机器码中消除运行时的边界检查，提高性能。
   - 例如 `f0` 函数中，多次访问 `a[0]` 和 `a[6]`，编译器在第一次访问后应该能证明后续的访问是安全的。

   ```go
   func f0(a []int) int {
       a[0] = 1
       a[0] = 1 // ERROR "Proved IsInBounds$"
       // ...
   }
   ```

**2. 基于条件判断的边界检查消除:**

   - `f1` 函数通过 `if len(a) <= 5` 检查切片长度，如果在 `if` 块之外访问 `a[6]`，编译器仍然需要进行边界检查。
   - 但在 `if` 块内部，由于 `len(a) > 5`，访问 `a[0]` 到 `a[5]` 是安全的，编译器应该能证明。

   ```go
   func f1(a []int) int {
       if len(a) <= 5 {
           return 18
       }
       a[0] = 1 // ERROR "Proved IsInBounds$"
       // ...
       a[5] = 1 // ERROR "Proved IsInBounds$"
       return 26
   }
   ```

**3. 更复杂的索引条件证明:**

   - `f1b` 函数展示了更复杂的索引条件判断，例如 `i >= 0 && i < len(a)`，编译器需要推断出在这些条件下访问 `a[i]` 是安全的。

   ```go
   func f1b(a []int, i int, j uint) int {
       if i >= 0 && i < len(a) {
           return a[i] // ERROR "Proved IsInBounds$"
       }
       // ...
   }
   ```

**4. 循环中的边界检查消除:**

   - `f2` 和 `f3` 函数演示了在 `for...range` 和普通 `for` 循环中，编译器如何证明索引访问的安全性。
   - `// ERROR "Induction variable: limits \[0,\?\), increment 1$"` 注释表明编译器识别了循环变量的范围和步长。

   ```go
   func f2(a []int) int {
       for i := range a { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
           a[i+1] = i
           a[i+1] = i // ERROR "Proved IsInBounds$"
       }
       return 34
   }
   ```

**5. 基于逻辑推理的条件证明:**

   - `f4a` 到 `f4f` 以及后续的 `f5`, `f6a` 等函数，测试了编译器进行逻辑推理的能力。例如，如果 `a < b` 并且后面又判断 `a == b`，编译器应该能推断出 `a == b` 的条件永远为假 (`// ERROR "Disproved Eq64$"`）。反之，如果条件可以被证明为真 (`// ERROR "Proved Less64$"`）。

   ```go
   func f4a(a, b, c int) int {
       if a < b {
           if a == b { // ERROR "Disproved Eq64$"
               return 47
           }
           // ...
       }
       return 63
   }
   ```

**6. 其他优化证明:**

   - `sm1` 函数测试了编译器能否证明在某些切片操作中不需要进行 `slicemask` 操作。
   - 涉及到位运算、类型转换、字符串操作等，也都有相应的测试用例来验证 `prove` 阶段的正确性。

**7. 测试归纳变量分析:**

   - 许多循环结构的测试用例（例如 `f2`, `f3`, `range1`, `range2`, `signHint1`, `unrollUpExcl` 等）旨在验证编译器是否能够正确分析循环中的归纳变量，并利用这些信息进行优化。

**8. 测试常量传播和计算:**

   - `f6a` 和 `f6b` 中，`a < a` 永远为假，编译器应该能直接识别并标记为 `Disproved Less8U$`.

**9. 测试位操作相关的证明:**

   - `ctz64`, `bitLen64`, `xor64`, `or64` 等函数测试了编译器对于位操作函数的推理能力，例如 `bits.TrailingZeros64(x)` 返回的是非负数 (`Proved Ctz64 non-zero$`).

**推断 Go 语言功能实现：静态分析和优化（特别是边界检查消除）**

这个代码片段主要测试了Go编译器中用于静态分析和优化的 `prove` 阶段。`prove` 阶段的核心目标是通过分析程序的 SSA 中间表示，**证明**关于变量、表达式和控制流的各种属性。这些被证明的属性可以用于后续的优化阶段，例如消除冗余的边界检查，提高程序的执行效率。

**Go 代码举例说明:**

假设我们有以下简单的 Go 代码：

```go
package main

func main() {
	arr := [5]int{1, 2, 3, 4, 5}
	index := 2
	_ = arr[index] // 编译器可能无法直接证明 index < 5
	if index >= 0 && index < len(arr) {
		_ = arr[index] // 编译器应该能够证明此处访问安全
	}
}
```

`prove` 阶段的目标是证明第二个 `arr[index]` 的访问是安全的，因为在 `if` 条件中已经保证了 `index` 的取值范围。

**带假设的输入与输出（代码推理）:**

考虑函数 `f1b`：

```go
func f1b(a []int, i int, j uint) int {
	if i >= 0 && i < len(a) {
		return a[i] // ERROR "Proved IsInBounds$"
	}
	// ...
}
```

**假设输入:**

```
a := []int{1, 2, 3}
i := 1
j := uint(0)
```

**预期输出 (基于 `prove` 阶段的分析):**

当程序执行到 `return a[i]` 时，由于 `i` 的值为 1，且 `len(a)` 为 3，条件 `i >= 0 && i < len(a)` 为真。因此，`prove` 阶段会证明 `a[i]` 的访问是合法的，从而消除运行时的边界检查。这就是 `// ERROR "Proved IsInBounds$"` 的含义。

**命令行参数的具体处理:**

代码开头的 `// errorcheck -0 -d=ssa/prove/debug=1` 注释指示了运行此测试用例时需要传递的命令行参数给 Go 编译器：

- **`-0`**:  这个标志告诉编译器禁用一些优化。这看似反常，但在这里的目的是为了更清晰地观察 `prove` 阶段本身的效果。如果开启了所有优化，后续的优化阶段可能会将 `prove` 阶段的成果进一步转化，导致测试结果不那么直接。
- **`-d=ssa/prove/debug=1`**: 这个标志启用了 `ssa/prove` 模块的调试输出，级别为 1。这会在编译过程中打印出 `prove` 阶段的详细信息，例如它成功证明了哪些属性，或者未能证明哪些。这对于开发和调试 `prove` 阶段的功能非常有用。

**使用者易犯错的点:**

开发者在编写代码时，如果未能充分利用Go编译器的静态分析能力，可能会无意中阻止 `prove` 阶段证明某些属性，导致潜在的性能损失（因为边界检查没有被消除）。

**例子：**

```go
func process(data []int, index int) {
    if index >= 0 {
        if index < len(data) {
            _ = data[index] // 编译器可以证明此处安全
        }
    }
}

func processWithError(data []int, index int) {
    if index >= 0 && index < len(data) {
        _ = data[index] // 编译器可以证明此处安全
    }
}

func processLessOptimal(data []int, index int) {
    if index >= 0 {
        // 这里即使有 index < len(data) 的判断，
        // 如果在外部访问，编译器可能无法像第一个例子那样直接证明
    }
    if index < len(data) && index >= 0 {
        _ = data[index] // 编译器可以证明此处安全
    }
}

func processHardToProve(data []int, index int) {
    if someExternalCondition() {
        if index >= 0 && index < len(data) {
            _ = data[index] // 如果 someExternalCondition() 的结果在编译时未知，证明会更困难
        }
    }
}
```

- **不必要的重复判断:** 在 `processLessOptimal` 中，虽然条件相同，但分开写可能会影响编译器的分析。
- **复杂的外部条件:** 在 `processHardToProve` 中，如果条件依赖于运行时信息，静态分析可能无法进行。
- **忘记检查边界:** 最常见的错误是直接访问数组或切片，而没有先进行边界检查，这会导致运行时错误。

总而言之，这个代码片段是Go编译器内部用于测试其静态分析和优化能力的重要组成部分，特别是针对 `prove` 阶段的功能验证。通过大量的测试用例，确保编译器能够正确地推断代码属性，从而实现更高效和安全的代码生成。

Prompt: 
```
这是路径为go/test/prove.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
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

"""



```