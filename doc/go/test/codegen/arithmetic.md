Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the given Go code and relate it to Go compiler optimizations. The `// asmcheck` comment is a strong hint that this code is designed to verify the assembly output of the Go compiler for specific arithmetic operations.

**2. Initial Scan and Pattern Recognition:**

The first pass involves quickly scanning the code and looking for recurring patterns. Key observations include:

* **Function Naming:** Descriptive names like `AddLargeConst`, `SubMem`, `Pow2Muls`, `ConstDivs`, `LenDiv1`, `Int64Min`, etc., strongly suggest the operations being tested.
* **Comments with Assembly Directives:** Lines like `// ppc64x/power10:"ADD\t[$]4294967296,"` are crucial. They indicate expected assembly instructions for specific architectures and sub-architectures. This is the core of the `asmcheck` functionality.
* **Simple Arithmetic Operations:** The function bodies contain basic arithmetic operations (+, -, *, /, %, bit shifts) with various combinations of variables and constants.
* **Focus on Integers:** The code primarily deals with integer types (`int`, `uint`, `int64`, `uint64`, etc.). There are some sections for floats as well.
* **`asmcheck` Comment:** This comment at the beginning signals that the file is used for assembly code verification.

**3. Deciphering the `asmcheck` Mechanism:**

The assembly directive comments are the key to understanding the file's purpose. The format seems to be:

`// architecture[/sub-architecture]:"assembly instruction pattern", "optional additional pattern", ...`

This indicates that the `asmcheck` tool (or a similar mechanism) will compile this Go code for the specified architectures and verify that the generated assembly code matches the provided patterns. This is how compiler optimizations are verified – by checking if the compiler produces the expected efficient assembly instructions.

**4. Grouping by Functionality:**

The code is logically divided into sections based on arithmetic operations (Addition, Subtraction, Multiplication, Division, Modulo, etc.). This organization makes it easier to understand the purpose of each set of functions.

**5. Analyzing Individual Functions (Example: `AddLargeConst`):**

Let's take `AddLargeConst` as an example:

* **Input:** `a uint64`, `out []uint64`
* **Operation:** Adds various large constants (positive and negative) to `a` and stores the results in the `out` slice.
* **Assembly Directives:** The comments show the expected assembly instructions for different PPC64x processor architectures (power10, power9, power8). This tells us that the test is checking how the compiler optimizes the addition of large constants on these architectures. For instance, for `a + 0x100000000`, the expectation on power10 is a single `ADD` instruction with the immediate value, while older architectures might require multiple instructions (load, shift, add).

**6. Generalizing the Functionality:**

After analyzing a few functions, the overall purpose becomes clear:

* **Testing Compiler Optimizations:** The code aims to test whether the Go compiler correctly applies optimizations for various arithmetic operations on different architectures.
* **Focus on Assembly Output:** The verification is done by checking the generated assembly code.
* **Specific Architectures:** The `asmcheck` directives target specific architectures (amd64, 386, arm, arm64, ppc64x, s390x, riscv64).
* **Testing Edge Cases and Common Patterns:** The code includes tests for large constants, powers of two, signed/unsigned operations, and common simplification rules.

**7. Inferring Go Language Features (Based on Optimizations):**

By observing the tested optimizations, we can infer the Go language features involved:

* **Integer Arithmetic:** The core focus is on integer addition, subtraction, multiplication, division, and modulo operations.
* **Unsigned and Signed Integers:** The code handles both unsigned (`uint`) and signed (`int`) integer types.
* **Slices:**  Slices are used as input and output in some functions.
* **Constants:**  The tests often involve arithmetic with constant values.
* **Function Calls (`len`, `cap`, `min`, `max`):**  Optimizations related to built-in functions are also tested.

**8. Constructing Go Code Examples:**

Based on the identified functionalities, we can create simple Go code examples that demonstrate the operations being tested. This helps to illustrate the concepts in a practical way.

**9. Inferring Command-Line Arguments (If Applicable):**

While the provided code itself doesn't explicitly show command-line argument parsing, the `asmcheck` comment strongly implies the existence of a testing tool. We can infer that this tool likely takes the Go source file as input and potentially architecture targets as command-line arguments to perform the assembly checks.

**10. Identifying Potential Pitfalls:**

Analyzing the optimizations can reveal potential pitfalls for users:

* **Assuming Naive Compilation:** Developers might assume their code will be compiled literally, without optimizations. Understanding that the compiler might transform their code (e.g., turning division by a constant into multiplication) is important for performance considerations and debugging.
* **Micro-optimizations:**  While the compiler does a good job of optimizing, attempting manual micro-optimizations might sometimes be counterproductive or even hinder the compiler's own optimization passes.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption:** I might initially think the code is directly related to implementing arithmetic operations *within* the Go runtime. However, the `asmcheck` comments quickly correct this to indicate it's about *testing the compiler's optimization* of these operations.
* **Focusing on Specific Architectures:**  It's important to note the architecture-specific assembly directives. The optimizations might vary across different platforms.

By following this structured thought process, combining pattern recognition, logical deduction, and understanding the purpose of the `asmcheck` mechanism, we can effectively analyze the provided Go code snippet and summarize its functionality.
这个 `go/test/codegen/arithmetic.go` 文件是 Go 语言代码生成测试的一部分，专门用于测试 **整数类型的算术运算简化和优化**。

**功能归纳:**

该文件的主要功能是定义了一系列 Go 函数，这些函数包含了各种整数类型的算术运算（加法、减法、乘法、除法、取模等），并通过在注释中嵌入特定架构下的预期汇编指令，来验证 Go 编译器是否对这些运算进行了正确的优化。

**推理 Go 语言功能实现:**

这个文件本身 **不是** Go 语言某个特定功能的实现。它更像是一个测试工具，用于验证 Go 编译器在代码生成阶段的功能，特别是算术运算的优化。它依赖于 Go 编译器的内部机制来生成汇编代码。

**Go 代码举例说明 (展示被测试的 Go 语言功能):**

以下是一些简单的 Go 代码示例，展示了文件中正在测试的 Go 语言算术运算功能：

```go
package main

import "fmt"

func main() {
	a := 10
	b := 5
	var c int

	// 加法
	c = a + b
	fmt.Println("a + b =", c)

	// 减法
	c = a - b
	fmt.Println("a - b =", c)

	// 乘法
	c = a * b
	fmt.Println("a * b =", c)

	// 除法
	c = a / b
	fmt.Println("a / b =", c)

	// 取模
	c = a % b
	fmt.Println("a % b =", c)
}
```

**代码逻辑介绍 (带假设的输入与输出):**

每个函数都针对特定的算术运算场景进行测试。例如 `AddLargeConst` 函数：

**假设输入:**
`a = 10` (uint64 类型)
`out` 是一个长度至少为 10 的 `uint64` 类型的切片。

**代码逻辑:**
该函数将 `a` 与不同的常量进行加减运算，并将结果存储到 `out` 切片中。  关键在于注释中指定的汇编指令，例如 `// ppc64x/power10:"ADD\t[$]4294967296,"`，这表明在 ppc64x 架构的 power10 子架构上，编译器应该使用一条 `ADD` 指令，并将立即数 `4294967296` 直接加到寄存器中。

**预期输出 (部分):**
`out[0]` 的值应该为 `10 + 4294967296 = 4294967206`
`out[1]` 的值应该为 `10 + 0xFFFFFFFE00000000 = 18446744073709551626`
...以此类推。

**涉及的命令行参数的具体处理:**

这个文件本身不直接处理命令行参数。它是作为 Go 编译器测试套件的一部分运行的。通常，Go 编译器的测试工具（例如 `go test`）会根据特定的配置和目标架构来编译和运行这些测试文件。

测试工具会解析注释中的架构信息（例如 `ppc64x/power10`），然后针对该架构编译代码，并检查生成的汇编代码是否符合注释中指定的模式。

**使用者易犯错的点:**

这个文件主要是给 Go 编译器开发者使用的，普通 Go 语言使用者不会直接修改或运行它。但是，理解其背后的原理可以帮助开发者避免一些性能陷阱：

1. **假设编译器不会优化：**  开发者可能会编写冗余的代码，认为编译器会逐行执行。但实际上，Go 编译器会进行各种优化，例如将常量运算直接计算出来，或者将乘以 2 的幂转换为位移操作。

   **例如：**

   ```go
   func calculate() int {
       x := 5
       y := 10
       return x * 8 // 开发者可能认为这里会执行乘法
   }
   ```

   Go 编译器很可能会将 `x * 8` 优化为 `x << 3` (左移 3 位)，因为位移运算通常比乘法运算更快。

2. **过度手动优化：**  有时开发者可能会尝试手动进行一些微优化，但这可能会与编译器的优化策略冲突，反而导致性能下降或代码可读性变差。

   **例如：**

   ```go
   // 不推荐：尝试手动进行除以 2 的幂的优化
   func divideByPowerOfTwo(n int) int {
       if n >= 0 {
           return n >> 2
       } else {
           // ... 需要处理负数的情况，比较复杂
           return n / 4
       }
   }

   // 推荐：直接使用除法，编译器会进行优化
   func divideByFour(n int) int {
       return n / 4
   }
   ```

   Go 编译器对于除以 2 的幂的情况会进行优化，开发者无需手动进行位移操作，反而可能引入额外的复杂性。

**总结:**

`go/test/codegen/arithmetic.go` 是 Go 语言代码生成测试套件的关键组成部分，用于验证编译器在处理整数算术运算时的优化能力。它通过对比生成的汇编代码与预期指令来确保编译器的正确性。理解其背后的原理有助于 Go 开发者编写更高效且符合语言习惯的代码。

### 提示词
```
这是路径为go/test/codegen/arithmetic.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// asmcheck

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

// This file contains codegen tests related to arithmetic
// simplifications and optimizations on integer types.
// For codegen tests on float types, see floats.go.

// ----------------- //
//    Addition       //
// ----------------- //

func AddLargeConst(a uint64, out []uint64) {
	// ppc64x/power10:"ADD\t[$]4294967296,"
	// ppc64x/power9:"MOVD\t[$]1", "SLD\t[$]32" "ADD\tR[0-9]*"
	// ppc64x/power8:"MOVD\t[$]1", "SLD\t[$]32" "ADD\tR[0-9]*"
	out[0] = a + 0x100000000
	// ppc64x/power10:"ADD\t[$]-8589934592,"
	// ppc64x/power9:"MOVD\t[$]-1", "SLD\t[$]33" "ADD\tR[0-9]*"
	// ppc64x/power8:"MOVD\t[$]-1", "SLD\t[$]33" "ADD\tR[0-9]*"
	out[1] = a + 0xFFFFFFFE00000000
	// ppc64x/power10:"ADD\t[$]1234567,"
	// ppc64x/power9:"ADDIS\t[$]19,", "ADD\t[$]-10617,"
	// ppc64x/power8:"ADDIS\t[$]19,", "ADD\t[$]-10617,"
	out[2] = a + 1234567
	// ppc64x/power10:"ADD\t[$]-1234567,"
	// ppc64x/power9:"ADDIS\t[$]-19,", "ADD\t[$]10617,"
	// ppc64x/power8:"ADDIS\t[$]-19,", "ADD\t[$]10617,"
	out[3] = a - 1234567
	// ppc64x/power10:"ADD\t[$]2147450879,"
	// ppc64x/power9:"ADDIS\t[$]32767,", "ADD\t[$]32767,"
	// ppc64x/power8:"ADDIS\t[$]32767,", "ADD\t[$]32767,"
	out[4] = a + 0x7FFF7FFF
	// ppc64x/power10:"ADD\t[$]-2147483647,"
	// ppc64x/power9:"ADDIS\t[$]-32768,", "ADD\t[$]1,"
	// ppc64x/power8:"ADDIS\t[$]-32768,", "ADD\t[$]1,"
	out[5] = a - 2147483647
	// ppc64x:"ADDIS\t[$]-32768,", ^"ADD\t"
	out[6] = a - 2147483648
	// ppc64x:"ADD\t[$]2147450880,", ^"ADDIS\t"
	out[7] = a + 0x7FFF8000
	// ppc64x:"ADD\t[$]-32768,", ^"ADDIS\t"
	out[8] = a - 32768
	// ppc64x/power10:"ADD\t[$]-32769,"
	// ppc64x/power9:"ADDIS\t[$]-1,", "ADD\t[$]32767,"
	// ppc64x/power8:"ADDIS\t[$]-1,", "ADD\t[$]32767,"
	out[9] = a - 32769
}

// ----------------- //
//    Subtraction    //
// ----------------- //

var ef int

func SubMem(arr []int, b, c, d int) int {
	// 386:`SUBL\s[A-Z]+,\s8\([A-Z]+\)`
	// amd64:`SUBQ\s[A-Z]+,\s16\([A-Z]+\)`
	arr[2] -= b
	// 386:`SUBL\s[A-Z]+,\s12\([A-Z]+\)`
	// amd64:`SUBQ\s[A-Z]+,\s24\([A-Z]+\)`
	arr[3] -= b
	// 386:`DECL\s16\([A-Z]+\)`
	arr[4]--
	// 386:`ADDL\s[$]-20,\s20\([A-Z]+\)`
	arr[5] -= 20
	// 386:`SUBL\s\([A-Z]+\)\([A-Z]+\*4\),\s[A-Z]+`
	ef -= arr[b]
	// 386:`SUBL\s[A-Z]+,\s\([A-Z]+\)\([A-Z]+\*4\)`
	arr[c] -= b
	// 386:`ADDL\s[$]-15,\s\([A-Z]+\)\([A-Z]+\*4\)`
	arr[d] -= 15
	// 386:`DECL\s\([A-Z]+\)\([A-Z]+\*4\)`
	arr[b]--
	// amd64:`DECQ\s64\([A-Z]+\)`
	arr[8]--
	// 386:"SUBL\t4"
	// amd64:"SUBQ\t8"
	return arr[0] - arr[1]
}

func SubFromConst(a int) int {
	// ppc64x: `SUBC\tR[0-9]+,\s[$]40,\sR`
	b := 40 - a
	return b
}

func SubFromConstNeg(a int) int {
	// ppc64x: `ADD\t[$]40,\sR[0-9]+,\sR`
	c := 40 - (-a)
	return c
}

func SubSubFromConst(a int) int {
	// ppc64x: `ADD\t[$]20,\sR[0-9]+,\sR`
	c := 40 - (20 - a)
	return c
}

func AddSubFromConst(a int) int {
	// ppc64x: `SUBC\tR[0-9]+,\s[$]60,\sR`
	c := 40 + (20 - a)
	return c
}

func NegSubFromConst(a int) int {
	// ppc64x: `ADD\t[$]-20,\sR[0-9]+,\sR`
	c := -(20 - a)
	return c
}

func NegAddFromConstNeg(a int) int {
	// ppc64x: `SUBC\tR[0-9]+,\s[$]40,\sR`
	c := -(-40 + a)
	return c
}

func SubSubNegSimplify(a, b int) int {
	// amd64:"NEGQ"
	// ppc64x:"NEG"
	r := (a - b) - a
	return r
}

func SubAddSimplify(a, b int) int {
	// amd64:-"SUBQ",-"ADDQ"
	// ppc64x:-"SUB",-"ADD"
	r := a + (b - a)
	return r
}

func SubAddSimplify2(a, b, c int) (int, int, int, int, int, int) {
	// amd64:-"ADDQ"
	r := (a + b) - (a + c)
	// amd64:-"ADDQ"
	r1 := (a + b) - (c + a)
	// amd64:-"ADDQ"
	r2 := (b + a) - (a + c)
	// amd64:-"ADDQ"
	r3 := (b + a) - (c + a)
	// amd64:-"SUBQ"
	r4 := (a - c) + (c + b)
	// amd64:-"SUBQ"
	r5 := (a - c) + (b + c)
	return r, r1, r2, r3, r4, r5
}

func SubAddNegSimplify(a, b int) int {
	// amd64:"NEGQ",-"ADDQ",-"SUBQ"
	// ppc64x:"NEG",-"ADD",-"SUB"
	r := a - (b + a)
	return r
}

func AddAddSubSimplify(a, b, c int) int {
	// amd64:-"SUBQ"
	// ppc64x:-"SUB"
	r := a + (b + (c - a))
	return r
}

// -------------------- //
//    Multiplication    //
// -------------------- //

func Pow2Muls(n1, n2 int) (int, int) {
	// amd64:"SHLQ\t[$]5",-"IMULQ"
	// 386:"SHLL\t[$]5",-"IMULL"
	// arm:"SLL\t[$]5",-"MUL"
	// arm64:"LSL\t[$]5",-"MUL"
	// ppc64x:"SLD\t[$]5",-"MUL"
	a := n1 * 32

	// amd64:"SHLQ\t[$]6",-"IMULQ"
	// 386:"SHLL\t[$]6",-"IMULL"
	// arm:"SLL\t[$]6",-"MUL"
	// arm64:`NEG\sR[0-9]+<<6,\sR[0-9]+`,-`LSL`,-`MUL`
	// ppc64x:"SLD\t[$]6","NEG\\sR[0-9]+,\\sR[0-9]+",-"MUL"
	b := -64 * n2

	return a, b
}

func Mul_96(n int) int {
	// amd64:`SHLQ\t[$]5`,`LEAQ\t\(.*\)\(.*\*2\),`,-`IMULQ`
	// 386:`SHLL\t[$]5`,`LEAL\t\(.*\)\(.*\*2\),`,-`IMULL`
	// arm64:`LSL\t[$]5`,`ADD\sR[0-9]+<<1,\sR[0-9]+`,-`MUL`
	// arm:`SLL\t[$]5`,`ADD\sR[0-9]+<<1,\sR[0-9]+`,-`MUL`
	// s390x:`SLD\t[$]5`,`SLD\t[$]6`,-`MULLD`
	return n * 96
}

func Mul_n120(n int) int {
	// s390x:`SLD\t[$]3`,`SLD\t[$]7`,-`MULLD`
	return n * -120
}

func MulMemSrc(a []uint32, b []float32) {
	// 386:`IMULL\s4\([A-Z]+\),\s[A-Z]+`
	a[0] *= a[1]
	// 386/sse2:`MULSS\s4\([A-Z]+\),\sX[0-9]+`
	// amd64:`MULSS\s4\([A-Z]+\),\sX[0-9]+`
	b[0] *= b[1]
}

// Multiplications merging tests

func MergeMuls1(n int) int {
	// amd64:"IMUL3Q\t[$]46"
	// 386:"IMUL3L\t[$]46"
	// ppc64x:"MULLD\t[$]46"
	return 15*n + 31*n // 46n
}

func MergeMuls2(n int) int {
	// amd64:"IMUL3Q\t[$]23","(ADDQ\t[$]29)|(LEAQ\t29)"
	// 386:"IMUL3L\t[$]23","ADDL\t[$]29"
	// ppc64x/power9:"MADDLD",-"MULLD\t[$]23",-"ADD\t[$]29"
	// ppc64x/power8:"MULLD\t[$]23","ADD\t[$]29"
	return 5*n + 7*(n+1) + 11*(n+2) // 23n + 29
}

func MergeMuls3(a, n int) int {
	// amd64:"ADDQ\t[$]19",-"IMULQ\t[$]19"
	// 386:"ADDL\t[$]19",-"IMULL\t[$]19"
	// ppc64x:"ADD\t[$]19",-"MULLD\t[$]19"
	return a*n + 19*n // (a+19)n
}

func MergeMuls4(n int) int {
	// amd64:"IMUL3Q\t[$]14"
	// 386:"IMUL3L\t[$]14"
	// ppc64x:"MULLD\t[$]14"
	return 23*n - 9*n // 14n
}

func MergeMuls5(a, n int) int {
	// amd64:"ADDQ\t[$]-19",-"IMULQ\t[$]19"
	// 386:"ADDL\t[$]-19",-"IMULL\t[$]19"
	// ppc64x:"ADD\t[$]-19",-"MULLD\t[$]19"
	return a*n - 19*n // (a-19)n
}

// -------------- //
//    Division    //
// -------------- //

func DivMemSrc(a []float64) {
	// 386/sse2:`DIVSD\s8\([A-Z]+\),\sX[0-9]+`
	// amd64:`DIVSD\s8\([A-Z]+\),\sX[0-9]+`
	a[0] /= a[1]
}

func Pow2Divs(n1 uint, n2 int) (uint, int) {
	// 386:"SHRL\t[$]5",-"DIVL"
	// amd64:"SHRQ\t[$]5",-"DIVQ"
	// arm:"SRL\t[$]5",-".*udiv"
	// arm64:"LSR\t[$]5",-"UDIV"
	// ppc64x:"SRD"
	a := n1 / 32 // unsigned

	// amd64:"SARQ\t[$]6",-"IDIVQ"
	// 386:"SARL\t[$]6",-"IDIVL"
	// arm:"SRA\t[$]6",-".*udiv"
	// arm64:"ASR\t[$]6",-"SDIV"
	// ppc64x:"SRAD"
	b := n2 / 64 // signed

	return a, b
}

// Check that constant divisions get turned into MULs
func ConstDivs(n1 uint, n2 int) (uint, int) {
	// amd64:"MOVQ\t[$]-1085102592571150095","MULQ",-"DIVQ"
	// 386:"MOVL\t[$]-252645135","MULL",-"DIVL"
	// arm64:`MOVD`,`UMULH`,-`DIV`
	// arm:`MOVW`,`MUL`,-`.*udiv`
	a := n1 / 17 // unsigned

	// amd64:"MOVQ\t[$]-1085102592571150095","IMULQ",-"IDIVQ"
	// 386:"MOVL\t[$]-252645135","IMULL",-"IDIVL"
	// arm64:`SMULH`,-`DIV`
	// arm:`MOVW`,`MUL`,-`.*udiv`
	b := n2 / 17 // signed

	return a, b
}

func FloatDivs(a []float32) float32 {
	// amd64:`DIVSS\s8\([A-Z]+\),\sX[0-9]+`
	// 386/sse2:`DIVSS\s8\([A-Z]+\),\sX[0-9]+`
	return a[1] / a[2]
}

func Pow2Mods(n1 uint, n2 int) (uint, int) {
	// 386:"ANDL\t[$]31",-"DIVL"
	// amd64:"ANDL\t[$]31",-"DIVQ"
	// arm:"AND\t[$]31",-".*udiv"
	// arm64:"AND\t[$]31",-"UDIV"
	// ppc64x:"RLDICL"
	a := n1 % 32 // unsigned

	// 386:"SHRL",-"IDIVL"
	// amd64:"SHRQ",-"IDIVQ"
	// arm:"SRA",-".*udiv"
	// arm64:"ASR",-"REM"
	// ppc64x:"SRAD"
	b := n2 % 64 // signed

	return a, b
}

// Check that signed divisibility checks get converted to AND on low bits
func Pow2DivisibleSigned(n1, n2 int) (bool, bool) {
	// 386:"TESTL\t[$]63",-"DIVL",-"SHRL"
	// amd64:"TESTQ\t[$]63",-"DIVQ",-"SHRQ"
	// arm:"AND\t[$]63",-".*udiv",-"SRA"
	// arm64:"TST\t[$]63",-"UDIV",-"ASR",-"AND"
	// ppc64x:"ANDCC",-"RLDICL",-"SRAD",-"CMP"
	a := n1%64 == 0 // signed divisible

	// 386:"TESTL\t[$]63",-"DIVL",-"SHRL"
	// amd64:"TESTQ\t[$]63",-"DIVQ",-"SHRQ"
	// arm:"AND\t[$]63",-".*udiv",-"SRA"
	// arm64:"TST\t[$]63",-"UDIV",-"ASR",-"AND"
	// ppc64x:"ANDCC",-"RLDICL",-"SRAD",-"CMP"
	b := n2%64 != 0 // signed indivisible

	return a, b
}

// Check that constant modulo divs get turned into MULs
func ConstMods(n1 uint, n2 int) (uint, int) {
	// amd64:"MOVQ\t[$]-1085102592571150095","MULQ",-"DIVQ"
	// 386:"MOVL\t[$]-252645135","MULL",-"DIVL"
	// arm64:`MOVD`,`UMULH`,-`DIV`
	// arm:`MOVW`,`MUL`,-`.*udiv`
	a := n1 % 17 // unsigned

	// amd64:"MOVQ\t[$]-1085102592571150095","IMULQ",-"IDIVQ"
	// 386:"MOVL\t[$]-252645135","IMULL",-"IDIVL"
	// arm64:`SMULH`,-`DIV`
	// arm:`MOVW`,`MUL`,-`.*udiv`
	b := n2 % 17 // signed

	return a, b
}

// Check that divisibility checks x%c==0 are converted to MULs and rotates
func DivisibleU(n uint) (bool, bool) {
	// amd64:"MOVQ\t[$]-6148914691236517205","IMULQ","ROLQ\t[$]63",-"DIVQ"
	// 386:"IMUL3L\t[$]-1431655765","ROLL\t[$]31",-"DIVQ"
	// arm64:"MOVD\t[$]-6148914691236517205","MOVD\t[$]3074457345618258602","MUL","ROR",-"DIV"
	// arm:"MUL","CMP\t[$]715827882",-".*udiv"
	// ppc64x:"MULLD","ROTL\t[$]63"
	even := n%6 == 0

	// amd64:"MOVQ\t[$]-8737931403336103397","IMULQ",-"ROLQ",-"DIVQ"
	// 386:"IMUL3L\t[$]678152731",-"ROLL",-"DIVQ"
	// arm64:"MOVD\t[$]-8737931403336103397","MUL",-"ROR",-"DIV"
	// arm:"MUL","CMP\t[$]226050910",-".*udiv"
	// ppc64x:"MULLD",-"ROTL"
	odd := n%19 == 0

	return even, odd
}

func Divisible(n int) (bool, bool) {
	// amd64:"IMULQ","ADD","ROLQ\t[$]63",-"DIVQ"
	// 386:"IMUL3L\t[$]-1431655765","ADDL\t[$]715827882","ROLL\t[$]31",-"DIVQ"
	// arm64:"MOVD\t[$]-6148914691236517205","MOVD\t[$]3074457345618258602","MUL","ADD\tR","ROR",-"DIV"
	// arm:"MUL","ADD\t[$]715827882",-".*udiv"
	// ppc64x/power8:"MULLD","ADD","ROTL\t[$]63"
	// ppc64x/power9:"MADDLD","ROTL\t[$]63"
	even := n%6 == 0

	// amd64:"IMULQ","ADD",-"ROLQ",-"DIVQ"
	// 386:"IMUL3L\t[$]678152731","ADDL\t[$]113025455",-"ROLL",-"DIVQ"
	// arm64:"MUL","MOVD\t[$]485440633518672410","ADD",-"ROR",-"DIV"
	// arm:"MUL","ADD\t[$]113025455",-".*udiv"
	// ppc64x/power8:"MULLD","ADD",-"ROTL"
	// ppc64x/power9:"MADDLD",-"ROTL"
	odd := n%19 == 0

	return even, odd
}

// Check that fix-up code is not generated for divisions where it has been proven that
// that the divisor is not -1 or that the dividend is > MinIntNN.
func NoFix64A(divr int64) (int64, int64) {
	var d int64 = 42
	var e int64 = 84
	if divr > 5 {
		d /= divr // amd64:-"JMP"
		e %= divr // amd64:-"JMP"
		// The following statement is to avoid conflict between the above check
		// and the normal JMP generated at the end of the block.
		d += e
	}
	return d, e
}

func NoFix64B(divd int64) (int64, int64) {
	var d int64
	var e int64
	var divr int64 = -1
	if divd > -9223372036854775808 {
		d = divd / divr // amd64:-"JMP"
		e = divd % divr // amd64:-"JMP"
		d += e
	}
	return d, e
}

func NoFix32A(divr int32) (int32, int32) {
	var d int32 = 42
	var e int32 = 84
	if divr > 5 {
		// amd64:-"JMP"
		// 386:-"JMP"
		d /= divr
		// amd64:-"JMP"
		// 386:-"JMP"
		e %= divr
		d += e
	}
	return d, e
}

func NoFix32B(divd int32) (int32, int32) {
	var d int32
	var e int32
	var divr int32 = -1
	if divd > -2147483648 {
		// amd64:-"JMP"
		// 386:-"JMP"
		d = divd / divr
		// amd64:-"JMP"
		// 386:-"JMP"
		e = divd % divr
		d += e
	}
	return d, e
}

func NoFix16A(divr int16) (int16, int16) {
	var d int16 = 42
	var e int16 = 84
	if divr > 5 {
		// amd64:-"JMP"
		// 386:-"JMP"
		d /= divr
		// amd64:-"JMP"
		// 386:-"JMP"
		e %= divr
		d += e
	}
	return d, e
}

func NoFix16B(divd int16) (int16, int16) {
	var d int16
	var e int16
	var divr int16 = -1
	if divd > -32768 {
		// amd64:-"JMP"
		// 386:-"JMP"
		d = divd / divr
		// amd64:-"JMP"
		// 386:-"JMP"
		e = divd % divr
		d += e
	}
	return d, e
}

// Check that len() and cap() calls divided by powers of two are
// optimized into shifts and ands

func LenDiv1(a []int) int {
	// 386:"SHRL\t[$]10"
	// amd64:"SHRQ\t[$]10"
	// arm64:"LSR\t[$]10",-"SDIV"
	// arm:"SRL\t[$]10",-".*udiv"
	// ppc64x:"SRD"\t[$]10"
	return len(a) / 1024
}

func LenDiv2(s string) int {
	// 386:"SHRL\t[$]11"
	// amd64:"SHRQ\t[$]11"
	// arm64:"LSR\t[$]11",-"SDIV"
	// arm:"SRL\t[$]11",-".*udiv"
	// ppc64x:"SRD\t[$]11"
	return len(s) / (4097 >> 1)
}

func LenMod1(a []int) int {
	// 386:"ANDL\t[$]1023"
	// amd64:"ANDL\t[$]1023"
	// arm64:"AND\t[$]1023",-"SDIV"
	// arm/6:"AND",-".*udiv"
	// arm/7:"BFC",-".*udiv",-"AND"
	// ppc64x:"RLDICL"
	return len(a) % 1024
}

func LenMod2(s string) int {
	// 386:"ANDL\t[$]2047"
	// amd64:"ANDL\t[$]2047"
	// arm64:"AND\t[$]2047",-"SDIV"
	// arm/6:"AND",-".*udiv"
	// arm/7:"BFC",-".*udiv",-"AND"
	// ppc64x:"RLDICL"
	return len(s) % (4097 >> 1)
}

func CapDiv(a []int) int {
	// 386:"SHRL\t[$]12"
	// amd64:"SHRQ\t[$]12"
	// arm64:"LSR\t[$]12",-"SDIV"
	// arm:"SRL\t[$]12",-".*udiv"
	// ppc64x:"SRD\t[$]12"
	return cap(a) / ((1 << 11) + 2048)
}

func CapMod(a []int) int {
	// 386:"ANDL\t[$]4095"
	// amd64:"ANDL\t[$]4095"
	// arm64:"AND\t[$]4095",-"SDIV"
	// arm/6:"AND",-".*udiv"
	// arm/7:"BFC",-".*udiv",-"AND"
	// ppc64x:"RLDICL"
	return cap(a) % ((1 << 11) + 2048)
}

func AddMul(x int) int {
	// amd64:"LEAQ\t1"
	return 2*x + 1
}

func MULA(a, b, c uint32) (uint32, uint32, uint32) {
	// arm:`MULA`,-`MUL\s`
	// arm64:`MADDW`,-`MULW`
	r0 := a*b + c
	// arm:`MULA`,-`MUL\s`
	// arm64:`MADDW`,-`MULW`
	r1 := c*79 + a
	// arm:`ADD`,-`MULA`,-`MUL\s`
	// arm64:`ADD`,-`MADD`,-`MULW`
	// ppc64x:`ADD`,-`MULLD`
	r2 := b*64 + c
	return r0, r1, r2
}

func MULS(a, b, c uint32) (uint32, uint32, uint32) {
	// arm/7:`MULS`,-`MUL\s`
	// arm/6:`SUB`,`MUL\s`,-`MULS`
	// arm64:`MSUBW`,-`MULW`
	r0 := c - a*b
	// arm/7:`MULS`,-`MUL\s`
	// arm/6:`SUB`,`MUL\s`,-`MULS`
	// arm64:`MSUBW`,-`MULW`
	r1 := a - c*79
	// arm/7:`SUB`,-`MULS`,-`MUL\s`
	// arm64:`SUB`,-`MSUBW`,-`MULW`
	// ppc64x:`SUB`,-`MULLD`
	r2 := c - b*64
	return r0, r1, r2
}

func addSpecial(a, b, c uint32) (uint32, uint32, uint32) {
	// amd64:`INCL`
	a++
	// amd64:`DECL`
	b--
	// amd64:`SUBL.*-128`
	c += 128
	return a, b, c
}

// Divide -> shift rules usually require fixup for negative inputs.
// If the input is non-negative, make sure the fixup is eliminated.
func divInt(v int64) int64 {
	if v < 0 {
		return 0
	}
	// amd64:-`.*SARQ.*63,`, -".*SHRQ", ".*SARQ.*[$]9,"
	return v / 512
}

// The reassociate rules "x - (z + C) -> (x - z) - C" and
// "(z + C) -x -> C + (z - x)" can optimize the following cases.
func constantFold1(i0, j0, i1, j1, i2, j2, i3, j3 int) (int, int, int, int) {
	// arm64:"SUB","ADD\t[$]2"
	// ppc64x:"SUB","ADD\t[$]2"
	r0 := (i0 + 3) - (j0 + 1)
	// arm64:"SUB","SUB\t[$]4"
	// ppc64x:"SUB","ADD\t[$]-4"
	r1 := (i1 - 3) - (j1 + 1)
	// arm64:"SUB","ADD\t[$]4"
	// ppc64x:"SUB","ADD\t[$]4"
	r2 := (i2 + 3) - (j2 - 1)
	// arm64:"SUB","SUB\t[$]2"
	// ppc64x:"SUB","ADD\t[$]-2"
	r3 := (i3 - 3) - (j3 - 1)
	return r0, r1, r2, r3
}

// The reassociate rules "x - (z + C) -> (x - z) - C" and
// "(C - z) - x -> C - (z + x)" can optimize the following cases.
func constantFold2(i0, j0, i1, j1 int) (int, int) {
	// arm64:"ADD","MOVD\t[$]2","SUB"
	// ppc64x: `SUBC\tR[0-9]+,\s[$]2,\sR`
	r0 := (3 - i0) - (j0 + 1)
	// arm64:"ADD","MOVD\t[$]4","SUB"
	// ppc64x: `SUBC\tR[0-9]+,\s[$]4,\sR`
	r1 := (3 - i1) - (j1 - 1)
	return r0, r1
}

func constantFold3(i, j int) int {
	// arm64: "MOVD\t[$]30","MUL",-"ADD",-"LSL"
	// ppc64x:"MULLD\t[$]30","MULLD"
	r := (5 * i) * (6 * j)
	return r
}

// ----------------- //
//  Integer Min/Max  //
// ----------------- //

func Int64Min(a, b int64) int64 {
	// amd64: "CMPQ","CMOVQLT"
	// arm64: "CMP","CSEL"
	// riscv64/rva20u64:"BLT\t"
	// riscv64/rva22u64:"MIN\t"
	return min(a, b)
}

func Int64Max(a, b int64) int64 {
	// amd64: "CMPQ","CMOVQGT"
	// arm64: "CMP","CSEL"
	// riscv64/rva20u64:"BLT\t"
	// riscv64/rva22u64:"MAX\t"
	return max(a, b)
}

func Uint64Min(a, b uint64) uint64 {
	// amd64: "CMPQ","CMOVQCS"
	// arm64: "CMP","CSEL"
	// riscv64/rva20u64:"BLTU"
	// riscv64/rva22u64:"MINU"
	return min(a, b)
}

func Uint64Max(a, b uint64) uint64 {
	// amd64: "CMPQ","CMOVQHI"
	// arm64: "CMP","CSEL"
	// riscv64/rva20u64:"BLTU"
	// riscv64/rva22u64:"MAXU"
	return max(a, b)
}
```