Response: Let's break down the thought process for analyzing this Go code.

1. **Understand the Goal:** The initial comments are crucial. They state the purpose: "Generate test of 64-bit arithmetic."  This immediately tells us the script isn't *performing* 64-bit arithmetic directly, but rather *generating Go code* that *will* test it. The note about "buggy or missing 64-bit support" reinforces this generator nature.

2. **Identify Core Data Structures:**  The `Uint64` and `Int64` structs are the building blocks. Notice they simulate 64-bit numbers using two 32-bit integers. This confirms the generator aspect – it's working around potential limitations of the environment where it runs.

3. **Analyze the Methods on `Uint64` and `Int64`:**  These methods implement the basic arithmetic and bitwise operations (+, -, *, /, %, &, |, ^, &^, <<, >>, comparison, negation, etc.) for these simulated 64-bit types. Pay attention to how they handle the high and low parts separately, especially for operations like addition and subtraction (carry/borrow). The shift operations are particularly interesting due to the need to handle shifts across the 32-bit boundary.

4. **Look for Test Data:** The `int64Values`, `uint64Values`, and `shiftValues` slices are clearly designed to provide a diverse set of inputs for testing. This further solidifies the idea that the code generates tests.

5. **Examine the Output Generation:** The `prolog`, `binaryConstL`, `binaryConstR`, `shiftConstL`, `shiftConstR` strings are templates for generating Go test functions. The `fmt.Fprintf(bout, ...)` calls within `varTests` and `constTests` show how these templates are used and populated with data.

6. **Distinguish `varTests` and `constTests`:**
    * `varTests`: Generates tests where both operands are variables of the simulated 64-bit types.
    * `constTests`: Generates tests where one operand is a constant (of the simulated 64-bit type) and the other is a variable. This is important for testing how the Go compiler handles constant folding and different operand types.

7. **Trace the `main` Function:** The `main` function orchestrates the test generation process:
    * Initializes the output buffer (`bout`).
    * Calls `varTests` and `constTests` to generate the individual test functions.
    * Generates a `main` function in the output that calls all the generated test functions.
    * Includes a check (`if !ok { os.Exit(1) }`) to see if any tests failed (indicated by the `ok` variable in the generated code).

8. **Infer the "Go Language Feature":** Based on the purpose and output, it becomes clear that this code is designed to test the correctness of Go's built-in `int64` and `uint64` types and their associated operations. It's generating comprehensive test cases, particularly focusing on edge cases and the interaction of constants and variables.

9. **Construct Example Go Code:** To illustrate the generated output, pick a simple test case. For instance, taking one value from `int64Values` and showing how a `testInt64Unary` function would be generated.

10. **Explain the Logic:** Focus on *why* the code is structured the way it is. Emphasize the simulation of 64-bit numbers, the generation of test functions, the distinction between variable and constant tests, and the use of diverse input values.

11. **Describe Command-Line Arguments (or lack thereof):**  Notice that the code itself doesn't use `os.Args`. This is important to state explicitly.

12. **Identify Potential User Errors (in the *generated* code, not this generator script):** Think about common mistakes when working with 64-bit integers. Overflow, incorrect bit manipulation, and signed vs. unsigned issues are prime candidates. Provide simple examples of such errors in actual Go code.

13. **Review and Refine:**  Read through the analysis to ensure clarity, accuracy, and completeness. Make sure all parts of the prompt have been addressed. For example, initially, I might have just focused on the `Uint64` and `Int64` types, but recognizing the output generation and the *purpose* of testing Go's native 64-bit types is crucial for a complete understanding.
### 功能归纳

这段Go代码的主要功能是**生成用于测试Go语言中64位整数运算的测试代码**。它并没有直接进行64位运算，而是通过模拟64位整数（使用两个32位整数 `hi` 和 `lo` 来表示）的方式，生成一系列的测试函数，这些测试函数会使用Go语言原生的 `int64` 和 `uint64` 类型进行各种运算，并与预期的结果进行比较，从而验证Go语言编译器对64位整数运算的实现是否正确。

### 推理：Go语言功能测试

这段代码是为了测试Go语言内置的 `int64` 和 `uint64` 类型的算术和位运算功能。由于Go语言本身就支持 `int64` 和 `uint64`，这段代码的目的是生成测试用例来验证这些功能的正确性，尤其是在处理常量和变量的不同组合以及各种边界条件时。

**Go代码示例 (生成的测试代码片段):**

```go
package main

import "os"

var ok = true

func testInt64Binary(a, b, add, sub, mul, div, mod, and, or, xor, andnot int64, dodiv bool) {
	if n, op, want := a + b, `+`, add; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
	// ... 其他二元运算的测试
}

func main() {
	test0()
	test1()
	// ... 更多测试函数
	if !ok { os.Exit(1) }
}
```

在这个例子中，`testInt64Binary` 函数接收两个 `int64` 类型的变量 `a` 和 `b`，以及它们进行各种运算的预期结果。它会实际执行这些运算，并将结果与预期值进行比较。`main` 函数会调用所有生成的 `test` 函数，如果任何测试失败，`ok` 变量会被设置为 `false`，程序会以非零状态退出。

### 代码逻辑介绍

这段代码的核心在于 `Uint64` 和 `Int64` 结构体及其关联的方法。这些方法模拟了64位整数的各种运算，但实际上是在32位的基础上实现的。

**假设输入：**

假设 `uint64Values` 中包含一个 `Uint64` 值 `a = {hi: 0x00000001, lo: 0x00000000}` (表示十进制的 4294967296)，`shiftValues` 中包含一个 `Uint64` 值 `b = {hi: 0x00000000, lo: 0x00000001}` (表示十进制的 1)。

**输出 (生成的代码片段):**

```go
func testN() { // 假设这是针对上述输入的测试函数
	a := Uint64{0x00000001, 0x00000000}
	b := Uint64{0x00000000, 0x00000001}
	testUint64Shift(a, b, Uint64{0x00000002, 0x00000000}, Uint64{0x00000000, 0x80000000})
}

func testUint64Shift(a, b Uint64, left, right uint64) {
	if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`uint64`, a, op, `uint64`, s, `=`, n, `should be`, want); }
	if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`uint64`, a, op, `uint64`, s, `=`, n, `should be`, want); }
	// ... 其他类型转换的移位测试
}
```

**代码逻辑:**

1. **定义模拟的64位类型:** `Uint64` 和 `Int64` 结构体使用两个32位整数来表示一个64位整数。
2. **实现基本运算:**  为 `Uint64` 和 `Int64` 定义了各种算术运算（加、减、乘、除、取模）和位运算（与、或、异或、取反、左移、右移）的方法。这些方法内部使用了32位运算来模拟64位运算，例如加法需要处理进位。
3. **生成测试数据:** `int64Values`, `uint64Values`, `shiftValues` 包含了各种各样的64位整数值，用于生成全面的测试用例。
4. **生成测试函数:** `varTests` 和 `constTests` 函数负责生成实际的测试函数。
    - `varTests` 生成的测试函数会对两个64位变量进行各种运算。
    - `constTests` 生成的测试函数会测试一个64位常量和一个64位变量之间的运算。
5. **生成主函数:** `main` 函数生成最终的 `main` 函数，该函数会调用所有生成的测试函数，并检查全局变量 `ok` 的值，以判断是否有测试失败。
6. **处理除法:** 代码中特别注意了除法运算，避免除零错误，并且对于 `Int64` 的除法，还考虑了符号问题。

### 命令行参数的具体处理

这段代码本身**不涉及任何命令行参数的处理**。它是一个独立的程序，其输出是生成的Go测试代码，这个生成的代码才会被Go的测试工具（例如 `go test`）执行。

### 使用者易犯错的点

使用者（通常是Go语言的开发者或测试人员）在使用这段代码生成的测试时，可能会遇到以下易错点：

1. **直接运行生成的文件:** 用户可能会尝试直接运行生成的 `.go` 文件，而不是使用 `go test` 命令。生成的代码本身是一个测试套件，需要Go的测试框架来执行。
2. **忽略测试输出:** 生成的测试代码在运行时，如果 `ok` 变量为 `false`，会打印出详细的错误信息。用户可能会忽略这些信息，导致无法定位问题。
3. **修改生成的文件后重新生成:** 如果用户手动修改了生成的测试文件，之后又重新运行了这个生成器，之前的手动修改将会丢失。

**例子:**

假设用户生成了一个名为 `64bit_test.go` 的文件，并尝试直接运行：

```bash
go run 64bit_test.go
```

这通常不会得到预期的测试结果，因为生成的代码依赖于 `go test` 框架提供的机制来报告测试结果。正确的做法是使用 `go test` 命令：

```bash
go test 64bit_test.go
```

或者，如果将生成的代码放在一个包目录下，可以使用：

```bash
go test ./your_package_directory
```

总结来说，这段Go代码是一个用于生成64位整数运算测试用例的工具，它通过模拟64位运算来生成针对Go原生 `int64` 和 `uint64` 类型的测试代码，帮助验证Go语言编译器在处理64位整数时的正确性。

### 提示词
```
这是路径为go/test/64bit.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// runoutput

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate test of 64-bit arithmetic.
// Most synthesized routines have different cases for
// constants vs variables and even the generated code has
// different cases for large and small constants,
// so try a good range of inputs.

package main

import (
	"bufio"
	"fmt"
	"os"
)

var bout *bufio.Writer

// 64-bit math without using 64-bit numbers,
// so that we can generate the test program even
// if the compiler has buggy or missing 64-bit support.

type Uint64 struct {
	hi	uint32
	lo	uint32
}

type Int64 struct {
	hi	int32
	lo	uint32
}

func (a Uint64) Int64() (c Int64) {
	c.hi = int32(a.hi)
	c.lo = a.lo
	return
}

func (a Uint64) Cmp(b Uint64) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	}
	return 0
}

func (a Uint64) LeftShift(b uint) (c Uint64) {
	switch {
	case b >= 64:
		c.hi = 0
		c.lo = 0
	case b >= 32:
		c.hi = a.lo << (b - 32)
		c.lo = 0
	default:
		c.hi = a.hi<<b | a.lo>>(32-b)
		c.lo = a.lo << b
	}
	return
}

func (a Uint64) RightShift(b uint) (c Uint64) {
	switch {
	case b >= 64:
		c.hi = 0
		c.lo = a.hi
	case b >= 32:
		c.hi = 0
		c.lo = a.hi >> (b - 32)
	default:
		c.hi = a.hi >> b
		c.lo = a.hi<<(32-b) | a.lo>>b
	}
	return
}

func (a Uint64) LeftShift64(b Uint64) (c Uint64) {
	if b.hi != 0 || b.lo >= 64 {
		return
	}
	return a.LeftShift(uint(b.lo))
}

func (a Uint64) RightShift64(b Uint64) (c Uint64) {
	if b.hi != 0 || b.lo >= 64 {
		return
	}
	return a.RightShift(uint(b.lo))
}

func (a Uint64) Plus(b Uint64) (c Uint64) {
	var carry uint32
	if c.lo = a.lo + b.lo; c.lo < a.lo {
		carry = 1
	}
	c.hi = a.hi + b.hi + carry
	return
}

func (a Uint64) Minus(b Uint64) (c Uint64) {
	var borrow uint32
	if c.lo = a.lo - b.lo; c.lo > a.lo {
		borrow = 1
	}
	c.hi = a.hi - b.hi - borrow
	return
}

func (a Uint64) Neg() (c Uint64) {
	var zero Uint64
	return zero.Minus(a)
}

func (a Uint64) Com() (c Uint64) {
	c.hi = ^a.hi
	c.lo = ^a.lo
	return
}

func (a Uint64) Len() int {
	switch {
	case a.hi != 0:
		for i := 31; i >= 0; i-- {
			if a.hi&(1<<uint(i)) != 0 {
				return i + 1 + 32
			}
		}
	case a.lo != 0:
		for i := 31; i >= 0; i-- {
			if a.lo&(1<<uint(i)) != 0 {
				return i + 1
			}
		}
	}
	return 0
}

func (a Uint64) HasBit(b uint) bool {
	switch {
	case b >= 64:
		return false
	case b >= 32:
		return a.hi&(1<<(b-32)) != 0
	}
	return a.lo&(1<<b) != 0
}

func (a Uint64) Times(b Uint64) (c Uint64) {
	for i := uint(0); i < 64; i++ {
		if b.HasBit(i) {
			c = c.Plus(a.LeftShift(i))
		}
	}
	return
}

func (a Uint64) DivMod(b Uint64) (quo, rem Uint64) {
	n := a.Len() - b.Len()
	if n >= 0 {
		b = b.LeftShift(uint(n))
		for i := 0; i <= n; i++ {
			quo = quo.LeftShift(1)
			if b.Cmp(a) <= 0 {	// b <= a
				quo.lo |= 1
				a = a.Minus(b)
			}
			b = b.RightShift(1)
		}
	}
	rem = a
	return
}

func (a Uint64) And(b Uint64) (c Uint64) {
	c.hi = a.hi & b.hi
	c.lo = a.lo & b.lo
	return
}

func (a Uint64) AndNot(b Uint64) (c Uint64) {
	c.hi = a.hi &^ b.hi
	c.lo = a.lo &^ b.lo
	return
}

func (a Uint64) Or(b Uint64) (c Uint64) {
	c.hi = a.hi | b.hi
	c.lo = a.lo | b.lo
	return
}

func (a Uint64) Xor(b Uint64) (c Uint64) {
	c.hi = a.hi ^ b.hi
	c.lo = a.lo ^ b.lo
	return
}

func (a Uint64) String() string	{ return fmt.Sprintf("%#x%08x", a.hi, a.lo) }

func (a Int64) Uint64() (c Uint64) {
	c.hi = uint32(a.hi)
	c.lo = a.lo
	return
}

func (a Int64) Cmp(b Int64) int {
	// Same body as Uint64.Cmp,
	// but behaves differently
	// because hi is uint32 not int32.
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	}
	return 0
}

func (a Int64) LeftShift(b uint) (c Int64)	{ return a.Uint64().LeftShift(b).Int64() }

func (a Int64) RightShift(b uint) (c Int64) {
	switch {
	case b >= 64:
		c.hi = a.hi >> 31	// sign extend
		c.lo = uint32(c.hi)
	case b >= 32:
		c.hi = a.hi >> 31	// sign extend
		c.lo = uint32(a.hi >> (b - 32))
	default:
		c.hi = a.hi >> b
		c.lo = uint32(a.hi<<(32-b)) | a.lo>>b
	}
	return
}

func (a Int64) LeftShift64(b Uint64) (c Int64) {
	if b.hi != 0 || b.lo >= 64 {
		return
	}
	return a.LeftShift(uint(b.lo))
}

func (a Int64) RightShift64(b Uint64) (c Int64) {
	if b.hi != 0 || b.lo >= 64 {
		return a.RightShift(64)
	}
	return a.RightShift(uint(b.lo))
}

func (a Int64) Plus(b Int64) (c Int64)	{ return a.Uint64().Plus(b.Uint64()).Int64() }

func (a Int64) Minus(b Int64) (c Int64)	{ return a.Uint64().Minus(b.Uint64()).Int64() }

func (a Int64) Neg() (c Int64)	{ return a.Uint64().Neg().Int64() }

func (a Int64) Com() (c Int64)	{ return a.Uint64().Com().Int64() }

func (a Int64) Times(b Int64) (c Int64)	{ return a.Uint64().Times(b.Uint64()).Int64() }

func (a Int64) DivMod(b Int64) (quo Int64, rem Int64) {
	var zero Int64

	quoSign := +1
	remSign := +1
	if a.Cmp(zero) < 0 {
		quoSign = -1
		remSign = -1
		a = a.Neg()
	}
	if b.Cmp(zero) < 0 {
		quoSign = -quoSign
		b = b.Neg()
	}

	q, r := a.Uint64().DivMod(b.Uint64())
	quo = q.Int64()
	rem = r.Int64()

	if quoSign < 0 {
		quo = quo.Neg()
	}
	if remSign < 0 {
		rem = rem.Neg()
	}
	return
}

func (a Int64) And(b Int64) (c Int64)	{ return a.Uint64().And(b.Uint64()).Int64() }

func (a Int64) AndNot(b Int64) (c Int64)	{ return a.Uint64().AndNot(b.Uint64()).Int64() }

func (a Int64) Or(b Int64) (c Int64)	{ return a.Uint64().Or(b.Uint64()).Int64() }

func (a Int64) Xor(b Int64) (c Int64)	{ return a.Uint64().Xor(b.Uint64()).Int64() }

func (a Int64) String() string {
	if a.hi < 0 {
		return fmt.Sprintf("-%s", a.Neg().Uint64())
	}
	return a.Uint64().String()
}

var int64Values = []Int64{
	Int64{0, 0},
	Int64{0, 1},
	Int64{0, 2},
	Int64{0, 3},
	Int64{0, 100},
	Int64{0, 10001},
	Int64{0, 1<<31 - 1},
	Int64{0, 1 << 31},
	Int64{0, 1<<31 + 1},
	Int64{0, 1<<32 - 1<<30},
	Int64{0, 1<<32 - 1},
	Int64{1, 0},
	Int64{1, 1},
	Int64{2, 0},
	Int64{1<<31 - 1, 1<<32 - 10000},
	Int64{1<<31 - 1, 1<<32 - 1},
	Int64{0x789abcde, 0xf0123456},

	Int64{-1, 1<<32 - 1},
	Int64{-1, 1<<32 - 2},
	Int64{-1, 1<<32 - 3},
	Int64{-1, 1<<32 - 100},
	Int64{-1, 1<<32 - 10001},
	Int64{-1, 1<<32 - (1<<31 - 1)},
	Int64{-1, 1<<32 - 1<<31},
	Int64{-1, 1<<32 - (1<<31 + 1)},
	Int64{-1, 1<<32 - (1<<32 - 1<<30)},
	Int64{-1, 0},
	Int64{-1, 1},
	Int64{-2, 0},
	Int64{-(1 << 31), 10000},
	Int64{-(1 << 31), 1},
	Int64{-(1 << 31), 0},
	Int64{-0x789abcde, 0xf0123456},
}

var uint64Values = []Uint64{
	Uint64{0, 0},
	Uint64{0, 1},
	Uint64{0, 2},
	Uint64{0, 3},
	Uint64{0, 100},
	Uint64{0, 10001},
	Uint64{0, 1<<31 - 1},
	Uint64{0, 1 << 31},
	Uint64{0, 1<<31 + 1},
	Uint64{0, 1<<32 - 1<<30},
	Uint64{0, 1<<32 - 1},
	Uint64{1, 0},
	Uint64{1, 1},
	Uint64{2, 0},
	Uint64{1<<31 - 1, 1<<32 - 10000},
	Uint64{1<<31 - 1, 1<<32 - 1},
	Uint64{1<<32 - 1<<30, 0},
	Uint64{1<<32 - 1, 0},
	Uint64{1<<32 - 1, 1<<32 - 100},
	Uint64{1<<32 - 1, 1<<32 - 1},
	Uint64{0x789abcde, 0xf0123456},
	Uint64{0xfedcba98, 0x76543210},
}

var shiftValues = []Uint64{
	Uint64{0, 0},
	Uint64{0, 1},
	Uint64{0, 2},
	Uint64{0, 3},
	Uint64{0, 15},
	Uint64{0, 16},
	Uint64{0, 17},
	Uint64{0, 31},
	Uint64{0, 32},
	Uint64{0, 33},
	Uint64{0, 61},
	Uint64{0, 62},
	Uint64{0, 63},
	Uint64{0, 64},
	Uint64{0, 65},
	Uint64{0, 1<<32 - 1},
	Uint64{1, 0},
	Uint64{1, 1},
	Uint64{1 << 28, 0},
	Uint64{1 << 31, 0},
	Uint64{1<<32 - 1, 0},
	Uint64{1<<32 - 1, 1<<32 - 1},
}

var ntest = 0

// Part 1 is tests of variable operations; generic functions
// called by repetitive code.  Could make a table but not worth it.

const prolog = "\n" +
	"package main\n" +
	"\n" +
	"import \"os\"\n" +
	"\n" +
	"var ok = true\n" +
	"\n" +
	"func testInt64Unary(a, plus, xor, minus int64) {\n" +
	"	if n, op, want := +a, `+`, plus; n != want { ok=false; println(`int64`, op, a, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := ^a, `^`, xor; n != want { ok=false; println(`int64`, op, a, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := -a, `-`, minus; n != want { ok=false; println(`int64`, op, a, `=`, n, `should be`, want); }\n" +
	"}\n" +
	"\n" +
	"func testInt64Binary(a, b, add, sub, mul, div, mod, and, or, xor, andnot int64, dodiv bool) {\n" +
	"	if n, op, want := a + b, `+`, add; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a - b, `-`, sub; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a * b, `*`, mul; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if dodiv {\n" +
	"		if n, op, want := a / b, `/`, div; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"		if n, op, want := a % b, `%`, mod; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if n, op, want := a & b, `&`, and; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a | b, `|`, or; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a ^ b, `^`, xor; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a &^ b, `&^`, andnot; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"}\n" +
	"\n" +
	"func testInt64Shift(a int64, b uint64, left, right int64) {\n" +
	"	if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`int64`, a, op, `uint64`, s, `=`, n, `should be`, want); }\n" +
	"	if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`int64`, a, op, `uint64`, s, `=`, n, `should be`, want); }\n" +
	"	if uint64(uint(b)) == b {\n" +
	"		b := uint(b);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`int64`, a, op, `uint`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`int64`, a, op, `uint`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if uint64(uint32(b)) == b {\n" +
	"		b := uint32(b);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`int64`, a, op, `uint32`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`int64`, a, op, `uint32`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if uint64(uint16(b)) == b {\n" +
	"		b := uint16(b);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`int64`, a, op, `uint16`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`int64`, a, op, `uint16`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if uint64(uint8(b)) == b {\n" +
	"		b := uint8(b);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`int64`, a, op, `uint8`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`int64`, a, op, `uint8`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"}\n" +
	"\n" +
	"func testUint64Unary(a, plus, xor, minus uint64) {\n" +
	"	if n, op, want := +a, `+`, plus; n != want { ok=false; println(`uint64`, op, a, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := ^a, `^`, xor; n != want { ok=false; println(`uint64`, op, a, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := -a, `-`, minus; n != want { ok=false; println(`uint64`, op, a, `=`, n, `should be`, want); }\n" +
	"}\n" +
	"\n" +
	"func testUint64Binary(a, b, add, sub, mul, div, mod, and, or, xor, andnot uint64, dodiv bool) {\n" +
	"	if n, op, want := a + b, `+`, add; n != want { ok=false; println(`uint64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a - b, `-`, sub; n != want { ok=false; println(`uint64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a * b, `*`, mul; n != want { ok=false; println(`uint64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if dodiv {\n" +
	"		if n, op, want := a / b, `/`, div; n != want { ok=false; println(`uint64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"		if n, op, want := a % b, `%`, mod; n != want { ok=false; println(`uint64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if n, op, want := a & b, `&`, and; n != want { ok=false; println(`uint64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a | b, `|`, or; n != want { ok=false; println(`uint64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a ^ b, `^`, xor; n != want { ok=false; println(`uint64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a &^ b, `&^`, andnot; n != want { ok=false; println(`uint64`, a, op, b, `=`, n, `should be`, want); }\n" +
	"}\n" +
	"\n" +
	"func testUint64Shift(a, b, left, right uint64) {\n" +
	"	if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`uint64`, a, op, `uint64`, s, `=`, n, `should be`, want); }\n" +
	"	if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`uint64`, a, op, `uint64`, s, `=`, n, `should be`, want); }\n" +
	"	if uint64(uint(b)) == b {\n" +
	"		b := uint(b);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`uint64`, a, op, `uint`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`uint64`, a, op, `uint`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if uint64(uint32(b)) == b {\n" +
	"		b := uint32(b);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`uint64`, a, op, `uint32`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`uint64`, a, op, `uint32`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if uint64(uint16(b)) == b {\n" +
	"		b := uint16(b);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`uint64`, a, op, `uint16`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`uint64`, a, op, `uint16`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if uint64(uint8(b)) == b {\n" +
	"		b := uint8(b);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`uint64`, a, op, `uint8`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`uint64`, a, op, `uint8`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"}\n" +
	"\n"

func varTests() {
	fmt.Fprint(bout, prolog)
	for _, a := range int64Values {
		fmt.Fprintf(bout, "func test%v() {\n", ntest)
		ntest++
		fmt.Fprintf(bout, "\ttestInt64Unary(%v, %v, %v, %v);\n", a, a, a.Com(), a.Neg())
		for _, b := range int64Values {
			var div, mod Int64
			dodiv := false
			var zero Int64
			if b.Cmp(zero) != 0 {	// b != 0
				// Can't divide by zero but also can't divide -0x8000...000 by -1.
				var bigneg = Int64{-0x80000000, 0}
				var minus1 = Int64{-1, ^uint32(0)}
				if a.Cmp(bigneg) != 0 || b.Cmp(minus1) != 0 {	// a != -1<<63 || b != -1
					div, mod = a.DivMod(b)
					dodiv = true
				}
			}
			fmt.Fprintf(bout, "\ttestInt64Binary(%v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v);\n",
				a, b, a.Plus(b), a.Minus(b), a.Times(b), div, mod,
				a.And(b), a.Or(b), a.Xor(b), a.AndNot(b), dodiv)
		}
		for _, b := range shiftValues {
			fmt.Fprintf(bout, "\ttestInt64Shift(%v, %v, %v, %v);\n",
				a, b, a.LeftShift64(b), a.RightShift64(b))
		}
		fmt.Fprintf(bout, "}\n")
	}

	for _, a := range uint64Values {
		fmt.Fprintf(bout, "func test%v() {\n", ntest)
		ntest++
		fmt.Fprintf(bout, "\ttestUint64Unary(%v, %v, %v, %v);\n", a, a, a.Com(), a.Neg())
		for _, b := range uint64Values {
			var div, mod Uint64
			dodiv := false
			var zero Uint64
			if b.Cmp(zero) != 0 {	// b != 0
				div, mod = a.DivMod(b)
				dodiv = true
			}
			fmt.Fprintf(bout, "\ttestUint64Binary(%v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v);\n",
				a, b, a.Plus(b), a.Minus(b), a.Times(b), div, mod,
				a.And(b), a.Or(b), a.Xor(b), a.AndNot(b), dodiv)
		}
		for _, b := range shiftValues {
			fmt.Fprintf(bout, "\ttestUint64Shift(%v, %v, %v, %v);\n",
				a, b, a.LeftShift64(b), a.RightShift64(b))
		}
		fmt.Fprintf(bout, "}\n")
	}
}

// Part 2 is tests of operations involving one variable and one constant.

const binaryConstL = "func test%vBinaryL%v(b, add, sub, mul, div, mod, and, or, xor, andnot %v, dodiv bool) {\n" +
	"	const a %v = %v;\n" +
	"	const typ = `%s`;\n" +
	"	if n, op, want := a + b, `+`, add; n != want { ok=false; println(typ, `const`, a, op, `var`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a - b, `-`, sub; n != want { ok=false; println(typ, `const`, a, op, `var`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a * b, `*`, mul; n != want { ok=false; println(typ, `const`, a, op, `var`, b, `=`, n, `should be`, want); }\n" +
	"	if dodiv {\n" +
	"		if n, op, want := a / b, `/`, div; n != want { ok=false; println(typ, `const`, a, op, `var`, b, `=`, n, `should be`, want); }\n" +
	"		if n, op, want := a %% b, `%%`, mod; n != want { ok=false; println(typ, `const`, a, op, `var`, b, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if n, op, want := a & b, `&`, and; n != want { ok=false; println(typ, `const`, a, op, `var`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a | b, `|`, or; n != want { ok=false; println(typ, `const`, a, op, `var`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a ^ b, `^`, xor; n != want { ok=false; println(typ, `const`, a, op, `var`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a &^ b, `&^`, andnot; n != want { ok=false; println(typ, `const`, a, op, `var`, b, `=`, n, `should be`, want); }\n" +
	"}\n" +
	"\n"

const binaryConstR = "func test%vBinaryR%v(a, add, sub, mul, div, mod, and, or, xor, andnot %v, dodiv bool) {\n" +
	"	const b %v = %v;\n" +
	"	const typ = `%s`;\n" +
	"	if n, op, want := a + b, `+`, add; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a - b, `-`, sub; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a * b, `*`, mul; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if dodiv {\n" +
	"		if n, op, want := a / b, `/`, div; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"		if n, op, want := a %% b, `%%`, mod; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"	if n, op, want := a & b, `&`, and; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a | b, `|`, or; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a ^ b, `^`, xor; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a &^ b, `&^`, andnot; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"}\n" +
	"\n"

const binaryConstR0 = "func test%vBinaryR%v(a, add, sub, mul, div, mod, and, or, xor, andnot %v, dodiv bool) {\n" +
	"	const b %v = %v;\n" +
	"	const typ = `%s`;\n" +
	"	if n, op, want := a + b, `+`, add; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a - b, `-`, sub; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a * b, `*`, mul; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a & b, `&`, and; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a | b, `|`, or; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a ^ b, `^`, xor; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"	if n, op, want := a &^ b, `&^`, andnot; n != want { ok=false; println(typ, `var`, a, op, `const`, b, `=`, n, `should be`, want); }\n" +
	"}\n" +
	"\n"

const shiftConstL = "func test%vShiftL%v(b uint64, left, right %v) {\n" +
	"	const a %v = %v;\n" +
	"	const typ = `%s`;\n" +
	"	if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(typ, `const`, a, op, `var`, s, `=`, n, `should be`, want); }\n" +
	"	if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(typ, `const`, a, op, `var`, s, `=`, n, `should be`, want); }\n" +
	"	if uint64(uint32(b)) == b {\n" +
	"		b := uint32(b);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(typ, `const`, a, op, `var`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(typ, `const`, a, op, `var`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"}\n"

const shiftConstR = "func test%vShiftR%v(a, left, right %v) {\n" +
	"	const b uint64 = %v;\n" +
	"	const typ = `%s`;\n" +
	"	if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(typ, `var`, a, op, `const`, s, `=`, n, `should be`, want); }\n" +
	"	if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(typ, `var`, a, op, `const`, s, `=`, n, `should be`, want); }\n" +
	"	if b & 0xffffffff == b {\n" +
	"		const b = uint32(b & 0xffffffff);\n" +
	"		if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(typ, `var`, a, op, `const`, s, `=`, n, `should be`, want); }\n" +
	"		if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(typ, `var`, a, op, `const`, s, `=`, n, `should be`, want); }\n" +
	"	}\n" +
	"}\n"

func constTests() {
	for i, a := range int64Values {
		fmt.Fprintf(bout, binaryConstL, "Int64", i, "int64", "int64", a, "int64")
		if a.hi == 0 && a.lo == 0 {
			fmt.Fprintf(bout, binaryConstR0, "Int64", i, "int64", "int64", a, "int64")
		} else {
			fmt.Fprintf(bout, binaryConstR, "Int64", i, "int64", "int64", a, "int64")
		}
		fmt.Fprintf(bout, shiftConstL, "Int64", i, "int64", "int64", a, "int64")
	}
	for i, a := range uint64Values {
		fmt.Fprintf(bout, binaryConstL, "Uint64", i, "uint64", "uint64", a, "uint64")
		if a.hi == 0 && a.lo == 0 {
			fmt.Fprintf(bout, binaryConstR0, "Uint64", i, "uint64", "uint64", a, "uint64")
		} else {
			fmt.Fprintf(bout, binaryConstR, "Uint64", i, "uint64", "uint64", a, "uint64")
		}
		fmt.Fprintf(bout, shiftConstL, "Uint64", i, "uint64", "uint64", a, "uint64")
	}
	for i, a := range shiftValues {
		fmt.Fprintf(bout, shiftConstR, "Int64", i, "int64", a, "int64")
		fmt.Fprintf(bout, shiftConstR, "Uint64", i, "uint64", a, "uint64")
	}
	for i, a := range int64Values {
		fmt.Fprintf(bout, "func test%v() {\n", ntest)
		ntest++
		for j, b := range int64Values {
			var div, mod Int64
			dodiv := false
			var zero Int64
			if b.Cmp(zero) != 0 {	// b != 0
				// Can't divide by zero but also can't divide -0x8000...000 by -1.
				var bigneg = Int64{-0x80000000, 0}
				var minus1 = Int64{-1, ^uint32(0)}
				if a.Cmp(bigneg) != 0 || b.Cmp(minus1) != 0 {	// a != -1<<63 || b != -1
					div, mod = a.DivMod(b)
					dodiv = true
				}
			}
			fmt.Fprintf(bout, "\ttestInt64BinaryL%v(%v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v);\n",
				i, b, a.Plus(b), a.Minus(b), a.Times(b), div, mod,
				a.And(b), a.Or(b), a.Xor(b), a.AndNot(b), dodiv)
			fmt.Fprintf(bout, "\ttestInt64BinaryR%v(%v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v);\n",
				j, a, a.Plus(b), a.Minus(b), a.Times(b), div, mod,
				a.And(b), a.Or(b), a.Xor(b), a.AndNot(b), dodiv)
		}
		for j, b := range shiftValues {
			fmt.Fprintf(bout, "\ttestInt64ShiftL%v(%v, %v, %v);\n",
				i, b, a.LeftShift64(b), a.RightShift64(b))
			fmt.Fprintf(bout, "\ttestInt64ShiftR%v(%v, %v, %v);\n",
				j, a, a.LeftShift64(b), a.RightShift64(b))
		}
		fmt.Fprintf(bout, "}\n")
	}
	for i, a := range uint64Values {
		fmt.Fprintf(bout, "func test%v() {\n", ntest)
		ntest++
		for j, b := range uint64Values {
			var div, mod Uint64
			dodiv := false
			var zero Uint64
			if b.Cmp(zero) != 0 {	// b != 0
				div, mod = a.DivMod(b)
				dodiv = true
			}
			fmt.Fprintf(bout, "\ttestUint64BinaryL%v(%v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v);\n",
				i, b, a.Plus(b), a.Minus(b), a.Times(b), div, mod,
				a.And(b), a.Or(b), a.Xor(b), a.AndNot(b), dodiv)
			fmt.Fprintf(bout, "\ttestUint64BinaryR%v(%v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v);\n",
				j, a, a.Plus(b), a.Minus(b), a.Times(b), div, mod,
				a.And(b), a.Or(b), a.Xor(b), a.AndNot(b), dodiv)
		}
		for j, b := range shiftValues {
			fmt.Fprintf(bout, "\ttestUint64ShiftL%v(%v, %v, %v);\n",
				i, b, a.LeftShift64(b), a.RightShift64(b))
			fmt.Fprintf(bout, "\ttestUint64ShiftR%v(%v, %v, %v);\n",
				j, a, a.LeftShift64(b), a.RightShift64(b))
		}
		fmt.Fprintf(bout, "}\n")
	}
}

func main() {
	bout = bufio.NewWriter(os.Stdout)
	varTests()
	constTests()

	fmt.Fprintf(bout, "func main() {\n")
	for i := 0; i < ntest; i++ {
		fmt.Fprintf(bout, "\ttest%v();\n", i)
	}
	fmt.Fprintf(bout, "\tif !ok { os.Exit(1) }\n")
	fmt.Fprintf(bout, "}\n")
	bout.Flush()
}
```