Response: Let's break down the thought process for analyzing this Go code.

1. **Initial Scan and Purpose Identification:** The first thing I do is quickly scan the code for keywords and overall structure. I see `package main`, `import`, and a `main` function, indicating an executable program. The comment `// Generate test of 64-bit arithmetic` immediately jumps out as the core purpose. The "runoutput" comment suggests this program *generates* Go code that will be run and whose output is expected.

2. **Data Structures for 64-bit Representation:**  I notice the `Uint64` and `Int64` structs. These are defined using `uint32` and `int32`. The comment `// 64-bit math without using 64-bit numbers` confirms that this code implements 64-bit arithmetic using two 32-bit integers. This is a key insight.

3. **Methods on the 64-bit Types:** I start examining the methods associated with `Uint64` and `Int64`. I see methods like `Plus`, `Minus`, `Times`, `DivMod`, `LeftShift`, `RightShift`, `Cmp`, `Neg`, `Com`, `And`, `Or`, `Xor`, `AndNot`. These clearly correspond to standard arithmetic and bitwise operations. The presence of both unsigned (`Uint64`) and signed (`Int64`) types is also important.

4. **Implementation of 64-bit Operations:**  I look *inside* the methods to understand how the 64-bit operations are implemented using 32-bit parts. For example, in `Uint64.Plus`, I see the carry logic (`if c.lo = a.lo + b.lo; c.lo < a.lo { carry = 1 }`). Similarly, the shift operations handle cases where the shift amount is greater than 32. This reinforces the idea that this code is performing low-level 64-bit emulation.

5. **Test Data Generation:**  I see the `int64Values`, `uint64Values`, and `shiftValues` variables, which are slices of `Int64` and `Uint64`. These are pre-defined test cases covering a range of values, including zero, small numbers, large numbers, and edge cases (like maximum and minimum values for 32-bit integers).

6. **Code Generation Logic:** The `varTests` and `constTests` functions are crucial. I see them using `fmt.Fprintf` to write Go code to the `bout` buffer. The generated code includes function definitions like `testInt64Unary`, `testInt64Binary`, `testInt64Shift`, and their `Uint64` counterparts. These functions contain assertions (using `if n != want`) to check the results of the 64-bit operations. The distinction between "var" and "const" tests is also evident in the generated code.

7. **`main` Function:** The `main` function initializes a buffered writer, calls `varTests` and `constTests` to generate the test code, and then generates the `main` function of the *test program* that will execute all the generated test functions. The `os.Exit(1)` if `!ok` part indicates that the generated test program will exit with an error code if any test fails.

8. **Command-Line Arguments and Input:**  I carefully reread the prompt looking for mentions of command-line arguments. There are *no* explicit command-line argument parsing in the provided code. The program's output is directly written to `os.Stdout`. This means it's designed to be run without any specific command-line parameters.

9. **Identifying the Go Feature:** Based on the analysis, it becomes clear that this code is a **test generator** for 64-bit integer arithmetic in Go. It's designed to create comprehensive test cases that exercise the 64-bit integer operations. It does this by generating Go source code that performs these operations and checks the results. The reason for implementing 64-bit arithmetic using 32-bit types is to create the tests even if the Go compiler itself has issues with 64-bit types during the *generation* phase.

10. **Potential Pitfalls:** I think about how someone might misuse this. Since it's a *test generator*, users wouldn't typically *call* the functions within this code directly in their own programs. The potential pitfall lies in misunderstanding its purpose and trying to use the `Uint64` and `Int64` types for general 64-bit arithmetic instead of using Go's built-in `uint64` and `int64` types. This leads to the "using the generated code directly for 64-bit arithmetic in other programs" point.

11. **Structuring the Answer:** Finally, I organize my findings into a clear and structured answer, addressing each part of the prompt: functionality, Go feature, code examples (of the *generated* code), command-line arguments, and potential pitfalls. I use code blocks to illustrate the generated test functions.

This detailed thought process, moving from a high-level overview to examining the specific implementation details, allows for a comprehensive understanding of the code's purpose and functionality. The key is to pay attention to comments, variable names, function names, and the overall flow of execution.
这是对路径为 `go/test/64bit.go` 的 Go 语言实现的一部分的分析。

**功能列举:**

1. **定义了表示 64 位无符号整数的结构体 `Uint64`:**  该结构体使用两个 `uint32` 类型的字段 `hi` (高 32 位) 和 `lo` (低 32 位) 来模拟 64 位整数。
2. **定义了表示 64 位有符号整数的结构体 `Int64`:**  类似于 `Uint64`，使用 `int32` 类型的 `hi` 和 `uint32` 类型的 `lo` 来模拟 64 位有符号整数。
3. **为 `Uint64` 和 `Int64` 实现了各种算术和位运算方法:**  包括加法 (`Plus`)、减法 (`Minus`)、乘法 (`Times`)、除法和取模 (`DivMod`)、左移 (`LeftShift`, `LeftShift64`)、右移 (`RightShift`, `RightShift64`)、按位与 (`And`)、按位或 (`Or`)、按位异或 (`Xor`)、按位与非 (`AndNot`)、取反 (`Neg`)、按位取反 (`Com`) 和比较 (`Cmp`)。
4. **实现了将 `Uint64` 转换为 `Int64` 和反向转换的方法 (`Int64()`, `Uint64()`).**
5. **实现了获取 `Uint64` 类型表示的有效位数的方法 (`Len()`).**
6. **实现了检查 `Uint64` 类型的特定位是否被设置的方法 (`HasBit()`).**
7. **为 `Uint64` 和 `Int64` 实现了 `String()` 方法，用于格式化输出 16 进制表示。**
8. **生成用于测试 64 位算术运算的 Go 代码:**  `varTests()` 和 `constTests()` 函数生成了大量的 Go 测试代码，这些代码会调用上面定义的 `Uint64` 和 `Int64` 的方法，并使用 Go 的内置运算符进行比较，以验证这些方法的正确性。
9. **使用预定义的测试用例:**  `int64Values`, `uint64Values`, 和 `shiftValues` 包含了各种 64 位整数和移位值的测试用例，覆盖了零、正数、负数、边界值等。
10. **区分变量运算和常量运算的测试:**  生成的测试代码中，既有变量之间的运算测试，也有变量和常量之间的运算测试。
11. **处理除零错误:**  在生成除法测试时，会检查除数是否为零，避免生成导致程序崩溃的测试用例。

**推理 Go 语言功能实现:**

这段代码实际上是在为一个可能早期或不支持完整 64 位运算的 Go 编译器生成 64 位算术运算的测试代码。它的目的是在没有原生 64 位支持的情况下，验证编译器对 64 位算术的编译是否正确。

**Go 代码举例说明 (生成的测试代码):**

假设 `int64Values` 中包含 `Int64{10, 0}` 和 `Int64{5, 0}`，`varTests()` 函数会生成类似下面的 Go 代码：

```go
package main

import "os"

var ok = true

func testInt64Unary(a, plus, xor, minus int64) {
	if n, op, want := +a, `+`, plus; n != want { ok=false; println(`int64`, op, a, `=`, n, `should be`, want); }
	if n, op, want := ^a, `^`, xor; n != want { ok=false; println(`int64`, op, a, `=`, n, `should be`, want); }
	if n, op, want := -a, `-`, minus; n != want { ok=false; println(`int64`, op, a, `=`, n, `should be`, want); }
}

func testInt64Binary(a, b, add, sub, mul, div, mod, and, or, xor, andnot int64, dodiv bool) {
	if n, op, want := a + b, `+`, add; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
	if n, op, want := a - b, `-`, sub; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
	if n, op, want := a * b, `*`, mul; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
	if dodiv {
		if n, op, want := a / b, `/`, div; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
		if n, op, want := a % b, `%`, mod; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
	}
	if n, op, want := a & b, `&`, and; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
	if n, op, want := a | b, `|`, or; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
	if n, op, want := a ^ b, `^`, xor; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
	if n, op, want := a &^ b, `&^`, andnot; n != want { ok=false; println(`int64`, a, op, b, `=`, n, `should be`, want); }
}

func testInt64Shift(a int64, b uint64, left, right int64) {
	if n, op, s, want := a << b, `<<`, b, left; n != want { ok=false; println(`int64`, a, op, `uint64`, s, `=`, n, `should be`, want); }
	if n, op, s, want := a >> b, `>>`, b, right; n != want { ok=false; println(`int64`, a, op, `uint64`, s, `=`, n, `should be`, want); }
	// ... (other shift variations)
}

func test0() {
	a := Int64{10, 0}
	testInt64Unary(int64(a.hi)<<32|int64(a.lo), int64(a.hi)<<32|int64(a.lo), ^(int64(a.hi)<<32|int64(a.lo)), -(int64(a.hi)<<32|int64(a.lo)))
	b := Int64{5, 0}
	testInt64Binary(int64(a.hi)<<32|int64(a.lo), int64(b.hi)<<32|int64(b.lo), (int64(a.hi)<<32|int64(a.lo))+(int64(b.hi)<<32|int64(b.lo)), (int64(a.hi)<<32|int64(a.lo))-(int64(b.hi)<<32|int64(b.lo)), (int64(a.hi)<<32|int64(a.lo))*(int64(b.hi)<<32|int64(b.lo)), (int64(a.hi)<<32|int64(a.lo))/(int64(b.hi)<<32|int64(b.lo)), (int64(a.hi)<<32|int64(a.lo))%(int64(b.hi)<<32|int64(b.lo)), (int64(a.hi)<<32|int64(a.lo))&(int64(b.hi)<<32|int64(b.lo)), (int64(a.hi)<<32|int64(a.lo))|(int64(b.hi)<<32|int64(b.lo)), (int64(a.hi)<<32|int64(a.lo))^(int64(b.hi)<<32|int64(b.lo)), (int64(a.hi)<<32|int64(a.lo))&^(int64(b.hi)<<32|int64(b.lo)), true)
    // ... (shift tests)
}
```

**假设的输入与输出:**

该程序本身并不接受直接的用户输入。它的“输入”是硬编码在 `int64Values`, `uint64Values`, 和 `shiftValues` 中的测试用例。

该程序的“输出”是生成的 Go 源代码，它会被写入标准输出。这个生成的源代码本身是一个可执行的测试程序。

**命令行参数的具体处理:**

该程序没有定义任何命令行参数的处理逻辑。它直接将生成的测试代码输出到标准输出。如果需要将生成的代码保存到文件，需要使用 shell 的重定向功能，例如：

```bash
go run 64bit.go > 64bit_test.go
```

**使用者易犯错的点:**

1. **误解代码的用途:**  使用者可能会错误地认为这段代码是用于在 Go 中进行 64 位算术的通用库。实际上，它是用来生成 *测试代码* 的，而不是提供直接的 64 位运算功能。在实际的 Go 开发中，应该使用 Go 内置的 `int64` 和 `uint64` 类型进行 64 位算术运算。

   **错误示例:**  在自己的代码中直接使用 `Uint64` 和 `Int64` 类型进行计算，而不是使用 Go 的内置类型。

   ```go
   package main

   import "fmt"

   // 错误地使用了测试代码中的类型
   type Uint64 struct {
       hi uint32
       lo uint32
   }

   func main() {
       a := Uint64{hi: 1, lo: 0}
       b := Uint64{hi: 2, lo: 0}
       c := a.Plus(b) // 期望使用 Go 内置的 uint64 进行运算
       fmt.Println(c)
   }
   ```

   **正确做法:** 使用 Go 的内置类型。

   ```go
   package main

   import "fmt"

   func main() {
       var a uint64 = 1 << 32
       var b uint64 = 2 << 32
       c := a + b
       fmt.Println(c)
   }
   ```

2. **不理解生成的测试代码的运行方式:**  使用者可能不清楚该程序生成的是一个独立的 Go 测试文件，需要编译和运行这个生成的文件才能执行测试。

   **正确流程:**
   1. 运行 `go run 64bit.go > 64bit_test.go` 生成测试文件。
   2. 运行 `go test 64bit_test.go` (或者 `go run 64bit_test.go`，取决于测试文件的结构) 来执行测试。

总而言之，`go/test/64bit.go` 的这段代码是一个用于生成 64 位算术运算测试的工具，其目的是验证 Go 编译器在处理 64 位运算时的正确性。使用者需要理解其生成测试代码的本质，并在实际开发中使用 Go 的内置 64 位类型。

Prompt: 
```
这是路径为go/test/64bit.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
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

"""



```