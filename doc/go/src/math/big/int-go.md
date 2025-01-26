Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of a Go code snippet, specifically focusing on the `Int` type in the `math/big` package. It also requests demonstration with Go code examples, inference of the underlying Go feature, handling of command-line arguments (if applicable), identification of common user errors, and finally, a concise summary for "part 1".

2. **Initial Scan and Keyword Identification:**  I'll quickly read through the code, looking for key words and structural elements. I see:
    * `package big` -  Confirms the package.
    * `type Int struct` -  Defines the core data structure.
    * Comments explaining the purpose of `Int`.
    * Methods associated with `Int` like `Sign`, `SetInt64`, `Add`, `Mul`, `Quo`, `Rem`, `Cmp`, etc.

3. **Categorize Functionality:** I'll mentally group the methods based on their general purpose:
    * **Creation/Initialization:** `NewInt`, `Set`, `SetInt64`, `SetUint64`, `SetBits`, `SetString`, `SetBytes`.
    * **Basic Arithmetic:** `Add`, `Sub`, `Mul`, `Quo`, `Rem`, `Div`, `Mod`, `QuoRem`, `DivMod`.
    * **Comparison:** `Sign`, `Cmp`, `CmpAbs`.
    * **Bit Manipulation:** `BitLen`, `TrailingZeroBits`, `Bit`, `SetBit`, `Lsh`, `Rsh`, `And`, `AndNot`, `Or`, `Xor`.
    * **Conversion:** `Int64`, `Uint64`, `IsInt64`, `IsUint64`, `Float64`, `Bytes`, `FillBytes`.
    * **Advanced Math:** `MulRange`, `Binomial`, `Exp`, `GCD`, `ModInverse`, `Jacobi`, `ModSqrt`.
    * **Random Number Generation:** `Rand`.

4. **Infer Go Feature:**  The existence of `Int` with methods for arithmetic, comparison, and bit manipulation strongly suggests this is the implementation of **arbitrary-precision integers** in Go. This allows working with integers larger than the built-in `int` and `int64` types.

5. **Code Examples (with Hypothesized Inputs/Outputs):** For key functionalities, I'll write simple Go code demonstrating their use. It's important to include assumed inputs and expected outputs to make the examples concrete. I will choose examples that highlight the arbitrary-precision aspect.

    * **Addition:** Show adding two large numbers that would overflow standard integer types.
    * **Multiplication:** Similar to addition.
    * **String Conversion:** Demonstrate converting a large string representation to an `Int`.
    * **Comparison:** Compare two large `Int` values.

6. **Command-Line Arguments:** I will carefully review the methods. None of the exposed methods in this snippet directly process command-line arguments. The `SetString` method can *interpret* a string that *could* come from a command-line argument, but the code itself doesn't handle the argument parsing. So, I'll state that it doesn't directly handle command-line arguments.

7. **Common User Errors:**  I will consider how users might misuse the `Int` type, focusing on the points emphasized in the comments. The key error is **incorrect copying**. Because `Int` uses pointers, a simple assignment (`=`) will create a shallow copy, leading to unexpected behavior. I need to demonstrate the correct way using the `Set` method.

8. **Part 1 Summary:** Finally, I will synthesize the information gathered into a concise summary for "part 1," focusing on the main purpose and core functionalities.

9. **Review and Refine:**  I'll reread my answer to ensure accuracy, clarity, and completeness, addressing all parts of the request. I will double-check the code examples for correctness and the explanations for clarity. I will make sure the language is in Chinese as requested.

**(Self-Correction Example during thought process):**

*Initially, I might think `SetString` implies command-line argument handling.*  However, on closer inspection, I realize `SetString` *takes* a string as input. The string could come from anywhere, including a command-line argument, but the `Int` type itself isn't responsible for parsing the command line. This distinction is important, and I'd correct my understanding accordingly. Similarly, I might initially forget the crucial point about copying and add it upon rereading the comments.
这是 `go/src/math/big/int.go` 文件中 `Int` 类型定义及其部分方法的实现。`Int` 类型在 Go 语言中用于表示**任意精度的有符号整数**。由于其精度不受固定大小（如 `int` 或 `int64`）的限制，它可以表示非常大或非常小的整数。

**`Int` 类型的主要功能归纳如下（基于提供的代码片段）：**

1. **表示和创建大整数:**
   - `type Int struct`: 定义了表示大整数的结构体，包含一个表示符号的 `neg` 字段和一个表示绝对值的 `abs` 字段 (类型为 `nat`，未在此片段中定义，但可以推断是用于存储无符号大整数的切片)。
   - `NewInt(x int64) *Int`:  创建一个新的 `Int` 指针，并将其值设置为 `x`（`int64` 类型）。
   - `SetInt64(x int64) *Int`: 将 `Int` 指针 `z` 的值设置为 `x`（`int64` 类型）。
   - `SetUint64(x uint64) *Int`: 将 `Int` 指针 `z` 的值设置为 `x`（`uint64` 类型）。
   - `Set(x *Int) *Int`: 将 `Int` 指针 `z` 的值设置为另一个 `Int` 指针 `x` 的值（深拷贝）。
   - `SetBits(abs []Word) *Int`: 将 `Int` 指针 `z` 的值设置为给定的 `Word` 切片 `abs` 表示的无符号大整数。
   - `SetString(s string, base int) (*Int, bool)`: 将 `Int` 指针 `z` 的值设置为字符串 `s` 在给定 `base` 下表示的整数。

2. **基本算术运算:**
   - `Sign() int`: 返回 `Int` 的符号（-1 表示负数，0 表示零，1 表示正数）。
   - `Abs(x *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 的绝对值。
   - `Neg(x *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 的相反数。
   - `Add(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 和 `y` 的和。
   - `Sub(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 和 `y` 的差。
   - `Mul(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 和 `y` 的积。
   - `Quo(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 除以 `y` 的商（截断除法）。
   - `Rem(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 除以 `y` 的余数（截断模）。
   - `QuoRem(x, y, r *Int) (*Int, *Int)`:  计算 `x` 除以 `y` 的商和余数，分别存入 `z` 和 `r`。
   - `Div(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 除以 `y` 的商（欧几里得除法）。
   - `Mod(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 除以 `y` 的余数（欧几里得模）。
   - `DivMod(x, y, m *Int) (*Int, *Int)`: 计算 `x` 除以 `y` 的商和余数（欧几里得除法），分别存入 `z` 和 `m`。
   - `MulRange(a, b int64) *Int`: 将 `Int` 指针 `z` 的值设置为 `[a, b]` 范围内所有整数的乘积。
   - `Binomial(n, k int64) *Int`: 将 `Int` 指针 `z` 的值设置为二项式系数 C(n, k)。

3. **比较运算:**
   - `Cmp(y *Int) int`: 比较 `Int` 指针 `x` 和 `y` 的大小，返回 -1 (x < y)，0 (x == y)，或 1 (x > y)。
   - `CmpAbs(y *Int) int`: 比较 `Int` 指针 `x` 和 `y` 的绝对值大小。

4. **类型转换和信息获取:**
   - `Int64() int64`: 返回 `Int` 的 `int64` 表示。如果 `Int` 的值无法用 `int64` 表示，结果是未定义的。
   - `Uint64() uint64`: 返回 `Int` 的 `uint64` 表示。如果 `Int` 的值无法用 `uint64` 表示，结果是未定义的。
   - `IsInt64() bool`: 判断 `Int` 的值是否可以用 `int64` 表示。
   - `IsUint64() bool`: 判断 `Int` 的值是否可以用 `uint64` 表示。
   - `Float64() (float64, Accuracy)`: 返回最接近 `Int` 值的 `float64` 值，并指示是否发生了舍入。
   - `Bits() []Word`:  以小端字节序返回 `Int` 绝对值的 `Word` 切片。
   - `Bytes() []byte`: 返回 `Int` 绝对值的大端字节序表示。
   - `FillBytes(buf []byte) []byte`: 将 `Int` 的绝对值以大端字节序填充到 `buf` 中。
   - `BitLen() int`: 返回 `Int` 绝对值的比特长度。
   - `TrailingZeroBits() uint`: 返回 `Int` 绝对值末尾连续零比特的个数。

5. **高级数学运算:**
   - `Exp(x, y, m *Int) *Int`: 计算 `x` 的 `y` 次方模 `|m|` 的结果。
   - `GCD(x, y, a, b *Int) *Int`: 计算 `a` 和 `b` 的最大公约数，并可选择性地计算满足 `z = a*x + b*y` 的系数 `x` 和 `y`。
   - `ModInverse(g, n *Int) *Int`: 计算 `g` 在模 `n` 意义下的乘法逆元。
   - `Jacobi(x, y *Int) int`: 计算雅可比符号 (x/y)。
   - `ModSqrt(x, p *Int) *Int`: 计算 `x` 在模 `p` 意义下的平方根。

6. **位运算:**
   - `Lsh(x *Int, n uint) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 左移 `n` 位的结果。
   - `Rsh(x *Int, n uint) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 右移 `n` 位的结果。
   - `Bit(i int) uint`: 返回 `Int` 的第 `i` 位的值。
   - `SetBit(x *Int, i int, b uint) *Int`: 将 `Int` 指针 `z` 的值设置为 `x`，并将第 `i` 位设置为 `b`。
   - `And(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 和 `y` 的按位与。
   - `AndNot(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 和 `y` 的按位与非。
   - `Or(x, y *Int) *Int`: 将 `Int` 指针 `z` 的值设置为 `Int` 指针 `x` 和 `y` 的按位或。

7. **随机数生成:**
   - `Rand(rnd *rand.Rand, n *Int) *Int`:  将 `Int` 指针 `z` 的值设置为 `[0, n)` 范围内的伪随机数。

**它是什么 Go 语言功能的实现？**

根据这些方法的功能，可以推断出 `Int` 类型是 Go 语言中 **`math/big` 包提供的用于处理任意精度整数的功能** 的核心实现。这允许 Go 程序执行涉及超出标准整数类型范围的数学运算。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	// 创建两个大整数
	a := big.NewInt(1234567890123456789)
	b := big.NewInt(9876543210987654321)

	// 执行加法运算
	sum := new(big.Int)
	sum.Add(a, b)
	fmt.Println("Sum:", sum.String()) // 输出 Sum: 11111111101111111110

	// 执行乘法运算
	product := new(big.Int)
	product.Mul(a, b)
	fmt.Println("Product:", product.String())
	// 假设输出: Product: 1219326311370217951085754635329

	// 比较大小
	if a.Cmp(b) < 0 {
		fmt.Println("a is less than b")
	} else if a.Cmp(b) > 0 {
		fmt.Println("a is greater than b")
	} else {
		fmt.Println("a is equal to b")
	}

	// 设置字符串表示
	c := new(big.Int)
	c.SetString("1000000000000000000000000000000", 10)
	fmt.Println("C from string:", c.String())

	// 获取比特长度
	fmt.Println("Bit length of a:", a.BitLen())
}
```

**假设的输入与输出：**

上面的代码示例中，我们假设了 `a` 和 `b` 的初始值，并展示了加法和乘法运算的输出。对于比较操作，由于 `a` 小于 `b`，预计输出 "a is less than b"。对于字符串设置，预计 `c` 的值为 1 后面跟着 30 个 0。`a` 的比特长度取决于其具体数值，但会是一个合理的位数。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。`Int` 类型的方法主要用于数值运算和转换。如果需要从命令行读取大整数，你需要使用 Go 的 `os` 包和字符串处理函数，然后使用 `SetString` 方法将字符串转换为 `big.Int`。

例如：

```go
package main

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run main.go <integer1> <integer2>")
		return
	}

	numStr1 := os.Args[1]
	numStr2 := os.Args[2]

	base := 10 // 假设输入是十进制数

	a := new(big.Int)
	_, ok := a.SetString(numStr1, base)
	if !ok {
		fmt.Println("Invalid integer:", numStr1)
		return
	}

	b := new(big.Int)
	_, ok = b.SetString(numStr2, base)
	if !ok {
		fmt.Println("Invalid integer:", numStr2)
		return
	}

	sum := new(big.Int)
	sum.Add(a, b)
	fmt.Println("Sum:", sum.String())
}
```

在这个例子中，命令行参数 `os.Args[1]` 和 `os.Args[2]` 被作为字符串读取，然后使用 `SetString` 转换为 `big.Int`。

**使用者易犯错的点：**

1. **浅拷贝问题:**  `big.Int` 类型使用指针。直接赋值 (`=`) 会创建浅拷贝，这意味着两个 `big.Int` 变量会指向同一个底层数据。修改其中一个会影响另一个。应该使用 `Set` 方法进行深拷贝。

   ```go
   package main

   import (
   	"fmt"
   	"math/big"
   )

   func main() {
   	a := big.NewInt(100)
   	b := a // 错误：浅拷贝
   	b.SetInt64(200)
   	fmt.Println("a:", a) // 输出 a: 200，期望可能是 100

   	c := big.NewInt(300)
   	d := new(big.Int).Set(c) // 正确：深拷贝
   	d.SetInt64(400)
   	fmt.Println("c:", c) // 输出 c: 300，符合预期
   }
   ```

**这是第1部分，共2部分，请归纳一下它的功能**

总而言之，这份代码片段定义并实现了 Go 语言 `math/big` 包中的 `Int` 类型及其核心功能。`Int` 类型允许程序处理任意精度的有符号整数，提供了创建、基本算术运算、比较、类型转换、信息获取、高级数学运算（如模幂、最大公约数、模逆元、平方根等）以及位运算等丰富的功能。这使得 Go 语言能够处理需要大整数运算的场景，例如密码学、高精度计算等。

Prompt: 
```
这是路径为go/src/math/big/int.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements signed multi-precision integers.

package big

import (
	"fmt"
	"io"
	"math/rand"
	"strings"
)

// An Int represents a signed multi-precision integer.
// The zero value for an Int represents the value 0.
//
// Operations always take pointer arguments (*Int) rather
// than Int values, and each unique Int value requires
// its own unique *Int pointer. To "copy" an Int value,
// an existing (or newly allocated) Int must be set to
// a new value using the [Int.Set] method; shallow copies
// of Ints are not supported and may lead to errors.
//
// Note that methods may leak the Int's value through timing side-channels.
// Because of this and because of the scope and complexity of the
// implementation, Int is not well-suited to implement cryptographic operations.
// The standard library avoids exposing non-trivial Int methods to
// attacker-controlled inputs and the determination of whether a bug in math/big
// is considered a security vulnerability might depend on the impact on the
// standard library.
type Int struct {
	neg bool // sign
	abs nat  // absolute value of the integer
}

var intOne = &Int{false, natOne}

// Sign returns:
//   - -1 if x < 0;
//   - 0 if x == 0;
//   - +1 if x > 0.
func (x *Int) Sign() int {
	// This function is used in cryptographic operations. It must not leak
	// anything but the Int's sign and bit size through side-channels. Any
	// changes must be reviewed by a security expert.
	if len(x.abs) == 0 {
		return 0
	}
	if x.neg {
		return -1
	}
	return 1
}

// SetInt64 sets z to x and returns z.
func (z *Int) SetInt64(x int64) *Int {
	neg := false
	if x < 0 {
		neg = true
		x = -x
	}
	z.abs = z.abs.setUint64(uint64(x))
	z.neg = neg
	return z
}

// SetUint64 sets z to x and returns z.
func (z *Int) SetUint64(x uint64) *Int {
	z.abs = z.abs.setUint64(x)
	z.neg = false
	return z
}

// NewInt allocates and returns a new [Int] set to x.
func NewInt(x int64) *Int {
	// This code is arranged to be inlineable and produce
	// zero allocations when inlined. See issue 29951.
	u := uint64(x)
	if x < 0 {
		u = -u
	}
	var abs []Word
	if x == 0 {
	} else if _W == 32 && u>>32 != 0 {
		abs = []Word{Word(u), Word(u >> 32)}
	} else {
		abs = []Word{Word(u)}
	}
	return &Int{neg: x < 0, abs: abs}
}

// Set sets z to x and returns z.
func (z *Int) Set(x *Int) *Int {
	if z != x {
		z.abs = z.abs.set(x.abs)
		z.neg = x.neg
	}
	return z
}

// Bits provides raw (unchecked but fast) access to x by returning its
// absolute value as a little-endian [Word] slice. The result and x share
// the same underlying array.
// Bits is intended to support implementation of missing low-level [Int]
// functionality outside this package; it should be avoided otherwise.
func (x *Int) Bits() []Word {
	// This function is used in cryptographic operations. It must not leak
	// anything but the Int's sign and bit size through side-channels. Any
	// changes must be reviewed by a security expert.
	return x.abs
}

// SetBits provides raw (unchecked but fast) access to z by setting its
// value to abs, interpreted as a little-endian [Word] slice, and returning
// z. The result and abs share the same underlying array.
// SetBits is intended to support implementation of missing low-level [Int]
// functionality outside this package; it should be avoided otherwise.
func (z *Int) SetBits(abs []Word) *Int {
	z.abs = nat(abs).norm()
	z.neg = false
	return z
}

// Abs sets z to |x| (the absolute value of x) and returns z.
func (z *Int) Abs(x *Int) *Int {
	z.Set(x)
	z.neg = false
	return z
}

// Neg sets z to -x and returns z.
func (z *Int) Neg(x *Int) *Int {
	z.Set(x)
	z.neg = len(z.abs) > 0 && !z.neg // 0 has no sign
	return z
}

// Add sets z to the sum x+y and returns z.
func (z *Int) Add(x, y *Int) *Int {
	neg := x.neg
	if x.neg == y.neg {
		// x + y == x + y
		// (-x) + (-y) == -(x + y)
		z.abs = z.abs.add(x.abs, y.abs)
	} else {
		// x + (-y) == x - y == -(y - x)
		// (-x) + y == y - x == -(x - y)
		if x.abs.cmp(y.abs) >= 0 {
			z.abs = z.abs.sub(x.abs, y.abs)
		} else {
			neg = !neg
			z.abs = z.abs.sub(y.abs, x.abs)
		}
	}
	z.neg = len(z.abs) > 0 && neg // 0 has no sign
	return z
}

// Sub sets z to the difference x-y and returns z.
func (z *Int) Sub(x, y *Int) *Int {
	neg := x.neg
	if x.neg != y.neg {
		// x - (-y) == x + y
		// (-x) - y == -(x + y)
		z.abs = z.abs.add(x.abs, y.abs)
	} else {
		// x - y == x - y == -(y - x)
		// (-x) - (-y) == y - x == -(x - y)
		if x.abs.cmp(y.abs) >= 0 {
			z.abs = z.abs.sub(x.abs, y.abs)
		} else {
			neg = !neg
			z.abs = z.abs.sub(y.abs, x.abs)
		}
	}
	z.neg = len(z.abs) > 0 && neg // 0 has no sign
	return z
}

// Mul sets z to the product x*y and returns z.
func (z *Int) Mul(x, y *Int) *Int {
	// x * y == x * y
	// x * (-y) == -(x * y)
	// (-x) * y == -(x * y)
	// (-x) * (-y) == x * y
	if x == y {
		z.abs = z.abs.sqr(x.abs)
		z.neg = false
		return z
	}
	z.abs = z.abs.mul(x.abs, y.abs)
	z.neg = len(z.abs) > 0 && x.neg != y.neg // 0 has no sign
	return z
}

// MulRange sets z to the product of all integers
// in the range [a, b] inclusively and returns z.
// If a > b (empty range), the result is 1.
func (z *Int) MulRange(a, b int64) *Int {
	switch {
	case a > b:
		return z.SetInt64(1) // empty range
	case a <= 0 && b >= 0:
		return z.SetInt64(0) // range includes 0
	}
	// a <= b && (b < 0 || a > 0)

	neg := false
	if a < 0 {
		neg = (b-a)&1 == 0
		a, b = -b, -a
	}

	z.abs = z.abs.mulRange(uint64(a), uint64(b))
	z.neg = neg
	return z
}

// Binomial sets z to the binomial coefficient C(n, k) and returns z.
func (z *Int) Binomial(n, k int64) *Int {
	if k > n {
		return z.SetInt64(0)
	}
	// reduce the number of multiplications by reducing k
	if k > n-k {
		k = n - k // C(n, k) == C(n, n-k)
	}
	// C(n, k) == n * (n-1) * ... * (n-k+1) / k * (k-1) * ... * 1
	//         == n * (n-1) * ... * (n-k+1) / 1 * (1+1) * ... * k
	//
	// Using the multiplicative formula produces smaller values
	// at each step, requiring fewer allocations and computations:
	//
	// z = 1
	// for i := 0; i < k; i = i+1 {
	//     z *= n-i
	//     z /= i+1
	// }
	//
	// finally to avoid computing i+1 twice per loop:
	//
	// z = 1
	// i := 0
	// for i < k {
	//     z *= n-i
	//     i++
	//     z /= i
	// }
	var N, K, i, t Int
	N.SetInt64(n)
	K.SetInt64(k)
	z.Set(intOne)
	for i.Cmp(&K) < 0 {
		z.Mul(z, t.Sub(&N, &i))
		i.Add(&i, intOne)
		z.Quo(z, &i)
	}
	return z
}

// Quo sets z to the quotient x/y for y != 0 and returns z.
// If y == 0, a division-by-zero run-time panic occurs.
// Quo implements truncated division (like Go); see [Int.QuoRem] for more details.
func (z *Int) Quo(x, y *Int) *Int {
	z.abs, _ = z.abs.div(nil, x.abs, y.abs)
	z.neg = len(z.abs) > 0 && x.neg != y.neg // 0 has no sign
	return z
}

// Rem sets z to the remainder x%y for y != 0 and returns z.
// If y == 0, a division-by-zero run-time panic occurs.
// Rem implements truncated modulus (like Go); see [Int.QuoRem] for more details.
func (z *Int) Rem(x, y *Int) *Int {
	_, z.abs = nat(nil).div(z.abs, x.abs, y.abs)
	z.neg = len(z.abs) > 0 && x.neg // 0 has no sign
	return z
}

// QuoRem sets z to the quotient x/y and r to the remainder x%y
// and returns the pair (z, r) for y != 0.
// If y == 0, a division-by-zero run-time panic occurs.
//
// QuoRem implements T-division and modulus (like Go):
//
//	q = x/y      with the result truncated to zero
//	r = x - y*q
//
// (See Daan Leijen, “Division and Modulus for Computer Scientists”.)
// See [Int.DivMod] for Euclidean division and modulus (unlike Go).
func (z *Int) QuoRem(x, y, r *Int) (*Int, *Int) {
	z.abs, r.abs = z.abs.div(r.abs, x.abs, y.abs)
	z.neg, r.neg = len(z.abs) > 0 && x.neg != y.neg, len(r.abs) > 0 && x.neg // 0 has no sign
	return z, r
}

// Div sets z to the quotient x/y for y != 0 and returns z.
// If y == 0, a division-by-zero run-time panic occurs.
// Div implements Euclidean division (unlike Go); see [Int.DivMod] for more details.
func (z *Int) Div(x, y *Int) *Int {
	y_neg := y.neg // z may be an alias for y
	var r Int
	z.QuoRem(x, y, &r)
	if r.neg {
		if y_neg {
			z.Add(z, intOne)
		} else {
			z.Sub(z, intOne)
		}
	}
	return z
}

// Mod sets z to the modulus x%y for y != 0 and returns z.
// If y == 0, a division-by-zero run-time panic occurs.
// Mod implements Euclidean modulus (unlike Go); see [Int.DivMod] for more details.
func (z *Int) Mod(x, y *Int) *Int {
	y0 := y // save y
	if z == y || alias(z.abs, y.abs) {
		y0 = new(Int).Set(y)
	}
	var q Int
	q.QuoRem(x, y, z)
	if z.neg {
		if y0.neg {
			z.Sub(z, y0)
		} else {
			z.Add(z, y0)
		}
	}
	return z
}

// DivMod sets z to the quotient x div y and m to the modulus x mod y
// and returns the pair (z, m) for y != 0.
// If y == 0, a division-by-zero run-time panic occurs.
//
// DivMod implements Euclidean division and modulus (unlike Go):
//
//	q = x div y  such that
//	m = x - y*q  with 0 <= m < |y|
//
// (See Raymond T. Boute, “The Euclidean definition of the functions
// div and mod”. ACM Transactions on Programming Languages and
// Systems (TOPLAS), 14(2):127-144, New York, NY, USA, 4/1992.
// ACM press.)
// See [Int.QuoRem] for T-division and modulus (like Go).
func (z *Int) DivMod(x, y, m *Int) (*Int, *Int) {
	y0 := y // save y
	if z == y || alias(z.abs, y.abs) {
		y0 = new(Int).Set(y)
	}
	z.QuoRem(x, y, m)
	if m.neg {
		if y0.neg {
			z.Add(z, intOne)
			m.Sub(m, y0)
		} else {
			z.Sub(z, intOne)
			m.Add(m, y0)
		}
	}
	return z, m
}

// Cmp compares x and y and returns:
//   - -1 if x < y;
//   - 0 if x == y;
//   - +1 if x > y.
func (x *Int) Cmp(y *Int) (r int) {
	// x cmp y == x cmp y
	// x cmp (-y) == x
	// (-x) cmp y == y
	// (-x) cmp (-y) == -(x cmp y)
	switch {
	case x == y:
		// nothing to do
	case x.neg == y.neg:
		r = x.abs.cmp(y.abs)
		if x.neg {
			r = -r
		}
	case x.neg:
		r = -1
	default:
		r = 1
	}
	return
}

// CmpAbs compares the absolute values of x and y and returns:
//   - -1 if |x| < |y|;
//   - 0 if |x| == |y|;
//   - +1 if |x| > |y|.
func (x *Int) CmpAbs(y *Int) int {
	return x.abs.cmp(y.abs)
}

// low32 returns the least significant 32 bits of x.
func low32(x nat) uint32 {
	if len(x) == 0 {
		return 0
	}
	return uint32(x[0])
}

// low64 returns the least significant 64 bits of x.
func low64(x nat) uint64 {
	if len(x) == 0 {
		return 0
	}
	v := uint64(x[0])
	if _W == 32 && len(x) > 1 {
		return uint64(x[1])<<32 | v
	}
	return v
}

// Int64 returns the int64 representation of x.
// If x cannot be represented in an int64, the result is undefined.
func (x *Int) Int64() int64 {
	v := int64(low64(x.abs))
	if x.neg {
		v = -v
	}
	return v
}

// Uint64 returns the uint64 representation of x.
// If x cannot be represented in a uint64, the result is undefined.
func (x *Int) Uint64() uint64 {
	return low64(x.abs)
}

// IsInt64 reports whether x can be represented as an int64.
func (x *Int) IsInt64() bool {
	if len(x.abs) <= 64/_W {
		w := int64(low64(x.abs))
		return w >= 0 || x.neg && w == -w
	}
	return false
}

// IsUint64 reports whether x can be represented as a uint64.
func (x *Int) IsUint64() bool {
	return !x.neg && len(x.abs) <= 64/_W
}

// Float64 returns the float64 value nearest x,
// and an indication of any rounding that occurred.
func (x *Int) Float64() (float64, Accuracy) {
	n := x.abs.bitLen() // NB: still uses slow crypto impl!
	if n == 0 {
		return 0.0, Exact
	}

	// Fast path: no more than 53 significant bits.
	if n <= 53 || n < 64 && n-int(x.abs.trailingZeroBits()) <= 53 {
		f := float64(low64(x.abs))
		if x.neg {
			f = -f
		}
		return f, Exact
	}

	return new(Float).SetInt(x).Float64()
}

// SetString sets z to the value of s, interpreted in the given base,
// and returns z and a boolean indicating success. The entire string
// (not just a prefix) must be valid for success. If SetString fails,
// the value of z is undefined but the returned value is nil.
//
// The base argument must be 0 or a value between 2 and [MaxBase].
// For base 0, the number prefix determines the actual base: A prefix of
// “0b” or “0B” selects base 2, “0”, “0o” or “0O” selects base 8,
// and “0x” or “0X” selects base 16. Otherwise, the selected base is 10
// and no prefix is accepted.
//
// For bases <= 36, lower and upper case letters are considered the same:
// The letters 'a' to 'z' and 'A' to 'Z' represent digit values 10 to 35.
// For bases > 36, the upper case letters 'A' to 'Z' represent the digit
// values 36 to 61.
//
// For base 0, an underscore character “_” may appear between a base
// prefix and an adjacent digit, and between successive digits; such
// underscores do not change the value of the number.
// Incorrect placement of underscores is reported as an error if there
// are no other errors. If base != 0, underscores are not recognized
// and act like any other character that is not a valid digit.
func (z *Int) SetString(s string, base int) (*Int, bool) {
	return z.setFromScanner(strings.NewReader(s), base)
}

// setFromScanner implements SetString given an io.ByteScanner.
// For documentation see comments of SetString.
func (z *Int) setFromScanner(r io.ByteScanner, base int) (*Int, bool) {
	if _, _, err := z.scan(r, base); err != nil {
		return nil, false
	}
	// entire content must have been consumed
	if _, err := r.ReadByte(); err != io.EOF {
		return nil, false
	}
	return z, true // err == io.EOF => scan consumed all content of r
}

// SetBytes interprets buf as the bytes of a big-endian unsigned
// integer, sets z to that value, and returns z.
func (z *Int) SetBytes(buf []byte) *Int {
	z.abs = z.abs.setBytes(buf)
	z.neg = false
	return z
}

// Bytes returns the absolute value of x as a big-endian byte slice.
//
// To use a fixed length slice, or a preallocated one, use [Int.FillBytes].
func (x *Int) Bytes() []byte {
	// This function is used in cryptographic operations. It must not leak
	// anything but the Int's sign and bit size through side-channels. Any
	// changes must be reviewed by a security expert.
	buf := make([]byte, len(x.abs)*_S)
	return buf[x.abs.bytes(buf):]
}

// FillBytes sets buf to the absolute value of x, storing it as a zero-extended
// big-endian byte slice, and returns buf.
//
// If the absolute value of x doesn't fit in buf, FillBytes will panic.
func (x *Int) FillBytes(buf []byte) []byte {
	// Clear whole buffer.
	clear(buf)
	x.abs.bytes(buf)
	return buf
}

// BitLen returns the length of the absolute value of x in bits.
// The bit length of 0 is 0.
func (x *Int) BitLen() int {
	// This function is used in cryptographic operations. It must not leak
	// anything but the Int's sign and bit size through side-channels. Any
	// changes must be reviewed by a security expert.
	return x.abs.bitLen()
}

// TrailingZeroBits returns the number of consecutive least significant zero
// bits of |x|.
func (x *Int) TrailingZeroBits() uint {
	return x.abs.trailingZeroBits()
}

// Exp sets z = x**y mod |m| (i.e. the sign of m is ignored), and returns z.
// If m == nil or m == 0, z = x**y unless y <= 0 then z = 1. If m != 0, y < 0,
// and x and m are not relatively prime, z is unchanged and nil is returned.
//
// Modular exponentiation of inputs of a particular size is not a
// cryptographically constant-time operation.
func (z *Int) Exp(x, y, m *Int) *Int {
	return z.exp(x, y, m, false)
}

func (z *Int) expSlow(x, y, m *Int) *Int {
	return z.exp(x, y, m, true)
}

func (z *Int) exp(x, y, m *Int, slow bool) *Int {
	// See Knuth, volume 2, section 4.6.3.
	xWords := x.abs
	if y.neg {
		if m == nil || len(m.abs) == 0 {
			return z.SetInt64(1)
		}
		// for y < 0: x**y mod m == (x**(-1))**|y| mod m
		inverse := new(Int).ModInverse(x, m)
		if inverse == nil {
			return nil
		}
		xWords = inverse.abs
	}
	yWords := y.abs

	var mWords nat
	if m != nil {
		if z == m || alias(z.abs, m.abs) {
			m = new(Int).Set(m)
		}
		mWords = m.abs // m.abs may be nil for m == 0
	}

	z.abs = z.abs.expNN(xWords, yWords, mWords, slow)
	z.neg = len(z.abs) > 0 && x.neg && len(yWords) > 0 && yWords[0]&1 == 1 // 0 has no sign
	if z.neg && len(mWords) > 0 {
		// make modulus result positive
		z.abs = z.abs.sub(mWords, z.abs) // z == x**y mod |m| && 0 <= z < |m|
		z.neg = false
	}

	return z
}

// GCD sets z to the greatest common divisor of a and b and returns z.
// If x or y are not nil, GCD sets their value such that z = a*x + b*y.
//
// a and b may be positive, zero or negative. (Before Go 1.14 both had
// to be > 0.) Regardless of the signs of a and b, z is always >= 0.
//
// If a == b == 0, GCD sets z = x = y = 0.
//
// If a == 0 and b != 0, GCD sets z = |b|, x = 0, y = sign(b) * 1.
//
// If a != 0 and b == 0, GCD sets z = |a|, x = sign(a) * 1, y = 0.
func (z *Int) GCD(x, y, a, b *Int) *Int {
	if len(a.abs) == 0 || len(b.abs) == 0 {
		lenA, lenB, negA, negB := len(a.abs), len(b.abs), a.neg, b.neg
		if lenA == 0 {
			z.Set(b)
		} else {
			z.Set(a)
		}
		z.neg = false
		if x != nil {
			if lenA == 0 {
				x.SetUint64(0)
			} else {
				x.SetUint64(1)
				x.neg = negA
			}
		}
		if y != nil {
			if lenB == 0 {
				y.SetUint64(0)
			} else {
				y.SetUint64(1)
				y.neg = negB
			}
		}
		return z
	}

	return z.lehmerGCD(x, y, a, b)
}

// lehmerSimulate attempts to simulate several Euclidean update steps
// using the leading digits of A and B.  It returns u0, u1, v0, v1
// such that A and B can be updated as:
//
//	A = u0*A + v0*B
//	B = u1*A + v1*B
//
// Requirements: A >= B and len(B.abs) >= 2
// Since we are calculating with full words to avoid overflow,
// we use 'even' to track the sign of the cosequences.
// For even iterations: u0, v1 >= 0 && u1, v0 <= 0
// For odd  iterations: u0, v1 <= 0 && u1, v0 >= 0
func lehmerSimulate(A, B *Int) (u0, u1, v0, v1 Word, even bool) {
	// initialize the digits
	var a1, a2, u2, v2 Word

	m := len(B.abs) // m >= 2
	n := len(A.abs) // n >= m >= 2

	// extract the top Word of bits from A and B
	h := nlz(A.abs[n-1])
	a1 = A.abs[n-1]<<h | A.abs[n-2]>>(_W-h)
	// B may have implicit zero words in the high bits if the lengths differ
	switch {
	case n == m:
		a2 = B.abs[n-1]<<h | B.abs[n-2]>>(_W-h)
	case n == m+1:
		a2 = B.abs[n-2] >> (_W - h)
	default:
		a2 = 0
	}

	// Since we are calculating with full words to avoid overflow,
	// we use 'even' to track the sign of the cosequences.
	// For even iterations: u0, v1 >= 0 && u1, v0 <= 0
	// For odd  iterations: u0, v1 <= 0 && u1, v0 >= 0
	// The first iteration starts with k=1 (odd).
	even = false
	// variables to track the cosequences
	u0, u1, u2 = 0, 1, 0
	v0, v1, v2 = 0, 0, 1

	// Calculate the quotient and cosequences using Collins' stopping condition.
	// Note that overflow of a Word is not possible when computing the remainder
	// sequence and cosequences since the cosequence size is bounded by the input size.
	// See section 4.2 of Jebelean for details.
	for a2 >= v2 && a1-a2 >= v1+v2 {
		q, r := a1/a2, a1%a2
		a1, a2 = a2, r
		u0, u1, u2 = u1, u2, u1+q*u2
		v0, v1, v2 = v1, v2, v1+q*v2
		even = !even
	}
	return
}

// lehmerUpdate updates the inputs A and B such that:
//
//	A = u0*A + v0*B
//	B = u1*A + v1*B
//
// where the signs of u0, u1, v0, v1 are given by even
// For even == true: u0, v1 >= 0 && u1, v0 <= 0
// For even == false: u0, v1 <= 0 && u1, v0 >= 0
// q, r, s, t are temporary variables to avoid allocations in the multiplication.
func lehmerUpdate(A, B, q, r, s, t *Int, u0, u1, v0, v1 Word, even bool) {

	t.abs = t.abs.setWord(u0)
	s.abs = s.abs.setWord(v0)
	t.neg = !even
	s.neg = even

	t.Mul(A, t)
	s.Mul(B, s)

	r.abs = r.abs.setWord(u1)
	q.abs = q.abs.setWord(v1)
	r.neg = even
	q.neg = !even

	r.Mul(A, r)
	q.Mul(B, q)

	A.Add(t, s)
	B.Add(r, q)
}

// euclidUpdate performs a single step of the Euclidean GCD algorithm
// if extended is true, it also updates the cosequence Ua, Ub.
func euclidUpdate(A, B, Ua, Ub, q, r, s, t *Int, extended bool) {
	q, r = q.QuoRem(A, B, r)

	*A, *B, *r = *B, *r, *A

	if extended {
		// Ua, Ub = Ub, Ua - q*Ub
		t.Set(Ub)
		s.Mul(Ub, q)
		Ub.Sub(Ua, s)
		Ua.Set(t)
	}
}

// lehmerGCD sets z to the greatest common divisor of a and b,
// which both must be != 0, and returns z.
// If x or y are not nil, their values are set such that z = a*x + b*y.
// See Knuth, The Art of Computer Programming, Vol. 2, Section 4.5.2, Algorithm L.
// This implementation uses the improved condition by Collins requiring only one
// quotient and avoiding the possibility of single Word overflow.
// See Jebelean, "Improving the multiprecision Euclidean algorithm",
// Design and Implementation of Symbolic Computation Systems, pp 45-58.
// The cosequences are updated according to Algorithm 10.45 from
// Cohen et al. "Handbook of Elliptic and Hyperelliptic Curve Cryptography" pp 192.
func (z *Int) lehmerGCD(x, y, a, b *Int) *Int {
	var A, B, Ua, Ub *Int

	A = new(Int).Abs(a)
	B = new(Int).Abs(b)

	extended := x != nil || y != nil

	if extended {
		// Ua (Ub) tracks how many times input a has been accumulated into A (B).
		Ua = new(Int).SetInt64(1)
		Ub = new(Int)
	}

	// temp variables for multiprecision update
	q := new(Int)
	r := new(Int)
	s := new(Int)
	t := new(Int)

	// ensure A >= B
	if A.abs.cmp(B.abs) < 0 {
		A, B = B, A
		Ub, Ua = Ua, Ub
	}

	// loop invariant A >= B
	for len(B.abs) > 1 {
		// Attempt to calculate in single-precision using leading words of A and B.
		u0, u1, v0, v1, even := lehmerSimulate(A, B)

		// multiprecision Step
		if v0 != 0 {
			// Simulate the effect of the single-precision steps using the cosequences.
			// A = u0*A + v0*B
			// B = u1*A + v1*B
			lehmerUpdate(A, B, q, r, s, t, u0, u1, v0, v1, even)

			if extended {
				// Ua = u0*Ua + v0*Ub
				// Ub = u1*Ua + v1*Ub
				lehmerUpdate(Ua, Ub, q, r, s, t, u0, u1, v0, v1, even)
			}

		} else {
			// Single-digit calculations failed to simulate any quotients.
			// Do a standard Euclidean step.
			euclidUpdate(A, B, Ua, Ub, q, r, s, t, extended)
		}
	}

	if len(B.abs) > 0 {
		// extended Euclidean algorithm base case if B is a single Word
		if len(A.abs) > 1 {
			// A is longer than a single Word, so one update is needed.
			euclidUpdate(A, B, Ua, Ub, q, r, s, t, extended)
		}
		if len(B.abs) > 0 {
			// A and B are both a single Word.
			aWord, bWord := A.abs[0], B.abs[0]
			if extended {
				var ua, ub, va, vb Word
				ua, ub = 1, 0
				va, vb = 0, 1
				even := true
				for bWord != 0 {
					q, r := aWord/bWord, aWord%bWord
					aWord, bWord = bWord, r
					ua, ub = ub, ua+q*ub
					va, vb = vb, va+q*vb
					even = !even
				}

				t.abs = t.abs.setWord(ua)
				s.abs = s.abs.setWord(va)
				t.neg = !even
				s.neg = even

				t.Mul(Ua, t)
				s.Mul(Ub, s)

				Ua.Add(t, s)
			} else {
				for bWord != 0 {
					aWord, bWord = bWord, aWord%bWord
				}
			}
			A.abs[0] = aWord
		}
	}
	negA := a.neg
	if y != nil {
		// avoid aliasing b needed in the division below
		if y == b {
			B.Set(b)
		} else {
			B = b
		}
		// y = (z - a*x)/b
		y.Mul(a, Ua) // y can safely alias a
		if negA {
			y.neg = !y.neg
		}
		y.Sub(A, y)
		y.Div(y, B)
	}

	if x != nil {
		*x = *Ua
		if negA {
			x.neg = !x.neg
		}
	}

	*z = *A

	return z
}

// Rand sets z to a pseudo-random number in [0, n) and returns z.
//
// As this uses the [math/rand] package, it must not be used for
// security-sensitive work. Use [crypto/rand.Int] instead.
func (z *Int) Rand(rnd *rand.Rand, n *Int) *Int {
	// z.neg is not modified before the if check, because z and n might alias.
	if n.neg || len(n.abs) == 0 {
		z.neg = false
		z.abs = nil
		return z
	}
	z.neg = false
	z.abs = z.abs.random(rnd, n.abs, n.abs.bitLen())
	return z
}

// ModInverse sets z to the multiplicative inverse of g in the ring ℤ/nℤ
// and returns z. If g and n are not relatively prime, g has no multiplicative
// inverse in the ring ℤ/nℤ.  In this case, z is unchanged and the return value
// is nil. If n == 0, a division-by-zero run-time panic occurs.
func (z *Int) ModInverse(g, n *Int) *Int {
	// GCD expects parameters a and b to be > 0.
	if n.neg {
		var n2 Int
		n = n2.Neg(n)
	}
	if g.neg {
		var g2 Int
		g = g2.Mod(g, n)
	}
	var d, x Int
	d.GCD(&x, nil, g, n)

	// if and only if d==1, g and n are relatively prime
	if d.Cmp(intOne) != 0 {
		return nil
	}

	// x and y are such that g*x + n*y = 1, therefore x is the inverse element,
	// but it may be negative, so convert to the range 0 <= z < |n|
	if x.neg {
		z.Add(&x, n)
	} else {
		z.Set(&x)
	}
	return z
}

func (z nat) modInverse(g, n nat) nat {
	// TODO(rsc): ModInverse should be implemented in terms of this function.
	return (&Int{abs: z}).ModInverse(&Int{abs: g}, &Int{abs: n}).abs
}

// Jacobi returns the Jacobi symbol (x/y), either +1, -1, or 0.
// The y argument must be an odd integer.
func Jacobi(x, y *Int) int {
	if len(y.abs) == 0 || y.abs[0]&1 == 0 {
		panic(fmt.Sprintf("big: invalid 2nd argument to Int.Jacobi: need odd integer but got %s", y.String()))
	}

	// We use the formulation described in chapter 2, section 2.4,
	// "The Yacas Book of Algorithms":
	// http://yacas.sourceforge.net/Algo.book.pdf

	var a, b, c Int
	a.Set(x)
	b.Set(y)
	j := 1

	if b.neg {
		if a.neg {
			j = -1
		}
		b.neg = false
	}

	for {
		if b.Cmp(intOne) == 0 {
			return j
		}
		if len(a.abs) == 0 {
			return 0
		}
		a.Mod(&a, &b)
		if len(a.abs) == 0 {
			return 0
		}
		// a > 0

		// handle factors of 2 in 'a'
		s := a.abs.trailingZeroBits()
		if s&1 != 0 {
			bmod8 := b.abs[0] & 7
			if bmod8 == 3 || bmod8 == 5 {
				j = -j
			}
		}
		c.Rsh(&a, s) // a = 2^s*c

		// swap numerator and denominator
		if b.abs[0]&3 == 3 && c.abs[0]&3 == 3 {
			j = -j
		}
		a.Set(&b)
		b.Set(&c)
	}
}

// modSqrt3Mod4 uses the identity
//
//	   (a^((p+1)/4))^2  mod p
//	== u^(p+1)          mod p
//	== u^2              mod p
//
// to calculate the square root of any quadratic residue mod p quickly for 3
// mod 4 primes.
func (z *Int) modSqrt3Mod4Prime(x, p *Int) *Int {
	e := new(Int).Add(p, intOne) // e = p + 1
	e.Rsh(e, 2)                  // e = (p + 1) / 4
	z.Exp(x, e, p)               // z = x^e mod p
	return z
}

// modSqrt5Mod8Prime uses Atkin's observation that 2 is not a square mod p
//
//	alpha ==  (2*a)^((p-5)/8)    mod p
//	beta  ==  2*a*alpha^2        mod p  is a square root of -1
//	b     ==  a*alpha*(beta-1)   mod p  is a square root of a
//
// to calculate the square root of any quadratic residue mod p quickly for 5
// mod 8 primes.
func (z *Int) modSqrt5Mod8Prime(x, p *Int) *Int {
	// p == 5 mod 8 implies p = e*8 + 5
	// e is the quotient and 5 the remainder on division by 8
	e := new(Int).Rsh(p, 3)  // e = (p - 5) / 8
	tx := new(Int).Lsh(x, 1) // tx = 2*x
	alpha := new(Int).Exp(tx, e, p)
	beta := new(Int).Mul(alpha, alpha)
	beta.Mod(beta, p)
	beta.Mul(beta, tx)
	beta.Mod(beta, p)
	beta.Sub(beta, intOne)
	beta.Mul(beta, x)
	beta.Mod(beta, p)
	beta.Mul(beta, alpha)
	z.Mod(beta, p)
	return z
}

// modSqrtTonelliShanks uses the Tonelli-Shanks algorithm to find the square
// root of a quadratic residue modulo any prime.
func (z *Int) modSqrtTonelliShanks(x, p *Int) *Int {
	// Break p-1 into s*2^e such that s is odd.
	var s Int
	s.Sub(p, intOne)
	e := s.abs.trailingZeroBits()
	s.Rsh(&s, e)

	// find some non-square n
	var n Int
	n.SetInt64(2)
	for Jacobi(&n, p) != -1 {
		n.Add(&n, intOne)
	}

	// Core of the Tonelli-Shanks algorithm. Follows the description in
	// section 6 of "Square roots from 1; 24, 51, 10 to Dan Shanks" by Ezra
	// Brown:
	// https://www.maa.org/sites/default/files/pdf/upload_library/22/Polya/07468342.di020786.02p0470a.pdf
	var y, b, g, t Int
	y.Add(&s, intOne)
	y.Rsh(&y, 1)
	y.Exp(x, &y, p)  // y = x^((s+1)/2)
	b.Exp(x, &s, p)  // b = x^s
	g.Exp(&n, &s, p) // g = n^s
	r := e
	for {
		// find the least m such that ord_p(b) = 2^m
		var m uint
		t.Set(&b)
		for t.Cmp(intOne) != 0 {
			t.Mul(&t, &t).Mod(&t, p)
			m++
		}

		if m == 0 {
			return z.Set(&y)
		}

		t.SetInt64(0).SetBit(&t, int(r-m-1), 1).Exp(&g, &t, p)
		// t = g^(2^(r-m-1)) mod p
		g.Mul(&t, &t).Mod(&g, p) // g = g^(2^(r-m)) mod p
		y.Mul(&y, &t).Mod(&y, p)
		b.Mul(&b, &g).Mod(&b, p)
		r = m
	}
}

// ModSqrt sets z to a square root of x mod p if such a square root exists, and
// returns z. The modulus p must be an odd prime. If x is not a square mod p,
// ModSqrt leaves z unchanged and returns nil. This function panics if p is
// not an odd integer, its behavior is undefined if p is odd but not prime.
func (z *Int) ModSqrt(x, p *Int) *Int {
	switch Jacobi(x, p) {
	case -1:
		return nil // x is not a square mod p
	case 0:
		return z.SetInt64(0) // sqrt(0) mod p = 0
	case 1:
		break
	}
	if x.neg || x.Cmp(p) >= 0 { // ensure 0 <= x < p
		x = new(Int).Mod(x, p)
	}

	switch {
	case p.abs[0]%4 == 3:
		// Check whether p is 3 mod 4, and if so, use the faster algorithm.
		return z.modSqrt3Mod4Prime(x, p)
	case p.abs[0]%8 == 5:
		// Check whether p is 5 mod 8, use Atkin's algorithm.
		return z.modSqrt5Mod8Prime(x, p)
	default:
		// Otherwise, use Tonelli-Shanks.
		return z.modSqrtTonelliShanks(x, p)
	}
}

// Lsh sets z = x << n and returns z.
func (z *Int) Lsh(x *Int, n uint) *Int {
	z.abs = z.abs.shl(x.abs, n)
	z.neg = x.neg
	return z
}

// Rsh sets z = x >> n and returns z.
func (z *Int) Rsh(x *Int, n uint) *Int {
	if x.neg {
		// (-x) >> s == ^(x-1) >> s == ^((x-1) >> s) == -(((x-1) >> s) + 1)
		t := z.abs.sub(x.abs, natOne) // no underflow because |x| > 0
		t = t.shr(t, n)
		z.abs = t.add(t, natOne)
		z.neg = true // z cannot be zero if x is negative
		return z
	}

	z.abs = z.abs.shr(x.abs, n)
	z.neg = false
	return z
}

// Bit returns the value of the i'th bit of x. That is, it
// returns (x>>i)&1. The bit index i must be >= 0.
func (x *Int) Bit(i int) uint {
	if i == 0 {
		// optimization for common case: odd/even test of x
		if len(x.abs) > 0 {
			return uint(x.abs[0] & 1) // bit 0 is same for -x
		}
		return 0
	}
	if i < 0 {
		panic("negative bit index")
	}
	if x.neg {
		t := nat(nil).sub(x.abs, natOne)
		return t.bit(uint(i)) ^ 1
	}

	return x.abs.bit(uint(i))
}

// SetBit sets z to x, with x's i'th bit set to b (0 or 1).
// That is,
//   - if b is 1, SetBit sets z = x | (1 << i);
//   - if b is 0, SetBit sets z = x &^ (1 << i);
//   - if b is not 0 or 1, SetBit will panic.
func (z *Int) SetBit(x *Int, i int, b uint) *Int {
	if i < 0 {
		panic("negative bit index")
	}
	if x.neg {
		t := z.abs.sub(x.abs, natOne)
		t = t.setBit(t, uint(i), b^1)
		z.abs = t.add(t, natOne)
		z.neg = len(z.abs) > 0
		return z
	}
	z.abs = z.abs.setBit(x.abs, uint(i), b)
	z.neg = false
	return z
}

// And sets z = x & y and returns z.
func (z *Int) And(x, y *Int) *Int {
	if x.neg == y.neg {
		if x.neg {
			// (-x) & (-y) == ^(x-1) & ^(y-1) == ^((x-1) | (y-1)) == -(((x-1) | (y-1)) + 1)
			x1 := nat(nil).sub(x.abs, natOne)
			y1 := nat(nil).sub(y.abs, natOne)
			z.abs = z.abs.add(z.abs.or(x1, y1), natOne)
			z.neg = true // z cannot be zero if x and y are negative
			return z
		}

		// x & y == x & y
		z.abs = z.abs.and(x.abs, y.abs)
		z.neg = false
		return z
	}

	// x.neg != y.neg
	if x.neg {
		x, y = y, x // & is symmetric
	}

	// x & (-y) == x & ^(y-1) == x &^ (y-1)
	y1 := nat(nil).sub(y.abs, natOne)
	z.abs = z.abs.andNot(x.abs, y1)
	z.neg = false
	return z
}

// AndNot sets z = x &^ y and returns z.
func (z *Int) AndNot(x, y *Int) *Int {
	if x.neg == y.neg {
		if x.neg {
			// (-x) &^ (-y) == ^(x-1) &^ ^(y-1) == ^(x-1) & (y-1) == (y-1) &^ (x-1)
			x1 := nat(nil).sub(x.abs, natOne)
			y1 := nat(nil).sub(y.abs, natOne)
			z.abs = z.abs.andNot(y1, x1)
			z.neg = false
			return z
		}

		// x &^ y == x &^ y
		z.abs = z.abs.andNot(x.abs, y.abs)
		z.neg = false
		return z
	}

	if x.neg {
		// (-x) &^ y == ^(x-1) &^ y == ^(x-1) & ^y == ^((x-1) | y) == -(((x-1) | y) + 1)
		x1 := nat(nil).sub(x.abs, natOne)
		z.abs = z.abs.add(z.abs.or(x1, y.abs), natOne)
		z.neg = true // z cannot be zero if x is negative and y is positive
		return z
	}

	// x &^ (-y) == x &^ ^(y-1) == x & (y-1)
	y1 := nat(nil).sub(y.abs, natOne)
	z.abs = z.abs.and(x.abs, y1)
	z.neg = false
	return z
}

// Or sets z = x | y and returns z.
func (z *Int) Or(x, y *Int) *Int {
	if x.neg == y.neg {
		if x.neg {
			// (-x) | (-y) == ^(x-1) | ^(y-1) == ^((x-1) & (y-1)) == -(((x-1) & (y-1)) + 1)
			x1 := nat(nil).sub(x.abs, natOne)
			y1 := nat(nil).sub(y.abs, natOne)
			z.abs = z.abs.add(z.abs.and(x1, y1), natOne)
			z.neg = true // z cannot be zero if x and y are negative
			return z
		}

		// x | y == x | y
		z.abs = z.abs.or(x.abs, y.abs)
		z.neg = false
		return z
	}

	// x.neg != y.neg
	if x.neg {
		x, y = y, x // | is symmetric
	}

	// x | (-y) == x | ^(y-1) == ^((y-1) &^ x) == -(^((y-1) &^ x) + 1)
	y1 := nat(nil).sub(y.abs, natOne)
	z.abs = z.abs.add(z.abs.andNot(y1, x.abs), natOne)
	z.neg = true // z cannot be zero if one of x or y is negative
	return z
}

// Xor sets z = x ^ y and returns z.
func (z *Int) Xor(x, y *Int) *I
"""




```