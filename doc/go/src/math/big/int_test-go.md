Response:
Thinking Process to Summarize `int_test.go` Part 1:

1. **Goal:** Understand the primary function of this code snippet within the context of Go's `math/big` package.

2. **Initial Scan:** Look for key terms, function names, and data structures. Notice `Test...` functions, `Benchmark...` functions, and data structures like `argZZ`, `sumZZ`, `prodZZ`, `mulRangesZ`, `gcdTests`, etc. The file name `int_test.go` strongly suggests it's for testing the `Int` type.

3. **Identify Core Functionality:** The presence of numerous `Test` functions indicates the primary goal is testing the `Int` type. The specific test function names (`TestSignZ`, `TestSetZ`, `TestAbsZ`, `TestSumZZ`, `TestProdZZ`, `TestMul`, `TestMulRangeZ`, `TestBinomial`, `TestDivisionSigns`, `TestBits`, `TestSetBytes`, `TestBytes`, `TestQuo`, `TestBitLen`, `TestExp`, `TestGcd`) directly correspond to methods or operations on `Int`.

4. **Categorize Tests:** Group the tests by the functionality they are verifying:
    * Basic `Int` operations: `Sign`, `Set`, `Abs`, `Cmp`, `isNormalized`.
    * Arithmetic operations: `Add`, `Sub`, `Mul`, `MulRange`, `Binomial`, `Quo`, `Rem`, `Div`, `Mod`, `Exp`, `GCD`.
    * Bit manipulation: `BitLen`, `SetBits`, `Bits`.
    * Byte conversion: `SetBytes`, `Bytes`.
    * Internal helper functions (like `mulBytes`).

5. **Look for Examples:** The code includes example data (`sumZZ`, `prodZZ`, `mulRangesZ`, `divisionSignsTests`, `gcdTests`, `expTests`). These are crucial for understanding the expected behavior and for providing illustrative examples in the summary.

6. **Identify Benchmarks:** The presence of `Benchmark...` functions indicates performance testing. Note the specific operations being benchmarked (`BenchmarkBinomial`, `BenchmarkQuoRem`, `BenchmarkExp`, `BenchmarkExpMont`, `BenchmarkExp2`).

7. **Infer Go Feature Implementation:** Based on the tested functionalities, infer that this code is testing the implementation of arbitrary-precision integers in Go. The `math/big` package is designed for this purpose.

8. **Synthesize the Summary:** Combine the observations into a concise summary, highlighting the main purpose (testing), the types of operations being tested, and the inclusion of benchmarks. Mention the underlying Go feature (arbitrary-precision integers).

9. **Review and Refine:** Ensure the summary is clear, accurate, and addresses the prompt's requirements. Specifically, check if it identifies the *function* of the code and if it can infer the underlying Go feature being tested.
这是 `go/src/math/big/int_test.go` 文件的一部分，主要功能是**测试 `math/big` 包中 `Int` 类型的各种功能和方法的正确性**。

具体来说，这部分代码涵盖了以下 `Int` 类型的功能测试：

1. **基本属性和操作:**
   - `isNormalized()`: 检查 `Int` 实例是否处于规范化状态（例如，绝对值切片末尾不为 0）。
   - `Sign()`: 获取 `Int` 的符号（-1, 0, 或 1）。
   - `Set()`: 设置 `Int` 的值。
   - `Abs()`: 计算 `Int` 的绝对值。
   - `Cmp()`: 比较两个 `Int` 的大小。

2. **算术运算:**
   - `Add()`: 加法运算。
   - `Sub()`: 减法运算。
   - `Mul()`: 乘法运算。
   - `MulRange()`: 计算一个整数范围的乘积。
   - `Binomial()`: 计算二项式系数。
   - `Quo()` 和 `Rem()`:  T-除法（Truncated division）的商和余数。
   - `Div()` 和 `Mod()`: 欧几里得除法的商和余数。
   - `QuoRem()`: 同时计算 T-除法的商和余数。
   - `DivMod()`: 同时计算欧几里得除法的商和余数。
   - `Exp()`: 指数运算（可以带模）。
   - `GCD()`: 计算最大公约数。

3. **位操作和字节转换:**
   - `Bits()`: 以 `[]Word` (或 `nat`) 的形式返回 `Int` 的绝对值的位表示。
   - `SetBits()`: 从 `[]Word` 设置 `Int` 的绝对值。
   - `Bytes()`: 将 `Int` 转换为大端字节数组。
   - `SetBytes()`: 从大端字节数组设置 `Int` 的值。
   - `BitLen()`: 返回表示 `Int` 所需的最小位数。

4. **内部辅助函数测试:**
   - `mulBytes()`: 一个使用小学乘法算法实现的字节数组乘法函数，用于对比测试 `Int.Mul()` 的正确性。
   - `checkMul()`, `checkSetBytes()`, `checkBytes()`, `checkQuo()`, `checkGcd()`, `checkLehmerGcd()`, `checkLehmerExtGcd()`:  使用 `testing/quick` 包进行属性测试的辅助函数，用于验证某些操作的性质对于随机输入是否成立。

**它可以被推理为 Go 语言 `math/big` 包中 `Int` 类型的实现。**  `math/big` 包提供了用于表示任意大小整数（和有理数、浮点数）的类型。

**Go 代码举例说明 (假设输入与输出):**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	a := big.NewInt(10)
	b := big.NewInt(5)

	// 加法
	sum := new(big.Int).Add(a, b)
	fmt.Println("Sum:", sum) // 输出: Sum: 15

	// 乘法
	product := new(big.Int).Mul(a, b)
	fmt.Println("Product:", product) // 输出: Product: 50

	// 除法 (T-除法)
	quotient := new(big.Int).Quo(a, b)
	remainder := new(big.Int).Rem(a, b)
	fmt.Println("Quotient:", quotient, "Remainder:", remainder) // 输出: Quotient: 2 Remainder: 0

	// 指数运算
	exponent := big.NewInt(3)
	power := new(big.Int).Exp(a, exponent, nil) // nil 表示不进行模运算
	fmt.Println("Power:", power) // 输出: Power: 1000

	// 设置和获取字节
	bytes := a.Bytes()
	fmt.Println("Bytes:", bytes) // 输出: Bytes: [10]
	c := new(big.Int).SetBytes(bytes)
	fmt.Println("SetBytes:", c) // 输出: SetBytes: 10

	// 计算阶乘 (使用 MulRange)
	factorial := new(big.Int).MulRange(1, 5)
	fmt.Println("Factorial:", factorial) // 输出: Factorial: 120
}
```

**代码推理 (带假设的输入与输出):**

例如，`TestSumZZ` 函数测试了 `Add` 和 `Sub` 方法。它定义了一组测试用例 `sumZZ`，每个用例包含期望的结果 `z` 和两个操作数 `x` 和 `y`。

假设 `sumZZ` 中的一个用例是:

```go
{NewInt(1111111110), NewInt(123456789), NewInt(987654321)}
```

`TestSumZZ` 会执行以下操作:

1. **加法测试:**
   - `z.Add(x, y)`，其中 `x` 是 `NewInt(123456789)`，`y` 是 `NewInt(987654321)`。
   - 期望结果 `z` 是 `NewInt(1111111110)`。
   - 测试会比较计算结果和期望结果是否一致。

2. **减法测试 (及其对称性):**
   - `z.Sub(x, y)`，其中 `x` 是 `NewInt(1111111110)`，`y` 是 `NewInt(987654321)`。 期望结果是 `NewInt(123456789)`。
   - `z.Sub(x, y)`，其中 `x` 是 `NewInt(1111111110)`，`y` 是 `NewInt(123456789)`。 期望结果是 `NewInt(987654321)`。

**命令行参数的具体处理:**

这段代码本身是测试代码，通常通过 `go test` 命令执行。它不直接处理用户提供的命令行参数。  `go test` 命令有一些标准的参数，例如 `-v` (显示详细输出), `-run` (指定要运行的测试函数) 等，但这些是由 `go test` 工具处理的，而不是这段代码。

**使用者易犯错的点:**

这段代码主要是测试，所以使用者直接与之交互较少。 但在 *使用* `math/big` 包时，容易犯以下错误（虽然这段测试代码没有直接体现，但与之相关）：

1. **未初始化 `big.Int` 指针:**  `big.Int` 是指针类型，需要使用 `NewInt()` 或者 `new(big.Int)` 进行初始化，否则会发生空指针引用。

   ```go
   var n *big.Int // 未初始化
   // n.Add(...) // 会导致 panic
   n = new(big.Int) // 正确初始化
   n.SetInt64(10)
   ```

2. **假设 `big.Int` 是值类型:** 赋值 `big.Int` 变量时，实际上是复制了指针，而不是底层的数据。 如果需要复制 `big.Int` 的值，应该使用 `Set()` 方法。

   ```go
   a := big.NewInt(10)
   b := a // b 指向与 a 相同的底层数据
   b.SetInt64(20)
   fmt.Println(a) // 输出: 20 (a 的值也被修改了)

   c := big.NewInt(10)
   d := new(big.Int).Set(c) // 正确复制值
   d.SetInt64(30)
   fmt.Println(c) // 输出: 10 (c 的值没有被修改)
   ```

3. **性能问题:**  `big.Int` 的运算比内置的整数类型慢，不应该在性能敏感的场合过度使用，或者在不需要大数运算时使用。

**归纳一下它的功能（第1部分）:**

这部分 `int_test.go` 代码的主要功能是 **对 `math/big` 包中的 `Int` 类型进行全面的单元测试，验证其基本属性、各种算术运算、位操作、字节转换等功能的正确性**。它通过定义一系列测试函数和测试用例，确保 `Int` 类型的实现符合预期。 同时，它也包含了一些用于性能基准测试的函数。

Prompt: 
```
这是路径为go/src/math/big/int_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package big

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"internal/testenv"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
)

func isNormalized(x *Int) bool {
	if len(x.abs) == 0 {
		return !x.neg
	}
	// len(x.abs) > 0
	return x.abs[len(x.abs)-1] != 0
}

type funZZ func(z, x, y *Int) *Int
type argZZ struct {
	z, x, y *Int
}

var sumZZ = []argZZ{
	{NewInt(0), NewInt(0), NewInt(0)},
	{NewInt(1), NewInt(1), NewInt(0)},
	{NewInt(1111111110), NewInt(123456789), NewInt(987654321)},
	{NewInt(-1), NewInt(-1), NewInt(0)},
	{NewInt(864197532), NewInt(-123456789), NewInt(987654321)},
	{NewInt(-1111111110), NewInt(-123456789), NewInt(-987654321)},
}

var prodZZ = []argZZ{
	{NewInt(0), NewInt(0), NewInt(0)},
	{NewInt(0), NewInt(1), NewInt(0)},
	{NewInt(1), NewInt(1), NewInt(1)},
	{NewInt(-991 * 991), NewInt(991), NewInt(-991)},
	// TODO(gri) add larger products
}

func TestSignZ(t *testing.T) {
	var zero Int
	for _, a := range sumZZ {
		s := a.z.Sign()
		e := a.z.Cmp(&zero)
		if s != e {
			t.Errorf("got %d; want %d for z = %v", s, e, a.z)
		}
	}
}

func TestSetZ(t *testing.T) {
	for _, a := range sumZZ {
		var z Int
		z.Set(a.z)
		if !isNormalized(&z) {
			t.Errorf("%v is not normalized", z)
		}
		if (&z).Cmp(a.z) != 0 {
			t.Errorf("got z = %v; want %v", z, a.z)
		}
	}
}

func TestAbsZ(t *testing.T) {
	var zero Int
	for _, a := range sumZZ {
		var z Int
		z.Abs(a.z)
		var e Int
		e.Set(a.z)
		if e.Cmp(&zero) < 0 {
			e.Sub(&zero, &e)
		}
		if z.Cmp(&e) != 0 {
			t.Errorf("got z = %v; want %v", z, e)
		}
	}
}

func testFunZZ(t *testing.T, msg string, f funZZ, a argZZ) {
	var z Int
	f(&z, a.x, a.y)
	if !isNormalized(&z) {
		t.Errorf("%s%v is not normalized", msg, z)
	}
	if (&z).Cmp(a.z) != 0 {
		t.Errorf("%v %s %v\n\tgot z = %v; want %v", a.x, msg, a.y, &z, a.z)
	}
}

func TestSumZZ(t *testing.T) {
	AddZZ := func(z, x, y *Int) *Int { return z.Add(x, y) }
	SubZZ := func(z, x, y *Int) *Int { return z.Sub(x, y) }
	for _, a := range sumZZ {
		arg := a
		testFunZZ(t, "AddZZ", AddZZ, arg)

		arg = argZZ{a.z, a.y, a.x}
		testFunZZ(t, "AddZZ symmetric", AddZZ, arg)

		arg = argZZ{a.x, a.z, a.y}
		testFunZZ(t, "SubZZ", SubZZ, arg)

		arg = argZZ{a.y, a.z, a.x}
		testFunZZ(t, "SubZZ symmetric", SubZZ, arg)
	}
}

func TestProdZZ(t *testing.T) {
	MulZZ := func(z, x, y *Int) *Int { return z.Mul(x, y) }
	for _, a := range prodZZ {
		arg := a
		testFunZZ(t, "MulZZ", MulZZ, arg)

		arg = argZZ{a.z, a.y, a.x}
		testFunZZ(t, "MulZZ symmetric", MulZZ, arg)
	}
}

// mulBytes returns x*y via grade school multiplication. Both inputs
// and the result are assumed to be in big-endian representation (to
// match the semantics of Int.Bytes and Int.SetBytes).
func mulBytes(x, y []byte) []byte {
	z := make([]byte, len(x)+len(y))

	// multiply
	k0 := len(z) - 1
	for j := len(y) - 1; j >= 0; j-- {
		d := int(y[j])
		if d != 0 {
			k := k0
			carry := 0
			for i := len(x) - 1; i >= 0; i-- {
				t := int(z[k]) + int(x[i])*d + carry
				z[k], carry = byte(t), t>>8
				k--
			}
			z[k] = byte(carry)
		}
		k0--
	}

	// normalize (remove leading 0's)
	i := 0
	for i < len(z) && z[i] == 0 {
		i++
	}

	return z[i:]
}

func checkMul(a, b []byte) bool {
	var x, y, z1 Int
	x.SetBytes(a)
	y.SetBytes(b)
	z1.Mul(&x, &y)

	var z2 Int
	z2.SetBytes(mulBytes(a, b))

	return z1.Cmp(&z2) == 0
}

func TestMul(t *testing.T) {
	if err := quick.Check(checkMul, nil); err != nil {
		t.Error(err)
	}
}

var mulRangesZ = []struct {
	a, b int64
	prod string
}{
	// entirely positive ranges are covered by mulRangesN
	{-1, 1, "0"},
	{-2, -1, "2"},
	{-3, -2, "6"},
	{-3, -1, "-6"},
	{1, 3, "6"},
	{-10, -10, "-10"},
	{0, -1, "1"},                      // empty range
	{-1, -100, "1"},                   // empty range
	{-1, 1, "0"},                      // range includes 0
	{-1e9, 0, "0"},                    // range includes 0
	{-1e9, 1e9, "0"},                  // range includes 0
	{-10, -1, "3628800"},              // 10!
	{-20, -2, "-2432902008176640000"}, // -20!
	{-99, -1,
		"-933262154439441526816992388562667004907159682643816214685929" +
			"638952175999932299156089414639761565182862536979208272237582" +
			"511852109168640000000000000000000000", // -99!
	},

	// overflow situations
	{math.MaxInt64 - 0, math.MaxInt64, "9223372036854775807"},
	{math.MaxInt64 - 1, math.MaxInt64, "85070591730234615838173535747377725442"},
	{math.MaxInt64 - 2, math.MaxInt64, "784637716923335094969050127519550606919189611815754530810"},
	{math.MaxInt64 - 3, math.MaxInt64, "7237005577332262206126809393809643289012107973151163787181513908099760521240"},
}

func TestMulRangeZ(t *testing.T) {
	var tmp Int
	// test entirely positive ranges
	for i, r := range mulRangesN {
		// skip mulRangesN entries that overflow int64
		if int64(r.a) < 0 || int64(r.b) < 0 {
			continue
		}
		prod := tmp.MulRange(int64(r.a), int64(r.b)).String()
		if prod != r.prod {
			t.Errorf("#%da: got %s; want %s", i, prod, r.prod)
		}
	}
	// test other ranges
	for i, r := range mulRangesZ {
		prod := tmp.MulRange(r.a, r.b).String()
		if prod != r.prod {
			t.Errorf("#%db: got %s; want %s", i, prod, r.prod)
		}
	}
}

func TestBinomial(t *testing.T) {
	var z Int
	for _, test := range []struct {
		n, k int64
		want string
	}{
		{0, 0, "1"},
		{0, 1, "0"},
		{1, 0, "1"},
		{1, 1, "1"},
		{1, 10, "0"},
		{4, 0, "1"},
		{4, 1, "4"},
		{4, 2, "6"},
		{4, 3, "4"},
		{4, 4, "1"},
		{10, 1, "10"},
		{10, 9, "10"},
		{10, 5, "252"},
		{11, 5, "462"},
		{11, 6, "462"},
		{100, 10, "17310309456440"},
		{100, 90, "17310309456440"},
		{1000, 10, "263409560461970212832400"},
		{1000, 990, "263409560461970212832400"},
	} {
		if got := z.Binomial(test.n, test.k).String(); got != test.want {
			t.Errorf("Binomial(%d, %d) = %s; want %s", test.n, test.k, got, test.want)
		}
	}
}

func BenchmarkBinomial(b *testing.B) {
	var z Int
	for i := 0; i < b.N; i++ {
		z.Binomial(1000, 990)
	}
}

// Examples from the Go Language Spec, section "Arithmetic operators"
var divisionSignsTests = []struct {
	x, y int64
	q, r int64 // T-division
	d, m int64 // Euclidean division
}{
	{5, 3, 1, 2, 1, 2},
	{-5, 3, -1, -2, -2, 1},
	{5, -3, -1, 2, -1, 2},
	{-5, -3, 1, -2, 2, 1},
	{1, 2, 0, 1, 0, 1},
	{8, 4, 2, 0, 2, 0},
}

func TestDivisionSigns(t *testing.T) {
	for i, test := range divisionSignsTests {
		x := NewInt(test.x)
		y := NewInt(test.y)
		q := NewInt(test.q)
		r := NewInt(test.r)
		d := NewInt(test.d)
		m := NewInt(test.m)

		q1 := new(Int).Quo(x, y)
		r1 := new(Int).Rem(x, y)
		if !isNormalized(q1) {
			t.Errorf("#%d Quo: %v is not normalized", i, *q1)
		}
		if !isNormalized(r1) {
			t.Errorf("#%d Rem: %v is not normalized", i, *r1)
		}
		if q1.Cmp(q) != 0 || r1.Cmp(r) != 0 {
			t.Errorf("#%d QuoRem: got (%s, %s), want (%s, %s)", i, q1, r1, q, r)
		}

		q2, r2 := new(Int).QuoRem(x, y, new(Int))
		if !isNormalized(q2) {
			t.Errorf("#%d Quo: %v is not normalized", i, *q2)
		}
		if !isNormalized(r2) {
			t.Errorf("#%d Rem: %v is not normalized", i, *r2)
		}
		if q2.Cmp(q) != 0 || r2.Cmp(r) != 0 {
			t.Errorf("#%d QuoRem: got (%s, %s), want (%s, %s)", i, q2, r2, q, r)
		}

		d1 := new(Int).Div(x, y)
		m1 := new(Int).Mod(x, y)
		if !isNormalized(d1) {
			t.Errorf("#%d Div: %v is not normalized", i, *d1)
		}
		if !isNormalized(m1) {
			t.Errorf("#%d Mod: %v is not normalized", i, *m1)
		}
		if d1.Cmp(d) != 0 || m1.Cmp(m) != 0 {
			t.Errorf("#%d DivMod: got (%s, %s), want (%s, %s)", i, d1, m1, d, m)
		}

		d2, m2 := new(Int).DivMod(x, y, new(Int))
		if !isNormalized(d2) {
			t.Errorf("#%d Div: %v is not normalized", i, *d2)
		}
		if !isNormalized(m2) {
			t.Errorf("#%d Mod: %v is not normalized", i, *m2)
		}
		if d2.Cmp(d) != 0 || m2.Cmp(m) != 0 {
			t.Errorf("#%d DivMod: got (%s, %s), want (%s, %s)", i, d2, m2, d, m)
		}
	}
}

func norm(x nat) nat {
	i := len(x)
	for i > 0 && x[i-1] == 0 {
		i--
	}
	return x[:i]
}

func TestBits(t *testing.T) {
	for _, test := range []nat{
		nil,
		{0},
		{1},
		{0, 1, 2, 3, 4},
		{4, 3, 2, 1, 0},
		{4, 3, 2, 1, 0, 0, 0, 0},
	} {
		var z Int
		z.neg = true
		got := z.SetBits(test)
		want := norm(test)
		if got.abs.cmp(want) != 0 {
			t.Errorf("SetBits(%v) = %v; want %v", test, got.abs, want)
		}

		if got.neg {
			t.Errorf("SetBits(%v): got negative result", test)
		}

		bits := nat(z.Bits())
		if bits.cmp(want) != 0 {
			t.Errorf("%v.Bits() = %v; want %v", z.abs, bits, want)
		}
	}
}

func checkSetBytes(b []byte) bool {
	hex1 := hex.EncodeToString(new(Int).SetBytes(b).Bytes())
	hex2 := hex.EncodeToString(b)

	for len(hex1) < len(hex2) {
		hex1 = "0" + hex1
	}

	for len(hex1) > len(hex2) {
		hex2 = "0" + hex2
	}

	return hex1 == hex2
}

func TestSetBytes(t *testing.T) {
	if err := quick.Check(checkSetBytes, nil); err != nil {
		t.Error(err)
	}
}

func checkBytes(b []byte) bool {
	// trim leading zero bytes since Bytes() won't return them
	// (was issue 12231)
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	b2 := new(Int).SetBytes(b).Bytes()
	return bytes.Equal(b, b2)
}

func TestBytes(t *testing.T) {
	if err := quick.Check(checkBytes, nil); err != nil {
		t.Error(err)
	}
}

func checkQuo(x, y []byte) bool {
	u := new(Int).SetBytes(x)
	v := new(Int).SetBytes(y)

	if len(v.abs) == 0 {
		return true
	}

	r := new(Int)
	q, r := new(Int).QuoRem(u, v, r)

	if r.Cmp(v) >= 0 {
		return false
	}

	uprime := new(Int).Set(q)
	uprime.Mul(uprime, v)
	uprime.Add(uprime, r)

	return uprime.Cmp(u) == 0
}

var quoTests = []struct {
	x, y string
	q, r string
}{
	{
		"476217953993950760840509444250624797097991362735329973741718102894495832294430498335824897858659711275234906400899559094370964723884706254265559534144986498357",
		"9353930466774385905609975137998169297361893554149986716853295022578535724979483772383667534691121982974895531435241089241440253066816724367338287092081996",
		"50911",
		"1",
	},
	{
		"11510768301994997771168",
		"1328165573307167369775",
		"8",
		"885443715537658812968",
	},
}

func TestQuo(t *testing.T) {
	if err := quick.Check(checkQuo, nil); err != nil {
		t.Error(err)
	}

	for i, test := range quoTests {
		x, _ := new(Int).SetString(test.x, 10)
		y, _ := new(Int).SetString(test.y, 10)
		expectedQ, _ := new(Int).SetString(test.q, 10)
		expectedR, _ := new(Int).SetString(test.r, 10)

		r := new(Int)
		q, r := new(Int).QuoRem(x, y, r)

		if q.Cmp(expectedQ) != 0 || r.Cmp(expectedR) != 0 {
			t.Errorf("#%d got (%s, %s) want (%s, %s)", i, q, r, expectedQ, expectedR)
		}
	}
}

func TestQuoStepD6(t *testing.T) {
	// See Knuth, Volume 2, section 4.3.1, exercise 21. This code exercises
	// a code path which only triggers 1 in 10^{-19} cases.

	u := &Int{false, nat{0, 0, 1 + 1<<(_W-1), _M ^ (1 << (_W - 1))}}
	v := &Int{false, nat{5, 2 + 1<<(_W-1), 1 << (_W - 1)}}

	r := new(Int)
	q, r := new(Int).QuoRem(u, v, r)
	const expectedQ64 = "18446744073709551613"
	const expectedR64 = "3138550867693340382088035895064302439801311770021610913807"
	const expectedQ32 = "4294967293"
	const expectedR32 = "39614081266355540837921718287"
	if q.String() != expectedQ64 && q.String() != expectedQ32 ||
		r.String() != expectedR64 && r.String() != expectedR32 {
		t.Errorf("got (%s, %s) want (%s, %s) or (%s, %s)", q, r, expectedQ64, expectedR64, expectedQ32, expectedR32)
	}
}

func BenchmarkQuoRem(b *testing.B) {
	x, _ := new(Int).SetString("153980389784927331788354528594524332344709972855165340650588877572729725338415474372475094155672066328274535240275856844648695200875763869073572078279316458648124537905600131008790701752441155668003033945258023841165089852359980273279085783159654751552359397986180318708491098942831252291841441726305535546071", 0)
	y, _ := new(Int).SetString("7746362281539803897849273317883545285945243323447099728551653406505888775727297253384154743724750941556720663282745352402758568446486952008757638690735720782793164586481245379056001310087907017524411556680030339452580238411650898523599802732790857831596547515523593979861803187084910989428312522918414417263055355460715745539358014631136245887418412633787074173796862711588221766398229333338511838891484974940633857861775630560092874987828057333663969469797013996401149696897591265769095952887917296740109742927689053276850469671231961384715398038978492733178835452859452433234470997285516534065058887757272972533841547437247509415567206632827453524027585684464869520087576386907357207827931645864812453790560013100879070175244115566800303394525802384116508985235998027327908578315965475155235939798618031870849109894283125229184144172630553554607112725169432413343763989564437170644270643461665184965150423819594083121075825", 0)
	q := new(Int)
	r := new(Int)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.QuoRem(y, x, r)
	}
}

var bitLenTests = []struct {
	in  string
	out int
}{
	{"-1", 1},
	{"0", 0},
	{"1", 1},
	{"2", 2},
	{"4", 3},
	{"0xabc", 12},
	{"0x8000", 16},
	{"0x80000000", 32},
	{"0x800000000000", 48},
	{"0x8000000000000000", 64},
	{"0x80000000000000000000", 80},
	{"-0x4000000000000000000000", 87},
}

func TestBitLen(t *testing.T) {
	for i, test := range bitLenTests {
		x, ok := new(Int).SetString(test.in, 0)
		if !ok {
			t.Errorf("#%d test input invalid: %s", i, test.in)
			continue
		}

		if n := x.BitLen(); n != test.out {
			t.Errorf("#%d got %d want %d", i, n, test.out)
		}
	}
}

var expTests = []struct {
	x, y, m string
	out     string
}{
	// y <= 0
	{"0", "0", "", "1"},
	{"1", "0", "", "1"},
	{"-10", "0", "", "1"},
	{"1234", "-1", "", "1"},
	{"1234", "-1", "0", "1"},
	{"17", "-100", "1234", "865"},
	{"2", "-100", "1234", ""},

	// m == 1
	{"0", "0", "1", "0"},
	{"1", "0", "1", "0"},
	{"-10", "0", "1", "0"},
	{"1234", "-1", "1", "0"},

	// misc
	{"5", "1", "3", "2"},
	{"5", "-7", "", "1"},
	{"-5", "-7", "", "1"},
	{"5", "0", "", "1"},
	{"-5", "0", "", "1"},
	{"5", "1", "", "5"},
	{"-5", "1", "", "-5"},
	{"-5", "1", "7", "2"},
	{"-2", "3", "2", "0"},
	{"5", "2", "", "25"},
	{"1", "65537", "2", "1"},
	{"0x8000000000000000", "2", "", "0x40000000000000000000000000000000"},
	{"0x8000000000000000", "2", "6719", "4944"},
	{"0x8000000000000000", "3", "6719", "5447"},
	{"0x8000000000000000", "1000", "6719", "1603"},
	{"0x8000000000000000", "1000000", "6719", "3199"},
	{"0x8000000000000000", "-1000000", "6719", "3663"}, // 3663 = ModInverse(3199, 6719) Issue #25865

	{"0xffffffffffffffffffffffffffffffff", "0x12345678123456781234567812345678123456789", "0x01112222333344445555666677778889", "0x36168FA1DB3AAE6C8CE647E137F97A"},

	{
		"2938462938472983472983659726349017249287491026512746239764525612965293865296239471239874193284792387498274256129746192347",
		"298472983472983471903246121093472394872319615612417471234712061",
		"29834729834729834729347290846729561262544958723956495615629569234729836259263598127342374289365912465901365498236492183464",
		"23537740700184054162508175125554701713153216681790245129157191391322321508055833908509185839069455749219131480588829346291",
	},
	// test case for issue 8822
	{
		"11001289118363089646017359372117963499250546375269047542777928006103246876688756735760905680604646624353196869572752623285140408755420374049317646428185270079555372763503115646054602867593662923894140940837479507194934267532831694565516466765025434902348314525627418515646588160955862839022051353653052947073136084780742729727874803457643848197499548297570026926927502505634297079527299004267769780768565695459945235586892627059178884998772989397505061206395455591503771677500931269477503508150175717121828518985901959919560700853226255420793148986854391552859459511723547532575574664944815966793196961286234040892865",
		"0xB08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
		"0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
		"21484252197776302499639938883777710321993113097987201050501182909581359357618579566746556372589385361683610524730509041328855066514963385522570894839035884713051640171474186548713546686476761306436434146475140156284389181808675016576845833340494848283681088886584219750554408060556769486628029028720727393293111678826356480455433909233520504112074401376133077150471237549474149190242010469539006449596611576612573955754349042329130631128234637924786466585703488460540228477440853493392086251021228087076124706778899179648655221663765993962724699135217212118535057766739392069738618682722216712319320435674779146070442",
	},
	{
		"-0x1BCE04427D8032319A89E5C4136456671AC620883F2C4139E57F91307C485AD2D6204F4F87A58262652DB5DBBAC72B0613E51B835E7153BEC6068F5C8D696B74DBD18FEC316AEF73985CF0475663208EB46B4F17DD9DA55367B03323E5491A70997B90C059FB34809E6EE55BCFBD5F2F52233BFE62E6AA9E4E26A1D4C2439883D14F2633D55D8AA66A1ACD5595E778AC3A280517F1157989E70C1A437B849F1877B779CC3CDDEDE2DAA6594A6C66D181A00A5F777EE60596D8773998F6E988DEAE4CCA60E4DDCF9590543C89F74F603259FCAD71660D30294FBBE6490300F78A9D63FA660DC9417B8B9DDA28BEB3977B621B988E23D4D954F322C3540541BC649ABD504C50FADFD9F0987D58A2BF689313A285E773FF02899A6EF887D1D4A0D2",
		"0xB08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
		"0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
		"21484252197776302499639938883777710321993113097987201050501182909581359357618579566746556372589385361683610524730509041328855066514963385522570894839035884713051640171474186548713546686476761306436434146475140156284389181808675016576845833340494848283681088886584219750554408060556769486628029028720727393293111678826356480455433909233520504112074401376133077150471237549474149190242010469539006449596611576612573955754349042329130631128234637924786466585703488460540228477440853493392086251021228087076124706778899179648655221663765993962724699135217212118535057766739392069738618682722216712319320435674779146070442",
	},

	// test cases for issue 13907
	{"0xffffffff00000001", "0xffffffff00000001", "0xffffffff00000001", "0"},
	{"0xffffffffffffffff00000001", "0xffffffffffffffff00000001", "0xffffffffffffffff00000001", "0"},
	{"0xffffffffffffffffffffffff00000001", "0xffffffffffffffffffffffff00000001", "0xffffffffffffffffffffffff00000001", "0"},
	{"0xffffffffffffffffffffffffffffffff00000001", "0xffffffffffffffffffffffffffffffff00000001", "0xffffffffffffffffffffffffffffffff00000001", "0"},

	{
		"2",
		"0xB08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
		"0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", // odd
		"0x6AADD3E3E424D5B713FCAA8D8945B1E055166132038C57BBD2D51C833F0C5EA2007A2324CE514F8E8C2F008A2F36F44005A4039CB55830986F734C93DAF0EB4BAB54A6A8C7081864F44346E9BC6F0A3EB9F2C0146A00C6A05187D0C101E1F2D038CDB70CB5E9E05A2D188AB6CBB46286624D4415E7D4DBFAD3BCC6009D915C406EED38F468B940F41E6BEDC0430DD78E6F19A7DA3A27498A4181E24D738B0072D8F6ADB8C9809A5B033A09785814FD9919F6EF9F83EEA519BEC593855C4C10CBEEC582D4AE0792158823B0275E6AEC35242740468FAF3D5C60FD1E376362B6322F78B7ED0CA1C5BBCD2B49734A56C0967A1D01A100932C837B91D592CE08ABFF",
	},
	{
		"2",
		"0xB08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
		"0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF72", // even
		"0x7858794B5897C29F4ED0B40913416AB6C48588484E6A45F2ED3E26C941D878E923575AAC434EE2750E6439A6976F9BB4D64CEDB2A53CE8D04DD48CADCDF8E46F22747C6B81C6CEA86C0D873FBF7CEF262BAAC43A522BD7F32F3CDAC52B9337C77B3DCFB3DB3EDD80476331E82F4B1DF8EFDC1220C92656DFC9197BDC1877804E28D928A2A284B8DED506CBA304435C9D0133C246C98A7D890D1DE60CBC53A024361DA83A9B8775019083D22AC6820ED7C3C68F8E801DD4EC779EE0A05C6EB682EF9840D285B838369BA7E148FA27691D524FAEAF7C6ECE2A4B99A294B9F2C241857B5B90CC8BFFCFCF18DFA7D676131D5CD3855A5A3E8EBFA0CDFADB4D198B4A",
	},
}

func TestExp(t *testing.T) {
	for i, test := range expTests {
		x, ok1 := new(Int).SetString(test.x, 0)
		y, ok2 := new(Int).SetString(test.y, 0)

		var ok3, ok4 bool
		var out, m *Int

		if len(test.out) == 0 {
			out, ok3 = nil, true
		} else {
			out, ok3 = new(Int).SetString(test.out, 0)
		}

		if len(test.m) == 0 {
			m, ok4 = nil, true
		} else {
			m, ok4 = new(Int).SetString(test.m, 0)
		}

		if !ok1 || !ok2 || !ok3 || !ok4 {
			t.Errorf("#%d: error in input", i)
			continue
		}

		z1 := new(Int).Exp(x, y, m)
		if z1 != nil && !isNormalized(z1) {
			t.Errorf("#%d: %v is not normalized", i, *z1)
		}
		if !(z1 == nil && out == nil || z1.Cmp(out) == 0) {
			t.Errorf("#%d: got %x want %x", i, z1, out)
		}

		if m == nil {
			// The result should be the same as for m == 0;
			// specifically, there should be no div-zero panic.
			m = &Int{abs: nat{}} // m != nil && len(m.abs) == 0
			z2 := new(Int).Exp(x, y, m)
			if z2.Cmp(z1) != 0 {
				t.Errorf("#%d: got %x want %x", i, z2, z1)
			}
		}
	}
}

func BenchmarkExp(b *testing.B) {
	x, _ := new(Int).SetString("11001289118363089646017359372117963499250546375269047542777928006103246876688756735760905680604646624353196869572752623285140408755420374049317646428185270079555372763503115646054602867593662923894140940837479507194934267532831694565516466765025434902348314525627418515646588160955862839022051353653052947073136084780742729727874803457643848197499548297570026926927502505634297079527299004267769780768565695459945235586892627059178884998772989397505061206395455591503771677500931269477503508150175717121828518985901959919560700853226255420793148986854391552859459511723547532575574664944815966793196961286234040892865", 0)
	y, _ := new(Int).SetString("0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF72", 0)
	n, _ := new(Int).SetString("0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 0)
	out := new(Int)
	for i := 0; i < b.N; i++ {
		out.Exp(x, y, n)
	}
}

func BenchmarkExpMont(b *testing.B) {
	x, _ := new(Int).SetString("297778224889315382157302278696111964193", 0)
	y, _ := new(Int).SetString("2548977943381019743024248146923164919440527843026415174732254534318292492375775985739511369575861449426580651447974311336267954477239437734832604782764979371984246675241012538135715981292390886872929238062252506842498360562303324154310849745753254532852868768268023732398278338025070694508489163836616810661033068070127919590264734220833816416141878688318329193389865030063416339367925710474801991305827284114894677717927892032165200876093838921477120036402410731159852999623461591709308405270748511350289172153076023215", 0)
	var mods = []struct {
		name string
		val  string
	}{
		{"Odd", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF"},
		{"Even1", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FE"},
		{"Even2", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FC"},
		{"Even3", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281F8"},
		{"Even4", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281F0"},
		{"Even8", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B21828100"},
		{"Even32", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B00000000"},
		{"Even64", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF82828282828200FF0000000000000000"},
		{"Even96", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF82828283000000000000000000000000"},
		{"Even128", "0x82828282828200FFFF28FF2B218281FF82828282828200FFFF28FF2B218281FF00000000000000000000000000000000"},
		{"Even255", "0x82828282828200FFFF28FF2B218281FF8000000000000000000000000000000000000000000000000000000000000000"},
		{"SmallEven1", "0x7E"},
		{"SmallEven2", "0x7C"},
		{"SmallEven3", "0x78"},
		{"SmallEven4", "0x70"},
	}
	for _, mod := range mods {
		n, _ := new(Int).SetString(mod.val, 0)
		out := new(Int)
		b.Run(mod.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				out.Exp(x, y, n)
			}
		})
	}
}

func BenchmarkExp2(b *testing.B) {
	x, _ := new(Int).SetString("2", 0)
	y, _ := new(Int).SetString("0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF72", 0)
	n, _ := new(Int).SetString("0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 0)
	out := new(Int)
	for i := 0; i < b.N; i++ {
		out.Exp(x, y, n)
	}
}

func checkGcd(aBytes, bBytes []byte) bool {
	x := new(Int)
	y := new(Int)
	a := new(Int).SetBytes(aBytes)
	b := new(Int).SetBytes(bBytes)

	d := new(Int).GCD(x, y, a, b)
	x.Mul(x, a)
	y.Mul(y, b)
	x.Add(x, y)

	return x.Cmp(d) == 0
}

// euclidExtGCD is a reference implementation of Euclid's
// extended GCD algorithm for testing against optimized algorithms.
// Requirements: a, b > 0
func euclidExtGCD(a, b *Int) (g, x, y *Int) {
	A := new(Int).Set(a)
	B := new(Int).Set(b)

	// A = Ua*a + Va*b
	// B = Ub*a + Vb*b
	Ua := new(Int).SetInt64(1)
	Va := new(Int)

	Ub := new(Int)
	Vb := new(Int).SetInt64(1)

	q := new(Int)
	temp := new(Int)

	r := new(Int)
	for len(B.abs) > 0 {
		q, r = q.QuoRem(A, B, r)

		A, B, r = B, r, A

		// Ua, Ub = Ub, Ua-q*Ub
		temp.Set(Ub)
		Ub.Mul(Ub, q)
		Ub.Sub(Ua, Ub)
		Ua.Set(temp)

		// Va, Vb = Vb, Va-q*Vb
		temp.Set(Vb)
		Vb.Mul(Vb, q)
		Vb.Sub(Va, Vb)
		Va.Set(temp)
	}
	return A, Ua, Va
}

func checkLehmerGcd(aBytes, bBytes []byte) bool {
	a := new(Int).SetBytes(aBytes)
	b := new(Int).SetBytes(bBytes)

	if a.Sign() <= 0 || b.Sign() <= 0 {
		return true // can only test positive arguments
	}

	d := new(Int).lehmerGCD(nil, nil, a, b)
	d0, _, _ := euclidExtGCD(a, b)

	return d.Cmp(d0) == 0
}

func checkLehmerExtGcd(aBytes, bBytes []byte) bool {
	a := new(Int).SetBytes(aBytes)
	b := new(Int).SetBytes(bBytes)
	x := new(Int)
	y := new(Int)

	if a.Sign() <= 0 || b.Sign() <= 0 {
		return true // can only test positive arguments
	}

	d := new(Int).lehmerGCD(x, y, a, b)
	d0, x0, y0 := euclidExtGCD(a, b)

	return d.Cmp(d0) == 0 && x.Cmp(x0) == 0 && y.Cmp(y0) == 0
}

var gcdTests = []struct {
	d, x, y, a, b string
}{
	// a <= 0 || b <= 0
	{"0", "0", "0", "0", "0"},
	{"7", "0", "1", "0", "7"},
	{"7", "0", "-1", "0", "-7"},
	{"11", "1", "0", "11", "0"},
	{"7", "-1", "-2", "-77", "35"},
	{"935", "-3", "8", "64515", "24310"},
	{"935", "-3", "-8", "64515", "-24310"},
	{"935", "3", "-8", "-64515", "-24310"},

	{"1", "-9", "47", "120", "23"},
	{"7", "1", "-2", "77", "35"},
	{"935", "-3", "8", "64515", "24310"},
	{"935000000000000000", "-3", "8", "64515000000000000000", "24310000000000000000"},
	{"1", "-221", "22059940471369027483332068679400581064239780177629666810348940098015901108344", "98920366548084643601728869055592650835572950932266967461790948584315647051443", "991"},
}

func testGcd(t *testing.T, d, x, y, a, b *Int) {
	var X *Int
	if x != nil {
		X = new(Int)
	}
	var Y *Int
	if y != nil {
		Y = new(Int)
	}

	D := new(Int).GCD(X, Y, a, b)
	if D.Cmp(d) != 0 {
		t.Errorf("GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, D, d)
	}
	if x != nil && X.Cmp(x) != 0 {
		t.Errorf("GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, X, x)
	}
	if y != nil && Y.Cmp(y) != 0 {
		t.Errorf("GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, Y, y)
	}

	// check results in presence of aliasing (issue #11284)
	a2 := new(Int).Set(a)
	b2 := new(Int).Set(b)
	a2.GCD(X, Y, a2, b2) // result is same as 1st argument
	if a2.Cmp(d) != 0 {
		t.Errorf("aliased z = a GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, a2, d)
	}
	if x != nil && X.Cmp(x) != 0 {
		t.Errorf("aliased z = a GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, X, x)
	}
	if y != nil && Y.Cmp(y) != 0 {
		t.Errorf("aliased z = a GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, Y, y)
	}

	a2 = new(Int).Set(a)
	b2 = new(Int).Set(b)
	b2.GCD(X, Y, a2, b2) // result is same as 2nd argument
	if b2.Cmp(d) != 0 {
		t.Errorf("aliased z = b GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, b2, d)
	}
	if x != nil && X.Cmp(x) != 0 {
		t.Errorf("aliased z = b GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, X, x)
	}
	if y != nil && Y.Cmp(y) != 0 {
		t.Errorf("aliased z = b GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, Y, y)
	}

	a2 = new(Int).Set(a)
	b2 = new(Int).Set(b)
	D = new(Int).GCD(a2, b2, a2, b2) // x = a, y = b
	if D.Cmp(d) != 0 {
		t.Errorf("aliased x = a, y = b GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, D, d)
	}
	if x != nil && a2.Cmp(x) != 0 {
		t.Errorf("aliased x = a, y = b GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, a2, x)
	}
	if y != nil && b2.Cmp(y) != 0 {
		t.Errorf("aliased x = a, y = b GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, b2, y)
	}

	a2 = new(Int).Set(a)
	b2 = new(Int).Set(b)
	D = new(Int).GCD(b2, a2, a2, b2) // x = b, y = a
	if D.Cmp(d) != 0 {
		t.Errorf("aliased x = b, y = a GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, D, d)
	}
	if x != nil && b2.Cmp(x) != 0 {
		t.Errorf("aliased x = b, y = a GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, b2, x)
	}
	if y != nil && a2.Cmp(y) != 0 {
		t.Errorf("aliased x = b, y = a GCD(%s, %s, %s, %s): got y = %s, want %s",
"""




```