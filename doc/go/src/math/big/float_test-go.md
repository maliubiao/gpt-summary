Response:
Let's break down the thought process for analyzing the provided Go code snippet and fulfilling the prompt's requirements.

**1. Understanding the Goal:**

The core task is to analyze a Go test file (`float_test.go`) and describe its functionality. The prompt also asks for specific examples related to Go language features demonstrated in the code.

**2. Initial Scan and Keyword Spotting:**

First, I quickly scanned the code, looking for obvious clues. Keywords like `package big`, `import`, `func Test...`, `Float`, `SetPrec`, `Sign`, `MantExp`, `Uint64`, `Int64`, `Float32`, `Float64`, `Rat`, etc., immediately stand out. These keywords hint at the package being tested (likely `math/big`), the types being tested (`Float`), and the kinds of operations being performed. The presence of `func Test...` functions clearly indicates this is a testing file.

**3. Identifying the Core Functionality Being Tested:**

Based on the keywords and the overall structure, it's clear the code is testing the `Float` type within the `math/big` package. The test functions cover various aspects of `Float` manipulation.

**4. Categorizing the Test Functions:**

To get a better grasp, I mentally categorized the test functions:

* **Basic Properties:** `TestFloatZeroValue`, `TestFloatSetPrec`, `TestFloatMinPrec`, `TestFloatSign` (testing fundamental characteristics of `Float`).
* **Mantissa and Exponent:** `TestFloatMantExp`, `TestFloatMantExpAliasing`, `TestFloatSetMantExp` (testing operations related to the internal representation of floating-point numbers).
* **Predicates and Type Checking:** `TestFloatPredicates`, `TestFloatIsInt` (testing functions that check properties of `Float` values).
* **Rounding:** `TestFloatRound`, `TestFloatRound24` (testing different rounding modes).
* **Setting Values:** `TestFloatSetUint64`, `TestFloatSetInt64`, `TestFloatSetFloat64`, `TestFloatSetInt`, `TestFloatSetRat`, `TestFloatSetInf` (testing ways to initialize or change `Float` values).
* **Getting Values (Conversions):** `TestFloatUint64`, `TestFloatInt64`, `TestFloatFloat32`, `TestFloatFloat64`, `TestFloatInt`, `TestFloatRat` (testing methods to convert `Float` to other types).

**5. Inferring the Go Language Features Being Tested:**

By looking at the operations performed within the test functions, I can infer the Go language features being used and tested:

* **`math/big.Float`:** This is the central type being tested, a high-precision floating-point number type.
* **Methods on Structs:** The tests extensively use methods on the `Float` struct (e.g., `SetPrec`, `Sign`, `Add`).
* **Error Handling:** The code checks for `ErrNaN`, indicating testing of error conditions.
* **Testing Framework (`testing` package):** The `testing` package is used for writing unit tests (`t.Errorf`).
* **Flags (`flag` package):** The import of `flag` suggests the possibility of command-line flags affecting the tests, although they aren't actively used in *this specific snippet*.
* **String Conversion (`strconv` package):** Functions like `ParseFloat`, `FormatInt` are used for converting between strings and numbers.
* **Mathematical Constants and Functions (`math` package):**  Constants like `math.Inf`, `math.NaN`, and functions like `math.Signbit` are used for comparison and testing edge cases.
* **Rounding Modes:** The code tests different rounding modes provided by the `Float` type.
* **Accuracy Tracking:** The `Accuracy` type and its values (`Exact`, `Above`, `Below`) are used, indicating that the `Float` type tracks the accuracy of its calculations.

**6. Constructing Examples:**

Based on the identified features, I started constructing code examples:

* **Zero Value:**  The `TestFloatZeroValue` function directly demonstrates the behavior of an uninitialized `Float`.
* **Setting Precision:**  `TestFloatSetPrec` provides examples of how `SetPrec` works.
* **Mantissa and Exponent:** `TestFloatMantExp` and `TestFloatSetMantExp` illustrate these concepts.
* **Conversions:**  `TestFloatUint64`, `TestFloatInt64`, etc., provide clear examples of converting `Float` to other types.

**7. Considering Command-Line Arguments:**

The presence of `import "flag"` prompted me to think about command-line arguments. Even though the provided snippet *doesn't explicitly use flags*, it's important to acknowledge their potential presence in a larger test suite. I noted that further parts of the file might use them.

**8. Identifying Potential User Errors:**

I reviewed the test cases and thought about common mistakes a user might make when working with `big.Float`:

* **Assuming Exact Conversions:** Users might expect `Float64()` or `Int64()` to always return an exact value, neglecting to check the `Accuracy`.
* **Incorrect Rounding Assumptions:**  Users might not be aware of the different rounding modes and their implications.
* **Ignoring Precision:**  Users might not set the precision appropriately for their calculations, leading to loss of accuracy.

**9. Structuring the Answer:**

Finally, I structured the answer according to the prompt's requirements:

* **功能列举:**  A concise summary of the test file's purpose.
* **Go语言功能实现推理:** Listing the Go language features demonstrated.
* **代码举例:** Providing concrete code examples with input and output (where applicable).
* **命令行参数处理:** Addressing the `flag` import (even though not used in this snippet).
* **使用者易犯错的点:**  Giving examples of potential user errors.
* **功能归纳:** A final summary of the tested functionality.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the individual test functions. I then shifted to identifying the *broader categories* of functionality being tested.
*  Realizing the `flag` package was imported but not used in *this snippet* required a nuance in the explanation. I made sure to acknowledge its presence while pointing out its lack of explicit use here.
* Ensuring the code examples were clear, concise, and directly related to the tested functionality was an iterative process. I aimed for examples that clearly illustrated the points I was making.

By following this structured approach, combining keyword spotting, categorization, and inference, I was able to effectively analyze the Go code snippet and provide a comprehensive answer to the prompt.
这个go语言实现的文件 `go/src/math/big/float_test.go` 的一部分，主要功能是**测试 `math/big` 包中 `Float` 类型的各种功能和方法的正确性**。

**功能归纳：**

这部分代码主要针对 `big.Float` 类型进行单元测试，涵盖了以下几个方面的功能：

1. **`Float` 类型的基本属性和创建:**
   - 测试零值 `Float` 的行为。
   - 测试设置 `Float` 精度 (`SetPrec`) 的功能和影响。
   - 测试获取 `Float` 最小精度 (`MinPrec`) 的功能。
   - 测试获取 `Float` 符号 (`Sign`) 的功能。
   - 测试判断 `Float` 的符号位 (`Signbit`) 和是否为无穷大 (`IsInf`) 的功能。
   - 测试判断 `Float` 是否为整数 (`IsInt`) 的功能。

2. **`Float` 类型的内部表示和操作:**
   - 测试获取和设置 `Float` 的尾数和指数 (`MantExp`, `SetMantExp`) 的功能。

3. **`Float` 类型的舍入功能:**
   - 测试不同精度和舍入模式下 `Float` 的舍入行为 (`TestFloatRound`, `TestFloatRound24`)。

4. **`Float` 类型与其他类型的转换和设置:**
   - 测试将 `uint64` 设置为 `Float` (`SetUint64`) 以及从 `Float` 转换为 `uint64` (`Uint64`) 的功能。
   - 测试将 `int64` 设置为 `Float` (`SetInt64`) 以及从 `Float` 转换为 `int64` (`Int64`) 的功能。
   - 测试将 `float64` 设置为 `Float` (`SetFloat64`) 以及从 `Float` 转换为 `float32` (`Float32`) 和 `float64` (`Float64`) 的功能。
   - 测试将 `Int` 设置为 `Float` (`SetInt`) 以及从 `Float` 转换为 `Int` (`Int`) 的功能。
   - 测试将 `Rat` 设置为 `Float` (`SetRat`) 以及从 `Float` 转换为 `Rat` (`Rat`) 的功能。
   - 测试设置 `Float` 为无穷大 (`SetInf`) 的功能。

**Go 语言功能实现举例：**

这段代码大量使用了 Go 语言的以下功能：

* **结构体和方法 (`struct` and methods):**  `Float` 是一个结构体，代码中定义了许多操作 `Float` 的方法，例如 `SetPrec`, `Sign`, `Uint64` 等。

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	f := new(big.Float).SetPrec(64) // 创建一个精度为 64 位的 Float
	f.SetFloat64(3.14159)         // 将 float64 值设置为 Float
	fmt.Println(f.String())         // 输出 Float 的字符串表示

	sign := f.Sign()             // 获取 Float 的符号
	fmt.Println("Sign:", sign)

	integerPart, accuracy := f.Int(nil) // 将 Float 转换为 Int
	fmt.Println("Integer part:", integerPart)
	fmt.Println("Accuracy:", accuracy)
}
```

**假设的输入与输出：**

对于上面的代码示例，假设的输出可能是：

```
3.1415899999999999
Sign: 1
Integer part: 3
Accuracy: big.Below
```

**代码推理：**

例如，`TestFloatSetPrec` 函数通过不同的输入字符串和精度，断言设置精度后 `Float` 的字符串表示和精度是否符合预期。

```go
func TestFloatSetPrec(t *testing.T) {
	for _, test := range []struct {
		x    string
		prec uint
		want string
		acc  Accuracy
	}{
		// ... (测试用例) ...
		{"1.5", 1, "2", Above},
		{"-1.5", 1, "-2", Below},
		// ...
	} {
		x := makeFloat(test.x).SetPrec(test.prec) // 创建 Float 并设置精度
		// ... (断言精度和字符串表示) ...
		if got, acc := x.String(), x.Acc(); got != test.want || acc != test.acc {
			t.Errorf("%s.SetPrec(%d) = %s (%s); want %s (%s)", test.x, test.prec, got, acc, test.want, test.acc)
		}
	}
}
```

在这个测试用例中，如果输入字符串 `x` 为 "1.5"，精度 `prec` 为 1，那么期望的输出字符串 `want` 是 "2"，精度状态 `acc` 是 `Above`，因为 1.5 舍入到最接近的 1 位精度整数是 2，并且发生了向上舍入。

**命令行参数的具体处理：**

虽然这段代码中引入了 `flag` 包，但**在这部分代码中并没有看到具体的命令行参数处理逻辑**。通常，`flag` 包用于定义和解析命令行参数，以便在运行测试时可以动态地配置测试行为。  在文件的其他部分，可能会有类似以下的用法：

```go
var (
	verbose = flag.Bool("verbose", false, "enable verbose output")
)

func init() {
	flag.Parse()
}

func TestSomeFunction(t *testing.T) {
	if *verbose {
		fmt.Println("Running test with verbose output...")
	}
	// ... 测试逻辑 ...
}
```

如果存在这样的代码，运行测试时可以使用命令行参数，例如：`go test -verbose`。

**使用者易犯错的点：**

一个常见的错误是**忽略 `Float` 类型操作的精度和舍入模式**，导致计算结果与预期不符。 例如：

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	f1 := new(big.Float).SetFloat64(1.0 / 3.0)
	f2 := new(big.Float).SetFloat64(1.0 / 3.0)
	f3 := new(big.Float)
	f3.Mul(f1, f2)
	fmt.Println(f3.String()) // 输出结果可能不是精确的 1/9
}
```

在这个例子中，由于 `f1` 和 `f2` 是从 `float64` 转换而来，本身就存在精度损失。如果不显式设置更高的精度，`f3` 的结果可能不是精确的 1/9。

另一个易错点是**在比较 `Float` 类型时直接使用 `==`**。 应该使用 `Cmp` 方法进行比较，因为 `Float` 类型可能表示非常接近但不完全相等的值。

总而言之，这部分 `float_test.go` 代码是 `math/big` 包中 `Float` 类型功能的详细单元测试，确保了该类型在各种场景下的行为符合预期。它覆盖了 `Float` 类型的创建、属性访问、内部操作、舍入、与其他类型的转换等多个方面。

Prompt: 
```
这是路径为go/src/math/big/float_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package big

import (
	"flag"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

// Verify that ErrNaN implements the error interface.
var _ error = ErrNaN{}

func (x *Float) uint64() uint64 {
	u, acc := x.Uint64()
	if acc != Exact {
		panic(fmt.Sprintf("%s is not a uint64", x.Text('g', 10)))
	}
	return u
}

func (x *Float) int64() int64 {
	i, acc := x.Int64()
	if acc != Exact {
		panic(fmt.Sprintf("%s is not an int64", x.Text('g', 10)))
	}
	return i
}

func TestFloatZeroValue(t *testing.T) {
	// zero (uninitialized) value is a ready-to-use 0.0
	var x Float
	if s := x.Text('f', 1); s != "0.0" {
		t.Errorf("zero value = %s; want 0.0", s)
	}

	// zero value has precision 0
	if prec := x.Prec(); prec != 0 {
		t.Errorf("prec = %d; want 0", prec)
	}

	// zero value can be used in any and all positions of binary operations
	make := func(x int) *Float {
		var f Float
		if x != 0 {
			f.SetInt64(int64(x))
		}
		// x == 0 translates into the zero value
		return &f
	}
	for _, test := range []struct {
		z, x, y, want int
		opname        rune
		op            func(z, x, y *Float) *Float
	}{
		{0, 0, 0, 0, '+', (*Float).Add},
		{0, 1, 2, 3, '+', (*Float).Add},
		{1, 2, 0, 2, '+', (*Float).Add},
		{2, 0, 1, 1, '+', (*Float).Add},

		{0, 0, 0, 0, '-', (*Float).Sub},
		{0, 1, 2, -1, '-', (*Float).Sub},
		{1, 2, 0, 2, '-', (*Float).Sub},
		{2, 0, 1, -1, '-', (*Float).Sub},

		{0, 0, 0, 0, '*', (*Float).Mul},
		{0, 1, 2, 2, '*', (*Float).Mul},
		{1, 2, 0, 0, '*', (*Float).Mul},
		{2, 0, 1, 0, '*', (*Float).Mul},

		// {0, 0, 0, 0, '/', (*Float).Quo}, // panics
		{0, 2, 1, 2, '/', (*Float).Quo},
		{1, 2, 0, 0, '/', (*Float).Quo}, // = +Inf
		{2, 0, 1, 0, '/', (*Float).Quo},
	} {
		z := make(test.z)
		test.op(z, make(test.x), make(test.y))
		got := 0
		if !z.IsInf() {
			got = int(z.int64())
		}
		if got != test.want {
			t.Errorf("%d %c %d = %d; want %d", test.x, test.opname, test.y, got, test.want)
		}
	}

	// TODO(gri) test how precision is set for zero value results
}

func makeFloat(s string) *Float {
	x, _, err := ParseFloat(s, 0, 1000, ToNearestEven)
	if err != nil {
		panic(err)
	}
	return x
}

func TestFloatSetPrec(t *testing.T) {
	for _, test := range []struct {
		x    string
		prec uint
		want string
		acc  Accuracy
	}{
		// prec 0
		{"0", 0, "0", Exact},
		{"-0", 0, "-0", Exact},
		{"-Inf", 0, "-Inf", Exact},
		{"+Inf", 0, "+Inf", Exact},
		{"123", 0, "0", Below},
		{"-123", 0, "-0", Above},

		// prec at upper limit
		{"0", MaxPrec, "0", Exact},
		{"-0", MaxPrec, "-0", Exact},
		{"-Inf", MaxPrec, "-Inf", Exact},
		{"+Inf", MaxPrec, "+Inf", Exact},

		// just a few regular cases - general rounding is tested elsewhere
		{"1.5", 1, "2", Above},
		{"-1.5", 1, "-2", Below},
		{"123", 1e6, "123", Exact},
		{"-123", 1e6, "-123", Exact},
	} {
		x := makeFloat(test.x).SetPrec(test.prec)
		prec := test.prec
		if prec > MaxPrec {
			prec = MaxPrec
		}
		if got := x.Prec(); got != prec {
			t.Errorf("%s.SetPrec(%d).Prec() == %d; want %d", test.x, test.prec, got, prec)
		}
		if got, acc := x.String(), x.Acc(); got != test.want || acc != test.acc {
			t.Errorf("%s.SetPrec(%d) = %s (%s); want %s (%s)", test.x, test.prec, got, acc, test.want, test.acc)
		}
	}
}

func TestFloatMinPrec(t *testing.T) {
	const max = 100
	for _, test := range []struct {
		x    string
		want uint
	}{
		{"0", 0},
		{"-0", 0},
		{"+Inf", 0},
		{"-Inf", 0},
		{"1", 1},
		{"2", 1},
		{"3", 2},
		{"0x8001", 16},
		{"0x8001p-1000", 16},
		{"0x8001p+1000", 16},
		{"0.1", max},
	} {
		x := makeFloat(test.x).SetPrec(max)
		if got := x.MinPrec(); got != test.want {
			t.Errorf("%s.MinPrec() = %d; want %d", test.x, got, test.want)
		}
	}
}

func TestFloatSign(t *testing.T) {
	for _, test := range []struct {
		x string
		s int
	}{
		{"-Inf", -1},
		{"-1", -1},
		{"-0", 0},
		{"+0", 0},
		{"+1", +1},
		{"+Inf", +1},
	} {
		x := makeFloat(test.x)
		s := x.Sign()
		if s != test.s {
			t.Errorf("%s.Sign() = %d; want %d", test.x, s, test.s)
		}
	}
}

// alike(x, y) is like x.Cmp(y) == 0 but also considers the sign of 0 (0 != -0).
func alike(x, y *Float) bool {
	return x.Cmp(y) == 0 && x.Signbit() == y.Signbit()
}

func alike32(x, y float32) bool {
	// we can ignore NaNs
	return x == y && math.Signbit(float64(x)) == math.Signbit(float64(y))
}

func alike64(x, y float64) bool {
	// we can ignore NaNs
	return x == y && math.Signbit(x) == math.Signbit(y)
}

func TestFloatMantExp(t *testing.T) {
	for _, test := range []struct {
		x    string
		mant string
		exp  int
	}{
		{"0", "0", 0},
		{"+0", "0", 0},
		{"-0", "-0", 0},
		{"Inf", "+Inf", 0},
		{"+Inf", "+Inf", 0},
		{"-Inf", "-Inf", 0},
		{"1.5", "0.75", 1},
		{"1.024e3", "0.5", 11},
		{"-0.125", "-0.5", -2},
	} {
		x := makeFloat(test.x)
		mant := makeFloat(test.mant)
		m := new(Float)
		e := x.MantExp(m)
		if !alike(m, mant) || e != test.exp {
			t.Errorf("%s.MantExp() = %s, %d; want %s, %d", test.x, m.Text('g', 10), e, test.mant, test.exp)
		}
	}
}

func TestFloatMantExpAliasing(t *testing.T) {
	x := makeFloat("0.5p10")
	if e := x.MantExp(x); e != 10 {
		t.Fatalf("Float.MantExp aliasing error: got %d; want 10", e)
	}
	if want := makeFloat("0.5"); !alike(x, want) {
		t.Fatalf("Float.MantExp aliasing error: got %s; want %s", x.Text('g', 10), want.Text('g', 10))
	}
}

func TestFloatSetMantExp(t *testing.T) {
	for _, test := range []struct {
		frac string
		exp  int
		z    string
	}{
		{"0", 0, "0"},
		{"+0", 0, "0"},
		{"-0", 0, "-0"},
		{"Inf", 1234, "+Inf"},
		{"+Inf", -1234, "+Inf"},
		{"-Inf", -1234, "-Inf"},
		{"0", MinExp, "0"},
		{"0.25", MinExp, "+0"},    // exponent underflow
		{"-0.25", MinExp, "-0"},   // exponent underflow
		{"1", MaxExp, "+Inf"},     // exponent overflow
		{"2", MaxExp - 1, "+Inf"}, // exponent overflow
		{"0.75", 1, "1.5"},
		{"0.5", 11, "1024"},
		{"-0.5", -2, "-0.125"},
		{"32", 5, "1024"},
		{"1024", -10, "1"},
	} {
		frac := makeFloat(test.frac)
		want := makeFloat(test.z)
		var z Float
		z.SetMantExp(frac, test.exp)
		if !alike(&z, want) {
			t.Errorf("SetMantExp(%s, %d) = %s; want %s", test.frac, test.exp, z.Text('g', 10), test.z)
		}
		// test inverse property
		mant := new(Float)
		if z.SetMantExp(mant, want.MantExp(mant)).Cmp(want) != 0 {
			t.Errorf("Inverse property not satisfied: got %s; want %s", z.Text('g', 10), test.z)
		}
	}
}

func TestFloatPredicates(t *testing.T) {
	for _, test := range []struct {
		x            string
		sign         int
		signbit, inf bool
	}{
		{x: "-Inf", sign: -1, signbit: true, inf: true},
		{x: "-1", sign: -1, signbit: true},
		{x: "-0", signbit: true},
		{x: "0"},
		{x: "1", sign: 1},
		{x: "+Inf", sign: 1, inf: true},
	} {
		x := makeFloat(test.x)
		if got := x.Signbit(); got != test.signbit {
			t.Errorf("(%s).Signbit() = %v; want %v", test.x, got, test.signbit)
		}
		if got := x.Sign(); got != test.sign {
			t.Errorf("(%s).Sign() = %d; want %d", test.x, got, test.sign)
		}
		if got := x.IsInf(); got != test.inf {
			t.Errorf("(%s).IsInf() = %v; want %v", test.x, got, test.inf)
		}
	}
}

func TestFloatIsInt(t *testing.T) {
	for _, test := range []string{
		"0 int",
		"-0 int",
		"1 int",
		"-1 int",
		"0.5",
		"1.23",
		"1.23e1",
		"1.23e2 int",
		"0.000000001e+8",
		"0.000000001e+9 int",
		"1.2345e200 int",
		"Inf",
		"+Inf",
		"-Inf",
	} {
		s := strings.TrimSuffix(test, " int")
		want := s != test
		if got := makeFloat(s).IsInt(); got != want {
			t.Errorf("%s.IsInt() == %t", s, got)
		}
	}
}

func fromBinary(s string) int64 {
	x, err := strconv.ParseInt(s, 2, 64)
	if err != nil {
		panic(err)
	}
	return x
}

func toBinary(x int64) string {
	return strconv.FormatInt(x, 2)
}

func testFloatRound(t *testing.T, x, r int64, prec uint, mode RoundingMode) {
	// verify test data
	var ok bool
	switch mode {
	case ToNearestEven, ToNearestAway:
		ok = true // nothing to do for now
	case ToZero:
		if x < 0 {
			ok = r >= x
		} else {
			ok = r <= x
		}
	case AwayFromZero:
		if x < 0 {
			ok = r <= x
		} else {
			ok = r >= x
		}
	case ToNegativeInf:
		ok = r <= x
	case ToPositiveInf:
		ok = r >= x
	default:
		panic("unreachable")
	}
	if !ok {
		t.Fatalf("incorrect test data for prec = %d, %s: x = %s, r = %s", prec, mode, toBinary(x), toBinary(r))
	}

	// compute expected accuracy
	a := Exact
	switch {
	case r < x:
		a = Below
	case r > x:
		a = Above
	}

	// round
	f := new(Float).SetMode(mode).SetInt64(x).SetPrec(prec)

	// check result
	r1 := f.int64()
	p1 := f.Prec()
	a1 := f.Acc()
	if r1 != r || p1 != prec || a1 != a {
		t.Errorf("round %s (%d bits, %s) incorrect: got %s (%d bits, %s); want %s (%d bits, %s)",
			toBinary(x), prec, mode,
			toBinary(r1), p1, a1,
			toBinary(r), prec, a)
		return
	}

	// g and f should be the same
	// (rounding by SetPrec after SetInt64 using default precision
	// should be the same as rounding by SetInt64 after setting the
	// precision)
	g := new(Float).SetMode(mode).SetPrec(prec).SetInt64(x)
	if !alike(g, f) {
		t.Errorf("round %s (%d bits, %s) not symmetric: got %s and %s; want %s",
			toBinary(x), prec, mode,
			toBinary(g.int64()),
			toBinary(r1),
			toBinary(r),
		)
		return
	}

	// h and f should be the same
	// (repeated rounding should be idempotent)
	h := new(Float).SetMode(mode).SetPrec(prec).Set(f)
	if !alike(h, f) {
		t.Errorf("round %s (%d bits, %s) not idempotent: got %s and %s; want %s",
			toBinary(x), prec, mode,
			toBinary(h.int64()),
			toBinary(r1),
			toBinary(r),
		)
		return
	}
}

// TestFloatRound tests basic rounding.
func TestFloatRound(t *testing.T) {
	for _, test := range []struct {
		prec                        uint
		x, zero, neven, naway, away string // input, results rounded to prec bits
	}{
		{5, "1000", "1000", "1000", "1000", "1000"},
		{5, "1001", "1001", "1001", "1001", "1001"},
		{5, "1010", "1010", "1010", "1010", "1010"},
		{5, "1011", "1011", "1011", "1011", "1011"},
		{5, "1100", "1100", "1100", "1100", "1100"},
		{5, "1101", "1101", "1101", "1101", "1101"},
		{5, "1110", "1110", "1110", "1110", "1110"},
		{5, "1111", "1111", "1111", "1111", "1111"},

		{4, "1000", "1000", "1000", "1000", "1000"},
		{4, "1001", "1001", "1001", "1001", "1001"},
		{4, "1010", "1010", "1010", "1010", "1010"},
		{4, "1011", "1011", "1011", "1011", "1011"},
		{4, "1100", "1100", "1100", "1100", "1100"},
		{4, "1101", "1101", "1101", "1101", "1101"},
		{4, "1110", "1110", "1110", "1110", "1110"},
		{4, "1111", "1111", "1111", "1111", "1111"},

		{3, "1000", "1000", "1000", "1000", "1000"},
		{3, "1001", "1000", "1000", "1010", "1010"},
		{3, "1010", "1010", "1010", "1010", "1010"},
		{3, "1011", "1010", "1100", "1100", "1100"},
		{3, "1100", "1100", "1100", "1100", "1100"},
		{3, "1101", "1100", "1100", "1110", "1110"},
		{3, "1110", "1110", "1110", "1110", "1110"},
		{3, "1111", "1110", "10000", "10000", "10000"},

		{3, "1000001", "1000000", "1000000", "1000000", "1010000"},
		{3, "1001001", "1000000", "1010000", "1010000", "1010000"},
		{3, "1010001", "1010000", "1010000", "1010000", "1100000"},
		{3, "1011001", "1010000", "1100000", "1100000", "1100000"},
		{3, "1100001", "1100000", "1100000", "1100000", "1110000"},
		{3, "1101001", "1100000", "1110000", "1110000", "1110000"},
		{3, "1110001", "1110000", "1110000", "1110000", "10000000"},
		{3, "1111001", "1110000", "10000000", "10000000", "10000000"},

		{2, "1000", "1000", "1000", "1000", "1000"},
		{2, "1001", "1000", "1000", "1000", "1100"},
		{2, "1010", "1000", "1000", "1100", "1100"},
		{2, "1011", "1000", "1100", "1100", "1100"},
		{2, "1100", "1100", "1100", "1100", "1100"},
		{2, "1101", "1100", "1100", "1100", "10000"},
		{2, "1110", "1100", "10000", "10000", "10000"},
		{2, "1111", "1100", "10000", "10000", "10000"},

		{2, "1000001", "1000000", "1000000", "1000000", "1100000"},
		{2, "1001001", "1000000", "1000000", "1000000", "1100000"},
		{2, "1010001", "1000000", "1100000", "1100000", "1100000"},
		{2, "1011001", "1000000", "1100000", "1100000", "1100000"},
		{2, "1100001", "1100000", "1100000", "1100000", "10000000"},
		{2, "1101001", "1100000", "1100000", "1100000", "10000000"},
		{2, "1110001", "1100000", "10000000", "10000000", "10000000"},
		{2, "1111001", "1100000", "10000000", "10000000", "10000000"},

		{1, "1000", "1000", "1000", "1000", "1000"},
		{1, "1001", "1000", "1000", "1000", "10000"},
		{1, "1010", "1000", "1000", "1000", "10000"},
		{1, "1011", "1000", "1000", "1000", "10000"},
		{1, "1100", "1000", "10000", "10000", "10000"},
		{1, "1101", "1000", "10000", "10000", "10000"},
		{1, "1110", "1000", "10000", "10000", "10000"},
		{1, "1111", "1000", "10000", "10000", "10000"},

		{1, "1000001", "1000000", "1000000", "1000000", "10000000"},
		{1, "1001001", "1000000", "1000000", "1000000", "10000000"},
		{1, "1010001", "1000000", "1000000", "1000000", "10000000"},
		{1, "1011001", "1000000", "1000000", "1000000", "10000000"},
		{1, "1100001", "1000000", "10000000", "10000000", "10000000"},
		{1, "1101001", "1000000", "10000000", "10000000", "10000000"},
		{1, "1110001", "1000000", "10000000", "10000000", "10000000"},
		{1, "1111001", "1000000", "10000000", "10000000", "10000000"},
	} {
		x := fromBinary(test.x)
		z := fromBinary(test.zero)
		e := fromBinary(test.neven)
		n := fromBinary(test.naway)
		a := fromBinary(test.away)
		prec := test.prec

		testFloatRound(t, x, z, prec, ToZero)
		testFloatRound(t, x, e, prec, ToNearestEven)
		testFloatRound(t, x, n, prec, ToNearestAway)
		testFloatRound(t, x, a, prec, AwayFromZero)

		testFloatRound(t, x, z, prec, ToNegativeInf)
		testFloatRound(t, x, a, prec, ToPositiveInf)

		testFloatRound(t, -x, -a, prec, ToNegativeInf)
		testFloatRound(t, -x, -z, prec, ToPositiveInf)
	}
}

// TestFloatRound24 tests that rounding a float64 to 24 bits
// matches IEEE 754 rounding to nearest when converting a
// float64 to a float32 (excluding denormal numbers).
func TestFloatRound24(t *testing.T) {
	const x0 = 1<<26 - 0x10 // 11...110000 (26 bits)
	for d := 0; d <= 0x10; d++ {
		x := float64(x0 + d)
		f := new(Float).SetPrec(24).SetFloat64(x)
		got, _ := f.Float32()
		want := float32(x)
		if got != want {
			t.Errorf("Round(%g, 24) = %g; want %g", x, got, want)
		}
	}
}

func TestFloatSetUint64(t *testing.T) {
	for _, want := range []uint64{
		0,
		1,
		2,
		10,
		100,
		1<<32 - 1,
		1 << 32,
		1<<64 - 1,
	} {
		var f Float
		f.SetUint64(want)
		if got := f.uint64(); got != want {
			t.Errorf("got %#x (%s); want %#x", got, f.Text('p', 0), want)
		}
	}

	// test basic rounding behavior (exhaustive rounding testing is done elsewhere)
	const x uint64 = 0x8765432187654321 // 64 bits needed
	for prec := uint(1); prec <= 64; prec++ {
		f := new(Float).SetPrec(prec).SetMode(ToZero).SetUint64(x)
		got := f.uint64()
		want := x &^ (1<<(64-prec) - 1) // cut off (round to zero) low 64-prec bits
		if got != want {
			t.Errorf("got %#x (%s); want %#x", got, f.Text('p', 0), want)
		}
	}
}

func TestFloatSetInt64(t *testing.T) {
	for _, want := range []int64{
		0,
		1,
		2,
		10,
		100,
		1<<32 - 1,
		1 << 32,
		1<<63 - 1,
	} {
		for i := range [2]int{} {
			if i&1 != 0 {
				want = -want
			}
			var f Float
			f.SetInt64(want)
			if got := f.int64(); got != want {
				t.Errorf("got %#x (%s); want %#x", got, f.Text('p', 0), want)
			}
		}
	}

	// test basic rounding behavior (exhaustive rounding testing is done elsewhere)
	const x int64 = 0x7654321076543210 // 63 bits needed
	for prec := uint(1); prec <= 63; prec++ {
		f := new(Float).SetPrec(prec).SetMode(ToZero).SetInt64(x)
		got := f.int64()
		want := x &^ (1<<(63-prec) - 1) // cut off (round to zero) low 63-prec bits
		if got != want {
			t.Errorf("got %#x (%s); want %#x", got, f.Text('p', 0), want)
		}
	}
}

func TestFloatSetFloat64(t *testing.T) {
	for _, want := range []float64{
		0,
		1,
		2,
		12345,
		1e10,
		1e100,
		3.14159265e10,
		2.718281828e-123,
		1.0 / 3,
		math.MaxFloat32,
		math.MaxFloat64,
		math.SmallestNonzeroFloat32,
		math.SmallestNonzeroFloat64,
		math.Inf(-1),
		math.Inf(0),
		-math.Inf(1),
	} {
		for i := range [2]int{} {
			if i&1 != 0 {
				want = -want
			}
			var f Float
			f.SetFloat64(want)
			if got, acc := f.Float64(); got != want || acc != Exact {
				t.Errorf("got %g (%s, %s); want %g (Exact)", got, f.Text('p', 0), acc, want)
			}
		}
	}

	// test basic rounding behavior (exhaustive rounding testing is done elsewhere)
	const x uint64 = 0x8765432143218 // 53 bits needed
	for prec := uint(1); prec <= 52; prec++ {
		f := new(Float).SetPrec(prec).SetMode(ToZero).SetFloat64(float64(x))
		got, _ := f.Float64()
		want := float64(x &^ (1<<(52-prec) - 1)) // cut off (round to zero) low 53-prec bits
		if got != want {
			t.Errorf("got %g (%s); want %g", got, f.Text('p', 0), want)
		}
	}

	// test NaN
	defer func() {
		if p, ok := recover().(ErrNaN); !ok {
			t.Errorf("got %v; want ErrNaN panic", p)
		}
	}()
	var f Float
	f.SetFloat64(math.NaN())
	// should not reach here
	t.Errorf("got %s; want ErrNaN panic", f.Text('p', 0))
}

func TestFloatSetInt(t *testing.T) {
	for _, want := range []string{
		"0",
		"1",
		"-1",
		"1234567890",
		"123456789012345678901234567890",
		"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
	} {
		var x Int
		_, ok := x.SetString(want, 0)
		if !ok {
			t.Errorf("invalid integer %s", want)
			continue
		}
		n := x.BitLen()

		var f Float
		f.SetInt(&x)

		// check precision
		if n < 64 {
			n = 64
		}
		if prec := f.Prec(); prec != uint(n) {
			t.Errorf("got prec = %d; want %d", prec, n)
		}

		// check value
		got := f.Text('g', 100)
		if got != want {
			t.Errorf("got %s (%s); want %s", got, f.Text('p', 0), want)
		}
	}

	// TODO(gri) test basic rounding behavior
}

func TestFloatSetRat(t *testing.T) {
	for _, want := range []string{
		"0",
		"1",
		"-1",
		"1234567890",
		"123456789012345678901234567890",
		"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"1.2",
		"3.14159265",
		// TODO(gri) expand
	} {
		var x Rat
		_, ok := x.SetString(want)
		if !ok {
			t.Errorf("invalid fraction %s", want)
			continue
		}
		n := max(x.Num().BitLen(), x.Denom().BitLen())

		var f1, f2 Float
		f2.SetPrec(1000)
		f1.SetRat(&x)
		f2.SetRat(&x)

		// check precision when set automatically
		if n < 64 {
			n = 64
		}
		if prec := f1.Prec(); prec != uint(n) {
			t.Errorf("got prec = %d; want %d", prec, n)
		}

		got := f2.Text('g', 100)
		if got != want {
			t.Errorf("got %s (%s); want %s", got, f2.Text('p', 0), want)
		}
	}
}

func TestFloatSetInf(t *testing.T) {
	var f Float
	for _, test := range []struct {
		signbit bool
		prec    uint
		want    string
	}{
		{false, 0, "+Inf"},
		{true, 0, "-Inf"},
		{false, 10, "+Inf"},
		{true, 30, "-Inf"},
	} {
		x := f.SetPrec(test.prec).SetInf(test.signbit)
		if got := x.String(); got != test.want || x.Prec() != test.prec {
			t.Errorf("SetInf(%v) = %s (prec = %d); want %s (prec = %d)", test.signbit, got, x.Prec(), test.want, test.prec)
		}
	}
}

func TestFloatUint64(t *testing.T) {
	for _, test := range []struct {
		x   string
		out uint64
		acc Accuracy
	}{
		{"-Inf", 0, Above},
		{"-1", 0, Above},
		{"-1e-1000", 0, Above},
		{"-0", 0, Exact},
		{"0", 0, Exact},
		{"1e-1000", 0, Below},
		{"1", 1, Exact},
		{"1.000000000000000000001", 1, Below},
		{"12345.0", 12345, Exact},
		{"12345.000000000000000000001", 12345, Below},
		{"18446744073709551615", 18446744073709551615, Exact},
		{"18446744073709551615.000000000000000000001", math.MaxUint64, Below},
		{"18446744073709551616", math.MaxUint64, Below},
		{"1e10000", math.MaxUint64, Below},
		{"+Inf", math.MaxUint64, Below},
	} {
		x := makeFloat(test.x)
		out, acc := x.Uint64()
		if out != test.out || acc != test.acc {
			t.Errorf("%s: got %d (%s); want %d (%s)", test.x, out, acc, test.out, test.acc)
		}
	}
}

func TestFloatInt64(t *testing.T) {
	for _, test := range []struct {
		x   string
		out int64
		acc Accuracy
	}{
		{"-Inf", math.MinInt64, Above},
		{"-1e10000", math.MinInt64, Above},
		{"-9223372036854775809", math.MinInt64, Above},
		{"-9223372036854775808.000000000000000000001", math.MinInt64, Above},
		{"-9223372036854775808", -9223372036854775808, Exact},
		{"-9223372036854775807.000000000000000000001", -9223372036854775807, Above},
		{"-9223372036854775807", -9223372036854775807, Exact},
		{"-12345.000000000000000000001", -12345, Above},
		{"-12345.0", -12345, Exact},
		{"-1.000000000000000000001", -1, Above},
		{"-1.5", -1, Above},
		{"-1", -1, Exact},
		{"-1e-1000", 0, Above},
		{"0", 0, Exact},
		{"1e-1000", 0, Below},
		{"1", 1, Exact},
		{"1.000000000000000000001", 1, Below},
		{"1.5", 1, Below},
		{"12345.0", 12345, Exact},
		{"12345.000000000000000000001", 12345, Below},
		{"9223372036854775807", 9223372036854775807, Exact},
		{"9223372036854775807.000000000000000000001", math.MaxInt64, Below},
		{"9223372036854775808", math.MaxInt64, Below},
		{"1e10000", math.MaxInt64, Below},
		{"+Inf", math.MaxInt64, Below},
	} {
		x := makeFloat(test.x)
		out, acc := x.Int64()
		if out != test.out || acc != test.acc {
			t.Errorf("%s: got %d (%s); want %d (%s)", test.x, out, acc, test.out, test.acc)
		}
	}
}

func TestFloatFloat32(t *testing.T) {
	for _, test := range []struct {
		x   string
		out float32
		acc Accuracy
	}{
		{"0", 0, Exact},

		// underflow to zero
		{"1e-1000", 0, Below},
		{"0x0.000002p-127", 0, Below},
		{"0x.0000010p-126", 0, Below},

		// denormals
		{"1.401298464e-45", math.SmallestNonzeroFloat32, Above}, // rounded up to smallest denormal
		{"0x.ffffff8p-149", math.SmallestNonzeroFloat32, Above}, // rounded up to smallest denormal
		{"0x.0000018p-126", math.SmallestNonzeroFloat32, Above}, // rounded up to smallest denormal
		{"0x.0000020p-126", math.SmallestNonzeroFloat32, Exact},
		{"0x.8p-148", math.SmallestNonzeroFloat32, Exact},
		{"1p-149", math.SmallestNonzeroFloat32, Exact},
		{"0x.fffffep-126", math.Float32frombits(0x7fffff), Exact}, // largest denormal

		// special denormal cases (see issues 14553, 14651)
		{"0x0.0000001p-126", math.Float32frombits(0x00000000), Below}, // underflow to zero
		{"0x0.0000008p-126", math.Float32frombits(0x00000000), Below}, // underflow to zero
		{"0x0.0000010p-126", math.Float32frombits(0x00000000), Below}, // rounded down to even
		{"0x0.0000011p-126", math.Float32frombits(0x00000001), Above}, // rounded up to smallest denormal
		{"0x0.0000018p-126", math.Float32frombits(0x00000001), Above}, // rounded up to smallest denormal

		{"0x1.0000000p-149", math.Float32frombits(0x00000001), Exact}, // smallest denormal
		{"0x0.0000020p-126", math.Float32frombits(0x00000001), Exact}, // smallest denormal
		{"0x0.fffffe0p-126", math.Float32frombits(0x007fffff), Exact}, // largest denormal
		{"0x1.0000000p-126", math.Float32frombits(0x00800000), Exact}, // smallest normal

		{"0x0.8p-149", math.Float32frombits(0x000000000), Below}, // rounded down to even
		{"0x0.9p-149", math.Float32frombits(0x000000001), Above}, // rounded up to smallest denormal
		{"0x0.ap-149", math.Float32frombits(0x000000001), Above}, // rounded up to smallest denormal
		{"0x0.bp-149", math.Float32frombits(0x000000001), Above}, // rounded up to smallest denormal
		{"0x0.cp-149", math.Float32frombits(0x000000001), Above}, // rounded up to smallest denormal

		{"0x1.0p-149", math.Float32frombits(0x000000001), Exact}, // smallest denormal
		{"0x1.7p-149", math.Float32frombits(0x000000001), Below},
		{"0x1.8p-149", math.Float32frombits(0x000000002), Above},
		{"0x1.9p-149", math.Float32frombits(0x000000002), Above},

		{"0x2.0p-149", math.Float32frombits(0x000000002), Exact},
		{"0x2.8p-149", math.Float32frombits(0x000000002), Below}, // rounded down to even
		{"0x2.9p-149", math.Float32frombits(0x000000003), Above},

		{"0x3.0p-149", math.Float32frombits(0x000000003), Exact},
		{"0x3.7p-149", math.Float32frombits(0x000000003), Below},
		{"0x3.8p-149", math.Float32frombits(0x000000004), Above}, // rounded up to even

		{"0x4.0p-149", math.Float32frombits(0x000000004), Exact},
		{"0x4.8p-149", math.Float32frombits(0x000000004), Below}, // rounded down to even
		{"0x4.9p-149", math.Float32frombits(0x000000005), Above},

		// specific case from issue 14553
		{"0x7.7p-149", math.Float32frombits(0x000000007), Below},
		{"0x7.8p-149", math.Float32frombits(0x000000008), Above},
		{"0x7.9p-149", math.Float32frombits(0x000000008), Above},

		// normals
		{"0x.ffffffp-126", math.Float32frombits(0x00800000), Above}, // rounded up to smallest normal
		{"1p-126", math.Float32frombits(0x00800000), Exact},         // smallest normal
		{"0x1.fffffep-126", math.Float32frombits(0x00ffffff), Exact},
		{"0x1.ffffffp-126", math.Float32frombits(0x01000000), Above}, // rounded up
		{"1", 1, Exact},
		{"1.000000000000000000001", 1, Below},
		{"12345.0", 12345, Exact},
		{"12345.000000000000000000001", 12345, Below},
		{"0x1.fffffe0p127", math.MaxFloat32, Exact},
		{"0x1.fffffe8p127", math.MaxFloat32, Below},

		// overflow
		{"0x1.ffffff0p127", float32(math.Inf(+1)), Above},
		{"0x1p128", float32(math.Inf(+1)), Above},
		{"1e10000", float32(math.Inf(+1)), Above},
		{"0x1.ffffff0p2147483646", float32(math.Inf(+1)), Above}, // overflow in rounding

		// inf
		{"Inf", float32(math.Inf(+1)), Exact},
	} {
		for i := 0; i < 2; i++ {
			// test both signs
			tx, tout, tacc := test.x, test.out, test.acc
			if i != 0 {
				tx = "-" + tx
				tout = -tout
				tacc = -tacc
			}

			// conversion should match strconv where syntax is agreeable
			if f, err := strconv.ParseFloat(tx, 32); err == nil && !alike32(float32(f), tout) {
				t.Errorf("%s: got %g; want %g (incorrect test data)", tx, f, tout)
			}

			x := makeFloat(tx)
			out, acc := x.Float32()
			if !alike32(out, tout) || acc != tacc {
				t.Errorf("%s: got %g (%#08x, %s); want %g (%#08x, %s)", tx, out, math.Float32bits(out), acc, test.out, math.Float32bits(test.out), tacc)
			}

			// test that x.SetFloat64(float64(f)).Float32() == f
			var x2 Float
			out2, acc2 := x2.SetFloat64(float64(out)).Float32()
			if !alike32(out2, out) || acc2 != Exact {
				t.Errorf("idempotency test: got %g (%s); want %g (Exact)", out2, acc2, out)
			}
		}
	}
}

func TestFloatFloat64(t *testing.T) {
	const smallestNormalFloat64 = 2.2250738585072014e-308 // 1p-1022
	for _, test := range []struct {
		x   string
		out float64
		acc Accuracy
	}{
		{"0", 0, Exact},

		// underflow to zero
		{"1e-1000", 0, Below},
		{"0x0.0000000000001p-1023", 0, Below},
		{"0x0.00000000000008p-1022", 0, Below},

		// denormals
		{"0x0.0000000000000cp-1022", math.SmallestNonzeroFloat64, Above}, // rounded up to smallest denormal
		{"0x0.00000000000010p-1022", math.SmallestNonzeroFloat64, Exact}, // smallest denormal
		{"0x.8p-1073", math.SmallestNonzeroFloat64, Exact},
		{"1p-1074", math.SmallestNonzeroFloat64, Exact},
		{"0x.fffffffffffffp-1022", math.Float64frombits(0x000fffffffffffff), Exact}, // largest denormal

		// special denormal cases (see issues 14553, 14651)
		{"0x0.00000000000001p-1022", math.Float64frombits(0x00000000000000000), Below}, // underflow to zero
		{"0x0.00000000000004p-1022", math.Float64frombits(0x00000000000000000), Below}, // underflow to zero
		{"0x0.00000000000008p-1022", math.Float64frombits(0x00000000000000000), Below}, // rounded down to even
		{"0x0.00000000000009p-1022", math.Float64frombits(0x00000000000000001), Above}, // rounded up to smallest denormal
		{"0x0.0000000000000ap-1022", math.Float64frombits(0x00000000000000001), Above}, // rounded up to smallest denormal

		{"0x0.8p-1074", math.Float64frombits(0x00000000000000000), Below}, // rounded down to even
		{"0x0.9p-1074", math.Float64frombits(0x00000000000000001), Above}, // rounded up to smallest denormal
		{"0x0.ap-1074", math.Float64frombits(0x00000000000000001), Above}, // rounded up to smallest denormal
		{"0x0.bp-1074", math.Float64frombits(0x00000000000000001), Above}, // rounded up to smallest denormal
		{"0x0.cp-1074", math.Float64frombits(0x00000000000000001), Above}, // rounded up to smallest denormal

		{"0x1.0p-1074", math.Float64frombits(0x00000000000000001), Exact},
		{"0x1.7p-1074", math.Float64frombits(0x00000000000000001), Below},
		{"0x1.8p-1074", math.Float64frombits(0x00000000000000002), Above},
		{"0x1.9p-1074", math.Float64frombits(0x00000000000000002), Above},

		{"0x2.0p-1074", math.Float64frombits(0x00000000000000002), Exact},
		{"0x2.8p-1074", math.Float64frombits(0x00000000000000002), Below}, // rounded down to even
		{"0x2.9p-1074", math.Float64frombits(0x00000000000000003), Above},

		{"0x3.0p-1074", math.Float64frombits(0x00000000000000003), Exact},
		{"0x3.7p-1074", math.Float64frombits(0x00000000000000003), Below},
		{"0x3.8p-1074", math.Float64frombits(0x00000000000000004), Above}, // rounded up to even

		{"0x4.0p-1074", math.Float64frombits(0x00000000000000004), Exact},
		{"0x4.8p-1074", math.Float64frombits(0x00000000000000004), Below}, // rounded down to even
		{"0x4.9p-1074", math.Float64frombits(0x00000000000000005), Above},

		// normals
		{"0x.fffffffffffff8p-1022", math.Float64frombits(0x0010000000000000), Above}, // rounded up to smallest normal
		{"1p-1022", math.Float64frombits(0x0010000000000000), Exact},                 // smallest normal
		{"1", 1, Exact},
		{"1.000000000000000000001", 1, Below},
		{"12345.0", 12345, Exact},
		{"12345.000000000000000000001", 12345, Below},
		{"0x1.fffffffffffff0p1023", math.MaxFloat64, Exact},
		{"0x1.fffffffffffff4p1023", math.MaxFloat64, Below},

		// overflow
		{"0x1.fffffffffffff8p1023", math.Inf(+1), Above},
		{"0x1p1024", math.Inf(+1), Above},
		{"1e10000", math.Inf(+1), Above},
		{"0x1.fffffffffffff8p2147483646", math.Inf(+1), Above}, // overflow in rounding
		{"Inf", math.Inf(+1), Exact},

		// selected denormalized values that were handled incorrectly in the past
		{"0x.fffffffffffffp-1022", smallestNormalFloat64 - math.SmallestNonzeroFloat64, Exact},
		{"4503599627370495p-1074", smallestNormalFloat64 - math.SmallestNonzeroFloat64, Exact},

		// https://www.exploringbinary.com/php-hangs-on-numeric-value-2-2250738585072011e-308/
		{"2.2250738585072011e-308", 2.225073858507201e-308, Below},
		// https://www.exploringbinary.com/java-hangs-when-converting-2-2250738585072012e-308/
		{"2.2250738585072012e-308", 2.2250738585072014e-308, Above},
	} {
		for i := 0; i < 2; i++ {
			// test both signs
			tx, tout, tacc := test.x, test.out, test.acc
			if i != 0 {
				tx = "-" + tx
				tout = -tout
				tacc = -tacc
			}

			// conversion should match strconv where syntax is agreeable
			if f, err := strconv.ParseFloat(tx, 64); err == nil && !alike64(f, tout) {
				t.Errorf("%s: got %g; want %g (incorrect test data)", tx, f, tout)
			}

			x := makeFloat(tx)
			out, acc := x.Float64()
			if !alike64(out, tout) || acc != tacc {
				t.Errorf("%s: got %g (%#016x, %s); want %g (%#016x, %s)", tx, out, math.Float64bits(out), acc, test.out, math.Float64bits(test.out), tacc)
			}

			// test that x.SetFloat64(f).Float64() == f
			var x2 Float
			out2, acc2 := x2.SetFloat64(out).Float64()
			if !alike64(out2, out) || acc2 != Exact {
				t.Errorf("idempotency test: got %g (%s); want %g (Exact)", out2, acc2, out)
			}
		}
	}
}

func TestFloatInt(t *testing.T) {
	for _, test := range []struct {
		x    string
		want string
		acc  Accuracy
	}{
		{"0", "0", Exact},
		{"+0", "0", Exact},
		{"-0", "0", Exact},
		{"Inf", "nil", Below},
		{"+Inf", "nil", Below},
		{"-Inf", "nil", Above},
		{"1", "1", Exact},
		{"-1", "-1", Exact},
		{"1.23", "1", Below},
		{"-1.23", "-1", Above},
		{"123e-2", "1", Below},
		{"123e-3", "0", Below},
		{"123e-4", "0", Below},
		{"1e-1000", "0", Below},
		{"-1e-1000", "0", Above},
		{"1e+10", "10000000000", Exact},
		{"1e+100", "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", Exact},
	} {
		x := makeFloat(test.x)
		res, acc := x.Int(nil)
		got := "nil"
		if res != nil {
			got = res.String()
		}
		if got != test.want || acc != test.acc {
			t.Errorf("%s: got %s (%s); want %s (%s)", test.x, got, acc, test.want, test.acc)
		}
	}

	// check that supplied *Int is used
	for _, f := range []string{"0", "1", "-1", "1234"} {
		x := makeFloat(f)
		i := new(Int)
		if res, _ := x.Int(i); res != i {
			t.Errorf("(%s).Int is not using supplied *Int", f)
		}
	}
}

func TestFloatRat(t *testing.T) {
	for _, test := range []struct {
		x, want string
		acc     Accuracy
	}{
		{"0", "0/1", Exact},
		{"+0", "0/1", Exact},
		{"-0", "0/1", Exact},
		{"Inf", "nil", Below},
		{"+Inf", "nil", Below},
		{"-Inf", "nil", Above},
		{"1", "1/1", Exact},
		{"-1", "-1/1", Exact},
		{"1.25", "5/4", Exact},
		{"-1.25", "-5/4", Exact},
		{"1e10", "10000000000/1", Exact},
		{"1p10", "1024/1", Exact},
		{"-1p-10", "-1/1024", Exact},
		{"3.14159265", "7244019449799623199/23058430092136939
"""




```