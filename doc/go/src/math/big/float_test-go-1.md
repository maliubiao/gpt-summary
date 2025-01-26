Response:
Let's break down the thought process for analyzing the provided Go code snippet from `float_test.go`.

**1. Understanding the Request:**

The core request is to understand the *functionality* of the given Go code, which is a part of the `math/big` package's testing suite for the `Float` type. The request specifically asks for:

* **Listing functionalities:** What specific aspects of `Float` are being tested?
* **Inferring the Go feature:**  What broader Go language feature is being implemented and tested? (In this case, arbitrary-precision floating-point numbers).
* **Code examples:**  Illustrative Go code demonstrating the feature.
* **Code reasoning:**  Explaining the logic of specific test cases with example inputs and outputs.
* **Command-line parameters:**  Information about relevant command-line flags used in testing.
* **Common mistakes:**  Potential pitfalls for users of the `Float` type.
* **Summarizing the functionality (for this specific part):** Condensing the purpose of *this particular chunk* of the test file.

**2. Initial Code Scan and Identification of Test Functions:**

The first step is to quickly scan the code and identify the function signatures. We see functions like `TestFloatRat`, `TestFloatAbs`, `TestFloatNeg`, `TestFloatInc`, `TestFloatAdd`, `TestFloatAddRoundZero`, `TestFloatAdd32`, `TestFloatAdd64`, `TestIssue20490`, `TestFloatMul`, `TestFloatMul64`, `TestIssue6866`, `TestFloatQuo`, `TestFloatQuoSmoke`, `TestFloatArithmeticSpecialValues`, `TestFloatArithmeticOverflow`, `TestFloatArithmeticRounding`, and `TestFloatCmpSpecialValues`. The names themselves are highly indicative of what's being tested.

**3. Analyzing Individual Test Functions (Iterative Process):**

For each test function, the process involves:

* **Identifying the tested method:**  The function name usually includes the `Float` method being tested (e.g., `TestFloatRat` tests `Float.Rat`).
* **Examining the test cases:**  Look for `for...range` loops iterating over slices of test data (structs or basic types). These test cases provide concrete examples of inputs and expected outputs.
* **Understanding the assertions:** The `if` statements inside the loops usually contain calls to `t.Errorf`, which indicate a test failure. The conditions in these `if` statements reveal what the test is checking. Functions like `alike` (likely a helper function for comparing floats with potential for slight inaccuracies) are important to notice.
* **Inferring the purpose of specific tests:** For example, `TestFloatAddRoundZero` explicitly tests rounding behavior when the result is zero for different rounding modes. `TestFloatAdd32` and `TestFloatAdd64` verify behavior against the standard `float32` and `float64` types. `TestIssue` functions usually target specific bug fixes.
* **Looking for helper functions/constants:**  Notice `makeFloat`, `precList`, and `bitsList`. These provide context about how test inputs are generated and what kinds of scenarios are being covered.
* **Considering edge cases:**  Tests often include edge cases like zero, infinity, and very large/small numbers.

**4. Synthesizing Functionalities:**

After analyzing individual test functions, group them by the feature they are testing. For instance, several tests focus on arithmetic operations (`Add`, `Sub`, `Mul`, `Quo`), conversions (`Rat`, `Float32`, `Float64`), and other core functionalities (`Abs`, `Neg`, `Cmp`).

**5. Inferring the Go Feature:**

Based on the tested methods and the package name (`math/big`), it's clear that the code is testing the implementation of arbitrary-precision floating-point numbers in Go.

**6. Creating Code Examples:**

The test cases themselves provide excellent starting points for creating illustrative code examples. Adapt these examples to show how a user would typically use the `Float` type.

**7. Explaining Code Reasoning:**

Choose a few representative test cases (especially those involving calculations or conversions) and explain the input, the operation being performed, and the expected output. If the test involves specific rounding modes or edge cases, highlight those.

**8. Identifying Command-Line Parameters:**

Look for the `flag` package being used. In this snippet, the `--long` flag is evident and its purpose is explained in the `TestFloatQuoSmoke` function.

**9. Spotting Common Mistakes:**

Consider how a user unfamiliar with arbitrary-precision arithmetic might make errors. For example, assuming default precision is sufficient or misunderstanding rounding modes are common pitfalls. The tests themselves sometimes hint at these potential issues (e.g., tests focusing on precision).

**10. Summarizing Functionality (for this part):**

Focus on the overall theme of the provided code snippet. In this case, it's primarily about testing the basic arithmetic operations (`Add`, `Sub`, `Mul`, `Quo`), conversions to `Rat`, and other fundamental methods like `Abs`, `Neg`, and `Cmp`, along with handling of special values and potential overflow/underflow scenarios.

**Self-Correction/Refinement during the process:**

* **Initial assumptions might be wrong:**  If a test case doesn't make immediate sense, revisit the documentation for the relevant `Float` method or related concepts.
* **Missing context:** Sometimes you might need to look at other parts of the `float_test.go` file or even the `float.go` implementation to fully understand a test. The prompt provides the file path, which is a good hint.
* **Overly detailed vs. concise:**  Strike a balance between providing enough detail to be informative and keeping the explanation concise and easy to understand. The request to "归纳一下它的功能" (summarize its functionality) emphasizes conciseness.

By following these steps iteratively and refining the analysis as needed, you can effectively understand and explain the functionality of a Go test file like the one provided.
这是 `go/src/math/big/float_test.go` 文件的一部分，主要功能是测试 `math/big` 包中 `Float` 类型的各种方法和功能。 这是该测试文件的第二部分，让我们归纳一下这部分代码的功能。

**归纳一下这部分代码的功能:**

这部分代码主要集中在测试 `math/big.Float` 类型的一些核心算术运算和属性操作，包括：

1. **`Rat()` 方法测试:**  验证将 `Float` 类型转换为 `Rat` (有理数) 类型的正确性，包括精度和 `Accuracy` 信息的校验，以及反向转换的测试。
2. **`Abs()` 方法测试:**  测试计算 `Float` 类型数值的绝对值的功能，包括正数、负数、零和无穷大的情况。
3. **`Neg()` 方法测试:**  测试计算 `Float` 类型数值的相反数的功能。
4. **`Inc()` 方法测试:**  一个简单的递增测试，验证在一定精度下重复加 1 的正确性。
5. **`Add()` 和 `Sub()` 方法的全面测试:**
    * 通过比较手动计算（使用 `Bits` 类型表示浮点数）的结果与 `Float.Add`/`Float.Sub` 的结果，来测试加法和减法的正确性，并覆盖不同的精度和舍入模式。
    * 特别测试了结果为精确零时的舍入行为。
    * 针对 `float32` 和 `float64` 的精度，测试 `Float.Add`/`Float.Sub` 是否与标准浮点数运算行为一致。
    * 包含一个针对特定 issue (#20490) 的回归测试。
6. **`Mul()` 和 `Quo()` 方法的全面测试:**
    * 类似于 `Add`/`Sub` 的测试方法，通过比较手动计算的结果与 `Float.Mul`/`Float.Quo` 的结果，来测试乘法和除法的正确性，并覆盖不同的精度和舍入模式。
    * 针对 `float64` 的精度，测试 `Float.Mul`/`Float.Quo` 是否与标准浮点数运算行为一致。
    * 包含一个针对特定 issue (#6866) 的回归测试。
7. **`Quo()` 方法的更深入测试:**
    * 通过构造精确的被除数和除数，并在不同的精度和舍入模式下测试除法的结果。
    * 包含一个使用随机数进行大规模测试的 `TestFloatQuoSmoke` 函数（可以通过命令行参数 `--long` 启用更长时间的测试）。
8. **特殊值算术运算测试:**  测试 `Float` 类型在处理零（正负零）、有限值（正负 1 和正负 2.71828）以及无穷大（正负无穷大）时的算术运算行为是否符合预期。
9. **算术运算溢出测试:**  测试 `Float` 类型在进行加、减、乘、除运算时，当结果发生上溢或下溢时的行为，包括不同的精度和舍入模式下的情况。
10. **算术运算舍入测试:**  针对特定的舍入模式（`ToNegativeInf` 和 `ToPositiveInf`），测试舍入操作是否在设置结果符号之后进行，以确保结果的正确性。
11. **`Cmp()` 方法的特殊值测试:** 测试 `Float.Cmp()` 方法在比较零、有限值和无穷大时的行为是否正确。
12. **性能基准测试:** 包含 `BenchmarkFloatAdd` 和 `BenchmarkFloatSub` 两个基准测试，用于评估 `Float` 类型的加法和减法运算的性能。

总而言之，这部分代码通过大量的测试用例，细致地检验了 `math/big.Float` 类型的基本算术运算的正确性、在不同精度和舍入模式下的行为、以及对特殊值的处理能力，确保了 `Float` 类型作为任意精度浮点数实现的可靠性。

Prompt: 
```
这是路径为go/src/math/big/float_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
52", Exact},
	} {
		x := makeFloat(test.x).SetPrec(64)
		res, acc := x.Rat(nil)
		got := "nil"
		if res != nil {
			got = res.String()
		}
		if got != test.want {
			t.Errorf("%s: got %s; want %s", test.x, got, test.want)
			continue
		}
		if acc != test.acc {
			t.Errorf("%s: got %s; want %s", test.x, acc, test.acc)
			continue
		}

		// inverse conversion
		if res != nil {
			got := new(Float).SetPrec(64).SetRat(res)
			if got.Cmp(x) != 0 {
				t.Errorf("%s: got %s; want %s", test.x, got, x)
			}
		}
	}

	// check that supplied *Rat is used
	for _, f := range []string{"0", "1", "-1", "1234"} {
		x := makeFloat(f)
		r := new(Rat)
		if res, _ := x.Rat(r); res != r {
			t.Errorf("(%s).Rat is not using supplied *Rat", f)
		}
	}
}

func TestFloatAbs(t *testing.T) {
	for _, test := range []string{
		"0",
		"1",
		"1234",
		"1.23e-2",
		"1e-1000",
		"1e1000",
		"Inf",
	} {
		p := makeFloat(test)
		a := new(Float).Abs(p)
		if !alike(a, p) {
			t.Errorf("%s: got %s; want %s", test, a.Text('g', 10), test)
		}

		n := makeFloat("-" + test)
		a.Abs(n)
		if !alike(a, p) {
			t.Errorf("-%s: got %s; want %s", test, a.Text('g', 10), test)
		}
	}
}

func TestFloatNeg(t *testing.T) {
	for _, test := range []string{
		"0",
		"1",
		"1234",
		"1.23e-2",
		"1e-1000",
		"1e1000",
		"Inf",
	} {
		p1 := makeFloat(test)
		n1 := makeFloat("-" + test)
		n2 := new(Float).Neg(p1)
		p2 := new(Float).Neg(n2)
		if !alike(n2, n1) {
			t.Errorf("%s: got %s; want %s", test, n2.Text('g', 10), n1.Text('g', 10))
		}
		if !alike(p2, p1) {
			t.Errorf("%s: got %s; want %s", test, p2.Text('g', 10), p1.Text('g', 10))
		}
	}
}

func TestFloatInc(t *testing.T) {
	const n = 10
	for _, prec := range precList {
		if 1<<prec < n {
			continue // prec must be large enough to hold all numbers from 0 to n
		}
		var x, one Float
		x.SetPrec(prec)
		one.SetInt64(1)
		for i := 0; i < n; i++ {
			x.Add(&x, &one)
		}
		if x.Cmp(new(Float).SetInt64(n)) != 0 {
			t.Errorf("prec = %d: got %s; want %d", prec, &x, n)
		}
	}
}

// Selected precisions with which to run various tests.
var precList = [...]uint{1, 2, 5, 8, 10, 16, 23, 24, 32, 50, 53, 64, 100, 128, 500, 511, 512, 513, 1000, 10000}

// Selected bits with which to run various tests.
// Each entry is a list of bits representing a floating-point number (see fromBits).
var bitsList = [...]Bits{
	{},           // = 0
	{0},          // = 1
	{1},          // = 2
	{-1},         // = 1/2
	{10},         // = 2**10 == 1024
	{-10},        // = 2**-10 == 1/1024
	{100, 10, 1}, // = 2**100 + 2**10 + 2**1
	{0, -1, -2, -10},
	// TODO(gri) add more test cases
}

// TestFloatAdd tests Float.Add/Sub by comparing the result of a "manual"
// addition/subtraction of arguments represented by Bits values with the
// respective Float addition/subtraction for a variety of precisions
// and rounding modes.
func TestFloatAdd(t *testing.T) {
	for _, xbits := range bitsList {
		for _, ybits := range bitsList {
			// exact values
			x := xbits.Float()
			y := ybits.Float()
			zbits := xbits.add(ybits)
			z := zbits.Float()

			for i, mode := range [...]RoundingMode{ToZero, ToNearestEven, AwayFromZero} {
				for _, prec := range precList {
					got := new(Float).SetPrec(prec).SetMode(mode)
					got.Add(x, y)
					want := zbits.round(prec, mode)
					if got.Cmp(want) != 0 {
						t.Errorf("i = %d, prec = %d, %s:\n\t     %s %v\n\t+    %s %v\n\t=    %s\n\twant %s",
							i, prec, mode, x, xbits, y, ybits, got, want)
					}

					got.Sub(z, x)
					want = ybits.round(prec, mode)
					if got.Cmp(want) != 0 {
						t.Errorf("i = %d, prec = %d, %s:\n\t     %s %v\n\t-    %s %v\n\t=    %s\n\twant %s",
							i, prec, mode, z, zbits, x, xbits, got, want)
					}
				}
			}
		}
	}
}

// TestFloatAddRoundZero tests Float.Add/Sub rounding when the result is exactly zero.
// x + (-x) or x - x for non-zero x should be +0 in all cases except when
// the rounding mode is ToNegativeInf in which case it should be -0.
func TestFloatAddRoundZero(t *testing.T) {
	for _, mode := range [...]RoundingMode{ToNearestEven, ToNearestAway, ToZero, AwayFromZero, ToPositiveInf, ToNegativeInf} {
		x := NewFloat(5.0)
		y := new(Float).Neg(x)
		want := NewFloat(0.0)
		if mode == ToNegativeInf {
			want.Neg(want)
		}
		got := new(Float).SetMode(mode)
		got.Add(x, y)
		if got.Cmp(want) != 0 || got.neg != (mode == ToNegativeInf) {
			t.Errorf("%s:\n\t     %v\n\t+    %v\n\t=    %v\n\twant %v",
				mode, x, y, got, want)
		}
		got.Sub(x, x)
		if got.Cmp(want) != 0 || got.neg != (mode == ToNegativeInf) {
			t.Errorf("%v:\n\t     %v\n\t-    %v\n\t=    %v\n\twant %v",
				mode, x, x, got, want)
		}
	}
}

// TestFloatAdd32 tests that Float.Add/Sub of numbers with
// 24bit mantissa behaves like float32 addition/subtraction
// (excluding denormal numbers).
func TestFloatAdd32(t *testing.T) {
	// chose base such that we cross the mantissa precision limit
	const base = 1<<26 - 0x10 // 11...110000 (26 bits)
	for d := 0; d <= 0x10; d++ {
		for i := range [2]int{} {
			x0, y0 := float64(base), float64(d)
			if i&1 != 0 {
				x0, y0 = y0, x0
			}

			x := NewFloat(x0)
			y := NewFloat(y0)
			z := new(Float).SetPrec(24)

			z.Add(x, y)
			got, acc := z.Float32()
			want := float32(y0) + float32(x0)
			if got != want || acc != Exact {
				t.Errorf("d = %d: %g + %g = %g (%s); want %g (Exact)", d, x0, y0, got, acc, want)
			}

			z.Sub(z, y)
			got, acc = z.Float32()
			want = float32(want) - float32(y0)
			if got != want || acc != Exact {
				t.Errorf("d = %d: %g - %g = %g (%s); want %g (Exact)", d, x0+y0, y0, got, acc, want)
			}
		}
	}
}

// TestFloatAdd64 tests that Float.Add/Sub of numbers with
// 53bit mantissa behaves like float64 addition/subtraction.
func TestFloatAdd64(t *testing.T) {
	// chose base such that we cross the mantissa precision limit
	const base = 1<<55 - 0x10 // 11...110000 (55 bits)
	for d := 0; d <= 0x10; d++ {
		for i := range [2]int{} {
			x0, y0 := float64(base), float64(d)
			if i&1 != 0 {
				x0, y0 = y0, x0
			}

			x := NewFloat(x0)
			y := NewFloat(y0)
			z := new(Float).SetPrec(53)

			z.Add(x, y)
			got, acc := z.Float64()
			want := x0 + y0
			if got != want || acc != Exact {
				t.Errorf("d = %d: %g + %g = %g (%s); want %g (Exact)", d, x0, y0, got, acc, want)
			}

			z.Sub(z, y)
			got, acc = z.Float64()
			want -= y0
			if got != want || acc != Exact {
				t.Errorf("d = %d: %g - %g = %g (%s); want %g (Exact)", d, x0+y0, y0, got, acc, want)
			}
		}
	}
}

func TestIssue20490(t *testing.T) {
	var tests = []struct {
		a, b float64
	}{
		{4, 1},
		{-4, 1},
		{4, -1},
		{-4, -1},
	}

	for _, test := range tests {
		a, b := NewFloat(test.a), NewFloat(test.b)
		diff := new(Float).Sub(a, b)
		b.Sub(a, b)
		if b.Cmp(diff) != 0 {
			t.Errorf("got %g - %g = %g; want %g\n", a, NewFloat(test.b), b, diff)
		}

		b = NewFloat(test.b)
		sum := new(Float).Add(a, b)
		b.Add(a, b)
		if b.Cmp(sum) != 0 {
			t.Errorf("got %g + %g = %g; want %g\n", a, NewFloat(test.b), b, sum)
		}

	}
}

// TestFloatMul tests Float.Mul/Quo by comparing the result of a "manual"
// multiplication/division of arguments represented by Bits values with the
// respective Float multiplication/division for a variety of precisions
// and rounding modes.
func TestFloatMul(t *testing.T) {
	for _, xbits := range bitsList {
		for _, ybits := range bitsList {
			// exact values
			x := xbits.Float()
			y := ybits.Float()
			zbits := xbits.mul(ybits)
			z := zbits.Float()

			for i, mode := range [...]RoundingMode{ToZero, ToNearestEven, AwayFromZero} {
				for _, prec := range precList {
					got := new(Float).SetPrec(prec).SetMode(mode)
					got.Mul(x, y)
					want := zbits.round(prec, mode)
					if got.Cmp(want) != 0 {
						t.Errorf("i = %d, prec = %d, %s:\n\t     %v %v\n\t*    %v %v\n\t=    %v\n\twant %v",
							i, prec, mode, x, xbits, y, ybits, got, want)
					}

					if x.Sign() == 0 {
						continue // ignore div-0 case (not invertable)
					}
					got.Quo(z, x)
					want = ybits.round(prec, mode)
					if got.Cmp(want) != 0 {
						t.Errorf("i = %d, prec = %d, %s:\n\t     %v %v\n\t/    %v %v\n\t=    %v\n\twant %v",
							i, prec, mode, z, zbits, x, xbits, got, want)
					}
				}
			}
		}
	}
}

// TestFloatMul64 tests that Float.Mul/Quo of numbers with
// 53bit mantissa behaves like float64 multiplication/division.
func TestFloatMul64(t *testing.T) {
	for _, test := range []struct {
		x, y float64
	}{
		{0, 0},
		{0, 1},
		{1, 1},
		{1, 1.5},
		{1.234, 0.5678},
		{2.718281828, 3.14159265358979},
		{2.718281828e10, 3.14159265358979e-32},
		{1.0 / 3, 1e200},
	} {
		for i := range [8]int{} {
			x0, y0 := test.x, test.y
			if i&1 != 0 {
				x0 = -x0
			}
			if i&2 != 0 {
				y0 = -y0
			}
			if i&4 != 0 {
				x0, y0 = y0, x0
			}

			x := NewFloat(x0)
			y := NewFloat(y0)
			z := new(Float).SetPrec(53)

			z.Mul(x, y)
			got, _ := z.Float64()
			want := x0 * y0
			if got != want {
				t.Errorf("%g * %g = %g; want %g", x0, y0, got, want)
			}

			if y0 == 0 {
				continue // avoid division-by-zero
			}
			z.Quo(z, y)
			got, _ = z.Float64()
			want /= y0
			if got != want {
				t.Errorf("%g / %g = %g; want %g", x0*y0, y0, got, want)
			}
		}
	}
}

func TestIssue6866(t *testing.T) {
	for _, prec := range precList {
		two := new(Float).SetPrec(prec).SetInt64(2)
		one := new(Float).SetPrec(prec).SetInt64(1)
		three := new(Float).SetPrec(prec).SetInt64(3)
		msix := new(Float).SetPrec(prec).SetInt64(-6)
		psix := new(Float).SetPrec(prec).SetInt64(+6)

		p := new(Float).SetPrec(prec)
		z1 := new(Float).SetPrec(prec)
		z2 := new(Float).SetPrec(prec)

		// z1 = 2 + 1.0/3*-6
		p.Quo(one, three)
		p.Mul(p, msix)
		z1.Add(two, p)

		// z2 = 2 - 1.0/3*+6
		p.Quo(one, three)
		p.Mul(p, psix)
		z2.Sub(two, p)

		if z1.Cmp(z2) != 0 {
			t.Fatalf("prec %d: got z1 = %v != z2 = %v; want z1 == z2\n", prec, z1, z2)
		}
		if z1.Sign() != 0 {
			t.Errorf("prec %d: got z1 = %v; want 0", prec, z1)
		}
		if z2.Sign() != 0 {
			t.Errorf("prec %d: got z2 = %v; want 0", prec, z2)
		}
	}
}

func TestFloatQuo(t *testing.T) {
	// TODO(gri) make the test vary these precisions
	preci := 200 // precision of integer part
	precf := 20  // precision of fractional part

	for i := 0; i < 8; i++ {
		// compute accurate (not rounded) result z
		bits := Bits{preci - 1}
		if i&3 != 0 {
			bits = append(bits, 0)
		}
		if i&2 != 0 {
			bits = append(bits, -1)
		}
		if i&1 != 0 {
			bits = append(bits, -precf)
		}
		z := bits.Float()

		// compute accurate x as z*y
		y := NewFloat(3.14159265358979323e123)

		x := new(Float).SetPrec(z.Prec() + y.Prec()).SetMode(ToZero)
		x.Mul(z, y)

		// leave for debugging
		// fmt.Printf("x = %s\ny = %s\nz = %s\n", x, y, z)

		if got := x.Acc(); got != Exact {
			t.Errorf("got acc = %s; want exact", got)
		}

		// round accurate z for a variety of precisions and
		// modes and compare against result of x / y.
		for _, mode := range [...]RoundingMode{ToZero, ToNearestEven, AwayFromZero} {
			for d := -5; d < 5; d++ {
				prec := uint(preci + d)
				got := new(Float).SetPrec(prec).SetMode(mode).Quo(x, y)
				want := bits.round(prec, mode)
				if got.Cmp(want) != 0 {
					t.Errorf("i = %d, prec = %d, %s:\n\t     %s\n\t/    %s\n\t=    %s\n\twant %s",
						i, prec, mode, x, y, got, want)
				}
			}
		}
	}
}

var long = flag.Bool("long", false, "run very long tests")

// TestFloatQuoSmoke tests all divisions x/y for values x, y in the range [-n, +n];
// it serves as a smoke test for basic correctness of division.
func TestFloatQuoSmoke(t *testing.T) {
	n := 10
	if *long {
		n = 1000
	}

	const dprec = 3         // max. precision variation
	const prec = 10 + dprec // enough bits to hold n precisely
	for x := -n; x <= n; x++ {
		for y := -n; y < n; y++ {
			if y == 0 {
				continue
			}

			a := float64(x)
			b := float64(y)
			c := a / b

			// vary operand precision (only ok as long as a, b can be represented correctly)
			for ad := -dprec; ad <= dprec; ad++ {
				for bd := -dprec; bd <= dprec; bd++ {
					A := new(Float).SetPrec(uint(prec + ad)).SetFloat64(a)
					B := new(Float).SetPrec(uint(prec + bd)).SetFloat64(b)
					C := new(Float).SetPrec(53).Quo(A, B) // C has float64 mantissa width

					cc, acc := C.Float64()
					if cc != c {
						t.Errorf("%g/%g = %s; want %.5g\n", a, b, C.Text('g', 5), c)
						continue
					}
					if acc != Exact {
						t.Errorf("%g/%g got %s result; want exact result", a, b, acc)
					}
				}
			}
		}
	}
}

// TestFloatArithmeticSpecialValues tests that Float operations produce the
// correct results for combinations of zero (±0), finite (±1 and ±2.71828),
// and infinite (±Inf) operands.
func TestFloatArithmeticSpecialValues(t *testing.T) {
	zero := 0.0
	args := []float64{math.Inf(-1), -2.71828, -1, -zero, zero, 1, 2.71828, math.Inf(1)}
	xx := new(Float)
	yy := new(Float)
	got := new(Float)
	want := new(Float)
	for i := 0; i < 4; i++ {
		for _, x := range args {
			xx.SetFloat64(x)
			// check conversion is correct
			// (no need to do this for y, since we see exactly the
			// same values there)
			if got, acc := xx.Float64(); got != x || acc != Exact {
				t.Errorf("Float(%g) == %g (%s)", x, got, acc)
			}
			for _, y := range args {
				yy.SetFloat64(y)
				var (
					op string
					z  float64
					f  func(z, x, y *Float) *Float
				)
				switch i {
				case 0:
					op = "+"
					z = x + y
					f = (*Float).Add
				case 1:
					op = "-"
					z = x - y
					f = (*Float).Sub
				case 2:
					op = "*"
					z = x * y
					f = (*Float).Mul
				case 3:
					op = "/"
					z = x / y
					f = (*Float).Quo
				default:
					panic("unreachable")
				}
				var errnan bool // set if execution of f panicked with ErrNaN
				// protect execution of f
				func() {
					defer func() {
						if p := recover(); p != nil {
							_ = p.(ErrNaN) // re-panic if not ErrNaN
							errnan = true
						}
					}()
					f(got, xx, yy)
				}()
				if math.IsNaN(z) {
					if !errnan {
						t.Errorf("%5g %s %5g = %5s; want ErrNaN panic", x, op, y, got)
					}
					continue
				}
				if errnan {
					t.Errorf("%5g %s %5g panicked with ErrNan; want %5s", x, op, y, want)
					continue
				}
				want.SetFloat64(z)
				if !alike(got, want) {
					t.Errorf("%5g %s %5g = %5s; want %5s", x, op, y, got, want)
				}
			}
		}
	}
}

func TestFloatArithmeticOverflow(t *testing.T) {
	for _, test := range []struct {
		prec       uint
		mode       RoundingMode
		op         byte
		x, y, want string
		acc        Accuracy
	}{
		{4, ToNearestEven, '+', "0", "0", "0", Exact},                   // smoke test
		{4, ToNearestEven, '+', "0x.8p+0", "0x.8p+0", "0x.8p+1", Exact}, // smoke test

		{4, ToNearestEven, '+', "0", "0x.8p2147483647", "0x.8p+2147483647", Exact},
		{4, ToNearestEven, '+', "0x.8p2147483500", "0x.8p2147483647", "0x.8p+2147483647", Below}, // rounded to zero
		{4, ToNearestEven, '+', "0x.8p2147483647", "0x.8p2147483647", "+Inf", Above},             // exponent overflow in +
		{4, ToNearestEven, '+', "-0x.8p2147483647", "-0x.8p2147483647", "-Inf", Below},           // exponent overflow in +
		{4, ToNearestEven, '-', "-0x.8p2147483647", "0x.8p2147483647", "-Inf", Below},            // exponent overflow in -

		{4, ToZero, '+', "0x.fp2147483647", "0x.8p2147483643", "0x.fp+2147483647", Below}, // rounded to zero
		{4, ToNearestEven, '+', "0x.fp2147483647", "0x.8p2147483643", "+Inf", Above},      // exponent overflow in rounding
		{4, AwayFromZero, '+', "0x.fp2147483647", "0x.8p2147483643", "+Inf", Above},       // exponent overflow in rounding

		{4, AwayFromZero, '-', "-0x.fp2147483647", "0x.8p2147483644", "-Inf", Below},        // exponent overflow in rounding
		{4, ToNearestEven, '-', "-0x.fp2147483647", "0x.8p2147483643", "-Inf", Below},       // exponent overflow in rounding
		{4, ToZero, '-', "-0x.fp2147483647", "0x.8p2147483643", "-0x.fp+2147483647", Above}, // rounded to zero

		{4, ToNearestEven, '+', "0", "0x.8p-2147483648", "0x.8p-2147483648", Exact},
		{4, ToNearestEven, '+', "0x.8p-2147483648", "0x.8p-2147483648", "0x.8p-2147483647", Exact},

		{4, ToNearestEven, '*', "1", "0x.8p2147483647", "0x.8p+2147483647", Exact},
		{4, ToNearestEven, '*', "2", "0x.8p2147483647", "+Inf", Above},  // exponent overflow in *
		{4, ToNearestEven, '*', "-2", "0x.8p2147483647", "-Inf", Below}, // exponent overflow in *

		{4, ToNearestEven, '/', "0.5", "0x.8p2147483647", "0x.8p-2147483646", Exact},
		{4, ToNearestEven, '/', "0x.8p+0", "0x.8p2147483647", "0x.8p-2147483646", Exact},
		{4, ToNearestEven, '/', "0x.8p-1", "0x.8p2147483647", "0x.8p-2147483647", Exact},
		{4, ToNearestEven, '/', "0x.8p-2", "0x.8p2147483647", "0x.8p-2147483648", Exact},
		{4, ToNearestEven, '/', "0x.8p-3", "0x.8p2147483647", "0", Below}, // exponent underflow in /
	} {
		x := makeFloat(test.x)
		y := makeFloat(test.y)
		z := new(Float).SetPrec(test.prec).SetMode(test.mode)
		switch test.op {
		case '+':
			z.Add(x, y)
		case '-':
			z.Sub(x, y)
		case '*':
			z.Mul(x, y)
		case '/':
			z.Quo(x, y)
		default:
			panic("unreachable")
		}
		if got := z.Text('p', 0); got != test.want || z.Acc() != test.acc {
			t.Errorf(
				"prec = %d (%s): %s %c %s = %s (%s); want %s (%s)",
				test.prec, test.mode, x.Text('p', 0), test.op, y.Text('p', 0), got, z.Acc(), test.want, test.acc,
			)
		}
	}
}

// TODO(gri) Add tests that check correctness in the presence of aliasing.

// For rounding modes ToNegativeInf and ToPositiveInf, rounding is affected
// by the sign of the value to be rounded. Test that rounding happens after
// the sign of a result has been set.
// This test uses specific values that are known to fail if rounding is
// "factored" out before setting the result sign.
func TestFloatArithmeticRounding(t *testing.T) {
	for _, test := range []struct {
		mode       RoundingMode
		prec       uint
		x, y, want int64
		op         byte
	}{
		{ToZero, 3, -0x8, -0x1, -0x8, '+'},
		{AwayFromZero, 3, -0x8, -0x1, -0xa, '+'},
		{ToNegativeInf, 3, -0x8, -0x1, -0xa, '+'},

		{ToZero, 3, -0x8, 0x1, -0x8, '-'},
		{AwayFromZero, 3, -0x8, 0x1, -0xa, '-'},
		{ToNegativeInf, 3, -0x8, 0x1, -0xa, '-'},

		{ToZero, 3, -0x9, 0x1, -0x8, '*'},
		{AwayFromZero, 3, -0x9, 0x1, -0xa, '*'},
		{ToNegativeInf, 3, -0x9, 0x1, -0xa, '*'},

		{ToZero, 3, -0x9, 0x1, -0x8, '/'},
		{AwayFromZero, 3, -0x9, 0x1, -0xa, '/'},
		{ToNegativeInf, 3, -0x9, 0x1, -0xa, '/'},
	} {
		var x, y, z Float
		x.SetInt64(test.x)
		y.SetInt64(test.y)
		z.SetPrec(test.prec).SetMode(test.mode)
		switch test.op {
		case '+':
			z.Add(&x, &y)
		case '-':
			z.Sub(&x, &y)
		case '*':
			z.Mul(&x, &y)
		case '/':
			z.Quo(&x, &y)
		default:
			panic("unreachable")
		}
		if got, acc := z.Int64(); got != test.want || acc != Exact {
			t.Errorf("%s, %d bits: %d %c %d = %d (%s); want %d (Exact)",
				test.mode, test.prec, test.x, test.op, test.y, got, acc, test.want,
			)
		}
	}
}

// TestFloatCmpSpecialValues tests that Cmp produces the correct results for
// combinations of zero (±0), finite (±1 and ±2.71828), and infinite (±Inf)
// operands.
func TestFloatCmpSpecialValues(t *testing.T) {
	zero := 0.0
	args := []float64{math.Inf(-1), -2.71828, -1, -zero, zero, 1, 2.71828, math.Inf(1)}
	xx := new(Float)
	yy := new(Float)
	for i := 0; i < 4; i++ {
		for _, x := range args {
			xx.SetFloat64(x)
			// check conversion is correct
			// (no need to do this for y, since we see exactly the
			// same values there)
			if got, acc := xx.Float64(); got != x || acc != Exact {
				t.Errorf("Float(%g) == %g (%s)", x, got, acc)
			}
			for _, y := range args {
				yy.SetFloat64(y)
				got := xx.Cmp(yy)
				want := 0
				switch {
				case x < y:
					want = -1
				case x > y:
					want = +1
				}
				if got != want {
					t.Errorf("(%g).Cmp(%g) = %v; want %v", x, y, got, want)
				}
			}
		}
	}
}

func BenchmarkFloatAdd(b *testing.B) {
	x := new(Float)
	y := new(Float)
	z := new(Float)

	for _, prec := range []uint{10, 1e2, 1e3, 1e4, 1e5} {
		x.SetPrec(prec).SetRat(NewRat(1, 3))
		y.SetPrec(prec).SetRat(NewRat(1, 6))
		z.SetPrec(prec)

		b.Run(fmt.Sprintf("%v", prec), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				z.Add(x, y)
			}
		})
	}
}

func BenchmarkFloatSub(b *testing.B) {
	x := new(Float)
	y := new(Float)
	z := new(Float)

	for _, prec := range []uint{10, 1e2, 1e3, 1e4, 1e5} {
		x.SetPrec(prec).SetRat(NewRat(1, 3))
		y.SetPrec(prec).SetRat(NewRat(1, 6))
		z.SetPrec(prec)

		b.Run(fmt.Sprintf("%v", prec), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				z.Sub(x, y)
			}
		})
	}
}

"""




```