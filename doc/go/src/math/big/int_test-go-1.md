Response:
Let's break down the thought process for summarizing the provided Go code snippet, `int_test.go`.

1. **Understand the Context:** The prompt explicitly states this is part of the `go/src/math/big/int_test.go` file. This immediately tells us we're dealing with testing functionality for the `big.Int` type in Go's standard library. The "part 2 of 2" indicates this is the concluding portion of the file.

2. **Identify Key Functions and Data Structures:** Scan through the code, looking for:
    * Function definitions (starting with `func`). Notice names like `TestGcd`, `TestRsh`, `TestLsh`, `TestCmpAbs`, `TestInt64`, `TestUint64`, `TestBitwise`, `TestNot`, `TestModInverse`, `TestModSqrt`, `TestJacobi`, `TestSqrt`, `Benchmark...`, `testBitFun`, `testBitFunSelf`, `testBitset`, `testModSqrt`, `checkGcd`, etc.
    * Global variable declarations (starting with `var`). Observe `gcdTests`, `rshTests`, `lshTests`, `cmpAbsTests`, `int64Tests`, `uint64Tests`, `bitwiseTests`, `notTests`, `modInverseTests`, `tzbTests`, `bitsetTests`.
    * Struct definitions (starting with `type`). Spot `intShiftTest`.

3. **Group Related Tests:** Based on the function and variable names, group the tests by the functionality they are testing. For example:
    * `TestGcd`, `gcdTests`, `checkGcd`, `checkLehmerGcd`, `checkLehmerExtGcd` are clearly about Greatest Common Divisor (GCD).
    * `TestRsh`, `rshTests`, `TestRshSelf` deal with right bit shifts.
    * `TestLsh`, `lshTests`, `TestLshSelf` deal with left bit shifts.
    * `TestCmpAbs`, `cmpAbsTests`, `TestIntCmpSelf` are about comparing absolute values.
    * `TestInt64`, `int64Tests` and `TestUint64`, `uint64Tests` test conversion to/from 64-bit integers.
    * `TestBitwise`, `bitwiseTests`, `testBitFun`, `testBitFunSelf`, `testBitset`, `bitsetTests`, `TestBitSet`, `TestTrailingZeroBits`, `tzbTests` are focused on bitwise operations.
    * `TestNot`, `notTests` tests the bitwise NOT operation.
    * `TestModInverse`, `modInverseTests` checks modular inverse.
    * `TestModSqrt` tests modular square root.
    * `TestJacobi` tests the Jacobi symbol.
    * `TestSqrt` tests integer square root.
    * The `Benchmark...` functions are performance tests (benchmarks).

4. **Infer the Purpose of Helper Functions:** Notice functions like `testGcd`, `checkGcd`, `testBitFun`, `testBitset`, `testModSqrt`. These are clearly helper functions used to simplify and organize the test logic, often by iterating over test cases defined in the global variables.

5. **Identify Property-Based Testing:**  The lines using `quick.Check` (e.g., `quick.Check(checkGcd, nil)`) stand out. This indicates property-based testing, where the code is tested against a range of randomly generated inputs to ensure certain properties hold.

6. **Recognize Specific Test Cases:** The global `...Tests` variables are collections of specific input/output pairs designed to verify the correctness of the `big.Int` implementation for various edge cases and common scenarios.

7. **Summarize Each Group:**  For each group identified in step 3, write a concise description of its purpose. Focus on what aspect of `big.Int` it's testing.

8. **Synthesize an Overall Summary:** Combine the summaries of each group into a cohesive overview of the code's functionality. Emphasize that it's a test suite for `big.Int`.

9. **Refine and Organize:** Review the summary for clarity and conciseness. Group related functionalities together. Use clear and descriptive language. For instance, instead of saying "tests for Rsh and Lsh," say "Tests for bitwise right shift (Rsh) and left shift (Lsh) operations."

10. **Consider the "Part 2" Aspect:** Since the prompt mentions this is the second part, ensure the summary reflects the content *within this specific snippet*. It shouldn't try to cover functionality that might have been in "part 1".

By following these steps, you can systematically analyze the code and generate a comprehensive and accurate summary of its functionality, much like the example answer provided in the prompt. The key is to move from individual code elements to broader functional units and finally to an overall understanding of the code's role.
这是路径为go/src/math/big/int_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明,
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

这段代码是 Go 语言标准库 `math/big` 包中 `Int` 类型的测试代码的第二部分。它主要包含以下功能的测试：

1. **最大公约数 (GCD) 的测试 (`TestGcd`)**:
   - 测试了 `Int` 类型的 `GCD` 方法，用于计算两个数的最大公约数。
   - 使用了预定义的测试用例 (`gcdTests`) 和基于属性的快速测试 (`quick.Check`) 来验证 `GCD` 方法的正确性。
   - 包含了对普通 GCD 算法 (`checkGcd`) 和 Lehmer GCD 算法及其扩展形式 (`checkLehmerGcd`, `checkLehmerExtGcd`) 的测试。

   ```go
   // 假设 a = 12, b = 18
   a := big.NewInt(12)
   b := big.NewInt(18)
   gcd := big.NewInt(0)
   result := big.NewInt(0)
   result.GCD(nil, nil, a, b) // 计算 a 和 b 的 GCD，结果存储在 result 中
   // 预期 result 的值为 6
   ```

2. **位移操作的测试 (`TestRsh`, `TestRshSelf`, `TestLsh`, `TestLshSelf`, `TestLshRsh`)**:
   - 测试了 `Int` 类型的右移 (`Rsh`) 和左移 (`Lsh`) 方法。
   - `TestRsh` 和 `TestLsh` 测试了将一个 `Int` 值位移指定位数后得到的新值。
   - `TestRshSelf` 和 `TestLshSelf` 测试了原地进行位移操作。
   - `TestLshRsh` 测试了连续进行左移和右移操作后结果的正确性。
   - 使用预定义的测试用例 (`rshTests`, `lshTests`) 来覆盖不同的输入情况。

   ```go
   // 假设 in = 10 (二进制 1010), shift = 2
   in := big.NewInt(10)
   shift := uint(2)
   out := big.NewInt(0)

   out.Rsh(in, shift) // 将 in 右移 2 位，结果存储在 out 中
   // 预期 out 的值为 2 (二进制 10)

   out.Lsh(in, shift) // 将 in 左移 2 位，结果存储在 out 中
   // 预期 out 的值为 40 (二进制 101000)
   ```

3. **绝对值比较的测试 (`TestCmpAbs`)**:
   - 测试了 `Int` 类型的 `CmpAbs` 方法，用于比较两个 `Int` 值的绝对值大小。
   - 使用预定义的排序好的测试用例 (`cmpAbsTests`)，并遍历所有符号组合来确保比较的正确性。

   ```go
   // 假设 a = -5, b = 3
   a := big.NewInt(-5)
   b := big.NewInt(3)

   result := a.CmpAbs(b) // 比较 |a| 和 |b|
   // 预期 result 的值为 1，因为 |-5| > |3|

   result = b.CmpAbs(a) // 比较 |b| 和 |a|
   // 预期 result 的值为 -1，因为 |3| < |-5|
   ```

4. **自身比较的测试 (`TestIntCmpSelf`)**:
   - 测试了 `Int` 类型的 `Cmp` 方法，用于比较一个 `Int` 值和自身是否相等。

   ```go
   // 假设 x = 10
   x := big.NewInt(10)
   result := x.Cmp(x)
   // 预期 result 的值为 0
   ```

5. **与 `int64` 和 `uint64` 互操作的测试 (`TestInt64`, `TestUint64`)**:
   - 测试了 `Int` 类型与 `int64` 和 `uint64` 之间的转换方法 (`IsInt64`, `Int64`, `IsUint64`, `Uint64`)。
   - 使用预定义的测试用例 (`int64Tests`, `uint64Tests`) 来覆盖各种边界情况。

   ```go
   // 假设 x 是一个可以表示为 int64 的大整数
   x := big.NewInt(9223372036854775807)
   isInt64 := x.IsInt64() // 检查 x 是否可以表示为 int64
   // 预期 isInt64 为 true
   int64Value := x.Int64() // 获取 x 的 int64 值
   // 预期 int64Value 为 9223372036854775807

   // 假设 y 是一个无法表示为 int64 的大整数
   y := new(big.Int).SetString("9223372036854775808", 10)
   isUint64 := y.IsUint64() // 检查 y 是否可以表示为 uint64
   // 预期 isUint64 为 true
   uint64Value := y.Uint64() // 获取 y 的 uint64 值
   // 预期 uint64Value 为 9223372036854775808
   ```

6. **位运算的测试 (`TestBitwise`)**:
   - 测试了 `Int` 类型的位运算方法，包括与 (`And`)、或 (`Or`)、异或 (`Xor`) 和与非 (`AndNot`)。
   - 使用预定义的测试用例 (`bitwiseTests`) 和辅助函数 (`testBitFun`, `testBitFunSelf`) 来验证结果。

   ```go
   // 假设 x = 0x05 (二进制 0101), y = 0x0F (二进制 1111)
   x := new(big.Int).SetString("05", 16)
   y := new(big.Int).SetString("0F", 16)
   result := big.NewInt(0)

   result.And(x, y) // 计算 x & y，结果存储在 result 中
   // 预期 result 的值为 0x05 (二进制 0101)

   result.Or(x, y)  // 计算 x | y，结果存储在 result 中
   // 预期 result 的值为 0x0F (二进制 1111)

   result.Xor(x, y) // 计算 x ^ y，结果存储在 result 中
   // 预期 result 的值为 0x0A (二进制 1010)

   result.AndNot(x, y) // 计算 x &^ y，结果存储在 result 中
   // 预期 result 的值为 0x00 (二进制 0000)
   ```

7. **按位取反的测试 (`TestNot`)**:
   - 测试了 `Int` 类型的按位取反方法 (`Not`)。

   ```go
   // 假设 in = 7 (二进制 ...00000111)
   in := big.NewInt(7)
   out := big.NewInt(0)
   out.Not(in) // 计算 ^in，结果存储在 out 中
   // 预期 out 的值为 -8 (二进制 ...11111000，取决于机器的字长和表示)
   ```

8. **模逆元的测试 (`TestModInverse`)**:
   - 测试了 `Int` 类型的模逆元方法 (`ModInverse`)。

   ```go
   // 假设 element = 3, modulus = 7
   element := big.NewInt(3)
   modulus := big.NewInt(7)
   inverse := big.NewInt(0)
   inverse.ModInverse(element, modulus)
   // 预期 inverse 的值为 5，因为 (3 * 5) % 7 = 1
   ```

9. **模平方根的测试 (`TestModSqrt`)**:
   - 测试了 `Int` 类型的模平方根方法 (`ModSqrt`)。

   ```go
   // 假设 sq = 4, mod = 7
   sq := big.NewInt(4)
   mod := big.NewInt(7)
   sqrt := big.NewInt(0)
   sqrt.ModSqrt(sq, mod)
   // 预期 sqrt 的值为 2 或 5，因为 (2 * 2) % 7 = 4 且 (5 * 5) % 7 = 4
   ```

10. **雅可比符号的测试 (`TestJacobi`, `TestJacobiPanic`)**:
    - 测试了计算雅可比符号的函数 `Jacobi`。
    - `TestJacobiPanic` 检查了当第二个参数为偶数时是否会发生 panic。

   ```go
   // 假设 x = 3, y = 5
   x := big.NewInt(3)
   y := big.NewInt(5)
   result := big.Jacobi(x, y)
   // 预期 result 的值为 -1
   ```

11. **平方根的测试 (`TestSqrt`)**:
    - 测试了 `Int` 类型的整数平方根方法 (`Sqrt`)。

   ```go
   // 假设 n = 16
   n := big.NewInt(16)
   r := big.NewInt(0)
   r.Sqrt(n)
   // 预期 r 的值为 4
   ```

12. **性能测试 (Benchmarks)**:
    - 代码中包含了一些以 `Benchmark` 开头的函数，例如 `BenchmarkBitset`, `BenchmarkModSqrt...`, `BenchmarkDiv`, `BenchmarkSqrt`, `BenchmarkIntSqr`, `BenchmarkModInverse` 等，用于评估各种 `Int` 类型操作的性能。这些通常使用 `go test -bench=.` 命令来运行。

13. **位操作的更细致测试 (`TestBitSet`, `TestTrailingZeroBits`)**:
    - `TestBitSet` 测试了设置和获取特定位的值 (`SetBit`, `Bit`)。
    - `TestTrailingZeroBits` 测试了计算尾部零位的数量。

14. **字节填充测试 (`TestFillBytes`)**:
    - 测试了将 `Int` 的值填充到字节切片中的功能 (`FillBytes`)。

15. **从 `int64` 创建 `Int` 的测试 (`TestNewIntMinInt64`)**:
    - 特别测试了使用 `math.MinInt64` 作为参数创建 `Int` 的情况。

16. **内存分配测试 (`TestNewIntAllocs`)**:
    - 使用 `testing.AllocsPerRun` 来检查 `NewInt` 函数在某些场景下的内存分配情况，目标是优化性能，避免不必要的堆分配。

17. **转换为 `float64` 的测试 (`TestFloat64`)**:
    - 测试了 `Int` 类型转换为 `float64` 的方法 (`Float64`)，并检查转换的精度 (`Accuracy`)。

**归纳一下它的功能：**

这段 `int_test.go` 代码的主要功能是 **全面测试 `math/big` 包中 `Int` 类型的各种算术和位运算方法**。它通过大量的预定义测试用例、基于属性的随机测试以及性能测试，来确保 `Int` 类型的实现符合预期，能够正确处理各种数值和操作，并且具有良好的性能。这部分测试覆盖了 GCD 计算、位移操作、比较操作、与基本整型类型的转换、位运算、模运算、平方根计算以及转换为浮点数等多个关键功能点。

Prompt: 
```
这是路径为go/src/math/big/int_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
 x, y, a, b, a2, y)
	}
}

func TestGcd(t *testing.T) {
	for _, test := range gcdTests {
		d, _ := new(Int).SetString(test.d, 0)
		x, _ := new(Int).SetString(test.x, 0)
		y, _ := new(Int).SetString(test.y, 0)
		a, _ := new(Int).SetString(test.a, 0)
		b, _ := new(Int).SetString(test.b, 0)

		testGcd(t, d, nil, nil, a, b)
		testGcd(t, d, x, nil, a, b)
		testGcd(t, d, nil, y, a, b)
		testGcd(t, d, x, y, a, b)
	}

	if err := quick.Check(checkGcd, nil); err != nil {
		t.Error(err)
	}

	if err := quick.Check(checkLehmerGcd, nil); err != nil {
		t.Error(err)
	}

	if err := quick.Check(checkLehmerExtGcd, nil); err != nil {
		t.Error(err)
	}
}

type intShiftTest struct {
	in    string
	shift uint
	out   string
}

var rshTests = []intShiftTest{
	{"0", 0, "0"},
	{"-0", 0, "0"},
	{"0", 1, "0"},
	{"0", 2, "0"},
	{"1", 0, "1"},
	{"1", 1, "0"},
	{"1", 2, "0"},
	{"2", 0, "2"},
	{"2", 1, "1"},
	{"-1", 0, "-1"},
	{"-1", 1, "-1"},
	{"-1", 10, "-1"},
	{"-100", 2, "-25"},
	{"-100", 3, "-13"},
	{"-100", 100, "-1"},
	{"4294967296", 0, "4294967296"},
	{"4294967296", 1, "2147483648"},
	{"4294967296", 2, "1073741824"},
	{"18446744073709551616", 0, "18446744073709551616"},
	{"18446744073709551616", 1, "9223372036854775808"},
	{"18446744073709551616", 2, "4611686018427387904"},
	{"18446744073709551616", 64, "1"},
	{"340282366920938463463374607431768211456", 64, "18446744073709551616"},
	{"340282366920938463463374607431768211456", 128, "1"},
}

func TestRsh(t *testing.T) {
	for i, test := range rshTests {
		in, _ := new(Int).SetString(test.in, 10)
		expected, _ := new(Int).SetString(test.out, 10)
		out := new(Int).Rsh(in, test.shift)

		if !isNormalized(out) {
			t.Errorf("#%d: %v is not normalized", i, *out)
		}
		if out.Cmp(expected) != 0 {
			t.Errorf("#%d: got %s want %s", i, out, expected)
		}
	}
}

func TestRshSelf(t *testing.T) {
	for i, test := range rshTests {
		z, _ := new(Int).SetString(test.in, 10)
		expected, _ := new(Int).SetString(test.out, 10)
		z.Rsh(z, test.shift)

		if !isNormalized(z) {
			t.Errorf("#%d: %v is not normalized", i, *z)
		}
		if z.Cmp(expected) != 0 {
			t.Errorf("#%d: got %s want %s", i, z, expected)
		}
	}
}

var lshTests = []intShiftTest{
	{"0", 0, "0"},
	{"0", 1, "0"},
	{"0", 2, "0"},
	{"1", 0, "1"},
	{"1", 1, "2"},
	{"1", 2, "4"},
	{"2", 0, "2"},
	{"2", 1, "4"},
	{"2", 2, "8"},
	{"-87", 1, "-174"},
	{"4294967296", 0, "4294967296"},
	{"4294967296", 1, "8589934592"},
	{"4294967296", 2, "17179869184"},
	{"18446744073709551616", 0, "18446744073709551616"},
	{"9223372036854775808", 1, "18446744073709551616"},
	{"4611686018427387904", 2, "18446744073709551616"},
	{"1", 64, "18446744073709551616"},
	{"18446744073709551616", 64, "340282366920938463463374607431768211456"},
	{"1", 128, "340282366920938463463374607431768211456"},
}

func TestLsh(t *testing.T) {
	for i, test := range lshTests {
		in, _ := new(Int).SetString(test.in, 10)
		expected, _ := new(Int).SetString(test.out, 10)
		out := new(Int).Lsh(in, test.shift)

		if !isNormalized(out) {
			t.Errorf("#%d: %v is not normalized", i, *out)
		}
		if out.Cmp(expected) != 0 {
			t.Errorf("#%d: got %s want %s", i, out, expected)
		}
	}
}

func TestLshSelf(t *testing.T) {
	for i, test := range lshTests {
		z, _ := new(Int).SetString(test.in, 10)
		expected, _ := new(Int).SetString(test.out, 10)
		z.Lsh(z, test.shift)

		if !isNormalized(z) {
			t.Errorf("#%d: %v is not normalized", i, *z)
		}
		if z.Cmp(expected) != 0 {
			t.Errorf("#%d: got %s want %s", i, z, expected)
		}
	}
}

func TestLshRsh(t *testing.T) {
	for i, test := range rshTests {
		in, _ := new(Int).SetString(test.in, 10)
		out := new(Int).Lsh(in, test.shift)
		out = out.Rsh(out, test.shift)

		if !isNormalized(out) {
			t.Errorf("#%d: %v is not normalized", i, *out)
		}
		if in.Cmp(out) != 0 {
			t.Errorf("#%d: got %s want %s", i, out, in)
		}
	}
	for i, test := range lshTests {
		in, _ := new(Int).SetString(test.in, 10)
		out := new(Int).Lsh(in, test.shift)
		out.Rsh(out, test.shift)

		if !isNormalized(out) {
			t.Errorf("#%d: %v is not normalized", i, *out)
		}
		if in.Cmp(out) != 0 {
			t.Errorf("#%d: got %s want %s", i, out, in)
		}
	}
}

// Entries must be sorted by value in ascending order.
var cmpAbsTests = []string{
	"0",
	"1",
	"2",
	"10",
	"10000000",
	"2783678367462374683678456387645876387564783686583485",
	"2783678367462374683678456387645876387564783686583486",
	"32957394867987420967976567076075976570670947609750670956097509670576075067076027578341538",
}

func TestCmpAbs(t *testing.T) {
	values := make([]*Int, len(cmpAbsTests))
	var prev *Int
	for i, s := range cmpAbsTests {
		x, ok := new(Int).SetString(s, 0)
		if !ok {
			t.Fatalf("SetString(%s, 0) failed", s)
		}
		if prev != nil && prev.Cmp(x) >= 0 {
			t.Fatal("cmpAbsTests entries not sorted in ascending order")
		}
		values[i] = x
		prev = x
	}

	for i, x := range values {
		for j, y := range values {
			// try all combinations of signs for x, y
			for k := 0; k < 4; k++ {
				var a, b Int
				a.Set(x)
				b.Set(y)
				if k&1 != 0 {
					a.Neg(&a)
				}
				if k&2 != 0 {
					b.Neg(&b)
				}

				got := a.CmpAbs(&b)
				want := 0
				switch {
				case i > j:
					want = 1
				case i < j:
					want = -1
				}
				if got != want {
					t.Errorf("absCmp |%s|, |%s|: got %d; want %d", &a, &b, got, want)
				}
			}
		}
	}
}

func TestIntCmpSelf(t *testing.T) {
	for _, s := range cmpAbsTests {
		x, ok := new(Int).SetString(s, 0)
		if !ok {
			t.Fatalf("SetString(%s, 0) failed", s)
		}
		got := x.Cmp(x)
		want := 0
		if got != want {
			t.Errorf("x = %s: x.Cmp(x): got %d; want %d", x, got, want)
		}
	}
}

var int64Tests = []string{
	// int64
	"0",
	"1",
	"-1",
	"4294967295",
	"-4294967295",
	"4294967296",
	"-4294967296",
	"9223372036854775807",
	"-9223372036854775807",
	"-9223372036854775808",

	// not int64
	"0x8000000000000000",
	"-0x8000000000000001",
	"38579843757496759476987459679745",
	"-38579843757496759476987459679745",
}

func TestInt64(t *testing.T) {
	for _, s := range int64Tests {
		var x Int
		_, ok := x.SetString(s, 0)
		if !ok {
			t.Errorf("SetString(%s, 0) failed", s)
			continue
		}

		want, err := strconv.ParseInt(s, 0, 64)
		if err != nil {
			if err.(*strconv.NumError).Err == strconv.ErrRange {
				if x.IsInt64() {
					t.Errorf("IsInt64(%s) succeeded unexpectedly", s)
				}
			} else {
				t.Errorf("ParseInt(%s) failed", s)
			}
			continue
		}

		if !x.IsInt64() {
			t.Errorf("IsInt64(%s) failed unexpectedly", s)
		}

		got := x.Int64()
		if got != want {
			t.Errorf("Int64(%s) = %d; want %d", s, got, want)
		}
	}
}

var uint64Tests = []string{
	// uint64
	"0",
	"1",
	"4294967295",
	"4294967296",
	"8589934591",
	"8589934592",
	"9223372036854775807",
	"9223372036854775808",
	"0x08000000000000000",

	// not uint64
	"0x10000000000000000",
	"-0x08000000000000000",
	"-1",
}

func TestUint64(t *testing.T) {
	for _, s := range uint64Tests {
		var x Int
		_, ok := x.SetString(s, 0)
		if !ok {
			t.Errorf("SetString(%s, 0) failed", s)
			continue
		}

		want, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			// check for sign explicitly (ErrRange doesn't cover signed input)
			if s[0] == '-' || err.(*strconv.NumError).Err == strconv.ErrRange {
				if x.IsUint64() {
					t.Errorf("IsUint64(%s) succeeded unexpectedly", s)
				}
			} else {
				t.Errorf("ParseUint(%s) failed", s)
			}
			continue
		}

		if !x.IsUint64() {
			t.Errorf("IsUint64(%s) failed unexpectedly", s)
		}

		got := x.Uint64()
		if got != want {
			t.Errorf("Uint64(%s) = %d; want %d", s, got, want)
		}
	}
}

var bitwiseTests = []struct {
	x, y                 string
	and, or, xor, andNot string
}{
	{"0x00", "0x00", "0x00", "0x00", "0x00", "0x00"},
	{"0x00", "0x01", "0x00", "0x01", "0x01", "0x00"},
	{"0x01", "0x00", "0x00", "0x01", "0x01", "0x01"},
	{"-0x01", "0x00", "0x00", "-0x01", "-0x01", "-0x01"},
	{"-0xaf", "-0x50", "-0xf0", "-0x0f", "0xe1", "0x41"},
	{"0x00", "-0x01", "0x00", "-0x01", "-0x01", "0x00"},
	{"0x01", "0x01", "0x01", "0x01", "0x00", "0x00"},
	{"-0x01", "-0x01", "-0x01", "-0x01", "0x00", "0x00"},
	{"0x07", "0x08", "0x00", "0x0f", "0x0f", "0x07"},
	{"0x05", "0x0f", "0x05", "0x0f", "0x0a", "0x00"},
	{"0xff", "-0x0a", "0xf6", "-0x01", "-0xf7", "0x09"},
	{"0x013ff6", "0x9a4e", "0x1a46", "0x01bffe", "0x01a5b8", "0x0125b0"},
	{"-0x013ff6", "0x9a4e", "0x800a", "-0x0125b2", "-0x01a5bc", "-0x01c000"},
	{"-0x013ff6", "-0x9a4e", "-0x01bffe", "-0x1a46", "0x01a5b8", "0x8008"},
	{
		"0x1000009dc6e3d9822cba04129bcbe3401",
		"0xb9bd7d543685789d57cb918e833af352559021483cdb05cc21fd",
		"0x1000001186210100001000009048c2001",
		"0xb9bd7d543685789d57cb918e8bfeff7fddb2ebe87dfbbdfe35fd",
		"0xb9bd7d543685789d57ca918e8ae69d6fcdb2eae87df2b97215fc",
		"0x8c40c2d8822caa04120b8321400",
	},
	{
		"0x1000009dc6e3d9822cba04129bcbe3401",
		"-0xb9bd7d543685789d57cb918e833af352559021483cdb05cc21fd",
		"0x8c40c2d8822caa04120b8321401",
		"-0xb9bd7d543685789d57ca918e82229142459020483cd2014001fd",
		"-0xb9bd7d543685789d57ca918e8ae69d6fcdb2eae87df2b97215fe",
		"0x1000001186210100001000009048c2000",
	},
	{
		"-0x1000009dc6e3d9822cba04129bcbe3401",
		"-0xb9bd7d543685789d57cb918e833af352559021483cdb05cc21fd",
		"-0xb9bd7d543685789d57cb918e8bfeff7fddb2ebe87dfbbdfe35fd",
		"-0x1000001186210100001000009048c2001",
		"0xb9bd7d543685789d57ca918e8ae69d6fcdb2eae87df2b97215fc",
		"0xb9bd7d543685789d57ca918e82229142459020483cd2014001fc",
	},
}

type bitFun func(z, x, y *Int) *Int

func testBitFun(t *testing.T, msg string, f bitFun, x, y *Int, exp string) {
	expected := new(Int)
	expected.SetString(exp, 0)

	out := f(new(Int), x, y)
	if out.Cmp(expected) != 0 {
		t.Errorf("%s: got %s want %s", msg, out, expected)
	}
}

func testBitFunSelf(t *testing.T, msg string, f bitFun, x, y *Int, exp string) {
	self := new(Int)
	self.Set(x)
	expected := new(Int)
	expected.SetString(exp, 0)

	self = f(self, self, y)
	if self.Cmp(expected) != 0 {
		t.Errorf("%s: got %s want %s", msg, self, expected)
	}
}

func altBit(x *Int, i int) uint {
	z := new(Int).Rsh(x, uint(i))
	z = z.And(z, NewInt(1))
	if z.Cmp(new(Int)) != 0 {
		return 1
	}
	return 0
}

func altSetBit(z *Int, x *Int, i int, b uint) *Int {
	one := NewInt(1)
	m := one.Lsh(one, uint(i))
	switch b {
	case 1:
		return z.Or(x, m)
	case 0:
		return z.AndNot(x, m)
	}
	panic("set bit is not 0 or 1")
}

func testBitset(t *testing.T, x *Int) {
	n := x.BitLen()
	z := new(Int).Set(x)
	z1 := new(Int).Set(x)
	for i := 0; i < n+10; i++ {
		old := z.Bit(i)
		old1 := altBit(z1, i)
		if old != old1 {
			t.Errorf("bitset: inconsistent value for Bit(%s, %d), got %v want %v", z1, i, old, old1)
		}
		z := new(Int).SetBit(z, i, 1)
		z1 := altSetBit(new(Int), z1, i, 1)
		if z.Bit(i) == 0 {
			t.Errorf("bitset: bit %d of %s got 0 want 1", i, x)
		}
		if z.Cmp(z1) != 0 {
			t.Errorf("bitset: inconsistent value after SetBit 1, got %s want %s", z, z1)
		}
		z.SetBit(z, i, 0)
		altSetBit(z1, z1, i, 0)
		if z.Bit(i) != 0 {
			t.Errorf("bitset: bit %d of %s got 1 want 0", i, x)
		}
		if z.Cmp(z1) != 0 {
			t.Errorf("bitset: inconsistent value after SetBit 0, got %s want %s", z, z1)
		}
		altSetBit(z1, z1, i, old)
		z.SetBit(z, i, old)
		if z.Cmp(z1) != 0 {
			t.Errorf("bitset: inconsistent value after SetBit old, got %s want %s", z, z1)
		}
	}
	if z.Cmp(x) != 0 {
		t.Errorf("bitset: got %s want %s", z, x)
	}
}

var bitsetTests = []struct {
	x string
	i int
	b uint
}{
	{"0", 0, 0},
	{"0", 200, 0},
	{"1", 0, 1},
	{"1", 1, 0},
	{"-1", 0, 1},
	{"-1", 200, 1},
	{"0x2000000000000000000000000000", 108, 0},
	{"0x2000000000000000000000000000", 109, 1},
	{"0x2000000000000000000000000000", 110, 0},
	{"-0x2000000000000000000000000001", 108, 1},
	{"-0x2000000000000000000000000001", 109, 0},
	{"-0x2000000000000000000000000001", 110, 1},
}

func TestBitSet(t *testing.T) {
	for _, test := range bitwiseTests {
		x := new(Int)
		x.SetString(test.x, 0)
		testBitset(t, x)
		x = new(Int)
		x.SetString(test.y, 0)
		testBitset(t, x)
	}
	for i, test := range bitsetTests {
		x := new(Int)
		x.SetString(test.x, 0)
		b := x.Bit(test.i)
		if b != test.b {
			t.Errorf("#%d got %v want %v", i, b, test.b)
		}
	}
	z := NewInt(1)
	z.SetBit(NewInt(0), 2, 1)
	if z.Cmp(NewInt(4)) != 0 {
		t.Errorf("destination leaked into result; got %s want 4", z)
	}
}

var tzbTests = []struct {
	in  string
	out uint
}{
	{"0", 0},
	{"1", 0},
	{"-1", 0},
	{"4", 2},
	{"-8", 3},
	{"0x4000000000000000000", 74},
	{"-0x8000000000000000000", 75},
}

func TestTrailingZeroBits(t *testing.T) {
	for i, test := range tzbTests {
		in, _ := new(Int).SetString(test.in, 0)
		want := test.out
		got := in.TrailingZeroBits()

		if got != want {
			t.Errorf("#%d: got %v want %v", i, got, want)
		}
	}
}

func BenchmarkBitset(b *testing.B) {
	z := new(Int)
	z.SetBit(z, 512, 1)
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		z.SetBit(z, i&512, 1)
	}
}

func BenchmarkBitsetNeg(b *testing.B) {
	z := NewInt(-1)
	z.SetBit(z, 512, 0)
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		z.SetBit(z, i&512, 0)
	}
}

func BenchmarkBitsetOrig(b *testing.B) {
	z := new(Int)
	altSetBit(z, z, 512, 1)
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		altSetBit(z, z, i&512, 1)
	}
}

func BenchmarkBitsetNegOrig(b *testing.B) {
	z := NewInt(-1)
	altSetBit(z, z, 512, 0)
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		altSetBit(z, z, i&512, 0)
	}
}

// tri generates the trinomial 2**(n*2) - 2**n - 1, which is always 3 mod 4 and
// 7 mod 8, so that 2 is always a quadratic residue.
func tri(n uint) *Int {
	x := NewInt(1)
	x.Lsh(x, n)
	x2 := new(Int).Lsh(x, n)
	x2.Sub(x2, x)
	x2.Sub(x2, intOne)
	return x2
}

func BenchmarkModSqrt225_Tonelli(b *testing.B) {
	p := tri(225)
	x := NewInt(2)
	for i := 0; i < b.N; i++ {
		x.SetUint64(2)
		x.modSqrtTonelliShanks(x, p)
	}
}

func BenchmarkModSqrt225_3Mod4(b *testing.B) {
	p := tri(225)
	x := new(Int).SetUint64(2)
	for i := 0; i < b.N; i++ {
		x.SetUint64(2)
		x.modSqrt3Mod4Prime(x, p)
	}
}

func BenchmarkModSqrt231_Tonelli(b *testing.B) {
	p := tri(231)
	p.Sub(p, intOne)
	p.Sub(p, intOne) // tri(231) - 2 is a prime == 5 mod 8
	x := new(Int).SetUint64(7)
	for i := 0; i < b.N; i++ {
		x.SetUint64(7)
		x.modSqrtTonelliShanks(x, p)
	}
}

func BenchmarkModSqrt231_5Mod8(b *testing.B) {
	p := tri(231)
	p.Sub(p, intOne)
	p.Sub(p, intOne) // tri(231) - 2 is a prime == 5 mod 8
	x := new(Int).SetUint64(7)
	for i := 0; i < b.N; i++ {
		x.SetUint64(7)
		x.modSqrt5Mod8Prime(x, p)
	}
}

func TestBitwise(t *testing.T) {
	x := new(Int)
	y := new(Int)
	for _, test := range bitwiseTests {
		x.SetString(test.x, 0)
		y.SetString(test.y, 0)

		testBitFun(t, "and", (*Int).And, x, y, test.and)
		testBitFunSelf(t, "and", (*Int).And, x, y, test.and)
		testBitFun(t, "andNot", (*Int).AndNot, x, y, test.andNot)
		testBitFunSelf(t, "andNot", (*Int).AndNot, x, y, test.andNot)
		testBitFun(t, "or", (*Int).Or, x, y, test.or)
		testBitFunSelf(t, "or", (*Int).Or, x, y, test.or)
		testBitFun(t, "xor", (*Int).Xor, x, y, test.xor)
		testBitFunSelf(t, "xor", (*Int).Xor, x, y, test.xor)
	}
}

var notTests = []struct {
	in  string
	out string
}{
	{"0", "-1"},
	{"1", "-2"},
	{"7", "-8"},
	{"0", "-1"},
	{"-81910", "81909"},
	{
		"298472983472983471903246121093472394872319615612417471234712061",
		"-298472983472983471903246121093472394872319615612417471234712062",
	},
}

func TestNot(t *testing.T) {
	in := new(Int)
	out := new(Int)
	expected := new(Int)
	for i, test := range notTests {
		in.SetString(test.in, 10)
		expected.SetString(test.out, 10)
		out = out.Not(in)
		if out.Cmp(expected) != 0 {
			t.Errorf("#%d: got %s want %s", i, out, expected)
		}
		out = out.Not(out)
		if out.Cmp(in) != 0 {
			t.Errorf("#%d: got %s want %s", i, out, in)
		}
	}
}

var modInverseTests = []struct {
	element string
	modulus string
}{
	{"1234567", "458948883992"},
	{"239487239847", "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919"},
	{"-10", "13"}, // issue #16984
	{"10", "-13"},
	{"-17", "-13"},
}

func TestModInverse(t *testing.T) {
	var element, modulus, gcd, inverse Int
	one := NewInt(1)
	for _, test := range modInverseTests {
		(&element).SetString(test.element, 10)
		(&modulus).SetString(test.modulus, 10)
		(&inverse).ModInverse(&element, &modulus)
		(&inverse).Mul(&inverse, &element)
		(&inverse).Mod(&inverse, &modulus)
		if (&inverse).Cmp(one) != 0 {
			t.Errorf("ModInverse(%d,%d)*%d%%%d=%d, not 1", &element, &modulus, &element, &modulus, &inverse)
		}
	}
	// exhaustive test for small values
	for n := 2; n < 100; n++ {
		(&modulus).SetInt64(int64(n))
		for x := 1; x < n; x++ {
			(&element).SetInt64(int64(x))
			(&gcd).GCD(nil, nil, &element, &modulus)
			if (&gcd).Cmp(one) != 0 {
				continue
			}
			(&inverse).ModInverse(&element, &modulus)
			(&inverse).Mul(&inverse, &element)
			(&inverse).Mod(&inverse, &modulus)
			if (&inverse).Cmp(one) != 0 {
				t.Errorf("ModInverse(%d,%d)*%d%%%d=%d, not 1", &element, &modulus, &element, &modulus, &inverse)
			}
		}
	}
}

func BenchmarkModInverse(b *testing.B) {
	p := new(Int).SetInt64(1) // Mersenne prime 2**1279 -1
	p.abs = p.abs.shl(p.abs, 1279)
	p.Sub(p, intOne)
	x := new(Int).Sub(p, intOne)
	z := new(Int)
	for i := 0; i < b.N; i++ {
		z.ModInverse(x, p)
	}
}

// testModSqrt is a helper for TestModSqrt,
// which checks that ModSqrt can compute a square-root of elt^2.
func testModSqrt(t *testing.T, elt, mod, sq, sqrt *Int) bool {
	var sqChk, sqrtChk, sqrtsq Int
	sq.Mul(elt, elt)
	sq.Mod(sq, mod)
	z := sqrt.ModSqrt(sq, mod)
	if z != sqrt {
		t.Errorf("ModSqrt returned wrong value %s", z)
	}

	// test ModSqrt arguments outside the range [0,mod)
	sqChk.Add(sq, mod)
	z = sqrtChk.ModSqrt(&sqChk, mod)
	if z != &sqrtChk || z.Cmp(sqrt) != 0 {
		t.Errorf("ModSqrt returned inconsistent value %s", z)
	}
	sqChk.Sub(sq, mod)
	z = sqrtChk.ModSqrt(&sqChk, mod)
	if z != &sqrtChk || z.Cmp(sqrt) != 0 {
		t.Errorf("ModSqrt returned inconsistent value %s", z)
	}

	// test x aliasing z
	z = sqrtChk.ModSqrt(sqrtChk.Set(sq), mod)
	if z != &sqrtChk || z.Cmp(sqrt) != 0 {
		t.Errorf("ModSqrt returned inconsistent value %s", z)
	}

	// make sure we actually got a square root
	if sqrt.Cmp(elt) == 0 {
		return true // we found the "desired" square root
	}
	sqrtsq.Mul(sqrt, sqrt) // make sure we found the "other" one
	sqrtsq.Mod(&sqrtsq, mod)
	return sq.Cmp(&sqrtsq) == 0
}

func TestModSqrt(t *testing.T) {
	var elt, mod, modx4, sq, sqrt Int
	r := rand.New(rand.NewSource(9))
	for i, s := range primes[1:] { // skip 2, use only odd primes
		mod.SetString(s, 10)
		modx4.Lsh(&mod, 2)

		// test a few random elements per prime
		for x := 1; x < 5; x++ {
			elt.Rand(r, &modx4)
			elt.Sub(&elt, &mod) // test range [-mod, 3*mod)
			if !testModSqrt(t, &elt, &mod, &sq, &sqrt) {
				t.Errorf("#%d: failed (sqrt(e) = %s)", i, &sqrt)
			}
		}

		if testing.Short() && i > 2 {
			break
		}
	}

	if testing.Short() {
		return
	}

	// exhaustive test for small values
	for n := 3; n < 100; n++ {
		mod.SetInt64(int64(n))
		if !mod.ProbablyPrime(10) {
			continue
		}
		isSquare := make([]bool, n)

		// test all the squares
		for x := 1; x < n; x++ {
			elt.SetInt64(int64(x))
			if !testModSqrt(t, &elt, &mod, &sq, &sqrt) {
				t.Errorf("#%d: failed (sqrt(%d,%d) = %s)", x, &elt, &mod, &sqrt)
			}
			isSquare[sq.Uint64()] = true
		}

		// test all non-squares
		for x := 1; x < n; x++ {
			sq.SetInt64(int64(x))
			z := sqrt.ModSqrt(&sq, &mod)
			if !isSquare[x] && z != nil {
				t.Errorf("#%d: failed (sqrt(%d,%d) = nil)", x, &sqrt, &mod)
			}
		}
	}
}

func TestJacobi(t *testing.T) {
	testCases := []struct {
		x, y   int64
		result int
	}{
		{0, 1, 1},
		{0, -1, 1},
		{1, 1, 1},
		{1, -1, 1},
		{0, 5, 0},
		{1, 5, 1},
		{2, 5, -1},
		{-2, 5, -1},
		{2, -5, -1},
		{-2, -5, 1},
		{3, 5, -1},
		{5, 5, 0},
		{-5, 5, 0},
		{6, 5, 1},
		{6, -5, 1},
		{-6, 5, 1},
		{-6, -5, -1},
	}

	var x, y Int

	for i, test := range testCases {
		x.SetInt64(test.x)
		y.SetInt64(test.y)
		expected := test.result
		actual := Jacobi(&x, &y)
		if actual != expected {
			t.Errorf("#%d: Jacobi(%d, %d) = %d, but expected %d", i, test.x, test.y, actual, expected)
		}
	}
}

func TestJacobiPanic(t *testing.T) {
	const failureMsg = "test failure"
	defer func() {
		msg := recover()
		if msg == nil || msg == failureMsg {
			panic(msg)
		}
		t.Log(msg)
	}()
	x := NewInt(1)
	y := NewInt(2)
	// Jacobi should panic when the second argument is even.
	Jacobi(x, y)
	panic(failureMsg)
}

func TestIssue2607(t *testing.T) {
	// This code sequence used to hang.
	n := NewInt(10)
	n.Rand(rand.New(rand.NewSource(9)), n)
}

func TestSqrt(t *testing.T) {
	root := 0
	r := new(Int)
	for i := 0; i < 10000; i++ {
		if (root+1)*(root+1) <= i {
			root++
		}
		n := NewInt(int64(i))
		r.SetInt64(-2)
		r.Sqrt(n)
		if r.Cmp(NewInt(int64(root))) != 0 {
			t.Errorf("Sqrt(%v) = %v, want %v", n, r, root)
		}
	}

	for i := 0; i < 1000; i += 10 {
		n, _ := new(Int).SetString("1"+strings.Repeat("0", i), 10)
		r := new(Int).Sqrt(n)
		root, _ := new(Int).SetString("1"+strings.Repeat("0", i/2), 10)
		if r.Cmp(root) != 0 {
			t.Errorf("Sqrt(1e%d) = %v, want 1e%d", i, r, i/2)
		}
	}

	// Test aliasing.
	r.SetInt64(100)
	r.Sqrt(r)
	if r.Int64() != 10 {
		t.Errorf("Sqrt(100) = %v, want 10 (aliased output)", r.Int64())
	}
}

// We can't test this together with the other Exp tests above because
// it requires a different receiver setup.
func TestIssue22830(t *testing.T) {
	one := new(Int).SetInt64(1)
	base, _ := new(Int).SetString("84555555300000000000", 10)
	mod, _ := new(Int).SetString("66666670001111111111", 10)
	want, _ := new(Int).SetString("17888885298888888889", 10)

	var tests = []int64{
		0, 1, -1,
	}

	for _, n := range tests {
		m := NewInt(n)
		if got := m.Exp(base, one, mod); got.Cmp(want) != 0 {
			t.Errorf("(%v).Exp(%s, 1, %s) = %s, want %s", n, base, mod, got, want)
		}
	}
}

func BenchmarkSqrt(b *testing.B) {
	n, _ := new(Int).SetString("1"+strings.Repeat("0", 1001), 10)
	b.ResetTimer()
	t := new(Int)
	for i := 0; i < b.N; i++ {
		t.Sqrt(n)
	}
}

func benchmarkIntSqr(b *testing.B, nwords int) {
	x := new(Int)
	x.abs = rndNat(nwords)
	t := new(Int)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Mul(x, x)
	}
}

func BenchmarkIntSqr(b *testing.B) {
	for _, n := range sqrBenchSizes {
		if isRaceBuilder && n > 1e3 {
			continue
		}
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			benchmarkIntSqr(b, n)
		})
	}
}

func benchmarkDiv(b *testing.B, aSize, bSize int) {
	var r = rand.New(rand.NewSource(1234))
	aa := randInt(r, uint(aSize))
	bb := randInt(r, uint(bSize))
	if aa.Cmp(bb) < 0 {
		aa, bb = bb, aa
	}
	x := new(Int)
	y := new(Int)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.DivMod(aa, bb, y)
	}
}

func BenchmarkDiv(b *testing.B) {
	sizes := []int{
		10, 20, 50, 100, 200, 500, 1000,
		1e4, 1e5, 1e6, 1e7,
	}
	for _, i := range sizes {
		j := 2 * i
		b.Run(fmt.Sprintf("%d/%d", j, i), func(b *testing.B) {
			benchmarkDiv(b, j, i)
		})
	}
}

func TestFillBytes(t *testing.T) {
	checkResult := func(t *testing.T, buf []byte, want *Int) {
		t.Helper()
		got := new(Int).SetBytes(buf)
		if got.CmpAbs(want) != 0 {
			t.Errorf("got 0x%x, want 0x%x: %x", got, want, buf)
		}
	}
	panics := func(f func()) (panic bool) {
		defer func() { panic = recover() != nil }()
		f()
		return
	}

	for _, n := range []string{
		"0",
		"1000",
		"0xffffffff",
		"-0xffffffff",
		"0xffffffffffffffff",
		"0x10000000000000000",
		"0xabababababababababababababababababababababababababa",
		"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	} {
		t.Run(n, func(t *testing.T) {
			t.Log(n)
			x, ok := new(Int).SetString(n, 0)
			if !ok {
				panic("invalid test entry")
			}

			// Perfectly sized buffer.
			byteLen := (x.BitLen() + 7) / 8
			buf := make([]byte, byteLen)
			checkResult(t, x.FillBytes(buf), x)

			// Way larger, checking all bytes get zeroed.
			buf = make([]byte, 100)
			for i := range buf {
				buf[i] = 0xff
			}
			checkResult(t, x.FillBytes(buf), x)

			// Too small.
			if byteLen > 0 {
				buf = make([]byte, byteLen-1)
				if !panics(func() { x.FillBytes(buf) }) {
					t.Errorf("expected panic for small buffer and value %x", x)
				}
			}
		})
	}
}

func TestNewIntMinInt64(t *testing.T) {
	// Test for uint64 cast in NewInt.
	want := int64(math.MinInt64)
	if got := NewInt(want).Int64(); got != want {
		t.Fatalf("wanted %d, got %d", want, got)
	}
}

func TestNewIntAllocs(t *testing.T) {
	testenv.SkipIfOptimizationOff(t)
	for _, n := range []int64{0, 7, -7, 1 << 30, -1 << 30, 1 << 50, -1 << 50} {
		x := NewInt(3)
		got := testing.AllocsPerRun(100, func() {
			// NewInt should inline, and all its allocations
			// can happen on the stack. Passing the result of NewInt
			// to Add should not cause any of those allocations to escape.
			x.Add(x, NewInt(n))
		})
		if got != 0 {
			t.Errorf("x.Add(x, NewInt(%d)), wanted 0 allocations, got %f", n, got)
		}
	}
}

func TestFloat64(t *testing.T) {
	for _, test := range []struct {
		istr string
		f    float64
		acc  Accuracy
	}{
		{"-1000000000000000000000000000000000000000000000000000000", -1000000000000000078291540404596243842305360299886116864.000000, Below},
		{"-9223372036854775809", math.MinInt64, Above},
		{"-9223372036854775808", -9223372036854775808, Exact}, // -2^63
		{"-9223372036854775807", -9223372036854775807, Below},
		{"-18014398509481985", -18014398509481984.000000, Above},
		{"-18014398509481984", -18014398509481984.000000, Exact}, // -2^54
		{"-18014398509481983", -18014398509481984.000000, Below},
		{"-9007199254740993", -9007199254740992.000000, Above},
		{"-9007199254740992", -9007199254740992.000000, Exact}, // -2^53
		{"-9007199254740991", -9007199254740991.000000, Exact},
		{"-4503599627370497", -4503599627370497.000000, Exact},
		{"-4503599627370496", -4503599627370496.000000, Exact}, // -2^52
		{"-4503599627370495", -4503599627370495.000000, Exact},
		{"-12345", -12345, Exact},
		{"-1", -1, Exact},
		{"0", 0, Exact},
		{"1", 1, Exact},
		{"12345", 12345, Exact},
		{"0x1010000000000000", 0x1010000000000000, Exact}, // >2^53 but exact nonetheless
		{"9223372036854775807", 9223372036854775808, Above},
		{"9223372036854775808", 9223372036854775808, Exact}, // +2^63
		{"1000000000000000000000000000000000000000000000000000000", 1000000000000000078291540404596243842305360299886116864.000000, Above},
	} {
		i, ok := new(Int).SetString(test.istr, 0)
		if !ok {
			t.Errorf("SetString(%s) failed", test.istr)
			continue
		}

		// Test against expectation.
		f, acc := i.Float64()
		if f != test.f || acc != test.acc {
			t.Errorf("%s: got %f (%s); want %f (%s)", test.istr, f, acc, test.f, test.acc)
		}

		// Cross-check the fast path against the big.Float implementation.
		f2, acc2 := new(Float).SetInt(i).Float64()
		if f != f2 || acc != acc2 {
			t.Errorf("%s: got %f (%s); Float.Float64 gives %f (%s)", test.istr, f, acc, f2, acc2)
		}
	}
}

"""




```