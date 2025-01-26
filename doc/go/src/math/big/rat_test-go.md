Response:
Let's break down the thought process for analyzing this Go test file.

1. **Identify the Core Purpose:** The file name `rat_test.go` and the package declaration `package big` immediately suggest this file contains tests for the `Rat` type within the `math/big` package. This `Rat` likely represents rational numbers (fractions).

2. **Examine Imports:** The imports `math` and `testing` confirm this is a standard Go test file. The `math` import suggests interactions with standard math functions, potentially related to floating-point conversions.

3. **Analyze Individual Test Functions:**  Iterate through each function starting with `Test...`. This is the standard Go testing convention. For each function, try to understand its objective:

    * **`TestZeroRat`:**  The name is a strong clue. The code checks how a zero `Rat` behaves in various operations (comparison, string representation, addition, subtraction, multiplication, division). The `recover()` part for division by zero is important.

    * **`TestRatSign`:** This tests the `Sign()` method, likely returning -1, 0, or 1. It compares the result to the output of `Cmp(zero)`, reinforcing the understanding of the sign.

    * **`TestRatCmp`:**  Clearly tests the `Cmp()` method for comparing `Rat` values. The `ratCmpTests` slice provides various test cases, including edge cases and negative numbers.

    * **`TestIsInt`:**  Checks the `IsInt()` method, determining if a `Rat` represents an integer. It compares the denominator to 1.

    * **`TestRatAbs`:**  Tests the absolute value function `Abs()`. It compares the result with manually calculating the absolute value.

    * **`TestRatNeg`:** Tests the negation function `Neg()`. It compares the result with subtracting from zero.

    * **`TestRatInv`:** Tests the inverse function `Inv()`. It swaps the numerator and denominator and compares. The check for zero is crucial.

    * **`testRatBin` and `TestRatBin`:** These work together. `testRatBin` is a helper function to run a binary operation test. `TestRatBin` defines a table of test cases (`ratBinTests`) for addition, subtraction, multiplication, and division, including symmetry checks.

    * **`TestIssue820`:**  The name suggests this test addresses a specific bug (`Issue820`). The code tests the `Quo()` method with specific values and expected results.

    * **`TestRatSetFrac64Rat`:** Tests the `SetFrac64()` method, which likely sets the `Rat` from two `int64` values.

    * **`TestIssue2379`:** Addresses another specific bug (`Issue2379`), focusing on aliasing issues when using `SetFrac()`.

    * **`TestIssue3521`:** Addresses `Issue3521`, focusing on the behavior of the denominator of `Rat` values, especially for zero values and after initialization.

    * **`TestFloat32Distribution` and `TestFloat64Distribution`:** These are more complex. They generate a wide range of numbers and test the accuracy of `Float32()` and `Float64()` conversions, ensuring the closest float approximation is chosen. The `checkIsBestApprox` functions are key here.

    * **`TestSetFloat64NonFinite`:** Specifically tests the handling of non-finite floating-point values (NaN, Inf) in `SetFloat64()`.

    * **`checkNonLossyRoundtrip32` and `checkNonLossyRoundtrip64`:** Verify that converting a finite float to a `Rat` and back to a float doesn't lose precision.

    * **Helper functions like `delta`, `checkIsBestApprox32`, `checkIsBestApprox64`, `isEven32`, `isEven64`, `isFinite`:** These support the floating-point conversion tests.

    * **`TestRatSetInt64` and `TestRatSetUint64`:** Test setting `Rat` values from `int64` and `uint64`.

    * **`BenchmarkRatCmp`:**  A benchmark test to measure the performance of the `Cmp()` method.

    * **`TestIssue34919`:** Tests that accessing `Rat` values (like getting the float representation or sign) doesn't unintentionally modify the denominator.

    * **`TestDenomRace`:** Specifically tests for race conditions when accessing the denominator concurrently, a common problem when dealing with shared mutable state.

4. **Identify Implemented Go Features:** Based on the test functions, the code is clearly testing the `math/big.Rat` type. This involves:

    * **Rational Number Representation:** The `Rat` struct likely holds the numerator and denominator.
    * **Basic Arithmetic Operations:**  Addition (`Add`), subtraction (`Sub`), multiplication (`Mul`), division (`Quo`).
    * **Comparison:**  `Cmp()`.
    * **Sign Determination:** `Sign()`.
    * **Absolute Value:** `Abs()`.
    * **Negation:** `Neg()`.
    * **Inverse:** `Inv()`.
    * **Integer Check:** `IsInt()`.
    * **String Conversion:** `String()` and `RatString()`.
    * **Setting Values:** `SetFrac()`, `SetFrac64()`, `SetString()`, `SetInt64()`, `SetUint64()`, `SetFloat64()`.
    * **Floating-Point Conversion:** `Float32()` and `Float64()`.

5. **Code Examples (with Assumptions):** For each identified feature, construct a simple Go code example. This often requires making assumptions about how the `Rat` type is used.

6. **Code Reasoning (with Assumptions):** When a test involves more complex logic (like the floating-point conversion tests), explain the *intent* of the test and the *assumptions* made about how the underlying functions work. For instance, the floating-point tests assume a "closest approximation" rounding behavior.

7. **Command-Line Arguments:** Look for any interaction with command-line flags. The presence of `*long` suggests a `-long` flag is used to control the intensity of certain tests.

8. **Common Mistakes:**  Think about potential pitfalls users might encounter. Division by zero with `Rat` is an obvious one. Aliasing issues (modifying a `big.Int` that's also used by a `Rat`) are another. The subtleties of floating-point conversions and potential precision loss are also relevant.

9. **Structure the Answer:** Organize the findings logically, starting with a high-level summary, then detailing each aspect (functionality, Go features, examples, reasoning, etc.). Use clear and concise language. Use formatting (like bullet points and code blocks) to improve readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about basic rational number arithmetic."
* **Correction:** "Wait, there are significant parts dealing with floating-point conversions. This is more comprehensive than just basic arithmetic."
* **Initial thought:** "The test names are pretty self-explanatory."
* **Refinement:** "While mostly true, some tests like `TestIssue820` require looking at the code to understand the specific scenario being tested."
* **Initial thought:** "I don't need to explain every single line of code."
* **Refinement:** "Focus on explaining the *purpose* of each test and the overall functionality being verified."

By following this structured approach, and being willing to refine your understanding as you go, you can effectively analyze and explain the functionality of a complex test file like this one.
这个文件 `go/src/math/big/rat_test.go` 是 Go 语言 `math/big` 包中关于有理数 (`Rat` 类型) 的单元测试代码。它旨在全面测试 `Rat` 类型的功能和各种边界情况，以确保其实现的正确性和健壮性。

以下是该文件测试的主要功能点：

**1. `Rat` 类型的基本操作：**

*   **零值处理 (`TestZeroRat`)：** 测试零值有理数的各种行为，例如比较、字符串表示、加减乘除运算。它还检查了除零错误的抛出。
*   **符号判断 (`TestRatSign`)：** 测试 `Sign()` 方法，判断有理数的正负性或零。
*   **比较运算 (`TestRatCmp`)：** 测试 `Cmp()` 方法，比较两个有理数的大小关系。
*   **是否为整数 (`TestIsInt`)：** 测试 `IsInt()` 方法，判断有理数是否为整数。
*   **绝对值 (`TestRatAbs`)：** 测试 `Abs()` 方法，计算有理数的绝对值。
*   **取负 (`TestRatNeg`)：** 测试 `Neg()` 方法，计算有理数的相反数。
*   **求倒数 (`TestRatInv`)：** 测试 `Inv()` 方法，计算有理数的倒数。

**2. `Rat` 类型的二元运算：**

*   **加法、减法、乘法、除法 (`TestRatBin`)：** 通过定义 `ratBinFun` 函数类型和 `ratBinArg` 结构体，以及 `testRatBin` 辅助函数，批量测试了有理数的加 (`Add`)、减 (`Sub`)、乘 (`Mul`)、除 (`Quo`) 四种基本二元运算的正确性，并考虑了运算的对称性。

**3. 特定问题的测试：**

*   **Issue 820 (`TestIssue820`)：**  针对之前发现的 Issue 820 进行测试，确保在特定的除法场景下结果的正确性。
*   **`SetFrac64` 方法 (`TestRatSetFrac64Rat`)：** 测试使用 `SetFrac64` 方法从 `int64` 类型的分子和分母创建有理数的正确性。
*   **Issue 2379 (`TestIssue2379`)：** 针对 Issue 2379 进行测试，主要关注 `SetFrac` 方法在分子和分母存在别名时的行为，确保不会出现意外的修改。
*   **Issue 3521 (`TestIssue3521`)：**  针对 Issue 3521 进行测试，详细检查了 `Rat` 类型分母的初始化、共享和修改行为，特别是零值的处理以及分子分母独立性的问题。
*   **Issue 34919 (`TestIssue34919`)：**  测试在访问 `Rat` 值的某些属性（例如通过 `Float32` 或 `Float64` 获取浮点数表示，或者调用 `Sign`、`IsInt`、`Num` 等方法）时，是否会意外地修改其分母。
*   **并发安全 (`TestDenomRace`)：**  使用并发 Goroutine 测试在多线程环境下访问 `Rat` 的分母是否安全，防止出现数据竞争。

**4. 与浮点数的转换：**

*   **`Float32` 和 `Float64` 的精度测试 (`TestFloat32Distribution`, `TestFloat64Distribution`)：**  通过生成大量不同范围的有理数，并将其转换为 `float32` 和 `float64` 类型，然后检查转换结果是否是**最接近**的浮点数近似值。这些测试还使用了 `checkIsBestApprox32` 和 `checkIsBestApprox64` 辅助函数来进行精度校验。
*   **非有限浮点数的处理 (`TestSetFloat64NonFinite`)：** 测试 `SetFloat64` 方法如何处理非有限的浮点数（如 NaN 和正负无穷）。
*   **无损往返测试 (`checkNonLossyRoundtrip32`, `checkNonLossyRoundtrip64`)：** 测试有限浮点数转换为 `Rat`，然后再转换回浮点数时，是否能保持精度不丢失。

**5. 从整数创建 `Rat`：**

*   **`SetInt64` 和 `SetUint64` (`TestRatSetInt64`, `TestRatSetUint64`)：** 测试使用 `SetInt64` 和 `SetUint64` 方法从 `int64` 和 `uint64` 类型创建有理数的正确性。

**6. 性能测试：**

*   **`BenchmarkRatCmp`：**  提供了一个基准测试，用于衡量 `Rat` 类型 `Cmp` 方法的性能。

**它是什么 Go 语言功能的实现？**

这个测试文件主要测试了 Go 语言 `math/big` 包中的 `Rat` 类型，它实现了**任意精度的有理数**。有理数可以精确地表示分数，避免了浮点数运算中可能出现的精度损失。`math/big` 包还包含了 `Int` (任意精度整数) 和 `Float` (任意精度浮点数) 类型，`Rat` 类型经常与它们一起使用。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	// 创建一个有理数 1/3
	r1 := big.NewRat(1, 3)
	fmt.Println("r1:", r1.String()) // 输出: r1: 1/3

	// 创建一个有理数 2/5
	r2 := big.NewRat(2, 5)
	fmt.Println("r2:", r2.String()) // 输出: r2: 2/5

	// 加法运算
	sum := new(big.Rat).Add(r1, r2)
	fmt.Println("r1 + r2:", sum.String()) // 输出: r1 + r2: 11/15

	// 比较运算
	if r1.Cmp(r2) < 0 {
		fmt.Println("r1 小于 r2") // 输出: r1 小于 r2
	}

	// 转换为浮点数
	f64, _ := r1.Float64()
	fmt.Println("r1 转换为 float64:", f64) // 输出: r1 转换为 float64: 0.3333333333333333

	// 判断是否为整数
	r3 := big.NewRat(6, 2)
	fmt.Println("r3 是否为整数:", r3.IsInt()) // 输出: r3 是否为整数: true

	r4 := big.NewRat(5, 2)
	fmt.Println("r4 是否为整数:", r4.IsInt()) // 输出: r4 是否为整数: false
}
```

**代码推理 (带假设的输入与输出)：**

假设 `TestRatBin` 中的一个测试用例：

```go
{"1/2", "1/2", "1", "1/4"},
```

当测试加法时，输入 `x` 为 "1/2"，`y` 为 "1/2"。`testRatBin` 函数会将这些字符串转换为 `big.Rat` 类型，然后调用 `(*Rat).Add(new(Rat), x, y)`。

**假设的内部计算过程：**

1. 将字符串 "1/2" 解析为 `big.Rat`，分子为 1，分母为 2。
2. 将字符串 "1/2" 解析为 `big.Rat`，分子为 1，分母为 2。
3. `Add` 方法内部计算 `(1*2 + 1*2) / (2*2)`，得到 `4/4`。
4. 结果约简为 `1/1`，其字符串表示为 "1"。
5. 将计算结果与预期的结果 "1" 进行比较，如果一致则测试通过。

当测试乘法时，输入 `x` 为 "1/2"，`y` 为 "1/2"。

**假设的内部计算过程：**

1. 将字符串 "1/2" 解析为 `big.Rat`。
2. 将字符串 "1/2" 解析为 `big.Rat`。
3. `Mul` 方法内部计算 `(1*1) / (2*2)`，得到 `1/4`。
4. 将计算结果与预期的结果 "1/4" 进行比较，如果一致则测试通过。

**命令行参数的具体处理：**

在这个测试文件中，可以观察到对一个名为 `long` 的变量的使用，它通常是通过命令行参数 `-long` 传递的。

```go
var winc, einc = uint64(5), 15 // quick test (~60ms on x86-64)
if *long {
	winc, einc = uint64(1), 1 // soak test (~1.5s on x86-64)
}
```

这里，`winc` 和 `einc` 是在 `TestFloat32Distribution` 和 `TestFloat64Distribution` 中控制测试数据生成步长的变量。

*   **不使用 `-long` 参数：**  测试会使用较大的步长 (`winc = 5`, `einc = 15`)，这意味着测试的数据量较小，运行速度较快，适合快速验证基本功能。
*   **使用 `-long` 参数：**  测试会使用较小的步长 (`winc = 1`, `einc = 1`)，这意味着测试的数据量很大，覆盖范围更广，可以进行更彻底的测试，但运行时间会更长，通常用于更全面的回归测试或性能测试。

要运行这些带有 `-long` 参数的测试，可以使用以下命令：

```bash
go test -run TestFloat32Distribution -args -long
go test -run TestFloat64Distribution -args -long
```

`-args` 告诉 `go test` 将后面的参数传递给测试程序。

**使用者易犯错的点：**

*   **除零错误：**  对零值有理数进行除法运算会导致 panic。使用者需要确保除数不为零。

    ```go
    package main

    import (
        "fmt"
        "math/big"
    )

    func main() {
        zero := big.NewRat(0, 1)
        one := big.NewRat(1, 2)

        // 错误的用法，会导致 panic
        // result := new(big.Rat).Quo(one, zero)
        // fmt.Println(result)

        // 正确的用法，先判断除数是否为零
        if zero.Sign() != 0 {
            result := new(big.Rat).Quo(one, zero)
            fmt.Println(result)
        } else {
            fmt.Println("除数不能为零")
        }
    }
    ```

*   **精度丢失（与浮点数转换相关）：** 当有理数转换为浮点数时，可能会发生精度丢失，因为浮点数的表示范围和精度是有限的。使用者需要理解这种潜在的精度损失。

    ```go
    package main

    import (
        "fmt"
        "math/big"
    )

    func main() {
        r := big.NewRat(1, 3)
        f64, _ := r.Float64()
        fmt.Println("1/3 as float64:", f64) // 输出: 1/3 as float64: 0.3333333333333333
    }
    ```

*   **修改 `Rat` 的内部 `Int`：**  直接修改 `Rat` 内部的 `Num()` 或 `Denom()` 返回的 `big.Int` 可能会导致 `Rat` 对象的状态不一致。应该使用 `Rat` 提供的 `SetFrac` 等方法进行修改。Issue 3521 和 Issue 34919 的测试都与此相关。

    ```go
    package main

    import (
        "fmt"
        "math/big"
    )

    func main() {
        r := big.NewRat(3, 5)
        num := r.Num()
        num.SetInt64(6) // 不推荐：直接修改内部的 Int

        fmt.Println(r.String()) // 输出可能是错误的，因为 Rat 对象的状态没有正确更新

        // 推荐的做法
        r.SetFrac64(6, 5)
        fmt.Println(r.String())
    }
    ```

总而言之，`go/src/math/big/rat_test.go` 是一个非常详尽的测试文件，它覆盖了 `math/big.Rat` 类型的各种功能和潜在的错误场景，是理解和使用 `big.Rat` 的重要参考资料。

Prompt: 
```
这是路径为go/src/math/big/rat_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package big

import (
	"math"
	"testing"
)

func TestZeroRat(t *testing.T) {
	var x, y, z Rat
	y.SetFrac64(0, 42)

	if x.Cmp(&y) != 0 {
		t.Errorf("x and y should be both equal and zero")
	}

	if s := x.String(); s != "0/1" {
		t.Errorf("got x = %s, want 0/1", s)
	}

	if s := x.RatString(); s != "0" {
		t.Errorf("got x = %s, want 0", s)
	}

	z.Add(&x, &y)
	if s := z.RatString(); s != "0" {
		t.Errorf("got x+y = %s, want 0", s)
	}

	z.Sub(&x, &y)
	if s := z.RatString(); s != "0" {
		t.Errorf("got x-y = %s, want 0", s)
	}

	z.Mul(&x, &y)
	if s := z.RatString(); s != "0" {
		t.Errorf("got x*y = %s, want 0", s)
	}

	// check for division by zero
	defer func() {
		if s := recover(); s == nil || s.(string) != "division by zero" {
			panic(s)
		}
	}()
	z.Quo(&x, &y)
}

func TestRatSign(t *testing.T) {
	zero := NewRat(0, 1)
	for _, a := range setStringTests {
		x, ok := new(Rat).SetString(a.in)
		if !ok {
			continue
		}
		s := x.Sign()
		e := x.Cmp(zero)
		if s != e {
			t.Errorf("got %d; want %d for z = %v", s, e, &x)
		}
	}
}

var ratCmpTests = []struct {
	rat1, rat2 string
	out        int
}{
	{"0", "0/1", 0},
	{"1/1", "1", 0},
	{"-1", "-2/2", 0},
	{"1", "0", 1},
	{"0/1", "1/1", -1},
	{"-5/1434770811533343057144", "-5/1434770811533343057145", -1},
	{"49832350382626108453/8964749413", "49832350382626108454/8964749413", -1},
	{"-37414950961700930/7204075375675961", "37414950961700930/7204075375675961", -1},
	{"37414950961700930/7204075375675961", "74829901923401860/14408150751351922", 0},
}

func TestRatCmp(t *testing.T) {
	for i, test := range ratCmpTests {
		x, _ := new(Rat).SetString(test.rat1)
		y, _ := new(Rat).SetString(test.rat2)

		out := x.Cmp(y)
		if out != test.out {
			t.Errorf("#%d got out = %v; want %v", i, out, test.out)
		}
	}
}

func TestIsInt(t *testing.T) {
	one := NewInt(1)
	for _, a := range setStringTests {
		x, ok := new(Rat).SetString(a.in)
		if !ok {
			continue
		}
		i := x.IsInt()
		e := x.Denom().Cmp(one) == 0
		if i != e {
			t.Errorf("got IsInt(%v) == %v; want %v", x, i, e)
		}
	}
}

func TestRatAbs(t *testing.T) {
	zero := new(Rat)
	for _, a := range setStringTests {
		x, ok := new(Rat).SetString(a.in)
		if !ok {
			continue
		}
		e := new(Rat).Set(x)
		if e.Cmp(zero) < 0 {
			e.Sub(zero, e)
		}
		z := new(Rat).Abs(x)
		if z.Cmp(e) != 0 {
			t.Errorf("got Abs(%v) = %v; want %v", x, z, e)
		}
	}
}

func TestRatNeg(t *testing.T) {
	zero := new(Rat)
	for _, a := range setStringTests {
		x, ok := new(Rat).SetString(a.in)
		if !ok {
			continue
		}
		e := new(Rat).Sub(zero, x)
		z := new(Rat).Neg(x)
		if z.Cmp(e) != 0 {
			t.Errorf("got Neg(%v) = %v; want %v", x, z, e)
		}
	}
}

func TestRatInv(t *testing.T) {
	zero := new(Rat)
	for _, a := range setStringTests {
		x, ok := new(Rat).SetString(a.in)
		if !ok {
			continue
		}
		if x.Cmp(zero) == 0 {
			continue // avoid division by zero
		}
		e := new(Rat).SetFrac(x.Denom(), x.Num())
		z := new(Rat).Inv(x)
		if z.Cmp(e) != 0 {
			t.Errorf("got Inv(%v) = %v; want %v", x, z, e)
		}
	}
}

type ratBinFun func(z, x, y *Rat) *Rat
type ratBinArg struct {
	x, y, z string
}

func testRatBin(t *testing.T, i int, name string, f ratBinFun, a ratBinArg) {
	x, _ := new(Rat).SetString(a.x)
	y, _ := new(Rat).SetString(a.y)
	z, _ := new(Rat).SetString(a.z)
	out := f(new(Rat), x, y)

	if out.Cmp(z) != 0 {
		t.Errorf("%s #%d got %s want %s", name, i, out, z)
	}
}

var ratBinTests = []struct {
	x, y      string
	sum, prod string
}{
	{"0", "0", "0", "0"},
	{"0", "1", "1", "0"},
	{"-1", "0", "-1", "0"},
	{"-1", "1", "0", "-1"},
	{"1", "1", "2", "1"},
	{"1/2", "1/2", "1", "1/4"},
	{"1/4", "1/3", "7/12", "1/12"},
	{"2/5", "-14/3", "-64/15", "-28/15"},
	{"4707/49292519774798173060", "-3367/70976135186689855734", "84058377121001851123459/1749296273614329067191168098769082663020", "-1760941/388732505247628681598037355282018369560"},
	{"-61204110018146728334/3", "-31052192278051565633/2", "-215564796870448153567/6", "950260896245257153059642991192710872711/3"},
	{"-854857841473707320655/4237645934602118692642972629634714039", "-18/31750379913563777419", "-27/133467566250814981", "15387441146526731771790/134546868362786310073779084329032722548987800600710485341"},
	{"618575745270541348005638912139/19198433543745179392300736", "-19948846211000086/637313996471", "27674141753240653/30123979153216", "-6169936206128396568797607742807090270137721977/6117715203873571641674006593837351328"},
	{"-3/26206484091896184128", "5/2848423294177090248", "15310893822118706237/9330894968229805033368778458685147968", "-5/24882386581946146755650075889827061248"},
	{"26946729/330400702820", "41563965/225583428284", "1238218672302860271/4658307703098666660055", "224002580204097/14906584649915733312176"},
	{"-8259900599013409474/7", "-84829337473700364773/56707961321161574960", "-468402123685491748914621885145127724451/396955729248131024720", "350340947706464153265156004876107029701/198477864624065512360"},
	{"575775209696864/1320203974639986246357", "29/712593081308", "410331716733912717985762465/940768218243776489278275419794956", "808/45524274987585732633"},
	{"1786597389946320496771/2066653520653241", "6269770/1992362624741777", "3559549865190272133656109052308126637/4117523232840525481453983149257", "8967230/3296219033"},
	{"-36459180403360509753/32150500941194292113930", "9381566963714/9633539", "301622077145533298008420642898530153/309723104686531919656937098270", "-3784609207827/3426986245"},
}

func TestRatBin(t *testing.T) {
	for i, test := range ratBinTests {
		arg := ratBinArg{test.x, test.y, test.sum}
		testRatBin(t, i, "Add", (*Rat).Add, arg)

		arg = ratBinArg{test.y, test.x, test.sum}
		testRatBin(t, i, "Add symmetric", (*Rat).Add, arg)

		arg = ratBinArg{test.sum, test.x, test.y}
		testRatBin(t, i, "Sub", (*Rat).Sub, arg)

		arg = ratBinArg{test.sum, test.y, test.x}
		testRatBin(t, i, "Sub symmetric", (*Rat).Sub, arg)

		arg = ratBinArg{test.x, test.y, test.prod}
		testRatBin(t, i, "Mul", (*Rat).Mul, arg)

		arg = ratBinArg{test.y, test.x, test.prod}
		testRatBin(t, i, "Mul symmetric", (*Rat).Mul, arg)

		if test.x != "0" {
			arg = ratBinArg{test.prod, test.x, test.y}
			testRatBin(t, i, "Quo", (*Rat).Quo, arg)
		}

		if test.y != "0" {
			arg = ratBinArg{test.prod, test.y, test.x}
			testRatBin(t, i, "Quo symmetric", (*Rat).Quo, arg)
		}
	}
}

func TestIssue820(t *testing.T) {
	x := NewRat(3, 1)
	y := NewRat(2, 1)
	z := y.Quo(x, y)
	q := NewRat(3, 2)
	if z.Cmp(q) != 0 {
		t.Errorf("got %s want %s", z, q)
	}

	y = NewRat(3, 1)
	x = NewRat(2, 1)
	z = y.Quo(x, y)
	q = NewRat(2, 3)
	if z.Cmp(q) != 0 {
		t.Errorf("got %s want %s", z, q)
	}

	x = NewRat(3, 1)
	z = x.Quo(x, x)
	q = NewRat(3, 3)
	if z.Cmp(q) != 0 {
		t.Errorf("got %s want %s", z, q)
	}
}

var setFrac64Tests = []struct {
	a, b int64
	out  string
}{
	{0, 1, "0"},
	{0, -1, "0"},
	{1, 1, "1"},
	{-1, 1, "-1"},
	{1, -1, "-1"},
	{-1, -1, "1"},
	{-9223372036854775808, -9223372036854775808, "1"},
}

func TestRatSetFrac64Rat(t *testing.T) {
	for i, test := range setFrac64Tests {
		x := new(Rat).SetFrac64(test.a, test.b)
		if x.RatString() != test.out {
			t.Errorf("#%d got %s want %s", i, x.RatString(), test.out)
		}
	}
}

func TestIssue2379(t *testing.T) {
	// 1) no aliasing
	q := NewRat(3, 2)
	x := new(Rat)
	x.SetFrac(NewInt(3), NewInt(2))
	if x.Cmp(q) != 0 {
		t.Errorf("1) got %s want %s", x, q)
	}

	// 2) aliasing of numerator
	x = NewRat(2, 3)
	x.SetFrac(NewInt(3), x.Num())
	if x.Cmp(q) != 0 {
		t.Errorf("2) got %s want %s", x, q)
	}

	// 3) aliasing of denominator
	x = NewRat(2, 3)
	x.SetFrac(x.Denom(), NewInt(2))
	if x.Cmp(q) != 0 {
		t.Errorf("3) got %s want %s", x, q)
	}

	// 4) aliasing of numerator and denominator
	x = NewRat(2, 3)
	x.SetFrac(x.Denom(), x.Num())
	if x.Cmp(q) != 0 {
		t.Errorf("4) got %s want %s", x, q)
	}

	// 5) numerator and denominator are the same
	q = NewRat(1, 1)
	x = new(Rat)
	n := NewInt(7)
	x.SetFrac(n, n)
	if x.Cmp(q) != 0 {
		t.Errorf("5) got %s want %s", x, q)
	}
}

func TestIssue3521(t *testing.T) {
	a := new(Int)
	b := new(Int)
	a.SetString("64375784358435883458348587", 0)
	b.SetString("4789759874531", 0)

	// 0) a raw zero value has 1 as denominator
	zero := new(Rat)
	one := NewInt(1)
	if zero.Denom().Cmp(one) != 0 {
		t.Errorf("0) got %s want %s", zero.Denom(), one)
	}

	// 1a) the denominator of an (uninitialized) zero value is not shared with the value
	s := &zero.b
	d := zero.Denom()
	if d == s {
		t.Errorf("1a) got %s (%p) == %s (%p) want different *Int values", d, d, s, s)
	}

	// 1b) the denominator of an (uninitialized) value is a new 1 each time
	d1 := zero.Denom()
	d2 := zero.Denom()
	if d1 == d2 {
		t.Errorf("1b) got %s (%p) == %s (%p) want different *Int values", d1, d1, d2, d2)
	}

	// 1c) the denominator of an initialized zero value is shared with the value
	x := new(Rat)
	x.Set(x) // initialize x (any operation that sets x explicitly will do)
	s = &x.b
	d = x.Denom()
	if d != s {
		t.Errorf("1c) got %s (%p) != %s (%p) want identical *Int values", d, d, s, s)
	}

	// 1d) a zero value remains zero independent of denominator
	x.Denom().Set(new(Int).Neg(b))
	if x.Cmp(zero) != 0 {
		t.Errorf("1d) got %s want %s", x, zero)
	}

	// 1e) a zero value may have a denominator != 0 and != 1
	x.Num().Set(a)
	qab := new(Rat).SetFrac(a, b)
	if x.Cmp(qab) != 0 {
		t.Errorf("1e) got %s want %s", x, qab)
	}

	// 2a) an integral value becomes a fraction depending on denominator
	x.SetFrac64(10, 2)
	x.Denom().SetInt64(3)
	q53 := NewRat(5, 3)
	if x.Cmp(q53) != 0 {
		t.Errorf("2a) got %s want %s", x, q53)
	}

	// 2b) an integral value becomes a fraction depending on denominator
	x = NewRat(10, 2)
	x.Denom().SetInt64(3)
	if x.Cmp(q53) != 0 {
		t.Errorf("2b) got %s want %s", x, q53)
	}

	// 3) changing the numerator/denominator of a Rat changes the Rat
	x.SetFrac(a, b)
	a = x.Num()
	b = x.Denom()
	a.SetInt64(5)
	b.SetInt64(3)
	if x.Cmp(q53) != 0 {
		t.Errorf("3) got %s want %s", x, q53)
	}
}

func TestFloat32Distribution(t *testing.T) {
	// Generate a distribution of (sign, mantissa, exp) values
	// broader than the float32 range, and check Rat.Float32()
	// always picks the closest float32 approximation.
	var add = []int64{
		0,
		1,
		3,
		5,
		7,
		9,
		11,
	}
	var winc, einc = uint64(5), 15 // quick test (~60ms on x86-64)
	if *long {
		winc, einc = uint64(1), 1 // soak test (~1.5s on x86-64)
	}

	for _, sign := range "+-" {
		for _, a := range add {
			for wid := uint64(0); wid < 30; wid += winc {
				b := 1<<wid + a
				if sign == '-' {
					b = -b
				}
				for exp := -150; exp < 150; exp += einc {
					num, den := NewInt(b), NewInt(1)
					if exp > 0 {
						num.Lsh(num, uint(exp))
					} else {
						den.Lsh(den, uint(-exp))
					}
					r := new(Rat).SetFrac(num, den)
					f, _ := r.Float32()

					if !checkIsBestApprox32(t, f, r) {
						// Append context information.
						t.Errorf("(input was mantissa %#x, exp %d; f = %g (%b); f ~ %g; r = %v)",
							b, exp, f, f, math.Ldexp(float64(b), exp), r)
					}

					checkNonLossyRoundtrip32(t, f)
				}
			}
		}
	}
}

func TestFloat64Distribution(t *testing.T) {
	// Generate a distribution of (sign, mantissa, exp) values
	// broader than the float64 range, and check Rat.Float64()
	// always picks the closest float64 approximation.
	var add = []int64{
		0,
		1,
		3,
		5,
		7,
		9,
		11,
	}
	var winc, einc = uint64(10), 500 // quick test (~12ms on x86-64)
	if *long {
		winc, einc = uint64(1), 1 // soak test (~75s on x86-64)
	}

	for _, sign := range "+-" {
		for _, a := range add {
			for wid := uint64(0); wid < 60; wid += winc {
				b := 1<<wid + a
				if sign == '-' {
					b = -b
				}
				for exp := -1100; exp < 1100; exp += einc {
					num, den := NewInt(b), NewInt(1)
					if exp > 0 {
						num.Lsh(num, uint(exp))
					} else {
						den.Lsh(den, uint(-exp))
					}
					r := new(Rat).SetFrac(num, den)
					f, _ := r.Float64()

					if !checkIsBestApprox64(t, f, r) {
						// Append context information.
						t.Errorf("(input was mantissa %#x, exp %d; f = %g (%b); f ~ %g; r = %v)",
							b, exp, f, f, math.Ldexp(float64(b), exp), r)
					}

					checkNonLossyRoundtrip64(t, f)
				}
			}
		}
	}
}

// TestSetFloat64NonFinite checks that SetFloat64 of a non-finite value
// returns nil.
func TestSetFloat64NonFinite(t *testing.T) {
	for _, f := range []float64{math.NaN(), math.Inf(+1), math.Inf(-1)} {
		var r Rat
		if r2 := r.SetFloat64(f); r2 != nil {
			t.Errorf("SetFloat64(%g) was %v, want nil", f, r2)
		}
	}
}

// checkNonLossyRoundtrip32 checks that a float->Rat->float roundtrip is
// non-lossy for finite f.
func checkNonLossyRoundtrip32(t *testing.T, f float32) {
	if !isFinite(float64(f)) {
		return
	}
	r := new(Rat).SetFloat64(float64(f))
	if r == nil {
		t.Errorf("Rat.SetFloat64(float64(%g) (%b)) == nil", f, f)
		return
	}
	f2, exact := r.Float32()
	if f != f2 || !exact {
		t.Errorf("Rat.SetFloat64(float64(%g)).Float32() = %g (%b), %v, want %g (%b), %v; delta = %b",
			f, f2, f2, exact, f, f, true, f2-f)
	}
}

// checkNonLossyRoundtrip64 checks that a float->Rat->float roundtrip is
// non-lossy for finite f.
func checkNonLossyRoundtrip64(t *testing.T, f float64) {
	if !isFinite(f) {
		return
	}
	r := new(Rat).SetFloat64(f)
	if r == nil {
		t.Errorf("Rat.SetFloat64(%g (%b)) == nil", f, f)
		return
	}
	f2, exact := r.Float64()
	if f != f2 || !exact {
		t.Errorf("Rat.SetFloat64(%g).Float64() = %g (%b), %v, want %g (%b), %v; delta = %b",
			f, f2, f2, exact, f, f, true, f2-f)
	}
}

// delta returns the absolute difference between r and f.
func delta(r *Rat, f float64) *Rat {
	d := new(Rat).Sub(r, new(Rat).SetFloat64(f))
	return d.Abs(d)
}

// checkIsBestApprox32 checks that f is the best possible float32
// approximation of r.
// Returns true on success.
func checkIsBestApprox32(t *testing.T, f float32, r *Rat) bool {
	if math.Abs(float64(f)) >= math.MaxFloat32 {
		// Cannot check +Inf, -Inf, nor the float next to them (MaxFloat32).
		// But we have tests for these special cases.
		return true
	}

	// r must be strictly between f0 and f1, the floats bracketing f.
	f0 := math.Nextafter32(f, float32(math.Inf(-1)))
	f1 := math.Nextafter32(f, float32(math.Inf(+1)))

	// For f to be correct, r must be closer to f than to f0 or f1.
	df := delta(r, float64(f))
	df0 := delta(r, float64(f0))
	df1 := delta(r, float64(f1))
	if df.Cmp(df0) > 0 {
		t.Errorf("Rat(%v).Float32() = %g (%b), but previous float32 %g (%b) is closer", r, f, f, f0, f0)
		return false
	}
	if df.Cmp(df1) > 0 {
		t.Errorf("Rat(%v).Float32() = %g (%b), but next float32 %g (%b) is closer", r, f, f, f1, f1)
		return false
	}
	if df.Cmp(df0) == 0 && !isEven32(f) {
		t.Errorf("Rat(%v).Float32() = %g (%b); halfway should have rounded to %g (%b) instead", r, f, f, f0, f0)
		return false
	}
	if df.Cmp(df1) == 0 && !isEven32(f) {
		t.Errorf("Rat(%v).Float32() = %g (%b); halfway should have rounded to %g (%b) instead", r, f, f, f1, f1)
		return false
	}
	return true
}

// checkIsBestApprox64 checks that f is the best possible float64
// approximation of r.
// Returns true on success.
func checkIsBestApprox64(t *testing.T, f float64, r *Rat) bool {
	if math.Abs(f) >= math.MaxFloat64 {
		// Cannot check +Inf, -Inf, nor the float next to them (MaxFloat64).
		// But we have tests for these special cases.
		return true
	}

	// r must be strictly between f0 and f1, the floats bracketing f.
	f0 := math.Nextafter(f, math.Inf(-1))
	f1 := math.Nextafter(f, math.Inf(+1))

	// For f to be correct, r must be closer to f than to f0 or f1.
	df := delta(r, f)
	df0 := delta(r, f0)
	df1 := delta(r, f1)
	if df.Cmp(df0) > 0 {
		t.Errorf("Rat(%v).Float64() = %g (%b), but previous float64 %g (%b) is closer", r, f, f, f0, f0)
		return false
	}
	if df.Cmp(df1) > 0 {
		t.Errorf("Rat(%v).Float64() = %g (%b), but next float64 %g (%b) is closer", r, f, f, f1, f1)
		return false
	}
	if df.Cmp(df0) == 0 && !isEven64(f) {
		t.Errorf("Rat(%v).Float64() = %g (%b); halfway should have rounded to %g (%b) instead", r, f, f, f0, f0)
		return false
	}
	if df.Cmp(df1) == 0 && !isEven64(f) {
		t.Errorf("Rat(%v).Float64() = %g (%b); halfway should have rounded to %g (%b) instead", r, f, f, f1, f1)
		return false
	}
	return true
}

func isEven32(f float32) bool { return math.Float32bits(f)&1 == 0 }
func isEven64(f float64) bool { return math.Float64bits(f)&1 == 0 }

func TestIsFinite(t *testing.T) {
	finites := []float64{
		1.0 / 3,
		4891559871276714924261e+222,
		math.MaxFloat64,
		math.SmallestNonzeroFloat64,
		-math.MaxFloat64,
		-math.SmallestNonzeroFloat64,
	}
	for _, f := range finites {
		if !isFinite(f) {
			t.Errorf("!IsFinite(%g (%b))", f, f)
		}
	}
	nonfinites := []float64{
		math.NaN(),
		math.Inf(-1),
		math.Inf(+1),
	}
	for _, f := range nonfinites {
		if isFinite(f) {
			t.Errorf("IsFinite(%g, (%b))", f, f)
		}
	}
}

func TestRatSetInt64(t *testing.T) {
	var testCases = []int64{
		0,
		1,
		-1,
		12345,
		-98765,
		math.MaxInt64,
		math.MinInt64,
	}
	var r = new(Rat)
	for i, want := range testCases {
		r.SetInt64(want)
		if !r.IsInt() {
			t.Errorf("#%d: Rat.SetInt64(%d) is not an integer", i, want)
		}
		num := r.Num()
		if !num.IsInt64() {
			t.Errorf("#%d: Rat.SetInt64(%d) numerator is not an int64", i, want)
		}
		got := num.Int64()
		if got != want {
			t.Errorf("#%d: Rat.SetInt64(%d) = %d, but expected %d", i, want, got, want)
		}
	}
}

func TestRatSetUint64(t *testing.T) {
	var testCases = []uint64{
		0,
		1,
		12345,
		^uint64(0),
	}
	var r = new(Rat)
	for i, want := range testCases {
		r.SetUint64(want)
		if !r.IsInt() {
			t.Errorf("#%d: Rat.SetUint64(%d) is not an integer", i, want)
		}
		num := r.Num()
		if !num.IsUint64() {
			t.Errorf("#%d: Rat.SetUint64(%d) numerator is not a uint64", i, want)
		}
		got := num.Uint64()
		if got != want {
			t.Errorf("#%d: Rat.SetUint64(%d) = %d, but expected %d", i, want, got, want)
		}
	}
}

func BenchmarkRatCmp(b *testing.B) {
	x, y := NewRat(4, 1), NewRat(7, 2)
	for i := 0; i < b.N; i++ {
		x.Cmp(y)
	}
}

// TestIssue34919 verifies that a Rat's denominator is not modified
// when simply accessing the Rat value.
func TestIssue34919(t *testing.T) {
	for _, acc := range []struct {
		name string
		f    func(*Rat)
	}{
		{"Float32", func(x *Rat) { x.Float32() }},
		{"Float64", func(x *Rat) { x.Float64() }},
		{"Inv", func(x *Rat) { new(Rat).Inv(x) }},
		{"Sign", func(x *Rat) { x.Sign() }},
		{"IsInt", func(x *Rat) { x.IsInt() }},
		{"Num", func(x *Rat) { x.Num() }},
		// {"Denom", func(x *Rat) { x.Denom() }}, TODO(gri) should we change the API? See issue #33792.
	} {
		// A denominator of length 0 is interpreted as 1. Make sure that
		// "materialization" of the denominator doesn't lead to setting
		// the underlying array element 0 to 1.
		r := &Rat{Int{abs: nat{991}}, Int{abs: make(nat, 0, 1)}}
		acc.f(r)
		if d := r.b.abs[:1][0]; d != 0 {
			t.Errorf("%s modified denominator: got %d, want 0", acc.name, d)
		}
	}
}

func TestDenomRace(t *testing.T) {
	x := NewRat(1, 2)
	const N = 3
	c := make(chan bool, N)
	for i := 0; i < N; i++ {
		go func() {
			// Denom (also used by Float.SetRat) used to mutate x unnecessarily,
			// provoking race reports when run in the race detector.
			x.Denom()
			new(Float).SetRat(x)
			c <- true
		}()
	}
	for i := 0; i < N; i++ {
		<-c
	}
}

"""



```