Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Functionality:** The initial comments and the package name (`math`) strongly suggest this code implements mathematical functions. The specific functions `erf(x)` and `erfc(x)` are clearly defined and their mathematical formulas are given. This is the primary purpose of the code.

2. **Deconstruct the Comments:** The comments are extremely valuable. They provide:
    * **Copyright and Licensing:** Standard legal information.
    * **Function Definitions:**  Mathematical formulas for `erf(x)` and `erfc(x)`.
    * **Relationship between `erf` and `erfc`:** `erfc(x) = 1 - erf(x)`.
    * **Symmetry Properties:** `erf(-x) = -erf(x)` and `erfc(-x) = 2 - erfc(x)`.
    * **Implementation Method:** This is crucial. The code doesn't use a single formula; it employs different approximation methods based on the input value `x`. This suggests the need for different code paths and coefficient sets. The comments outline five different ranges for `x` and the approximation techniques used for each.
    * **Polynomial Approximations:**  The comments repeatedly mention rational approximations (P/Q) using polynomials. This explains the presence of many constant variables (like `pp0`, `qq1`, `pa0`, etc.) – these are the coefficients of those polynomials.
    * **Error Bounds:**  The comments provide information about the accuracy of the approximations.
    * **Special Cases:**  Handling of `0`, `Inf`, and `NaN` is explicitly mentioned.

3. **Analyze the Code Structure:**
    * **Package Declaration:** `package math` confirms its purpose.
    * **Import Statements:**  None, which implies reliance on built-in Go features.
    * **Constant Definitions:** A large block of `const` declarations with descriptive names (e.g., `erx`, `efx`, `pp0`, `qq1`). These are clearly the coefficients mentioned in the comments. The hexadecimal representations are for internal accuracy and are not something a typical user needs to worry about directly.
    * **Function Signatures:** `func Erf(x float64) float64` and `func Erfc(x float64) float64` are the exported (capitalized) functions.
    * **Internal Functions:** `func erf(x float64) float64` and `func erfc(x float64) float64` (lowercase) are the actual implementations. The exported functions likely act as wrappers, potentially for architecture-specific optimizations (as indicated by `haveArchErf`).
    * **Conditional Logic:** The code uses `switch` statements and `if-else if` chains to handle the different ranges of `x` and the special cases. This directly corresponds to the "Method" section in the comments.
    * **Mathematical Operations:** Basic arithmetic operations, multiplication, division, and calls to `Exp()` (likely the exponential function from the `math` package).
    * **Bit Manipulation:**  The line `Float64frombits(Float64bits(x) & 0xffffffff00000000)` is interesting. The comment says "pseudo-single (20-bit) precision x," suggesting a technique to improve accuracy or performance in certain ranges by reducing precision temporarily.

4. **Connect Comments and Code:** This is the crucial step. Match the ranges and methods described in the comments to the conditional statements and the specific polynomial coefficients used in each section of the code. For example:
    * The "For |x| in [0, 0.84375]" section in the comments directly corresponds to the `if x < 0.84375` block in the `erf` and `erfc` functions, and the constants `pp0` through `qq5` are used here.
    * The handling of special cases (NaN, +/-Inf) at the beginning of both functions aligns with the "Special case" section in the comments.

5. **Infer Go Language Feature:** The core Go language feature implemented here is providing standard mathematical functions as part of the `math` package. Specifically, it's implementing the error function and the complementary error function.

6. **Construct Go Code Examples:**  To illustrate the usage, create simple examples that call the `Erf` and `Erfc` functions with different inputs, including normal values, edge cases (like 0), and special values (like `Inf` and `NaN`). Show the expected outputs based on the mathematical definitions and the special case handling.

7. **Identify Potential User Errors:** Think about how someone might misuse these functions. Common mistakes with mathematical functions include:
    * **Incorrectly interpreting the output:** Not understanding what the error function represents.
    * **Passing invalid inputs:** While the functions handle `NaN` and `Inf` gracefully, users might not realize the implications.
    * **Expecting exact results:**  The comments emphasize *approximations*, so users should be aware of potential floating-point inaccuracies.

8. **Address Command-Line Arguments:**  Scan the code for any usage of `os.Args` or similar mechanisms for processing command-line input. Since there are none, explicitly state that command-line arguments are not relevant.

9. **Structure the Answer:** Organize the findings into logical sections: Functionality, Implemented Go Feature, Code Examples, Code Reasoning (connecting comments to code), Handling of Command-Line Arguments, and Potential User Errors. Use clear and concise language.

By following this systematic approach, you can effectively analyze and explain even complex code snippets like this one. The key is to leverage the provided comments and understand the underlying logic and mathematical concepts.
这个Go语言源文件 `go/src/math/erf.go` 的一部分实现了**误差函数 (Error Function)** 和**互补误差函数 (Complementary Error Function)**。

**功能列举:**

1. **`Erf(x float64) float64`:**  计算给定浮点数 `x` 的误差函数值。误差函数的定义如下：
   ```
   erf(x) = (2 / sqrt(pi)) * ∫[0, x] exp(-t^2) dt
   ```
   它表示标准正态分布的累积分布函数的一部分。

2. **`Erfc(x float64) float64`:** 计算给定浮点数 `x` 的互补误差函数值。互补误差函数与误差函数的关系是：
   ```
   erfc(x) = 1 - erf(x)
   ```

3. **特殊情况处理:**  `Erf` 和 `Erfc` 函数都考虑了以下特殊输入情况：
   - `Erf(+Inf) = 1`, `Erfc(+Inf) = 0`
   - `Erf(-Inf) = -1`, `Erfc(-Inf) = 2`
   - `Erf(NaN) = NaN`, `Erfc(NaN) = NaN`

**实现的Go语言功能:**

这个文件实现了 Go 语言标准库 `math` 包中 `Erf` 和 `Erfc` 这两个数学函数。  `math` 包提供了基本的数学常数和函数，方便 Go 语言开发者进行数值计算。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"math"
)

func main() {
	x1 := 0.0
	erf_x1 := math.Erf(x1)
	erfc_x1 := math.Erfc(x1)
	fmt.Printf("Erf(%f) = %f\n", x1, erf_x1)   // 输出: Erf(0.000000) = 0.000000
	fmt.Printf("Erfc(%f) = %f\n", x1, erfc_x1)  // 输出: Erfc(0.000000) = 1.000000

	x2 := 1.0
	erf_x2 := math.Erf(x2)
	erfc_x2 := math.Erfc(x2)
	fmt.Printf("Erf(%f) = %f\n", x2, erf_x2)   // 输出: Erf(1.000000) = 0.842701
	fmt.Printf("Erfc(%f) = %f\n", x2, erfc_x2)  // 输出: Erfc(1.000000) = 0.157299

	x3 := -1.0
	erf_x3 := math.Erf(x3)
	erfc_x3 := math.Erfc(x3)
	fmt.Printf("Erf(%f) = %f\n", x3, erf_x3)   // 输出: Erf(-1.000000) = -0.842701
	fmt.Printf("Erfc(%f) = %f\n", x3, erfc_x3)  // 输出: Erfc(-1.000000) = 1.842701

	x4 := math.Inf(1) // 正无穷
	erf_x4 := math.Erf(x4)
	erfc_x4 := math.Erfc(x4)
	fmt.Printf("Erf(%f) = %f\n", x4, erf_x4)   // 输出: Erf(+Inf) = 1.000000
	fmt.Printf("Erfc(%f) = %f\n", x4, erfc_x4)  // 输出: Erfc(+Inf) = 0.000000

	x5 := math.NaN()
	erf_x5 := math.Erf(x5)
	erfc_x5 := math.Erfc(x5)
	fmt.Printf("Erf(%f) = %f\n", x5, erf_x5)   // 输出: Erf(NaN) = NaN
	fmt.Printf("Erfc(%f) = %f\n", x5, erfc_x5)  // 输出: Erfc(NaN) = NaN
}
```

**代码推理 (带假设的输入与输出):**

这段代码的实现并没有使用单一的公式来计算误差函数和互补误差函数。为了提高效率和精度，它采用了分段逼近的方法，针对不同的输入范围使用不同的多项式或有理函数进行近似计算。

例如，对于 `Erf(x)` 函数，代码中可以看到针对不同的 `x` 值范围使用了不同的计算逻辑：

- **假设输入 `x = 0.5`:**  由于 `0.5 < 0.84375`，代码会进入第一个 `if x < 0.84375` 的分支。
    - 因为 `0.5` 不小于 `Small` (假设 `Small` 是一个很小的正数，例如 `1.0 / (1 << 28)`), 代码会计算 `z = x * x`，然后使用定义好的多项式系数 `pp0` 到 `qq5` 来计算有理函数 `r / s`，最终得到 `temp = x + x*y`。
    - 由于 `x` 是正数，`sign` 为 `false`，所以返回 `temp`。
    - **假设输出:** 大约是 `0.5205` (这是一个近似值，实际精度取决于多项式的系数)。

- **假设输入 `x = 1.0`:** 由于 `0.84375 <= 1.0 < 1.25`，代码会进入第二个 `else if x < 1.25` 的分支。
    - 计算 `s = x - 1`。
    - 使用另一组多项式系数 `pa0` 到 `qa6` 计算 `P` 和 `Q`。
    - 返回 `erx + P/Q` (因为 `x` 是正数)。
    - **假设输出:** 大约是 `0.8427`。

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。它是 `math` 标准库的一部分，其功能是通过在 Go 程序中调用相应的函数来实现的。如果需要在命令行程序中使用误差函数，你需要编写一个 Go 程序，导入 `math` 包，并在程序中调用 `math.Erf` 或 `math.Erfc` 函数。你可以使用 `os.Args` 来获取命令行参数，并将参数转换为浮点数传递给这些函数。

**使用者易犯错的点:**

1. **混淆 Erf 和 Erfc 的定义:**  使用者可能会忘记 `erfc(x) = 1 - erf(x)`，导致在需要互补误差函数时错误地使用了误差函数，或者反之。

   **例子:**  假设一个场景需要计算某个事件发生的概率，而该概率与互补误差函数有关。如果使用者错误地使用了 `math.Erf(x)` 而不是 `math.Erfc(x)`，得到的结果将会是错误的。

2. **假设精度过高:**  虽然 Go 的 `float64` 提供了较高的精度，但这些函数是通过近似计算实现的，并非绝对精确。使用者不应该期望得到无限精度的结果，尤其是在进行多次迭代或复杂计算时，需要注意误差的累积。

3. **未处理 NaN 输入:**  虽然函数本身会返回 `NaN`，但如果使用者在程序中没有正确处理 `NaN` 值，可能会导致后续计算出现问题。

**总结:**

这段 `go/src/math/erf.go` 代码实现了 Go 语言标准库中用于计算误差函数 `Erf(x)` 和互补误差函数 `Erfc(x)` 的功能。它通过分段多项式逼近的方法在不同的输入范围内提供高效且精确的计算。使用者需要理解这两个函数的定义以及它们之间的关系，并注意浮点数计算的精度问题。

Prompt: 
```
这是路径为go/src/math/erf.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package math

/*
	Floating-point error function and complementary error function.
*/

// The original C code and the long comment below are
// from FreeBSD's /usr/src/lib/msun/src/s_erf.c and
// came with this notice. The go code is a simplified
// version of the original C.
//
// ====================================================
// Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
//
// Developed at SunPro, a Sun Microsystems, Inc. business.
// Permission to use, copy, modify, and distribute this
// software is freely granted, provided that this notice
// is preserved.
// ====================================================
//
//
// double erf(double x)
// double erfc(double x)
//                           x
//                    2      |\
//     erf(x)  =  ---------  | exp(-t*t)dt
//                 sqrt(pi) \|
//                           0
//
//     erfc(x) =  1-erf(x)
//  Note that
//              erf(-x) = -erf(x)
//              erfc(-x) = 2 - erfc(x)
//
// Method:
//      1. For |x| in [0, 0.84375]
//          erf(x)  = x + x*R(x**2)
//          erfc(x) = 1 - erf(x)           if x in [-.84375,0.25]
//                  = 0.5 + ((0.5-x)-x*R)  if x in [0.25,0.84375]
//         where R = P/Q where P is an odd poly of degree 8 and
//         Q is an odd poly of degree 10.
//                                               -57.90
//                      | R - (erf(x)-x)/x | <= 2
//
//
//         Remark. The formula is derived by noting
//          erf(x) = (2/sqrt(pi))*(x - x**3/3 + x**5/10 - x**7/42 + ....)
//         and that
//          2/sqrt(pi) = 1.128379167095512573896158903121545171688
//         is close to one. The interval is chosen because the fix
//         point of erf(x) is near 0.6174 (i.e., erf(x)=x when x is
//         near 0.6174), and by some experiment, 0.84375 is chosen to
//         guarantee the error is less than one ulp for erf.
//
//      2. For |x| in [0.84375,1.25], let s = |x| - 1, and
//         c = 0.84506291151 rounded to single (24 bits)
//              erf(x)  = sign(x) * (c  + P1(s)/Q1(s))
//              erfc(x) = (1-c)  - P1(s)/Q1(s) if x > 0
//                        1+(c+P1(s)/Q1(s))    if x < 0
//              |P1/Q1 - (erf(|x|)-c)| <= 2**-59.06
//         Remark: here we use the taylor series expansion at x=1.
//              erf(1+s) = erf(1) + s*Poly(s)
//                       = 0.845.. + P1(s)/Q1(s)
//         That is, we use rational approximation to approximate
//                      erf(1+s) - (c = (single)0.84506291151)
//         Note that |P1/Q1|< 0.078 for x in [0.84375,1.25]
//         where
//              P1(s) = degree 6 poly in s
//              Q1(s) = degree 6 poly in s
//
//      3. For x in [1.25,1/0.35(~2.857143)],
//              erfc(x) = (1/x)*exp(-x*x-0.5625+R1/S1)
//              erf(x)  = 1 - erfc(x)
//         where
//              R1(z) = degree 7 poly in z, (z=1/x**2)
//              S1(z) = degree 8 poly in z
//
//      4. For x in [1/0.35,28]
//              erfc(x) = (1/x)*exp(-x*x-0.5625+R2/S2) if x > 0
//                      = 2.0 - (1/x)*exp(-x*x-0.5625+R2/S2) if -6<x<0
//                      = 2.0 - tiny            (if x <= -6)
//              erf(x)  = sign(x)*(1.0 - erfc(x)) if x < 6, else
//              erf(x)  = sign(x)*(1.0 - tiny)
//         where
//              R2(z) = degree 6 poly in z, (z=1/x**2)
//              S2(z) = degree 7 poly in z
//
//      Note1:
//         To compute exp(-x*x-0.5625+R/S), let s be a single
//         precision number and s := x; then
//              -x*x = -s*s + (s-x)*(s+x)
//              exp(-x*x-0.5626+R/S) =
//                      exp(-s*s-0.5625)*exp((s-x)*(s+x)+R/S);
//      Note2:
//         Here 4 and 5 make use of the asymptotic series
//                        exp(-x*x)
//              erfc(x) ~ ---------- * ( 1 + Poly(1/x**2) )
//                        x*sqrt(pi)
//         We use rational approximation to approximate
//              g(s)=f(1/x**2) = log(erfc(x)*x) - x*x + 0.5625
//         Here is the error bound for R1/S1 and R2/S2
//              |R1/S1 - f(x)|  < 2**(-62.57)
//              |R2/S2 - f(x)|  < 2**(-61.52)
//
//      5. For inf > x >= 28
//              erf(x)  = sign(x) *(1 - tiny)  (raise inexact)
//              erfc(x) = tiny*tiny (raise underflow) if x > 0
//                      = 2 - tiny if x<0
//
//      7. Special case:
//              erf(0)  = 0, erf(inf)  = 1, erf(-inf) = -1,
//              erfc(0) = 1, erfc(inf) = 0, erfc(-inf) = 2,
//              erfc/erf(NaN) is NaN

const (
	erx = 8.45062911510467529297e-01 // 0x3FEB0AC160000000
	// Coefficients for approximation to  erf in [0, 0.84375]
	efx  = 1.28379167095512586316e-01  // 0x3FC06EBA8214DB69
	efx8 = 1.02703333676410069053e+00  // 0x3FF06EBA8214DB69
	pp0  = 1.28379167095512558561e-01  // 0x3FC06EBA8214DB68
	pp1  = -3.25042107247001499370e-01 // 0xBFD4CD7D691CB913
	pp2  = -2.84817495755985104766e-02 // 0xBF9D2A51DBD7194F
	pp3  = -5.77027029648944159157e-03 // 0xBF77A291236668E4
	pp4  = -2.37630166566501626084e-05 // 0xBEF8EAD6120016AC
	qq1  = 3.97917223959155352819e-01  // 0x3FD97779CDDADC09
	qq2  = 6.50222499887672944485e-02  // 0x3FB0A54C5536CEBA
	qq3  = 5.08130628187576562776e-03  // 0x3F74D022C4D36B0F
	qq4  = 1.32494738004321644526e-04  // 0x3F215DC9221C1A10
	qq5  = -3.96022827877536812320e-06 // 0xBED09C4342A26120
	// Coefficients for approximation to  erf  in [0.84375, 1.25]
	pa0 = -2.36211856075265944077e-03 // 0xBF6359B8BEF77538
	pa1 = 4.14856118683748331666e-01  // 0x3FDA8D00AD92B34D
	pa2 = -3.72207876035701323847e-01 // 0xBFD7D240FBB8C3F1
	pa3 = 3.18346619901161753674e-01  // 0x3FD45FCA805120E4
	pa4 = -1.10894694282396677476e-01 // 0xBFBC63983D3E28EC
	pa5 = 3.54783043256182359371e-02  // 0x3FA22A36599795EB
	pa6 = -2.16637559486879084300e-03 // 0xBF61BF380A96073F
	qa1 = 1.06420880400844228286e-01  // 0x3FBB3E6618EEE323
	qa2 = 5.40397917702171048937e-01  // 0x3FE14AF092EB6F33
	qa3 = 7.18286544141962662868e-02  // 0x3FB2635CD99FE9A7
	qa4 = 1.26171219808761642112e-01  // 0x3FC02660E763351F
	qa5 = 1.36370839120290507362e-02  // 0x3F8BEDC26B51DD1C
	qa6 = 1.19844998467991074170e-02  // 0x3F888B545735151D
	// Coefficients for approximation to  erfc in [1.25, 1/0.35]
	ra0 = -9.86494403484714822705e-03 // 0xBF843412600D6435
	ra1 = -6.93858572707181764372e-01 // 0xBFE63416E4BA7360
	ra2 = -1.05586262253232909814e+01 // 0xC0251E0441B0E726
	ra3 = -6.23753324503260060396e+01 // 0xC04F300AE4CBA38D
	ra4 = -1.62396669462573470355e+02 // 0xC0644CB184282266
	ra5 = -1.84605092906711035994e+02 // 0xC067135CEBCCABB2
	ra6 = -8.12874355063065934246e+01 // 0xC054526557E4D2F2
	ra7 = -9.81432934416914548592e+00 // 0xC023A0EFC69AC25C
	sa1 = 1.96512716674392571292e+01  // 0x4033A6B9BD707687
	sa2 = 1.37657754143519042600e+02  // 0x4061350C526AE721
	sa3 = 4.34565877475229228821e+02  // 0x407B290DD58A1A71
	sa4 = 6.45387271733267880336e+02  // 0x40842B1921EC2868
	sa5 = 4.29008140027567833386e+02  // 0x407AD02157700314
	sa6 = 1.08635005541779435134e+02  // 0x405B28A3EE48AE2C
	sa7 = 6.57024977031928170135e+00  // 0x401A47EF8E484A93
	sa8 = -6.04244152148580987438e-02 // 0xBFAEEFF2EE749A62
	// Coefficients for approximation to  erfc in [1/.35, 28]
	rb0 = -9.86494292470009928597e-03 // 0xBF84341239E86F4A
	rb1 = -7.99283237680523006574e-01 // 0xBFE993BA70C285DE
	rb2 = -1.77579549177547519889e+01 // 0xC031C209555F995A
	rb3 = -1.60636384855821916062e+02 // 0xC064145D43C5ED98
	rb4 = -6.37566443368389627722e+02 // 0xC083EC881375F228
	rb5 = -1.02509513161107724954e+03 // 0xC09004616A2E5992
	rb6 = -4.83519191608651397019e+02 // 0xC07E384E9BDC383F
	sb1 = 3.03380607434824582924e+01  // 0x403E568B261D5190
	sb2 = 3.25792512996573918826e+02  // 0x40745CAE221B9F0A
	sb3 = 1.53672958608443695994e+03  // 0x409802EB189D5118
	sb4 = 3.19985821950859553908e+03  // 0x40A8FFB7688C246A
	sb5 = 2.55305040643316442583e+03  // 0x40A3F219CEDF3BE6
	sb6 = 4.74528541206955367215e+02  // 0x407DA874E79FE763
	sb7 = -2.24409524465858183362e+01 // 0xC03670E242712D62
)

// Erf returns the error function of x.
//
// Special cases are:
//
//	Erf(+Inf) = 1
//	Erf(-Inf) = -1
//	Erf(NaN) = NaN
func Erf(x float64) float64 {
	if haveArchErf {
		return archErf(x)
	}
	return erf(x)
}

func erf(x float64) float64 {
	const (
		VeryTiny = 2.848094538889218e-306 // 0x0080000000000000
		Small    = 1.0 / (1 << 28)        // 2**-28
	)
	// special cases
	switch {
	case IsNaN(x):
		return NaN()
	case IsInf(x, 1):
		return 1
	case IsInf(x, -1):
		return -1
	}
	sign := false
	if x < 0 {
		x = -x
		sign = true
	}
	if x < 0.84375 { // |x| < 0.84375
		var temp float64
		if x < Small { // |x| < 2**-28
			if x < VeryTiny {
				temp = 0.125 * (8.0*x + efx8*x) // avoid underflow
			} else {
				temp = x + efx*x
			}
		} else {
			z := x * x
			r := pp0 + z*(pp1+z*(pp2+z*(pp3+z*pp4)))
			s := 1 + z*(qq1+z*(qq2+z*(qq3+z*(qq4+z*qq5))))
			y := r / s
			temp = x + x*y
		}
		if sign {
			return -temp
		}
		return temp
	}
	if x < 1.25 { // 0.84375 <= |x| < 1.25
		s := x - 1
		P := pa0 + s*(pa1+s*(pa2+s*(pa3+s*(pa4+s*(pa5+s*pa6)))))
		Q := 1 + s*(qa1+s*(qa2+s*(qa3+s*(qa4+s*(qa5+s*qa6)))))
		if sign {
			return -erx - P/Q
		}
		return erx + P/Q
	}
	if x >= 6 { // inf > |x| >= 6
		if sign {
			return -1
		}
		return 1
	}
	s := 1 / (x * x)
	var R, S float64
	if x < 1/0.35 { // |x| < 1 / 0.35  ~ 2.857143
		R = ra0 + s*(ra1+s*(ra2+s*(ra3+s*(ra4+s*(ra5+s*(ra6+s*ra7))))))
		S = 1 + s*(sa1+s*(sa2+s*(sa3+s*(sa4+s*(sa5+s*(sa6+s*(sa7+s*sa8)))))))
	} else { // |x| >= 1 / 0.35  ~ 2.857143
		R = rb0 + s*(rb1+s*(rb2+s*(rb3+s*(rb4+s*(rb5+s*rb6)))))
		S = 1 + s*(sb1+s*(sb2+s*(sb3+s*(sb4+s*(sb5+s*(sb6+s*sb7))))))
	}
	z := Float64frombits(Float64bits(x) & 0xffffffff00000000) // pseudo-single (20-bit) precision x
	r := Exp(-z*z-0.5625) * Exp((z-x)*(z+x)+R/S)
	if sign {
		return r/x - 1
	}
	return 1 - r/x
}

// Erfc returns the complementary error function of x.
//
// Special cases are:
//
//	Erfc(+Inf) = 0
//	Erfc(-Inf) = 2
//	Erfc(NaN) = NaN
func Erfc(x float64) float64 {
	if haveArchErfc {
		return archErfc(x)
	}
	return erfc(x)
}

func erfc(x float64) float64 {
	const Tiny = 1.0 / (1 << 56) // 2**-56
	// special cases
	switch {
	case IsNaN(x):
		return NaN()
	case IsInf(x, 1):
		return 0
	case IsInf(x, -1):
		return 2
	}
	sign := false
	if x < 0 {
		x = -x
		sign = true
	}
	if x < 0.84375 { // |x| < 0.84375
		var temp float64
		if x < Tiny { // |x| < 2**-56
			temp = x
		} else {
			z := x * x
			r := pp0 + z*(pp1+z*(pp2+z*(pp3+z*pp4)))
			s := 1 + z*(qq1+z*(qq2+z*(qq3+z*(qq4+z*qq5))))
			y := r / s
			if x < 0.25 { // |x| < 1/4
				temp = x + x*y
			} else {
				temp = 0.5 + (x*y + (x - 0.5))
			}
		}
		if sign {
			return 1 + temp
		}
		return 1 - temp
	}
	if x < 1.25 { // 0.84375 <= |x| < 1.25
		s := x - 1
		P := pa0 + s*(pa1+s*(pa2+s*(pa3+s*(pa4+s*(pa5+s*pa6)))))
		Q := 1 + s*(qa1+s*(qa2+s*(qa3+s*(qa4+s*(qa5+s*qa6)))))
		if sign {
			return 1 + erx + P/Q
		}
		return 1 - erx - P/Q

	}
	if x < 28 { // |x| < 28
		s := 1 / (x * x)
		var R, S float64
		if x < 1/0.35 { // |x| < 1 / 0.35 ~ 2.857143
			R = ra0 + s*(ra1+s*(ra2+s*(ra3+s*(ra4+s*(ra5+s*(ra6+s*ra7))))))
			S = 1 + s*(sa1+s*(sa2+s*(sa3+s*(sa4+s*(sa5+s*(sa6+s*(sa7+s*sa8)))))))
		} else { // |x| >= 1 / 0.35 ~ 2.857143
			if sign && x > 6 {
				return 2 // x < -6
			}
			R = rb0 + s*(rb1+s*(rb2+s*(rb3+s*(rb4+s*(rb5+s*rb6)))))
			S = 1 + s*(sb1+s*(sb2+s*(sb3+s*(sb4+s*(sb5+s*(sb6+s*sb7))))))
		}
		z := Float64frombits(Float64bits(x) & 0xffffffff00000000) // pseudo-single (20-bit) precision x
		r := Exp(-z*z-0.5625) * Exp((z-x)*(z+x)+R/S)
		if sign {
			return 2 - r/x
		}
		return r / x
	}
	if sign {
		return 2
	}
	return 0
}

"""



```