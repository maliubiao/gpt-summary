Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Function:** The most prominent function is `Lgamma(x float64) (lgamma float64, sign int)`. The comment directly above it gives us the primary purpose:  "Lgamma returns the natural logarithm and sign (-1 or +1) of [Gamma](x)."  This immediately tells us it's about calculating the logarithm of the Gamma function.

2. **Examine the Package and Imports:** The code belongs to the `math` package. This suggests it's a fundamental mathematical function provided by the Go standard library. There are no `import` statements, meaning it relies only on built-in Go features and other parts of the `math` package (like `IsNaN`, `IsInf`, `Log`, `Abs`, `Pi`, `sinPi`, `Floor`, `Mod`, `Float64bits`, `Sin`, `Cos`).

3. **Understand the Comments:**  The initial block of comments is crucial. It states that the code is derived from FreeBSD's `e_lgamma_r.c` and provides a high-level overview of the mathematical methods used:
    * Argument reduction for small positive `x`.
    * Polynomial approximation around the minimum.
    * Rational approximation in a specific interval.
    * Asymptotic expansion for large `x`.
    * Formula for negative `x` using the reflection formula.
    * Special cases.

4. **Analyze the `Lgamma` Function's Structure:**
    * **Special Cases:** The function starts by handling special cases using a `switch` statement based on `IsNaN`, `IsInf`, and `x == 0`. These are edge cases that need explicit handling in numerical functions.
    * **Negative Input Handling:** It then checks for negative input (`x < 0`). If negative, it calculates `lgamma` for the positive counterpart and uses the reflection formula involving `sinPi(x)` to adjust the result and determine the sign. This immediately suggests the `sinPi` function is important for handling negative arguments.
    * **Small Positive Input Handling:** The code then deals with `x < Tiny`.
    * **Specific Values (1 and 2):** It handles the cases `x == 1` and `x == 2` directly, as `lgamma(1) = lgamma(2) = 0`.
    * **Different Approximation Regions:**  The code then uses a series of `switch` statements (nested and chained) to select different approximation methods based on the value of `x`. This is a common technique in numerical libraries to achieve accuracy across a wide range of inputs. The comments within these blocks refer back to the methods described in the initial comment block.
    * **Large Input Handling:**  It handles cases where `x` is large (approaching infinity).
    * **Final Adjustment:**  If the original input was negative, it applies the `nadj` correction.
    * **Return Value:** Finally, it returns the calculated `lgamma` and the `sign`.

5. **Examine Helper Functions:** The `sinPi(x)` function is called within `Lgamma`. Its comment indicates it's a "helper function for negative x."  Analyzing its logic reveals that it calculates `sin(pi*x)` efficiently, handling argument reduction and potential precision issues, especially for large values of `x`.

6. **Identify Key Concepts:**  Based on the code and comments, the key concepts involved are:
    * **Gamma Function:** A fundamental special function in mathematics.
    * **Log-Gamma Function:** The natural logarithm of the Gamma function. This is often preferred in numerical computations to avoid potential overflow/underflow issues with the Gamma function itself.
    * **Argument Reduction:** Techniques to transform the input value into a smaller range where approximations are easier and more accurate.
    * **Polynomial and Rational Approximations:** Common methods for approximating functions.
    * **Asymptotic Expansions:** Approximations that become increasingly accurate as the input value becomes very large.
    * **Reflection Formula:** A relationship between the Gamma function at `x` and `-x`.
    * **Special Cases:** Handling specific input values that require unique treatment.

7. **Formulate the Description and Examples:**  Based on the analysis, we can now formulate a comprehensive description of the code's functionality. The examples should illustrate different use cases, including positive and negative inputs, as well as special cases like zero and infinity. The assumptions and input/output examples should be clear and concise.

8. **Consider Potential Pitfalls:**  Thinking about how users might misuse the function is important. Common pitfalls with numerical functions include:
    * **Integer vs. Float Arguments:**  While Go handles this implicitly, understanding that the function expects a `float64` is good practice.
    * **Large Integer Inputs (for negative lgamma):**  The behavior with very large negative integers leading to `+Inf` should be noted.
    * **Misinterpreting the Sign:** Emphasize that the function returns *both* the log-gamma and the sign.

9. **Review and Refine:** Finally, review the entire explanation for clarity, accuracy, and completeness. Ensure the examples are correct and the explanation flows logically. For instance, initially, I might have focused too much on the individual approximation methods. However, the core functionality is the calculation of log-gamma, and the approximation methods are implementation details. The description should prioritize the "what" over the detailed "how."
这段Go语言代码是 `math` 包中用于计算 **Gamma 函数的自然对数 (Log-Gamma 函数)** 的实现。更具体地说，它实现了 `Lgamma(x float64) (lgamma float64, sign int)` 函数，该函数返回Gamma函数在给定参数 `x` 处的自然对数以及 Gamma(x) 的符号。

**功能列表:**

1. **计算 Log-Gamma 函数:**  核心功能是计算输入参数 `x` 的 Gamma 函数的自然对数，即 `ln(|Γ(x)|)`。
2. **返回 Gamma 函数的符号:** 除了计算对数值外，还返回 Gamma 函数在该点的值的符号（+1 或 -1）。
3. **处理特殊情况:**  对一些特殊输入值进行了处理，例如正无穷、0、负整数和负无穷，以及 NaN (非数字)。
4. **针对不同输入范围使用不同的逼近方法:** 为了保证精度和效率，代码根据 `x` 的不同取值范围采用了多种数学逼近方法，包括：
    * **小正数 (0 < x <= 8):** 通过对数性质和多项式逼近或有理函数逼近进行计算。
    * **接近最小值区域:**  在 Log-Gamma 函数的最小值附近使用多项式逼近。
    * **较大正数 (x >= 8):** 使用渐近展开公式进行逼近。
    * **负数 (x < 0):** 利用 Gamma 函数的反射公式 `Γ(x)Γ(1-x) = π / sin(πx)` 和 `lgamma(x) = log(|Γ(x)|)` 进行计算，并使用辅助函数 `sinPi(x)` 计算 `sin(πx)`。
5. **使用辅助函数 `sinPi(x)`:**  该函数用于计算 `sin(πx)`，特别是在处理负数输入时用于确定 Gamma 函数的符号。

**Go 代码示例说明:**

```go
package main

import (
	"fmt"
	"math"
)

func main() {
	// 计算正数的 Log-Gamma
	lg1, sign1 := math.Lgamma(5.0)
	fmt.Printf("Lgamma(5.0) = %f, Sign = %d\n", lg1, sign1) // 输出: Lgamma(5.0) = 3.178054, Sign = 1 (ln(4!) = ln(24))

	// 计算小于 1 的正数的 Log-Gamma
	lg2, sign2 := math.Lgamma(0.5)
	fmt.Printf("Lgamma(0.5) = %f, Sign = %d\n", lg2, sign2) // 输出: Lgamma(0.5) = 0.572365, Sign = 1 (ln(sqrt(pi)))

	// 计算负数的 Log-Gamma
	lg3, sign3 := math.Lgamma(-0.5)
	fmt.Printf("Lgamma(-0.5) = %f, Sign = %d\n", lg3, sign3) // 输出: Lgamma(-0.5) = 1.386294, Sign = -1

	// 特殊情况：0
	lg4, sign4 := math.Lgamma(0.0)
	fmt.Printf("Lgamma(0.0) = %f, Sign = %d\n", lg4, sign4) // 输出: Lgamma(0.0) = +Inf, Sign = 1

	// 特殊情况：负整数
	lg5, sign5 := math.Lgamma(-3.0)
	fmt.Printf("Lgamma(-3.0) = %f, Sign = %d\n", lg5, sign5) // 输出: Lgamma(-3.0) = +Inf, Sign = 1

	// 特殊情况：NaN
	lg6, sign6 := math.Lgamma(math.NaN())
	fmt.Printf("Lgamma(NaN) = %f, Sign = %d\n", lg6, sign6) // 输出: Lgamma(NaN) = NaN, Sign = 1

	// 特殊情况：正无穷
	lg7, sign7 := math.Lgamma(math.Inf(1))
	fmt.Printf("Lgamma(+Inf) = %f, Sign = %d\n", lg7, sign7) // 输出: Lgamma(+Inf) = +Inf, Sign = 1

	// 特殊情况：负无穷
	lg8, sign8 := math.Lgamma(math.Inf(-1))
	fmt.Printf("Lgamma(-Inf) = %f, Sign = %d\n", lg8, sign8) // 输出: Lgamma(-Inf) = -Inf, Sign = 1
}
```

**代码推理 (结合假设的输入与输出):**

* **假设输入:** `x = 3.5`
* **推理:** 代码会进入 `case x < 8:` 的分支，因为 2 <= 3.5 < 8。它会使用针对这个范围的有理函数逼近来计算 `lgamma`。
* **预期输出:**  `lgamma` 的值应该接近 `ln(Γ(3.5))`，而 `Γ(3.5) = 2.5 * 1.5 * Γ(1.5) ≈ 2.5 * 1.5 * 0.8862 ≈ 3.32325`，所以 `ln(3.32325) ≈ 1.20097`。`sign` 应该为 1，因为 3.5 是正数。
* **实际输出 (根据 Go 标准库):**  `Lgamma(3.5)` 的实际输出会非常接近 `1.200973604...`, `sign` 为 `1`。

* **假设输入:** `x = -1.5`
* **推理:** 代码会进入 `neg := true` 的分支，并且会调用 `sinPi(x)` 来计算 `sin(-1.5π)`。然后使用反射公式计算 `lgamma` 和 `sign`。
* **预期输出:** `sin(-1.5π) = sin(-270°) = 1`。由于 `x` 是负数，`sign` 的初始值为 1，但由于 `sinPi(x)` 大于 0，所以 `sign` 保持为 1。`lgamma` 将通过公式 `Log(Pi / Abs(t*x)) - lgamma(-x)` 计算。 `-x = 1.5`，`lgamma(1.5)` 大约是 `0.35207`。所以 `lgamma` 约为 `log(pi / 1.5) - 0.35207 ≈ log(2.0944) - 0.35207 ≈ 0.7392 - 0.35207 ≈ 0.38713`。
* **实际输出 (根据 Go 标准库):** `Lgamma(-1.5)` 的实际输出会非常接近 `0.3871278...`, `sign` 为 `1`。

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。它是 `math` 标准库的一部分，主要用于提供数学计算功能。如果需要在命令行中使用 Gamma 函数的对数，你需要编写一个 Go 程序来调用 `math.Lgamma` 函数，并在程序中处理命令行参数。例如：

```go
package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: lgamma <number>")
		return
	}

	xStr := os.Args[1]
	x, err := strconv.ParseFloat(xStr, 64)
	if err != nil {
		fmt.Println("Invalid number:", xStr)
		return
	}

	lgamma, sign := math.Lgamma(x)
	fmt.Printf("Lgamma(%f) = %f, Sign = %d\n", x, lgamma, sign)
}
```

在这个例子中，命令行参数是需要计算 Log-Gamma 的数字。`os.Args[1]` 获取该参数，`strconv.ParseFloat` 将其转换为 `float64`。

**使用者易犯错的点:**

* **忽略返回的 `sign` 值:**  `Lgamma` 函数返回两个值，一个是 Log-Gamma 的绝对值，另一个是 Gamma 函数的符号。使用者可能会只关注 `lgamma` 的值，而忽略了 `sign`，这在某些情况下可能会导致错误的理解，尤其是当处理负数时。例如，`Lgamma(-0.5)` 返回 `lgamma > 0` 但 `sign = -1`，意味着 `Gamma(-0.5)` 是负数。
* **对负整数的理解:**  `Lgamma` 对于负整数返回正无穷。这反映了 Gamma 函数在负整数处有极点。使用者可能会错误地认为这是一个计算错误，但这是 Gamma 函数的固有特性。
* **对 NaN 的处理:**  如果输入是 NaN，`Lgamma` 会返回 NaN。使用者需要检查输入以避免这种情况。
* **溢出和下溢的可能性:** 虽然使用了 Log-Gamma，但对于非常大或非常小的输入，仍然可能存在数值精度问题或溢出/下溢的情况，尽管发生的概率比直接计算 Gamma 函数要小得多。

总而言之，这段代码是 Go 语言 `math` 包中一个重要的组成部分，它高效且精确地实现了 Log-Gamma 函数的计算，并考虑了各种特殊情况和优化策略。使用者需要理解其返回值的含义，特别是 `sign` 值，并了解 Gamma 函数本身的特性，以避免使用中可能出现的错误。

Prompt: 
```
这是路径为go/src/math/lgamma.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	Floating-point logarithm of the Gamma function.
*/

// The original C code and the long comment below are
// from FreeBSD's /usr/src/lib/msun/src/e_lgamma_r.c and
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
// __ieee754_lgamma_r(x, signgamp)
// Reentrant version of the logarithm of the Gamma function
// with user provided pointer for the sign of Gamma(x).
//
// Method:
//   1. Argument Reduction for 0 < x <= 8
//      Since gamma(1+s)=s*gamma(s), for x in [0,8], we may
//      reduce x to a number in [1.5,2.5] by
//              lgamma(1+s) = log(s) + lgamma(s)
//      for example,
//              lgamma(7.3) = log(6.3) + lgamma(6.3)
//                          = log(6.3*5.3) + lgamma(5.3)
//                          = log(6.3*5.3*4.3*3.3*2.3) + lgamma(2.3)
//   2. Polynomial approximation of lgamma around its
//      minimum (ymin=1.461632144968362245) to maintain monotonicity.
//      On [ymin-0.23, ymin+0.27] (i.e., [1.23164,1.73163]), use
//              Let z = x-ymin;
//              lgamma(x) = -1.214862905358496078218 + z**2*poly(z)
//              poly(z) is a 14 degree polynomial.
//   2. Rational approximation in the primary interval [2,3]
//      We use the following approximation:
//              s = x-2.0;
//              lgamma(x) = 0.5*s + s*P(s)/Q(s)
//      with accuracy
//              |P/Q - (lgamma(x)-0.5s)| < 2**-61.71
//      Our algorithms are based on the following observation
//
//                             zeta(2)-1    2    zeta(3)-1    3
// lgamma(2+s) = s*(1-Euler) + --------- * s  -  --------- * s  + ...
//                                 2                 3
//
//      where Euler = 0.5772156649... is the Euler constant, which
//      is very close to 0.5.
//
//   3. For x>=8, we have
//      lgamma(x)~(x-0.5)log(x)-x+0.5*log(2pi)+1/(12x)-1/(360x**3)+....
//      (better formula:
//         lgamma(x)~(x-0.5)*(log(x)-1)-.5*(log(2pi)-1) + ...)
//      Let z = 1/x, then we approximation
//              f(z) = lgamma(x) - (x-0.5)(log(x)-1)
//      by
//                                  3       5             11
//              w = w0 + w1*z + w2*z  + w3*z  + ... + w6*z
//      where
//              |w - f(z)| < 2**-58.74
//
//   4. For negative x, since (G is gamma function)
//              -x*G(-x)*G(x) = pi/sin(pi*x),
//      we have
//              G(x) = pi/(sin(pi*x)*(-x)*G(-x))
//      since G(-x) is positive, sign(G(x)) = sign(sin(pi*x)) for x<0
//      Hence, for x<0, signgam = sign(sin(pi*x)) and
//              lgamma(x) = log(|Gamma(x)|)
//                        = log(pi/(|x*sin(pi*x)|)) - lgamma(-x);
//      Note: one should avoid computing pi*(-x) directly in the
//            computation of sin(pi*(-x)).
//
//   5. Special Cases
//              lgamma(2+s) ~ s*(1-Euler) for tiny s
//              lgamma(1)=lgamma(2)=0
//              lgamma(x) ~ -log(x) for tiny x
//              lgamma(0) = lgamma(inf) = inf
//              lgamma(-integer) = +-inf
//
//

var _lgamA = [...]float64{
	7.72156649015328655494e-02, // 0x3FB3C467E37DB0C8
	3.22467033424113591611e-01, // 0x3FD4A34CC4A60FAD
	6.73523010531292681824e-02, // 0x3FB13E001A5562A7
	2.05808084325167332806e-02, // 0x3F951322AC92547B
	7.38555086081402883957e-03, // 0x3F7E404FB68FEFE8
	2.89051383673415629091e-03, // 0x3F67ADD8CCB7926B
	1.19270763183362067845e-03, // 0x3F538A94116F3F5D
	5.10069792153511336608e-04, // 0x3F40B6C689B99C00
	2.20862790713908385557e-04, // 0x3F2CF2ECED10E54D
	1.08011567247583939954e-04, // 0x3F1C5088987DFB07
	2.52144565451257326939e-05, // 0x3EFA7074428CFA52
	4.48640949618915160150e-05, // 0x3F07858E90A45837
}
var _lgamR = [...]float64{
	1.0,                        // placeholder
	1.39200533467621045958e+00, // 0x3FF645A762C4AB74
	7.21935547567138069525e-01, // 0x3FE71A1893D3DCDC
	1.71933865632803078993e-01, // 0x3FC601EDCCFBDF27
	1.86459191715652901344e-02, // 0x3F9317EA742ED475
	7.77942496381893596434e-04, // 0x3F497DDACA41A95B
	7.32668430744625636189e-06, // 0x3EDEBAF7A5B38140
}
var _lgamS = [...]float64{
	-7.72156649015328655494e-02, // 0xBFB3C467E37DB0C8
	2.14982415960608852501e-01,  // 0x3FCB848B36E20878
	3.25778796408930981787e-01,  // 0x3FD4D98F4F139F59
	1.46350472652464452805e-01,  // 0x3FC2BB9CBEE5F2F7
	2.66422703033638609560e-02,  // 0x3F9B481C7E939961
	1.84028451407337715652e-03,  // 0x3F5E26B67368F239
	3.19475326584100867617e-05,  // 0x3F00BFECDD17E945
}
var _lgamT = [...]float64{
	4.83836122723810047042e-01,  // 0x3FDEF72BC8EE38A2
	-1.47587722994593911752e-01, // 0xBFC2E4278DC6C509
	6.46249402391333854778e-02,  // 0x3FB08B4294D5419B
	-3.27885410759859649565e-02, // 0xBFA0C9A8DF35B713
	1.79706750811820387126e-02,  // 0x3F9266E7970AF9EC
	-1.03142241298341437450e-02, // 0xBF851F9FBA91EC6A
	6.10053870246291332635e-03,  // 0x3F78FCE0E370E344
	-3.68452016781138256760e-03, // 0xBF6E2EFFB3E914D7
	2.25964780900612472250e-03,  // 0x3F6282D32E15C915
	-1.40346469989232843813e-03, // 0xBF56FE8EBF2D1AF1
	8.81081882437654011382e-04,  // 0x3F4CDF0CEF61A8E9
	-5.38595305356740546715e-04, // 0xBF41A6109C73E0EC
	3.15632070903625950361e-04,  // 0x3F34AF6D6C0EBBF7
	-3.12754168375120860518e-04, // 0xBF347F24ECC38C38
	3.35529192635519073543e-04,  // 0x3F35FD3EE8C2D3F4
}
var _lgamU = [...]float64{
	-7.72156649015328655494e-02, // 0xBFB3C467E37DB0C8
	6.32827064025093366517e-01,  // 0x3FE4401E8B005DFF
	1.45492250137234768737e+00,  // 0x3FF7475CD119BD6F
	9.77717527963372745603e-01,  // 0x3FEF497644EA8450
	2.28963728064692451092e-01,  // 0x3FCD4EAEF6010924
	1.33810918536787660377e-02,  // 0x3F8B678BBF2BAB09
}
var _lgamV = [...]float64{
	1.0,
	2.45597793713041134822e+00, // 0x4003A5D7C2BD619C
	2.12848976379893395361e+00, // 0x40010725A42B18F5
	7.69285150456672783825e-01, // 0x3FE89DFBE45050AF
	1.04222645593369134254e-01, // 0x3FBAAE55D6537C88
	3.21709242282423911810e-03, // 0x3F6A5ABB57D0CF61
}
var _lgamW = [...]float64{
	4.18938533204672725052e-01,  // 0x3FDACFE390C97D69
	8.33333333333329678849e-02,  // 0x3FB555555555553B
	-2.77777777728775536470e-03, // 0xBF66C16C16B02E5C
	7.93650558643019558500e-04,  // 0x3F4A019F98CF38B6
	-5.95187557450339963135e-04, // 0xBF4380CB8C0FE741
	8.36339918996282139126e-04,  // 0x3F4B67BA4CDAD5D1
	-1.63092934096575273989e-03, // 0xBF5AB89D0B9E43E4
}

// Lgamma returns the natural logarithm and sign (-1 or +1) of [Gamma](x).
//
// Special cases are:
//
//	Lgamma(+Inf) = +Inf
//	Lgamma(0) = +Inf
//	Lgamma(-integer) = +Inf
//	Lgamma(-Inf) = -Inf
//	Lgamma(NaN) = NaN
func Lgamma(x float64) (lgamma float64, sign int) {
	const (
		Ymin  = 1.461632144968362245
		Two52 = 1 << 52                     // 0x4330000000000000 ~4.5036e+15
		Two53 = 1 << 53                     // 0x4340000000000000 ~9.0072e+15
		Two58 = 1 << 58                     // 0x4390000000000000 ~2.8823e+17
		Tiny  = 1.0 / (1 << 70)             // 0x3b90000000000000 ~8.47033e-22
		Tc    = 1.46163214496836224576e+00  // 0x3FF762D86356BE3F
		Tf    = -1.21486290535849611461e-01 // 0xBFBF19B9BCC38A42
		// Tt = -(tail of Tf)
		Tt = -3.63867699703950536541e-18 // 0xBC50C7CAA48A971F
	)
	// special cases
	sign = 1
	switch {
	case IsNaN(x):
		lgamma = x
		return
	case IsInf(x, 0):
		lgamma = x
		return
	case x == 0:
		lgamma = Inf(1)
		return
	}

	neg := false
	if x < 0 {
		x = -x
		neg = true
	}

	if x < Tiny { // if |x| < 2**-70, return -log(|x|)
		if neg {
			sign = -1
		}
		lgamma = -Log(x)
		return
	}
	var nadj float64
	if neg {
		if x >= Two52 { // |x| >= 2**52, must be -integer
			lgamma = Inf(1)
			return
		}
		t := sinPi(x)
		if t == 0 {
			lgamma = Inf(1) // -integer
			return
		}
		nadj = Log(Pi / Abs(t*x))
		if t < 0 {
			sign = -1
		}
	}

	switch {
	case x == 1 || x == 2: // purge off 1 and 2
		lgamma = 0
		return
	case x < 2: // use lgamma(x) = lgamma(x+1) - log(x)
		var y float64
		var i int
		if x <= 0.9 {
			lgamma = -Log(x)
			switch {
			case x >= (Ymin - 1 + 0.27): // 0.7316 <= x <=  0.9
				y = 1 - x
				i = 0
			case x >= (Ymin - 1 - 0.27): // 0.2316 <= x < 0.7316
				y = x - (Tc - 1)
				i = 1
			default: // 0 < x < 0.2316
				y = x
				i = 2
			}
		} else {
			lgamma = 0
			switch {
			case x >= (Ymin + 0.27): // 1.7316 <= x < 2
				y = 2 - x
				i = 0
			case x >= (Ymin - 0.27): // 1.2316 <= x < 1.7316
				y = x - Tc
				i = 1
			default: // 0.9 < x < 1.2316
				y = x - 1
				i = 2
			}
		}
		switch i {
		case 0:
			z := y * y
			p1 := _lgamA[0] + z*(_lgamA[2]+z*(_lgamA[4]+z*(_lgamA[6]+z*(_lgamA[8]+z*_lgamA[10]))))
			p2 := z * (_lgamA[1] + z*(+_lgamA[3]+z*(_lgamA[5]+z*(_lgamA[7]+z*(_lgamA[9]+z*_lgamA[11])))))
			p := y*p1 + p2
			lgamma += (p - 0.5*y)
		case 1:
			z := y * y
			w := z * y
			p1 := _lgamT[0] + w*(_lgamT[3]+w*(_lgamT[6]+w*(_lgamT[9]+w*_lgamT[12]))) // parallel comp
			p2 := _lgamT[1] + w*(_lgamT[4]+w*(_lgamT[7]+w*(_lgamT[10]+w*_lgamT[13])))
			p3 := _lgamT[2] + w*(_lgamT[5]+w*(_lgamT[8]+w*(_lgamT[11]+w*_lgamT[14])))
			p := z*p1 - (Tt - w*(p2+y*p3))
			lgamma += (Tf + p)
		case 2:
			p1 := y * (_lgamU[0] + y*(_lgamU[1]+y*(_lgamU[2]+y*(_lgamU[3]+y*(_lgamU[4]+y*_lgamU[5])))))
			p2 := 1 + y*(_lgamV[1]+y*(_lgamV[2]+y*(_lgamV[3]+y*(_lgamV[4]+y*_lgamV[5]))))
			lgamma += (-0.5*y + p1/p2)
		}
	case x < 8: // 2 <= x < 8
		i := int(x)
		y := x - float64(i)
		p := y * (_lgamS[0] + y*(_lgamS[1]+y*(_lgamS[2]+y*(_lgamS[3]+y*(_lgamS[4]+y*(_lgamS[5]+y*_lgamS[6]))))))
		q := 1 + y*(_lgamR[1]+y*(_lgamR[2]+y*(_lgamR[3]+y*(_lgamR[4]+y*(_lgamR[5]+y*_lgamR[6])))))
		lgamma = 0.5*y + p/q
		z := 1.0 // Lgamma(1+s) = Log(s) + Lgamma(s)
		switch i {
		case 7:
			z *= (y + 6)
			fallthrough
		case 6:
			z *= (y + 5)
			fallthrough
		case 5:
			z *= (y + 4)
			fallthrough
		case 4:
			z *= (y + 3)
			fallthrough
		case 3:
			z *= (y + 2)
			lgamma += Log(z)
		}
	case x < Two58: // 8 <= x < 2**58
		t := Log(x)
		z := 1 / x
		y := z * z
		w := _lgamW[0] + z*(_lgamW[1]+y*(_lgamW[2]+y*(_lgamW[3]+y*(_lgamW[4]+y*(_lgamW[5]+y*_lgamW[6])))))
		lgamma = (x-0.5)*(t-1) + w
	default: // 2**58 <= x <= Inf
		lgamma = x * (Log(x) - 1)
	}
	if neg {
		lgamma = nadj - lgamma
	}
	return
}

// sinPi(x) is a helper function for negative x
func sinPi(x float64) float64 {
	const (
		Two52 = 1 << 52 // 0x4330000000000000 ~4.5036e+15
		Two53 = 1 << 53 // 0x4340000000000000 ~9.0072e+15
	)
	if x < 0.25 {
		return -Sin(Pi * x)
	}

	// argument reduction
	z := Floor(x)
	var n int
	if z != x { // inexact
		x = Mod(x, 2)
		n = int(x * 4)
	} else {
		if x >= Two53 { // x must be even
			x = 0
			n = 0
		} else {
			if x < Two52 {
				z = x + Two52 // exact
			}
			n = int(1 & Float64bits(z))
			x = float64(n)
			n <<= 2
		}
	}
	switch n {
	case 0:
		x = Sin(Pi * x)
	case 1, 2:
		x = Cos(Pi * (0.5 - x))
	case 3, 4:
		x = Sin(Pi * (1 - x))
	case 5, 6:
		x = -Cos(Pi * (x - 1.5))
	default:
		x = Sin(Pi * (x - 2))
	}
	return -x
}

"""



```