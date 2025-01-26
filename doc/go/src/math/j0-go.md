Response:
我的思考过程如下：

1. **理解目标:**  用户提供了一段 Go 语言代码，要求我分析其功能，解释它是如何实现 Go 语言特定功能的，并提供代码示例、输入输出、命令行参数处理、以及可能的错误点。

2. **代码结构概览:** 首先，我快速浏览代码，注意到以下几个关键点：
    * 文件路径 `go/src/math/j0.go` 表明这是 Go 语言标准库 `math` 包的一部分。
    * 代码开头注释提到了 Bessel 函数，特别是第一类和第二类的零阶 Bessel 函数 (J0 和 Y0)。
    * 注释中包含了来自 FreeBSD 的 C 代码和详细的数学推导，这对于理解代码背后的逻辑至关重要。
    * 定义了两个主要的公共函数 `J0(x float64)` 和 `Y0(x float64)`，分别计算 J0 和 Y0。
    * 代码中使用了常量和查找表（例如 `R02`, `S01`, `p0R8`, `q0R8` 等），这暗示了分段逼近或查表优化的方法。
    * 代码中处理了特殊的输入情况，如 NaN、无穷大和零。
    * 存在辅助函数 `pzero(x float64)` 和 `qzero(x float64)`，它们在计算 `J0` 和 `Y0` 中被调用。

3. **功能识别:**  基于代码结构和注释，我可以明确地判断出这段代码的核心功能是实现了**零阶 Bessel 函数 J0(x) 和 Y0(x) 的计算**。

4. **Go 语言功能关联:**  这是一个数学函数的实现，它属于 Go 语言标准库的 `math` 包。`math` 包提供了各种常用的数学函数。因此，这段代码是 **Go 语言标准库中提供数学计算功能** 的一个具体例子。

5. **实现原理推理:**  注释中的数学公式和分段逼近的描述是理解实现原理的关键。
    * **小 x 的情况:**  使用了泰勒展开的近似。
    * **中等 x 的情况 (0 到 2):**  使用了有理函数逼近。
    * **大 x 的情况 (大于 2):**  使用了渐近展开，涉及到三角函数 `sin` 和 `cos` 的计算。
    * **辅助函数 `pzero` 和 `qzero`:** 用于计算渐近展开中的多项式部分。

6. **代码示例:**  为了说明 `J0` 和 `Y0` 的使用，我编写了简单的 Go 代码示例，演示如何调用这两个函数并打印结果。  同时，我选择了几个具有代表性的输入值 (0, 小数, 中等值, 大数, NaN, 无穷大) 来覆盖不同的计算路径和特殊情况。

7. **输入输出推断:**  结合代码示例和 Bessel 函数的定义，我推断出了示例代码的输出。这需要对 Bessel 函数的基本性质有所了解。

8. **命令行参数处理:**  这段代码本身是纯粹的数学计算函数，不涉及任何命令行参数的处理。因此，这部分我直接说明了这一点。

9. **易犯错误点:** 我仔细查看了代码中的特殊情况处理，并结合 Bessel 函数的特性，想到了以下可能的错误：
    * **`Y0` 的负数输入:**  Bessel 函数 `Y0` 对于负数输入是未定义的，代码也返回 NaN。这是一个常见的易错点。
    * **误用整数作为输入:** 虽然 Go 允许将整数隐式转换为浮点数，但用户可能没有意识到精度问题。我决定不将其作为主要的易错点，因为这更属于 Go 语言的通用问题，而非 Bessel 函数的特定问题。

10. **组织答案和使用中文:**  最后，我将所有分析结果组织成结构清晰的中文答案，包括功能概述、Go 语言功能关联、代码示例、输入输出、命令行参数处理和易犯错误点。我力求用简洁明了的语言解释复杂的数学概念和代码逻辑。

**反思和改进:**

* 在最初的思考中，我主要关注了 `J0` 函数，忽略了 `Y0` 函数的特殊性，在“易犯错误点”的思考中，我补充了 `Y0` 的负数输入问题。
* 我意识到仅仅解释代码的功能是不够的，还需要将其与 Go 语言的特性联系起来，因此明确指出了它是 `math` 包的一部分，体现了 Go 语言的数学计算能力。
* 在代码示例中，我一开始只打算提供 `J0` 的示例，后来补充了 `Y0` 的示例，以更全面地展示代码的功能。
* 我努力将注释中复杂的数学公式转化为更易于理解的语言。

通过以上思考过程，我最终得到了一个相对完整和准确的答案。

这段Go语言代码文件 `j0.go` 是 `math` 标准库的一部分，它实现了**零阶贝塞尔函数**的计算，具体包括：

1. **`J0(x float64) float64`**:  计算第一类零阶贝塞尔函数 (Bessel function of the first kind of order zero)，通常记作 J₀(x)。

2. **`Y0(x float64) float64`**: 计算第二类零阶贝塞尔函数 (Bessel function of the second kind of order zero)，通常记作 Y₀(x)。

代码中还包含两个私有辅助函数：

3. **`pzero(x float64) float64`**:  用于计算 `J0` 和 `Y0` 在较大 `x` 值时的渐近展开式中的多项式部分。

4. **`qzero(x float64) float64`**:  同样用于计算 `J0` 和 `Y0` 在较大 `x` 值时的渐近展开式中的另一个多项式部分。

**它是如何实现 Go 语言功能的：**

这段代码是 Go 语言标准库 `math` 包提供的数学计算功能的一部分。`math` 包包含了各种常用的数学函数，例如三角函数、指数函数、对数函数等等。贝塞尔函数在物理学、工程学等领域有着广泛的应用，将其纳入标准库可以方便 Go 语言开发者直接使用，而无需自行实现或依赖第三方库。

**Go 代码举例说明：**

```go
package main

import (
	"fmt"
	"math"
)

func main() {
	x1 := 0.0
	x2 := 1.0
	x3 := 5.0
	x4 := -1.0
	x5 := math.Inf(1)
	x6 := math.NaN()

	fmt.Printf("J0(%f) = %f\n", x1, math.J0(x1))   // 假设输入: 0.0, 输出: 1.0
	fmt.Printf("J0(%f) = %f\n", x2, math.J0(x2))   // 假设输入: 1.0, 输出: 0.7651976865579666
	fmt.Printf("J0(%f) = %f\n", x3, math.J0(x3))   // 假设输入: 5.0, 输出: -0.1775967751313438
	fmt.Printf("J0(%f) = %f\n", x4, math.J0(x4))   // 假设输入: -1.0, 输出: 0.7651976865579666 (J0是偶函数)
	fmt.Printf("J0(%f) = %f\n", x5, math.J0(x5))   // 假设输入: +Inf, 输出: 0.0
	fmt.Printf("J0(%f) = %f\n", x6, math.J0(x6))   // 假设输入: NaN, 输出: NaN

	fmt.Println("---")

	fmt.Printf("Y0(%f) = %f\n", x1, math.Y0(x1))   // 假设输入: 0.0, 输出: -Inf
	fmt.Printf("Y0(%f) = %f\n", x2, math.Y0(x2))   // 假设输入: 1.0, 输出: 0.08825696421567947
	fmt.Printf("Y0(%f) = %f\n", x3, math.Y0(x3))   // 假设输入: 5.0, 输出: -0.04729378351028187
	fmt.Printf("Y0(%f) = %f\n", x4, math.Y0(x4))   // 假设输入: -1.0, 输出: NaN (Y0对负数无定义)
	fmt.Printf("Y0(%f) = %f\n", x5, math.Y0(x5))   // 假设输入: +Inf, 输出: 0.0
	fmt.Printf("Y0(%f) = %f\n", x6, math.Y0(x6))   // 假设输入: NaN, 输出: NaN
}
```

**代码推理 (基于注释中的方法)：**

代码的实现基于注释中描述的不同方法，针对不同的 `x` 值范围采用不同的近似计算方式，以保证精度和效率：

* **小 `x` (|x| < ~1.2207e-4):** 使用泰勒展开的近似： `j0(x) = 1 - x**2/4 + x**4/64 - ...`，代码中简化为 `1 - 0.25*x*x` 或直接返回 `1`。
* **中等 `x` (0 < |x| < 2):** 使用有理函数逼近，例如对于 `J0`:
    * `j0(x) = 1-z/4+ z**2*R0/S0`, 其中 `z = x*x`。
    * 代码中通过定义一系列常量 `R02`, `R03`, ..., `S01`, `S02`, ... 来计算 `R0` 和 `S0` 的多项式。
* **大 `x` (|x| >= 2):** 使用渐近展开：
    * `j0(x) = sqrt(2/(pi*x))*(p0(x)*cos(x0)-q0(x)*sin(x0))`
    * `y0(x) = sqrt(2/(pi*x))*(p0(x)*cos(x0)+q0(x)*sin(x0))`
    * 其中 `x0 = x-pi/4`，`p0(x)` 和 `q0(x)` 由 `pzero(x)` 和 `qzero(x)` 函数计算，也是通过分段多项式逼近实现。
* **特殊情况处理:** 代码中针对 NaN, ±Inf, 0 等特殊输入值进行了处理，返回符合贝塞尔函数定义的特殊值。

**命令行参数的具体处理：**

这段代码本身是一个库函数，不直接处理命令行参数。它被 `math` 包导入并在其他 Go 程序中被调用。如果需要从命令行获取参数并计算贝塞尔函数，需要在主程序中进行处理。例如：

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
		fmt.Println("Usage: go run main.go <value>")
		return
	}

	inputValue := os.Args[1]
	x, err := strconv.ParseFloat(inputValue, 64)
	if err != nil {
		fmt.Println("Invalid input:", err)
		return
	}

	fmt.Printf("J0(%f) = %f\n", x, math.J0(x))
	fmt.Printf("Y0(%f) = %f\n", x, math.Y0(x))
}
```

在这个例子中，命令行参数被 `os.Args` 获取，并通过 `strconv.ParseFloat` 转换为 `float64` 类型，然后传递给 `math.J0` 和 `math.Y0` 函数。

**使用者易犯错的点：**

* **`Y0(x)` 的定义域:**  `Y0(x)` 对于 `x <= 0` 是没有定义的。如果使用者传入非正数给 `Y0` 函数，将会得到 `NaN` (Not a Number)。这是使用者容易犯的错误。

   ```go
   package main

   import (
       "fmt"
       "math"
   )

   func main() {
       x := -2.0
       y := math.Y0(x)
       fmt.Println("Y0(-2.0) =", y) // 输出: Y0(-2.0) = NaN
   }
   ```

* **精度问题:** 虽然代码中使用了高精度的浮点数 `float64`，并且针对不同的 `x` 值范围使用了不同的近似方法，但在极端的数值情况下，仍然可能存在一定的精度损失。使用者需要了解浮点数运算的 inherent 局限性。

总而言之，`j0.go` 文件实现了 `math` 包中零阶贝塞尔函数的计算，通过分段近似和特殊情况处理，提供了在各种输入条件下精确且高效的计算能力。使用者需要注意 `Y0` 函数的定义域，避免传入非正数。

Prompt: 
```
这是路径为go/src/math/j0.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	Bessel function of the first and second kinds of order zero.
*/

// The original C code and the long comment below are
// from FreeBSD's /usr/src/lib/msun/src/e_j0.c and
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
// __ieee754_j0(x), __ieee754_y0(x)
// Bessel function of the first and second kinds of order zero.
// Method -- j0(x):
//      1. For tiny x, we use j0(x) = 1 - x**2/4 + x**4/64 - ...
//      2. Reduce x to |x| since j0(x)=j0(-x),  and
//         for x in (0,2)
//              j0(x) = 1-z/4+ z**2*R0/S0,  where z = x*x;
//         (precision:  |j0-1+z/4-z**2R0/S0 |<2**-63.67 )
//         for x in (2,inf)
//              j0(x) = sqrt(2/(pi*x))*(p0(x)*cos(x0)-q0(x)*sin(x0))
//         where x0 = x-pi/4. It is better to compute sin(x0),cos(x0)
//         as follow:
//              cos(x0) = cos(x)cos(pi/4)+sin(x)sin(pi/4)
//                      = 1/sqrt(2) * (cos(x) + sin(x))
//              sin(x0) = sin(x)cos(pi/4)-cos(x)sin(pi/4)
//                      = 1/sqrt(2) * (sin(x) - cos(x))
//         (To avoid cancellation, use
//              sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
//         to compute the worse one.)
//
//      3 Special cases
//              j0(nan)= nan
//              j0(0) = 1
//              j0(inf) = 0
//
// Method -- y0(x):
//      1. For x<2.
//         Since
//              y0(x) = 2/pi*(j0(x)*(ln(x/2)+Euler) + x**2/4 - ...)
//         therefore y0(x)-2/pi*j0(x)*ln(x) is an even function.
//         We use the following function to approximate y0,
//              y0(x) = U(z)/V(z) + (2/pi)*(j0(x)*ln(x)), z= x**2
//         where
//              U(z) = u00 + u01*z + ... + u06*z**6
//              V(z) = 1  + v01*z + ... + v04*z**4
//         with absolute approximation error bounded by 2**-72.
//         Note: For tiny x, U/V = u0 and j0(x)~1, hence
//              y0(tiny) = u0 + (2/pi)*ln(tiny), (choose tiny<2**-27)
//      2. For x>=2.
//              y0(x) = sqrt(2/(pi*x))*(p0(x)*cos(x0)+q0(x)*sin(x0))
//         where x0 = x-pi/4. It is better to compute sin(x0),cos(x0)
//         by the method mentioned above.
//      3. Special cases: y0(0)=-inf, y0(x<0)=NaN, y0(inf)=0.
//

// J0 returns the order-zero Bessel function of the first kind.
//
// Special cases are:
//
//	J0(±Inf) = 0
//	J0(0) = 1
//	J0(NaN) = NaN
func J0(x float64) float64 {
	const (
		Huge   = 1e300
		TwoM27 = 1.0 / (1 << 27) // 2**-27 0x3e40000000000000
		TwoM13 = 1.0 / (1 << 13) // 2**-13 0x3f20000000000000
		Two129 = 1 << 129        // 2**129 0x4800000000000000
		// R0/S0 on [0, 2]
		R02 = 1.56249999999999947958e-02  // 0x3F8FFFFFFFFFFFFD
		R03 = -1.89979294238854721751e-04 // 0xBF28E6A5B61AC6E9
		R04 = 1.82954049532700665670e-06  // 0x3EBEB1D10C503919
		R05 = -4.61832688532103189199e-09 // 0xBE33D5E773D63FCE
		S01 = 1.56191029464890010492e-02  // 0x3F8FFCE882C8C2A4
		S02 = 1.16926784663337450260e-04  // 0x3F1EA6D2DD57DBF4
		S03 = 5.13546550207318111446e-07  // 0x3EA13B54CE84D5A9
		S04 = 1.16614003333790000205e-09  // 0x3E1408BCF4745D8F
	)
	// special cases
	switch {
	case IsNaN(x):
		return x
	case IsInf(x, 0):
		return 0
	case x == 0:
		return 1
	}

	x = Abs(x)
	if x >= 2 {
		s, c := Sincos(x)
		ss := s - c
		cc := s + c

		// make sure x+x does not overflow
		if x < MaxFloat64/2 {
			z := -Cos(x + x)
			if s*c < 0 {
				cc = z / ss
			} else {
				ss = z / cc
			}
		}

		// j0(x) = 1/sqrt(pi) * (P(0,x)*cc - Q(0,x)*ss) / sqrt(x)
		// y0(x) = 1/sqrt(pi) * (P(0,x)*ss + Q(0,x)*cc) / sqrt(x)

		var z float64
		if x > Two129 { // |x| > ~6.8056e+38
			z = (1 / SqrtPi) * cc / Sqrt(x)
		} else {
			u := pzero(x)
			v := qzero(x)
			z = (1 / SqrtPi) * (u*cc - v*ss) / Sqrt(x)
		}
		return z // |x| >= 2.0
	}
	if x < TwoM13 { // |x| < ~1.2207e-4
		if x < TwoM27 {
			return 1 // |x| < ~7.4506e-9
		}
		return 1 - 0.25*x*x // ~7.4506e-9 < |x| < ~1.2207e-4
	}
	z := x * x
	r := z * (R02 + z*(R03+z*(R04+z*R05)))
	s := 1 + z*(S01+z*(S02+z*(S03+z*S04)))
	if x < 1 {
		return 1 + z*(-0.25+(r/s)) // |x| < 1.00
	}
	u := 0.5 * x
	return (1+u)*(1-u) + z*(r/s) // 1.0 < |x| < 2.0
}

// Y0 returns the order-zero Bessel function of the second kind.
//
// Special cases are:
//
//	Y0(+Inf) = 0
//	Y0(0) = -Inf
//	Y0(x < 0) = NaN
//	Y0(NaN) = NaN
func Y0(x float64) float64 {
	const (
		TwoM27 = 1.0 / (1 << 27)             // 2**-27 0x3e40000000000000
		Two129 = 1 << 129                    // 2**129 0x4800000000000000
		U00    = -7.38042951086872317523e-02 // 0xBFB2E4D699CBD01F
		U01    = 1.76666452509181115538e-01  // 0x3FC69D019DE9E3FC
		U02    = -1.38185671945596898896e-02 // 0xBF8C4CE8B16CFA97
		U03    = 3.47453432093683650238e-04  // 0x3F36C54D20B29B6B
		U04    = -3.81407053724364161125e-06 // 0xBECFFEA773D25CAD
		U05    = 1.95590137035022920206e-08  // 0x3E5500573B4EABD4
		U06    = -3.98205194132103398453e-11 // 0xBDC5E43D693FB3C8
		V01    = 1.27304834834123699328e-02  // 0x3F8A127091C9C71A
		V02    = 7.60068627350353253702e-05  // 0x3F13ECBBF578C6C1
		V03    = 2.59150851840457805467e-07  // 0x3E91642D7FF202FD
		V04    = 4.41110311332675467403e-10  // 0x3DFE50183BD6D9EF
	)
	// special cases
	switch {
	case x < 0 || IsNaN(x):
		return NaN()
	case IsInf(x, 1):
		return 0
	case x == 0:
		return Inf(-1)
	}

	if x >= 2 { // |x| >= 2.0

		// y0(x) = sqrt(2/(pi*x))*(p0(x)*sin(x0)+q0(x)*cos(x0))
		//     where x0 = x-pi/4
		// Better formula:
		//     cos(x0) = cos(x)cos(pi/4)+sin(x)sin(pi/4)
		//             =  1/sqrt(2) * (sin(x) + cos(x))
		//     sin(x0) = sin(x)cos(3pi/4)-cos(x)sin(3pi/4)
		//             =  1/sqrt(2) * (sin(x) - cos(x))
		// To avoid cancellation, use
		//     sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
		// to compute the worse one.

		s, c := Sincos(x)
		ss := s - c
		cc := s + c

		// j0(x) = 1/sqrt(pi) * (P(0,x)*cc - Q(0,x)*ss) / sqrt(x)
		// y0(x) = 1/sqrt(pi) * (P(0,x)*ss + Q(0,x)*cc) / sqrt(x)

		// make sure x+x does not overflow
		if x < MaxFloat64/2 {
			z := -Cos(x + x)
			if s*c < 0 {
				cc = z / ss
			} else {
				ss = z / cc
			}
		}
		var z float64
		if x > Two129 { // |x| > ~6.8056e+38
			z = (1 / SqrtPi) * ss / Sqrt(x)
		} else {
			u := pzero(x)
			v := qzero(x)
			z = (1 / SqrtPi) * (u*ss + v*cc) / Sqrt(x)
		}
		return z // |x| >= 2.0
	}
	if x <= TwoM27 {
		return U00 + (2/Pi)*Log(x) // |x| < ~7.4506e-9
	}
	z := x * x
	u := U00 + z*(U01+z*(U02+z*(U03+z*(U04+z*(U05+z*U06)))))
	v := 1 + z*(V01+z*(V02+z*(V03+z*V04)))
	return u/v + (2/Pi)*J0(x)*Log(x) // ~7.4506e-9 < |x| < 2.0
}

// The asymptotic expansions of pzero is
//      1 - 9/128 s**2 + 11025/98304 s**4 - ..., where s = 1/x.
// For x >= 2, We approximate pzero by
// 	pzero(x) = 1 + (R/S)
// where  R = pR0 + pR1*s**2 + pR2*s**4 + ... + pR5*s**10
// 	  S = 1 + pS0*s**2 + ... + pS4*s**10
// and
//      | pzero(x)-1-R/S | <= 2  ** ( -60.26)

// for x in [inf, 8]=1/[0,0.125]
var p0R8 = [6]float64{
	0.00000000000000000000e+00,  // 0x0000000000000000
	-7.03124999999900357484e-02, // 0xBFB1FFFFFFFFFD32
	-8.08167041275349795626e+00, // 0xC02029D0B44FA779
	-2.57063105679704847262e+02, // 0xC07011027B19E863
	-2.48521641009428822144e+03, // 0xC0A36A6ECD4DCAFC
	-5.25304380490729545272e+03, // 0xC0B4850B36CC643D
}
var p0S8 = [5]float64{
	1.16534364619668181717e+02, // 0x405D223307A96751
	3.83374475364121826715e+03, // 0x40ADF37D50596938
	4.05978572648472545552e+04, // 0x40E3D2BB6EB6B05F
	1.16752972564375915681e+05, // 0x40FC810F8F9FA9BD
	4.76277284146730962675e+04, // 0x40E741774F2C49DC
}

// for x in [8,4.5454]=1/[0.125,0.22001]
var p0R5 = [6]float64{
	-1.14125464691894502584e-11, // 0xBDA918B147E495CC
	-7.03124940873599280078e-02, // 0xBFB1FFFFE69AFBC6
	-4.15961064470587782438e+00, // 0xC010A370F90C6BBF
	-6.76747652265167261021e+01, // 0xC050EB2F5A7D1783
	-3.31231299649172967747e+02, // 0xC074B3B36742CC63
	-3.46433388365604912451e+02, // 0xC075A6EF28A38BD7
}
var p0S5 = [5]float64{
	6.07539382692300335975e+01, // 0x404E60810C98C5DE
	1.05125230595704579173e+03, // 0x40906D025C7E2864
	5.97897094333855784498e+03, // 0x40B75AF88FBE1D60
	9.62544514357774460223e+03, // 0x40C2CCB8FA76FA38
	2.40605815922939109441e+03, // 0x40A2CC1DC70BE864
}

// for x in [4.547,2.8571]=1/[0.2199,0.35001]
var p0R3 = [6]float64{
	-2.54704601771951915620e-09, // 0xBE25E1036FE1AA86
	-7.03119616381481654654e-02, // 0xBFB1FFF6F7C0E24B
	-2.40903221549529611423e+00, // 0xC00345B2AEA48074
	-2.19659774734883086467e+01, // 0xC035F74A4CB94E14
	-5.80791704701737572236e+01, // 0xC04D0A22420A1A45
	-3.14479470594888503854e+01, // 0xC03F72ACA892D80F
}
var p0S3 = [5]float64{
	3.58560338055209726349e+01, // 0x4041ED9284077DD3
	3.61513983050303863820e+02, // 0x40769839464A7C0E
	1.19360783792111533330e+03, // 0x4092A66E6D1061D6
	1.12799679856907414432e+03, // 0x40919FFCB8C39B7E
	1.73580930813335754692e+02, // 0x4065B296FC379081
}

// for x in [2.8570,2]=1/[0.3499,0.5]
var p0R2 = [6]float64{
	-8.87534333032526411254e-08, // 0xBE77D316E927026D
	-7.03030995483624743247e-02, // 0xBFB1FF62495E1E42
	-1.45073846780952986357e+00, // 0xBFF736398A24A843
	-7.63569613823527770791e+00, // 0xC01E8AF3EDAFA7F3
	-1.11931668860356747786e+01, // 0xC02662E6C5246303
	-3.23364579351335335033e+00, // 0xC009DE81AF8FE70F
}
var p0S2 = [5]float64{
	2.22202997532088808441e+01, // 0x40363865908B5959
	1.36206794218215208048e+02, // 0x4061069E0EE8878F
	2.70470278658083486789e+02, // 0x4070E78642EA079B
	1.53875394208320329881e+02, // 0x40633C033AB6FAFF
	1.46576176948256193810e+01, // 0x402D50B344391809
}

func pzero(x float64) float64 {
	var p *[6]float64
	var q *[5]float64
	if x >= 8 {
		p = &p0R8
		q = &p0S8
	} else if x >= 4.5454 {
		p = &p0R5
		q = &p0S5
	} else if x >= 2.8571 {
		p = &p0R3
		q = &p0S3
	} else if x >= 2 {
		p = &p0R2
		q = &p0S2
	}
	z := 1 / (x * x)
	r := p[0] + z*(p[1]+z*(p[2]+z*(p[3]+z*(p[4]+z*p[5]))))
	s := 1 + z*(q[0]+z*(q[1]+z*(q[2]+z*(q[3]+z*q[4]))))
	return 1 + r/s
}

// For x >= 8, the asymptotic expansions of qzero is
//      -1/8 s + 75/1024 s**3 - ..., where s = 1/x.
// We approximate pzero by
//      qzero(x) = s*(-1.25 + (R/S))
// where R = qR0 + qR1*s**2 + qR2*s**4 + ... + qR5*s**10
//       S = 1 + qS0*s**2 + ... + qS5*s**12
// and
//      | qzero(x)/s +1.25-R/S | <= 2**(-61.22)

// for x in [inf, 8]=1/[0,0.125]
var q0R8 = [6]float64{
	0.00000000000000000000e+00, // 0x0000000000000000
	7.32421874999935051953e-02, // 0x3FB2BFFFFFFFFE2C
	1.17682064682252693899e+01, // 0x402789525BB334D6
	5.57673380256401856059e+02, // 0x40816D6315301825
	8.85919720756468632317e+03, // 0x40C14D993E18F46D
	3.70146267776887834771e+04, // 0x40E212D40E901566
}
var q0S8 = [6]float64{
	1.63776026895689824414e+02,  // 0x406478D5365B39BC
	8.09834494656449805916e+03,  // 0x40BFA2584E6B0563
	1.42538291419120476348e+05,  // 0x4101665254D38C3F
	8.03309257119514397345e+05,  // 0x412883DA83A52B43
	8.40501579819060512818e+05,  // 0x4129A66B28DE0B3D
	-3.43899293537866615225e+05, // 0xC114FD6D2C9530C5
}

// for x in [8,4.5454]=1/[0.125,0.22001]
var q0R5 = [6]float64{
	1.84085963594515531381e-11, // 0x3DB43D8F29CC8CD9
	7.32421766612684765896e-02, // 0x3FB2BFFFD172B04C
	5.83563508962056953777e+00, // 0x401757B0B9953DD3
	1.35111577286449829671e+02, // 0x4060E3920A8788E9
	1.02724376596164097464e+03, // 0x40900CF99DC8C481
	1.98997785864605384631e+03, // 0x409F17E953C6E3A6
}
var q0S5 = [6]float64{
	8.27766102236537761883e+01,  // 0x4054B1B3FB5E1543
	2.07781416421392987104e+03,  // 0x40A03BA0DA21C0CE
	1.88472887785718085070e+04,  // 0x40D267D27B591E6D
	5.67511122894947329769e+04,  // 0x40EBB5E397E02372
	3.59767538425114471465e+04,  // 0x40E191181F7A54A0
	-5.35434275601944773371e+03, // 0xC0B4EA57BEDBC609
}

// for x in [4.547,2.8571]=1/[0.2199,0.35001]
var q0R3 = [6]float64{
	4.37741014089738620906e-09, // 0x3E32CD036ADECB82
	7.32411180042911447163e-02, // 0x3FB2BFEE0E8D0842
	3.34423137516170720929e+00, // 0x400AC0FC61149CF5
	4.26218440745412650017e+01, // 0x40454F98962DAEDD
	1.70808091340565596283e+02, // 0x406559DBE25EFD1F
	1.66733948696651168575e+02, // 0x4064D77C81FA21E0
}
var q0S3 = [6]float64{
	4.87588729724587182091e+01,  // 0x40486122BFE343A6
	7.09689221056606015736e+02,  // 0x40862D8386544EB3
	3.70414822620111362994e+03,  // 0x40ACF04BE44DFC63
	6.46042516752568917582e+03,  // 0x40B93C6CD7C76A28
	2.51633368920368957333e+03,  // 0x40A3A8AAD94FB1C0
	-1.49247451836156386662e+02, // 0xC062A7EB201CF40F
}

// for x in [2.8570,2]=1/[0.3499,0.5]
var q0R2 = [6]float64{
	1.50444444886983272379e-07, // 0x3E84313B54F76BDB
	7.32234265963079278272e-02, // 0x3FB2BEC53E883E34
	1.99819174093815998816e+00, // 0x3FFFF897E727779C
	1.44956029347885735348e+01, // 0x402CFDBFAAF96FE5
	3.16662317504781540833e+01, // 0x403FAA8E29FBDC4A
	1.62527075710929267416e+01, // 0x403040B171814BB4
}
var q0S2 = [6]float64{
	3.03655848355219184498e+01,  // 0x403E5D96F7C07AED
	2.69348118608049844624e+02,  // 0x4070D591E4D14B40
	8.44783757595320139444e+02,  // 0x408A664522B3BF22
	8.82935845112488550512e+02,  // 0x408B977C9C5CC214
	2.12666388511798828631e+02,  // 0x406A95530E001365
	-5.31095493882666946917e+00, // 0xC0153E6AF8B32931
}

func qzero(x float64) float64 {
	var p, q *[6]float64
	if x >= 8 {
		p = &q0R8
		q = &q0S8
	} else if x >= 4.5454 {
		p = &q0R5
		q = &q0S5
	} else if x >= 2.8571 {
		p = &q0R3
		q = &q0S3
	} else if x >= 2 {
		p = &q0R2
		q = &q0S2
	}
	z := 1 / (x * x)
	r := p[0] + z*(p[1]+z*(p[2]+z*(p[3]+z*(p[4]+z*p[5]))))
	s := 1 + z*(q[0]+z*(q[1]+z*(q[2]+z*(q[3]+z*(q[4]+z*q[5])))))
	return (-0.125 + r/s) / x
}

"""



```