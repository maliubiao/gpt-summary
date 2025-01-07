Response:
The user wants a summary of the functionality of the provided Go code snippet, which is a part of the `go/src/math/all_test.go` file. This file is likely used for testing the `math` package in Go.

The code defines several global variables which are slices or arrays. These variables seem to hold sets of floating-point numbers and their expected results for various mathematical functions. The naming convention suggests:

* `vf...SC`: Slices of `float64` used as input test cases for a function. 'SC' likely stands for "special cases".
* `...SC`:  Slices of expected output values corresponding to the input in `vf...SC`.
* `[][]float64`:  Arrays of `float64` pairs, likely used as input for functions taking two arguments.
* `[]fi`: Slices of a custom struct `fi` which holds a `float64` and an `int`. This is likely used for functions returning a float and an integer (like `Frexp`).

Therefore, the code seems to be setting up test cases for various mathematical functions in the `math` package, covering regular values and special cases like infinity, NaN, and signed zeros.
这段代码是 Go 语言 `math` 包测试的一部分，它定义了一系列用于测试不同数学函数的**特殊输入用例**及其对应的**预期输出**。

**具体功能归纳如下：**

这段代码主要定义了多个全局变量，这些变量用于存储特定数学函数的输入和预期的输出值。这些变量的命名模式通常是 `vf<函数名>SC` 表示 `float64` 类型的输入特殊用例，而 `<函数名>SC` 则表示对应的预期输出结果。

以下列举一些变量及其可能对应的功能：

*   **`vflogSC` 和 `logSC`:**  很可能用于测试 `Log` 函数（自然对数）在一些特殊输入下的行为，比如负数、零、无穷大和 NaN。
*   **`vflogbSC` 和 `logbSC`:**  可能用于测试 `Logb` 函数，该函数返回浮点数的二进制指数。
*   **`vflog1pSC` 和 `log1pSC`:**  可能用于测试 `Log1p` 函数，该函数计算 `log(1 + x)`，对于接近零的 `x` 值能提供更高的精度。
*   **`vfmodfSC` 和 `modfSC`:**  用于测试 `Modf` 函数，该函数将浮点数分解为整数部分和小数部分。
*   **`vfnextafter32SC` 和 `nextafter32SC`， `vfnextafter64SC` 和 `nextafter64SC`:**  用于测试 `Nextafter` 函数的单精度和双精度版本，该函数返回目标方向上与第一个参数相邻的浮点数。
*   **`vfpowSC` 和 `powSC`:**  用于测试 `Pow` 函数（幂运算）在各种特殊输入下的行为。
*   **`vfpow10SC` 和 `pow10SC`:**  用于测试 `Pow10` 函数，该函数计算 10 的整数次幂。
*   **`vfroundSC` 和 `vfroundEvenSC`:**  可能用于测试 `Round` 和 `RoundToEven` 函数，它们将浮点数四舍五入到最接近的整数。
*   **`vfsignbitSC` 和 `signbitSC`:**  用于测试 `Signbit` 函数，该函数返回浮点数的符号位是否为负。
*   **`vfsinSC` 和 `sinSC`:**  用于测试 `Sin` 函数（正弦）在特殊输入下的行为。
*   **`vfsinhSC` 和 `sinhSC`:**  用于测试 `Sinh` 函数（双曲正弦）在特殊输入下的行为。
*   **`vfsqrtSC` 和 `sqrtSC`:**  用于测试 `Sqrt` 函数（平方根）在特殊输入下的行为。
*   **`vftanhSC` 和 `tanhSC`:**  用于测试 `Tanh` 函数（双曲正切）在特殊输入下的行为。
*   **`vfy0SC`， `y0SC`， `y1SC`， `y2SC`， `yM3SC`:**  可能用于测试不同阶数的第二类贝塞尔函数 (`Y0`, `Y1`, `Yn`) 在特殊输入下的行为。
*   **`vffrexpBC` 和 `frexpBC`， `vfldexpBC` 和 `ldexpBC`， `logbBC`:** 用于测试 `Frexp`（将浮点数分解为尾数和指数）、`Ldexp`（用二进制指数调整浮点数）和 `Logb` 在边界情况下的行为。这里的 "BC" 可能代表 "boundary cases"。
*   **`fmaC`:** 用于测试 `FMA` 函数（融合乘法加法），这是一个三元运算，可以提高计算精度。
*   **`sqrt32`:**  可能包含一些用于测试单精度浮点数平方根的特定值。

**总而言之，这段代码的功能是为 `math` 包中的各种数学函数提供一组详尽的特殊测试用例，以确保这些函数在处理边界条件、特殊数值（如无穷大、NaN、零）时能够返回预期的结果，保证了 `math` 包的健壮性和准确性。**

Prompt: 
```
这是路径为go/src/math/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
1), 1},
	{0, 1},
	{0, 1},
	{Inf(1), 1},
	{NaN(), 1},
}

var vflogSC = []float64{
	Inf(-1),
	-Pi,
	Copysign(0, -1),
	0,
	1,
	Inf(1),
	NaN(),
}
var logSC = []float64{
	NaN(),
	NaN(),
	Inf(-1),
	Inf(-1),
	0,
	Inf(1),
	NaN(),
}

var vflogbSC = []float64{
	Inf(-1),
	0,
	Inf(1),
	NaN(),
}
var logbSC = []float64{
	Inf(1),
	Inf(-1),
	Inf(1),
	NaN(),
}

var vflog1pSC = []float64{
	Inf(-1),
	-Pi,
	-1,
	Copysign(0, -1),
	0,
	Inf(1),
	NaN(),
	4503599627370496.5, // Issue #29488
}
var log1pSC = []float64{
	NaN(),
	NaN(),
	Inf(-1),
	Copysign(0, -1),
	0,
	Inf(1),
	NaN(),
	36.04365338911715, // Issue #29488
}

var vfmodfSC = []float64{
	Inf(-1),
	Copysign(0, -1),
	Inf(1),
	NaN(),
}
var modfSC = [][2]float64{
	{Inf(-1), NaN()}, // [2]float64{Copysign(0, -1), Inf(-1)},
	{Copysign(0, -1), Copysign(0, -1)},
	{Inf(1), NaN()}, // [2]float64{0, Inf(1)},
	{NaN(), NaN()},
}

var vfnextafter32SC = [][2]float32{
	{0, 0},
	{0, float32(Copysign(0, -1))},
	{0, -1},
	{0, float32(NaN())},
	{float32(Copysign(0, -1)), 1},
	{float32(Copysign(0, -1)), 0},
	{float32(Copysign(0, -1)), float32(Copysign(0, -1))},
	{float32(Copysign(0, -1)), -1},
	{float32(NaN()), 0},
	{float32(NaN()), float32(NaN())},
}
var nextafter32SC = []float32{
	0,
	0,
	-1.401298464e-45, // Float32frombits(0x80000001)
	float32(NaN()),
	1.401298464e-45, // Float32frombits(0x00000001)
	float32(Copysign(0, -1)),
	float32(Copysign(0, -1)),
	-1.401298464e-45, // Float32frombits(0x80000001)
	float32(NaN()),
	float32(NaN()),
}

var vfnextafter64SC = [][2]float64{
	{0, 0},
	{0, Copysign(0, -1)},
	{0, -1},
	{0, NaN()},
	{Copysign(0, -1), 1},
	{Copysign(0, -1), 0},
	{Copysign(0, -1), Copysign(0, -1)},
	{Copysign(0, -1), -1},
	{NaN(), 0},
	{NaN(), NaN()},
}
var nextafter64SC = []float64{
	0,
	0,
	-4.9406564584124654418e-324, // Float64frombits(0x8000000000000001)
	NaN(),
	4.9406564584124654418e-324, // Float64frombits(0x0000000000000001)
	Copysign(0, -1),
	Copysign(0, -1),
	-4.9406564584124654418e-324, // Float64frombits(0x8000000000000001)
	NaN(),
	NaN(),
}

var vfpowSC = [][2]float64{
	{Inf(-1), -Pi},
	{Inf(-1), -3},
	{Inf(-1), Copysign(0, -1)},
	{Inf(-1), 0},
	{Inf(-1), 1},
	{Inf(-1), 3},
	{Inf(-1), Pi},
	{Inf(-1), 0.5},
	{Inf(-1), NaN()},

	{-Pi, Inf(-1)},
	{-Pi, -Pi},
	{-Pi, Copysign(0, -1)},
	{-Pi, 0},
	{-Pi, 1},
	{-Pi, Pi},
	{-Pi, Inf(1)},
	{-Pi, NaN()},

	{-1, Inf(-1)},
	{-1, Inf(1)},
	{-1, NaN()},
	{-0.5, Inf(-1)},
	{-0.5, Inf(1)},
	{Copysign(0, -1), Inf(-1)},
	{Copysign(0, -1), -Pi},
	{Copysign(0, -1), -0.5},
	{Copysign(0, -1), -3},
	{Copysign(0, -1), 3},
	{Copysign(0, -1), Pi},
	{Copysign(0, -1), 0.5},
	{Copysign(0, -1), Inf(1)},

	{0, Inf(-1)},
	{0, -Pi},
	{0, -3},
	{0, Copysign(0, -1)},
	{0, 0},
	{0, 3},
	{0, Pi},
	{0, Inf(1)},
	{0, NaN()},

	{0.5, Inf(-1)},
	{0.5, Inf(1)},
	{1, Inf(-1)},
	{1, Inf(1)},
	{1, NaN()},

	{Pi, Inf(-1)},
	{Pi, Copysign(0, -1)},
	{Pi, 0},
	{Pi, 1},
	{Pi, Inf(1)},
	{Pi, NaN()},
	{Inf(1), -Pi},
	{Inf(1), Copysign(0, -1)},
	{Inf(1), 0},
	{Inf(1), 1},
	{Inf(1), Pi},
	{Inf(1), NaN()},
	{NaN(), -Pi},
	{NaN(), Copysign(0, -1)},
	{NaN(), 0},
	{NaN(), 1},
	{NaN(), Pi},
	{NaN(), NaN()},

	// Issue #7394 overflow checks
	{2, float64(1 << 32)},
	{2, -float64(1 << 32)},
	{-2, float64(1<<32 + 1)},
	{0.5, float64(1 << 45)},
	{0.5, -float64(1 << 45)},
	{Nextafter(1, 2), float64(1 << 63)},
	{Nextafter(1, -2), float64(1 << 63)},
	{Nextafter(-1, 2), float64(1 << 63)},
	{Nextafter(-1, -2), float64(1 << 63)},

	// Issue #57465
	{Copysign(0, -1), 1e19},
	{Copysign(0, -1), -1e19},
	{Copysign(0, -1), 1<<53 - 1},
	{Copysign(0, -1), -(1<<53 - 1)},
}
var powSC = []float64{
	0,               // pow(-Inf, -Pi)
	Copysign(0, -1), // pow(-Inf, -3)
	1,               // pow(-Inf, -0)
	1,               // pow(-Inf, +0)
	Inf(-1),         // pow(-Inf, 1)
	Inf(-1),         // pow(-Inf, 3)
	Inf(1),          // pow(-Inf, Pi)
	Inf(1),          // pow(-Inf, 0.5)
	NaN(),           // pow(-Inf, NaN)
	0,               // pow(-Pi, -Inf)
	NaN(),           // pow(-Pi, -Pi)
	1,               // pow(-Pi, -0)
	1,               // pow(-Pi, +0)
	-Pi,             // pow(-Pi, 1)
	NaN(),           // pow(-Pi, Pi)
	Inf(1),          // pow(-Pi, +Inf)
	NaN(),           // pow(-Pi, NaN)
	1,               // pow(-1, -Inf) IEEE 754-2008
	1,               // pow(-1, +Inf) IEEE 754-2008
	NaN(),           // pow(-1, NaN)
	Inf(1),          // pow(-1/2, -Inf)
	0,               // pow(-1/2, +Inf)
	Inf(1),          // pow(-0, -Inf)
	Inf(1),          // pow(-0, -Pi)
	Inf(1),          // pow(-0, -0.5)
	Inf(-1),         // pow(-0, -3) IEEE 754-2008
	Copysign(0, -1), // pow(-0, 3) IEEE 754-2008
	0,               // pow(-0, +Pi)
	0,               // pow(-0, 0.5)
	0,               // pow(-0, +Inf)
	Inf(1),          // pow(+0, -Inf)
	Inf(1),          // pow(+0, -Pi)
	Inf(1),          // pow(+0, -3)
	1,               // pow(+0, -0)
	1,               // pow(+0, +0)
	0,               // pow(+0, 3)
	0,               // pow(+0, +Pi)
	0,               // pow(+0, +Inf)
	NaN(),           // pow(+0, NaN)
	Inf(1),          // pow(1/2, -Inf)
	0,               // pow(1/2, +Inf)
	1,               // pow(1, -Inf) IEEE 754-2008
	1,               // pow(1, +Inf) IEEE 754-2008
	1,               // pow(1, NaN) IEEE 754-2008
	0,               // pow(+Pi, -Inf)
	1,               // pow(+Pi, -0)
	1,               // pow(+Pi, +0)
	Pi,              // pow(+Pi, 1)
	Inf(1),          // pow(+Pi, +Inf)
	NaN(),           // pow(+Pi, NaN)
	0,               // pow(+Inf, -Pi)
	1,               // pow(+Inf, -0)
	1,               // pow(+Inf, +0)
	Inf(1),          // pow(+Inf, 1)
	Inf(1),          // pow(+Inf, Pi)
	NaN(),           // pow(+Inf, NaN)
	NaN(),           // pow(NaN, -Pi)
	1,               // pow(NaN, -0)
	1,               // pow(NaN, +0)
	NaN(),           // pow(NaN, 1)
	NaN(),           // pow(NaN, +Pi)
	NaN(),           // pow(NaN, NaN)

	// Issue #7394 overflow checks
	Inf(1),  // pow(2, float64(1 << 32))
	0,       // pow(2, -float64(1 << 32))
	Inf(-1), // pow(-2, float64(1<<32 + 1))
	0,       // pow(1/2, float64(1 << 45))
	Inf(1),  // pow(1/2, -float64(1 << 45))
	Inf(1),  // pow(Nextafter(1, 2), float64(1 << 63))
	0,       // pow(Nextafter(1, -2), float64(1 << 63))
	0,       // pow(Nextafter(-1, 2), float64(1 << 63))
	Inf(1),  // pow(Nextafter(-1, -2), float64(1 << 63))

	// Issue #57465
	0,               // pow(-0, 1e19)
	Inf(1),          // pow(-0, -1e19)
	Copysign(0, -1), // pow(-0, 1<<53 -1)
	Inf(-1),         // pow(-0, -(1<<53 -1))
}

var vfpow10SC = []int{
	MinInt32,
	-324,
	-323,
	-50,
	-22,
	-1,
	0,
	1,
	22,
	50,
	100,
	200,
	308,
	309,
	MaxInt32,
}

var pow10SC = []float64{
	0,        // pow10(MinInt32)
	0,        // pow10(-324)
	1.0e-323, // pow10(-323)
	1.0e-50,  // pow10(-50)
	1.0e-22,  // pow10(-22)
	1.0e-1,   // pow10(-1)
	1.0e0,    // pow10(0)
	1.0e1,    // pow10(1)
	1.0e22,   // pow10(22)
	1.0e50,   // pow10(50)
	1.0e100,  // pow10(100)
	1.0e200,  // pow10(200)
	1.0e308,  // pow10(308)
	Inf(1),   // pow10(309)
	Inf(1),   // pow10(MaxInt32)
}

var vfroundSC = [][2]float64{
	{0, 0},
	{1.390671161567e-309, 0}, // denormal
	{0.49999999999999994, 0}, // 0.5-epsilon
	{0.5, 1},
	{0.5000000000000001, 1}, // 0.5+epsilon
	{-1.5, -2},
	{-2.5, -3},
	{NaN(), NaN()},
	{Inf(1), Inf(1)},
	{2251799813685249.5, 2251799813685250}, // 1 bit fraction
	{2251799813685250.5, 2251799813685251},
	{4503599627370495.5, 4503599627370496}, // 1 bit fraction, rounding to 0 bit fraction
	{4503599627370497, 4503599627370497},   // large integer
}
var vfroundEvenSC = [][2]float64{
	{0, 0},
	{1.390671161567e-309, 0}, // denormal
	{0.49999999999999994, 0}, // 0.5-epsilon
	{0.5, 0},
	{0.5000000000000001, 1}, // 0.5+epsilon
	{-1.5, -2},
	{-2.5, -2},
	{NaN(), NaN()},
	{Inf(1), Inf(1)},
	{2251799813685249.5, 2251799813685250}, // 1 bit fraction
	{2251799813685250.5, 2251799813685250},
	{4503599627370495.5, 4503599627370496}, // 1 bit fraction, rounding to 0 bit fraction
	{4503599627370497, 4503599627370497},   // large integer
}

var vfsignbitSC = []float64{
	Inf(-1),
	Copysign(0, -1),
	0,
	Inf(1),
	NaN(),
}
var signbitSC = []bool{
	true,
	true,
	false,
	false,
	false,
}

var vfsinSC = []float64{
	Inf(-1),
	Copysign(0, -1),
	0,
	Inf(1),
	NaN(),
}
var sinSC = []float64{
	NaN(),
	Copysign(0, -1),
	0,
	NaN(),
	NaN(),
}

var vfsinhSC = []float64{
	Inf(-1),
	Copysign(0, -1),
	0,
	Inf(1),
	NaN(),
}
var sinhSC = []float64{
	Inf(-1),
	Copysign(0, -1),
	0,
	Inf(1),
	NaN(),
}

var vfsqrtSC = []float64{
	Inf(-1),
	-Pi,
	Copysign(0, -1),
	0,
	Inf(1),
	NaN(),
	Float64frombits(2), // subnormal; see https://golang.org/issue/13013
}
var sqrtSC = []float64{
	NaN(),
	NaN(),
	Copysign(0, -1),
	0,
	Inf(1),
	NaN(),
	3.1434555694052576e-162,
}

var vftanhSC = []float64{
	Inf(-1),
	Copysign(0, -1),
	0,
	Inf(1),
	NaN(),
}
var tanhSC = []float64{
	-1,
	Copysign(0, -1),
	0,
	1,
	NaN(),
}

var vfy0SC = []float64{
	Inf(-1),
	0,
	Inf(1),
	NaN(),
	-1,
}
var y0SC = []float64{
	NaN(),
	Inf(-1),
	0,
	NaN(),
	NaN(),
}
var y1SC = []float64{
	NaN(),
	Inf(-1),
	0,
	NaN(),
	NaN(),
}
var y2SC = []float64{
	NaN(),
	Inf(-1),
	0,
	NaN(),
	NaN(),
}
var yM3SC = []float64{
	NaN(),
	Inf(1),
	0,
	NaN(),
	NaN(),
}

// arguments and expected results for boundary cases
const (
	SmallestNormalFloat64   = 2.2250738585072014e-308 // 2**-1022
	LargestSubnormalFloat64 = SmallestNormalFloat64 - SmallestNonzeroFloat64
)

var vffrexpBC = []float64{
	SmallestNormalFloat64,
	LargestSubnormalFloat64,
	SmallestNonzeroFloat64,
	MaxFloat64,
	-SmallestNormalFloat64,
	-LargestSubnormalFloat64,
	-SmallestNonzeroFloat64,
	-MaxFloat64,
}
var frexpBC = []fi{
	{0.5, -1021},
	{0.99999999999999978, -1022},
	{0.5, -1073},
	{0.99999999999999989, 1024},
	{-0.5, -1021},
	{-0.99999999999999978, -1022},
	{-0.5, -1073},
	{-0.99999999999999989, 1024},
}

var vfldexpBC = []fi{
	{SmallestNormalFloat64, -52},
	{LargestSubnormalFloat64, -51},
	{SmallestNonzeroFloat64, 1074},
	{MaxFloat64, -(1023 + 1074)},
	{1, -1075},
	{-1, -1075},
	{1, 1024},
	{-1, 1024},
	{1.0000000000000002, -1075},
	{1, -1075},
}
var ldexpBC = []float64{
	SmallestNonzeroFloat64,
	1e-323, // 2**-1073
	1,
	1e-323, // 2**-1073
	0,
	Copysign(0, -1),
	Inf(1),
	Inf(-1),
	SmallestNonzeroFloat64,
	0,
}

var logbBC = []float64{
	-1022,
	-1023,
	-1074,
	1023,
	-1022,
	-1023,
	-1074,
	1023,
}

// Test cases were generated with Berkeley TestFloat-3e/testfloat_gen.
// http://www.jhauser.us/arithmetic/TestFloat.html.
// The default rounding mode is selected (nearest/even), and exception flags are ignored.
var fmaC = []struct{ x, y, z, want float64 }{
	// Large exponent spread
	{-3.999999999999087, -1.1123914289620494e-16, -7.999877929687506, -7.999877929687505},
	{-262112.0000004768, -0.06251525855623184, 1.1102230248837136e-16, 16385.99945072085},
	{-6.462348523533467e-27, -2.3763644720331857e-211, 4.000000000931324, 4.000000000931324},

	// Effective addition
	{-2.0000000037252907, 6.7904383376e-313, -3.3951933161e-313, -1.697607001654e-312},
	{-0.12499999999999999, 512.007568359375, -1.4193627164960366e-16, -64.00094604492188},
	{-2.7550648847397148e-39, -3.4028301595800694e+38, 0.9960937495343386, 1.9335955376735676},
	{5.723369164769208e+24, 3.8149300927159385e-06, 1.84489958778182e+19, 4.028324913621874e+19},
	{-0.4843749999990904, -3.6893487872543293e+19, 9.223653786709391e+18, 2.7093936974938993e+19},
	{-3.8146972665201165e-06, 4.2949672959999385e+09, -2.2204460489938386e-16, -16384.000003844263},
	{6.98156394130982e-309, -1.1072962560000002e+09, -4.4414561548793455e-308, -7.73065965765153e-300},

	// Effective subtraction
	{5e-324, 4.5, -2e-323, 0},
	{5e-324, 7, -3.5e-323, 0},
	{5e-324, 0.5000000000000001, -5e-324, Copysign(0, -1)},
	{-2.1240680525e-314, -1.233647078189316e+308, -0.25781249999954525, -0.25780987964919844},
	{8.579992955364441e-308, 0.6037391876780558, -4.4501307410480706e-308, 7.29947236107098e-309},
	{-4.450143471986689e-308, -0.9960937499927239, -4.450419332475649e-308, -1.7659233458788e-310},
	{1.4932076393918112, -2.2248022430460833e-308, 4.449875571054211e-308, 1.127783865601762e-308},

	// Overflow
	{-2.288020632214759e+38, -8.98846570988901e+307, 1.7696041796300924e+308, Inf(0)},
	{1.4888652783208255e+308, -9.007199254742012e+15, -6.807282911929205e+38, Inf(-1)},
	{9.142703268902826e+192, -1.3504889569802838e+296, -1.9082200803806996e-89, Inf(-1)},

	// Finite x and y, but non-finite z.
	{31.99218749627471, -1.7976930544991702e+308, Inf(0), Inf(0)},
	{-1.7976931281784667e+308, -2.0009765625002265, Inf(-1), Inf(-1)},

	// Special
	{0, 0, 0, 0},
	{Copysign(0, -1), 0, 0, 0},
	{0, 0, Copysign(0, -1), 0},
	{Copysign(0, -1), 0, Copysign(0, -1), Copysign(0, -1)},
	{-1.1754226043408471e-38, NaN(), Inf(0), NaN()},
	{0, 0, 2.22507385643494e-308, 2.22507385643494e-308},
	{-8.65697792e+09, NaN(), -7.516192799999999e+09, NaN()},
	{-0.00012207403779029757, 3.221225471996093e+09, NaN(), NaN()},
	{Inf(-1), 0.1252441407414153, -1.387184532981584e-76, Inf(-1)},
	{Inf(0), 1.525878907671432e-05, -9.214364835452549e+18, Inf(0)},

	// Random
	{0.1777916152213626, -32.000015266239636, -2.2204459148334633e-16, -5.689334401293007},
	{-2.0816681711722314e-16, -0.4997558592585846, -0.9465627129124969, -0.9465627129124968},
	{-1.9999997615814211, 1.8518819259933516e+19, 16.874999999999996, -3.703763410463646e+19},
	{-0.12499994039717421, 32767.99999976135, -2.0752587082923246e+19, -2.075258708292325e+19},
	{7.705600568510257e-34, -1.801432979000528e+16, -0.17224197722973714, -0.17224197722973716},
	{3.8988133103758913e-308, -0.9848632812499999, 3.893879244098556e-308, 5.40811742605814e-310},
	{-0.012651981190687427, 6.911985574912436e+38, 6.669240527007144e+18, -8.745031148409496e+36},
	{4.612811918325842e+18, 1.4901161193847641e-08, 2.6077032311277997e-08, 6.873625395187494e+10},
	{-9.094947033611148e-13, 4.450691014249257e-308, 2.086006742350485e-308, 2.086006742346437e-308},
	{-7.751454006381804e-05, 5.588653777189071e-308, -2.2207280111272877e-308, -2.2211612130544025e-308},

	// Issue #61130
	{-1, 1, 1, 0},
	{1, 1, -1, 0},
}

var sqrt32 = []float32{
	0,
	float32(Copysign(0, -1)),
	float32(NaN()),
	float32(Inf(1)),
	float32(Inf(-1)),
	1,
	2,
	-2,
	4.9790119248836735e+00,
	7.7388724745781045e+00,
	-2.7688005719200159e-01,
	-5.0106036182710749e+00,
}

func tolerance(a, b, e float64) bool {
	// Multiplying by e here can underflow denormal values to zero.
	// Check a==b so that at least if a and b are small and identical
	// we say they match.
	if a == b {
		return true
	}
	d := a - b
	if d < 0 {
		d = -d
	}

	// note: b is correct (expected) value, a is actual value.
	// make error tolerance a fraction of b, not a.
	if b != 0 {
		e = e * b
		if e < 0 {
			e = -e
		}
	}
	return d < e
}
func close(a, b float64) bool      { return tolerance(a, b, 1e-14) }
func veryclose(a, b float64) bool  { return tolerance(a, b, 4e-16) }
func soclose(a, b, e float64) bool { return tolerance(a, b, e) }
func alike(a, b float64) bool {
	switch {
	case IsNaN(a) && IsNaN(b):
		return true
	case a == b:
		return Signbit(a) == Signbit(b)
	}
	return false
}

func TestNaN(t *testing.T) {
	f64 := NaN()
	if f64 == f64 {
		t.Fatalf("NaN() returns %g, expected NaN", f64)
	}
	f32 := float32(f64)
	if f32 == f32 {
		t.Fatalf("float32(NaN()) is %g, expected NaN", f32)
	}
}

func TestAcos(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := Acos(a); !close(acos[i], f) {
			t.Errorf("Acos(%g) = %g, want %g", a, f, acos[i])
		}
	}
	for i := 0; i < len(vfacosSC); i++ {
		if f := Acos(vfacosSC[i]); !alike(acosSC[i], f) {
			t.Errorf("Acos(%g) = %g, want %g", vfacosSC[i], f, acosSC[i])
		}
	}
}

func TestAcosh(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := 1 + Abs(vf[i])
		if f := Acosh(a); !veryclose(acosh[i], f) {
			t.Errorf("Acosh(%g) = %g, want %g", a, f, acosh[i])
		}
	}
	for i := 0; i < len(vfacoshSC); i++ {
		if f := Acosh(vfacoshSC[i]); !alike(acoshSC[i], f) {
			t.Errorf("Acosh(%g) = %g, want %g", vfacoshSC[i], f, acoshSC[i])
		}
	}
}

func TestAsin(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := Asin(a); !veryclose(asin[i], f) {
			t.Errorf("Asin(%g) = %g, want %g", a, f, asin[i])
		}
	}
	for i := 0; i < len(vfasinSC); i++ {
		if f := Asin(vfasinSC[i]); !alike(asinSC[i], f) {
			t.Errorf("Asin(%g) = %g, want %g", vfasinSC[i], f, asinSC[i])
		}
	}
}

func TestAsinh(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Asinh(vf[i]); !veryclose(asinh[i], f) {
			t.Errorf("Asinh(%g) = %g, want %g", vf[i], f, asinh[i])
		}
	}
	for i := 0; i < len(vfasinhSC); i++ {
		if f := Asinh(vfasinhSC[i]); !alike(asinhSC[i], f) {
			t.Errorf("Asinh(%g) = %g, want %g", vfasinhSC[i], f, asinhSC[i])
		}
	}
}

func TestAtan(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Atan(vf[i]); !veryclose(atan[i], f) {
			t.Errorf("Atan(%g) = %g, want %g", vf[i], f, atan[i])
		}
	}
	for i := 0; i < len(vfatanSC); i++ {
		if f := Atan(vfatanSC[i]); !alike(atanSC[i], f) {
			t.Errorf("Atan(%g) = %g, want %g", vfatanSC[i], f, atanSC[i])
		}
	}
}

func TestAtanh(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := Atanh(a); !veryclose(atanh[i], f) {
			t.Errorf("Atanh(%g) = %g, want %g", a, f, atanh[i])
		}
	}
	for i := 0; i < len(vfatanhSC); i++ {
		if f := Atanh(vfatanhSC[i]); !alike(atanhSC[i], f) {
			t.Errorf("Atanh(%g) = %g, want %g", vfatanhSC[i], f, atanhSC[i])
		}
	}
}

func TestAtan2(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Atan2(10, vf[i]); !veryclose(atan2[i], f) {
			t.Errorf("Atan2(10, %g) = %g, want %g", vf[i], f, atan2[i])
		}
	}
	for i := 0; i < len(vfatan2SC); i++ {
		if f := Atan2(vfatan2SC[i][0], vfatan2SC[i][1]); !alike(atan2SC[i], f) {
			t.Errorf("Atan2(%g, %g) = %g, want %g", vfatan2SC[i][0], vfatan2SC[i][1], f, atan2SC[i])
		}
	}
}

func TestCbrt(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Cbrt(vf[i]); !veryclose(cbrt[i], f) {
			t.Errorf("Cbrt(%g) = %g, want %g", vf[i], f, cbrt[i])
		}
	}
	for i := 0; i < len(vfcbrtSC); i++ {
		if f := Cbrt(vfcbrtSC[i]); !alike(cbrtSC[i], f) {
			t.Errorf("Cbrt(%g) = %g, want %g", vfcbrtSC[i], f, cbrtSC[i])
		}
	}
}

func TestCeil(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Ceil(vf[i]); !alike(ceil[i], f) {
			t.Errorf("Ceil(%g) = %g, want %g", vf[i], f, ceil[i])
		}
	}
	for i := 0; i < len(vfceilSC); i++ {
		if f := Ceil(vfceilSC[i]); !alike(ceilSC[i], f) {
			t.Errorf("Ceil(%g) = %g, want %g", vfceilSC[i], f, ceilSC[i])
		}
	}
}

func TestCopysign(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Copysign(vf[i], -1); copysign[i] != f {
			t.Errorf("Copysign(%g, -1) = %g, want %g", vf[i], f, copysign[i])
		}
	}
	for i := 0; i < len(vf); i++ {
		if f := Copysign(vf[i], 1); -copysign[i] != f {
			t.Errorf("Copysign(%g, 1) = %g, want %g", vf[i], f, -copysign[i])
		}
	}
	for i := 0; i < len(vfcopysignSC); i++ {
		if f := Copysign(vfcopysignSC[i], -1); !alike(copysignSC[i], f) {
			t.Errorf("Copysign(%g, -1) = %g, want %g", vfcopysignSC[i], f, copysignSC[i])
		}
	}
}

func TestCos(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Cos(vf[i]); !veryclose(cos[i], f) {
			t.Errorf("Cos(%g) = %g, want %g", vf[i], f, cos[i])
		}
	}
	for i := 0; i < len(vfcosSC); i++ {
		if f := Cos(vfcosSC[i]); !alike(cosSC[i], f) {
			t.Errorf("Cos(%g) = %g, want %g", vfcosSC[i], f, cosSC[i])
		}
	}
}

func TestCosh(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Cosh(vf[i]); !close(cosh[i], f) {
			t.Errorf("Cosh(%g) = %g, want %g", vf[i], f, cosh[i])
		}
	}
	for i := 0; i < len(vfcoshSC); i++ {
		if f := Cosh(vfcoshSC[i]); !alike(coshSC[i], f) {
			t.Errorf("Cosh(%g) = %g, want %g", vfcoshSC[i], f, coshSC[i])
		}
	}
}

func TestErf(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := Erf(a); !veryclose(erf[i], f) {
			t.Errorf("Erf(%g) = %g, want %g", a, f, erf[i])
		}
	}
	for i := 0; i < len(vferfSC); i++ {
		if f := Erf(vferfSC[i]); !alike(erfSC[i], f) {
			t.Errorf("Erf(%g) = %g, want %g", vferfSC[i], f, erfSC[i])
		}
	}
}

func TestErfc(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := Erfc(a); !veryclose(erfc[i], f) {
			t.Errorf("Erfc(%g) = %g, want %g", a, f, erfc[i])
		}
	}
	for i := 0; i < len(vferfcSC); i++ {
		if f := Erfc(vferfcSC[i]); !alike(erfcSC[i], f) {
			t.Errorf("Erfc(%g) = %g, want %g", vferfcSC[i], f, erfcSC[i])
		}
	}
}

func TestErfinv(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 10
		if f := Erfinv(a); !veryclose(erfinv[i], f) {
			t.Errorf("Erfinv(%g) = %g, want %g", a, f, erfinv[i])
		}
	}
	for i := 0; i < len(vferfinvSC); i++ {
		if f := Erfinv(vferfinvSC[i]); !alike(erfinvSC[i], f) {
			t.Errorf("Erfinv(%g) = %g, want %g", vferfinvSC[i], f, erfinvSC[i])
		}
	}
	for x := -0.9; x <= 0.90; x += 1e-2 {
		if f := Erf(Erfinv(x)); !close(x, f) {
			t.Errorf("Erf(Erfinv(%g)) = %g, want %g", x, f, x)
		}
	}
	for x := -0.9; x <= 0.90; x += 1e-2 {
		if f := Erfinv(Erf(x)); !close(x, f) {
			t.Errorf("Erfinv(Erf(%g)) = %g, want %g", x, f, x)
		}
	}
}

func TestErfcinv(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := 1.0 - (vf[i] / 10)
		if f := Erfcinv(a); !veryclose(erfinv[i], f) {
			t.Errorf("Erfcinv(%g) = %g, want %g", a, f, erfinv[i])
		}
	}
	for i := 0; i < len(vferfcinvSC); i++ {
		if f := Erfcinv(vferfcinvSC[i]); !alike(erfcinvSC[i], f) {
			t.Errorf("Erfcinv(%g) = %g, want %g", vferfcinvSC[i], f, erfcinvSC[i])
		}
	}
	for x := 0.1; x <= 1.9; x += 1e-2 {
		if f := Erfc(Erfcinv(x)); !close(x, f) {
			t.Errorf("Erfc(Erfcinv(%g)) = %g, want %g", x, f, x)
		}
	}
	for x := 0.1; x <= 1.9; x += 1e-2 {
		if f := Erfcinv(Erfc(x)); !close(x, f) {
			t.Errorf("Erfcinv(Erfc(%g)) = %g, want %g", x, f, x)
		}
	}
}

func TestExp(t *testing.T) {
	testExp(t, Exp, "Exp")
	testExp(t, ExpGo, "ExpGo")
}

func testExp(t *testing.T, Exp func(float64) float64, name string) {
	for i := 0; i < len(vf); i++ {
		if f := Exp(vf[i]); !veryclose(exp[i], f) {
			t.Errorf("%s(%g) = %g, want %g", name, vf[i], f, exp[i])
		}
	}
	for i := 0; i < len(vfexpSC); i++ {
		if f := Exp(vfexpSC[i]); !alike(expSC[i], f) {
			t.Errorf("%s(%g) = %g, want %g", name, vfexpSC[i], f, expSC[i])
		}
	}
}

func TestExpm1(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := vf[i] / 100
		if f := Expm1(a); !veryclose(expm1[i], f) {
			t.Errorf("Expm1(%g) = %g, want %g", a, f, expm1[i])
		}
	}
	for i := 0; i < len(vf); i++ {
		a := vf[i] * 10
		if f := Expm1(a); !close(expm1Large[i], f) {
			t.Errorf("Expm1(%g) = %g, want %g", a, f, expm1Large[i])
		}
	}
	for i := 0; i < len(vfexpm1SC); i++ {
		if f := Expm1(vfexpm1SC[i]); !alike(expm1SC[i], f) {
			t.Errorf("Expm1(%g) = %g, want %g", vfexpm1SC[i], f, expm1SC[i])
		}
	}
}

func TestExp2(t *testing.T) {
	testExp2(t, Exp2, "Exp2")
	testExp2(t, Exp2Go, "Exp2Go")
}

func testExp2(t *testing.T, Exp2 func(float64) float64, name string) {
	for i := 0; i < len(vf); i++ {
		if f := Exp2(vf[i]); !close(exp2[i], f) {
			t.Errorf("%s(%g) = %g, want %g", name, vf[i], f, exp2[i])
		}
	}
	for i := 0; i < len(vfexp2SC); i++ {
		if f := Exp2(vfexp2SC[i]); !alike(exp2SC[i], f) {
			t.Errorf("%s(%g) = %g, want %g", name, vfexp2SC[i], f, exp2SC[i])
		}
	}
	for n := -1074; n < 1024; n++ {
		f := Exp2(float64(n))
		vf := Ldexp(1, n)
		if f != vf {
			t.Errorf("%s(%d) = %g, want %g", name, n, f, vf)
		}
	}
}

func TestAbs(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Abs(vf[i]); fabs[i] != f {
			t.Errorf("Abs(%g) = %g, want %g", vf[i], f, fabs[i])
		}
	}
	for i := 0; i < len(vffabsSC); i++ {
		if f := Abs(vffabsSC[i]); !alike(fabsSC[i], f) {
			t.Errorf("Abs(%g) = %g, want %g", vffabsSC[i], f, fabsSC[i])
		}
	}
}

func TestDim(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Dim(vf[i], 0); fdim[i] != f {
			t.Errorf("Dim(%g, %g) = %g, want %g", vf[i], 0.0, f, fdim[i])
		}
	}
	for i := 0; i < len(vffdimSC); i++ {
		if f := Dim(vffdimSC[i][0], vffdimSC[i][1]); !alike(fdimSC[i], f) {
			t.Errorf("Dim(%g, %g) = %g, want %g", vffdimSC[i][0], vffdimSC[i][1], f, fdimSC[i])
		}
	}
	for i := 0; i < len(vffdim2SC); i++ {
		if f := Dim(vffdim2SC[i][0], vffdim2SC[i][1]); !alike(fdimSC[i], f) {
			t.Errorf("Dim(%g, %g) = %g, want %g", vffdim2SC[i][0], vffdim2SC[i][1], f, fdimSC[i])
		}
	}
}

func TestFloor(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Floor(vf[i]); !alike(floor[i], f) {
			t.Errorf("Floor(%g) = %g, want %g", vf[i], f, floor[i])
		}
	}
	for i := 0; i < len(vfceilSC); i++ {
		if f := Floor(vfceilSC[i]); !alike(floorSC[i], f) {
			t.Errorf("Floor(%g) = %g, want %g", vfceilSC[i], f, floorSC[i])
		}
	}
}

func TestMax(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Max(vf[i], ceil[i]); ceil[i] != f {
			t.Errorf("Max(%g, %g) = %g, want %g", vf[i], ceil[i], f, ceil[i])
		}
	}
	for i := 0; i < len(vffdimSC); i++ {
		if f := Max(vffdimSC[i][0], vffdimSC[i][1]); !alike(fmaxSC[i], f) {
			t.Errorf("Max(%g, %g) = %g, want %g", vffdimSC[i][0], vffdimSC[i][1], f, fmaxSC[i])
		}
	}
	for i := 0; i < len(vffdim2SC); i++ {
		if f := Max(vffdim2SC[i][0], vffdim2SC[i][1]); !alike(fmaxSC[i], f) {
			t.Errorf("Max(%g, %g) = %g, want %g", vffdim2SC[i][0], vffdim2SC[i][1], f, fmaxSC[i])
		}
	}
}

func TestMin(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Min(vf[i], floor[i]); floor[i] != f {
			t.Errorf("Min(%g, %g) = %g, want %g", vf[i], floor[i], f, floor[i])
		}
	}
	for i := 0; i < len(vffdimSC); i++ {
		if f := Min(vffdimSC[i][0], vffdimSC[i][1]); !alike(fminSC[i], f) {
			t.Errorf("Min(%g, %g) = %g, want %g", vffdimSC[i][0], vffdimSC[i][1], f, fminSC[i])
		}
	}
	for i := 0; i < len(vffdim2SC); i++ {
		if f := Min(vffdim2SC[i][0], vffdim2SC[i][1]); !alike(fminSC[i], f) {
			t.Errorf("Min(%g, %g) = %g, want %g", vffdim2SC[i][0], vffdim2SC[i][1], f, fminSC[i])
		}
	}
}

func TestMod(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Mod(10, vf[i]); fmod[i] != f {
			t.Errorf("Mod(10, %g) = %g, want %g", vf[i], f, fmod[i])
		}
	}
	for i := 0; i < len(vffmodSC); i++ {
		if f := Mod(vffmodSC[i][0], vffmodSC[i][1]); !alike(fmodSC[i], f) {
			t.Errorf("Mod(%g, %g) = %g, want %g", vffmodSC[i][0], vffmodSC[i][1], f, fmodSC[i])
		}
	}
	// verify precision of result for extreme inputs
	if f := Mod(5.9790119248836734e+200, 1.1258465975523544); 0.6447968302508578 != f {
		t.Errorf("Remainder(5.9790119248836734e+200, 1.1258465975523544) = %g, want 0.6447968302508578", f)
	}
}

func TestFrexp(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f, j := Frexp(vf[i]); !veryclose(frexp[i].f, f) || frexp[i].i != j {
			t.Errorf("Frexp(%g) = %g, %d, want %g, %d", vf[i], f, j, frexp[i].f, frexp[i].i)
		}
	}
	for i := 0; i < len(vffrexpSC); i++ {
		if f, j := Frexp(vffrexpSC[i]); !alike(frexpSC[i].f, f) || frexpSC[i].i != j {
			t.Errorf("Frexp(%g) = %g, %d, want %g, %d", vffrexpSC[i], f, j, frexpSC[i].f, frexpSC[i].i)
		}
	}
	for i := 0; i < len(vffrexpBC); i++ {
		if f, j := Frexp(vffrexpBC[i]); !alike(frexpBC[i].f, f) || frexpBC[i].i != j {
			t.Errorf("Frexp(%g) = %g, %d, want %g, %d", vffrexpBC[i], f, j, frexpBC[i].f, frexpBC[i].i)
		}
	}
}

func TestGamma(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Gamma(vf[i]); !close(gamma[i], f) {
			t.Errorf("Gamma(%g) = %g, want %g", vf[i], f, gamma[i])
		}
	}
	for _, g := range vfgamma {
		f := Gamma(g[0])
		var ok bool
		if IsNaN(g[1]) || IsInf(g[1], 0) || g[1] == 0 || f == 0 {
			ok = alike(g[1], f)
		} else if g[0] > -50 && g[0] <= 171 {
			ok = veryclose(g[1], f)
		} else {
			ok = close(g[1], f)
		}
		if !ok {
			t.Errorf("Gamma(%g) = %g, want %g", g[0], f, g[1])
		}
	}
}

func TestHypot(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := Abs(1e200 * tanh[i] * Sqrt(2))
		if f := Hypot(1e200*tanh[i], 1e200*tanh[i]); !veryclose(a, f) {
			t.Errorf("Hypot(%g, %g) = %g, want %g", 1e200*tanh[i], 1e200*tanh[i], f, a)
		}
	}
	for i := 0; i < len(vfhypotSC); i++ {
		if f := Hypot(vfhypotSC[i][0], vfhypotSC[i][1]); !alike(hypotSC[i], f) {
			t.Errorf("Hypot(%g, %g) = %g, want %g", vfhypotSC[i][0], vfhypotSC[i][1], f, hypotSC[i])
		}
	}
}

func TestHypotGo(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := Abs(1e200 * tanh[i] * Sqrt(2))
		if f := HypotGo(1e200*tanh[i], 1e200*tanh[i]); !veryclose(a, f) {
			t.Errorf("HypotGo(%g, %g) = %g, want %g", 1e200*tanh[i], 1e200*tanh[i], f, a)
		}
	}
	for i := 0; i < len(vfhypotSC); i++ {
		if f := HypotGo(vfhypotSC[i][0], vfhypotSC[i][1]); !alike(hypotSC[i], f) {
			t.Errorf("HypotGo(%g, %g) = %g, want %g", vfhypotSC[i][0], vfhypotSC[i][1], f, hypotSC[i])
		}
	}
}

func TestIlogb(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := frexp[i].i - 1 // adjust because fr in the interval [½, 1)
		if e := Ilogb(vf[i]); a != e {
			t.Errorf("Ilogb(%g) = %d, want %d", vf[i], e, a)
		}
	}
	for i := 0; i < len(vflogbSC); i++ {
		if e := Ilogb(vflogbSC[i]); ilogbSC[i] != e {
			t.Errorf("Ilogb(%g) = %d, want %d", vflogbSC[i], e, ilogbSC[i])
		}
	}
	for i := 0; i < len(vffrexpBC); i++ {
		if e := Ilogb(vffrexpBC[i]); int(logbBC[i]) != e {
			t.Errorf("Ilogb(%g) = %d, want %d", vffrexpBC[i], e, int(logbBC[i]))
		}
	}
}

func TestJ0(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := J0(vf[i]); !soclose(j0[i], f, 4e-14) {
			t.Errorf("J0(%g) = %g, want %g", vf[i], f, j0[i])
		}
	}
	for i := 0; i < len(vfj0SC); i++ {
		if f := J0(vfj0SC[i]); !alike(j0SC[i], f) {
			t.Errorf("J0(%g) = %g, want %g", vfj0SC[i], f, j0SC[i])
		}
	}
}

func TestJ1(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := J1(vf[i]); !close(j1[i], f) {
			t.Errorf("J1(%g) = %g, want %g", vf[i], f, j1[i])
		}
	}
	for i := 0; i < len(vfj0SC); i++ {
		if f := J1(vfj0SC[i]); !alike(j1SC[i], f) {
			t.Errorf("J1(%g) = %g, want %g", vfj0SC[i], f, j1SC[i])
		}
	}
}

func TestJn(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Jn(2, vf[i]); !close(j2[i], f) {
			t.Errorf("Jn(2, %g) = %g, want %g", vf[i], f, j2[i])
		}
		if f := Jn(-3, vf[i]); !close(jM3[i], f) {
			t.Errorf("Jn(-3, %g) = %g, want %g", vf[i], f, jM3[i])
		}
	}
	for i := 0; i < len(vfj0SC); i++ {
		if f := Jn(2, vfj0SC[i]); !alike(j2SC[i], f) {
			t.Errorf("Jn(2, %g) = %g, want %g", vfj0SC[i], f, j2SC[i])
		}
		if f := Jn(-3, vfj0SC[i]); !alike(jM3SC[i], f) {
			t.Errorf("Jn(-3, %g) = %g, want %g", vfj0SC[i], f, jM3SC[i])
		}
	}
}

func TestLdexp(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Ldexp(frexp[i].f, frexp[i].i); !veryclose(vf[i], f) {
			t.Errorf("Ldexp(%g, %d) = %g, want %g", frexp[i].f, frexp[i].i, f, vf[i])
		}
	}
	for i := 0; i < len(vffrexpSC); i++ {
		if f := Ldexp(frexpSC[i].f, frexpSC[i].i); !alike(vffrexpSC[i], f) {
			t.Errorf("Ldexp(%g, %d) = %g, want %g", frexpSC[i].f, frexpSC[i].i, f, vffrexpSC[i])
		}
	}
	for i := 0; i < len(vfldexpSC); i++ {
		if f := Ldexp(vfldexpSC[i].f, vfldexpSC[i].i); !alike(ldexpSC[i], f) {
			t.Errorf("Ldexp(%g, %d) = %g, want %g", vfldexpSC[i].f, vfldexpSC[i].i, f, ldexpSC[i])
		}
	}
	for i := 0; i < len(vffrexpBC); i++ {
		if f := Ldexp(frexpBC[i].f, frexpBC[i].i); !alike(vffrexpBC[i], f) {
			t.Errorf("Ldexp(%g, %d) = %g, want %g", frexpBC[i].f, frexpBC[i].i, f, vffrexpBC[i])
		}
	}
	for i := 0; i < len(vfldexpBC); i++ {
		if f := Ldexp(vfldexpBC[i].f, vfldexpBC[i].i); !alike(ldexpBC[i], f) {
			t.Errorf("Ldexp(%g, %d) = %g, want %g", vfldexpBC[i].f, vfldexpBC[i].i, f, ldexpBC[i])
		}
	}
}

func TestLgamma(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f, s := Lgamma(vf[i]); !close(lgamma[i].f, f) || lgamma[i].i != s {
			t.Errorf("Lgamma(%g) = %g, %d, want %g, %d", vf[i], f, s, lgamma[i].f, lgamma[i].i)
		}
	}
	for i := 0; i < len(vflgammaSC); i++ {
		if f, s := Lgamma(vflgammaSC[i]); !alike(lgammaSC[i].f, f) || lgammaSC[i].i != s {
			t.Errorf("Lgamma(%g) = %g, %d, want %g, %d", vflgammaSC[i], f, s, lgammaSC[i].f, lgammaSC[i].i)
		}
	}
}

func TestLog(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := Abs(vf[i])
		if f := Log(a); log[i] != f {
			t.Errorf("Log(%g) = %g, want %g", a, f, log[i])
		}
	}
	if f := Log(10); f != Ln10 {
		t.Errorf("Log(%g) = %g, want %g", 10.0, f, Ln10)
	}
	for i := 0; i < len(vflogSC); i++ {
		if f := Log(vflogSC[i]); !alike(logSC[i], f) {
			t.Errorf("Log(%g) = %g, want %g", vflogSC[i], f, logSC[i])
		}
	}
}

func TestLogb(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		if f := Logb(vf[i]); logb[i] != f {
			t.Errorf("Logb(%g) = %g, want %g", vf[i], f, logb[i])
		}
	}
	for i := 0; i < len(vflogbSC); i++ {
		if f := Logb(vflogbSC[i]); !alike(logbSC[i], f) {
			t.Errorf("Logb(%g) = %g, want %g", vflogbSC[i], f, logbSC[i])
		}
	}
	for i := 0; i < len(vffrexpBC); i++ {
		if f := Logb(vffrexpBC[i]); !alike(logbBC[i], f) {
			t.Errorf("Logb(%g) = %g, want %g", vffrexpBC[i], f, logbBC[i])
		}
	}
}

func TestLog10(t *testing.T) {
	for i := 0; i < len(vf); i++ {
		a := Abs(vf[i])
		if f := Log10(a); !veryclose(log10[i], f) {
			t.Errorf("Log10(%g) = %g, want %g", a, f, log10[i])
		}
	}
	if f := Log10(E); f != Log10E {
		t.Errorf("Log10(%g) = 
"""




```