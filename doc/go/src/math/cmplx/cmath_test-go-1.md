Response:
The user wants me to summarize the functionality of the provided Go code snippet, which is the second part of a test file for complex number math functions.

**Plan:**
1. **Identify the purpose of the code:** The code is part of a test suite for the `cmplx` package in Go.
2. **List the tested functions:** Iterate through the code and identify all functions being tested. These will be the core functionalities.
3. **Describe the testing approach:** Observe how each function is tested (e.g., using predefined values, special cases, boundary conditions, continuity checks).
4. **Summarize the overall function:** Combine the information to give a concise overview of what the code does.
这是 Go 语言标准库 `math/cmplx` 包的一部分测试代码。这个代码片段的主要功能是**测试 `cmplx` 包中一系列复数运算函数的正确性**。

具体来说，它针对以下复数函数进行了测试：

*   `Asinh`: 反双曲正弦函数
*   `Atan`: 反正切函数
*   `Atanh`: 反双曲正切函数
*   `Conj`:  共轭复数函数
*   `Cos`:  余弦函数
*   `Cosh`: 双曲余弦函数
*   `Exp`:  指数函数
*   `IsNaN`: 判断是否为 NaN (Not a Number)
*   `Log`:  自然对数函数
*   `Log10`: 以 10 为底的对数函数
*   `Polar`: 将复数转换为极坐标
*   `Pow`:  幂函数
*   `Rect`: 将极坐标转换为复数
*   `Sin`:  正弦函数
*   `Sinh`: 双曲正弦函数
*   `Sqrt`: 平方根函数
*   `Tan`:  正切函数
*   `Tanh`: 双曲正切函数
*   `Cot`: 余切函数 (通过测试用例 `TestInfiniteLoopIntanSeries` 间接测试)

**归纳一下它的功能：**

这个代码片段是 `math/cmplx` 包测试套件的一部分，它专注于验证该包中各种复数函数的计算结果是否符合预期。测试方法包括：

1. **使用预定义的测试用例 (`vc`, `asinhSC`, `atanSC` 等):**  将函数的计算结果与预先计算好的正确结果进行比较，判断其精度是否在可接受的范围内。
2. **测试特殊情况和边界条件:**  例如，测试 `Pow(0, c)` 的各种情况，以及涉及 NaN 的输入。
3. **验证函数的性质:** 例如，利用共轭、取负等操作来验证函数是否满足特定的数学性质，例如 `Asinh(Conj(z)) == Conj(Asinh(z))` 和 `Asinh(-z) == -Asinh(z)`。
4. **检查函数在分支点的连续性:**  对于存在分支切割的函数（如 `Asinh`, `Atan`, `Atanh`, `Log`, `Sqrt`, `Pow`），测试在分支点附近的结果是否连续。
5. **性能基准测试 (`Benchmark...` 函数):**  对各个函数进行基准测试，用于评估其性能。

总的来说，这个代码片段通过大量的测试用例，确保了 `math/cmplx` 包中这些复数运算函数的正确性和可靠性。

Prompt: 
```
这是路径为go/src/math/cmplx/cmath_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
}
	for _, v := range asinhSC {
		if f := Asinh(v.in); !cAlike(v.want, f) {
			t.Errorf("Asinh(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Asinh(Conj(z))  == Asinh(Sinh(z))
		if f := Asinh(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Asinh(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
		if math.IsNaN(real(v.in)) || math.IsNaN(real(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Asinh(-z)  == -Asinh(z)
		if f := Asinh(-v.in); !cAlike(-v.want, f) && !cAlike(v.in, -v.in) {
			t.Errorf("Asinh(%g) = %g, want %g", -v.in, f, -v.want)
		}
	}
	for _, pt := range branchPoints {
		if f0, f1 := Asinh(pt[0]), Asinh(pt[1]); !cVeryclose(f0, f1) {
			t.Errorf("Asinh(%g) not continuous, got %g want %g", pt[0], f0, f1)
		}
	}
}
func TestAtan(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Atan(vc[i]); !cVeryclose(atan[i], f) {
			t.Errorf("Atan(%g) = %g, want %g", vc[i], f, atan[i])
		}
	}
	for _, v := range atanSC {
		if f := Atan(v.in); !cAlike(v.want, f) {
			t.Errorf("Atan(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Atan(Conj(z))  == Conj(Atan(z))
		if f := Atan(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Atan(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
		if math.IsNaN(real(v.in)) || math.IsNaN(real(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Atan(-z)  == -Atan(z)
		if f := Atan(-v.in); !cAlike(-v.want, f) && !cAlike(v.in, -v.in) {
			t.Errorf("Atan(%g) = %g, want %g", -v.in, f, -v.want)
		}
	}
	for _, pt := range branchPoints {
		if f0, f1 := Atan(pt[0]), Atan(pt[1]); !cVeryclose(f0, f1) {
			t.Errorf("Atan(%g) not continuous, got %g want %g", pt[0], f0, f1)
		}
	}
}
func TestAtanh(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Atanh(vc[i]); !cVeryclose(atanh[i], f) {
			t.Errorf("Atanh(%g) = %g, want %g", vc[i], f, atanh[i])
		}
	}
	for _, v := range atanhSC {
		if f := Atanh(v.in); !cAlike(v.want, f) {
			t.Errorf("Atanh(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Atanh(Conj(z))  == Conj(Atanh(z))
		if f := Atanh(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Atanh(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
		if math.IsNaN(real(v.in)) || math.IsNaN(real(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Atanh(-z)  == -Atanh(z)
		if f := Atanh(-v.in); !cAlike(-v.want, f) && !cAlike(v.in, -v.in) {
			t.Errorf("Atanh(%g) = %g, want %g", -v.in, f, -v.want)
		}
	}
	for _, pt := range branchPoints {
		if f0, f1 := Atanh(pt[0]), Atanh(pt[1]); !cVeryclose(f0, f1) {
			t.Errorf("Atanh(%g) not continuous, got %g want %g", pt[0], f0, f1)
		}
	}
}
func TestConj(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Conj(vc[i]); !cVeryclose(conj[i], f) {
			t.Errorf("Conj(%g) = %g, want %g", vc[i], f, conj[i])
		}
	}
	for i := 0; i < len(vcConjSC); i++ {
		if f := Conj(vcConjSC[i]); !cAlike(conjSC[i], f) {
			t.Errorf("Conj(%g) = %g, want %g", vcConjSC[i], f, conjSC[i])
		}
	}
}
func TestCos(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Cos(vc[i]); !cSoclose(cos[i], f, 3e-15) {
			t.Errorf("Cos(%g) = %g, want %g", vc[i], f, cos[i])
		}
	}
	for _, v := range cosSC {
		if f := Cos(v.in); !cAlike(v.want, f) {
			t.Errorf("Cos(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Cos(Conj(z))  == Cos(Cosh(z))
		if f := Cos(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Cos(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
		if math.IsNaN(real(v.in)) || math.IsNaN(real(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Cos(-z)  == Cos(z)
		if f := Cos(-v.in); !cAlike(v.want, f) && !cAlike(v.in, -v.in) {
			t.Errorf("Cos(%g) = %g, want %g", -v.in, f, v.want)
		}
	}
}
func TestCosh(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Cosh(vc[i]); !cSoclose(cosh[i], f, 2e-15) {
			t.Errorf("Cosh(%g) = %g, want %g", vc[i], f, cosh[i])
		}
	}
	for _, v := range coshSC {
		if f := Cosh(v.in); !cAlike(v.want, f) {
			t.Errorf("Cosh(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Cosh(Conj(z))  == Conj(Cosh(z))
		if f := Cosh(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Cosh(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
		if math.IsNaN(real(v.in)) || math.IsNaN(real(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Cosh(-z)  == Cosh(z)
		if f := Cosh(-v.in); !cAlike(v.want, f) && !cAlike(v.in, -v.in) {
			t.Errorf("Cosh(%g) = %g, want %g", -v.in, f, v.want)
		}
	}
}
func TestExp(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Exp(vc[i]); !cSoclose(exp[i], f, 1e-15) {
			t.Errorf("Exp(%g) = %g, want %g", vc[i], f, exp[i])
		}
	}
	for _, v := range expSC {
		if f := Exp(v.in); !cAlike(v.want, f) {
			t.Errorf("Exp(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Exp(Conj(z))  == Exp(Cosh(z))
		if f := Exp(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Exp(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
	}
}
func TestIsNaN(t *testing.T) {
	for i := 0; i < len(vcIsNaNSC); i++ {
		if f := IsNaN(vcIsNaNSC[i]); isNaNSC[i] != f {
			t.Errorf("IsNaN(%v) = %v, want %v", vcIsNaNSC[i], f, isNaNSC[i])
		}
	}
}
func TestLog(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Log(vc[i]); !cVeryclose(log[i], f) {
			t.Errorf("Log(%g) = %g, want %g", vc[i], f, log[i])
		}
	}
	for _, v := range logSC {
		if f := Log(v.in); !cAlike(v.want, f) {
			t.Errorf("Log(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Log(Conj(z))  == Conj(Log(z))
		if f := Log(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Log(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
	}
	for _, pt := range branchPoints {
		if f0, f1 := Log(pt[0]), Log(pt[1]); !cVeryclose(f0, f1) {
			t.Errorf("Log(%g) not continuous, got %g want %g", pt[0], f0, f1)
		}
	}
}
func TestLog10(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Log10(vc[i]); !cVeryclose(log10[i], f) {
			t.Errorf("Log10(%g) = %g, want %g", vc[i], f, log10[i])
		}
	}
	for _, v := range log10SC {
		if f := Log10(v.in); !cAlike(v.want, f) {
			t.Errorf("Log10(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Log10(Conj(z))  == Conj(Log10(z))
		if f := Log10(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Log10(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
	}
}
func TestPolar(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if r, theta := Polar(vc[i]); !veryclose(polar[i].r, r) && !veryclose(polar[i].theta, theta) {
			t.Errorf("Polar(%g) = %g, %g want %g, %g", vc[i], r, theta, polar[i].r, polar[i].theta)
		}
	}
	for i := 0; i < len(vcPolarSC); i++ {
		if r, theta := Polar(vcPolarSC[i]); !alike(polarSC[i].r, r) && !alike(polarSC[i].theta, theta) {
			t.Errorf("Polar(%g) = %g, %g, want %g, %g", vcPolarSC[i], r, theta, polarSC[i].r, polarSC[i].theta)
		}
	}
}
func TestPow(t *testing.T) {
	// Special cases for Pow(0, c).
	var zero = complex(0, 0)
	zeroPowers := [][2]complex128{
		{0, 1 + 0i},
		{1.5, 0 + 0i},
		{-1.5, complex(math.Inf(0), 0)},
		{-1.5 + 1.5i, Inf()},
	}
	for _, zp := range zeroPowers {
		if f := Pow(zero, zp[0]); f != zp[1] {
			t.Errorf("Pow(%g, %g) = %g, want %g", zero, zp[0], f, zp[1])
		}
	}
	var a = complex(3.0, 3.0)
	for i := 0; i < len(vc); i++ {
		if f := Pow(a, vc[i]); !cSoclose(pow[i], f, 4e-15) {
			t.Errorf("Pow(%g, %g) = %g, want %g", a, vc[i], f, pow[i])
		}
	}
	for i := 0; i < len(vcPowSC); i++ {
		if f := Pow(vcPowSC[i][0], vcPowSC[i][1]); !cAlike(powSC[i], f) {
			t.Errorf("Pow(%g, %g) = %g, want %g", vcPowSC[i][0], vcPowSC[i][1], f, powSC[i])
		}
	}
	for _, pt := range branchPoints {
		if f0, f1 := Pow(pt[0], 0.1), Pow(pt[1], 0.1); !cVeryclose(f0, f1) {
			t.Errorf("Pow(%g, 0.1) not continuous, got %g want %g", pt[0], f0, f1)
		}
	}
}
func TestRect(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Rect(polar[i].r, polar[i].theta); !cVeryclose(vc[i], f) {
			t.Errorf("Rect(%g, %g) = %g want %g", polar[i].r, polar[i].theta, f, vc[i])
		}
	}
	for i := 0; i < len(vcPolarSC); i++ {
		if f := Rect(polarSC[i].r, polarSC[i].theta); !cAlike(vcPolarSC[i], f) {
			t.Errorf("Rect(%g, %g) = %g, want %g", polarSC[i].r, polarSC[i].theta, f, vcPolarSC[i])
		}
	}
}
func TestSin(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Sin(vc[i]); !cSoclose(sin[i], f, 2e-15) {
			t.Errorf("Sin(%g) = %g, want %g", vc[i], f, sin[i])
		}
	}
	for _, v := range sinSC {
		if f := Sin(v.in); !cAlike(v.want, f) {
			t.Errorf("Sin(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Sin(Conj(z))  == Conj(Sin(z))
		if f := Sin(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Sinh(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
		if math.IsNaN(real(v.in)) || math.IsNaN(real(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Sin(-z)  == -Sin(z)
		if f := Sin(-v.in); !cAlike(-v.want, f) && !cAlike(v.in, -v.in) {
			t.Errorf("Sinh(%g) = %g, want %g", -v.in, f, -v.want)
		}
	}
}
func TestSinh(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Sinh(vc[i]); !cSoclose(sinh[i], f, 2e-15) {
			t.Errorf("Sinh(%g) = %g, want %g", vc[i], f, sinh[i])
		}
	}
	for _, v := range sinhSC {
		if f := Sinh(v.in); !cAlike(v.want, f) {
			t.Errorf("Sinh(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Sinh(Conj(z))  == Conj(Sinh(z))
		if f := Sinh(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Sinh(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
		if math.IsNaN(real(v.in)) || math.IsNaN(real(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Sinh(-z)  == -Sinh(z)
		if f := Sinh(-v.in); !cAlike(-v.want, f) && !cAlike(v.in, -v.in) {
			t.Errorf("Sinh(%g) = %g, want %g", -v.in, f, -v.want)
		}
	}
}
func TestSqrt(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Sqrt(vc[i]); !cVeryclose(sqrt[i], f) {
			t.Errorf("Sqrt(%g) = %g, want %g", vc[i], f, sqrt[i])
		}
	}
	for _, v := range sqrtSC {
		if f := Sqrt(v.in); !cAlike(v.want, f) {
			t.Errorf("Sqrt(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Sqrt(Conj(z)) == Conj(Sqrt(z))
		if f := Sqrt(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Sqrt(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
	}
	for _, pt := range branchPoints {
		if f0, f1 := Sqrt(pt[0]), Sqrt(pt[1]); !cVeryclose(f0, f1) {
			t.Errorf("Sqrt(%g) not continuous, got %g want %g", pt[0], f0, f1)
		}
	}
}
func TestTan(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Tan(vc[i]); !cSoclose(tan[i], f, 3e-15) {
			t.Errorf("Tan(%g) = %g, want %g", vc[i], f, tan[i])
		}
	}
	for _, v := range tanSC {
		if f := Tan(v.in); !cAlike(v.want, f) {
			t.Errorf("Tan(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Tan(Conj(z))  == Conj(Tan(z))
		if f := Tan(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Tan(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
		if math.IsNaN(real(v.in)) || math.IsNaN(real(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Tan(-z)  == -Tan(z)
		if f := Tan(-v.in); !cAlike(-v.want, f) && !cAlike(v.in, -v.in) {
			t.Errorf("Tan(%g) = %g, want %g", -v.in, f, -v.want)
		}
	}
}
func TestTanh(t *testing.T) {
	for i := 0; i < len(vc); i++ {
		if f := Tanh(vc[i]); !cSoclose(tanh[i], f, 2e-15) {
			t.Errorf("Tanh(%g) = %g, want %g", vc[i], f, tanh[i])
		}
	}
	for _, v := range tanhSC {
		if f := Tanh(v.in); !cAlike(v.want, f) {
			t.Errorf("Tanh(%g) = %g, want %g", v.in, f, v.want)
		}
		if math.IsNaN(imag(v.in)) || math.IsNaN(imag(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Tanh(Conj(z))  == Conj(Tanh(z))
		if f := Tanh(Conj(v.in)); !cAlike(Conj(v.want), f) && !cAlike(v.in, Conj(v.in)) {
			t.Errorf("Tanh(%g) = %g, want %g", Conj(v.in), f, Conj(v.want))
		}
		if math.IsNaN(real(v.in)) || math.IsNaN(real(v.want)) {
			// Negating NaN is undefined with regard to the sign bit produced.
			continue
		}
		// Tanh(-z)  == -Tanh(z)
		if f := Tanh(-v.in); !cAlike(-v.want, f) && !cAlike(v.in, -v.in) {
			t.Errorf("Tanh(%g) = %g, want %g", -v.in, f, -v.want)
		}
	}
}

// See issue 17577
func TestInfiniteLoopIntanSeries(t *testing.T) {
	want := Inf()
	if got := Cot(0); got != want {
		t.Errorf("Cot(0): got %g, want %g", got, want)
	}
}

func BenchmarkAbs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Abs(complex(2.5, 3.5))
	}
}
func BenchmarkAcos(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Acos(complex(2.5, 3.5))
	}
}
func BenchmarkAcosh(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Acosh(complex(2.5, 3.5))
	}
}
func BenchmarkAsin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Asin(complex(2.5, 3.5))
	}
}
func BenchmarkAsinh(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Asinh(complex(2.5, 3.5))
	}
}
func BenchmarkAtan(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Atan(complex(2.5, 3.5))
	}
}
func BenchmarkAtanh(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Atanh(complex(2.5, 3.5))
	}
}
func BenchmarkConj(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Conj(complex(2.5, 3.5))
	}
}
func BenchmarkCos(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Cos(complex(2.5, 3.5))
	}
}
func BenchmarkCosh(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Cosh(complex(2.5, 3.5))
	}
}
func BenchmarkExp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Exp(complex(2.5, 3.5))
	}
}
func BenchmarkLog(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Log(complex(2.5, 3.5))
	}
}
func BenchmarkLog10(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Log10(complex(2.5, 3.5))
	}
}
func BenchmarkPhase(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Phase(complex(2.5, 3.5))
	}
}
func BenchmarkPolar(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Polar(complex(2.5, 3.5))
	}
}
func BenchmarkPow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Pow(complex(2.5, 3.5), complex(2.5, 3.5))
	}
}
func BenchmarkRect(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Rect(2.5, 1.5)
	}
}
func BenchmarkSin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sin(complex(2.5, 3.5))
	}
}
func BenchmarkSinh(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sinh(complex(2.5, 3.5))
	}
}
func BenchmarkSqrt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sqrt(complex(2.5, 3.5))
	}
}
func BenchmarkTan(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Tan(complex(2.5, 3.5))
	}
}
func BenchmarkTanh(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Tanh(complex(2.5, 3.5))
	}
}

"""




```