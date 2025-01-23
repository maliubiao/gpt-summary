Response:
Let's break down the thought process for analyzing this Go test file.

1. **Understand the Goal:** The primary goal is to understand the functionality of `go/src/crypto/elliptic/elliptic_test.go`. This means identifying what aspects of the `elliptic` package are being tested and how.

2. **High-Level Structure:**  Recognize that this is a Go test file. This immediately tells us we should look for functions starting with `Test` and `Benchmark`. The `package elliptic` declaration confirms this is testing the `elliptic` package.

3. **Iterate Through Functions:** Systematically go through each function defined in the file.

4. **`genericParamsForCurve`:**  This looks like a helper function. It takes a `Curve` interface and returns a `*CurveParams`. The comment hints at forcing the use of the generic implementation. This suggests one aspect being tested is the generic curve implementation versus specific optimized ones.

5. **`testAllCurves`:**  This is a crucial helper function for structuring tests. It iterates over a predefined set of curves (P256, P224, P384, P521), optionally including the "generic params" versions. The `testing.Short()` check indicates a way to reduce test execution time. The core is calling the passed-in function `f` for each curve. This pattern suggests many tests will be performed against all defined curves.

6. **`TestOnCurve`:**  This test specifically checks if the base point (Gx, Gy) of each curve lies on the curve using the `IsOnCurve` method. It confirms a fundamental property of elliptic curves.

7. **`TestOffCurve`:** This test verifies that points *not* on the curve are correctly identified as such by `IsOnCurve`. It also tests the `Unmarshal` function's behavior when given byte representations of points that are off the curve. It's testing both positive and negative cases.

8. **`TestInfinity`:** This test focuses on the point at infinity (the identity element in the elliptic curve group). It checks how different operations (`ScalarMult`, `ScalarBaseMult`, `Double`, `Add`, `Marshal`, `Unmarshal`) behave when involving the point at infinity. The `isInfinity` helper function is used for comparison.

9. **`TestMarshal`:** This is a standard serialization/deserialization test. It generates a key pair, marshals the public key (an elliptic curve point), unmarshals it, and verifies that the original and recovered points are identical.

10. **`TestUnmarshalToLargeCoordinates`:** This test specifically addresses a past issue (referenced by the Go issue link) related to handling large coordinates during unmarshaling. It attempts to unmarshal points with coordinates exceeding the curve's modulus to ensure proper rejection.

11. **`TestInvalidCoordinates`:** This test checks how the `IsOnCurve` method handles invalid coordinates (negative, larger than the modulus). It expects `IsOnCurve` to return `false` in these cases.

12. **`TestMarshalCompressed`:**  This test focuses on compressed point serialization. It includes specific test cases for P256 with known compressed representations and also tests the error handling for invalid compressed data. It then runs the same round-trip test (marshal, unmarshal, compare) for all curves.

13. **`TestLargeIsOnCurve`:** This is a simple check to ensure that `IsOnCurve` correctly identifies very large, arbitrary points as being off the curve.

14. **Benchmark Functions (`BenchmarkScalarBaseMult`, `BenchmarkScalarMult`, `BenchmarkMarshalUnmarshal`):** These functions measure the performance of key elliptic curve operations: scalar base multiplication, scalar multiplication, and marshaling/unmarshaling (both compressed and uncompressed). The `benchmarkAllCurves` helper function is used to run these benchmarks against different curves.

15. **Synthesize Functionality:** Based on the individual test functions, summarize the overall functionality being tested. This includes:
    * Basic curve properties (base point being on the curve).
    * Correct identification of points on and off the curve.
    * Correct handling of the point at infinity.
    * Functionality of point serialization (marshaling) and deserialization (unmarshaling) in both compressed and uncompressed formats.
    * Robustness against invalid input (off-curve points, large coordinates, invalid coordinates, invalid compressed data).
    * Performance of key operations.

16. **Infer Go Feature:** Connect the tested functionality to the broader Go language features. Elliptic curve cryptography is clearly related to digital signatures and key exchange, which are essential security primitives.

17. **Code Example:** Create a simple Go code example demonstrating how to use the `elliptic` package for generating a key pair and performing basic operations.

18. **Input/Output for Code Reasoning:**  Provide a concrete example with specific inputs and expected outputs for the marshaling and unmarshaling tests to illustrate the process.

19. **Command-Line Arguments:** Explain the role of `go test` and the `-short` flag.

20. **Common Mistakes:** Think about potential pitfalls developers might encounter when using elliptic curve cryptography, such as incorrect handling of the point at infinity or not validating inputs.

21. **Structure and Language:** Organize the information logically and use clear, concise Chinese. Use formatting (bullet points, code blocks) to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus only on the `Test` functions.
* **Correction:** Realize that `benchmark` functions are also important for understanding the file's purpose (performance testing).
* **Initial thought:**  Just list the tests.
* **Correction:**  Realize the need to explain *what* each test is doing and *why* it's important.
* **Initial thought:** The `genericParamsForCurve` function is just an internal helper.
* **Correction:**  Understand that it's specifically used to test the generic curve implementation, which is a key aspect of the package.
* **Initial thought:**  Omit the specific hex data in `TestMarshalCompressed`.
* **Correction:** Include it as it provides concrete examples of compressed point representations.

By following this systematic approach, including reviewing the code, understanding the testing logic, and considering the broader context, we can arrive at a comprehensive and accurate description of the functionality of the `elliptic_test.go` file.
这段代码是 Go 语言标准库 `crypto/elliptic` 包的一部分，专门用于测试椭圆曲线密码学相关的功能。它包含了多个测试函数，覆盖了椭圆曲线的各种操作和属性。

**主要功能列表:**

1. **测试不同椭圆曲线的参数:**  它会针对 `P256`, `P224`, `P384`, `P521` 这些 NIST 标准的椭圆曲线进行测试。同时，它还会测试通过 `genericParamsForCurve` 函数获取的通用 `CurveParams` 结构体，这可以验证通用的椭圆曲线实现。

2. **测试点是否在曲线上 (`TestOnCurve`, `TestOffCurve`, `TestInvalidCoordinates`):**
   - `TestOnCurve`: 验证椭圆曲线的基点 (Gx, Gy) 是否在该曲线上。
   - `TestOffCurve`: 验证不在曲线上的点是否被正确地识别出来。
   - `TestInvalidCoordinates`: 验证当提供无效的坐标值（例如，负数或大于曲线参数 P 的数）时，`IsOnCurve` 方法是否返回 `false`。

3. **测试无穷远点的处理 (`TestInfinity`):** 验证椭圆曲线中的无穷远点（也称为零点或单位元）在各种运算中的行为，例如：
   - 标量乘法（乘以群的阶数 N 应该得到无穷远点）。
   - 乘以 0 应该得到无穷远点。
   - 无穷远点与任何点的加法。
   - 倍乘无穷远点。
   - 序列化和反序列化无穷远点是否会产生错误。

4. **测试点的序列化和反序列化 (`TestMarshal`, `TestMarshalCompressed`):**
   - `TestMarshal`: 测试将椭圆曲线上的点序列化为字节数组，然后再反序列化回来的过程是否正确，验证数据的一致性。使用未压缩的格式。
   - `TestMarshalCompressed`: 测试使用压缩格式进行序列化和反序列化的过程。压缩格式可以节省空间。

5. **测试处理过大坐标的情况 (`TestUnmarshalToLargeCoordinates`):**  测试当尝试反序列化具有超出曲线定义范围的坐标的点时，是否能正确处理并返回错误。这主要是为了防止某些安全漏洞。

6. **性能基准测试 (`BenchmarkScalarBaseMult`, `BenchmarkScalarMult`, `BenchmarkMarshalUnmarshal`):**  衡量椭圆曲线的一些关键操作的性能，例如：
   - `ScalarBaseMult`: 基点标量乘法。
   - `ScalarMult`: 任意点的标量乘法。
   - `MarshalUnmarshal`: 序列化和反序列化的性能（包括压缩和非压缩格式）。

**它是什么Go语言功能的实现？**

这段代码是针对 Go 语言标准库中 `crypto/elliptic` 包提供的椭圆曲线密码学功能的测试。`crypto/elliptic` 包实现了常用的 NIST 标准椭圆曲线，并提供了进行椭圆曲线运算的基础方法，例如：

- `IsOnCurve`: 判断一个点是否在椭圆曲线上。
- `Add`:  椭圆曲线上的点加法。
- `Double`: 椭圆曲线上的点倍乘。
- `ScalarMult`:  椭圆曲线上的点标量乘法。
- `ScalarBaseMult`: 椭圆曲线基点的标量乘法。
- `Marshal`: 将椭圆曲线上的点序列化为字节数组（未压缩格式）。
- `Unmarshal`: 将字节数组反序列化为椭圆曲线上的点。
- `MarshalCompressed`: 将椭圆曲线上的点序列化为字节数组（压缩格式）。
- `UnmarshalCompressed`: 将字节数组反序列化为椭圆曲线上的点（压缩格式）。
- `GenerateKey`: 生成椭圆曲线密钥对。

**Go 代码举例说明:**

假设我们要测试 `elliptic.P256()` 曲线的 `IsOnCurve` 方法：

```go
package main

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

func main() {
	curve := elliptic.P256()
	// P256 的基点
	gx := curve.Params().Gx
	gy := curve.Params().Gy

	isOnCurve := curve.IsOnCurve(gx, gy)
	fmt.Printf("基点 (%v, %v) 是否在 P256 曲线上: %t\n", gx, gy, isOnCurve)

	// 一个不在 P256 曲线上的点 (随意选择)
	offX := big.NewInt(1)
	offY := big.NewInt(1)
	isOffCurve := curve.IsOnCurve(offX, offY)
	fmt.Printf("点 (%v, %v) 是否在 P256 曲线上: %t\n", offX, offY, isOffCurve)
}
```

**假设的输入与输出：**

对于上面的代码示例，假设的输出如下：

```
基点 (&{550662630222773436695102281605821279001947759383544640573403AD777D2ECE3CACA73}) 是否在 P256 曲线上: true
点 (&{1}) 是否在 P256 曲线上: false
```

**命令行参数的具体处理:**

这段代码本身是一个测试文件，它通常通过 `go test` 命令来运行。 `go test` 命令会查找当前目录（或指定目录）下所有以 `_test.go` 结尾的文件，并执行其中的测试函数（函数名以 `Test` 开头）和性能基准测试函数（函数名以 `Benchmark` 开头）。

在 `elliptic_test.go` 中，可以看到使用了 `testing.Short()`。当使用 `go test -short` 命令运行时，`testing.Short()` 会返回 `true`，这会导致一些耗时较长的测试被跳过，例如在 `testAllCurves` 函数中，当 `testing.Short()` 为 `true` 时，只会测试第一个曲线 (`P256`)。

**使用者易犯错的点:**

1. **错误地假设无穷远点的坐标:**  无穷远点在数学上是特殊的，在代码中通常用 x 和 y 都为 0 的 `big.Int` 表示。使用者可能会错误地认为无穷远点有其他的坐标值。

   ```go
   // 错误的做法：
   infinityX := big.NewInt(0)
   infinityY := big.NewInt(1) // 错误！无穷远点的 y 坐标也应该是 0

   curve := elliptic.P256()
   isOnCurve := curve.IsOnCurve(infinityX, infinityY) // 这将返回 false
   ```

2. **不验证反序列化后的点是否在曲线上:**  在接收或处理来自外部的数据时，反序列化得到的点可能并不真的在预期的椭圆曲线上。  为了安全，应该始终验证反序列化后的点是否满足曲线方程。

   ```go
   // 假设 receivedBytes 是从网络接收到的表示椭圆曲线点的字节数组
   curve := elliptic.P256()
   x, y := elliptic.Unmarshal(curve, receivedBytes)
   if x == nil {
       // 反序列化失败
       // ...
   }
   if !curve.IsOnCurve(x, y) {
       // 接收到的点不在曲线上，可能是恶意数据
       // ...
   }
   ```

3. **混淆压缩和非压缩的序列化格式:**  椭圆曲线点的序列化有两种格式：压缩和非压缩。  `elliptic.Marshal` 生成非压缩格式，而 `elliptic.MarshalCompressed` 生成压缩格式。  使用错误的 `Unmarshal` 函数解析另一种格式的数据会导致错误。

   ```go
   curve := elliptic.P256()
   x, y, _ := elliptic.GenerateKey(curve, rand.Reader)

   // 使用压缩格式序列化
   compressedBytes := elliptic.MarshalCompressed(curve, x, y)

   // 尝试使用非压缩格式反序列化 (会失败)
   x_uncompressed, y_uncompressed := elliptic.Unmarshal(curve, compressedBytes)
   if x_uncompressed != nil {
       fmt.Println("错误：应该反序列化失败")
   }

   // 正确的做法是使用 UnmarshalCompressed
   x_compressed, y_compressed := elliptic.UnmarshalCompressed(curve, compressedBytes)
   if x_compressed == nil {
       fmt.Println("反序列化压缩格式失败")
   }
   ```

这段测试代码覆盖了 `crypto/elliptic` 包的关键功能和边界情况，有助于确保该包的正确性和健壮性。 理解这些测试用例可以帮助开发者更好地理解和使用 Go 语言的椭圆曲线密码学库。

### 提示词
```
这是路径为go/src/crypto/elliptic/elliptic_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package elliptic

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

// genericParamsForCurve returns the dereferenced CurveParams for
// the specified curve. This is used to avoid the logic for
// upgrading a curve to its specific implementation, forcing
// usage of the generic implementation.
func genericParamsForCurve(c Curve) *CurveParams {
	d := *(c.Params())
	return &d
}

func testAllCurves(t *testing.T, f func(*testing.T, Curve)) {
	tests := []struct {
		name  string
		curve Curve
	}{
		{"P256", P256()},
		{"P256/Params", genericParamsForCurve(P256())},
		{"P224", P224()},
		{"P224/Params", genericParamsForCurve(P224())},
		{"P384", P384()},
		{"P384/Params", genericParamsForCurve(P384())},
		{"P521", P521()},
		{"P521/Params", genericParamsForCurve(P521())},
	}
	if testing.Short() {
		tests = tests[:1]
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestOnCurve(t *testing.T) {
	t.Parallel()
	testAllCurves(t, func(t *testing.T, curve Curve) {
		if !curve.IsOnCurve(curve.Params().Gx, curve.Params().Gy) {
			t.Error("basepoint is not on the curve")
		}
	})
}

func TestOffCurve(t *testing.T) {
	t.Parallel()
	testAllCurves(t, func(t *testing.T, curve Curve) {
		x, y := new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)
		if curve.IsOnCurve(x, y) {
			t.Errorf("point off curve is claimed to be on the curve")
		}

		byteLen := (curve.Params().BitSize + 7) / 8
		b := make([]byte, 1+2*byteLen)
		b[0] = 4 // uncompressed point
		x.FillBytes(b[1 : 1+byteLen])
		y.FillBytes(b[1+byteLen : 1+2*byteLen])

		x1, y1 := Unmarshal(curve, b)
		if x1 != nil || y1 != nil {
			t.Errorf("unmarshaling a point not on the curve succeeded")
		}
	})
}

func TestInfinity(t *testing.T) {
	t.Parallel()
	testAllCurves(t, testInfinity)
}

func isInfinity(x, y *big.Int) bool {
	return x.Sign() == 0 && y.Sign() == 0
}

func testInfinity(t *testing.T, curve Curve) {
	x0, y0 := new(big.Int), new(big.Int)
	xG, yG := curve.Params().Gx, curve.Params().Gy

	if !isInfinity(curve.ScalarMult(xG, yG, curve.Params().N.Bytes())) {
		t.Errorf("x^q != ∞")
	}
	if !isInfinity(curve.ScalarMult(xG, yG, []byte{0})) {
		t.Errorf("x^0 != ∞")
	}

	if !isInfinity(curve.ScalarMult(x0, y0, []byte{1, 2, 3})) {
		t.Errorf("∞^k != ∞")
	}
	if !isInfinity(curve.ScalarMult(x0, y0, []byte{0})) {
		t.Errorf("∞^0 != ∞")
	}

	if !isInfinity(curve.ScalarBaseMult(curve.Params().N.Bytes())) {
		t.Errorf("b^q != ∞")
	}
	if !isInfinity(curve.ScalarBaseMult([]byte{0})) {
		t.Errorf("b^0 != ∞")
	}

	if !isInfinity(curve.Double(x0, y0)) {
		t.Errorf("2∞ != ∞")
	}
	// There is no other point of order two on the NIST curves (as they have
	// cofactor one), so Double can't otherwise return the point at infinity.

	nMinusOne := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	x, y := curve.ScalarMult(xG, yG, nMinusOne.Bytes())
	x, y = curve.Add(x, y, xG, yG)
	if !isInfinity(x, y) {
		t.Errorf("x^(q-1) + x != ∞")
	}
	x, y = curve.Add(xG, yG, x0, y0)
	if x.Cmp(xG) != 0 || y.Cmp(yG) != 0 {
		t.Errorf("x+∞ != x")
	}
	x, y = curve.Add(x0, y0, xG, yG)
	if x.Cmp(xG) != 0 || y.Cmp(yG) != 0 {
		t.Errorf("∞+x != x")
	}

	if curve.IsOnCurve(x0, y0) {
		t.Errorf("IsOnCurve(∞) == true")
	}

	if xx, yy := Unmarshal(curve, Marshal(curve, x0, y0)); xx != nil || yy != nil {
		t.Errorf("Unmarshal(Marshal(∞)) did not return an error")
	}
	// We don't test UnmarshalCompressed(MarshalCompressed(∞)) because there are
	// two valid points with x = 0.
	if xx, yy := Unmarshal(curve, []byte{0x00}); xx != nil || yy != nil {
		t.Errorf("Unmarshal(∞) did not return an error")
	}
	byteLen := (curve.Params().BitSize + 7) / 8
	buf := make([]byte, byteLen*2+1)
	buf[0] = 4 // Uncompressed format.
	if xx, yy := Unmarshal(curve, buf); xx != nil || yy != nil {
		t.Errorf("Unmarshal((0,0)) did not return an error")
	}
}

func TestMarshal(t *testing.T) {
	t.Parallel()
	testAllCurves(t, func(t *testing.T, curve Curve) {
		_, x, y, err := GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serialized := Marshal(curve, x, y)
		xx, yy := Unmarshal(curve, serialized)
		if xx == nil {
			t.Fatal("failed to unmarshal")
		}
		if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
			t.Fatal("unmarshal returned different values")
		}
	})
}

func TestUnmarshalToLargeCoordinates(t *testing.T) {
	t.Parallel()
	// See https://golang.org/issues/20482.
	testAllCurves(t, testUnmarshalToLargeCoordinates)
}

func testUnmarshalToLargeCoordinates(t *testing.T, curve Curve) {
	p := curve.Params().P
	byteLen := (p.BitLen() + 7) / 8

	// Set x to be greater than curve's parameter P – specifically, to P+5.
	// Set y to mod_sqrt(x^3 - 3x + B)) so that (x mod P = 5 , y) is on the
	// curve.
	x := new(big.Int).Add(p, big.NewInt(5))
	y := curve.Params().polynomial(x)
	y.ModSqrt(y, p)

	invalid := make([]byte, byteLen*2+1)
	invalid[0] = 4 // uncompressed encoding
	x.FillBytes(invalid[1 : 1+byteLen])
	y.FillBytes(invalid[1+byteLen:])

	if X, Y := Unmarshal(curve, invalid); X != nil || Y != nil {
		t.Errorf("Unmarshal accepts invalid X coordinate")
	}

	if curve == p256 {
		// This is a point on the curve with a small y value, small enough that
		// we can add p and still be within 32 bytes.
		x, _ = new(big.Int).SetString("31931927535157963707678568152204072984517581467226068221761862915403492091210", 10)
		y, _ = new(big.Int).SetString("5208467867388784005506817585327037698770365050895731383201516607147", 10)
		y.Add(y, p)

		if p.Cmp(y) > 0 || y.BitLen() != 256 {
			t.Fatal("y not within expected range")
		}

		// marshal
		x.FillBytes(invalid[1 : 1+byteLen])
		y.FillBytes(invalid[1+byteLen:])

		if X, Y := Unmarshal(curve, invalid); X != nil || Y != nil {
			t.Errorf("Unmarshal accepts invalid Y coordinate")
		}
	}
}

// TestInvalidCoordinates tests big.Int values that are not valid field elements
// (negative or bigger than P). They are expected to return false from
// IsOnCurve, all other behavior is undefined.
func TestInvalidCoordinates(t *testing.T) {
	t.Parallel()
	testAllCurves(t, testInvalidCoordinates)
}

func testInvalidCoordinates(t *testing.T, curve Curve) {
	checkIsOnCurveFalse := func(name string, x, y *big.Int) {
		if curve.IsOnCurve(x, y) {
			t.Errorf("IsOnCurve(%s) unexpectedly returned true", name)
		}
	}

	p := curve.Params().P
	_, x, y, _ := GenerateKey(curve, rand.Reader)
	xx, yy := new(big.Int), new(big.Int)

	// Check if the sign is getting dropped.
	xx.Neg(x)
	checkIsOnCurveFalse("-x, y", xx, y)
	yy.Neg(y)
	checkIsOnCurveFalse("x, -y", x, yy)

	// Check if negative values are reduced modulo P.
	xx.Sub(x, p)
	checkIsOnCurveFalse("x-P, y", xx, y)
	yy.Sub(y, p)
	checkIsOnCurveFalse("x, y-P", x, yy)

	// Check if positive values are reduced modulo P.
	xx.Add(x, p)
	checkIsOnCurveFalse("x+P, y", xx, y)
	yy.Add(y, p)
	checkIsOnCurveFalse("x, y+P", x, yy)

	// Check if the overflow is dropped.
	xx.Add(x, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x+2⁵³⁵, y", xx, y)
	yy.Add(y, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x, y+2⁵³⁵", x, yy)

	// Check if P is treated like zero (if possible).
	// y^2 = x^3 - 3x + B
	// y = mod_sqrt(x^3 - 3x + B)
	// y = mod_sqrt(B) if x = 0
	// If there is no modsqrt, there is no point with x = 0, can't test x = P.
	if yy := new(big.Int).ModSqrt(curve.Params().B, p); yy != nil {
		if !curve.IsOnCurve(big.NewInt(0), yy) {
			t.Fatal("(0, mod_sqrt(B)) is not on the curve?")
		}
		checkIsOnCurveFalse("P, y", p, yy)
	}
}

func TestMarshalCompressed(t *testing.T) {
	t.Parallel()
	t.Run("P-256/03", func(t *testing.T) {
		data, _ := hex.DecodeString("031e3987d9f9ea9d7dd7155a56a86b2009e1e0ab332f962d10d8beb6406ab1ad79")
		x, _ := new(big.Int).SetString("13671033352574878777044637384712060483119675368076128232297328793087057702265", 10)
		y, _ := new(big.Int).SetString("66200849279091436748794323380043701364391950689352563629885086590854940586447", 10)
		testMarshalCompressed(t, P256(), x, y, data)
	})
	t.Run("P-256/02", func(t *testing.T) {
		data, _ := hex.DecodeString("021e3987d9f9ea9d7dd7155a56a86b2009e1e0ab332f962d10d8beb6406ab1ad79")
		x, _ := new(big.Int).SetString("13671033352574878777044637384712060483119675368076128232297328793087057702265", 10)
		y, _ := new(big.Int).SetString("49591239931264812013903123569363872165694192725937750565648544718012157267504", 10)
		testMarshalCompressed(t, P256(), x, y, data)
	})

	t.Run("Invalid", func(t *testing.T) {
		data, _ := hex.DecodeString("02fd4bf61763b46581fd9174d623516cf3c81edd40e29ffa2777fb6cb0ae3ce535")
		X, Y := UnmarshalCompressed(P256(), data)
		if X != nil || Y != nil {
			t.Error("expected an error for invalid encoding")
		}
	})

	if testing.Short() {
		t.Skip("skipping other curves on short test")
	}

	testAllCurves(t, func(t *testing.T, curve Curve) {
		_, x, y, err := GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		testMarshalCompressed(t, curve, x, y, nil)
	})

}

func testMarshalCompressed(t *testing.T, curve Curve, x, y *big.Int, want []byte) {
	if !curve.IsOnCurve(x, y) {
		t.Fatal("invalid test point")
	}
	got := MarshalCompressed(curve, x, y)
	if want != nil && !bytes.Equal(got, want) {
		t.Errorf("got unexpected MarshalCompressed result: got %x, want %x", got, want)
	}

	X, Y := UnmarshalCompressed(curve, got)
	if X == nil || Y == nil {
		t.Fatalf("UnmarshalCompressed failed unexpectedly")
	}

	if !curve.IsOnCurve(X, Y) {
		t.Error("UnmarshalCompressed returned a point not on the curve")
	}
	if X.Cmp(x) != 0 || Y.Cmp(y) != 0 {
		t.Errorf("point did not round-trip correctly: got (%v, %v), want (%v, %v)", X, Y, x, y)
	}
}

func TestLargeIsOnCurve(t *testing.T) {
	t.Parallel()
	testAllCurves(t, func(t *testing.T, curve Curve) {
		large := big.NewInt(1)
		large.Lsh(large, 1000)
		if curve.IsOnCurve(large, large) {
			t.Errorf("(2^1000, 2^1000) is reported on the curve")
		}
	})
}

func benchmarkAllCurves(b *testing.B, f func(*testing.B, Curve)) {
	tests := []struct {
		name  string
		curve Curve
	}{
		{"P256", P256()},
		{"P224", P224()},
		{"P384", P384()},
		{"P521", P521()},
	}
	for _, test := range tests {
		curve := test.curve
		b.Run(test.name, func(b *testing.B) {
			f(b, curve)
		})
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve Curve) {
		priv, _, _, _ := GenerateKey(curve, rand.Reader)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			x, _ := curve.ScalarBaseMult(priv)
			// Prevent the compiler from optimizing out the operation.
			priv[0] ^= byte(x.Bits()[0])
		}
	})
}

func BenchmarkScalarMult(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve Curve) {
		_, x, y, _ := GenerateKey(curve, rand.Reader)
		priv, _, _, _ := GenerateKey(curve, rand.Reader)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			x, y = curve.ScalarMult(x, y, priv)
		}
	})
}

func BenchmarkMarshalUnmarshal(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve Curve) {
		_, x, y, _ := GenerateKey(curve, rand.Reader)
		b.Run("Uncompressed", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf := Marshal(curve, x, y)
				xx, yy := Unmarshal(curve, buf)
				if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
					b.Error("Unmarshal output different from Marshal input")
				}
			}
		})
		b.Run("Compressed", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf := MarshalCompressed(curve, x, y)
				xx, yy := UnmarshalCompressed(curve, buf)
				if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
					b.Error("Unmarshal output different from Marshal input")
				}
			}
		})
	})
}
```