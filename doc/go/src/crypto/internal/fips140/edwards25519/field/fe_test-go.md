Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the *functionality* of the provided Go code, focusing on `fe_test.go`. It also asks to infer the *Go language feature* being tested, provide examples, and highlight potential pitfalls.

2. **Initial Scan - Identify Key Components:**  Quickly read through the code to identify major sections and keywords. This reveals:
    * **Package `field`:**  This immediately suggests the code is dealing with some kind of mathematical field, likely in a cryptographic context given the file path (`crypto/internal/fips140/edwards25519`).
    * **Imports:**  `bytes`, `crypto/rand`, `encoding/hex`, `io`, `math/big`, `math/bits`, `math/rand`, `reflect`, `testing`, `testing/quick`. These imports hint at operations like random number generation, byte manipulation, large number arithmetic, reflection, and most importantly, testing. The presence of `testing/quick` is a strong indicator of property-based testing.
    * **Struct `Element`:** This is likely the fundamental data type representing elements within the field.
    * **Functions with `Test` prefix:**  `TestMultiplyDistributesOverAdd`, `TestMul64to128`, `TestSetBytesRoundTrip`, etc. These are standard Go testing functions.
    * **Helper Functions:**  `quickCheckConfig`, `generateFieldElement`, `generateWeirdFieldElement`, `isInBounds`, `swapEndianness`, `fromBig`, `toBig`, `fromDecimal`, `decodeHex`. These assist in setting up and executing the tests.
    * **Global Variables:** `weirdLimbs51`, `weirdLimbs52`, `sqrtM1`. These likely represent specific values or edge cases used in testing.
    * **Methods on `Element`:** `String`, `Bytes`, `SetBytes`, `Equal`, `Add`, `Multiply`, `Square`, `Invert`, `Select`, `Swap`, `Mult32`, `SqrtRatio`, `reduce`, `carryPropagate`, `carryPropagateGeneric`. These are the core operations being tested.
    * **Assembly-like Functions (ending in `Generic` and non-`Generic`):**  `feSquare`, `feSquareGeneric`, `feMul`, `feMulGeneric`. This suggests the code is comparing optimized (likely assembly-based) implementations against generic Go implementations.

3. **Infer the Go Language Feature:**  The presence of `testing` and especially `testing/quick` strongly points to **unit testing** and, more specifically, **property-based testing**. `testing/quick` allows you to define properties your code should satisfy (e.g., multiplication distributes over addition) and then automatically generate random inputs to verify those properties.

4. **Categorize Functionality by Tests:**  Go through each `Test...` function and summarize its purpose:
    * `TestMultiplyDistributesOverAdd`: Checks the distributive property of multiplication over addition.
    * `TestMul64to128`: Tests a low-level 64-bit multiplication function.
    * `TestSetBytesRoundTrip`: Verifies that converting an `Element` to bytes and back yields the original `Element`. It also checks fixed test vectors.
    * `TestBytesBigEquivalence`: Checks the consistency between the `Element`'s byte representation and its representation as a `big.Int`.
    * `TestDecimalConstants`: Checks if hardcoded decimal string representations match expected `Element` values.
    * `TestSetBytesRoundTripEdgeCases`:  (Note: this is incomplete in the provided code). Likely intended to test `SetBytes` with boundary values.
    * `TestConsistency`: Checks if `Multiply` and `Square` produce the same result when squaring.
    * `TestEqual`: Tests the `Equal` method for equality and inequality.
    * `TestInvert`: Tests the `Invert` method and verifies the identity property (x * x⁻¹ = 1).
    * `TestSelectSwap`: Tests the `Select` (conditional assignment) and `Swap` methods.
    * `TestMult32`: Checks if multiplying by a `uint32` is equivalent to multiplying by an `Element` constructed from that `uint32`.
    * `TestSqrtRatio`: Tests the `SqrtRatio` function, which computes the square root of a ratio.
    * `TestCarryPropagate`: Compares assembly-optimized and generic carry propagation implementations.
    * `TestFeSquare`: Compares assembly-optimized and generic squaring implementations.
    * `TestFeMul`: Compares assembly-optimized and generic multiplication implementations.

5. **Provide Go Code Examples:** For the key functionality (property-based testing, byte conversion), construct simple illustrative examples.

6. **Address Code Reasoning with Assumptions:** Focus on the more complex logic, like `TestBytesBigEquivalence`. Clearly state the assumptions being made about the underlying representation and the purpose of the `swapEndianness` function. Explain how the code verifies the equivalence between the custom `Element` and the standard `big.Int`.

7. **Command-Line Arguments:**  The code uses the `testing` package, so explain the common command-line flags relevant to testing, particularly `-short`.

8. **Identify Potential Pitfalls:** Think about common mistakes when working with the tested functionalities. For example, misunderstanding the bit masking in `SetBytes` or the non-canonical representation of `Element`s.

9. **Structure and Refine:** Organize the information logically with clear headings and explanations. Use precise language and provide code snippets that are easy to understand. Ensure the answer directly addresses all parts of the original request. For instance, explicitly mention the FIPS 140 context and the Edwards25519 curve.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is just standard unit testing.
* **Correction:** The presence of `testing/quick` indicates property-based testing is a significant part of the functionality. Need to emphasize this.
* **Initial thought:** Briefly mention the purpose of each test function.
* **Refinement:** Group the tests by the functionality they are verifying (e.g., arithmetic operations, byte conversion) for better clarity.
* **Initial thought:**  Just show the basic usage of `SetBytes` and `Bytes`.
* **Refinement:** Highlight the potential confusion with the most significant bit masking in `SetBytes`.
* **Initial thought:**  Explain `TestBytesBigEquivalence` simply.
* **Refinement:**  Realize the endianness conversion is a crucial part of understanding this test. Add an explanation of `swapEndianness` and why it's needed.

By following these steps, combining code analysis with an understanding of Go testing practices, and iteratively refining the explanations, we can arrive at a comprehensive and accurate answer to the request.
这段代码是 Go 语言中 `crypto/internal/fips140/edwards25519/field` 包下 `fe_test.go` 文件的一部分，它主要用于**测试有限域元素（Field Element）的相关操作**。这个有限域是用于实现 Edwards25519 椭圆曲线密码学的，并且特别强调了符合 FIPS 140 标准。

以下是这段代码的主要功能分解：

1. **`Element` 类型的字符串表示：**
   - `func (v Element) String() string`
   - 功能：将 `Element` 类型的值转换为十六进制字符串表示，方便调试和日志输出。

2. **配置快速检查测试（QuickCheck）：**
   - `func quickCheckConfig(slowScale int) *quick.Config`
   - 功能：根据 `-short` 命令行标志，动态调整 `testing/quick` 包的测试用例数量。如果未设置 `-short` 标志，则会增加测试用例的数量，进行更彻底的测试。

3. **生成随机的有限域元素：**
   - `func generateFieldElement(rand *mathrand.Rand) Element`
   - 功能：生成一个随机的 `Element` 值。注意它使用了一个掩码 `maskLow52Bits`，这意味着生成的元素的每个 64 位字只使用低 52 位。这可能是为了模拟某些底层优化的场景或者避免溢出。

4. **生成特殊的有限域元素（用于边界测试）：**
   - `var weirdLimbs51 = []uint64{...}`
   - `var weirdLimbs52 = []uint64{...}`
   - `func generateWeirdFieldElement(rand *mathrand.Rand) Element`
   - 功能：定义了一些特定的 `uint64` 值切片 (`weirdLimbs51` 和 `weirdLimbs52`)，用于生成边界情况或容易出错的 `Element` 值。这些值包括 0、1、接近 2 的幂等特殊数字，用于更全面的测试。

5. **`Element` 类型的生成器，用于 QuickCheck：**
   - `func (Element) Generate(rand *mathrand.Rand, size int) reflect.Value`
   - 功能：实现了 `quick.Generator` 接口，用于 `testing/quick` 包自动生成 `Element` 类型的测试数据。它会随机选择生成普通的随机元素或特殊的边界元素。

6. **检查有限域元素是否在界内：**
   - `func isInBounds(x *Element) bool`
   - 功能：检查一个 `Element` 的每个 64 位字是否都小于等于 52 位。这可能是在轻量规约（light reduction）后检查元素是否在一个预期的范围内。

7. **测试乘法对加法的分配律：**
   - `func TestMultiplyDistributesOverAdd(t *testing.T)`
   - 功能：使用 `testing/quick` 包测试有限域元素的乘法是否满足对加法的分配律：`(x + y) * z == x * z + y * z`。
   - **Go 代码示例：**
     ```go
     package main

     import (
         "fmt"
         "go/src/crypto/internal/fips140/edwards25519/field" // 假设你的项目结构
         "testing/quick"
     )

     func multiplyDistributesOverAddExample(x, y, z field.Element) bool {
         t1 := new(field.Element)
         t1.Add(&x, &y)
         t1.Multiply(t1, &z)

         t2 := new(field.Element)
         t3 := new(field.Element)
         t2.Multiply(&x, &z)
         t3.Multiply(&y, &z)
         t2.Add(t2, t3)

         return t1.Equal(t2) == 1
     }

     func main() {
         config := new(quick.Config)
         err := quick.Check(multiplyDistributesOverAddExample, config)
         if err != nil {
             fmt.Println("乘法对加法的分配律测试失败:", err)
         } else {
             fmt.Println("乘法对加法的分配律测试通过")
         }
     }
     ```
     **假设输入：** `x`, `y`, `z` 是由 `field.Element` 的 `Generate` 方法生成的随机 `Element` 值。
     **预期输出：** 如果乘法对加法的分配律成立，`t1.Equal(t2)` 应该返回 `1` (真)。

8. **测试 64 位整数的乘法：**
   - `func TestMul64to128(t *testing.T)`
   - 功能：测试一个用于执行 64 位整数乘法并返回 128 位结果的函数 `mul64` (代码中未显示，但被使用)。它测试了低位和高位的乘法结果，以及多次累加乘法的结果。

9. **测试字节数组和有限域元素之间的转换：**
   - `func TestSetBytesRoundTrip(t *testing.T)`
   - 功能：测试 `SetBytes` 和 `Bytes` 方法的正确性，确保将字节数组转换为 `Element` 再转换回字节数组时，结果一致。它也测试了从 `Element` 转换到字节数组再转换回 `Element` 的过程。
   - **Go 代码示例：**
     ```go
     package main

     import (
         "bytes"
         "fmt"
         "go/src/crypto/internal/fips140/edwards25519/field" // 假设你的项目结构
     )

     func main() {
         // 假设有一个 Element 实例
         fe := field.Element{1, 2, 3, 4, 5}
         fmt.Println("原始 Element:", fe)

         // 转换为字节数组
         b := fe.Bytes()
         fmt.Printf("转换为字节数组: %x\n", b)

         // 从字节数组恢复 Element
         fe2 := new(field.Element)
         fe2.SetBytes(b)
         fmt.Println("从字节数组恢复的 Element:", fe2)

         // 比较
         if fe.Equal(fe2) == 1 {
             fmt.Println("转换过程无损")
         } else {
             fmt.Println("转换过程有损失")
         }

         // 使用固定的字节数组进行测试
         var in [32]byte = [32]byte{0x01, 0x02, 0x03, /* ... 其他字节 ... */}
         fe3 := new(field.Element)
         fe3.SetBytes(in[:])
         b3 := fe3.Bytes()
         if bytes.Equal(in[:], b3) {
             fmt.Println("固定字节数组转换测试通过")
         } else {
             fmt.Println("固定字节数组转换测试失败")
         }
     }
     ```
     **假设输入：** `fe` 是一个 `Element` 实例，或者 `in` 是一个 32 字节的数组。
     **预期输出：** 如果转换无误，原始 `Element` 和恢复后的 `Element` 应该相等，原始字节数组和从恢复后的 `Element` 转换来的字节数组也应该相等。

10. **测试字节数组与 `big.Int` 的等价性：**
    - `func TestBytesBigEquivalence(t *testing.T)`
    - 功能：测试 `Element` 的字节数组表示与 `math/big.Int` 的表示是否一致。它将字节数组转换为 `Element`，再转换为 `big.Int`，反之亦然，并进行比较。
    - **代码推理示例：**
      - 假设输入一个 32 字节的数组 `in`，例如 `[32]byte{0x01, 0x02, ..., 0x20}`。
      - `fe.SetBytes(in[:])` 将字节数组转换为 `Element`。
      - `in[len(in)-1] &= (1 << 7) - 1` 屏蔽了最高位，这表明 `SetBytes` 方法可能忽略了最高位。
      - `b := new(big.Int).SetBytes(swapEndianness(in[:]))` 将字节数组（可能需要反转字节序）转换为 `big.Int`。`swapEndianness` 函数很可能用于处理大端和小端之间的差异。
      - `fe1.fromBig(b)` 将 `big.Int` 转换回 `Element`。
      - 测试 `fe != fe1` 检查两个 `Element` 表示是否相同。
      - `buf := make([]byte, 32)` 创建一个 32 字节的缓冲区。
      - `buf = swapEndianness(fe1.toBig().FillBytes(buf))` 将 `fe1` 转换为 `big.Int`，再填充到字节缓冲区，并可能需要反转字节序。
      - 最后，比较 `fe.Bytes()` 和 `buf`，确保字节表示也一致。

11. **从 `big.Int` 和十进制字符串设置 `Element`：**
    - `func (v *Element) fromBig(n *big.Int) *Element`
    - `func (v *Element) fromDecimal(s string) *Element`
    - `func (v *Element) toBig() *big.Int`
    - 功能：提供了 `Element` 和 `math/big.Int` 之间的转换方法，以及从十进制字符串创建 `Element` 的方法。

12. **测试十进制常量：**
    - `func TestDecimalConstants(t *testing.T)`
    - 功能：测试代码中定义的十进制字符串常量（如 `sqrtM1String`）是否与通过 `fromDecimal` 方法创建的 `Element` 值一致。

13. **测试 `SetBytes` 的边界情况：**
    - `func TestSetBytesRoundTripEdgeCases(t *testing.T)`
    - 功能：尽管代码中此函数为空，但其目的是测试 `SetBytes` 方法处理边界情况（如接近 0、接近模数等）时的行为。

14. **测试 `Multiply` 和 `Square` 的一致性：**
    - `func TestConsistency(t *testing.T)`
    - 功能：测试 `Multiply(x, x)` 和 `Square(x)` 是否产生相同的结果，验证乘法和平方运算的一致性。

15. **测试 `Equal` 方法：**
    - `func TestEqual(t *testing.T)`
    - 功能：测试 `Element` 的 `Equal` 方法是否能正确判断两个元素是否相等。

16. **测试求逆运算：**
    - `func TestInvert(t *testing.T)`
    - 功能：测试 `Invert` 方法的正确性，包括验证逆元的性质（`x * x.Invert(x) == 1`）以及处理零元素的情况。

17. **测试条件选择和交换：**
    - `func TestSelectSwap(t *testing.T)`
    - 功能：测试 `Select` 方法（根据条件选择两个元素之一）和 `Swap` 方法（根据条件交换两个元素）的正确性。

18. **测试与 32 位整数的乘法：**
    - `func TestMult32(t *testing.T)`
    - 功能：测试 `Mult32` 方法（将 `Element` 乘以一个 32 位整数）是否等价于将 `Element` 乘以由该整数构造的另一个 `Element`。

19. **测试平方根比率运算：**
    - `func TestSqrtRatio(t *testing.T)`
    - 功能：测试 `SqrtRatio` 方法，该方法计算 `u/v` 的平方根（如果存在）。它使用了一些来自参考文档的测试用例。

20. **测试进位传播：**
    - `func TestCarryPropagate(t *testing.T)`
    - 功能：比较汇编优化版本 (`carryPropagate`) 和通用版本 (`carryPropagateGeneric`) 的进位传播逻辑是否一致。

21. **测试有限域元素的平方运算：**
    - `func TestFeSquare(t *testing.T)`
    - 功能：比较汇编优化版本 (`feSquare`) 和通用版本 (`feSquareGeneric`) 的平方运算结果是否一致。

22. **测试有限域元素的乘法运算：**
    - `func TestFeMul(t *testing.T)`
    - 功能：比较汇编优化版本 (`feMul`) 和通用版本 (`feMulGeneric`) 的乘法运算结果是否一致。

23. **解码十六进制字符串：**
    - `func decodeHex(s string) []byte`
    - 功能：一个辅助函数，用于将十六进制字符串解码为字节数组，方便测试用例的编写。

**涉及的 Go 语言功能实现：**

这段代码主要测试了以下 Go 语言功能的实现：

* **自定义数据类型 (`Element`) 及其方法：**  定义了表示有限域元素的结构体，并为其实现了各种算术运算和转换方法。
* **单元测试 (`testing` 包)：** 使用 `testing` 包编写单元测试，验证代码的正确性。
* **属性测试 (`testing/quick` 包)：** 使用 `testing/quick` 包进行属性测试，通过生成大量随机输入来验证代码是否满足某些性质（例如，乘法对加法的分配律）。
* **基准测试（虽然代码中未直接包含，但通常与单元测试放在一起）：**  虽然此代码段未显示，但通常会包含基准测试来衡量性能。
* **与 `math/big` 包的交互：** 使用 `math/big` 包处理大整数，方便进行一些复杂的转换和比较。
* **字节数组操作 (`bytes` 包)：**  进行字节数组和自定义类型之间的转换。
* **随机数生成 (`crypto/rand` 和 `math/rand` 包)：**  生成随机的测试数据。
* **位运算 (`math/bits` 包)：**  进行位级别的操作，例如检查位长度。
* **命令行参数处理 (`testing` 包的 `-short` 标志)：**  根据命令行参数调整测试行为。
* **反射 (`reflect` 包)：** 用于 `testing/quick` 包生成自定义类型的测试数据。

**命令行参数的具体处理：**

* **`-short` 标志：**  `quickCheckConfig` 函数检查是否设置了 `-short` 命令行标志。
    - 如果运行 `go test` 或 `go test -short`，`testing.Short()` 将返回 `true`，`quickCheckConfig` 将返回一个默认配置的 `quick.Config`。这意味着测试会运行较少的用例，速度更快，适用于快速检查。
    - 如果运行 `go test` 而不带 `-short` 标志，`testing.Short()` 将返回 `false`，`quickCheckConfig` 会将 `MaxCountScale` 设置为一个更大的值 (`slowScale`)，从而让 `testing/quick` 运行更多的测试用例，进行更 thorough 的测试。

**使用者易犯错的点：**

1. **误解 `SetBytes` 方法的行为：**  `TestBytesBigEquivalence` 中 `in[len(in)-1] &= (1 << 7) - 1` 表明 `SetBytes` 可能会忽略输入字节数组的最高位。使用者可能会认为 `SetBytes` 会完全按照输入的 32 个字节来设置 `Element`，但实际上可能存在这种细微的差异。
   - **举例：** 如果使用者有一个 32 字节的数组，其最后一个字节的最高位被设置了，他们期望通过 `SetBytes` 创建的 `Element` 能反映这个最高位。但实际上，根据这段测试代码，这个最高位会被忽略。

2. **假设 `Element` 的字节表示是直接的大端或小端：** `TestBytesBigEquivalence` 中使用了 `swapEndianness` 函数，说明 `Element` 的内部表示和外部字节表示可能需要进行字节序的转换。使用者可能会错误地假设字节数组的顺序与 `Element` 内部的字顺序一致，而忽略了字节序的问题。

总而言之，这段代码是 `edwards25519` 椭圆曲线有限域运算的重要测试部分，它使用了多种 Go 语言的测试工具和技术，确保了有限域运算的正确性和健壮性，并特别关注了 FIPS 140 标准的要求。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/edwards25519/field/fe_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package field

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"math/bits"
	mathrand "math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

func (v Element) String() string {
	return hex.EncodeToString(v.Bytes())
}

// quickCheckConfig returns a quick.Config that scales the max count by the
// given factor if the -short flag is not set.
func quickCheckConfig(slowScale int) *quick.Config {
	cfg := new(quick.Config)
	if !testing.Short() {
		cfg.MaxCountScale = float64(slowScale)
	}
	return cfg
}

func generateFieldElement(rand *mathrand.Rand) Element {
	const maskLow52Bits = (1 << 52) - 1
	return Element{
		rand.Uint64() & maskLow52Bits,
		rand.Uint64() & maskLow52Bits,
		rand.Uint64() & maskLow52Bits,
		rand.Uint64() & maskLow52Bits,
		rand.Uint64() & maskLow52Bits,
	}
}

// weirdLimbs can be combined to generate a range of edge-case field elements.
// 0 and -1 are intentionally more weighted, as they combine well.
var (
	weirdLimbs51 = []uint64{
		0, 0, 0, 0,
		1,
		19 - 1,
		19,
		0x2aaaaaaaaaaaa,
		0x5555555555555,
		(1 << 51) - 20,
		(1 << 51) - 19,
		(1 << 51) - 1, (1 << 51) - 1,
		(1 << 51) - 1, (1 << 51) - 1,
	}
	weirdLimbs52 = []uint64{
		0, 0, 0, 0, 0, 0,
		1,
		19 - 1,
		19,
		0x2aaaaaaaaaaaa,
		0x5555555555555,
		(1 << 51) - 20,
		(1 << 51) - 19,
		(1 << 51) - 1, (1 << 51) - 1,
		(1 << 51) - 1, (1 << 51) - 1,
		(1 << 51) - 1, (1 << 51) - 1,
		1 << 51,
		(1 << 51) + 1,
		(1 << 52) - 19,
		(1 << 52) - 1,
	}
)

func generateWeirdFieldElement(rand *mathrand.Rand) Element {
	return Element{
		weirdLimbs52[rand.Intn(len(weirdLimbs52))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
	}
}

func (Element) Generate(rand *mathrand.Rand, size int) reflect.Value {
	if rand.Intn(2) == 0 {
		return reflect.ValueOf(generateWeirdFieldElement(rand))
	}
	return reflect.ValueOf(generateFieldElement(rand))
}

// isInBounds returns whether the element is within the expected bit size bounds
// after a light reduction.
func isInBounds(x *Element) bool {
	return bits.Len64(x.l0) <= 52 &&
		bits.Len64(x.l1) <= 52 &&
		bits.Len64(x.l2) <= 52 &&
		bits.Len64(x.l3) <= 52 &&
		bits.Len64(x.l4) <= 52
}

func TestMultiplyDistributesOverAdd(t *testing.T) {
	multiplyDistributesOverAdd := func(x, y, z Element) bool {
		// Compute t1 = (x+y)*z
		t1 := new(Element)
		t1.Add(&x, &y)
		t1.Multiply(t1, &z)

		// Compute t2 = x*z + y*z
		t2 := new(Element)
		t3 := new(Element)
		t2.Multiply(&x, &z)
		t3.Multiply(&y, &z)
		t2.Add(t2, t3)

		return t1.Equal(t2) == 1 && isInBounds(t1) && isInBounds(t2)
	}

	if err := quick.Check(multiplyDistributesOverAdd, quickCheckConfig(1024)); err != nil {
		t.Error(err)
	}
}

func TestMul64to128(t *testing.T) {
	a := uint64(5)
	b := uint64(5)
	r := mul64(a, b)
	if r.lo != 0x19 || r.hi != 0 {
		t.Errorf("lo-range wide mult failed, got %d + %d*(2**64)", r.lo, r.hi)
	}

	a = uint64(18014398509481983) // 2^54 - 1
	b = uint64(18014398509481983) // 2^54 - 1
	r = mul64(a, b)
	if r.lo != 0xff80000000000001 || r.hi != 0xfffffffffff {
		t.Errorf("hi-range wide mult failed, got %d + %d*(2**64)", r.lo, r.hi)
	}

	a = uint64(1125899906842661)
	b = uint64(2097155)
	r = mul64(a, b)
	r = addMul64(r, a, b)
	r = addMul64(r, a, b)
	r = addMul64(r, a, b)
	r = addMul64(r, a, b)
	if r.lo != 16888498990613035 || r.hi != 640 {
		t.Errorf("wrong answer: %d + %d*(2**64)", r.lo, r.hi)
	}
}

func TestSetBytesRoundTrip(t *testing.T) {
	f1 := func(in [32]byte, fe Element) bool {
		fe.SetBytes(in[:])

		// Mask the most significant bit as it's ignored by SetBytes. (Now
		// instead of earlier so we check the masking in SetBytes is working.)
		in[len(in)-1] &= (1 << 7) - 1

		return bytes.Equal(in[:], fe.Bytes()) && isInBounds(&fe)
	}
	if err := quick.Check(f1, nil); err != nil {
		t.Errorf("failed bytes->FE->bytes round-trip: %v", err)
	}

	f2 := func(fe, r Element) bool {
		r.SetBytes(fe.Bytes())

		// Intentionally not using Equal not to go through Bytes again.
		// Calling reduce because both Generate and SetBytes can produce
		// non-canonical representations.
		fe.reduce()
		r.reduce()
		return fe == r
	}
	if err := quick.Check(f2, nil); err != nil {
		t.Errorf("failed FE->bytes->FE round-trip: %v", err)
	}

	// Check some fixed vectors from dalek
	type feRTTest struct {
		fe Element
		b  []byte
	}
	var tests = []feRTTest{
		{
			fe: Element{358744748052810, 1691584618240980, 977650209285361, 1429865912637724, 560044844278676},
			b:  []byte{74, 209, 69, 197, 70, 70, 161, 222, 56, 226, 229, 19, 112, 60, 25, 92, 187, 74, 222, 56, 50, 153, 51, 233, 40, 74, 57, 6, 160, 185, 213, 31},
		},
		{
			fe: Element{84926274344903, 473620666599931, 365590438845504, 1028470286882429, 2146499180330972},
			b:  []byte{199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122},
		},
	}

	for _, tt := range tests {
		b := tt.fe.Bytes()
		fe, _ := new(Element).SetBytes(tt.b)
		if !bytes.Equal(b, tt.b) || fe.Equal(&tt.fe) != 1 {
			t.Errorf("Failed fixed roundtrip: %v", tt)
		}
	}
}

func swapEndianness(buf []byte) []byte {
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-i-1] = buf[len(buf)-i-1], buf[i]
	}
	return buf
}

func TestBytesBigEquivalence(t *testing.T) {
	f1 := func(in [32]byte, fe, fe1 Element) bool {
		fe.SetBytes(in[:])

		in[len(in)-1] &= (1 << 7) - 1 // mask the most significant bit
		b := new(big.Int).SetBytes(swapEndianness(in[:]))
		fe1.fromBig(b)

		if fe != fe1 {
			return false
		}

		buf := make([]byte, 32)
		buf = swapEndianness(fe1.toBig().FillBytes(buf))

		return bytes.Equal(fe.Bytes(), buf) && isInBounds(&fe) && isInBounds(&fe1)
	}
	if err := quick.Check(f1, nil); err != nil {
		t.Error(err)
	}
}

// fromBig sets v = n, and returns v. The bit length of n must not exceed 256.
func (v *Element) fromBig(n *big.Int) *Element {
	if n.BitLen() > 32*8 {
		panic("edwards25519: invalid field element input size")
	}

	buf := make([]byte, 0, 32)
	for _, word := range n.Bits() {
		for i := 0; i < bits.UintSize; i += 8 {
			if len(buf) >= cap(buf) {
				break
			}
			buf = append(buf, byte(word))
			word >>= 8
		}
	}

	v.SetBytes(buf[:32])
	return v
}

func (v *Element) fromDecimal(s string) *Element {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("not a valid decimal: " + s)
	}
	return v.fromBig(n)
}

// toBig returns v as a big.Int.
func (v *Element) toBig() *big.Int {
	buf := v.Bytes()

	words := make([]big.Word, 32*8/bits.UintSize)
	for n := range words {
		for i := 0; i < bits.UintSize; i += 8 {
			if len(buf) == 0 {
				break
			}
			words[n] |= big.Word(buf[0]) << big.Word(i)
			buf = buf[1:]
		}
	}

	return new(big.Int).SetBits(words)
}

func TestDecimalConstants(t *testing.T) {
	sqrtM1String := "19681161376707505956807079304988542015446066515923890162744021073123829784752"
	if exp := new(Element).fromDecimal(sqrtM1String); sqrtM1.Equal(exp) != 1 {
		t.Errorf("sqrtM1 is %v, expected %v", sqrtM1, exp)
	}
	// d is in the parent package, and we don't want to expose d or fromDecimal.
	// dString := "37095705934669439343138083508754565189542113879843219016388785533085940283555"
	// if exp := new(Element).fromDecimal(dString); d.Equal(exp) != 1 {
	// 	t.Errorf("d is %v, expected %v", d, exp)
	// }
}

func TestSetBytesRoundTripEdgeCases(t *testing.T) {
	// TODO: values close to 0, close to 2^255-19, between 2^255-19 and 2^255-1,
	// and between 2^255 and 2^256-1. Test both the documented SetBytes
	// behavior, and that Bytes reduces them.
}

// Tests self-consistency between Multiply and Square.
func TestConsistency(t *testing.T) {
	var x Element
	var x2, x2sq Element

	x = Element{1, 1, 1, 1, 1}
	x2.Multiply(&x, &x)
	x2sq.Square(&x)

	if x2 != x2sq {
		t.Fatalf("all ones failed\nmul: %x\nsqr: %x\n", x2, x2sq)
	}

	var bytes [32]byte

	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		t.Fatal(err)
	}
	x.SetBytes(bytes[:])

	x2.Multiply(&x, &x)
	x2sq.Square(&x)

	if x2 != x2sq {
		t.Fatalf("all ones failed\nmul: %x\nsqr: %x\n", x2, x2sq)
	}
}

func TestEqual(t *testing.T) {
	x := Element{1, 1, 1, 1, 1}
	y := Element{5, 4, 3, 2, 1}

	eq := x.Equal(&x)
	if eq != 1 {
		t.Errorf("wrong about equality")
	}

	eq = x.Equal(&y)
	if eq != 0 {
		t.Errorf("wrong about inequality")
	}
}

func TestInvert(t *testing.T) {
	x := Element{1, 1, 1, 1, 1}
	one := Element{1, 0, 0, 0, 0}
	var xinv, r Element

	xinv.Invert(&x)
	r.Multiply(&x, &xinv)
	r.reduce()

	if one != r {
		t.Errorf("inversion identity failed, got: %x", r)
	}

	var bytes [32]byte

	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		t.Fatal(err)
	}
	x.SetBytes(bytes[:])

	xinv.Invert(&x)
	r.Multiply(&x, &xinv)
	r.reduce()

	if one != r {
		t.Errorf("random inversion identity failed, got: %x for field element %x", r, x)
	}

	zero := Element{}
	x.Set(&zero)
	if xx := xinv.Invert(&x); xx != &xinv {
		t.Errorf("inverting zero did not return the receiver")
	} else if xinv.Equal(&zero) != 1 {
		t.Errorf("inverting zero did not return zero")
	}
}

func TestSelectSwap(t *testing.T) {
	a := Element{358744748052810, 1691584618240980, 977650209285361, 1429865912637724, 560044844278676}
	b := Element{84926274344903, 473620666599931, 365590438845504, 1028470286882429, 2146499180330972}

	var c, d Element

	c.Select(&a, &b, 1)
	d.Select(&a, &b, 0)

	if c.Equal(&a) != 1 || d.Equal(&b) != 1 {
		t.Errorf("Select failed")
	}

	c.Swap(&d, 0)

	if c.Equal(&a) != 1 || d.Equal(&b) != 1 {
		t.Errorf("Swap failed")
	}

	c.Swap(&d, 1)

	if c.Equal(&b) != 1 || d.Equal(&a) != 1 {
		t.Errorf("Swap failed")
	}
}

func TestMult32(t *testing.T) {
	mult32EquivalentToMul := func(x Element, y uint32) bool {
		t1 := new(Element)
		for i := 0; i < 100; i++ {
			t1.Mult32(&x, y)
		}

		ty := new(Element)
		ty.l0 = uint64(y)

		t2 := new(Element)
		for i := 0; i < 100; i++ {
			t2.Multiply(&x, ty)
		}

		return t1.Equal(t2) == 1 && isInBounds(t1) && isInBounds(t2)
	}

	if err := quick.Check(mult32EquivalentToMul, quickCheckConfig(1024)); err != nil {
		t.Error(err)
	}
}

func TestSqrtRatio(t *testing.T) {
	// From draft-irtf-cfrg-ristretto255-decaf448-00, Appendix A.4.
	type test struct {
		u, v      []byte
		wasSquare int
		r         []byte
	}
	var tests = []test{
		// If u is 0, the function is defined to return (0, TRUE), even if v
		// is zero. Note that where used in this package, the denominator v
		// is never zero.
		{
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			1, decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
		},
		// 0/1 == 0²
		{
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("0100000000000000000000000000000000000000000000000000000000000000"),
			1, decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
		},
		// If u is non-zero and v is zero, defined to return (0, FALSE).
		{
			decodeHex("0100000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			0, decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
		},
		// 2/1 is not square in this field.
		{
			decodeHex("0200000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("0100000000000000000000000000000000000000000000000000000000000000"),
			0, decodeHex("3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54"),
		},
		// 4/1 == 2²
		{
			decodeHex("0400000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("0100000000000000000000000000000000000000000000000000000000000000"),
			1, decodeHex("0200000000000000000000000000000000000000000000000000000000000000"),
		},
		// 1/4 == (2⁻¹)² == (2^(p-2))² per Euler's theorem
		{
			decodeHex("0100000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("0400000000000000000000000000000000000000000000000000000000000000"),
			1, decodeHex("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"),
		},
	}

	for i, tt := range tests {
		u, _ := new(Element).SetBytes(tt.u)
		v, _ := new(Element).SetBytes(tt.v)
		want, _ := new(Element).SetBytes(tt.r)
		got, wasSquare := new(Element).SqrtRatio(u, v)
		if got.Equal(want) == 0 || wasSquare != tt.wasSquare {
			t.Errorf("%d: got (%v, %v), want (%v, %v)", i, got, wasSquare, want, tt.wasSquare)
		}
	}
}

func TestCarryPropagate(t *testing.T) {
	asmLikeGeneric := func(a [5]uint64) bool {
		t1 := &Element{a[0], a[1], a[2], a[3], a[4]}
		t2 := &Element{a[0], a[1], a[2], a[3], a[4]}

		t1.carryPropagate()
		t2.carryPropagateGeneric()

		if *t1 != *t2 {
			t.Logf("got: %#v,\nexpected: %#v", t1, t2)
		}

		return *t1 == *t2 && isInBounds(t2)
	}

	if err := quick.Check(asmLikeGeneric, quickCheckConfig(1024)); err != nil {
		t.Error(err)
	}

	if !asmLikeGeneric([5]uint64{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}) {
		t.Errorf("failed for {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}")
	}
}

func TestFeSquare(t *testing.T) {
	asmLikeGeneric := func(a Element) bool {
		t1 := a
		t2 := a

		feSquareGeneric(&t1, &t1)
		feSquare(&t2, &t2)

		if t1 != t2 {
			t.Logf("got: %#v,\nexpected: %#v", t1, t2)
		}

		return t1 == t2 && isInBounds(&t2)
	}

	if err := quick.Check(asmLikeGeneric, quickCheckConfig(1024)); err != nil {
		t.Error(err)
	}
}

func TestFeMul(t *testing.T) {
	asmLikeGeneric := func(a, b Element) bool {
		a1 := a
		a2 := a
		b1 := b
		b2 := b

		feMulGeneric(&a1, &a1, &b1)
		feMul(&a2, &a2, &b2)

		if a1 != a2 || b1 != b2 {
			t.Logf("got: %#v,\nexpected: %#v", a1, a2)
			t.Logf("got: %#v,\nexpected: %#v", b1, b2)
		}

		return a1 == a2 && isInBounds(&a2) &&
			b1 == b2 && isInBounds(&b2)
	}

	if err := quick.Check(asmLikeGeneric, quickCheckConfig(1024)); err != nil {
		t.Error(err)
	}
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
```