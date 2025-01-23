Response:
这个Go语言文件的目的是测试 `crypto/internal/fips140/bigmod` 包中的 `Nat` 类型的功能。`Nat` 类型很可能用于表示任意精度的自然数，并提供了模运算等功能，这在密码学中很常见。

我将按照以下步骤进行思考和组织答案：

1. **理解文件结构和导入:**  首先浏览导入的包，了解测试所依赖的工具和类型，如 `testing`，`quick`， `big` 等。
2. **识别核心被测类型 `Nat`:**  注意到文件中大量使用了 `Nat` 类型，以及相关的 `Modulus` 类型，推断这是核心被测对象。
3. **分析辅助函数:**  关注 `setBig`, `asBig`, `String`, `Generate`, `natBytes`, `natFromBytes`, `modulusFromBytes`, `maxModulus` 等辅助函数，理解它们在测试中的作用，例如类型转换、随机数生成等。
4. **分类测试函数:** 将测试函数按照功能进行分类，例如模加法、模减法、模乘法、模指数运算、Montgomery表示、位运算、字节转换等。
5. **分析每个测试函数:**  仔细阅读每个 `Test...` 函数的逻辑，理解它们要测试的具体功能和边界条件。例如 `TestModAddCommutative` 测试模加法的交换律， `TestMontgomeryRoundtrip` 测试 Montgomery 表示的转换和逆转换。
6. **推理 `Nat` 和 `Modulus` 的作用:**  根据测试用例和函数名，推断 `Nat` 类型可能用于表示大整数，`Modulus` 类型用于表示模数，并且 `Nat` 提供了模运算的相关方法。
7. **构建代码示例:**  选择几个典型的测试用例，将其转化为更通俗易懂的 Go 代码示例，并提供假设的输入和输出。
8. **分析易错点:**  关注 `TestSetBytes` 和 `TestModulusAndNatSizes` 等测试，尝试找出使用 `Nat` 和 `Modulus` 时可能出现的错误。
9. **总结功能:** 总结 `nat_test.go` 文件的主要功能。

**详细思考过程:**

* **导入:** `bufio`, `bytes`, `cryptorand`, `encoding/hex`, `fmt`, `math/big`, `math/bits`, `math/rand`, `os`, `reflect`, `slices`, `strings`, `testing`, `testing/quick` 这些导入揭示了这个文件用于测试，涉及到随机数生成、大数运算、字节处理、字符串操作等。
* **`Nat` 结构体和辅助方法:** `setBig` 从 `big.Int` 设置 `Nat`， `asBig` 反之， `String` 用于打印 `Nat` 的调试信息， `Generate` 用于生成随机的 `Nat` 值，这些都是测试的基础设施。
* **模运算测试:** `TestModAddCommutative`, `TestModSubThenAddIdentity`, `TestModSub`, `TestModAdd`, `TestMod` 明确表明了对模加法和模减法的测试。 `quick.Check` 的使用暗示了使用 property-based testing 来验证这些运算的性质。
* **Montgomery 表示:** `TestMontgomeryRoundtrip` 专门测试了 Montgomery 表示的转换，这是一种用于加速模乘运算的技术。
* **位运算:** `TestShiftIn`, `TestTrailingZeroBits`, `TestRightShift` 关注了 `Nat` 的位操作功能。
* **字节转换:** `TestSetBytes`, `TestModulusAndNatSizes` 测试了 `Nat` 对象和字节数组之间的转换，以及可能出现的边界情况，例如前导零的处理。
* **模指数运算:** `TestExp`, `TestExpShort` 测试了模指数运算的不同实现。
* **模逆运算:** `TestInverse` 使用外部测试数据验证了模逆运算的正确性。
* **性能测试:** `Benchmark...` 系列函数用于衡量各种操作的性能。
* **错误处理:** `TestNewModulus` 专门测试了创建 `Modulus` 对象时的错误处理。

**易错点推断:** `TestModulusAndNatSizes` 提到了“leading zeroes are stripped”，暗示了 `Modulus` 和 `Nat` 在处理字节数组时可能存在差异，这可能是用户容易犯错的地方。 `TestSetBytes` 中大量的测试用例也暗示了从字节数组创建 `Nat` 对象时需要注意模数的限制。

通过以上分析，最终形成了对 `nat_test.go` 文件功能的总结和代码示例。
这个Go语言文件 `nat_test.go` 是 `crypto/internal/fips140/bigmod` 包的一部分，专门用于测试该包中 `Nat` 类型的功能。`Nat` 类型很可能用于表示任意精度的自然数，并提供了模运算等功能，这在密码学中是常见的需求。

以下是该文件的主要功能：

1. **`Nat` 类型的基本操作测试:**
   - **赋值和转换:** 测试 `Nat` 类型与 `big.Int` 之间的相互转换 (`setBig`, `asBig`)。
   - **字符串表示:** 测试 `Nat` 类型的字符串输出格式 (`String`)。
   - **随机数生成:** 使用 `testing/quick` 框架生成随机的 `Nat` 值进行测试 (`Generate`)。
   - **判等:** 测试 `Nat` 类型的判等操作 (`Equal`)。

2. **模运算测试:**
   - **模加法:** 测试模加法的交换律 (`TestModAddCommutative`) 和加法逆运算 (`TestModSubThenAddIdentity`, `TestModAdd`)。
   - **模减法:** 测试模减法 (`TestModSub`)。
   - **模乘法:** 测试模乘法 (`TestMul`, `TestMulReductions`)，包括 Montgomery 乘法的回环测试 (`TestMontgomeryRoundtrip`)。
   - **模指数运算:** 测试模指数运算 (`TestExp`, `TestExpShort`)。
   - **模运算通用测试:** 测试一般的模运算 (`TestMod`)。

3. **位运算测试:**
   - **左移位:** (`TestShiftIn`)
   - **尾部零比特计数:** (`TestTrailingZeroBits`)
   - **右移位:** (`TestRightShift`)

4. **字节数组与 `Nat` 类型的转换测试:**
   - **从字节数组创建 `Nat`:** (`TestSetBytes`)，重点测试了在给定模数的情况下，从字节数组创建 `Nat` 对象的正确性，包括边界情况和错误处理（例如，字节数组表示的数值大于等于模数）。
   - **`Nat` 转换为字节数组:** (`natBytes`)

5. **`Modulus` 类型相关测试:**
   - **`NewModulus` 函数测试:** (`TestNewModulus`)，测试了创建 `Modulus` 对象时的错误条件，例如模数小于等于1。
   - **模数大小与 `Nat` 大小的关系测试:** (`TestModulusAndNatSizes`)，测试了在模数和 `Nat` 对象大小不一致时的处理情况。

6. **辅助测试函数:**
   - `natBytes`: 将 `Nat` 对象转换为字节数组。
   - `natFromBytes`: 从字节数组创建 `Nat` 对象。
   - `modulusFromBytes`: 从字节数组创建 `Modulus` 对象。
   - `maxModulus`: 创建一个指定 limb 数的最大模数。

7. **性能测试:**
   - 提供了一系列 benchmark 函数 (`BenchmarkModAdd`, `BenchmarkModSub`, `BenchmarkMontgomeryRepr`, `BenchmarkMontgomeryMul`, `BenchmarkModMul`, `BenchmarkExpBig`, `BenchmarkExp`) 用于评估不同操作的性能。

8. **其他功能测试:**
   - **`Is` 系列函数测试:** (`TestIs`)，测试了判断 `Nat` 对象是否为零、一、负一（相对于模数）以及奇数的功能。
   - **`InverseVarTime` 函数测试:** (`TestInverse`)，测试了计算模逆的功能，并使用了外部测试数据。
   - **`Expand` 函数测试:** (`TestExpand`)，测试了扩展 `Nat` 对象内部表示的能力。
   - **`AddMulVVWSized` 函数测试:** (`TestAddMulVVWSized`)，测试了特定大小的优化的加法乘法函数。

**它可以推理出是什么go语言功能的实现：**

根据测试内容，可以推断 `crypto/internal/fips140/bigmod` 包实现了**任意精度整数的模运算功能**。 `Nat` 类型很可能代表一个大整数，而 `Modulus` 类型代表模数。该包提供了高效的模加、模减、模乘、模指数以及模逆等运算，这通常用于密码学算法中，例如 RSA 加密、椭圆曲线密码学等。

**Go 代码举例说明：**

假设我们要测试模加法：

```go
package bigmod_test

import (
	"crypto/internal/fips140/bigmod"
	"fmt"
	"testing"
)

func TestExampleModAdd(t *testing.T) {
	// 假设的模数
	modulusBytes := []byte{13}
	m, err := bigmod.NewModulus(modulusBytes)
	if err != nil {
		t.Fatal(err)
	}

	// 假设的两个 Nat 对象
	aBytes := []byte{6}
	a, err := bigmod.NewNat().SetBytes(aBytes, m)
	if err != nil {
		t.Fatal(err)
	}

	bBytes := []byte{7}
	b, err := bigmod.NewNat().SetBytes(bBytes, m)
	if err != nil {
		t.Fatal(err)
	}

	// 执行模加法
	sum := bigmod.NewNat()
	sum.Add(a, m) // 先将 a 设置到 sum
	sum.Add(b, m) // 然后加上 b

	// 期望的结果 (6 + 7) mod 13 = 0
	expectedBytes := []byte{0}
	expected, err := bigmod.NewNat().SetBytes(expectedBytes, m)
	if err != nil {
		t.Fatal(err)
	}

	// 验证结果
	if sum.Equal(expected) != 1 {
		t.Errorf("模加法结果错误: got %v, want %v", sum, expected)
	} else {
		fmt.Println("模加法测试通过") // 假设的输出
	}
}

// 假设的输入和输出：
// 输入： a = 6, b = 7, modulus = 13
// 输出： 模加法测试通过 (如果测试成功)
```

**涉及命令行参数的具体处理：**

这个测试文件本身不直接处理命令行参数。Go 的 `testing` 包通过 `go test` 命令来运行测试。你可以使用 `go test` 的各种标志来控制测试的执行，例如：

- `-v`:  显示所有测试的详细输出。
- `-run <regexp>`:  只运行匹配正则表达式的测试函数。
- `-bench <regexp>`: 只运行匹配正则表达式的 benchmark 函数。
- `-count n`: 运行每个测试 `n` 次。
- `-cpuprofile <file>`: 将 CPU profile 写入文件。
- `-memprofile <file>`: 将内存 profile 写入文件。

例如，要只运行 `TestModAddCommutative` 这个测试，可以使用命令：

```bash
go test -v -run TestModAddCommutative
```

要运行所有的 benchmark，可以使用命令：

```bash
go test -bench=.
```

**使用者易犯错的点：**

1. **模数的设置错误:**  `Nat` 类型的很多操作都需要提供一个 `Modulus` 对象。如果 `Modulus` 对象设置不正确（例如，模数小于等于 1），会导致错误或 panic。 `TestNewModulus` 就是测试这种情况。

   ```go
   // 错误示例：模数小于等于 1
   modulusBytes := []byte{0}
   m, err := bigmod.NewModulus(modulusBytes)
   if err != nil {
       fmt.Println("创建模数失败:", err) // 正确处理应该检查错误
   }
   ```

2. **字节数组到 `Nat` 的转换时，数值大于等于模数:** 当使用 `SetBytes` 将字节数组转换为 `Nat` 对象时，如果字节数组表示的数值大于或等于给定的模数，`SetBytes` 方法可能会返回错误，或者行为未定义。 `TestSetBytes` 中有很多测试用例覆盖了这种情况。

   ```go
   // 错误示例：尝试设置一个大于模数的值
   modulusBytes := []byte{0xff} // 模数 255
   m, err := bigmod.NewModulus(modulusBytes)
   if err != nil {
       // ...
   }
   valueBytes := []byte{0xff, 0x01} // 值 256
   n, err := bigmod.NewNat().SetBytes(valueBytes, m)
   if err != nil {
       fmt.Println("设置 Nat 失败:", err) // 需要处理此错误
   }
   ```

3. **`Nat` 对象的生命周期和复用:**  `Nat` 对象是可变的，在进行模运算时会修改自身的值。如果需要在多次运算中使用同一个原始值，需要进行拷贝。

   ```go
   // 可能的错误：未拷贝 Nat 对象导致意外修改
   modulusBytes := []byte{10}
   m, _ := bigmod.NewModulus(modulusBytes)
   aBytes := []byte{3}
   a, _ := bigmod.NewNat().SetBytes(aBytes, m)

   b := bigmod.NewNat().Set(a) // 正确：拷贝 a 的值

   a.Add(a, m) // 修改了 a

   // 此时 b 的值仍然是 3，而 a 的值是 6 (3+3 mod 10)
   fmt.Println(b)
   ```

总而言之，`nat_test.go` 提供了一个全面的测试套件，用于验证 `crypto/internal/fips140/bigmod` 包中 `Nat` 类型的各种功能和边界条件，确保其在密码学应用中的正确性和可靠性。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/bigmod/nat_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bigmod

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/bits"
	"math/rand"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/quick"
)

// setBig assigns x = n, optionally resizing n to the appropriate size.
//
// The announced length of x is set based on the actual bit size of the input,
// ignoring leading zeroes.
func (x *Nat) setBig(n *big.Int) *Nat {
	limbs := n.Bits()
	x.reset(len(limbs))
	for i := range limbs {
		x.limbs[i] = uint(limbs[i])
	}
	return x
}

func (n *Nat) asBig() *big.Int {
	bits := make([]big.Word, len(n.limbs))
	for i := range n.limbs {
		bits[i] = big.Word(n.limbs[i])
	}
	return new(big.Int).SetBits(bits)
}

func (n *Nat) String() string {
	var limbs []string
	for i := range n.limbs {
		limbs = append(limbs, fmt.Sprintf("%016X", n.limbs[len(n.limbs)-1-i]))
	}
	return "{" + strings.Join(limbs, " ") + "}"
}

// Generate generates an even nat. It's used by testing/quick to produce random
// *nat values for quick.Check invocations.
func (*Nat) Generate(r *rand.Rand, size int) reflect.Value {
	limbs := make([]uint, size)
	for i := 0; i < size; i++ {
		limbs[i] = uint(r.Uint64()) & ((1 << _W) - 2)
	}
	return reflect.ValueOf(&Nat{limbs})
}

func testModAddCommutative(a *Nat, b *Nat) bool {
	m := maxModulus(uint(len(a.limbs)))
	aPlusB := new(Nat).set(a)
	aPlusB.Add(b, m)
	bPlusA := new(Nat).set(b)
	bPlusA.Add(a, m)
	return aPlusB.Equal(bPlusA) == 1
}

func TestModAddCommutative(t *testing.T) {
	err := quick.Check(testModAddCommutative, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func testModSubThenAddIdentity(a *Nat, b *Nat) bool {
	m := maxModulus(uint(len(a.limbs)))
	original := new(Nat).set(a)
	a.Sub(b, m)
	a.Add(b, m)
	return a.Equal(original) == 1
}

func TestModSubThenAddIdentity(t *testing.T) {
	err := quick.Check(testModSubThenAddIdentity, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func TestMontgomeryRoundtrip(t *testing.T) {
	err := quick.Check(func(a *Nat) bool {
		one := &Nat{make([]uint, len(a.limbs))}
		one.limbs[0] = 1
		aPlusOne := new(big.Int).SetBytes(natBytes(a))
		aPlusOne.Add(aPlusOne, big.NewInt(1))
		m, _ := NewModulus(aPlusOne.Bytes())
		monty := new(Nat).set(a)
		monty.montgomeryRepresentation(m)
		aAgain := new(Nat).set(monty)
		aAgain.montgomeryMul(monty, one, m)
		if a.Equal(aAgain) != 1 {
			t.Errorf("%v != %v", a, aAgain)
			return false
		}
		return true
	}, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func TestShiftIn(t *testing.T) {
	if bits.UintSize != 64 {
		t.Skip("examples are only valid in 64 bit")
	}
	examples := []struct {
		m, x, expected []byte
		y              uint64
	}{{
		m:        []byte{13},
		x:        []byte{0},
		y:        0xFFFF_FFFF_FFFF_FFFF,
		expected: []byte{2},
	}, {
		m:        []byte{13},
		x:        []byte{7},
		y:        0xFFFF_FFFF_FFFF_FFFF,
		expected: []byte{10},
	}, {
		m:        []byte{0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d},
		x:        make([]byte, 9),
		y:        0xFFFF_FFFF_FFFF_FFFF,
		expected: []byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}, {
		m:        []byte{0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d},
		x:        []byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		y:        0,
		expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
	}}

	for i, tt := range examples {
		m := modulusFromBytes(tt.m)
		got := natFromBytes(tt.x).ExpandFor(m).shiftIn(uint(tt.y), m)
		if exp := natFromBytes(tt.expected).ExpandFor(m); got.Equal(exp) != 1 {
			t.Errorf("%d: got %v, expected %v", i, got, exp)
		}
	}
}

func TestModulusAndNatSizes(t *testing.T) {
	// These are 126 bit (2 * _W on 64-bit architectures) values, serialized as
	// 128 bits worth of bytes. If leading zeroes are stripped, they fit in two
	// limbs, if they are not, they fit in three. This can be a problem because
	// modulus strips leading zeroes and nat does not.
	m := modulusFromBytes([]byte{
		0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	xb := []byte{0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}
	natFromBytes(xb).ExpandFor(m) // must not panic for shrinking
	NewNat().SetBytes(xb, m)
}

func TestSetBytes(t *testing.T) {
	tests := []struct {
		m, b []byte
		fail bool
	}{{
		m: []byte{0xff, 0xff},
		b: []byte{0x00, 0x01},
	}, {
		m:    []byte{0xff, 0xff},
		b:    []byte{0xff, 0xff},
		fail: true,
	}, {
		m: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		b: []byte{0x00, 0x01},
	}, {
		m: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		b: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
	}, {
		m:    []byte{0xff, 0xff},
		b:    []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		fail: true,
	}, {
		m:    []byte{0xff, 0xff},
		b:    []byte{0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		fail: true,
	}, {
		m: []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		b: []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
	}, {
		m:    []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		b:    []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
		fail: true,
	}, {
		m:    []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		b:    []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		fail: true,
	}, {
		m:    []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		b:    []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
		fail: true,
	}, {
		m:    []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd},
		b:    []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		fail: true,
	}}

	for i, tt := range tests {
		m := modulusFromBytes(tt.m)
		got, err := NewNat().SetBytes(tt.b, m)
		if err != nil {
			if !tt.fail {
				t.Errorf("%d: unexpected error: %v", i, err)
			}
			continue
		}
		if tt.fail {
			t.Errorf("%d: unexpected success", i)
			continue
		}
		if expected := natFromBytes(tt.b).ExpandFor(m); got.Equal(expected) != yes {
			t.Errorf("%d: got %v, expected %v", i, got, expected)
		}
	}

	f := func(xBytes []byte) bool {
		m := maxModulus(uint(len(xBytes)*8/_W + 1))
		got, err := NewNat().SetBytes(xBytes, m)
		if err != nil {
			return false
		}
		return got.Equal(natFromBytes(xBytes).ExpandFor(m)) == yes
	}

	err := quick.Check(f, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func TestExpand(t *testing.T) {
	sliced := []uint{1, 2, 3, 4}
	examples := []struct {
		in  []uint
		n   int
		out []uint
	}{{
		[]uint{1, 2},
		4,
		[]uint{1, 2, 0, 0},
	}, {
		sliced[:2],
		4,
		[]uint{1, 2, 0, 0},
	}, {
		[]uint{1, 2},
		2,
		[]uint{1, 2},
	}}

	for i, tt := range examples {
		got := (&Nat{tt.in}).expand(tt.n)
		if len(got.limbs) != len(tt.out) || got.Equal(&Nat{tt.out}) != 1 {
			t.Errorf("%d: got %v, expected %v", i, got, tt.out)
		}
	}
}

func TestMod(t *testing.T) {
	m := modulusFromBytes([]byte{0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d})
	x := natFromBytes([]byte{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	out := new(Nat)
	out.Mod(x, m)
	expected := natFromBytes([]byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09})
	if out.Equal(expected) != 1 {
		t.Errorf("%+v != %+v", out, expected)
	}
}

func TestModSub(t *testing.T) {
	m := modulusFromBytes([]byte{13})
	x := &Nat{[]uint{6}}
	y := &Nat{[]uint{7}}
	x.Sub(y, m)
	expected := &Nat{[]uint{12}}
	if x.Equal(expected) != 1 {
		t.Errorf("%+v != %+v", x, expected)
	}
	x.Sub(y, m)
	expected = &Nat{[]uint{5}}
	if x.Equal(expected) != 1 {
		t.Errorf("%+v != %+v", x, expected)
	}
}

func TestModAdd(t *testing.T) {
	m := modulusFromBytes([]byte{13})
	x := &Nat{[]uint{6}}
	y := &Nat{[]uint{7}}
	x.Add(y, m)
	expected := &Nat{[]uint{0}}
	if x.Equal(expected) != 1 {
		t.Errorf("%+v != %+v", x, expected)
	}
	x.Add(y, m)
	expected = &Nat{[]uint{7}}
	if x.Equal(expected) != 1 {
		t.Errorf("%+v != %+v", x, expected)
	}
}

func TestExp(t *testing.T) {
	m := modulusFromBytes([]byte{13})
	x := &Nat{[]uint{3}}
	out := &Nat{[]uint{0}}
	out.Exp(x, []byte{12}, m)
	expected := &Nat{[]uint{1}}
	if out.Equal(expected) != 1 {
		t.Errorf("%+v != %+v", out, expected)
	}
}

func TestExpShort(t *testing.T) {
	m := modulusFromBytes([]byte{13})
	x := &Nat{[]uint{3}}
	out := &Nat{[]uint{0}}
	out.ExpShortVarTime(x, 12, m)
	expected := &Nat{[]uint{1}}
	if out.Equal(expected) != 1 {
		t.Errorf("%+v != %+v", out, expected)
	}
}

// TestMulReductions tests that Mul reduces results equal or slightly greater
// than the modulus. Some Montgomery algorithms don't and need extra care to
// return correct results. See https://go.dev/issue/13907.
func TestMulReductions(t *testing.T) {
	// Two short but multi-limb primes.
	a, _ := new(big.Int).SetString("773608962677651230850240281261679752031633236267106044359907", 10)
	b, _ := new(big.Int).SetString("180692823610368451951102211649591374573781973061758082626801", 10)
	n := new(big.Int).Mul(a, b)

	N, _ := NewModulus(n.Bytes())
	A := NewNat().setBig(a).ExpandFor(N)
	B := NewNat().setBig(b).ExpandFor(N)

	if A.Mul(B, N).IsZero() != 1 {
		t.Error("a * b mod (a * b) != 0")
	}

	i := new(big.Int).ModInverse(a, b)
	N, _ = NewModulus(b.Bytes())
	A = NewNat().setBig(a).ExpandFor(N)
	I := NewNat().setBig(i).ExpandFor(N)
	one := NewNat().setBig(big.NewInt(1)).ExpandFor(N)

	if A.Mul(I, N).Equal(one) != 1 {
		t.Error("a * inv(a) mod b != 1")
	}
}

func TestMul(t *testing.T) {
	t.Run("small", func(t *testing.T) { testMul(t, 760/8) })
	t.Run("1024", func(t *testing.T) { testMul(t, 1024/8) })
	t.Run("1536", func(t *testing.T) { testMul(t, 1536/8) })
	t.Run("2048", func(t *testing.T) { testMul(t, 2048/8) })
}

func testMul(t *testing.T, n int) {
	a, b, m := make([]byte, n), make([]byte, n), make([]byte, n)
	cryptorand.Read(a)
	cryptorand.Read(b)
	cryptorand.Read(m)

	// Pick the highest as the modulus.
	if bytes.Compare(a, m) > 0 {
		a, m = m, a
	}
	if bytes.Compare(b, m) > 0 {
		b, m = m, b
	}

	M, err := NewModulus(m)
	if err != nil {
		t.Fatal(err)
	}
	A, err := NewNat().SetBytes(a, M)
	if err != nil {
		t.Fatal(err)
	}
	B, err := NewNat().SetBytes(b, M)
	if err != nil {
		t.Fatal(err)
	}

	A.Mul(B, M)
	ABytes := A.Bytes(M)

	mBig := new(big.Int).SetBytes(m)
	aBig := new(big.Int).SetBytes(a)
	bBig := new(big.Int).SetBytes(b)
	nBig := new(big.Int).Mul(aBig, bBig)
	nBig.Mod(nBig, mBig)
	nBigBytes := make([]byte, len(ABytes))
	nBig.FillBytes(nBigBytes)

	if !bytes.Equal(ABytes, nBigBytes) {
		t.Errorf("got %x, want %x", ABytes, nBigBytes)
	}
}

func TestIs(t *testing.T) {
	checkYes := func(c choice, err string) {
		t.Helper()
		if c != yes {
			t.Error(err)
		}
	}
	checkNot := func(c choice, err string) {
		t.Helper()
		if c != no {
			t.Error(err)
		}
	}

	mFour := modulusFromBytes([]byte{4})
	n, err := NewNat().SetBytes([]byte{3}, mFour)
	if err != nil {
		t.Fatal(err)
	}
	checkYes(n.IsMinusOne(mFour), "3 is not -1 mod 4")
	checkNot(n.IsZero(), "3 is zero")
	checkNot(n.IsOne(), "3 is one")
	checkYes(n.IsOdd(), "3 is not odd")
	n.SubOne(mFour)
	checkNot(n.IsMinusOne(mFour), "2 is -1 mod 4")
	checkNot(n.IsZero(), "2 is zero")
	checkNot(n.IsOne(), "2 is one")
	checkNot(n.IsOdd(), "2 is odd")
	n.SubOne(mFour)
	checkNot(n.IsMinusOne(mFour), "1 is -1 mod 4")
	checkNot(n.IsZero(), "1 is zero")
	checkYes(n.IsOne(), "1 is not one")
	checkYes(n.IsOdd(), "1 is not odd")
	n.SubOne(mFour)
	checkNot(n.IsMinusOne(mFour), "0 is -1 mod 4")
	checkYes(n.IsZero(), "0 is not zero")
	checkNot(n.IsOne(), "0 is one")
	checkNot(n.IsOdd(), "0 is odd")
	n.SubOne(mFour)
	checkYes(n.IsMinusOne(mFour), "-1 is not -1 mod 4")
	checkNot(n.IsZero(), "-1 is zero")
	checkNot(n.IsOne(), "-1 is one")
	checkYes(n.IsOdd(), "-1 mod 4 is not odd")

	mTwoLimbs := maxModulus(2)
	n, err = NewNat().SetBytes([]byte{0x01}, mTwoLimbs)
	if err != nil {
		t.Fatal(err)
	}
	if n.IsOne() != 1 {
		t.Errorf("1 is not one")
	}
}

func TestTrailingZeroBits(t *testing.T) {
	nb := new(big.Int).SetBytes([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7e})
	nb.Lsh(nb, 128)
	expected := 129
	for expected >= 0 {
		n := NewNat().setBig(nb)
		if n.TrailingZeroBitsVarTime() != uint(expected) {
			t.Errorf("%d != %d", n.TrailingZeroBitsVarTime(), expected)
		}
		nb.Rsh(nb, 1)
		expected--
	}
}

func TestRightShift(t *testing.T) {
	nb, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 1024))
	if err != nil {
		t.Fatal(err)
	}
	for _, shift := range []uint{1, 32, 64, 128, 1024 - 128, 1024 - 64, 1024 - 32, 1024 - 1} {
		testShift := func(t *testing.T, shift uint) {
			n := NewNat().setBig(nb)
			oldLen := len(n.limbs)
			n.ShiftRightVarTime(shift)
			if len(n.limbs) != oldLen {
				t.Errorf("len(n.limbs) = %d, want %d", len(n.limbs), oldLen)
			}
			exp := new(big.Int).Rsh(nb, shift)
			if n.asBig().Cmp(exp) != 0 {
				t.Errorf("%v != %v", n.asBig(), exp)
			}
		}
		t.Run(fmt.Sprint(shift-1), func(t *testing.T) { testShift(t, shift-1) })
		t.Run(fmt.Sprint(shift), func(t *testing.T) { testShift(t, shift) })
		t.Run(fmt.Sprint(shift+1), func(t *testing.T) { testShift(t, shift+1) })
	}
}

func natBytes(n *Nat) []byte {
	return n.Bytes(maxModulus(uint(len(n.limbs))))
}

func natFromBytes(b []byte) *Nat {
	// Must not use Nat.SetBytes as it's used in TestSetBytes.
	bb := new(big.Int).SetBytes(b)
	return NewNat().setBig(bb)
}

func modulusFromBytes(b []byte) *Modulus {
	bb := new(big.Int).SetBytes(b)
	m, _ := NewModulus(bb.Bytes())
	return m
}

// maxModulus returns the biggest modulus that can fit in n limbs.
func maxModulus(n uint) *Modulus {
	b := big.NewInt(1)
	b.Lsh(b, n*_W)
	b.Sub(b, big.NewInt(1))
	m, _ := NewModulus(b.Bytes())
	return m
}

func makeBenchmarkModulus() *Modulus {
	return maxModulus(32)
}

func makeBenchmarkValue() *Nat {
	x := make([]uint, 32)
	for i := 0; i < 32; i++ {
		x[i]--
	}
	return &Nat{limbs: x}
}

func makeBenchmarkExponent() []byte {
	e := make([]byte, 256)
	for i := 0; i < 32; i++ {
		e[i] = 0xFF
	}
	return e
}

func BenchmarkModAdd(b *testing.B) {
	x := makeBenchmarkValue()
	y := makeBenchmarkValue()
	m := makeBenchmarkModulus()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Add(y, m)
	}
}

func BenchmarkModSub(b *testing.B) {
	x := makeBenchmarkValue()
	y := makeBenchmarkValue()
	m := makeBenchmarkModulus()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Sub(y, m)
	}
}

func BenchmarkMontgomeryRepr(b *testing.B) {
	x := makeBenchmarkValue()
	m := makeBenchmarkModulus()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.montgomeryRepresentation(m)
	}
}

func BenchmarkMontgomeryMul(b *testing.B) {
	x := makeBenchmarkValue()
	y := makeBenchmarkValue()
	out := makeBenchmarkValue()
	m := makeBenchmarkModulus()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.montgomeryMul(x, y, m)
	}
}

func BenchmarkModMul(b *testing.B) {
	x := makeBenchmarkValue()
	y := makeBenchmarkValue()
	m := makeBenchmarkModulus()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Mul(y, m)
	}
}

func BenchmarkExpBig(b *testing.B) {
	out := new(big.Int)
	exponentBytes := makeBenchmarkExponent()
	x := new(big.Int).SetBytes(exponentBytes)
	e := new(big.Int).SetBytes(exponentBytes)
	n := new(big.Int).SetBytes(exponentBytes)
	one := new(big.Int).SetUint64(1)
	n.Add(n, one)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Exp(x, e, n)
	}
}

func BenchmarkExp(b *testing.B) {
	x := makeBenchmarkValue()
	e := makeBenchmarkExponent()
	out := makeBenchmarkValue()
	m := makeBenchmarkModulus()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Exp(x, e, m)
	}
}

func TestNewModulus(t *testing.T) {
	expected := "modulus must be > 1"
	_, err := NewModulus([]byte{})
	if err == nil || err.Error() != expected {
		t.Errorf("NewModulus(0) got %q, want %q", err, expected)
	}
	_, err = NewModulus([]byte{0})
	if err == nil || err.Error() != expected {
		t.Errorf("NewModulus(0) got %q, want %q", err, expected)
	}
	_, err = NewModulus([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err == nil || err.Error() != expected {
		t.Errorf("NewModulus(0) got %q, want %q", err, expected)
	}
	_, err = NewModulus([]byte{1})
	if err == nil || err.Error() != expected {
		t.Errorf("NewModulus(1) got %q, want %q", err, expected)
	}
	_, err = NewModulus([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err == nil || err.Error() != expected {
		t.Errorf("NewModulus(1) got %q, want %q", err, expected)
	}
}

func makeTestValue(nbits int) []uint {
	n := nbits / _W
	x := make([]uint, n)
	for i := range n {
		x[i]--
	}
	return x
}

func TestAddMulVVWSized(t *testing.T) {
	// Sized addMulVVW have architecture-specific implementations on
	// a number of architectures. Test that they match the generic
	// implementation.
	tests := []struct {
		n int
		f func(z, x *uint, y uint) uint
	}{
		{1024, addMulVVW1024},
		{1536, addMulVVW1536},
		{2048, addMulVVW2048},
	}
	for _, test := range tests {
		t.Run(fmt.Sprint(test.n), func(t *testing.T) {
			x := makeTestValue(test.n)
			z := makeTestValue(test.n)
			z2 := slices.Clone(z)
			var y uint
			y--
			c := addMulVVW(z, x, y)
			c2 := test.f(&z2[0], &x[0], y)
			if !slices.Equal(z, z2) || c != c2 {
				t.Errorf("%016X, %016X != %016X, %016X", z, c, z2, c2)
			}
		})
	}
}

func TestInverse(t *testing.T) {
	f, err := os.Open("testdata/mod_inv_tests.txt")
	if err != nil {
		t.Fatal(err)
	}

	var ModInv, A, M string
	var lineNum int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		k, v, _ := strings.Cut(line, " = ")
		switch k {
		case "ModInv":
			ModInv = v
		case "A":
			A = v
		case "M":
			M = v

			t.Run(fmt.Sprintf("line %d", lineNum), func(t *testing.T) {
				m, err := NewModulus(decodeHex(t, M))
				if err != nil {
					t.Skip("modulus <= 1")
				}
				a, err := NewNat().SetBytes(decodeHex(t, A), m)
				if err != nil {
					t.Fatal(err)
				}

				got, ok := NewNat().InverseVarTime(a, m)
				if !ok {
					t.Fatal("not invertible")
				}
				exp, err := NewNat().SetBytes(decodeHex(t, ModInv), m)
				if err != nil {
					t.Fatal(err)
				}
				if got.Equal(exp) != 1 {
					t.Errorf("%v != %v", got, exp)
				}
			})
		default:
			t.Fatalf("unknown key %q on line %d", k, lineNum)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex %q: %v", s, err)
	}
	return b
}
```