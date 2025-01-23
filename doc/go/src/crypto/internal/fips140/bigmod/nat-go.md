Response:
Thinking Process:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet, specifically the `nat.go` file within the `bigmod` package. It also wants examples, potential errors, and other relevant information.

2. **Identify Key Structures and Functions:**  Scan the code for important types and functions. The most prominent is the `Nat` struct, which likely represents large natural numbers. Then, look for functions that operate on `Nat` values, like `NewNat`, `resetToBytes`, `SetBytes`, `Add`, `Mul`, `Mod`, `Exp`, etc. The `Modulus` struct is also crucial for modular arithmetic.

3. **Analyze Functionality by Category:** Group the identified functions by their purpose:
    * **Creation and Initialization:** `NewNat`, `reset`, `resetToBytes`, `setBytes`, `SetUint`.
    * **Comparison:** `Equal`, `IsZero`, `IsOne`, `IsMinusOne`, `IsOdd`, `cmpGeq`.
    * **Arithmetic Operations:** `add`, `sub`, `Add`, `Sub`, `Mul`, `Mod`, `Exp`, `ExpShortVarTime`, `InverseVarTime`.
    * **Bit Manipulation:** `TrailingZeroBitsVarTime`, `ShiftRightVarTime`, `BitLenVarTime`.
    * **Internal Helpers:** `ctEq`, `ctMask`, `assign`, `maybeSubtractModulus`, `montgomeryMul`, `addMulVVW`, `rshift1`.
    * **Modulus Related:** `NewModulus`, `NewModulusProduct`, `Size`, `BitLen`, `Nat` (method on `Modulus`), `montgomeryRepresentation`, `montgomeryReduction`.

4. **Explain Core Concepts:** Before diving into individual functions, explain the fundamental ideas:
    * **Arbitrary Precision Integers (`Nat`):** How they are represented (little-endian limbs), and the concept of "announced length."
    * **Constant-Time Operations:** The significance of `choice` and functions like `ctEq`, and the reason for the `//go:norace` comments.
    * **Modular Arithmetic (`Modulus`):**  Explain the purpose of the `Modulus` struct and its role in calculations. Mention Montgomery multiplication as a key optimization.

5. **Provide Concrete Examples:** For important functionalities, create simple Go code snippets demonstrating their usage. Include:
    * Creating and setting `Nat` values.
    * Basic arithmetic operations (addition, subtraction, multiplication, modulo).
    * Exponentiation.
    * Modular inverse.
    * Be sure to include example inputs and expected outputs.

6. **Address Specific Instructions:**
    * **Code Inference:** The examples fulfill this requirement.
    * **Assumptions for Code Inference:**  Explicitly state the assumptions made about inputs and outputs for the examples.
    * **Command-Line Arguments:**  The provided code doesn't directly handle command-line arguments. State this clearly.
    * **Common Mistakes:** Identify potential pitfalls users might encounter:
        * Incorrect operand lengths in certain functions.
        * Forgetting that some functions require inputs to be already reduced modulo `m`.
        * Misunderstanding the difference between `Nat` and `Modulus`.
        * Potential confusion around constant-time operations.

7. **Structure the Answer:** Organize the information logically:
    * Start with a general overview of the file's purpose.
    * Detail the functionality of the `Nat` struct and its related functions.
    * Explain the `Modulus` struct and its role.
    * Provide illustrative Go code examples.
    * Discuss potential user errors.
    * Conclude with a summary.

8. **Refine and Review:**  Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. Make sure the language is precise and easy to understand. For instance, initially, I might have just listed the functions. Reviewing made me realize that grouping by functionality and explaining core concepts first would be much clearer. Also, explicitly mentioning that there's no command-line argument handling is important because the prompt specifically asked about it. Similarly, emphasizing the "constant-time" aspect is crucial given the code's focus on security.

By following these steps, we can systematically analyze the code and generate a comprehensive and informative response that addresses all aspects of the request.这段代码是 Go 语言 `crypto/internal/fips140/bigmod` 包中 `nat.go` 文件的一部分，它实现了**任意精度自然数（非负整数）**的相关操作。 这个实现是为了满足 FIPS 140 标准的安全需求，特别是在密码学计算中需要防止侧信道攻击。

以下是代码的主要功能：

**1. `Nat` 类型：表示任意精度的自然数**

*   `limbs []uint`:  存储数字的“肢”（limbs）。每个 `uint` 代表一个固定大小的字（word），例如 32 位或 64 位。 `limbs` 使用小端序存储。
*   `announced length`: 虽然 `limbs` 的实际长度可以变化，但 `Nat` 对象在某些操作中会有一个“声明的长度”，这有助于进行常量时间操作。

**2. 常量时间布尔值 (`choice`)**

*   `choice uint`:  使用 `uint` (0 或 1) 来表示布尔值，而不是 `bool`。这是为了在代码中进行常量时间判断，防止根据布尔值的分支执行时间不同而泄露信息。
*   `ctMask(on choice) uint`: 根据 `choice` 的值生成全 1 或全 0 的掩码。
*   `ctEq(x, y uint) choice`:  常量时间比较两个无符号整数是否相等。

**3. `NewNat()`: 创建新的 `Nat` 对象**

*   创建一个新的 `Nat` 实例，预分配了一定的容量，以优化性能。

**4. 内存管理和大小调整**

*   `expand(n int)`:  将 `Nat` 的 `limbs` 扩展到指定的长度 `n`，保留原有值。
*   `reset(n int)`:  创建一个长度为 `n` 的零值 `Nat`，如果可能，会重用现有的存储空间。
*   `resetToBytes(b []byte)`: 将大端字节切片 `b` 转换为 `Nat`，并根据实际位数调整大小。
*   `trim()`:  去除 `Nat` 末尾的零值 limb，减小其大小。

**5. 赋值和转换**

*   `set(y *Nat)`:  将 `Nat` `y` 的值赋给 `x`。
*   `Bytes(m *Modulus) []byte`: 将 `Nat` 转换为大端字节切片，大小与 `Modulus` `m` 相同。
*   `SetBytes(b []byte, m *Modulus) (*Nat, error)`: 将大端字节切片 `b` 转换为 `Nat`，并确保其小于模数 `m`。
*   `SetOverflowingBytes(b []byte, m *Modulus) (*Nat, error)`:  类似 `SetBytes`，但允许输入值略大于模数。
*   `SetUint(y uint)`: 将无符号整数 `y` 转换为 `Nat`。

**6. 比较操作 (常量时间)**

*   `Equal(y *Nat) choice`:  常量时间比较两个 `Nat` 是否相等。
*   `IsZero() choice`:  常量时间检查 `Nat` 是否为零。
*   `IsOne() choice`:  常量时间检查 `Nat` 是否为一。
*   `IsMinusOne(m *Modulus) choice`: 常量时间检查 `Nat` 是否为模 `m` 下的 -1。
*   `IsOdd() choice`:  检查 `Nat` 是否为奇数。
*   `cmpGeq(y *Nat) choice`: 常量时间比较两个 `Nat` 的大小 (大于等于)。

**7. 算术运算 (通常是常量时间或旨在抵抗侧信道)**

*   `assign(on choice, y *Nat)`:  如果 `on` 为 1，则将 `y` 赋值给 `x`，否则不做任何操作 (常量时间)。
*   `add(y *Nat) (c uint)`:  常量时间执行加法，返回进位。
*   `sub(y *Nat) (c uint)`:  常量时间执行减法，返回借位。
*   `ShiftRightVarTime(n uint)`:  变长时间右移 `n` 位。
*   `Add(y *Nat, m *Modulus) *Nat`:  模加运算。
*   `Sub(y *Nat, m *Modulus) *Nat`:  模减运算。
*   `SubOne(m *Modulus) *Nat`:  模减一运算。
*   `Mul(y *Nat, m *Modulus) *Nat`:  模乘运算。
*   `Mod(x *Nat, m *Modulus) *Nat`:  模运算。
*   `Exp(x *Nat, e []byte, m *Modulus) *Nat`:  模幂运算（常量时间）。
*   `ExpShortVarTime(x *Nat, e uint, m *Modulus) *Nat`:  模幂运算（变长时间，对短指数优化）。
*   `InverseVarTime(a *Nat, m *Modulus) (*Nat, bool)`:  计算模逆元（变长时间）。

**8. 辅助函数**

*   `ctMask`: 生成常量时间掩码。
*   `ctEq`: 常量时间比较。
*   `bitLen(n uint)`:  计算无符号整数的位数。
*   `maybeSubtractModulus(always choice, m *Modulus)`:  条件性地执行模减操作。
*   `montgomeryRepresentation(m *Modulus)`:  转换为 Montgomery 表示。
*   `montgomeryReduction(m *Modulus)`:  从 Montgomery 表示转换回来。
*   `montgomeryMul(a *Nat, b *Nat, m *Modulus)`:  Montgomery 乘法。
*   `addMulVVW(z, x []uint, y uint)`:  多精度乘法和加法操作。
*   `rshift1(a *Nat, carry uint)`:  右移一位。

**9. `Modulus` 类型：表示模数**

*   `nat *Nat`:  模数的实际值。
*   `odd bool`:  指示模数是否为奇数。
*   `m0inv uint`:  用于 Montgomery 乘法的预计算值。
*   `rr *Nat`:  用于 Montgomery 乘法的预计算值 (R^2 mod m)。
*   提供了创建 `Modulus` 对象的方法，如 `NewModulus` 和 `NewModulusProduct`。

**推理 `nat.go` 的 Go 语言功能实现：**

这段代码是 Go 语言中**大整数算术**功能的实现，主要用于**密码学**领域，特别是需要**模运算**和**侧信道攻击防护**的场景。它提供了对任意大小的非负整数进行基本算术运算、比较以及模运算的功能。

**Go 代码示例：**

假设我们要计算 `(12345^6789) mod 1000000007`。

```go
package main

import (
	"fmt"
	"crypto/internal/fips140/bigmod"
)

func main() {
	baseBytes := []byte{0, 0, 0, 0, 0, 0, 48, 57} // 12345 (大端)
	expBytes := []byte{0, 0, 0, 0, 0, 0, 26, 165} // 6789 (大端)
	modBytes := []byte{0, 0, 0, 0, 3, 234, 195, 175} // 1000000007 (大端)

	base := bigmod.NewNat()
	base.ResetToBytes(baseBytes)

	modulus, err := bigmod.NewModulus(modBytes)
	if err != nil {
		fmt.Println("Error creating modulus:", err)
		return
	}

	result := bigmod.NewNat()
	reducedBase := bigmod.NewNat()
	reducedBase.Mod(base, modulus) // 先将底数约减到模数范围内

	result.Exp(reducedBase, expBytes, modulus)

	resultBytes := result.Bytes(modulus)
	fmt.Printf("Result: %x\n", resultBytes) // 输出结果的十六进制表示
}
```

**假设的输入与输出：**

*   **输入：**
    *   `baseBytes`: `[]byte{0, 0, 0, 0, 0, 0, 48, 57}`  (代表十进制的 12345)
    *   `expBytes`:  `[]byte{0, 0, 0, 0, 0, 0, 26, 165}` (代表十进制的 6789)
    *   `modBytes`:  `[]byte{0, 0, 0, 0, 3, 234, 195, 175}` (代表十进制的 1000000007)
*   **输出：** (实际输出会根据 `_W` 的值而有所不同，这里假设 `_W` 为 64)
    *   `Result: [一些十六进制数字]`  （代表 `(12345^6789) mod 1000000007` 的结果）

**命令行参数的具体处理：**

这段代码本身**不处理任何命令行参数**。它是一个库，提供大整数算术功能。如果需要处理命令行参数来使用这些功能，需要在调用此库的程序中进行处理。例如，可以使用 `flag` 包来解析命令行参数，并将解析后的参数传递给 `bigmod` 包中的函数。

**使用者易犯错的点：**

1. **操作数长度不匹配：** 许多函数，特别是常量时间的算术运算 (`add`, `sub`) 和比较 (`Equal`, `cmpGeq`)，要求操作数的 `Nat` 对象的“声明的长度”相同。如果长度不一致，可能会导致错误或未定义的行为。

    ```go
    // 错误示例
    nat1 := bigmod.NewNat()
    nat1.Reset([]uint{1, 2, 3})

    nat2 := bigmod.NewNat()
    nat2.Reset([]uint{4, 5})

    // nat1.add(nat2) // 可能会 panic 或产生错误结果，因为长度不同
    ```

2. **忘记模运算前的约减：** 在进行模运算之前，通常需要将操作数约减到模数的范围内。例如，在计算模幂时，底数应该先对模数取模。

    ```go
    // 容易出错的地方
    base := bigmod.NewNat()
    base.SetUint(12345)

    modulus, _ := bigmod.NewModulus([]byte{ /* ... */ })

    // 直接进行模幂运算，可能效率较低，如果 base 很大可能超出处理能力
    // result.Exp(base, expBytes, modulus)

    // 正确的做法是先约减底数
    reducedBase := bigmod.NewNat()
    reducedBase.Mod(base, modulus)
    result := bigmod.NewNat()
    result.Exp(reducedBase, []byte{ /* ... */ }, modulus)
    ```

3. **混淆 `Nat` 和 `Modulus`：** `Nat` 表示一个自然数，而 `Modulus` 表示模数，包含了额外的预计算信息。将 `Nat` 对象直接传递给需要 `Modulus` 的函数（反之亦然）会导致类型错误或逻辑错误。

4. **不理解常量时间操作的含义：**  `bigmod` 包为了防止侧信道攻击，大量使用了常量时间操作。这意味着某些操作的执行时间不会依赖于输入的值。使用者需要理解这一点，并避免编写依赖于执行时间差异的代码。

5. **错误地使用变长时间操作：**  某些操作（例如 `InverseVarTime`，带有 `VarTime` 后缀）是变长的，这意味着它们的执行时间可能会泄露关于输入的信息。在对安全性要求高的场景中，应该谨慎使用这些函数。

总而言之，`nat.go` 文件是 Go 语言 `crypto/internal/fips140/bigmod` 包中实现任意精度自然数算术的核心部分，它特别关注密码学安全性和抗侧信道攻击能力。 理解其功能和正确使用方式对于开发安全的密码学应用至关重要。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/bigmod/nat.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	_ "crypto/internal/fips140/check"
	"crypto/internal/fips140deps/byteorder"
	"errors"
	"math/bits"
)

const (
	// _W is the size in bits of our limbs.
	_W = bits.UintSize
	// _S is the size in bytes of our limbs.
	_S = _W / 8
)

// Note: These functions make many loops over all the words in a Nat.
// These loops used to be in assembly, invisible to -race, -asan, and -msan,
// but now they are in Go and incur significant overhead in those modes.
// To bring the old performance back, we mark all functions that loop
// over Nat words with //go:norace. Because //go:norace does not
// propagate across inlining, we must also mark functions that inline
// //go:norace functions - specifically, those that inline add, addMulVVW,
// assign, cmpGeq, rshift1, and sub.

// choice represents a constant-time boolean. The value of choice is always
// either 1 or 0. We use an int instead of bool in order to make decisions in
// constant time by turning it into a mask.
type choice uint

func not(c choice) choice { return 1 ^ c }

const yes = choice(1)
const no = choice(0)

// ctMask is all 1s if on is yes, and all 0s otherwise.
func ctMask(on choice) uint { return -uint(on) }

// ctEq returns 1 if x == y, and 0 otherwise. The execution time of this
// function does not depend on its inputs.
func ctEq(x, y uint) choice {
	// If x != y, then either x - y or y - x will generate a carry.
	_, c1 := bits.Sub(x, y, 0)
	_, c2 := bits.Sub(y, x, 0)
	return not(choice(c1 | c2))
}

// Nat represents an arbitrary natural number
//
// Each Nat has an announced length, which is the number of limbs it has stored.
// Operations on this number are allowed to leak this length, but will not leak
// any information about the values contained in those limbs.
type Nat struct {
	// limbs is little-endian in base 2^W with W = bits.UintSize.
	limbs []uint
}

// preallocTarget is the size in bits of the numbers used to implement the most
// common and most performant RSA key size. It's also enough to cover some of
// the operations of key sizes up to 4096.
const preallocTarget = 2048
const preallocLimbs = (preallocTarget + _W - 1) / _W

// NewNat returns a new nat with a size of zero, just like new(Nat), but with
// the preallocated capacity to hold a number of up to preallocTarget bits.
// NewNat inlines, so the allocation can live on the stack.
func NewNat() *Nat {
	limbs := make([]uint, 0, preallocLimbs)
	return &Nat{limbs}
}

// expand expands x to n limbs, leaving its value unchanged.
func (x *Nat) expand(n int) *Nat {
	if len(x.limbs) > n {
		panic("bigmod: internal error: shrinking nat")
	}
	if cap(x.limbs) < n {
		newLimbs := make([]uint, n)
		copy(newLimbs, x.limbs)
		x.limbs = newLimbs
		return x
	}
	extraLimbs := x.limbs[len(x.limbs):n]
	clear(extraLimbs)
	x.limbs = x.limbs[:n]
	return x
}

// reset returns a zero nat of n limbs, reusing x's storage if n <= cap(x.limbs).
func (x *Nat) reset(n int) *Nat {
	if cap(x.limbs) < n {
		x.limbs = make([]uint, n)
		return x
	}
	clear(x.limbs)
	x.limbs = x.limbs[:n]
	return x
}

// resetToBytes assigns x = b, where b is a slice of big-endian bytes, resizing
// n to the appropriate size.
//
// The announced length of x is set based on the actual bit size of the input,
// ignoring leading zeroes.
func (x *Nat) resetToBytes(b []byte) *Nat {
	x.reset((len(b) + _S - 1) / _S)
	if err := x.setBytes(b); err != nil {
		panic("bigmod: internal error: bad arithmetic")
	}
	return x.trim()
}

// trim reduces the size of x to match its value.
func (x *Nat) trim() *Nat {
	// Trim most significant (trailing in little-endian) zero limbs.
	// We assume comparison with zero (but not the branch) is constant time.
	for i := len(x.limbs) - 1; i >= 0; i-- {
		if x.limbs[i] != 0 {
			break
		}
		x.limbs = x.limbs[:i]
	}
	return x
}

// set assigns x = y, optionally resizing x to the appropriate size.
func (x *Nat) set(y *Nat) *Nat {
	x.reset(len(y.limbs))
	copy(x.limbs, y.limbs)
	return x
}

// Bytes returns x as a zero-extended big-endian byte slice. The size of the
// slice will match the size of m.
//
// x must have the same size as m and it must be less than or equal to m.
func (x *Nat) Bytes(m *Modulus) []byte {
	i := m.Size()
	bytes := make([]byte, i)
	for _, limb := range x.limbs {
		for j := 0; j < _S; j++ {
			i--
			if i < 0 {
				if limb == 0 {
					break
				}
				panic("bigmod: modulus is smaller than nat")
			}
			bytes[i] = byte(limb)
			limb >>= 8
		}
	}
	return bytes
}

// SetBytes assigns x = b, where b is a slice of big-endian bytes.
// SetBytes returns an error if b >= m.
//
// The output will be resized to the size of m and overwritten.
//
//go:norace
func (x *Nat) SetBytes(b []byte, m *Modulus) (*Nat, error) {
	x.resetFor(m)
	if err := x.setBytes(b); err != nil {
		return nil, err
	}
	if x.cmpGeq(m.nat) == yes {
		return nil, errors.New("input overflows the modulus")
	}
	return x, nil
}

// SetOverflowingBytes assigns x = b, where b is a slice of big-endian bytes.
// SetOverflowingBytes returns an error if b has a longer bit length than m, but
// reduces overflowing values up to 2^⌈log2(m)⌉ - 1.
//
// The output will be resized to the size of m and overwritten.
func (x *Nat) SetOverflowingBytes(b []byte, m *Modulus) (*Nat, error) {
	x.resetFor(m)
	if err := x.setBytes(b); err != nil {
		return nil, err
	}
	// setBytes would have returned an error if the input overflowed the limb
	// size of the modulus, so now we only need to check if the most significant
	// limb of x has more bits than the most significant limb of the modulus.
	if bitLen(x.limbs[len(x.limbs)-1]) > bitLen(m.nat.limbs[len(m.nat.limbs)-1]) {
		return nil, errors.New("input overflows the modulus size")
	}
	x.maybeSubtractModulus(no, m)
	return x, nil
}

// bigEndianUint returns the contents of buf interpreted as a
// big-endian encoded uint value.
func bigEndianUint(buf []byte) uint {
	if _W == 64 {
		return uint(byteorder.BEUint64(buf))
	}
	return uint(byteorder.BEUint32(buf))
}

func (x *Nat) setBytes(b []byte) error {
	i, k := len(b), 0
	for k < len(x.limbs) && i >= _S {
		x.limbs[k] = bigEndianUint(b[i-_S : i])
		i -= _S
		k++
	}
	for s := 0; s < _W && k < len(x.limbs) && i > 0; s += 8 {
		x.limbs[k] |= uint(b[i-1]) << s
		i--
	}
	if i > 0 {
		return errors.New("input overflows the modulus size")
	}
	return nil
}

// SetUint assigns x = y.
//
// The output will be resized to a single limb and overwritten.
func (x *Nat) SetUint(y uint) *Nat {
	x.reset(1)
	x.limbs[0] = y
	return x
}

// Equal returns 1 if x == y, and 0 otherwise.
//
// Both operands must have the same announced length.
//
//go:norace
func (x *Nat) Equal(y *Nat) choice {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	equal := yes
	for i := 0; i < size; i++ {
		equal &= ctEq(xLimbs[i], yLimbs[i])
	}
	return equal
}

// IsZero returns 1 if x == 0, and 0 otherwise.
//
//go:norace
func (x *Nat) IsZero() choice {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]

	zero := yes
	for i := 0; i < size; i++ {
		zero &= ctEq(xLimbs[i], 0)
	}
	return zero
}

// IsOne returns 1 if x == 1, and 0 otherwise.
//
//go:norace
func (x *Nat) IsOne() choice {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]

	if len(xLimbs) == 0 {
		return no
	}

	one := ctEq(xLimbs[0], 1)
	for i := 1; i < size; i++ {
		one &= ctEq(xLimbs[i], 0)
	}
	return one
}

// IsMinusOne returns 1 if x == -1 mod m, and 0 otherwise.
//
// The length of x must be the same as the modulus. x must already be reduced
// modulo m.
//
//go:norace
func (x *Nat) IsMinusOne(m *Modulus) choice {
	minusOne := m.Nat()
	minusOne.SubOne(m)
	return x.Equal(minusOne)
}

// IsOdd returns 1 if x is odd, and 0 otherwise.
func (x *Nat) IsOdd() choice {
	if len(x.limbs) == 0 {
		return no
	}
	return choice(x.limbs[0] & 1)
}

// TrailingZeroBitsVarTime returns the number of trailing zero bits in x.
func (x *Nat) TrailingZeroBitsVarTime() uint {
	var t uint
	limbs := x.limbs
	for _, l := range limbs {
		if l == 0 {
			t += _W
			continue
		}
		t += uint(bits.TrailingZeros(l))
		break
	}
	return t
}

// cmpGeq returns 1 if x >= y, and 0 otherwise.
//
// Both operands must have the same announced length.
//
//go:norace
func (x *Nat) cmpGeq(y *Nat) choice {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	var c uint
	for i := 0; i < size; i++ {
		_, c = bits.Sub(xLimbs[i], yLimbs[i], c)
	}
	// If there was a carry, then subtracting y underflowed, so
	// x is not greater than or equal to y.
	return not(choice(c))
}

// assign sets x <- y if on == 1, and does nothing otherwise.
//
// Both operands must have the same announced length.
//
//go:norace
func (x *Nat) assign(on choice, y *Nat) *Nat {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	mask := ctMask(on)
	for i := 0; i < size; i++ {
		xLimbs[i] ^= mask & (xLimbs[i] ^ yLimbs[i])
	}
	return x
}

// add computes x += y and returns the carry.
//
// Both operands must have the same announced length.
//
//go:norace
func (x *Nat) add(y *Nat) (c uint) {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	for i := 0; i < size; i++ {
		xLimbs[i], c = bits.Add(xLimbs[i], yLimbs[i], c)
	}
	return
}

// sub computes x -= y. It returns the borrow of the subtraction.
//
// Both operands must have the same announced length.
//
//go:norace
func (x *Nat) sub(y *Nat) (c uint) {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	for i := 0; i < size; i++ {
		xLimbs[i], c = bits.Sub(xLimbs[i], yLimbs[i], c)
	}
	return
}

// ShiftRightVarTime sets x = x >> n.
//
// The announced length of x is unchanged.
//
//go:norace
func (x *Nat) ShiftRightVarTime(n uint) *Nat {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]

	shift := int(n % _W)
	shiftLimbs := int(n / _W)

	var shiftedLimbs []uint
	if shiftLimbs < size {
		shiftedLimbs = xLimbs[shiftLimbs:]
	}

	for i := range xLimbs {
		if i >= len(shiftedLimbs) {
			xLimbs[i] = 0
			continue
		}

		xLimbs[i] = shiftedLimbs[i] >> shift
		if i+1 < len(shiftedLimbs) {
			xLimbs[i] |= shiftedLimbs[i+1] << (_W - shift)
		}
	}

	return x
}

// BitLenVarTime returns the actual size of x in bits.
//
// The actual size of x (but nothing more) leaks through timing side-channels.
// Note that this is ordinarily secret, as opposed to the announced size of x.
func (x *Nat) BitLenVarTime() int {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]

	for i := size - 1; i >= 0; i-- {
		if xLimbs[i] != 0 {
			return i*_W + bitLen(xLimbs[i])
		}
	}
	return 0
}

// bitLen is a version of bits.Len that only leaks the bit length of n, but not
// its value. bits.Len and bits.LeadingZeros use a lookup table for the
// low-order bits on some architectures.
func bitLen(n uint) int {
	len := 0
	// We assume, here and elsewhere, that comparison to zero is constant time
	// with respect to different non-zero values.
	for n != 0 {
		len++
		n >>= 1
	}
	return len
}

// Modulus is used for modular arithmetic, precomputing relevant constants.
//
// A Modulus can leak the exact number of bits needed to store its value
// and is stored without padding. Its actual value is still kept secret.
type Modulus struct {
	// The underlying natural number for this modulus.
	//
	// This will be stored without any padding, and shouldn't alias with any
	// other natural number being used.
	nat *Nat

	// If m is even, the following fields are not set.
	odd   bool
	m0inv uint // -nat.limbs[0]⁻¹ mod _W
	rr    *Nat // R*R for montgomeryRepresentation
}

// rr returns R*R with R = 2^(_W * n) and n = len(m.nat.limbs).
func rr(m *Modulus) *Nat {
	rr := NewNat().ExpandFor(m)
	n := uint(len(rr.limbs))
	mLen := uint(m.BitLen())
	logR := _W * n

	// We start by computing R = 2^(_W * n) mod m. We can get pretty close, to
	// 2^⌊log₂m⌋, by setting the highest bit we can without having to reduce.
	rr.limbs[n-1] = 1 << ((mLen - 1) % _W)
	// Then we double until we reach 2^(_W * n).
	for i := mLen - 1; i < logR; i++ {
		rr.Add(rr, m)
	}

	// Next we need to get from R to 2^(_W * n) R mod m (aka from one to R in
	// the Montgomery domain, meaning we can use Montgomery multiplication now).
	// We could do that by doubling _W * n times, or with a square-and-double
	// chain log2(_W * n) long. Turns out the fastest thing is to start out with
	// doublings, and switch to square-and-double once the exponent is large
	// enough to justify the cost of the multiplications.

	// The threshold is selected experimentally as a linear function of n.
	threshold := n / 4

	// We calculate how many of the most-significant bits of the exponent we can
	// compute before crossing the threshold, and we do it with doublings.
	i := bits.UintSize
	for logR>>i <= threshold {
		i--
	}
	for k := uint(0); k < logR>>i; k++ {
		rr.Add(rr, m)
	}

	// Then we process the remaining bits of the exponent with a
	// square-and-double chain.
	for i > 0 {
		rr.montgomeryMul(rr, rr, m)
		i--
		if logR>>i&1 != 0 {
			rr.Add(rr, m)
		}
	}

	return rr
}

// minusInverseModW computes -x⁻¹ mod _W with x odd.
//
// This operation is used to precompute a constant involved in Montgomery
// multiplication.
func minusInverseModW(x uint) uint {
	// Every iteration of this loop doubles the least-significant bits of
	// correct inverse in y. The first three bits are already correct (1⁻¹ = 1,
	// 3⁻¹ = 3, 5⁻¹ = 5, and 7⁻¹ = 7 mod 8), so doubling five times is enough
	// for 64 bits (and wastes only one iteration for 32 bits).
	//
	// See https://crypto.stackexchange.com/a/47496.
	y := x
	for i := 0; i < 5; i++ {
		y = y * (2 - x*y)
	}
	return -y
}

// NewModulus creates a new Modulus from a slice of big-endian bytes. The
// modulus must be greater than one.
//
// The number of significant bits and whether the modulus is even is leaked
// through timing side-channels.
func NewModulus(b []byte) (*Modulus, error) {
	n := NewNat().resetToBytes(b)
	return newModulus(n)
}

// NewModulusProduct creates a new Modulus from the product of two numbers
// represented as big-endian byte slices. The result must be greater than one.
//
//go:norace
func NewModulusProduct(a, b []byte) (*Modulus, error) {
	x := NewNat().resetToBytes(a)
	y := NewNat().resetToBytes(b)
	n := NewNat().reset(len(x.limbs) + len(y.limbs))
	for i := range y.limbs {
		n.limbs[i+len(x.limbs)] = addMulVVW(n.limbs[i:i+len(x.limbs)], x.limbs, y.limbs[i])
	}
	return newModulus(n.trim())
}

func newModulus(n *Nat) (*Modulus, error) {
	m := &Modulus{nat: n}
	if m.nat.IsZero() == yes || m.nat.IsOne() == yes {
		return nil, errors.New("modulus must be > 1")
	}
	if m.nat.IsOdd() == 1 {
		m.odd = true
		m.m0inv = minusInverseModW(m.nat.limbs[0])
		m.rr = rr(m)
	}
	return m, nil
}

// Size returns the size of m in bytes.
func (m *Modulus) Size() int {
	return (m.BitLen() + 7) / 8
}

// BitLen returns the size of m in bits.
func (m *Modulus) BitLen() int {
	return m.nat.BitLenVarTime()
}

// Nat returns m as a Nat.
func (m *Modulus) Nat() *Nat {
	// Make a copy so that the caller can't modify m.nat or alias it with
	// another Nat in a modulus operation.
	n := NewNat()
	n.set(m.nat)
	return n
}

// shiftIn calculates x = x << _W + y mod m.
//
// This assumes that x is already reduced mod m.
//
//go:norace
func (x *Nat) shiftIn(y uint, m *Modulus) *Nat {
	d := NewNat().resetFor(m)

	// Eliminate bounds checks in the loop.
	size := len(m.nat.limbs)
	xLimbs := x.limbs[:size]
	dLimbs := d.limbs[:size]
	mLimbs := m.nat.limbs[:size]

	// Each iteration of this loop computes x = 2x + b mod m, where b is a bit
	// from y. Effectively, it left-shifts x and adds y one bit at a time,
	// reducing it every time.
	//
	// To do the reduction, each iteration computes both 2x + b and 2x + b - m.
	// The next iteration (and finally the return line) will use either result
	// based on whether 2x + b overflows m.
	needSubtraction := no
	for i := _W - 1; i >= 0; i-- {
		carry := (y >> i) & 1
		var borrow uint
		mask := ctMask(needSubtraction)
		for i := 0; i < size; i++ {
			l := xLimbs[i] ^ (mask & (xLimbs[i] ^ dLimbs[i]))
			xLimbs[i], carry = bits.Add(l, l, carry)
			dLimbs[i], borrow = bits.Sub(xLimbs[i], mLimbs[i], borrow)
		}
		// Like in maybeSubtractModulus, we need the subtraction if either it
		// didn't underflow (meaning 2x + b > m) or if computing 2x + b
		// overflowed (meaning 2x + b > 2^_W*n > m).
		needSubtraction = not(choice(borrow)) | choice(carry)
	}
	return x.assign(needSubtraction, d)
}

// Mod calculates out = x mod m.
//
// This works regardless how large the value of x is.
//
// The output will be resized to the size of m and overwritten.
//
//go:norace
func (out *Nat) Mod(x *Nat, m *Modulus) *Nat {
	out.resetFor(m)
	// Working our way from the most significant to the least significant limb,
	// we can insert each limb at the least significant position, shifting all
	// previous limbs left by _W. This way each limb will get shifted by the
	// correct number of bits. We can insert at least N - 1 limbs without
	// overflowing m. After that, we need to reduce every time we shift.
	i := len(x.limbs) - 1
	// For the first N - 1 limbs we can skip the actual shifting and position
	// them at the shifted position, which starts at min(N - 2, i).
	start := len(m.nat.limbs) - 2
	if i < start {
		start = i
	}
	for j := start; j >= 0; j-- {
		out.limbs[j] = x.limbs[i]
		i--
	}
	// We shift in the remaining limbs, reducing modulo m each time.
	for i >= 0 {
		out.shiftIn(x.limbs[i], m)
		i--
	}
	return out
}

// ExpandFor ensures x has the right size to work with operations modulo m.
//
// The announced size of x must be smaller than or equal to that of m.
func (x *Nat) ExpandFor(m *Modulus) *Nat {
	return x.expand(len(m.nat.limbs))
}

// resetFor ensures out has the right size to work with operations modulo m.
//
// out is zeroed and may start at any size.
func (out *Nat) resetFor(m *Modulus) *Nat {
	return out.reset(len(m.nat.limbs))
}

// maybeSubtractModulus computes x -= m if and only if x >= m or if "always" is yes.
//
// It can be used to reduce modulo m a value up to 2m - 1, which is a common
// range for results computed by higher level operations.
//
// always is usually a carry that indicates that the operation that produced x
// overflowed its size, meaning abstractly x > 2^_W*n > m even if x < m.
//
// x and m operands must have the same announced length.
//
//go:norace
func (x *Nat) maybeSubtractModulus(always choice, m *Modulus) {
	t := NewNat().set(x)
	underflow := t.sub(m.nat)
	// We keep the result if x - m didn't underflow (meaning x >= m)
	// or if always was set.
	keep := not(choice(underflow)) | choice(always)
	x.assign(keep, t)
}

// Sub computes x = x - y mod m.
//
// The length of both operands must be the same as the modulus. Both operands
// must already be reduced modulo m.
//
//go:norace
func (x *Nat) Sub(y *Nat, m *Modulus) *Nat {
	underflow := x.sub(y)
	// If the subtraction underflowed, add m.
	t := NewNat().set(x)
	t.add(m.nat)
	x.assign(choice(underflow), t)
	return x
}

// SubOne computes x = x - 1 mod m.
//
// The length of x must be the same as the modulus.
func (x *Nat) SubOne(m *Modulus) *Nat {
	one := NewNat().ExpandFor(m)
	one.limbs[0] = 1
	// Sub asks for x to be reduced modulo m, while SubOne doesn't, but when
	// y = 1, it works, and this is an internal use.
	return x.Sub(one, m)
}

// Add computes x = x + y mod m.
//
// The length of both operands must be the same as the modulus. Both operands
// must already be reduced modulo m.
//
//go:norace
func (x *Nat) Add(y *Nat, m *Modulus) *Nat {
	overflow := x.add(y)
	x.maybeSubtractModulus(choice(overflow), m)
	return x
}

// montgomeryRepresentation calculates x = x * R mod m, with R = 2^(_W * n) and
// n = len(m.nat.limbs).
//
// Faster Montgomery multiplication replaces standard modular multiplication for
// numbers in this representation.
//
// This assumes that x is already reduced mod m.
func (x *Nat) montgomeryRepresentation(m *Modulus) *Nat {
	// A Montgomery multiplication (which computes a * b / R) by R * R works out
	// to a multiplication by R, which takes the value out of the Montgomery domain.
	return x.montgomeryMul(x, m.rr, m)
}

// montgomeryReduction calculates x = x / R mod m, with R = 2^(_W * n) and
// n = len(m.nat.limbs).
//
// This assumes that x is already reduced mod m.
func (x *Nat) montgomeryReduction(m *Modulus) *Nat {
	// By Montgomery multiplying with 1 not in Montgomery representation, we
	// convert out back from Montgomery representation, because it works out to
	// dividing by R.
	one := NewNat().ExpandFor(m)
	one.limbs[0] = 1
	return x.montgomeryMul(x, one, m)
}

// montgomeryMul calculates x = a * b / R mod m, with R = 2^(_W * n) and
// n = len(m.nat.limbs), also known as a Montgomery multiplication.
//
// All inputs should be the same length and already reduced modulo m.
// x will be resized to the size of m and overwritten.
//
//go:norace
func (x *Nat) montgomeryMul(a *Nat, b *Nat, m *Modulus) *Nat {
	n := len(m.nat.limbs)
	mLimbs := m.nat.limbs[:n]
	aLimbs := a.limbs[:n]
	bLimbs := b.limbs[:n]

	switch n {
	default:
		// Attempt to use a stack-allocated backing array.
		T := make([]uint, 0, preallocLimbs*2)
		if cap(T) < n*2 {
			T = make([]uint, 0, n*2)
		}
		T = T[:n*2]

		// This loop implements Word-by-Word Montgomery Multiplication, as
		// described in Algorithm 4 (Fig. 3) of "Efficient Software
		// Implementations of Modular Exponentiation" by Shay Gueron
		// [https://eprint.iacr.org/2011/239.pdf].
		var c uint
		for i := 0; i < n; i++ {
			_ = T[n+i] // bounds check elimination hint

			// Step 1 (T = a × b) is computed as a large pen-and-paper column
			// multiplication of two numbers with n base-2^_W digits. If we just
			// wanted to produce 2n-wide T, we would do
			//
			//   for i := 0; i < n; i++ {
			//       d := bLimbs[i]
			//       T[n+i] = addMulVVW(T[i:n+i], aLimbs, d)
			//   }
			//
			// where d is a digit of the multiplier, T[i:n+i] is the shifted
			// position of the product of that digit, and T[n+i] is the final carry.
			// Note that T[i] isn't modified after processing the i-th digit.
			//
			// Instead of running two loops, one for Step 1 and one for Steps 2–6,
			// the result of Step 1 is computed during the next loop. This is
			// possible because each iteration only uses T[i] in Step 2 and then
			// discards it in Step 6.
			d := bLimbs[i]
			c1 := addMulVVW(T[i:n+i], aLimbs, d)

			// Step 6 is replaced by shifting the virtual window we operate
			// over: T of the algorithm is T[i:] for us. That means that T1 in
			// Step 2 (T mod 2^_W) is simply T[i]. k0 in Step 3 is our m0inv.
			Y := T[i] * m.m0inv

			// Step 4 and 5 add Y × m to T, which as mentioned above is stored
			// at T[i:]. The two carries (from a × d and Y × m) are added up in
			// the next word T[n+i], and the carry bit from that addition is
			// brought forward to the next iteration.
			c2 := addMulVVW(T[i:n+i], mLimbs, Y)
			T[n+i], c = bits.Add(c1, c2, c)
		}

		// Finally for Step 7 we copy the final T window into x, and subtract m
		// if necessary (which as explained in maybeSubtractModulus can be the
		// case both if x >= m, or if x overflowed).
		//
		// The paper suggests in Section 4 that we can do an "Almost Montgomery
		// Multiplication" by subtracting only in the overflow case, but the
		// cost is very similar since the constant time subtraction tells us if
		// x >= m as a side effect, and taking care of the broken invariant is
		// highly undesirable (see https://go.dev/issue/13907).
		copy(x.reset(n).limbs, T[n:])
		x.maybeSubtractModulus(choice(c), m)

	// The following specialized cases follow the exact same algorithm, but
	// optimized for the sizes most used in RSA. addMulVVW is implemented in
	// assembly with loop unrolling depending on the architecture and bounds
	// checks are removed by the compiler thanks to the constant size.
	case 1024 / _W:
		const n = 1024 / _W // compiler hint
		T := make([]uint, n*2)
		var c uint
		for i := 0; i < n; i++ {
			d := bLimbs[i]
			c1 := addMulVVW1024(&T[i], &aLimbs[0], d)
			Y := T[i] * m.m0inv
			c2 := addMulVVW1024(&T[i], &mLimbs[0], Y)
			T[n+i], c = bits.Add(c1, c2, c)
		}
		copy(x.reset(n).limbs, T[n:])
		x.maybeSubtractModulus(choice(c), m)

	case 1536 / _W:
		const n = 1536 / _W // compiler hint
		T := make([]uint, n*2)
		var c uint
		for i := 0; i < n; i++ {
			d := bLimbs[i]
			c1 := addMulVVW1536(&T[i], &aLimbs[0], d)
			Y := T[i] * m.m0inv
			c2 := addMulVVW1536(&T[i], &mLimbs[0], Y)
			T[n+i], c = bits.Add(c1, c2, c)
		}
		copy(x.reset(n).limbs, T[n:])
		x.maybeSubtractModulus(choice(c), m)

	case 2048 / _W:
		const n = 2048 / _W // compiler hint
		T := make([]uint, n*2)
		var c uint
		for i := 0; i < n; i++ {
			d := bLimbs[i]
			c1 := addMulVVW2048(&T[i], &aLimbs[0], d)
			Y := T[i] * m.m0inv
			c2 := addMulVVW2048(&T[i], &mLimbs[0], Y)
			T[n+i], c = bits.Add(c1, c2, c)
		}
		copy(x.reset(n).limbs, T[n:])
		x.maybeSubtractModulus(choice(c), m)
	}

	return x
}

// addMulVVW multiplies the multi-word value x by the single-word value y,
// adding the result to the multi-word value z and returning the final carry.
// It can be thought of as one row of a pen-and-paper column multiplication.
//
//go:norace
func addMulVVW(z, x []uint, y uint) (carry uint) {
	_ = x[len(z)-1] // bounds check elimination hint
	for i := range z {
		hi, lo := bits.Mul(x[i], y)
		lo, c := bits.Add(lo, z[i], 0)
		// We use bits.Add with zero to get an add-with-carry instruction that
		// absorbs the carry from the previous bits.Add.
		hi, _ = bits.Add(hi, 0, c)
		lo, c = bits.Add(lo, carry, 0)
		hi, _ = bits.Add(hi, 0, c)
		carry = hi
		z[i] = lo
	}
	return carry
}

// Mul calculates x = x * y mod m.
//
// The length of both operands must be the same as the modulus. Both operands
// must already be reduced modulo m.
//
//go:norace
func (x *Nat) Mul(y *Nat, m *Modulus) *Nat {
	if m.odd {
		// A Montgomery multiplication by a value out of the Montgomery domain
		// takes the result out of Montgomery representation.
		xR := NewNat().set(x).montgomeryRepresentation(m) // xR = x * R mod m
		return x.montgomeryMul(xR, y, m)                  // x = xR * y / R mod m
	}

	n := len(m.nat.limbs)
	xLimbs := x.limbs[:n]
	yLimbs := y.limbs[:n]

	switch n {
	default:
		// Attempt to use a stack-allocated backing array.
		T := make([]uint, 0, preallocLimbs*2)
		if cap(T) < n*2 {
			T = make([]uint, 0, n*2)
		}
		T = T[:n*2]

		// T = x * y
		for i := 0; i < n; i++ {
			T[n+i] = addMulVVW(T[i:n+i], xLimbs, yLimbs[i])
		}

		// x = T mod m
		return x.Mod(&Nat{limbs: T}, m)

	// The following specialized cases follow the exact same algorithm, but
	// optimized for the sizes most used in RSA. See montgomeryMul for details.
	case 1024 / _W:
		const n = 1024 / _W // compiler hint
		T := make([]uint, n*2)
		for i := 0; i < n; i++ {
			T[n+i] = addMulVVW1024(&T[i], &xLimbs[0], yLimbs[i])
		}
		return x.Mod(&Nat{limbs: T}, m)
	case 1536 / _W:
		const n = 1536 / _W // compiler hint
		T := make([]uint, n*2)
		for i := 0; i < n; i++ {
			T[n+i] = addMulVVW1536(&T[i], &xLimbs[0], yLimbs[i])
		}
		return x.Mod(&Nat{limbs: T}, m)
	case 2048 / _W:
		const n = 2048 / _W // compiler hint
		T := make([]uint, n*2)
		for i := 0; i < n; i++ {
			T[n+i] = addMulVVW2048(&T[i], &xLimbs[0], yLimbs[i])
		}
		return x.Mod(&Nat{limbs: T}, m)
	}
}

// Exp calculates out = x^e mod m.
//
// The exponent e is represented in big-endian order. The output will be resized
// to the size of m and overwritten. x must already be reduced modulo m.
//
// m must be odd, or Exp will panic.
//
//go:norace
func (out *Nat) Exp(x *Nat, e []byte, m *Modulus) *Nat {
	if !m.odd {
		panic("bigmod: modulus for Exp must be odd")
	}

	// We use a 4 bit window. For our RSA workload, 4 bit windows are faster
	// than 2 bit windows, but use an extra 12 nats worth of scratch space.
	// Using bit sizes that don't divide 8 are more complex to implement, but
	// are likely to be more efficient if necessary.

	table := [(1 << 4) - 1]*Nat{ // table[i] = x ^ (i+1)
		// newNat calls are unrolled so they are allocated on the stack.
		NewNat(), NewNat(), NewNat(), NewNat(), NewNat(),
		NewNat(), NewNat(), NewNat(), NewNat(), NewNat(),
		NewNat(), NewNat(), NewNat(), NewNat(), NewNat(),
	}
	table[0].set(x).montgomeryRepresentation(m)
	for i := 1; i < len(table); i++ {
		table[i].montgomeryMul(table[i-1], table[0], m)
	}

	out.resetFor(m)
	out.limbs[0] = 1
	out.montgomeryRepresentation(m)
	tmp := NewNat().ExpandFor(m)
	for _, b := range e {
		for _, j := range []int{4, 0} {
			// Square four times. Optimization note: this can be implemented
			// more efficiently than with generic Montgomery multiplication.
			out.montgomeryMul(out, out, m)
			out.montgomeryMul(out, out, m)
			out.montgomeryMul(out, out, m)
			out.montgomeryMul(out, out, m)

			// Select x^k in constant time from the table.
			k := uint((b >> j) & 0b1111)
			for i := range table {
				tmp.assign(ctEq(k, uint(i+1)), table[i])
			}

			// Multiply by x^k, discarding the result if k = 0.
			tmp.montgomeryMul(out, tmp, m)
			out.assign(not(ctEq(k, 0)), tmp)
		}
	}

	return out.montgomeryReduction(m)
}

// ExpShortVarTime calculates out = x^e mod m.
//
// The output will be resized to the size of m and overwritten. x must already
// be reduced modulo m. This leaks the exponent through timing side-channels.
//
// m must be odd, or ExpShortVarTime will panic.
func (out *Nat) ExpShortVarTime(x *Nat, e uint, m *Modulus) *Nat {
	if !m.odd {
		panic("bigmod: modulus for ExpShortVarTime must be odd")
	}
	// For short exponents, precomputing a table and using a window like in Exp
	// doesn't pay off. Instead, we do a simple conditional square-and-multiply
	// chain, skipping the initial run of zeroes.
	xR := NewNat().set(x).montgomeryRepresentation(m)
	out.set(xR)
	for i := bits.UintSize - bits.Len(e) + 1; i < bits.UintSize; i++ {
		out.montgomeryMul(out, out, m)
		if k := (e >> (bits.UintSize - i - 1)) & 1; k != 0 {
			out.montgomeryMul(out, xR, m)
		}
	}
	return out.montgomeryReduction(m)
}

// InverseVarTime calculates x = a⁻¹ mod m and returns (x, true) if a is
// invertible. Otherwise, InverseVarTime returns (x, false) and x is not
// modified.
//
// a must be reduced modulo m, but doesn't need to have the same size. The
// output will be resized to the size of m and overwritten.
//
//go:norace
func (x *Nat) InverseVarTime(a *Nat, m *Modulus) (*Nat, bool) {
	// This is the extended binary GCD algorithm described in the Handbook of
	// Applied Cryptography, Algorithm 14.61, adapted by BoringSSL to bound
	// coefficients and avoid negative numbers. For more details and proof of
	// correctness, see https://github.com/mit-plv/fiat-crypto/pull/333/files.
	//
	// Following the proof linked in the PR above, the changes are:
	//
	// 1. Negate [B] and [C] so they are positive. The invariant now involves a
	//    subtraction.
	// 2. If step 2 (both [x] and [y] are even) runs, abort immediately. This
	//    algorithm only cares about [x] and [y] relatively prime.
	// 3. Subtract copies of [x] and [y] as needed in step 6 (both [u] and [v]
	//    are odd) so coefficients stay in bounds.
	// 4. Replace the [u >= v] check with [u > v]. This changes the end
	//    condition to [v = 0] rather than [u = 0]. This saves an extra
	//    subtraction due to which coefficients were negated.
	// 5. Rename x and y to a and n, to capture that one is a modulus.
	// 6. Rearrange steps 4 through 6 slightly. Merge the loops in steps 4 and
	//    5 into the main loop (step 7's goto), and move step 6 to the start of
	//    the loop iteration, ensuring each loop iteration halves at least one
	//    value.
	//
	// Note this algorithm does not handle either input being zero.

	if a.IsZero() == yes {
		return x, false
	}
	if a.IsOdd() == no && !m.odd {
		// a and m are not coprime, as they are both even.
		return x, false
	}

	u := NewNat().set(a).ExpandFor(m)
	v := m.Nat()

	A := NewNat().reset(len(m.nat.limbs))
	A.limbs[0] = 1
	B := NewNat().reset(len(a.limbs))
	C := NewNat().reset(len(m.nat.limbs))
	D := NewNat().reset(len(a.limbs))
	D.limbs[0] = 1

	// Before and after each loop iteration, the following hold:
	//
	//   u = A*a - B*m
	//   v = D*m - C*a
	//   0 < u <= a
	//   0 <= v <= m
	//   0 <= A < m
	//   0 <= B <= a
	//   0 <= C < m
	//   0 <= D <= a
	//
	// After each loop iteration, u and v only get smaller, and at least one of
	// them shrinks by at least a factor of two.
	for {
		// If both u and v are odd, subtract the smaller from the larger.
		// If u = v, we need to subtract from v to hit the modified exit condition.
		if u.IsOdd() == yes && v.IsOdd() == yes {
			if v.cmpGeq(u) == no {
				u.sub(v)
				A.Add(C, m)
				B.Add(D, &Modulus{nat: a})
			} else {
				v.sub(u)
				C.Add(A, m)
				D.Add(B, &Modulus{nat: a})
			}
		}

		// Exactly one of u and v is now even.
		if u.IsOdd() == v.IsOdd() {
			panic("bigmod: internal error: u and v are not in the expected state")
		}

		// Halve the even one and adjust the corresponding coefficient.
		if u.IsOdd() == no {
			rshift1(u, 0)
			if A.IsOdd() == yes || B.IsOdd() == yes {
				rshift1(A, A.add(m.nat))
				rshift1(B, B.add(a))
			} else {
				rshift1(A, 0)
				rshift1(B, 0)
			}
		} else { // v.IsOdd() == no
			rshift1(v, 0)
			if C.IsOdd() == yes || D.IsOdd() == yes {
				rshift1(C, C.add(m.nat))
				rshift1(D, D.add(a))
			} else {
				rshift1(C, 0)
				rshift1(D, 0)
			}
		}

		if v.IsZero() == yes {
			if u.IsOne() == no {
				return x, false
			}
			return x.set(A), true
		}
	}
}

//go:norace
func rshift1(a *Nat, carry uint) {
	size := len(a.limbs)
	aLimbs := a.limbs[:size]

	for i := range size {
		aLimbs[i] >>= 1
		if i+1 < size {
			aLimbs[i] |= aLimbs[i+1] << (_W - 1)
		} else {
			aLimbs[i] |= carry << (_W - 1)
		}
	}
}
```