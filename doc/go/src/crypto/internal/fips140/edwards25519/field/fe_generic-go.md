Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Reading and Identifying Core Functionality:**

First, I'd read through the code to get a general sense of what it's doing. I'd notice keywords like `mul64`, `addMul64`, `shiftRightBy51`, `feMulGeneric`, `feSquareGeneric`, and `carryPropagateGeneric`. The comments mentioning "limbs," "multiplication," "squaring," and "reduction identity" (a * 2²⁵⁵ + b = a * 19 + b) are strong hints. The `uint128` struct also suggests dealing with large numbers.

**2. Focusing on Key Functions:**

I'd then focus on the main functions:

* **`mul64`, `addMul64`, `shiftRightBy51`:** These seem like low-level helper functions for manipulating 64-bit integers, potentially for performing arithmetic on larger numbers. `mul64` and `addMul64` are clearly related to multiplication. `shiftRightBy51` suggests handling bitwise operations and might be related to modular arithmetic or carrying.

* **`feMulGeneric`:** The name strongly suggests a generic function for field element multiplication. The detailed comments about "pen-and-paper columnar multiplication" and the reduction identity confirm this. The variables `a0` to `a4` and `b0` to `b4` likely represent the "limbs" of the field elements being multiplied.

* **`feSquareGeneric`:** Similar to `feMulGeneric`, this is likely for squaring a field element. The comment about symmetry reinforces this.

* **`carryPropagateGeneric`:** This function appears to be for normalizing the "limbs" of a field element after an operation, ensuring they stay within a certain range.

**3. Understanding the Underlying Math (or Cryptographic Context):**

The comment `// We can then use the reduction identity (a * 2²⁵⁵ + b = a * 19 + b)` is crucial. This immediately points towards modular arithmetic in a field where 2²⁵⁵ is congruent to 19. This is a strong indicator that the code is related to the Edwards25519 elliptic curve, which is known to use this reduction. The "limbs" likely represent the coefficients of a polynomial representation of a field element. The 51-bit size of the limbs is also characteristic of optimized implementations of this curve.

**4. Reconstructing the Big Picture:**

Based on the function names and the reduction identity, I would infer that the code is implementing arithmetic operations (multiplication and squaring) in the finite field used by the Edwards25519 elliptic curve. The "generic" suffix might indicate that this is a less optimized version, potentially used for clarity or when specific optimizations aren't necessary.

**5. Illustrative Code Examples:**

To demonstrate the functionality, I would create simple examples that use the provided functions. Since the `Element` struct and its internal representation are central, an example of how to create and multiply two `Element` values would be most effective. I'd also demonstrate the carry propagation.

* **Multiplication Example:** Create two `Element` instances, call `feMulGeneric`, and show the result. Since the internal structure of `Element` is important, I'd need to make an educated guess about how to populate its fields, or rely on existing knowledge of the Edwards25519 field representation. I'd use small, easily manageable values for the input to make manual verification possible.

* **Squaring Example:**  Similar to multiplication, but call `feSquareGeneric`.

* **Carry Propagation Example:** Create an `Element` with values exceeding the 51-bit limit, call `carryPropagateGeneric`, and show the normalized result.

**6. Identifying Potential Pitfalls:**

I would consider what assumptions the code makes and where users might go wrong.

* **Incorrectly initializing `Element`:**  The internal structure of `Element` (the five `uint64` fields) is crucial. Users need to understand that these represent the limbs of the field element. Directly assigning arbitrary values without understanding the 51-bit constraint could lead to incorrect results before carry propagation.

* **Ignoring `carryPropagateGeneric`:** After multiplication or squaring, the limbs might exceed the 51-bit limit. Forgetting to call `carryPropagateGeneric` would leave the `Element` in an invalid state for further operations.

**7. Command-line Arguments and Deeper Dive (If Applicable):**

Since the provided code snippet doesn't involve command-line arguments or interact with external systems, this part of the prompt is not relevant to this specific code. If the code *did* involve command-line arguments (e.g., for specifying input values), I would analyze how the `flag` package or `os.Args` is used to parse and handle them.

**8. Refinement and Explanation:**

Finally, I would organize my findings into a clear and structured answer, using the requested format (Chinese). I would explain the purpose of each function, provide illustrative code examples with hypothetical inputs and outputs, and highlight potential pitfalls. The key is to connect the code with the underlying mathematical concept of finite field arithmetic used in elliptic curve cryptography.

This iterative process of reading, analyzing, inferring, and testing (even mentally for simple examples) allows for a comprehensive understanding of the code's functionality.
这段Go语言代码是 `crypto/internal/fips140/edwards25519/field/fe_generic.go` 文件的一部分，它实现了一个**有限域上的元素进行通用乘法和平方运算的功能，以及一个通用的进位传播（carry propagation）方法。** 这个有限域是用于 Edwards25519 椭圆曲线密码学的。

更具体地说，它实现了以下功能：

1. **`uint128` 结构体:**  定义了一个表示 128 位无符号整数的结构体，由两个 64 位的部分组成 (`lo` 和 `hi`)。这主要用于高效地进行 64 位整数的乘法运算。

2. **`mul64(a, b uint64) uint128` 函数:**  计算两个 64 位无符号整数 `a` 和 `b` 的乘积，并将结果作为一个 `uint128` 结构体返回。它使用了 `math/bits` 包中的 `Mul64` 函数。

3. **`addMul64(v uint128, a, b uint64) uint128` 函数:** 计算 `v + a * b`，其中 `v` 是一个 `uint128`，`a` 和 `b` 是 64 位无符号整数。它高效地将乘法结果加到 `uint128` 上，并处理进位。

4. **`shiftRightBy51(a uint128) uint64` 函数:**  将一个 `uint128` 类型的 `a` 右移 51 位。  这里假设 `a` 的值最多为 115 位。这个操作在有限域乘法后进行归约时用于提取进位。

5. **`feMulGeneric(v, a, b *Element)` 函数:**  实现了有限域元素的通用乘法。它将两个 `Element` 类型的 `a` 和 `b` 相乘，并将结果存储到 `v` 中。
   - `Element` 类型（未在此代码片段中定义，但可以推断出它由五个 51 位的 "limbs" 组成）表示有限域中的一个元素。
   - 该函数使用了类似于手算乘法的列式乘法方法，将 `a` 和 `b` 的五个 "limbs" 分别相乘。
   - 它还利用了 Edwards25519 曲线的模数特性 (2²⁵⁵ - 19 = 0 mod p)，通过将高位的乘积乘以 19 并加到低位来执行归约。
   -  计算过程涉及到多个 `mul64` 和 `addMul64` 操作来计算中间结果，然后使用 `shiftRightBy51` 来提取进位。
   - 最后，通过加法和移位操作将结果归约到 `Element` 的表示范围内。

6. **`feSquareGeneric(v, a *Element)` 函数:** 实现了有限域元素的通用平方运算。它将 `Element` 类型的 `a` 自乘，并将结果存储到 `v` 中。
   - 该函数的实现类似于 `feMulGeneric`，但由于是平方运算，所以可以利用对称性来优化计算。

7. **`(v *Element).carryPropagateGeneric() *Element` 函数:**  实现了有限域元素的通用进位传播。它将 `Element` `v` 的各个 "limbs" 中的进位传播到更高的 "limbs"，并利用模数特性将最高位的进位归约到最低位。
   - 这个函数确保 `Element` 的每个 "limb" 都小于其上限（稍大于 2⁵¹），从而维持 `Element` 的内部表示一致性。

**它是什么Go语言功能的实现？**

这段代码主要实现了**高性能的、针对特定有限域的算术运算**。它利用了 Go 语言的以下特性：

* **结构体 (`struct`)**: 用于定义 `uint128` 和 `Element` 这样的复合数据类型。
* **函数 (`func`)**: 用于封装不同的操作，如乘法、加法、移位和进位传播。
* **方法 (`(v *Element).carryPropagateGeneric()`)**:  用于定义与特定类型关联的操作。
* **内置的 `math/bits` 包**:  提供了底层的位操作函数，如 `Mul64` 和 `Add64`，用于高效地进行 64 位整数的算术运算。

**Go 代码举例说明:**

由于 `Element` 类型的定义不在提供的代码片段中，我们需要假设它的结构。假设 `Element` 定义如下：

```go
type Element struct {
	l0 uint64
	l1 uint64
	l2 uint64
	l3 uint64
	l4 uint64
}
```

**`feMulGeneric` 示例:**

```go
package main

import (
	"fmt"
	"math/bits"
)

// uint128 holds a 128-bit number as two 64-bit limbs, for use with the
// bits.Mul64 and bits.Add64 intrinsics.
type uint128 struct {
	lo, hi uint64
}

// mul64 returns a * b.
func mul64(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	return uint128{lo, hi}
}

// addMul64 returns v + a * b.
func addMul64(v uint128, a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	lo, c := bits.Add64(lo, v.lo, 0)
	hi, _ = bits.Add64(hi, v.hi, c)
	return uint128{lo, hi}
}

// shiftRightBy51 returns a >> 51. a is assumed to be at most 115 bits.
func shiftRightBy51(a uint128) uint64 {
	return (a.hi << (64 - 51)) | (a.lo >> 51)
}

type Element struct {
	l0 uint64
	l1 uint64
	l2 uint64
	l3 uint64
	l4 uint64
}

func feMulGeneric(v, a, b *Element) {
	// ... (feMulGeneric 的代码) ...
	a0 := a.l0
	a1 := a.l1
	a2 := a.l2
	a3 := a.l3
	a4 := a.l4

	b0 := b.l0
	b1 := b.l1
	b2 := b.l2
	b3 := b.l3
	b4 := b.l4

	a1_19 := a1 * 19
	a2_19 := a2 * 19
	a3_19 := a3 * 19
	a4_19 := a4 * 19

	r0 := mul64(a0, b0)
	r0 = addMul64(r0, a1_19, b4)
	r0 = addMul64(r0, a2_19, b3)
	r0 = addMul64(r0, a3_19, b2)
	r0 = addMul64(r0, a4_19, b1)

	r1 := mul64(a0, b1)
	r1 = addMul64(r1, a1, b0)
	r1 = addMul64(r1, a2_19, b4)
	r1 = addMul64(r1, a3_19, b3)
	r1 = addMul64(r1, a4_19, b2)

	r2 := mul64(a0, b2)
	r2 = addMul64(r2, a1, b1)
	r2 = addMul64(r2, a2, b0)
	r2 = addMul64(r2, a3_19, b4)
	r2 = addMul64(r2, a4_19, b3)

	r3 := mul64(a0, b3)
	r3 = addMul64(r3, a1, b2)
	r3 = addMul64(r3, a2, b1)
	r3 = addMul64(r3, a3, b0)
	r3 = addMul64(r3, a4_19, b4)

	r4 := mul64(a0, b4)
	r4 = addMul64(r4, a1, b3)
	r4 = addMul64(r4, a2, b2)
	r4 = addMul64(r4, a3, b1)
	r4 = addMul64(r4, a4, b0)

	maskLow51Bits := uint64(1<<51 - 1)

	c0 := shiftRightBy51(r0)
	c1 := shiftRightBy51(r1)
	c2 := shiftRightBy51(r2)
	c3 := shiftRightBy51(r3)
	c4 := shiftRightBy51(r4)

	rr0 := r0.lo&maskLow51Bits + c4*19
	rr1 := r1.lo&maskLow51Bits + c0
	rr2 := r2.lo&maskLow51Bits + c1
	rr3 := r3.lo&maskLow51Bits + c2
	rr4 := r4.lo&maskLow51Bits + c3

	*v = Element{rr0, rr1, rr2, rr3, rr4}
	v.carryPropagate()
}

func (v *Element) carryPropagate() *Element {
	maskLow51Bits := uint64(1<<51 - 1)
	c0 := v.l0 >> 51
	c1 := v.l1 >> 51
	c2 := v.l2 >> 51
	c3 := v.l3 >> 51
	c4 := v.l4 >> 51

	v.l0 = v.l0&maskLow51Bits + c4*19
	v.l1 = v.l1&maskLow51Bits + c0
	v.l2 = v.l2&maskLow51Bits + c1
	v.l3 = v.l3&maskLow51Bits + c2
	v.l4 = v.l4&maskLow51Bits + c3
	return v
}

func main() {
	a := Element{l0: 3, l1: 5, l2: 7, l3: 9, l4: 11}
	b := Element{l0: 2, l1: 4, l2: 6, l3: 8, l4: 10}
	result := Element{}

	feMulGeneric(&result, &a, &b)
	fmt.Printf("Result of multiplication: %+v\n", result)
}
```

**假设的输入与输出:**

在上面的 `feMulGeneric` 示例中，我们假设输入 `a` 和 `b` 的 "limbs" 是一些小的整数。  实际的 Edwards25519 实现中，这些 "limbs" 是 51 位的。

**假设输入:**
```
a = {l0: 3, l1: 5, l2: 7, l3: 9, l4: 11}
b = {l0: 2, l1: 4, l2: 6, l3: 8, l4: 10}
```

**可能的输出 (需要实际运行代码才能得到精确结果):**

输出将是一个 `Element` 结构体，其 `l0` 到 `l4` 的值是乘法结果经过归约和进位传播后的值。由于计算较为复杂，手动计算输出比较困难。 运行上述代码会得到具体的输出结果。

**`feSquareGeneric` 示例:**

```go
package main

import (
	"fmt"
	"math/bits"
)

// ... (uint128, mul64, addMul64, shiftRightBy51, Element 的定义) ...

func feSquareGeneric(v, a *Element) {
	// ... (feSquareGeneric 的代码) ...
	l0 := a.l0
	l1 := a.l1
	l2 := a.l2
	l3 := a.l3
	l4 := a.l4

	l0_2 := l0 * 2
	l1_2 := l1 * 2

	l1_38 := l1 * 38
	l2_38 := l2 * 38
	l3_38 := l3 * 38

	l3_19 := l3 * 19
	l4_19 := l4 * 19

	r0 := mul64(l0, l0)
	r0 = addMul64(r0, l1_38, l4)
	r0 = addMul64(r0, l2_38, l3)

	r1 := mul64(l0_2, l1)
	r1 = addMul64(r1, l2_38, l4)
	r1 = addMul64(r1, l3_19, l3)

	r2 := mul64(l0_2, l2)
	r2 = addMul64(r2, l1, l1)
	r2 = addMul64(r2, l3_38, l4)

	r3 := mul64(l0_2, l3)
	r3 = addMul64(r3, l1_2, l2)
	r3 = addMul64(r3, l4_19, l4)

	r4 := mul64(l0_2, l4)
	r4 = addMul64(r4, l1_2, l3)
	r4 = addMul64(r4, l2, l2)

	maskLow51Bits := uint64(1<<51 - 1)

	c0 := shiftRightBy51(r0)
	c1 := shiftRightBy51(r1)
	c2 := shiftRightBy51(r2)
	c3 := shiftRightBy51(r3)
	c4 := shiftRightBy51(r4)

	rr0 := r0.lo&maskLow51Bits + c4*19
	rr1 := r1.lo&maskLow51Bits + c0
	rr2 := r2.lo&maskLow51Bits + c1
	rr3 := r3.lo&maskLow51Bits + c2
	rr4 := r4.lo&maskLow51Bits + c3

	*v = Element{rr0, rr1, rr2, rr3, rr4}
	v.carryPropagate()
}

func main() {
	a := Element{l0: 3, l1: 5, l2: 7, l3: 9, l4: 11}
	result := Element{}

	feSquareGeneric(&result, &a)
	fmt.Printf("Result of squaring: %+v\n", result)
}
```

**假设的输入与输出:**

**假设输入:**
```
a = {l0: 3, l1: 5, l2: 7, l3: 9, l4: 11}
```

**可能的输出 (需要实际运行代码才能得到精确结果):**

输出将是 `a` 的平方经过归约和进位传播后的 `Element` 结构体。

**命令行参数的具体处理:**

这段代码片段本身不涉及任何命令行参数的处理。它只是实现了底层的算术运算。如果上层代码需要处理命令行参数来指定要操作的有限域元素，它可能会使用 Go 语言的 `flag` 包或者直接解析 `os.Args`。

**使用者易犯错的点:**

1. **不理解 `Element` 的内部表示:** 使用者需要理解 `Element` 结构体是由五个 51 位的 "limbs" 组成的，并且这些 "limbs" 的值的范围需要符合特定的约束。直接赋值超出范围的值可能会导致不正确的结果。

   **例如:** 如果直接创建一个 `Element`，其某个 `l` 字段的值大于 `(1 << 51) - 1`，那么在进行乘法或平方运算之前，可能就需要进行额外的处理或确保调用 `carryPropagateGeneric`。

2. **忘记调用 `carryPropagateGeneric`:** 在 `feMulGeneric` 或 `feSquareGeneric` 执行后，结果的 "limbs" 可能大于 51 位。忘记调用 `carryPropagateGeneric` 来进行进位传播和归约，会导致后续使用这个结果进行计算时得到错误的结果。

   **例如:**
   ```go
   package main

   import "fmt"
   // ... (其他代码) ...

   func main() {
       a := Element{l0: (1 << 51) + 1, l1: 0, l2: 0, l3: 0, l4: 0} // l0 超出 51 位
       b := Element{l0: 1, l1: 0, l2: 0, l3: 0, l4: 0}
       result := Element{}
       feMulGeneric(&result, &a, &b)
       fmt.Printf("Result without carry propagate: %+v\n", result) // 结果可能不符合预期

       result.carryPropagate()
       fmt.Printf("Result with carry propagate: %+v\n", result) // 正确的结果
   }
   ```

总而言之，这段代码是 Edwards25519 曲线密码学中有限域算术运算的关键组成部分，它通过精细的位操作和优化的算法实现了高效的乘法和平方运算，并确保结果始终保持在正确的表示范围内。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/edwards25519/field/fe_generic.go的go语言实现的一部分， 请列举一下它的功能, 　
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

import "math/bits"

// uint128 holds a 128-bit number as two 64-bit limbs, for use with the
// bits.Mul64 and bits.Add64 intrinsics.
type uint128 struct {
	lo, hi uint64
}

// mul64 returns a * b.
func mul64(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	return uint128{lo, hi}
}

// addMul64 returns v + a * b.
func addMul64(v uint128, a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	lo, c := bits.Add64(lo, v.lo, 0)
	hi, _ = bits.Add64(hi, v.hi, c)
	return uint128{lo, hi}
}

// shiftRightBy51 returns a >> 51. a is assumed to be at most 115 bits.
func shiftRightBy51(a uint128) uint64 {
	return (a.hi << (64 - 51)) | (a.lo >> 51)
}

func feMulGeneric(v, a, b *Element) {
	a0 := a.l0
	a1 := a.l1
	a2 := a.l2
	a3 := a.l3
	a4 := a.l4

	b0 := b.l0
	b1 := b.l1
	b2 := b.l2
	b3 := b.l3
	b4 := b.l4

	// Limb multiplication works like pen-and-paper columnar multiplication, but
	// with 51-bit limbs instead of digits.
	//
	//                          a4   a3   a2   a1   a0  x
	//                          b4   b3   b2   b1   b0  =
	//                         ------------------------
	//                        a4b0 a3b0 a2b0 a1b0 a0b0  +
	//                   a4b1 a3b1 a2b1 a1b1 a0b1       +
	//              a4b2 a3b2 a2b2 a1b2 a0b2            +
	//         a4b3 a3b3 a2b3 a1b3 a0b3                 +
	//    a4b4 a3b4 a2b4 a1b4 a0b4                      =
	//   ----------------------------------------------
	//      r8   r7   r6   r5   r4   r3   r2   r1   r0
	//
	// We can then use the reduction identity (a * 2²⁵⁵ + b = a * 19 + b) to
	// reduce the limbs that would overflow 255 bits. r5 * 2²⁵⁵ becomes 19 * r5,
	// r6 * 2³⁰⁶ becomes 19 * r6 * 2⁵¹, etc.
	//
	// Reduction can be carried out simultaneously to multiplication. For
	// example, we do not compute r5: whenever the result of a multiplication
	// belongs to r5, like a1b4, we multiply it by 19 and add the result to r0.
	//
	//            a4b0    a3b0    a2b0    a1b0    a0b0  +
	//            a3b1    a2b1    a1b1    a0b1 19×a4b1  +
	//            a2b2    a1b2    a0b2 19×a4b2 19×a3b2  +
	//            a1b3    a0b3 19×a4b3 19×a3b3 19×a2b3  +
	//            a0b4 19×a4b4 19×a3b4 19×a2b4 19×a1b4  =
	//           --------------------------------------
	//              r4      r3      r2      r1      r0
	//
	// Finally we add up the columns into wide, overlapping limbs.

	a1_19 := a1 * 19
	a2_19 := a2 * 19
	a3_19 := a3 * 19
	a4_19 := a4 * 19

	// r0 = a0×b0 + 19×(a1×b4 + a2×b3 + a3×b2 + a4×b1)
	r0 := mul64(a0, b0)
	r0 = addMul64(r0, a1_19, b4)
	r0 = addMul64(r0, a2_19, b3)
	r0 = addMul64(r0, a3_19, b2)
	r0 = addMul64(r0, a4_19, b1)

	// r1 = a0×b1 + a1×b0 + 19×(a2×b4 + a3×b3 + a4×b2)
	r1 := mul64(a0, b1)
	r1 = addMul64(r1, a1, b0)
	r1 = addMul64(r1, a2_19, b4)
	r1 = addMul64(r1, a3_19, b3)
	r1 = addMul64(r1, a4_19, b2)

	// r2 = a0×b2 + a1×b1 + a2×b0 + 19×(a3×b4 + a4×b3)
	r2 := mul64(a0, b2)
	r2 = addMul64(r2, a1, b1)
	r2 = addMul64(r2, a2, b0)
	r2 = addMul64(r2, a3_19, b4)
	r2 = addMul64(r2, a4_19, b3)

	// r3 = a0×b3 + a1×b2 + a2×b1 + a3×b0 + 19×a4×b4
	r3 := mul64(a0, b3)
	r3 = addMul64(r3, a1, b2)
	r3 = addMul64(r3, a2, b1)
	r3 = addMul64(r3, a3, b0)
	r3 = addMul64(r3, a4_19, b4)

	// r4 = a0×b4 + a1×b3 + a2×b2 + a3×b1 + a4×b0
	r4 := mul64(a0, b4)
	r4 = addMul64(r4, a1, b3)
	r4 = addMul64(r4, a2, b2)
	r4 = addMul64(r4, a3, b1)
	r4 = addMul64(r4, a4, b0)

	// After the multiplication, we need to reduce (carry) the five coefficients
	// to obtain a result with limbs that are at most slightly larger than 2⁵¹,
	// to respect the Element invariant.
	//
	// Overall, the reduction works the same as carryPropagate, except with
	// wider inputs: we take the carry for each coefficient by shifting it right
	// by 51, and add it to the limb above it. The top carry is multiplied by 19
	// according to the reduction identity and added to the lowest limb.
	//
	// The largest coefficient (r0) will be at most 111 bits, which guarantees
	// that all carries are at most 111 - 51 = 60 bits, which fits in a uint64.
	//
	//     r0 = a0×b0 + 19×(a1×b4 + a2×b3 + a3×b2 + a4×b1)
	//     r0 < 2⁵²×2⁵² + 19×(2⁵²×2⁵² + 2⁵²×2⁵² + 2⁵²×2⁵² + 2⁵²×2⁵²)
	//     r0 < (1 + 19 × 4) × 2⁵² × 2⁵²
	//     r0 < 2⁷ × 2⁵² × 2⁵²
	//     r0 < 2¹¹¹
	//
	// Moreover, the top coefficient (r4) is at most 107 bits, so c4 is at most
	// 56 bits, and c4 * 19 is at most 61 bits, which again fits in a uint64 and
	// allows us to easily apply the reduction identity.
	//
	//     r4 = a0×b4 + a1×b3 + a2×b2 + a3×b1 + a4×b0
	//     r4 < 5 × 2⁵² × 2⁵²
	//     r4 < 2¹⁰⁷
	//

	c0 := shiftRightBy51(r0)
	c1 := shiftRightBy51(r1)
	c2 := shiftRightBy51(r2)
	c3 := shiftRightBy51(r3)
	c4 := shiftRightBy51(r4)

	rr0 := r0.lo&maskLow51Bits + c4*19
	rr1 := r1.lo&maskLow51Bits + c0
	rr2 := r2.lo&maskLow51Bits + c1
	rr3 := r3.lo&maskLow51Bits + c2
	rr4 := r4.lo&maskLow51Bits + c3

	// Now all coefficients fit into 64-bit registers but are still too large to
	// be passed around as an Element. We therefore do one last carry chain,
	// where the carries will be small enough to fit in the wiggle room above 2⁵¹.
	*v = Element{rr0, rr1, rr2, rr3, rr4}
	v.carryPropagate()
}

func feSquareGeneric(v, a *Element) {
	l0 := a.l0
	l1 := a.l1
	l2 := a.l2
	l3 := a.l3
	l4 := a.l4

	// Squaring works precisely like multiplication above, but thanks to its
	// symmetry we get to group a few terms together.
	//
	//                          l4   l3   l2   l1   l0  x
	//                          l4   l3   l2   l1   l0  =
	//                         ------------------------
	//                        l4l0 l3l0 l2l0 l1l0 l0l0  +
	//                   l4l1 l3l1 l2l1 l1l1 l0l1       +
	//              l4l2 l3l2 l2l2 l1l2 l0l2            +
	//         l4l3 l3l3 l2l3 l1l3 l0l3                 +
	//    l4l4 l3l4 l2l4 l1l4 l0l4                      =
	//   ----------------------------------------------
	//      r8   r7   r6   r5   r4   r3   r2   r1   r0
	//
	//            l4l0    l3l0    l2l0    l1l0    l0l0  +
	//            l3l1    l2l1    l1l1    l0l1 19×l4l1  +
	//            l2l2    l1l2    l0l2 19×l4l2 19×l3l2  +
	//            l1l3    l0l3 19×l4l3 19×l3l3 19×l2l3  +
	//            l0l4 19×l4l4 19×l3l4 19×l2l4 19×l1l4  =
	//           --------------------------------------
	//              r4      r3      r2      r1      r0
	//
	// With precomputed 2×, 19×, and 2×19× terms, we can compute each limb with
	// only three Mul64 and four Add64, instead of five and eight.

	l0_2 := l0 * 2
	l1_2 := l1 * 2

	l1_38 := l1 * 38
	l2_38 := l2 * 38
	l3_38 := l3 * 38

	l3_19 := l3 * 19
	l4_19 := l4 * 19

	// r0 = l0×l0 + 19×(l1×l4 + l2×l3 + l3×l2 + l4×l1) = l0×l0 + 19×2×(l1×l4 + l2×l3)
	r0 := mul64(l0, l0)
	r0 = addMul64(r0, l1_38, l4)
	r0 = addMul64(r0, l2_38, l3)

	// r1 = l0×l1 + l1×l0 + 19×(l2×l4 + l3×l3 + l4×l2) = 2×l0×l1 + 19×2×l2×l4 + 19×l3×l3
	r1 := mul64(l0_2, l1)
	r1 = addMul64(r1, l2_38, l4)
	r1 = addMul64(r1, l3_19, l3)

	// r2 = l0×l2 + l1×l1 + l2×l0 + 19×(l3×l4 + l4×l3) = 2×l0×l2 + l1×l1 + 19×2×l3×l4
	r2 := mul64(l0_2, l2)
	r2 = addMul64(r2, l1, l1)
	r2 = addMul64(r2, l3_38, l4)

	// r3 = l0×l3 + l1×l2 + l2×l1 + l3×l0 + 19×l4×l4 = 2×l0×l3 + 2×l1×l2 + 19×l4×l4
	r3 := mul64(l0_2, l3)
	r3 = addMul64(r3, l1_2, l2)
	r3 = addMul64(r3, l4_19, l4)

	// r4 = l0×l4 + l1×l3 + l2×l2 + l3×l1 + l4×l0 = 2×l0×l4 + 2×l1×l3 + l2×l2
	r4 := mul64(l0_2, l4)
	r4 = addMul64(r4, l1_2, l3)
	r4 = addMul64(r4, l2, l2)

	c0 := shiftRightBy51(r0)
	c1 := shiftRightBy51(r1)
	c2 := shiftRightBy51(r2)
	c3 := shiftRightBy51(r3)
	c4 := shiftRightBy51(r4)

	rr0 := r0.lo&maskLow51Bits + c4*19
	rr1 := r1.lo&maskLow51Bits + c0
	rr2 := r2.lo&maskLow51Bits + c1
	rr3 := r3.lo&maskLow51Bits + c2
	rr4 := r4.lo&maskLow51Bits + c3

	*v = Element{rr0, rr1, rr2, rr3, rr4}
	v.carryPropagate()
}

// carryPropagateGeneric brings the limbs below 52 bits by applying the reduction
// identity (a * 2²⁵⁵ + b = a * 19 + b) to the l4 carry.
func (v *Element) carryPropagateGeneric() *Element {
	c0 := v.l0 >> 51
	c1 := v.l1 >> 51
	c2 := v.l2 >> 51
	c3 := v.l3 >> 51
	c4 := v.l4 >> 51

	// c4 is at most 64 - 51 = 13 bits, so c4*19 is at most 18 bits, and
	// the final l0 will be at most 52 bits. Similarly for the rest.
	v.l0 = v.l0&maskLow51Bits + c4*19
	v.l1 = v.l1&maskLow51Bits + c0
	v.l2 = v.l2&maskLow51Bits + c1
	v.l3 = v.l3&maskLow51Bits + c2
	v.l4 = v.l4&maskLow51Bits + c3

	return v
}
```