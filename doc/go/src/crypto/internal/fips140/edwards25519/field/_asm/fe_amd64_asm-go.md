Response:
Let's break down the thought process for analyzing the given Go assembly generation code.

1. **Understanding the Context:** The first step is to recognize the filename and package path: `go/src/crypto/internal/fips140/edwards25519/field/_asm/fe_amd64_asm.go`. This immediately tells us a few key things:
    * **Cryptography:** The `crypto` package indicates cryptographic operations.
    * **Specific Algorithm:** `edwards25519` points to the Edwards-curve Digital Signature Algorithm.
    * **Field Arithmetic:** `field` suggests this code is likely related to performing arithmetic operations within a finite field, a common concept in elliptic curve cryptography.
    * **Assembly Generation:** `_asm` and `fe_amd64_asm.go` strongly imply this code generates assembly language instructions specifically for the AMD64 architecture.
    * **FIPS 140:**  The `fips140` part suggests this implementation aims to comply with the Federal Information Processing Standard Publication 140, a US government standard for cryptographic modules. This often implies stricter requirements and optimizations.

2. **Initial Code Scan - Identifying Key Components:**  Quickly scan the code to identify major elements:
    * **`package main` and `import` statements:** Standard Go structure, importing necessary libraries. Notice `github.com/mmcloughlin/avo/build`, `avo/gotypes`, `avo/operand`, and `avo/reg`. This immediately signals the use of the `avo` library for assembly generation.
    * **`//go:generate` directive:** This indicates how the assembly code is generated. `go run . -out ../fe_amd64.s -stubs ../fe_amd64.go -pkg field` shows the command to execute this code, outputting an assembly file (`fe_amd64.s`) and Go stub file (`fe_amd64.go`).
    * **`func main()`:** The entry point, responsible for setting up the package, constraints, and calling the functions that generate the assembly for specific field operations.
    * **`feMul()` and `feSquare()`:** These are clearly functions that generate assembly code for field multiplication and squaring operations, respectively. The `Doc` comments confirm this.
    * **Helper functions:** `namedComponent`, `uint128`, `mul64`, `addMul64`, `shiftRightBy51`, `maskAndAdd`, `mustAddr`. These suggest the underlying mathematical operations and data structures involved. `uint128` particularly points towards handling larger intermediate results.

3. **Analyzing `feSquare()` and `feMul()`:** Focus on these core functions.
    * **Input Parameters:**  Both take `out`, `a`, and optionally `b` as parameters of type `*Element`. This `Element` type likely represents an element in the finite field.
    * **Dereferencing and Field Access:**  `Dereference(Param("a")).Field("l0")` shows how to access the individual components of the `Element`. The names `l0`, `l1`, `l2`, `l3`, `l4` suggest a representation of the field element with five 64-bit limbs (likely representing a number modulo a large prime).
    * **Mathematical Operations:** The code performs a series of multiplications and additions. The comments like `r0 = l0×l0 + 19×2×(l1×l4 + l2×l3)` give away the exact mathematical formula being implemented for squaring. Similarly, `feMul` implements the multiplication formula. The constant `19` likely comes from the specifics of the Edwards25519 curve's field.
    * **`uint128` Usage:** Intermediate multiplication results are stored in `uint128` variables. This is necessary because multiplying two 64-bit numbers can result in a 128-bit value.
    * **Reduction Chains:** The "First reduction chain" and "Second reduction chain (carryPropagate)" sections are crucial. These implement the modular reduction step, bringing the potentially large intermediate results back within the bounds of the finite field. The magic number `(1<<51)-1` suggests the field modulus might be related to a power of 2 close to 2^255. The shifts by 51 bits are part of this reduction process.
    * **Assembly Instructions:** The code uses `MOVQ`, `MULQ`, `ADDQ`, `ADCQ`, `SHRQ`, `SHLQ`, `ANDQ`, `IMUL3Q`. These are standard AMD64 assembly instructions for moving data, multiplication, addition (with carry), shifting, and bitwise AND. The `avo` library provides a Go-like way to generate these.
    * **Output Storage:** Finally, the reduced results are stored back into the `out` `Element`.

4. **Analyzing Helper Functions:**
    * **`namedComponent`:** A simple struct to associate a name with a field component, useful for generating readable assembly comments.
    * **`uint128`:** Represents a 128-bit integer using two 64-bit registers.
    * **`mul64` and `addMul64`:**  These functions generate the assembly code for multiplying two 64-bit values (optionally by a small integer constant) and adding the result to a `uint128`. They use the `MULQ` instruction, which produces a 128-bit result in the `RDX:RAX` register pair.
    * **`shiftRightBy51`:** Implements a right bit shift by 51 bits on a `uint128`, extracting the high bits and the lower 51 bits. This is key to the modular reduction.
    * **`maskAndAdd`:** Performs a bitwise AND operation and adds a value (potentially scaled) to the result. Again, crucial for the reduction step.
    * **`mustAddr`:** A helper function to get the memory address of a component, used when generating assembly operands.

5. **Inferring Go Functionality and Providing Examples:** Based on the analysis, it's clear this code implements optimized field multiplication and squaring for Edwards25519 using assembly.

    * **`feSquare`:**  The Go equivalent would be a function taking an `Element` and returning its square, performing the field arithmetic described in the assembly generation code.
    * **`feMul`:**  The Go equivalent would be a function taking two `Element`s and returning their product in the field.

    The examples then demonstrate how these functions would be used in Go, performing field squaring and multiplication. The `Element` struct and its `l0` to `l4` fields are inferred from the assembly generation logic.

6. **Command-line Arguments and Potential Errors:**

    * **Command-line Arguments:** The `//go:generate` directive reveals the command-line arguments used to execute the code. Explain what each argument does (`-out`, `-stubs`, `-pkg`).
    * **Common Mistakes:** Focus on errors related to assembly generation and the constraints imposed by FIPS 140 (like not using `purego`). Misunderstanding the field element representation or the reduction process are also potential pitfalls.

7. **Structuring the Answer:** Organize the findings into clear sections: 功能, Go语言功能实现, 代码推理, 命令行参数, 使用者易犯错的点. Use clear and concise language, explaining the concepts in a way that is easy to understand. Use code blocks for examples and assembly snippets for clarity.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the code is directly implementing the Edwards25519 signature algorithm.
* **Correction:** The `field` package and the function names `feMul` and `feSquare` suggest it's focused on the underlying field arithmetic, a building block for the signature algorithm.
* **Initial thought:** The `avo` library is just a simple assembly emitter.
* **Correction:** `avo` provides a higher-level abstraction, allowing you to work with Go types and generate assembly more conveniently.
* **Initial thought:** The reduction steps are complex and might involve very obscure optimizations.
* **Correction:** While optimized, the reduction steps are based on standard techniques for modular arithmetic in finite fields, specifically taking advantage of the field modulus properties. The bit shifts and masking are key to this.

By following this systematic process of understanding the context, identifying key components, analyzing the core logic, and then generalizing to the Go level, we can effectively understand and explain the functionality of the provided code snippet.
这段代码是 Go 语言中 `crypto/internal/fips140/edwards25519/field` 包的一部分，专门用于为 AMD64 架构生成高效的汇编代码，以执行 Edwards25519 曲线的有限域运算。它使用 `avo` 库来生成汇编代码。

**功能列举:**

1. **定义包信息和约束:**
   - `Package("crypto/internal/fips140/edwards25519/field")`：声明生成的汇编代码属于 `crypto/internal/fips140/edwards25519/field` 包。
   - `ConstraintExpr("!purego")`：设置构建约束，表明这段代码只在 `purego` 构建标签不存在时才会被编译，这意味着它不是纯 Go 实现，而是架构特定的优化版本。

2. **定义汇编生成入口:**
   - `func main()`：定义了汇编代码生成的主函数。
   - `feMul()`：调用 `feMul` 函数来生成有限域乘法的汇编代码。
   - `feSquare()`：调用 `feSquare` 函数来生成有限域平方的汇编代码。
   - `Generate()`：调用 `avo` 库的 `Generate` 函数，将生成的汇编代码写入文件。

3. **定义数据结构:**
   - `namedComponent`：一个辅助结构体，用于将 `avo` 的 `Component` 和一个字符串名称关联起来，方便在生成的汇编代码中添加注释。
   - `uint128`：一个表示 128 位无符号整数的结构体，由两个 64 位寄存器组成，用于存储中间计算结果。

4. **生成有限域平方的汇编代码 (`feSquare`)**
   - `TEXT("feSquare", NOSPLIT, "func(out, a *Element)")`：定义名为 `feSquare` 的汇编函数，它接受两个参数：`out` 和 `a`，都是指向 `Element` 类型的指针。
   - `Doc("feSquare sets out = a * a. It works like feSquareGeneric.")`：生成函数的文档注释，说明该函数的功能是将 `a` 的平方结果赋值给 `out`，其行为类似于通用的 Go 实现。
   - `Pragma("noescape")`：指示编译器该函数内部的变量不会逃逸到堆上。
   - 代码首先从内存中加载 `a` 的五个 64 位部分 (`l0` 到 `l4`)。
   - 然后，它使用一系列 `mul64` 和 `addMul64` 函数调用，计算 `a` 的平方，并将中间结果存储在 `uint128` 类型的变量 `r0` 到 `r4` 中。这些计算是基于 Edwards25519 曲线特定的域运算公式。
   - 接着，代码执行两次“归约链”（reduction chain），这是有限域运算中将中间结果缩减到域范围内的关键步骤。它使用 `shiftRightBy51` 函数将 128 位的结果右移 51 位，提取高位作为进位，并使用 `maskAndAdd` 函数将低 51 位与进位进行处理。这个过程涉及到模运算，常量 `19` 与 Edwards25519 曲线的参数有关。
   - 最后，计算得到的五个 64 位结果被存储回 `out` 指向的 `Element` 结构体的相应字段。

5. **生成有限域乘法的汇编代码 (`feMul`)**
   - `TEXT("feMul", NOSPLIT, "func(out, a, b *Element)")`：定义名为 `feMul` 的汇编函数，它接受三个参数：`out`，`a` 和 `b`，都是指向 `Element` 类型的指针。
   - `Doc("feMul sets out = a * b. It works like feMulGeneric.")`：生成函数的文档注释，说明该函数的功能是将 `a` 和 `b` 的乘积结果赋值给 `out`，其行为类似于通用的 Go 实现。
   - 其余部分与 `feSquare` 类似，只是计算的是 `a` 和 `b` 的乘积，而不是 `a` 的平方。使用的公式略有不同，但核心的乘法和归约流程是相似的。

6. **辅助函数:**
   - `mul64(r uint128, i int, aX, bX namedComponent)`：生成汇编代码，将 `aX` 和 `bX` 相乘（可选地乘以小的整数 `i`），结果存储在 `r` 中。
   - `addMul64(r uint128, i uint64, aX, bX namedComponent)`：生成汇编代码，将 `i * aX * bX` 的结果加到 `r` 中。
   - `shiftRightBy51(r *uint128) (out, lo GPVirtual)`：生成汇编代码，将 128 位整数 `r` 右移 51 位，返回高位和低位部分。这用于实现高效的模运算。
   - `maskAndAdd(r, mask, c GPVirtual, i uint64)`：生成汇编代码，执行按位与操作和加法操作，用于归约过程。
   - `mustAddr(c Component) Op`：辅助函数，用于获取 `avo` 组件的内存地址。

**推理 Go 语言功能的实现:**

这段代码是为 Edwards25519 曲线的有限域乘法和平方运算生成优化的汇编代码。在 Go 语言中，可能存在一个通用的、非汇编优化的版本，用于在不支持汇编优化的平台上或进行功能验证。

假设在 Go 中有一个名为 `Element` 的结构体，用于表示有限域的元素。这个结构体可能包含五个 64 位整数，对应汇编代码中使用的 `l0` 到 `l4` 字段。

```go
package field

type Element struct {
	l0 uint64
	l1 uint64
	l2 uint64
	l3 uint64
	l4 uint64
}

//go:noescape
func feMulGeneric(out, a, b *Element) {
	// 这里是通用的、非汇编优化的有限域乘法实现
	// ... (具体的数学运算) ...
}

//go:noescape
func feSquareGeneric(out, a *Element) {
	// 这里是通用的、非汇编优化的有限域平方实现
	// ... (具体的数学运算) ...
}

//go:linkname feMul crypto/internal/fips140/edwards25519/field.feMul
func feMul(out, a, b *Element)

//go:linkname feSquare crypto/internal/fips140/edwards25519/field.feSquare
func feSquare(out, a *Element)
```

在这个例子中，`feMulGeneric` 和 `feSquareGeneric` 是通用的 Go 实现，而 `feMul` 和 `feSquare` 是汇编优化的版本。`//go:linkname` 指令用于将当前包中的 `feMul` 和 `feSquare` 函数链接到 `crypto/internal/fips140/edwards25519/field` 包中同名的函数上，这样在支持汇编优化的平台上，就会调用汇编版本。

**代码推理示例:**

假设我们有一个 `Element` 类型的变量 `a`，其值为 `l0=1, l1=2, l2=3, l3=4, l4=5`。我们想计算 `a` 的平方并将结果存储在 `out` 中。

**假设输入:**

```go
a := &Element{l0: 1, l1: 2, l2: 3, l3: 4, l4: 5}
out := &Element{}
```

**调用 `feSquare` (汇编版本):**

在汇编代码中，`feSquare` 函数会加载 `a` 的各个字段，执行一系列乘法和加法运算，然后进行模归约，最终将结果存储在 `out` 的字段中。

**可能的输出 (数值仅为示例，实际计算会更复杂):**

```go
// out 的值会被汇编代码修改
// 假设平方和归约后的结果是这些值
out = &Element{l0: 100, l1: 200, l2: 300, l3: 400, l4: 500}
```

**命令行参数的具体处理:**

```
//go:generate go run . -out ../fe_amd64.s -stubs ../fe_amd64.go -pkg field
```

- `go run .`:  执行当前目录下的 `fe_amd64_asm.go` 文件。
- `-out ../fe_amd64.s`:  指定生成的汇编代码的输出文件路径为上一级目录下的 `fe_amd64.s`。
- `-stubs ../fe_amd64.go`: 指定生成的 Go 语言桩代码（用于声明汇编函数的 Go 函数原型）的输出文件路径为上一级目录下的 `fe_amd64.go`。
- `-pkg field`:  指定生成的 Go 语言桩代码所属的包名。

`avo` 库会解析这些参数，并据此生成相应的汇编代码和 Go 语言桩代码文件。

**使用者易犯错的点:**

这段代码本身是用于生成汇编代码的，直接的使用者通常是 Go 语言的开发者，他们会调用 `crypto/internal/fips140/edwards25519/field` 包提供的函数，例如 `feMul` 和 `feSquare`。

一个潜在的错误是开发者可能会尝试直接在纯 Go 环境中使用这些汇编优化的函数，而没有相应的 `!purego` 构建标签。在这种情况下，编译器会找不到这些函数的实现，导致编译错误。

另一个错误可能是开发者错误地理解了 `Element` 结构体的内部表示，并在其他地方尝试手动操作这些字段，而没有考虑到汇编优化代码的特定实现细节。例如，直接修改 `Element` 的字段而不通过 `feMul` 或 `feSquare` 等函数可能会导致不正确的结果，因为这些函数内部包含了特定的模运算和归约逻辑。

总而言之，这段代码是 Edwards25519 曲线有限域运算的关键部分，通过生成高效的汇编代码来提升性能，尤其在需要满足 FIPS 140 标准的场景下。使用者通常通过 Go 语言接口间接使用这些优化的实现。

Prompt: 
```
这是路径为go/src/crypto/internal/fips140/edwards25519/field/_asm/fe_amd64_asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright (c) 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/gotypes"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run . -out ../fe_amd64.s -stubs ../fe_amd64.go -pkg field

func main() {
	Package("crypto/internal/fips140/edwards25519/field")
	ConstraintExpr("!purego")
	feMul()
	feSquare()
	Generate()
}

type namedComponent struct {
	Component
	name string
}

func (c namedComponent) String() string { return c.name }

type uint128 struct {
	name   string
	hi, lo GPVirtual
}

func (c uint128) String() string { return c.name }

func feSquare() {
	TEXT("feSquare", NOSPLIT, "func(out, a *Element)")
	Doc("feSquare sets out = a * a. It works like feSquareGeneric.")
	Pragma("noescape")

	a := Dereference(Param("a"))
	l0 := namedComponent{a.Field("l0"), "l0"}
	l1 := namedComponent{a.Field("l1"), "l1"}
	l2 := namedComponent{a.Field("l2"), "l2"}
	l3 := namedComponent{a.Field("l3"), "l3"}
	l4 := namedComponent{a.Field("l4"), "l4"}

	// r0 = l0×l0 + 19×2×(l1×l4 + l2×l3)
	r0 := uint128{"r0", GP64(), GP64()}
	mul64(r0, 1, l0, l0)
	addMul64(r0, 38, l1, l4)
	addMul64(r0, 38, l2, l3)

	// r1 = 2×l0×l1 + 19×2×l2×l4 + 19×l3×l3
	r1 := uint128{"r1", GP64(), GP64()}
	mul64(r1, 2, l0, l1)
	addMul64(r1, 38, l2, l4)
	addMul64(r1, 19, l3, l3)

	// r2 = = 2×l0×l2 + l1×l1 + 19×2×l3×l4
	r2 := uint128{"r2", GP64(), GP64()}
	mul64(r2, 2, l0, l2)
	addMul64(r2, 1, l1, l1)
	addMul64(r2, 38, l3, l4)

	// r3 = = 2×l0×l3 + 2×l1×l2 + 19×l4×l4
	r3 := uint128{"r3", GP64(), GP64()}
	mul64(r3, 2, l0, l3)
	addMul64(r3, 2, l1, l2)
	addMul64(r3, 19, l4, l4)

	// r4 = = 2×l0×l4 + 2×l1×l3 + l2×l2
	r4 := uint128{"r4", GP64(), GP64()}
	mul64(r4, 2, l0, l4)
	addMul64(r4, 2, l1, l3)
	addMul64(r4, 1, l2, l2)

	Comment("First reduction chain")
	maskLow51Bits := GP64()
	MOVQ(Imm((1<<51)-1), maskLow51Bits)
	c0, r0lo := shiftRightBy51(&r0)
	c1, r1lo := shiftRightBy51(&r1)
	c2, r2lo := shiftRightBy51(&r2)
	c3, r3lo := shiftRightBy51(&r3)
	c4, r4lo := shiftRightBy51(&r4)
	maskAndAdd(r0lo, maskLow51Bits, c4, 19)
	maskAndAdd(r1lo, maskLow51Bits, c0, 1)
	maskAndAdd(r2lo, maskLow51Bits, c1, 1)
	maskAndAdd(r3lo, maskLow51Bits, c2, 1)
	maskAndAdd(r4lo, maskLow51Bits, c3, 1)

	Comment("Second reduction chain (carryPropagate)")
	// c0 = r0 >> 51
	MOVQ(r0lo, c0)
	SHRQ(Imm(51), c0)
	// c1 = r1 >> 51
	MOVQ(r1lo, c1)
	SHRQ(Imm(51), c1)
	// c2 = r2 >> 51
	MOVQ(r2lo, c2)
	SHRQ(Imm(51), c2)
	// c3 = r3 >> 51
	MOVQ(r3lo, c3)
	SHRQ(Imm(51), c3)
	// c4 = r4 >> 51
	MOVQ(r4lo, c4)
	SHRQ(Imm(51), c4)
	maskAndAdd(r0lo, maskLow51Bits, c4, 19)
	maskAndAdd(r1lo, maskLow51Bits, c0, 1)
	maskAndAdd(r2lo, maskLow51Bits, c1, 1)
	maskAndAdd(r3lo, maskLow51Bits, c2, 1)
	maskAndAdd(r4lo, maskLow51Bits, c3, 1)

	Comment("Store output")
	out := Dereference(Param("out"))
	Store(r0lo, out.Field("l0"))
	Store(r1lo, out.Field("l1"))
	Store(r2lo, out.Field("l2"))
	Store(r3lo, out.Field("l3"))
	Store(r4lo, out.Field("l4"))

	RET()
}

func feMul() {
	TEXT("feMul", NOSPLIT, "func(out, a, b *Element)")
	Doc("feMul sets out = a * b. It works like feMulGeneric.")
	Pragma("noescape")

	a := Dereference(Param("a"))
	a0 := namedComponent{a.Field("l0"), "a0"}
	a1 := namedComponent{a.Field("l1"), "a1"}
	a2 := namedComponent{a.Field("l2"), "a2"}
	a3 := namedComponent{a.Field("l3"), "a3"}
	a4 := namedComponent{a.Field("l4"), "a4"}

	b := Dereference(Param("b"))
	b0 := namedComponent{b.Field("l0"), "b0"}
	b1 := namedComponent{b.Field("l1"), "b1"}
	b2 := namedComponent{b.Field("l2"), "b2"}
	b3 := namedComponent{b.Field("l3"), "b3"}
	b4 := namedComponent{b.Field("l4"), "b4"}

	// r0 = a0×b0 + 19×(a1×b4 + a2×b3 + a3×b2 + a4×b1)
	r0 := uint128{"r0", GP64(), GP64()}
	mul64(r0, 1, a0, b0)
	addMul64(r0, 19, a1, b4)
	addMul64(r0, 19, a2, b3)
	addMul64(r0, 19, a3, b2)
	addMul64(r0, 19, a4, b1)

	// r1 = a0×b1 + a1×b0 + 19×(a2×b4 + a3×b3 + a4×b2)
	r1 := uint128{"r1", GP64(), GP64()}
	mul64(r1, 1, a0, b1)
	addMul64(r1, 1, a1, b0)
	addMul64(r1, 19, a2, b4)
	addMul64(r1, 19, a3, b3)
	addMul64(r1, 19, a4, b2)

	// r2 = a0×b2 + a1×b1 + a2×b0 + 19×(a3×b4 + a4×b3)
	r2 := uint128{"r2", GP64(), GP64()}
	mul64(r2, 1, a0, b2)
	addMul64(r2, 1, a1, b1)
	addMul64(r2, 1, a2, b0)
	addMul64(r2, 19, a3, b4)
	addMul64(r2, 19, a4, b3)

	// r3 = a0×b3 + a1×b2 + a2×b1 + a3×b0 + 19×a4×b4
	r3 := uint128{"r3", GP64(), GP64()}
	mul64(r3, 1, a0, b3)
	addMul64(r3, 1, a1, b2)
	addMul64(r3, 1, a2, b1)
	addMul64(r3, 1, a3, b0)
	addMul64(r3, 19, a4, b4)

	// r4 = a0×b4 + a1×b3 + a2×b2 + a3×b1 + a4×b0
	r4 := uint128{"r4", GP64(), GP64()}
	mul64(r4, 1, a0, b4)
	addMul64(r4, 1, a1, b3)
	addMul64(r4, 1, a2, b2)
	addMul64(r4, 1, a3, b1)
	addMul64(r4, 1, a4, b0)

	Comment("First reduction chain")
	maskLow51Bits := GP64()
	MOVQ(Imm((1<<51)-1), maskLow51Bits)
	c0, r0lo := shiftRightBy51(&r0)
	c1, r1lo := shiftRightBy51(&r1)
	c2, r2lo := shiftRightBy51(&r2)
	c3, r3lo := shiftRightBy51(&r3)
	c4, r4lo := shiftRightBy51(&r4)
	maskAndAdd(r0lo, maskLow51Bits, c4, 19)
	maskAndAdd(r1lo, maskLow51Bits, c0, 1)
	maskAndAdd(r2lo, maskLow51Bits, c1, 1)
	maskAndAdd(r3lo, maskLow51Bits, c2, 1)
	maskAndAdd(r4lo, maskLow51Bits, c3, 1)

	Comment("Second reduction chain (carryPropagate)")
	// c0 = r0 >> 51
	MOVQ(r0lo, c0)
	SHRQ(Imm(51), c0)
	// c1 = r1 >> 51
	MOVQ(r1lo, c1)
	SHRQ(Imm(51), c1)
	// c2 = r2 >> 51
	MOVQ(r2lo, c2)
	SHRQ(Imm(51), c2)
	// c3 = r3 >> 51
	MOVQ(r3lo, c3)
	SHRQ(Imm(51), c3)
	// c4 = r4 >> 51
	MOVQ(r4lo, c4)
	SHRQ(Imm(51), c4)
	maskAndAdd(r0lo, maskLow51Bits, c4, 19)
	maskAndAdd(r1lo, maskLow51Bits, c0, 1)
	maskAndAdd(r2lo, maskLow51Bits, c1, 1)
	maskAndAdd(r3lo, maskLow51Bits, c2, 1)
	maskAndAdd(r4lo, maskLow51Bits, c3, 1)

	Comment("Store output")
	out := Dereference(Param("out"))
	Store(r0lo, out.Field("l0"))
	Store(r1lo, out.Field("l1"))
	Store(r2lo, out.Field("l2"))
	Store(r3lo, out.Field("l3"))
	Store(r4lo, out.Field("l4"))

	RET()
}

// mul64 sets r to i * aX * bX.
func mul64(r uint128, i int, aX, bX namedComponent) {
	switch i {
	case 1:
		Comment(fmt.Sprintf("%s = %s×%s", r, aX, bX))
		Load(aX, RAX)
	case 2:
		Comment(fmt.Sprintf("%s = 2×%s×%s", r, aX, bX))
		Load(aX, RAX)
		SHLQ(Imm(1), RAX)
	default:
		panic("unsupported i value")
	}
	MULQ(mustAddr(bX)) // RDX, RAX = RAX * bX
	MOVQ(RAX, r.lo)
	MOVQ(RDX, r.hi)
}

// addMul64 sets r to r + i * aX * bX.
func addMul64(r uint128, i uint64, aX, bX namedComponent) {
	switch i {
	case 1:
		Comment(fmt.Sprintf("%s += %s×%s", r, aX, bX))
		Load(aX, RAX)
	default:
		Comment(fmt.Sprintf("%s += %d×%s×%s", r, i, aX, bX))
		IMUL3Q(Imm(i), Load(aX, GP64()), RAX)
	}
	MULQ(mustAddr(bX)) // RDX, RAX = RAX * bX
	ADDQ(RAX, r.lo)
	ADCQ(RDX, r.hi)
}

// shiftRightBy51 returns r >> 51 and r.lo.
//
// After this function is called, the uint128 may not be used anymore.
func shiftRightBy51(r *uint128) (out, lo GPVirtual) {
	out = r.hi
	lo = r.lo
	SHLQ(Imm(64-51), r.lo, r.hi)
	r.lo, r.hi = nil, nil // make sure the uint128 is unusable
	return
}

// maskAndAdd sets r = r&mask + c*i.
func maskAndAdd(r, mask, c GPVirtual, i uint64) {
	ANDQ(mask, r)
	if i != 1 {
		IMUL3Q(Imm(i), c, c)
	}
	ADDQ(c, r)
}

func mustAddr(c Component) Op {
	b, err := c.Resolve()
	if err != nil {
		panic(err)
	}
	return b.Addr
}

"""



```