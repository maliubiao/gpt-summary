Response:
Let's break down the thought process for analyzing this Go assembly code generator.

1. **Identify the Core Purpose:** The first and most crucial step is to recognize the `//go:generate` comment and the `main` function. This immediately signals that this isn't a standard Go library; it's a program that *generates* code. The file path `go/src/crypto/internal/fips140/sha512/_asm/sha512block_amd64_asm.go` strongly suggests it's generating assembly code for the SHA512 block function, specifically for AMD64 architecture and within a FIPS 140 context (implying security/compliance constraints).

2. **Analyze the `main` Function:** The `main` function sets environment variables (`GOOS`, `GOARCH`), sets the `Package` name, applies a `ConstraintExpr` (`!purego`), calls `blockAMD64()` and `blockAVX2()`, and finally calls `Generate()`. This reveals several key things:
    * It targets `linux` and `amd64`.
    * The generated code belongs to the `crypto/internal/fips140/sha512` package.
    * The generated code is *not* intended for "pure Go" environments, meaning it relies on architecture-specific features (like assembly instructions).
    * It generates two versions of the block function: `blockAMD64` (likely a baseline implementation) and `blockAVX2` (an optimized version using AVX2 instructions).
    * It uses the `avo` library (`github.com/mmcloughlin/avo/build`, etc.) to construct the assembly.

3. **Examine the Function Signatures and Comments:**  Look at functions like `MSGSCHEDULE0`, `MSGSCHEDULE1`, `SHA512T1`, `SHA512T2`, `SHA512ROUND`, `SHA512ROUND0`, `SHA512ROUND1`, `blockAMD64`, and `blockAVX2`. The comments within these functions are extremely helpful. They explicitly link the assembly code to steps in the SHA512 algorithm described in FIPS 180-4. This confirms the initial hypothesis about the code's purpose. Pay attention to the formulas and the register assignments.

4. **Understand `avo` Usage:**  Notice the usage of functions like `MOVQ`, `ADDQ`, `RORQ`, `SHRQ`, `XORQ`, `ANDQ`, `NOTQ`, `U64`, `Imm`, `Mem`, `Label`, `JEQ`, `RET`, `Implement`, `AllocLocal`, `Load`, `Store`, `LEAQ`, etc. These are part of the `avo` library and represent assembly instructions and directives. Understanding that `avo` is a Go library for generating assembly code programmatically is key.

5. **Identify Key Algorithm Components:** The comments and function names clearly map to the SHA512 algorithm:
    * **Message Schedule:** `MSGSCHEDULE0`, `MSGSCHEDULE1`
    * **Round Functions:** `SHA512T1`, `SHA512T2`, `SHA512ROUND`
    * **Block Processing:** `blockAMD64`, `blockAVX2`
    * **Constants:** The `_K` array contains the round constants.

6. **Differentiate `blockAMD64` and `blockAVX2`:** Observe the different approaches. `blockAMD64` uses standard general-purpose registers and a loop structure. `blockAVX2` uses YMM registers (AVX2) and more complex instructions like `VMOVDQU`, `VPSHUFB`, `VPALIGNR`, and a different loop structure. This indicates optimization for processors supporting AVX2.

7. **Infer the Go Functionality:** Based on the file path, the algorithm being implemented, and the `//go:generate` directive, the most likely Go functionality is the `crypto/sha512` package's block processing logic. This assembly code is a performance-critical implementation that bypasses the standard Go runtime for speed.

8. **Construct the Go Example:** Based on the inference above, a Go example would involve using the `crypto/sha512` package to hash data. Since this specific file is about the *block* processing, the example should highlight the incremental nature of the hashing process, or at least demonstrate a basic usage of `sha512.Sum512`.

9. **Address Command-Line Arguments:** Since this is a code generator, the primary "command-line argument" is the `-out` flag in the `//go:generate` comment. Explain its purpose.

10. **Identify Potential Pitfalls:**  Think about what could go wrong when using optimized assembly implementations. Common issues include:
    * **Architecture Dependence:** The generated code is specific to AMD64.
    * **FIPS 140 Context:**  The code is part of a FIPS 140 implementation, which has strict requirements. Incorrect usage could violate these.
    * **Build Constraints:** The `!purego` constraint means this code won't be used in all Go builds.

11. **Structure the Answer:** Organize the findings logically, starting with the main purpose, then detailing the functions, the algorithm, the Go integration, and potential issues. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is some low-level crypto code."  **Refinement:** "It's not *just* low-level; it's *generated* assembly code for a specific part of the SHA512 algorithm."
* **Initial thought:** "The `main` function runs the SHA512 algorithm." **Refinement:** "No, the `main` function *generates* the assembly code that *implements* the algorithm."
* **Considering Go examples:** Initially might think of complex examples. **Refinement:** A simple `sha512.Sum512` example is sufficient to demonstrate the higher-level Go API that this assembly code supports. No need to delve into the internal `block` function directly in the Go example.
* **Thinking about errors:** Focus on practical user errors, not abstract assembly errors. The key is how a *user* of the `crypto/sha512` package might encounter issues related to this underlying assembly.

By following this detailed analysis process, combining code examination with an understanding of Go's build system and common practices in performance-critical libraries, we can accurately determine the functionality of the provided code snippet.
这段代码是Go语言标准库中 `crypto/internal/fips140/sha512` 包的一部分，它的主要功能是**生成用于计算 SHA512 哈希值的 AMD64 架构的汇编代码**。

更具体地说，它实现了 SHA512 算法中的**块处理（block processing）**部分。这意味着它负责处理输入数据的 128 字节块，并根据 SHA512 的规则更新哈希值的内部状态。

**代码功能分解：**

1. **代码生成框架 (avo):**  这段代码使用了 `github.com/mmcloughlin/avo` 这个库。`avo` 是一个 Go 语言库，允许开发者用 Go 代码编写并生成汇编代码。 这使得编写和维护汇编代码更加结构化和类型安全。

2. **`//go:generate go run . -out ../sha512block_amd64.s`:**  这个注释是一个 Go 语言的指令。当开发者运行 `go generate` 命令时，Go 工具链会执行 `go run . -out ../sha512block_amd64.s`。
   - `go run .`：运行当前目录下的 Go 程序（即这个文件）。
   - `-out ../sha512block_amd64.s`：指定生成的汇编代码输出到 `../sha512block_amd64.s` 文件中。

3. **SHA512 算法实现:** 代码中定义了实现 SHA512 算法块处理逻辑的函数：
   - **`MSGSCHEDULE0` 和 `MSGSCHEDULE1`:**  实现了 SHA512 的消息扩展步骤，将 16 个 64 位字的输入块扩展成 80 个 64 位字。
   - **`SHA512T1` 和 `SHA512T2`:**  实现了 SHA512 轮函数中的两个主要计算部分。
   - **`SHA512ROUND`，`SHA512ROUND0`，`SHA512ROUND1`:** 实现了 SHA512 的单轮计算，结合了消息扩展和轮函数。
   - **`blockAMD64`:** 生成了基于标准 AMD64 指令集的 SHA512 块处理汇编代码。
   - **`blockAVX2`:**  生成了利用 AVX2 指令集优化的 SHA512 块处理汇编代码，可以提供更高的性能。
   - **`loop`，`loop0`，`loop1`，`loop2`:**  定义了循环结构，用于迭代处理 SHA512 的 80 轮计算。
   - **`end`，`done_hash`:**  定义了代码执行结束的标签。

4. **常量 `_K`:**  定义了 SHA512 算法中使用的 80 个 64 位轮常量。

5. **`main` 函数:**
   - 设置了 `GOOS` 和 `GOARCH` 环境变量为 "linux" 和 "amd64"，确保生成的汇编代码的目标平台。
   - 使用 `Package("crypto/internal/fips140/sha512")` 指定了生成的汇编代码所属的 Go 包。
   - 使用 `ConstraintExpr("!purego")` 添加了构建约束，表示这段汇编代码只在非 "purego" 构建模式下使用（"purego" 构建模式会强制使用纯 Go 实现）。
   - 调用 `blockAMD64()` 和 `blockAVX2()` 生成两种不同版本的汇编代码。
   - 调用 `Generate()` 触发 `avo` 库将生成的汇编代码写入到输出文件。

**它是什么go语言功能的实现，请用go代码举例说明:**

这段代码实际上是 `crypto/sha512` 包中 SHA512 哈希函数底层实现的一部分。当你在 Go 代码中使用 `crypto/sha512` 包进行哈希计算时，如果你的操作系统和架构符合条件（例如 Linux 和 AMD64），并且构建时没有使用 `purego` 标签，那么最终执行的哈希计算很可能会用到这里生成的汇编代码，因为它通常比纯 Go 实现更快。

**Go 代码示例：**

```go
package main

import (
	"crypto/sha512"
	"fmt"
)

func main() {
	data := []byte("hello world")
	hash := sha512.Sum512(data)
	fmt.Printf("%x\n", hash)
}
```

**假设的输入与输出：**

在这个 Go 代码示例中：

- **输入:** `data` 变量，其值为 `[]byte("hello world")`。
- **输出:**  `sha512.Sum512(data)` 将返回一个 `[64]byte` 类型的数组，包含 "hello world" 的 SHA512 哈希值。例如（实际输出）：
  ```
  309ecc489c12d6f4cc55467b4e698140ad864cdcf3708e4a9802baefd4895ca2206c73e9541450f2a2eb61c1a54b0fa9a38a261c6076ea6446fc8e51130bdf24
  ```

**代码推理:**

这段汇编代码生成器的逻辑是按照 SHA512 算法的步骤来实现的。  例如，`MSGSCHEDULE0` 和 `MSGSCHEDULE1` 函数对应于 FIPS 180-4 标准中定义的消息扩展的公式。 `SHA512T1` 和 `SHA512T2` 函数对应于轮函数的计算。 `blockAMD64` 和 `blockAVX2` 函数则组织这些基本操作，并处理输入数据的块。

`avo` 库提供的函数，如 `MOVQ` (移动 quad word), `ADDQ` (加法 quad word), `RORQ` (循环右移 quad word) 等，都是 x86-64 汇编指令。代码生成器通过调用这些 `avo` 函数，最终生成可执行的汇编代码。

**命令行参数的具体处理:**

这个代码本身是一个 Go 程序，它处理的“命令行参数”体现在 `//go:generate` 指令中：

- **`-out ../sha512block_amd64.s`:**  这个 `-out` 参数是传递给当前 Go 程序的，告诉它将生成的汇编代码输出到 `../sha512block_amd64.s` 这个文件中。

当你在终端运行 `go generate` 时，Go 工具链会解析这个指令，并以相应的参数运行当前的 Go 程序。

**使用者易犯错的点:**

由于这段代码是 Go 标准库的内部实现，并且通过 `go generate` 生成汇编代码，**直接使用这段代码的开发者不太容易犯错**。 开发者通常会使用上层的 `crypto/sha512` 包。

然而，对于维护 Go 标准库或理解其底层实现的开发者来说，可能会遇到以下易错点：

1. **理解汇编指令的含义:**  需要熟悉 AMD64 汇编语言，才能理解生成的汇编代码的正确性。
2. **`avo` 库的使用:**  需要理解 `avo` 库提供的抽象和如何将其映射到实际的汇编指令。
3. **SHA512 算法的细节:**  需要对 SHA512 算法的每个步骤非常熟悉，才能正确地用汇编实现。
4. **AVX2 指令的使用:** 对于 `blockAVX2`，需要正确地使用 AVX2 指令，包括寄存器的管理和指令的语义，否则可能导致性能下降或错误。
5. **构建约束 (`!purego`):**  如果错误地理解或修改了构建约束，可能会导致在不应该使用汇编代码的情况下使用了它，或者反之，影响性能或功能。

**总结:**

这段 Go 代码是一个用于生成 SHA512 算法 AMD64 汇编实现的程序。它是 Go 标准库 `crypto/sha512` 包性能优化的关键部分。开发者通常不需要直接与这段代码交互，而是通过上层的 Go API 使用 SHA512 功能。理解这段代码的功能需要对 Go 代码生成、汇编语言和 SHA512 算法有深入的了解。

Prompt: 
```
这是路径为go/src/crypto/internal/fips140/sha512/_asm/sha512block_amd64_asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run . -out ../sha512block_amd64.s

// SHA512 block routine. See sha512block.go for Go equivalent.
//
// The algorithm is detailed in FIPS 180-4:
//
//  https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
//
// Wt = Mt; for 0 <= t <= 15
// Wt = SIGMA1(Wt-2) + SIGMA0(Wt-15) + Wt-16; for 16 <= t <= 79
//
// a = H0
// b = H1
// c = H2
// d = H3
// e = H4
// f = H5
// g = H6
// h = H7
//
// for t = 0 to 79 {
//    T1 = h + BIGSIGMA1(e) + Ch(e,f,g) + Kt + Wt
//    T2 = BIGSIGMA0(a) + Maj(a,b,c)
//    h = g
//    g = f
//    f = e
//    e = d + T1
//    d = c
//    c = b
//    b = a
//    a = T1 + T2
// }
//
// H0 = a + H0
// H1 = b + H1
// H2 = c + H2
// H3 = d + H3
// H4 = e + H4
// H5 = f + H5
// H6 = g + H6
// H7 = h + H7

const ThatPeskyUnicodeDot = "\u00b7"

var _K = []uint64{
	0x428a2f98d728ae22,
	0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f,
	0xe9b5dba58189dbbc,
	0x3956c25bf348b538,
	0x59f111f1b605d019,
	0x923f82a4af194f9b,
	0xab1c5ed5da6d8118,
	0xd807aa98a3030242,
	0x12835b0145706fbe,
	0x243185be4ee4b28c,
	0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f,
	0x80deb1fe3b1696b1,
	0x9bdc06a725c71235,
	0xc19bf174cf692694,
	0xe49b69c19ef14ad2,
	0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5,
	0x240ca1cc77ac9c65,
	0x2de92c6f592b0275,
	0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4,
	0x76f988da831153b5,
	0x983e5152ee66dfab,
	0xa831c66d2db43210,
	0xb00327c898fb213f,
	0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2,
	0xd5a79147930aa725,
	0x06ca6351e003826f,
	0x142929670a0e6e70,
	0x27b70a8546d22ffc,
	0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df,
	0x650a73548baf63de,
	0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6,
	0x92722c851482353b,
	0xa2bfe8a14cf10364,
	0xa81a664bbc423001,
	0xc24b8b70d0f89791,
	0xc76c51a30654be30,
	0xd192e819d6ef5218,
	0xd69906245565a910,
	0xf40e35855771202a,
	0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8,
	0x1e376c085141ab53,
	0x2748774cdf8eeb99,
	0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63,
	0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc,
	0x78a5636f43172f60,
	0x84c87814a1f0ab72,
	0x8cc702081a6439ec,
	0x90befffa23631e28,
	0xa4506cebde82bde9,
	0xbef9a3f7b2c67915,
	0xc67178f2e372532b,
	0xca273eceea26619c,
	0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e,
	0xf57d4f7fee6ed178,
	0x06f067aa72176fba,
	0x0a637dc5a2c898a6,
	0x113f9804bef90dae,
	0x1b710b35131c471b,
	0x28db77f523047d84,
	0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6,
	0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec,
	0x6c44198c4a475817,
}

func main() {
	// https://github.com/mmcloughlin/avo/issues/450
	os.Setenv("GOOS", "linux")
	os.Setenv("GOARCH", "amd64")

	Package("crypto/internal/fips140/sha512")
	ConstraintExpr("!purego")
	blockAMD64()
	blockAVX2()
	Generate()
}

// Wt = Mt; for 0 <= t <= 15
//
// Line 50
func MSGSCHEDULE0(index int) {
	MOVQ(Mem{Base: SI}.Offset(index*8), RAX)
	BSWAPQ(RAX)
	MOVQ(RAX, Mem{Base: BP}.Offset(index*8))
}

// Wt = SIGMA1(Wt-2) + Wt-7 + SIGMA0(Wt-15) + Wt-16; for 16 <= t <= 79
//
//	SIGMA0(x) = ROTR(1,x) XOR ROTR(8,x) XOR SHR(7,x)
//	SIGMA1(x) = ROTR(19,x) XOR ROTR(61,x) XOR SHR(6,x)
//
// Line 58
func MSGSCHEDULE1(index int) {
	MOVQ(Mem{Base: BP}.Offset((index-2)*8), RAX)
	MOVQ(RAX, RCX)
	RORQ(Imm(19), RAX)
	MOVQ(RCX, RDX)
	RORQ(Imm(61), RCX)
	SHRQ(Imm(6), RDX)
	MOVQ(Mem{Base: BP}.Offset((index-15)*8), RBX)
	XORQ(RCX, RAX)
	MOVQ(RBX, RCX)
	XORQ(RDX, RAX)
	RORQ(Imm(1), RBX)
	MOVQ(RCX, RDX)
	SHRQ(Imm(7), RDX)
	RORQ(Imm(8), RCX)
	ADDQ(Mem{Base: BP}.Offset((index-7)*8), RAX)
	XORQ(RCX, RBX)
	XORQ(RDX, RBX)
	ADDQ(Mem{Base: BP}.Offset((index-16)*8), RBX)
	ADDQ(RBX, RAX)
	MOVQ(RAX, Mem{Base: BP}.Offset((index)*8))
}

// Calculate T1 in AX - uses AX, CX and DX registers.
// h is also used as an accumulator. Wt is passed in AX.
//
//	T1 = h + BIGSIGMA1(e) + Ch(e, f, g) + Kt + Wt
//	  BIGSIGMA1(x) = ROTR(14,x) XOR ROTR(18,x) XOR ROTR(41,x)
//	  Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
//
// Line 85
func SHA512T1(konst uint64, e, f, g, h GPPhysical) {
	MOVQ(U64(konst), RDX)
	ADDQ(RAX, h)
	MOVQ(e, RAX)
	ADDQ(RDX, h)
	MOVQ(e, RCX)
	RORQ(U8(14), RAX)
	MOVQ(e, RDX)
	RORQ(U8(18), RCX)
	XORQ(RCX, RAX)
	MOVQ(e, RCX)
	RORQ(U8(41), RDX)
	ANDQ(f, RCX)
	XORQ(RAX, RDX)
	MOVQ(e, RAX)
	NOTQ(RAX)
	ADDQ(RDX, h)
	ANDQ(g, RAX)
	XORQ(RCX, RAX)
	ADDQ(h, RAX)
}

// Calculate T2 in BX - uses BX, CX, DX and DI registers.
//
//	T2 = BIGSIGMA0(a) + Maj(a, b, c)
//	  BIGSIGMA0(x) = ROTR(28,x) XOR ROTR(34,x) XOR ROTR(39,x)
//	  Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
//
// Line 110
func SHA512T2(a, b, c GPPhysical) {
	MOVQ(a, RDI)
	MOVQ(c, RBX)
	RORQ(Imm(28), RDI)
	MOVQ(a, RDX)
	ANDQ(b, RBX)
	RORQ(Imm(34), RDX)
	MOVQ(a, RCX)
	ANDQ(c, RCX)
	XORQ(RDX, RDI)
	XORQ(RCX, RBX)
	MOVQ(a, RDX)
	MOVQ(b, RCX)
	RORQ(Imm(39), RDX)
	ANDQ(a, RCX)
	XORQ(RCX, RBX)
	XORQ(RDX, RDI)
	ADDQ(RDI, RBX)
}

// Calculate T1 and T2, then e = d + T1 and a = T1 + T2.
// The values for e and a are stored in d and h, ready for rotation.
//
// Line 131
func SHA512ROUND(index int, konst uint64, a, b, c, d, e, f, g, h GPPhysical) {
	SHA512T1(konst, e, f, g, h)
	SHA512T2(a, b, c)
	MOVQ(RBX, h)
	ADDQ(RAX, d)
	ADDQ(RAX, h)
}

// Line 169
func SHA512ROUND0(index int, konst uint64, a, b, c, d, e, f, g, h GPPhysical) {
	MSGSCHEDULE0(index)
	SHA512ROUND(index, konst, a, b, c, d, e, f, g, h)
}

// Line 142
func SHA512ROUND1(index int, konst uint64, a, b, c, d, e, f, g, h GPPhysical) {
	MSGSCHEDULE1(index)
	SHA512ROUND(index, konst, a, b, c, d, e, f, g, h)
}

// Line 146
func blockAMD64() {
	Implement("blockAMD64")
	AllocLocal(648)

	Load(Param("p").Base(), RSI)
	Load(Param("p").Len(), RDX)
	SHRQ(Imm(7), RDX)
	SHLQ(Imm(7), RDX)

	LEAQ(Mem{Base: SI, Index: DX, Scale: 1}, RDI)
	MOVQ(RDI, Mem{Base: SP}.Offset(640))
	CMPQ(RSI, RDI)
	JEQ(LabelRef("end"))

	Load(Param("dig"), RBP)
	MOVQ(Mem{Base: BP}.Offset(0*8), R8)  // a = H0
	MOVQ(Mem{Base: BP}.Offset(1*8), R9)  // b = H1
	MOVQ(Mem{Base: BP}.Offset(2*8), R10) // c = H2
	MOVQ(Mem{Base: BP}.Offset(3*8), R11) // d = H3
	MOVQ(Mem{Base: BP}.Offset(4*8), R12) // e = H4
	MOVQ(Mem{Base: BP}.Offset(5*8), R13) // f = H5
	MOVQ(Mem{Base: BP}.Offset(6*8), R14) // g = H6
	MOVQ(Mem{Base: BP}.Offset(7*8), R15) // h = H7
	PSHUFFLE_BYTE_FLIP_MASK_DATA()
	loop()
	end()
}

func rotateRight(slice *[]GPPhysical) []GPPhysical {
	n := len(*slice)
	new := make([]GPPhysical, n)
	for i, reg := range *slice {
		new[(i+1)%n] = reg
	}
	return new
}

// Line 167
func loop() {
	Label("loop")
	MOVQ(RSP, RBP) // message schedule

	n := len(_K)
	regs := []GPPhysical{R8, R9, R10, R11, R12, R13, R14, R15}

	for i := 0; i < 16; i++ {
		SHA512ROUND0(i, _K[i], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7])
		regs = rotateRight(&regs)
	}

	for i := 16; i < n; i++ {
		SHA512ROUND1(i, _K[i], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7])
		regs = rotateRight(&regs)
	}

	Load(Param("dig"), RBP)

	BP_Mem := Mem{Base: BP}
	ADDQ(BP_Mem.Offset(0*8), R8) // H0 = a + H0
	MOVQ(R8, BP_Mem.Offset(0*8))
	ADDQ(BP_Mem.Offset(1*8), R9) // H1 = b + H1
	MOVQ(R9, BP_Mem.Offset(1*8))
	ADDQ(BP_Mem.Offset(2*8), R10) // H2 = c + H2
	MOVQ(R10, BP_Mem.Offset(2*8))
	ADDQ(BP_Mem.Offset(3*8), R11) // H3 = d + H3
	MOVQ(R11, BP_Mem.Offset(3*8))
	ADDQ(BP_Mem.Offset(4*8), R12) // H4 = e + H4
	MOVQ(R12, BP_Mem.Offset(4*8))
	ADDQ(BP_Mem.Offset(5*8), R13) // H5 = f + H5
	MOVQ(R13, BP_Mem.Offset(5*8))
	ADDQ(BP_Mem.Offset(6*8), R14) // H6 = g + H6
	MOVQ(R14, BP_Mem.Offset(6*8))
	ADDQ(BP_Mem.Offset(7*8), R15) // H7 = h + H7
	MOVQ(R15, BP_Mem.Offset(7*8))

	ADDQ(Imm(128), RSI)
	CMPQ(RSI, Mem{Base: SP}.Offset(640))
	JB(LabelRef("loop"))
}

// Line 274
func end() {
	Label("end")
	RET()
}

// Version below is based on "Fast SHA512 Implementations on Intel
// Architecture Processors" White-paper
// https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/fast-sha512-implementations-ia-processors-paper.pdf
// AVX2 version by Intel, same algorithm in Linux kernel:
// https://github.com/torvalds/linux/blob/master/arch/x86/crypto/sha512-avx2-asm.S

// James Guilford <james.guilford@intel.com>
// Kirk Yap <kirk.s.yap@intel.com>
// Tim Chen <tim.c.chen@linux.intel.com>
// David Cote <david.m.cote@intel.com>
// Aleksey Sidorov <aleksey.sidorov@intel.com>

// Line 289
var (
	YFER_SIZE int = (4 * 8)
	SRND_SIZE     = (1 * 8)
	INP_SIZE      = (1 * 8)

	frame_YFER   = (0)
	frame_SRND   = (frame_YFER + YFER_SIZE)
	frame_INP    = (frame_SRND + SRND_SIZE)
	frame_INPEND = (frame_INP + INP_SIZE)
)

// Line 298
func addm(p1 Mem, p2 GPPhysical) {
	ADDQ(p1, p2)
	MOVQ(p2, p1)
}

// Line 302
func COPY_YMM_AND_BSWAP(p1 VecPhysical, p2 Mem, p3 VecPhysical) {
	VMOVDQU(p2, p1)
	VPSHUFB(p3, p1, p1)
}

// Line 306
func MY_VPALIGNR(YDST, YSRC1, YSRC2 VecPhysical, RVAL int) {
	VPERM2F128(U8(0x3), YSRC2, YSRC1, YDST)
	VPALIGNR(U8(RVAL), YSRC2, YDST, YDST)
}

// Line 324
func blockAVX2() {
	Implement("blockAVX2")
	Attributes(NOSPLIT)
	AllocLocal(56)

	Load(Param("dig"), RSI)
	Load(Param("p").Base(), RDI)
	Load(Param("p").Len(), RDX)

	SHRQ(Imm(7), RDX)
	SHLQ(Imm(7), RDX)

	JZ(LabelRef("done_hash"))
	ADDQ(RDI, RDX)
	MOVQ(RDX, Mem{Base: SP}.Offset(frame_INPEND))

	MOVQ(Mem{Base: SI}.Offset(0*8), RAX)
	MOVQ(Mem{Base: SI}.Offset(1*8), RBX)
	MOVQ(Mem{Base: SI}.Offset(2*8), RCX)
	MOVQ(Mem{Base: SI}.Offset(3*8), R8)
	MOVQ(Mem{Base: SI}.Offset(4*8), RDX)
	MOVQ(Mem{Base: SI}.Offset(5*8), R9)
	MOVQ(Mem{Base: SI}.Offset(6*8), R10)
	MOVQ(Mem{Base: SI}.Offset(7*8), R11)

	PSHUFFLE_BYTE_FLIP_MASK := PSHUFFLE_BYTE_FLIP_MASK_DATA()
	VMOVDQU(PSHUFFLE_BYTE_FLIP_MASK, Y9)

	loop0()
	loop1()
	loop2()
	done_hash()
}

// Line 347
func loop0() {
	Label("loop0")

	_K := NewDataAddr(Symbol{Name: "$" + ThatPeskyUnicodeDot + "_K"}, 0)
	MOVQ(_K, RBP)

	// byte swap first 16 dwords
	COPY_YMM_AND_BSWAP(Y4, Mem{Base: DI}.Offset(0*32), Y9)
	COPY_YMM_AND_BSWAP(Y5, Mem{Base: DI}.Offset(1*32), Y9)
	COPY_YMM_AND_BSWAP(Y6, Mem{Base: DI}.Offset(2*32), Y9)
	COPY_YMM_AND_BSWAP(Y7, Mem{Base: DI}.Offset(3*32), Y9)

	MOVQ(RDI, Mem{Base: SP}.Offset(frame_INP))

	// schedule 64 input dwords, by doing 12 rounds of 4 each
	MOVQ(U32(4), Mem{Base: SP}.Offset(frame_SRND))
}

// Line 361
func loop1() {
	Label("loop1")
	VPADDQ(Mem{Base: BP}, Y4, Y0)
	VMOVDQU(Y0, Mem{Base: SP}.Offset(frame_YFER))

	MY_VPALIGNR(Y0, Y7, Y6, 8)

	VPADDQ(Y4, Y0, Y0)

	MY_VPALIGNR(Y1, Y5, Y4, 8)

	VPSRLQ(Imm(1), Y1, Y2)
	VPSLLQ(Imm(64-1), Y1, Y3)
	VPOR(Y2, Y3, Y3)

	VPSRLQ(Imm(7), Y1, Y8)

	MOVQ(RAX, RDI)
	RORXQ(Imm(41), RDX, R13)
	RORXQ(Imm(18), RDX, R14)
	ADDQ(Mem{Base: SP}.Offset(frame_YFER), R11)
	ORQ(RCX, RDI)
	MOVQ(R9, R15)
	RORXQ(Imm(34), RAX, R12)

	XORQ(R14, R13)
	XORQ(R10, R15)
	RORXQ(Imm(14), RDX, R14)

	ANDQ(RDX, R15)
	XORQ(R14, R13)
	RORXQ(Imm(39), RAX, R14)
	ADDQ(R11, R8)

	ANDQ(RBX, RDI)
	XORQ(R12, R14)
	RORXQ(Imm(28), RAX, R12)

	XORQ(R10, R15)
	XORQ(R12, R14)
	MOVQ(RAX, R12)
	ANDQ(RCX, R12)

	ADDQ(R13, R15)
	ORQ(R12, RDI)
	ADDQ(R14, R11)

	ADDQ(R15, R8)

	ADDQ(R15, R11)
	ADDQ(RDI, R11)

	VPSRLQ(Imm(8), Y1, Y2)
	VPSLLQ(Imm(64-8), Y1, Y1)
	VPOR(Y2, Y1, Y1)

	VPXOR(Y8, Y3, Y3)
	VPXOR(Y1, Y3, Y1)

	VPADDQ(Y1, Y0, Y0)

	VPERM2F128(Imm(0x0), Y0, Y0, Y4)

	MASK_YMM_LO := MASK_YMM_LO_DATA()
	VPAND(MASK_YMM_LO, Y0, Y0)

	VPERM2F128(Imm(0x11), Y7, Y7, Y2)
	VPSRLQ(Imm(6), Y2, Y8)

	MOVQ(R11, RDI)
	RORXQ(Imm(41), R8, R13)
	RORXQ(Imm(18), R8, R14)
	ADDQ(Mem{Base: SP}.Offset(1*8+frame_YFER), R10)
	ORQ(RBX, RDI)

	MOVQ(RDX, R15)
	RORXQ(Imm(34), R11, R12)
	XORQ(R14, R13)
	XORQ(R9, R15)

	RORXQ(Imm(14), R8, R14)
	XORQ(R14, R13)
	RORXQ(Imm(39), R11, R14)
	ANDQ(R8, R15)
	ADDQ(R10, RCX)

	ANDQ(RAX, RDI)
	XORQ(R12, R14)

	RORXQ(Imm(28), R11, R12)
	XORQ(R9, R15)

	XORQ(R12, R14)
	MOVQ(R11, R12)
	ANDQ(RBX, R12)
	ADDQ(R13, R15)

	ORQ(R12, RDI)
	ADDQ(R14, R10)

	ADDQ(R15, RCX)
	ADDQ(R15, R10)
	ADDQ(RDI, R10)

	VPSRLQ(Imm(19), Y2, Y3)
	VPSLLQ(Imm(64-19), Y2, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)
	VPSRLQ(Imm(61), Y2, Y3)
	VPSLLQ(Imm(64-61), Y2, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)

	VPADDQ(Y8, Y4, Y4)

	VPSRLQ(Imm(6), Y4, Y8)

	MOVQ(R10, RDI)
	RORXQ(Imm(41), RCX, R13)
	ADDQ(Mem{Base: SP}.Offset(2*8+frame_YFER), R9)

	RORXQ(Imm(18), RCX, R14)
	ORQ(RAX, RDI)
	MOVQ(R8, R15)
	XORQ(RDX, R15)

	RORXQ(Imm(34), R10, R12)
	XORQ(R14, R13)
	ANDQ(RCX, R15)

	RORXQ(Imm(14), RCX, R14)
	ADDQ(R9, RBX)
	ANDQ(R11, RDI)

	XORQ(R14, R13)
	RORXQ(Imm(39), R10, R14)
	XORQ(RDX, R15)

	XORQ(R12, R14)
	RORXQ(Imm(28), R10, R12)

	XORQ(R12, R14)
	MOVQ(R10, R12)
	ANDQ(RAX, R12)
	ADDQ(R13, R15)

	ORQ(R12, RDI)
	ADDQ(R14, R9)
	ADDQ(R15, RBX)
	ADDQ(R15, R9)

	ADDQ(RDI, R9)

	VPSRLQ(Imm(19), Y4, Y3)
	VPSLLQ(Imm(64-19), Y4, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)
	VPSRLQ(Imm(61), Y4, Y3)
	VPSLLQ(Imm(64-61), Y4, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)

	VPADDQ(Y8, Y0, Y2)

	VPBLENDD(Imm(0xF0), Y2, Y4, Y4)

	MOVQ(R9, RDI)
	RORXQ(Imm(41), RBX, R13)
	RORXQ(Imm(18), RBX, R14)
	ADDQ(Mem{Base: SP}.Offset(3*8+frame_YFER), RDX)
	ORQ(R11, RDI)

	MOVQ(RCX, R15)
	RORXQ(Imm(34), R9, R12)
	XORQ(R14, R13)
	XORQ(R8, R15)

	RORXQ(Imm(14), RBX, R14)
	ANDQ(RBX, R15)
	ADDQ(RDX, RAX)
	ANDQ(R10, RDI)

	XORQ(R14, R13)
	XORQ(R8, R15)

	RORXQ(Imm(39), R9, R14)
	ADDQ(R13, R15)

	XORQ(R12, R14)
	ADDQ(R15, RAX)

	RORXQ(Imm(28), R9, R12)

	XORQ(R12, R14)
	MOVQ(R9, R12)
	ANDQ(R11, R12)
	ORQ(R12, RDI)

	ADDQ(R14, RDX)
	ADDQ(R15, RDX)
	ADDQ(RDI, RDX)

	VPADDQ(Mem{Base: BP}.Offset(1*32), Y5, Y0)
	VMOVDQU(Y0, Mem{Base: SP}.Offset(frame_YFER))

	MY_VPALIGNR(Y0, Y4, Y7, 8)

	VPADDQ(Y5, Y0, Y0)

	MY_VPALIGNR(Y1, Y6, Y5, 8)

	VPSRLQ(Imm(1), Y1, Y2)
	VPSLLQ(Imm(64-1), Y1, Y3)
	VPOR(Y2, Y3, Y3)

	VPSRLQ(Imm(7), Y1, Y8)

	MOVQ(RDX, RDI)
	RORXQ(Imm(41), RAX, R13)
	RORXQ(Imm(18), RAX, R14)
	ADDQ(Mem{Base: SP}.Offset(frame_YFER), R8)
	ORQ(R10, RDI)
	MOVQ(RBX, R15)
	RORXQ(Imm(34), RDX, R12)

	XORQ(R14, R13)
	XORQ(RCX, R15)
	RORXQ(Imm(14), RAX, R14)

	ANDQ(RAX, R15)
	XORQ(R14, R13)
	RORXQ(Imm(39), RDX, R14)
	ADDQ(R8, R11)

	ANDQ(R9, RDI)
	XORQ(R12, R14)
	RORXQ(Imm(28), RDX, R12)

	XORQ(RCX, R15)
	XORQ(R12, R14)
	MOVQ(RDX, R12)
	ANDQ(R10, R12)

	ADDQ(R13, R15)
	ORQ(R12, RDI)
	ADDQ(R14, R8)

	ADDQ(R15, R11)

	ADDQ(R15, R8)
	ADDQ(RDI, R8)

	VPSRLQ(Imm(8), Y1, Y2)
	VPSLLQ(Imm(64-8), Y1, Y1)
	VPOR(Y2, Y1, Y1)

	VPXOR(Y8, Y3, Y3)
	VPXOR(Y1, Y3, Y1)

	VPADDQ(Y1, Y0, Y0)

	VPERM2F128(Imm(0x0), Y0, Y0, Y5)

	VPAND(MASK_YMM_LO, Y0, Y0)

	VPERM2F128(Imm(0x11), Y4, Y4, Y2)
	VPSRLQ(Imm(6), Y2, Y8)

	MOVQ(R8, RDI)
	RORXQ(Imm(41), R11, R13)
	RORXQ(Imm(18), R11, R14)
	ADDQ(Mem{Base: SP}.Offset(1*8+frame_YFER), RCX)
	ORQ(R9, RDI)

	MOVQ(RAX, R15)
	RORXQ(Imm(34), R8, R12)
	XORQ(R14, R13)
	XORQ(RBX, R15)

	RORXQ(Imm(14), R11, R14)
	XORQ(R14, R13)
	RORXQ(Imm(39), R8, R14)
	ANDQ(R11, R15)
	ADDQ(RCX, R10)

	ANDQ(RDX, RDI)
	XORQ(R12, R14)

	RORXQ(Imm(28), R8, R12)
	XORQ(RBX, R15)

	XORQ(R12, R14)
	MOVQ(R8, R12)
	ANDQ(R9, R12)
	ADDQ(R13, R15)

	ORQ(R12, RDI)
	ADDQ(R14, RCX)

	ADDQ(R15, R10)
	ADDQ(R15, RCX)
	ADDQ(RDI, RCX)

	VPSRLQ(Imm(19), Y2, Y3)
	VPSLLQ(Imm(64-19), Y2, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)
	VPSRLQ(Imm(61), Y2, Y3)
	VPSLLQ(Imm(64-61), Y2, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)

	VPADDQ(Y8, Y5, Y5)

	VPSRLQ(Imm(6), Y5, Y8)

	MOVQ(RCX, RDI)
	RORXQ(Imm(41), R10, R13)
	ADDQ(Mem{Base: SP}.Offset(2*8+frame_YFER), RBX)

	RORXQ(Imm(18), R10, R14)
	ORQ(RDX, RDI)
	MOVQ(R11, R15)
	XORQ(RAX, R15)

	RORXQ(Imm(34), RCX, R12)
	XORQ(R14, R13)
	ANDQ(R10, R15)

	RORXQ(Imm(14), R10, R14)
	ADDQ(RBX, R9)
	ANDQ(R8, RDI)

	XORQ(R14, R13)
	RORXQ(Imm(39), RCX, R14)
	XORQ(RAX, R15)

	XORQ(R12, R14)
	RORXQ(Imm(28), RCX, R12)

	XORQ(R12, R14)
	MOVQ(RCX, R12)
	ANDQ(RDX, R12)
	ADDQ(R13, R15)

	ORQ(R12, RDI)
	ADDQ(R14, RBX)
	ADDQ(R15, R9)
	ADDQ(R15, RBX)

	ADDQ(RDI, RBX)

	VPSRLQ(Imm(19), Y5, Y3)
	VPSLLQ(Imm(64-19), Y5, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)
	VPSRLQ(Imm(61), Y5, Y3)
	VPSLLQ(Imm(64-61), Y5, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)

	VPADDQ(Y8, Y0, Y2)

	VPBLENDD(Imm(0xF0), Y2, Y5, Y5)

	MOVQ(RBX, RDI)
	RORXQ(Imm(41), R9, R13)
	RORXQ(Imm(18), R9, R14)
	ADDQ(Mem{Base: SP}.Offset(3*8+frame_YFER), RAX)
	ORQ(R8, RDI)

	MOVQ(R10, R15)
	RORXQ(Imm(34), RBX, R12)
	XORQ(R14, R13)
	XORQ(R11, R15)

	RORXQ(Imm(14), R9, R14)
	ANDQ(R9, R15)
	ADDQ(RAX, RDX)
	ANDQ(RCX, RDI)

	XORQ(R14, R13)
	XORQ(R11, R15)

	RORXQ(Imm(39), RBX, R14)
	ADDQ(R13, R15)

	XORQ(R12, R14)
	ADDQ(R15, RDX)

	RORXQ(Imm(28), RBX, R12)

	XORQ(R12, R14)
	MOVQ(RBX, R12)
	ANDQ(R8, R12)
	ORQ(R12, RDI)

	ADDQ(R14, RAX)
	ADDQ(R15, RAX)
	ADDQ(RDI, RAX)

	VPADDQ(Mem{Base: BP}.Offset(2*32), Y6, Y0)
	VMOVDQU(Y0, Mem{Base: SP}.Offset(frame_YFER))

	MY_VPALIGNR(Y0, Y5, Y4, 8)

	VPADDQ(Y6, Y0, Y0)

	MY_VPALIGNR(Y1, Y7, Y6, 8)

	VPSRLQ(Imm(1), Y1, Y2)
	VPSLLQ(Imm(64-1), Y1, Y3)
	VPOR(Y2, Y3, Y3)

	VPSRLQ(Imm(7), Y1, Y8)

	MOVQ(RAX, RDI)
	RORXQ(Imm(41), RDX, R13)
	RORXQ(Imm(18), RDX, R14)
	ADDQ(Mem{Base: SP}.Offset(frame_YFER), R11)
	ORQ(RCX, RDI)
	MOVQ(R9, R15)
	RORXQ(Imm(34), RAX, R12)

	XORQ(R14, R13)
	XORQ(R10, R15)
	RORXQ(Imm(14), RDX, R14)

	ANDQ(RDX, R15)
	XORQ(R14, R13)
	RORXQ(Imm(39), RAX, R14)
	ADDQ(R11, R8)

	ANDQ(RBX, RDI)
	XORQ(R12, R14)
	RORXQ(Imm(28), RAX, R12)

	XORQ(R10, R15)
	XORQ(R12, R14)
	MOVQ(RAX, R12)
	ANDQ(RCX, R12)

	ADDQ(R13, R15)
	ORQ(R12, RDI)
	ADDQ(R14, R11)

	ADDQ(R15, R8)

	ADDQ(R15, R11)
	ADDQ(RDI, R11)

	VPSRLQ(Imm(8), Y1, Y2)
	VPSLLQ(Imm(64-8), Y1, Y1)
	VPOR(Y2, Y1, Y1)

	VPXOR(Y8, Y3, Y3)
	VPXOR(Y1, Y3, Y1)

	VPADDQ(Y1, Y0, Y0)

	VPERM2F128(Imm(0x0), Y0, Y0, Y6)

	VPAND(MASK_YMM_LO, Y0, Y0)

	VPERM2F128(Imm(0x11), Y5, Y5, Y2)
	VPSRLQ(Imm(6), Y2, Y8)

	MOVQ(R11, RDI)
	RORXQ(Imm(41), R8, R13)
	RORXQ(Imm(18), R8, R14)
	ADDQ(Mem{Base: SP}.Offset(1*8+frame_YFER), R10)
	ORQ(RBX, RDI)

	MOVQ(RDX, R15)
	RORXQ(Imm(34), R11, R12)
	XORQ(R14, R13)
	XORQ(R9, R15)

	RORXQ(Imm(14), R8, R14)
	XORQ(R14, R13)
	RORXQ(Imm(39), R11, R14)
	ANDQ(R8, R15)
	ADDQ(R10, RCX)

	ANDQ(RAX, RDI)
	XORQ(R12, R14)

	RORXQ(Imm(28), R11, R12)
	XORQ(R9, R15)

	XORQ(R12, R14)
	MOVQ(R11, R12)
	ANDQ(RBX, R12)
	ADDQ(R13, R15)

	ORQ(R12, RDI)
	ADDQ(R14, R10)

	ADDQ(R15, RCX)
	ADDQ(R15, R10)
	ADDQ(RDI, R10)

	VPSRLQ(Imm(19), Y2, Y3)
	VPSLLQ(Imm(64-19), Y2, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)
	VPSRLQ(Imm(61), Y2, Y3)
	VPSLLQ(Imm(64-61), Y2, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)

	VPADDQ(Y8, Y6, Y6)

	VPSRLQ(Imm(6), Y6, Y8)

	MOVQ(R10, RDI)
	RORXQ(Imm(41), RCX, R13)
	ADDQ(Mem{Base: SP}.Offset(2*8+frame_YFER), R9)

	RORXQ(Imm(18), RCX, R14)
	ORQ(RAX, RDI)
	MOVQ(R8, R15)
	XORQ(RDX, R15)

	RORXQ(Imm(34), R10, R12)
	XORQ(R14, R13)
	ANDQ(RCX, R15)

	RORXQ(Imm(14), RCX, R14)
	ADDQ(R9, RBX)
	ANDQ(R11, RDI)

	XORQ(R14, R13)
	RORXQ(Imm(39), R10, R14)
	XORQ(RDX, R15)

	XORQ(R12, R14)
	RORXQ(Imm(28), R10, R12)

	XORQ(R12, R14)
	MOVQ(R10, R12)
	ANDQ(RAX, R12)
	ADDQ(R13, R15)

	ORQ(R12, RDI)
	ADDQ(R14, R9)
	ADDQ(R15, RBX)
	ADDQ(R15, R9)

	ADDQ(RDI, R9)

	VPSRLQ(Imm(19), Y6, Y3)
	VPSLLQ(Imm(64-19), Y6, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)
	VPSRLQ(Imm(61), Y6, Y3)
	VPSLLQ(Imm(64-61), Y6, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)

	VPADDQ(Y8, Y0, Y2)

	VPBLENDD(Imm(0xF0), Y2, Y6, Y6)

	MOVQ(R9, RDI)
	RORXQ(Imm(41), RBX, R13)
	RORXQ(Imm(18), RBX, R14)
	ADDQ(Mem{Base: SP}.Offset(3*8+frame_YFER), RDX)
	ORQ(R11, RDI)

	MOVQ(RCX, R15)
	RORXQ(Imm(34), R9, R12)
	XORQ(R14, R13)
	XORQ(R8, R15)

	RORXQ(Imm(14), RBX, R14)
	ANDQ(RBX, R15)
	ADDQ(RDX, RAX)
	ANDQ(R10, RDI)

	XORQ(R14, R13)
	XORQ(R8, R15)

	RORXQ(Imm(39), R9, R14)
	ADDQ(R13, R15)

	XORQ(R12, R14)
	ADDQ(R15, RAX)

	RORXQ(Imm(28), R9, R12)

	XORQ(R12, R14)
	MOVQ(R9, R12)
	ANDQ(R11, R12)
	ORQ(R12, RDI)

	ADDQ(R14, RDX)
	ADDQ(R15, RDX)
	ADDQ(RDI, RDX)

	VPADDQ(Mem{Base: BP}.Offset(3*32), Y7, Y0)
	VMOVDQU(Y0, Mem{Base: SP}.Offset(frame_YFER))
	ADDQ(U8(4*32), RBP)

	MY_VPALIGNR(Y0, Y6, Y5, 8)

	VPADDQ(Y7, Y0, Y0)

	MY_VPALIGNR(Y1, Y4, Y7, 8)

	VPSRLQ(Imm(1), Y1, Y2)
	VPSLLQ(Imm(64-1), Y1, Y3)
	VPOR(Y2, Y3, Y3)

	VPSRLQ(Imm(7), Y1, Y8)

	MOVQ(RDX, RDI)
	RORXQ(Imm(41), RAX, R13)
	RORXQ(Imm(18), RAX, R14)
	ADDQ(Mem{Base: SP}.Offset(frame_YFER), R8)
	ORQ(R10, RDI)
	MOVQ(RBX, R15)
	RORXQ(Imm(34), RDX, R12)

	XORQ(R14, R13)
	XORQ(RCX, R15)
	RORXQ(Imm(14), RAX, R14)

	ANDQ(RAX, R15)
	XORQ(R14, R13)
	RORXQ(Imm(39), RDX, R14)
	ADDQ(R8, R11)

	ANDQ(R9, RDI)
	XORQ(R12, R14)
	RORXQ(Imm(28), RDX, R12)

	XORQ(RCX, R15)
	XORQ(R12, R14)
	MOVQ(RDX, R12)
	ANDQ(R10, R12)

	ADDQ(R13, R15)
	ORQ(R12, RDI)
	ADDQ(R14, R8)

	ADDQ(R15, R11)

	ADDQ(R15, R8)
	ADDQ(RDI, R8)

	VPSRLQ(Imm(8), Y1, Y2)
	VPSLLQ(Imm(64-8), Y1, Y1)
	VPOR(Y2, Y1, Y1)

	VPXOR(Y8, Y3, Y3)
	VPXOR(Y1, Y3, Y1)

	VPADDQ(Y1, Y0, Y0)

	VPERM2F128(Imm(0x0), Y0, Y0, Y7)

	VPAND(MASK_YMM_LO, Y0, Y0)

	VPERM2F128(Imm(0x11), Y6, Y6, Y2)
	VPSRLQ(Imm(6), Y2, Y8)

	MOVQ(R8, RDI)
	RORXQ(Imm(41), R11, R13)
	RORXQ(Imm(18), R11, R14)
	ADDQ(Mem{Base: SP}.Offset(1*8+frame_YFER), RCX)
	ORQ(R9, RDI)

	MOVQ(RAX, R15)
	RORXQ(Imm(34), R8, R12)
	XORQ(R14, R13)
	XORQ(RBX, R15)

	RORXQ(Imm(14), R11, R14)
	XORQ(R14, R13)
	RORXQ(Imm(39), R8, R14)
	ANDQ(R11, R15)
	ADDQ(RCX, R10)

	ANDQ(RDX, RDI)
	XORQ(R12, R14)

	RORXQ(Imm(28), R8, R12)
	XORQ(RBX, R15)

	XORQ(R12, R14)
	MOVQ(R8, R12)
	ANDQ(R9, R12)
	ADDQ(R13, R15)

	ORQ(R12, RDI)
	ADDQ(R14, RCX)

	ADDQ(R15, R10)
	ADDQ(R15, RCX)
	ADDQ(RDI, RCX)

	VPSRLQ(Imm(19), Y2, Y3)
	VPSLLQ(Imm(64-19), Y2, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)
	VPSRLQ(Imm(61), Y2, Y3)
	VPSLLQ(Imm(64-61), Y2, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)

	VPADDQ(Y8, Y7, Y7)

	VPSRLQ(Imm(6), Y7, Y8)

	MOVQ(RCX, RDI)
	RORXQ(Imm(41), R10, R13)
	ADDQ(Mem{Base: SP}.Offset(2*8+frame_YFER), RBX)

	RORXQ(Imm(18), R10, R14)
	ORQ(RDX, RDI)
	MOVQ(R11, R15)
	XORQ(RAX, R15)

	RORXQ(Imm(34), RCX, R12)
	XORQ(R14, R13)
	ANDQ(R10, R15)

	RORXQ(Imm(14), R10, R14)
	ADDQ(RBX, R9)
	ANDQ(R8, RDI)

	XORQ(R14, R13)
	RORXQ(Imm(39), RCX, R14)
	XORQ(RAX, R15)

	XORQ(R12, R14)
	RORXQ(Imm(28), RCX, R12)

	XORQ(R12, R14)
	MOVQ(RCX, R12)
	ANDQ(RDX, R12)
	ADDQ(R13, R15)

	ORQ(R12, RDI)
	ADDQ(R14, RBX)
	ADDQ(R15, R9)
	ADDQ(R15, RBX)

	ADDQ(RDI, RBX)

	VPSRLQ(Imm(19), Y7, Y3)
	VPSLLQ(Imm(64-19), Y7, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)
	VPSRLQ(Imm(61), Y7, Y3)
	VPSLLQ(Imm(64-61), Y7, Y1)
	VPOR(Y1, Y3, Y3)
	VPXOR(Y3, Y8, Y8)

	VPADDQ(Y8, Y0, Y2)

	VPBLENDD(Imm(0xF0), Y2, Y7, Y7)

	MOVQ(RBX, RDI)
	RORXQ(Imm(41), R9, R13)
	RORXQ(Imm(18), R9, R14)
	ADDQ(Mem{Base: SP}.Offset(3*8+frame_YFER), RAX)
	ORQ(R8, RDI)

	MOVQ(R10, R15)
	RORXQ(Imm(34), RBX, R12)
	XORQ(R14, R13)
	XORQ(R11, R15)

	RORXQ(Imm(14), R9, R14)
	ANDQ(R9, R15)
	ADDQ(RAX, RDX)
	ANDQ(RCX, RDI)

	XORQ(R14, R13)
	XORQ(R11, R15)

	RORXQ(Imm(39), RBX, R14)
	ADDQ(R13, R15)

	XORQ(R12, R14)
	ADDQ(R15, RDX)

	RORXQ(Imm(28), RBX, R12)

	XORQ(R12, R14)
	MOVQ(RBX, R12)
	ANDQ(R8, R12)
	ORQ(R12, RDI)

	ADDQ(R14, RAX)
	ADDQ(R15, RAX)
	ADDQ(RDI, RAX)

	SUBQ(Imm(1), Mem{Base: SP}.Offset(frame_SRND))
	JNE(LabelRef("loop1"))

	MOVQ(U32(2), Mem{Base: SP}.Offset(frame_SRND))
}

// Line 1164
func loop2() {
	Label("loop2")
	VPADDQ(Mem{Base: BP}, Y4, Y0)
	VMOVDQU(Y0, Mem{Base: SP}.Offset(frame_YFER))

	MOVQ(R9, R15)
	RORXQ(Imm(41), RDX, R13)
	RORXQ(Imm(18), RDX, R14)
	XORQ(R10, R15)

	XORQ(R14, R13)
	RORXQ(Imm(14), RDX, R14)
	ANDQ(RDX, R15)

	XORQ(R14, R13)
	RORXQ(Imm(34), RAX, R12)
	XORQ(R10, R15)
	RORXQ(Imm(39), RAX, R14)
	MOVQ(RAX, RDI)

	XORQ(R12, R14)
	RORXQ(Imm(28), RAX, R12)
	ADDQ(Mem{Base: SP}.Offset(frame_YFER), R11)
	ORQ(RCX, RDI)

	XORQ(R12, R14)
	MOVQ(RAX, R12)
	ANDQ(RBX, RDI)
	ANDQ(RCX, R12)
	ADDQ(R13, R15)

	ADDQ(R11, R8)
	ORQ(R12, RDI)
	ADDQ(R14, R11)

	ADDQ(R15, R8)

	ADDQ(R15, R11)
	MOVQ(RDX, R15)
	RORXQ(Imm(41), R8, R13)
	RORXQ(Imm(18), R8, R14)
	XORQ(R9, R15)

	XORQ(R14, R13)
	RORXQ(Imm(14), R8, R14)
	ANDQ(R8, R15)
	ADDQ(RDI, R11)

	XORQ(R14, R13)
	RORXQ(Imm(34), R11, R12)
	XORQ(R9, R15)
	RORXQ(Imm(39), R11, R14)
	MOVQ(R11, RDI)

	XORQ(R12, R14)
	RORXQ(Imm(28), R11, R12)
	ADDQ(Mem{Base: SP}.Offset(8*1+frame_YFER), R10)
	ORQ(RBX, RDI)

	XORQ(R12, R14)
	MOVQ(R11, R12)
	ANDQ(RAX, RDI)
	ANDQ(RBX, R12)
	ADDQ(R13, R15)

	ADDQ(R10, RCX)
	ORQ(R12, RDI)
	ADDQ(R14, R10)

	ADDQ(R15, RCX)

	ADDQ(R15, R10)
	MOVQ(R8, R15)
	RORXQ(Imm(41), RCX, R13)
	RORXQ(Imm(18), RCX, R14)
	XORQ(RDX, R15)

	XORQ(R14, R13)
	RORXQ(Imm(14), RCX, R14)
	ANDQ(RCX, R15)
	ADDQ(RDI, R10)

	XORQ(R14, R13)
	RORXQ(Imm(34), R10, R12)
	XORQ(RDX, R15)
	RORXQ(Imm(39), R10, R14)
	MOVQ(R10, RDI)

	XORQ(R12, R14)
	RORXQ(Imm(28), R10, R12)
	ADDQ(Mem{Base: SP}.Offset(8*2+frame_YFER), R9)
	ORQ(RAX, RDI)

	XORQ(R12, R14)
	MOVQ(R10, R12)
	ANDQ(R11, RDI)
	ANDQ(RAX, R12)
	ADDQ(R13, R15)

	ADDQ(R9, RBX)
	ORQ(R12, RDI)
	ADDQ(R14, R9)

	ADDQ(R15, RBX)

	ADDQ(R15, R9)
	MOVQ(RCX, R15)
	RORXQ(Imm(41), RBX, R13)
	RORXQ(Imm(18), RBX, R14)
	XORQ(R8, R15)

	XORQ(R14, R13)
	RORXQ(Imm(14), RBX, R14)
	ANDQ(RBX, R15)
	ADDQ(RDI, R9)

	XORQ(R14, R13)
	RORXQ(Imm(34), R9, R12)
	XORQ(R8, R15)
	RORXQ(Imm(39), R9, R14)
	MOVQ(R9, RDI)

	XORQ(R12, R14)
	RORXQ(Imm(28), R9, R12)
	ADDQ(Mem{Base: SP}.Offset(8*3+frame_YFER), RDX)
	ORQ(R11, RDI)

	XORQ(R12, R14)
	MOVQ(R9, R12)
	ANDQ(R10, RDI)
	ANDQ(R11, R12)
	ADDQ(R13, R15)

	ADDQ(RDX, RAX)
	ORQ(R12, RDI)
	ADDQ(R14, RDX)

	ADDQ(R15, RAX)

	ADDQ(R15, RDX)

	ADDQ(RDI, RDX)

	VPADDQ(Mem{Base: BP}.Offset(1*32), Y5, Y0)
	VMOVDQU(Y0, Mem{Base: SP}.Offset(frame_YFER))
	ADDQ(U8(2*32), RBP)

	MOVQ(RBX, R15)
	RORXQ(Imm(41), RAX, R13)
	RORXQ(Imm(18), RAX, R14)
	XORQ(RCX, R15)

	XORQ(R14, R13)
	RORXQ(Imm(14), RAX, R14)
	ANDQ(RAX, R15)

	XORQ(R14, R13)
	RORXQ(Imm(34), RDX, R12)
	XORQ(RCX, R15)
	RORXQ(Imm(39), RDX, R14)
	MOVQ(RDX, RDI)

	XORQ(R12, R14)
	RORXQ(Imm(28), RDX, R12)
	ADDQ(Mem{Base: SP}.Offset(frame_YFER), R8)
	ORQ(R10, RDI)

	XORQ(R12, R14)
	MOVQ(RDX, R12)
	ANDQ(R9, RDI)
	ANDQ(R10, R12)
	ADDQ(R13, R15)

	ADDQ(R8, R11)
	ORQ(R12, RDI)
	ADDQ(R14, R8)

	ADDQ(R15, R11)

	ADDQ(R15, R8)
	MOVQ(RAX, R15)
	RORXQ(Imm(41), R11, R13)
	RORXQ(Imm(18), R11, R14)
	XORQ(RBX, R15)

	XORQ(R14, R13)
	RORXQ(Imm(14), R11, R14)
	ANDQ(R11, R15)
	ADDQ(RDI, R8)

	XORQ(R14, R13)
	RORXQ(Imm(34), R8, R12)
	XORQ(RBX, R15)
	RORXQ(Imm(39), R8, R14)
	MOVQ(R8, RDI)

	XORQ(R12, R14)
	RORXQ(Imm(28), R8, R12)
	ADDQ(Mem{Base: SP}.Offset(8*1+frame_YFER), RCX)
	ORQ(R9, RDI)

	XORQ(R12, R14)
	MOVQ(R8, R12)
	ANDQ(RDX, RDI)
	ANDQ(R9, R12)
	ADDQ(R13, R15)

	ADDQ(RCX, R10)
	ORQ(R12, RDI)
	ADDQ(R14, RCX)

	ADDQ(R15, R10)

	ADDQ(R15, RCX)
	MOVQ(R11, R15)
	RORXQ(Imm(41), R10, R13)
	RORXQ(Imm(18), R10, R14)
	XORQ(RAX, R15)

	XORQ(R14, R13)
	RORXQ(Imm(14), R10, R14)
	ANDQ(R10, R15)
	ADDQ(RDI, RCX)

	XORQ(R14, R13)
	RORXQ(Imm(34), RCX, R12)
	XORQ(RAX, R15)
	RORXQ(Imm(39), RCX, R14)
	MOVQ(RCX, RDI)

	XORQ(R12, R14)
	RORXQ(Imm(28), RCX, R12)
	ADDQ(Mem{Base: SP}.Offset(8*2+frame_YFER), RBX)
	ORQ(RDX, RDI)

	XORQ(R12, R14)
	MOVQ(RCX, R12)
	ANDQ(R8, RDI)
	ANDQ(RDX, R12)
	ADDQ(R13, R15)

	ADDQ(RBX, R9)
	ORQ(R12, RDI)
	ADDQ(R14, RBX)

	ADDQ(R15, R9)

	ADDQ(R15, RBX)
	MOVQ(R10, R15)
	RORXQ(Imm(41), R9, R13)
	RORXQ(Imm(18), R9, R14)
	XORQ(R11, R15)

	XORQ(R14, R13)
	RORXQ(Imm(14), R9, R14)
	ANDQ(R9, R15)
	ADDQ(RDI, RBX)

	XORQ(R14, R13)
	RORXQ(Imm(34), RBX, R12)
	XORQ(R11, R15)
	RORXQ(Imm(39), RBX, R14)
	MOVQ(RBX, RDI)

	XORQ(R12, R14)
	RORXQ(Imm(28), RBX, R12)
	ADDQ(Mem{Base: SP}.Offset(8*3+frame_YFER), RAX)
	ORQ(R8, RDI)

	XORQ(R12, R14)
	MOVQ(RBX, R12)
	ANDQ(RCX, RDI)
	ANDQ(R8, R12)
	ADDQ(R13, R15)

	ADDQ(RAX, RDX)
	ORQ(R12, RDI)
	ADDQ(R14, RAX)

	ADDQ(R15, RDX)

	ADDQ(R15, RAX)

	ADDQ(RDI, RAX)

	VMOVDQU(Y6, Y4)
	VMOVDQU(Y7, Y5)

	SUBQ(Imm(1), Mem{Base: SP}.Offset(frame_SRND))
	JNE(LabelRef("loop2"))

	addm(Mem{Base: SI}.Offset(8*0), RAX)
	addm(Mem{Base: SI}.Offset(8*1), RBX)
	addm(Mem{Base: SI}.Offset(8*2), RCX)
	addm(Mem{Base: SI}.Offset(8*3), R8)
	addm(Mem{Base: SI}.Offset(8*4), RDX)
	addm(Mem{Base: SI}.Offset(8*5), R9)
	addm(Mem{Base: SI}.Offset(8*6), R10)
	addm(Mem{Base: SI}.Offset(8*7), R11)

	MOVQ(Mem{Base: SP}.Offset(frame_INP), RDI)
	ADDQ(Imm(128), RDI)
	CMPQ(RDI, Mem{Base: SP}.Offset(frame_INPEND))
	JNE(LabelRef("loop0"))
}

// Line 1468
func done_hash() {
	Label("done_hash")
	VZEROUPPER()
	RET()
}

// ##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~DATA SECTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##

// Pointers for memoizing Data section symbols
var PSHUFFLE_BYTE_FLIP_MASK_DATA_ptr, MASK_YMM_LO_ptr *Mem

// Line 310
func PSHUFFLE_BYTE_FLIP_MASK_DATA() Mem {
	if PSHUFFLE_BYTE_FLIP_MASK_DATA_ptr != nil {
		return *PSHUFFLE_BYTE_FLIP_MASK_DATA_ptr
	}

	PSHUFFLE_BYTE_FLIP_MASK_DATA := GLOBL("PSHUFFLE_BYTE_FLIP_MASK", NOPTR|RODATA)
	PSHUFFLE_BYTE_FLIP_MASK_DATA_ptr = &PSHUFFLE_BYTE_FLIP_MASK_DATA
	DATA(0x00, U64(0x0001020304050607))
	DATA(0x08, U64(0x08090a0b0c0d0e0f))
	DATA(0x10, U64(0x1011121314151617))
	DATA(0x18, U64(0x18191a1b1c1d1e1f))
	return PSHUFFLE_BYTE_FLIP_MASK_DATA
}

// Line 317
func MASK_YMM_LO_DATA() Mem {
	if MASK_YMM_LO_ptr != nil {
		return *MASK_YMM_LO_ptr
	}

	MASK_YMM_LO := GLOBL("MASK_YMM_LO", NOPTR|RODATA)
	MASK_YMM_LO_ptr = &MASK_YMM_LO
	DATA(0x00, U64(0x0000000000000000))
	DATA(0x08, U64(0x0000000000000000))
	DATA(0x10, U64(0xFFFFFFFFFFFFFFFF))
	DATA(0x18, U64(0xFFFFFFFFFFFFFFFF))
	return MASK_YMM_LO
}

"""



```