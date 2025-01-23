Response:
Let's break down the thought process for analyzing this Go assembly generation code.

1. **Initial Scan for Keywords and Structure:** The first step is to quickly scan the code for recognizable Go keywords and patterns. We see `package main`, `import`, `//go:generate`, `var`, `func main()`, and function definitions like `keccakF1600()`. The `//go:generate` line is a big clue, suggesting code generation is a primary function. The `avo` imports stand out as less common, hinting at assembly generation.

2. **Identify the Core Functionality:** The `main` function's `os.Setenv` calls and the `Package`, `ConstraintExpr`, `keccakF1600`, and `Generate` calls strongly suggest this program *generates* Go assembly code. The file path also indicates it's related to `crypto/internal/fips140/sha3`. Combining these, the primary function is generating optimized assembly for the Keccak-f1600 permutation used in SHA-3.

3. **Analyze the `//go:generate` Directive:**  The line `//go:generate go run . -out ../sha3_amd64.s` is crucial. It tells us *how* the code generation happens. It runs the current file (`.`) as a Go program and uses the `-out` flag to specify the output file name (`../sha3_amd64.s`). This confirms the code's role as a code generator.

4. **Examine the Imports:**  The imports confirm the suspicion of assembly generation. `github.com/mmcloughlin/avo/build`, `github.com/mmcloughlin/avo/operand`, and `github.com/mmcloughlin/avo/reg` are all part of the `avo` assembly generation library. The import of `golang.org/x/crypto/sha3` indicates the generated assembly will be used by the standard SHA-3 library.

5. **Understand the `keccakF1600` Function:**  This function appears to be the heart of the assembly generation. The `Implement("keccakF1600")` call likely tells `avo` to generate assembly for a function named `keccakF1600`. The code within this function manipulates registers and memory (`MOVQ`, `XORQ`, `ROLQ`), which are typical assembly instructions. The `rpState` and `rpStack` variables suggest it's operating on some internal state. The loop and the `mKeccakRound` function clearly implement the repeated rounds of the Keccak permutation.

6. **Deconstruct `mKeccakRound`:** This function is a macro or a helper function to generate the assembly code for a single round of the Keccak permutation. The `ArgMacro` type and the way the function is called within the loop suggest it's designed to generate similar blocks of assembly with slight variations. The comments within this function ("Prepare round", "Result b", etc.) align with the steps of the Keccak algorithm.

7. **Identify Constants and Variables:** The `RoundConstants` array is clearly the round constants used in the Keccak algorithm. The `rT1`, `rpState`, `rpStack`, and `rDa` through `rCu` variables are registers used in the assembly code. The constants `_ba`, `_be`, etc., appear to be offsets within the state array.

8. **Infer the Go Language Feature:** Based on the file path, imports, and the `keccakF1600` function's structure, it's highly probable this code implements the core Keccak-f1600 permutation, a fundamental building block of the SHA-3 algorithm. This is further reinforced by the mention of "Round Constants" and the general structure resembling the steps of the Keccak algorithm.

9. **Construct the Example:** To illustrate the Go feature, we need to show how the generated assembly is used. The `golang.org/x/crypto/sha3` import is the key. A simple example would involve hashing some data using `sha3.NewKeccak256()` (or a similar function) and demonstrating that the optimized assembly is used under the hood when `!purego` is in effect. The input and output for the example should be basic, like hashing a short string.

10. **Explain Command-Line Arguments:** The `//go:generate` directive directly shows how to run the program and the meaning of the `-out` flag. This part is relatively straightforward.

11. **Identify Potential Pitfalls:**  The `//go:generate` directive itself is a source of potential errors. Users might forget to run it, run it in the wrong directory, or have issues with the `avo` library setup. Also, directly modifying the generated assembly is a bad practice as it will be overwritten.

12. **Structure the Answer:** Finally, organize the findings into the requested sections: functionality, Go feature implementation with example, command-line arguments, and potential pitfalls. Use clear and concise language, explaining technical terms where necessary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe it's just some utility code related to SHA-3.
* **Correction:** The `avo` imports and the structure of `keccakF1600` strongly suggest code *generation*, not just utility functions.
* **Initial thought:** The example should involve direct calls to the assembly.
* **Correction:** The beauty of this approach is the seamless integration. The example should demonstrate how the standard `crypto/sha3` package *uses* the generated assembly implicitly when the constraints are met.
* **Consideration:**  Should I explain the Keccak algorithm in detail?
* **Decision:**  Focus on the code's function as a *generator*. Briefly mentioning that it's for the Keccak permutation is sufficient without going deep into the algorithm's specifics. The comments within the code offer some hints for those familiar with Keccak.

By following these steps and iteratively refining the understanding, we can arrive at a comprehensive and accurate explanation of the provided code snippet.
这段代码是 Go 语言标准库 `crypto/internal/fips140/sha3` 包中用于生成 AMD64 汇编代码的一部分，专门针对 Keccak-f1600 算法的实现。

**功能列举:**

1. **生成 Keccak-f1600 算法的 AMD64 汇编代码:**  这是代码的主要目的。它使用 `avo` 库（一个 Go 语言的汇编代码生成器）来产生高效的汇编指令，以实现 Keccak-f1600 这一核心的 SHA-3 算法的置换操作。
2. **定义 Keccak-f1600 算法的轮常数 (Round Constants):** `RoundConstants` 变量存储了 Keccak 算法每一轮迭代中使用的常数值。
3. **定义临时寄存器和状态变量:** 代码中定义了一系列寄存器（如 `rT1`, `rDa`, `rBe` 等）和内存地址（如 `rpState`, `rpStack`），用于在汇编代码生成过程中表示和操作 Keccak 算法的状态。
4. **实现 Keccak 轮函数 (`mKeccakRound`):**  `mKeccakRound` 函数是一个用于生成单轮 Keccak 运算汇编代码的“宏”或模板。它接收输入和输出状态的内存地址、轮常数以及一系列用于生成不同汇编指令的 `ArgMacro` 函数。
5. **实现完整的 Keccak-f1600 置换函数 (`keccakF1600`):** `keccakF1600` 函数通过循环调用 `mKeccakRound` 来生成 24 轮 Keccak 置换的汇编代码。
6. **使用 `avo` 库的 API:**  代码大量使用了 `avo` 库提供的函数和类型，如 `Package`, `ConstraintExpr`, `MOVQ`, `XORQ`, `ROLQ`, `Implement`, `AllocLocal`, `Load`, `RET`, `Generate` 等，来构建汇编指令。
7. **设置构建环境:** `main` 函数中使用了 `os.Setenv` 来设置 `GOOS` 和 `GOARCH` 环境变量，这通常是为了确保 `avo` 库能够生成目标平台的汇编代码。
8. **使用 `//go:generate` 指令:**  `//go:generate go run . -out ../sha3_amd64.s` 指令表明可以通过运行当前 Go 程序来生成汇编代码，并将输出保存到 `../sha3_amd64.s` 文件中。

**Go 语言功能实现推理 (基于代码结构和 `avo` 库的使用):**

这段代码的核心功能是利用 Go 语言的元编程能力，通过 `avo` 库动态生成汇编代码。 这是一种常见的优化手段，尤其是在密码学等对性能要求极高的领域。  通过手写汇编或者使用汇编代码生成器，可以更精细地控制硬件资源，获得比纯 Go 代码更高的执行效率。

**Go 代码示例 (说明如何使用 `crypto/sha3` 包，并间接使用到生成的汇编代码):**

```go
package main

import (
	"fmt"
	"golang.org/x/crypto/sha3"
)

func main() {
	data := []byte("hello world")

	// 创建一个 Keccak-256 哈希对象
	h := sha3.New256()

	// 写入数据
	h.Write(data)

	// 计算哈希值
	hash := h.Sum(nil)

	fmt.Printf("SHA3-256 hash of '%s': %x\n", string(data), hash)

	// 如果构建时满足了代码中的约束条件 (!purego)，
	// 那么在底层的 Keccak-f1600 运算中，将会使用生成的 AMD64 汇编代码，
	// 而不是纯 Go 实现。
}
```

**假设输入与输出 (针对 `keccakF1600` 函数的生成结果):**

由于这段代码是生成器，它的输入是 Go 代码本身，输出是汇编代码。  假设我们运行了 `go generate` 命令，并且当前的 Go 环境配置为 AMD64 架构，那么 `keccakF1600` 函数将会生成类似于以下的 AMD64 汇编代码片段（这只是一个简化的示意，实际生成的代码会更复杂）：

```assembly
// ... 其他汇编指令 ...

// func keccakF1600()
TEXT ·keccakF1600(SB), NOSPLIT, $200-8
	// Allocate local frame
	SUBQ $200, RSP
	MOVQ RSP, RP // RP is likely the frame pointer

	// Load the input state
	MOVQ a+0(FP), DI // 将输入参数 'a' (指向状态的指针) 加载到 RDI 寄存器

	// Convert the user state into an internal state
	NOTQ 1*8(DI) //  对状态的某些部分进行位运算 (对应 Go 代码中的 NOTQ)
	NOTQ 2*8(DI)
	// ... 其他 NOTQ 指令 ...

	// Execute the KeccakF permutation
	MOVQ 0*8(DI), AX  // 将状态的某些部分加载到寄存器 (对应 Go 代码中的 MOVQ)
	MOVQ 1*8(DI), CX
	MOVQ 4*8(DI), R9

	XORQ 5*8(DI), AX  // 进行异或运算 (对应 Go 代码中的 XORQ)
	XORQ 6*8(DI), CX
	XORQ 9*8(DI), R9

	// ... 循环调用 mKeccakRound 生成的汇编代码 ...

	// Revert the internal state to the user state
	NOTQ 1*8(DI)
	NOTQ 2*8(DI)
	// ... 其他 NOTQ 指令 ...

	// Return
	ADDQ $200, RSP
	RET

// ... 其他汇编指令 ...
```

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。  但是，它使用了 `//go:generate` 指令。  当你在代码所在的目录下运行 `go generate` 命令时，Go 工具链会执行 `//go:generate` 后面的命令，即：

```bash
go run . -out ../sha3_amd64.s
```

这里的命令行参数是：

* **`.`**: 这表示运行当前目录下的 Go 源文件（即 `keccakf_amd64_asm.go`）。
* **`-out ../sha3_amd64.s`**: 这是一个由 `avo` 库（或者可能是代码自身通过某种方式处理）识别的参数，用于指定生成的汇编代码的输出文件路径为当前目录的上一级目录下的 `sha3_amd64.s` 文件。

**使用者易犯错的点:**

1. **忘记运行 `go generate`:**  如果开发者修改了 `keccakf_amd64_asm.go` 文件，但没有运行 `go generate` 命令，那么 `../sha3_amd64.s` 中的汇编代码将不会更新，这可能导致构建出的程序使用的不是最新的优化实现。
2. **`avo` 库环境问题:**  如果开发者没有正确安装或配置 `avo` 库，运行 `go generate` 命令将会失败。
3. **修改生成的汇编代码:** 开发者可能会尝试直接修改 `../sha3_amd64.s` 文件中的汇编代码。这样做是不推荐的，因为下次运行 `go generate` 时，这些修改将会被覆盖。  如果需要修改汇编逻辑，应该修改 `keccakf_amd64_asm.go` 这个生成器文件。
4. **构建约束条件不满足:** 代码中有 `ConstraintExpr("!purego")`。这意味着生成的汇编代码只有在构建时满足 `!purego` 这个条件时才会被使用。 如果构建时使用了 `purego` 标签，那么将会使用纯 Go 实现的 Keccak 算法，而不会使用生成的汇编代码。开发者可能没有意识到这一点，导致性能不如预期。
5. **不理解代码生成流程:**  开发者可能不清楚 `keccakf_amd64_asm.go` 的作用是生成汇编代码，而不是直接参与程序的运行时逻辑。这可能导致他们以错误的方式理解和使用 `crypto/sha3` 包。

总而言之，这段代码是 Go 语言中一种高级的优化技巧，利用代码生成来提升密码学算法的性能。它展示了如何使用 `avo` 库在 Go 中生成汇编代码，并将其集成到标准库中。理解其功能和使用方式对于进行底层性能优化至关重要。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/sha3/_asm/keccakf_amd64_asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This code was translated into a form compatible with 6a from the public
// domain sources at https://github.com/gvanas/KeccakCodePackage

package main

import (
	"os"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
	_ "golang.org/x/crypto/sha3"
)

//go:generate go run . -out ../sha3_amd64.s

// Round Constants for use in the ι step.
var RoundConstants = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

var (
	// Temporary registers
	rT1 GPPhysical = RAX

	// Round vars
	rpState = Mem{Base: RDI}
	rpStack = Mem{Base: RSP}

	rDa = RBX
	rDe = RCX
	rDi = RDX
	rDo = R8
	rDu = R9

	rBa = R10
	rBe = R11
	rBi = R12
	rBo = R13
	rBu = R14

	rCa = RSI
	rCe = RBP
	rCi = rBi
	rCo = rBo
	rCu = R15
)

const (
	_ba = iota * 8
	_be
	_bi
	_bo
	_bu
	_ga
	_ge
	_gi
	_go
	_gu
	_ka
	_ke
	_ki
	_ko
	_ku
	_ma
	_me
	_mi
	_mo
	_mu
	_sa
	_se
	_si
	_so
	_su
)

func main() {
	// https://github.com/mmcloughlin/avo/issues/450
	os.Setenv("GOOS", "linux")
	os.Setenv("GOARCH", "amd64")

	Package("crypto/internal/fips140/sha3")
	ConstraintExpr("!purego")
	keccakF1600()
	Generate()
}

func MOVQ_RBI_RCE() { MOVQ(rBi, rCe) }
func XORQ_RT1_RCA() { XORQ(rT1, rCa) }
func XORQ_RT1_RCE() { XORQ(rT1, rCe) }
func XORQ_RBA_RCU() { XORQ(rBa, rCu) }
func XORQ_RBE_RCU() { XORQ(rBe, rCu) }
func XORQ_RDU_RCU() { XORQ(rDu, rCu) }
func XORQ_RDA_RCA() { XORQ(rDa, rCa) }
func XORQ_RDE_RCE() { XORQ(rDe, rCe) }

type ArgMacro func()

func mKeccakRound(
	iState, oState Mem,
	rc U64,
	B_RBI_RCE, G_RT1_RCA, G_RT1_RCE, G_RBA_RCU,
	K_RT1_RCA, K_RT1_RCE, K_RBA_RCU, M_RT1_RCA,
	M_RT1_RCE, M_RBE_RCU, S_RDU_RCU, S_RDA_RCA,
	S_RDE_RCE ArgMacro,
) {
	Comment("Prepare round")
	MOVQ(rCe, rDa)
	ROLQ(Imm(1), rDa)

	MOVQ(iState.Offset(_bi), rCi)
	XORQ(iState.Offset(_gi), rDi)
	XORQ(rCu, rDa)
	XORQ(iState.Offset(_ki), rCi)
	XORQ(iState.Offset(_mi), rDi)
	XORQ(rDi, rCi)

	MOVQ(rCi, rDe)
	ROLQ(Imm(1), rDe)

	MOVQ(iState.Offset(_bo), rCo)
	XORQ(iState.Offset(_go), rDo)
	XORQ(rCa, rDe)
	XORQ(iState.Offset(_ko), rCo)
	XORQ(iState.Offset(_mo), rDo)
	XORQ(rDo, rCo)

	MOVQ(rCo, rDi)
	ROLQ(Imm(1), rDi)

	MOVQ(rCu, rDo)
	XORQ(rCe, rDi)
	ROLQ(Imm(1), rDo)

	MOVQ(rCa, rDu)
	XORQ(rCi, rDo)
	ROLQ(Imm(1), rDu)

	Comment("Result b")
	MOVQ(iState.Offset(_ba), rBa)
	MOVQ(iState.Offset(_ge), rBe)
	XORQ(rCo, rDu)
	MOVQ(iState.Offset(_ki), rBi)
	MOVQ(iState.Offset(_mo), rBo)
	MOVQ(iState.Offset(_su), rBu)
	XORQ(rDe, rBe)
	ROLQ(Imm(44), rBe)
	XORQ(rDi, rBi)
	XORQ(rDa, rBa)
	ROLQ(Imm(43), rBi)

	MOVQ(rBe, rCa)
	MOVQ(rc, rT1)
	ORQ(rBi, rCa)
	XORQ(rBa, rT1)
	XORQ(rT1, rCa)
	MOVQ(rCa, oState.Offset(_ba))

	XORQ(rDu, rBu)
	ROLQ(Imm(14), rBu)
	MOVQ(rBa, rCu)
	ANDQ(rBe, rCu)
	XORQ(rBu, rCu)
	MOVQ(rCu, oState.Offset(_bu))

	XORQ(rDo, rBo)
	ROLQ(Imm(21), rBo)
	MOVQ(rBo, rT1)
	ANDQ(rBu, rT1)
	XORQ(rBi, rT1)
	MOVQ(rT1, oState.Offset(_bi))

	NOTQ(rBi)
	ORQ(rBa, rBu)
	ORQ(rBo, rBi)
	XORQ(rBo, rBu)
	XORQ(rBe, rBi)
	MOVQ(rBu, oState.Offset(_bo))
	MOVQ(rBi, oState.Offset(_be))
	B_RBI_RCE()

	Comment("Result g")
	MOVQ(iState.Offset(_gu), rBe)
	XORQ(rDu, rBe)
	MOVQ(iState.Offset(_ka), rBi)
	ROLQ(Imm(20), rBe)
	XORQ(rDa, rBi)
	ROLQ(Imm(3), rBi)
	MOVQ(iState.Offset(_bo), rBa)
	MOVQ(rBe, rT1)
	ORQ(rBi, rT1)
	XORQ(rDo, rBa)
	MOVQ(iState.Offset(_me), rBo)
	MOVQ(iState.Offset(_si), rBu)
	ROLQ(Imm(28), rBa)
	XORQ(rBa, rT1)
	MOVQ(rT1, oState.Offset(_ga))
	G_RT1_RCA()

	XORQ(rDe, rBo)
	ROLQ(Imm(45), rBo)
	MOVQ(rBi, rT1)
	ANDQ(rBo, rT1)
	XORQ(rBe, rT1)
	MOVQ(rT1, oState.Offset(_ge))
	G_RT1_RCE()

	XORQ(rDi, rBu)
	ROLQ(Imm(61), rBu)
	MOVQ(rBu, rT1)
	ORQ(rBa, rT1)
	XORQ(rBo, rT1)
	MOVQ(rT1, oState.Offset(_go))

	ANDQ(rBe, rBa)
	XORQ(rBu, rBa)
	MOVQ(rBa, oState.Offset(_gu))
	NOTQ(rBu)
	G_RBA_RCU()

	ORQ(rBu, rBo)
	XORQ(rBi, rBo)
	MOVQ(rBo, oState.Offset(_gi))

	Comment("Result k")
	MOVQ(iState.Offset(_be), rBa)
	MOVQ(iState.Offset(_gi), rBe)
	MOVQ(iState.Offset(_ko), rBi)
	MOVQ(iState.Offset(_mu), rBo)
	MOVQ(iState.Offset(_sa), rBu)
	XORQ(rDi, rBe)
	ROLQ(Imm(6), rBe)
	XORQ(rDo, rBi)
	ROLQ(Imm(25), rBi)
	MOVQ(rBe, rT1)
	ORQ(rBi, rT1)
	XORQ(rDe, rBa)
	ROLQ(Imm(1), rBa)
	XORQ(rBa, rT1)
	MOVQ(rT1, oState.Offset(_ka))
	K_RT1_RCA()

	XORQ(rDu, rBo)
	ROLQ(Imm(8), rBo)
	MOVQ(rBi, rT1)
	ANDQ(rBo, rT1)
	XORQ(rBe, rT1)
	MOVQ(rT1, oState.Offset(_ke))
	K_RT1_RCE()

	XORQ(rDa, rBu)
	ROLQ(Imm(18), rBu)
	NOTQ(rBo)
	MOVQ(rBo, rT1)
	ANDQ(rBu, rT1)
	XORQ(rBi, rT1)
	MOVQ(rT1, oState.Offset(_ki))

	MOVQ(rBu, rT1)
	ORQ(rBa, rT1)
	XORQ(rBo, rT1)
	MOVQ(rT1, oState.Offset(_ko))

	ANDQ(rBe, rBa)
	XORQ(rBu, rBa)
	MOVQ(rBa, oState.Offset(_ku))
	K_RBA_RCU()

	Comment("Result m")
	MOVQ(iState.Offset(_ga), rBe)
	XORQ(rDa, rBe)
	MOVQ(iState.Offset(_ke), rBi)
	ROLQ(Imm(36), rBe)
	XORQ(rDe, rBi)
	MOVQ(iState.Offset(_bu), rBa)
	ROLQ(Imm(10), rBi)
	MOVQ(rBe, rT1)
	MOVQ(iState.Offset(_mi), rBo)
	ANDQ(rBi, rT1)
	XORQ(rDu, rBa)
	MOVQ(iState.Offset(_so), rBu)
	ROLQ(Imm(27), rBa)
	XORQ(rBa, rT1)
	MOVQ(rT1, oState.Offset(_ma))
	M_RT1_RCA()

	XORQ(rDi, rBo)
	ROLQ(Imm(15), rBo)
	MOVQ(rBi, rT1)
	ORQ(rBo, rT1)
	XORQ(rBe, rT1)
	MOVQ(rT1, oState.Offset(_me))
	M_RT1_RCE()

	XORQ(rDo, rBu)
	ROLQ(Imm(56), rBu)
	NOTQ(rBo)
	MOVQ(rBo, rT1)
	ORQ(rBu, rT1)
	XORQ(rBi, rT1)
	MOVQ(rT1, oState.Offset(_mi))

	ORQ(rBa, rBe)
	XORQ(rBu, rBe)
	MOVQ(rBe, oState.Offset(_mu))

	ANDQ(rBa, rBu)
	XORQ(rBo, rBu)
	MOVQ(rBu, oState.Offset(_mo))
	M_RBE_RCU()

	Comment("Result s")
	MOVQ(iState.Offset(_bi), rBa)
	MOVQ(iState.Offset(_go), rBe)
	MOVQ(iState.Offset(_ku), rBi)
	XORQ(rDi, rBa)
	MOVQ(iState.Offset(_ma), rBo)
	ROLQ(Imm(62), rBa)
	XORQ(rDo, rBe)
	MOVQ(iState.Offset(_se), rBu)
	ROLQ(Imm(55), rBe)

	XORQ(rDu, rBi)
	MOVQ(rBa, rDu)
	XORQ(rDe, rBu)
	ROLQ(Imm(2), rBu)
	ANDQ(rBe, rDu)
	XORQ(rBu, rDu)
	MOVQ(rDu, oState.Offset(_su))

	ROLQ(Imm(39), rBi)
	S_RDU_RCU()
	NOTQ(rBe)
	XORQ(rDa, rBo)
	MOVQ(rBe, rDa)
	ANDQ(rBi, rDa)
	XORQ(rBa, rDa)
	MOVQ(rDa, oState.Offset(_sa))
	S_RDA_RCA()

	ROLQ(Imm(41), rBo)
	MOVQ(rBi, rDe)
	ORQ(rBo, rDe)
	XORQ(rBe, rDe)
	MOVQ(rDe, oState.Offset(_se))
	S_RDE_RCE()

	MOVQ(rBo, rDi)
	MOVQ(rBu, rDo)
	ANDQ(rBu, rDi)
	ORQ(rBa, rDo)
	XORQ(rBi, rDi)
	XORQ(rBo, rDo)
	MOVQ(rDi, oState.Offset(_si))
	MOVQ(rDo, oState.Offset(_so))
}

// keccakF1600 applies the Keccak permutation to a 1600b-wide
// state represented as a slice of 25 uint64s.
func keccakF1600() {
	Implement("keccakF1600")
	AllocLocal(200)

	Load(Param("a"), rpState.Base)

	Comment("Convert the user state into an internal state")
	NOTQ(rpState.Offset(_be))
	NOTQ(rpState.Offset(_bi))
	NOTQ(rpState.Offset(_go))
	NOTQ(rpState.Offset(_ki))
	NOTQ(rpState.Offset(_mi))
	NOTQ(rpState.Offset(_sa))

	Comment("Execute the KeccakF permutation")
	MOVQ(rpState.Offset(_ba), rCa)
	MOVQ(rpState.Offset(_be), rCe)
	MOVQ(rpState.Offset(_bu), rCu)

	XORQ(rpState.Offset(_ga), rCa)
	XORQ(rpState.Offset(_ge), rCe)
	XORQ(rpState.Offset(_gu), rCu)

	XORQ(rpState.Offset(_ka), rCa)
	XORQ(rpState.Offset(_ke), rCe)
	XORQ(rpState.Offset(_ku), rCu)

	XORQ(rpState.Offset(_ma), rCa)
	XORQ(rpState.Offset(_me), rCe)
	XORQ(rpState.Offset(_mu), rCu)

	XORQ(rpState.Offset(_sa), rCa)
	XORQ(rpState.Offset(_se), rCe)
	MOVQ(rpState.Offset(_si), rDi)
	MOVQ(rpState.Offset(_so), rDo)
	XORQ(rpState.Offset(_su), rCu)

	for i, rc := range RoundConstants[:len(RoundConstants)-1] {
		var iState, oState Mem
		if i%2 == 0 {
			iState, oState = rpState, rpStack
		} else {
			iState, oState = rpStack, rpState
		}
		mKeccakRound(iState, oState, U64(rc), MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	}
	mKeccakRound(rpStack, rpState, U64(RoundConstants[len(RoundConstants)-1]), NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP)

	Comment("Revert the internal state to the user state")
	NOTQ(rpState.Offset(_be))
	NOTQ(rpState.Offset(_bi))
	NOTQ(rpState.Offset(_go))
	NOTQ(rpState.Offset(_ki))
	NOTQ(rpState.Offset(_mi))
	NOTQ(rpState.Offset(_sa))

	RET()
}
```