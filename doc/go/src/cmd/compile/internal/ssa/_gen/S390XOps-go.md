Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding: Context is Key**

The first step is to recognize the file path: `go/src/cmd/compile/internal/ssa/_gen/S390XOps.go`. This immediately tells us several things:

* **`go/src`**: This is part of the Go standard library source code.
* **`cmd/compile`**: This relates to the Go compiler.
* **`internal/ssa`**: This points to the Static Single Assignment (SSA) intermediate representation used by the Go compiler for optimization.
* **`_gen`**: This suggests that the file is likely auto-generated or contains data that's used for code generation.
* **`S390XOps.go`**: This specifically targets the S390X architecture (IBM mainframe).
* **`Ops`**: This strongly implies that the file defines the *operations* that can be performed in the SSA form for the S390X architecture.

**2. Reading the Comments (Crucial)**

The comments at the beginning are incredibly informative. They provide high-level context and important details about the S390X architecture and how it's handled within the Go compiler's SSA framework. Key takeaways from the comments:

* **Register Usage**: How integer and boolean types are stored in registers.
* **Sub-register Operations**: The strategy to write the whole register to avoid partial writes.
* **`AuxInt`**: How the `AuxInt` field is used and the potential for sign-extension issues.
* **SB Register**: The special handling of the SB (static base) register and its implications for addressing. The alignment requirement for loads and stores is a critical detail.
* **z/Architecture Principles of Operation Link**:  This provides a direct link to the official documentation.
* **Suffixes**:  The meaning of suffixes like D, W, H, B, S in instruction names.

**3. Analyzing the Code Structure**

After understanding the context and the comments, we look at the code itself:

* **`package main` and `import "strings"`**: Standard Go setup. The `strings` package will be used for string manipulation, likely related to register names.
* **`regNamesS390X`**: This is a slice of strings representing the names of the S390X registers (R0-R15, F0-F15, SB).
* **`init()` function**: This function will be executed automatically when the package is loaded. This is where the core logic resides.
* **Register Mapping**: The `init` function creates a map (`num`) to associate register names with their integer IDs. This is a common pattern for efficient lookups.
* **`buildReg` function**: This helper function takes a string of register names and converts it into a `regMask`. This suggests that registers are represented by bitmasks for efficient set operations.
* **Register Masks (e.g., `sp`, `sb`, `gp`, `fp`)**:  These variables define common groups of registers using the `buildReg` function. The comments clearly explain the purpose of each mask (e.g., `gp` for general-purpose registers).
* **`regInfo` struct**: This struct likely holds information about the input, output, and clobbered registers for an operation.
* **`S390Xops` slice of `opData`**:  This is the most important part. It's a slice of structs, where each struct (`opData`) describes a specific S390X operation. The fields of `opData` provide details about the operation:
    * `name`: The name of the operation (e.g., "ADD", "MOVDload").
    * `argLength`: The number of arguments the operation takes.
    * `reg`: A `regInfo` struct specifying register constraints.
    * `typ`: The type of the operands (e.g., "Float64", "UInt64", "Mem").
    * `asm`: The corresponding assembly instruction.
    * `commutative`: Whether the operation is commutative.
    * `resultInArg0`: Whether the result is stored in the first argument.
    * `aux`: Information about auxiliary data (like immediate values or symbol offsets).
    * `faultOnNilArg0`: Whether the operation faults if the first argument is nil.
    * `symEffect`: The effect on symbols (Read, Write, Addr).
    * `clobberFlags`: Whether the operation clobbers the flags register.
    * ... and many other fields defining the characteristics of the operation.
* **`S390Xblocks` slice of `blockData`**: This defines the different types of control flow blocks in the SSA representation for S390X, such as branches and conditional jumps.
* **`archs` slice**: This is where the S390X architecture definition is appended. It contains pointers to the `S390Xops` and `S390Xblocks` data, as well as other architecture-specific information.

**4. Inferring Functionality and Providing Examples**

Based on the structure and the data within `S390Xops`, we can infer that this code defines the set of operations that the Go compiler's SSA backend can use to represent S390X instructions. Each `opData` entry maps a higher-level operation to a specific assembly instruction and defines its constraints and properties.

To provide examples, we look for common operations and their corresponding `opData` entries. For instance, the "ADD" operation clearly corresponds to integer addition. We can then construct a simple Go code example that would likely result in the generation of this "ADD" operation in the SSA form. The key is to bridge the gap between high-level Go code and the low-level SSA representation.

**5. Identifying Potential Pitfalls**

The comments themselves highlight potential issues, particularly regarding `AuxInt` usage and the constraints related to the SB register. The need for careful handling of signed vs. unsigned interpretations of `AuxInt`, and the alignment requirements for SB-relative addressing, are prime examples of things developers working at this level need to be aware of.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  This might be directly generating assembly.
* **Correction:** The `ssa` directory indicates it's working with the intermediate representation, not directly with assembly generation (although it informs assembly generation later).
* **Initial thought:**  The register masks are just for naming.
* **Correction:** The use of bitwise OR and the name `regMask` strongly suggest they're used for actual bitwise operations to represent sets of registers.

By following these steps, combining careful reading with an understanding of compiler architecture and the SSA concept, we can arrive at a comprehensive understanding of the provided Go code snippet.
`go/src/cmd/compile/internal/ssa/_gen/S390XOps.go` 是 Go 编译器中用于 **S390X (IBM System/z) 架构** 的一部分，它定义了在 **静态单赋值 (SSA)** 中间表示中可用的操作 (operations) 和代码块 (blocks)。

**功能列举:**

1. **定义 S390X 架构的寄存器名称和编号:**  `regNamesS390X` 定义了 S390X 架构的通用寄存器 (R0-R15)、浮点寄存器 (F0-F15) 和特殊寄存器 (SB) 的名称。
2. **定义寄存器掩码 (regMask):**  通过 `buildReg` 函数，可以将寄存器名称字符串转换为 `regMask`，这是一个表示一组寄存器的位掩码。这用于方便地表示指令可以使用的寄存器集合。
3. **定义操作的寄存器信息 (regInfo):** `regInfo` 结构体描述了 SSA 操作的输入、输出和可能被破坏的寄存器。这对于寄存器分配至关重要。
4. **定义 S390X 架构的 SSA 操作 (opData):** `S390Xops` 是一个 `opData` 类型的切片，其中每个 `opData` 结构体定义了一个可以在 SSA 中表示的 S390X 指令或伪指令。这些定义包括：
    * **name:** 操作的名称 (例如 "ADD", "MOVDload")。
    * **argLength:** 操作需要的参数数量。
    * **reg:**  `regInfo` 结构体，描述操作的寄存器约束。
    * **typ:** 操作数和结果的类型。
    * **asm:** 对应的汇编指令助记符。
    * **commutative:**  指示操作是否满足交换律。
    * **resultInArg0:** 指示结果是否存储在第一个参数中。
    * **aux:**  用于存储辅助信息的字段，例如立即数、符号偏移等。
    * **faultOnNilArg0:** 指示当第一个参数为 nil 时是否会发生错误。
    * **symEffect:** 指示操作对符号的影响 (例如 "Read", "Write", "Addr")。
    * **clobberFlags:** 指示操作是否会修改标志寄存器。
    * 其他用于描述操作特性的字段。
5. **定义 S390X 架构的 SSA 代码块 (blockData):** `S390Xblocks` 是一个 `blockData` 类型的切片，定义了 SSA 中可以使用的 S390X 代码块类型，例如条件分支 (BRC) 和比较分支 (CRJ, CGIJ 等)。
6. **将 S390X 架构信息添加到 `archs`:**  `init` 函数的最后一部分将定义的 S390X 操作、代码块和其他架构相关信息添加到全局的 `archs` 切片中，供编译器使用。

**推理 Go 语言功能的实现 (示例):**

这个文件本身并不直接实现某个 Go 语言功能，而是为 Go 编译器在处理 S390X 架构的代码时提供必要的底层信息。 它可以被视为 Go 编译器理解如何在 S390X 上执行各种操作的 "词汇表"。

例如，考虑一个简单的 Go 语言加法操作：

```go
package main

func main() {
	a := 10
	b := 20
	c := a + b
	println(c)
}
```

在编译这个程序时，Go 编译器会将其转换为 SSA 中间表示。 对于 `c := a + b` 这行代码，在 S390X 架构下，编译器可能会使用 `S390XOps.go` 中定义的 `ADD` 操作。

**Go 代码示例 (体现 `ADD` 操作):**

假设 SSA 生成器将 `a` 和 `b` 分配到寄存器 R1 和 R2， 那么 `c := a + b`  在 SSA 中可能会表示为一个使用 `ADD` 操作的指令。  根据 `S390XOps.go` 中的定义：

```go
{name: "ADD", argLength: 2, reg: gp21sp, asm: "ADD", commutative: true, clobberFlags: true},
```

* **假设输入:** 寄存器 R1 包含值 10，寄存器 R2 包含值 20。
* **对应的 SSA 指令 (伪代码):** `v3 = ADD <type:Int, flags> R1, R2`  (这里 v3 是一个虚拟寄存器，用于存储结果)
* **对应的汇编指令:** `AGR R1, R2` (S390X 的 64 位加法指令，结果存储在第一个操作数寄存器中，可能会修改标志位)

**命令行参数的具体处理:**

这个文件本身不直接处理命令行参数。 命令行参数的处理发生在 Go 编译器的其他部分，例如 `cmd/compile/internal/gc/main.go` 等。  `S390XOps.go` 提供的定义会被编译器在代码生成阶段使用，根据目标架构 (S390X) 选择相应的操作和指令。

**使用者易犯错的点 (对于 Go 编译器开发者):**

1. **`AuxInt` 的有符号和无符号解释:**  注释中特别提到，`AuxInt` 字段有时会被解释为有符号数，有时会被解释为无符号数。 对于像移位操作这样的场景，如果将 `AuxInt` 作为无符号数解释，需要特别小心，因为未使用的部分会进行符号扩展。  例如，如果一个移位操作的 `AuxInt` 本意是表示一个较小的无符号数，但由于符号扩展，高位为 1，可能会导致意外的移位量。

   **示例 (假设的错误使用):**  一个开发者错误地将一个原本是 5 位的无符号移位量存储在 `AuxInt` 中，但没有意识到 `AuxInt` 被解释为有符号数，导致高位被符号扩展，最终的移位量可能非常大，而不是预期的 5 位。

2. **SB 寄存器的使用限制:**  注释中详细说明了使用 SB 寄存器进行内存寻址时的限制：
    * **伪指令映射:**  使用 SB 寄存器时，伪指令可能不会映射到单个机器指令，因为许多机器指令没有相对长 (RL 后缀) 的等效形式。
    * **对齐要求:**  相对于 SB 寻址的数据需要根据其大小进行对齐 (例如，双字 8 字节对齐，字 4 字节对齐)。

   **示例:**  如果开发者试图使用 `ADDload` 伪指令加载一个相对于 SB 寻址的非 8 字节对齐的双字，汇编器可能会报错或者生成错误的代码。  或者，如果尝试使用 SB 寄存器寻址的数据，但该数据位于距离当前指令很远的位置，可能因为指令的地址偏移范围限制而无法直接寻址，需要插入额外的 `LARL` 指令。

总而言之，`go/src/cmd/compile/internal/ssa/_gen/S390XOps.go` 是 Go 编译器中针对 S390X 架构的核心数据定义文件，它描述了 SSA 中可用的操作和代码块，为编译器的代码生成和优化提供了基础。理解这个文件的内容对于理解 Go 编译器如何为 S390X 架构生成高效代码至关重要。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/_gen/S390XOps.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "strings"

// Notes:
//  - Integer types live in the low portion of registers. Upper portions are junk.
//  - Boolean types use the low-order byte of a register. 0=false, 1=true.
//    Upper bytes are junk.
//  - When doing sub-register operations, we try to write the whole
//    destination register to avoid a partial-register write.
//  - Unused portions of AuxInt (or the Val portion of ValAndOff) are
//    filled by sign-extending the used portion. Users of AuxInt which interpret
//    AuxInt as unsigned (e.g. shifts) must be careful.
//  - The SB 'register' is implemented using instruction-relative addressing. This
//    places some limitations on when and how memory operands that are addressed
//    relative to SB can be used:
//
//     1. Pseudo-instructions do not always map to a single machine instruction when
//        using the SB 'register' to address data. This is because many machine
//        instructions do not have relative long (RL suffix) equivalents. For example,
//        ADDload, which is assembled as AG.
//
//     2. Loads and stores using relative addressing require the data be aligned
//        according to its size (8-bytes for double words, 4-bytes for words
//        and so on).
//
//    We can always work around these by inserting LARL instructions (load address
//    relative long) in the assembler, but typically this results in worse code
//    generation because the address can't be re-used. Inserting instructions in the
//    assembler also means clobbering the temp register and it is a long-term goal
//    to prevent the compiler doing this so that it can be allocated as a normal
//    register.
//
// For more information about the z/Architecture, the instruction set and the
// addressing modes it supports take a look at the z/Architecture Principles of
// Operation: http://publibfp.boulder.ibm.com/epubs/pdf/dz9zr010.pdf
//
// Suffixes encode the bit width of pseudo-instructions.
// D (double word)  = 64 bit (frequently omitted)
// W (word)         = 32 bit
// H (half word)    = 16 bit
// B (byte)         = 8 bit
// S (single prec.) = 32 bit (double precision is omitted)

// copied from ../../s390x/reg.go
var regNamesS390X = []string{
	"R0",
	"R1",
	"R2",
	"R3",
	"R4",
	"R5",
	"R6",
	"R7",
	"R8",
	"R9",
	"R10",
	"R11",
	"R12",
	"g", // R13
	"R14",
	"SP", // R15
	"F0",
	"F1",
	"F2",
	"F3",
	"F4",
	"F5",
	"F6",
	"F7",
	"F8",
	"F9",
	"F10",
	"F11",
	"F12",
	"F13",
	"F14",
	"F15",

	// If you add registers, update asyncPreempt in runtime.

	//pseudo-registers
	"SB",
}

func init() {
	// Make map from reg names to reg integers.
	if len(regNamesS390X) > 64 {
		panic("too many registers")
	}
	num := map[string]int{}
	for i, name := range regNamesS390X {
		num[name] = i
	}
	buildReg := func(s string) regMask {
		m := regMask(0)
		for _, r := range strings.Split(s, " ") {
			if n, ok := num[r]; ok {
				m |= regMask(1) << uint(n)
				continue
			}
			panic("register " + r + " not found")
		}
		return m
	}

	// Common individual register masks
	var (
		sp  = buildReg("SP")
		sb  = buildReg("SB")
		r0  = buildReg("R0")
		tmp = buildReg("R11") // R11 is used as a temporary in a small number of instructions.

		// R10 is reserved by the assembler.
		gp   = buildReg("R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14")
		gpg  = gp | buildReg("g")
		gpsp = gp | sp

		// R0 is considered to contain the value 0 in address calculations.
		ptr     = gp &^ r0
		ptrsp   = ptr | sp
		ptrspsb = ptrsp | sb

		fp         = buildReg("F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15")
		callerSave = gp | fp | buildReg("g") // runtime.setg (and anything calling it) may clobber g
		r1         = buildReg("R1")
		r2         = buildReg("R2")
		r3         = buildReg("R3")
		r9         = buildReg("R9")
	)
	// Common slices of register masks
	var (
		gponly = []regMask{gp}
		fponly = []regMask{fp}
	)

	// Common regInfo
	var (
		gp01    = regInfo{inputs: []regMask{}, outputs: gponly}
		gp11    = regInfo{inputs: []regMask{gp}, outputs: gponly}
		gp11sp  = regInfo{inputs: []regMask{gpsp}, outputs: gponly}
		gp21    = regInfo{inputs: []regMask{gp, gp}, outputs: gponly}
		gp21sp  = regInfo{inputs: []regMask{gpsp, gp}, outputs: gponly}
		gp21tmp = regInfo{inputs: []regMask{gp &^ tmp, gp &^ tmp}, outputs: []regMask{gp &^ tmp}, clobbers: tmp}

		// R0 evaluates to 0 when used as the number of bits to shift
		// so we need to exclude it from that operand.
		sh21 = regInfo{inputs: []regMask{gp, ptr}, outputs: gponly}

		addr    = regInfo{inputs: []regMask{sp | sb}, outputs: gponly}
		addridx = regInfo{inputs: []regMask{sp | sb, ptrsp}, outputs: gponly}

		gp2flags       = regInfo{inputs: []regMask{gpsp, gpsp}}
		gp1flags       = regInfo{inputs: []regMask{gpsp}}
		gp2flags1      = regInfo{inputs: []regMask{gp, gp}, outputs: gponly}
		gp11flags      = regInfo{inputs: []regMask{gp}, outputs: gponly}
		gp21flags      = regInfo{inputs: []regMask{gp, gp}, outputs: gponly}
		gp2flags1flags = regInfo{inputs: []regMask{gp, gp}, outputs: gponly}

		gpload       = regInfo{inputs: []regMask{ptrspsb, 0}, outputs: gponly}
		gploadidx    = regInfo{inputs: []regMask{ptrspsb, ptrsp, 0}, outputs: gponly}
		gpopload     = regInfo{inputs: []regMask{gp, ptrsp, 0}, outputs: gponly}
		gpstore      = regInfo{inputs: []regMask{ptrspsb, gpsp, 0}}
		gpstoreconst = regInfo{inputs: []regMask{ptrspsb, 0}}
		gpstoreidx   = regInfo{inputs: []regMask{ptrsp, ptrsp, gpsp, 0}}
		gpstorebr    = regInfo{inputs: []regMask{ptrsp, gpsp, 0}}
		gpstorelaa   = regInfo{inputs: []regMask{ptrspsb, gpsp, 0}, outputs: gponly}
		gpstorelab   = regInfo{inputs: []regMask{r1, gpsp, 0}, clobbers: r1}

		gpmvc = regInfo{inputs: []regMask{ptrsp, ptrsp, 0}}

		fp01        = regInfo{inputs: []regMask{}, outputs: fponly}
		fp21        = regInfo{inputs: []regMask{fp, fp}, outputs: fponly}
		fp31        = regInfo{inputs: []regMask{fp, fp, fp}, outputs: fponly}
		fp21clobber = regInfo{inputs: []regMask{fp, fp}, outputs: fponly}
		fpgp        = regInfo{inputs: fponly, outputs: gponly}
		gpfp        = regInfo{inputs: gponly, outputs: fponly}
		fp11        = regInfo{inputs: fponly, outputs: fponly}
		fp1flags    = regInfo{inputs: []regMask{fp}}
		fp11clobber = regInfo{inputs: fponly, outputs: fponly}
		fp2flags    = regInfo{inputs: []regMask{fp, fp}}

		fpload    = regInfo{inputs: []regMask{ptrspsb, 0}, outputs: fponly}
		fploadidx = regInfo{inputs: []regMask{ptrsp, ptrsp, 0}, outputs: fponly}

		fpstore    = regInfo{inputs: []regMask{ptrspsb, fp, 0}}
		fpstoreidx = regInfo{inputs: []regMask{ptrsp, ptrsp, fp, 0}}

		sync = regInfo{inputs: []regMask{0}}

		// LoweredAtomicCas may overwrite arg1, so force it to R0 for now.
		cas = regInfo{inputs: []regMask{ptrsp, r0, gpsp, 0}, outputs: []regMask{gp, 0}, clobbers: r0}

		// LoweredAtomicExchange overwrites the output before executing
		// CS{,G}, so the output register must not be the same as the
		// input register. For now we just force the output register to
		// R0.
		exchange = regInfo{inputs: []regMask{ptrsp, gpsp &^ r0, 0}, outputs: []regMask{r0, 0}}
	)

	var S390Xops = []opData{
		// fp ops
		{name: "FADDS", argLength: 2, reg: fp21clobber, typ: "(Float32,Flags)", asm: "FADDS", commutative: true, resultInArg0: true}, // fp32 arg0 + arg1
		{name: "FADD", argLength: 2, reg: fp21clobber, typ: "(Float64,Flags)", asm: "FADD", commutative: true, resultInArg0: true},   // fp64 arg0 + arg1
		{name: "FSUBS", argLength: 2, reg: fp21clobber, typ: "(Float32,Flags)", asm: "FSUBS", resultInArg0: true},                    // fp32 arg0 - arg1
		{name: "FSUB", argLength: 2, reg: fp21clobber, typ: "(Float64,Flags)", asm: "FSUB", resultInArg0: true},                      // fp64 arg0 - arg1
		{name: "FMULS", argLength: 2, reg: fp21, asm: "FMULS", commutative: true, resultInArg0: true},                                // fp32 arg0 * arg1
		{name: "FMUL", argLength: 2, reg: fp21, asm: "FMUL", commutative: true, resultInArg0: true},                                  // fp64 arg0 * arg1
		{name: "FDIVS", argLength: 2, reg: fp21, asm: "FDIVS", resultInArg0: true},                                                   // fp32 arg0 / arg1
		{name: "FDIV", argLength: 2, reg: fp21, asm: "FDIV", resultInArg0: true},                                                     // fp64 arg0 / arg1
		{name: "FNEGS", argLength: 1, reg: fp11clobber, asm: "FNEGS", clobberFlags: true},                                            // fp32 -arg0
		{name: "FNEG", argLength: 1, reg: fp11clobber, asm: "FNEG", clobberFlags: true},                                              // fp64 -arg0
		{name: "FMADDS", argLength: 3, reg: fp31, asm: "FMADDS", resultInArg0: true},                                                 // fp32 arg1 * arg2 + arg0
		{name: "FMADD", argLength: 3, reg: fp31, asm: "FMADD", resultInArg0: true},                                                   // fp64 arg1 * arg2 + arg0
		{name: "FMSUBS", argLength: 3, reg: fp31, asm: "FMSUBS", resultInArg0: true},                                                 // fp32 arg1 * arg2 - arg0
		{name: "FMSUB", argLength: 3, reg: fp31, asm: "FMSUB", resultInArg0: true},                                                   // fp64 arg1 * arg2 - arg0
		{name: "LPDFR", argLength: 1, reg: fp11, asm: "LPDFR"},                                                                       // fp64/fp32 set sign bit
		{name: "LNDFR", argLength: 1, reg: fp11, asm: "LNDFR"},                                                                       // fp64/fp32 clear sign bit
		{name: "CPSDR", argLength: 2, reg: fp21, asm: "CPSDR"},                                                                       // fp64/fp32 copy arg1 sign bit to arg0

		// Round to integer, float64 only.
		//
		// aux | rounding mode
		// ----+-----------------------------------
		//   1 | round to nearest, ties away from 0
		//   4 | round to nearest, ties to even
		//   5 | round toward 0
		//   6 | round toward +∞
		//   7 | round toward -∞
		{name: "FIDBR", argLength: 1, reg: fp11, asm: "FIDBR", aux: "Int8"},

		{name: "FMOVSload", argLength: 2, reg: fpload, asm: "FMOVS", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"}, // fp32 load
		{name: "FMOVDload", argLength: 2, reg: fpload, asm: "FMOVD", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"}, // fp64 load
		{name: "FMOVSconst", reg: fp01, asm: "FMOVS", aux: "Float32", rematerializeable: true},                               // fp32 constant
		{name: "FMOVDconst", reg: fp01, asm: "FMOVD", aux: "Float64", rematerializeable: true},                               // fp64 constant
		{name: "FMOVSloadidx", argLength: 3, reg: fploadidx, asm: "FMOVS", aux: "SymOff", symEffect: "Read"},                 // fp32 load indexed by i
		{name: "FMOVDloadidx", argLength: 3, reg: fploadidx, asm: "FMOVD", aux: "SymOff", symEffect: "Read"},                 // fp64 load indexed by i

		{name: "FMOVSstore", argLength: 3, reg: fpstore, asm: "FMOVS", aux: "SymOff", faultOnNilArg0: true, symEffect: "Write"}, // fp32 store
		{name: "FMOVDstore", argLength: 3, reg: fpstore, asm: "FMOVD", aux: "SymOff", faultOnNilArg0: true, symEffect: "Write"}, // fp64 store
		{name: "FMOVSstoreidx", argLength: 4, reg: fpstoreidx, asm: "FMOVS", aux: "SymOff", symEffect: "Write"},                 // fp32 indexed by i store
		{name: "FMOVDstoreidx", argLength: 4, reg: fpstoreidx, asm: "FMOVD", aux: "SymOff", symEffect: "Write"},                 // fp64 indexed by i store

		// binary ops
		{name: "ADD", argLength: 2, reg: gp21sp, asm: "ADD", commutative: true, clobberFlags: true},                                                                  // arg0 + arg1
		{name: "ADDW", argLength: 2, reg: gp21sp, asm: "ADDW", commutative: true, clobberFlags: true},                                                                // arg0 + arg1
		{name: "ADDconst", argLength: 1, reg: gp11sp, asm: "ADD", aux: "Int32", typ: "UInt64", clobberFlags: true},                                                   // arg0 + auxint
		{name: "ADDWconst", argLength: 1, reg: gp11sp, asm: "ADDW", aux: "Int32", clobberFlags: true},                                                                // arg0 + auxint
		{name: "ADDload", argLength: 3, reg: gpopload, asm: "ADD", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},   // arg0 + *arg1. arg2=mem
		{name: "ADDWload", argLength: 3, reg: gpopload, asm: "ADDW", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"}, // arg0 + *arg1. arg2=mem

		{name: "SUB", argLength: 2, reg: gp21, asm: "SUB", clobberFlags: true},                                                                                       // arg0 - arg1
		{name: "SUBW", argLength: 2, reg: gp21, asm: "SUBW", clobberFlags: true},                                                                                     // arg0 - arg1
		{name: "SUBconst", argLength: 1, reg: gp11, asm: "SUB", aux: "Int32", resultInArg0: true, clobberFlags: true},                                                // arg0 - auxint
		{name: "SUBWconst", argLength: 1, reg: gp11, asm: "SUBW", aux: "Int32", resultInArg0: true, clobberFlags: true},                                              // arg0 - auxint
		{name: "SUBload", argLength: 3, reg: gpopload, asm: "SUB", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},   // arg0 - *arg1. arg2=mem
		{name: "SUBWload", argLength: 3, reg: gpopload, asm: "SUBW", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"}, // arg0 - *arg1. arg2=mem

		{name: "MULLD", argLength: 2, reg: gp21, asm: "MULLD", typ: "Int64", commutative: true, resultInArg0: true, clobberFlags: true},                                // arg0 * arg1
		{name: "MULLW", argLength: 2, reg: gp21, asm: "MULLW", typ: "Int32", commutative: true, resultInArg0: true, clobberFlags: true},                                // arg0 * arg1
		{name: "MULLDconst", argLength: 1, reg: gp11, asm: "MULLD", aux: "Int32", typ: "Int64", resultInArg0: true, clobberFlags: true},                                // arg0 * auxint
		{name: "MULLWconst", argLength: 1, reg: gp11, asm: "MULLW", aux: "Int32", typ: "Int32", resultInArg0: true, clobberFlags: true},                                // arg0 * auxint
		{name: "MULLDload", argLength: 3, reg: gpopload, asm: "MULLD", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"}, // arg0 * *arg1. arg2=mem
		{name: "MULLWload", argLength: 3, reg: gpopload, asm: "MULLW", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"}, // arg0 * *arg1. arg2=mem

		{name: "MULHD", argLength: 2, reg: gp21tmp, asm: "MULHD", typ: "Int64", commutative: true, resultInArg0: true, clobberFlags: true},   // (arg0 * arg1) >> width
		{name: "MULHDU", argLength: 2, reg: gp21tmp, asm: "MULHDU", typ: "Int64", commutative: true, resultInArg0: true, clobberFlags: true}, // (arg0 * arg1) >> width

		{name: "DIVD", argLength: 2, reg: gp21tmp, asm: "DIVD", resultInArg0: true, clobberFlags: true},   // arg0 / arg1
		{name: "DIVW", argLength: 2, reg: gp21tmp, asm: "DIVW", resultInArg0: true, clobberFlags: true},   // arg0 / arg1
		{name: "DIVDU", argLength: 2, reg: gp21tmp, asm: "DIVDU", resultInArg0: true, clobberFlags: true}, // arg0 / arg1
		{name: "DIVWU", argLength: 2, reg: gp21tmp, asm: "DIVWU", resultInArg0: true, clobberFlags: true}, // arg0 / arg1

		{name: "MODD", argLength: 2, reg: gp21tmp, asm: "MODD", resultInArg0: true, clobberFlags: true}, // arg0 % arg1
		{name: "MODW", argLength: 2, reg: gp21tmp, asm: "MODW", resultInArg0: true, clobberFlags: true}, // arg0 % arg1

		{name: "MODDU", argLength: 2, reg: gp21tmp, asm: "MODDU", resultInArg0: true, clobberFlags: true}, // arg0 % arg1
		{name: "MODWU", argLength: 2, reg: gp21tmp, asm: "MODWU", resultInArg0: true, clobberFlags: true}, // arg0 % arg1

		{name: "AND", argLength: 2, reg: gp21, asm: "AND", commutative: true, clobberFlags: true},                                                                    // arg0 & arg1
		{name: "ANDW", argLength: 2, reg: gp21, asm: "ANDW", commutative: true, clobberFlags: true},                                                                  // arg0 & arg1
		{name: "ANDconst", argLength: 1, reg: gp11, asm: "AND", aux: "Int64", resultInArg0: true, clobberFlags: true},                                                // arg0 & auxint
		{name: "ANDWconst", argLength: 1, reg: gp11, asm: "ANDW", aux: "Int32", resultInArg0: true, clobberFlags: true},                                              // arg0 & auxint
		{name: "ANDload", argLength: 3, reg: gpopload, asm: "AND", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},   // arg0 & *arg1. arg2=mem
		{name: "ANDWload", argLength: 3, reg: gpopload, asm: "ANDW", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"}, // arg0 & *arg1. arg2=mem

		{name: "OR", argLength: 2, reg: gp21, asm: "OR", commutative: true, clobberFlags: true},                                                                    // arg0 | arg1
		{name: "ORW", argLength: 2, reg: gp21, asm: "ORW", commutative: true, clobberFlags: true},                                                                  // arg0 | arg1
		{name: "ORconst", argLength: 1, reg: gp11, asm: "OR", aux: "Int64", resultInArg0: true, clobberFlags: true},                                                // arg0 | auxint
		{name: "ORWconst", argLength: 1, reg: gp11, asm: "ORW", aux: "Int32", resultInArg0: true, clobberFlags: true},                                              // arg0 | auxint
		{name: "ORload", argLength: 3, reg: gpopload, asm: "OR", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},   // arg0 | *arg1. arg2=mem
		{name: "ORWload", argLength: 3, reg: gpopload, asm: "ORW", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"}, // arg0 | *arg1. arg2=mem

		{name: "XOR", argLength: 2, reg: gp21, asm: "XOR", commutative: true, clobberFlags: true},                                                                    // arg0 ^ arg1
		{name: "XORW", argLength: 2, reg: gp21, asm: "XORW", commutative: true, clobberFlags: true},                                                                  // arg0 ^ arg1
		{name: "XORconst", argLength: 1, reg: gp11, asm: "XOR", aux: "Int64", resultInArg0: true, clobberFlags: true},                                                // arg0 ^ auxint
		{name: "XORWconst", argLength: 1, reg: gp11, asm: "XORW", aux: "Int32", resultInArg0: true, clobberFlags: true},                                              // arg0 ^ auxint
		{name: "XORload", argLength: 3, reg: gpopload, asm: "XOR", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},   // arg0 ^ *arg1. arg2=mem
		{name: "XORWload", argLength: 3, reg: gpopload, asm: "XORW", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"}, // arg0 ^ *arg1. arg2=mem

		// Arithmetic ops with carry/borrow chain.
		//
		// A carry is represented by a condition code of 2 or 3 (GT or OV).
		// A borrow is represented by a condition code of 0 or 1 (EQ or LT).
		{name: "ADDC", argLength: 2, reg: gp21flags, asm: "ADDC", typ: "(UInt64,Flags)", commutative: true},                          // (arg0 + arg1, carry out)
		{name: "ADDCconst", argLength: 1, reg: gp11flags, asm: "ADDC", typ: "(UInt64,Flags)", aux: "Int16"},                          // (arg0 + auxint, carry out)
		{name: "ADDE", argLength: 3, reg: gp2flags1flags, asm: "ADDE", typ: "(UInt64,Flags)", commutative: true, resultInArg0: true}, // (arg0 + arg1 + arg2 (carry in), carry out)
		{name: "SUBC", argLength: 2, reg: gp21flags, asm: "SUBC", typ: "(UInt64,Flags)"},                                             // (arg0 - arg1, borrow out)
		{name: "SUBE", argLength: 3, reg: gp2flags1flags, asm: "SUBE", typ: "(UInt64,Flags)", resultInArg0: true},                    // (arg0 - arg1 - arg2 (borrow in), borrow out)

		// Comparisons.
		{name: "CMP", argLength: 2, reg: gp2flags, asm: "CMP", typ: "Flags"},   // arg0 compare to arg1
		{name: "CMPW", argLength: 2, reg: gp2flags, asm: "CMPW", typ: "Flags"}, // arg0 compare to arg1

		{name: "CMPU", argLength: 2, reg: gp2flags, asm: "CMPU", typ: "Flags"},   // arg0 compare to arg1
		{name: "CMPWU", argLength: 2, reg: gp2flags, asm: "CMPWU", typ: "Flags"}, // arg0 compare to arg1

		{name: "CMPconst", argLength: 1, reg: gp1flags, asm: "CMP", typ: "Flags", aux: "Int32"},     // arg0 compare to auxint
		{name: "CMPWconst", argLength: 1, reg: gp1flags, asm: "CMPW", typ: "Flags", aux: "Int32"},   // arg0 compare to auxint
		{name: "CMPUconst", argLength: 1, reg: gp1flags, asm: "CMPU", typ: "Flags", aux: "Int32"},   // arg0 compare to auxint
		{name: "CMPWUconst", argLength: 1, reg: gp1flags, asm: "CMPWU", typ: "Flags", aux: "Int32"}, // arg0 compare to auxint

		{name: "FCMPS", argLength: 2, reg: fp2flags, asm: "CEBR", typ: "Flags"},  // arg0 compare to arg1, f32
		{name: "FCMP", argLength: 2, reg: fp2flags, asm: "FCMPU", typ: "Flags"},  // arg0 compare to arg1, f64
		{name: "LTDBR", argLength: 1, reg: fp1flags, asm: "LTDBR", typ: "Flags"}, // arg0 compare to 0, f64
		{name: "LTEBR", argLength: 1, reg: fp1flags, asm: "LTEBR", typ: "Flags"}, // arg0 compare to 0, f32

		{name: "SLD", argLength: 2, reg: sh21, asm: "SLD"},                    // arg0 << arg1, shift amount is mod 64
		{name: "SLW", argLength: 2, reg: sh21, asm: "SLW"},                    // arg0 << arg1, shift amount is mod 64
		{name: "SLDconst", argLength: 1, reg: gp11, asm: "SLD", aux: "UInt8"}, // arg0 << auxint, shift amount 0-63
		{name: "SLWconst", argLength: 1, reg: gp11, asm: "SLW", aux: "UInt8"}, // arg0 << auxint, shift amount 0-31

		{name: "SRD", argLength: 2, reg: sh21, asm: "SRD"},                    // unsigned arg0 >> arg1, shift amount is mod 64
		{name: "SRW", argLength: 2, reg: sh21, asm: "SRW"},                    // unsigned uint32(arg0) >> arg1, shift amount is mod 64
		{name: "SRDconst", argLength: 1, reg: gp11, asm: "SRD", aux: "UInt8"}, // unsigned arg0 >> auxint, shift amount 0-63
		{name: "SRWconst", argLength: 1, reg: gp11, asm: "SRW", aux: "UInt8"}, // unsigned uint32(arg0) >> auxint, shift amount 0-31

		// Arithmetic shifts clobber flags.
		{name: "SRAD", argLength: 2, reg: sh21, asm: "SRAD", clobberFlags: true},                    // signed arg0 >> arg1, shift amount is mod 64
		{name: "SRAW", argLength: 2, reg: sh21, asm: "SRAW", clobberFlags: true},                    // signed int32(arg0) >> arg1, shift amount is mod 64
		{name: "SRADconst", argLength: 1, reg: gp11, asm: "SRAD", aux: "UInt8", clobberFlags: true}, // signed arg0 >> auxint, shift amount 0-63
		{name: "SRAWconst", argLength: 1, reg: gp11, asm: "SRAW", aux: "UInt8", clobberFlags: true}, // signed int32(arg0) >> auxint, shift amount 0-31

		// Rotate instructions.
		// Note: no RLLGconst - use RISBGZ instead.
		{name: "RLLG", argLength: 2, reg: sh21, asm: "RLLG"},                  // arg0 rotate left arg1, rotate amount 0-63
		{name: "RLL", argLength: 2, reg: sh21, asm: "RLL"},                    // arg0 rotate left arg1, rotate amount 0-31
		{name: "RLLconst", argLength: 1, reg: gp11, asm: "RLL", aux: "UInt8"}, // arg0 rotate left auxint, rotate amount 0-31

		// Rotate then (and|or|xor|insert) selected bits instructions.
		//
		// Aux is an s390x.RotateParams struct containing Start, End and rotation
		// Amount fields.
		//
		// arg1 is rotated left by the rotation amount then the bits from the start
		// bit to the end bit (inclusive) are combined with arg0 using the logical
		// operation specified. Bit indices are specified from left to right - the
		// MSB is 0 and the LSB is 63.
		//
		// Examples:
		//               |          aux         |
		// | instruction | start | end | amount |          arg0         |          arg1         |         result        |
		// +-------------+-------+-----+--------+-----------------------+-----------------------+-----------------------+
		// | RXSBG (XOR) |     0 |   1 |      0 | 0xffff_ffff_ffff_ffff | 0xffff_ffff_ffff_ffff | 0x3fff_ffff_ffff_ffff |
		// | RXSBG (XOR) |    62 |  63 |      0 | 0xffff_ffff_ffff_ffff | 0xffff_ffff_ffff_ffff | 0xffff_ffff_ffff_fffc |
		// | RXSBG (XOR) |     0 |  47 |     16 | 0xffff_ffff_ffff_ffff | 0x0000_0000_0000_ffff | 0xffff_ffff_0000_ffff |
		// +-------------+-------+-----+--------+-----------------------+-----------------------+-----------------------+
		//
		{name: "RXSBG", argLength: 2, reg: gp21, asm: "RXSBG", resultInArg0: true, aux: "S390XRotateParams", clobberFlags: true}, // rotate then xor selected bits
		{name: "RISBGZ", argLength: 1, reg: gp11, asm: "RISBGZ", aux: "S390XRotateParams", clobberFlags: true},                   // rotate then insert selected bits [into zero]

		// unary ops
		{name: "NEG", argLength: 1, reg: gp11, asm: "NEG", clobberFlags: true},   // -arg0
		{name: "NEGW", argLength: 1, reg: gp11, asm: "NEGW", clobberFlags: true}, // -arg0

		{name: "NOT", argLength: 1, reg: gp11, resultInArg0: true, clobberFlags: true},  // ^arg0
		{name: "NOTW", argLength: 1, reg: gp11, resultInArg0: true, clobberFlags: true}, // ^arg0

		{name: "FSQRT", argLength: 1, reg: fp11, asm: "FSQRT"},   // sqrt(arg0)
		{name: "FSQRTS", argLength: 1, reg: fp11, asm: "FSQRTS"}, // sqrt(arg0), float32

		// Conditional register-register moves.
		// The aux for these values is an s390x.CCMask value representing the condition code mask.
		{name: "LOCGR", argLength: 3, reg: gp2flags1, resultInArg0: true, asm: "LOCGR", aux: "S390XCCMask"}, // load arg1 into arg0 if the condition code in arg2 matches a masked bit in aux.

		{name: "MOVBreg", argLength: 1, reg: gp11sp, asm: "MOVB", typ: "Int64"},    // sign extend arg0 from int8 to int64
		{name: "MOVBZreg", argLength: 1, reg: gp11sp, asm: "MOVBZ", typ: "UInt64"}, // zero extend arg0 from int8 to int64
		{name: "MOVHreg", argLength: 1, reg: gp11sp, asm: "MOVH", typ: "Int64"},    // sign extend arg0 from int16 to int64
		{name: "MOVHZreg", argLength: 1, reg: gp11sp, asm: "MOVHZ", typ: "UInt64"}, // zero extend arg0 from int16 to int64
		{name: "MOVWreg", argLength: 1, reg: gp11sp, asm: "MOVW", typ: "Int64"},    // sign extend arg0 from int32 to int64
		{name: "MOVWZreg", argLength: 1, reg: gp11sp, asm: "MOVWZ", typ: "UInt64"}, // zero extend arg0 from int32 to int64

		{name: "MOVDconst", reg: gp01, asm: "MOVD", typ: "UInt64", aux: "Int64", rematerializeable: true}, // auxint

		{name: "LDGR", argLength: 1, reg: gpfp, asm: "LDGR"}, // move int64 to float64 (no conversion)
		{name: "LGDR", argLength: 1, reg: fpgp, asm: "LGDR"}, // move float64 to int64 (no conversion)

		{name: "CFDBRA", argLength: 1, reg: fpgp, asm: "CFDBRA", clobberFlags: true}, // convert float64 to int32
		{name: "CGDBRA", argLength: 1, reg: fpgp, asm: "CGDBRA", clobberFlags: true}, // convert float64 to int64
		{name: "CFEBRA", argLength: 1, reg: fpgp, asm: "CFEBRA", clobberFlags: true}, // convert float32 to int32
		{name: "CGEBRA", argLength: 1, reg: fpgp, asm: "CGEBRA", clobberFlags: true}, // convert float32 to int64
		{name: "CEFBRA", argLength: 1, reg: gpfp, asm: "CEFBRA", clobberFlags: true}, // convert int32 to float32
		{name: "CDFBRA", argLength: 1, reg: gpfp, asm: "CDFBRA", clobberFlags: true}, // convert int32 to float64
		{name: "CEGBRA", argLength: 1, reg: gpfp, asm: "CEGBRA", clobberFlags: true}, // convert int64 to float32
		{name: "CDGBRA", argLength: 1, reg: gpfp, asm: "CDGBRA", clobberFlags: true}, // convert int64 to float64
		{name: "CLFEBR", argLength: 1, reg: fpgp, asm: "CLFEBR", clobberFlags: true}, // convert float32 to uint32
		{name: "CLFDBR", argLength: 1, reg: fpgp, asm: "CLFDBR", clobberFlags: true}, // convert float64 to uint32
		{name: "CLGEBR", argLength: 1, reg: fpgp, asm: "CLGEBR", clobberFlags: true}, // convert float32 to uint64
		{name: "CLGDBR", argLength: 1, reg: fpgp, asm: "CLGDBR", clobberFlags: true}, // convert float64 to uint64
		{name: "CELFBR", argLength: 1, reg: gpfp, asm: "CELFBR", clobberFlags: true}, // convert uint32 to float32
		{name: "CDLFBR", argLength: 1, reg: gpfp, asm: "CDLFBR", clobberFlags: true}, // convert uint32 to float64
		{name: "CELGBR", argLength: 1, reg: gpfp, asm: "CELGBR", clobberFlags: true}, // convert uint64 to float32
		{name: "CDLGBR", argLength: 1, reg: gpfp, asm: "CDLGBR", clobberFlags: true}, // convert uint64 to float64

		{name: "LEDBR", argLength: 1, reg: fp11, asm: "LEDBR"}, // convert float64 to float32
		{name: "LDEBR", argLength: 1, reg: fp11, asm: "LDEBR"}, // convert float32 to float64

		{name: "MOVDaddr", argLength: 1, reg: addr, aux: "SymOff", rematerializeable: true, symEffect: "Addr"}, // arg0 + auxint + offset encoded in aux
		{name: "MOVDaddridx", argLength: 2, reg: addridx, aux: "SymOff", symEffect: "Addr"},                    // arg0 + arg1 + auxint + aux

		// auxint+aux == add auxint and the offset of the symbol in aux (if any) to the effective address
		{name: "MOVBZload", argLength: 2, reg: gpload, asm: "MOVBZ", aux: "SymOff", typ: "UInt8", faultOnNilArg0: true, symEffect: "Read"},  // load byte from arg0+auxint+aux. arg1=mem.  Zero extend.
		{name: "MOVBload", argLength: 2, reg: gpload, asm: "MOVB", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},                  // ditto, sign extend to int64
		{name: "MOVHZload", argLength: 2, reg: gpload, asm: "MOVHZ", aux: "SymOff", typ: "UInt16", faultOnNilArg0: true, symEffect: "Read"}, // load 2 bytes from arg0+auxint+aux. arg1=mem.  Zero extend.
		{name: "MOVHload", argLength: 2, reg: gpload, asm: "MOVH", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},                  // ditto, sign extend to int64
		{name: "MOVWZload", argLength: 2, reg: gpload, asm: "MOVWZ", aux: "SymOff", typ: "UInt32", faultOnNilArg0: true, symEffect: "Read"}, // load 4 bytes from arg0+auxint+aux. arg1=mem.  Zero extend.
		{name: "MOVWload", argLength: 2, reg: gpload, asm: "MOVW", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},                  // ditto, sign extend to int64
		{name: "MOVDload", argLength: 2, reg: gpload, asm: "MOVD", aux: "SymOff", typ: "UInt64", faultOnNilArg0: true, symEffect: "Read"},   // load 8 bytes from arg0+auxint+aux. arg1=mem

		{name: "MOVWBR", argLength: 1, reg: gp11, asm: "MOVWBR"}, // arg0 swap bytes
		{name: "MOVDBR", argLength: 1, reg: gp11, asm: "MOVDBR"}, // arg0 swap bytes

		{name: "MOVHBRload", argLength: 2, reg: gpload, asm: "MOVHBR", aux: "SymOff", typ: "UInt16", faultOnNilArg0: true, symEffect: "Read"}, // load 2 bytes from arg0+auxint+aux. arg1=mem. Reverse bytes.
		{name: "MOVWBRload", argLength: 2, reg: gpload, asm: "MOVWBR", aux: "SymOff", typ: "UInt32", faultOnNilArg0: true, symEffect: "Read"}, // load 4 bytes from arg0+auxint+aux. arg1=mem. Reverse bytes.
		{name: "MOVDBRload", argLength: 2, reg: gpload, asm: "MOVDBR", aux: "SymOff", typ: "UInt64", faultOnNilArg0: true, symEffect: "Read"}, // load 8 bytes from arg0+auxint+aux. arg1=mem. Reverse bytes.

		{name: "MOVBstore", argLength: 3, reg: gpstore, asm: "MOVB", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},       // store byte in arg1 to arg0+auxint+aux. arg2=mem
		{name: "MOVHstore", argLength: 3, reg: gpstore, asm: "MOVH", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},       // store 2 bytes in arg1 to arg0+auxint+aux. arg2=mem
		{name: "MOVWstore", argLength: 3, reg: gpstore, asm: "MOVW", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},       // store 4 bytes in arg1 to arg0+auxint+aux. arg2=mem
		{name: "MOVDstore", argLength: 3, reg: gpstore, asm: "MOVD", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},       // store 8 bytes in arg1 to arg0+auxint+aux. arg2=mem
		{name: "MOVHBRstore", argLength: 3, reg: gpstorebr, asm: "MOVHBR", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 2 bytes in arg1 to arg0+auxint+aux. arg2=mem. Reverse bytes.
		{name: "MOVWBRstore", argLength: 3, reg: gpstorebr, asm: "MOVWBR", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 4 bytes in arg1 to arg0+auxint+aux. arg2=mem. Reverse bytes.
		{name: "MOVDBRstore", argLength: 3, reg: gpstorebr, asm: "MOVDBR", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 8 bytes in arg1 to arg0+auxint+aux. arg2=mem. Reverse bytes.

		{name: "MVC", argLength: 3, reg: gpmvc, asm: "MVC", aux: "SymValAndOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, faultOnNilArg1: true, symEffect: "None"}, // arg0=destptr, arg1=srcptr, arg2=mem, auxint=size,off

		// indexed loads/stores
		{name: "MOVBZloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVBZ", aux: "SymOff", typ: "UInt8", symEffect: "Read"},   // load a byte from arg0+arg1+auxint+aux. arg2=mem. Zero extend.
		{name: "MOVBloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVB", aux: "SymOff", typ: "Int8", symEffect: "Read"},      // load a byte from arg0+arg1+auxint+aux. arg2=mem. Sign extend.
		{name: "MOVHZloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVHZ", aux: "SymOff", typ: "UInt16", symEffect: "Read"},  // load 2 bytes from arg0+arg1+auxint+aux. arg2=mem. Zero extend.
		{name: "MOVHloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVH", aux: "SymOff", typ: "Int16", symEffect: "Read"},     // load 2 bytes from arg0+arg1+auxint+aux. arg2=mem. Sign extend.
		{name: "MOVWZloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVWZ", aux: "SymOff", typ: "UInt32", symEffect: "Read"},  // load 4 bytes from arg0+arg1+auxint+aux. arg2=mem. Zero extend.
		{name: "MOVWloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVW", aux: "SymOff", typ: "Int32", symEffect: "Read"},     // load 4 bytes from arg0+arg1+auxint+aux. arg2=mem. Sign extend.
		{name: "MOVDloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVD", aux: "SymOff", typ: "UInt64", symEffect: "Read"},    // load 8 bytes from arg0+arg1+auxint+aux. arg2=mem
		{name: "MOVHBRloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVHBR", aux: "SymOff", typ: "Int16", symEffect: "Read"}, // load 2 bytes from arg0+arg1+auxint+aux. arg2=mem. Reverse bytes.
		{name: "MOVWBRloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVWBR", aux: "SymOff", typ: "Int32", symEffect: "Read"}, // load 4 bytes from arg0+arg1+auxint+aux. arg2=mem. Reverse bytes.
		{name: "MOVDBRloadidx", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVDBR", aux: "SymOff", typ: "Int64", symEffect: "Read"}, // load 8 bytes from arg0+arg1+auxint+aux. arg2=mem. Reverse bytes.
		{name: "MOVBstoreidx", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVB", aux: "SymOff", symEffect: "Write"},                // store byte in arg2 to arg0+arg1+auxint+aux. arg3=mem
		{name: "MOVHstoreidx", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVH", aux: "SymOff", symEffect: "Write"},                // store 2 bytes in arg2 to arg0+arg1+auxint+aux. arg3=mem
		{name: "MOVWstoreidx", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVW", aux: "SymOff", symEffect: "Write"},                // store 4 bytes in arg2 to arg0+arg1+auxint+aux. arg3=mem
		{name: "MOVDstoreidx", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVD", aux: "SymOff", symEffect: "Write"},                // store 8 bytes in arg2 to arg0+arg1+auxint+aux. arg3=mem
		{name: "MOVHBRstoreidx", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVHBR", aux: "SymOff", symEffect: "Write"},            // store 2 bytes in arg2 to arg0+arg1+auxint+aux. arg3=mem. Reverse bytes.
		{name: "MOVWBRstoreidx", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVWBR", aux: "SymOff", symEffect: "Write"},            // store 4 bytes in arg2 to arg0+arg1+auxint+aux. arg3=mem. Reverse bytes.
		{name: "MOVDBRstoreidx", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVDBR", aux: "SymOff", symEffect: "Write"},            // store 8 bytes in arg2 to arg0+arg1+auxint+aux. arg3=mem. Reverse bytes.

		// For storeconst ops, the AuxInt field encodes both
		// the value to store and an address offset of the store.
		// Cast AuxInt to a ValAndOff to extract Val and Off fields.
		{name: "MOVBstoreconst", argLength: 2, reg: gpstoreconst, asm: "MOVB", aux: "SymValAndOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store low byte of ValAndOff(AuxInt).Val() to arg0+ValAndOff(AuxInt).Off()+aux.  arg1=mem
		{name: "MOVHstoreconst", argLength: 2, reg: gpstoreconst, asm: "MOVH", aux: "SymValAndOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store low 2 bytes of ...
		{name: "MOVWstoreconst", argLength: 2, reg: gpstoreconst, asm: "MOVW", aux: "SymValAndOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store low 4 bytes of ...
		{name: "MOVDstoreconst", argLength: 2, reg: gpstoreconst, asm: "MOVD", aux: "SymValAndOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 8 bytes of ...

		{name: "CLEAR", argLength: 2, reg: regInfo{inputs: []regMask{ptr, 0}}, asm: "CLEAR", aux: "SymValAndOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Write"},

		{name: "CALLstatic", argLength: 1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                                                // call static function aux.(*obj.LSym).  arg0=mem, auxint=argsize, returns mem
		{name: "CALLtail", argLength: 1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true, tailCall: true},                                  // tail call static function aux.(*obj.LSym).  arg0=mem, auxint=argsize, returns mem
		{name: "CALLclosure", argLength: 3, reg: regInfo{inputs: []regMask{ptrsp, buildReg("R12"), 0}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true}, // call function via closure.  arg0=codeptr, arg1=closure, arg2=mem, auxint=argsize, returns mem
		{name: "CALLinter", argLength: 2, reg: regInfo{inputs: []regMask{ptr}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                         // call fn by pointer.  arg0=codeptr, arg1=mem, auxint=argsize, returns mem

		// (InvertFlags (CMP a b)) == (CMP b a)
		// InvertFlags is a pseudo-op which can't appear in assembly output.
		{name: "InvertFlags", argLength: 1}, // reverse direction of arg0

		// Pseudo-ops
		{name: "LoweredGetG", argLength: 1, reg: gp01}, // arg0=mem
		// Scheduler ensures LoweredGetClosurePtr occurs only in entry block,
		// and sorts it to the very beginning of the block to prevent other
		// use of R12 (the closure pointer)
		{name: "LoweredGetClosurePtr", reg: regInfo{outputs: []regMask{buildReg("R12")}}, zeroWidth: true},
		// arg0=ptr,arg1=mem, returns void.  Faults if ptr is nil.
		// LoweredGetCallerSP returns the SP of the caller of the current function. arg0=mem.
		{name: "LoweredGetCallerSP", argLength: 1, reg: gp01, rematerializeable: true},
		// LoweredGetCallerPC evaluates to the PC to which its "caller" will return.
		// I.e., if f calls g "calls" sys.GetCallerPC,
		// the result should be the PC within f that g will return to.
		// See runtime/stubs.go for a more detailed discussion.
		{name: "LoweredGetCallerPC", reg: gp01, rematerializeable: true},
		{name: "LoweredNilCheck", argLength: 2, reg: regInfo{inputs: []regMask{ptrsp}}, clobberFlags: true, nilCheck: true, faultOnNilArg0: true},
		// Round ops to block fused-multiply-add extraction.
		{name: "LoweredRound32F", argLength: 1, reg: fp11, resultInArg0: true, zeroWidth: true},
		{name: "LoweredRound64F", argLength: 1, reg: fp11, resultInArg0: true, zeroWidth: true},

		// LoweredWB invokes runtime.gcWriteBarrier. arg0=mem, aux=# of buffer entries needed
		// It saves all GP registers if necessary,
		// but clobbers R14 (LR) because it's a call,
		// and also clobbers R1 as the PLT stub does.
		// Returns a pointer to a write barrier buffer in R9.
		{name: "LoweredWB", argLength: 1, reg: regInfo{clobbers: (callerSave &^ gpg) | buildReg("R14") | r1, outputs: []regMask{r9}}, clobberFlags: true, aux: "Int64"},

		// There are three of these functions so that they can have three different register inputs.
		// When we check 0 <= c <= cap (A), then 0 <= b <= c (B), then 0 <= a <= b (C), we want the
		// default registers to match so we don't need to copy registers around unnecessarily.
		{name: "LoweredPanicBoundsA", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r2, r3}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in generic.go).
		{name: "LoweredPanicBoundsB", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r1, r2}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in generic.go).
		{name: "LoweredPanicBoundsC", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r0, r1}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in generic.go).

		// Constant condition code values. The condition code can be 0, 1, 2 or 3.
		{name: "FlagEQ"}, // CC=0 (equal)
		{name: "FlagLT"}, // CC=1 (less than)
		{name: "FlagGT"}, // CC=2 (greater than)
		{name: "FlagOV"}, // CC=3 (overflow)

		// Fast-BCR-serialization to ensure store-load ordering.
		{name: "SYNC", argLength: 1, reg: sync, asm: "SYNC", typ: "Mem"},

		// Atomic loads. These are just normal loads but return <value,memory> tuples
		// so they can be properly ordered with other loads.
		// load from arg0+auxint+aux.  arg1=mem.
		{name: "MOVBZatomicload", argLength: 2, reg: gpload, asm: "MOVBZ", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVWZatomicload", argLength: 2, reg: gpload, asm: "MOVWZ", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVDatomicload", argLength: 2, reg: gpload, asm: "MOVD", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},

		// Atomic stores. These are just normal stores.
		// store arg1 to arg0+auxint+aux. arg2=mem.
		{name: "MOVBatomicstore", argLength: 3, reg: gpstore, asm: "MOVB", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "Write"},
		{name: "MOVWatomicstore", argLength: 3, reg: gpstore, asm: "MOVW", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "Write"},
		{name: "MOVDatomicstore", argLength: 3, reg: gpstore, asm: "MOVD", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "Write"},

		// Atomic adds.
		// *(arg0+auxint+aux) += arg1.  arg2=mem.
		// Returns a tuple of <old contents of *(arg0+auxint+aux), memory>.
		{name: "LAA", argLength: 3, reg: gpstorelaa, asm: "LAA", typ: "(UInt32,Mem)", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},
		{name: "LAAG", argLength: 3, reg: gpstorelaa, asm: "LAAG", typ: "(UInt64,Mem)", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},
		{name: "AddTupleFirst32", argLength: 2}, // arg1=tuple <x,y>.  Returns <x+arg0,y>.
		{name: "AddTupleFirst64", argLength: 2}, // arg1=tuple <x,y>.  Returns <x+arg0,y>.

		// Atomic bitwise operations.
		// Note: 'floor' operations round the pointer down to the nearest word boundary
		// which reflects how they are used in the runtime.
		{name: "LAN", argLength: 3, reg: gpstore, asm: "LAN", typ: "Mem", clobberFlags: true, hasSideEffects: true},         // *arg0 &= arg1. arg2 = mem.
		{name: "LANfloor", argLength: 3, reg: gpstorelab, asm: "LAN", typ: "Mem", clobberFlags: true, hasSideEffects: true}, // *(floor(arg0, 4)) &= arg1. arg2 = mem.
		{name: "LAO", argLength: 3, reg: gpstore, asm: "LAO", typ: "Mem", clobberFlags: true, hasSideEffects: true},         // *arg0 |= arg1. arg2 = mem.
		{name: "LAOfloor", argLength: 3, reg: gpstorelab, asm: "LAO", typ: "Mem", clobberFlags: true, hasSideEffects: true}, // *(floor(arg0, 4)) |= arg1. arg2 = mem.

		// Compare and swap.
		// arg0 = pointer, arg1 = old value, arg2 = new value, arg3 = memory.
		// if *(arg0+auxint+aux) == arg1 {
		//   *(arg0+auxint+aux) = arg2
		//   return (true, memory)
		// } else {
		//   return (false, memory)
		// }
		// Note that these instructions also return the old value in arg1, but we ignore it.
		// TODO: have these return flags instead of bool.  The current system generates:
		//    CS ...
		//    MOVD  $0, ret
		//    BNE   2(PC)
		//    MOVD  $1, ret
		//    CMPW  ret, $0
		//    BNE ...
		// instead of just
		//    CS ...
		//    BEQ ...
		// but we can't do that because memory-using ops can't generate flags yet
		// (flagalloc wants to move flag-generating instructions around).
		{name: "LoweredAtomicCas32", argLength: 4, reg: cas, asm: "CS", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},
		{name: "LoweredAtomicCas64", argLength: 4, reg: cas, asm: "CSG", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},

		// Lowered atomic swaps, emulated using compare-and-swap.
		// store arg1 to arg0+auxint+aux, arg2=mem.
		{name: "LoweredAtomicExchange32", argLength: 3, reg: exchange, asm: "CS", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},
		{name: "LoweredAtomicExchange64", argLength: 3, reg: exchange, asm: "CSG", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},

		// find leftmost one
		{
			name:         "FLOGR",
			argLength:    1,
			reg:          regInfo{inputs: gponly, outputs: []regMask{buildReg("R0")}, clobbers: buildReg("R1")},
			asm:          "FLOGR",
			typ:          "UInt64",
			clobberFlags: true,
		},

		// population count
		//
		// Counts the number of ones in each byte of arg0
		// and places the result into the corresponding byte
		// of the result.
		{
			name:         "POPCNT",
			argLength:    1,
			reg:          gp11,
			asm:          "POPCNT",
			typ:          "UInt64",
			clobberFlags: true,
		},

		// unsigned multiplication (64x64 → 128)
		//
		// Multiply the two 64-bit input operands together and place the 128-bit result into
		// an even-odd register pair. The second register in the target pair also contains
		// one of the input operands. Since we don't currently have a way to specify an
		// even-odd register pair we hardcode this register pair as R2:R3.
		{
			name:      "MLGR",
			argLength: 2,
			reg:       regInfo{inputs: []regMask{gp, r3}, outputs: []regMask{r2, r3}},
			asm:       "MLGR",
		},

		// pseudo operations to sum the output of the POPCNT instruction
		{name: "SumBytes2", argLength: 1, typ: "UInt8"}, // sum the rightmost 2 bytes in arg0 ignoring overflow
		{name: "SumBytes4", argLength: 1, typ: "UInt8"}, // sum the rightmost 4 bytes in arg0 ignoring overflow
		{name: "SumBytes8", argLength: 1, typ: "UInt8"}, // sum all the bytes in arg0 ignoring overflow

		// store multiple
		{
			name:           "STMG2",
			argLength:      4,
			reg:            regInfo{inputs: []regMask{ptrsp, buildReg("R1"), buildReg("R2"), 0}},
			aux:            "SymOff",
			typ:            "Mem",
			asm:            "STMG",
			faultOnNilArg0: true,
			symEffect:      "Write",
			clobberFlags:   true, // TODO(mundaym): currently uses AGFI to handle large offsets
		},
		{
			name:           "STMG3",
			argLength:      5,
			reg:            regInfo{inputs: []regMask{ptrsp, buildReg("R1"), buildReg("R2"), buildReg("R3"), 0}},
			aux:            "SymOff",
			typ:            "Mem",
			asm:            "STMG",
			faultOnNilArg0: true,
			symEffect:      "Write",
			clobberFlags:   true, // TODO(mundaym): currently uses AGFI to handle large offsets
		},
		{
			name:      "STMG4",
			argLength: 6,
			reg: regInfo{inputs: []regMask{
				ptrsp,
				buildReg("R1"),
				buildReg("R2"),
				buildReg("R3"),
				buildReg("R4"),
				0,
			}},
			aux:            "SymOff",
			typ:            "Mem",
			asm:            "STMG",
			faultOnNilArg0: true,
			symEffect:      "Write",
			clobberFlags:   true, // TODO(mundaym): currently uses AGFI to handle large offsets
		},
		{
			name:           "STM2",
			argLength:      4,
			reg:            regInfo{inputs: []regMask{ptrsp, buildReg("R1"), buildReg("R2"), 0}},
			aux:            "SymOff",
			typ:            "Mem",
			asm:            "STMY",
			faultOnNilArg0: true,
			symEffect:      "Write",
			clobberFlags:   true, // TODO(mundaym): currently uses AGFI to handle large offsets
		},
		{
			name:           "STM3",
			argLength:      5,
			reg:            regInfo{inputs: []regMask{ptrsp, buildReg("R1"), buildReg("R2"), buildReg("R3"), 0}},
			aux:            "SymOff",
			typ:            "Mem",
			asm:            "STMY",
			faultOnNilArg0: true,
			symEffect:      "Write",
			clobberFlags:   true, // TODO(mundaym): currently uses AGFI to handle large offsets
		},
		{
			name:      "STM4",
			argLength: 6,
			reg: regInfo{inputs: []regMask{
				ptrsp,
				buildReg("R1"),
				buildReg("R2"),
				buildReg("R3"),
				buildReg("R4"),
				0,
			}},
			aux:            "SymOff",
			typ:            "Mem",
			asm:            "STMY",
			faultOnNilArg0: true,
			symEffect:      "Write",
			clobberFlags:   true, // TODO(mundaym): currently uses AGFI to handle large offsets
		},

		// large move
		// auxint = remaining bytes after loop (rem)
		// arg0 = address of dst memory (in R1, changed as a side effect)
		// arg1 = address of src memory (in R2, changed as a side effect)
		// arg2 = pointer to last address to move in loop + 256
		// arg3 = mem
		// returns mem
		//
		// mvc: MVC  $256, 0(R2), 0(R1)
		//      MOVD $256(R1), R1
		//      MOVD $256(R2), R2
		//      CMP  R2, Rarg2
		//      BNE  mvc
		//	MVC  $rem, 0(R2), 0(R1) // if rem > 0
		{
			name:      "LoweredMove",
			aux:       "Int64",
			argLength: 4,
			reg: regInfo{
				inputs:   []regMask{buildReg("R1"), buildReg("R2"), gpsp},
				clobbers: buildReg("R1 R2"),
			},
			clobberFlags:   true,
			typ:            "Mem",
			faultOnNilArg0: true,
			faultOnNilArg1: true,
		},

		// large clear
		// auxint = remaining bytes after loop (rem)
		// arg0 = address of dst memory (in R1, changed as a side effect)
		// arg1 = pointer to last address to zero in loop + 256
		// arg2 = mem
		// returns mem
		//
		// clear: CLEAR $256, 0(R1)
		//        MOVD  $256(R1), R1
		//        CMP   R1, Rarg2
		//        BNE   clear
		//	  CLEAR $rem, 0(R1) // if rem > 0
		{
			name:      "LoweredZero",
			aux:       "Int64",
			argLength: 3,
			reg: regInfo{
				inputs:   []regMask{buildReg("R1"), gpsp},
				clobbers: buildReg("R1"),
			},
			clobberFlags:   true,
			typ:            "Mem",
			faultOnNilArg0: true,
		},
	}

	// All blocks on s390x have their condition code mask (s390x.CCMask) as the Aux value.
	// The condition code mask is a 4-bit mask where each bit corresponds to a condition
	// code value. If the value of the condition code matches a bit set in the condition
	// code mask then the first successor is executed. Otherwise the second successor is
	// executed.
	//
	// | condition code value |  mask bit  |
	// +----------------------+------------+
	// | 0 (equal)            | 0b1000 (8) |
	// | 1 (less than)        | 0b0100 (4) |
	// | 2 (greater than)     | 0b0010 (2) |
	// | 3 (unordered)        | 0b0001 (1) |
	//
	// Note: that compare-and-branch instructions must not have bit 3 (0b0001) set.
	var S390Xblocks = []blockData{
		// branch on condition
		{name: "BRC", controls: 1, aux: "S390XCCMask"}, // condition code value (flags) is Controls[0]

		// compare-and-branch (register-register)
		//  - integrates comparison of Controls[0] with Controls[1]
		//  - both control values must be in general purpose registers
		{name: "CRJ", controls: 2, aux: "S390XCCMask"},   // signed 32-bit integer comparison
		{name: "CGRJ", controls: 2, aux: "S390XCCMask"},  // signed 64-bit integer comparison
		{name: "CLRJ", controls: 2, aux: "S390XCCMask"},  // unsigned 32-bit integer comparison
		{name: "CLGRJ", controls: 2, aux: "S390XCCMask"}, // unsigned 64-bit integer comparison

		// compare-and-branch (register-immediate)
		//  - integrates comparison of Controls[0] with AuxInt
		//  - control value must be in a general purpose register
		//  - the AuxInt value is sign-extended for signed comparisons
		//    and zero-extended for unsigned comparisons
		{name: "CIJ", controls: 1, aux: "S390XCCMaskInt8"},    // signed 32-bit integer comparison
		{name: "CGIJ", controls: 1, aux: "S390XCCMaskInt8"},   // signed 64-bit integer comparison
		{name: "CLIJ", controls: 1, aux: "S390XCCMaskUint8"},  // unsigned 32-bit integer comparison
		{name: "CLGIJ", controls: 1, aux: "S390XCCMaskUint8"}, // unsigned 64-bit integer comparison
	}

	archs = append(archs, arch{
		name:            "S390X",
		pkg:             "cmd/internal/obj/s390x",
		genfile:         "../../s390x/ssa.go",
		ops:             S390Xops,
		blocks:          S390Xblocks,
		regnames:        regNamesS390X,
		gpregmask:       gp,
		fpregmask:       fp,
		framepointerreg: -1, // not used
		linkreg:         int8(num["R14"]),
		imports: []string{
			"cmd/internal/obj/s390x",
		},
	})
}

"""



```