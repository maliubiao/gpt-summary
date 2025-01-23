Response:
My thinking process to answer the request about `ARMOps.go` goes like this:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet, its purpose within the Go compiler, examples of its use, and potential pitfalls.

2. **Identify the Core Functionality:** The code defines a large array named `ops` of type `opData`. Each `opData` struct seems to represent a specific ARM assembly instruction or a higher-level operation. This immediately suggests that the file is involved in the code generation phase of the Go compiler for the ARM architecture.

3. **Analyze `opData` Structure:**  Looking at the fields of `opData` provides more details about its purpose:
    * `name`: The symbolic name of the operation (e.g., "ADD", "MOVWload").
    * `argLength`: The number of arguments the operation takes.
    * `reg`: A `regInfo` struct detailing register usage (inputs, outputs, clobbered registers).
    * `asm`: The actual ARM assembly mnemonic (if applicable).
    * `aux`:  Indicates the type of auxiliary data (e.g., "Int32", "SymOff").
    * `commutative`: Whether the operation is commutative.
    * `typ`: The Go type associated with the operation.
    * `call`, `tailCall`: Flags related to function calls.
    * `nilCheck`: Flag for nil checks.
    * `faultOnNilArg0`, `faultOnNilArg1`: Flags for potential nil pointer dereferences.
    * `symEffect`:  Indicates if the operation interacts with symbols (for linking).
    * `rematerializeable`: Whether the operation can be recomputed.
    * `resultInArg0`:  If the result overwrites the first argument.
    * `clobberFlags`:  If the operation modifies CPU flags.

4. **Infer the Role within the Compiler:** Based on the `opData` structure and the file path (`go/src/cmd/compile/internal/ssa/_gen/ARMOps.go`), it's clear this file is part of the SSA (Static Single Assignment) backend of the Go compiler. Specifically, the `_gen` directory suggests it's a *generated* file. This means the contents are likely derived from some other source of truth (perhaps a more abstract description of ARM operations). The file's name strongly indicates it defines the set of available operations for the ARM architecture within the SSA framework.

5. **Connect to Go Language Features:**  The defined operations directly correspond to low-level CPU operations. Therefore, this file is crucial for implementing various Go language features that eventually translate into these ARM instructions. This includes:
    * **Arithmetic operations:** `+`, `-`, `*`, `/`, `%`, bitwise operations.
    * **Memory access:** Loading and storing variables (`x := y`, `y = x`).
    * **Comparisons:** `<`, `>`, `==`, `!=`.
    * **Control flow:** Function calls, conditional statements (`if`), loops (`for`).
    * **Type conversions:** Converting between integers and floating-point numbers.
    * **Shifts and rotations.**

6. **Provide Go Code Examples:**  To illustrate how these operations are used, I need to show simple Go code snippets and how they might be represented using the defined ARM operations. This requires making some assumptions about the compiler's internal translation, but focusing on common scenarios is key. For example:
    * Simple addition translates to the "ADD" operation.
    * Loading a variable from memory uses "MOVWload".
    * An `if` statement involves comparison operations like "CMP" and conditional branches based on flags.

7. **Address Code Reasoning and Assumptions:** Since I'm inferring how Go code maps to these low-level operations, it's important to explicitly state the assumptions made. For instance, assuming that local variables are stored in registers or on the stack and that memory access involves base addresses and offsets. Providing input and output examples helps solidify these assumptions.

8. **Consider Command-line Arguments:** This file itself doesn't directly process command-line arguments. It's a data definition file. However, it's important to mention that the *compiler* using this data will be influenced by command-line flags related to target architecture (`GOARCH=arm`), optimization levels, and potentially flags that control specific ARM features (like VFPv4).

9. **Identify Potential Pitfalls:**  Understanding how the compiler uses this data helps identify potential issues for users. Common mistakes might involve:
    * **Incorrect type assumptions:**  Assuming a variable is in a register when it's in memory.
    * **Forgetting about memory management:**  Not considering the overhead of memory access when optimizing.
    * **Ignoring architecture-specific details:**  Assuming code will behave the same way on different architectures.
    * **Over-reliance on low-level optimizations:**  The Go compiler generally handles low-level optimization well, so manual intervention might not always be beneficial and could even be detrimental.

10. **Structure the Answer:** Organize the information logically with clear headings and bullet points to make it easy to understand. Start with a high-level summary of the file's purpose and then delve into more specific details. Use code examples to illustrate the concepts.

11. **Review and Refine:**  Before submitting the answer, reread it to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better.

By following this systematic approach, I can effectively analyze the provided code snippet and provide a comprehensive and informative answer that addresses all aspects of the request. The key is to connect the low-level details of the code to the higher-level concepts of the Go compiler and the Go programming language itself.
`go/src/cmd/compile/internal/ssa/_gen/ARMOps.go` 是 Go 语言编译器中用于定义 ARM 架构下 SSA 中间表示的操作码的文件。它是一个**生成文件**，通常由其他工具生成，而不是手动编写。

**主要功能:**

1. **定义 ARM 架构的 SSA 操作码 (Op Codes):**  它定义了一个名为 `ops` 的切片，其中包含了 `opData` 类型的结构体。每个 `opData` 结构体描述了一个特定的 ARM 汇编指令或者一个更高级的抽象操作。这些操作是 SSA 中间表示的基础构建块，用于表示 Go 代码在 ARM 架构上的各种操作。

2. **指定操作的属性:** `opData` 结构体包含关于每个操作的各种信息，例如：
   - `name`: 操作的名称（例如 "ADD", "MOVWload"）。
   - `argLength`: 操作需要的参数数量。
   - `reg`: 一个 `regInfo` 结构体，描述了操作对寄存器的使用（输入、输出、可能被覆盖的寄存器）。
   - `asm`:  对应的 ARM 汇编指令助记符（例如 "ADD", "MOVW"）。
   - `aux`:  辅助信息类型（例如 "Int32", "SymOff"）。
   - `commutative`:  指示操作是否满足交换律。
   - `typ`:  操作的 Go 语言类型。
   - `call`, `tailCall`:  指示操作是否为函数调用或尾调用。
   - `nilCheck`: 指示操作是否进行空指针检查。
   - `faultOnNilArg0`, `faultOnNilArg1`: 指示如果特定参数为空指针是否会触发错误。
   - `symEffect`:  指示操作是否影响符号（用于链接）。
   - `rematerializeable`: 指示操作的结果是否可以重新计算。

3. **定义 ARM 架构的寄存器名称和分组:**
   - `regNamesARM`:  定义了 ARM 架构中使用的寄存器名称（例如 "R0", "SP", "F0"）。
   - `buildReg` 函数和相关的 `gp`, `fp`, `callerSave` 等变量：用于创建寄存器掩码（`regMask`），方便在 `regInfo` 中指定操作使用的寄存器。例如，`gp` 表示通用寄存器，`fp` 表示浮点寄存器，`callerSave` 表示调用者保存的寄存器。

4. **定义代码块类型:**  `blocks` 切片定义了控制流代码块的类型，例如条件跳转 (`EQ`, `NE`, `LT` 等)。

5. **架构信息:** `archs` 切片包含了关于 ARM 架构的信息，例如包名、生成文件的路径、操作码、代码块类型、寄存器名称、通用寄存器掩码、浮点寄存器掩码等。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言编译器将**高级 Go 代码**转换为**低级 ARM 汇编代码**的关键组成部分。 具体来说，它参与了编译器后端将 **SSA 中间表示** 降低到目标架构（ARM）指令的过程。

当 Go 编译器处理 Go 源代码时，它会经历多个阶段，其中包括：

1. **解析和类型检查:** 将 Go 代码解析成抽象语法树 (AST)，并进行类型检查。
2. **生成 SSA:** 将 AST 转换为静态单赋值 (SSA) 中间表示。SSA 是一种更接近机器代码的抽象表示，方便进行各种优化。
3. **SSA 优化:** 对 SSA 进行各种优化，例如死代码消除、常量折叠等。
4. **SSA 降低 (Lowering):** 将与架构无关的 SSA 操作转换为目标架构特定的操作。`ARMOps.go` 中定义的操作码就在这个阶段被使用。
5. **指令选择和调度:** 选择合适的 ARM 指令来实现 SSA 操作，并进行指令调度以提高性能。
6. **寄存器分配:** 将 SSA 中的虚拟寄存器分配到实际的 ARM 物理寄存器。
7. **汇编代码生成:** 生成最终的 ARM 汇编代码。

`ARMOps.go` 文件主要服务于 **SSA 降低** 阶段。编译器会根据 Go 代码的操作，在 `ops` 切片中查找对应的 ARM 操作码，并生成相应的 SSA 指令。

**Go 代码举例说明:**

假设有以下简单的 Go 代码：

```go
package main

func add(a, b int32) int32 {
	return a + b
}

func main() {
	x := 10
	y := 20
	z := add(x, y)
	println(z)
}
```

在编译这个代码并生成 ARM 汇编的过程中，`ARMOps.go` 中定义的某些操作码会被使用。例如， `add` 函数中的 `a + b` 操作会被转换为 SSA 中的一个加法操作。在降低阶段，这个 SSA 加法操作可能会对应到 `ARMOps.go` 中的 `ADD` 操作码。

**代码推理 (带假设的输入与输出):**

假设 SSA 中间表示中有一个加法操作，表示两个 `int32` 类型的变量相加。

**输入 (SSA 操作):**  `OpAdd32 <type:int32> arg0 arg1` (假设 `arg0` 和 `arg1` 是表示 `a` 和 `b` 的 SSA 值)

**推理:**  编译器会在 `ARMOps.go` 的 `ops` 切片中找到 `name: "ADD"` 并且 `argLength: 2`, `reg: gp21` 的 `opData`。 这表示这是一个二元操作，输入和输出都是通用寄存器。

**输出 (ARM SSA 操作):**  一个针对 ARM 架构的 SSA 指令，可能类似于： `ADDW <type:int32> Rsrc1 Rsrc2 Rdst`  (其中 `Rsrc1`, `Rsrc2`, `Rdst` 是分配给 `arg0`, `arg1` 和结果的寄存器)。

**假设:**
- 编译器选择了 `ADDW` (Add Word) 作为对应的 ARM 汇编指令。
- 寄存器分配器将 SSA 值 `arg0` 和 `arg1` 分配到了 ARM 寄存器 `Rsrc1` 和 `Rsrc2`，并将结果分配到了 `Rdst`。

**命令行参数的具体处理:**

`ARMOps.go` 本身是一个数据定义文件，并不直接处理命令行参数。但是，Go 编译器的命令行参数会间接影响到这个文件的使用。

例如：

- **`-gcflags "-S"`:**  这个参数会让编译器打印生成的汇编代码，你可以从中看到与 `ARMOps.go` 中定义的操作码对应的 ARM 汇编指令。
- **`-o <output_file>`:** 指定输出文件的名称。
- **`-p <package_path>`:**  指定要编译的包的路径。
- **`GOARCH=arm`:** 这个环境变量告诉 Go 编译器目标架构是 ARM，从而会使用 `ARMOps.go` 中定义的 ARM 特定操作码。

当使用 `go build` 或 `go run` 命令时，编译器会根据目标架构 (`GOARCH`) 加载相应的 `*_Ops.go` 文件。

**使用者易犯错的点:**

由于 `ARMOps.go` 是一个由工具生成的文件，并且是编译器内部实现的一部分，**普通的 Go 开发者不会直接与这个文件交互，因此不太可能犯错。**

但是，对于 **Go 编译器开发者** 来说，在修改或扩展这个文件时，可能会遇到以下易错点：

1. **寄存器约束错误:**  在 `regInfo` 中定义了不正确的寄存器约束，可能导致生成的代码无法正常工作或者性能下降。例如，错误地指定了输入或输出寄存器，或者忘记标记可能被覆盖的寄存器。

2. **操作码定义不完整或错误:**  如果添加新的操作码，需要确保所有相关的属性（`argLength`, `asm`, `aux`, `typ` 等）都定义正确。错误的定义可能导致编译器崩溃或生成错误的汇编代码。

3. **与现有操作码冲突:**  添加新的操作码时，需要确保其名称和语义不会与现有的操作码冲突。

4. **辅助信息类型不匹配:**  如果操作码使用了辅助信息 (`aux`)，需要确保辅助信息的类型与实际使用时的类型匹配。

5. **忽略指令的副作用:**  某些 ARM 指令会设置 CPU 的标志位。在定义操作码时，需要正确地标记 `clobberFlags` 属性，以便后续的优化和代码生成能够正确处理这些副作用。

**举例说明 (编译器开发者易犯的错误):**

假设一个编译器开发者想为 ARM 架构添加一个新的原子加法操作 `ATOMICADD`。他可能会定义如下的 `opData`:

```go
{name: "ATOMICADD", argLength: 2, reg: gp21, asm: "LDADD", commutative: false /* 假设原子加法不满足交换律 */},
```

**潜在错误:**

- **ARM 指令助记符错误:**  `LDADD` 可能不是 ARM 中原子加法的正确指令助记符，或者需要更详细的指令形式。
- **寄存器约束不足:** 原子操作通常对寄存器的使用有特殊的要求，可能需要指定特定的寄存器或者内存地址对齐方式。 `gp21` 可能无法满足这些要求。
- **缺少内存屏障考虑:** 原子操作通常需要配合内存屏障指令来保证操作的正确性。这个 `opData` 中没有体现对内存屏障的处理。
- **`commutative` 属性可能需要仔细考虑:**  虽然原子加法操作本身逻辑上是可交换的，但其在内存中的执行顺序会影响其他线程的观察，因此标记为 `false` 可能更安全。

总之，`go/src/cmd/compile/internal/ssa/_gen/ARMOps.go` 是 Go 编译器针对 ARM 架构进行代码生成的核心数据定义文件，它定义了 SSA 中间表示到 ARM 汇编指令的映射关系，是理解 Go 编译器后端工作原理的重要部分。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/_gen/ARMOps.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "strings"

// Notes:
//  - Integer types live in the low portion of registers. Upper portions are junk.
//  - Boolean types use the low-order byte of a register. 0=false, 1=true.
//    Upper bytes are junk.
//  - *const instructions may use a constant larger than the instruction can encode.
//    In this case the assembler expands to multiple instructions and uses tmp
//    register (R11).

// Suffixes encode the bit width of various instructions.
// W (word)      = 32 bit
// H (half word) = 16 bit
// HU            = 16 bit unsigned
// B (byte)      = 8 bit
// BU            = 8 bit unsigned
// F (float)     = 32 bit float
// D (double)    = 64 bit float

var regNamesARM = []string{
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
	"g",   // aka R10
	"R11", // tmp
	"R12",
	"SP",  // aka R13
	"R14", // link
	"R15", // pc

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
	"F15", // tmp

	// If you add registers, update asyncPreempt in runtime.

	// pseudo-registers
	"SB",
}

func init() {
	// Make map from reg names to reg integers.
	if len(regNamesARM) > 64 {
		panic("too many registers")
	}
	num := map[string]int{}
	for i, name := range regNamesARM {
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
		gp         = buildReg("R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14")
		gpg        = gp | buildReg("g")
		gpsp       = gp | buildReg("SP")
		gpspg      = gpg | buildReg("SP")
		gpspsbg    = gpspg | buildReg("SB")
		fp         = buildReg("F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15")
		callerSave = gp | fp | buildReg("g") // runtime.setg (and anything calling it) may clobber g
		r0         = buildReg("R0")
		r1         = buildReg("R1")
		r2         = buildReg("R2")
		r3         = buildReg("R3")
		r4         = buildReg("R4")
	)
	// Common regInfo
	var (
		gp01      = regInfo{inputs: nil, outputs: []regMask{gp}}
		gp11      = regInfo{inputs: []regMask{gpg}, outputs: []regMask{gp}}
		gp11carry = regInfo{inputs: []regMask{gpg}, outputs: []regMask{gp, 0}}
		gp11sp    = regInfo{inputs: []regMask{gpspg}, outputs: []regMask{gp}}
		gp1flags  = regInfo{inputs: []regMask{gpg}}
		gp1flags1 = regInfo{inputs: []regMask{gp}, outputs: []regMask{gp}}
		gp21      = regInfo{inputs: []regMask{gpg, gpg}, outputs: []regMask{gp}}
		gp21carry = regInfo{inputs: []regMask{gpg, gpg}, outputs: []regMask{gp, 0}}
		gp2flags  = regInfo{inputs: []regMask{gpg, gpg}}
		gp2flags1 = regInfo{inputs: []regMask{gp, gp}, outputs: []regMask{gp}}
		gp22      = regInfo{inputs: []regMask{gpg, gpg}, outputs: []regMask{gp, gp}}
		gp31      = regInfo{inputs: []regMask{gp, gp, gp}, outputs: []regMask{gp}}
		gp31carry = regInfo{inputs: []regMask{gp, gp, gp}, outputs: []regMask{gp, 0}}
		gp3flags  = regInfo{inputs: []regMask{gp, gp, gp}}
		gp3flags1 = regInfo{inputs: []regMask{gp, gp, gp}, outputs: []regMask{gp}}
		gpload    = regInfo{inputs: []regMask{gpspsbg}, outputs: []regMask{gp}}
		gpstore   = regInfo{inputs: []regMask{gpspsbg, gpg}}
		gp2load   = regInfo{inputs: []regMask{gpspsbg, gpg}, outputs: []regMask{gp}}
		gp2store  = regInfo{inputs: []regMask{gpspsbg, gpg, gpg}}
		fp01      = regInfo{inputs: nil, outputs: []regMask{fp}}
		fp11      = regInfo{inputs: []regMask{fp}, outputs: []regMask{fp}}
		fp1flags  = regInfo{inputs: []regMask{fp}}
		fpgp      = regInfo{inputs: []regMask{fp}, outputs: []regMask{gp}, clobbers: buildReg("F15")} // int-float conversion uses F15 as tmp
		gpfp      = regInfo{inputs: []regMask{gp}, outputs: []regMask{fp}, clobbers: buildReg("F15")}
		fp21      = regInfo{inputs: []regMask{fp, fp}, outputs: []regMask{fp}}
		fp31      = regInfo{inputs: []regMask{fp, fp, fp}, outputs: []regMask{fp}}
		fp2flags  = regInfo{inputs: []regMask{fp, fp}}
		fpload    = regInfo{inputs: []regMask{gpspsbg}, outputs: []regMask{fp}}
		fpstore   = regInfo{inputs: []regMask{gpspsbg, fp}}
		readflags = regInfo{inputs: nil, outputs: []regMask{gp}}
	)
	ops := []opData{
		// binary ops
		{name: "ADD", argLength: 2, reg: gp21, asm: "ADD", commutative: true},     // arg0 + arg1
		{name: "ADDconst", argLength: 1, reg: gp11sp, asm: "ADD", aux: "Int32"},   // arg0 + auxInt
		{name: "SUB", argLength: 2, reg: gp21, asm: "SUB"},                        // arg0 - arg1
		{name: "SUBconst", argLength: 1, reg: gp11, asm: "SUB", aux: "Int32"},     // arg0 - auxInt
		{name: "RSB", argLength: 2, reg: gp21, asm: "RSB"},                        // arg1 - arg0
		{name: "RSBconst", argLength: 1, reg: gp11, asm: "RSB", aux: "Int32"},     // auxInt - arg0
		{name: "MUL", argLength: 2, reg: gp21, asm: "MUL", commutative: true},     // arg0 * arg1
		{name: "HMUL", argLength: 2, reg: gp21, asm: "MULL", commutative: true},   // (arg0 * arg1) >> 32, signed
		{name: "HMULU", argLength: 2, reg: gp21, asm: "MULLU", commutative: true}, // (arg0 * arg1) >> 32, unsigned

		// udiv runtime call for soft division
		// output0 = arg0/arg1, output1 = arg0%arg1
		// see ../../../../../runtime/vlop_arm.s
		{
			name:      "CALLudiv",
			argLength: 2,
			reg: regInfo{
				inputs:   []regMask{buildReg("R1"), buildReg("R0")},
				outputs:  []regMask{buildReg("R0"), buildReg("R1")},
				clobbers: buildReg("R2 R3 R12 R14"), // R14 is LR, R12 is linker trampoline scratch register
			},
			clobberFlags: true,
			typ:          "(UInt32,UInt32)",
			call:         false, // TODO(mdempsky): Should this be true?
		},

		{name: "ADDS", argLength: 2, reg: gp21carry, asm: "ADD", commutative: true}, // arg0 + arg1, set carry flag
		{name: "ADDSconst", argLength: 1, reg: gp11carry, asm: "ADD", aux: "Int32"}, // arg0 + auxInt, set carry flag
		{name: "ADC", argLength: 3, reg: gp2flags1, asm: "ADC", commutative: true},  // arg0 + arg1 + carry, arg2=flags
		{name: "ADCconst", argLength: 2, reg: gp1flags1, asm: "ADC", aux: "Int32"},  // arg0 + auxInt + carry, arg1=flags
		{name: "SUBS", argLength: 2, reg: gp21carry, asm: "SUB"},                    // arg0 - arg1, set carry flag
		{name: "SUBSconst", argLength: 1, reg: gp11carry, asm: "SUB", aux: "Int32"}, // arg0 - auxInt, set carry flag
		{name: "RSBSconst", argLength: 1, reg: gp11carry, asm: "RSB", aux: "Int32"}, // auxInt - arg0, set carry flag
		{name: "SBC", argLength: 3, reg: gp2flags1, asm: "SBC"},                     // arg0 - arg1 - carry, arg2=flags
		{name: "SBCconst", argLength: 2, reg: gp1flags1, asm: "SBC", aux: "Int32"},  // arg0 - auxInt - carry, arg1=flags
		{name: "RSCconst", argLength: 2, reg: gp1flags1, asm: "RSC", aux: "Int32"},  // auxInt - arg0 - carry, arg1=flags

		{name: "MULLU", argLength: 2, reg: gp22, asm: "MULLU", commutative: true}, // arg0 * arg1, high 32 bits in out0, low 32 bits in out1
		{name: "MULA", argLength: 3, reg: gp31, asm: "MULA"},                      // arg0 * arg1 + arg2
		{name: "MULS", argLength: 3, reg: gp31, asm: "MULS"},                      // arg2 - arg0 * arg1

		{name: "ADDF", argLength: 2, reg: fp21, asm: "ADDF", commutative: true},   // arg0 + arg1
		{name: "ADDD", argLength: 2, reg: fp21, asm: "ADDD", commutative: true},   // arg0 + arg1
		{name: "SUBF", argLength: 2, reg: fp21, asm: "SUBF"},                      // arg0 - arg1
		{name: "SUBD", argLength: 2, reg: fp21, asm: "SUBD"},                      // arg0 - arg1
		{name: "MULF", argLength: 2, reg: fp21, asm: "MULF", commutative: true},   // arg0 * arg1
		{name: "MULD", argLength: 2, reg: fp21, asm: "MULD", commutative: true},   // arg0 * arg1
		{name: "NMULF", argLength: 2, reg: fp21, asm: "NMULF", commutative: true}, // -(arg0 * arg1)
		{name: "NMULD", argLength: 2, reg: fp21, asm: "NMULD", commutative: true}, // -(arg0 * arg1)
		{name: "DIVF", argLength: 2, reg: fp21, asm: "DIVF"},                      // arg0 / arg1
		{name: "DIVD", argLength: 2, reg: fp21, asm: "DIVD"},                      // arg0 / arg1

		{name: "MULAF", argLength: 3, reg: fp31, asm: "MULAF", resultInArg0: true}, // arg0 + (arg1 * arg2)
		{name: "MULAD", argLength: 3, reg: fp31, asm: "MULAD", resultInArg0: true}, // arg0 + (arg1 * arg2)
		{name: "MULSF", argLength: 3, reg: fp31, asm: "MULSF", resultInArg0: true}, // arg0 - (arg1 * arg2)
		{name: "MULSD", argLength: 3, reg: fp31, asm: "MULSD", resultInArg0: true}, // arg0 - (arg1 * arg2)

		// FMULAD only exists on platforms with the VFPv4 instruction set.
		// Any use must be preceded by a successful check of runtime.arm_support_vfpv4.
		{name: "FMULAD", argLength: 3, reg: fp31, asm: "FMULAD", resultInArg0: true}, // arg0 + (arg1 * arg2)

		{name: "AND", argLength: 2, reg: gp21, asm: "AND", commutative: true}, // arg0 & arg1
		{name: "ANDconst", argLength: 1, reg: gp11, asm: "AND", aux: "Int32"}, // arg0 & auxInt
		{name: "OR", argLength: 2, reg: gp21, asm: "ORR", commutative: true},  // arg0 | arg1
		{name: "ORconst", argLength: 1, reg: gp11, asm: "ORR", aux: "Int32"},  // arg0 | auxInt
		{name: "XOR", argLength: 2, reg: gp21, asm: "EOR", commutative: true}, // arg0 ^ arg1
		{name: "XORconst", argLength: 1, reg: gp11, asm: "EOR", aux: "Int32"}, // arg0 ^ auxInt
		{name: "BIC", argLength: 2, reg: gp21, asm: "BIC"},                    // arg0 &^ arg1
		{name: "BICconst", argLength: 1, reg: gp11, asm: "BIC", aux: "Int32"}, // arg0 &^ auxInt

		// bit extraction, AuxInt = Width<<8 | LSB
		{name: "BFX", argLength: 1, reg: gp11, asm: "BFX", aux: "Int32"},   // extract W bits from bit L in arg0, then signed extend
		{name: "BFXU", argLength: 1, reg: gp11, asm: "BFXU", aux: "Int32"}, // extract W bits from bit L in arg0, then unsigned extend

		// unary ops
		{name: "MVN", argLength: 1, reg: gp11, asm: "MVN"}, // ^arg0

		{name: "NEGF", argLength: 1, reg: fp11, asm: "NEGF"},   // -arg0, float32
		{name: "NEGD", argLength: 1, reg: fp11, asm: "NEGD"},   // -arg0, float64
		{name: "SQRTD", argLength: 1, reg: fp11, asm: "SQRTD"}, // sqrt(arg0), float64
		{name: "SQRTF", argLength: 1, reg: fp11, asm: "SQRTF"}, // sqrt(arg0), float32
		{name: "ABSD", argLength: 1, reg: fp11, asm: "ABSD"},   // abs(arg0), float64

		{name: "CLZ", argLength: 1, reg: gp11, asm: "CLZ"},     // count leading zero
		{name: "REV", argLength: 1, reg: gp11, asm: "REV"},     // reverse byte order
		{name: "REV16", argLength: 1, reg: gp11, asm: "REV16"}, // reverse byte order in 16-bit halfwords
		{name: "RBIT", argLength: 1, reg: gp11, asm: "RBIT"},   // reverse bit order

		// shifts
		{name: "SLL", argLength: 2, reg: gp21, asm: "SLL"},                    // arg0 << arg1, shift amount is mod 256
		{name: "SLLconst", argLength: 1, reg: gp11, asm: "SLL", aux: "Int32"}, // arg0 << auxInt, 0 <= auxInt < 32
		{name: "SRL", argLength: 2, reg: gp21, asm: "SRL"},                    // arg0 >> arg1, unsigned, shift amount is mod 256
		{name: "SRLconst", argLength: 1, reg: gp11, asm: "SRL", aux: "Int32"}, // arg0 >> auxInt, unsigned, 0 <= auxInt < 32
		{name: "SRA", argLength: 2, reg: gp21, asm: "SRA"},                    // arg0 >> arg1, signed, shift amount is mod 256
		{name: "SRAconst", argLength: 1, reg: gp11, asm: "SRA", aux: "Int32"}, // arg0 >> auxInt, signed, 0 <= auxInt < 32
		{name: "SRR", argLength: 2, reg: gp21},                                // arg0 right rotate by arg1 bits
		{name: "SRRconst", argLength: 1, reg: gp11, aux: "Int32"},             // arg0 right rotate by auxInt bits, 0 <= auxInt < 32

		// auxInt for all of these satisfy 0 <= auxInt < 32
		{name: "ADDshiftLL", argLength: 2, reg: gp21, asm: "ADD", aux: "Int32"}, // arg0 + arg1<<auxInt
		{name: "ADDshiftRL", argLength: 2, reg: gp21, asm: "ADD", aux: "Int32"}, // arg0 + arg1>>auxInt, unsigned shift
		{name: "ADDshiftRA", argLength: 2, reg: gp21, asm: "ADD", aux: "Int32"}, // arg0 + arg1>>auxInt, signed shift
		{name: "SUBshiftLL", argLength: 2, reg: gp21, asm: "SUB", aux: "Int32"}, // arg0 - arg1<<auxInt
		{name: "SUBshiftRL", argLength: 2, reg: gp21, asm: "SUB", aux: "Int32"}, // arg0 - arg1>>auxInt, unsigned shift
		{name: "SUBshiftRA", argLength: 2, reg: gp21, asm: "SUB", aux: "Int32"}, // arg0 - arg1>>auxInt, signed shift
		{name: "RSBshiftLL", argLength: 2, reg: gp21, asm: "RSB", aux: "Int32"}, // arg1<<auxInt - arg0
		{name: "RSBshiftRL", argLength: 2, reg: gp21, asm: "RSB", aux: "Int32"}, // arg1>>auxInt - arg0, unsigned shift
		{name: "RSBshiftRA", argLength: 2, reg: gp21, asm: "RSB", aux: "Int32"}, // arg1>>auxInt - arg0, signed shift
		{name: "ANDshiftLL", argLength: 2, reg: gp21, asm: "AND", aux: "Int32"}, // arg0 & (arg1<<auxInt)
		{name: "ANDshiftRL", argLength: 2, reg: gp21, asm: "AND", aux: "Int32"}, // arg0 & (arg1>>auxInt), unsigned shift
		{name: "ANDshiftRA", argLength: 2, reg: gp21, asm: "AND", aux: "Int32"}, // arg0 & (arg1>>auxInt), signed shift
		{name: "ORshiftLL", argLength: 2, reg: gp21, asm: "ORR", aux: "Int32"},  // arg0 | arg1<<auxInt
		{name: "ORshiftRL", argLength: 2, reg: gp21, asm: "ORR", aux: "Int32"},  // arg0 | arg1>>auxInt, unsigned shift
		{name: "ORshiftRA", argLength: 2, reg: gp21, asm: "ORR", aux: "Int32"},  // arg0 | arg1>>auxInt, signed shift
		{name: "XORshiftLL", argLength: 2, reg: gp21, asm: "EOR", aux: "Int32"}, // arg0 ^ arg1<<auxInt
		{name: "XORshiftRL", argLength: 2, reg: gp21, asm: "EOR", aux: "Int32"}, // arg0 ^ arg1>>auxInt, unsigned shift
		{name: "XORshiftRA", argLength: 2, reg: gp21, asm: "EOR", aux: "Int32"}, // arg0 ^ arg1>>auxInt, signed shift
		{name: "XORshiftRR", argLength: 2, reg: gp21, asm: "EOR", aux: "Int32"}, // arg0 ^ (arg1 right rotate by auxInt)
		{name: "BICshiftLL", argLength: 2, reg: gp21, asm: "BIC", aux: "Int32"}, // arg0 &^ (arg1<<auxInt)
		{name: "BICshiftRL", argLength: 2, reg: gp21, asm: "BIC", aux: "Int32"}, // arg0 &^ (arg1>>auxInt), unsigned shift
		{name: "BICshiftRA", argLength: 2, reg: gp21, asm: "BIC", aux: "Int32"}, // arg0 &^ (arg1>>auxInt), signed shift
		{name: "MVNshiftLL", argLength: 1, reg: gp11, asm: "MVN", aux: "Int32"}, // ^(arg0<<auxInt)
		{name: "MVNshiftRL", argLength: 1, reg: gp11, asm: "MVN", aux: "Int32"}, // ^(arg0>>auxInt), unsigned shift
		{name: "MVNshiftRA", argLength: 1, reg: gp11, asm: "MVN", aux: "Int32"}, // ^(arg0>>auxInt), signed shift

		{name: "ADCshiftLL", argLength: 3, reg: gp2flags1, asm: "ADC", aux: "Int32"}, // arg0 + arg1<<auxInt + carry, arg2=flags
		{name: "ADCshiftRL", argLength: 3, reg: gp2flags1, asm: "ADC", aux: "Int32"}, // arg0 + arg1>>auxInt + carry, unsigned shift, arg2=flags
		{name: "ADCshiftRA", argLength: 3, reg: gp2flags1, asm: "ADC", aux: "Int32"}, // arg0 + arg1>>auxInt + carry, signed shift, arg2=flags
		{name: "SBCshiftLL", argLength: 3, reg: gp2flags1, asm: "SBC", aux: "Int32"}, // arg0 - arg1<<auxInt - carry, arg2=flags
		{name: "SBCshiftRL", argLength: 3, reg: gp2flags1, asm: "SBC", aux: "Int32"}, // arg0 - arg1>>auxInt - carry, unsigned shift, arg2=flags
		{name: "SBCshiftRA", argLength: 3, reg: gp2flags1, asm: "SBC", aux: "Int32"}, // arg0 - arg1>>auxInt - carry, signed shift, arg2=flags
		{name: "RSCshiftLL", argLength: 3, reg: gp2flags1, asm: "RSC", aux: "Int32"}, // arg1<<auxInt - arg0 - carry, arg2=flags
		{name: "RSCshiftRL", argLength: 3, reg: gp2flags1, asm: "RSC", aux: "Int32"}, // arg1>>auxInt - arg0 - carry, unsigned shift, arg2=flags
		{name: "RSCshiftRA", argLength: 3, reg: gp2flags1, asm: "RSC", aux: "Int32"}, // arg1>>auxInt - arg0 - carry, signed shift, arg2=flags

		{name: "ADDSshiftLL", argLength: 2, reg: gp21carry, asm: "ADD", aux: "Int32"}, // arg0 + arg1<<auxInt, set carry flag
		{name: "ADDSshiftRL", argLength: 2, reg: gp21carry, asm: "ADD", aux: "Int32"}, // arg0 + arg1>>auxInt, unsigned shift, set carry flag
		{name: "ADDSshiftRA", argLength: 2, reg: gp21carry, asm: "ADD", aux: "Int32"}, // arg0 + arg1>>auxInt, signed shift, set carry flag
		{name: "SUBSshiftLL", argLength: 2, reg: gp21carry, asm: "SUB", aux: "Int32"}, // arg0 - arg1<<auxInt, set carry flag
		{name: "SUBSshiftRL", argLength: 2, reg: gp21carry, asm: "SUB", aux: "Int32"}, // arg0 - arg1>>auxInt, unsigned shift, set carry flag
		{name: "SUBSshiftRA", argLength: 2, reg: gp21carry, asm: "SUB", aux: "Int32"}, // arg0 - arg1>>auxInt, signed shift, set carry flag
		{name: "RSBSshiftLL", argLength: 2, reg: gp21carry, asm: "RSB", aux: "Int32"}, // arg1<<auxInt - arg0, set carry flag
		{name: "RSBSshiftRL", argLength: 2, reg: gp21carry, asm: "RSB", aux: "Int32"}, // arg1>>auxInt - arg0, unsigned shift, set carry flag
		{name: "RSBSshiftRA", argLength: 2, reg: gp21carry, asm: "RSB", aux: "Int32"}, // arg1>>auxInt - arg0, signed shift, set carry flag

		{name: "ADDshiftLLreg", argLength: 3, reg: gp31, asm: "ADD"}, // arg0 + arg1<<arg2
		{name: "ADDshiftRLreg", argLength: 3, reg: gp31, asm: "ADD"}, // arg0 + arg1>>arg2, unsigned shift
		{name: "ADDshiftRAreg", argLength: 3, reg: gp31, asm: "ADD"}, // arg0 + arg1>>arg2, signed shift
		{name: "SUBshiftLLreg", argLength: 3, reg: gp31, asm: "SUB"}, // arg0 - arg1<<arg2
		{name: "SUBshiftRLreg", argLength: 3, reg: gp31, asm: "SUB"}, // arg0 - arg1>>arg2, unsigned shift
		{name: "SUBshiftRAreg", argLength: 3, reg: gp31, asm: "SUB"}, // arg0 - arg1>>arg2, signed shift
		{name: "RSBshiftLLreg", argLength: 3, reg: gp31, asm: "RSB"}, // arg1<<arg2 - arg0
		{name: "RSBshiftRLreg", argLength: 3, reg: gp31, asm: "RSB"}, // arg1>>arg2 - arg0, unsigned shift
		{name: "RSBshiftRAreg", argLength: 3, reg: gp31, asm: "RSB"}, // arg1>>arg2 - arg0, signed shift
		{name: "ANDshiftLLreg", argLength: 3, reg: gp31, asm: "AND"}, // arg0 & (arg1<<arg2)
		{name: "ANDshiftRLreg", argLength: 3, reg: gp31, asm: "AND"}, // arg0 & (arg1>>arg2), unsigned shift
		{name: "ANDshiftRAreg", argLength: 3, reg: gp31, asm: "AND"}, // arg0 & (arg1>>arg2), signed shift
		{name: "ORshiftLLreg", argLength: 3, reg: gp31, asm: "ORR"},  // arg0 | arg1<<arg2
		{name: "ORshiftRLreg", argLength: 3, reg: gp31, asm: "ORR"},  // arg0 | arg1>>arg2, unsigned shift
		{name: "ORshiftRAreg", argLength: 3, reg: gp31, asm: "ORR"},  // arg0 | arg1>>arg2, signed shift
		{name: "XORshiftLLreg", argLength: 3, reg: gp31, asm: "EOR"}, // arg0 ^ arg1<<arg2
		{name: "XORshiftRLreg", argLength: 3, reg: gp31, asm: "EOR"}, // arg0 ^ arg1>>arg2, unsigned shift
		{name: "XORshiftRAreg", argLength: 3, reg: gp31, asm: "EOR"}, // arg0 ^ arg1>>arg2, signed shift
		{name: "BICshiftLLreg", argLength: 3, reg: gp31, asm: "BIC"}, // arg0 &^ (arg1<<arg2)
		{name: "BICshiftRLreg", argLength: 3, reg: gp31, asm: "BIC"}, // arg0 &^ (arg1>>arg2), unsigned shift
		{name: "BICshiftRAreg", argLength: 3, reg: gp31, asm: "BIC"}, // arg0 &^ (arg1>>arg2), signed shift
		{name: "MVNshiftLLreg", argLength: 2, reg: gp21, asm: "MVN"}, // ^(arg0<<arg1)
		{name: "MVNshiftRLreg", argLength: 2, reg: gp21, asm: "MVN"}, // ^(arg0>>arg1), unsigned shift
		{name: "MVNshiftRAreg", argLength: 2, reg: gp21, asm: "MVN"}, // ^(arg0>>arg1), signed shift

		{name: "ADCshiftLLreg", argLength: 4, reg: gp3flags1, asm: "ADC"}, // arg0 + arg1<<arg2 + carry, arg3=flags
		{name: "ADCshiftRLreg", argLength: 4, reg: gp3flags1, asm: "ADC"}, // arg0 + arg1>>arg2 + carry, unsigned shift, arg3=flags
		{name: "ADCshiftRAreg", argLength: 4, reg: gp3flags1, asm: "ADC"}, // arg0 + arg1>>arg2 + carry, signed shift, arg3=flags
		{name: "SBCshiftLLreg", argLength: 4, reg: gp3flags1, asm: "SBC"}, // arg0 - arg1<<arg2 - carry, arg3=flags
		{name: "SBCshiftRLreg", argLength: 4, reg: gp3flags1, asm: "SBC"}, // arg0 - arg1>>arg2 - carry, unsigned shift, arg3=flags
		{name: "SBCshiftRAreg", argLength: 4, reg: gp3flags1, asm: "SBC"}, // arg0 - arg1>>arg2 - carry, signed shift, arg3=flags
		{name: "RSCshiftLLreg", argLength: 4, reg: gp3flags1, asm: "RSC"}, // arg1<<arg2 - arg0 - carry, arg3=flags
		{name: "RSCshiftRLreg", argLength: 4, reg: gp3flags1, asm: "RSC"}, // arg1>>arg2 - arg0 - carry, unsigned shift, arg3=flags
		{name: "RSCshiftRAreg", argLength: 4, reg: gp3flags1, asm: "RSC"}, // arg1>>arg2 - arg0 - carry, signed shift, arg3=flags

		{name: "ADDSshiftLLreg", argLength: 3, reg: gp31carry, asm: "ADD"}, // arg0 + arg1<<arg2, set carry flag
		{name: "ADDSshiftRLreg", argLength: 3, reg: gp31carry, asm: "ADD"}, // arg0 + arg1>>arg2, unsigned shift, set carry flag
		{name: "ADDSshiftRAreg", argLength: 3, reg: gp31carry, asm: "ADD"}, // arg0 + arg1>>arg2, signed shift, set carry flag
		{name: "SUBSshiftLLreg", argLength: 3, reg: gp31carry, asm: "SUB"}, // arg0 - arg1<<arg2, set carry flag
		{name: "SUBSshiftRLreg", argLength: 3, reg: gp31carry, asm: "SUB"}, // arg0 - arg1>>arg2, unsigned shift, set carry flag
		{name: "SUBSshiftRAreg", argLength: 3, reg: gp31carry, asm: "SUB"}, // arg0 - arg1>>arg2, signed shift, set carry flag
		{name: "RSBSshiftLLreg", argLength: 3, reg: gp31carry, asm: "RSB"}, // arg1<<arg2 - arg0, set carry flag
		{name: "RSBSshiftRLreg", argLength: 3, reg: gp31carry, asm: "RSB"}, // arg1>>arg2 - arg0, unsigned shift, set carry flag
		{name: "RSBSshiftRAreg", argLength: 3, reg: gp31carry, asm: "RSB"}, // arg1>>arg2 - arg0, signed shift, set carry flag

		// comparisons
		{name: "CMP", argLength: 2, reg: gp2flags, asm: "CMP", typ: "Flags"},                    // arg0 compare to arg1
		{name: "CMPconst", argLength: 1, reg: gp1flags, asm: "CMP", aux: "Int32", typ: "Flags"}, // arg0 compare to auxInt
		{name: "CMN", argLength: 2, reg: gp2flags, asm: "CMN", typ: "Flags", commutative: true}, // arg0 compare to -arg1, provided arg1 is not 1<<63
		{name: "CMNconst", argLength: 1, reg: gp1flags, asm: "CMN", aux: "Int32", typ: "Flags"}, // arg0 compare to -auxInt
		{name: "TST", argLength: 2, reg: gp2flags, asm: "TST", typ: "Flags", commutative: true}, // arg0 & arg1 compare to 0
		{name: "TSTconst", argLength: 1, reg: gp1flags, asm: "TST", aux: "Int32", typ: "Flags"}, // arg0 & auxInt compare to 0
		{name: "TEQ", argLength: 2, reg: gp2flags, asm: "TEQ", typ: "Flags", commutative: true}, // arg0 ^ arg1 compare to 0
		{name: "TEQconst", argLength: 1, reg: gp1flags, asm: "TEQ", aux: "Int32", typ: "Flags"}, // arg0 ^ auxInt compare to 0
		{name: "CMPF", argLength: 2, reg: fp2flags, asm: "CMPF", typ: "Flags"},                  // arg0 compare to arg1, float32
		{name: "CMPD", argLength: 2, reg: fp2flags, asm: "CMPD", typ: "Flags"},                  // arg0 compare to arg1, float64

		{name: "CMPshiftLL", argLength: 2, reg: gp2flags, asm: "CMP", aux: "Int32", typ: "Flags"}, // arg0 compare to arg1<<auxInt
		{name: "CMPshiftRL", argLength: 2, reg: gp2flags, asm: "CMP", aux: "Int32", typ: "Flags"}, // arg0 compare to arg1>>auxInt, unsigned shift
		{name: "CMPshiftRA", argLength: 2, reg: gp2flags, asm: "CMP", aux: "Int32", typ: "Flags"}, // arg0 compare to arg1>>auxInt, signed shift
		{name: "CMNshiftLL", argLength: 2, reg: gp2flags, asm: "CMN", aux: "Int32", typ: "Flags"}, // arg0 compare to -(arg1<<auxInt)
		{name: "CMNshiftRL", argLength: 2, reg: gp2flags, asm: "CMN", aux: "Int32", typ: "Flags"}, // arg0 compare to -(arg1>>auxInt), unsigned shift
		{name: "CMNshiftRA", argLength: 2, reg: gp2flags, asm: "CMN", aux: "Int32", typ: "Flags"}, // arg0 compare to -(arg1>>auxInt), signed shift
		{name: "TSTshiftLL", argLength: 2, reg: gp2flags, asm: "TST", aux: "Int32", typ: "Flags"}, // arg0 & (arg1<<auxInt) compare to 0
		{name: "TSTshiftRL", argLength: 2, reg: gp2flags, asm: "TST", aux: "Int32", typ: "Flags"}, // arg0 & (arg1>>auxInt) compare to 0, unsigned shift
		{name: "TSTshiftRA", argLength: 2, reg: gp2flags, asm: "TST", aux: "Int32", typ: "Flags"}, // arg0 & (arg1>>auxInt) compare to 0, signed shift
		{name: "TEQshiftLL", argLength: 2, reg: gp2flags, asm: "TEQ", aux: "Int32", typ: "Flags"}, // arg0 ^ (arg1<<auxInt) compare to 0
		{name: "TEQshiftRL", argLength: 2, reg: gp2flags, asm: "TEQ", aux: "Int32", typ: "Flags"}, // arg0 ^ (arg1>>auxInt) compare to 0, unsigned shift
		{name: "TEQshiftRA", argLength: 2, reg: gp2flags, asm: "TEQ", aux: "Int32", typ: "Flags"}, // arg0 ^ (arg1>>auxInt) compare to 0, signed shift

		{name: "CMPshiftLLreg", argLength: 3, reg: gp3flags, asm: "CMP", typ: "Flags"}, // arg0 compare to arg1<<arg2
		{name: "CMPshiftRLreg", argLength: 3, reg: gp3flags, asm: "CMP", typ: "Flags"}, // arg0 compare to arg1>>arg2, unsigned shift
		{name: "CMPshiftRAreg", argLength: 3, reg: gp3flags, asm: "CMP", typ: "Flags"}, // arg0 compare to arg1>>arg2, signed shift
		{name: "CMNshiftLLreg", argLength: 3, reg: gp3flags, asm: "CMN", typ: "Flags"}, // arg0 + (arg1<<arg2) compare to 0
		{name: "CMNshiftRLreg", argLength: 3, reg: gp3flags, asm: "CMN", typ: "Flags"}, // arg0 + (arg1>>arg2) compare to 0, unsigned shift
		{name: "CMNshiftRAreg", argLength: 3, reg: gp3flags, asm: "CMN", typ: "Flags"}, // arg0 + (arg1>>arg2) compare to 0, signed shift
		{name: "TSTshiftLLreg", argLength: 3, reg: gp3flags, asm: "TST", typ: "Flags"}, // arg0 & (arg1<<arg2) compare to 0
		{name: "TSTshiftRLreg", argLength: 3, reg: gp3flags, asm: "TST", typ: "Flags"}, // arg0 & (arg1>>arg2) compare to 0, unsigned shift
		{name: "TSTshiftRAreg", argLength: 3, reg: gp3flags, asm: "TST", typ: "Flags"}, // arg0 & (arg1>>arg2) compare to 0, signed shift
		{name: "TEQshiftLLreg", argLength: 3, reg: gp3flags, asm: "TEQ", typ: "Flags"}, // arg0 ^ (arg1<<arg2) compare to 0
		{name: "TEQshiftRLreg", argLength: 3, reg: gp3flags, asm: "TEQ", typ: "Flags"}, // arg0 ^ (arg1>>arg2) compare to 0, unsigned shift
		{name: "TEQshiftRAreg", argLength: 3, reg: gp3flags, asm: "TEQ", typ: "Flags"}, // arg0 ^ (arg1>>arg2) compare to 0, signed shift

		{name: "CMPF0", argLength: 1, reg: fp1flags, asm: "CMPF", typ: "Flags"}, // arg0 compare to 0, float32
		{name: "CMPD0", argLength: 1, reg: fp1flags, asm: "CMPD", typ: "Flags"}, // arg0 compare to 0, float64

		// moves
		{name: "MOVWconst", argLength: 0, reg: gp01, aux: "Int32", asm: "MOVW", typ: "UInt32", rematerializeable: true},    // 32 low bits of auxint
		{name: "MOVFconst", argLength: 0, reg: fp01, aux: "Float64", asm: "MOVF", typ: "Float32", rematerializeable: true}, // auxint as 64-bit float, convert to 32-bit float
		{name: "MOVDconst", argLength: 0, reg: fp01, aux: "Float64", asm: "MOVD", typ: "Float64", rematerializeable: true}, // auxint as 64-bit float

		{name: "MOVWaddr", argLength: 1, reg: regInfo{inputs: []regMask{buildReg("SP") | buildReg("SB")}, outputs: []regMask{gp}}, aux: "SymOff", asm: "MOVW", rematerializeable: true, symEffect: "Addr"}, // arg0 + auxInt + aux.(*gc.Sym), arg0=SP/SB

		{name: "MOVBload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVB", typ: "Int8", faultOnNilArg0: true, symEffect: "Read"},     // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVBUload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVBU", typ: "UInt8", faultOnNilArg0: true, symEffect: "Read"},  // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVHload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVH", typ: "Int16", faultOnNilArg0: true, symEffect: "Read"},    // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVHUload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVHU", typ: "UInt16", faultOnNilArg0: true, symEffect: "Read"}, // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVWload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVW", typ: "UInt32", faultOnNilArg0: true, symEffect: "Read"},   // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVFload", argLength: 2, reg: fpload, aux: "SymOff", asm: "MOVF", typ: "Float32", faultOnNilArg0: true, symEffect: "Read"},  // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVDload", argLength: 2, reg: fpload, aux: "SymOff", asm: "MOVD", typ: "Float64", faultOnNilArg0: true, symEffect: "Read"},  // load from arg0 + auxInt + aux.  arg1=mem.

		{name: "MOVBstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVB", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 1 byte of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVHstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVH", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 2 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVWstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVW", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 4 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVFstore", argLength: 3, reg: fpstore, aux: "SymOff", asm: "MOVF", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 4 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVDstore", argLength: 3, reg: fpstore, aux: "SymOff", asm: "MOVD", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 8 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.

		{name: "MOVWloadidx", argLength: 3, reg: gp2load, asm: "MOVW", typ: "UInt32"},                   // load from arg0 + arg1. arg2=mem
		{name: "MOVWloadshiftLL", argLength: 3, reg: gp2load, asm: "MOVW", aux: "Int32", typ: "UInt32"}, // load from arg0 + arg1<<auxInt. arg2=mem
		{name: "MOVWloadshiftRL", argLength: 3, reg: gp2load, asm: "MOVW", aux: "Int32", typ: "UInt32"}, // load from arg0 + arg1>>auxInt, unsigned shift. arg2=mem
		{name: "MOVWloadshiftRA", argLength: 3, reg: gp2load, asm: "MOVW", aux: "Int32", typ: "UInt32"}, // load from arg0 + arg1>>auxInt, signed shift. arg2=mem
		{name: "MOVBUloadidx", argLength: 3, reg: gp2load, asm: "MOVBU", typ: "UInt8"},                  // load from arg0 + arg1. arg2=mem
		{name: "MOVBloadidx", argLength: 3, reg: gp2load, asm: "MOVB", typ: "Int8"},                     // load from arg0 + arg1. arg2=mem
		{name: "MOVHUloadidx", argLength: 3, reg: gp2load, asm: "MOVHU", typ: "UInt16"},                 // load from arg0 + arg1. arg2=mem
		{name: "MOVHloadidx", argLength: 3, reg: gp2load, asm: "MOVH", typ: "Int16"},                    // load from arg0 + arg1. arg2=mem

		{name: "MOVWstoreidx", argLength: 4, reg: gp2store, asm: "MOVW", typ: "Mem"},                   // store arg2 to arg0 + arg1. arg3=mem
		{name: "MOVWstoreshiftLL", argLength: 4, reg: gp2store, asm: "MOVW", aux: "Int32", typ: "Mem"}, // store arg2 to arg0 + arg1<<auxInt. arg3=mem
		{name: "MOVWstoreshiftRL", argLength: 4, reg: gp2store, asm: "MOVW", aux: "Int32", typ: "Mem"}, // store arg2 to arg0 + arg1>>auxInt, unsigned shift. arg3=mem
		{name: "MOVWstoreshiftRA", argLength: 4, reg: gp2store, asm: "MOVW", aux: "Int32", typ: "Mem"}, // store arg2 to arg0 + arg1>>auxInt, signed shift. arg3=mem
		{name: "MOVBstoreidx", argLength: 4, reg: gp2store, asm: "MOVB", typ: "Mem"},                   // store arg2 to arg0 + arg1. arg3=mem
		{name: "MOVHstoreidx", argLength: 4, reg: gp2store, asm: "MOVH", typ: "Mem"},                   // store arg2 to arg0 + arg1. arg3=mem

		{name: "MOVBreg", argLength: 1, reg: gp11, asm: "MOVBS"},  // move from arg0, sign-extended from byte
		{name: "MOVBUreg", argLength: 1, reg: gp11, asm: "MOVBU"}, // move from arg0, unsign-extended from byte
		{name: "MOVHreg", argLength: 1, reg: gp11, asm: "MOVHS"},  // move from arg0, sign-extended from half
		{name: "MOVHUreg", argLength: 1, reg: gp11, asm: "MOVHU"}, // move from arg0, unsign-extended from half
		{name: "MOVWreg", argLength: 1, reg: gp11, asm: "MOVW"},   // move from arg0

		{name: "MOVWnop", argLength: 1, reg: regInfo{inputs: []regMask{gp}, outputs: []regMask{gp}}, resultInArg0: true}, // nop, return arg0 in same register

		{name: "MOVWF", argLength: 1, reg: gpfp, asm: "MOVWF"},  // int32 -> float32
		{name: "MOVWD", argLength: 1, reg: gpfp, asm: "MOVWD"},  // int32 -> float64
		{name: "MOVWUF", argLength: 1, reg: gpfp, asm: "MOVWF"}, // uint32 -> float32, set U bit in the instruction
		{name: "MOVWUD", argLength: 1, reg: gpfp, asm: "MOVWD"}, // uint32 -> float64, set U bit in the instruction
		{name: "MOVFW", argLength: 1, reg: fpgp, asm: "MOVFW"},  // float32 -> int32
		{name: "MOVDW", argLength: 1, reg: fpgp, asm: "MOVDW"},  // float64 -> int32
		{name: "MOVFWU", argLength: 1, reg: fpgp, asm: "MOVFW"}, // float32 -> uint32, set U bit in the instruction
		{name: "MOVDWU", argLength: 1, reg: fpgp, asm: "MOVDW"}, // float64 -> uint32, set U bit in the instruction
		{name: "MOVFD", argLength: 1, reg: fp11, asm: "MOVFD"},  // float32 -> float64
		{name: "MOVDF", argLength: 1, reg: fp11, asm: "MOVDF"},  // float64 -> float32

		// conditional instructions, for lowering shifts
		{name: "CMOVWHSconst", argLength: 2, reg: gp1flags1, asm: "MOVW", aux: "Int32", resultInArg0: true}, // replace arg0 w/ const if flags indicates HS, arg1=flags
		{name: "CMOVWLSconst", argLength: 2, reg: gp1flags1, asm: "MOVW", aux: "Int32", resultInArg0: true}, // replace arg0 w/ const if flags indicates LS, arg1=flags
		{name: "SRAcond", argLength: 3, reg: gp2flags1, asm: "SRA"},                                         // arg0 >> 31 if flags indicates HS, arg0 >> arg1 otherwise, signed shift, arg2=flags

		// function calls
		{name: "CALLstatic", argLength: 1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                                              // call static function aux.(*obj.LSym).  arg0=mem, auxint=argsize, returns mem
		{name: "CALLtail", argLength: 1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true, tailCall: true},                                // tail call static function aux.(*obj.LSym).  arg0=mem, auxint=argsize, returns mem
		{name: "CALLclosure", argLength: 3, reg: regInfo{inputs: []regMask{gpsp, buildReg("R7"), 0}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true}, // call function via closure.  arg0=codeptr, arg1=closure, arg2=mem, auxint=argsize, returns mem
		{name: "CALLinter", argLength: 2, reg: regInfo{inputs: []regMask{gp}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                        // call fn by pointer.  arg0=codeptr, arg1=mem, auxint=argsize, returns mem

		// pseudo-ops
		{name: "LoweredNilCheck", argLength: 2, reg: regInfo{inputs: []regMask{gpg}}, nilCheck: true, faultOnNilArg0: true}, // panic if arg0 is nil.  arg1=mem.

		{name: "Equal", argLength: 1, reg: readflags},         // bool, true flags encode x==y false otherwise.
		{name: "NotEqual", argLength: 1, reg: readflags},      // bool, true flags encode x!=y false otherwise.
		{name: "LessThan", argLength: 1, reg: readflags},      // bool, true flags encode signed x<y false otherwise.
		{name: "LessEqual", argLength: 1, reg: readflags},     // bool, true flags encode signed x<=y false otherwise.
		{name: "GreaterThan", argLength: 1, reg: readflags},   // bool, true flags encode signed x>y false otherwise.
		{name: "GreaterEqual", argLength: 1, reg: readflags},  // bool, true flags encode signed x>=y false otherwise.
		{name: "LessThanU", argLength: 1, reg: readflags},     // bool, true flags encode unsigned x<y false otherwise.
		{name: "LessEqualU", argLength: 1, reg: readflags},    // bool, true flags encode unsigned x<=y false otherwise.
		{name: "GreaterThanU", argLength: 1, reg: readflags},  // bool, true flags encode unsigned x>y false otherwise.
		{name: "GreaterEqualU", argLength: 1, reg: readflags}, // bool, true flags encode unsigned x>=y false otherwise.

		// duffzero (must be 4-byte aligned)
		// arg0 = address of memory to zero (in R1, changed as side effect)
		// arg1 = value to store (always zero)
		// arg2 = mem
		// auxint = offset into duffzero code to start executing
		// returns mem
		{
			name:      "DUFFZERO",
			aux:       "Int64",
			argLength: 3,
			reg: regInfo{
				inputs:   []regMask{buildReg("R1"), buildReg("R0")},
				clobbers: buildReg("R1 R12 R14"), // R14 is LR, R12 is linker trampoline scratch register
			},
			faultOnNilArg0: true,
		},

		// duffcopy (must be 4-byte aligned)
		// arg0 = address of dst memory (in R2, changed as side effect)
		// arg1 = address of src memory (in R1, changed as side effect)
		// arg2 = mem
		// auxint = offset into duffcopy code to start executing
		// returns mem
		{
			name:      "DUFFCOPY",
			aux:       "Int64",
			argLength: 3,
			reg: regInfo{
				inputs:   []regMask{buildReg("R2"), buildReg("R1")},
				clobbers: buildReg("R0 R1 R2 R12 R14"), // R14 is LR, R12 is linker trampoline scratch register
			},
			faultOnNilArg0: true,
			faultOnNilArg1: true,
		},

		// large or unaligned zeroing
		// arg0 = address of memory to zero (in R1, changed as side effect)
		// arg1 = address of the last element to zero
		// arg2 = value to store (always zero)
		// arg3 = mem
		// returns mem
		//	MOVW.P	Rarg2, 4(R1)
		//	CMP	R1, Rarg1
		//	BLE	-2(PC)
		{
			name:      "LoweredZero",
			aux:       "Int64",
			argLength: 4,
			reg: regInfo{
				inputs:   []regMask{buildReg("R1"), gp, gp},
				clobbers: buildReg("R1"),
			},
			clobberFlags:   true,
			faultOnNilArg0: true,
		},

		// large or unaligned move
		// arg0 = address of dst memory (in R2, changed as side effect)
		// arg1 = address of src memory (in R1, changed as side effect)
		// arg2 = address of the last element of src
		// arg3 = mem
		// returns mem
		//	MOVW.P	4(R1), Rtmp
		//	MOVW.P	Rtmp, 4(R2)
		//	CMP	R1, Rarg2
		//	BLE	-3(PC)
		{
			name:      "LoweredMove",
			aux:       "Int64",
			argLength: 4,
			reg: regInfo{
				inputs:   []regMask{buildReg("R2"), buildReg("R1"), gp},
				clobbers: buildReg("R1 R2"),
			},
			clobberFlags:   true,
			faultOnNilArg0: true,
			faultOnNilArg1: true,
		},

		// Scheduler ensures LoweredGetClosurePtr occurs only in entry block,
		// and sorts it to the very beginning of the block to prevent other
		// use of R7 (arm.REGCTXT, the closure pointer)
		{name: "LoweredGetClosurePtr", reg: regInfo{outputs: []regMask{buildReg("R7")}}, zeroWidth: true},

		// LoweredGetCallerSP returns the SP of the caller of the current function. arg0=mem.
		{name: "LoweredGetCallerSP", argLength: 1, reg: gp01, rematerializeable: true},

		// LoweredGetCallerPC evaluates to the PC to which its "caller" will return.
		// I.e., if f calls g "calls" sys.GetCallerPC,
		// the result should be the PC within f that g will return to.
		// See runtime/stubs.go for a more detailed discussion.
		{name: "LoweredGetCallerPC", reg: gp01, rematerializeable: true},

		// There are three of these functions so that they can have three different register inputs.
		// When we check 0 <= c <= cap (A), then 0 <= b <= c (B), then 0 <= a <= b (C), we want the
		// default registers to match so we don't need to copy registers around unnecessarily.
		{name: "LoweredPanicBoundsA", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r2, r3}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in genericOps.go).
		{name: "LoweredPanicBoundsB", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r1, r2}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in genericOps.go).
		{name: "LoweredPanicBoundsC", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r0, r1}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in genericOps.go).
		// Extend ops are the same as Bounds ops except the indexes are 64-bit.
		{name: "LoweredPanicExtendA", argLength: 4, aux: "Int64", reg: regInfo{inputs: []regMask{r4, r2, r3}}, typ: "Mem", call: true}, // arg0=idxHi, arg1=idxLo, arg2=len, arg3=mem, returns memory. AuxInt contains report code (see PanicExtend in genericOps.go).
		{name: "LoweredPanicExtendB", argLength: 4, aux: "Int64", reg: regInfo{inputs: []regMask{r4, r1, r2}}, typ: "Mem", call: true}, // arg0=idxHi, arg1=idxLo, arg2=len, arg3=mem, returns memory. AuxInt contains report code (see PanicExtend in genericOps.go).
		{name: "LoweredPanicExtendC", argLength: 4, aux: "Int64", reg: regInfo{inputs: []regMask{r4, r0, r1}}, typ: "Mem", call: true}, // arg0=idxHi, arg1=idxLo, arg2=len, arg3=mem, returns memory. AuxInt contains report code (see PanicExtend in genericOps.go).

		// Constant flag value.
		// Note: there's an "unordered" outcome for floating-point
		// comparisons, but we don't use such a beast yet.
		// This op is for temporary use by rewrite rules. It
		// cannot appear in the generated assembly.
		{name: "FlagConstant", aux: "FlagConstant"},

		// (InvertFlags (CMP a b)) == (CMP b a)
		// InvertFlags is a pseudo-op which can't appear in assembly output.
		{name: "InvertFlags", argLength: 1}, // reverse direction of arg0

		// LoweredWB invokes runtime.gcWriteBarrier. arg0=mem, auxint=# of buffer entries needed
		// It saves all GP registers if necessary,
		// but clobbers R14 (LR) because it's a call, and R12 which is linker trampoline scratch register.
		// Returns a pointer to a write barrier buffer in R8.
		{name: "LoweredWB", argLength: 1, reg: regInfo{clobbers: (callerSave &^ gpg) | buildReg("R12 R14"), outputs: []regMask{buildReg("R8")}}, clobberFlags: true, aux: "Int64"}}

	blocks := []blockData{
		{name: "EQ", controls: 1},
		{name: "NE", controls: 1},
		{name: "LT", controls: 1},
		{name: "LE", controls: 1},
		{name: "GT", controls: 1},
		{name: "GE", controls: 1},
		{name: "ULT", controls: 1},
		{name: "ULE", controls: 1},
		{name: "UGT", controls: 1},
		{name: "UGE", controls: 1},
		{name: "LTnoov", controls: 1}, // 'LT' but without honoring overflow
		{name: "LEnoov", controls: 1}, // 'LE' but without honoring overflow
		{name: "GTnoov", controls: 1}, // 'GT' but without honoring overflow
		{name: "GEnoov", controls: 1}, // 'GE' but without honoring overflow
	}

	archs = append(archs, arch{
		name:            "ARM",
		pkg:             "cmd/internal/obj/arm",
		genfile:         "../../arm/ssa.go",
		ops:             ops,
		blocks:          blocks,
		regnames:        regNamesARM,
		gpregmask:       gp,
		fpregmask:       fp,
		framepointerreg: -1, // not used
		linkreg:         int8(num["R14"]),
	})
}
```