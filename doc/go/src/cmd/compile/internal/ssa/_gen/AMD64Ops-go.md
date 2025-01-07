Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet, which is a part of the Go compiler for the AMD64 architecture. It wants a summary, examples, and identification of potential pitfalls.

2. **Initial Scan for High-Level Purpose:** I first quickly scan the code for keywords and overall structure. I see:
    * `package main` - It's an executable, but given the file path (`go/src/cmd/compile/internal/ssa/_gen/AMD64Ops.go`), it's clearly a tool for generating code within the compiler.
    * Comments like `"// Copyright ..."` and `"// copied from ../../amd64/reg.go"` - Standard Go file boilerplate and a hint about register definitions.
    * Variable declarations like `regNamesAMD64` and `AMD64ops`. The `AMD64ops` seems to be the core data structure.
    * The `init()` function suggests some setup is happening when the package is loaded.
    * Comments within `AMD64ops` like `// {ADD,SUB,MUL,DIV}Sx: floating-point arithmetic` - This strongly indicates it's defining the instruction set and properties for AMD64.

3. **Focus on the `AMD64ops` Variable:**  This array of `opData` structs seems to be the heart of the functionality. I examine the fields of `opData`:
    * `name`: The name of the operation (e.g., "ADDQ", "MOVSSload").
    * `argLength`: Number of arguments the operation takes.
    * `reg`: A `regInfo` struct, presumably describing register usage.
    * `asm`: The actual assembly instruction.
    * `commutative`: Whether the operation is commutative.
    * `resultInArg0`:  Whether the result is stored in the first argument.
    * `aux`:  Indicates use of the `AuxInt` field (immediate values, symbols, etc.).
    * `scale`: Scaling factor for indexed memory access.
    * `typ`:  The type of the result or memory location.
    * `clobberFlags`: Whether the operation modifies CPU flags.
    * `faultOnNilArg0`: Indicates a potential memory access fault.
    * `symEffect`:  Indicates whether the operation reads or writes memory associated with a symbol.
    * `rematerializeable`: Whether the operation's result can be easily recomputed.
    * `needIntTemp`: Suggests the need for temporary registers during code generation.

4. **Infer Functionality from `opData`:** Based on the fields in `opData`, I can deduce that this code defines:
    * **A representation of the AMD64 instruction set** used by the Go compiler's SSA (Static Single Assignment) backend.
    * **Properties of each instruction**, such as the number of operands, register constraints, assembly mnemonic, commutativity, and side effects (like modifying flags or accessing memory).
    * **Information needed for instruction selection and register allocation** during the compilation process.

5. **Consider the `init()` Function:**  This function builds helper data structures:
    * `regNamesAMD64`: Defines the names of AMD64 registers.
    * The `buildReg` function and the subsequent variable assignments (like `ax`, `gp`, `fp`) create `regMask` values, which are bitmasks representing sets of registers. This allows for concisely specifying register constraints for instructions.
    * The `regInfo` structs define input and output register constraints for different instruction patterns.

6. **Address Specific Parts of the Request:**

    * **List the functionalities:**  My deduction above covers this. It's about defining the AMD64 instruction set for the Go compiler.
    * **What Go feature does it implement?** This is the most insightful part. It's the *low-level code generation* aspect of the Go compiler. It translates the intermediate representation (SSA) into machine instructions for the AMD64 architecture.
    * **Go code example:**  To illustrate the connection to Go, I need to show a simple Go program and explain how these definitions are used to compile it. A basic arithmetic operation is a good choice.
    * **Code reasoning (input/output):** For the example, the *input* is the Go source code, and the *output* (hypothetically) is the corresponding AMD64 assembly generated using the definitions in this file.
    * **Command-line arguments:** This file itself doesn't directly process command-line arguments. It's data used by the compiler.
    * **User errors:**  Since this is internal compiler code, typical users don't interact with it directly. However, *compiler developers* could make mistakes when adding or modifying instruction definitions. Incorrect register constraints or missing flags are potential issues.
    * **Summarize the functionality:**  Reiterate the core purpose: defining the AMD64 instruction set for the Go compiler's SSA backend.

7. **Structure the Answer:**  Organize the findings into the requested sections: Functionalities, Go Feature Implementation, Code Example, Command-line Arguments, User Errors, and Summary. Use clear language and code formatting.

8. **Refine and Review:** Read through the answer to ensure accuracy, clarity, and completeness. Make sure the Go code example and the explanation of how it relates to `AMD64Ops.go` are coherent.

By following these steps, I can systematically analyze the code and construct a comprehensive answer that addresses all aspects of the request. The key is to recognize the file's role within the larger Go compilation pipeline.
好的，让我们来分析一下 `go/src/cmd/compile/internal/ssa/_gen/AMD64Ops.go` 这个文件的功能。

**文件功能归纳**

这个 Go 源代码文件的主要功能是：

**定义了 AMD64 架构下 Go 编译器 SSA 中间表示层所支持的操作码 (Opcode) 及其相关属性。**

具体来说，它是一个**数据定义文件**，用于描述 AMD64 架构的各种指令，并为 Go 编译器的 SSA 后端提供关于这些指令的元数据。这些元数据包括：

* **指令名称 (name)**:  例如 "ADDQ", "MOVSSload" 等。
* **操作数的数量 (argLength)**: 指令需要多少个输入参数。
* **寄存器约束 (reg)**: 定义了指令对输入和输出寄存器的要求和影响。
* **汇编指令助记符 (asm)**:  与操作码对应的实际汇编指令字符串。
* **指令的属性**:
    * **commutative (是否可交换)**: 对于像加法和乘法这样的操作，操作数的顺序是否可以改变。
    * **resultInArg0 (结果是否在第一个参数中)**:  指示结果是否覆盖了第一个输入参数。
    * **aux (辅助信息类型)**:  指定了 `AuxInt` 字段的用途，例如表示常量值、符号偏移等。
    * **scale (缩放因子)**: 用于索引寻址的缩放值。
    * **typ (类型)**:  指令操作或返回的数据类型。
    * **clobberFlags (是否影响标志位)**:  指示指令是否会修改 CPU 的标志寄存器。
    * **faultOnNilArg0 (第一个参数为 nil 时是否会出错)**: 用于内存访问指令。
    * **symEffect (符号影响)**:  指示指令是否读写了符号地址。
    * **rematerializeable (是否可重新生成)**:  指示指令的结果是否容易重新计算，这对于优化很有用。
    * **needIntTemp (是否需要临时整数寄存器)**: 在代码生成过程中可能需要额外的寄存器。

**它是什么Go语言功能的实现**

这个文件是 Go 语言编译器中 **静态单赋值 (SSA) 中间表示** 的一部分，专门针对 **AMD64 架构**。它定义了 SSA 到 AMD64 机器码转换过程中可以使用的底层操作。

简单来说，当 Go 编译器将 Go 源代码转换成机器码时，会经历多个阶段。其中一个重要阶段是将高级的 Go 代码转换为一种更接近机器码的中间表示形式，这就是 SSA。 `AMD64Ops.go` 文件就定义了 SSA 中间表示在 AMD64 架构上的具体操作。

**Go 代码举例说明**

假设我们有以下简单的 Go 代码：

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	x := 10
	y := 20
	z := add(x, y)
	println(z)
}
```

当 Go 编译器编译这个 `add` 函数时，它可能会在 SSA 中间表示阶段生成类似于以下的指令序列（这只是一个简化的概念性例子，实际的 SSA 会更复杂）：

```
v1 = LocalInt a
v2 = LocalInt b
v3 = ADDQ v1, v2  // 使用了 AMD64Ops.go 中定义的 ADDQ 操作
Ret v3
```

在这个例子中，`ADDQ` 就是 `AMD64Ops.go` 中定义的一个操作码，它表示 64 位整数的加法操作。编译器会根据 `AMD64Ops.go` 中 `ADDQ` 的定义，知道它需要两个寄存器作为输入，执行加法运算，并将结果存储在一个寄存器中。

**代码推理（带假设的输入与输出）**

假设在 SSA 中间表示中，我们有一个加法操作：

**输入 (SSA 指令):**

```
op:      OpAMD64ADDQ
args[0]: (R1, int64)  // 假设变量 a 位于寄存器 R1
args[1]: (R2, int64)  // 假设变量 b 位于寄存器 R2
```

**`AMD64Ops.go` 中 `ADDQ` 的定义 (部分):**

```go
{name: "ADDQ", argLength: 2, reg: gp21sp, asm: "ADDQ", commutative: true, clobberFlags: true},
```

**推理过程:**

1. 编译器识别到 SSA 操作码是 `OpAMD64ADDQ`，它对应着 `AMD64Ops.go` 中的 `"ADDQ"` 定义。
2. 根据 `argLength: 2`，编译器知道这个操作需要两个参数。
3. 根据 `reg: gp21sp`，编译器知道输入和输出寄存器都需要是通用寄存器 (gp)，并且输出会覆盖第一个输入寄存器。 `sp` 部分可能暗示栈指针也可能参与。
4. 根据 `asm: "ADDQ"`，编译器知道需要生成的汇编指令是 `ADDQ`。
5. 根据 `commutative: true`，编译器知道操作数的顺序可以互换（虽然在这个例子中已经指定了顺序）。
6. 根据 `clobberFlags: true`，编译器知道这个操作会修改 CPU 的标志寄存器。

**输出 (假设生成的 AMD64 汇编指令):**

```assembly
ADDQ R2, R1  // 将 R2 的值加到 R1，结果存储在 R1 中
```

**命令行参数的具体处理**

`AMD64Ops.go` 文件本身并不直接处理命令行参数。它是一个数据定义文件，被 Go 编译器内部的代码使用。Go 编译器的命令行参数处理逻辑位于 `go/src/cmd/compile` 目录下的其他文件中，例如 `go/src/cmd/compile/main.go`。

**使用者易犯错的点**

由于 `AMD64Ops.go` 是 Go 编译器内部的文件，普通的 Go 语言开发者不会直接修改它。然而，对于**Go 编译器的开发者**来说，在修改或添加操作码定义时，可能会犯以下错误：

* **寄存器约束定义错误**:  错误地指定了指令可以使用的寄存器，导致寄存器分配阶段出错或生成错误的汇编代码。例如，将一个需要特定寄存器的指令标记为可以使用任何通用寄存器。
* **指令属性设置错误**:  错误地标记了指令是否可交换、是否影响标志位等，可能导致编译器进行错误的优化或生成不正确的代码。
* **`AuxInt` 用途定义不当**:  对 `AuxInt` 的解释不一致，例如将其作为有符号数和无符号数混合使用，可能导致计算错误。
* **汇编指令助记符错误**:  拼写错误的汇编指令助记符会导致汇编器报错。
* **遗漏或错误的 `symEffect` 标记**: 可能导致编译器对内存访问的分析不准确，影响逃逸分析或垃圾回收。

**例如，假设一个编译器开发者错误地将 `SUBQ` (减法) 指令标记为 `commutative: true`：**

```go
// 错误示例
{name: "SUBQ", argLength: 2, reg: gp21, asm: "SUBQ", commutative: true, resultInArg0: true, clobberFlags: true},
```

这将导致编译器认为 `a - b` 和 `b - a` 是等价的，从而可能进行错误的优化，例如将 `x = a - b` 替换为 `x = -(b - a)`，这在某些情况下可能不是期望的行为。

**功能归纳**

总而言之，`go/src/cmd/compile/internal/ssa/_gen/AMD64Ops.go` 文件的主要功能是**为 Go 编译器在 AMD64 架构上进行代码生成时，提供关于可用操作码的详尽描述和约束信息**。它是一个关键的数据定义文件，确保编译器能够正确地将 SSA 中间表示转换为 AMD64 汇编代码。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/_gen/AMD64Ops.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "strings"

// Notes:
//  - Integer types live in the low portion of registers. Upper portions are junk.
//  - Boolean types use the low-order byte of a register. 0=false, 1=true.
//    Upper bytes are junk.
//  - Floating-point types live in the low natural slot of an sse2 register.
//    Unused portions are junk.
//  - We do not use AH,BH,CH,DH registers.
//  - When doing sub-register operations, we try to write the whole
//    destination register to avoid a partial-register write.
//  - Unused portions of AuxInt (or the Val portion of ValAndOff) are
//    filled by sign-extending the used portion.  Users of AuxInt which interpret
//    AuxInt as unsigned (e.g. shifts) must be careful.
//  - All SymOff opcodes require their offset to fit in an int32.

// Suffixes encode the bit width of various instructions.
// Q (quad word) = 64 bit
// L (long word) = 32 bit
// W (word)      = 16 bit
// B (byte)      = 8 bit
// D (double)    = 64 bit float
// S (single)    = 32 bit float

// copied from ../../amd64/reg.go
var regNamesAMD64 = []string{
	"AX",
	"CX",
	"DX",
	"BX",
	"SP",
	"BP",
	"SI",
	"DI",
	"R8",
	"R9",
	"R10",
	"R11",
	"R12",
	"R13",
	"g", // a.k.a. R14
	"R15",
	"X0",
	"X1",
	"X2",
	"X3",
	"X4",
	"X5",
	"X6",
	"X7",
	"X8",
	"X9",
	"X10",
	"X11",
	"X12",
	"X13",
	"X14",
	"X15", // constant 0 in ABIInternal

	// If you add registers, update asyncPreempt in runtime

	// pseudo-registers
	"SB",
}

func init() {
	// Make map from reg names to reg integers.
	if len(regNamesAMD64) > 64 {
		panic("too many registers")
	}
	num := map[string]int{}
	for i, name := range regNamesAMD64 {
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
		ax         = buildReg("AX")
		cx         = buildReg("CX")
		dx         = buildReg("DX")
		bx         = buildReg("BX")
		gp         = buildReg("AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15")
		g          = buildReg("g")
		fp         = buildReg("X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14")
		x15        = buildReg("X15")
		gpsp       = gp | buildReg("SP")
		gpspsb     = gpsp | buildReg("SB")
		gpspsbg    = gpspsb | g
		callerSave = gp | fp | g // runtime.setg (and anything calling it) may clobber g
	)
	// Common slices of register masks
	var (
		gponly = []regMask{gp}
		fponly = []regMask{fp}
	)

	// Common regInfo
	var (
		gp01           = regInfo{inputs: nil, outputs: gponly}
		gp11           = regInfo{inputs: []regMask{gp}, outputs: gponly}
		gp11sp         = regInfo{inputs: []regMask{gpsp}, outputs: gponly}
		gp11sb         = regInfo{inputs: []regMask{gpspsbg}, outputs: gponly}
		gp21           = regInfo{inputs: []regMask{gp, gp}, outputs: gponly}
		gp21sp         = regInfo{inputs: []regMask{gpsp, gp}, outputs: gponly}
		gp21sb         = regInfo{inputs: []regMask{gpspsbg, gpsp}, outputs: gponly}
		gp21shift      = regInfo{inputs: []regMask{gp, cx}, outputs: []regMask{gp}}
		gp31shift      = regInfo{inputs: []regMask{gp, gp, cx}, outputs: []regMask{gp}}
		gp11div        = regInfo{inputs: []regMask{ax, gpsp &^ dx}, outputs: []regMask{ax, dx}}
		gp21hmul       = regInfo{inputs: []regMask{ax, gpsp}, outputs: []regMask{dx}, clobbers: ax}
		gp21flags      = regInfo{inputs: []regMask{gp, gp}, outputs: []regMask{gp, 0}}
		gp2flags1flags = regInfo{inputs: []regMask{gp, gp, 0}, outputs: []regMask{gp, 0}}

		gp2flags     = regInfo{inputs: []regMask{gpsp, gpsp}}
		gp1flags     = regInfo{inputs: []regMask{gpsp}}
		gp0flagsLoad = regInfo{inputs: []regMask{gpspsbg, 0}}
		gp1flagsLoad = regInfo{inputs: []regMask{gpspsbg, gpsp, 0}}
		gp2flagsLoad = regInfo{inputs: []regMask{gpspsbg, gpsp, gpsp, 0}}
		flagsgp      = regInfo{inputs: nil, outputs: gponly}

		gp11flags      = regInfo{inputs: []regMask{gp}, outputs: []regMask{gp, 0}}
		gp1flags1flags = regInfo{inputs: []regMask{gp, 0}, outputs: []regMask{gp, 0}}

		readflags = regInfo{inputs: nil, outputs: gponly}

		gpload         = regInfo{inputs: []regMask{gpspsbg, 0}, outputs: gponly}
		gp21load       = regInfo{inputs: []regMask{gp, gpspsbg, 0}, outputs: gponly}
		gploadidx      = regInfo{inputs: []regMask{gpspsbg, gpsp, 0}, outputs: gponly}
		gp21loadidx    = regInfo{inputs: []regMask{gp, gpspsbg, gpsp, 0}, outputs: gponly}
		gp21shxload    = regInfo{inputs: []regMask{gpspsbg, gp, 0}, outputs: gponly}
		gp21shxloadidx = regInfo{inputs: []regMask{gpspsbg, gpsp, gp, 0}, outputs: gponly}

		gpstore         = regInfo{inputs: []regMask{gpspsbg, gpsp, 0}}
		gpstoreconst    = regInfo{inputs: []regMask{gpspsbg, 0}}
		gpstoreidx      = regInfo{inputs: []regMask{gpspsbg, gpsp, gpsp, 0}}
		gpstoreconstidx = regInfo{inputs: []regMask{gpspsbg, gpsp, 0}}
		gpstorexchg     = regInfo{inputs: []regMask{gp, gpspsbg, 0}, outputs: []regMask{gp}}
		cmpxchg         = regInfo{inputs: []regMask{gp, ax, gp, 0}, outputs: []regMask{gp, 0}, clobbers: ax}
		atomicLogic     = regInfo{inputs: []regMask{gp &^ ax, gp &^ ax, 0}, outputs: []regMask{ax, 0}}

		fp01        = regInfo{inputs: nil, outputs: fponly}
		fp21        = regInfo{inputs: []regMask{fp, fp}, outputs: fponly}
		fp31        = regInfo{inputs: []regMask{fp, fp, fp}, outputs: fponly}
		fp21load    = regInfo{inputs: []regMask{fp, gpspsbg, 0}, outputs: fponly}
		fp21loadidx = regInfo{inputs: []regMask{fp, gpspsbg, gpspsb, 0}, outputs: fponly}
		fpgp        = regInfo{inputs: fponly, outputs: gponly}
		gpfp        = regInfo{inputs: gponly, outputs: fponly}
		fp11        = regInfo{inputs: fponly, outputs: fponly}
		fp2flags    = regInfo{inputs: []regMask{fp, fp}}

		fpload    = regInfo{inputs: []regMask{gpspsb, 0}, outputs: fponly}
		fploadidx = regInfo{inputs: []regMask{gpspsb, gpsp, 0}, outputs: fponly}

		fpstore    = regInfo{inputs: []regMask{gpspsb, fp, 0}}
		fpstoreidx = regInfo{inputs: []regMask{gpspsb, gpsp, fp, 0}}

		prefreg = regInfo{inputs: []regMask{gpspsbg}}
	)

	var AMD64ops = []opData{
		// {ADD,SUB,MUL,DIV}Sx: floating-point arithmetic
		// x==S for float32, x==D for float64
		// computes arg0 OP arg1
		{name: "ADDSS", argLength: 2, reg: fp21, asm: "ADDSS", commutative: true, resultInArg0: true},
		{name: "ADDSD", argLength: 2, reg: fp21, asm: "ADDSD", commutative: true, resultInArg0: true},
		{name: "SUBSS", argLength: 2, reg: fp21, asm: "SUBSS", resultInArg0: true},
		{name: "SUBSD", argLength: 2, reg: fp21, asm: "SUBSD", resultInArg0: true},
		{name: "MULSS", argLength: 2, reg: fp21, asm: "MULSS", commutative: true, resultInArg0: true},
		{name: "MULSD", argLength: 2, reg: fp21, asm: "MULSD", commutative: true, resultInArg0: true},
		{name: "DIVSS", argLength: 2, reg: fp21, asm: "DIVSS", resultInArg0: true},
		{name: "DIVSD", argLength: 2, reg: fp21, asm: "DIVSD", resultInArg0: true},

		// MOVSxload: floating-point loads
		// x==S for float32, x==D for float64
		// load from arg0+auxint+aux, arg1 = mem
		{name: "MOVSSload", argLength: 2, reg: fpload, asm: "MOVSS", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVSDload", argLength: 2, reg: fpload, asm: "MOVSD", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},

		// MOVSxconst: floatint-point constants
		// x==S for float32, x==D for float64
		{name: "MOVSSconst", reg: fp01, asm: "MOVSS", aux: "Float32", rematerializeable: true},
		{name: "MOVSDconst", reg: fp01, asm: "MOVSD", aux: "Float64", rematerializeable: true},

		// MOVSxloadidx: floating-point indexed loads
		// x==S for float32, x==D for float64
		// load from arg0 + scale*arg1+auxint+aux, arg2 = mem
		{name: "MOVSSloadidx1", argLength: 3, reg: fploadidx, asm: "MOVSS", scale: 1, aux: "SymOff", symEffect: "Read"},
		{name: "MOVSSloadidx4", argLength: 3, reg: fploadidx, asm: "MOVSS", scale: 4, aux: "SymOff", symEffect: "Read"},
		{name: "MOVSDloadidx1", argLength: 3, reg: fploadidx, asm: "MOVSD", scale: 1, aux: "SymOff", symEffect: "Read"},
		{name: "MOVSDloadidx8", argLength: 3, reg: fploadidx, asm: "MOVSD", scale: 8, aux: "SymOff", symEffect: "Read"},

		// MOVSxstore: floating-point stores
		// x==S for float32, x==D for float64
		// does *(arg0+auxint+aux) = arg1, arg2 = mem
		{name: "MOVSSstore", argLength: 3, reg: fpstore, asm: "MOVSS", aux: "SymOff", faultOnNilArg0: true, symEffect: "Write"},
		{name: "MOVSDstore", argLength: 3, reg: fpstore, asm: "MOVSD", aux: "SymOff", faultOnNilArg0: true, symEffect: "Write"},

		// MOVSxstoreidx: floating-point indexed stores
		// x==S for float32, x==D for float64
		// does *(arg0+scale*arg1+auxint+aux) = arg2, arg3 = mem
		{name: "MOVSSstoreidx1", argLength: 4, reg: fpstoreidx, asm: "MOVSS", scale: 1, aux: "SymOff", symEffect: "Write"},
		{name: "MOVSSstoreidx4", argLength: 4, reg: fpstoreidx, asm: "MOVSS", scale: 4, aux: "SymOff", symEffect: "Write"},
		{name: "MOVSDstoreidx1", argLength: 4, reg: fpstoreidx, asm: "MOVSD", scale: 1, aux: "SymOff", symEffect: "Write"},
		{name: "MOVSDstoreidx8", argLength: 4, reg: fpstoreidx, asm: "MOVSD", scale: 8, aux: "SymOff", symEffect: "Write"},

		// {ADD,SUB,MUL,DIV}Sxload: floating-point load / op combo
		// x==S for float32, x==D for float64
		// computes arg0 OP *(arg1+auxint+aux), arg2=mem
		{name: "ADDSSload", argLength: 3, reg: fp21load, asm: "ADDSS", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "ADDSDload", argLength: 3, reg: fp21load, asm: "ADDSD", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "SUBSSload", argLength: 3, reg: fp21load, asm: "SUBSS", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "SUBSDload", argLength: 3, reg: fp21load, asm: "SUBSD", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "MULSSload", argLength: 3, reg: fp21load, asm: "MULSS", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "MULSDload", argLength: 3, reg: fp21load, asm: "MULSD", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "DIVSSload", argLength: 3, reg: fp21load, asm: "DIVSS", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "DIVSDload", argLength: 3, reg: fp21load, asm: "DIVSD", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, symEffect: "Read"},

		// {ADD,SUB,MUL,DIV}Sxloadidx: floating-point indexed load / op combo
		// x==S for float32, x==D for float64
		// computes arg0 OP *(arg1+scale*arg2+auxint+aux), arg3=mem
		{name: "ADDSSloadidx1", argLength: 4, reg: fp21loadidx, asm: "ADDSS", scale: 1, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "ADDSSloadidx4", argLength: 4, reg: fp21loadidx, asm: "ADDSS", scale: 4, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "ADDSDloadidx1", argLength: 4, reg: fp21loadidx, asm: "ADDSD", scale: 1, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "ADDSDloadidx8", argLength: 4, reg: fp21loadidx, asm: "ADDSD", scale: 8, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "SUBSSloadidx1", argLength: 4, reg: fp21loadidx, asm: "SUBSS", scale: 1, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "SUBSSloadidx4", argLength: 4, reg: fp21loadidx, asm: "SUBSS", scale: 4, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "SUBSDloadidx1", argLength: 4, reg: fp21loadidx, asm: "SUBSD", scale: 1, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "SUBSDloadidx8", argLength: 4, reg: fp21loadidx, asm: "SUBSD", scale: 8, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "MULSSloadidx1", argLength: 4, reg: fp21loadidx, asm: "MULSS", scale: 1, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "MULSSloadidx4", argLength: 4, reg: fp21loadidx, asm: "MULSS", scale: 4, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "MULSDloadidx1", argLength: 4, reg: fp21loadidx, asm: "MULSD", scale: 1, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "MULSDloadidx8", argLength: 4, reg: fp21loadidx, asm: "MULSD", scale: 8, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "DIVSSloadidx1", argLength: 4, reg: fp21loadidx, asm: "DIVSS", scale: 1, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "DIVSSloadidx4", argLength: 4, reg: fp21loadidx, asm: "DIVSS", scale: 4, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "DIVSDloadidx1", argLength: 4, reg: fp21loadidx, asm: "DIVSD", scale: 1, aux: "SymOff", resultInArg0: true, symEffect: "Read"},
		{name: "DIVSDloadidx8", argLength: 4, reg: fp21loadidx, asm: "DIVSD", scale: 8, aux: "SymOff", resultInArg0: true, symEffect: "Read"},

		// {ADD,SUB,MUL,DIV,AND,OR,XOR}x: binary integer ops
		//   unadorned versions compute arg0 OP arg1
		//       const versions compute arg0 OP auxint (auxint is a sign-extended 32-bit value)
		// constmodify versions compute *(arg0+ValAndOff(AuxInt).Off().aux) OP= ValAndOff(AuxInt).Val(), arg1 = mem
		// x==L operations zero the upper 4 bytes of the destination register (not meaningful for constmodify versions).
		{name: "ADDQ", argLength: 2, reg: gp21sp, asm: "ADDQ", commutative: true, clobberFlags: true},
		{name: "ADDL", argLength: 2, reg: gp21sp, asm: "ADDL", commutative: true, clobberFlags: true},
		{name: "ADDQconst", argLength: 1, reg: gp11sp, asm: "ADDQ", aux: "Int32", typ: "UInt64", clobberFlags: true},
		{name: "ADDLconst", argLength: 1, reg: gp11sp, asm: "ADDL", aux: "Int32", clobberFlags: true},
		{name: "ADDQconstmodify", argLength: 2, reg: gpstoreconst, asm: "ADDQ", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "ADDLconstmodify", argLength: 2, reg: gpstoreconst, asm: "ADDL", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},

		{name: "SUBQ", argLength: 2, reg: gp21, asm: "SUBQ", resultInArg0: true, clobberFlags: true},
		{name: "SUBL", argLength: 2, reg: gp21, asm: "SUBL", resultInArg0: true, clobberFlags: true},
		{name: "SUBQconst", argLength: 1, reg: gp11, asm: "SUBQ", aux: "Int32", resultInArg0: true, clobberFlags: true},
		{name: "SUBLconst", argLength: 1, reg: gp11, asm: "SUBL", aux: "Int32", resultInArg0: true, clobberFlags: true},

		{name: "MULQ", argLength: 2, reg: gp21, asm: "IMULQ", commutative: true, resultInArg0: true, clobberFlags: true},
		{name: "MULL", argLength: 2, reg: gp21, asm: "IMULL", commutative: true, resultInArg0: true, clobberFlags: true},
		{name: "MULQconst", argLength: 1, reg: gp11, asm: "IMUL3Q", aux: "Int32", clobberFlags: true},
		{name: "MULLconst", argLength: 1, reg: gp11, asm: "IMUL3L", aux: "Int32", clobberFlags: true},

		// Let x = arg0*arg1 (full 32x32->64  unsigned multiply). Returns uint32(x), and flags set to overflow if uint32(x) != x.
		{name: "MULLU", argLength: 2, reg: regInfo{inputs: []regMask{ax, gpsp}, outputs: []regMask{ax, 0}, clobbers: dx}, typ: "(UInt32,Flags)", asm: "MULL", commutative: true, clobberFlags: true},
		// Let x = arg0*arg1 (full 64x64->128 unsigned multiply). Returns uint64(x), and flags set to overflow if uint64(x) != x.
		{name: "MULQU", argLength: 2, reg: regInfo{inputs: []regMask{ax, gpsp}, outputs: []regMask{ax, 0}, clobbers: dx}, typ: "(UInt64,Flags)", asm: "MULQ", commutative: true, clobberFlags: true},

		// HMULx[U]: computes the high bits of an integer multiply.
		// computes arg0 * arg1 >> (x==L?32:64)
		// The multiply is unsigned for the U versions, signed for the non-U versions.
		// HMULx[U] are intentionally not marked as commutative, even though they are.
		// This is because they have asymmetric register requirements.
		// There are rewrite rules to try to place arguments in preferable slots.
		{name: "HMULQ", argLength: 2, reg: gp21hmul, asm: "IMULQ", clobberFlags: true},
		{name: "HMULL", argLength: 2, reg: gp21hmul, asm: "IMULL", clobberFlags: true},
		{name: "HMULQU", argLength: 2, reg: gp21hmul, asm: "MULQ", clobberFlags: true},
		{name: "HMULLU", argLength: 2, reg: gp21hmul, asm: "MULL", clobberFlags: true},

		// (arg0 + arg1) / 2 as unsigned, all 64 result bits
		{name: "AVGQU", argLength: 2, reg: gp21, commutative: true, resultInArg0: true, clobberFlags: true},

		// DIVx[U] computes [arg0 / arg1, arg0 % arg1]
		// For signed versions, AuxInt non-zero means that the divisor has been proved to be not -1.
		{name: "DIVQ", argLength: 2, reg: gp11div, typ: "(Int64,Int64)", asm: "IDIVQ", aux: "Bool", clobberFlags: true},
		{name: "DIVL", argLength: 2, reg: gp11div, typ: "(Int32,Int32)", asm: "IDIVL", aux: "Bool", clobberFlags: true},
		{name: "DIVW", argLength: 2, reg: gp11div, typ: "(Int16,Int16)", asm: "IDIVW", aux: "Bool", clobberFlags: true},
		{name: "DIVQU", argLength: 2, reg: gp11div, typ: "(UInt64,UInt64)", asm: "DIVQ", clobberFlags: true},
		{name: "DIVLU", argLength: 2, reg: gp11div, typ: "(UInt32,UInt32)", asm: "DIVL", clobberFlags: true},
		{name: "DIVWU", argLength: 2, reg: gp11div, typ: "(UInt16,UInt16)", asm: "DIVW", clobberFlags: true},

		// computes -arg0, flags set for 0-arg0.
		{name: "NEGLflags", argLength: 1, reg: gp11flags, typ: "(UInt32,Flags)", asm: "NEGL", resultInArg0: true},

		// The following 4 add opcodes return the low 64 bits of the sum in the first result and
		// the carry (the 65th bit) in the carry flag.
		{name: "ADDQcarry", argLength: 2, reg: gp21flags, typ: "(UInt64,Flags)", asm: "ADDQ", commutative: true, resultInArg0: true}, // r = arg0+arg1
		{name: "ADCQ", argLength: 3, reg: gp2flags1flags, typ: "(UInt64,Flags)", asm: "ADCQ", commutative: true, resultInArg0: true}, // r = arg0+arg1+carry(arg2)
		{name: "ADDQconstcarry", argLength: 1, reg: gp11flags, typ: "(UInt64,Flags)", asm: "ADDQ", aux: "Int32", resultInArg0: true}, // r = arg0+auxint
		{name: "ADCQconst", argLength: 2, reg: gp1flags1flags, typ: "(UInt64,Flags)", asm: "ADCQ", aux: "Int32", resultInArg0: true}, // r = arg0+auxint+carry(arg1)

		// The following 4 add opcodes return the low 64 bits of the difference in the first result and
		// the borrow (if the result is negative) in the carry flag.
		{name: "SUBQborrow", argLength: 2, reg: gp21flags, typ: "(UInt64,Flags)", asm: "SUBQ", resultInArg0: true},                    // r = arg0-arg1
		{name: "SBBQ", argLength: 3, reg: gp2flags1flags, typ: "(UInt64,Flags)", asm: "SBBQ", resultInArg0: true},                     // r = arg0-(arg1+carry(arg2))
		{name: "SUBQconstborrow", argLength: 1, reg: gp11flags, typ: "(UInt64,Flags)", asm: "SUBQ", aux: "Int32", resultInArg0: true}, // r = arg0-auxint
		{name: "SBBQconst", argLength: 2, reg: gp1flags1flags, typ: "(UInt64,Flags)", asm: "SBBQ", aux: "Int32", resultInArg0: true},  // r = arg0-(auxint+carry(arg1))

		{name: "MULQU2", argLength: 2, reg: regInfo{inputs: []regMask{ax, gpsp}, outputs: []regMask{dx, ax}}, commutative: true, asm: "MULQ", clobberFlags: true}, // arg0 * arg1, returns (hi, lo)
		{name: "DIVQU2", argLength: 3, reg: regInfo{inputs: []regMask{dx, ax, gpsp}, outputs: []regMask{ax, dx}}, asm: "DIVQ", clobberFlags: true},                // arg0:arg1 / arg2 (128-bit divided by 64-bit), returns (q, r)

		{name: "ANDQ", argLength: 2, reg: gp21, asm: "ANDQ", commutative: true, resultInArg0: true, clobberFlags: true},                                                 // arg0 & arg1
		{name: "ANDL", argLength: 2, reg: gp21, asm: "ANDL", commutative: true, resultInArg0: true, clobberFlags: true},                                                 // arg0 & arg1
		{name: "ANDQconst", argLength: 1, reg: gp11, asm: "ANDQ", aux: "Int32", resultInArg0: true, clobberFlags: true},                                                 // arg0 & auxint
		{name: "ANDLconst", argLength: 1, reg: gp11, asm: "ANDL", aux: "Int32", resultInArg0: true, clobberFlags: true},                                                 // arg0 & auxint
		{name: "ANDQconstmodify", argLength: 2, reg: gpstoreconst, asm: "ANDQ", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"}, // and ValAndOff(AuxInt).Val() to arg0+ValAndOff(AuxInt).Off()+aux, arg1=mem
		{name: "ANDLconstmodify", argLength: 2, reg: gpstoreconst, asm: "ANDL", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"}, // and ValAndOff(AuxInt).Val() to arg0+ValAndOff(AuxInt).Off()+aux, arg1=mem

		{name: "ORQ", argLength: 2, reg: gp21, asm: "ORQ", commutative: true, resultInArg0: true, clobberFlags: true},                                                 // arg0 | arg1
		{name: "ORL", argLength: 2, reg: gp21, asm: "ORL", commutative: true, resultInArg0: true, clobberFlags: true},                                                 // arg0 | arg1
		{name: "ORQconst", argLength: 1, reg: gp11, asm: "ORQ", aux: "Int32", resultInArg0: true, clobberFlags: true},                                                 // arg0 | auxint
		{name: "ORLconst", argLength: 1, reg: gp11, asm: "ORL", aux: "Int32", resultInArg0: true, clobberFlags: true},                                                 // arg0 | auxint
		{name: "ORQconstmodify", argLength: 2, reg: gpstoreconst, asm: "ORQ", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"}, // or ValAndOff(AuxInt).Val() to arg0+ValAndOff(AuxInt).Off()+aux, arg1=mem
		{name: "ORLconstmodify", argLength: 2, reg: gpstoreconst, asm: "ORL", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"}, // or ValAndOff(AuxInt).Val() to arg0+ValAndOff(AuxInt).Off()+aux, arg1=mem

		{name: "XORQ", argLength: 2, reg: gp21, asm: "XORQ", commutative: true, resultInArg0: true, clobberFlags: true},                                                 // arg0 ^ arg1
		{name: "XORL", argLength: 2, reg: gp21, asm: "XORL", commutative: true, resultInArg0: true, clobberFlags: true},                                                 // arg0 ^ arg1
		{name: "XORQconst", argLength: 1, reg: gp11, asm: "XORQ", aux: "Int32", resultInArg0: true, clobberFlags: true},                                                 // arg0 ^ auxint
		{name: "XORLconst", argLength: 1, reg: gp11, asm: "XORL", aux: "Int32", resultInArg0: true, clobberFlags: true},                                                 // arg0 ^ auxint
		{name: "XORQconstmodify", argLength: 2, reg: gpstoreconst, asm: "XORQ", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"}, // xor ValAndOff(AuxInt).Val() to arg0+ValAndOff(AuxInt).Off()+aux, arg1=mem
		{name: "XORLconstmodify", argLength: 2, reg: gpstoreconst, asm: "XORL", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"}, // xor ValAndOff(AuxInt).Val() to arg0+ValAndOff(AuxInt).Off()+aux, arg1=mem

		// CMPx: compare arg0 to arg1.
		{name: "CMPQ", argLength: 2, reg: gp2flags, asm: "CMPQ", typ: "Flags"},
		{name: "CMPL", argLength: 2, reg: gp2flags, asm: "CMPL", typ: "Flags"},
		{name: "CMPW", argLength: 2, reg: gp2flags, asm: "CMPW", typ: "Flags"},
		{name: "CMPB", argLength: 2, reg: gp2flags, asm: "CMPB", typ: "Flags"},

		// CMPxconst: compare arg0 to auxint.
		{name: "CMPQconst", argLength: 1, reg: gp1flags, asm: "CMPQ", typ: "Flags", aux: "Int32"},
		{name: "CMPLconst", argLength: 1, reg: gp1flags, asm: "CMPL", typ: "Flags", aux: "Int32"},
		{name: "CMPWconst", argLength: 1, reg: gp1flags, asm: "CMPW", typ: "Flags", aux: "Int16"},
		{name: "CMPBconst", argLength: 1, reg: gp1flags, asm: "CMPB", typ: "Flags", aux: "Int8"},

		// CMPxload: compare *(arg0+auxint+aux) to arg1 (in that order). arg2=mem.
		{name: "CMPQload", argLength: 3, reg: gp1flagsLoad, asm: "CMPQ", aux: "SymOff", typ: "Flags", symEffect: "Read", faultOnNilArg0: true},
		{name: "CMPLload", argLength: 3, reg: gp1flagsLoad, asm: "CMPL", aux: "SymOff", typ: "Flags", symEffect: "Read", faultOnNilArg0: true},
		{name: "CMPWload", argLength: 3, reg: gp1flagsLoad, asm: "CMPW", aux: "SymOff", typ: "Flags", symEffect: "Read", faultOnNilArg0: true},
		{name: "CMPBload", argLength: 3, reg: gp1flagsLoad, asm: "CMPB", aux: "SymOff", typ: "Flags", symEffect: "Read", faultOnNilArg0: true},

		// CMPxconstload: compare *(arg0+ValAndOff(AuxInt).Off()+aux) to ValAndOff(AuxInt).Val() (in that order). arg1=mem.
		{name: "CMPQconstload", argLength: 2, reg: gp0flagsLoad, asm: "CMPQ", aux: "SymValAndOff", typ: "Flags", symEffect: "Read", faultOnNilArg0: true},
		{name: "CMPLconstload", argLength: 2, reg: gp0flagsLoad, asm: "CMPL", aux: "SymValAndOff", typ: "Flags", symEffect: "Read", faultOnNilArg0: true},
		{name: "CMPWconstload", argLength: 2, reg: gp0flagsLoad, asm: "CMPW", aux: "SymValAndOff", typ: "Flags", symEffect: "Read", faultOnNilArg0: true},
		{name: "CMPBconstload", argLength: 2, reg: gp0flagsLoad, asm: "CMPB", aux: "SymValAndOff", typ: "Flags", symEffect: "Read", faultOnNilArg0: true},

		// CMPxloadidx: compare *(arg0+N*arg1+auxint+aux) to arg2 (in that order). arg3=mem.
		{name: "CMPQloadidx8", argLength: 4, reg: gp2flagsLoad, asm: "CMPQ", scale: 8, aux: "SymOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPQloadidx1", argLength: 4, reg: gp2flagsLoad, asm: "CMPQ", scale: 1, commutative: true, aux: "SymOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPLloadidx4", argLength: 4, reg: gp2flagsLoad, asm: "CMPL", scale: 4, aux: "SymOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPLloadidx1", argLength: 4, reg: gp2flagsLoad, asm: "CMPL", scale: 1, commutative: true, aux: "SymOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPWloadidx2", argLength: 4, reg: gp2flagsLoad, asm: "CMPW", scale: 2, aux: "SymOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPWloadidx1", argLength: 4, reg: gp2flagsLoad, asm: "CMPW", scale: 1, commutative: true, aux: "SymOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPBloadidx1", argLength: 4, reg: gp2flagsLoad, asm: "CMPB", scale: 1, commutative: true, aux: "SymOff", typ: "Flags", symEffect: "Read"},

		// CMPxconstloadidx: compare *(arg0+N*arg1+ValAndOff(AuxInt).Off()+aux) to ValAndOff(AuxInt).Val() (in that order). arg2=mem.
		{name: "CMPQconstloadidx8", argLength: 3, reg: gp1flagsLoad, asm: "CMPQ", scale: 8, aux: "SymValAndOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPQconstloadidx1", argLength: 3, reg: gp1flagsLoad, asm: "CMPQ", scale: 1, commutative: true, aux: "SymValAndOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPLconstloadidx4", argLength: 3, reg: gp1flagsLoad, asm: "CMPL", scale: 4, aux: "SymValAndOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPLconstloadidx1", argLength: 3, reg: gp1flagsLoad, asm: "CMPL", scale: 1, commutative: true, aux: "SymValAndOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPWconstloadidx2", argLength: 3, reg: gp1flagsLoad, asm: "CMPW", scale: 2, aux: "SymValAndOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPWconstloadidx1", argLength: 3, reg: gp1flagsLoad, asm: "CMPW", scale: 1, commutative: true, aux: "SymValAndOff", typ: "Flags", symEffect: "Read"},
		{name: "CMPBconstloadidx1", argLength: 3, reg: gp1flagsLoad, asm: "CMPB", scale: 1, commutative: true, aux: "SymValAndOff", typ: "Flags", symEffect: "Read"},

		// UCOMISx: floating-point compare arg0 to arg1
		// x==S for float32, x==D for float64
		{name: "UCOMISS", argLength: 2, reg: fp2flags, asm: "UCOMISS", typ: "Flags"},
		{name: "UCOMISD", argLength: 2, reg: fp2flags, asm: "UCOMISD", typ: "Flags"},

		// bit test/set/clear operations
		{name: "BTL", argLength: 2, reg: gp2flags, asm: "BTL", typ: "Flags"},                                           // test whether bit arg0%32 in arg1 is set
		{name: "BTQ", argLength: 2, reg: gp2flags, asm: "BTQ", typ: "Flags"},                                           // test whether bit arg0%64 in arg1 is set
		{name: "BTCL", argLength: 2, reg: gp21, asm: "BTCL", resultInArg0: true, clobberFlags: true},                   // complement bit arg1%32 in arg0
		{name: "BTCQ", argLength: 2, reg: gp21, asm: "BTCQ", resultInArg0: true, clobberFlags: true},                   // complement bit arg1%64 in arg0
		{name: "BTRL", argLength: 2, reg: gp21, asm: "BTRL", resultInArg0: true, clobberFlags: true},                   // reset bit arg1%32 in arg0
		{name: "BTRQ", argLength: 2, reg: gp21, asm: "BTRQ", resultInArg0: true, clobberFlags: true},                   // reset bit arg1%64 in arg0
		{name: "BTSL", argLength: 2, reg: gp21, asm: "BTSL", resultInArg0: true, clobberFlags: true},                   // set bit arg1%32 in arg0
		{name: "BTSQ", argLength: 2, reg: gp21, asm: "BTSQ", resultInArg0: true, clobberFlags: true},                   // set bit arg1%64 in arg0
		{name: "BTLconst", argLength: 1, reg: gp1flags, asm: "BTL", typ: "Flags", aux: "Int8"},                         // test whether bit auxint in arg0 is set, 0 <= auxint < 32
		{name: "BTQconst", argLength: 1, reg: gp1flags, asm: "BTQ", typ: "Flags", aux: "Int8"},                         // test whether bit auxint in arg0 is set, 0 <= auxint < 64
		{name: "BTCQconst", argLength: 1, reg: gp11, asm: "BTCQ", resultInArg0: true, clobberFlags: true, aux: "Int8"}, // complement bit auxint in arg0, 31 <= auxint < 64
		{name: "BTRQconst", argLength: 1, reg: gp11, asm: "BTRQ", resultInArg0: true, clobberFlags: true, aux: "Int8"}, // reset bit auxint in arg0, 31 <= auxint < 64
		{name: "BTSQconst", argLength: 1, reg: gp11, asm: "BTSQ", resultInArg0: true, clobberFlags: true, aux: "Int8"}, // set bit auxint in arg0, 31 <= auxint < 64

		// BT[SRC]Qconstmodify
		//
		//  S: set bit
		//  R: reset (clear) bit
		//  C: complement bit
		//
		// Apply operation to bit ValAndOff(AuxInt).Val() in the 64 bits at
		// memory address arg0+ValAndOff(AuxInt).Off()+aux
		// Bit index must be in range (31-63).
		// (We use OR/AND/XOR for thinner targets and lower bit indexes.)
		// arg1=mem, returns mem
		//
		// Note that there aren't non-const versions of these instructions.
		// Well, there are such instructions, but they are slow and weird so we don't use them.
		{name: "BTSQconstmodify", argLength: 2, reg: gpstoreconst, asm: "BTSQ", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "BTRQconstmodify", argLength: 2, reg: gpstoreconst, asm: "BTRQ", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "BTCQconstmodify", argLength: 2, reg: gpstoreconst, asm: "BTCQ", aux: "SymValAndOff", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},

		// TESTx: compare (arg0 & arg1) to 0
		{name: "TESTQ", argLength: 2, reg: gp2flags, commutative: true, asm: "TESTQ", typ: "Flags"},
		{name: "TESTL", argLength: 2, reg: gp2flags, commutative: true, asm: "TESTL", typ: "Flags"},
		{name: "TESTW", argLength: 2, reg: gp2flags, commutative: true, asm: "TESTW", typ: "Flags"},
		{name: "TESTB", argLength: 2, reg: gp2flags, commutative: true, asm: "TESTB", typ: "Flags"},

		// TESTxconst: compare (arg0 & auxint) to 0
		{name: "TESTQconst", argLength: 1, reg: gp1flags, asm: "TESTQ", typ: "Flags", aux: "Int32"},
		{name: "TESTLconst", argLength: 1, reg: gp1flags, asm: "TESTL", typ: "Flags", aux: "Int32"},
		{name: "TESTWconst", argLength: 1, reg: gp1flags, asm: "TESTW", typ: "Flags", aux: "Int16"},
		{name: "TESTBconst", argLength: 1, reg: gp1flags, asm: "TESTB", typ: "Flags", aux: "Int8"},

		// S{HL, HR, AR}x: shift operations
		// SHL: shift left
		// SHR: shift right logical (0s are shifted in from beyond the word size)
		// SAR: shift right arithmetic (sign bit is shifted in from beyond the word size)
		// arg0 is the value being shifted
		// arg1 is the amount to shift, interpreted mod (Q=64,L=32,W=32,B=32)
		// (Note: x86 is weird, the 16 and 8 byte shifts still use all 5 bits of shift amount!)
		// For *const versions, use auxint instead of arg1 as the shift amount. auxint must be in the range 0 to (Q=63,L=31,W=15,B=7) inclusive.
		{name: "SHLQ", argLength: 2, reg: gp21shift, asm: "SHLQ", resultInArg0: true, clobberFlags: true},
		{name: "SHLL", argLength: 2, reg: gp21shift, asm: "SHLL", resultInArg0: true, clobberFlags: true},
		{name: "SHLQconst", argLength: 1, reg: gp11, asm: "SHLQ", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "SHLLconst", argLength: 1, reg: gp11, asm: "SHLL", aux: "Int8", resultInArg0: true, clobberFlags: true},

		{name: "SHRQ", argLength: 2, reg: gp21shift, asm: "SHRQ", resultInArg0: true, clobberFlags: true},
		{name: "SHRL", argLength: 2, reg: gp21shift, asm: "SHRL", resultInArg0: true, clobberFlags: true},
		{name: "SHRW", argLength: 2, reg: gp21shift, asm: "SHRW", resultInArg0: true, clobberFlags: true},
		{name: "SHRB", argLength: 2, reg: gp21shift, asm: "SHRB", resultInArg0: true, clobberFlags: true},
		{name: "SHRQconst", argLength: 1, reg: gp11, asm: "SHRQ", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "SHRLconst", argLength: 1, reg: gp11, asm: "SHRL", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "SHRWconst", argLength: 1, reg: gp11, asm: "SHRW", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "SHRBconst", argLength: 1, reg: gp11, asm: "SHRB", aux: "Int8", resultInArg0: true, clobberFlags: true},

		{name: "SARQ", argLength: 2, reg: gp21shift, asm: "SARQ", resultInArg0: true, clobberFlags: true},
		{name: "SARL", argLength: 2, reg: gp21shift, asm: "SARL", resultInArg0: true, clobberFlags: true},
		{name: "SARW", argLength: 2, reg: gp21shift, asm: "SARW", resultInArg0: true, clobberFlags: true},
		{name: "SARB", argLength: 2, reg: gp21shift, asm: "SARB", resultInArg0: true, clobberFlags: true},
		{name: "SARQconst", argLength: 1, reg: gp11, asm: "SARQ", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "SARLconst", argLength: 1, reg: gp11, asm: "SARL", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "SARWconst", argLength: 1, reg: gp11, asm: "SARW", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "SARBconst", argLength: 1, reg: gp11, asm: "SARB", aux: "Int8", resultInArg0: true, clobberFlags: true},

		// unsigned arg0 >> arg2, shifting in bits from arg1 (==(arg1<<64+arg0)>>arg2, keeping low 64 bits), shift amount is mod 64
		{name: "SHRDQ", argLength: 3, reg: gp31shift, asm: "SHRQ", resultInArg0: true, clobberFlags: true},
		// unsigned arg0 << arg2, shifting in bits from arg1 (==(arg0<<64+arg1)<<arg2, keeping high 64 bits), shift amount is mod 64
		{name: "SHLDQ", argLength: 3, reg: gp31shift, asm: "SHLQ", resultInArg0: true, clobberFlags: true},

		// RO{L,R}x: rotate instructions
		// computes arg0 rotate (L=left,R=right) arg1 bits.
		// Bits are rotated within the low (Q=64,L=32,W=16,B=8) bits of the register.
		// For *const versions use auxint instead of arg1 as the rotate amount. auxint must be in the range 0 to (Q=63,L=31,W=15,B=7) inclusive.
		// x==L versions zero the upper 32 bits of the destination register.
		// x==W and x==B versions leave the upper bits unspecified.
		{name: "ROLQ", argLength: 2, reg: gp21shift, asm: "ROLQ", resultInArg0: true, clobberFlags: true},
		{name: "ROLL", argLength: 2, reg: gp21shift, asm: "ROLL", resultInArg0: true, clobberFlags: true},
		{name: "ROLW", argLength: 2, reg: gp21shift, asm: "ROLW", resultInArg0: true, clobberFlags: true},
		{name: "ROLB", argLength: 2, reg: gp21shift, asm: "ROLB", resultInArg0: true, clobberFlags: true},
		{name: "RORQ", argLength: 2, reg: gp21shift, asm: "RORQ", resultInArg0: true, clobberFlags: true},
		{name: "RORL", argLength: 2, reg: gp21shift, asm: "RORL", resultInArg0: true, clobberFlags: true},
		{name: "RORW", argLength: 2, reg: gp21shift, asm: "RORW", resultInArg0: true, clobberFlags: true},
		{name: "RORB", argLength: 2, reg: gp21shift, asm: "RORB", resultInArg0: true, clobberFlags: true},
		{name: "ROLQconst", argLength: 1, reg: gp11, asm: "ROLQ", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "ROLLconst", argLength: 1, reg: gp11, asm: "ROLL", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "ROLWconst", argLength: 1, reg: gp11, asm: "ROLW", aux: "Int8", resultInArg0: true, clobberFlags: true},
		{name: "ROLBconst", argLength: 1, reg: gp11, asm: "ROLB", aux: "Int8", resultInArg0: true, clobberFlags: true},

		// [ADD,SUB,AND,OR]xload: integer load/op combo
		// L = int32, Q = int64
		// x==L operations zero the upper 4 bytes of the destination register.
		// computes arg0 op *(arg1+auxint+aux), arg2=mem
		{name: "ADDLload", argLength: 3, reg: gp21load, asm: "ADDL", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "ADDQload", argLength: 3, reg: gp21load, asm: "ADDQ", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "SUBQload", argLength: 3, reg: gp21load, asm: "SUBQ", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "SUBLload", argLength: 3, reg: gp21load, asm: "SUBL", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "ANDLload", argLength: 3, reg: gp21load, asm: "ANDL", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "ANDQload", argLength: 3, reg: gp21load, asm: "ANDQ", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "ORQload", argLength: 3, reg: gp21load, asm: "ORQ", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "ORLload", argLength: 3, reg: gp21load, asm: "ORL", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "XORQload", argLength: 3, reg: gp21load, asm: "XORQ", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},
		{name: "XORLload", argLength: 3, reg: gp21load, asm: "XORL", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, symEffect: "Read"},

		// integer indexed load/op combo
		// L = int32, Q = int64
		// L operations zero the upper 4 bytes of the destination register.
		// computes arg0 op *(arg1+scale*arg2+auxint+aux), arg3=mem
		{name: "ADDLloadidx1", argLength: 4, reg: gp21loadidx, asm: "ADDL", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ADDLloadidx4", argLength: 4, reg: gp21loadidx, asm: "ADDL", scale: 4, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ADDLloadidx8", argLength: 4, reg: gp21loadidx, asm: "ADDL", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ADDQloadidx1", argLength: 4, reg: gp21loadidx, asm: "ADDQ", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ADDQloadidx8", argLength: 4, reg: gp21loadidx, asm: "ADDQ", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "SUBLloadidx1", argLength: 4, reg: gp21loadidx, asm: "SUBL", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "SUBLloadidx4", argLength: 4, reg: gp21loadidx, asm: "SUBL", scale: 4, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "SUBLloadidx8", argLength: 4, reg: gp21loadidx, asm: "SUBL", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "SUBQloadidx1", argLength: 4, reg: gp21loadidx, asm: "SUBQ", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "SUBQloadidx8", argLength: 4, reg: gp21loadidx, asm: "SUBQ", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ANDLloadidx1", argLength: 4, reg: gp21loadidx, asm: "ANDL", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ANDLloadidx4", argLength: 4, reg: gp21loadidx, asm: "ANDL", scale: 4, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ANDLloadidx8", argLength: 4, reg: gp21loadidx, asm: "ANDL", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ANDQloadidx1", argLength: 4, reg: gp21loadidx, asm: "ANDQ", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ANDQloadidx8", argLength: 4, reg: gp21loadidx, asm: "ANDQ", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ORLloadidx1", argLength: 4, reg: gp21loadidx, asm: "ORL", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ORLloadidx4", argLength: 4, reg: gp21loadidx, asm: "ORL", scale: 4, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ORLloadidx8", argLength: 4, reg: gp21loadidx, asm: "ORL", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ORQloadidx1", argLength: 4, reg: gp21loadidx, asm: "ORQ", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "ORQloadidx8", argLength: 4, reg: gp21loadidx, asm: "ORQ", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "XORLloadidx1", argLength: 4, reg: gp21loadidx, asm: "XORL", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "XORLloadidx4", argLength: 4, reg: gp21loadidx, asm: "XORL", scale: 4, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "XORLloadidx8", argLength: 4, reg: gp21loadidx, asm: "XORL", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "XORQloadidx1", argLength: 4, reg: gp21loadidx, asm: "XORQ", scale: 1, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},
		{name: "XORQloadidx8", argLength: 4, reg: gp21loadidx, asm: "XORQ", scale: 8, aux: "SymOff", resultInArg0: true, clobberFlags: true, symEffect: "Read"},

		// direct binary op on memory (read-modify-write)
		// L = int32, Q = int64
		// does *(arg0+auxint+aux) op= arg1, arg2=mem
		{name: "ADDQmodify", argLength: 3, reg: gpstore, asm: "ADDQ", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "SUBQmodify", argLength: 3, reg: gpstore, asm: "SUBQ", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "ANDQmodify", argLength: 3, reg: gpstore, asm: "ANDQ", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "ORQmodify", argLength: 3, reg: gpstore, asm: "ORQ", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "XORQmodify", argLength: 3, reg: gpstore, asm: "XORQ", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "ADDLmodify", argLength: 3, reg: gpstore, asm: "ADDL", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "SUBLmodify", argLength: 3, reg: gpstore, asm: "SUBL", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "ANDLmodify", argLength: 3, reg: gpstore, asm: "ANDL", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "ORLmodify", argLength: 3, reg: gpstore, asm: "ORL", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},
		{name: "XORLmodify", argLength: 3, reg: gpstore, asm: "XORL", aux: "SymOff", typ: "Mem", clobberFlags: true, faultOnNilArg0: true, symEffect: "Read,Write"},

		// indexed direct binary op on memory.
		// does *(arg0+scale*arg1+auxint+aux) op= arg2, arg3=mem
		{name: "ADDQmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "ADDQ", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ADDQmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "ADDQ", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "SUBQmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "SUBQ", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "SUBQmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "SUBQ", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDQmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "ANDQ", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDQmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "ANDQ", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORQmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "ORQ", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORQmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "ORQ", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORQmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "XORQ", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORQmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "XORQ", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ADDLmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "ADDL", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ADDLmodifyidx4", argLength: 4, reg: gpstoreidx, asm: "ADDL", scale: 4, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ADDLmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "ADDL", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "SUBLmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "SUBL", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "SUBLmodifyidx4", argLength: 4, reg: gpstoreidx, asm: "SUBL", scale: 4, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "SUBLmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "SUBL", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDLmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "ANDL", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDLmodifyidx4", argLength: 4, reg: gpstoreidx, asm: "ANDL", scale: 4, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDLmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "ANDL", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORLmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "ORL", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORLmodifyidx4", argLength: 4, reg: gpstoreidx, asm: "ORL", scale: 4, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORLmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "ORL", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORLmodifyidx1", argLength: 4, reg: gpstoreidx, asm: "XORL", scale: 1, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORLmodifyidx4", argLength: 4, reg: gpstoreidx, asm: "XORL", scale: 4, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORLmodifyidx8", argLength: 4, reg: gpstoreidx, asm: "XORL", scale: 8, aux: "SymOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},

		// indexed direct binary op on memory with constant argument.
		// does *(arg0+scale*arg1+ValAndOff(AuxInt).Off()+aux) op= ValAndOff(AuxInt).Val(), arg2=mem
		{name: "ADDQconstmodifyidx1", argLength: 3, reg: gpstoreconstidx, asm: "ADDQ", scale: 1, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ADDQconstmodifyidx8", argLength: 3, reg: gpstoreconstidx, asm: "ADDQ", scale: 8, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDQconstmodifyidx1", argLength: 3, reg: gpstoreconstidx, asm: "ANDQ", scale: 1, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDQconstmodifyidx8", argLength: 3, reg: gpstoreconstidx, asm: "ANDQ", scale: 8, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORQconstmodifyidx1", argLength: 3, reg: gpstoreconstidx, asm: "ORQ", scale: 1, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORQconstmodifyidx8", argLength: 3, reg: gpstoreconstidx, asm: "ORQ", scale: 8, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORQconstmodifyidx1", argLength: 3, reg: gpstoreconstidx, asm: "XORQ", scale: 1, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORQconstmodifyidx8", argLength: 3, reg: gpstoreconstidx, asm: "XORQ", scale: 8, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ADDLconstmodifyidx1", argLength: 3, reg: gpstoreconstidx, asm: "ADDL", scale: 1, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ADDLconstmodifyidx4", argLength: 3, reg: gpstoreconstidx, asm: "ADDL", scale: 4, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ADDLconstmodifyidx8", argLength: 3, reg: gpstoreconstidx, asm: "ADDL", scale: 8, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDLconstmodifyidx1", argLength: 3, reg: gpstoreconstidx, asm: "ANDL", scale: 1, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDLconstmodifyidx4", argLength: 3, reg: gpstoreconstidx, asm: "ANDL", scale: 4, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ANDLconstmodifyidx8", argLength: 3, reg: gpstoreconstidx, asm: "ANDL", scale: 8, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORLconstmodifyidx1", argLength: 3, reg: gpstoreconstidx, asm: "ORL", scale: 1, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORLconstmodifyidx4", argLength: 3, reg: gpstoreconstidx, asm: "ORL", scale: 4, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "ORLconstmodifyidx8", argLength: 3, reg: gpstoreconstidx, asm: "ORL", scale: 8, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORLconstmodifyidx1", argLength: 3, reg: gpstoreconstidx, asm: "XORL", scale: 1, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORLconstmodifyidx4", argLength: 3, reg: gpstoreconstidx, asm: "XORL", scale: 4, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},
		{name: "XORLconstmodifyidx8", argLength: 3, reg: gpstoreconstidx, asm: "XORL", scale: 8, aux: "SymValAndOff", typ: "Mem", clobberFlags: true, symEffect: "Read,Write"},

		// {NEG,NOT}x: unary ops
		// computes [NEG:-,NOT:^]arg0
		// L = int32, Q = int64
		// L operations zero the upper 4 bytes of the destination register.
		{name: "NEGQ", argLength: 1, reg: gp11, asm: "NEGQ", resultInArg0: true, clobberFlags: true},
		{name: "NEGL", argLength: 1, reg: gp11, asm: "NEGL", resultInArg0: true, clobberFlags: true},
		{name: "NOTQ", argLength: 1, reg: gp11, asm: "NOTQ", resultInArg0: true},
		{name: "NOTL", argLength: 1, reg: gp11, asm: "NOTL", resultInArg0: true},

		// BS{F,R}Q returns a tuple [result, flags]
		// result is undefined if the input is zero.
		// flags are set to "equal" if the input is zero, "not equal" otherwise.
		// BS{F,R}L returns only the result.
		{name: "BSFQ", argLength: 1, reg: gp11flags, asm: "BSFQ", typ: "(UInt64,Flags)"},        // # of low-order zeroes in 64-bit arg
		{name: "BSFL", argLength: 1, reg: gp11, asm: "BSFL", typ: "UInt32", clobberFlags: true}, // # of low-order zeroes in 32-bit arg
		{name: "BSRQ", argLength: 1, reg: gp11flags, asm: "BSRQ", typ: "(UInt64,Flags)"},        // # of high-order zeroes in 64-bit arg
		{name: "BSRL", argLength: 1, reg: gp11, asm: "BSRL", typ: "UInt32", clobberFlags: true}, // # of high-order zeroes in 32-bit arg

		// CMOV instructions: 64, 32 and 16-bit sizes.
		// if arg2 encodes a true result, return arg1, else arg0
		{name: "CMOVQEQ", argLength: 3, reg: gp21, asm: "CMOVQEQ", resultInArg0: true},
		{name: "CMOVQNE", argLength: 3, reg: gp21, asm: "CMOVQNE", resultInArg0: true},
		{name: "CMOVQLT", argLength: 3, reg: gp21, asm: "CMOVQLT", resultInArg0: true},
		{name: "CMOVQGT", argLength: 3, reg: gp21, asm: "CMOVQGT", resultInArg0: true},
		{name: "CMOVQLE", argLength: 3, reg: gp21, asm: "CMOVQLE", resultInArg0: true},
		{name: "CMOVQGE", argLength: 3, reg: gp21, asm: "CMOVQGE", resultInArg0: true},
		{name: "CMOVQLS", argLength: 3, reg: gp21, asm: "CMOVQLS", resultInArg0: true},
		{name: "CMOVQHI", argLength: 3, reg: gp21, asm: "CMOVQHI", resultInArg0: true},
		{name: "CMOVQCC", argLength: 3, reg: gp21, asm: "CMOVQCC", resultInArg0: true},
		{name: "CMOVQCS", argLength: 3, reg: gp21, asm: "CMOVQCS", resultInArg0: true},

		{name: "CMOVLEQ", argLength: 3, reg: gp21, asm: "CMOVLEQ", resultInArg0: true},
		{name: "CMOVLNE", argLength: 3, reg: gp21, asm: "CMOVLNE", resultInArg0: true},
		{name: "CMOVLLT", argLength: 3, reg: gp21, asm: "CMOVLLT", resultInArg0: true},
		{name: "CMOVLGT", argLength: 3, reg: gp21, asm: "CMOVLGT", resultInArg0: true},
		{name: "CMOVLLE", argLength: 3, reg: gp21, asm: "CMOVLLE", resultInArg0: true},
		{name: "CMOVLGE", argLength: 3, reg: gp21, asm: "CMOVLGE", resultInArg0: true},
		{name: "CMOVLLS", argLength: 3, reg: gp21, asm: "CMOVLLS", resultInArg0: true},
		{name: "CMOVLHI", argLength: 3, reg: gp21, asm: "CMOVLHI", resultInArg0: true},
		{name: "CMOVLCC", argLength: 3, reg: gp21, asm: "CMOVLCC", resultInArg0: true},
		{name: "CMOVLCS", argLength: 3, reg: gp21, asm: "CMOVLCS", resultInArg0: true},

		{name: "CMOVWEQ", argLength: 3, reg: gp21, asm: "CMOVWEQ", resultInArg0: true},
		{name: "CMOVWNE", argLength: 3, reg: gp21, asm: "CMOVWNE", resultInArg0: true},
		{name: "CMOVWLT", argLength: 3, reg: gp21, asm: "CMOVWLT", resultInArg0: true},
		{name: "CMOVWGT", argLength: 3, reg: gp21, asm: "CMOVWGT", resultInArg0: true},
		{name: "CMOVWLE", argLength: 3, reg: gp21, asm: "CMOVWLE", resultInArg0: true},
		{name: "CMOVWGE", argLength: 3, reg: gp21, asm: "CMOVWGE", resultInArg0: true},
		{name: "CMOVWLS", argLength: 3, reg: gp21, asm: "CMOVWLS", resultInArg0: true},
		{name: "CMOVWHI", argLength: 3, reg: gp21, asm: "CMOVWHI", resultInArg0: true},
		{name: "CMOVWCC", argLength: 3, reg: gp21, asm: "CMOVWCC", resultInArg0: true},
		{name: "CMOVWCS", argLength: 3, reg: gp21, asm: "CMOVWCS", resultInArg0: true},

		// CMOV with floating point instructions. We need separate pseudo-op to handle
		// InvertFlags correctly, and to generate special code that handles NaN (unordered flag).
		// NOTE: the fact that CMOV*EQF here is marked to generate CMOV*NE is not a bug. See
		// code generation in amd64/ssa.go.
		{name: "CMOVQEQF", argLength: 3, reg: gp21, asm: "CMOVQNE", resultInArg0: true, needIntTemp: true},
		{name: "CMOVQNEF", argLength: 3, reg: gp21, asm: "CMOVQNE", resultInArg0: true},
		{name: "CMOVQGTF", argLength: 3, reg: gp21, asm: "CMOVQHI", resultInArg0: true},
		{name: "CMOVQGEF", argLength: 3, reg: gp21, asm: "CMOVQCC", resultInArg0: true},
		{name: "CMOVLEQF", argLength: 3, reg: gp21, asm: "CMOVLNE", resultInArg0: true, needIntTemp: true},
		{name: "CMOVLNEF", argLength: 3, reg: gp21, asm: "CMOVLNE", resultInArg0: true},
		{name: "CMOVLGTF", argLength: 3, reg: gp21, asm: "CMOVLHI", resultInArg0: true},
		{name: "CMOVLGEF", argLength: 3, reg: gp21, asm: "CMOVLCC", resultInArg0: true},
		{name: "CMOVWEQF", argLength: 3, reg: gp21, asm: "CMOVWNE", resultInArg0: true, needIntTemp: true},
		{name: "CMOVWNEF", argLength: 3, reg: gp21, asm: "CMOVWNE", resultInArg0: true},
		{name: "CMOVWGTF", argLength: 3, reg: gp21, asm: "CMOVWHI", resultInArg0: true},
		{name: "CMOVWGEF", argLength: 3, reg: gp21, asm: "CMOVWCC", resultInArg0: true},

		// BSWAPx swaps the low-order (L=4,Q=8) bytes of arg0.
		// Q: abcdefgh -> hgfedcba
		// L: abcdefgh -> 0000hgfe (L zeros the upper 4 bytes)
		{name: "BSWAPQ", argLength: 1, reg: gp11, asm: "BSWAPQ", resultInArg0: true},
		{name: "BSWAPL", argLength: 1, reg: gp11, asm: "BSWAPL", resultInArg0: true},

		// POPCNTx counts the number of set bits in the low-order (L=32,Q=64) bits of arg0.
		// POPCNTx instructions are only guaranteed to be available if GOAMD64>=v2.
		// For GOAMD64<v2, any use must be preceded by a successful runtime check of runtime.x86HasPOPCNT.
		{name: "POPCNTQ", argLength: 1, reg: gp11, asm: "POPCNTQ", clobberFlags: true},
		{name: "POPCNTL", argLength: 1, reg: gp11, asm: "POPCNTL", clobberFlags: true},

		// SQRTSx computes sqrt(arg0)
		// S = float32, D = float64
		{name: "SQRTSD", argLength: 1, reg: fp11, asm: "SQRTSD"},
		{name: "SQRTSS", argLength: 1, reg: fp11, asm: "SQRTSS"},

		// ROUNDSD rounds arg0 to an integer depending on auxint
		// 0 means math.RoundToEven, 1 means math.Floor, 2 math.Ceil, 3 math.Trunc
		// (The result is still a float64.)
		// ROUNDSD instruction is only guaraneteed to be available if GOAMD64>=v2.
		// For GOAMD64<v2, any use must be preceded by a successful check of runtime.x86HasSSE41.
		{name: "ROUNDSD", argLength: 1, reg: fp11, aux: "Int8", asm: "ROUNDSD"},

		// VFMADD231SD only exists on platforms with the FMA3 instruction set.
		// Any use must be preceded by a successful check of runtime.support_fma.
		{name: "VFMADD231SD", argLength: 3, reg: fp31, resultInArg0: true, asm: "VFMADD231SD"},

		// Note that these operations don't exactly match the semantics of Go's
		// builtin min. In particular, these aren't commutative, because on various
		// special cases the 2nd argument is preferred.
		{name: "MINSD", argLength: 2, reg: fp21, resultInArg0: true, asm: "MINSD"}, // min(arg0,arg1)
		{name: "MINSS", argLength: 2, reg: fp21, resultInArg0: true, asm: "MINSS"}, // min(arg0,arg1)

		{name: "SBBQcarrymask", argLength: 1, reg: flagsgp, asm: "SBBQ"}, // (int64)(-1) if carry is set, 0 if carry is clear.
		{name: "SBBLcarrymask", argLength: 1, reg: flagsgp, asm: "SBBL"}, // (int32)(-1) if carry is set, 0 if carry is clear.
		// Note: SBBW and SBBB are subsumed by SBBL

		{name: "SETEQ", argLength: 1, reg: readflags, asm: "SETEQ"}, // extract == condition from arg0
		{name: "SETNE", argLength: 1, reg: readflags, asm: "SETNE"}, // extract != condition from arg0
		{name: "SETL", argLength: 1, reg: readflags, asm: "SETLT"},  // extract signed < condition from arg0
		{name: "SETLE", argLength: 1, reg: readflags, asm: "SETLE"}, // extract signed <= condition from arg0
		{name: "SETG", argLength: 1, reg: readflags, asm: "SETGT"},  // extract signed > condition from arg0
		{name: "SETGE", argLength: 1, reg: readflags, asm: "SETGE"}, // extract signed >= condition from arg0
		{name: "SETB", argLength: 1, reg: readflags, asm: "SETCS"},  // extract unsigned < condition from arg0
		{name: "SETBE", argLength: 1, reg: readflags, asm: "SETLS"}, // extract unsigned <= condition from arg0
		{name: "SETA", argLength: 1, reg: readflags, asm: "SETHI"},  // extract unsigned > condition from arg0
		{name: "SETAE", argLength: 1, reg: readflags, asm: "SETCC"}, // extract unsigned >= condition from arg0
		{name: "SETO", argLength: 1, reg: readflags, asm: "SETOS"},  // extract if overflow flag is set from arg0
		// Variants that store result to memory
		{name: "SETEQstore", argLength: 3, reg: gpstoreconst, asm: "SETEQ", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},               // extract == condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETNEstore", argLength: 3, reg: gpstoreconst, asm: "SETNE", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},               // extract != condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETLstore", argLength: 3, reg: gpstoreconst, asm: "SETLT", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},                // extract signed < condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETLEstore", argLength: 3, reg: gpstoreconst, asm: "SETLE", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},               // extract signed <= condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETGstore", argLength: 3, reg: gpstoreconst, asm: "SETGT", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},                // extract signed > condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETGEstore", argLength: 3, reg: gpstoreconst, asm: "SETGE", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},               // extract signed >= condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETBstore", argLength: 3, reg: gpstoreconst, asm: "SETCS", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},                // extract unsigned < condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETBEstore", argLength: 3, reg: gpstoreconst, asm: "SETLS", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},               // extract unsigned <= condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETAstore", argLength: 3, reg: gpstoreconst, asm: "SETHI", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},                // extract unsigned > condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETAEstore", argLength: 3, reg: gpstoreconst, asm: "SETCC", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},               // extract unsigned >= condition from arg1 to arg0+auxint+aux, arg2=mem
		{name: "SETEQstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETEQ", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"}, // extract == condition from arg2 to arg0+arg1+auxint+aux, arg3=mem
		{name: "SETNEstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETNE", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"}, // extract != condition from arg2 to arg0+arg1+auxint+aux, arg3=mem
		{name: "SETLstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETLT", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"},  // extract signed < condition from arg2 to arg0+arg1+auxint+aux, arg3=mem
		{name: "SETLEstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETLE", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"}, // extract signed <= condition from arg2 to arg0+arg1+auxint+aux, arg3=mem
		{name: "SETGstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETGT", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"},  // extract signed > condition from arg2 to arg0+arg1+auxint+aux, arg3=mem
		{name: "SETGEstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETGE", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"}, // extract signed >= condition from arg2 to arg0+arg1+auxint+aux, arg3=mem
		{name: "SETBstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETCS", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"},  // extract unsigned < condition from arg2 to arg0+arg1+auxint+aux, arg3=mem
		{name: "SETBEstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETLS", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"}, // extract unsigned <= condition from arg2 to arg0+arg1+auxint+aux, arg3=mem
		{name: "SETAstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETHI", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"},  // extract unsigned > condition from arg2 to arg0+arg1+auxint+aux, arg3=mem
		{name: "SETAEstoreidx1", argLength: 4, reg: gpstoreconstidx, asm: "SETCC", aux: "SymOff", typ: "Mem", scale: 1, commutative: true, symEffect: "Write"}, // extract unsigned >= condition from arg2 to arg0+arg1+auxint+aux, arg3=mem

		// Need different opcodes for floating point conditions because
		// any comparison involving a NaN is always FALSE and thus
		// the patterns for inverting conditions cannot be used.
		{name: "SETEQF", argLength: 1, reg: flagsgp, asm: "SETEQ", clobberFlags: true, needIntTemp: true}, // extract == condition from arg0
		{name: "SETNEF", argLength: 1, reg: flagsgp, asm: "SETNE", clobberFlags: true, needIntTemp: true}, // extract != condition from arg0
		{name: "SETORD", argLength: 1, reg: flagsgp, asm: "SETPC"},                                        // extract "ordered" (No Nan present) condition from arg0
		{name: "SETNAN", argLength: 1, reg: flagsgp, asm: "SETPS"},                                        // extract "unordered" (Nan present) condition from arg0

		{name: "SETGF", argLength: 1, reg: flagsgp, asm: "SETHI"},  // extract floating > condition from arg0
		{name: "SETGEF", argLength: 1, reg: flagsgp, asm: "SETCC"}, // extract floating >= condition from arg0

		{name: "MOVBQSX", argLength: 1, reg: gp11, asm: "MOVBQSX"}, // si
"""




```