Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Goal:** The request asks for the *functionality* of the `LOONG64Ops.go` file, along with explanations and examples. The key is to understand what kind of code this is and what purpose it serves within the Go compiler.

2. **Initial Scan and Keywords:**  A quick scan reveals important keywords and patterns:
    * `"// Copyright 2022 The Go Authors"`: Indicates this is part of the official Go project.
    * `package main`: Suggests this is an executable, but the filename and content strongly hint at a code generation tool rather than a standalone application.
    * `import "strings"`: Basic string manipulation.
    * `regNamesLOONG64`:  A list of register names – strongly suggesting assembly or low-level operations for the LOONG64 architecture.
    * `regMask`: A type likely used for bitmasks related to registers.
    * `buildReg`: A function to create `regMask` from register names.
    * `regInfo`: A struct likely describing the input and output register requirements of operations.
    * `opData`:  A struct containing information about individual operations (name, arguments, registers, assembly instruction).
    * `blockData`:  Describes control flow block types.
    * `arch`: A struct holding architecture-specific information.
    * `init()`:  A standard Go initialization function.
    * `archs = append(archs, ...)`:  Appends architecture data to a slice.

3. **Inferring the Purpose:**  Based on the keywords, the structure of `opData`, and the architecture name "LOONG64," the core functionality is clearly about defining and managing the instruction set and register usage for the LOONG64 architecture within the Go compiler. This file is *not* part of the runtime or standard library; it's a build-time tool.

4. **Deconstructing Key Structures:**

    * **`regNamesLOONG64`:**  This is a simple mapping of symbolic register names (R0, SP, F0, SB) to strings.
    * **`buildReg`:**  This function takes a string of register names, splits them, and creates a bitmask (`regMask`) where each bit corresponds to a register. This is crucial for representing register sets.
    * **`regInfo`:** This structure is vital for register allocation. `inputs` and `outputs` specify which registers are read from and written to by an operation. This information is used by the compiler's register allocator to assign physical registers to virtual registers.
    * **`opData`:** This is the heart of the file. Each `opData` entry describes a single operation the LOONG64 architecture can perform. Key fields are:
        * `name`: The internal name of the operation within the Go compiler.
        * `asm`: The corresponding assembly instruction.
        * `argLength`: The number of arguments the operation takes.
        * `reg`: The `regInfo` for this operation.
        * `aux`:  Indicates the type of auxiliary information (like constants or symbols).
        * `typ`:  The data type involved.
        * `commutative`: Whether the order of operands matters.
        * Other flags (like `faultOnNilArg0`, `call`, `rematerializable`).
    * **`blockData`:** Describes different control flow block types and how many control inputs they have (e.g., a conditional branch has one control input).
    * **`arch`:** This structure aggregates all the architecture-specific data.

5. **Reasoning about Functionality:**

    * **Register Management:** The code defines the register set and provides a way to represent and manipulate sets of registers using bitmasks.
    * **Instruction Set Definition:**  The `ops` slice defines the supported instructions for the LOONG64 architecture. Each entry provides the Go compiler with the necessary information to translate intermediate representation (SSA) into LOONG64 assembly.
    * **Register Allocation Hints:** The `regInfo` structure within `opData` provides crucial hints to the register allocator about how each instruction uses registers.
    * **Code Generation:** This file is a critical part of the code generation phase of the Go compiler. It allows the compiler to generate correct assembly code for the target architecture.
    * **Architecture Abstraction:** The `arch` struct encapsulates all the LOONG64-specific details, allowing the rest of the compiler to work with a more abstract representation.

6. **Providing Examples (Conceptual):** Since this is about compiler internals, concrete Go code examples that *directly* use this file are impossible for a regular Go programmer. The examples need to demonstrate the *kind* of Go code that would eventually be translated using these definitions. Think about the kinds of operations defined (addition, subtraction, loads, stores, comparisons) and provide simple Go snippets that would result in those low-level operations.

7. **Considering Command-Line Arguments:** This file itself doesn't process command-line arguments. It's a data definition file used *by* the compiler. The command-line arguments for the `go` command (like `go build`) trigger the compiler, which then uses this data.

8. **Identifying Potential Mistakes (Conceptual):**  The most likely mistakes are related to the *correctness* of the definitions. For example:
    * Incorrect register masks in `regInfo`.
    * Mismatched assembly instruction names in `asm`.
    * Incorrect `argLength`.
    * Mistakes in the `commutative` flag.
    * Not accounting for all necessary registers in `callerSave`.

9. **Structuring the Answer:** Organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the key data structures and their roles.
    * Provide illustrative Go code examples (showing the *source* that leads to these operations).
    * Explain the lack of direct command-line interaction.
    * Discuss potential errors in maintaining this file.

10. **Refinement and Clarity:**  Review the answer for clarity, accuracy, and completeness. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. For instance, explicitly stating that this is for the *compiler's* code generation phase is important.

By following these steps, the detailed and accurate explanation of the `LOONG64Ops.go` file can be constructed. The key is to recognize the file's role within the Go compiler's architecture and to interpret the data structures in that context.
这是一个Go语言源文件，路径为 `go/src/cmd/compile/internal/ssa/_gen/LOONG64Ops.go`。从文件名和路径来看，它位于 Go 编译器的内部，并且看起来是自动生成的（`_gen` 目录）。文件名 `LOONG64Ops.go` 强烈暗示它定义了与 LOONG64 架构相关的操作 (Operations)。

**核心功能：**

该文件的主要功能是**定义了 Go 编译器在将中间代码（SSA，Static Single Assignment）转换为 LOONG64 汇编代码时所能使用的所有操作**。 它详细描述了每个操作的属性，例如：

1. **操作名称 (`name`)**:  例如 "ADDV", "MOVVload", "CALLstatic" 等。
2. **参数长度 (`argLength`)**: 操作数目的数量。
3. **寄存器信息 (`reg`)**:  描述了操作的输入和输出寄存器约束，以及可能被操作修改的寄存器。 这对于编译器的寄存器分配阶段至关重要。
4. **汇编指令 (`asm`)**:  与 Go SSA 操作对应的 LOONG64 汇编指令助记符。
5. **辅助信息 (`aux`)**: 一些操作可能需要额外的辅助信息，例如常量值 (`Int64`, `Float64`) 或符号偏移 (`SymOff`).
6. **数据类型 (`typ`)**: 操作处理的数据类型，例如 `Int64`, `UInt32`, `Float32`, `Mem` 等。
7. **其他属性**:  例如 `commutative`（是否满足交换律），`rematerializeable`（是否可以重新计算），`faultOnNilArg0`（如果第一个参数为 nil 是否会发生错误），`call`（是否是函数调用），`clobberFlags`（是否会修改标志寄存器）等等。
8. **块类型信息 (`blocks`)**: 定义了控制流图中的基本块类型，例如条件分支 (EQ, NE, LTZ...) 和无条件分支。
9. **架构信息 (`archs`)**: 汇总了 LOONG64 架构的特定信息，包括寄存器名称、通用寄存器和浮点寄存器的掩码、函数参数传递的寄存器名称等。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 编译器中**目标架构代码生成**的关键部分。 当 Go 编译器为 LOONG64 架构编译代码时，它会将 Go 代码转换为一种中间表示形式 (SSA)。 然后，编译器会使用 `LOONG64Ops.go` 中定义的操作信息，将这些 SSA 指令 Lowering（降低抽象级别）为具体的 LOONG64 汇编指令。

**Go 代码示例说明（需要代码推理和假设）：**

假设我们有以下简单的 Go 代码：

```go
package main

func add(a, b int64) int64 {
	return a + b
}

func main() {
	x := 10
	y := 20
	z := add(int64(x), int64(y))
	println(z)
}
```

**推理过程：**

1. 编译器在处理 `a + b` 时，会生成一个 SSA 的加法操作。
2. 对于 LOONG64 架构，编译器会查找 `LOONG64Ops.go` 中名为 "ADDV" 的操作。
3. `LOONG64Ops.go` 中 "ADDV" 的定义如下（简化）：
   ```go
   {name: "ADDV", argLength: 2, reg: gp21, asm: "ADDVU", commutative: true},
   ```
4. 这告诉编译器：
   -  "ADDV" 操作对应 LOONG64 汇编指令 `ADDVU` (无符号加法，这里可能根据具体情况使用有符号或无符号版本)。
   - 它需要两个输入参数 (`argLength: 2`)。
   - 输入和输出寄存器都属于通用寄存器 (`reg: gp21`)，意味着它会将两个通用寄存器中的值相加，并将结果存储到一个通用寄存器中。

**生成的 LOONG64 汇编代码（简化和假设）：**

假设 `a` 和 `b` 分别被分配到寄存器 `R4` 和 `R5`，并且结果需要存储到 `R6`，那么生成的汇编代码可能如下所示：

```assembly
  ADDVU R4, R5, R6  // R6 = R4 + R5
```

**假设的输入与输出：**

* **输入 (SSA 形式的加法操作):**  一个表示 `a + b` 的 SSA 指令，其中 `a` 和 `b` 是 int64 类型的值。
* **输出 (LOONG64 汇编指令):**  `ADDVU Rsrc1, Rsrc2, Rdest`  (具体的寄存器分配取决于编译器的寄存器分配算法)。

**命令行参数的具体处理：**

`LOONG64Ops.go` 文件本身 **不处理命令行参数**。 它是 Go 编译器源代码的一部分。 命令行参数是由 `go` 工具链（例如 `go build`, `go run`）处理的。  当使用 `go build -arch=loong64 ...` 这样的命令时，`go` 工具链会指示编译器为 LOONG64 架构生成代码，这时编译器才会加载和使用 `LOONG64Ops.go` 中定义的信息。

**使用者易犯错的点（通常是 Go 编译器开发者）：**

这个文件主要是给 Go 编译器开发者维护的。 普通 Go 语言使用者通常不需要直接接触或修改这个文件。  对于编译器开发者来说，常见的错误点可能包括：

1. **错误的寄存器约束 (`regInfo`)**:  如果 `regInfo` 配置不正确，可能导致寄存器分配错误，生成无效的汇编代码，或者导致性能问题。 例如，错误地指定了输入或输出寄存器，或者遗漏了会被操作修改的寄存器。
2. **汇编指令助记符错误 (`asm`)**:  拼写错误的汇编指令会导致汇编器报错。
3. **辅助信息类型错误 (`aux`)**:  如果操作需要特定的辅助信息（例如常量），但 `aux` 字段的类型不匹配，会导致编译错误或运行时错误。
4. **数据类型 (`typ`) 不匹配**:  如果 SSA 操作处理的数据类型与 `LOONG64Ops.go` 中定义的数据类型不一致，可能导致类型错误。
5. **遗漏或错误的属性设置**: 例如，如果一个操作是可交换的，但 `commutative` 标志没有设置为 `true`，可能会影响编译器的优化。
6. **添加新的操作时没有正确更新相关结构**:  例如，添加新的指令可能需要更新寄存器名称列表 (`regNamesLOONG64`) 或通用/浮点寄存器掩码。

**示例： 错误的寄存器约束**

假设 `MULV` (乘法) 操作的 `regInfo` 被错误地定义为只使用一个寄存器作为输入：

```go
// 错误示例
{name: "MULV", argLength: 2, reg: regInfo{inputs: []regMask{gpg}}, asm: "MULV", commutative: true, typ: "Int64"},
```

这将导致编译器在分配寄存器时可能只为一个输入操作数分配寄存器，从而导致错误的汇编代码生成。 正确的定义应该指明需要两个输入寄存器。

总结来说， `LOONG64Ops.go` 是 Go 编译器中一个关键的、自动生成的文件，它详细描述了 LOONG64 架构的指令集和相关属性，用于将 Go 的中间表示形式转换为最终的机器码。 它的正确性对于生成高效且正确的 LOONG64 代码至关重要。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/_gen/LOONG64Ops.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2022 The Go Authors. All rights reserved.
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
//    register (R23).

// Suffixes encode the bit width of various instructions.
// V (vlong)     = 64 bit
// WU (word)     = 32 bit unsigned
// W (word)      = 32 bit
// H (half word) = 16 bit
// HU            = 16 bit unsigned
// B (byte)      = 8 bit
// BU            = 8 bit unsigned
// F (float)     = 32 bit float
// D (double)    = 64 bit float

// Note: registers not used in regalloc are not included in this list,
// so that regmask stays within int64
// Be careful when hand coding regmasks.
var regNamesLOONG64 = []string{
	"R0", // constant 0
	"R1",
	"SP", // aka R3
	"R4",
	"R5",
	"R6",
	"R7",
	"R8",
	"R9",
	"R10",
	"R11",
	"R12",
	"R13",
	"R14",
	"R15",
	"R16",
	"R17",
	"R18",
	"R19",
	"R20",
	"R21",
	"g", // aka R22
	"R23",
	"R24",
	"R25",
	"R26",
	"R27",
	"R28",
	"R29",
	// R30 is REGTMP not used in regalloc
	"R31",

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
	"F16",
	"F17",
	"F18",
	"F19",
	"F20",
	"F21",
	"F22",
	"F23",
	"F24",
	"F25",
	"F26",
	"F27",
	"F28",
	"F29",
	"F30",
	"F31",

	// If you add registers, update asyncPreempt in runtime.

	// pseudo-registers
	"SB",
}

func init() {
	// Make map from reg names to reg integers.
	if len(regNamesLOONG64) > 64 {
		panic("too many registers")
	}
	num := map[string]int{}
	for i, name := range regNamesLOONG64 {
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
		gp         = buildReg("R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31") // R1 is LR, R2 is thread pointer, R3 is stack pointer, R22 is g, R30 is REGTMP
		gpg        = gp | buildReg("g")
		gpsp       = gp | buildReg("SP")
		gpspg      = gpg | buildReg("SP")
		gpspsbg    = gpspg | buildReg("SB")
		fp         = buildReg("F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31")
		callerSave = gp | fp | buildReg("g") // runtime.setg (and anything calling it) may clobber g
		r1         = buildReg("R20")
		r2         = buildReg("R21")
		r3         = buildReg("R23")
		r4         = buildReg("R24")
	)
	// Common regInfo
	var (
		gp01      = regInfo{inputs: nil, outputs: []regMask{gp}}
		gp11      = regInfo{inputs: []regMask{gpg}, outputs: []regMask{gp}}
		gp11sp    = regInfo{inputs: []regMask{gpspg}, outputs: []regMask{gp}}
		gp21      = regInfo{inputs: []regMask{gpg, gpg}, outputs: []regMask{gp}}
		gpload    = regInfo{inputs: []regMask{gpspsbg}, outputs: []regMask{gp}}
		gp2load   = regInfo{inputs: []regMask{gpspsbg, gpg}, outputs: []regMask{gp}}
		gpstore   = regInfo{inputs: []regMask{gpspsbg, gpg}}
		gpstore0  = regInfo{inputs: []regMask{gpspsbg}}
		gpstore2  = regInfo{inputs: []regMask{gpspsbg, gpg, gpg}}
		gpxchg    = regInfo{inputs: []regMask{gpspsbg, gpg}, outputs: []regMask{gp}}
		gpcas     = regInfo{inputs: []regMask{gpspsbg, gpg, gpg}, outputs: []regMask{gp}}
		fp01      = regInfo{inputs: nil, outputs: []regMask{fp}}
		fp11      = regInfo{inputs: []regMask{fp}, outputs: []regMask{fp}}
		fp21      = regInfo{inputs: []regMask{fp, fp}, outputs: []regMask{fp}}
		fp31      = regInfo{inputs: []regMask{fp, fp, fp}, outputs: []regMask{fp}}
		fp2flags  = regInfo{inputs: []regMask{fp, fp}}
		fpload    = regInfo{inputs: []regMask{gpspsbg}, outputs: []regMask{fp}}
		fp2load   = regInfo{inputs: []regMask{gpspsbg, gpg}, outputs: []regMask{fp}}
		fpstore   = regInfo{inputs: []regMask{gpspsbg, fp}}
		fpstore2  = regInfo{inputs: []regMask{gpspsbg, gpg, fp}}
		fpgp      = regInfo{inputs: []regMask{fp}, outputs: []regMask{gp}}
		gpfp      = regInfo{inputs: []regMask{gp}, outputs: []regMask{fp}}
		readflags = regInfo{inputs: nil, outputs: []regMask{gp}}
	)
	ops := []opData{
		// unary ops
		{name: "NEGV", argLength: 1, reg: gp11},              // -arg0
		{name: "NEGF", argLength: 1, reg: fp11, asm: "NEGF"}, // -arg0, float32
		{name: "NEGD", argLength: 1, reg: fp11, asm: "NEGD"}, // -arg0, float64

		{name: "SQRTD", argLength: 1, reg: fp11, asm: "SQRTD"}, // sqrt(arg0), float64
		{name: "SQRTF", argLength: 1, reg: fp11, asm: "SQRTF"}, // sqrt(arg0), float32

		{name: "ABSD", argLength: 1, reg: fp11, asm: "ABSD"}, // abs(arg0), float64

		{name: "CLZW", argLength: 1, reg: gp11, asm: "CLZW"}, // Count leading (high order) zeroes (returns 0-32)
		{name: "CLZV", argLength: 1, reg: gp11, asm: "CLZV"}, // Count leading (high order) zeroes (returns 0-64)
		{name: "CTZW", argLength: 1, reg: gp11, asm: "CTZW"}, // Count trailing (low order) zeroes (returns 0-32)
		{name: "CTZV", argLength: 1, reg: gp11, asm: "CTZV"}, // Count trailing (low order) zeroes (returns 0-64)

		{name: "REVB2H", argLength: 1, reg: gp11, asm: "REVB2H"}, // Swap bytes: 0x11223344 -> 0x22114433 (sign extends to 64 bits)
		{name: "REVB2W", argLength: 1, reg: gp11, asm: "REVB2W"}, // Swap bytes: 0x1122334455667788 -> 0x4433221188776655
		{name: "REVBV", argLength: 1, reg: gp11, asm: "REVBV"},   // Swap bytes: 0x1122334455667788 -> 0x8877665544332211

		{name: "BITREV4B", argLength: 1, reg: gp11, asm: "BITREV4B"}, // Reverse the bits of each byte inside a 32-bit arg[0]
		{name: "BITREVW", argLength: 1, reg: gp11, asm: "BITREVW"},   // Reverse the bits in a 32-bit arg[0]
		{name: "BITREVV", argLength: 1, reg: gp11, asm: "BITREVV"},   // Reverse the bits in a 64-bit arg[0]

		{name: "VPCNT64", argLength: 1, reg: fp11, asm: "VPCNTV"}, // count set bits for each 64-bit unit and store the result in each 64-bit unit
		{name: "VPCNT32", argLength: 1, reg: fp11, asm: "VPCNTW"}, // count set bits for each 32-bit unit and store the result in each 32-bit unit
		{name: "VPCNT16", argLength: 1, reg: fp11, asm: "VPCNTH"}, // count set bits for each 16-bit unit and store the result in each 16-bit unit

		// binary ops
		{name: "ADDV", argLength: 2, reg: gp21, asm: "ADDVU", commutative: true},   // arg0 + arg1
		{name: "ADDVconst", argLength: 1, reg: gp11sp, asm: "ADDVU", aux: "Int64"}, // arg0 + auxInt. auxInt is 32-bit, also in other *const ops.
		{name: "SUBV", argLength: 2, reg: gp21, asm: "SUBVU"},                      // arg0 - arg1
		{name: "SUBVconst", argLength: 1, reg: gp11, asm: "SUBVU", aux: "Int64"},   // arg0 - auxInt

		{name: "MULV", argLength: 2, reg: gp21, asm: "MULV", commutative: true, typ: "Int64"},      // arg0 * arg1
		{name: "MULHV", argLength: 2, reg: gp21, asm: "MULHV", commutative: true, typ: "Int64"},    // (arg0 * arg1) >> 64, signed
		{name: "MULHVU", argLength: 2, reg: gp21, asm: "MULHVU", commutative: true, typ: "UInt64"}, // (arg0 * arg1) >> 64, unsigned
		{name: "DIVV", argLength: 2, reg: gp21, asm: "DIVV", typ: "Int64"},                         // arg0 / arg1, signed
		{name: "DIVVU", argLength: 2, reg: gp21, asm: "DIVVU", typ: "UInt64"},                      // arg0 / arg1, unsigned
		{name: "REMV", argLength: 2, reg: gp21, asm: "REMV", typ: "Int64"},                         // arg0 / arg1, signed
		{name: "REMVU", argLength: 2, reg: gp21, asm: "REMVU", typ: "UInt64"},                      // arg0 / arg1, unsigned

		{name: "ADDF", argLength: 2, reg: fp21, asm: "ADDF", commutative: true}, // arg0 + arg1
		{name: "ADDD", argLength: 2, reg: fp21, asm: "ADDD", commutative: true}, // arg0 + arg1
		{name: "SUBF", argLength: 2, reg: fp21, asm: "SUBF"},                    // arg0 - arg1
		{name: "SUBD", argLength: 2, reg: fp21, asm: "SUBD"},                    // arg0 - arg1
		{name: "MULF", argLength: 2, reg: fp21, asm: "MULF", commutative: true}, // arg0 * arg1
		{name: "MULD", argLength: 2, reg: fp21, asm: "MULD", commutative: true}, // arg0 * arg1
		{name: "DIVF", argLength: 2, reg: fp21, asm: "DIVF"},                    // arg0 / arg1
		{name: "DIVD", argLength: 2, reg: fp21, asm: "DIVD"},                    // arg0 / arg1

		{name: "AND", argLength: 2, reg: gp21, asm: "AND", commutative: true},                // arg0 & arg1
		{name: "ANDconst", argLength: 1, reg: gp11, asm: "AND", aux: "Int64"},                // arg0 & auxInt
		{name: "OR", argLength: 2, reg: gp21, asm: "OR", commutative: true},                  // arg0 | arg1
		{name: "ORconst", argLength: 1, reg: gp11, asm: "OR", aux: "Int64"},                  // arg0 | auxInt
		{name: "XOR", argLength: 2, reg: gp21, asm: "XOR", commutative: true, typ: "UInt64"}, // arg0 ^ arg1
		{name: "XORconst", argLength: 1, reg: gp11, asm: "XOR", aux: "Int64", typ: "UInt64"}, // arg0 ^ auxInt
		{name: "NOR", argLength: 2, reg: gp21, asm: "NOR", commutative: true},                // ^(arg0 | arg1)
		{name: "NORconst", argLength: 1, reg: gp11, asm: "NOR", aux: "Int64"},                // ^(arg0 | auxInt)

		{name: "FMADDF", argLength: 3, reg: fp31, asm: "FMADDF", commutative: true, typ: "Float32"},   // (arg0 * arg1) + arg2
		{name: "FMADDD", argLength: 3, reg: fp31, asm: "FMADDD", commutative: true, typ: "Float64"},   // (arg0 * arg1) + arg2
		{name: "FMSUBF", argLength: 3, reg: fp31, asm: "FMSUBF", commutative: true, typ: "Float32"},   // (arg0 * arg1) - arg2
		{name: "FMSUBD", argLength: 3, reg: fp31, asm: "FMSUBD", commutative: true, typ: "Float64"},   // (arg0 * arg1) - arg2
		{name: "FNMADDF", argLength: 3, reg: fp31, asm: "FNMADDF", commutative: true, typ: "Float32"}, // -((arg0 * arg1) + arg2)
		{name: "FNMADDD", argLength: 3, reg: fp31, asm: "FNMADDD", commutative: true, typ: "Float64"}, // -((arg0 * arg1) + arg2)
		{name: "FNMSUBF", argLength: 3, reg: fp31, asm: "FNMSUBF", commutative: true, typ: "Float32"}, // -((arg0 * arg1) - arg2)
		{name: "FNMSUBD", argLength: 3, reg: fp31, asm: "FNMSUBD", commutative: true, typ: "Float64"}, // -((arg0 * arg1) - arg2)

		{name: "FMINF", argLength: 2, reg: fp21, resultNotInArgs: true, asm: "FMINF", commutative: true, typ: "Float32"}, // min(arg0, arg1), float32
		{name: "FMIND", argLength: 2, reg: fp21, resultNotInArgs: true, asm: "FMIND", commutative: true, typ: "Float64"}, // min(arg0, arg1), float64
		{name: "FMAXF", argLength: 2, reg: fp21, resultNotInArgs: true, asm: "FMAXF", commutative: true, typ: "Float32"}, // max(arg0, arg1), float32
		{name: "FMAXD", argLength: 2, reg: fp21, resultNotInArgs: true, asm: "FMAXD", commutative: true, typ: "Float64"}, // max(arg0, arg1), float64

		{name: "MASKEQZ", argLength: 2, reg: gp21, asm: "MASKEQZ"},   // returns 0 if arg1 == 0, otherwise returns arg0
		{name: "MASKNEZ", argLength: 2, reg: gp21, asm: "MASKNEZ"},   // returns 0 if arg1 != 0, otherwise returns arg0
		{name: "FCOPYSGD", argLength: 2, reg: fp21, asm: "FCOPYSGD"}, // float64

		// shifts
		{name: "SLLV", argLength: 2, reg: gp21, asm: "SLLV"},                      // arg0 << arg1, shift amount is mod 64
		{name: "SLLVconst", argLength: 1, reg: gp11, asm: "SLLV", aux: "Int64"},   // arg0 << auxInt
		{name: "SRLV", argLength: 2, reg: gp21, asm: "SRLV"},                      // arg0 >> arg1, unsigned, shift amount is mod 64
		{name: "SRLVconst", argLength: 1, reg: gp11, asm: "SRLV", aux: "Int64"},   // arg0 >> auxInt, unsigned
		{name: "SRAV", argLength: 2, reg: gp21, asm: "SRAV"},                      // arg0 >> arg1, signed, shift amount is mod 64
		{name: "SRAVconst", argLength: 1, reg: gp11, asm: "SRAV", aux: "Int64"},   // arg0 >> auxInt, signed
		{name: "ROTR", argLength: 2, reg: gp21, asm: "ROTR"},                      // arg0 right rotate by (arg1 mod 32) bits
		{name: "ROTRV", argLength: 2, reg: gp21, asm: "ROTRV"},                    // arg0 right rotate by (arg1 mod 64) bits
		{name: "ROTRconst", argLength: 1, reg: gp11, asm: "ROTR", aux: "Int64"},   // uint32(arg0) right rotate by auxInt bits, auxInt should be in the range 0 to 31.
		{name: "ROTRVconst", argLength: 1, reg: gp11, asm: "ROTRV", aux: "Int64"}, // arg0 right rotate by auxInt bits, auxInt should be in the range 0 to 63.

		// comparisons
		{name: "SGT", argLength: 2, reg: gp21, asm: "SGT", typ: "Bool"},                      // 1 if arg0 > arg1 (signed), 0 otherwise
		{name: "SGTconst", argLength: 1, reg: gp11, asm: "SGT", aux: "Int64", typ: "Bool"},   // 1 if auxInt > arg0 (signed), 0 otherwise
		{name: "SGTU", argLength: 2, reg: gp21, asm: "SGTU", typ: "Bool"},                    // 1 if arg0 > arg1 (unsigned), 0 otherwise
		{name: "SGTUconst", argLength: 1, reg: gp11, asm: "SGTU", aux: "Int64", typ: "Bool"}, // 1 if auxInt > arg0 (unsigned), 0 otherwise

		{name: "CMPEQF", argLength: 2, reg: fp2flags, asm: "CMPEQF", typ: "Flags"}, // flags=true if arg0 = arg1, float32
		{name: "CMPEQD", argLength: 2, reg: fp2flags, asm: "CMPEQD", typ: "Flags"}, // flags=true if arg0 = arg1, float64
		{name: "CMPGEF", argLength: 2, reg: fp2flags, asm: "CMPGEF", typ: "Flags"}, // flags=true if arg0 >= arg1, float32
		{name: "CMPGED", argLength: 2, reg: fp2flags, asm: "CMPGED", typ: "Flags"}, // flags=true if arg0 >= arg1, float64
		{name: "CMPGTF", argLength: 2, reg: fp2flags, asm: "CMPGTF", typ: "Flags"}, // flags=true if arg0 > arg1, float32
		{name: "CMPGTD", argLength: 2, reg: fp2flags, asm: "CMPGTD", typ: "Flags"}, // flags=true if arg0 > arg1, float64

		// bitfield ops
		// for bstrpick.w msbw is auxInt>>5, lsbw is auxInt&0x1f
		// for bstrpick.d msbd is auxInt>>6, lsbd is auxInt&0x3f
		{name: "BSTRPICKW", argLength: 1, reg: gp11, asm: "BSTRPICKW", aux: "Int64"},
		{name: "BSTRPICKV", argLength: 1, reg: gp11, asm: "BSTRPICKV", aux: "Int64"},

		// moves
		{name: "MOVVconst", argLength: 0, reg: gp01, aux: "Int64", asm: "MOVV", typ: "UInt64", rematerializeable: true},    // auxint
		{name: "MOVFconst", argLength: 0, reg: fp01, aux: "Float64", asm: "MOVF", typ: "Float32", rematerializeable: true}, // auxint as 64-bit float, convert to 32-bit float
		{name: "MOVDconst", argLength: 0, reg: fp01, aux: "Float64", asm: "MOVD", typ: "Float64", rematerializeable: true}, // auxint as 64-bit float

		{name: "MOVVaddr", argLength: 1, reg: regInfo{inputs: []regMask{buildReg("SP") | buildReg("SB")}, outputs: []regMask{gp}}, aux: "SymOff", asm: "MOVV", rematerializeable: true, symEffect: "Addr"}, // arg0 + auxInt + aux.(*gc.Sym), arg0=SP/SB

		{name: "MOVBload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVB", typ: "Int8", faultOnNilArg0: true, symEffect: "Read"},     // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVBUload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVBU", typ: "UInt8", faultOnNilArg0: true, symEffect: "Read"},  // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVHload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVH", typ: "Int16", faultOnNilArg0: true, symEffect: "Read"},    // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVHUload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVHU", typ: "UInt16", faultOnNilArg0: true, symEffect: "Read"}, // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVWload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVW", typ: "Int32", faultOnNilArg0: true, symEffect: "Read"},    // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVWUload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVWU", typ: "UInt32", faultOnNilArg0: true, symEffect: "Read"}, // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVVload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVV", typ: "UInt64", faultOnNilArg0: true, symEffect: "Read"},   // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVFload", argLength: 2, reg: fpload, aux: "SymOff", asm: "MOVF", typ: "Float32", faultOnNilArg0: true, symEffect: "Read"},  // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVDload", argLength: 2, reg: fpload, aux: "SymOff", asm: "MOVD", typ: "Float64", faultOnNilArg0: true, symEffect: "Read"},  // load from arg0 + auxInt + aux.  arg1=mem.

		// register indexed load
		{name: "MOVVloadidx", argLength: 3, reg: gp2load, asm: "MOVV", typ: "UInt64"},   // load 64-bit dword from arg0 + arg1, arg2 = mem.
		{name: "MOVWloadidx", argLength: 3, reg: gp2load, asm: "MOVW", typ: "Int32"},    // load 32-bit word from arg0 + arg1, sign-extended to 64-bit, arg2=mem.
		{name: "MOVWUloadidx", argLength: 3, reg: gp2load, asm: "MOVWU", typ: "UInt32"}, // load 32-bit word from arg0 + arg1, zero-extended to 64-bit, arg2=mem.
		{name: "MOVHloadidx", argLength: 3, reg: gp2load, asm: "MOVH", typ: "Int16"},    // load 16-bit word from arg0 + arg1, sign-extended to 64-bit, arg2=mem.
		{name: "MOVHUloadidx", argLength: 3, reg: gp2load, asm: "MOVHU", typ: "UInt16"}, // load 16-bit word from arg0 + arg1, zero-extended to 64-bit, arg2=mem.
		{name: "MOVBloadidx", argLength: 3, reg: gp2load, asm: "MOVB", typ: "Int8"},     // load 8-bit word from arg0 + arg1, sign-extended to 64-bit, arg2=mem.
		{name: "MOVBUloadidx", argLength: 3, reg: gp2load, asm: "MOVBU", typ: "UInt8"},  // load 8-bit word from arg0 + arg1, zero-extended to 64-bit, arg2=mem.
		{name: "MOVFloadidx", argLength: 3, reg: fp2load, asm: "MOVF", typ: "Float32"},  // load 32-bit float from arg0 + arg1, arg2=mem.
		{name: "MOVDloadidx", argLength: 3, reg: fp2load, asm: "MOVD", typ: "Float64"},  // load 64-bit float from arg0 + arg1, arg2=mem.

		{name: "MOVBstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVB", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 1 byte of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVHstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVH", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 2 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVWstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVW", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 4 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVVstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVV", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 8 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVFstore", argLength: 3, reg: fpstore, aux: "SymOff", asm: "MOVF", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 4 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVDstore", argLength: 3, reg: fpstore, aux: "SymOff", asm: "MOVD", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 8 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.

		// register indexed store
		{name: "MOVBstoreidx", argLength: 4, reg: gpstore2, asm: "MOVB", typ: "Mem"}, // store 1 byte of arg2 to arg0 + arg1, arg3 = mem.
		{name: "MOVHstoreidx", argLength: 4, reg: gpstore2, asm: "MOVH", typ: "Mem"}, // store 2 bytes of arg2 to arg0 + arg1, arg3 = mem.
		{name: "MOVWstoreidx", argLength: 4, reg: gpstore2, asm: "MOVW", typ: "Mem"}, // store 4 bytes of arg2 to arg0 + arg1, arg3 = mem.
		{name: "MOVVstoreidx", argLength: 4, reg: gpstore2, asm: "MOVV", typ: "Mem"}, // store 8 bytes of arg2 to arg0 + arg1, arg3 = mem.
		{name: "MOVFstoreidx", argLength: 4, reg: fpstore2, asm: "MOVF", typ: "Mem"}, // store 32-bit float of arg2 to arg0 + arg1, arg3=mem.
		{name: "MOVDstoreidx", argLength: 4, reg: fpstore2, asm: "MOVD", typ: "Mem"}, // store 64-bit float of arg2 to arg0 + arg1, arg3=mem.

		{name: "MOVBstorezero", argLength: 2, reg: gpstore0, aux: "SymOff", asm: "MOVB", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 1 byte of zero to arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVHstorezero", argLength: 2, reg: gpstore0, aux: "SymOff", asm: "MOVH", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 2 bytes of zero to arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVWstorezero", argLength: 2, reg: gpstore0, aux: "SymOff", asm: "MOVW", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 4 bytes of zero to arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVVstorezero", argLength: 2, reg: gpstore0, aux: "SymOff", asm: "MOVV", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 8 bytes of zero to arg0 + auxInt + aux.  ar12=mem.

		// register indexed store zero
		{name: "MOVBstorezeroidx", argLength: 3, reg: gpstore, asm: "MOVB", typ: "Mem"}, // store 1 byte of zero to arg0 + arg1, arg2 = mem.
		{name: "MOVHstorezeroidx", argLength: 3, reg: gpstore, asm: "MOVH", typ: "Mem"}, // store 2 bytes of zero to arg0 + arg1, arg2 = mem.
		{name: "MOVWstorezeroidx", argLength: 3, reg: gpstore, asm: "MOVW", typ: "Mem"}, // store 4 bytes of zero to arg0 + arg1, arg2 = mem.
		{name: "MOVVstorezeroidx", argLength: 3, reg: gpstore, asm: "MOVV", typ: "Mem"}, // store 8 bytes of zero to arg0 + arg1, arg2 = mem.

		// moves (no conversion)
		{name: "MOVWfpgp", argLength: 1, reg: fpgp, asm: "MOVW"}, // move float32 to int32 (no conversion).
		{name: "MOVWgpfp", argLength: 1, reg: gpfp, asm: "MOVW"}, // move int32 to float32 (no conversion).
		{name: "MOVVfpgp", argLength: 1, reg: fpgp, asm: "MOVV"}, // move float64 to int64 (no conversion).
		{name: "MOVVgpfp", argLength: 1, reg: gpfp, asm: "MOVV"}, // move int64 to float64 (no conversion).

		// conversions
		{name: "MOVBreg", argLength: 1, reg: gp11, asm: "MOVB"},   // move from arg0, sign-extended from byte
		{name: "MOVBUreg", argLength: 1, reg: gp11, asm: "MOVBU"}, // move from arg0, unsign-extended from byte
		{name: "MOVHreg", argLength: 1, reg: gp11, asm: "MOVH"},   // move from arg0, sign-extended from half
		{name: "MOVHUreg", argLength: 1, reg: gp11, asm: "MOVHU"}, // move from arg0, unsign-extended from half
		{name: "MOVWreg", argLength: 1, reg: gp11, asm: "MOVW"},   // move from arg0, sign-extended from word
		{name: "MOVWUreg", argLength: 1, reg: gp11, asm: "MOVWU"}, // move from arg0, unsign-extended from word
		{name: "MOVVreg", argLength: 1, reg: gp11, asm: "MOVV"},   // move from arg0

		{name: "MOVVnop", argLength: 1, reg: regInfo{inputs: []regMask{gp}, outputs: []regMask{gp}}, resultInArg0: true}, // nop, return arg0 in same register

		{name: "MOVWF", argLength: 1, reg: fp11, asm: "MOVWF"},     // int32 -> float32
		{name: "MOVWD", argLength: 1, reg: fp11, asm: "MOVWD"},     // int32 -> float64
		{name: "MOVVF", argLength: 1, reg: fp11, asm: "MOVVF"},     // int64 -> float32
		{name: "MOVVD", argLength: 1, reg: fp11, asm: "MOVVD"},     // int64 -> float64
		{name: "TRUNCFW", argLength: 1, reg: fp11, asm: "TRUNCFW"}, // float32 -> int32
		{name: "TRUNCDW", argLength: 1, reg: fp11, asm: "TRUNCDW"}, // float64 -> int32
		{name: "TRUNCFV", argLength: 1, reg: fp11, asm: "TRUNCFV"}, // float32 -> int64
		{name: "TRUNCDV", argLength: 1, reg: fp11, asm: "TRUNCDV"}, // float64 -> int64
		{name: "MOVFD", argLength: 1, reg: fp11, asm: "MOVFD"},     // float32 -> float64
		{name: "MOVDF", argLength: 1, reg: fp11, asm: "MOVDF"},     // float64 -> float32

		// Round ops to block fused-multiply-add extraction.
		{name: "LoweredRound32F", argLength: 1, reg: fp11, resultInArg0: true},
		{name: "LoweredRound64F", argLength: 1, reg: fp11, resultInArg0: true},

		// function calls
		{name: "CALLstatic", argLength: -1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                                               // call static function aux.(*obj.LSym).  last arg=mem, auxint=argsize, returns mem
		{name: "CALLtail", argLength: -1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true, tailCall: true},                                 // tail call static function aux.(*obj.LSym).  last arg=mem, auxint=argsize, returns mem
		{name: "CALLclosure", argLength: -1, reg: regInfo{inputs: []regMask{gpsp, buildReg("R29"), 0}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true}, // call function via closure.  arg0=codeptr, arg1=closure, last arg=mem, auxint=argsize, returns mem
		{name: "CALLinter", argLength: -1, reg: regInfo{inputs: []regMask{gp}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                         // call fn by pointer.  arg0=codeptr, last arg=mem, auxint=argsize, returns mem

		// duffzero
		// arg0 = address of memory to zero
		// arg1 = mem
		// auxint = offset into duffzero code to start executing
		// returns mem
		// R20 aka loong64.REGRT1 changed as side effect
		{
			name:      "DUFFZERO",
			aux:       "Int64",
			argLength: 2,
			reg: regInfo{
				inputs:   []regMask{buildReg("R20")},
				clobbers: buildReg("R20 R1"),
			},
			typ:            "Mem",
			faultOnNilArg0: true,
		},

		// duffcopy
		// arg0 = address of dst memory (in R21, changed as side effect)
		// arg1 = address of src memory (in R20, changed as side effect)
		// arg2 = mem
		// auxint = offset into duffcopy code to start executing
		// returns mem
		{
			name:      "DUFFCOPY",
			aux:       "Int64",
			argLength: 3,
			reg: regInfo{
				inputs:   []regMask{buildReg("R21"), buildReg("R20")},
				clobbers: buildReg("R20 R21 R1"),
			},
			typ:            "Mem",
			faultOnNilArg0: true,
			faultOnNilArg1: true,
		},

		// large or unaligned zeroing
		// arg0 = address of memory to zero (in R20, changed as side effect)
		// arg1 = address of the last element to zero
		// arg2 = mem
		// auxint = alignment
		// returns mem
		//	MOVx	R0, (R20)
		//	ADDV	$sz, R20
		//	BGEU	Rarg1, R20, -2(PC)
		{
			name:      "LoweredZero",
			aux:       "Int64",
			argLength: 3,
			reg: regInfo{
				inputs:   []regMask{buildReg("R20"), gp},
				clobbers: buildReg("R20"),
			},
			typ:            "Mem",
			faultOnNilArg0: true,
		},

		// large or unaligned move
		// arg0 = address of dst memory (in R21, changed as side effect)
		// arg1 = address of src memory (in R20, changed as side effect)
		// arg2 = address of the last element of src
		// arg3 = mem
		// auxint = alignment
		// returns mem
		//	MOVx	(R20), Rtmp
		//	MOVx	Rtmp, (R21)
		//	ADDV	$sz, R20
		//	ADDV	$sz, R21
		//	BGEU	Rarg2, R20, -4(PC)
		{
			name:      "LoweredMove",
			aux:       "Int64",
			argLength: 4,
			reg: regInfo{
				inputs:   []regMask{buildReg("R21"), buildReg("R20"), gp},
				clobbers: buildReg("R20 R21"),
			},
			typ:            "Mem",
			faultOnNilArg0: true,
			faultOnNilArg1: true,
		},

		// atomic loads.
		// load from arg0. arg1=mem.
		// returns <value,memory> so they can be properly ordered with other loads.
		{name: "LoweredAtomicLoad8", argLength: 2, reg: gpload, faultOnNilArg0: true},
		{name: "LoweredAtomicLoad32", argLength: 2, reg: gpload, faultOnNilArg0: true},
		{name: "LoweredAtomicLoad64", argLength: 2, reg: gpload, faultOnNilArg0: true},

		// atomic stores.
		// store arg1 to arg0. arg2=mem. returns memory.
		{name: "LoweredAtomicStore8", argLength: 3, reg: gpstore, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicStore32", argLength: 3, reg: gpstore, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicStore64", argLength: 3, reg: gpstore, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicStore8Variant", argLength: 3, reg: gpstore, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicStore32Variant", argLength: 3, reg: gpstore, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicStore64Variant", argLength: 3, reg: gpstore, faultOnNilArg0: true, hasSideEffects: true},

		// atomic exchange.
		// store arg1 to arg0. arg2=mem. returns <old content of *arg0, memory>.
		{name: "LoweredAtomicExchange32", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicExchange64", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},

		// atomic exchange variant.
		// store arg1 to arg0. arg2=mem. returns <old content of *arg0, memory>. auxint must be zero.
		// AMSWAPDBB   Rarg1, (Rarg0), Rout
		{name: "LoweredAtomicExchange8Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},

		// atomic add.
		// *arg0 += arg1. arg2=mem. returns <new content of *arg0, memory>.
		{name: "LoweredAtomicAdd32", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicAdd64", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},

		// atomic compare and swap.
		// arg0 = pointer, arg1 = old value, arg2 = new value, arg3 = memory.
		// if *arg0 == arg1 {
		//   *arg0 = arg2
		//   return (true, memory)
		// } else {
		//   return (false, memory)
		// }
		// MOVV $0, Rout
		// DBAR 0x14
		// LL	(Rarg0), Rtmp
		// BNE	Rtmp, Rarg1, 4(PC)
		// MOVV Rarg2, Rout
		// SC	Rout, (Rarg0)
		// BEQ	Rout, -4(PC)
		// DBAR 0x12
		{name: "LoweredAtomicCas32", argLength: 4, reg: gpcas, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicCas64", argLength: 4, reg: gpcas, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},

		// atomic compare and swap variant.
		// arg0 = pointer, arg1 = old value, arg2 = new value, arg3 = memory. auxint must be zero.
		// if *arg0 == arg1 {
		//   *arg0 = arg2
		//   return (true, memory)
		// } else {
		//   return (false, memory)
		// }
		// MOVV         $0, Rout
		// MOVV         Rarg1, Rtmp
		// AMCASDBx     Rarg2, (Rarg0), Rtmp
		// BNE          Rarg1, Rtmp, 2(PC)
		// MOVV         $1, Rout
		// NOP
		{name: "LoweredAtomicCas64Variant", argLength: 4, reg: gpcas, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicCas32Variant", argLength: 4, reg: gpcas, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},

		// Atomic 32 bit AND/OR.
		// *arg0 &= (|=) arg1. arg2=mem. returns nil.
		{name: "LoweredAtomicAnd32", argLength: 3, reg: gpxchg, asm: "AMANDDBW", resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicOr32", argLength: 3, reg: gpxchg, asm: "AMORDBW", resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},

		// Atomic 32,64 bit AND/OR.
		// *arg0 &= (|=) arg1. arg2=mem. returns <old content of *arg0, memory>. auxint must be zero.
		{name: "LoweredAtomicAnd32value", argLength: 3, reg: gpxchg, asm: "AMANDDBW", resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicAnd64value", argLength: 3, reg: gpxchg, asm: "AMANDDBV", resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicOr32value", argLength: 3, reg: gpxchg, asm: "AMORDBW", resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicOr64value", argLength: 3, reg: gpxchg, asm: "AMORDBV", resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},

		// pseudo-ops
		{name: "LoweredNilCheck", argLength: 2, reg: regInfo{inputs: []regMask{gpg}}, nilCheck: true, faultOnNilArg0: true}, // panic if arg0 is nil.  arg1=mem.

		{name: "FPFlagTrue", argLength: 1, reg: readflags},  // bool, true if FP flag is true
		{name: "FPFlagFalse", argLength: 1, reg: readflags}, // bool, true if FP flag is false

		// Scheduler ensures LoweredGetClosurePtr occurs only in entry block,
		// and sorts it to the very beginning of the block to prevent other
		// use of R22 (loong64.REGCTXT, the closure pointer)
		{name: "LoweredGetClosurePtr", reg: regInfo{outputs: []regMask{buildReg("R29")}}, zeroWidth: true},

		// LoweredGetCallerSP returns the SP of the caller of the current function. arg0=mem.
		{name: "LoweredGetCallerSP", argLength: 1, reg: gp01, rematerializeable: true},

		// LoweredGetCallerPC evaluates to the PC to which its "caller" will return.
		// I.e., if f calls g "calls" sys.GetCallerPC,
		// the result should be the PC within f that g will return to.
		// See runtime/stubs.go for a more detailed discussion.
		{name: "LoweredGetCallerPC", reg: gp01, rematerializeable: true},

		// LoweredWB invokes runtime.gcWriteBarrier. arg0=mem, auxint=# of buffer entries needed
		// It saves all GP registers if necessary,
		// but clobbers R1 (LR) because it's a call
		// and R30 (REGTMP).
		// Returns a pointer to a write barrier buffer in R29.
		{name: "LoweredWB", argLength: 1, reg: regInfo{clobbers: (callerSave &^ gpg) | buildReg("R1"), outputs: []regMask{buildReg("R29")}}, clobberFlags: true, aux: "Int64"},

		// Do data barrier. arg0=memorys
		{name: "LoweredPubBarrier", argLength: 1, asm: "DBAR", hasSideEffects: true},

		// There are three of these functions so that they can have three different register inputs.
		// When we check 0 <= c <= cap (A), then 0 <= b <= c (B), then 0 <= a <= b (C), we want the
		// default registers to match so we don't need to copy registers around unnecessarily.
		{name: "LoweredPanicBoundsA", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r3, r4}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in genericOps.go).
		{name: "LoweredPanicBoundsB", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r2, r3}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in genericOps.go).
		{name: "LoweredPanicBoundsC", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r1, r2}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in genericOps.go).
	}

	blocks := []blockData{
		{name: "EQ", controls: 1},
		{name: "NE", controls: 1},
		{name: "LTZ", controls: 1},  // < 0
		{name: "LEZ", controls: 1},  // <= 0
		{name: "GTZ", controls: 1},  // > 0
		{name: "GEZ", controls: 1},  // >= 0
		{name: "FPT", controls: 1},  // FP flag is true
		{name: "FPF", controls: 1},  // FP flag is false
		{name: "BEQ", controls: 2},  // controls[0] == controls[1]
		{name: "BNE", controls: 2},  // controls[0] == controls[1]
		{name: "BGE", controls: 2},  // controls[0] >= controls[1]
		{name: "BLT", controls: 2},  // controls[0] < controls[1]
		{name: "BGEU", controls: 2}, // controls[0] >= controls[1], unsigned
		{name: "BLTU", controls: 2}, // controls[0] < controls[1], unsigned
	}

	archs = append(archs, arch{
		name:     "LOONG64",
		pkg:      "cmd/internal/obj/loong64",
		genfile:  "../../loong64/ssa.go",
		ops:      ops,
		blocks:   blocks,
		regnames: regNamesLOONG64,
		// TODO: support register ABI on loong64
		ParamIntRegNames:   "R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19",
		ParamFloatRegNames: "F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15",
		gpregmask:          gp,
		fpregmask:          fp,
		framepointerreg:    -1, // not used
		linkreg:            int8(num["R1"]),
	})
}

"""



```