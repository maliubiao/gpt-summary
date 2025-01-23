Response:
Let's break down the thought process to analyze the given Go code snippet.

1. **Understanding the Goal:** The request asks for the functionality of the provided Go code, which is a part of the Go compiler for the ARM64 architecture. The core task is to describe what this specific file does within the larger context of the compiler.

2. **Initial Scan and Keywords:**  Quickly scanning the code reveals key terms and patterns:
    * `package main`: Indicates this is an executable, but in the context of the compiler, it's likely a code generation tool.
    * `import "strings"`:  Suggests string manipulation, potentially for naming things.
    * `// Notes:` and comments describing register usage, data types, and instruction suffixes. This points to low-level architecture-specific details.
    * `var regNamesARM64`:  A list of register names for the ARM64 architecture.
    * `func init()`:  A function that runs automatically when the package is initialized. This is where the core logic seems to reside.
    * `buildReg`: A helper function to create register masks.
    * `regInfo`: A struct likely holding information about register usage for instructions.
    * `opData`: A struct containing data about individual ARM64 instructions (name, arguments, registers, assembly representation, etc.).
    * `blockData`: A struct describing control flow block types (e.g., conditional branches).
    * `archs`: A slice containing architecture-specific information.
    * Suffixes like `D`, `W`, `H`, `S`:  Indicate data sizes.
    * Assembly mnemonics like `ADD`, `SUB`, `MOV`, `CMP`.

3. **Inferring the Purpose:** Based on the keywords and structure, it becomes clear that this code defines the set of supported ARM64 instructions for the Go compiler's intermediate representation (SSA - Static Single Assignment). It maps Go-level operations to specific ARM64 assembly instructions, along with details about register usage, data types, and how these instructions affect flags.

4. **Dissecting the `init` function:** This is the heart of the code.
    * **Register Names and Mapping:** The code first establishes a mapping between register names (strings like "R0", "SP") and integer identifiers. This is crucial for later referencing registers.
    * **`buildReg` Function:** This function takes a space-separated string of register names and converts it into a bitmask (`regMask`). Each bit in the mask represents a register.
    * **Register Masks (`gp`, `fp`, `callerSave`, etc.):**  The code defines common sets of registers using `buildReg`. `gp` likely stands for general-purpose registers, `fp` for floating-point registers, and `callerSave` for registers that a function call might overwrite.
    * **`regInfo` Structs:**  These structs define the input and output register requirements and effects of various operations. For instance, `gp21` means an operation takes two general-purpose registers as input and produces one general-purpose register as output. The `flags` suffix indicates that flags are also involved.
    * **`opData` Structs:** This is the core data structure. Each `opData` entry describes a single Go SSA operation that can be translated to ARM64 assembly. Key fields include:
        * `name`: The name of the SSA operation (e.g., "ADD", "MOVDload").
        * `argLength`: The number of arguments the operation takes.
        * `reg`: A `regInfo` struct describing register usage.
        * `typ`: The Go types involved.
        * `asm`: The corresponding ARM64 assembly instruction.
        * `aux`:  Additional information (like a constant value or a symbol).
        * `commutative`: Whether the operation is commutative (order of operands doesn't matter).
        * Other flags like `rematerializeable`, `faultOnNilArg0`, `call`, `tailCall`, etc., providing more semantic information.
    * **`blockData` Structs:** These define the different types of control flow blocks the compiler can generate for ARM64 (conditional branches, jump tables).
    * **`archs` Slice:** This collects all the ARM64-specific data (ops, blocks, register names) into a single structure.

5. **Reasoning about Go Functionality:**  The code doesn't implement a specific Go *language* feature directly. Instead, it's part of the *compiler* that *enables* those features on the ARM64 architecture. It defines how the compiler's internal representation of operations (like addition, memory access, function calls) is translated into actual ARM64 instructions.

6. **Illustrative Go Code Examples:** To demonstrate the *effect* of this code, you need to show Go code that would generate the corresponding ARM64 instructions. This involves simple arithmetic operations, memory accesses, and function calls. Think about how the `opData` entries relate to these Go constructs. For example:
    * `a + b` might use the `ADD` op.
    * `x := *ptr` might use the `MOVDload` op.
    * `f()` might use `CALLstatic` or `CALLclosure`.

7. **Command-Line Parameters (If Applicable):** This specific file doesn't directly handle command-line parameters. Command-line flags for the Go compiler (like `-gcflags`, `-ldflags`, and architecture-specific flags) are processed in other parts of the `cmd/compile` package.

8. **Common Pitfalls:** The code itself is data-driven. Errors are most likely to occur in:
    * **Incorrect Register Masks:**  Defining the wrong input/output registers for an operation.
    * **Incorrect Assembly Mnemonics:**  Using the wrong ARM64 instruction.
    * **Missing or Incorrect `aux` Information:**  For constants or symbols.
    * **Forgetting Flags:**  Not accounting for how instructions affect processor flags.

9. **Structuring the Answer:**  Organize the findings logically:
    * Start with a high-level overview of the file's purpose.
    * Explain the key data structures (`regNamesARM64`, `regInfo`, `opData`, `blockData`).
    * Provide Go code examples illustrating how the defined operations are used.
    * Explain the role of command-line parameters (even if this file doesn't handle them directly).
    * Point out common mistakes developers might make when working with this kind of code.

10. **Refinement:**  Review the generated answer for clarity, accuracy, and completeness. Ensure the Go examples are simple and directly related to the described functionality. Make sure the explanation of command-line arguments is accurate (that this file doesn't handle them).
这个 Go 语言代码文件 `go/src/cmd/compile/internal/ssa/_gen/ARM64Ops.go` 的主要功能是**定义了 Go 编译器在 ARM64 架构下进行 SSA (Static Single Assignment) 中间表示到机器码转换时所使用的操作码 (ops) 和控制流块 (blocks) 的详细信息。**

更具体地说，它做了以下几件事情：

1. **定义 ARM64 寄存器名称:**  `regNamesARM64` 变量存储了 ARM64 架构中使用的通用寄存器、浮点寄存器和一些特殊寄存器的名称。这个列表是后续定义操作码时引用寄存器的基础。

2. **创建寄存器名称到编号的映射:**  `init` 函数中的代码遍历 `regNamesARM64`，创建了一个从寄存器名称（字符串）到其对应整数编号的映射。这方便了在定义操作码时使用寄存器。

3. **定义寄存器掩码 (regMask):**  `buildReg` 函数用于根据给定的寄存器名称字符串（用空格分隔）生成一个位掩码。这个掩码可以表示一个或多个寄存器的集合。代码中定义了一些常用的寄存器掩码，例如 `gp` (通用寄存器), `fp` (浮点寄存器), `callerSave` (调用者保存的寄存器) 等。

4. **定义寄存器信息 (regInfo):** `regInfo` 结构体用于描述一个操作码的输入和输出寄存器需求。例如，一个加法操作可能需要两个输入寄存器和一个输出寄存器。`regInfo` 还包含一些其他信息，例如是否会修改标志位等。

5. **定义操作码数据 (opData):** `opData` 结构体是这个文件的核心。它定义了每一个 Go SSA 操作码的详细信息，包括：
    * `name`: 操作码的名称，例如 "ADD", "MOVDload"。
    * `argLength`: 操作码接受的参数数量。
    * `reg`:  与该操作码关联的 `regInfo`，描述了寄存器使用情况。
    * `typ`: 操作码操作的数据类型。
    * `asm`:  对应的 ARM64 汇编指令的助记符。
    * `aux`:  辅助信息，例如常量值、符号信息等。
    * 其他属性，例如是否可交换操作数 (`commutative`)，是否会产生副作用 (`hasSideEffects`)，是否是调用指令 (`call`) 等。

6. **定义控制流块数据 (blockData):** `blockData` 结构体定义了 Go SSA 中可以使用的控制流块类型，例如条件跳转 (`EQ`, `NE`, `LT` 等) 和跳转表 (`JUMPTABLE`)。它描述了每个块的控制参数数量以及可能的辅助信息。

7. **定义架构信息 (arch):**  `archs` 变量是一个包含 `arch` 结构体的切片。这个结构体汇总了特定架构（在这里是 ARM64）的操作码、控制流块、寄存器名称等信息。这是 Go 编译器后端处理特定架构的关键数据。

**它是什么 Go 语言功能的实现？**

这个文件本身并不直接实现某个特定的 Go *语言* 功能。相反，它为 Go 编译器在 ARM64 架构上 *实现* 这些功能提供了底层的指令映射和寄存器使用规则。

举例来说，当 Go 代码中执行一个整数加法操作时，编译器会将其转换为 SSA 中间表示中的一个 `ADD` 操作码。`ARM64Ops.go` 文件中关于 `ADD` 操作码的定义 (`{name: "ADD", argLength: 2, reg: gp21, asm: "ADD", commutative: true}`) 就告诉编译器：

* 这个 SSA `ADD` 操作对应 ARM64 的 `ADD` 汇编指令。
* 它需要两个通用寄存器作为输入 (`gp21` 表示两个输入，一个输出都是通用寄存器)。
* 该操作是可交换的。

**Go 代码举例说明:**

```go
package main

func add(a, b int64) int64 {
	return a + b
}

func main() {
	x := 10
	y := 20
	sum := add(int64(x), int64(y))
	println(sum)
}
```

**代码推理 (假设):**

当编译上面的 `add` 函数时，Go 编译器会生成类似以下的 SSA 中间代码 (简化表示)：

```
v1 = Param <int64> {a}
v2 = Param <int64> {b}
v3 = Add64 v1 v2
Return v3
```

根据 `ARM64Ops.go` 中的定义，`Add64` 可能会被映射到 `opData` 中 `name: "ADD"` 的条目。假设输入参数 `a` 和 `b` 分别被分配到寄存器 `R0` 和 `R1`，那么编译器可能会生成以下的 ARM64 汇编代码：

```assembly
ADD R0, R1, R0  // R0 = R0 + R1
RET
```

**假设的输入与输出:**

* **输入 (Go SSA):**  `Add64` 操作，输入为两个表示 `int64` 类型的 SSA 值。
* **输出 (ARM64 汇编):** `ADD` 指令，将两个输入寄存器的值相加，结果存储到一个输出寄存器中。

**命令行参数的具体处理:**

这个文件本身并不直接处理命令行参数。Go 编译器的命令行参数处理逻辑在 `cmd/compile` 包的其他文件中实现。 然而，一些命令行参数可能会影响到代码生成过程，从而间接地影响到这里定义的操作码的使用方式。例如：

* **`-gcflags`**:  可以传递额外的参数给 Go 编译器。某些 `gcflags` 可能会影响到 SSA 的生成和优化，从而影响最终选择的操作码。
* **`-N`**: 禁用优化。禁用优化可能会导致编译器生成更直接、更少优化的代码，选择的操作码可能更贴近原始的 Go 代码结构。
* **`-l`**: 禁用内联。禁用内联可能会导致更多的函数调用，从而涉及到 `CALLstatic` 或 `CALLclosure` 等操作码的使用。

**使用者易犯错的点:**

由于这个文件是 Go 编译器内部的一部分，普通的 Go 开发者不会直接修改或使用它。 易犯错的点主要集中在**编译器开发者**身上：

1. **错误的寄存器约束:**  在 `regInfo` 中错误地指定了输入或输出寄存器，可能导致寄存器分配错误，产生错误的机器码。例如，如果某个操作实际会修改标志位，但在 `regInfo` 中没有标记，可能会导致后续依赖标志位的代码出错。

2. **错误的汇编指令助记符:**  在 `asm` 字段中使用了错误的 ARM64 汇编指令助记符，会导致汇编器无法识别，编译失败。

3. **`aux` 信息的错误使用:**  对于需要辅助信息的操作码，例如加载常量，如果 `aux` 字段的信息不正确或类型不匹配，会导致编译错误或生成错误的机器码。

4. **忽略指令的副作用:**  没有正确标记操作码的副作用 (`hasSideEffects`) 可能会导致编译器进行错误的优化，例如删除本不应该删除的指令。

5. **不正确的 `commutative` 标记:**  错误地标记一个不可交换的操作为可交换的，可能会导致编译器在某些优化场景下交换操作数的顺序，产生错误的结果。

**例子 (假设一个错误):**

假设 `MUL` 操作的 `regInfo` 被错误地定义为 `gp11` (一个输入，一个输出)，而不是 `gp21` (两个输入，一个输出)。

```diff
--- a/go/src/cmd/compile/internal/ssa/_gen/ARM64Ops.go
+++ b/go/src/cmd/compile/internal/ssa/_gen/ARM64Ops.go
@@ -175,7 +175,7 @@
 		{name: "SUBconst", argLength: 1, reg: gp11, asm: "SUB", aux: "Int64"},                                         // arg0 - auxInt
 		{name: "SBCSflags", argLength: 3, reg: gp2flags1flags, typ: "(UInt64,Flags)", asm: "SBCS"},                    // arg0-(arg1+borrowing), set flags.
 		{name: "SUBSflags", argLength: 2, reg: gp21flags, typ: "(UInt64,Flags)", asm: "SUBS"},                         // arg0 - arg1, set flags.
-		{name: "MUL", argLength: 2, reg: gp21, asm: "MUL", commutative: true},                                         // arg0 * arg1
+		{name: "MUL", argLength: 2, reg: gp11, asm: "MUL", commutative: true},                                         // arg0 * arg1  <-- 错误：应该是 gp21
 		{name: "MULW", argLength: 2, reg: gp21, asm: "MULW", commutative: true},                                       // arg0 * arg1, 32-bit
 		{name: "MNEG", argLength: 2, reg: gp21, asm: "MNEG", commutative: true},                                       // -arg0 * arg1
 		{name: "MNEGW", argLength: 2, reg: gp21, asm: "MNEGW", commutative: true},                                     // -arg0 * arg1, 32-bit
```

在这种情况下，当编译器遇到一个乘法操作时，它会认为 `MUL` 操作只需要一个输入寄存器，这会导致寄存器分配器无法找到第二个输入操作数，从而导致编译错误。

总而言之，`ARM64Ops.go` 是 Go 编译器在 ARM64 架构下进行代码生成的核心配置文件，它将 Go 的高级抽象操作映射到底层的机器指令，确保 Go 代码能够在 ARM64 处理器上正确执行。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/_gen/ARM64Ops.go的go语言实现的一部分， 请列举一下它的功能, 　
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
//    register (R27).
//  - All 32-bit Ops will zero the upper 32 bits of the destination register.

// Suffixes encode the bit width of various instructions.
// D (double word) = 64 bit
// W (word)        = 32 bit
// H (half word)   = 16 bit
// HU              = 16 bit unsigned
// B (byte)        = 8 bit
// BU              = 8 bit unsigned
// S (single)      = 32 bit float
// D (double)      = 64 bit float

// Note: registers not used in regalloc are not included in this list,
// so that regmask stays within int64
// Be careful when hand coding regmasks.
var regNamesARM64 = []string{
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
	"R13",
	"R14",
	"R15",
	"R16",
	"R17",
	"R18", // platform register, not used
	"R19",
	"R20",
	"R21",
	"R22",
	"R23",
	"R24",
	"R25",
	"R26",
	// R27 = REGTMP not used in regalloc
	"g",   // aka R28
	"R29", // frame pointer, not used
	"R30", // aka REGLINK
	"SP",  // aka R31

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
	if len(regNamesARM64) > 64 {
		panic("too many registers")
	}
	num := map[string]int{}
	for i, name := range regNamesARM64 {
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
		gp         = buildReg("R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30")
		gpg        = gp | buildReg("g")
		gpsp       = gp | buildReg("SP")
		gpspg      = gpg | buildReg("SP")
		gpspsbg    = gpspg | buildReg("SB")
		fp         = buildReg("F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31")
		callerSave = gp | fp | buildReg("g") // runtime.setg (and anything calling it) may clobber g
		r0         = buildReg("R0")
		r1         = buildReg("R1")
		r2         = buildReg("R2")
		r3         = buildReg("R3")
	)
	// Common regInfo
	var (
		gp01           = regInfo{inputs: nil, outputs: []regMask{gp}}
		gp0flags1      = regInfo{inputs: []regMask{0}, outputs: []regMask{gp}}
		gp11           = regInfo{inputs: []regMask{gpg}, outputs: []regMask{gp}}
		gp11sp         = regInfo{inputs: []regMask{gpspg}, outputs: []regMask{gp}}
		gp1flags       = regInfo{inputs: []regMask{gpg}}
		gp1flags1      = regInfo{inputs: []regMask{gpg}, outputs: []regMask{gp}}
		gp11flags      = regInfo{inputs: []regMask{gpg}, outputs: []regMask{gp, 0}}
		gp21           = regInfo{inputs: []regMask{gpg, gpg}, outputs: []regMask{gp}}
		gp21nog        = regInfo{inputs: []regMask{gp, gp}, outputs: []regMask{gp}}
		gp21flags      = regInfo{inputs: []regMask{gp, gp}, outputs: []regMask{gp, 0}}
		gp2flags       = regInfo{inputs: []regMask{gpg, gpg}}
		gp2flags1      = regInfo{inputs: []regMask{gp, gp}, outputs: []regMask{gp}}
		gp2flags1flags = regInfo{inputs: []regMask{gp, gp, 0}, outputs: []regMask{gp, 0}}
		gp2load        = regInfo{inputs: []regMask{gpspsbg, gpg}, outputs: []regMask{gp}}
		gp31           = regInfo{inputs: []regMask{gpg, gpg, gpg}, outputs: []regMask{gp}}
		gpload         = regInfo{inputs: []regMask{gpspsbg}, outputs: []regMask{gp}}
		gpload2        = regInfo{inputs: []regMask{gpspsbg}, outputs: []regMask{gpg, gpg}}
		gpstore        = regInfo{inputs: []regMask{gpspsbg, gpg}}
		gpstore0       = regInfo{inputs: []regMask{gpspsbg}}
		gpstore2       = regInfo{inputs: []regMask{gpspsbg, gpg, gpg}}
		gpxchg         = regInfo{inputs: []regMask{gpspsbg, gpg}, outputs: []regMask{gp}}
		gpcas          = regInfo{inputs: []regMask{gpspsbg, gpg, gpg}, outputs: []regMask{gp}}
		fp01           = regInfo{inputs: nil, outputs: []regMask{fp}}
		fp11           = regInfo{inputs: []regMask{fp}, outputs: []regMask{fp}}
		fpgp           = regInfo{inputs: []regMask{fp}, outputs: []regMask{gp}}
		gpfp           = regInfo{inputs: []regMask{gp}, outputs: []regMask{fp}}
		fp21           = regInfo{inputs: []regMask{fp, fp}, outputs: []regMask{fp}}
		fp31           = regInfo{inputs: []regMask{fp, fp, fp}, outputs: []regMask{fp}}
		fp2flags       = regInfo{inputs: []regMask{fp, fp}}
		fp1flags       = regInfo{inputs: []regMask{fp}}
		fpload         = regInfo{inputs: []regMask{gpspsbg}, outputs: []regMask{fp}}
		fp2load        = regInfo{inputs: []regMask{gpspsbg, gpg}, outputs: []regMask{fp}}
		fpstore        = regInfo{inputs: []regMask{gpspsbg, fp}}
		fpstore2       = regInfo{inputs: []regMask{gpspsbg, gpg, fp}}
		readflags      = regInfo{inputs: nil, outputs: []regMask{gp}}
		prefreg        = regInfo{inputs: []regMask{gpspsbg}}
	)
	ops := []opData{
		// binary ops
		{name: "ADCSflags", argLength: 3, reg: gp2flags1flags, typ: "(UInt64,Flags)", asm: "ADCS", commutative: true}, // arg0+arg1+carry, set flags.
		{name: "ADCzerocarry", argLength: 1, reg: gp0flags1, typ: "UInt64", asm: "ADC"},                               // ZR+ZR+carry
		{name: "ADD", argLength: 2, reg: gp21, asm: "ADD", commutative: true},                                         // arg0 + arg1
		{name: "ADDconst", argLength: 1, reg: gp11sp, asm: "ADD", aux: "Int64"},                                       // arg0 + auxInt
		{name: "ADDSconstflags", argLength: 1, reg: gp11flags, typ: "(UInt64,Flags)", asm: "ADDS", aux: "Int64"},      // arg0+auxint, set flags.
		{name: "ADDSflags", argLength: 2, reg: gp21flags, typ: "(UInt64,Flags)", asm: "ADDS", commutative: true},      // arg0+arg1, set flags.
		{name: "SUB", argLength: 2, reg: gp21, asm: "SUB"},                                                            // arg0 - arg1
		{name: "SUBconst", argLength: 1, reg: gp11, asm: "SUB", aux: "Int64"},                                         // arg0 - auxInt
		{name: "SBCSflags", argLength: 3, reg: gp2flags1flags, typ: "(UInt64,Flags)", asm: "SBCS"},                    // arg0-(arg1+borrowing), set flags.
		{name: "SUBSflags", argLength: 2, reg: gp21flags, typ: "(UInt64,Flags)", asm: "SUBS"},                         // arg0 - arg1, set flags.
		{name: "MUL", argLength: 2, reg: gp21, asm: "MUL", commutative: true},                                         // arg0 * arg1
		{name: "MULW", argLength: 2, reg: gp21, asm: "MULW", commutative: true},                                       // arg0 * arg1, 32-bit
		{name: "MNEG", argLength: 2, reg: gp21, asm: "MNEG", commutative: true},                                       // -arg0 * arg1
		{name: "MNEGW", argLength: 2, reg: gp21, asm: "MNEGW", commutative: true},                                     // -arg0 * arg1, 32-bit
		{name: "MULH", argLength: 2, reg: gp21, asm: "SMULH", commutative: true},                                      // (arg0 * arg1) >> 64, signed
		{name: "UMULH", argLength: 2, reg: gp21, asm: "UMULH", commutative: true},                                     // (arg0 * arg1) >> 64, unsigned
		{name: "MULL", argLength: 2, reg: gp21, asm: "SMULL", commutative: true},                                      // arg0 * arg1, signed, 32-bit mult results in 64-bit
		{name: "UMULL", argLength: 2, reg: gp21, asm: "UMULL", commutative: true},                                     // arg0 * arg1, unsigned, 32-bit mult results in 64-bit
		{name: "DIV", argLength: 2, reg: gp21, asm: "SDIV"},                                                           // arg0 / arg1, signed
		{name: "UDIV", argLength: 2, reg: gp21, asm: "UDIV"},                                                          // arg0 / arg1, unsigned
		{name: "DIVW", argLength: 2, reg: gp21, asm: "SDIVW"},                                                         // arg0 / arg1, signed, 32 bit
		{name: "UDIVW", argLength: 2, reg: gp21, asm: "UDIVW"},                                                        // arg0 / arg1, unsigned, 32 bit
		{name: "MOD", argLength: 2, reg: gp21, asm: "REM"},                                                            // arg0 % arg1, signed
		{name: "UMOD", argLength: 2, reg: gp21, asm: "UREM"},                                                          // arg0 % arg1, unsigned
		{name: "MODW", argLength: 2, reg: gp21, asm: "REMW"},                                                          // arg0 % arg1, signed, 32 bit
		{name: "UMODW", argLength: 2, reg: gp21, asm: "UREMW"},                                                        // arg0 % arg1, unsigned, 32 bit

		{name: "FADDS", argLength: 2, reg: fp21, asm: "FADDS", commutative: true},   // arg0 + arg1
		{name: "FADDD", argLength: 2, reg: fp21, asm: "FADDD", commutative: true},   // arg0 + arg1
		{name: "FSUBS", argLength: 2, reg: fp21, asm: "FSUBS"},                      // arg0 - arg1
		{name: "FSUBD", argLength: 2, reg: fp21, asm: "FSUBD"},                      // arg0 - arg1
		{name: "FMULS", argLength: 2, reg: fp21, asm: "FMULS", commutative: true},   // arg0 * arg1
		{name: "FMULD", argLength: 2, reg: fp21, asm: "FMULD", commutative: true},   // arg0 * arg1
		{name: "FNMULS", argLength: 2, reg: fp21, asm: "FNMULS", commutative: true}, // -(arg0 * arg1)
		{name: "FNMULD", argLength: 2, reg: fp21, asm: "FNMULD", commutative: true}, // -(arg0 * arg1)
		{name: "FDIVS", argLength: 2, reg: fp21, asm: "FDIVS"},                      // arg0 / arg1
		{name: "FDIVD", argLength: 2, reg: fp21, asm: "FDIVD"},                      // arg0 / arg1

		{name: "AND", argLength: 2, reg: gp21, asm: "AND", commutative: true}, // arg0 & arg1
		{name: "ANDconst", argLength: 1, reg: gp11, asm: "AND", aux: "Int64"}, // arg0 & auxInt
		{name: "OR", argLength: 2, reg: gp21, asm: "ORR", commutative: true},  // arg0 | arg1
		{name: "ORconst", argLength: 1, reg: gp11, asm: "ORR", aux: "Int64"},  // arg0 | auxInt
		{name: "XOR", argLength: 2, reg: gp21, asm: "EOR", commutative: true}, // arg0 ^ arg1
		{name: "XORconst", argLength: 1, reg: gp11, asm: "EOR", aux: "Int64"}, // arg0 ^ auxInt
		{name: "BIC", argLength: 2, reg: gp21, asm: "BIC"},                    // arg0 &^ arg1
		{name: "EON", argLength: 2, reg: gp21, asm: "EON"},                    // arg0 ^ ^arg1
		{name: "ORN", argLength: 2, reg: gp21, asm: "ORN"},                    // arg0 | ^arg1

		// unary ops
		{name: "MVN", argLength: 1, reg: gp11, asm: "MVN"},                                    // ^arg0
		{name: "NEG", argLength: 1, reg: gp11, asm: "NEG"},                                    // -arg0
		{name: "NEGSflags", argLength: 1, reg: gp11flags, typ: "(UInt64,Flags)", asm: "NEGS"}, // -arg0, set flags.
		{name: "NGCzerocarry", argLength: 1, reg: gp0flags1, typ: "UInt64", asm: "NGC"},       // -1 if borrowing, 0 otherwise.
		{name: "FABSD", argLength: 1, reg: fp11, asm: "FABSD"},                                // abs(arg0), float64
		{name: "FNEGS", argLength: 1, reg: fp11, asm: "FNEGS"},                                // -arg0, float32
		{name: "FNEGD", argLength: 1, reg: fp11, asm: "FNEGD"},                                // -arg0, float64
		{name: "FSQRTD", argLength: 1, reg: fp11, asm: "FSQRTD"},                              // sqrt(arg0), float64
		{name: "FSQRTS", argLength: 1, reg: fp11, asm: "FSQRTS"},                              // sqrt(arg0), float32
		{name: "FMIND", argLength: 2, reg: fp21, asm: "FMIND"},                                // min(arg0, arg1)
		{name: "FMINS", argLength: 2, reg: fp21, asm: "FMINS"},                                // min(arg0, arg1)
		{name: "FMAXD", argLength: 2, reg: fp21, asm: "FMAXD"},                                // max(arg0, arg1)
		{name: "FMAXS", argLength: 2, reg: fp21, asm: "FMAXS"},                                // max(arg0, arg1)
		{name: "REV", argLength: 1, reg: gp11, asm: "REV"},                                    // byte reverse, 64-bit
		{name: "REVW", argLength: 1, reg: gp11, asm: "REVW"},                                  // byte reverse, 32-bit
		{name: "REV16", argLength: 1, reg: gp11, asm: "REV16"},                                // byte reverse in each 16-bit halfword, 64-bit
		{name: "REV16W", argLength: 1, reg: gp11, asm: "REV16W"},                              // byte reverse in each 16-bit halfword, 32-bit
		{name: "RBIT", argLength: 1, reg: gp11, asm: "RBIT"},                                  // bit reverse, 64-bit
		{name: "RBITW", argLength: 1, reg: gp11, asm: "RBITW"},                                // bit reverse, 32-bit
		{name: "CLZ", argLength: 1, reg: gp11, asm: "CLZ"},                                    // count leading zero, 64-bit
		{name: "CLZW", argLength: 1, reg: gp11, asm: "CLZW"},                                  // count leading zero, 32-bit
		{name: "VCNT", argLength: 1, reg: fp11, asm: "VCNT"},                                  // count set bits for each 8-bit unit and store the result in each 8-bit unit
		{name: "VUADDLV", argLength: 1, reg: fp11, asm: "VUADDLV"},                            // unsigned sum of eight bytes in a 64-bit value, zero extended to 64-bit.
		{name: "LoweredRound32F", argLength: 1, reg: fp11, resultInArg0: true, zeroWidth: true},
		{name: "LoweredRound64F", argLength: 1, reg: fp11, resultInArg0: true, zeroWidth: true},

		// 3-operand, the addend comes first
		{name: "FMADDS", argLength: 3, reg: fp31, asm: "FMADDS"},   // +arg0 + (arg1 * arg2)
		{name: "FMADDD", argLength: 3, reg: fp31, asm: "FMADDD"},   // +arg0 + (arg1 * arg2)
		{name: "FNMADDS", argLength: 3, reg: fp31, asm: "FNMADDS"}, // -arg0 - (arg1 * arg2)
		{name: "FNMADDD", argLength: 3, reg: fp31, asm: "FNMADDD"}, // -arg0 - (arg1 * arg2)
		{name: "FMSUBS", argLength: 3, reg: fp31, asm: "FMSUBS"},   // +arg0 - (arg1 * arg2)
		{name: "FMSUBD", argLength: 3, reg: fp31, asm: "FMSUBD"},   // +arg0 - (arg1 * arg2)
		{name: "FNMSUBS", argLength: 3, reg: fp31, asm: "FNMSUBS"}, // -arg0 + (arg1 * arg2)
		{name: "FNMSUBD", argLength: 3, reg: fp31, asm: "FNMSUBD"}, // -arg0 + (arg1 * arg2)
		{name: "MADD", argLength: 3, reg: gp31, asm: "MADD"},       // +arg0 + (arg1 * arg2)
		{name: "MADDW", argLength: 3, reg: gp31, asm: "MADDW"},     // +arg0 + (arg1 * arg2), 32-bit
		{name: "MSUB", argLength: 3, reg: gp31, asm: "MSUB"},       // +arg0 - (arg1 * arg2)
		{name: "MSUBW", argLength: 3, reg: gp31, asm: "MSUBW"},     // +arg0 - (arg1 * arg2), 32-bit

		// shifts
		{name: "SLL", argLength: 2, reg: gp21, asm: "LSL"},                        // arg0 << arg1, shift amount is mod 64
		{name: "SLLconst", argLength: 1, reg: gp11, asm: "LSL", aux: "Int64"},     // arg0 << auxInt, auxInt should be in the range 0 to 63.
		{name: "SRL", argLength: 2, reg: gp21, asm: "LSR"},                        // arg0 >> arg1, unsigned, shift amount is mod 64
		{name: "SRLconst", argLength: 1, reg: gp11, asm: "LSR", aux: "Int64"},     // arg0 >> auxInt, unsigned, auxInt should be in the range 0 to 63.
		{name: "SRA", argLength: 2, reg: gp21, asm: "ASR"},                        // arg0 >> arg1, signed, shift amount is mod 64
		{name: "SRAconst", argLength: 1, reg: gp11, asm: "ASR", aux: "Int64"},     // arg0 >> auxInt, signed, auxInt should be in the range 0 to 63.
		{name: "ROR", argLength: 2, reg: gp21, asm: "ROR"},                        // arg0 right rotate by (arg1 mod 64) bits
		{name: "RORW", argLength: 2, reg: gp21, asm: "RORW"},                      // arg0 right rotate by (arg1 mod 32) bits
		{name: "RORconst", argLength: 1, reg: gp11, asm: "ROR", aux: "Int64"},     // arg0 right rotate by auxInt bits, auxInt should be in the range 0 to 63.
		{name: "RORWconst", argLength: 1, reg: gp11, asm: "RORW", aux: "Int64"},   // uint32(arg0) right rotate by auxInt bits, auxInt should be in the range 0 to 31.
		{name: "EXTRconst", argLength: 2, reg: gp21, asm: "EXTR", aux: "Int64"},   // extract 64 bits from arg0:arg1 starting at lsb auxInt, auxInt should be in the range 0 to 63.
		{name: "EXTRWconst", argLength: 2, reg: gp21, asm: "EXTRW", aux: "Int64"}, // extract 32 bits from arg0[31:0]:arg1[31:0] starting at lsb auxInt and zero top 32 bits, auxInt should be in the range 0 to 31.

		// comparisons
		{name: "CMP", argLength: 2, reg: gp2flags, asm: "CMP", typ: "Flags"},                      // arg0 compare to arg1
		{name: "CMPconst", argLength: 1, reg: gp1flags, asm: "CMP", aux: "Int64", typ: "Flags"},   // arg0 compare to auxInt
		{name: "CMPW", argLength: 2, reg: gp2flags, asm: "CMPW", typ: "Flags"},                    // arg0 compare to arg1, 32 bit
		{name: "CMPWconst", argLength: 1, reg: gp1flags, asm: "CMPW", aux: "Int32", typ: "Flags"}, // arg0 compare to auxInt, 32 bit
		{name: "CMN", argLength: 2, reg: gp2flags, asm: "CMN", typ: "Flags", commutative: true},   // arg0 compare to -arg1, provided arg1 is not 1<<63
		{name: "CMNconst", argLength: 1, reg: gp1flags, asm: "CMN", aux: "Int64", typ: "Flags"},   // arg0 compare to -auxInt
		{name: "CMNW", argLength: 2, reg: gp2flags, asm: "CMNW", typ: "Flags", commutative: true}, // arg0 compare to -arg1, 32 bit, provided arg1 is not 1<<31
		{name: "CMNWconst", argLength: 1, reg: gp1flags, asm: "CMNW", aux: "Int32", typ: "Flags"}, // arg0 compare to -auxInt, 32 bit
		{name: "TST", argLength: 2, reg: gp2flags, asm: "TST", typ: "Flags", commutative: true},   // arg0 & arg1 compare to 0
		{name: "TSTconst", argLength: 1, reg: gp1flags, asm: "TST", aux: "Int64", typ: "Flags"},   // arg0 & auxInt compare to 0
		{name: "TSTW", argLength: 2, reg: gp2flags, asm: "TSTW", typ: "Flags", commutative: true}, // arg0 & arg1 compare to 0, 32 bit
		{name: "TSTWconst", argLength: 1, reg: gp1flags, asm: "TSTW", aux: "Int32", typ: "Flags"}, // arg0 & auxInt compare to 0, 32 bit
		{name: "FCMPS", argLength: 2, reg: fp2flags, asm: "FCMPS", typ: "Flags"},                  // arg0 compare to arg1, float32
		{name: "FCMPD", argLength: 2, reg: fp2flags, asm: "FCMPD", typ: "Flags"},                  // arg0 compare to arg1, float64
		{name: "FCMPS0", argLength: 1, reg: fp1flags, asm: "FCMPS", typ: "Flags"},                 // arg0 compare to 0, float32
		{name: "FCMPD0", argLength: 1, reg: fp1flags, asm: "FCMPD", typ: "Flags"},                 // arg0 compare to 0, float64

		// shifted ops
		{name: "MVNshiftLL", argLength: 1, reg: gp11, asm: "MVN", aux: "Int64"},                   // ^(arg0<<auxInt), auxInt should be in the range 0 to 63.
		{name: "MVNshiftRL", argLength: 1, reg: gp11, asm: "MVN", aux: "Int64"},                   // ^(arg0>>auxInt), unsigned shift, auxInt should be in the range 0 to 63.
		{name: "MVNshiftRA", argLength: 1, reg: gp11, asm: "MVN", aux: "Int64"},                   // ^(arg0>>auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "MVNshiftRO", argLength: 1, reg: gp11, asm: "MVN", aux: "Int64"},                   // ^(arg0 ROR auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "NEGshiftLL", argLength: 1, reg: gp11, asm: "NEG", aux: "Int64"},                   // -(arg0<<auxInt), auxInt should be in the range 0 to 63.
		{name: "NEGshiftRL", argLength: 1, reg: gp11, asm: "NEG", aux: "Int64"},                   // -(arg0>>auxInt), unsigned shift, auxInt should be in the range 0 to 63.
		{name: "NEGshiftRA", argLength: 1, reg: gp11, asm: "NEG", aux: "Int64"},                   // -(arg0>>auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "ADDshiftLL", argLength: 2, reg: gp21, asm: "ADD", aux: "Int64"},                   // arg0 + arg1<<auxInt, auxInt should be in the range 0 to 63.
		{name: "ADDshiftRL", argLength: 2, reg: gp21, asm: "ADD", aux: "Int64"},                   // arg0 + arg1>>auxInt, unsigned shift, auxInt should be in the range 0 to 63.
		{name: "ADDshiftRA", argLength: 2, reg: gp21, asm: "ADD", aux: "Int64"},                   // arg0 + arg1>>auxInt, signed shift, auxInt should be in the range 0 to 63.
		{name: "SUBshiftLL", argLength: 2, reg: gp21, asm: "SUB", aux: "Int64"},                   // arg0 - arg1<<auxInt, auxInt should be in the range 0 to 63.
		{name: "SUBshiftRL", argLength: 2, reg: gp21, asm: "SUB", aux: "Int64"},                   // arg0 - arg1>>auxInt, unsigned shift, auxInt should be in the range 0 to 63.
		{name: "SUBshiftRA", argLength: 2, reg: gp21, asm: "SUB", aux: "Int64"},                   // arg0 - arg1>>auxInt, signed shift, auxInt should be in the range 0 to 63.
		{name: "ANDshiftLL", argLength: 2, reg: gp21, asm: "AND", aux: "Int64"},                   // arg0 & (arg1<<auxInt), auxInt should be in the range 0 to 63.
		{name: "ANDshiftRL", argLength: 2, reg: gp21, asm: "AND", aux: "Int64"},                   // arg0 & (arg1>>auxInt), unsigned shift, auxInt should be in the range 0 to 63.
		{name: "ANDshiftRA", argLength: 2, reg: gp21, asm: "AND", aux: "Int64"},                   // arg0 & (arg1>>auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "ANDshiftRO", argLength: 2, reg: gp21, asm: "AND", aux: "Int64"},                   // arg0 & (arg1 ROR auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "ORshiftLL", argLength: 2, reg: gp21, asm: "ORR", aux: "Int64"},                    // arg0 | arg1<<auxInt, auxInt should be in the range 0 to 63.
		{name: "ORshiftRL", argLength: 2, reg: gp21, asm: "ORR", aux: "Int64"},                    // arg0 | arg1>>auxInt, unsigned shift, auxInt should be in the range 0 to 63.
		{name: "ORshiftRA", argLength: 2, reg: gp21, asm: "ORR", aux: "Int64"},                    // arg0 | arg1>>auxInt, signed shift, auxInt should be in the range 0 to 63.
		{name: "ORshiftRO", argLength: 2, reg: gp21, asm: "ORR", aux: "Int64"},                    // arg0 | arg1 ROR auxInt, signed shift, auxInt should be in the range 0 to 63.
		{name: "XORshiftLL", argLength: 2, reg: gp21, asm: "EOR", aux: "Int64"},                   // arg0 ^ arg1<<auxInt, auxInt should be in the range 0 to 63.
		{name: "XORshiftRL", argLength: 2, reg: gp21, asm: "EOR", aux: "Int64"},                   // arg0 ^ arg1>>auxInt, unsigned shift, auxInt should be in the range 0 to 63.
		{name: "XORshiftRA", argLength: 2, reg: gp21, asm: "EOR", aux: "Int64"},                   // arg0 ^ arg1>>auxInt, signed shift, auxInt should be in the range 0 to 63.
		{name: "XORshiftRO", argLength: 2, reg: gp21, asm: "EOR", aux: "Int64"},                   // arg0 ^ arg1 ROR auxInt, signed shift, auxInt should be in the range 0 to 63.
		{name: "BICshiftLL", argLength: 2, reg: gp21, asm: "BIC", aux: "Int64"},                   // arg0 &^ (arg1<<auxInt), auxInt should be in the range 0 to 63.
		{name: "BICshiftRL", argLength: 2, reg: gp21, asm: "BIC", aux: "Int64"},                   // arg0 &^ (arg1>>auxInt), unsigned shift, auxInt should be in the range 0 to 63.
		{name: "BICshiftRA", argLength: 2, reg: gp21, asm: "BIC", aux: "Int64"},                   // arg0 &^ (arg1>>auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "BICshiftRO", argLength: 2, reg: gp21, asm: "BIC", aux: "Int64"},                   // arg0 &^ (arg1 ROR auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "EONshiftLL", argLength: 2, reg: gp21, asm: "EON", aux: "Int64"},                   // arg0 ^ ^(arg1<<auxInt), auxInt should be in the range 0 to 63.
		{name: "EONshiftRL", argLength: 2, reg: gp21, asm: "EON", aux: "Int64"},                   // arg0 ^ ^(arg1>>auxInt), unsigned shift, auxInt should be in the range 0 to 63.
		{name: "EONshiftRA", argLength: 2, reg: gp21, asm: "EON", aux: "Int64"},                   // arg0 ^ ^(arg1>>auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "EONshiftRO", argLength: 2, reg: gp21, asm: "EON", aux: "Int64"},                   // arg0 ^ ^(arg1 ROR auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "ORNshiftLL", argLength: 2, reg: gp21, asm: "ORN", aux: "Int64"},                   // arg0 | ^(arg1<<auxInt), auxInt should be in the range 0 to 63.
		{name: "ORNshiftRL", argLength: 2, reg: gp21, asm: "ORN", aux: "Int64"},                   // arg0 | ^(arg1>>auxInt), unsigned shift, auxInt should be in the range 0 to 63.
		{name: "ORNshiftRA", argLength: 2, reg: gp21, asm: "ORN", aux: "Int64"},                   // arg0 | ^(arg1>>auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "ORNshiftRO", argLength: 2, reg: gp21, asm: "ORN", aux: "Int64"},                   // arg0 | ^(arg1 ROR auxInt), signed shift, auxInt should be in the range 0 to 63.
		{name: "CMPshiftLL", argLength: 2, reg: gp2flags, asm: "CMP", aux: "Int64", typ: "Flags"}, // arg0 compare to arg1<<auxInt, auxInt should be in the range 0 to 63.
		{name: "CMPshiftRL", argLength: 2, reg: gp2flags, asm: "CMP", aux: "Int64", typ: "Flags"}, // arg0 compare to arg1>>auxInt, unsigned shift, auxInt should be in the range 0 to 63.
		{name: "CMPshiftRA", argLength: 2, reg: gp2flags, asm: "CMP", aux: "Int64", typ: "Flags"}, // arg0 compare to arg1>>auxInt, signed shift, auxInt should be in the range 0 to 63.
		{name: "CMNshiftLL", argLength: 2, reg: gp2flags, asm: "CMN", aux: "Int64", typ: "Flags"}, // (arg0 + arg1<<auxInt) compare to 0, auxInt should be in the range 0 to 63.
		{name: "CMNshiftRL", argLength: 2, reg: gp2flags, asm: "CMN", aux: "Int64", typ: "Flags"}, // (arg0 + arg1>>auxInt) compare to 0, unsigned shift, auxInt should be in the range 0 to 63.
		{name: "CMNshiftRA", argLength: 2, reg: gp2flags, asm: "CMN", aux: "Int64", typ: "Flags"}, // (arg0 + arg1>>auxInt) compare to 0, signed shift, auxInt should be in the range 0 to 63.
		{name: "TSTshiftLL", argLength: 2, reg: gp2flags, asm: "TST", aux: "Int64", typ: "Flags"}, // (arg0 & arg1<<auxInt) compare to 0, auxInt should be in the range 0 to 63.
		{name: "TSTshiftRL", argLength: 2, reg: gp2flags, asm: "TST", aux: "Int64", typ: "Flags"}, // (arg0 & arg1>>auxInt) compare to 0, unsigned shift, auxInt should be in the range 0 to 63.
		{name: "TSTshiftRA", argLength: 2, reg: gp2flags, asm: "TST", aux: "Int64", typ: "Flags"}, // (arg0 & arg1>>auxInt) compare to 0, signed shift, auxInt should be in the range 0 to 63.
		{name: "TSTshiftRO", argLength: 2, reg: gp2flags, asm: "TST", aux: "Int64", typ: "Flags"}, // (arg0 & arg1 ROR auxInt) compare to 0, signed shift, auxInt should be in the range 0 to 63.

		// bitfield ops
		// for all bitfield ops lsb is auxInt>>8, width is auxInt&0xff
		// insert low width bits of arg1 into the result starting at bit lsb, copy other bits from arg0
		{name: "BFI", argLength: 2, reg: gp21nog, asm: "BFI", aux: "ARM64BitField", resultInArg0: true},
		// extract width bits of arg1 starting at bit lsb and insert at low end of result, copy other bits from arg0
		{name: "BFXIL", argLength: 2, reg: gp21nog, asm: "BFXIL", aux: "ARM64BitField", resultInArg0: true},
		// insert low width bits of arg0 into the result starting at bit lsb, bits to the left of the inserted bit field are set to the high/sign bit of the inserted bit field, bits to the right are zeroed
		{name: "SBFIZ", argLength: 1, reg: gp11, asm: "SBFIZ", aux: "ARM64BitField"},
		// extract width bits of arg0 starting at bit lsb and insert at low end of result, remaining high bits are set to the high/sign bit of the extracted bitfield
		{name: "SBFX", argLength: 1, reg: gp11, asm: "SBFX", aux: "ARM64BitField"},
		// insert low width bits of arg0 into the result starting at bit lsb, bits to the left and right of the inserted bit field are zeroed
		{name: "UBFIZ", argLength: 1, reg: gp11, asm: "UBFIZ", aux: "ARM64BitField"},
		// extract width bits of arg0 starting at bit lsb and insert at low end of result, remaining high bits are zeroed
		{name: "UBFX", argLength: 1, reg: gp11, asm: "UBFX", aux: "ARM64BitField"},

		// moves
		{name: "MOVDconst", argLength: 0, reg: gp01, aux: "Int64", asm: "MOVD", typ: "UInt64", rematerializeable: true},      // 64 bits from auxint
		{name: "FMOVSconst", argLength: 0, reg: fp01, aux: "Float64", asm: "FMOVS", typ: "Float32", rematerializeable: true}, // auxint as 64-bit float, convert to 32-bit float
		{name: "FMOVDconst", argLength: 0, reg: fp01, aux: "Float64", asm: "FMOVD", typ: "Float64", rematerializeable: true}, // auxint as 64-bit float

		{name: "MOVDaddr", argLength: 1, reg: regInfo{inputs: []regMask{buildReg("SP") | buildReg("SB")}, outputs: []regMask{gp}}, aux: "SymOff", asm: "MOVD", rematerializeable: true, symEffect: "Addr"}, // arg0 + auxInt + aux.(*gc.Sym), arg0=SP/SB

		{name: "MOVBload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVB", typ: "Int8", faultOnNilArg0: true, symEffect: "Read"},       // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVBUload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVBU", typ: "UInt8", faultOnNilArg0: true, symEffect: "Read"},    // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVHload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVH", typ: "Int16", faultOnNilArg0: true, symEffect: "Read"},      // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVHUload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVHU", typ: "UInt16", faultOnNilArg0: true, symEffect: "Read"},   // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVWload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVW", typ: "Int32", faultOnNilArg0: true, symEffect: "Read"},      // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVWUload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVWU", typ: "UInt32", faultOnNilArg0: true, symEffect: "Read"},   // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVDload", argLength: 2, reg: gpload, aux: "SymOff", asm: "MOVD", typ: "UInt64", faultOnNilArg0: true, symEffect: "Read"},     // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "LDP", argLength: 2, reg: gpload2, aux: "SymOff", asm: "LDP", typ: "(UInt64,UInt64)", faultOnNilArg0: true, symEffect: "Read"}, // load from ptr = arg0 + auxInt + aux, returns the tuple <*(*uint64)ptr, *(*uint64)(ptr+8)>. arg1=mem.
		{name: "FMOVSload", argLength: 2, reg: fpload, aux: "SymOff", asm: "FMOVS", typ: "Float32", faultOnNilArg0: true, symEffect: "Read"},  // load from arg0 + auxInt + aux.  arg1=mem.
		{name: "FMOVDload", argLength: 2, reg: fpload, aux: "SymOff", asm: "FMOVD", typ: "Float64", faultOnNilArg0: true, symEffect: "Read"},  // load from arg0 + auxInt + aux.  arg1=mem.

		// register indexed load
		{name: "MOVDloadidx", argLength: 3, reg: gp2load, asm: "MOVD", typ: "UInt64"},    // load 64-bit dword from arg0 + arg1, arg2 = mem.
		{name: "MOVWloadidx", argLength: 3, reg: gp2load, asm: "MOVW", typ: "Int32"},     // load 32-bit word from arg0 + arg1, sign-extended to 64-bit, arg2=mem.
		{name: "MOVWUloadidx", argLength: 3, reg: gp2load, asm: "MOVWU", typ: "UInt32"},  // load 32-bit word from arg0 + arg1, zero-extended to 64-bit, arg2=mem.
		{name: "MOVHloadidx", argLength: 3, reg: gp2load, asm: "MOVH", typ: "Int16"},     // load 16-bit word from arg0 + arg1, sign-extended to 64-bit, arg2=mem.
		{name: "MOVHUloadidx", argLength: 3, reg: gp2load, asm: "MOVHU", typ: "UInt16"},  // load 16-bit word from arg0 + arg1, zero-extended to 64-bit, arg2=mem.
		{name: "MOVBloadidx", argLength: 3, reg: gp2load, asm: "MOVB", typ: "Int8"},      // load 8-bit word from arg0 + arg1, sign-extended to 64-bit, arg2=mem.
		{name: "MOVBUloadidx", argLength: 3, reg: gp2load, asm: "MOVBU", typ: "UInt8"},   // load 8-bit word from arg0 + arg1, zero-extended to 64-bit, arg2=mem.
		{name: "FMOVSloadidx", argLength: 3, reg: fp2load, asm: "FMOVS", typ: "Float32"}, // load 32-bit float from arg0 + arg1, arg2=mem.
		{name: "FMOVDloadidx", argLength: 3, reg: fp2load, asm: "FMOVD", typ: "Float64"}, // load 64-bit float from arg0 + arg1, arg2=mem.

		// shifted register indexed load
		{name: "MOVHloadidx2", argLength: 3, reg: gp2load, asm: "MOVH", typ: "Int16"},     // load 16-bit half-word from arg0 + arg1*2, sign-extended to 64-bit, arg2=mem.
		{name: "MOVHUloadidx2", argLength: 3, reg: gp2load, asm: "MOVHU", typ: "UInt16"},  // load 16-bit half-word from arg0 + arg1*2, zero-extended to 64-bit, arg2=mem.
		{name: "MOVWloadidx4", argLength: 3, reg: gp2load, asm: "MOVW", typ: "Int32"},     // load 32-bit word from arg0 + arg1*4, sign-extended to 64-bit, arg2=mem.
		{name: "MOVWUloadidx4", argLength: 3, reg: gp2load, asm: "MOVWU", typ: "UInt32"},  // load 32-bit word from arg0 + arg1*4, zero-extended to 64-bit, arg2=mem.
		{name: "MOVDloadidx8", argLength: 3, reg: gp2load, asm: "MOVD", typ: "UInt64"},    // load 64-bit double-word from arg0 + arg1*8, arg2 = mem.
		{name: "FMOVSloadidx4", argLength: 3, reg: fp2load, asm: "FMOVS", typ: "Float32"}, // load 32-bit float from arg0 + arg1*4, arg2 = mem.
		{name: "FMOVDloadidx8", argLength: 3, reg: fp2load, asm: "FMOVD", typ: "Float64"}, // load 64-bit float from arg0 + arg1*8, arg2 = mem.

		{name: "MOVBstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVB", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},   // store 1 byte of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVHstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVH", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},   // store 2 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVWstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVW", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},   // store 4 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "MOVDstore", argLength: 3, reg: gpstore, aux: "SymOff", asm: "MOVD", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},   // store 8 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "STP", argLength: 4, reg: gpstore2, aux: "SymOff", asm: "STP", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},         // store 16 bytes of arg1 and arg2 to arg0 + auxInt + aux.  arg3=mem.
		{name: "FMOVSstore", argLength: 3, reg: fpstore, aux: "SymOff", asm: "FMOVS", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 4 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.
		{name: "FMOVDstore", argLength: 3, reg: fpstore, aux: "SymOff", asm: "FMOVD", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 8 bytes of arg1 to arg0 + auxInt + aux.  arg2=mem.

		// register indexed store
		{name: "MOVBstoreidx", argLength: 4, reg: gpstore2, asm: "MOVB", typ: "Mem"},   // store 1 byte of arg2 to arg0 + arg1, arg3 = mem.
		{name: "MOVHstoreidx", argLength: 4, reg: gpstore2, asm: "MOVH", typ: "Mem"},   // store 2 bytes of arg2 to arg0 + arg1, arg3 = mem.
		{name: "MOVWstoreidx", argLength: 4, reg: gpstore2, asm: "MOVW", typ: "Mem"},   // store 4 bytes of arg2 to arg0 + arg1, arg3 = mem.
		{name: "MOVDstoreidx", argLength: 4, reg: gpstore2, asm: "MOVD", typ: "Mem"},   // store 8 bytes of arg2 to arg0 + arg1, arg3 = mem.
		{name: "FMOVSstoreidx", argLength: 4, reg: fpstore2, asm: "FMOVS", typ: "Mem"}, // store 32-bit float of arg2 to arg0 + arg1, arg3=mem.
		{name: "FMOVDstoreidx", argLength: 4, reg: fpstore2, asm: "FMOVD", typ: "Mem"}, // store 64-bit float of arg2 to arg0 + arg1, arg3=mem.

		// shifted register indexed store
		{name: "MOVHstoreidx2", argLength: 4, reg: gpstore2, asm: "MOVH", typ: "Mem"},   // store 2 bytes of arg2 to arg0 + arg1*2, arg3 = mem.
		{name: "MOVWstoreidx4", argLength: 4, reg: gpstore2, asm: "MOVW", typ: "Mem"},   // store 4 bytes of arg2 to arg0 + arg1*4, arg3 = mem.
		{name: "MOVDstoreidx8", argLength: 4, reg: gpstore2, asm: "MOVD", typ: "Mem"},   // store 8 bytes of arg2 to arg0 + arg1*8, arg3 = mem.
		{name: "FMOVSstoreidx4", argLength: 4, reg: fpstore2, asm: "FMOVS", typ: "Mem"}, // store 32-bit float of arg2 to arg0 + arg1*4, arg3=mem.
		{name: "FMOVDstoreidx8", argLength: 4, reg: fpstore2, asm: "FMOVD", typ: "Mem"}, // store 64-bit float of arg2 to arg0 + arg1*8, arg3=mem.

		{name: "MOVBstorezero", argLength: 2, reg: gpstore0, aux: "SymOff", asm: "MOVB", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 1 byte of zero to arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVHstorezero", argLength: 2, reg: gpstore0, aux: "SymOff", asm: "MOVH", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 2 bytes of zero to arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVWstorezero", argLength: 2, reg: gpstore0, aux: "SymOff", asm: "MOVW", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 4 bytes of zero to arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVDstorezero", argLength: 2, reg: gpstore0, aux: "SymOff", asm: "MOVD", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 8 bytes of zero to arg0 + auxInt + aux.  arg1=mem.
		{name: "MOVQstorezero", argLength: 2, reg: gpstore0, aux: "SymOff", asm: "STP", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},  // store 16 bytes of zero to arg0 + auxInt + aux.  arg1=mem.

		// register indexed store zero
		{name: "MOVBstorezeroidx", argLength: 3, reg: gpstore, asm: "MOVB", typ: "Mem"}, // store 1 byte of zero to arg0 + arg1, arg2 = mem.
		{name: "MOVHstorezeroidx", argLength: 3, reg: gpstore, asm: "MOVH", typ: "Mem"}, // store 2 bytes of zero to arg0 + arg1, arg2 = mem.
		{name: "MOVWstorezeroidx", argLength: 3, reg: gpstore, asm: "MOVW", typ: "Mem"}, // store 4 bytes of zero to arg0 + arg1, arg2 = mem.
		{name: "MOVDstorezeroidx", argLength: 3, reg: gpstore, asm: "MOVD", typ: "Mem"}, // store 8 bytes of zero to arg0 + arg1, arg2 = mem.

		// shifted register indexed store zero
		{name: "MOVHstorezeroidx2", argLength: 3, reg: gpstore, asm: "MOVH", typ: "Mem"}, // store 2 bytes of zero to arg0 + arg1*2, arg2 = mem.
		{name: "MOVWstorezeroidx4", argLength: 3, reg: gpstore, asm: "MOVW", typ: "Mem"}, // store 4 bytes of zero to arg0 + arg1*4, arg2 = mem.
		{name: "MOVDstorezeroidx8", argLength: 3, reg: gpstore, asm: "MOVD", typ: "Mem"}, // store 8 bytes of zero to arg0 + arg1*8, arg2 = mem.

		{name: "FMOVDgpfp", argLength: 1, reg: gpfp, asm: "FMOVD"}, // move int64 to float64 (no conversion)
		{name: "FMOVDfpgp", argLength: 1, reg: fpgp, asm: "FMOVD"}, // move float64 to int64 (no conversion)
		{name: "FMOVSgpfp", argLength: 1, reg: gpfp, asm: "FMOVS"}, // move 32bits from int to float reg (no conversion)
		{name: "FMOVSfpgp", argLength: 1, reg: fpgp, asm: "FMOVS"}, // move 32bits from float to int reg, zero extend (no conversion)

		// conversions
		{name: "MOVBreg", argLength: 1, reg: gp11, asm: "MOVB"},   // move from arg0, sign-extended from byte
		{name: "MOVBUreg", argLength: 1, reg: gp11, asm: "MOVBU"}, // move from arg0, unsign-extended from byte
		{name: "MOVHreg", argLength: 1, reg: gp11, asm: "MOVH"},   // move from arg0, sign-extended from half
		{name: "MOVHUreg", argLength: 1, reg: gp11, asm: "MOVHU"}, // move from arg0, unsign-extended from half
		{name: "MOVWreg", argLength: 1, reg: gp11, asm: "MOVW"},   // move from arg0, sign-extended from word
		{name: "MOVWUreg", argLength: 1, reg: gp11, asm: "MOVWU"}, // move from arg0, unsign-extended from word
		{name: "MOVDreg", argLength: 1, reg: gp11, asm: "MOVD"},   // move from arg0

		{name: "MOVDnop", argLength: 1, reg: regInfo{inputs: []regMask{gp}, outputs: []regMask{gp}}, resultInArg0: true}, // nop, return arg0 in same register

		{name: "SCVTFWS", argLength: 1, reg: gpfp, asm: "SCVTFWS"},   // int32 -> float32
		{name: "SCVTFWD", argLength: 1, reg: gpfp, asm: "SCVTFWD"},   // int32 -> float64
		{name: "UCVTFWS", argLength: 1, reg: gpfp, asm: "UCVTFWS"},   // uint32 -> float32
		{name: "UCVTFWD", argLength: 1, reg: gpfp, asm: "UCVTFWD"},   // uint32 -> float64
		{name: "SCVTFS", argLength: 1, reg: gpfp, asm: "SCVTFS"},     // int64 -> float32
		{name: "SCVTFD", argLength: 1, reg: gpfp, asm: "SCVTFD"},     // int64 -> float64
		{name: "UCVTFS", argLength: 1, reg: gpfp, asm: "UCVTFS"},     // uint64 -> float32
		{name: "UCVTFD", argLength: 1, reg: gpfp, asm: "UCVTFD"},     // uint64 -> float64
		{name: "FCVTZSSW", argLength: 1, reg: fpgp, asm: "FCVTZSSW"}, // float32 -> int32
		{name: "FCVTZSDW", argLength: 1, reg: fpgp, asm: "FCVTZSDW"}, // float64 -> int32
		{name: "FCVTZUSW", argLength: 1, reg: fpgp, asm: "FCVTZUSW"}, // float32 -> uint32
		{name: "FCVTZUDW", argLength: 1, reg: fpgp, asm: "FCVTZUDW"}, // float64 -> uint32
		{name: "FCVTZSS", argLength: 1, reg: fpgp, asm: "FCVTZSS"},   // float32 -> int64
		{name: "FCVTZSD", argLength: 1, reg: fpgp, asm: "FCVTZSD"},   // float64 -> int64
		{name: "FCVTZUS", argLength: 1, reg: fpgp, asm: "FCVTZUS"},   // float32 -> uint64
		{name: "FCVTZUD", argLength: 1, reg: fpgp, asm: "FCVTZUD"},   // float64 -> uint64
		{name: "FCVTSD", argLength: 1, reg: fp11, asm: "FCVTSD"},     // float32 -> float64
		{name: "FCVTDS", argLength: 1, reg: fp11, asm: "FCVTDS"},     // float64 -> float32

		// floating-point round to integral
		{name: "FRINTAD", argLength: 1, reg: fp11, asm: "FRINTAD"},
		{name: "FRINTMD", argLength: 1, reg: fp11, asm: "FRINTMD"},
		{name: "FRINTND", argLength: 1, reg: fp11, asm: "FRINTND"},
		{name: "FRINTPD", argLength: 1, reg: fp11, asm: "FRINTPD"},
		{name: "FRINTZD", argLength: 1, reg: fp11, asm: "FRINTZD"},

		// conditional instructions; auxint is
		// one of the arm64 comparison pseudo-ops (LessThan, LessThanU, etc.)
		{name: "CSEL", argLength: 3, reg: gp2flags1, asm: "CSEL", aux: "CCop"},   // auxint(flags) ? arg0 : arg1
		{name: "CSEL0", argLength: 2, reg: gp1flags1, asm: "CSEL", aux: "CCop"},  // auxint(flags) ? arg0 : 0
		{name: "CSINC", argLength: 3, reg: gp2flags1, asm: "CSINC", aux: "CCop"}, // auxint(flags) ? arg0 : arg1 + 1
		{name: "CSINV", argLength: 3, reg: gp2flags1, asm: "CSINV", aux: "CCop"}, // auxint(flags) ? arg0 : ^arg1
		{name: "CSNEG", argLength: 3, reg: gp2flags1, asm: "CSNEG", aux: "CCop"}, // auxint(flags) ? arg0 : -arg1
		{name: "CSETM", argLength: 1, reg: readflags, asm: "CSETM", aux: "CCop"}, // auxint(flags) ? -1 : 0

		// function calls
		{name: "CALLstatic", argLength: -1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                                               // call static function aux.(*obj.LSym).  last arg=mem, auxint=argsize, returns mem
		{name: "CALLtail", argLength: -1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true, tailCall: true},                                 // tail call static function aux.(*obj.LSym).  last arg=mem, auxint=argsize, returns mem
		{name: "CALLclosure", argLength: -1, reg: regInfo{inputs: []regMask{gpsp, buildReg("R26"), 0}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true}, // call function via closure.  arg0=codeptr, arg1=closure, last arg=mem, auxint=argsize, returns mem
		{name: "CALLinter", argLength: -1, reg: regInfo{inputs: []regMask{gp}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                         // call fn by pointer.  arg0=codeptr, last arg=mem, auxint=argsize, returns mem

		// pseudo-ops
		{name: "LoweredNilCheck", argLength: 2, reg: regInfo{inputs: []regMask{gpg}}, nilCheck: true, faultOnNilArg0: true}, // panic if arg0 is nil.  arg1=mem.

		{name: "Equal", argLength: 1, reg: readflags},            // bool, true flags encode x==y false otherwise.
		{name: "NotEqual", argLength: 1, reg: readflags},         // bool, true flags encode x!=y false otherwise.
		{name: "LessThan", argLength: 1, reg: readflags},         // bool, true flags encode signed x<y false otherwise.
		{name: "LessEqual", argLength: 1, reg: readflags},        // bool, true flags encode signed x<=y false otherwise.
		{name: "GreaterThan", argLength: 1, reg: readflags},      // bool, true flags encode signed x>y false otherwise.
		{name: "GreaterEqual", argLength: 1, reg: readflags},     // bool, true flags encode signed x>=y false otherwise.
		{name: "LessThanU", argLength: 1, reg: readflags},        // bool, true flags encode unsigned x<y false otherwise.
		{name: "LessEqualU", argLength: 1, reg: readflags},       // bool, true flags encode unsigned x<=y false otherwise.
		{name: "GreaterThanU", argLength: 1, reg: readflags},     // bool, true flags encode unsigned x>y false otherwise.
		{name: "GreaterEqualU", argLength: 1, reg: readflags},    // bool, true flags encode unsigned x>=y false otherwise.
		{name: "LessThanF", argLength: 1, reg: readflags},        // bool, true flags encode floating-point x<y false otherwise.
		{name: "LessEqualF", argLength: 1, reg: readflags},       // bool, true flags encode floating-point x<=y false otherwise.
		{name: "GreaterThanF", argLength: 1, reg: readflags},     // bool, true flags encode floating-point x>y false otherwise.
		{name: "GreaterEqualF", argLength: 1, reg: readflags},    // bool, true flags encode floating-point x>=y false otherwise.
		{name: "NotLessThanF", argLength: 1, reg: readflags},     // bool, true flags encode floating-point x>=y || x is unordered with y, false otherwise.
		{name: "NotLessEqualF", argLength: 1, reg: readflags},    // bool, true flags encode floating-point x>y || x is unordered with y, false otherwise.
		{name: "NotGreaterThanF", argLength: 1, reg: readflags},  // bool, true flags encode floating-point x<=y || x is unordered with y, false otherwise.
		{name: "NotGreaterEqualF", argLength: 1, reg: readflags}, // bool, true flags encode floating-point x<y || x is unordered with y, false otherwise.
		{name: "LessThanNoov", argLength: 1, reg: readflags},     // bool, true flags encode signed x<y but without honoring overflow, false otherwise.
		{name: "GreaterEqualNoov", argLength: 1, reg: readflags}, // bool, true flags encode signed x>=y but without honoring overflow, false otherwise.

		// duffzero
		// arg0 = address of memory to zero
		// arg1 = mem
		// auxint = offset into duffzero code to start executing
		// returns mem
		// R20 changed as side effect
		// R16 and R17 may be clobbered by linker trampoline.
		{
			name:      "DUFFZERO",
			aux:       "Int64",
			argLength: 2,
			reg: regInfo{
				inputs:   []regMask{buildReg("R20")},
				clobbers: buildReg("R16 R17 R20 R30"),
			},
			faultOnNilArg0: true,
			unsafePoint:    true, // FP maintenance around DUFFZERO can be clobbered by interrupts
		},

		// large zeroing
		// arg0 = address of memory to zero (in R16 aka arm64.REGRT1, changed as side effect)
		// arg1 = address of the last 16-byte unit to zero
		// arg2 = mem
		// returns mem
		//	STP.P	(ZR,ZR), 16(R16)
		//	CMP	Rarg1, R16
		//	BLE	-2(PC)
		// Note: the-end-of-the-memory may be not a valid pointer. it's a problem if it is spilled.
		// the-end-of-the-memory - 16 is with the area to zero, ok to spill.
		{
			name:      "LoweredZero",
			argLength: 3,
			reg: regInfo{
				inputs:   []regMask{buildReg("R16"), gp},
				clobbers: buildReg("R16"),
			},
			clobberFlags:   true,
			faultOnNilArg0: true,
		},

		// duffcopy
		// arg0 = address of dst memory (in R21, changed as side effect)
		// arg1 = address of src memory (in R20, changed as side effect)
		// arg2 = mem
		// auxint = offset into duffcopy code to start executing
		// returns mem
		// R20, R21 changed as side effect
		// R16 and R17 may be clobbered by linker trampoline.
		{
			name:      "DUFFCOPY",
			aux:       "Int64",
			argLength: 3,
			reg: regInfo{
				inputs:   []regMask{buildReg("R21"), buildReg("R20")},
				clobbers: buildReg("R16 R17 R20 R21 R26 R30"),
			},
			faultOnNilArg0: true,
			faultOnNilArg1: true,
			unsafePoint:    true, // FP maintenance around DUFFCOPY can be clobbered by interrupts
		},

		// large move
		// arg0 = address of dst memory (in R17 aka arm64.REGRT2, changed as side effect)
		// arg1 = address of src memory (in R16 aka arm64.REGRT1, changed as side effect)
		// arg2 = address of the last element of src
		// arg3 = mem
		// returns mem
		//	LDP.P	16(R16), (R25, Rtmp)
		//	STP.P	(R25, Rtmp), 16(R17)
		//	CMP	Rarg2, R16
		//	BLE	-3(PC)
		// Note: the-end-of-src may be not a valid pointer. it's a problem if it is spilled.
		// the-end-of-src - 16 is within the area to copy, ok to spill.
		{
			name:      "LoweredMove",
			argLength: 4,
			reg: regInfo{
				inputs:   []regMask{buildReg("R17"), buildReg("R16"), gp &^ buildReg("R25")},
				clobbers: buildReg("R16 R17 R25"),
			},
			clobberFlags:   true,
			faultOnNilArg0: true,
			faultOnNilArg1: true,
		},

		// Scheduler ensures LoweredGetClosurePtr occurs only in entry block,
		// and sorts it to the very beginning of the block to prevent other
		// use of R26 (arm64.REGCTXT, the closure pointer)
		{name: "LoweredGetClosurePtr", reg: regInfo{outputs: []regMask{buildReg("R26")}}, zeroWidth: true},

		// LoweredGetCallerSP returns the SP of the caller of the current function. arg0=mem
		{name: "LoweredGetCallerSP", argLength: 1, reg: gp01, rematerializeable: true},

		// LoweredGetCallerPC evaluates to the PC to which its "caller" will return.
		// I.e., if f calls g "calls" sys.GetCallerPC,
		// the result should be the PC within f that g will return to.
		// See runtime/stubs.go for a more detailed discussion.
		{name: "LoweredGetCallerPC", reg: gp01, rematerializeable: true},

		// Constant flag value.
		// Note: there's an "unordered" outcome for floating-point
		// comparisons, but we don't use such a beast yet.
		// This op is for temporary use by rewrite rules. It
		// cannot appear in the generated assembly.
		{name: "FlagConstant", aux: "FlagConstant"},

		// (InvertFlags (CMP a b)) == (CMP b a)
		// InvertFlags is a pseudo-op which can't appear in assembly output.
		{name: "InvertFlags", argLength: 1}, // reverse direction of arg0

		// atomic loads.
		// load from arg0. arg1=mem. auxint must be zero.
		// returns <value,memory> so they can be properly ordered with other loads.
		{name: "LDAR", argLength: 2, reg: gpload, asm: "LDAR", faultOnNilArg0: true},
		{name: "LDARB", argLength: 2, reg: gpload, asm: "LDARB", faultOnNilArg0: true},
		{name: "LDARW", argLength: 2, reg: gpload, asm: "LDARW", faultOnNilArg0: true},

		// atomic stores.
		// store arg1 to arg0. arg2=mem. returns memory. auxint must be zero.
		{name: "STLRB", argLength: 3, reg: gpstore, asm: "STLRB", faultOnNilArg0: true, hasSideEffects: true},
		{name: "STLR", argLength: 3, reg: gpstore, asm: "STLR", faultOnNilArg0: true, hasSideEffects: true},
		{name: "STLRW", argLength: 3, reg: gpstore, asm: "STLRW", faultOnNilArg0: true, hasSideEffects: true},

		// atomic exchange.
		// store arg1 to arg0. arg2=mem. returns <old content of *arg0, memory>. auxint must be zero.
		// LDAXR	(Rarg0), Rout
		// STLXR	Rarg1, (Rarg0), Rtmp
		// CBNZ		Rtmp, -2(PC)
		{name: "LoweredAtomicExchange64", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicExchange32", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicExchange8", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},

		// atomic exchange variant.
		// store arg1 to arg0. arg2=mem. returns <old content of *arg0, memory>. auxint must be zero.
		// SWPALD	Rarg1, (Rarg0), Rout
		{name: "LoweredAtomicExchange64Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicExchange32Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicExchange8Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},

		// atomic add.
		// *arg0 += arg1. arg2=mem. returns <new content of *arg0, memory>. auxint must be zero.
		// LDAXR	(Rarg0), Rout
		// ADD		Rarg1, Rout
		// STLXR	Rout, (Rarg0), Rtmp
		// CBNZ		Rtmp, -3(PC)
		{name: "LoweredAtomicAdd64", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicAdd32", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},

		// atomic add variant.
		// *arg0 += arg1. arg2=mem. returns <new content of *arg0, memory>. auxint must be zero.
		// LDADDAL	(Rarg0), Rarg1, Rout
		// ADD		Rarg1, Rout
		{name: "LoweredAtomicAdd64Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicAdd32Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},

		// atomic compare and swap.
		// arg0 = pointer, arg1 = old value, arg2 = new value, arg3 = memory. auxint must be zero.
		// if *arg0 == arg1 {
		//   *arg0 = arg2
		//   return (true, memory)
		// } else {
		//   return (false, memory)
		// }
		// LDAXR	(Rarg0), Rtmp
		// CMP		Rarg1, Rtmp
		// BNE		3(PC)
		// STLXR	Rarg2, (Rarg0), Rtmp
		// CBNZ		Rtmp, -4(PC)
		// CSET		EQ, Rout
		{name: "LoweredAtomicCas64", argLength: 4, reg: gpcas, resultNotInArgs: true, clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicCas32", argLength: 4, reg: gpcas, resultNotInArgs: true, clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},

		// atomic compare and swap variant.
		// arg0 = pointer, arg1 = old value, arg2 = new value, arg3 = memory. auxint must be zero.
		// if *arg0 == arg1 {
		//   *arg0 = arg2
		//   return (true, memory)
		// } else {
		//   return (false, memory)
		// }
		// MOV  	Rarg1, Rtmp
		// CASAL	Rtmp, (Rarg0), Rarg2
		// CMP  	Rarg1, Rtmp
		// CSET 	EQ, Rout
		{name: "LoweredAtomicCas64Variant", argLength: 4, reg: gpcas, resultNotInArgs: true, clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicCas32Variant", argLength: 4, reg: gpcas, resultNotInArgs: true, clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},

		// atomic and/or.
		// *arg0 &= (|=) arg1. arg2=mem. returns <old content of *arg0, memory>. auxint must be zero.
		// LDAXR	(Rarg0), Rout
		// AND/OR	Rarg1, Rout, tempReg
		// STLXR	tempReg, (Rarg0), Rtmp
		// CBNZ		Rtmp, -3(PC)
		{name: "LoweredAtomicAnd8", argLength: 3, reg: gpxchg, resultNotInArgs: true, asm: "AND", faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true, needIntTemp: true},
		{name: "LoweredAtomicOr8", argLength: 3, reg: gpxchg, resultNotInArgs: true, asm: "ORR", faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true, needIntTemp: true},
		{name: "LoweredAtomicAnd64", argLength: 3, reg: gpxchg, resultNotInArgs: true, asm: "AND", faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true, needIntTemp: true},
		{name: "LoweredAtomicOr64", argLength: 3, reg: gpxchg, resultNotInArgs: true, asm: "ORR", faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true, needIntTemp: true},
		{name: "LoweredAtomicAnd32", argLength: 3, reg: gpxchg, resultNotInArgs: true, asm: "AND", faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true, needIntTemp: true},
		{name: "LoweredAtomicOr32", argLength: 3, reg: gpxchg, resultNotInArgs: true, asm: "ORR", faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true, needIntTemp: true},

		// atomic and/or variant.
		// *arg0 &= (|=) arg1. arg2=mem. returns <old content of *arg0, memory>. auxint must be zero.
		//   AND:
		// MNV       Rarg1, Rtemp
		// LDANDALB  Rtemp, (Rarg0), Rout
		//   OR:
		// LDORALB  Rarg1, (Rarg0), Rout
		{name: "LoweredAtomicAnd8Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicOr8Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicAnd64Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicOr64Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},
		{name: "LoweredAtomicAnd32Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true, unsafePoint: true},
		{name: "LoweredAtomicOr32Variant", argLength: 3, reg: gpxchg, resultNotInArgs: true, faultOnNilArg0: true, hasSideEffects: true},

		// LoweredWB invokes runtime.gcWriteBarrier. arg0=mem, auxint=# of buffer entries needed
		// It saves all GP registers if necessary,
		// but clobbers R30 (LR) because it's a call.
		// R16 and R17 may be clobbered by linker trampoline.
		// Returns a pointer to a write barrier buffer in R25.
		{name: "LoweredWB", argLength: 1, reg: regInfo{clobbers: (callerSave &^ gpg) | buildReg("R16 R17 R30"), outputs: []regMask{buildReg("R25")}}, clobberFlags: true, aux: "Int64"},

		// There are three of these functions so that they can have three different register inputs.
		// When we check 0 <= c <= cap (A), then 0 <= b <= c (B), then 0 <= a <= b (C), we want the
		// default registers to match so we don't need to copy registers around unnecessarily.
		{name: "LoweredPanicBoundsA", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r2, r3}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in generic.go).
		{name: "LoweredPanicBoundsB", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r1, r2}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in generic.go).
		{name: "LoweredPanicBoundsC", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{r0, r1}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in generic.go).

		// Prefetch instruction
		// Do prefetch arg0 address with option aux. arg0=addr, arg1=memory, aux=option.
		{name: "PRFM", argLength: 2, aux: "Int64", reg: prefreg, asm: "PRFM", hasSideEffects: true},

		// Publication barrier
		{name: "DMB", argLength: 1, aux: "Int64", asm: "DMB", hasSideEffects: true}, // Do data barrier. arg0=memory, aux=option.
	}

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
		{name: "Z", controls: 1},                  // Control == 0 (take a register instead of flags)
		{name: "NZ", controls: 1},                 // Control != 0
		{name: "ZW", controls: 1},                 // Control == 0, 32-bit
		{name: "NZW", controls: 1},                // Control != 0, 32-bit
		{name: "TBZ", controls: 1, aux: "Int64"},  // Control & (1 << AuxInt) == 0
		{name: "TBNZ", controls: 1, aux: "Int64"}, // Control & (1 << AuxInt) != 0
		{name: "FLT", controls: 1},
		{name: "FLE", controls: 1},
		{name: "FGT", controls: 1},
		{name: "FGE", controls: 1},
		{name: "LTnoov", controls: 1}, // 'LT' but without honoring overflow
		{name: "LEnoov", controls: 1}, // 'LE' but without honoring overflow
		{name: "GTnoov", controls: 1}, // 'GT' but without honoring overflow
		{name: "GEnoov", controls: 1}, // 'GE' but without honoring overflow

		// JUMPTABLE implements jump tables.
		// Aux is the symbol (an *obj.LSym) for the jump table.
		// control[0] is the index into the jump table.
		// control[1] is the address of the jump table (the address of the symbol stored in Aux).
		{name: "JUMPTABLE", controls: 2, aux: "Sym"},
	}

	archs = append(archs, arch{
		name:               "ARM64",
		pkg:                "cmd/internal/obj/arm64",
		genfile:            "../../arm64/ssa.go",
		ops:                ops,
		blocks:             blocks,
		regnames:           regNamesARM64,
		ParamIntRegNames:   "R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15",
		ParamFloatRegNames: "F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15",
		gpregmask:          gp,
		fpregmask:          fp,
		framepointerreg:    -1, // not used
		linkreg:            int8(num["R30"]),
	})
}
```