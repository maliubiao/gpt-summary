Response:
My thought process for analyzing the provided Go code snippet goes like this:

1. **Understand the Context:** The file path `go/src/cmd/compile/internal/ssa/_gen/WasmOps.go` immediately tells me this is related to the Go compiler (`cmd/compile`), specifically the Static Single Assignment (SSA) intermediate representation (`internal/ssa`), and even more specifically, it's involved in generating code for the WebAssembly (Wasm) target architecture (`_gen/WasmOps.go`). The `_gen` suggests it's generated code or part of a code generation process.

2. **Identify Key Data Structures:** I look for the main data structures being used.
    * `regNamesWasm`: This is a simple slice of strings, clearly defining the names of registers for the Wasm architecture. I note the distinction between integer registers (R0-R15), single-precision floating-point registers (F0-F15), double-precision floating-point registers (F16-F31), and special registers (SP, g, SB).
    * `buildReg`: This is a helper function to convert a string of register names into a `regMask`. A `regMask` is likely a bitmask representing a set of registers.
    * `regInfo`: This struct seems to describe the register requirements and effects of an operation, including input registers, output registers, and potentially registers that are clobbered (modified).
    * `opData`:  This is the core structure. It defines information about a specific Wasm operation, including its name, assembly mnemonic (`asm`), argument length, register constraints (`reg`), auxiliary information (`aux`), type information (`typ`), and boolean flags (`rematerializeable`, `call`, `tailCall`, `nilCheck`, `faultOnNilArg0`, `symEffect`).
    * `WasmOps`: This is a slice of `opData`, effectively a table of all the supported Wasm operations within this part of the Go compiler.
    * `arch`: This structure seems to define the architecture-specific information, including the name, package, generated file name, the `WasmOps` table, register names, and register masks.
    * `archs`: This is a slice that will likely hold architecture information, and in this case, it's being appended with the Wasm architecture details.

3. **Analyze the `init` Function:** The `init` function is crucial because it sets up the data structures.
    * **Register Name Mapping:** It creates a map (`num`) to quickly look up the integer representation of a register name.
    * **`buildReg` Function Usage:** It uses `buildReg` to define common register groups (general purpose, single-precision float, double-precision float, etc.) using bitmasks. The `callerSave` mask is particularly interesting as it identifies registers that need to be saved and restored across function calls.
    * **`regInfo` Definition:**  It defines several common `regInfo` instances (e.g., `gp01`, `gp11`, `fp32_01`) representing common register input/output patterns for different instruction types. This likely simplifies the definition of individual `opData` entries.
    * **`WasmOps` Population:** This is the main part of the `init` function. It creates a slice of `opData` where each element describes a specific WebAssembly instruction or a higher-level Go-specific operation that will be lowered to Wasm. I notice a pattern: each entry has a `name`, and many have an `asm` field (the actual Wasm instruction). The `reg` field uses the pre-defined `regInfo` structs to specify register constraints. The `aux` field often holds additional data like offsets or symbols. The `typ` field indicates the data type of the operation's result.
    * **`archs` Population:** It creates and appends an `arch` struct for the "Wasm" architecture, linking it to the `WasmOps` table and other relevant information.

4. **Deduce Functionality and Purpose:** Based on the data structures and the `init` function, I can infer the following:
    * **Wasm Code Generation:** This code is a key part of the Go compiler's backend for generating WebAssembly code. The `WasmOps` table defines the set of Wasm operations the compiler knows how to handle.
    * **Instruction Mapping:** The `opData` struct and the `WasmOps` slice act as a mapping between higher-level Go SSA operations and their corresponding low-level Wasm instructions.
    * **Register Allocation and Management:** The `regNamesWasm`, `regMask`, and `regInfo` structures are used for managing register usage during code generation, ensuring that instructions have the correct operands in the right registers and that registers are saved and restored when necessary.
    * **Operation Metadata:** The `opData` contains metadata about each operation, such as the number of arguments, the assembly mnemonic, the types of operands, and various flags.

5. **Consider Go Features and Examples:**  I think about Go language features that would require these Wasm operations.
    * **Function Calls:** The `LoweredStaticCall`, `LoweredTailCall`, `LoweredClosureCall`, and `LoweredInterCall` operations are clearly related to calling functions in Go.
    * **Memory Access:** The `I64Load*` and `I64Store*`, `F32Load`, `F64Load`, `F32Store`, `F64Store` operations are for accessing memory.
    * **Arithmetic and Logical Operations:**  The various `I64Add`, `I64Sub`, `I64Mul`, `F32Add`, `F64Add`, `I64And`, `I64Or`, etc., operations implement arithmetic and logical operations.
    * **Comparisons:** The `I64Eq`, `I64Ne`, `F32Eq`, `F64Eq`, etc., operations implement comparisons.
    * **Conversions:** The `I64TruncSatF64S`, `F32ConvertI64S`, etc., operations handle type conversions between integers and floating-point numbers.
    * **Constants:** `I64Const`, `F32Const`, `F64Const` are for loading constant values.

6. **Think about Potential User Errors:** Since this code is internal to the compiler, direct user errors are unlikely. However, someone working on the compiler itself could make mistakes:
    * **Incorrect `regInfo`:** Defining incorrect input/output register masks or clobbered registers could lead to incorrect code generation.
    * **Missing or Incorrect `opData`:**  Forgetting to add an entry for a Wasm instruction or providing incorrect information would mean the compiler couldn't handle that instruction.
    * **Confusing `aux` and `auxint`:**  Using the auxiliary information incorrectly could lead to wrong offsets or function call targets.

By following these steps, I can systematically analyze the code snippet and arrive at a comprehensive understanding of its purpose and functionality within the Go compiler.
这个Go语言代码片段是Go编译器中用于定义 **WebAssembly (Wasm) 目标架构的操作码 (Opcodes)** 的一部分。 它定义了 Go 的 SSA (Static Single Assignment) 中间表示如何映射到具体的 WebAssembly 指令。

以下是它的功能分解：

**1. 定义 WebAssembly 的寄存器:**

* `regNamesWasm`:  定义了一个字符串切片，包含了 WebAssembly 架构中使用的寄存器的名称。这些名称包括通用寄存器 (R0-R15)、单精度浮点寄存器 (F0-F15)、双精度浮点寄存器 (F16-F31) 以及一些特殊用途的寄存器，如栈指针 (SP)、goroutine 的 g 寄存器和静态基址寄存器 (SB)。

**2. 辅助函数 `buildReg`:**

*  `buildReg` 函数用于将一个包含空格分隔的寄存器名称字符串转换为一个 `regMask` 类型的值。`regMask` 很可能是一个位掩码，用于表示一组寄存器。这个函数用于方便地定义操作码的寄存器约束。

**3. 定义寄存器信息 `regInfo`:**

* `regInfo` 结构体用于描述一个操作码的寄存器使用情况。它包含：
    * `inputs`: 一个 `regMask` 切片，表示操作码的输入操作数可以使用的寄存器集合。
    * `outputs`: 一个 `regMask` 切片，表示操作码的输出结果会存储在哪些寄存器集合中。
    * `clobbers`: 一个 `regMask`，表示操作码执行后会破坏（覆盖）哪些寄存器的值。
    * 其他字段 (在 `opData` 中)：`nilCheck`, `faultOnNilArg0` 等，用于描述操作码的特殊行为。

**4. 定义 WebAssembly 操作码数据 `opData`:**

* `opData` 结构体定义了单个 WebAssembly 操作码的信息。重要的字段包括：
    * `name`:  Go SSA 中操作码的名称。
    * `asm`:  对应的 WebAssembly 汇编指令助记符。
    * `argLength`: 操作码的参数数量。
    * `reg`:  一个 `regInfo` 结构体，描述了该操作码的寄存器约束。
    * `aux`: 一个字符串，用于存储操作码的辅助信息，例如函数调用的目标符号。
    * `auxint`: 一个整数，用于存储操作码的辅助整数信息，例如内存偏移量或参数大小。
    * `typ`:  操作码结果的类型。
    * `rematerializeable`:  一个布尔值，表示该操作码的结果是否可以重新计算（而不是必须存储在寄存器中）。
    * `call`, `tailCall`: 布尔值，表示是否是函数调用或尾调用。
    * `nilCheck`, `faultOnNilArg0`: 布尔值，表示是否进行空指针检查以及在第一个参数为空时是否触发错误。
    * `symEffect`: 字符串，描述操作码对符号的影响。

**5. 定义 `WasmOps` 切片:**

* `WasmOps` 是一个 `opData` 类型的切片，它包含了所有 Go 编译器支持的、针对 WebAssembly 架构的操作码的定义。 每个 `opData` 结构体描述了一个具体的 WebAssembly 指令或一个需要被降低 (Lowered) 成 WebAssembly 指令的更高级别的操作。

**6. 定义架构信息 `arch`:**

* `arch` 结构体用于描述目标架构的特定信息。在这里，它定义了 "Wasm" 架构的名称、包名、生成的代码文件名、以及最重要的 `ops` 字段，它指向了 `WasmOps` 切片。它还包含了寄存器名称、通用寄存器掩码、浮点寄存器掩码等信息。

**7. 初始化函数 `init`:**

* `init` 函数在包被加载时执行，它负责：
    * 创建一个从寄存器名称到整数索引的映射 (`num`)。
    * 使用 `buildReg` 函数初始化各种寄存器掩码，例如 `gp` (通用寄存器)、`fp32` (单精度浮点寄存器)、`fp64` (双精度浮点寄存器) 等。
    * 定义 `callerSave` 寄存器掩码，表示函数调用时需要保存的寄存器。
    * 定义一系列通用的 `regInfo` 实例，方便在定义 `WasmOps` 时使用，例如 `gp01` 表示没有输入，一个通用寄存器输出；`gp11` 表示一个通用/栈指针输入，一个通用寄存器输出等等。
    * **核心功能**:  初始化 `WasmOps` 切片，为每个支持的 WebAssembly 操作码创建一个 `opData` 结构体，并填充其信息。
    * 创建并向 `archs` 切片添加一个 `arch` 结构体，注册 "Wasm" 架构。

**推理 Go 语言功能的实现:**

这段代码是 Go 编译器将高级 Go 代码转换为低级 WebAssembly 代码的关键部分。它定义了 Go 语言的 SSA 中间表示如何对应到 WebAssembly 的指令集。

**Go 代码示例 (假设):**

假设 Go 代码中有以下操作：

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

在编译这个 Go 代码时，编译器会将其转换为 SSA 中间表示。对于 `a + b` 这个加法操作，SSA 中可能会有一个类似于 `t = add i64 a b` 的指令。

`WasmOps.go` 中定义的 `I64Add` 操作码就描述了如何将这个 SSA 加法指令映射到 WebAssembly 的 `i64.add` 指令。

**假设的 SSA 输入和输出 (针对 `I64Add`):**

* **输入 SSA 指令:** `v3 = I64Add v1 v2`  (假设 `v1` 和 `v2` 是保存 `a` 和 `b` 值的 SSA 变量)
* **输出 WebAssembly 指令:** `i64.add local.get <index_of_v1> local.get <index_of_v2>` (实际的输出会涉及到寄存器分配，这里简化为局部变量)

**命令行参数:**

这段代码本身不处理命令行参数。它是在 Go 编译器的内部使用。Go 编译器的命令行参数（例如 `go build -o main.wasm main.go`）会触发整个编译流程，最终会用到这里定义的 WebAssembly 操作码信息。

**使用者易犯错的点 (主要针对编译器开发者):**

* **错误的寄存器约束 (`regInfo`)**: 如果为某个操作码定义了错误的输入或输出寄存器约束，可能导致生成的 WebAssembly 代码无法正常工作，或者出现寄存器冲突。
    * **例子**: 假设 `I64Add` 的 `regInfo` 被错误地定义为只允许一个输入寄存器，那么编译器就无法正确处理需要两个输入操作数的加法。
* **遗漏或错误的 `opData` 定义**: 如果漏掉了某个 WebAssembly 指令的定义，或者定义的信息不正确（例如错误的 `asm` 助记符或 `argLength`），编译器就无法生成相应的 WebAssembly 代码。
    * **例子**: 如果 `F32Add` 的 `asm` 字段被错误地写成 `f64.add`，那么在处理单精度浮点数加法时就会生成错误的 WebAssembly 指令。
* **`aux` 和 `auxint` 的误用**:  `aux` 和 `auxint` 用于存储操作码的额外信息。如果使用不当，例如在函数调用时传递了错误的函数符号到 `aux`，会导致调用错误的函数。
    * **例子**: `LoweredStaticCall` 使用 `aux` 存储要调用的静态函数的符号。如果这个符号错误，就会导致调用错误的函数。

总而言之，这段代码是 Go 编译器针对 WebAssembly 目标平台进行代码生成的核心数据结构定义，它将 Go 的高级抽象映射到底层的 WebAssembly 指令。 编译器开发者需要仔细维护这些定义，以确保生成的 WebAssembly 代码的正确性和效率。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/_gen/WasmOps.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "strings"

var regNamesWasm = []string{
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

	"SP",
	"g",

	// pseudo-registers
	"SB",
}

func init() {
	// Make map from reg names to reg integers.
	if len(regNamesWasm) > 64 {
		panic("too many registers")
	}
	num := map[string]int{}
	for i, name := range regNamesWasm {
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

	var (
		gp     = buildReg("R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15")
		fp32   = buildReg("F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15")
		fp64   = buildReg("F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31")
		gpsp   = gp | buildReg("SP")
		gpspsb = gpsp | buildReg("SB")
		// The "registers", which are actually local variables, can get clobbered
		// if we're switching goroutines, because it unwinds the WebAssembly stack.
		callerSave = gp | fp32 | fp64 | buildReg("g")
	)

	// Common regInfo
	var (
		gp01      = regInfo{inputs: nil, outputs: []regMask{gp}}
		gp11      = regInfo{inputs: []regMask{gpsp}, outputs: []regMask{gp}}
		gp21      = regInfo{inputs: []regMask{gpsp, gpsp}, outputs: []regMask{gp}}
		gp31      = regInfo{inputs: []regMask{gpsp, gpsp, gpsp}, outputs: []regMask{gp}}
		fp32_01   = regInfo{inputs: nil, outputs: []regMask{fp32}}
		fp32_11   = regInfo{inputs: []regMask{fp32}, outputs: []regMask{fp32}}
		fp32_21   = regInfo{inputs: []regMask{fp32, fp32}, outputs: []regMask{fp32}}
		fp32_21gp = regInfo{inputs: []regMask{fp32, fp32}, outputs: []regMask{gp}}
		fp64_01   = regInfo{inputs: nil, outputs: []regMask{fp64}}
		fp64_11   = regInfo{inputs: []regMask{fp64}, outputs: []regMask{fp64}}
		fp64_21   = regInfo{inputs: []regMask{fp64, fp64}, outputs: []regMask{fp64}}
		fp64_21gp = regInfo{inputs: []regMask{fp64, fp64}, outputs: []regMask{gp}}
		gpload    = regInfo{inputs: []regMask{gpspsb, 0}, outputs: []regMask{gp}}
		gpstore   = regInfo{inputs: []regMask{gpspsb, gpsp, 0}}
		fp32load  = regInfo{inputs: []regMask{gpspsb, 0}, outputs: []regMask{fp32}}
		fp32store = regInfo{inputs: []regMask{gpspsb, fp32, 0}}
		fp64load  = regInfo{inputs: []regMask{gpspsb, 0}, outputs: []regMask{fp64}}
		fp64store = regInfo{inputs: []regMask{gpspsb, fp64, 0}}
	)

	var WasmOps = []opData{
		{name: "LoweredStaticCall", argLength: 1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", call: true},                                // call static function aux.(*obj.LSym). arg0=mem, auxint=argsize, returns mem
		{name: "LoweredTailCall", argLength: 1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", call: true, tailCall: true},                  // tail call static function aux.(*obj.LSym). arg0=mem, auxint=argsize, returns mem
		{name: "LoweredClosureCall", argLength: 3, reg: regInfo{inputs: []regMask{gp, gp, 0}, clobbers: callerSave}, aux: "CallOff", call: true}, // call function via closure. arg0=codeptr, arg1=closure, arg2=mem, auxint=argsize, returns mem
		{name: "LoweredInterCall", argLength: 2, reg: regInfo{inputs: []regMask{gp}, clobbers: callerSave}, aux: "CallOff", call: true},          // call fn by pointer. arg0=codeptr, arg1=mem, auxint=argsize, returns mem

		{name: "LoweredAddr", argLength: 1, reg: gp11, aux: "SymOff", rematerializeable: true, symEffect: "Addr"}, // returns base+aux+auxint, arg0=base
		{name: "LoweredMove", argLength: 3, reg: regInfo{inputs: []regMask{gp, gp}}, aux: "Int64"},                // large move. arg0=dst, arg1=src, arg2=mem, auxint=len, returns mem
		{name: "LoweredZero", argLength: 2, reg: regInfo{inputs: []regMask{gp}}, aux: "Int64"},                    // large zeroing. arg0=start, arg1=mem, auxint=len, returns mem

		{name: "LoweredGetClosurePtr", reg: gp01},                                                                          // returns wasm.REG_CTXT, the closure pointer
		{name: "LoweredGetCallerPC", reg: gp01, rematerializeable: true},                                                   // returns the PC of the caller of the current function
		{name: "LoweredGetCallerSP", argLength: 1, reg: gp01, rematerializeable: true},                                     // returns the SP of the caller of the current function. arg0=mem.
		{name: "LoweredNilCheck", argLength: 2, reg: regInfo{inputs: []regMask{gp}}, nilCheck: true, faultOnNilArg0: true}, // panic if arg0 is nil. arg1=mem
		{name: "LoweredWB", argLength: 1, reg: regInfo{clobbers: callerSave, outputs: []regMask{gp}}, aux: "Int64"},        // invokes runtime.gcWriteBarrier{auxint}. arg0=mem, auxint=# of buffer entries needed. Returns a pointer to a write barrier buffer.

		// LoweredConvert converts between pointers and integers.
		// We have a special op for this so as to not confuse GCCallOff
		// (particularly stack maps). It takes a memory arg so it
		// gets correctly ordered with respect to GC safepoints.
		// arg0=ptr/int arg1=mem, output=int/ptr
		//
		// TODO(neelance): LoweredConvert should not be necessary any more, since OpConvert does not need to be lowered any more (CL 108496).
		{name: "LoweredConvert", argLength: 2, reg: regInfo{inputs: []regMask{gp}, outputs: []regMask{gp}}},

		// The following are native WebAssembly instructions, see https://webassembly.github.io/spec/core/syntax/instructions.html

		{name: "Select", asm: "Select", argLength: 3, reg: gp31}, // returns arg0 if arg2 != 0, otherwise returns arg1

		{name: "I64Load8U", asm: "I64Load8U", argLength: 2, reg: gpload, aux: "Int64", typ: "UInt8"},    // read unsigned 8-bit integer from address arg0+aux, arg1=mem
		{name: "I64Load8S", asm: "I64Load8S", argLength: 2, reg: gpload, aux: "Int64", typ: "Int8"},     // read signed 8-bit integer from address arg0+aux, arg1=mem
		{name: "I64Load16U", asm: "I64Load16U", argLength: 2, reg: gpload, aux: "Int64", typ: "UInt16"}, // read unsigned 16-bit integer from address arg0+aux, arg1=mem
		{name: "I64Load16S", asm: "I64Load16S", argLength: 2, reg: gpload, aux: "Int64", typ: "Int16"},  // read signed 16-bit integer from address arg0+aux, arg1=mem
		{name: "I64Load32U", asm: "I64Load32U", argLength: 2, reg: gpload, aux: "Int64", typ: "UInt32"}, // read unsigned 32-bit integer from address arg0+aux, arg1=mem
		{name: "I64Load32S", asm: "I64Load32S", argLength: 2, reg: gpload, aux: "Int64", typ: "Int32"},  // read signed 32-bit integer from address arg0+aux, arg1=mem
		{name: "I64Load", asm: "I64Load", argLength: 2, reg: gpload, aux: "Int64", typ: "UInt64"},       // read 64-bit integer from address arg0+aux, arg1=mem
		{name: "I64Store8", asm: "I64Store8", argLength: 3, reg: gpstore, aux: "Int64", typ: "Mem"},     // store 8-bit integer arg1 at address arg0+aux, arg2=mem, returns mem
		{name: "I64Store16", asm: "I64Store16", argLength: 3, reg: gpstore, aux: "Int64", typ: "Mem"},   // store 16-bit integer arg1 at address arg0+aux, arg2=mem, returns mem
		{name: "I64Store32", asm: "I64Store32", argLength: 3, reg: gpstore, aux: "Int64", typ: "Mem"},   // store 32-bit integer arg1 at address arg0+aux, arg2=mem, returns mem
		{name: "I64Store", asm: "I64Store", argLength: 3, reg: gpstore, aux: "Int64", typ: "Mem"},       // store 64-bit integer arg1 at address arg0+aux, arg2=mem, returns mem

		{name: "F32Load", asm: "F32Load", argLength: 2, reg: fp32load, aux: "Int64", typ: "Float32"}, // read 32-bit float from address arg0+aux, arg1=mem
		{name: "F64Load", asm: "F64Load", argLength: 2, reg: fp64load, aux: "Int64", typ: "Float64"}, // read 64-bit float from address arg0+aux, arg1=mem
		{name: "F32Store", asm: "F32Store", argLength: 3, reg: fp32store, aux: "Int64", typ: "Mem"},  // store 32-bit float arg1 at address arg0+aux, arg2=mem, returns mem
		{name: "F64Store", asm: "F64Store", argLength: 3, reg: fp64store, aux: "Int64", typ: "Mem"},  // store 64-bit float arg1 at address arg0+aux, arg2=mem, returns mem

		{name: "I64Const", reg: gp01, aux: "Int64", rematerializeable: true, typ: "Int64"},        // returns the constant integer aux
		{name: "F32Const", reg: fp32_01, aux: "Float32", rematerializeable: true, typ: "Float32"}, // returns the constant float aux
		{name: "F64Const", reg: fp64_01, aux: "Float64", rematerializeable: true, typ: "Float64"}, // returns the constant float aux

		{name: "I64Eqz", asm: "I64Eqz", argLength: 1, reg: gp11, typ: "Bool"}, // arg0 == 0
		{name: "I64Eq", asm: "I64Eq", argLength: 2, reg: gp21, typ: "Bool"},   // arg0 == arg1
		{name: "I64Ne", asm: "I64Ne", argLength: 2, reg: gp21, typ: "Bool"},   // arg0 != arg1
		{name: "I64LtS", asm: "I64LtS", argLength: 2, reg: gp21, typ: "Bool"}, // arg0 < arg1 (signed)
		{name: "I64LtU", asm: "I64LtU", argLength: 2, reg: gp21, typ: "Bool"}, // arg0 < arg1 (unsigned)
		{name: "I64GtS", asm: "I64GtS", argLength: 2, reg: gp21, typ: "Bool"}, // arg0 > arg1 (signed)
		{name: "I64GtU", asm: "I64GtU", argLength: 2, reg: gp21, typ: "Bool"}, // arg0 > arg1 (unsigned)
		{name: "I64LeS", asm: "I64LeS", argLength: 2, reg: gp21, typ: "Bool"}, // arg0 <= arg1 (signed)
		{name: "I64LeU", asm: "I64LeU", argLength: 2, reg: gp21, typ: "Bool"}, // arg0 <= arg1 (unsigned)
		{name: "I64GeS", asm: "I64GeS", argLength: 2, reg: gp21, typ: "Bool"}, // arg0 >= arg1 (signed)
		{name: "I64GeU", asm: "I64GeU", argLength: 2, reg: gp21, typ: "Bool"}, // arg0 >= arg1 (unsigned)

		{name: "F32Eq", asm: "F32Eq", argLength: 2, reg: fp32_21gp, typ: "Bool"}, // arg0 == arg1
		{name: "F32Ne", asm: "F32Ne", argLength: 2, reg: fp32_21gp, typ: "Bool"}, // arg0 != arg1
		{name: "F32Lt", asm: "F32Lt", argLength: 2, reg: fp32_21gp, typ: "Bool"}, // arg0 < arg1
		{name: "F32Gt", asm: "F32Gt", argLength: 2, reg: fp32_21gp, typ: "Bool"}, // arg0 > arg1
		{name: "F32Le", asm: "F32Le", argLength: 2, reg: fp32_21gp, typ: "Bool"}, // arg0 <= arg1
		{name: "F32Ge", asm: "F32Ge", argLength: 2, reg: fp32_21gp, typ: "Bool"}, // arg0 >= arg1

		{name: "F64Eq", asm: "F64Eq", argLength: 2, reg: fp64_21gp, typ: "Bool"}, // arg0 == arg1
		{name: "F64Ne", asm: "F64Ne", argLength: 2, reg: fp64_21gp, typ: "Bool"}, // arg0 != arg1
		{name: "F64Lt", asm: "F64Lt", argLength: 2, reg: fp64_21gp, typ: "Bool"}, // arg0 < arg1
		{name: "F64Gt", asm: "F64Gt", argLength: 2, reg: fp64_21gp, typ: "Bool"}, // arg0 > arg1
		{name: "F64Le", asm: "F64Le", argLength: 2, reg: fp64_21gp, typ: "Bool"}, // arg0 <= arg1
		{name: "F64Ge", asm: "F64Ge", argLength: 2, reg: fp64_21gp, typ: "Bool"}, // arg0 >= arg1

		{name: "I64Add", asm: "I64Add", argLength: 2, reg: gp21, typ: "Int64"},                    // arg0 + arg1
		{name: "I64AddConst", asm: "I64Add", argLength: 1, reg: gp11, aux: "Int64", typ: "Int64"}, // arg0 + aux
		{name: "I64Sub", asm: "I64Sub", argLength: 2, reg: gp21, typ: "Int64"},                    // arg0 - arg1
		{name: "I64Mul", asm: "I64Mul", argLength: 2, reg: gp21, typ: "Int64"},                    // arg0 * arg1
		{name: "I64DivS", asm: "I64DivS", argLength: 2, reg: gp21, typ: "Int64"},                  // arg0 / arg1 (signed)
		{name: "I64DivU", asm: "I64DivU", argLength: 2, reg: gp21, typ: "Int64"},                  // arg0 / arg1 (unsigned)
		{name: "I64RemS", asm: "I64RemS", argLength: 2, reg: gp21, typ: "Int64"},                  // arg0 % arg1 (signed)
		{name: "I64RemU", asm: "I64RemU", argLength: 2, reg: gp21, typ: "Int64"},                  // arg0 % arg1 (unsigned)
		{name: "I64And", asm: "I64And", argLength: 2, reg: gp21, typ: "Int64"},                    // arg0 & arg1
		{name: "I64Or", asm: "I64Or", argLength: 2, reg: gp21, typ: "Int64"},                      // arg0 | arg1
		{name: "I64Xor", asm: "I64Xor", argLength: 2, reg: gp21, typ: "Int64"},                    // arg0 ^ arg1
		{name: "I64Shl", asm: "I64Shl", argLength: 2, reg: gp21, typ: "Int64"},                    // arg0 << (arg1 % 64)
		{name: "I64ShrS", asm: "I64ShrS", argLength: 2, reg: gp21, typ: "Int64"},                  // arg0 >> (arg1 % 64) (signed)
		{name: "I64ShrU", asm: "I64ShrU", argLength: 2, reg: gp21, typ: "Int64"},                  // arg0 >> (arg1 % 64) (unsigned)

		{name: "F32Neg", asm: "F32Neg", argLength: 1, reg: fp32_11, typ: "Float32"}, // -arg0
		{name: "F32Add", asm: "F32Add", argLength: 2, reg: fp32_21, typ: "Float32"}, // arg0 + arg1
		{name: "F32Sub", asm: "F32Sub", argLength: 2, reg: fp32_21, typ: "Float32"}, // arg0 - arg1
		{name: "F32Mul", asm: "F32Mul", argLength: 2, reg: fp32_21, typ: "Float32"}, // arg0 * arg1
		{name: "F32Div", asm: "F32Div", argLength: 2, reg: fp32_21, typ: "Float32"}, // arg0 / arg1

		{name: "F64Neg", asm: "F64Neg", argLength: 1, reg: fp64_11, typ: "Float64"}, // -arg0
		{name: "F64Add", asm: "F64Add", argLength: 2, reg: fp64_21, typ: "Float64"}, // arg0 + arg1
		{name: "F64Sub", asm: "F64Sub", argLength: 2, reg: fp64_21, typ: "Float64"}, // arg0 - arg1
		{name: "F64Mul", asm: "F64Mul", argLength: 2, reg: fp64_21, typ: "Float64"}, // arg0 * arg1
		{name: "F64Div", asm: "F64Div", argLength: 2, reg: fp64_21, typ: "Float64"}, // arg0 / arg1

		{name: "I64TruncSatF64S", asm: "I64TruncSatF64S", argLength: 1, reg: regInfo{inputs: []regMask{fp64}, outputs: []regMask{gp}}, typ: "Int64"}, // truncates the float arg0 to a signed integer (saturating)
		{name: "I64TruncSatF64U", asm: "I64TruncSatF64U", argLength: 1, reg: regInfo{inputs: []regMask{fp64}, outputs: []regMask{gp}}, typ: "Int64"}, // truncates the float arg0 to an unsigned integer (saturating)
		{name: "I64TruncSatF32S", asm: "I64TruncSatF32S", argLength: 1, reg: regInfo{inputs: []regMask{fp32}, outputs: []regMask{gp}}, typ: "Int64"}, // truncates the float arg0 to a signed integer (saturating)
		{name: "I64TruncSatF32U", asm: "I64TruncSatF32U", argLength: 1, reg: regInfo{inputs: []regMask{fp32}, outputs: []regMask{gp}}, typ: "Int64"}, // truncates the float arg0 to an unsigned integer (saturating)
		{name: "F32ConvertI64S", asm: "F32ConvertI64S", argLength: 1, reg: regInfo{inputs: []regMask{gp}, outputs: []regMask{fp32}}, typ: "Float32"}, // converts the signed integer arg0 to a float
		{name: "F32ConvertI64U", asm: "F32ConvertI64U", argLength: 1, reg: regInfo{inputs: []regMask{gp}, outputs: []regMask{fp32}}, typ: "Float32"}, // converts the unsigned integer arg0 to a float
		{name: "F64ConvertI64S", asm: "F64ConvertI64S", argLength: 1, reg: regInfo{inputs: []regMask{gp}, outputs: []regMask{fp64}}, typ: "Float64"}, // converts the signed integer arg0 to a float
		{name: "F64ConvertI64U", asm: "F64ConvertI64U", argLength: 1, reg: regInfo{inputs: []regMask{gp}, outputs: []regMask{fp64}}, typ: "Float64"}, // converts the unsigned integer arg0 to a float
		{name: "F32DemoteF64", asm: "F32DemoteF64", argLength: 1, reg: regInfo{inputs: []regMask{fp64}, outputs: []regMask{fp32}}, typ: "Float32"},
		{name: "F64PromoteF32", asm: "F64PromoteF32", argLength: 1, reg: regInfo{inputs: []regMask{fp32}, outputs: []regMask{fp64}}, typ: "Float64"},

		{name: "I64Extend8S", asm: "I64Extend8S", argLength: 1, reg: gp11, typ: "Int64"},   // sign-extend arg0 from 8 to 64 bit
		{name: "I64Extend16S", asm: "I64Extend16S", argLength: 1, reg: gp11, typ: "Int64"}, // sign-extend arg0 from 16 to 64 bit
		{name: "I64Extend32S", asm: "I64Extend32S", argLength: 1, reg: gp11, typ: "Int64"}, // sign-extend arg0 from 32 to 64 bit

		{name: "F32Sqrt", asm: "F32Sqrt", argLength: 1, reg: fp32_11, typ: "Float32"},         // sqrt(arg0)
		{name: "F32Trunc", asm: "F32Trunc", argLength: 1, reg: fp32_11, typ: "Float32"},       // trunc(arg0)
		{name: "F32Ceil", asm: "F32Ceil", argLength: 1, reg: fp32_11, typ: "Float32"},         // ceil(arg0)
		{name: "F32Floor", asm: "F32Floor", argLength: 1, reg: fp32_11, typ: "Float32"},       // floor(arg0)
		{name: "F32Nearest", asm: "F32Nearest", argLength: 1, reg: fp32_11, typ: "Float32"},   // round(arg0)
		{name: "F32Abs", asm: "F32Abs", argLength: 1, reg: fp32_11, typ: "Float32"},           // abs(arg0)
		{name: "F32Copysign", asm: "F32Copysign", argLength: 2, reg: fp32_21, typ: "Float32"}, // copysign(arg0, arg1)

		{name: "F64Sqrt", asm: "F64Sqrt", argLength: 1, reg: fp64_11, typ: "Float64"},         // sqrt(arg0)
		{name: "F64Trunc", asm: "F64Trunc", argLength: 1, reg: fp64_11, typ: "Float64"},       // trunc(arg0)
		{name: "F64Ceil", asm: "F64Ceil", argLength: 1, reg: fp64_11, typ: "Float64"},         // ceil(arg0)
		{name: "F64Floor", asm: "F64Floor", argLength: 1, reg: fp64_11, typ: "Float64"},       // floor(arg0)
		{name: "F64Nearest", asm: "F64Nearest", argLength: 1, reg: fp64_11, typ: "Float64"},   // round(arg0)
		{name: "F64Abs", asm: "F64Abs", argLength: 1, reg: fp64_11, typ: "Float64"},           // abs(arg0)
		{name: "F64Copysign", asm: "F64Copysign", argLength: 2, reg: fp64_21, typ: "Float64"}, // copysign(arg0, arg1)

		{name: "I64Ctz", asm: "I64Ctz", argLength: 1, reg: gp11, typ: "Int64"},       // ctz(arg0)
		{name: "I64Clz", asm: "I64Clz", argLength: 1, reg: gp11, typ: "Int64"},       // clz(arg0)
		{name: "I32Rotl", asm: "I32Rotl", argLength: 2, reg: gp21, typ: "Int32"},     // rotl(arg0, arg1)
		{name: "I64Rotl", asm: "I64Rotl", argLength: 2, reg: gp21, typ: "Int64"},     // rotl(arg0, arg1)
		{name: "I64Popcnt", asm: "I64Popcnt", argLength: 1, reg: gp11, typ: "Int64"}, // popcnt(arg0)
	}

	archs = append(archs, arch{
		name:            "Wasm",
		pkg:             "cmd/internal/obj/wasm",
		genfile:         "../../wasm/ssa.go",
		ops:             WasmOps,
		blocks:          nil,
		regnames:        regNamesWasm,
		gpregmask:       gp,
		fpregmask:       fp32 | fp64,
		fp32regmask:     fp32,
		fp64regmask:     fp64,
		framepointerreg: -1, // not used
		linkreg:         -1, // not used
	})
}

"""



```