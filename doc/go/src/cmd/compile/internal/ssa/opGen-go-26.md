Response:
Let's break down the thought process for answering the request about the Go code snippet.

1. **Understand the Goal:** The core request is to analyze a portion of `opGen.go`, specifically the part dealing with instruction definitions for the PPC64 architecture. The prompt asks for the functionality, the Go language feature it relates to, example code, command-line arguments (if applicable), potential pitfalls, and a summary. The fact it's "part 27 of 36" suggests the entire file is about defining architecture-specific operations for the SSA (Static Single Assignment) intermediate representation used in the Go compiler.

2. **Identify Key Structures:** The code is structured as a large slice of structs. Each struct represents a single assembly instruction or a lower-level operation. The key fields within each struct are:
    * `name`: The name of the operation (e.g., "MOVBload", "ADD", "CALLstatic").
    * `argLen`: The number of arguments the operation takes. `-1` likely signifies a variable number of arguments.
    * `asm`:  The corresponding assembly instruction from the `ppc64` package (e.g., `ppc64.AMOVB`).
    * `reg`:  A `regInfo` struct detailing register constraints for inputs and outputs.
    * Other fields like `auxType`, `hasSideEffects`, `faultOnNilArg0`, `symEffect`, `rematerializeable`, `clobberFlags`, `call`, `tailCall`, `zeroWidth`, `resultInArg0`, `nilCheck`, `unsafePoint`. These provide more information about the operation's behavior and properties.

3. **Infer Functionality:** Based on the names and the `asm` field, it's clear this code defines the mapping between higher-level SSA operations and low-level PPC64 assembly instructions. It specifies how data is loaded, stored, manipulated, and how control flow is managed at the assembly level. The `regInfo` structure indicates how registers are used for inputs and outputs of these operations.

4. **Connect to Go Language Features:**  This level of detail in the compiler is directly related to how Go code is translated into machine code for a specific architecture. The operations described here are the building blocks for implementing Go's language features on PPC64. Specifically, this relates to:
    * **Data types and memory management:**  `MOVBload`, `MOVDstore`, etc., directly handle loading and storing different data types in memory.
    * **Arithmetic and logical operations:** `ADD`, `SUB`, `AND`, `OR`, etc., implement these fundamental operations.
    * **Control flow:** `CALLstatic`, `CALLclosure`, and comparison operations (`CMP`, `FCMPU`) are used to implement function calls, conditional statements, and loops.
    * **Pointers and addressing:** Operations like `MOVDaddr` are crucial for working with memory addresses.
    * **Function calls (including closures and interfaces):** The `CALL*` operations handle different calling conventions.
    * **Atomic operations:** `LoweredAtomicStore*`, `LoweredAtomicLoad*` support concurrent programming.
    * **Zeroing memory:** `LoweredZero*` is used for initializing memory.
    * **Moving memory:** `LoweredMove*` is used for copying blocks of memory.

5. **Provide Go Code Examples:**  To illustrate the connection, think about simple Go code snippets and how they might translate into the defined operations:
    * **Load:** `x := y` (where `y` is a variable) could involve a `MOVBload`, `MOVHload`, `MOVWload`, or `MOVDload` depending on the type of `y`.
    * **Store:** `x = 10` could involve a `MOVBstore`, `MOVHstore`, `MOVWstore`, or `MOVDstore`.
    * **Function call:** `f()` would translate to a `CALLstatic` (for regular functions) or `CALLclosure` (for closures).
    * **Arithmetic:** `a + b` would use an `ADD` operation.
    * **Comparison:** `if a > b` would use a `CMP` or `CMPU` followed by a conditional branch.

6. **Address Other Points in the Prompt:**
    * **Command-line arguments:** This specific code is part of the compiler's internal workings and doesn't directly interact with command-line arguments. The compiler itself takes arguments, but this file is a data structure within it.
    * **Pitfalls:**  Consider common errors when dealing with low-level operations. While users don't directly write these, the *compiler developers* need to be careful about:
        * **Incorrect register allocation:**  Assigning the wrong registers can lead to incorrect behavior or crashes. The `regInfo` helps enforce these constraints.
        * **Incorrect instruction selection:**  Choosing the wrong assembly instruction for a given operation.
        * **Handling side effects:**  Forgetting to mark an operation as having side effects can lead to incorrect optimization.
        * **Nil pointer dereferences:** The `faultOnNilArg0` flag highlights the importance of handling potential nil pointers.
    * **Input and Output for Code Inference:** The `regInfo` structure itself specifies the inputs and outputs in terms of register masks. This is the "input/output" in this context.

7. **Summarize Functionality:**  Combine the inferences into a concise summary. Emphasize the role of this code in the compilation process, bridging the gap between the SSA representation and the target architecture's assembly language.

8. **Structure the Answer:** Organize the findings logically, addressing each point in the prompt clearly and using headings for better readability. Use code blocks for examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is about some specific Go library or feature. *Correction:* The file path (`go/src/cmd/compile/internal/ssa/`) strongly suggests it's part of the Go compiler itself, specifically the SSA generation phase.
* **Considering command-line arguments:**  Initially think about compiler flags. *Correction:*  This specific code doesn't parse command-line arguments directly; it's used *by* the compiler, which *does* handle arguments.
* **Detailing pitfalls:** Focus on potential issues for *users* of Go. *Correction:*  This code is internal to the compiler. The pitfalls are more relevant for compiler *developers*. Reframe the pitfalls in that context.
* **Explaining `regInfo`:**  Realize the bitmasks in `regInfo` are crucial for understanding register allocation constraints. Explain what the numbers represent (sets of registers).

By following these steps, combining deduction with knowledge of compiler design and Go's internal structure, a comprehensive answer can be constructed.
这个 `opGen.go` 文件是 Go 语言编译器中 SSA（Static Single Assignment）中间表示生成的一部分，专门针对 **PPC64 架构** 定义了一系列的操作（operations）。这些操作是 Go 代码在编译过程中，被转换成更底层的、接近机器码的表示形式。

**功能归纳:**

从提供的第 27 部分代码来看，它主要定义了以下几类 PPC64 架构相关的操作：

1. **带索引的加载指令 (Load Indexed):**
   - `MOVBloadidx`, `MOVHloadidx`, `MOVWZloadidx`, `MOVDloadidx`:  从内存中加载不同大小（byte, half-word, word, double-word）的数据到寄存器。`Z` 后缀可能表示零扩展。
   - `MOVHBRloadidx`, `MOVWBRloadidx`, `MOVDBRloadidx`: 带字节反转的加载指令。这通常用于处理不同字节序的数据。
   - `FMOVDloadidx`, `FMOVSloadidx`: 加载浮点数（双精度和单精度）。
   - 这些指令的共同特点是使用一个基址寄存器和一个索引寄存器来计算内存地址。

2. **带索引的存储指令 (Store Indexed):**
   - `MOVBstoreidx`, `MOVHstoreidx`, `MOVWstoreidx`, `MOVDstoreidx`: 将寄存器中的数据存储到内存中的指定地址。
   - `FMOVDstoreidx`, `FMOVSstoreidx`: 存储浮点数。
   - `MOVHBRstoreidx`, `MOVWBRstoreidx`, `MOVDBRstoreidx`: 带字节反转的存储指令。

3. **其他内存操作:**
   - `DCBT`: 数据缓存块触摸 (Data Cache Block Touch)。这是一种缓存优化指令，用于预取数据到缓存中。
   - `MOVDBRstore`, `MOVWBRstore`, `MOVHBRstore`: 不带索引的带字节反转的存储指令。
   - `FMOVDload`, `FMOVSload`: 不带索引的浮点数加载指令。
   - `MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVDstore`: 不带索引的存储指令。
   - `MOVBstorezero`, `MOVHstorezero`, `MOVWstorezero`, `MOVDstorezero`: 将指定内存地址的值设置为零。

4. **地址和常量加载:**
   - `MOVDaddr`: 加载内存地址到寄存器。
   - `MOVDconst`: 加载 64 位常量到寄存器。
   - `FMOVDconst`, `FMOVSconst`: 加载浮点数常量到寄存器。

5. **比较指令:**
   - `FCMPU`: 浮点数比较 (Unordered)。
   - `CMP`, `CMPU`: 比较指令（有符号和无符号）。
   - `CMPW`, `CMPWU`: 比较字 (32 位) 指令（有符号和无符号）。
   - `CMPconst`, `CMPUconst`, `CMPWconst`, `CMPWUconst`:  与常量进行比较。

6. **条件选择指令:**
   - `ISEL`:  根据条件码选择两个寄存器中的一个。
   - `ISELZ`: 根据条件码选择一个寄存器或零。

7. **条件码设置指令:**
   - `SETBC`, `SETBCR`: 设置条件位。

8. **基于比较结果的布尔值生成:**
   - `Equal`, `NotEqual`, `LessThan`, `FLessThan`, `LessEqual`, `FLessEqual`, `GreaterThan`, `FGreaterThan`, `GreaterEqual`, `FGreaterEqual`:  基于之前的比较结果生成布尔值。

9. **获取运行时信息:**
   - `LoweredGetClosurePtr`: 获取闭包指针。
   - `LoweredGetCallerSP`: 获取调用者的栈指针。
   - `LoweredGetCallerPC`: 获取调用者的程序计数器。

10. **其他底层操作:**
    - `LoweredNilCheck`:  空指针检查。
    - `LoweredRound32F`, `LoweredRound64F`:  浮点数舍入。
    - `CALLstatic`, `CALLtail`, `CALLclosure`, `CALLinter`:  不同类型的函数调用指令。
    - `LoweredZero`, `LoweredZeroShort`, `LoweredQuadZero`, `LoweredQuadZeroShort`: 将内存区域置零。
    - `LoweredMove`, `LoweredMoveShort`, `LoweredQuadMove`, `LoweredQuadMoveShort`: 内存数据移动。
    - `LoweredAtomicStore8`, `LoweredAtomicStore32`, `LoweredAtomicStore64`: 原子存储操作。
    - `LoweredAtomicLoad8`, `LoweredAtomicLoad32`, `LoweredAtomicLoad64`: 原子加载操作。

**它是什么 Go 语言功能的实现？**

这些定义的操作是 Go 语言在 PPC64 架构上实现各种功能的基石。例如：

* **变量的加载和存储:**  `MOVBload`, `MOVDstore` 等指令直接对应 Go 语言中变量的读取和赋值操作。
* **函数调用:** `CALLstatic`, `CALLclosure` 等指令实现了 Go 语言的函数调用机制，包括普通函数、闭包和接口方法的调用。
* **指针操作:**  `MOVDaddr` 用于获取变量的地址，这在 Go 语言中使用指针时非常常见。
* **算术运算和比较:**  虽然这里没有直接列出算术运算，但同文件其他部分会定义 `ADD`, `SUB` 等操作。 `CMP` 系列指令用于实现 Go 语言中的比较运算符（`==`, `!=`, `<`, `>` 等）。
* **浮点数运算:**  `FMOVDload`, `FMOVDstore`, `FCMPU` 等指令支持 Go 语言中的 `float32` 和 `float64` 类型及其运算。
* **并发编程:** `LoweredAtomicStore` 和 `LoweredAtomicLoad` 系列指令是实现 Go 语言 `sync/atomic` 包的基础。
* **内存管理:** `LoweredZero` 和 `LoweredMove` 用于实现内存的初始化和拷贝，这在 Go 语言的切片、映射等数据结构的操作中非常重要。

**Go 代码举例说明:**

假设我们有以下 Go 代码片段：

```go
package main

func main() {
	var x int64 = 10
	var y int64
	y = x
	if y > 5 {
		println("y is greater than 5")
	}
}
```

在编译这个代码时，`opGen.go` 中定义的某些操作可能会被使用，例如（这是一个简化的例子，实际编译过程会更复杂）：

* `var x int64 = 10`:  可能会使用 `MOVDconst` 将常量 `10` 加载到寄存器，然后使用 `MOVDstore` 将其存储到 `x` 的内存地址。
* `y = x`: 可能会使用 `MOVDload` 将 `x` 的值加载到寄存器，然后使用 `MOVDstore` 将其存储到 `y` 的内存地址。
* `if y > 5`:
    * 可能会使用 `MOVDload` 将 `y` 的值加载到寄存器。
    * 可能会使用 `CMPconst` 将寄存器中的值与常量 `5` 进行比较。
    * 根据比较结果，后续可能会有条件分支指令（在 `opGen.go` 的其他部分定义）。

**假设的输入与输出（针对 `MOVDload` 指令）：**

假设我们正在编译 `y = x`，并且：

* **输入：**
    *  一个表示 `x` 的内存地址的 SSA 值（可能存储在某个寄存器中）。
* **输出：**
    *  一个表示 `x` 的值的 SSA 值（存储在某个寄存器中）。

在 `opGen.go` 中，`MOVDload` 的 `regInfo` 定义了输入和输出寄存器的限制：

```go
{
	name:           "MOVDload",
	auxType:        auxSymOff,
	argLen:         2,
	faultOnNilArg0: true,
	symEffect:      SymRead,
	asm:            ppc64.AMOVD,
	reg: regInfo{
		inputs: []inputInfo{
			{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
		},
		outputs: []outputInfo{
			{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
		},
	},
},
```

* **输入解释:** `{0, 1073733630}` 表示第一个输入参数（索引为 0）必须是一个寄存器，并且该寄存器可以是 SP, SB 或 R3-R12, R14-R29 中的任何一个。这里的 `1073733630` 是一个位掩码，表示这些寄存器的集合。
* **输出解释:** `{0, 1073733624}` 表示输出结果将存储在索引为 0 的寄存器中，并且该寄存器可以是 R3-R12, R14-R29 中的任何一个。

**命令行参数的具体处理:**

`opGen.go` 本身不处理命令行参数。它是 Go 编译器内部的一部分，用于生成 SSA 操作的定义。Go 编译器的命令行参数（例如 `-o`, `-gcflags` 等）在编译器的其他阶段进行处理，并最终影响到这里定义的 SSA 操作的使用方式。

**使用者易犯错的点:**

作为 Go 语言的开发者，你通常不会直接接触到 `opGen.go` 文件中的内容。这是编译器开发者的工作。普通开发者在使用 Go 语言时，不需要关心这些底层的指令定义。

**第 27 部分的功能总结:**

这部分 `opGen.go` 文件为 PPC64 架构定义了一系列用于内存访问（加载和存储）、常量加载、比较操作、条件选择、获取运行时信息以及其他底层操作的 SSA 操作。 这些操作是 Go 语言在 PPC64 平台上实现其各种高级功能的基础。它详细规定了每个操作的参数数量、对应的汇编指令、以及对输入和输出寄存器的要求，是 Go 编译器将 Go 代码转换为 PPC64 机器码的关键组成部分。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第27部分，共36部分，请归纳一下它的功能
```

### 源代码
```go
}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVWZloadidx",
		argLen: 3,
		asm:    ppc64.AMOVWZ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVDloadidx",
		argLen: 3,
		asm:    ppc64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVHBRloadidx",
		argLen: 3,
		asm:    ppc64.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVWBRloadidx",
		argLen: 3,
		asm:    ppc64.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVDBRloadidx",
		argLen: 3,
		asm:    ppc64.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "FMOVDloadidx",
		argLen: 3,
		asm:    ppc64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "FMOVSloadidx",
		argLen: 3,
		asm:    ppc64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:           "DCBT",
		auxType:        auxInt64,
		argLen:         2,
		hasSideEffects: true,
		asm:            ppc64.ADCBT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVDBRstore",
		argLen:         3,
		faultOnNilArg0: true,
		asm:            ppc64.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVWBRstore",
		argLen:         3,
		faultOnNilArg0: true,
		asm:            ppc64.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVHBRstore",
		argLen:         3,
		faultOnNilArg0: true,
		asm:            ppc64.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "FMOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            ppc64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:           "FMOVSload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            ppc64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVHstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "FMOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:           "FMOVSstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "MOVBstoreidx",
		argLen: 4,
		asm:    ppc64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVHstoreidx",
		argLen: 4,
		asm:    ppc64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVWstoreidx",
		argLen: 4,
		asm:    ppc64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVDstoreidx",
		argLen: 4,
		asm:    ppc64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "FMOVDstoreidx",
		argLen: 4,
		asm:    ppc64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "FMOVSstoreidx",
		argLen: 4,
		asm:    ppc64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "MOVHBRstoreidx",
		argLen: 4,
		asm:    ppc64.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVWBRstoreidx",
		argLen: 4,
		asm:    ppc64.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "MOVDBRstoreidx",
		argLen: 4,
		asm:    ppc64.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVBstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVHstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVWstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "MOVDstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            ppc64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:              "MOVDaddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		asm:               ppc64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:              "MOVDconst",
		auxType:           auxInt64,
		argLen:            0,
		rematerializeable: true,
		asm:               ppc64.AMOVD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:              "FMOVDconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               ppc64.AFMOVD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:              "FMOVSconst",
		auxType:           auxFloat32,
		argLen:            0,
		rematerializeable: true,
		asm:               ppc64.AFMOVS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "FCMPU",
		argLen: 2,
		asm:    ppc64.AFCMPU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "CMP",
		argLen: 2,
		asm:    ppc64.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "CMPU",
		argLen: 2,
		asm:    ppc64.ACMPU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "CMPW",
		argLen: 2,
		asm:    ppc64.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "CMPWU",
		argLen: 2,
		asm:    ppc64.ACMPWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "CMPconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "CMPUconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ACMPU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "CMPWconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     ppc64.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "CMPWUconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     ppc64.ACMPWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "ISEL",
		auxType: auxInt32,
		argLen:  3,
		asm:     ppc64.AISEL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "ISELZ",
		auxType: auxInt32,
		argLen:  2,
		asm:     ppc64.AISEL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "SETBC",
		auxType: auxInt32,
		argLen:  1,
		asm:     ppc64.ASETBC,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "SETBCR",
		auxType: auxInt32,
		argLen:  1,
		asm:     ppc64.ASETBCR,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "Equal",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "NotEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "LessThan",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "FLessThan",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "LessEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "FLessEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "GreaterThan",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "FGreaterThan",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "GreaterEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "FGreaterEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 2048}, // R11
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredNilCheck",
		argLen:         2,
		clobberFlags:   true,
		nilCheck:       true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 2147483648, // R31
		},
	},
	{
		name:         "LoweredRound32F",
		argLen:       1,
		resultInArg0: true,
		zeroWidth:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:         "LoweredRound64F",
		argLen:       1,
		resultInArg0: true,
		zeroWidth:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:         "CALLstatic",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			clobbers: 18446744071562059768, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29 g F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 XER
		},
	},
	{
		name:         "CALLtail",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		tailCall:     true,
		reg: regInfo{
			clobbers: 18446744071562059768, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29 g F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 XER
		},
	},
	{
		name:         "CALLclosure",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4096}, // R12
				{1, 2048}, // R11
			},
			clobbers: 18446744071562059768, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29 g F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 XER
		},
	},
	{
		name:         "CALLinter",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4096}, // R12
			},
			clobbers: 18446744071562059768, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29 g F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 XER
		},
	},
	{
		name:           "LoweredZero",
		auxType:        auxInt64,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1048576}, // R20
			},
			clobbers: 1048576, // R20
		},
	},
	{
		name:           "LoweredZeroShort",
		auxType:        auxInt64,
		argLen:         2,
		faultOnNilArg0: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredQuadZeroShort",
		auxType:        auxInt64,
		argLen:         2,
		faultOnNilArg0: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredQuadZero",
		auxType:        auxInt64,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1048576}, // R20
			},
			clobbers: 1048576, // R20
		},
	},
	{
		name:           "LoweredMove",
		auxType:        auxInt64,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1048576}, // R20
				{1, 2097152}, // R21
			},
			clobbers: 3145728, // R20 R21
		},
	},
	{
		name:           "LoweredMoveShort",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredQuadMove",
		auxType:        auxInt64,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1048576}, // R20
				{1, 2097152}, // R21
			},
			clobbers: 3145728, // R20 R21
		},
	},
	{
		name:           "LoweredQuadMoveShort",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicStore8",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicStore32",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicStore64",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicLoad8",
		auxType:        auxInt64,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicLoad32",
		auxType:        auxInt64,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicLoad64",
		auxType:        auxInt64,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R
```