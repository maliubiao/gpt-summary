Response:
Let's break down the thought process for answering this complex question.

1. **Understand the Goal:** The primary goal is to analyze the provided Go code snippet from `opGen.go` and explain its function within the larger Go compilation process. The request specifically asks for:
    * Functionality of the code.
    * Inferring the Go language feature it implements.
    * Illustrative Go code examples.
    * Details about command-line arguments (if applicable).
    * Common user errors (if applicable).
    * A summary of this specific section's function.

2. **Initial Observation and Keyword Spotting:**  The code is a large array of structs. Each struct has fields like `name`, `auxType`, `argLen`, `asm`, and `reg`. The `asm` field contains constants like `riscv.ASLLI`, `riscv.AAND`, etc. This immediately suggests that this section is defining *operations* for a specific architecture (RISC-V). The "opGen" in the file path reinforces this idea – it likely generates opcodes or operation descriptions.

3. **Analyzing the Struct Fields:**
    * `name`:  Clearly the name of the operation (e.g., "SLLI", "AND", "FADDS").
    * `auxType`:  Indicates if the operation uses an auxiliary value (like an immediate). The `auxInt64` suggests an integer auxiliary value.
    * `argLen`:  Number of arguments the operation takes. `-1` likely means a variable number of arguments (common for function calls).
    * `asm`:  The corresponding RISC-V assembly instruction.
    * `reg`:  A `regInfo` struct. This is the most complex part and needs further examination.

4. **Deciphering `regInfo`:**  The `regInfo` struct contains `inputs` and `outputs`, both slices of `inputInfo` and `outputInfo` respectively. These structs have a single field: an integer. The comments within these integer fields are crucial: "X5 X6...", "F0 F1...". This strongly suggests that these integers are *bitmasks* representing which registers are used as inputs and outputs for the operation.

5. **Inferring the Go Feature:** Given the context of compiler internals (`cmd/compile`), SSA (Static Single Assignment form), and the architecture-specific nature of the operations, the code is likely involved in the *instruction selection* or *register allocation* phases of the compilation process. It defines how high-level Go operations are translated into low-level RISC-V instructions and which registers are involved.

6. **Constructing Go Code Examples:**  To illustrate, pick a few representative operations:
    * **`SLLI` (Shift Left Logical Immediate):** This directly translates to the `<<` operator in Go with a constant shift amount.
    * **`AND` (Bitwise AND):**  The `&` operator in Go.
    * **`FADDS` (Floating-Point Add Single):** The `+` operator for `float32`.
    * **`CALLstatic` (Static Function Call):** A regular function call in Go.

7. **Considering Command-Line Arguments and User Errors:** This specific code snippet doesn't directly process command-line arguments. It's a data structure used by the compiler. Similarly, end-users don't directly interact with this code, so there aren't typical user errors to point out *within the context of this file*. However, a related error *could* be incorrect usage of the Go language constructs that these operations eventually implement (e.g., using bitwise operators on incompatible types). Decide to mention this broader connection rather than invent direct errors.

8. **Synthesizing the Section's Function:** This specific section of `opGen.go` (part 29/36) focuses on defining a set of *arithmetic, logical, and some control-flow related* operations for the RISC-V architecture. It specifies the operation names, their corresponding assembly instructions, and the register usage patterns. Since it's part 29, and the operations seem to be grouped thematically, it's likely that previous and subsequent sections handle other types of operations (memory access, comparisons, etc.).

9. **Structuring the Answer:** Organize the information logically, following the prompts in the request:
    * Start with a general statement of the file's purpose.
    * List the key functionalities observed in the provided snippet.
    * Explain the inferred Go feature (instruction selection/register allocation).
    * Provide clear and concise Go code examples, linking them to specific operations.
    * State that command-line arguments aren't directly handled here.
    * Explain why direct user errors aren't applicable to this internal file, but mention related language-level errors.
    * Conclude with a summary of this particular section's role.

10. **Refinement and Language:** Use precise language, avoid jargon where possible, and explain technical terms when necessary. Ensure the answer is in Chinese as requested. Double-check the Go code examples for correctness.

**(Self-Correction during the process):** Initially, I might have thought the `auxType` was directly related to Go types. However, seeing `auxInt64` used for various operations suggests it's more about an auxiliary *value* than a specific Go type. The register bitmasks need careful interpretation – realize they are not just arbitrary numbers but represent sets of registers. The `-1` for `argLen` for call instructions is a key detail to notice.
这个 `go/src/cmd/compile/internal/ssa/opGen.go` 文件的第 29 部分，定义了一系列针对 RISC-V 架构的**算术、逻辑和一些控制流**相关的 SSA 操作 (Operations)。

**它的主要功能是：**

1. **定义 SSA 操作的属性：**  对于每个 RISC-V 指令，这个代码片段定义了其在 SSA 中对应的操作名称 (`name`)、需要的辅助信息类型 (`auxType`)、操作数的数量 (`argLen`)、对应的汇编指令 (`asm`) 以及寄存器信息 (`reg`)。

2. **描述寄存器约束：** `reg` 字段中的 `regInfo` 结构体详细说明了该操作的输入和输出参数需要使用哪些寄存器。这对于后续的寄存器分配阶段至关重要。  例如，`inputs` 数组指定了哪些寄存器可以作为输入，而 `outputs` 数组指定了结果会存放在哪个寄存器中。  `1006632944` 这样的数字实际上是一个位掩码，用来表示一组可能的寄存器。例如，对于 X86 架构，这个掩码可能代表 `AX`, `BX`, `CX` 等寄存器。 在 RISC-V 的上下文中，`1006632944` 这个值（二进制是 `0b111111111111111111111111110000`） 对应于 X5 到 X30 这些通用寄存器。

3. **标记操作的特性：** 某些操作还带有额外的标记，如 `commutative: true` 表示操作满足交换律，`call: true` 表示这是一个函数调用操作， `tailCall: true` 表示这是一个尾调用， `faultOnNilArg0: true` 表示如果第一个参数为空指针则会触发错误， `hasSideEffects: true` 表示操作会产生副作用， `unsafePoint: true` 表示这是一个不安全点（可能需要保存寄存器）， `resultInArg0: true` 表示结果会写回到第一个输入参数的寄存器中， `resultNotInArgs: true` 表示结果不在输入参数的寄存器中， `nilCheck: true` 表示这是一个空指针检查操作， `rematerializeable: true` 表示这个操作可以重新计算， `clobberFlags: true` 表示这个操作会修改标志位。

**可以推理出它是什么 Go 语言功能的实现：**

这个代码片段是 Go 编译器中 **SSA 中间表示生成** 的一部分，并且更具体地涉及到 **指令选择 (Instruction Selection)** 和 **寄存器分配 (Register Allocation)** 的早期阶段。 它定义了如何将 Go 语言中的各种操作（例如加法、位运算、函数调用等）映射到目标架构（这里是 RISC-V）的机器指令，并初步规划了寄存器的使用。

**Go 代码举例说明：**

假设我们有以下 Go 代码：

```go
package main

func main() {
	a := 10
	b := 5
	c := a & b // 位与运算
	println(c)
}
```

当 Go 编译器编译这段代码并生成 RISC-V 汇编时， `c := a & b` 这个位与运算可能会对应到 `opGen.go` 中定义的 `AND` 操作。

**假设的 SSA 输入 (简化)：**

```
v1 = ConstInt 10
v2 = ConstInt 5
v3 = AND v1 v2
```

**对应的 `AND` 操作定义：**

```go
{
	name:        "AND",
	argLen:      2,
	commutative: true,
	asm:         riscv.AAND,
	reg: regInfo{
		inputs: []inputInfo{
			{0, 1006632944}, // X5 X6 ... X30
			{1, 1006632944}, // X5 X6 ... X30
		},
		outputs: []outputInfo{
			{0, 1006632944}, // X5 X6 ... X30
		},
	},
},
```

**可能的 RISC-V 汇编输出 (简化)：**

```assembly
# 假设 v1 被分配到 X5， v2 被分配到 X6， v3 被分配到 X7
andi x5, x0, 10  // 将常量 10 加载到 X5
andi x6, x0, 5   // 将常量 5 加载到 X6
and  x7, x5, x6  // 执行位与运算，结果存放在 X7
```

在这个例子中，`opGen.go` 中 `AND` 操作的定义告诉编译器：

* 这对应于 RISC-V 的 `and` 指令 (`riscv.AAND`).
* 它需要两个输入，并且这两个输入可以放在 X5 到 X30 的任何通用寄存器中。
* 它的输出结果会放在 X5 到 X30 的某个通用寄存器中。

**涉及代码推理的假设输入与输出：**

例如，对于 `SLLI` (Shift Left Logical Immediate，逻辑左移立即数) 操作：

**假设的 SSA 输入：**

```
v1 = SomeValue
v2 = ConstInt 3
v3 = SLLI v1 v2
```

**对应的 `SLLI` 操作定义：**

```go
{
	name:    "SLLI",
	auxType: auxInt64,
	argLen:  1,
	asm:     riscv.ASLLI,
	reg: regInfo{
		inputs: []inputInfo{
			{0, 1006632944}, // X5 X6 ... X30
		},
		outputs: []outputInfo{
			{0, 1006632944}, // X5 X6 ... X30
		},
	},
},
```

**可能的 RISC-V 汇编输出：**

```assembly
# 假设 v1 被分配到 X8， v3 被分配到 X9
mv x8, ... // 将 SomeValue 的值移动到 X8
slli x9, x8, 3 // 将 X8 的值逻辑左移 3 位，结果存放在 X9
```

这里， `auxType: auxInt64` 表明 `SLLI` 操作需要一个 64 位的立即数作为辅助信息（即移位的位数）。

**命令行参数的具体处理：**

这个 `opGen.go` 文件本身并不直接处理命令行参数。 它是 Go 编译器内部的一个数据定义文件。 命令行参数的处理发生在编译器的其他部分，例如 `go tool compile` 的入口点。  这些参数会影响编译器的行为，最终可能会影响到这里定义的 SSA 操作的使用方式，例如选择不同的优化级别可能会导致使用不同的指令序列。

**使用者易犯错的点：**

普通 Go 语言开发者不会直接接触到 `opGen.go` 这样的编译器内部文件，因此不存在直接使用上的错误。  这个文件是编译器开发者的工作内容。  然而，理解这里定义的操作有助于理解 Go 代码最终是如何被转换成机器码的，以及不同硬件架构之间的差异。

**第 29 部分的功能归纳：**

这个 `opGen.go` 文件的第 29 部分，专注于定义了一系列针对 RISC-V 架构的**基本的整数和逻辑运算**相关的 SSA 操作。 这些操作包括位移、按位逻辑运算（AND, OR, XOR, NOT 等）、加法变种（SH1ADD, SH2ADD, SH3ADD）以及一些比较运算和函数调用相关的操作。它详细描述了这些操作的名称、参数数量、对应的 RISC-V 汇编指令以及对寄存器的使用约束。 这是 Go 编译器将 Go 语言代码转化为高效的 RISC-V 机器码的关键步骤之一。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第29部分，共36部分，请归纳一下它的功能
```

### 源代码
```go
X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "SLLI",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ASLLI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "SLLIW",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ASLLIW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "SRAI",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ASRAI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "SRAIW",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ASRAIW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "SRLI",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ASRLI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "SRLIW",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ASRLIW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "SH1ADD",
		argLen: 2,
		asm:    riscv.ASH1ADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "SH2ADD",
		argLen: 2,
		asm:    riscv.ASH2ADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "SH3ADD",
		argLen: 2,
		asm:    riscv.ASH3ADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "AND",
		argLen:      2,
		commutative: true,
		asm:         riscv.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "ANDN",
		argLen: 2,
		asm:    riscv.AANDN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "ANDI",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.AANDI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "NOT",
		argLen: 1,
		asm:    riscv.ANOT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "OR",
		argLen:      2,
		commutative: true,
		asm:         riscv.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "ORN",
		argLen: 2,
		asm:    riscv.AORN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "ORI",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.AORI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "ROL",
		argLen: 2,
		asm:    riscv.AROL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "ROLW",
		argLen: 2,
		asm:    riscv.AROLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "ROR",
		argLen: 2,
		asm:    riscv.AROR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "RORI",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ARORI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "RORIW",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ARORIW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "RORW",
		argLen: 2,
		asm:    riscv.ARORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "XNOR",
		argLen:      2,
		commutative: true,
		asm:         riscv.AXNOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "XOR",
		argLen:      2,
		commutative: true,
		asm:         riscv.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "XORI",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.AXORI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "MIN",
		argLen:      2,
		commutative: true,
		asm:         riscv.AMIN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "MAX",
		argLen:      2,
		commutative: true,
		asm:         riscv.AMAX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "MINU",
		argLen:      2,
		commutative: true,
		asm:         riscv.AMINU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "MAXU",
		argLen:      2,
		commutative: true,
		asm:         riscv.AMAXU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "SEQZ",
		argLen: 1,
		asm:    riscv.ASEQZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "SNEZ",
		argLen: 1,
		asm:    riscv.ASNEZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "SLT",
		argLen: 2,
		asm:    riscv.ASLT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "SLTI",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ASLTI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "SLTU",
		argLen: 2,
		asm:    riscv.ASLTU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:    "SLTIU",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.ASLTIU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:         "LoweredRound32F",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:         "LoweredRound64F",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:    "CALLstatic",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		reg: regInfo{
			clobbers: 9223372035781033968, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:     "CALLtail",
		auxType:  auxCallOff,
		argLen:   -1,
		call:     true,
		tailCall: true,
		reg: regInfo{
			clobbers: 9223372035781033968, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:    "CALLclosure",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 33554432},   // X26
				{0, 1006632946}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			clobbers: 9223372035781033968, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:    "CALLinter",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			clobbers: 9223372035781033968, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:           "DUFFZERO",
		auxType:        auxInt64,
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 16777216}, // X25
			},
			clobbers: 16777216, // X25
		},
	},
	{
		name:           "DUFFCOPY",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 16777216}, // X25
				{1, 8388608},  // X24
			},
			clobbers: 25165824, // X24 X25
		},
	},
	{
		name:           "LoweredZero",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 16},         // X5
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			clobbers: 16, // X5
		},
	},
	{
		name:           "LoweredMove",
		auxType:        auxInt64,
		argLen:         4,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 16},         // X5
				{1, 32},         // X6
				{2, 1006632880}, // X5 X6 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			clobbers: 112, // X5 X6 X7
		},
	},
	{
		name:           "LoweredAtomicLoad8",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:           "LoweredAtomicLoad32",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:           "LoweredAtomicLoad64",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:           "LoweredAtomicStore8",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1006632946},          // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1006632946},          // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore64",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1006632946},          // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:            "LoweredAtomicExchange32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{0, 9223372037928517618}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:            "LoweredAtomicExchange64",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{0, 9223372037928517618}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:            "LoweredAtomicAdd32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{0, 9223372037928517618}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:            "LoweredAtomicAdd64",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{0, 9223372037928517618}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:            "LoweredAtomicCas32",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{2, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{0, 9223372037928517618}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:            "LoweredAtomicCas64",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{2, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{0, 9223372037928517618}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:           "LoweredAtomicAnd32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		asm:            riscv.AAMOANDW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{0, 9223372037928517618}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 SB
			},
		},
	},
	{
		name:           "LoweredAtomicOr32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		asm:            riscv.AAMOORW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741808},          // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30
				{0, 9223372037928517618}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 g X28 X29 X30 SB
			},
		},
	},
	{
		name:           "LoweredNilCheck",
		argLen:         2,
		nilCheck:       true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632946}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "LoweredGetClosurePtr",
		argLen: 0,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 33554432}, // X26
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 9223372034707292160, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			outputs: []outputInfo{
				{0, 8388608}, // X24
			},
		},
	},
	{
		name:           "LoweredPubBarrier",
		argLen:         1,
		hasSideEffects: true,
		asm:            riscv.AFENCE,
		reg:            regInfo{},
	},
	{
		name:    "LoweredPanicBoundsA",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 64},        // X7
				{1, 134217728}, // X28
			},
		},
	},
	{
		name:    "LoweredPanicBoundsB",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 32}, // X6
				{1, 64}, // X7
			},
		},
	},
	{
		name:    "LoweredPanicBoundsC",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 16}, // X5
				{1, 32}, // X6
			},
		},
	},
	{
		name:        "FADDS",
		argLen:      2,
		commutative: true,
		asm:         riscv.AFADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FSUBS",
		argLen: 2,
		asm:    riscv.AFSUBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FMULS",
		argLen:      2,
		commutative: true,
		asm:         riscv.AFMULS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FDIVS",
		argLen: 2,
		asm:    riscv.AFDIVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FMADDS",
		argLen:      3,
		commutative: true,
		asm:         riscv.AFMADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F
```