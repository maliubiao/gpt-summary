Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding and Goal:**

The prompt asks for the functionality of the provided Go code, specifically section 30 of a 36-part file (`opGen.go`). The goal is to understand what this code does within the context of the Go compiler.

**2. Code Structure and Key Observations:**

* **Array of Structs:** The code clearly defines a Go slice (array) of structs. Each struct literal within the slice represents an entry.
* **`name` Field:**  Each struct has a `name` field (e.g., "FADDS", "FMSUBS"). These names look like assembly instruction mnemonics, likely for floating-point operations.
* **`argLen` Field:**  This field indicates the number of arguments the operation takes.
* **`commutative` Field:** A boolean indicating if the order of operands doesn't matter.
* **`asm` Field:** This strongly suggests a connection to assembly instructions. The values like `riscv.AFMSUBS` and `s390x.AFADDS` point to specific assembly instruction sets for different architectures (RISC-V and s390x).
* **`reg` Field:** This field is a nested struct (`regInfo`) containing `inputs` and `outputs`. These are slices of `inputInfo` and `outputInfo`, respectively.
* **`inputInfo`/`outputInfo`:**  These structs have two fields. The first field (e.g., `0`, `1`, `2`) likely represents the index of the argument/result. The second field is a large integer.
* **Register Masks (The Large Integers):** The large integers in the `inputInfo` and `outputInfo` seem to be bitmasks. Let's examine one: `9223372034707292160`. Converting this to binary (mentally or with a calculator) reveals a pattern of set bits. Recognizing powers of 2 is key here. `2^30 + 2^29 + ... + 2^5`. This corresponds to floating-point registers F31 down to F5. Similarly, `1006632944` in binary maps to X30 down to X5 (general-purpose registers).
* **Architectural Specificity:** The presence of `riscv.` and `s390x.` prefixes in the `asm` field indicates that this code handles instruction definitions for multiple architectures. The snippet shows definitions for RISC-V and then a small set for s390x.
* **`auxType`, `faultOnNilArg0`, `symEffect`, `resultNotInArgs`, `resultInArg0`, `clobberFlags`:** These fields offer further details about the operations, like handling of auxiliary information (symbols and offsets), potential fault conditions, memory side effects, and how results are handled.

**3. Formulating Hypotheses:**

Based on these observations, we can form the following hypotheses:

* **Instruction Set Mapping:** This code defines a mapping between high-level intermediate representation (IR) operations and specific assembly instructions for different target architectures.
* **Register Allocation Information:** The `regInfo` structure provides constraints or preferences for which registers can be used for the inputs and outputs of each operation. The bitmasks represent sets of allowed registers.
* **SSA (Static Single Assignment):** The file path `go/src/cmd/compile/internal/ssa/opGen.go` strongly suggests that this code is part of the SSA generation or optimization phase of the Go compiler. SSA is an intermediate representation used in compilers.

**4. Reasoning about Functionality:**

Combining the hypotheses and observations leads to a clearer understanding of the functionality:

* **Operation Definitions:** The structs define the properties of various operations, including their names, number of arguments, commutativity, and the underlying assembly instruction.
* **Target Architecture Support:** The code supports multiple architectures (RISC-V and s390x in this snippet) by providing architecture-specific assembly mnemonics.
* **Register Constraints:** The `regInfo` section specifies which registers are permissible for the input and output values of each operation. This information is crucial for the register allocation phase of the compiler. The bitmasks efficiently represent these sets of registers.
* **Load/Store Operations:** The "FMOVWload" and "FMOVWstore" entries indicate how floating-point values are loaded from and stored to memory. The `auxType: auxSymOff` suggests handling of symbol offsets.
* **Floating-Point Comparisons:** Operations like "FEQS", "FLTS", and "FLES" represent floating-point comparison instructions, and their output is a general-purpose register (X registers), indicating a boolean result.
* **Floating-Point Conversions:**  Instructions like "FCVTSW" and "FCVTWS" handle conversions between floating-point and integer types.

**5. Go Code Example (Conceptual):**

To illustrate the functionality, a conceptual Go code example helps. Imagine the compiler encounters a floating-point addition. It would look up the "FADDS" entry in this table to determine the corresponding assembly instruction (`riscv.AFADDS` or `s390x.AFADDS` depending on the target) and the allowed registers for the operands and result.

**6. Command-Line Arguments (Inference):**

While the snippet doesn't show explicit command-line argument parsing, it's reasonable to infer that the target architecture is likely specified as a command-line argument to the Go compiler. This argument would determine which set of assembly instructions (`riscv.*` or `s390x.*`) are used.

**7. Potential Errors (Inference):**

Based on the register constraints, a potential error could occur if the register allocator fails to find a valid assignment of registers that satisfy the constraints defined in `regInfo`. This isn't an error a user would directly make in their Go code, but an internal compiler issue.

**8. Summarization (Final Step):**

Finally, the task asks for a summary. The core function is defining operations for the SSA intermediate representation, mapping them to target-specific assembly instructions, and providing register allocation information.

This detailed thought process, moving from low-level code observations to higher-level inferences about compiler behavior, is crucial for understanding such code snippets. Recognizing patterns (like the register masks), understanding compiler phases (like SSA and register allocation), and leveraging contextual information (like the file path) are key skills in reverse-engineering or analyzing compiler internals.
这是 `go/src/cmd/compile/internal/ssa/opGen.go` 文件的一部分，它定义了特定架构（这里主要是 RISC-V 和部分 s390x）的 SSA (Static Single Assignment) 中间表示的操作 (operations)。

**功能归纳:**

这部分代码定义了 RISC-V 和部分 s390x 架构下浮点数运算相关的 SSA 操作。它详细描述了每个操作的名称、参数个数、是否满足交换律、对应的汇编指令，以及输入和输出寄存器的限制。

**具体功能列表:**

1. **定义 SSA 操作名称 (`name`)**:  例如 "FADDS", "FMSUBS", "FSQRTS" 等，这些是 SSA 层面表示的浮点数操作。

2. **指定参数长度 (`argLen`)**:  指明该操作需要多少个输入参数。

3. **指示是否满足交换律 (`commutative`)**:  布尔值，表明操作数的顺序是否可以互换而不影响结果。

4. **关联目标架构的汇编指令 (`asm`)**:  使用 `riscv.` 或 `s390x.` 前缀，将 SSA 操作映射到具体的汇编指令。例如，SSA 的 "FADDS" 操作对应 RISC-V 的 `riscv.AFADDS` 指令。

5. **定义寄存器信息 (`reg`)**:  这是一个 `regInfo` 结构体，包含输入和输出寄存器的信息。
   - **输入寄存器 (`inputs`)**:  一个 `inputInfo` 数组，每个 `inputInfo` 结构体包含两个字段：
     - 寄存器索引 (通常是 `0`, `1`, `2`，表示第一个、第二个、第三个输入)。
     - 寄存器掩码 (一个大的整数，其二进制表示中为 1 的位对应允许使用的寄存器)。 例如，`9223372034707292160` 的二进制表示中，F31 到 F0 位为 1，表示可以使用浮点寄存器 F0 到 F31。`1006632944` 的二进制表示中，X30, X29, X28, X26, X25 到 X5 位为 1，表示可以使用通用寄存器 X5, X6, ... X30 (注意中间跳过了某些寄存器)。
   - **输出寄存器 (`outputs`)**: 一个 `outputInfo` 数组，结构与 `inputInfo` 类似，定义了输出结果可以存放的寄存器。

6. **其他属性**:
   - `auxType`:  指定辅助信息的类型，例如 `auxSymOff` 表示符号和偏移量。
   - `faultOnNilArg0`:  布尔值，表示如果第一个参数为 nil 是否会触发错误。
   - `symEffect`:  指定操作对符号的影响，例如 `SymRead` 或 `SymWrite`。
   - `resultNotInArgs`: 布尔值，表示结果不直接覆盖输入参数。
   - `resultInArg0`: 布尔值，表示结果会存储在第一个输入参数的寄存器中。
   - `clobberFlags`: 布尔值，表示该操作会修改 CPU 的标志位。

**推理的 Go 语言功能实现 (浮点数加法):**

这部分代码定义了编译器在进行 SSA 中间表示构建时如何表示浮点数加法操作。 当 Go 源代码中出现浮点数加法时，编译器会在 SSA 图中创建一个对应的 "FADDS" 或 "FADDD" (单精度或双精度) 操作节点。

```go
package main

import "fmt"

func main() {
	a := 3.14
	b := 2.71
	c := a + b
	fmt.Println(c)
}
```

**假设的输入与输出 (针对 "FADDS" 操作):**

假设编译器在处理上述代码时，遇到了单精度浮点数加法 `a + b`。

**假设输入:**

- SSA 操作类型:  `FADDS`
- 输入参数 0:  代表变量 `a` 的 SSA 值 (假设存储在浮点寄存器 F5)
- 输入参数 1:  代表变量 `b` 的 SSA 值 (假设存储在浮点寄存器 F6)

**根据 `opGen.go` 的定义，"FADDS" 的 `regInfo` 如下:**

```
{
	name:         "FADDS",
	argLen:       2,
	commutative:  true,
	resultInArg0: true,
	asm:          s390x.AFADDS, // 注意这里是 s390x 的例子，原文中也有 RISC-V 的 FADDS
	reg: regInfo{
		inputs: []inputInfo{
			{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
		outputs: []outputInfo{
			{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
},
```

**假设输出:**

- SSA 值代表 `c` 的结果，并且根据 `resultInArg0: true` 和 `outputs: [{0, ...}]`，结果会存储在与第一个输入参数相同的寄存器中 (即 F5)。
- 编译器会生成相应的汇编指令 (对于 s390x 架构是 `AFADDS`)，指示 CPU 执行浮点数加法。

**代码推理 (以 "FMVSX" 为例):**

"FMVSX" 操作将通用寄存器的值移动到浮点寄存器。

**假设输入:**

- SSA 操作类型: `FMVSX`
- 输入参数 0: 代表一个整型变量的 SSA 值 (假设存储在通用寄存器 X5)

**根据 `opGen.go` 的定义:**

```
{
	name:   "FMVSX",
	argLen: 1,
	asm:    riscv.AFMVSX,
	reg: regInfo{
		inputs: []inputInfo{
			{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
		},
		outputs: []outputInfo{
			{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
},
```

**假设输出:**

- SSA 值代表移动后的浮点数值，并且根据 `outputs: [{0, ...}]`，结果会存储在某个浮点寄存器中 (F0 到 F31 中的任意一个)。
- 编译器会生成 RISC-V 的 `AFMVSX` 汇编指令，将 X5 寄存器的值移动到选定的浮点寄存器。

**命令行参数的具体处理:**

这部分代码本身并不直接处理命令行参数。但是，`opGen.go` 文件会被 `go` 编译器的代码生成部分使用。 `go` 编译器的命令行参数 (例如 `-arch=riscv64` 或 `-gcflags=-S`) 会影响最终生成的代码，从而间接决定了这里定义的哪些 SSA 操作和对应的汇编指令会被使用。编译器会根据目标架构选择合适的指令集。

**使用者易犯错的点:**

作为编译器内部实现的一部分，普通 Go 语言开发者不会直接使用或编辑这个文件。 因此，这里不存在使用者易犯错的点。 这里的 "使用者" 主要是指 Go 编译器的开发者。

**总结 (针对第 30 部分):**

第 30 部分的 `opGen.go` 代码主要定义了 RISC-V 和部分 s390x 架构中与浮点数操作相关的 SSA 中间表示的细节，包括操作的属性、对应的汇编指令以及输入输出寄存器的限制。 这是 Go 编译器将高级 Go 代码转换为特定架构机器码的关键步骤之一。  它为后续的 SSA 优化和最终的汇编代码生成提供了基础信息。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第30部分，共36部分，请归纳一下它的功能

"""
4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FMSUBS",
		argLen:      3,
		commutative: true,
		asm:         riscv.AFMSUBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMADDS",
		argLen:      3,
		commutative: true,
		asm:         riscv.AFNMADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMSUBS",
		argLen:      3,
		commutative: true,
		asm:         riscv.AFNMSUBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FSQRTS",
		argLen: 1,
		asm:    riscv.AFSQRTS,
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
		name:   "FNEGS",
		argLen: 1,
		asm:    riscv.AFNEGS,
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
		name:   "FMVSX",
		argLen: 1,
		asm:    riscv.AFMVSX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FCVTSW",
		argLen: 1,
		asm:    riscv.AFCVTSW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FCVTSL",
		argLen: 1,
		asm:    riscv.AFCVTSL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FCVTWS",
		argLen: 1,
		asm:    riscv.AFCVTWS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "FCVTLS",
		argLen: 1,
		asm:    riscv.AFCVTLS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:           "FMOVWload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            riscv.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "FMOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FEQS",
		argLen:      2,
		commutative: true,
		asm:         riscv.AFEQS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "FNES",
		argLen:      2,
		commutative: true,
		asm:         riscv.AFNES,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "FLTS",
		argLen: 2,
		asm:    riscv.AFLTS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "FLES",
		argLen: 2,
		asm:    riscv.AFLES,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:            "LoweredFMAXS",
		argLen:          2,
		commutative:     true,
		resultNotInArgs: true,
		asm:             riscv.AFMAXS,
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
		name:            "LoweredFMINS",
		argLen:          2,
		commutative:     true,
		resultNotInArgs: true,
		asm:             riscv.AFMINS,
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
		name:        "FADDD",
		argLen:      2,
		commutative: true,
		asm:         riscv.AFADDD,
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
		name:   "FSUBD",
		argLen: 2,
		asm:    riscv.AFSUBD,
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
		name:        "FMULD",
		argLen:      2,
		commutative: true,
		asm:         riscv.AFMULD,
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
		name:   "FDIVD",
		argLen: 2,
		asm:    riscv.AFDIVD,
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
		name:        "FMADDD",
		argLen:      3,
		commutative: true,
		asm:         riscv.AFMADDD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FMSUBD",
		argLen:      3,
		commutative: true,
		asm:         riscv.AFMSUBD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMADDD",
		argLen:      3,
		commutative: true,
		asm:         riscv.AFNMADDD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMSUBD",
		argLen:      3,
		commutative: true,
		asm:         riscv.AFNMSUBD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FSQRTD",
		argLen: 1,
		asm:    riscv.AFSQRTD,
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
		name:   "FNEGD",
		argLen: 1,
		asm:    riscv.AFNEGD,
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
		name:   "FABSD",
		argLen: 1,
		asm:    riscv.AFABSD,
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
		name:   "FSGNJD",
		argLen: 2,
		asm:    riscv.AFSGNJD,
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
		name:   "FMVDX",
		argLen: 1,
		asm:    riscv.AFMVDX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FCVTDW",
		argLen: 1,
		asm:    riscv.AFCVTDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FCVTDL",
		argLen: 1,
		asm:    riscv.AFCVTDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FCVTWD",
		argLen: 1,
		asm:    riscv.AFCVTWD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "FCVTLD",
		argLen: 1,
		asm:    riscv.AFCVTLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "FCVTDS",
		argLen: 1,
		asm:    riscv.AFCVTDS,
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
		name:   "FCVTSD",
		argLen: 1,
		asm:    riscv.AFCVTSD,
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
		name:           "FMOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            riscv.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "FMOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FEQD",
		argLen:      2,
		commutative: true,
		asm:         riscv.AFEQD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:        "FNED",
		argLen:      2,
		commutative: true,
		asm:         riscv.AFNED,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "FLTD",
		argLen: 2,
		asm:    riscv.AFLTD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "FLED",
		argLen: 2,
		asm:    riscv.AFLED,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:            "LoweredFMIND",
		argLen:          2,
		commutative:     true,
		resultNotInArgs: true,
		asm:             riscv.AFMIND,
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
		name:            "LoweredFMAXD",
		argLen:          2,
		commutative:     true,
		resultNotInArgs: true,
		asm:             riscv.AFMAXD,
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
		name:         "FADDS",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          s390x.AFADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FADD",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          s390x.AFADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FSUBS",
		argLen:       2,
		resultInArg0: true,
		asm:          s390x.AFSUBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FSUB",
		argLen:       2,
		resultInArg0: true,
		asm:          s390x.AFSUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FMULS",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          s390x.AFMULS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FMUL",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          s390x.AFMUL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FDIVS",
		argLen:       2,
		resultInArg0: true,
		asm:          s390x.AFDIVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FDIV",
		argLen:       2,
		resultInArg0: true,
		asm:          s390x.AFDIV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FNEGS",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.AFNEGS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FNEG",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.AFNEG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FMADDS",
		argLen:       3,
		resultInArg0: true,
		asm:          s390x.AFMADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FMADD",
		argLen:       3,
		resultInArg0: true,
		asm:          s390x.AFMADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FMSUBS",
		argLen:       3,
		resultInArg0: true,
		asm:          s390x.AFMSUBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FMSUB",
		argLen:       3,
		resultInArg0: true,
		asm:          s390x.AFMSUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LPDFR",
		argLen: 1,
		asm:    s390x.ALPDFR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LNDFR",
		argLen: 1,
		asm:    s390x.ALNDFR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "CPSDR",
		argLen: 2,
		asm:    s390x.ACPSDR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 42949
"""




```