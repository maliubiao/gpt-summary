Response:
Let's break down the thought process for answering the request.

**1. Understanding the Request:**

The core request is to analyze a snippet of Go code from `go/src/cmd/compile/internal/ssa/opGen.go`, specifically part 25 of 36. The goal is to determine its function, provide examples if possible, explain command-line handling (unlikely here), discuss potential user errors (also less likely given the nature of the code), and finally, summarize its function in the context of being part 25.

**2. Initial Examination of the Code Snippet:**

The provided code is an array of structs. Each struct seems to define a specific operation. Key fields in the struct are:

* `name`:  A string like "FADDS", "SUB", "MULLD". These strongly suggest assembly-level instructions or something very close to it.
* `argLen`:  The number of arguments the operation takes.
* `commutative`: A boolean indicating if the order of arguments matters.
* `asm`: A value like `ppc64.AFADDS`. This confirms that these are PowerPC 64-bit assembly instructions.
* `reg`:  A nested struct containing `inputs` and `outputs`, each being a list of `inputInfo` or `outputInfo`. These seem to describe register constraints. The numbers within the `inputInfo` and `outputInfo` likely represent bitmasks indicating which registers are allowed.

**3. Formulating the Core Function:**

Based on the structure and content, the primary function is clearly to **define and describe the properties of various assembly-level operations** for the PowerPC 64-bit architecture within the Go compiler's SSA (Static Single Assignment) framework.

**4. Inferring the Larger Go Feature:**

Knowing that this is within the `cmd/compile` package and deals with SSA, the next logical step is to connect it to the compilation process. The SSA form is an intermediate representation of Go code used during compilation. This data structure is used to map higher-level Go operations to their lower-level assembly counterparts. Therefore, it's highly probable that this code is crucial for **code generation**, specifically for translating SSA instructions into actual machine code for the PowerPC 64-bit architecture.

**5. Providing a Go Code Example (Illustrative):**

Since this file directly describes low-level operations, it's not something a typical Go user would directly interact with in their everyday coding. Therefore, a direct user-level Go code example isn't appropriate. Instead, an *illustrative* example demonstrating *the kind of Go code that would eventually be translated using these definitions* is the right approach. A simple arithmetic operation like `a + b` for floats and integers would be suitable. This shows *what* is being compiled, even if the `opGen.go` file doesn't directly handle the Go source code.

**6. Explaining Register Information:**

The `reg` field is significant. The numbers within the `inputInfo` and `outputInfo` are bitmasks. It's important to explain that these bitmasks represent the allowed registers for the inputs and outputs of the operation. Mentioning the 'F' prefix for floating-point registers and the 'R' prefix for general-purpose registers is helpful.

**7. Addressing Command-Line Parameters and User Errors:**

Given the internal nature of this file, it's unlikely to be directly affected by command-line parameters or prone to typical user errors. Therefore, stating that these are not directly applicable is the correct approach.

**8. Summarizing the Function as Part 25:**

Since this is part 25 of 36, the context is the overall process of generating these operation definitions. The key takeaway is that this specific part contributes to the **complete set of operation definitions** for the target architecture (PPC64). It's not doing something fundamentally different from the other parts; it's just adding more operations.

**9. Review and Refinement:**

After drafting the initial answer, reviewing and refining it for clarity and accuracy is important. Ensure the language is precise and avoids jargon where possible. For instance, initially, I might just say "register allocation," but it's more accurate to say "constrains the registers that can be used."  Also, double-checking the interpretation of the bitmasks and the overall purpose within the compiler is crucial.

This systematic approach, starting from the concrete code snippet and progressively inferring the larger context and implications, allows for a comprehensive and accurate answer to the request. The illustrative Go example serves to bridge the gap between the low-level definitions and the high-level language they ultimately serve.
这段代码是Go语言编译器（`cmd/compile`）内部 `ssa` 包中 `opGen.go` 文件的一部分，专门用于 **定义和描述 PowerPC 64位架构（ppc64）的各种操作（operations）**。

更具体地说，它定义了一个 Go 结构体切片，其中每个结构体都描述了一个特定的操作码，例如加法、减法、乘法等。 这些定义包含了操作的名称、参数长度、是否满足交换律、对应的汇编指令以及对寄存器使用的约束。

**主要功能归纳：**

这段代码的主要功能是为 `ssa` 包提供 **PowerPC 64位架构指令集的元数据**。 这些元数据被编译器用来：

1. **理解和表示中间代码 (SSA)：**  编译器在将Go源代码转换为机器码的过程中，会先将其转换为一种中间表示形式，即静态单赋值 (Static Single Assignment, SSA)。 这段代码定义的操作对应了 SSA 中的各种操作节点。
2. **进行指令选择和优化：**  编译器根据这些定义，可以将 SSA 操作映射到具体的 PowerPC 64位汇编指令。同时，寄存器信息可以帮助编译器进行寄存器分配和指令调度优化。
3. **生成汇编代码：**  最终，编译器会利用这些信息生成目标平台的汇编代码。

**代码功能详解：**

让我们逐个分析结构体中的字段：

* **`name`**:  操作的名称，例如 "FADDS" (浮点数加法单精度), "SUB" (整数减法) 等。
* **`argLen`**:  操作需要的参数个数。
* **`commutative`**:  布尔值，指示该操作是否满足交换律（即 `a + b` 是否等于 `b + a`）。
* **`asm`**:  对应的 PowerPC 64位汇编指令，例如 `ppc64.AFADDS`, `ppc64.ASUB`。
* **`reg`**: 一个 `regInfo` 结构体，描述了操作对寄存器的使用约束：
    * **`inputs`**: 一个 `inputInfo` 切片，描述了输入参数的寄存器约束。 每个 `inputInfo` 包含：
        * **`0`**:  表示参数索引（从 0 开始）。
        * **`9223372032559808512` (或类似的大数字)**:  一个位掩码，指示哪些寄存器可以用于该输入。例如，`9223372032559808512` 可能对应于浮点寄存器 F0 到 F31。 `1073733630` 可能对应于通用寄存器 R3 到 R29 以及 SP 和 SB。
    * **`outputs`**: 一个 `outputInfo` 切片，描述了输出结果的寄存器约束。
    * **`clobbers`**: 一个位掩码，指示该操作会覆盖哪些寄存器（除了输出寄存器）。例如 `9223372036854775808` 可能代表 XER 寄存器。
* **`auxType`**:  指定辅助参数的类型，例如 `auxInt64` 或 `auxInt32`，用于表示立即数常量。
* **`resultInArg0`**: 布尔值，指示结果是否存储在第一个输入参数的位置。

**推理 Go 语言功能的实现及代码示例：**

这段代码是 Go 编译器内部实现的一部分，它本身并不直接对应用户编写的 Go 代码功能。 相反，它定义了编译器如何将用户编写的 Go 代码中的操作转换为底层的机器指令。

例如，考虑以下 Go 代码：

```go
package main

func main() {
	a := 10
	b := 5
	c := a + b

	x := 1.5
	y := 2.5
	z := x + y
}
```

当使用 `go build` 命令编译这段代码时，编译器内部会使用 `opGen.go` 中定义的元数据来生成 PowerPC 64位汇编代码。

**假设的 SSA 中间表示（简化）：**

对于 `c := a + b`，SSA 中可能存在一个加法操作，它会使用 `opGen.go` 中 `ADD` 或类似的定义。

对于 `z := x + y`，SSA 中可能存在一个浮点数加法操作，它会使用 `opGen.go` 中 `FADDS` 或类似的定义.

**生成的汇编代码（仅为示例，可能不完全匹配）：**

对于 `c := a + b`，可能会生成类似如下的汇编代码：

```assembly
// 假设 a 在 R3，b 在 R4
ADD R5, R3, R4  // 将 R3 和 R4 的值相加，结果存入 R5
// 假设 c 被分配到 R5
```

对于 `z := x + y`，可能会生成类似如下的汇编代码：

```assembly
// 假设 x 在 F1，y 在 F2
FADDS F3, F1, F2 // 将 F1 和 F2 的值相加，结果存入 F3
// 假设 z 被分配到 F3
```

**代码推理（带假设的输入与输出）：**

以 "SUB" 操作为例：

```
{
	name:   "SUB",
	argLen: 2,
	asm:    ppc64.ASUB,
	reg: regInfo{
		inputs: []inputInfo{
			{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
		},
		outputs: []outputInfo{
			{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
		},
	},
},
```

**假设输入：**

* SSA 中存在一个 `SUB` 操作，其第一个操作数的值存储在寄存器 R3 中，第二个操作数的值存储在寄存器 R4 中。

**推理过程：**

1. 编译器查找到 `SUB` 操作的定义。
2. `argLen: 2` 表示这个操作有两个输入。
3. `asm: ppc64.ASUB` 表示对应的汇编指令是 `ASUB`。
4. `reg.inputs[0]` 的位掩码 `1073733630` 表明第一个输入可以位于 SP, SB 以及 R3 到 R12，R14 到 R29 这些寄存器中。
5. `reg.inputs[1]` 的位掩码 `1073733630` 表明第二个输入也可以位于相同的寄存器集合中。
6. `reg.outputs[0]` 的位掩码 `1073733624` 表明输出结果可以存储在 R3 到 R12，R14 到 R29 这些寄存器中。 注意，SP 和 SB 不在输出寄存器的允许列表中。

**假设输出（生成的汇编代码）：**

```assembly
ASUB R5, R3, R4  // 将 R3 和 R4 的值相减，结果存入 R5 (R5 是允许的输出寄存器)
```

**命令行参数的具体处理：**

`opGen.go` 文件本身不直接处理命令行参数。 命令行参数的处理发生在 `go` 工具链的其他部分，例如 `cmd/go` 和 `cmd/compile/main.go`。 这些部分会解析用户提供的命令行参数，并根据参数调用相应的编译器功能。

**使用者易犯错的点：**

由于 `opGen.go` 是 Go 编译器内部的核心组件，普通 Go 开发者不会直接接触或修改它。 因此，对于普通使用者来说，不容易犯错。 只有在修改 Go 编译器源代码时，才需要理解和修改这个文件。 即使是编译器开发者，也需要非常谨慎地修改，因为任何错误都可能导致生成的代码不正确。

**归纳一下它的功能 (作为第25部分)：**

考虑到这是 36 个部分中的第 25 部分，可以推断出整个 `opGen.go` 文件很可能是通过某种代码生成的方式创建的，或者是一个结构化的数据定义文件，被编译器加载和使用。

作为第 25 部分，它很可能 **继续定义了 PowerPC 64位架构指令集中的一部分操作**。  整个 `opGen.go` 文件会涵盖该架构下所有需要编译器处理的操作。  每一部分都负责定义一组相关的操作，例如算术运算、逻辑运算、位操作、浮点运算等。  第 25 部分可能专注于定义某种特定类型的操作，例如：

* 更多的算术运算（例如，带进位的加减法）。
* 更多的浮点数运算（例如，乘加、乘减）。
* 更多的位操作（例如，移位、旋转）。

总而言之，这段代码在 Go 编译器的代码生成过程中扮演着至关重要的角色，它提供了将高级 Go 代码转换为特定硬件平台指令的关键信息。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第25部分，共36部分，请归纳一下它的功能
```

### 源代码
```go
12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:        "FADDS",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AFADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "SUB",
		argLen: 2,
		asm:    ppc64.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "SUBCC",
		argLen: 2,
		asm:    ppc64.ASUBCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "SUBFCconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ASUBC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "FSUB",
		argLen: 2,
		asm:    ppc64.AFSUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "FSUBS",
		argLen: 2,
		asm:    ppc64.AFSUBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "XSMINJDP",
		argLen: 2,
		asm:    ppc64.AXSMINJDP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "XSMAXJDP",
		argLen: 2,
		asm:    ppc64.AXSMAXJDP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:        "MULLD",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AMULLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "MULLW",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AMULLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "MULLDconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     ppc64.AMULLD,
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
		name:    "MULLWconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     ppc64.AMULLW,
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
		name:   "MADDLD",
		argLen: 3,
		asm:    ppc64.AMADDLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "MULHD",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AMULHD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "MULHW",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AMULHW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "MULHDU",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AMULHDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "MULHDUCC",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AMULHDUCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "MULHWU",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AMULHWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "FMUL",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AFMUL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:        "FMULS",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AFMULS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "FMADD",
		argLen: 3,
		asm:    ppc64.AFMADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{2, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "FMADDS",
		argLen: 3,
		asm:    ppc64.AFMADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{2, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "FMSUB",
		argLen: 3,
		asm:    ppc64.AFMSUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{2, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "FMSUBS",
		argLen: 3,
		asm:    ppc64.AFMSUBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{2, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
		},
	},
	{
		name:   "SRAD",
		argLen: 2,
		asm:    ppc64.ASRAD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "SRAW",
		argLen: 2,
		asm:    ppc64.ASRAW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "SRD",
		argLen: 2,
		asm:    ppc64.ASRD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "SRW",
		argLen: 2,
		asm:    ppc64.ASRW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "SLD",
		argLen: 2,
		asm:    ppc64.ASLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "SLW",
		argLen: 2,
		asm:    ppc64.ASLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "ROTL",
		argLen: 2,
		asm:    ppc64.AROTL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "ROTLW",
		argLen: 2,
		asm:    ppc64.AROTLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "CLRLSLWI",
		auxType: auxInt32,
		argLen:  1,
		asm:     ppc64.ACLRLSLWI,
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
		name:    "CLRLSLDI",
		auxType: auxInt32,
		argLen:  1,
		asm:     ppc64.ACLRLSLDI,
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
		name:        "ADDC",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AADDC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{1, 9223372036854775808}, // XER
				{0, 1073733624},          // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "SUBC",
		argLen: 2,
		asm:    ppc64.ASUBC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{1, 9223372036854775808}, // XER
				{0, 1073733624},          // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "ADDCconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.AADDC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{1, 9223372036854775808}, // XER
				{0, 1073733624},          // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "SUBCconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ASUBC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{1, 9223372036854775808}, // XER
				{0, 1073733624},          // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "ADDE",
		argLen:      3,
		commutative: true,
		asm:         ppc64.AADDE,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 9223372036854775808}, // XER
				{0, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{1, 9223372036854775808}, // XER
				{0, 1073733624},          // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "ADDZE",
		argLen: 2,
		asm:    ppc64.AADDZE,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 9223372036854775808}, // XER
				{0, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{1, 9223372036854775808}, // XER
				{0, 1073733624},          // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "SUBE",
		argLen: 3,
		asm:    ppc64.ASUBE,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 9223372036854775808}, // XER
				{0, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630},          // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{1, 9223372036854775808}, // XER
				{0, 1073733624},          // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "ADDZEzero",
		argLen: 1,
		asm:    ppc64.AADDZE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372036854775808}, // XER
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:   "SUBZEzero",
		argLen: 1,
		asm:    ppc64.ASUBZE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372036854775808}, // XER
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "SRADconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ASRAD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "SRAWconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ASRAW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "SRDconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ASRD,
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
		name:    "SRWconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ASRW,
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
		name:    "SLDconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ASLD,
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
		name:    "SLWconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ASLW,
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
		name:    "ROTLconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.AROTL,
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
		name:    "ROTLWconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.AROTLW,
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
		name:    "EXTSWSLconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.AEXTSWSLI,
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
		name:    "RLWINM",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ARLWNM,
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
		name:    "RLWNM",
		auxType: auxInt64,
		argLen:  2,
		asm:     ppc64.ARLWNM,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:         "RLWMI",
		auxType:      auxInt64,
		argLen:       2,
		resultInArg0: true,
		asm:          ppc64.ARLWMI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "RLDICL",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ARLDICL,
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
		name:    "RLDICLCC",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ARLDICLCC,
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
		name:    "RLDICR",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.ARLDICR,
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
		name:   "CNTLZD",
		argLen: 1,
		asm:    ppc64.ACNTLZD,
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
		name:   "CNTLZDCC",
		argLen: 1,
		asm:    ppc64.ACNTLZDCC,
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
		name:   "CNTLZW",
		argLen: 1,
		asm:    ppc64.ACNTLZW,
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
		name:   "CNTTZD",
		argLen: 1,
		asm:    ppc64.ACNTTZD,
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
		name:   "CNTTZW",
		argLen: 1,
		asm:    ppc64.ACNTTZW,
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
		name:   "POPCNTD",
		argLen: 1,
		asm:    ppc64.APOPCNTD,
		reg: regInfo{
			inputs: []inputInfo
```