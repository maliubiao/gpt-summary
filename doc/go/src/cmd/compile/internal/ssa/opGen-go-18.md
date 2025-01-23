Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understanding the Goal:** The request asks for the functionality of this Go code snippet, specifically within the context of the Go compiler's SSA (Static Single Assignment) phase. It also asks for examples, possible errors, and a summary of this specific part. The "part 19 of 36" hints that this is a structured configuration or data definition.

2. **Initial Scan and Pattern Recognition:**  A quick look reveals a repeating structure of Go structs. Each struct has fields like `name`, `argLen`, `asm`, and `reg`. This suggests a definition of operations or instructions. The `loong64` prefix in `asm` strongly indicates this is specific to the LoongArch 64-bit architecture.

3. **Focusing on the `reg` Field:** The `reg` field itself is another struct (`regInfo`) containing `inputs` and `outputs`, which are slices of `inputInfo` and `outputInfo`. These inner structs have an index (0 or 1, sometimes 2) and a large integer. This strongly suggests register allocation or constraint information. The large integers are likely bitmasks representing allowed registers.

4. **Connecting to Compiler Functionality:**  Knowing this is in `cmd/compile/internal/ssa`, the connection to code generation becomes clear. This code is defining the available operations (instructions) for the LoongArch64 architecture and specifying how they interact with registers. The SSA form is an intermediate representation, so this isn't the final machine code, but a step closer.

5. **Analyzing Individual Entries (Examples):**
    * `"SQRTF"`:  Square root of a single-precision float. `argLen: 1` means one input. `asm: loong64.ASQRTF` is the assembler mnemonic. The `reg` part says the input and output must be one of the floating-point registers F0-F31.
    * `"CLZW"`: Count leading zeros in a word. `argLen: 1`. `asm: loong64.ACLZW`. The `reg` part shows that input can be from general-purpose registers R4-R31 (excluding R22, which is 'g' likely a special register), and the output can be a subset of those.
    * `"ADDV"`:  Add two values. `argLen: 2`. `commutative: true`. The input registers and output registers are similar to `CLZW`.
    * `"ADDVconst"`: Add a constant to a value. `auxType: auxInt64`. `argLen: 1`. The input can be SP (stack pointer) in addition to other general-purpose registers.

6. **Inferring the Broader Purpose:**  By looking at a variety of entries, the pattern solidifies. This code is a table or list that maps:
    * **Logical Operation Name:**  (e.g., "SQRTF", "ADDV") used within the compiler's SSA representation.
    * **Number of Arguments:**  How many inputs the operation takes.
    * **Assembler Mnemonic:** The corresponding low-level instruction for the target architecture.
    * **Register Constraints:**  Which registers can be used for the input and output values of the operation.

7. **Formulating the Explanation:**  Now, it's time to structure the answer.
    * **Core Function:** Clearly state the main purpose: defining SSA operations and their mapping to LoongArch64 instructions, including register constraints.
    * **Go Feature Implementation:** Identify that it's part of the code generation pipeline. Provide a simple Go example demonstrating the *concept* of addition, but acknowledge that the *specific* code generation is internal to the compiler. Emphasize that users don't directly interact with this file.
    * **Code Inference:**  Explain the structure of the `regInfo` and how the bitmasks represent allowed registers. Provide examples like the floating-point and general-purpose register sets. Explain how the indices in `inputInfo` relate to the arguments.
    * **Command-Line Arguments:** Recognize that this specific code doesn't directly handle command-line arguments.
    * **Potential Errors:** Think about what could go wrong in such a configuration. Incorrect register masks or mismatched argument counts could lead to compiler errors. Provide a simple example of incorrect register usage (conceptually) even if users don't directly modify this file.
    * **Part 19 of 36 Summary:** Summarize that this part focuses on defining *arithmetic and logical* operations, distinguishing them from other potential operation types (like memory access or control flow) that might appear in other parts.

8. **Refinement and Language:**  Ensure the explanation is clear, concise, and uses appropriate terminology (SSA, registers, assembler, etc.). Use Chinese as requested.

Self-Correction/Refinement during the process:

* **Initial thought:** Maybe this directly generates assembly. **Correction:** Realized it's part of the SSA phase, so it's an intermediate representation definition.
* **Initial thought:**  Provide a complex Go example using assembly directives. **Correction:**  A simpler Go example demonstrating the *concept* is more appropriate since users don't directly interact with this file. Focus on the higher-level Go code that would *lead* to these SSA operations.
* **Initial thought:**  Focus heavily on the bitmask calculations. **Correction:** Explain the *meaning* of the bitmasks (allowed registers) rather than the low-level bitwise operations, which are internal implementation details. Keep the explanation accessible.

By following these steps, combining pattern recognition, domain knowledge of compilers, and a structured approach to explaining the code, we arrive at a comprehensive and accurate answer.
这个go语言实现的文件 `go/src/cmd/compile/internal/ssa/opGen.go` 的一部分，主要功能是**定义了针对特定架构（这里是loong64，即龙芯64位架构）的SSA操作码 (opcodes) 的属性和约束**。

具体来说，它定义了一系列的操作（例如加法、减法、乘法、位运算等），并为每个操作指定了以下信息：

* **操作名称 (name):**  在SSA中间表示中使用的操作的符号名称，例如 "SQRTF"（单精度浮点数平方根）。
* **参数长度 (argLen):**  该操作接受的参数数量。
* **汇编指令 (asm):**  该SSA操作对应于目标架构（loong64）的汇编指令，例如 `loong64.ASQRTF`。
* **寄存器信息 (reg):**  这是个 `regInfo` 结构，定义了该操作对输入和输出寄存器的约束。它包含：
    * **输入寄存器 (inputs):** 一个 `inputInfo` 数组，指定了每个输入参数可以使用的寄存器集合。`inputInfo` 包含两个字段：
        * 索引 (index):  表示是第几个输入参数（从0开始）。
        * 寄存器掩码 (register mask):  一个位掩码，其中每一位代表一个寄存器。如果该位为1，则表示对应的寄存器可以用于该输入参数。例如，`4611686017353646080` 这个掩码对应于浮点寄存器 F0-F31。`1073741816` 对应于通用寄存器 R4-R21, g(可能是某个特殊寄存器), R23-R31。
    * **输出寄存器 (outputs):** 一个 `outputInfo` 数组，指定了输出结果可以存储的寄存器集合。结构与 `inputInfo` 类似。

**可以推理出它是什么go语言功能的实现：**

这部分代码是 Go 编译器中 **后端代码生成** 阶段的一部分，更具体地说是 **指令选择和寄存器分配** 之前的准备工作。在将 SSA 中间表示转换为目标机器码时，编译器需要知道每个操作对应哪些具体的汇编指令，以及这些指令对寄存器的要求。`opGen.go` 文件（及其各个部分）就承担了定义这些信息的任务。

**Go 代码举例说明:**

虽然我们不能直接操作 `opGen.go` 中的定义，但可以理解这些定义是如何影响最终生成的汇编代码的。假设我们有以下 Go 代码：

```go
package main

func main() {
	var a float32 = 9.0
	b := sqrt(a)
	println(b)
}
```

当使用 `GOARCH=loong64` 编译这段代码时，编译器会将其转换为 SSA 中间表示。  其中，`sqrt(a)` 这个操作会被表示为一个 SSA 操作，其类型会与 `opGen.go` 中定义的 "SQRTF" 操作匹配。

根据 `opGen.go` 的定义，编译器会知道：

1. "SQRTF" 操作对应于 loong64 汇编指令 `ASQRTF`。
2. "SQRTF" 操作接受一个输入参数和一个输出结果。
3. 输入参数和输出结果都必须使用浮点寄存器 (F0-F31)。

因此，最终生成的 loong64 汇编代码可能会类似于（简化）：

```assembly
# ... 前面的代码 ...
MOVSS  a, F1   // 将变量 a 的值加载到浮点寄存器 F1
ASQRTF F1, F0   // 计算 F1 的平方根，结果存储到 F0
# ... 后面的代码，将 F0 的值用于后续操作或输出 ...
```

**假设的输入与输出 (针对代码推理):**

假设编译器在 SSA 中间表示中遇到了一个需要计算单精度浮点数平方根的操作，并且输入值存储在一个 SSA 变量 `v1` 中。

* **假设输入 (SSA):**  `v2 = SQRTF v1`
* **根据 `opGen.go` 的定义，编译器会查找 "SQRTF" 的信息。**
* **假设寄存器分配器决定将 `v1` 分配到浮点寄存器 F5，并将 `v2` 分配到浮点寄存器 F10。**
* **输出 (汇编):**  `ASQRTF F5, F10`

**命令行参数的具体处理:**

`opGen.go` 文件本身不直接处理命令行参数。它是 Go 编译器源代码的一部分。编译器的命令行参数（例如 `-gcflags`，`-ldflags` 等）由 `go` 工具链和编译器驱动程序处理。`opGen.go` 中定义的数据在编译过程中被编译器内部使用，以指导代码生成。

**功能归纳 (针对第19部分):**

从提供的代码片段来看，第 19 部分主要定义了以下类型的 **算术和逻辑运算** 的 SSA 操作码：

* **浮点运算:**  平方根 (SQRTF), 绝对值 (ABSD), 加法 (ADDF, ADDD), 减法 (SUBF, SUBD), 乘法 (MULF, MULD), 除法 (DIVF, DIVD), 融合乘加/减 (FMADDF, FMADDD, FMSUBF, FMSUBD, FNMADDF, FNMADDD, FNMSUBF, FNMSUBD), 最小值/最大值 (FMINF, FMIND, FMAXF, FMAXD), 浮点数符号位复制 (FCOPYSGD)。
* **整数运算:**  计算前导零 (CLZW, CLZV), 计算尾部零 (CTZW, CTZV), 字节/位反转 (REVB2H, REVB2W, REVBV, BITREV4B, BITREVW, BITREVV), 向量元素计数 (VPCNT64, VPCNT32, VPCNT16), 加法 (ADDV, ADDVconst), 减法 (SUBV, SUBVconst), 乘法 (MULV, MULHV, MULHVU), 除法 (DIVV, DIVVU), 求余 (REMV, REMVU)。
* **位运算:**  与 (AND, ANDconst), 或 (OR, ORconst), 异或 (XOR, XORconst), 同或 (NOR, NORconst)。
* **掩码操作:**  等于零时掩码 (MASKEQZ), 不等于零时掩码 (MASKNEZ)。
* **移位操作:**  逻辑左移 (SLLV, SLLVconst), 逻辑右移 (SRLV)。

总的来说，这部分专注于定义基础的数值计算和位操作，这些是 CPU 提供的基本指令。后续的部分可能会定义其他类型的操作，例如内存访问、控制流操作等。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第19部分，共36部分，请归纳一下它的功能
```

### 源代码
```go
2 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SQRTF",
		argLen: 1,
		asm:    loong64.ASQRTF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "ABSD",
		argLen: 1,
		asm:    loong64.AABSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CLZW",
		argLen: 1,
		asm:    loong64.ACLZW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "CLZV",
		argLen: 1,
		asm:    loong64.ACLZV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "CTZW",
		argLen: 1,
		asm:    loong64.ACTZW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "CTZV",
		argLen: 1,
		asm:    loong64.ACTZV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "REVB2H",
		argLen: 1,
		asm:    loong64.AREVB2H,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "REVB2W",
		argLen: 1,
		asm:    loong64.AREVB2W,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "REVBV",
		argLen: 1,
		asm:    loong64.AREVBV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "BITREV4B",
		argLen: 1,
		asm:    loong64.ABITREV4B,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "BITREVW",
		argLen: 1,
		asm:    loong64.ABITREVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "BITREVV",
		argLen: 1,
		asm:    loong64.ABITREVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "VPCNT64",
		argLen: 1,
		asm:    loong64.AVPCNTV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "VPCNT32",
		argLen: 1,
		asm:    loong64.AVPCNTW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "VPCNT16",
		argLen: 1,
		asm:    loong64.AVPCNTH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "ADDV",
		argLen:      2,
		commutative: true,
		asm:         loong64.AADDVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:    "ADDVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.AADDVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741820}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "SUBV",
		argLen: 2,
		asm:    loong64.ASUBVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:    "SUBVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.ASUBVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:        "MULV",
		argLen:      2,
		commutative: true,
		asm:         loong64.AMULV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:        "MULHV",
		argLen:      2,
		commutative: true,
		asm:         loong64.AMULHV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:        "MULHVU",
		argLen:      2,
		commutative: true,
		asm:         loong64.AMULHVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "DIVV",
		argLen: 2,
		asm:    loong64.ADIVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "DIVVU",
		argLen: 2,
		asm:    loong64.ADIVVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "REMV",
		argLen: 2,
		asm:    loong64.AREMV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "REMVU",
		argLen: 2,
		asm:    loong64.AREMVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:        "ADDF",
		argLen:      2,
		commutative: true,
		asm:         loong64.AADDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "ADDD",
		argLen:      2,
		commutative: true,
		asm:         loong64.AADDD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SUBF",
		argLen: 2,
		asm:    loong64.ASUBF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SUBD",
		argLen: 2,
		asm:    loong64.ASUBD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "MULF",
		argLen:      2,
		commutative: true,
		asm:         loong64.AMULF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "MULD",
		argLen:      2,
		commutative: true,
		asm:         loong64.AMULD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "DIVF",
		argLen: 2,
		asm:    loong64.ADIVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "DIVD",
		argLen: 2,
		asm:    loong64.ADIVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "AND",
		argLen:      2,
		commutative: true,
		asm:         loong64.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:    "ANDconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:        "OR",
		argLen:      2,
		commutative: true,
		asm:         loong64.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:    "ORconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:        "XOR",
		argLen:      2,
		commutative: true,
		asm:         loong64.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:    "XORconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:        "NOR",
		argLen:      2,
		commutative: true,
		asm:         loong64.ANOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:    "NORconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.ANOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:        "FMADDF",
		argLen:      3,
		commutative: true,
		asm:         loong64.AFMADDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FMADDD",
		argLen:      3,
		commutative: true,
		asm:         loong64.AFMADDD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FMSUBF",
		argLen:      3,
		commutative: true,
		asm:         loong64.AFMSUBF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FMSUBD",
		argLen:      3,
		commutative: true,
		asm:         loong64.AFMSUBD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMADDF",
		argLen:      3,
		commutative: true,
		asm:         loong64.AFNMADDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMADDD",
		argLen:      3,
		commutative: true,
		asm:         loong64.AFNMADDD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMSUBF",
		argLen:      3,
		commutative: true,
		asm:         loong64.AFNMSUBF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMSUBD",
		argLen:      3,
		commutative: true,
		asm:         loong64.AFNMSUBD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:            "FMINF",
		argLen:          2,
		commutative:     true,
		resultNotInArgs: true,
		asm:             loong64.AFMINF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:            "FMIND",
		argLen:          2,
		commutative:     true,
		resultNotInArgs: true,
		asm:             loong64.AFMIND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:            "FMAXF",
		argLen:          2,
		commutative:     true,
		resultNotInArgs: true,
		asm:             loong64.AFMAXF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:            "FMAXD",
		argLen:          2,
		commutative:     true,
		resultNotInArgs: true,
		asm:             loong64.AFMAXD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MASKEQZ",
		argLen: 2,
		asm:    loong64.AMASKEQZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MASKNEZ",
		argLen: 2,
		asm:    loong64.AMASKNEZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "FCOPYSGD",
		argLen: 2,
		asm:    loong64.AFCOPYSGD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SLLV",
		argLen: 2,
		asm:    loong64.ASLLV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:    "SLLVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.ASLLV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "SRLV",
		argLen: 2,
		asm:    loong64.ASRLV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{1, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0
```