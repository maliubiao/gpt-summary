Response:
The user wants to understand the functionality of the provided Go code snippet. This snippet seems to define a set of operations for the LoongArch64 architecture within the Go compiler's SSA (Static Single Assignment) framework.

Here's a breakdown of how to approach this:

1. **Identify the core structure:** The code defines a slice of structs. Each struct likely represents a specific assembly instruction or a high-level operation that can be translated to assembly.

2. **Analyze the struct fields:**
    - `name`:  The name of the operation (e.g., "SRLVconst", "MOVVload"). This gives a strong hint about the operation's purpose.
    - `auxType`:  Indicates if the operation uses an auxiliary value (e.g., a constant).
    - `argLen`: The number of arguments the operation takes.
    - `asm`: The actual LoongArch64 assembly instruction corresponding to the operation (e.g., `loong64.ASRLV`, `loong64.AMOVV`).
    - `reg`: A `regInfo` struct, likely describing register constraints for inputs and outputs.

3. **Infer the functionality of individual operations:** Based on the `name` and `asm` fields, I can deduce what each operation does. For example:
    - "SRLVconst" and `loong64.ASRLV`: Likely a logical right shift with a constant.
    - "MOVVload" and `loong64.AMOVV`: Likely loading a 64-bit value from memory.
    - "CMPEQF" and `loong64.ACMPEQF`: Likely comparing two single-precision floating-point numbers for equality.

4. **Connect to Go language features:**  Many of these operations directly map to Go's language features:
    - Arithmetic operations (+, -, *, /, %, shifts)
    - Comparisons (==, !=, <, >, <=, >=)
    - Memory access (loading and storing values)
    - Type conversions
    - Function calls (though not explicitly shown in this snippet)

5. **Provide examples:** For some key operations, illustrate how they might be used in Go code.

6. **Address specific instructions:** Explain `auxType`, `argLen`, `asm`, and the `regInfo` structure.

7. **Infer the broader context:** Understand that this code is part of the Go compiler's backend, specifically the part responsible for generating assembly code for the LoongArch64 architecture.

8. **Summarize the overall function:**  Concisely describe what this part of the `opGen.go` file does within the larger compiler framework.

**Self-Correction/Refinement during thought process:**

- Initially, I might focus too much on individual assembly instructions. It's important to also relate them back to higher-level Go concepts.
- The `regInfo` structure seems complex. I need to explain that it manages register allocation and constraints, ensuring the generated assembly is correct.
- I should explicitly mention that this code is specific to the LoongArch64 architecture.
- The "part 20 of 36" context is crucial for the summary. It indicates this file is likely auto-generated or systematically organized.

By following these steps, I can provide a comprehensive and accurate explanation of the provided Go code snippet.
这段 `go/src/cmd/compile/internal/ssa/opGen.go` 文件的一部分，主要定义了一系列**SSA操作（Operations）**，用于在 Go 编译器的 **静态单赋值（SSA）中间表示** 中表示针对 **LoongArch64** 架构的各种操作。

**它的主要功能是：**

定义了一组数据结构，每个数据结构描述了一个特定的操作，包括：

* **操作的名称 (`name`)**:  例如 "SRLVconst", "MOVVload"。
* **辅助值的类型 (`auxType`)**:  如果操作需要一个辅助值（例如常量），则指定其类型，如 `auxInt64`, `auxFloat64`, `auxSymOff`。
* **参数的长度 (`argLen`)**:  操作接收的参数个数。
* **对应的汇编指令 (`asm`)**:  与该 SSA 操作对应的 LoongArch64 汇编指令，例如 `loong64.ASRLV`, `loong64.AMOVV`。
* **寄存器信息 (`reg`)**: 一个 `regInfo` 结构，描述了操作的输入和输出值对寄存器的要求，例如哪些寄存器可以作为输入，哪些寄存器可以作为输出。

**可以推理出它是什么Go语言功能的实现：**

这段代码定义了与 **位运算、比较运算、内存加载和存储、常量加载** 等相关的底层操作。这些操作是 Go 语言构建更高级语言特性的基础。

**Go代码举例说明 (涉及代码推理，带上假设的输入与输出):**

假设我们有以下 Go 代码：

```go
package main

func main() {
	var x int64 = 10
	var y int64 = 2
	var z int64 = x >> y // 右移操作
	println(z)
}
```

当 Go 编译器将这段代码转换为 LoongArch64 汇编时，  `x >> y`  这个右移操作可能会对应到这里定义的 "SRLV" 或 "SRLVconst" 操作。

**假设：** 编译器能够识别出 `y` 的值在编译时是常量 `2`。

**SSA 中间表示（简化示意）：**

```
v1 = ConstInt64 <int64> 10
v2 = ConstInt64 <int64> 2
v3 = SRLVconst <int64> v1, auxInt:2
```

在这个例子中， `SRLVconst` 操作会被使用，因为它是一个常量右移。

**输入：**

* 操作名称: "SRLVconst"
* 第一个参数 (v1):  值为 10 的寄存器 (假设分配到 R4)
* 辅助值 (auxInt): 2

**输出：**

* 操作结果 (v3): 值为 2 的寄存器 (假设分配到 R5)

**Go代码举例说明 (内存加载)：**

```go
package main

func main() {
	var arr [10]int64
	var index int64 = 5
	var value int64 = arr[index]
	println(value)
}
```

访问数组元素 `arr[index]` 会涉及到内存加载操作。

**SSA 中间表示（简化示意）：**

```
v1 = ... // arr 的地址
v2 = ConstInt64 <int64> 5
v3 = MOVVloadidx <int64> v1, v2  // 从地址 v1 + v2 * sizeof(int64) 加载一个 64 位的值
```

**输入：**

* 操作名称: "MOVVloadidx"
* 第一个参数 (v1):  数组 `arr` 的起始地址 (可能在 SP 加上偏移)
* 第二个参数 (v2):  索引值 5 (假设分配到 R6)

**输出：**

* 操作结果 (v3):  从 `arr[5]` 加载的值 (假设分配到 R7)

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。  `opGen.go`  文件通常由一个代码生成器生成，该生成器可能会读取一些架构描述文件或其他输入来产生这些操作定义。  Go 编译器的命令行参数会影响到代码生成的整体流程，例如选择目标架构，但不会直接影响到这段已经生成的操作定义。

**归纳一下它的功能 (作为第 20 部分，共 36 部分):**

作为 `opGen.go` 文件的第 20 部分，这段代码继续定义了 **针对 LoongArch64 架构的 SSA 操作**。 它专注于 **位运算 (移位、旋转)、比较运算（包括浮点数比较）、以及各种大小的数据类型的内存加载操作（包括从内存加载不同大小的整数和浮点数，以及带索引的加载）**。  考虑到这是系列文件的一部分，可以推测之前的章节可能定义了更基础的操作，而之后的章节可能会定义更复杂的操作或与函数调用、控制流相关的操作。  `opGen.go` 文件的目标是完整地列出所有可以在 SSA 中表示的、针对特定架构的操作。

总而言之，这段代码是 Go 编译器针对 LoongArch64 架构进行代码生成的核心组成部分，它为将 Go 代码转换为机器码提供了必要的底层操作定义。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第20部分，共36部分，请归纳一下它的功能

"""
, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:    "SRLVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.ASRLV,
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
		name:   "SRAV",
		argLen: 2,
		asm:    loong64.ASRAV,
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
		name:    "SRAVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.ASRAV,
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
		name:   "ROTR",
		argLen: 2,
		asm:    loong64.AROTR,
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
		name:   "ROTRV",
		argLen: 2,
		asm:    loong64.AROTRV,
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
		name:    "ROTRconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.AROTR,
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
		name:    "ROTRVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.AROTRV,
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
		name:   "SGT",
		argLen: 2,
		asm:    loong64.ASGT,
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
		name:    "SGTconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.ASGT,
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
		name:   "SGTU",
		argLen: 2,
		asm:    loong64.ASGTU,
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
		name:    "SGTUconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.ASGTU,
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
		name:   "CMPEQF",
		argLen: 2,
		asm:    loong64.ACMPEQF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPEQD",
		argLen: 2,
		asm:    loong64.ACMPEQD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPGEF",
		argLen: 2,
		asm:    loong64.ACMPGEF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPGED",
		argLen: 2,
		asm:    loong64.ACMPGED,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPGTF",
		argLen: 2,
		asm:    loong64.ACMPGTF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPGTD",
		argLen: 2,
		asm:    loong64.ACMPGTD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:    "BSTRPICKW",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.ABSTRPICKW,
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
		name:    "BSTRPICKV",
		auxType: auxInt64,
		argLen:  1,
		asm:     loong64.ABSTRPICKV,
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
		name:              "MOVVconst",
		auxType:           auxInt64,
		argLen:            0,
		rematerializeable: true,
		asm:               loong64.AMOVV,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:              "MOVFconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               loong64.AMOVF,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:              "MOVDconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               loong64.AMOVD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:              "MOVVaddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		asm:               loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018427387908}, // SP SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "MOVBload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            loong64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "MOVBUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            loong64.AMOVBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "MOVHload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            loong64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "MOVHUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            loong64.AMOVHU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "MOVWload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            loong64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "MOVWUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            loong64.AMOVWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "MOVVload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "MOVFload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            loong64.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            loong64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVloadidx",
		argLen: 3,
		asm:    loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVWloadidx",
		argLen: 3,
		asm:    loong64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVWUloadidx",
		argLen: 3,
		asm:    loong64.AMOVWU,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVHloadidx",
		argLen: 3,
		asm:    loong64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVHUloadidx",
		argLen: 3,
		asm:    loong64.AMOVHU,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVBloadidx",
		argLen: 3,
		asm:    loong64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVBUloadidx",
		argLen: 3,
		asm:    loong64.AMOVBU,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVFloadidx",
		argLen: 3,
		asm:    loong64.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVDloadidx",
		argLen: 3,
		asm:    loong64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "MOVHstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "MOVVstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "MOVFstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
				{1, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVBstoreidx",
		argLen: 4,
		asm:    loong64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:   "MOVHstoreidx",
		argLen: 4,
		asm:    loong64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:   "MOVWstoreidx",
		argLen: 4,
		asm:    loong64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:   "MOVVstoreidx",
		argLen: 4,
		asm:    loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:   "MOVFstoreidx",
		argLen: 4,
		asm:    loong64.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVDstoreidx",
		argLen: 4,
		asm:    loong64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
				{2, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVBstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "MOVHstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "MOVWstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "MOVVstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:   "MOVBstorezeroidx",
		argLen: 3,
		asm:    loong64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:   "MOVHstorezeroidx",
		argLen: 3,
		asm:    loong64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:   "MOVWstorezeroidx",
		argLen: 3,
		asm:    loong64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:   "MOVVstorezeroidx",
		argLen: 3,
		asm:    loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:   "MOVWfpgp",
		argLen: 1,
		asm:    loong64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVWgpfp",
		argLen: 1,
		asm:    loong64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVfpgp",
		argLen: 1,
		asm:    loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVVgpfp",
		argLen: 1,
		asm:    loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVBreg",
		argLen: 1,
		asm:    loong64.AMOVB,
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
		name:   "MOVBUreg",
		argLen: 1,
		asm:    loong64.AMOVBU,
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
		name:   "MOVHreg",
		argLen: 1,
		asm:    loong64.AMOVH,
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
		name:   "MOVHUreg",
		argLen: 1,
		asm:    loong64.AMOVHU,
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
		name:   "MOVWreg",
		argLen: 1,
		asm:    loong64.AMOVW,
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
		name:   "MOVWUreg",
		argLen: 
"""




```