Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `opGen.go` file in the Go compiler for the s390x architecture. This file seems to define the properties of various SSA (Static Single Assignment) operations used in the compilation process.

The request asks for:
1. **Functionality:** What does this code do?
2. **Go feature implementation:** What Go language feature does it relate to? Provide a Go code example.
3. **Code reasoning:** Include assumptions, inputs, and outputs if reasoning about the code.
4. **Command-line arguments:** Detail any command-line parameter handling (not applicable here as it's data definition).
5. **Common mistakes:** Point out potential pitfalls for users (mostly internal to the compiler, less relevant for typical Go users).
6. **Summary:**  A brief summary of the functionality, considering it's part 31 of 36.

**Plan:**

1. **Analyze the structure:** The code defines a slice of structs, where each struct represents an SSA operation. Each struct has fields like `name`, `auxType`, `argLen`, `asm`, and `reg`. This structure likely serves as a data source for the compiler to understand the properties of each SSA operation.
2. **Identify the purpose of fields:**
    - `name`: The name of the SSA operation (e.g., "FMOVSload", "ADD").
    - `auxType`:  The type of auxiliary information associated with the operation.
    - `argLen`: The number of arguments the operation takes.
    - `asm`: The corresponding assembly instruction for the operation.
    - `reg`: Information about register usage (inputs, outputs, clobbered registers).
3. **Infer the broader context:** Given the file path and the structure, this code likely plays a crucial role in the backend of the Go compiler, specifically in the instruction selection and register allocation phases for the s390x architecture. It maps high-level SSA operations to low-level assembly instructions, while also specifying register constraints.
4. **Connect to Go features:** The described operations are fundamental to how Go code is translated into machine code. Many Go language features rely on these low-level operations, especially arithmetic, memory access, and floating-point operations.
5. **Provide a Go example:**  Illustrate a simple Go code snippet that would involve some of the defined operations (e.g., addition, memory load).
6. **Address specific instructions:**
    - **FIDBR/FIDBR:** These seem related to loading from or to floating-point registers based on an index.
    - **FMOVSload/FMOVDload:** Loading single/double-precision floating-point values from memory.
    - **FMOVSconst/FMOVDconst:** Loading floating-point constants.
    - **FMOVSloadidx/FMOVDloadidx:** Indexed loading of floating-point values.
    - **FMOVSstore/FMOVDstore:** Storing floating-point values to memory.
    - **FMOVSstoreidx/FMOVDstoreidx:** Indexed storing of floating-point values.
    - **ADD/SUB/MULLD/DIVD/MODD/AND/OR/XOR:** Standard arithmetic and logical operations.
    - **CMP/FCMPS/FCMP:** Comparison operations.
    - **SLD/SRD/SRAD/RLLG:** Shift and rotate operations.
    - **ADDC/SUBC/ADDE/SUBE:**  Arithmetic with carry/borrow.
7. **Summarize the functionality based on the part number:** Given it's part 31/36, the code is likely focused on defining a specific set of operations or a particular category (like floating-point or integer operations). The provided snippet seems to cover a mix of floating-point loads/stores and integer arithmetic/logical operations.
8. **Avoid unnecessary details:**  The request specifically asked to avoid mentioning things if not necessary (like common mistakes for end-users).
这是一个Go语言编译器的内部实现文件，路径为 `go/src/cmd/compile/internal/ssa/opGen.go`，它定义了 **SSA（Static Single Assignment）中间表示的操作码（Opcodes）的属性信息**。

**功能归纳 (针对提供的代码片段):**

这段代码具体定义了 **针对 s390x 架构** 的一系列 SSA 操作码的详细属性。这些属性包括：

* **name (操作名称):**  例如 "FIDBR", "FMOVSload", "ADD", "CMP" 等，表示一个具体的 SSA 操作。
* **auxType (辅助信息类型):**  指定操作可能需要的额外辅助信息的类型，例如 `auxInt8`, `auxSymOff`, `auxFloat32` 等。
* **argLen (参数长度):**  表示该操作接收的参数数量。
* **asm (汇编指令):**  关联到该 SSA 操作的具体的 s390x 汇编指令，例如 `s390x.AFIDBR`, `s390x.AFMOVS`, `s390x.AADD` 等。
* **reg (寄存器信息):**  详细描述了该操作对寄存器的使用情况：
    * **inputs (输入寄存器):**  指定了哪些寄存器可以作为该操作的输入，以及对应的寄存器掩码（bitmask）。例如，`{0, 4294901760}` 表示第一个输入参数可以位于 F0 到 F15 浮点寄存器中的任意一个。
    * **outputs (输出寄存器):**  指定了操作结果会输出到哪个寄存器，以及对应的寄存器掩码。
    * **clobbers (破坏的寄存器):**  （在部分操作中出现）列出了执行该操作后会被修改的寄存器。
* **faultOnNilArg0 (空指针错误):**  一个布尔值，指示如果第一个参数为空指针是否会产生错误。
* **symEffect (符号影响):**  指示该操作是否会读取或写入符号信息 (`SymRead`, `SymWrite`)。
* **rematerializeable (可重构):**  一个布尔值，指示该操作的结果是否可以重新计算，而不是必须存储和加载。
* **commutative (可交换):**  一个布尔值，指示操作数顺序是否可以交换（例如加法和乘法）。
* **resultInArg0 (结果在参数0):**  一个布尔值，指示操作的结果是否直接覆盖了第一个输入参数。
* **clobberFlags (破坏标志位):**  一个布尔值，指示该操作是否会修改 CPU 的标志位寄存器。

**推理的 Go 语言功能实现 (示例):**

这段代码描述的是在编译过程中，如何将 Go 语言的高级操作转换为底层的 s390x 汇编指令。 让我们以一个简单的加法操作为例：

```go
// 假设的 Go 代码
func add(a, b int64) int64 {
	return a + b
}
```

在编译过程中，`a + b` 这个操作可能会被表示为一个 SSA 的 `ADD` 操作。  根据 `opGen.go` 中的定义：

```go
{
	name:         "ADD",
	argLen:       2,
	commutative:  true,
	clobberFlags: true,
	asm:          s390x.AADD,
	reg: regInfo{
		inputs: []inputInfo{
			{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
		},
		outputs: []outputInfo{
			{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
		},
	},
},
```

* **假设输入：**  变量 `a` 的值存储在寄存器 R3 中，变量 `b` 的值存储在寄存器 R5 中。
* **操作:** 编译器会选择 `ADD` 这个 SSA 操作。
* **输出：**  根据 `regInfo`，输出结果会存储回第一个输入参数所在的寄存器，也就是 R3。
* **对应的汇编：** 最终会生成 s390x 的 `AADD` 汇编指令，可能的形式是 `A R3, R5` (将 R5 的值加到 R3 上，结果存回 R3)。

**代码推理 (带假设的输入与输出):**

以 `FMOVSload` (加载单精度浮点数) 为例：

```go
{
	name:           "FMOVSload",
	auxType:        auxSymOff,
	argLen:         2,
	faultOnNilArg0: true,
	symEffect:      SymRead,
	asm:            s390x.AFMOVS,
	reg: regInfo{
		inputs: []inputInfo{
			{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
		},
		outputs: []outputInfo{
			{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
},
```

* **假设的 Go 代码:**
  ```go
  var f float32
  var ptr *float32
  // ... (假设 ptr 指向一个有效的 float32 变量的地址)
  f = *ptr
  ```
* **假设输入:**
    * `ptr` 的值（内存地址）存储在寄存器 R2 中。
    * `auxType: auxSymOff` 表明可能还存在一个符号偏移量（这里假设偏移量为 0）。
* **操作:** 编译器会选择 `FMOVSload` 这个 SSA 操作。
* **输出:**  加载到的单精度浮点数值会存储到 F0 - F15 中的一个浮点寄存器，假设是 F4。
* **对应的汇编:** 最终会生成类似 `LF F4, 0(R2)` 的 s390x 汇编指令 (从 R2 指向的内存地址加载一个单精度浮点数到 F4)。

**命令行参数处理:**

这个代码片段本身不涉及命令行参数的处理。它是 Go 编译器内部的数据定义。命令行参数的处理通常发生在编译器的前端和驱动程序部分。

**易犯错的点:**

对于 *使用者* (通常是 Go 语言开发者) 而言，直接与 `opGen.go` 交互的可能性极低。 这是编译器内部的实现细节。

但对于 *编译器开发者* 而言，一些容易犯错的点可能包括：

* **寄存器掩码错误:**  错误地配置输入或输出寄存器的掩码，导致生成的汇编代码使用了错误的寄存器。
* **`auxType` 不匹配:** 在生成 SSA 代码时，如果提供的辅助信息类型与 `opGen.go` 中定义的 `auxType` 不符，会导致编译错误或生成错误的指令。
* **汇编指令名称错误:**  `asm` 字段指定的汇编指令名称必须与 s390x 汇编器的语法完全一致。
* **忽略副作用:**  没有正确设置 `symEffect` 或 `clobberFlags` 可能导致编译器进行错误的优化。

**功能总结 (第31部分，共36部分):**

考虑到这是整个 `opGen.go` 文件的第 31 部分，并且涵盖了浮点数的加载、存储以及一些基本的整数运算和逻辑运算，可以推断出这个部分的主要功能是 **定义 s390x 架构下，用于处理浮点数和基本算术逻辑运算的 SSA 操作码的属性信息**。  在整个 `opGen.go` 文件中，可能还会包含针对其他类型操作 (例如，内存操作、控制流操作等) 的定义。这个部分专注于为代码生成阶段提供关于如何将中间表示转换为特定机器指令的关键信息。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第31部分，共36部分，请归纳一下它的功能

"""
01760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:    "FIDBR",
		auxType: auxInt8,
		argLen:  1,
		asm:     s390x.AFIDBR,
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
		name:           "FMOVSload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:           "FMOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:              "FMOVSconst",
		auxType:           auxFloat32,
		argLen:            0,
		rematerializeable: true,
		asm:               s390x.AFMOVS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:              "FMOVDconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               s390x.AFMOVD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:      "FMOVSloadidx",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       s390x.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:      "FMOVDloadidx",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       s390x.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:           "FMOVSstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:           "FMOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:      "FMOVSstoreidx",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       s390x.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:      "FMOVDstoreidx",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       s390x.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "ADD",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ADDW",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AADDW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ADDconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ADDWconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.AADDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ADDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ADDWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AADDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUB",
		argLen:       2,
		clobberFlags: true,
		asm:          s390x.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUBW",
		argLen:       2,
		clobberFlags: true,
		asm:          s390x.ASUBW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUBconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUBWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ASUBW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "SUBload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "SUBWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.ASUBW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULLD",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULLW",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULLDconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULLWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MULLDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AMULLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MULLWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AMULLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULHD",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULHD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MULHDU",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULHDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "DIVD",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ADIVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "DIVW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ADIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "DIVDU",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ADIVDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "DIVWU",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ADIVWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MODD",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMODD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MODW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMODW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MODDU",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMODDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MODWU",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMODWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "AND",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ANDW",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AANDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ANDconst",
		auxType:      auxInt64,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ANDWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AANDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ANDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ANDWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AANDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "OR",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ORW",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ORconst",
		auxType:      auxInt64,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ORWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ORload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ORWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "XOR",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "XORW",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AXORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "XORconst",
		auxType:      auxInt64,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "XORWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AXORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "XORload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "XORWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AXORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "ADDC",
		argLen:      2,
		commutative: true,
		asm:         s390x.AADDC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "ADDCconst",
		auxType: auxInt16,
		argLen:  1,
		asm:     s390x.AADDC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ADDE",
		argLen:       3,
		commutative:  true,
		resultInArg0: true,
		asm:          s390x.AADDE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "SUBC",
		argLen: 2,
		asm:    s390x.ASUBC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUBE",
		argLen:       3,
		resultInArg0: true,
		asm:          s390x.ASUBE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "CMP",
		argLen: 2,
		asm:    s390x.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:   "CMPW",
		argLen: 2,
		asm:    s390x.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:   "CMPU",
		argLen: 2,
		asm:    s390x.ACMPU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:   "CMPWU",
		argLen: 2,
		asm:    s390x.ACMPWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:    "CMPconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     s390x.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:    "CMPWconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     s390x.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:    "CMPUconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     s390x.ACMPU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:    "CMPWUconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     s390x.ACMPWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:   "FCMPS",
		argLen: 2,
		asm:    s390x.ACEBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "FCMP",
		argLen: 2,
		asm:    s390x.AFCMPU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LTDBR",
		argLen: 1,
		asm:    s390x.ALTDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LTEBR",
		argLen: 1,
		asm:    s390x.ALTEBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "SLD",
		argLen: 2,
		asm:    s390x.ASLD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "SLW",
		argLen: 2,
		asm:    s390x.ASLW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "SLDconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ASLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "SLWconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ASLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "SRD",
		argLen: 2,
		asm:    s390x.ASRD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "SRW",
		argLen: 2,
		asm:    s390x.ASRW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "SRDconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ASRD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "SRWconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ASRW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SRAD",
		argLen:       2,
		clobberFlags: true,
		asm:          s390x.ASRAD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SRAW",
		argLen:       2,
		clobberFlags: true,
		asm:          s390x.ASRAW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SRADconst",
		auxType:      auxUInt8,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ASRAD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SRAWconst",
		auxType:      auxUInt8,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ASRAW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "RLLG",
		argLen: 2,
		asm:    s390x.ARLLG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "RLL",
		argLen: 2,
		asm:    s390x.ARLL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "RLLconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ARLL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "RXSBG",
		auxType:      auxS390XRotateParams,
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ARXSBG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "RISBGZ",
		auxType:      auxS390XRotatePar
"""




```