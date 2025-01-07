Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first line is crucial: "这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分". This tells us we're looking at a piece of the Go compiler, specifically within the SSA (Static Single Assignment) generation phase. The filename `opGen.go` strongly suggests this code is involved in *generating* SSA operations.

2. **Identify the Core Data Structure:**  The provided code is a large array (or slice) of structs. Each struct has fields like `name`, `auxType`, `argLen`, `resultInArg0`, `clobberFlags`, `asm`, and `reg`. This strongly indicates that each struct describes a single SSA operation.

3. **Analyze Individual Fields:** Let's examine some key fields:
    * `name`:  This is a string like "Int8", "ROLWconst", "ADDLload". These names often correspond to assembly instructions or logical operations. The suffixes like "const", "load", "idx" provide more detail.
    * `auxType`:  Types like `auxInt8`, `auxSymOff`, `auxSymValAndOff`. This suggests auxiliary information associated with the operation, likely constants, symbol offsets, or combinations.
    * `argLen`: The number of arguments the operation takes.
    * `resultInArg0`: A boolean indicating if the result of the operation is placed in the first argument register.
    * `clobberFlags`: Boolean, implying whether the operation modifies processor flags.
    * `asm`:  Values like `x86.AROLL`, `x86.AROLW`, `x86.AADDL`. These are clearly assembly language mnemonics for the x86 architecture.
    * `reg`: A struct named `regInfo` containing `inputs` and `outputs`. These are arrays of `inputInfo` and `outputInfo` respectively. Each `inputInfo` and `outputInfo` has an index and a bitmask (like `49135` or `4295032831`). The bitmask likely represents the allowed registers for that input or output.

4. **Infer the Purpose:** Based on the field analysis, it's clear this data structure defines a set of low-level operations. Each entry maps a high-level conceptual operation (e.g., "ADDLload") to its corresponding assembly instruction and specifies constraints on register usage and other properties. This looks like a crucial part of the compiler's backend, responsible for translating SSA form into machine code.

5. **Connect to Go Functionality:**  The operations like "Int8", "ROL" (rotate), "ADD", "SUB", "AND", "OR", "XOR" are fundamental arithmetic and bitwise operations present in Go. The "load" variants imply memory access. The "idx" variants suggest indexed addressing. The "modify" variants likely relate to in-place operations. The "CMOV" instructions are conditional moves, an optimization technique. The "BSWAP" and "POPCNT" are more specialized bit manipulation instructions. Floating-point operations like "SQRTSD" and "SQRTSS" are also present.

6. **Construct Go Examples:** To illustrate, pick a few representative operations and show how they might be used in Go code. Focus on the *effect* of the operation rather than a direct 1:1 mapping (as SSA is an intermediate representation). For instance, `ADDLload` represents adding a value loaded from memory. A simple `+=` operation in Go could potentially be lowered to this. Similarly, bitwise operations like `<<` and `>>` could be related to the rotate operations.

7. **Address Specific Instructions:** The prompt asks about:
    * **Functionality:** List the operations and their characteristics gleaned from the fields.
    * **Go Function Mapping:** Provide the Go code examples.
    * **Code Reasoning:**  The connection between the operation names, assembly, and Go constructs is the reasoning.
    * **Command-line Arguments:**  This snippet doesn't inherently process command-line arguments. Note this.
    * **Common Mistakes:**  Without more context on how this data is used, it's hard to pinpoint *user* mistakes. Focus on potential compiler implementation details.
    * **Summary:**  Concise statement of the overall purpose: defining SSA operations for the x86 architecture.

8. **Refine and Organize:** Structure the answer logically with clear headings. Use bullet points for listing functionalities. Ensure code examples are compilable and clearly demonstrate the intended operation. Explain the bitmask values' probable meaning.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on direct assembly mapping. Remember that SSA is an *intermediate* representation. The Go examples should represent the *semantic effect*.
* The bitmasks are likely register masks. Realizing that `49135` and `4295032831` likely represent sets of registers is a key insight. Trying to decode the exact register mapping isn't necessary, understanding it's a selection mechanism is sufficient.
* The "modify" operations hint at addressing modes and in-place updates, which is important to note.
*  Double-check the meaning of `auxType` and how it influences the operation. For example, "const" variants have an immediate value.
* The "loadidx" variants are clearly about indexed memory access.

By following these steps, including the self-correction, we can arrive at a comprehensive and accurate analysis of the provided code snippet.
好的，让我们来分析一下提供的Go代码片段。

**功能列举:**

这段代码定义了一个Go语言结构体切片（slice），其中每个结构体都描述了一个特定的SSA（Static Single Assignment）操作。这些操作主要针对x86架构，并且涵盖了以下功能：

1. **整数运算:**
   - `ADDLload`, `ADDQload`, `SUBLload`, `SUBQload`, `ANDLload`, `ANDQload`, `ORLload`, `ORQload`, `XORLload`, `XORQload`:  从内存加载值并执行加、减、与、或、异或操作。
   - `ADDLloadidx`, `ADDQloadidx`, `SUBLloadidx`, `SUBQloadidx`, `ANDLloadidx`, `ANDQloadidx`, `ORLloadidx`, `ORQloadidx`, `XORLloadidx`, `XORQloadidx`: 从带有索引的内存地址加载值并执行相应的操作。
   - `ADDQmodify`, `SUBQmodify`, `ANDQmodify`, `ORQmodify`, `XORQmodify`, `ADDLmodify`, `SUBLmodify`, `ANDLmodify`, `ORLmodify`, `XORLmodify`:  直接在内存中修改值（相当于 `+=`, `-=`, `&=`, `|=`, `^=`）。
   - `ADDQmodifyidx`, `SUBQmodifyidx`, `ANDQmodifyidx`, `ORQmodifyidx`, `XORQmodifyidx`, `ADDLmodifyidx`, `SUBLmodifyidx`, `ANDLmodifyidx`, `ORLmodifyidx`, `XORLmodifyidx`: 在带有索引的内存地址上修改值。
   - `ADDQconstmodifyidx`, `ANDQconstmodifyidx`, `ORQconstmodifyidx`, `XORQconstmodifyidx`, `ADDLconstmodifyidx`, `ANDLconstmodifyidx`, `ORLconstmodifyidx`, `XORLconstmodifyidx`:  在带有索引的内存地址上加上/与/或/异或一个常量值。
   - `NEGQ`, `NEGL`:  取负数。
   - `NOTQ`, `NOTL`:  按位取反。

2. **位操作:**
   - `ROLL`, `ROLWconst`, `ROLBconst`:  循环左移。
   - `BSFQ`, `BSFL`:  位扫描，查找最低位1的索引。
   - `BSRQ`, `BSRL`:  位扫描，查找最高位1的索引。
   - `BSWAPQ`, `BSWAPL`:  字节序反转。
   - `POPCNTQ`, `POPCNTL`:  计算二进制表示中1的个数。

3. **条件移动 (Conditional Move):**
   - `CMOVQEQ`, `CMOVQNE`, `CMOVQLT`, `CMOVQGT`, `CMOVQLE`, `CMOVQGE`, `CMOVQLS`, `CMOVQHI`, `CMOVQCC`, `CMOVQCS`: 基于不同的条件码移动64位值。
   - `CMOVLEQ`, `CMOVLNE`, `CMOVLLT`, `CMOVLGT`, `CMOVLLE`, `CMOVLGE`, `CMOVLLS`, `CMOVLHI`, `CMOVLCC`, `CMOVLCS`: 基于不同的条件码移动32位值。
   - `CMOVWEQ`, `CMOVWNE`, `CMOVWLT`, `CMOVWGT`, `CMOVWLE`, `CMOVWGE`, `CMOVWLS`, `CMOVWHI`, `CMOVWCC`, `CMOVWCS`: 基于不同的条件码移动16位值。
   - `CMOVQEQF`, `CMOVQNEF`, `CMOVQGTF`, `CMOVQGEF`, `CMOVLEQF`, `CMOVLNEF`, `CMOVLGTF`, `CMOVLGEF`, `CMOVWEQF`, `CMOVWNEF`, `CMOVWGTF`, `CMOVWGEF`:  一些基于浮点数比较结果的条件移动（带有 "F" 后缀可能指示与浮点数操作有关）。

4. **浮点数运算:**
   - `SQRTSD`, `SQRTSS`: 计算平方根（双精度和单精度）。
   - `ROUNDSD`:  浮点数舍入。

**推理解析：SSA操作定义**

这段代码是Go编译器中用于定义SSA中间表示层操作的一部分。SSA是一种编译器中间表示形式，它具有每个变量只被赋值一次的特性。 `opGen.go` 文件很可能负责生成特定架构（这里是x86）的SSA操作码。

每个结构体定义了一个SSA操作，包含了以下关键信息：

- **`name`**: 操作的名称，例如 "ADDLload"。
- **`auxType`**: 辅助信息的类型，例如 `auxInt8`（整型常量）、`auxSymOff`（符号偏移）、`auxSymValAndOff`（符号值和偏移）。
- **`argLen`**:  操作需要的参数个数。
- **`resultInArg0`**:  布尔值，指示操作的结果是否存储在第一个参数的位置。
- **`clobberFlags`**: 布尔值，指示操作是否会修改CPU的标志寄存器。
- **`faultOnNilArg1`**: 布尔值，指示当第二个参数为空指针时是否会触发错误（常用于内存加载操作）。
- **`symEffect`**:  指示操作对符号的影响，例如 `SymRead`（读取符号）、`SymWrite`（写入符号）、`SymRead | SymWrite`（读写符号）。
- **`asm`**:  对应的x86汇编指令，例如 `x86.AADDL`。
- **`reg`**:  `regInfo` 结构体，描述了操作数和结果的寄存器约束。
    - **`inputs`**:  输入参数的寄存器约束，每个 `inputInfo` 包含参数索引和可能的寄存器掩码（一个整数，其二进制位表示允许的寄存器）。
    - **`outputs`**: 输出结果的寄存器约束。
- **`scale`**:  用于索引寻址的比例因子 (1, 4, 8)。
- **`needIntTemp`**: 布尔值，指示操作是否需要一个额外的临时寄存器。

**Go代码举例说明:**

以 `ADDLload` 为例，它表示从内存加载一个32位整数并将其加到一个寄存器中。在Go中，这可能对应于如下操作：

```go
package main

func main() {
	var x int32 = 10
	var y int32 = 5
	var ptr *int32 = &y

	// 假设编译器的SSA生成阶段会将类似的操作转换为 ADDLload
	x += *ptr //  从 ptr 指向的内存地址加载 y 的值，并加到 x 上
	println(x)
}
```

**假设的输入与输出:**

对于 `ADDLload` 操作，假设SSA生成阶段有如下的输入：

- **操作码:** `ADDLload`
- **参数 0 (寄存器):**  假设寄存器是 `AX`，初始值为 10。
- **参数 1 (内存地址):** 假设是一个指向变量 `y` 的指针，`y` 的值为 5。
- **辅助信息:** 符号 `y` 的偏移地址。

**输出:**

执行 `ADDLload` 后，寄存器 `AX` 的值将变为 15 (10 + 5)。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。 `opGen.go` 文件是编译器内部的一部分，它的作用是定义编译器在中间表示阶段使用的操作。命令行参数的处理发生在编译器的前端，用于控制编译过程的各个方面（例如，优化级别、目标架构等）。

**易犯错的点:**

对于 `opGen.go` 的使用者（主要是Go编译器的开发者），一个潜在的易错点是：

- **错误地配置寄存器约束 (`regInfo`)**:  如果 `inputInfo` 或 `outputInfo` 中指定的寄存器掩码不正确，可能会导致编译器在寄存器分配阶段出错，或者生成非法的汇编代码。例如，错误地限制了某些操作必须使用的寄存器，导致寄存器冲突。

**归纳一下它的功能 (第 4 部分，共 18 部分):**

作为 `opGen.go` 文件的第4部分，这段代码的主要功能是**定义了Go编译器在SSA（静态单赋值）中间表示阶段，针对x86架构的一系列算术、逻辑、位操作、条件移动以及部分浮点数操作。**  这些定义包括了操作的名称、参数信息、副作用（例如是否修改标志寄存器）、对应的汇编指令以及对操作数和结果寄存器的约束。 这部分定义是编译器将高级Go代码转换为低级机器码的关键步骤之一。 它可以被认为是编译器后端生成x86机器码的基础蓝图。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共18部分，请归纳一下它的功能

"""
Int8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ROLWconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ROLBconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ADDLload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ADDQload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AADDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SUBQload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ASUBQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SUBLload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ASUBL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ANDLload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ANDQload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AANDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ORQload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ORLload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "XORQload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AXORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "XORLload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AXORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDLloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AADDL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDLloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AADDL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDLloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AADDL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDQloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AADDQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDQloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AADDQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBLloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.ASUBL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBLloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.ASUBL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBLloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.ASUBL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBQloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.ASUBQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBQloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.ASUBQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ANDLloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AANDL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ANDLloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AANDL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ANDLloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AANDL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ANDQloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AANDQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ANDQloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AANDQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ORLloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AORL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ORLloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AORL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ORLloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AORL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ORQloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AORQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ORQloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AORQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "XORLloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AXORL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "XORLloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AXORL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "XORLloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AXORL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "XORQloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AXORQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "XORQloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AXORQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ADDQmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AADDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SUBQmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.ASUBQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ANDQmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AANDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ORQmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "XORQmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AXORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ADDLmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SUBLmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.ASUBL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ANDLmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ORLmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "XORLmodify",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AXORL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDQmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDQmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "SUBQmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.ASUBQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "SUBQmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.ASUBQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDQmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDQmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORQmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORQmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORQmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORQmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDLmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDLmodifyidx4",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDLmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "SUBLmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.ASUBL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "SUBLmodifyidx4",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.ASUBL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "SUBLmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.ASUBL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDLmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDLmodifyidx4",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDLmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORLmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORLmodifyidx4",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORLmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORLmodifyidx1",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORLmodifyidx4",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORLmodifyidx8",
		auxType:      auxSymOff,
		argLen:       4,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDQconstmodifyidx1",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDQconstmodifyidx8",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDQconstmodifyidx1",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDQconstmodifyidx8",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORQconstmodifyidx1",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORQconstmodifyidx8",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORQconstmodifyidx1",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORQ,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORQconstmodifyidx8",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORQ,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDLconstmodifyidx1",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDLconstmodifyidx4",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ADDLconstmodifyidx8",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AADDL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDLconstmodifyidx1",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDLconstmodifyidx4",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDLconstmodifyidx8",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AANDL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORLconstmodifyidx1",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORLconstmodifyidx4",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORLconstmodifyidx8",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AORL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORLconstmodifyidx1",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORL,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORLconstmodifyidx4",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORL,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORLconstmodifyidx8",
		auxType:      auxSymValAndOff,
		argLen:       3,
		clobberFlags: true,
		symEffect:    SymRead | SymWrite,
		asm:          x86.AXORL,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "NEGQ",
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ANEGQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "NEGL",
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ANEGL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "NOTQ",
		argLen:       1,
		resultInArg0: true,
		asm:          x86.ANOTQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "NOTL",
		argLen:       1,
		resultInArg0: true,
		asm:          x86.ANOTL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "BSFQ",
		argLen: 1,
		asm:    x86.ABSFQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BSFL",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ABSFL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "BSRQ",
		argLen: 1,
		asm:    x86.ABSRQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BSRL",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ABSRL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQEQ",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQNE",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQLT",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQLT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQGT",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQGT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQLE",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQLE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQGE",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQGE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQLS",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQLS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQHI",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQHI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQCC",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQCS",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQCS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLEQ",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLNE",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLLT",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLLT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLGT",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLGT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLLE",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLLE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLGE",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLGE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLLS",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLLS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLHI",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLHI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLCC",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLCS",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLCS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWEQ",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWNE",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWLT",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWLT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWGT",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWGT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWLE",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWLE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWGE",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWGE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWLS",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWLS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWHI",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWHI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWCC",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWCS",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWCS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQEQF",
		argLen:       3,
		resultInArg0: true,
		needIntTemp:  true,
		asm:          x86.ACMOVQNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQNEF",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQGTF",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQHI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVQGEF",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVQCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLEQF",
		argLen:       3,
		resultInArg0: true,
		needIntTemp:  true,
		asm:          x86.ACMOVLNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLNEF",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLGTF",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLHI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVLGEF",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVLCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWEQF",
		argLen:       3,
		resultInArg0: true,
		needIntTemp:  true,
		asm:          x86.ACMOVWNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWNEF",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWGTF",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWHI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "CMOVWGEF",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ACMOVWCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BSWAPQ",
		argLen:       1,
		resultInArg0: true,
		asm:          x86.ABSWAPQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BSWAPL",
		argLen:       1,
		resultInArg0: true,
		asm:          x86.ABSWAPL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "POPCNTQ",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.APOPCNTQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "POPCNTL",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.APOPCNTL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SQRTSD",
		argLen: 1,
		asm:    x86.ASQRTSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "SQRTSS",
		argLen: 1,
		asm:    x86.ASQRTSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:    "ROUNDSD",
		auxType: auxInt8,
		argLen:  1,
		asm:     x86.AROUNDSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "VFMADD231SD",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.AVFMADD231SD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418
"""




```