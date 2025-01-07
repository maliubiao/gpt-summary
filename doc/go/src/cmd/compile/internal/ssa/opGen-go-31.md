Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The code is in `go/src/cmd/compile/internal/ssa/opGen.go`. The `opGen.go` suggests it's about generating or defining operations (ops) for the SSA (Static Single Assignment) form used in the Go compiler.

2. **Recognize the Data Structure:**  The provided text is a slice of structs. Each struct appears to represent a single SSA operation. The fields within the struct provide metadata about the operation.

3. **Deconstruct the Struct Fields:**  Go through each field of the struct and understand its meaning. This is crucial for inferring the functionality.

    * `name`:  A string, likely the name of the SSA operation (e.g., "NEG", "ADD", "MOVDload").
    * `argLen`: An integer, likely the number of input arguments the operation takes.
    * `clobberFlags`: A boolean, indicating if the operation modifies CPU flags.
    * `asm`:  Something related to assembly instructions (e.g., `s390x.ARISBGZ`). The `s390x` prefix strongly suggests this code is for the s390x architecture.
    * `reg`: A nested struct containing register information.
        * `inputs`: A slice of `inputInfo`, likely specifying register constraints for input arguments. The numbers might represent register masks.
        * `outputs`: A slice of `outputInfo`, likely specifying register constraints for the output of the operation.
        * `clobbers`:  A number, likely a bitmask representing registers that the operation might modify.
    * `auxType`: An identifier like `auxS390XCCMask` or `auxInt64`. This suggests auxiliary information related to the operation's operands or behavior.
    * `resultInArg0`: A boolean, indicating if the result of the operation is placed in the same register as the first argument.
    * `rematerializeable`: A boolean, hinting at optimizations related to recomputing the value instead of storing it.
    * `symEffect`: An identifier like `SymAddr` or `SymRead`. This likely relates to how the operation interacts with memory locations and symbols.
    * `faultOnNilArg0`: A boolean, suggesting a runtime check for nil pointers.
    * `commutative`: A boolean, indicating if the order of operands doesn't affect the result.
    * `call`: A boolean, marking the operation as a function call.
    * `tailCall`: A boolean, marking the operation as a tail call.
    * `zeroWidth`: A boolean, possibly indicating an operation that doesn't produce a value with a specific width.
    * `nilCheck`: A boolean, explicitly marking the operation as performing a nil check.

4. **Identify Patterns and Groups:** Look for commonalities among the operations. Notice groups of operations with similar prefixes or suffixes:

    * Arithmetic operations (`NEG`, `NEGW`, `NOT`, `NOTW`)
    * Floating-point operations (`FSQRT`, `FSQRTS`)
    * Load and store operations (`MOVBload`, `MOVBstore`, `MOVDloadidx`)
    * Call-related operations (`CALLstatic`, `CALLclosure`, `CALLinter`)
    * Lowered operations (`LoweredGetG`, `LoweredNilCheck`)

5. **Infer Functionality Based on Names and Assembly:** Combine the operation names with their corresponding assembly instructions to understand their purpose. For example:

    * `NEG` and `ANEG`:  Likely integer negation.
    * `FSQRT` and `AFSQRT`: Likely floating-point square root.
    * `MOVBload` and `AMOVB`: Likely loading a byte from memory.
    * `CALLstatic`: A static function call.

6. **Consider the `regInfo`:**  The `regInfo` is crucial for understanding how the operation interacts with the CPU's registers. The bitmasks in `inputs`, `outputs`, and `clobbers` define register constraints and potential side effects. While the exact meaning of the numbers might require looking up architecture-specific definitions, the general concept of register allocation and usage is clear.

7. **Relate to Go Language Features:**  Try to connect these low-level SSA operations to higher-level Go language constructs.

    * Load/store operations are fundamental to accessing variables and data structures.
    * Arithmetic and logical operations directly correspond to Go's operators.
    * Function calls are essential for program execution.
    * Nil checks are part of Go's safety mechanisms.

8. **Formulate Examples (If Possible):**  Based on the inferred functionality, try to write simple Go code snippets that might translate to these SSA operations. This helps solidify understanding. For instance, `x := -y` would likely involve a `NEG` operation.

9. **Address Specific Questions:**  Go back to the original prompt and address each point:

    * **Functionality Listing:** Summarize the different categories of operations.
    * **Go Language Function Implementation:** Provide code examples where feasible.
    * **Code Inference (with assumptions):**  Explain the reasoning behind connecting the operations to Go code.
    * **Command-Line Parameters:** This section doesn't seem relevant based on the provided code snippet.
    * **Common Mistakes:**  Think about potential pitfalls related to register usage or memory access, although the snippet itself doesn't directly expose user-level mistakes.
    * **归纳功能 (Summary):**  Provide a concise overview of the code's purpose.

10. **Self-Correction and Refinement:** Review the analysis for accuracy and completeness. Ensure the language is clear and addresses all parts of the prompt. For example, initially, I might not have explicitly mentioned the s390x architecture, but seeing the `s390x.` prefix makes that a crucial detail. Similarly, the register masks are important but can be described conceptually without needing to decode every bit.
让我来归纳一下 `go/src/cmd/compile/internal/ssa/opGen.go` 文件中第 32 部分的功能。

这部分代码定义了一系列针对 **s390x 架构**的 SSA (Static Single Assignment) 操作 (Operation)。每个操作都用一个结构体描述，包含了该操作的名称、参数长度、是否会影响标志位、对应的汇编指令、以及寄存器信息等。

**具体功能归纳：**

这部分定义了多种指令，可以大致分为以下几类：

1. **算术和逻辑运算 (Integer & Floating-point):**
   - `ARISBGZ`:  可能是 "Add Register Immediate Shifted by a Group of Zeroes"，具体功能不明确，但属于算术运算。
   - `NEG`, `NEGW`:  取反操作，分别针对 64 位和 32 位整数。
   - `NOT`, `NOTW`:  按位取反操作，分别针对 64 位和 32 位整数，结果会存储在第一个参数的寄存器中 (`resultInArg0: true`)。
   - `FSQRT`, `FSQRTS`: 浮点数平方根运算，分别针对双精度和单精度浮点数。
   - `LOCGR`:  可能涉及逻辑运算，需要三个参数，结果存储在第一个参数的寄存器中。

2. **数据移动 (Register & Memory):**
   - `MOVBreg`, `MOVBZreg`, `MOVHreg`, `MOVHZreg`, `MOVWreg`, `MOVWZreg`:  寄存器之间的数据移动，针对不同大小的整数，带 Z 后缀表示零扩展。
   - `MOVDconst`:  将常量值移动到寄存器。
   - `LDGR`, `LGDR`:  可能涉及浮点数和通用寄存器之间的数据移动。
   - `CFDBRA`, `CGDBRA`, `CFEBRA`, `CGEBRA`, `CEFBRA`, `CDFBRA`, `CEGBRA`, `CDGBRA`, `CLFEBR`, `CLFDBR`, `CLGEBR`, `CLGDBR`, `CELFBR`, `CDLFBR`, `CELGBR`, `CDLGBR`:  这些操作可能与浮点数和通用寄存器之间的转换或加载有关，名字比较复杂，具体含义需要参考 s390x 的指令集。
   - `LEDBR`, `LDEBR`:  可能与扩展加载浮点数有关。
   - `MOVDaddr`:  将地址（可能是栈或全局变量的地址）加载到寄存器。
   - `MOVDaddridx`:  将带索引的地址加载到寄存器。
   - `MOVBZload`, `MOVBload`, `MOVHZload`, `MOVHload`, `MOVWZload`, `MOVWload`, `MOVDload`:  从内存中加载不同大小的数据到寄存器。
   - `MOVWBR`, `MOVDBR`:  可能涉及字节序转换的内存加载。
   - `MOVHBRload`, `MOVWBRload`, `MOVDBRload`: 从内存加载数据并进行字节序转换。
   - `MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVDstore`:  将寄存器中的数据存储到内存中。
   - `MOVHBRstore`, `MOVWBRstore`, `MOVDBRstore`: 将寄存器中的数据存储到内存并进行字节序转换。
   - `MVC`:  内存拷贝操作。
   - `MOVBZloadidx`, `MOVBloadidx`, `MOVHZloadidx`, `MOVHloadidx`, `MOVWZloadidx`, `MOVWloadidx`, `MOVDloadidx`, `MOVHBRloadidx`, `MOVWBRloadidx`, `MOVDBRloadidx`: 带索引的内存加载操作。
   - `MOVBstoreidx`, `MOVHstoreidx`, `MOVWstoreidx`, `MOVDstoreidx`, `MOVHBRstoreidx`, `MOVWBRstoreidx`, `MOVDBRstoreidx`: 带索引的内存存储操作。
   - `MOVBstoreconst`, `MOVHstoreconst`, `MOVWstoreconst`, `MOVDstoreconst`: 将常量值存储到内存。
   - `CLEAR`:  清除内存区域。

3. **函数调用:**
   - `CALLstatic`:  静态函数调用。
   - `CALLtail`:  尾调用。
   - `CALLclosure`:  闭包调用。
   - `CALLinter`:  接口调用。

4. **特殊操作:**
   - `InvertFlags`:  反转标志位。
   - `LoweredGetG`:  获取 Goroutine 的 G 结构体指针。
   - `LoweredGetClosurePtr`: 获取闭包指针。
   - `LoweredGetCallerSP`: 获取调用者的栈指针。
   - `LoweredGetCallerPC`: 获取调用者的程序计数器。
   - `LoweredNilCheck`:  空指针检查。
   - `LoweredRound32F`, `LoweredRound64F`:  浮点数舍入操作。
   - `LoweredWB`:  写屏障操作，用于垃圾回收。
   - `LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC`:  数组越界 panic。
   - `FlagEQ`, `FlagLT`, `FlagGT`, `FlagOV`:  获取标志位状态。
   - `SYNC`:  内存同步指令。
   - `MOVBZatomicload`, `MOVWZatomicload`, `MOVDatomicload`:  原子加载操作。
   - `MOVBatomicstore`: 原子存储操作。

**可以推理出的 Go 语言功能实现 (示例):**

基于上述分析，我们可以推断出一些 Go 语言功能是如何通过这些 SSA 操作实现的。

**示例 1: 整数取反**

```go
package main

func main() {
	x := 10
	y := -x // 这会对应 SSA 的 NEG 或 NEGW 操作
	println(y)
}
```

**假设的 SSA 输出 (简化):**

```
v1 = ConstInt64 <int> 10
v2 = NEG <int> v1
```

**示例 2: 浮点数平方根**

```go
package main
import "math"

func main() {
	f := 9.0
	s := math.Sqrt(f) // 这会对应 SSA 的 FSQRT 或 FSQRTS 操作
	println(s)
}
```

**假设的 SSA 输出 (简化):**

```
v1 = ConstFloat64 <float64> 9.0
v2 = FSQRT <float64> v1
```

**示例 3: 从内存加载数据**

```go
package main

func main() {
	arr := [3]int{1, 2, 3}
	val := arr[1] // 这会对应 SSA 的 MOVWload 或 MOVDload 操作 (取决于 int 的大小)
	println(val)
}
```

**假设的 SSA 输出 (简化，假设 int 是 64 位):**

```
v1 = ... // 表示数组 arr 的地址
v2 = ConstInt64 <int> 8 // 偏移量，假设 int 是 8 字节
v3 = ADDQ v1 v2
v4 = MOVDload <int> v3
```

**涉及代码推理，需要带上假设的输入与输出:**

上面的示例中已经包含了假设的输入 (Go 源代码) 和输出 (简化的 SSA 代码)。

**命令行参数的具体处理:**

这个代码片段本身并不直接处理命令行参数。`opGen.go` 文件通常由 `compile` 命令在编译 Go 代码时使用，它读取内部的数据结构并生成 SSA 中间表示。命令行参数的处理发生在编译器的其他阶段。

**使用者易犯错的点:**

作为编译器开发者，理解这些操作的语义和约束至关重要。常见的错误可能包括：

* **错误地使用寄存器约束:**  例如，将需要特定寄存器的操作分配到错误的寄存器。
* **不正确地处理标志位:** 某些操作会影响标志位，后续的条件跳转指令依赖于这些标志位。
* **对内存操作的理解错误:**  例如，没有正确处理内存对齐或越界访问。

**归纳一下它的功能 (针对第 32 部分):**

第 32 部分的 `opGen.go` 文件主要定义了 **s390x 架构**下用于表示各种操作的 SSA 节点。 这些定义包含了操作的元数据，例如名称、参数信息、对标志位的影响、以及最重要的 **汇编指令和寄存器使用信息**。 这部分内容是 Go 编译器将高级 Go 代码转换为低级机器码的关键步骤，它描述了在 SSA 中间表示层面上，如何使用 s390x 的指令集来实现不同的 Go 语言功能。 它是架构相关的，并且是整个编译过程中的一个重要组成部分，负责将架构无关的 SSA 转换为架构相关的机器指令。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第32部分，共36部分，请归纳一下它的功能

"""
ams,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ARISBGZ,
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
		name:         "NEG",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ANEG,
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
		name:         "NEGW",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ANEGW,
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
		name:         "NOT",
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
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
		name:         "NOTW",
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
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
		name:   "FSQRT",
		argLen: 1,
		asm:    s390x.AFSQRT,
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
		name:   "FSQRTS",
		argLen: 1,
		asm:    s390x.AFSQRTS,
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
		name:         "LOCGR",
		auxType:      auxS390XCCMask,
		argLen:       3,
		resultInArg0: true,
		asm:          s390x.ALOCGR,
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
		name:   "MOVBreg",
		argLen: 1,
		asm:    s390x.AMOVB,
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
		name:   "MOVBZreg",
		argLen: 1,
		asm:    s390x.AMOVBZ,
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
		name:   "MOVHreg",
		argLen: 1,
		asm:    s390x.AMOVH,
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
		name:   "MOVHZreg",
		argLen: 1,
		asm:    s390x.AMOVHZ,
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
		name:   "MOVWreg",
		argLen: 1,
		asm:    s390x.AMOVW,
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
		name:   "MOVWZreg",
		argLen: 1,
		asm:    s390x.AMOVWZ,
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
		name:              "MOVDconst",
		auxType:           auxInt64,
		argLen:            0,
		rematerializeable: true,
		asm:               s390x.AMOVD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "LDGR",
		argLen: 1,
		asm:    s390x.ALDGR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LGDR",
		argLen: 1,
		asm:    s390x.ALGDR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CFDBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACFDBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CGDBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACGDBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CFEBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACFEBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CGEBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACGEBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CEFBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACEFBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CDFBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACDFBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CEGBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACEGBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CDGBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACDGBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CLFEBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACLFEBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CLFDBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACLFDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CLGEBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACLGEBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CLGDBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACLGDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CELFBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACELFBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CDLFBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACDLFBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CELGBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACELGBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CDLGBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACDLGBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LEDBR",
		argLen: 1,
		asm:    s390x.ALEDBR,
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
		name:   "LDEBR",
		argLen: 1,
		asm:    s390x.ALDEBR,
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
		name:              "MOVDaddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295000064}, // SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:      "MOVDaddridx",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295000064}, // SP SB
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVBZload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVBZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVBload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVHZload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVHZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVHload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVWZload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVWZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVWload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "MOVWBR",
		argLen: 1,
		asm:    s390x.AMOVWBR,
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
		name:   "MOVDBR",
		argLen: 1,
		asm:    s390x.AMOVDBR,
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
		name:           "MOVHBRload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVWBRload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVDBRload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVHstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVHBRstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVWBRstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVDBRstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MVC",
		auxType:        auxSymValAndOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		symEffect:      SymNone,
		asm:            s390x.AMVC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVBZloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVBZ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVBloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVHZloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVHZ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVHloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVWZloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVWZ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVWloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVDloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVHBRloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVWBRloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVDBRloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVBstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVHstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVWstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVDstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVHBRstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVWBRstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVDBRstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVBstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
		},
	},
	{
		name:           "MOVHstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
		},
	},
	{
		name:           "MOVWstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
		},
	},
	{
		name:           "MOVDstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
		},
	},
	{
		name:           "CLEAR",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ACLEAR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CALLstatic",
		auxType:      auxCallOff,
		argLen:       1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			clobbers: 4294933503, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 g R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
	{
		name:         "CALLtail",
		auxType:      auxCallOff,
		argLen:       1,
		clobberFlags: true,
		call:         true,
		tailCall:     true,
		reg: regInfo{
			clobbers: 4294933503, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 g R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
	{
		name:         "CALLclosure",
		auxType:      auxCallOff,
		argLen:       3,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 4096},  // R12
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 4294933503, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 g R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
	{
		name:         "CALLinter",
		auxType:      auxCallOff,
		argLen:       2,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			clobbers: 4294933503, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 g R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
	{
		name:   "InvertFlags",
		argLen: 1,
		reg:    regInfo{},
	},
	{
		name:   "LoweredGetG",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4096}, // R12
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
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
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:         "LoweredRound32F",
		argLen:       1,
		resultInArg0: true,
		zeroWidth:    true,
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
		name:         "LoweredRound64F",
		argLen:       1,
		resultInArg0: true,
		zeroWidth:    true,
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
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 4294918146, // R1 R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			outputs: []outputInfo{
				{0, 512}, // R9
			},
		},
	},
	{
		name:    "LoweredPanicBoundsA",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4}, // R2
				{1, 8}, // R3
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
				{0, 2}, // R1
				{1, 4}, // R2
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
				{0, 1}, // R0
				{1, 2}, // R1
			},
		},
	},
	{
		name:   "FlagEQ",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagLT",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagGT",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagOV",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "SYNC",
		argLen: 1,
		asm:    s390x.ASYNC,
		reg:    regInfo{},
	},
	{
		name:           "MOVBZatomicload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVBZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVWZatomicload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVWZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVDatomicload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVBatomicstore",
"""




```