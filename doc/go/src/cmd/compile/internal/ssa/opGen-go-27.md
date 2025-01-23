Response:
Let's break down the thought process for answering the user's request.

**1. Understanding the Core Request:**

The user has provided a snippet of Go code from `go/src/cmd/compile/internal/ssa/opGen.go` and wants to know its functionality. Crucially, they ask for a high-level description, code examples if possible, handling of command-line arguments (if any), common mistakes, and a summary of the functionality of this specific "part 28 of 36".

**2. Initial Analysis of the Code Snippet:**

The provided code is a Go slice of structs. Each struct seems to define an operation (`op`) used in the Go compiler's Static Single Assignment (SSA) intermediate representation. Key fields in each struct are:

* `name`: The name of the operation (e.g., "LoweredAtomicLoad", "ADD").
* `auxType`:  An auxiliary type, often related to constants or symbols (e.g., `auxInt64`, `auxSymOff`).
* `argLen`: The number of arguments the operation takes.
* `clobberFlags`: Indicates if the operation modifies processor flags.
* `faultOnNilArg0`: Indicates if the operation will fault if the first argument is nil.
* `hasSideEffects`: Indicates if the operation has side effects beyond its output.
* `asm`:  The assembly instruction the operation corresponds to (e.g., `ppc64.AAND`, `riscv.AADD`).
* `reg`: A `regInfo` struct which likely describes register constraints for the operation's inputs and outputs.
* `commutative`: Indicates if the order of arguments doesn't matter.
* `resultNotInArgs`:  Indicates if the result is stored in a register different from the input arguments.
* `rematerializeable`:  Indicates if the operation's result can be recalculated if needed.
* `symEffect`: Describes how the operation interacts with symbols.
* `call`: Indicates if the operation represents a function call.

**3. Identifying Key Themes and Functionality:**

Scanning the `name` fields reveals several categories of operations:

* **Atomic Operations:**  "LoweredAtomicLoad", "LoweredAtomicAdd", "LoweredAtomicExchange", "LoweredAtomicCas", "LoweredAtomicAnd", "LoweredAtomicOr". These are clearly related to thread-safe memory access.
* **Basic Arithmetic and Logical Operations:** "ADD", "ADDI", "SUB", "MUL", "DIV", "REM", "NEG", "SLL", "SRA", "SRL", "AND", "OR", "XOR". These are fundamental CPU instructions.
* **Memory Access (Loads and Stores):** "MOVBload", "MOVHload", "MOVWload", "MOVDload", "MOVBUload", "MOVHUload", "MOVWUload", "MOVBstore", "MOVHstore", "MOVWstore", "MOVDstore", "MOVaddr", "MOVDconst". These handle reading and writing data to memory.
* **Control Flow/Flags:** "InvertFlags", "FlagEQ", "FlagLT", "FlagGT". These relate to conditional execution.
* **Special Operations:** "LoweredWB" (Write Barrier), "LoweredPubBarrier" (Publication Barrier), "LoweredPanicBounds" (Panic related to array bounds).

**4. Inferring the Purpose of `opGen.go`:**

Given the structure and content, it's highly probable that `opGen.go` is responsible for *defining* and *describing* the low-level operations that the Go compiler's SSA backend can use. This file likely serves as a central repository of information about these operations, including their assembly equivalents, register requirements, and other properties.

**5. Constructing the Explanation:**

Based on the analysis, the explanation should cover the following points:

* **Overall Function:**  Define SSA operations, their properties, and assembly mappings.
* **Specific Operations in the Snippet:**  Categorize and briefly describe the atomic, arithmetic, memory access, and other operations present.
* **Inferring Go Features:** Connect the atomic operations to the `sync/atomic` package and the panic bounds checks to array/slice access with bounds checking.
* **Code Examples:** Provide simple Go code snippets demonstrating the use of the features inferred (atomic operations, array access). Include the *assumed* input and output behavior, noting this is based on the *likely* function of the underlying operations.
* **Command-Line Arguments:**  Acknowledge that this specific file doesn't seem to directly handle command-line arguments. Explain that other parts of the compiler handle this.
* **Common Mistakes:**  Focus on the potential pitfalls of using atomic operations (race conditions if used incorrectly) and the runtime panics for out-of-bounds access.
* **Summary of Part 28:**  Emphasize that this section focuses on *lowered* operations, meaning they are closer to the machine code level and handle atomic operations, memory access with specific sizes, and architecture-specific instructions (like write barriers).

**6. Pre-computation/Pre-analysis (for efficiency):**

While not strictly necessary for this specific example, in general, when analyzing code like this, it's helpful to:

* **Look up unfamiliar terms:**  "SSA," "write barrier," "publication barrier" might require quick searches if the context isn't immediately clear.
* **Consider the file path:**  `go/src/cmd/compile/internal/ssa/` strongly suggests this is part of the compiler's SSA generation or optimization phase.
* **Recognize patterns:** The consistent structure of the structs indicates a systematic definition of operations.

**7. Refinement and Language:**

Finally, the answer should be written clearly in Chinese, as requested. It should use appropriate technical terminology while remaining accessible. For instance, explaining "lowered" operations as being closer to machine code is helpful. The "第28部分" aspect needs to be addressed in the summary.

By following these steps, we can arrive at a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to analyze the code structure, identify patterns and themes, make informed inferences about the code's purpose, and then present the information in a clear and organized manner.
## 功能列举与推断

这段Go代码定义了一系列操作（operations），这些操作是Go语言编译器在进行静态单赋值（Static Single Assignment, SSA）中间表示时使用的。每个操作都用一个结构体来描述，包含了名称、参数长度、是否会修改标志位、是否可能因为空指针而崩溃、是否有副作用、寄存器信息以及汇编指令等信息。

**具体功能包括：**

1. **定义 SSA 操作的属性：**  每个结构体定义了一个 SSA 操作的各种属性，例如它接受多少个参数 (`argLen`)，它是否是可交换的 (`commutative`)，以及它对应的汇编指令 (`asm`)。
2. **描述寄存器分配约束：** `reg` 字段的 `regInfo` 结构体描述了操作数和结果需要使用的寄存器，以及哪些寄存器会被破坏 (`clobbers`)。 这对于编译器的寄存器分配阶段至关重要。
3. **指定操作的副作用：** `hasSideEffects` 字段表明操作除了计算结果外，是否还会产生其他影响，例如修改内存。
4. **指示潜在的运行时错误：** `faultOnNilArg0` 字段表明如果第一个参数是空指针，此操作是否会导致运行时错误（panic）。
5. **标记符号影响：** `symEffect` 字段表明操作是否会读取或写入符号表中的数据 (`SymRead`, `SymWrite`, `SymAddr`)。
6. **区分“降低”后的操作：**  以 "Lowered" 开头的操作名，例如 "LoweredAtomicLoadPtr"，暗示这些是经过“降低”（lowering）处理后的操作。降低是将高级的、抽象的 SSA 操作转换为更接近目标机器指令的操作的过程。

**推断 Go 语言功能的实现：**

根据代码中定义的操作，我们可以推断出它涉及以下 Go 语言功能的底层实现：

1. **原子操作 (`sync/atomic` 包)：**  定义了诸如 `LoweredAtomicLoadPtr`, `LoweredAtomicAdd32`, `LoweredAtomicExchange8`, `LoweredAtomicCas64` 等操作，这些明显对应 Go 语言的 `sync/atomic` 包提供的原子操作。这些操作保证了在多线程环境下的数据安全访问。

   ```go
   package main

   import (
       "fmt"
       "sync/atomic"
   )

   func main() {
       var counter int32
       atomic.AddInt32(&counter, 1)
       fmt.Println(atomic.LoadInt32(&counter))
   }
   ```

   **假设输入：** 运行上述代码。
   **输出：** `1`

   这里，`atomic.AddInt32` 对应 `LoweredAtomicAdd32`， `atomic.LoadInt32` 对应 `LoweredAtomicLoadPtr`（可能需要进一步降低）。

2. **内存屏障 (`sync` 包)：**  `LoweredWB` (Write Barrier) 和 `LoweredPubBarrier` (Publication Barrier) 等操作与 Go 语言的内存模型有关，用于确保在并发访问共享内存时的可见性和顺序性。这些可能在 `sync` 包的 Mutex 或 WaitGroup 的实现中使用。

   ```go
   package main

   import (
       "sync"
       "time"
   )

   func main() {
       var data string
       var wg sync.WaitGroup
       wg.Add(1)

       go func() {
           data = "hello"
           wg.Done() // 这里可能涉及到 Publication Barrier
       }()

       wg.Wait() // 这里可能涉及到 Write Barrier，等待数据写入完成
       println(data)
   }
   ```

   由于内存屏障通常是隐式插入的，直接用 Go 代码很难显式地展示其对应的 SSA 操作。上述代码仅为概念性示例，说明了可能需要内存屏障的场景。

3. **边界检查 (数组/切片访问)：** `LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC` 这些操作名暗示了数组或切片越界访问时的 panic 处理。

   ```go
   package main

   import "fmt"

   func main() {
       arr := [3]int{1, 2, 3}
       index := 5
       // 编译器可能会生成类似 LoweredPanicBounds 的指令来检查 index
       if index >= len(arr) {
           panic("index out of range")
       }
       fmt.Println(arr[index])
   }
   ```

   **假设输入：** 运行上述代码。
   **输出：** `panic: index out of range`

   编译器会在编译 `arr[index]` 时插入边界检查，如果 `index` 超出数组的范围，就会触发 panic，这与 `LoweredPanicBounds` 系列操作有关。

4. **基本的算术和逻辑运算：**  `ADD`, `ADDI`, `SUB`, `MUL`, `DIV`, `REM`, `NEG`, `SLL`, `SRA`, `SRL` 等操作对应 Go 语言中的基本算术和逻辑运算。

   ```go
   package main

   import "fmt"

   func main() {
       a := 10
       b := 5
       sum := a + b // 对应 ADD 或 ADDI
       fmt.Println(sum)
   }
   ```

   **假设输入：** 运行上述代码。
   **输出：** `15`

5. **内存加载和存储：** `MOVBload`, `MOVHload`, `MOVWload`, `MOVDload`, `MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVDstore` 等操作对应 Go 语言中的内存读取和写入操作。

   ```go
   package main

   import "fmt"

   func main() {
       var x int32 = 10
       y := x // 对应 MOVWload
       x = 20  // 对应 MOVWstore
       fmt.Println(y)
   }
   ```

   **假设输入：** 运行上述代码。
   **输出：** `10`

**命令行参数的具体处理：**

从这段代码本身来看，它并没有直接处理命令行参数。 `opGen.go` 文件通常是编译过程的一部分，用于生成或定义 SSA 操作。 命令行参数的处理通常发生在编译器的前端和驱动程序中，例如 `go build` 命令接收的参数。这些参数会影响编译过程，但不会直接体现在 `opGen.go` 定义的操作中。

**第28部分的功能归纳：**

作为36个部分中的第28部分，这段代码主要关注 **经过降低处理后的 SSA 操作**，特别是与 **原子操作、内存屏障** 以及 **特定架构（例如这里出现的 `ppc64` 和 `riscv` 指令）相关的低级操作**。  这部分的工作是将更通用的 SSA 操作转换为目标架构能够直接执行的或更接近目标架构的操作。  它还包含了与运行时错误处理相关的操作，例如边界检查导致的 panic。  从操作码的分布来看，这部分可能正在处理从一个更通用的 SSA 中间表示到特定 CPU 架构的转换过程中的关键步骤。

**总结来说，这部分 `opGen.go` 的功能是定义 Go 编译器 SSA 中间表示中一部分**“降低”后的操作**，这些操作与**并发控制（原子操作、内存屏障）**、**内存访问** 和 **运行时错误处理** 相关，并且开始体现出 **特定硬件架构** 的特征。**

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第28部分，共36部分，请归纳一下它的功能
```

### 源代码
```go
7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicLoadPtr",
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
		name:            "LoweredAtomicAdd32",
		argLen:          3,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
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
		name:            "LoweredAtomicAdd64",
		argLen:          3,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
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
		name:            "LoweredAtomicExchange8",
		argLen:          3,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
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
		name:            "LoweredAtomicExchange32",
		argLen:          3,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
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
		name:            "LoweredAtomicExchange64",
		argLen:          3,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
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
		name:            "LoweredAtomicCas64",
		auxType:         auxInt64,
		argLen:          4,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:            "LoweredAtomicCas32",
		auxType:         auxInt64,
		argLen:          4,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{2, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicAnd8",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		asm:            ppc64.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicAnd32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		asm:            ppc64.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicOr8",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		asm:            ppc64.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:           "LoweredAtomicOr32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		asm:            ppc64.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 18446744072632408064, // R11 R12 R18 R19 R22 R23 R24 R25 R26 R27 R28 R29 R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 XER
			outputs: []outputInfo{
				{0, 536870912}, // R29
			},
		},
	},
	{
		name:           "LoweredPubBarrier",
		argLen:         1,
		hasSideEffects: true,
		asm:            ppc64.ALWSYNC,
		reg:            regInfo{},
	},
	{
		name:    "LoweredPanicBoundsA",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 32}, // R5
				{1, 64}, // R6
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
				{0, 16}, // R4
				{1, 32}, // R5
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
				{0, 8},  // R3
				{1, 16}, // R4
			},
		},
	},
	{
		name:   "InvertFlags",
		argLen: 1,
		reg:    regInfo{},
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
		name:        "ADD",
		argLen:      2,
		commutative: true,
		asm:         riscv.AADD,
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
		name:    "ADDI",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.AADDI,
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
		name:    "ADDIW",
		auxType: auxInt64,
		argLen:  1,
		asm:     riscv.AADDIW,
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
		name:   "NEG",
		argLen: 1,
		asm:    riscv.ANEG,
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
		name:   "NEGW",
		argLen: 1,
		asm:    riscv.ANEGW,
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
		name:   "SUB",
		argLen: 2,
		asm:    riscv.ASUB,
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
		name:   "SUBW",
		argLen: 2,
		asm:    riscv.ASUBW,
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
		name:        "MUL",
		argLen:      2,
		commutative: true,
		asm:         riscv.AMUL,
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
		name:        "MULW",
		argLen:      2,
		commutative: true,
		asm:         riscv.AMULW,
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
		name:        "MULH",
		argLen:      2,
		commutative: true,
		asm:         riscv.AMULH,
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
		name:        "MULHU",
		argLen:      2,
		commutative: true,
		asm:         riscv.AMULHU,
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
		name:            "LoweredMuluhilo",
		argLen:          2,
		resultNotInArgs: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:            "LoweredMuluover",
		argLen:          2,
		resultNotInArgs: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:   "DIV",
		argLen: 2,
		asm:    riscv.ADIV,
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
		name:   "DIVU",
		argLen: 2,
		asm:    riscv.ADIVU,
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
		name:   "DIVW",
		argLen: 2,
		asm:    riscv.ADIVW,
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
		name:   "DIVUW",
		argLen: 2,
		asm:    riscv.ADIVUW,
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
		name:   "REM",
		argLen: 2,
		asm:    riscv.AREM,
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
		name:   "REMU",
		argLen: 2,
		asm:    riscv.AREMU,
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
		name:   "REMW",
		argLen: 2,
		asm:    riscv.AREMW,
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
		name:   "REMUW",
		argLen: 2,
		asm:    riscv.AREMUW,
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
		name:              "MOVaddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		asm:               riscv.AMOV,
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
		name:              "MOVDconst",
		auxType:           auxInt64,
		argLen:            0,
		rematerializeable: true,
		asm:               riscv.AMOV,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
			},
		},
	},
	{
		name:           "MOVBload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            riscv.AMOVB,
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
		name:           "MOVHload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            riscv.AMOVH,
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
		name:           "MOVWload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            riscv.AMOVW,
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
		name:           "MOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            riscv.AMOV,
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
		name:           "MOVBUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            riscv.AMOVBU,
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
		name:           "MOVHUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            riscv.AMOVHU,
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
		name:           "MOVWUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            riscv.AMOVWU,
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
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1006632946},          // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:           "MOVHstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1006632946},          // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1006632946},          // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:           "MOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOV,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1006632946},          // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:           "MOVBstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:           "MOVHstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:           "MOVWstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:           "MOVDstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            riscv.AMOV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372037861408754}, // SP X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30 SB
			},
		},
	},
	{
		name:   "MOVBreg",
		argLen: 1,
		asm:    riscv.AMOVB,
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
		name:   "MOVHreg",
		argLen: 1,
		asm:    riscv.AMOVH,
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
		name:   "MOVWreg",
		argLen: 1,
		asm:    riscv.AMOVW,
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
		name:   "MOVDreg",
		argLen: 1,
		asm:    riscv.AMOV,
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
		name:   "MOVBUreg",
		argLen: 1,
		asm:    riscv.AMOVBU,
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
		name:   "MOVHUreg",
		argLen: 1,
		asm:    riscv.AMOVHU,
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
		name:   "MOVWUreg",
		argLen: 1,
		asm:    riscv.AMOVWU,
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
		name:         "MOVDnop",
		argLen:       1,
		resultInArg0: true,
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
		name:   "SLL",
		argLen: 2,
		asm:    riscv.ASLL,
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
		name:   "SLLW",
		argLen: 2,
		asm:    riscv.ASLLW,
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
		name:   "SRA",
		argLen: 2,
		asm:    riscv.ASRA,
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
		name:   "SRAW",
		argLen: 2,
		asm:    riscv.ASRAW,
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
		name:   "SRL",
		argLen: 2,
		asm:    riscv.ASRL,
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
		name:   "SRLW",
		argLen: 2,
		asm:    riscv.ASRLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 X21 X22 X23 X24 X25 X26 X28 X29 X30
				{1, 1006632944}, // X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15
```