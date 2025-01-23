Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze a snippet of Go code that appears to be part of the Go compiler's SSA (Static Single Assignment) generation phase, specifically for the Loong64 architecture. The request asks about the functionality, potential Go language feature implementations, code examples, command-line argument handling, common errors, and a summary of the code's purpose within the larger context.

2. **Identify Key Information:** The provided code is a large array of structs. Each struct seems to describe an operation (`op`) supported by the Loong64 architecture. Key fields within each struct are:
    * `name`:  The name of the operation (e.g., "MOVWU", "MOVVreg", "CALLstatic").
    * `asm`: The corresponding assembly instruction for the Loong64 architecture (e.g., `loong64.AMOVWU`, `loong64.AMOVV`).
    * `argLen`: The number of arguments the operation takes. `-1` likely signifies a variable number of arguments (like for calls).
    * `reg`: A `regInfo` struct detailing register usage:
        * `inputs`:  The registers used as input for the operation. The number likely represents a bitmask indicating allowed registers.
        * `outputs`: The registers used for the output of the operation.
        * `clobbers`: Registers that are modified or whose values are undefined after the operation.
    * Other fields like `auxType`, `resultInArg0`, `clobberFlags`, `call`, `tailCall`, `faultOnNilArg0`, `hasSideEffects`, `unsafePoint`, `commutative`, `nilCheck`, `zeroWidth`, and `rematerializeable`. These provide more details about the operation's behavior and properties.

3. **Infer Functionality:** Based on the structure and the names of the operations, I can deduce that this code defines the mapping between high-level SSA operations and their corresponding low-level assembly instructions for the Loong64 architecture. It also specifies register constraints and side effects for each operation. This information is crucial for the compiler's back-end to generate correct and efficient machine code.

4. **Relate to Go Language Features:** I need to connect these low-level operations to higher-level Go constructs. Some obvious mappings include:
    * **`MOV` operations:** These directly correspond to assignment statements in Go. Different `MOV` variants handle different data types (word, double-word, float, double).
    * **`CALL` operations:**  These implement function calls in Go (static calls, closures, interface calls).
    * **Arithmetic operations (`ADD`, `SUB`, `MUL`, `DIV`, `ADDF`, `ADDD`, etc.):** These implement Go's arithmetic operators.
    * **Atomic operations (`LoweredAtomicLoad`, `LoweredAtomicStore`, `LoweredAtomicExchange`, `LoweredAtomicCas`, `LoweredAtomicAdd`, `LoweredAtomicAnd`, `LoweredAtomicOr`):** These correspond to the functions in the `sync/atomic` package in Go, which provide thread-safe operations on memory.
    * **`TRUNC` operations:** These likely implement type conversions between floating-point and integer types.
    * **`LoweredRound` operations:** These implement rounding of floating-point numbers.
    * **`DUFFZERO`, `DUFFCOPY`:**  These are related to optimized memory initialization (zeroing) and copying, often used for slices and arrays.
    * **`LoweredNilCheck`:** This implements Go's nil pointer checks.
    * **`LoweredGetClosurePtr`, `LoweredGetCallerSP`, `LoweredGetCallerPC`:** These are runtime-related operations for accessing closure context, stack pointers, and program counters.
    * **`LoweredWB`:** This is likely related to the write barrier in Go's garbage collector.
    * **`LoweredPubBarrier`:**  Likely a memory barrier to ensure memory ordering.
    * **`LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC`:** These are involved in implementing array bounds checks and triggering panics when those bounds are violated.

5. **Provide Go Code Examples:** For each inferred Go feature, I need to provide a simple Go code snippet that would likely result in the generation of the corresponding SSA operations defined in the provided code. This involves demonstrating the use of assignment, function calls, arithmetic, atomic operations, type conversions, etc. I should also consider edge cases or variations that might lead to different SSA opcodes.

6. **Consider Command-Line Arguments:** This section is tricky without more context. The `opGen.go` file itself is unlikely to directly handle command-line arguments. However, the Go compiler (`go build`, `go run`, etc.) uses command-line arguments. I need to think about how these arguments might indirectly influence the code generation process and the selection of these operations. For example, optimization levels might affect which operations are chosen. The target architecture (`GOARCH=loong64`) is clearly relevant.

7. **Identify Potential Mistakes:**  Based on my understanding of compiler construction and the nature of the data, I can anticipate common mistakes users might make that would lead to incorrect code generation or runtime errors. These often involve incorrect assumptions about register usage, calling conventions, or the semantics of specific assembly instructions.

8. **Structure the Answer:** I need to organize the information logically, following the prompts in the request. This involves:
    * Clearly stating the primary function of the code.
    * Listing specific Go language features and providing corresponding code examples.
    * Explaining how command-line arguments might be involved.
    * Giving examples of common user errors.
    * Providing a concise summary.

9. **Refine and Review:**  After drafting the answer, I should review it for clarity, accuracy, and completeness. Are the Go code examples correct? Is the explanation of the command-line arguments reasonable? Are the common errors plausible? Is the summary accurate?  Since the prompt emphasizes Chinese, ensuring proper and natural-sounding Chinese phrasing is essential.

By following this structured thought process, I can effectively analyze the given Go code snippet and provide a comprehensive and helpful answer to the request. The key is to break down the problem into smaller, manageable parts and to leverage my understanding of compilers and Go to connect the low-level details to higher-level concepts.
这段代码是Go语言编译器中用于为 **LoongArch 64位架构 (loong64)** 生成中间代码表示（SSA，Static Single Assignment）操作 (Operation) 的一部分。它定义了一系列的操作，每个操作都对应着一个特定的LoongArch汇编指令或者一个更高级的抽象操作。

**主要功能归纳:**

这段代码的主要功能是定义了从抽象的SSA操作到具体的LoongArch汇编指令的映射关系，并描述了每个操作的属性，例如：

* **操作名称 (name):**  例如 "MOVWU", "MOVVreg", "CALLstatic" 等，表示不同的操作类型。
* **参数长度 (argLen):**  表示该操作接收的参数个数。`-1` 通常表示可变参数。
* **对应的汇编指令 (asm):**  例如 `loong64.AMOVWU`, `loong64.AMOVV`，指定了该操作在LoongArch架构上对应的具体汇编指令。
* **寄存器信息 (reg):**  `regInfo` 结构体详细描述了该操作对寄存器的使用情况：
    * **输入寄存器 (inputs):**  指定了操作数需要放置的寄存器类型和范围。例如，`{0, 1073741816}` 表示第一个输入操作数可以放在通用寄存器 R4 到 R31 (以及 g 寄存器)。
    * **输出寄存器 (outputs):** 指定了操作结果会放置的寄存器类型和范围。
    * **覆盖寄存器 (clobbers):**  指定了执行该操作后会被修改的寄存器。
* **辅助类型 (auxType):**  用于存储一些额外的辅助信息，例如常数值或函数偏移量。
* **结果是否在参数中 (resultInArg0):**  表示操作的结果是否直接存储在第一个输入参数的位置。
* **是否覆盖标志位 (clobberFlags):** 表示操作是否会修改处理器的标志位。
* **是否是函数调用 (call):**  标记该操作是否表示函数调用。
* **是否是尾调用 (tailCall):** 标记该操作是否是尾调用优化。
* **访问空指针是否会出错 (faultOnNilArg0, faultOnNilArg1):**  标记操作是否会在访问空指针时触发错误。
* **是否有副作用 (hasSideEffects):** 标记操作是否会产生除了修改输出寄存器之外的副作用（例如，修改内存）。
* **是否是不安全点 (unsafePoint):**  在并发编程中标记可能导致数据竞争的点。
* **是否满足交换律 (commutative):** 标记操作是否满足交换律（例如，加法和乘法）。
* **是否进行空指针检查 (nilCheck):** 标记操作是否是空指针检查。
* **结果宽度是否为零 (zeroWidth):** 标记操作的结果是否不占用空间。
* **是否可以重新计算 (rematerializeable):** 标记操作的结果是否可以重新计算而不是存储。

**可以推理出的Go语言功能实现示例:**

基于代码中的操作名称和汇编指令，可以推断出它实现了以下一些Go语言的功能：

1. **基本数据类型的赋值和移动:**
   * `"MOVWU"` (Move Word Unsigned): 对应无符号 32 位整数的赋值操作。
   * `"MOVVreg"` (Move Value Register): 对应 64 位整数或指针的赋值操作。
   * `"MOVWF"`, `"MOVWD"`, `"MOVVF"`, `"MOVVD"`: 对应单精度浮点数 (float32) 和双精度浮点数 (float64) 的赋值操作。

   ```go
   package main

   func main() {
       var a uint32 = 10
       var b uint32 = a  // 可能对应 "MOVWU"

       var c int64 = 100
       var d int64 = c  // 可能对应 "MOVVreg"

       var e float32 = 3.14
       var f float32 = e  // 可能对应 "MOVWF"

       var g float64 = 2.718
       var h float64 = g  // 可能对应 "MOVWD"
   }
   ```

   **假设的 SSA 输入与输出:**

   假设对于 `var b uint32 = a`， SSA 生成器可能会生成类似如下的中间表示：

   ```
   v1 = LoadReg a // 将变量 a 的值加载到寄存器 (抽象表示)
   b = Move v1    // 将 v1 的值移动到变量 b (抽象表示，可能对应 "MOVWU")
   ```

   `opGen.go` 中的 `"MOVWU"` 条目会告诉编译器，在 LoongArch 架构上，这个 Move 操作可以使用 `loong64.AMOVWU` 指令，并将输入放在指定的通用寄存器，输出也放在指定的通用寄存器。

2. **函数调用:**
   * `"CALLstatic"`: 对应静态函数调用。
   * `"CALLclosure"`: 对应闭包调用。
   * `"CALLinter"`: 对应接口方法调用。

   ```go
   package main

   import "fmt"

   func add(x, y int) int {
       return x + y
   }

   func main() {
       result := add(5, 3) // 可能对应 "CALLstatic"
       fmt.Println(result)

       // 闭包示例
       multiplier := func(factor int) int {
           return result * factor
       }
       product := multiplier(2) // 可能对应 "CALLclosure"
       fmt.Println(product)

       // 接口示例 (简化)
       var s fmt.Stringer = fmt.Sprintf("value")
       s.String() // 可能对应 "CALLinter"
   }
   ```

   对于函数调用，`opGen.go` 中的 `CALL` 相关条目会指定调用约定，哪些寄存器用于传递参数和返回值，以及哪些寄存器会被调用修改 (clobber)。

3. **原子操作:**
   * `"LoweredAtomicLoad8"`, `"LoweredAtomicLoad32"`, `"LoweredAtomicLoad64"`: 对应原子加载操作。
   * `"LoweredAtomicStore8"`, `"LoweredAtomicStore32"`, `"LoweredAtomicStore64"`: 对应原子存储操作。
   * `"LoweredAtomicExchange32"`, `"LoweredAtomicExchange64"`: 对应原子交换操作。
   * `"LoweredAtomicCas32"`, `"LoweredAtomicCas64"`: 对应原子比较并交换操作。
   * `"LoweredAtomicAdd32"`, `"LoweredAtomicAdd64"`: 对应原子加法操作。
   * `"LoweredAtomicAnd32"`, `"LoweredAtomicOr32"`: 对应原子与和原子或操作。

   ```go
   package main

   import (
       "fmt"
       "sync/atomic"
   )

   func main() {
       var counter int32
       atomic.AddInt32(&counter, 1) // 可能对应 "LoweredAtomicAdd32"
       fmt.Println(atomic.LoadInt32(&counter)) // 可能对应 "LoweredAtomicLoad32"
   }
   ```

   `opGen.go` 中定义的原子操作条目会指定用于实现这些原子操作的 LoongArch 指令序列，并确保操作的原子性。

4. **浮点数运算:**
   * `"TRUNCFW"`, `"TRUNCDW"`, `"TRUNCFV"`, `"TRUNCDV"`: 可能是浮点数截断为整数的操作。
   * `"MOVFD"`, `"MOVDF"`: 可能是单精度和双精度浮点数之间的类型转换。
   * `"LoweredRound32F"`, `"LoweredRound64F"`: 可能是浮点数四舍五入操作。

   ```go
   package main

   import "fmt"

   func main() {
       var f float64 = 3.7
       var i int32 = int32(f) // 可能涉及 "TRUNCDW" 或 "TRUNCDV"
       fmt.Println(i)

       var g float32 = float32(f) // 可能涉及 "MOVDF" 或 "MOVFD"
       fmt.Println(g)
   }
   ```

5. **内存操作:**
   * `"DUFFZERO"`, `"DUFFCOPY"`:  这通常与高效地进行内存清零和复制有关，可能用于实现切片或数组的初始化和复制。

   ```go
   package main

   import "fmt"

   func main() {
       s := make([]int, 10) // 初始化切片，可能使用 "DUFFZERO"
       fmt.Println(s)

       t := make([]int, len(s))
       copy(t, s) // 复制切片，可能使用 "DUFFCOPY"
       fmt.Println(t)
   }
   ```

6. **其他底层操作:**
   * `"LoweredNilCheck"`: 对应于 Go 语言中的空指针检查。
   * `"LoweredGetClosurePtr"`, `"LoweredGetCallerSP"`, `"LoweredGetCallerPC"`: 这些是用于获取闭包指针、调用者栈指针和程序计数器的底层操作，通常由运行时系统使用。
   * `"LoweredWB"`:  对应于垃圾回收机制中的写屏障 (Write Barrier)。
   * `"LoweredPubBarrier"`:  对应于发布屏障 (Publish Barrier)，用于保证内存操作的顺序性。
   * `"LoweredPanicBoundsA"`, `"LoweredPanicBoundsB"`, `"LoweredPanicBoundsC"`: 对应于数组或切片的越界检查，当发生越界时会触发 panic。

**命令行参数的具体处理:**

`opGen.go` 文件本身并不直接处理命令行参数。它是 Go 编译器内部的一部分，用于生成代码。Go 编译器的命令行参数（例如 `-gcflags`, `-ldflags`, `-o` 等）会影响编译过程的各个阶段，包括 SSA 的生成和优化。

例如：

* **`-gcflags`**: 可以传递给 Go 编译器的标志，其中一些标志可能会影响 SSA 生成的策略和细节，间接地影响到 `opGen.go` 中定义的哪些操作会被使用以及如何使用。例如，优化级别会影响是否启用某些优化，从而改变 SSA 图的结构。
* **`GOARCH=loong64`**:  这个环境变量指定了目标架构为 LoongArch 64 位，这直接决定了编译器会使用 `opGen.go` 中为 LoongArch 定义的操作。

**使用者易犯错的点:**

作为编译器开发者，可能会犯以下错误：

* **寄存器约束不正确:**  `regInfo` 中的 `inputs` 和 `outputs` 定义错误，可能导致生成的汇编代码使用了错误的寄存器，导致程序崩溃或产生错误的结果。例如，将一个只需要特定寄存器的操作的输入限制放得太宽泛。
* **汇编指令映射错误:**  将 SSA 操作映射到错误的 LoongArch 汇编指令，导致程序执行逻辑错误。
* **副作用描述不准确:**  `hasSideEffects` 标记错误，可能导致编译器在进行某些优化时做出错误的假设。
* **调用约定错误:**  对于 `"CALL"` 相关的操作，没有正确描述参数传递和返回值的方式，导致函数调用失败。
* **原子操作实现错误:**  对于 `"LoweredAtomic..."` 操作，没有使用正确的原子指令序列，导致并发安全问题。

**第21部分的功能归纳:**

作为第21部分（共36部分），这段代码的主要功能是定义了 **LoongArch 64位架构下，一部分操作的 SSA 中间表示到机器指令的映射关系和寄存器使用约束**。它涵盖了基本的数据移动、浮点数操作、函数调用以及一些底层的运行时操作。在整个 `opGen.go` 文件中，不同的部分可能负责不同类型的操作或指令集扩展。这部分侧重于一些基础和常见的操作。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第21部分，共36部分，请归纳一下它的功能
```

### 源代码
```go
1,
		asm:    loong64.AMOVWU,
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
		name:   "MOVVreg",
		argLen: 1,
		asm:    loong64.AMOVV,
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
		name:         "MOVVnop",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVWF",
		argLen: 1,
		asm:    loong64.AMOVWF,
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
		name:   "MOVWD",
		argLen: 1,
		asm:    loong64.AMOVWD,
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
		name:   "MOVVF",
		argLen: 1,
		asm:    loong64.AMOVVF,
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
		name:   "MOVVD",
		argLen: 1,
		asm:    loong64.AMOVVD,
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
		name:   "TRUNCFW",
		argLen: 1,
		asm:    loong64.ATRUNCFW,
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
		name:   "TRUNCDW",
		argLen: 1,
		asm:    loong64.ATRUNCDW,
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
		name:   "TRUNCFV",
		argLen: 1,
		asm:    loong64.ATRUNCFV,
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
		name:   "TRUNCDV",
		argLen: 1,
		asm:    loong64.ATRUNCDV,
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
		name:   "MOVFD",
		argLen: 1,
		asm:    loong64.AMOVFD,
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
		name:   "MOVDF",
		argLen: 1,
		asm:    loong64.AMOVDF,
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
		name:         "LoweredRound32F",
		argLen:       1,
		resultInArg0: true,
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
		name:         "LoweredRound64F",
		argLen:       1,
		resultInArg0: true,
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
		name:         "CALLstatic",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			clobbers: 4611686018427387896, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
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
			clobbers: 4611686018427387896, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
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
				{1, 268435456},  // R29
				{0, 1071644668}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			clobbers: 4611686018427387896, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
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
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			clobbers: 4611686018427387896, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:           "DUFFZERO",
		auxType:        auxInt64,
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 524288}, // R20
			},
			clobbers: 524290, // R1 R20
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
				{0, 1048576}, // R21
				{1, 524288},  // R20
			},
			clobbers: 1572866, // R1 R20 R21
		},
	},
	{
		name:           "LoweredZero",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 524288},     // R20
				{1, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			clobbers: 524288, // R20
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
				{0, 1048576},    // R21
				{1, 524288},     // R20
				{2, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			clobbers: 1572864, // R20 R21
		},
	},
	{
		name:           "LoweredAtomicLoad8",
		argLen:         2,
		faultOnNilArg0: true,
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
		name:           "LoweredAtomicLoad32",
		argLen:         2,
		faultOnNilArg0: true,
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
		name:           "LoweredAtomicLoad64",
		argLen:         2,
		faultOnNilArg0: true,
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
		name:           "LoweredAtomicStore8",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore8Variant",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore32Variant",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore64Variant",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicExchange8Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
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
		name:            "LoweredAtomicAdd32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
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
		name:            "LoweredAtomicAdd64",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
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
		name:            "LoweredAtomicCas32",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicCas64Variant",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicCas32Variant",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAnd32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMANDDBW,
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
		name:            "LoweredAtomicOr32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMORDBW,
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
		name:            "LoweredAtomicAnd32value",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMANDDBW,
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
		name:            "LoweredAtomicAnd64value",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMANDDBV,
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
		name:            "LoweredAtomicOr32value",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMORDBW,
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
		name:            "LoweredAtomicOr64value",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMORDBV,
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
		name:           "LoweredNilCheck",
		argLen:         2,
		nilCheck:       true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "FPFlagTrue",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "FPFlagFalse",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 268435456}, // R29
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 4611686017353646082, // R1 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			outputs: []outputInfo{
				{0, 268435456}, // R29
			},
		},
	},
	{
		name:           "LoweredPubBarrier",
		argLen:         1,
		hasSideEffects: true,
		asm:            loong64.ADBAR,
		reg:            regInfo{},
	},
	{
		name:    "LoweredPanicBoundsA",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4194304}, // R23
				{1, 8388608}, // R24
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
				{0, 1048576}, // R21
				{1, 4194304}, // R23
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
				{0, 524288},  // R20
				{1, 1048576}, // R21
			},
		},
	},

	{
		name:        "ADD",
		argLen:      2,
		commutative: true,
		asm:         mips.AADDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "ADDconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.AADDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 536870910}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "SUB",
		argLen: 2,
		asm:    mips.ASUBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "SUBconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.ASUBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:        "MUL",
		argLen:      2,
		commutative: true,
		asm:         mips.AMUL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			clobbers: 105553116266496, // HI LO
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:        "MULT",
		argLen:      2,
		commutative: true,
		asm:         mips.AMUL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 35184372088832}, // HI
				{1, 70368744177664}, // LO
			},
		},
	},
	{
		name:        "MULTU",
		argLen:      2,
		commutative: true,
		asm:         mips.AMULU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 35184372088832}, // HI
				{1, 70368744177664}, // LO
			},
		},
	},
	{
		name:   "DIV",
		argLen: 2,
		asm:    mips.ADIV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 35184372088832}, // HI
				{1, 70368744177664}, // LO
			},
		},
	},
	{
		name:   "DIVU",
		argLen: 2,
		asm:    mips.ADIVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 35184372088832}, // HI
				{1, 70368744177664}, // LO
			},
		},
	},
	{
		name:        "ADDF",
		argLen:      2,
		commutative: true,
		asm:         mips.AADDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:        "ADDD",
		argLen:      2,
		commutative: true,
		asm:         mips.AADDD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "SUBF",
		argLen: 2,
		asm:    mips.ASUBF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "SUBD",
		argLen: 2,
		asm:    mips.ASUBD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:        "MULF",
		argLen:      2,
		commutative: true,
		asm:         mips.AMULF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4
```