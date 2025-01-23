Response:
Let's break down the thought process to answer the request about the provided Go code snippet.

1. **Understand the Context:** The prompt clearly states this is part of `go/src/cmd/compile/internal/ssa/opGen.go`. This immediately tells us we're dealing with the Go compiler's intermediate representation (SSA - Static Single Assignment) and how operations are generated for a specific architecture. The fact that it's part 33 of 36 suggests it's near the end of a larger definition of these operations.

2. **Identify the Core Data Structure:** The code is a large Go slice literal. The elements of this slice are structs. Examining the struct fields (`name`, `auxType`, `argLen`, `clobberFlags`, `faultOnNilArg0`, `hasSideEffects`, `symEffect`, `asm`, `reg`) reveals the purpose: defining properties of individual SSA operations.

3. **Infer the Purpose of Each Field:**
    * `name`:  A string identifier for the operation (e.g., "MOVBatomicstore", "LAA").
    * `auxType`: An auxiliary type, often related to symbols or integers (e.g., `auxSymOff`, `auxInt64`).
    * `argLen`: The number of arguments the operation takes.
    * `clobberFlags`:  Indicates if the operation modifies processor flags.
    * `faultOnNilArg0`:  Indicates if the operation will fault if the first argument is nil.
    * `hasSideEffects`:  Indicates if the operation has effects beyond its return value (e.g., memory writes).
    * `symEffect`:  Describes how the operation interacts with symbols in memory (`SymWrite`, `SymRdWr`, `SymAddr`).
    * `asm`: The assembly instruction corresponding to the operation (e.g., `s390x.AMOVB`, `wasm.AI64Add`). This clearly indicates the code is defining operations for *multiple* target architectures (s390x and wasm are present in this snippet).
    * `reg`: A nested struct (`regInfo`) describing register usage:
        * `inputs`:  Specifies which registers can be used for input arguments. The bitmasks (like `4295023614`) are likely representations of register sets.
        * `outputs`: Specifies which registers are used for output.
        * `clobbers`: Specifies registers whose values are overwritten by the operation.

4. **Connect to SSA Concepts:** Recognize that these operation definitions are crucial for the SSA generation phase of the compiler. The compiler uses this information to translate high-level Go code into low-level instructions for the target architecture. The `regInfo` is vital for register allocation during code generation.

5. **Identify Functionality Based on Operation Names:** The `name` field provides strong hints about the operation's function:
    * `MOV*atomicstore`: Atomic memory write operations.
    * `LAA`, `LAAG`, `LAN`, `LAO`: Load and arithmetic instructions (likely for address calculations or bitwise operations).
    * `LoweredAtomicCas*`, `LoweredAtomicExchange*`: Atomic compare-and-swap and exchange operations, fundamental for concurrency.
    * `FLOGR`, `POPCNT`:  Specific instructions (likely floating-point log and population count).
    * `STMG*`, `STM*`: Store multiple registers.
    * `LoweredMove`, `LoweredZero`:  Basic data movement and zeroing.
    * `LoweredStaticCall`, `LoweredTailCall`, `LoweredClosureCall`, `LoweredInterCall`: Different types of function calls.
    * `LoweredAddr`:  Taking the address of something.
    * `LoweredGetClosurePtr`, `LoweredGetCallerPC`, `LoweredGetCallerSP`: Operations related to function closures and call stack information.
    * `LoweredNilCheck`: Checking for nil pointers.
    * `LoweredWB`:  Write barrier for garbage collection.
    * `LoweredConvert`: Type conversions.
    * Operations prefixed with `I64`, `F32`, `F64` and associated with `wasm`: These are WebAssembly instructions. This confirms the code handles multiple architectures.

6. **Infer the "Go Language Feature" Implementation:**  Many of these operations map directly to Go language features:
    * Atomic operations (`atomic.Store`, `atomic.CompareAndSwap`).
    * Function calls.
    * Pointer operations.
    * Type conversions.
    * Garbage collection (write barriers).
    * Concurrency primitives.

7. **Construct Example Code:** For a concrete example, consider `MOVBatomicstore`. This likely implements `atomic.StoreByte`. Provide a simple Go example demonstrating its usage. Similarly, `LoweredAtomicCas32` and `LoweredAtomicCas64` relate to `atomic.CompareAndSwapInt32` and `atomic.CompareAndSwapInt64`.

8. **Address Command-Line Arguments:**  The provided code snippet *doesn't* directly handle command-line arguments. This is part of the compiler's internal workings. State that clearly.

9. **Identify Potential Pitfalls:** Consider common mistakes related to the features these operations implement: incorrect usage of atomic operations (e.g., not understanding memory ordering), issues with pointer arithmetic, or incorrect handling of function calls.

10. **Synthesize the Summary:** Based on the analysis, summarize the purpose of this code: defining a large set of low-level operations for the Go compiler's SSA representation, targeting multiple architectures (s390x and wasm in this snippet), and enabling the compilation of various Go language features. Emphasize that it's a machine-readable definition used by the compiler.

11. **Review and Refine:** Read through the answer to ensure clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. For instance, double-check the register bitmasks and their interpretation (although a detailed breakdown might be overly technical for the prompt). Make sure the Go code examples are correct and illustrative.

By following these steps, we can systematically analyze the code snippet and provide a comprehensive and accurate answer to the prompt. The key is to start with the context, identify the core data structures, infer the purpose of the fields, and then connect those pieces to higher-level Go concepts.
基于你提供的 Go 语言代码片段，`go/src/cmd/compile/internal/ssa/opGen.go` 文件的第 33 部分，可以归纳出以下功能：

**核心功能：定义和描述 SSA 中间表示的各种操作 (Operations)。**

这个代码片段定义了一个巨大的操作列表，每个操作都用一个结构体来描述。这些操作是 Go 编译器在将 Go 源代码转换为机器码的过程中，使用的静态单赋值 (SSA) 中间表示的关键组成部分。

具体来说，每个操作的结构体包含了以下信息：

* **`name`**: 操作的名称，例如 "MOVBatomicstore"、"LAA"、"LoweredStaticCall" 等。
* **`auxType`**: 辅助类型，通常用于携带额外的类型信息，例如 `auxSymOff` 表示符号偏移，`auxInt64` 表示 64 位整数。
* **`argLen`**: 操作的参数数量。
* **`clobberFlags`**: 布尔值，指示该操作是否会修改 CPU 的标志寄存器。
* **`faultOnNilArg0`**: 布尔值，指示当第一个参数为 nil 时是否会触发错误。
* **`hasSideEffects`**: 布尔值，指示该操作是否具有副作用，例如修改内存。
* **`symEffect`**: 枚举类型，描述操作对符号的影响，例如 `SymWrite`（写）、`SymRdWr`（读写）、`SymAddr`（取地址）。
* **`asm`**:  对应的汇编指令，例如 `s390x.AMOVB`、`wasm.AI64Add`。这表明代码片段中同时包含了针对不同架构 (例如 s390x 和 wasm) 的操作定义。
* **`reg`**:  一个 `regInfo` 结构体，描述了操作对寄存器的使用：
    * **`inputs`**:  操作的输入参数可以使用的寄存器集合。用位掩码表示，例如 `4295023614` 代表一组寄存器。
    * **`outputs`**: 操作的输出结果会存储在哪些寄存器中。
    * **`clobbers`**: 操作执行过程中会覆盖哪些寄存器的值。
* **`call`**: 布尔值，指示该操作是否是一个函数调用。
* **`tailCall`**: 布尔值，指示该操作是否是一个尾调用。
* **`nilCheck`**: 布尔值，指示该操作是否是一个空指针检查。
* **`rematerializeable`**: 布尔值，指示该操作的结果是否可以重新计算而不是必须存储。

**可以推理出的 Go 语言功能实现，并用 Go 代码举例说明：**

基于操作的名称和属性，我们可以推断出一些操作对应于特定的 Go 语言功能：

1. **原子操作 (Atomic Operations):**
   * `MOVBatomicstore`, `MOVWatomicstore`, `MOVDatomicstore`:  这些操作很明显对应于 Go 语言中 `sync/atomic` 包提供的原子存储操作，例如 `atomic.StoreInt8`, `atomic.StoreInt32`, `atomic.StoreInt64` 等。

   ```go
   package main

   import (
       "fmt"
       "sync/atomic"
   )

   func main() {
       var x int32
       atomic.StoreInt32(&x, 10)
       fmt.Println(atomic.LoadInt32(&x)) // 输出: 10
   }
   ```

   * **假设输入:**  内存地址 `&x` 和要存储的值 `10`。
   * **输出:**  将值 `10` 原子地写入内存地址 `&x`。

2. **原子比较并交换 (Atomic Compare and Swap):**
   * `LoweredAtomicCas32`, `LoweredAtomicCas64`: 对应于 `atomic.CompareAndSwapInt32` 和 `atomic.CompareAndSwapInt64`。

   ```go
   package main

   import (
       "fmt"
       "sync/atomic"
   )

   func main() {
       var x int32 = 5
       old := int32(5)
       new := int32(10)
       swapped := atomic.CompareAndSwapInt32(&x, old, new)
       fmt.Println("Swapped:", swapped, "Value of x:", atomic.LoadInt32(&x)) // 输出: Swapped: true Value of x: 10
   }
   ```

   * **假设输入:**  内存地址 `&x`，期望的旧值 `old` (5)，和新值 `new` (10)。
   * **输出:**  如果 `x` 的当前值等于 `old`，则将 `x` 的值更新为 `new` 并返回 `true`，否则返回 `false`。

3. **函数调用 (Function Calls):**
   * `LoweredStaticCall`, `LoweredTailCall`, `LoweredClosureCall`, `LoweredInterCall`:  这些操作分别对应于静态函数调用、尾调用、闭包调用和接口调用。

   ```go
   package main

   import "fmt"

   func add(a, b int) int {
       return a + b
   }

   func main() {
       result := add(3, 5) // 对应 LoweredStaticCall
       fmt.Println(result)   // 输出: 8
   }
   ```

   * **假设输入:**  函数地址 `add` 和参数 `3`, `5`。
   * **输出:**  执行函数 `add`，返回结果 `8`。

4. **地址操作 (Address Operations):**
   * `LoweredAddr`:  对应于 Go 语言中的取地址操作符 `&`。

   ```go
   package main

   import "fmt"

   func main() {
       x := 10
       ptr := &x // 对应 LoweredAddr
       fmt.Println(ptr) // 输出 x 的内存地址
   }
   ```

   * **假设输入:** 变量 `x`。
   * **输出:**  变量 `x` 的内存地址。

5. **空指针检查 (Nil Check):**
   * `LoweredNilCheck`:  对应于 Go 语言中对指针是否为 `nil` 的检查。

   ```go
   package main

   func main() {
       var p *int
       if p == nil { // 对应 LoweredNilCheck
           println("p is nil") // 输出: p is nil
       }
   }
   ```

   * **假设输入:**  指针 `p`。
   * **输出:**  如果 `p` 是 `nil`，则程序可能会执行相应的处理逻辑。

**命令行参数的具体处理：**

这个代码片段本身并不直接处理命令行参数。`opGen.go` 是 Go 编译器内部的一部分，它的作用是生成 SSA 中间表示的操作定义。命令行参数的处理通常发生在编译器的其他阶段，例如词法分析、语法分析和类型检查等。

**使用者易犯错的点：**

作为编译器开发的内部文件，普通 Go 语言开发者不会直接使用或修改 `opGen.go`。因此，不存在使用者易犯错的点。这个文件是 Go 编译器开发者维护的。

**总结 `opGen.go` 的功能：**

总而言之，`go/src/cmd/compile/internal/ssa/opGen.go` 文件的主要功能是：

* **定义 Go 编译器 SSA 中间表示所使用的所有操作。**
* **为每个操作提供详细的元数据，包括名称、参数数量、副作用、对寄存器的使用、对应的汇编指令等。**
* **作为 Go 编译器将高级 Go 代码转换为低级机器码的关键信息来源。**

第 33 部分是这个定义列表中的一部分，它延续了定义各种 SSA 操作的工作，涵盖了原子操作、函数调用、地址操作、WebAssembly 指令等。这部分与其他部分共同构成了 Go 编译器理解和生成目标代码的基础。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第33部分，共36部分，请归纳一下它的功能
```

### 源代码
```go
auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
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
		name:           "MOVWatomicstore",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
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
		name:           "MOVDatomicstore",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
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
		name:           "LAA",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ALAA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "LAAG",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ALAAG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "AddTupleFirst32",
		argLen: 2,
		reg:    regInfo{},
	},
	{
		name:   "AddTupleFirst64",
		argLen: 2,
		reg:    regInfo{},
	},
	{
		name:           "LAN",
		argLen:         3,
		clobberFlags:   true,
		hasSideEffects: true,
		asm:            s390x.ALAN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "LANfloor",
		argLen:         3,
		clobberFlags:   true,
		hasSideEffects: true,
		asm:            s390x.ALAN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2},     // R1
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 2, // R1
		},
	},
	{
		name:           "LAO",
		argLen:         3,
		clobberFlags:   true,
		hasSideEffects: true,
		asm:            s390x.ALAO,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "LAOfloor",
		argLen:         3,
		clobberFlags:   true,
		hasSideEffects: true,
		asm:            s390x.ALAO,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2},     // R1
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 2, // R1
		},
	},
	{
		name:           "LoweredAtomicCas32",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ACS,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1},     // R0
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 1, // R0
			outputs: []outputInfo{
				{1, 0},
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "LoweredAtomicCas64",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ACSG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1},     // R0
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 1, // R0
			outputs: []outputInfo{
				{1, 0},
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "LoweredAtomicExchange32",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ACS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // R0
			},
		},
	},
	{
		name:           "LoweredAtomicExchange64",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ACSG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // R0
			},
		},
	},
	{
		name:         "FLOGR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.AFLOGR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			clobbers: 2, // R1
			outputs: []outputInfo{
				{0, 1}, // R0
			},
		},
	},
	{
		name:         "POPCNT",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.APOPCNT,
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
		name:   "MLGR",
		argLen: 2,
		asm:    s390x.AMLGR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 8},     // R3
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4}, // R2
				{1, 8}, // R3
			},
		},
	},
	{
		name:   "SumBytes2",
		argLen: 1,
		reg:    regInfo{},
	},
	{
		name:   "SumBytes4",
		argLen: 1,
		reg:    regInfo{},
	},
	{
		name:   "SumBytes8",
		argLen: 1,
		reg:    regInfo{},
	},
	{
		name:           "STMG2",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STMG3",
		auxType:        auxSymOff,
		argLen:         5,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{3, 8},     // R3
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STMG4",
		auxType:        auxSymOff,
		argLen:         6,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{3, 8},     // R3
				{4, 16},    // R4
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STM2",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMY,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STM3",
		auxType:        auxSymOff,
		argLen:         5,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMY,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{3, 8},     // R3
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STM4",
		auxType:        auxSymOff,
		argLen:         6,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMY,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{3, 8},     // R3
				{4, 16},    // R4
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "LoweredMove",
		auxType:        auxInt64,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2},     // R1
				{1, 4},     // R2
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 6, // R1 R2
		},
	},
	{
		name:           "LoweredZero",
		auxType:        auxInt64,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2},     // R1
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 2, // R1
		},
	},

	{
		name:    "LoweredStaticCall",
		auxType: auxCallOff,
		argLen:  1,
		call:    true,
		reg: regInfo{
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
		},
	},
	{
		name:     "LoweredTailCall",
		auxType:  auxCallOff,
		argLen:   1,
		call:     true,
		tailCall: true,
		reg: regInfo{
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
		},
	},
	{
		name:    "LoweredClosureCall",
		auxType: auxCallOff,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
				{1, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
		},
	},
	{
		name:    "LoweredInterCall",
		auxType: auxCallOff,
		argLen:  2,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
		},
	},
	{
		name:              "LoweredAddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "LoweredMove",
		auxType: auxInt64,
		argLen:  3,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
				{1, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "LoweredZero",
		auxType: auxInt64,
		argLen:  2,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "LoweredGetClosurePtr",
		argLen: 0,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
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
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "LoweredWB",
		auxType: auxInt64,
		argLen:  1,
		reg: regInfo{
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "LoweredConvert",
		argLen: 2,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "Select",
		argLen: 3,
		asm:    wasm.ASelect,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{2, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load8U",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load8U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load8S",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load8S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load16U",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load16U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load16S",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load16S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load32U",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load32U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load32S",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load32S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Store8",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AI64Store8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281474976776191},  // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "I64Store16",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AI64Store16,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281474976776191},  // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "I64Store32",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AI64Store32,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281474976776191},  // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "I64Store",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AI64Store,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281474976776191},  // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "F32Load",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AF32Load,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:    "F64Load",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AF64Load,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:    "F32Store",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AF32Store,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 4294901760},       // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "F64Store",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AF64Store,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281470681743360},  // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:              "I64Const",
		auxType:           auxInt64,
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:              "F32Const",
		auxType:           auxFloat32,
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:              "F64Const",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "I64Eqz",
		argLen: 1,
		asm:    wasm.AI64Eqz,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Eq",
		argLen: 2,
		asm:    wasm.AI64Eq,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Ne",
		argLen: 2,
		asm:    wasm.AI64Ne,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64LtS",
		argLen: 2,
		asm:    wasm.AI64LtS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64LtU",
		argLen: 2,
		asm:    wasm.AI64LtU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64GtS",
		argLen: 2,
		asm:    wasm.AI64GtS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64GtU",
		argLen: 2,
		asm:    wasm.AI64GtU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64LeS",
		argLen: 2,
		asm:    wasm.AI64LeS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64LeU",
		argLen: 2,
		asm:    wasm.AI64LeU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64GeS",
		argLen: 2,
		asm:    wasm.AI64GeS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64GeU",
		argLen: 2,
		asm:    wasm.AI64GeU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Eq",
		argLen: 2,
		asm:    wasm.AF32Eq,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Ne",
		argLen: 2,
		asm:    wasm.AF32Ne,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Lt",
		argLen: 2,
		asm:    wasm.AF32Lt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Gt",
		argLen: 2,
		asm:    wasm.AF32Gt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Le",
		argLen: 2,
		asm:    wasm.AF32Le,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Ge",
		argLen: 2,
		asm:    wasm.AF32Ge,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Eq",
		argLen: 2,
		asm:    wasm.AF64Eq,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Ne",
		argLen: 2,
		asm:    wasm.AF64Ne,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Lt",
		argLen: 2,
		asm:    wasm.AF64Lt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Gt",
		argLen: 2,
		asm:    wasm.AF64Gt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Le",
		argLen: 2,
		asm:    wasm.AF64Le,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Ge",
		argLen: 2,
		asm:    wasm.AF64Ge,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Add",
		argLen: 2,
		asm:    wasm.AI64Add,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64AddConst",
		auxType: auxInt64,
		argLen:  1,
		asm:     wasm.AI64Add,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Sub",
		argLen: 2,
		asm:    wasm.AI64Sub,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Mul",
		argLen: 2,
		asm:    wasm.AI64Mul,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64DivS",
		argLen: 2,
		asm:    wasm.AI64DivS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64DivU",
		argLen: 2,
		asm:    wasm.AI64DivU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64RemS",
		argLen: 2,
		asm:    wasm.AI64RemS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64RemU",
		argLen: 2,
		asm:    wasm.AI64RemU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64And",
		argLen: 2,
		asm:    wasm.AI64And,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Or",
		argLen: 2,
		asm:    wasm.AI64Or,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Xor",
		argLen: 2,
		asm:    wasm.AI64Xor,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13
```