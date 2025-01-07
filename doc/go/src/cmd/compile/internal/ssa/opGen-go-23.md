Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze a snippet of Go code (`opGen.go`) and explain its function, particularly focusing on a section defining data structures. The request emphasizes inferring Go functionality, providing examples, and summarizing the specific provided excerpt.

2. **Identify the Key Data Structure:** The provided code defines a slice of structs. Each struct appears to describe an operation (op) within the Go compiler's intermediate representation (SSA - Static Single Assignment). The fields within each struct are clues to the characteristics of each operation.

3. **Analyze the Struct Fields:**  I examine the fields in the structs to understand their purpose:

    * `name`:  Clearly the name of the operation (e.g., "MOVWload", "ADD").
    * `auxType`:  Suggests an auxiliary type, likely providing additional information about the operation's operands or behavior. `auxSymOff` and `auxInt64` are examples.
    * `argLen`: The number of arguments the operation takes.
    * `faultOnNilArg0`, `faultOnNilArg1`: Indicates if the operation will fault if a specific argument is nil. This points to memory access operations.
    * `symEffect`: Describes the effect on symbols (e.g., `SymRead`, `SymWrite`), hinting at memory load/store operations.
    * `asm`: The assembly instruction corresponding to the operation (e.g., `mips.AMOVWU`, `mips.AMOVV`). This confirms the code is architecture-specific (MIPS in this case). The presence of `ppc64.AADD` later suggests it might contain definitions for multiple architectures or there's an error in the provided excerpt. *Self-correction:  Likely defines operations common to multiple architectures but with architecture-specific assembly*.
    * `reg`: A nested `regInfo` struct likely describes register usage.
    * `regInfo`:
        * `inputs`:  Information about the input registers. The bitmasks (`4611686018695823358`, etc.) likely represent sets of allowed input registers.
        * `outputs`: Information about the output registers, also using bitmasks.
        * `clobbers`: Registers that the operation might modify, even if not direct outputs.
    * `commutative`: Indicates if the order of operands doesn't matter for the operation.
    * `resultInArg0`, `resultNotInArgs`:  Indicates where the result of the operation is placed.
    * `clobberFlags`:  Indicates if the operation modifies processor flags (like the condition code register).
    * `call`, `tailCall`:  Marks operations that represent function calls.
    * `zeroWidth`:  Indicates an operation that doesn't produce a value.
    * `rematerializeable`: Suggests the operation's result can be recomputed if needed.
    * `hasSideEffects`: Indicates the operation has effects beyond producing a result.
    * `unsafePoint`:  Marks operations that can potentially cause a garbage collection.
    * `nilCheck`: Indicates an operation that explicitly checks for nil pointers.

4. **Infer Go Functionality:** Based on the analyzed fields, I can infer the following:

    * **Memory Access (Loads and Stores):**  Operations like `MOVWload`, `MOVVload`, `MOVBstore`, etc., along with `faultOnNilArg0` and `symEffect`, clearly represent loading and storing data from memory.
    * **Register Moves:**  Operations like `MOVBreg`, `MOVWreg`, `MOVVreg` suggest moving data between registers. The `fpgp` and `gpfp` suffixes indicate moves between floating-point and general-purpose registers.
    * **Arithmetic Operations:**  The presence of `ADD` suggests arithmetic operations.
    * **Function Calls:** `CALLstatic`, `CALLclosure`, `CALLinter`, `CALLtail` represent different types of function calls.
    * **Atomic Operations:** Operations prefixed with "LoweredAtomic" indicate atomic operations for concurrent programming.
    * **Conversions:** Operations like `TRUNCFW`, `TRUNCDW`, `MOVFD`, `MOVDF` suggest type conversions.
    * **Specialized Operations:**  `DUFFZERO` and `DUFFCOPY` likely relate to optimized memory zeroing/copying routines. `LoweredNilCheck` is an explicit nil check.
    * **Panic/Bounds Checks:** `LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC` are related to runtime error handling for array/slice bounds.

5. **Provide Go Code Examples:** I select representative operations and construct simple Go code snippets that would likely generate these SSA operations during compilation. I make assumptions about variable types to match the operation names (e.g., `int32` for `MOVW`, `int64` for `MOVV`, `float32` for `MOVF`, `float64` for `MOVD`).

6. **Address Specific Requests:**

    * **Command-line arguments:**  This specific code snippet doesn't directly handle command-line arguments. I note this.
    * **User errors:** I consider potential errors. For example, misunderstanding register constraints could lead to incorrect code generation if this were manually manipulated (which it isn't in normal Go usage). Nil pointer dereferences related to the `faultOnNilArg` flags are also a key point.
    * **Part Summary:** I summarize the function of the provided code snippet as defining a set of low-level operations used in the Go compiler's SSA intermediate representation, particularly for the MIPS architecture (and potentially others). This involves describing the operations' names, arguments, effects, and register usage.

7. **Refine and Organize:**  I structure the answer logically, using headings and bullet points for clarity. I ensure the Go code examples are syntactically correct and easy to understand. I double-check the terminology and explanations for accuracy. The mention of MIPS architecture is crucial and needs to be highlighted. The later appearance of `ppc64` instructions suggests either a multi-architecture context or a copy/paste error within the original data. I should acknowledge this discrepancy.
这段代码是Go语言编译器的一部分，具体来说，它位于 `go/src/cmd/compile/internal/ssa/opGen.go` 文件中，负责定义和描述 **SSA (Static Single Assignment) 中间表示的操作 (Operations)**。

**功能概括:**

这个代码片段定义了一个非常大的 **操作码 (opcode) 列表**，每个操作码都用一个结构体来描述。这些结构体包含了关于该操作的各种元信息，例如：

* **`name`**: 操作的名称，例如 "MOVWload" (Load Word), "ADD" (加法)。
* **`auxType`**:  辅助信息的类型，例如 `auxSymOff` (符号偏移), `auxInt64` (64位整数)。这用于携带操作的额外信息，比如内存访问的偏移量，或者常量的值。
* **`argLen`**: 操作所需的参数数量。
* **`faultOnNilArg0` / `faultOnNilArg1`**:  布尔值，指示如果第一个或第二个参数是 `nil` 时，该操作是否会引发错误 (通常用于内存访问操作)。
* **`symEffect`**:  该操作对符号 (symbol) 的影响，例如 `SymRead` (读取符号的值), `SymWrite` (写入符号的值)。
* **`asm`**:  与该 SSA 操作对应的 **汇编指令** (assembly instruction)，例如 `mips.AMOVWU` (MIPS架构的移动字指令)。这表明这段代码是特定于 **MIPS 架构** 的（至少大部分是，后面出现 `ppc64` 的指令需要注意）。
* **`reg`**: 一个 `regInfo` 结构体，描述了该操作对 **寄存器** 的使用情况，包括输入寄存器和输出寄存器。
    * **`inputs`**:  一个 `inputInfo` 切片，描述了输入参数所需的寄存器。每个 `inputInfo` 包含参数索引和允许使用的寄存器位掩码。例如，`{0, 4611686018695823358}` 表示第一个参数可以使用位掩码 `4611686018695823358` 所代表的寄存器。
    * **`outputs`**: 一个 `outputInfo` 切片，描述了输出结果所在的寄存器。结构类似 `inputs`。
    * **`clobbers`**:  一个位掩码，表示该操作会覆盖 (clobber) 的寄存器。
* **`commutative`**: 布尔值，指示该操作是否满足交换律 (例如加法)。
* **`resultInArg0`**: 布尔值，指示操作的结果是否直接存放在第一个参数的位置。
* **`clobberFlags`**: 布尔值，指示该操作是否会修改 CPU 的标志寄存器 (例如，用于条件跳转)。
* **`call`**: 布尔值，指示该操作是否是一个函数调用。
* **`tailCall`**: 布尔值，指示该操作是否是一个尾调用。
* **`zeroWidth`**: 布尔值，指示该操作是否不产生任何值 (例如，某些控制流操作)。
* **`rematerializeable`**: 布尔值，指示该操作的结果是否可以重新计算，而不是必须存储。
* **`hasSideEffects`**: 布尔值，指示该操作除了产生结果外，是否还有其他副作用。
* **`unsafePoint`**: 布尔值，指示该操作是否是一个“不安全点”，可能会导致垃圾回收。
* **`nilCheck`**: 布尔值，指示该操作是否执行了空指针检查。

**推理 Go 语言功能实现:**

这段代码是 Go 编译器将 Go 源代码转换为机器码过程中的一个关键环节。它定义了编译器内部使用的中间表示操作。这些操作比 Go 语言的高级语法更接近机器指令，但仍然是抽象的。

我们可以推断出它正在实现以下 Go 语言功能：

1. **基本数据类型的加载和存储:**  例如 `MOVBload`, `MOVHload`, `MOVWload`, `MOVVload`, `MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVVstore`  对应着 Go 语言中对 `byte`, `int16`, `int32`, `int64` (或者它们的无符号版本) 等基本类型进行读写内存的操作。

   ```go
   package main

   func main() {
       var x int32
       y := x // 可能会生成 MOVWload 操作
       z := 10
       x = z  // 可能会生成 MOVWstore 操作
   }
   ```
   **假设输入:**  编译器接收到上述 Go 代码。
   **输出 (推测的 SSA):**  编译器内部会将 `y := x` 转换为类似 `y = MOVWload(addr_of_x)` 的 SSA 指令。

2. **浮点数的加载和存储:** `MOVFload`, `MOVDload`, `MOVFstore`, `MOVDstore` 对应 `float32` 和 `float64` 类型的内存读写。

   ```go
   package main

   func main() {
       var f float32
       g := f // 可能会生成 MOVFload 操作
       h := 3.14
       f = float32(h) // 可能会生成 MOVFstore 操作
   }
   ```

3. **寄存器之间的移动:** `MOVBreg`, `MOVBUreg`, `MOVHreg`, `MOVHUreg`, `MOVWreg`, `MOVWUreg`, `MOVVreg`  对应在寄存器之间移动不同大小的数据。

   ```go
   package main

   func add(a int32) int32 {
       b := a // 可能会生成 MOVWreg 操作
       return b + 1
   }
   ```

4. **函数调用:** `CALLstatic`, `CALLclosure`, `CALLinter`, `CALLtail` 对应不同类型的函数调用。

   ```go
   package main

   import "fmt"

   func hello() {
       fmt.Println("Hello") // 可能会生成 CALLstatic 操作
   }

   func main() {
       hello()
   }
   ```

5. **原子操作:** `LoweredAtomicAnd32`, `LoweredAtomicOr32`, `LoweredAtomicLoad32` 等对应 `sync/atomic` 包提供的原子操作。

   ```go
   package main

   import "sync/atomic"

   func main() {
       var count int32
       atomic.AddInt32(&count, 1) // 可能会生成 LoweredAtomicAdd32 操作
   }
   ```

6. **类型转换:** `MOVWfpgp`, `MOVWgpfp`, `MOVVfpgp`, `MOVVgpfp`, `TRUNCFW`, `TRUNCDW`, `MOVFD`, `MOVDF`  对应不同类型之间的转换，例如浮点数和整数之间的转换。

   ```go
   package main

   func main() {
       var f float32 = 10.5
       i := int32(f) // 可能会生成 TRUNCFW 操作
       var d float64 = float64(i) // 可能会生成 MOVWF 或 MOVWD 操作，取决于目标类型的大小
   }
   ```

7. **内存清零和拷贝 (Duff's Device):** `DUFFZERO`, `DUFFCOPY`  是编译器优化的内存操作，可能用于 `make([]byte, n)` 或 `copy()` 等场景。

   ```go
   package main

   func main() {
       s := make([]byte, 100) // 可能会使用 DUFFZERO 初始化
       t := make([]byte, 100)
       copy(t, s) // 可能会使用 DUFFCOPY 进行拷贝
   }
   ```

8. **边界检查:** `LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC` 对应数组或切片的越界访问检查。

   ```go
   package main

   func main() {
       arr := [5]int{1, 2, 3, 4, 5}
       _ = arr[10] // 可能会触发 LoweredPanicBounds 操作
   }
   ```

**命令行参数的具体处理:**

这段代码本身 **不直接** 处理命令行参数。 `opGen.go` 的作用是生成 SSA 操作码的定义。命令行参数的处理发生在编译器的其他阶段，例如词法分析、语法分析和类型检查等。

**使用者易犯错的点:**

作为编译器开发者，理解这些操作码的含义和约束至关重要。对于普通的 Go 开发者来说，并不需要直接接触这些底层的 SSA 操作。  然而，理解编译器的工作原理可以帮助开发者写出更高效的代码。

**功能归纳 (针对提供的第 24 部分):**

这部分代码主要定义了 **内存加载、存储、寄存器移动、浮点数操作、类型转换以及一些特殊的内存操作 (如 Duff's Device)** 的 SSA 操作码。 这些操作码是 MIPS 架构下，编译器将高级 Go 代码转换为低级指令的关键中间步骤。 此外，它还包含了函数调用和原子操作的定义。 值得注意的是，代码中开始出现 `ppc64` 的汇编指令 (`ppc64.AADD`)，这可能意味着该文件包含了针对多种架构的操作定义，或者在提供的代码片段中存在混淆。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第24部分，共36部分，请归纳一下它的功能

"""
       2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVVload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVFload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVHstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVVstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVFstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVBstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVHstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVWstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVVstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:   "MOVWfpgp",
		argLen: 1,
		asm:    mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVWgpfp",
		argLen: 1,
		asm:    mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVfpgp",
		argLen: 1,
		asm:    mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVVgpfp",
		argLen: 1,
		asm:    mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVBreg",
		argLen: 1,
		asm:    mips.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVBUreg",
		argLen: 1,
		asm:    mips.AMOVBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVHreg",
		argLen: 1,
		asm:    mips.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVHUreg",
		argLen: 1,
		asm:    mips.AMOVHU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVWreg",
		argLen: 1,
		asm:    mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVWUreg",
		argLen: 1,
		asm:    mips.AMOVWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVVreg",
		argLen: 1,
		asm:    mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:         "MOVVnop",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVWF",
		argLen: 1,
		asm:    mips.AMOVWF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVWD",
		argLen: 1,
		asm:    mips.AMOVWD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVF",
		argLen: 1,
		asm:    mips.AMOVVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVD",
		argLen: 1,
		asm:    mips.AMOVVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCFW",
		argLen: 1,
		asm:    mips.ATRUNCFW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCDW",
		argLen: 1,
		asm:    mips.ATRUNCDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCFV",
		argLen: 1,
		asm:    mips.ATRUNCFV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCDV",
		argLen: 1,
		asm:    mips.ATRUNCDV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVFD",
		argLen: 1,
		asm:    mips.AMOVFD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVDF",
		argLen: 1,
		asm:    mips.AMOVDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
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
			clobbers: 4611686018393833470, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
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
			clobbers: 4611686018393833470, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
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
				{1, 4194304},   // R22
				{0, 201326590}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP R31
			},
			clobbers: 4611686018393833470, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
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
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			clobbers: 4611686018393833470, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
		},
	},
	{
		name:           "DUFFZERO",
		auxType:        auxInt64,
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			clobbers: 134217730, // R1 R31
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
				{0, 4}, // R2
				{1, 2}, // R1
			},
			clobbers: 134217734, // R1 R2 R31
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
				{0, 2},         // R1
				{1, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			clobbers: 2, // R1
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
				{0, 4},         // R2
				{1, 2},         // R1
				{2, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			clobbers: 6, // R1 R2
		},
	},
	{
		name:           "LoweredAtomicAnd32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		unsafePoint:    true,
		asm:            mips.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicOr32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		unsafePoint:    true,
		asm:            mips.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicLoad8",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "LoweredAtomicLoad32",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "LoweredAtomicLoad64",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
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
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
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
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
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
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStorezero32",
		argLen:         2,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStorezero64",
		argLen:         2,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:            "LoweredAtomicExchange32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicExchange64",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAdd32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAdd64",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAddconst32",
		auxType:         auxInt32,
		argLen:          2,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAddconst64",
		auxType:         auxInt64,
		argLen:          2,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
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
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{2, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
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
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{2, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
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
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
		},
	},
	{
		name:   "FPFlagTrue",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "FPFlagFalse",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4194304}, // R22
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 4611686018293170176, // R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
			outputs: []outputInfo{
				{0, 16777216}, // R25
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
				{0, 8},  // R3
				{1, 16}, // R4
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
				{0, 4}, // R2
				{1, 8}, // R3
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
				{0, 2}, // R1
				{1, 4}, // R2
			},
		},
	},

	{
		name:        "ADD",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AADD,
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
		name:        "ADDCC",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AADDCC,
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
		name:    "ADDconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.AADD,
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
		name:    "ADDCCconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.AADDCCC,
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
		name:        "FADD",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AFADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F
"""




```