Response:
The user wants to understand the functionality of the provided Go code snippet. This code seems to define a series of operations (`op`) used in the SSA (Static Single Assignment) intermediate representation of the Go compiler. Each `op` has attributes like `name`, `argLen` (number of arguments), `asm` (assembly instruction, likely for a WASM target based on the `wasm.` prefix), and `reg` (register constraints).

I need to:
1. **List the functionalities** implemented by the operations defined in the code. These are essentially different kinds of computations and manipulations of data.
2. **Infer the Go language features** these operations relate to. This will involve mapping the operations to common Go constructs like arithmetic, bit manipulation, floating-point operations, etc.
3. **Provide Go code examples** to illustrate these features. These examples should be simple and directly relate to the identified operations. I'll need to make assumptions about the input and show the expected output.
4. **Explain any command-line parameters** if the operations are directly tied to compiler flags or command-line arguments. Based on the snippet alone, there aren't explicit command-line parameters, but the *existence* of these operations is influenced by the target architecture (WASM in this case).
5. **Point out common mistakes** users might make when using these features. This requires understanding the semantics of each operation.
6. **Summarize the overall function** of this specific part of the `opGen.go` file. It's about defining the set of available operations for a specific target architecture within the SSA framework.

**Mental Sandbox:**

* **Operation Grouping:** I can group the operations based on their functionality: integer arithmetic, bitwise operations, floating-point arithmetic, type conversions, etc. This will help in explaining the Go language features.
* **WASM Connection:** The `asm` field strongly suggests these operations are for compiling Go to WebAssembly. I need to keep this context in mind.
* **Register Constraints:** The `regInfo` structure seems to define which registers can be used for inputs and outputs of each operation. This is important for the compiler's register allocation phase but might not be directly user-facing.
* **Generic Operations:** Some operations have `generic: true`, indicating they are not specific to the WASM backend and are part of the general SSA representation.

**Example Construction:**

For an operation like `I64Add`, I can create a simple Go function that performs 64-bit integer addition:

```go
package main

import "fmt"

func main() {
	a := int64(10)
	b := int64(20)
	result := a + b
	fmt.Println(result) // Output: 30
}
```

For `F32Neg`, I'll show negating a float32:

```go
package main

import "fmt"

func main() {
	f := float32(3.14)
	negF := -f
	fmt.Println(negF) // Output: -3.14
}
```

**Summarization:**

The core function of this code snippet is to define the set of low-level operations that the Go compiler can use when translating Go code into WebAssembly. This involves specifying the name of the operation, its arguments, the corresponding WASM instruction, and constraints on which registers can be used.

**Confidence Checklist:**

* List functionalities? Yes.
* Infer Go language features? Yes.
* Go code examples? Yes.
* Handle code reasoning? Yes (through example generation).
* Address command-line parameters?  No direct parameters, but will mention the target architecture influence.
* Identify user mistakes?  Will focus on the semantics of the operations.
* Use Chinese? Yes.
* Part of a larger sequence? Acknowledge that.
* Summarize the function? Yes.
这段代码是Go语言编译器 `cmd/compile/internal/ssa` 包中 `opGen.go` 文件的一部分，它定义了一系列的**SSA (Static Single Assignment) 中间表示的操作 (operations)**。这些操作是编译器在将Go源代码转换为机器码的过程中使用的抽象指令。

**它的主要功能是：**

1. **定义了针对特定架构（很可能是 WebAssembly - WASM，因为 `asm` 字段引用了 `wasm` 包）的底层操作。**  每个操作都有一个名称 (`name`)，需要的参数个数 (`argLen`)，以及对应的 WebAssembly 汇编指令 (`asm`)。
2. **描述了每个操作的寄存器约束 (`reg`)。** 这部分信息指定了哪些寄存器可以作为操作的输入和输出。`inputInfo` 描述了输入参数可以位于哪些寄存器，`outputInfo` 描述了输出结果会放在哪个寄存器。  这些信息对于编译器的寄存器分配阶段至关重要。
3. **定义了一些通用的、不依赖于特定架构的操作 (带有 `generic: true`)。** 这些操作代表了更高级别的概念，例如加法、减法、比较等等，可以在不同的目标架构上使用。

**可以推理出它是什么Go语言功能的实现：**

这段代码定义的操作涵盖了Go语言中常见的各种运算和数据类型操作，例如：

* **整数运算:** 加法 (`I64Add`), 减法, 乘法, 除法, 取模, 位运算 (左移 `I64Shl`, 右移 `I64ShrS`, `I64ShrU`, 与, 或, 异或), 旋转 (`I32Rotl`, `I64Rotl`), 计数前导零 (`I64Clz`), 计数尾部零 (`I64Ctz`), 统计置位数 (`I64Popcnt`) 等。
* **浮点数运算:** 加法 (`F32Add`, `F64Add`), 减法, 乘法, 除法, 取负 (`F32Neg`, `F64Neg`), 开方 (`F32Sqrt`, `F64Sqrt`),  类型转换 (`F32ConvertI64S`, `F64ConvertI64U`, `I64TruncSatF64S`),  取整 (`F32Trunc`, `F32Ceil`, `F32Floor`, `F32Nearest`), 绝对值 (`F32Abs`, `F64Abs`), 符号复制 (`F32Copysign`, `F64Copysign`) 等。
* **类型转换:**  整数和浮点数之间的转换。
* **比较运算:**  虽然这段代码没有明确列出比较操作的 WASM 指令，但后续的通用操作中包含了 `Eq8`, `Neq32`, `Less64` 等，说明 SSA 中有比较操作。
* **逻辑运算:**  与 (`AndB`), 或 (`OrB`), 非 (`Not`)。
* **位操作:**  移位，按位与、或、异或，取反。

**Go代码举例说明:**

例如，`I64Shl` 操作对应Go语言中的左移位运算 `<<`：

```go
package main

import "fmt"

func main() {
	var a int64 = 5 // 二进制: 0...0101
	var b uint = 2
	result := a << b
	fmt.Printf("将 %d 左移 %d 位得到: %d (二进制: %b)\n", a, b, result, result)
}
```

**假设的输入与输出：**

输入： `a = 5`, `b = 2`
输出： `将 5 左移 2 位得到: 20 (二进制: 10100)`

再例如， `F32Add` 操作对应Go语言中的 `float32` 类型的加法：

```go
package main

import "fmt"

func main() {
	var f1 float32 = 1.5
	var f2 float32 = 2.7
	sum := f1 + f2
	fmt.Printf("浮点数 %f 和 %f 的和是: %f\n", f1, f2, sum)
}
```

**假设的输入与输出：**

输入： `f1 = 1.5`, `f2 = 2.7`
输出： `浮点数 1.500000 和 2.700000 的和是: 4.200000`

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它定义的是编译过程中的中间表示。然而，Go编译器的命令行参数，例如 `-gcflags` 可以影响最终生成的代码，并可能间接影响到 SSA 的生成和优化，从而影响到这些操作的使用。 例如，选择不同的目标架构会使用不同的 `opGen.go` 文件或者其中的不同部分。

**使用者易犯错的点:**

由于这段代码是编译器内部的表示，普通 Go 开发者不会直接使用或操作这些 `op`。 易犯错的点更多体现在理解这些操作背后的 Go 语言行为：

* **整数溢出:**  例如，`I64Add` 在 Go 中如果发生溢出，会发生回绕，而不是抛出错误。开发者需要理解这种行为。
* **浮点数精度:** 浮点数运算存在精度问题，例如 `F32Add` 的结果可能不是精确的数学和。
* **有符号和无符号数的移位:**  `I64ShrS` 是有符号右移，`I64ShrU` 是无符号右移，行为不同。Go 开发者需要根据需求选择正确的移位操作。
* **类型转换的截断和饱和:**  例如 `I64TruncSatF64S` 是将 `float64` 截断为 `int64`，如果超出 `int64` 的范围会饱和到最大或最小值。 理解这种行为很重要。

**总结一下它的功能 (第34部分，共36部分):**

作为 `opGen.go` 文件的一部分，这段代码具体定义了一系列用于将 Go 代码编译到 WebAssembly 平台的 SSA 操作。 它详细描述了这些操作的名称、参数数量、对应的 WebAssembly 汇编指令以及寄存器使用约束。 这部分内容是 Go 编译器将高级 Go 代码转化为特定目标平台机器码的关键步骤，确保了编译器能够正确地进行底层的代码生成和优化。  考虑到这是 36 部分中的第 34 部分，可以推断出 `opGen.go` 的剩余部分可能包含更多操作的定义，或者是一些辅助函数和数据结构，用于管理和使用这些操作定义。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第34部分，共36部分，请归纳一下它的功能

"""
 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Shl",
		argLen: 2,
		asm:    wasm.AI64Shl,
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
		name:   "I64ShrS",
		argLen: 2,
		asm:    wasm.AI64ShrS,
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
		name:   "I64ShrU",
		argLen: 2,
		asm:    wasm.AI64ShrU,
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
		name:   "F32Neg",
		argLen: 1,
		asm:    wasm.AF32Neg,
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
		name:   "F32Add",
		argLen: 2,
		asm:    wasm.AF32Add,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F32Sub",
		argLen: 2,
		asm:    wasm.AF32Sub,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F32Mul",
		argLen: 2,
		asm:    wasm.AF32Mul,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F32Div",
		argLen: 2,
		asm:    wasm.AF32Div,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F64Neg",
		argLen: 1,
		asm:    wasm.AF64Neg,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Add",
		argLen: 2,
		asm:    wasm.AF64Add,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Sub",
		argLen: 2,
		asm:    wasm.AF64Sub,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Mul",
		argLen: 2,
		asm:    wasm.AF64Mul,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Div",
		argLen: 2,
		asm:    wasm.AF64Div,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "I64TruncSatF64S",
		argLen: 1,
		asm:    wasm.AI64TruncSatF64S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64TruncSatF64U",
		argLen: 1,
		asm:    wasm.AI64TruncSatF64U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64TruncSatF32S",
		argLen: 1,
		asm:    wasm.AI64TruncSatF32S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64TruncSatF32U",
		argLen: 1,
		asm:    wasm.AI64TruncSatF32U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32ConvertI64S",
		argLen: 1,
		asm:    wasm.AF32ConvertI64S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F32ConvertI64U",
		argLen: 1,
		asm:    wasm.AF32ConvertI64U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F64ConvertI64S",
		argLen: 1,
		asm:    wasm.AF64ConvertI64S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64ConvertI64U",
		argLen: 1,
		asm:    wasm.AF64ConvertI64U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F32DemoteF64",
		argLen: 1,
		asm:    wasm.AF32DemoteF64,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F64PromoteF32",
		argLen: 1,
		asm:    wasm.AF64PromoteF32,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "I64Extend8S",
		argLen: 1,
		asm:    wasm.AI64Extend8S,
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
		name:   "I64Extend16S",
		argLen: 1,
		asm:    wasm.AI64Extend16S,
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
		name:   "I64Extend32S",
		argLen: 1,
		asm:    wasm.AI64Extend32S,
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
		name:   "F32Sqrt",
		argLen: 1,
		asm:    wasm.AF32Sqrt,
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
		name:   "F32Trunc",
		argLen: 1,
		asm:    wasm.AF32Trunc,
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
		name:   "F32Ceil",
		argLen: 1,
		asm:    wasm.AF32Ceil,
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
		name:   "F32Floor",
		argLen: 1,
		asm:    wasm.AF32Floor,
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
		name:   "F32Nearest",
		argLen: 1,
		asm:    wasm.AF32Nearest,
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
		name:   "F32Abs",
		argLen: 1,
		asm:    wasm.AF32Abs,
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
		name:   "F32Copysign",
		argLen: 2,
		asm:    wasm.AF32Copysign,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F64Sqrt",
		argLen: 1,
		asm:    wasm.AF64Sqrt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Trunc",
		argLen: 1,
		asm:    wasm.AF64Trunc,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Ceil",
		argLen: 1,
		asm:    wasm.AF64Ceil,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Floor",
		argLen: 1,
		asm:    wasm.AF64Floor,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Nearest",
		argLen: 1,
		asm:    wasm.AF64Nearest,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Abs",
		argLen: 1,
		asm:    wasm.AF64Abs,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Copysign",
		argLen: 2,
		asm:    wasm.AF64Copysign,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "I64Ctz",
		argLen: 1,
		asm:    wasm.AI64Ctz,
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
		name:   "I64Clz",
		argLen: 1,
		asm:    wasm.AI64Clz,
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
		name:   "I32Rotl",
		argLen: 2,
		asm:    wasm.AI32Rotl,
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
		name:   "I64Rotl",
		argLen: 2,
		asm:    wasm.AI64Rotl,
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
		name:   "I64Popcnt",
		argLen: 1,
		asm:    wasm.AI64Popcnt,
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
		name:        "Add8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Add16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Add32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Add64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "AddPtr",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Add32F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Add64F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Sub8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub16",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "SubPtr",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub64F",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Mul8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul32F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul64F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Div32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div64F",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Hmul32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Hmul32u",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Hmul64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Hmul64u",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul32uhilo",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul64uhilo",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul32uover",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul64uover",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Avg32u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Avg64u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div8u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div16u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div32u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div64u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div128u",
		argLen:  3,
		generic: true,
	},
	{
		name:    "Mod8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod8u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod16u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod32u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod64u",
		argLen:  2,
		generic: true,
	},
	{
		name:        "And8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "And16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "And32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "And64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Or8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Or16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Or32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Or64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Xor8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Xor16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Xor32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Xor64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Lsh8x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh8x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh8x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh8x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh16x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh16x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh16x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh16x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh32x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh32x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh32x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh32x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh64x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh64x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh64x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh64x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8Ux8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8Ux16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8Ux32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8Ux64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16Ux8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16Ux16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16Ux32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16Ux64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32Ux8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32Ux16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32Ux32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32Ux64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64Ux8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64Ux16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64Ux32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64Ux64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:        "Eq8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Eq16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Eq32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Eq64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "EqPtr",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "EqInter",
		argLen:  2,
		generic: true,
	},
	{
		name:    "EqSlice",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Eq32F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Eq64F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "NeqPtr",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "NeqInter",
		argLen:  2,
		generic: true,
	},
	{
		name:    "NeqSlice",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Neq32F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq64F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Less8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less8U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less16",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less16U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less32U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less64U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less64F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq8U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq16",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq16U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq32U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq64U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq64F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "CondSelect",
		argLen:  3,
		generic: true,
	},
	{
		name:        "AndB",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "OrB",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "EqB",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "NeqB",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Not",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg32F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg64F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Com8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Com16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Com32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Com64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz64On32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Ctz8NonZero",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz16NonZero",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz32NonZero",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz64NonZero",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitLen8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitLen16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitLen32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitLen64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Bswap16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Bswap32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Bswap64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitRev8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitRev16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitRev32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitRev64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "PopCount8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "PopCount16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "PopCount32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "PopCount64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "RotateLeft64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "RotateLeft32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "RotateLeft16",
		argLen:  2,
		generic: true,
	},
	{
		name:    "RotateLeft8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sqrt",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Sqrt32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Floor",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ceil",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Trunc",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Round",
		argLen:  1,
		generic: true,
	},
	{
		name:    "RoundToEven",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Abs",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Copysign",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Min64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Max64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Min64u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Max64u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Min64F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Min32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Max64F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Max32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "FMA",
		argLen:  3,
		generic: true,
	},
	{
		name:      "Phi",
		argLen:    -1,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:    "Copy",
		argLen:  1,
		generic: true,
	},
	{
		name:         "Convert",
		argLen:       2,
		resultInArg0: true,
		zeroWidth:    true,
		generic:      true,
	},
	{
		name:    "ConstBool",
		auxType: auxBool,
		argLen:  0,
		generic: true,
	},
	{
		name:    "ConstString",
		auxType: auxString,
		argLen:  0,
		generic: true,
	},
	{
		name:    "ConstNil",
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const8",
		auxType: auxInt8,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const16",
		auxType: auxInt16,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const32",
		auxType: auxInt32,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const64",
		auxType: auxInt64,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const32F",
		auxType: auxFloat32,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const64F",
		auxType: auxFloat64,
		argLen:  0,
		generic: true,
	},
	{
		name:    "ConstInterface",
		argLen:  0,
		generic: true,
	},
	{
		name:    "ConstSlice",
		argLen:  0,
		generic: true,
	},
	{
		name:      "InitMem",
		argLen:    0,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:      "Arg",
		auxType:   auxSymOff,
		argLen:    0,
		zeroWidth: true,
		symEffect: SymRead,
		generic:   true,
	},
	{
		name:      "ArgIntReg",
		auxType:   auxNameOffsetInt8,
		argLen:    0,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:      "ArgFloatReg",
		auxType:   auxNameOffsetInt8,
		argLen:    0,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:      "Addr",
		auxType:   auxSym,
		argLen:    1,
		symEffect: SymAddr,
		generic:   true,
	},
	{
		name:      "LocalAddr",
		auxType:   auxSym,
		argLen:    2,
		symEffect: SymAddr,
		generic:   true,
	},
	{
		name:      "SP",
		argLen:    0,
		zeroWidth: true,
		generic: 
"""




```