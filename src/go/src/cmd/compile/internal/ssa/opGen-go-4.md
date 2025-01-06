Response: The user wants to understand the functionality of a Go code snippet from `go/src/cmd/compile/internal/ssa/opGen.go`. This file seems to define a large data structure likely used to generate or represent intermediate representation operations for the Go compiler, specifically for the x86 architecture.

Here's a breakdown of the thinking process:

1. **Identify the core data structure:** The provided code is a large slice of structs. Each struct represents an operation.

2. **Analyze the struct fields:**  The fields like `name`, `argLen`, `asm`, `reg`, `auxType`, etc., strongly suggest that this data structure describes the properties of different assembly-level instructions or intermediate representation operations.

3. **Infer the purpose:** Given the context of the file path (`cmd/compile/internal/ssa`), the purpose is likely to define the mapping between high-level Go operations and their low-level counterparts for the x86 architecture within the Static Single Assignment (SSA) intermediate representation used by the Go compiler.

4. **Connect fields to functionality:**
    * `name`:  The symbolic name of the operation (e.g., "ADDQ", "MOVQload").
    * `argLen`: The number of arguments the operation takes.
    * `asm`:  The corresponding assembly instruction (e.g., `x86.AADDQ`).
    * `reg`: Contains information about register constraints for inputs and outputs. The numerical values likely represent bitmasks indicating allowed registers.
    * `auxType`:  Specifies the type of auxiliary information the operation might need (e.g., `auxSymOff` for symbol offsets, `auxInt64` for 64-bit integers).
    * `resultInArg0`: Indicates if the result of the operation is stored in the first argument.
    * `commutative`:  Specifies if the order of arguments doesn't affect the result.
    * `faultOnNilArg0`: Indicates if the operation will fault if the first argument is nil.
    * `symEffect`: Describes the side effect on symbols (e.g., `SymRead`, `SymWrite`).
    * `scale`: For indexed memory access, the scaling factor.
    * `clobberFlags`: Indicates if the operation modifies processor flags.
    * `needIntTemp`:  Indicates if the operation requires a temporary integer register.
    * `call`, `tailCall`: Indicate if the operation is a function call.
    * `zeroWidth`: Indicates if the operation has zero width (doesn't produce a value).
    * `nilCheck`: Indicates if the operation performs a nil check.
    * `unsafePoint`: Marks an unsafe point in the execution.
    * `hasSideEffects`: Indicates if the operation has side effects beyond its result.
    * `resultNotInArgs`: Indicates the result is not stored in any of the input arguments.

5. **Formulate the core functionality:** The primary function is to provide a structured way to define and access information about various operations used in the SSA intermediate representation for the x86 architecture. This information is crucial for the compiler's code generation phase.

6. **Provide a Go code example:**  Demonstrate how this data structure might be used. This involves iterating through the slice and accessing the fields.

7. **Address code inference:**  Focus on a simple example, like the `ADDQ` operation, and show how the input and output register constraints relate to actual register usage in assembly. The bitmasks in `regInfo` are key here.

8. **Explain command-line arguments:**  Since this is an internal compiler file, it's unlikely to directly handle command-line arguments. The compiler driver (`go build`, etc.) handles those, and this file contributes to the compilation process.

9. **Identify potential errors:** Focus on misinterpreting the register constraints or the purpose of the different fields. For instance, assuming a specific register is *always* used when the bitmask only indicates *allowed* registers.

10. **Summarize the functionality:** Concisely restate the primary role of the code snippet.

11. **Address the "part 5 of 18" aspect:** Acknowledge that this is part of a larger system and that the current snippet likely interacts with other parts of the compiler.
```go
{
		name:        "MOVBELstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVBEL,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVBELstoreidx4",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVBEL,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVBELstoreidx8",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVBEL,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVBEQstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVBEQ,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVBEQstoreidx8",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVBEQ,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
}
```

## 功能列举

这部分 `opGen.go` 文件定义了一个 Go 结构体切片（`[]struct{...}`)，其中每个结构体描述了一个特定的 **SSA 操作 (operation)**。 这些操作是 Go 编译器在将 Go 代码转换为机器码过程中使用的中间表示形式。

每个结构体包含了以下信息，用于描述一个 SSA 操作：

* **`name`**: 操作的名称，例如 "ADDQ" (加法), "MOVQload" (加载四字), "CALLstatic" (静态函数调用) 等。
* **`argLen`**: 操作接收的参数数量。 `-1` 表示参数数量可变。
* **`resultInArg0`**:  一个布尔值，指示操作的结果是否存储在其第一个输入参数中。
* **`asm`**:  与该 SSA 操作对应的 x86 汇编指令，例如 `x86.AADDQ`。
* **`reg`**: 一个 `regInfo` 结构体，描述了操作数和结果的寄存器约束。这包括哪些寄存器可以作为输入 (`inputs`) 和输出 (`outputs`)，以及哪些寄存器会被破坏 (`clobbers`)。数值是位掩码，用于表示允许使用的寄存器集合。
* **`auxType`**:  指定操作可能需要的辅助值的类型，例如 `auxInt64` (64位整数), `auxSymOff` (符号偏移量) 等。
* **`commutative`**: 一个布尔值，指示操作是否满足交换律（即操作数的顺序是否可以改变）。
* **`faultOnNilArg0`**: 一个布尔值，指示如果第一个参数为 nil，操作是否会产生错误。
* **`symEffect`**:  描述操作对符号的影响，例如 `SymRead` (读取符号), `SymWrite` (写入符号), `SymAddr` (获取符号地址) 等。
* **`scale`**: 用于索引寻址的比例因子。
* **`clobberFlags`**: 一个布尔值，指示操作是否会修改 CPU 的标志寄存器。
* **`needIntTemp`**: 一个布尔值，指示操作是否需要一个临时的整数寄存器。
* **`call`**: 一个布尔值，指示操作是否是函数调用。
* **`tailCall`**: 一个布尔值，指示操作是否是尾调用。
* **`zeroWidth`**: 一个布尔值，指示操作是否不产生任何值（例如，只产生副作用）。
* **`nilCheck`**: 一个布尔值，指示操作是否执行空指针检查。
* **`unsafePoint`**: 一个布尔值，标记操作为一个不安全点。
* **`hasSideEffects`**: 一个布尔值，指示操作是否有副作用。
* **`resultNotInArgs`**: 一个布尔值，指示操作的结果不存储在任何输入参数中。

总而言之，这段代码定义了 Go 编译器后端在 x86 架构上进行代码生成时所需的 **SSA 指令集** 及其属性。

## 推理出的 Go 语言功能实现 (以 "ADDQ" 为例)

尽管 `opGen.go` 本身不直接实现 Go 语言的某个功能，但它为 Go 语言功能的编译提供了基础信息。例如，其中的 "ADDQ" 操作就与 Go 语言的加法运算有关。

**假设输入 Go 代码:**

```go
package main

func main() {
	a := 10
	b := 20
	c := a + b
	println(c)
}
```

**代码推理:**

在编译 `a + b` 这行代码时，Go 编译器会将其转换为 SSA 形式。对于 x86 架构，可能会生成类似以下的 SSA 操作序列（简化）：

1. `MOVQconst a_val -> R1`  // 将常量 10 加载到寄存器 R1
2. `MOVQconst b_val -> R2`  // 将常量 20 加载到寄存器 R2
3. `ADDQ R1, R2 -> R3`      // 将 R1 和 R2 的值相加，结果存储到 R3

`opGen.go` 中关于 "ADDQ" 的定义会告诉编译器：

* "ADDQ" 操作接收两个参数。
* 对应的汇编指令是 `x86.AADDQ`。
* `regInfo` 描述了输入和输出寄存器的约束（尽管在这个简单的例子中，寄存器分配是灵活的，但 `opGen.go` 定义了允许使用的寄存器）。

**由于 `opGen.go` 不处理具体的数值，我们无法提供带具体数值的输入输出。它的作用是描述操作的 *结构* 和 *约束*。**

## 命令行参数的具体处理

`opGen.go` 文件本身不处理任何命令行参数。它是 Go 编译器内部的一部分，由编译器驱动程序（例如 `go build`）调用。编译器驱动程序负责解析命令行参数，并根据这些参数配置编译过程。 `opGen.go` 生成的数据会被编译器在后续的 SSA 生成和优化阶段使用。

## 使用者易犯错的点

作为编译器开发的内部文件，`opGen.go`  不是普通 Go 开发者直接使用的。 易犯错的点主要存在于 **编译器开发者** 修改或添加操作定义时：

* **错误的寄存器约束**:  `regInfo` 中的位掩码如果设置不正确，可能导致生成的代码无法正常工作或性能下降。例如，错误地限制了可以使用的寄存器，导致不必要的 move 指令。
* **`argLen` 的错误设置**: 如果 `argLen` 与实际操作所需的参数数量不符，会导致编译错误或运行时崩溃。
* **`asm` 指令的错误关联**: 将 SSA 操作关联到错误的汇编指令会导致生成的机器码执行错误的功能。
* **忽略 `auxType` 的需求**: 某些操作需要辅助信息，如果 `auxType` 设置不正确或缺失，会导致编译失败。
* **对 `commutative`, `faultOnNilArg0`, `symEffect` 等属性的误用**: 这些属性会影响编译器的优化和代码生成策略，设置错误可能导致非预期的行为或安全问题。

**举例说明 (假设一个错误的 `ADDQ` 定义):**

如果 `opGen.go` 中 "ADDQ" 的 `regInfo` 被错误地定义为只允许使用特定的几个寄存器，即使在其他寄存器空闲的情况下，编译器也可能被迫生成额外的 `MOVQ` 指令来满足这些限制，从而降低性能。

## 功能归纳

这部分 `go/src/cmd/compile/internal/ssa/opGen.go` 的主要功能是：

**定义了 x86 架构下 Go 编译器 SSA 中间表示的各种操作 (operations) 及其属性。**

它提供了一个结构化的数据源，包含了每个 SSA 操作的名称、参数数量、对应的汇编指令、寄存器约束、辅助信息需求以及其他相关属性。 这些信息是 Go 编译器后端进行 SSA 生成、优化和最终代码生成的核心依据。 这部分代码是 Go 编译器将高级 Go 代码转换为低级机器码的关键组成部分。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第5部分，共18部分，请归纳一下它的功能

"""
112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "MINSD",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.AMINSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "MINSS",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.AMINSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "SBBQcarrymask",
		argLen: 1,
		asm:    x86.ASBBQ,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SBBLcarrymask",
		argLen: 1,
		asm:    x86.ASBBL,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETEQ",
		argLen: 1,
		asm:    x86.ASETEQ,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETNE",
		argLen: 1,
		asm:    x86.ASETNE,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETL",
		argLen: 1,
		asm:    x86.ASETLT,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETLE",
		argLen: 1,
		asm:    x86.ASETLE,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETG",
		argLen: 1,
		asm:    x86.ASETGT,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETGE",
		argLen: 1,
		asm:    x86.ASETGE,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETB",
		argLen: 1,
		asm:    x86.ASETCS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETBE",
		argLen: 1,
		asm:    x86.ASETLS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETA",
		argLen: 1,
		asm:    x86.ASETHI,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETAE",
		argLen: 1,
		asm:    x86.ASETCC,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETO",
		argLen: 1,
		asm:    x86.ASETOS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SETEQstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SETNEstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETNE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SETLstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETLT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SETLEstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETLE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SETGstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETGT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SETGEstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETGE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SETBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETCS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SETBEstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETLS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SETAstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETHI,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "SETAEstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.ASETCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETEQstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETEQ,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETNEstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETNE,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETLstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETLT,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETLEstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETLE,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETGstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETGT,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETGEstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETGE,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETBstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETCS,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETBEstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETLS,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETAstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETHI,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "SETAEstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.ASETCC,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "SETEQF",
		argLen:       1,
		clobberFlags: true,
		needIntTemp:  true,
		asm:          x86.ASETEQ,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SETNEF",
		argLen:       1,
		clobberFlags: true,
		needIntTemp:  true,
		asm:          x86.ASETNE,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETORD",
		argLen: 1,
		asm:    x86.ASETPC,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETNAN",
		argLen: 1,
		asm:    x86.ASETPS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETGF",
		argLen: 1,
		asm:    x86.ASETHI,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "SETGEF",
		argLen: 1,
		asm:    x86.ASETCC,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "MOVBQSX",
		argLen: 1,
		asm:    x86.AMOVBQSX,
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
		name:   "MOVBQZX",
		argLen: 1,
		asm:    x86.AMOVBLZX,
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
		name:   "MOVWQSX",
		argLen: 1,
		asm:    x86.AMOVWQSX,
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
		name:   "MOVWQZX",
		argLen: 1,
		asm:    x86.AMOVWLZX,
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
		name:   "MOVLQSX",
		argLen: 1,
		asm:    x86.AMOVLQSX,
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
		name:   "MOVLQZX",
		argLen: 1,
		asm:    x86.AMOVL,
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
		name:              "MOVLconst",
		auxType:           auxInt32,
		argLen:            0,
		rematerializeable: true,
		asm:               x86.AMOVL,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:              "MOVQconst",
		auxType:           auxInt64,
		argLen:            0,
		rematerializeable: true,
		asm:               x86.AMOVQ,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "CVTTSD2SL",
		argLen: 1,
		asm:    x86.ACVTTSD2SL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "CVTTSD2SQ",
		argLen: 1,
		asm:    x86.ACVTTSD2SQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "CVTTSS2SL",
		argLen: 1,
		asm:    x86.ACVTTSS2SL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "CVTTSS2SQ",
		argLen: 1,
		asm:    x86.ACVTTSS2SQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "CVTSL2SS",
		argLen: 1,
		asm:    x86.ACVTSL2SS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "CVTSL2SD",
		argLen: 1,
		asm:    x86.ACVTSL2SD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "CVTSQ2SS",
		argLen: 1,
		asm:    x86.ACVTSQ2SS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "CVTSQ2SD",
		argLen: 1,
		asm:    x86.ACVTSQ2SD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "CVTSD2SS",
		argLen: 1,
		asm:    x86.ACVTSD2SS,
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
		name:   "CVTSS2SD",
		argLen: 1,
		asm:    x86.ACVTSS2SD,
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
		name:   "MOVQi2f",
		argLen: 1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "MOVQf2i",
		argLen: 1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "MOVLi2f",
		argLen: 1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "MOVLf2i",
		argLen: 1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "PXOR",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          x86.APXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "POR",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          x86.APOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:              "LEAQ",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		asm:               x86.ALEAQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:              "LEAL",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		asm:               x86.ALEAL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:              "LEAW",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		asm:               x86.ALEAW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "LEAQ1",
		auxType:     auxSymOff,
		argLen:      2,
		commutative: true,
		symEffect:   SymAddr,
		asm:         x86.ALEAQ,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "LEAL1",
		auxType:     auxSymOff,
		argLen:      2,
		commutative: true,
		symEffect:   SymAddr,
		asm:         x86.ALEAL,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "LEAW1",
		auxType:     auxSymOff,
		argLen:      2,
		commutative: true,
		symEffect:   SymAddr,
		asm:         x86.ALEAW,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LEAQ2",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		asm:       x86.ALEAQ,
		scale:     2,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LEAL2",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		asm:       x86.ALEAL,
		scale:     2,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LEAW2",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		asm:       x86.ALEAW,
		scale:     2,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LEAQ4",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		asm:       x86.ALEAQ,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LEAL4",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		asm:       x86.ALEAL,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LEAW4",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		asm:       x86.ALEAW,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LEAQ8",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		asm:       x86.ALEAQ,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LEAL8",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		asm:       x86.ALEAL,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LEAW8",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		asm:       x86.ALEAW,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVBload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVBLZX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVBQSXload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVBQSX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVWload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVWLZX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVWQSXload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVWQSX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVLload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVLQSXload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVLQSX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVQload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVLstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVQstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVOload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVUPS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:           "MOVOstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVUPS,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
		},
	},
	{
		name:        "MOVBloadidx1",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.AMOVBLZX,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "MOVWloadidx1",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.AMOVWLZX,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "MOVWloadidx2",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVWLZX,
		scale:     2,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "MOVLloadidx1",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.AMOVL,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "MOVLloadidx4",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVL,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "MOVLloadidx8",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVL,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "MOVQloadidx1",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.AMOVQ,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "MOVQloadidx8",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVQ,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "MOVBstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVB,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVWstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVW,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVWstoreidx2",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVW,
		scale:     2,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVLstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVL,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVLstoreidx4",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVL,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVLstoreidx8",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVL,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVQstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVQ,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVQstoreidx8",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVQ,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVBstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVWstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVLstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVQstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVOstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVUPS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVBstoreconstidx1",
		auxType:     auxSymValAndOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVB,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVWstoreconstidx1",
		auxType:     auxSymValAndOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVW,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVWstoreconstidx2",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymWrite,
		asm:       x86.AMOVW,
		scale:     2,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVLstoreconstidx1",
		auxType:     auxSymValAndOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVL,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVLstoreconstidx4",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymWrite,
		asm:       x86.AMOVL,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVQstoreconstidx1",
		auxType:     auxSymValAndOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVQ,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVQstoreconstidx8",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymWrite,
		asm:       x86.AMOVQ,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "DUFFZERO",
		auxType:        auxInt64,
		argLen:         2,
		faultOnNilArg0: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 128}, // DI
			},
			clobbers: 128, // DI
		},
	},
	{
		name:           "REPSTOSQ",
		argLen:         4,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 128}, // DI
				{1, 2},   // CX
				{2, 1},   // AX
			},
			clobbers: 130, // CX DI
		},
	},
	{
		name:         "CALLstatic",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			clobbers: 2147483631, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 g R15 X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
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
			clobbers: 2147483631, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 g R15 X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
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
				{1, 4},     // DX
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 2147483631, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 g R15 X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
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
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 2147483631, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 g R15 X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
		},
	},
	{
		name:           "DUFFCOPY",
		auxType:        auxInt64,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 128}, // DI
				{1, 64},  // SI
			},
			clobbers: 65728, // SI DI X0
		},
	},
	{
		name:           "REPMOVSQ",
		argLen:         4,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 128}, // DI
				{1, 64},  // SI
				{2, 2},   // CX
			},
			clobbers: 194, // CX SI DI
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
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
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
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 2147418112, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			outputs: []outputInfo{
				{0, 2048}, // R11
			},
		},
	},
	{
		name:              "LoweredHasCPUFeature",
		auxType:           auxSym,
		argLen:            0,
		rematerializeable: true,
		symEffect:         SymNone,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
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
				{0, 4}, // DX
				{1, 8}, // BX
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
				{0, 2}, // CX
				{1, 4}, // DX
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
				{0, 1}, // AX
				{1, 2}, // CX
			},
		},
	},
	{
		name:   "FlagEQ",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagLT_ULT",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagLT_UGT",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagGT_UGT",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagGT_ULT",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:           "MOVBatomicload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVLatomicload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVQatomicload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "XCHGB",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AXCHGB,
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
		name:           "XCHGL",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AXCHGL,
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
		name:           "XCHGQ",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AXCHGQ,
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
		name:           "XADDLlock",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AXADDL,
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
		name:           "XADDQlock",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AXADDQ,
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
		name:           "CMPXCHGLlock",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.ACMPXCHGL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1},     // AX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "CMPXCHGQlock",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.ACMPXCHGQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1},     // AX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ANDBlock",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AANDB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ANDLlock",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ANDQlock",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AANDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ORBlock",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AORB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ORLlock",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ORQlock",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            x86.AORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:            "LoweredAtomicAnd64",
		auxType:         auxSymOff,
		argLen:          3,
		resultNotInArgs: true,
		clobberFlags:    true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		symEffect:       SymRdWr,
		asm:             x86.AANDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49134}, // CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49134}, // CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // AX
			},
		},
	},
	{
		name:            "LoweredAtomicAnd32",
		auxType:         auxSymOff,
		argLen:          3,
		resultNotInArgs: true,
		clobberFlags:    true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		symEffect:       SymRdWr,
		asm:             x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49134}, // CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49134}, // CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // AX
			},
		},
	},
	{
		name:            "LoweredAtomicOr64",
		auxType:         auxSymOff,
		argLen:          3,
		resultNotInArgs: true,
		clobberFlags:    true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		symEffect:       SymRdWr,
		asm:             x86.AORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49134}, // CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49134}, // CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // AX
			},
		},
	},
	{
		name:            "LoweredAtomicOr32",
		auxType:         auxSymOff,
		argLen:          3,
		resultNotInArgs: true,
		clobberFlags:    true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		symEffect:       SymRdWr,
		asm:             x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49134}, // CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49134}, // CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // AX
			},
		},
	},
	{
		name:           "PrefetchT0",
		argLen:         2,
		hasSideEffects: true,
		asm:            x86.APREFETCHT0,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "PrefetchNTA",
		argLen:         2,
		hasSideEffects: true,
		asm:            x86.APREFETCHNTA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ANDNQ",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AANDNQ,
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
		name:         "ANDNL",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AANDNL,
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
		name:         "BLSIQ",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ABLSIQ,
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
		name:         "BLSIL",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ABLSIL,
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
		name:         "BLSMSKQ",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ABLSMSKQ,
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
		name:         "BLSMSKL",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ABLSMSKL,
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
		name:   "BLSRQ",
		argLen: 1,
		asm:    x86.ABLSRQ,
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
		name:   "BLSRL",
		argLen: 1,
		asm:    x86.ABLSRL,
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
		name:         "TZCNTQ",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ATZCNTQ,
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
		name:         "TZCNTL",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ATZCNTL,
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
		name:         "LZCNTQ",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ALZCNTQ,
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
		name:         "LZCNTL",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ALZCNTL,
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
		name:           "MOVBEWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVBEW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVBELload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVBEL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVBELstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVBEL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "MOVBEQload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVBEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "MOVBEQstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVBEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVBELloadidx1",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.AMOVBEL,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "MOVBELloadidx4",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVBEL,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "MOVBELloadidx8",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVBEL,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "MOVBEQloadidx1",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.AMOVBEQ,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:      "MOVBEQloadidx8",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVBEQ,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "MOVBEWstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVBEW,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "MOVBEWstoreidx2",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVBEW,
		scale:     2,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "MOVBELstoreidx1",
	
"""




```