Response: The user wants to understand the functionality of the provided Go code snippet. This snippet is part of the `opGen.go` file within the `ssa` package of the Go compiler.

The code defines a large array of structs. Each struct seems to describe a specific operation supported by the Go compiler for the x86 architecture.

Each struct contains fields like `name`, `auxType`, `argLen`, `resultInArg0`, `asm`, and a `reg` field which itself is a struct containing information about input and output registers.

Therefore, the primary function of this code is to define the properties and constraints of various x86 assembly instructions as they are used within the Go compiler's intermediate representation (SSA).

Let's break down the structure of each element:
- `name`: The name of the operation within the SSA framework.
- `auxType`:  Indicates if the operation uses an auxiliary value and its type (e.g., `auxInt32`, `auxSymOff`).
- `argLen`: The number of arguments the operation takes.
- `resultInArg0`: A boolean indicating if the result of the operation is stored in the first argument.
- `faultOnNilArg1`: A boolean indicating if the operation will fault if the second argument is nil.
- `symEffect`: Indicates if the operation reads or writes to a symbol.
- `asm`: The actual x86 assembly instruction corresponding to the operation.
- `reg`: A struct containing:
    - `inputs`: A slice of `inputInfo` structs, each specifying the argument index and the allowed register set for that argument.
    - `outputs`: A slice of `outputInfo` structs, each specifying the result index and the allowed register set for the output.
    - `clobbers`:  Indicates which registers are modified by the operation.

Based on the names of the operations, this section seems to cover:
- Floating-point arithmetic operations with memory operands (`ADDSSload`, `ADDSDload`, etc.)
- Integer arithmetic and logical operations (`ADDL`, `SUBL`, `ANDL`, `ORL`, `XORL`, `MULL`, `DIVL`, `MODL`)
- Comparison operations (`CMPL`, `CMPW`, `CMPB`, `UCOMISS`, `UCOMISD`)
- Bitwise shift and rotate operations (`SHLL`, `SHRL`, `SARL`, `ROLL`)
- Load and store operations (`MOVBLSXload`, `MOVWload`, `MOVLstore`)
- Control flow operations (partially covered by `CALLstatic`, `CALLclosure`, `CALLinter`)
- Conversions (`CVTTSD2SL`, `CVTSL2SS`)
- Special instructions (`BSFL`, `BSRL`, `BSWAPL`, `SQRTSD`, `SQRTSS`)
- Set flag instructions (`SETEQ`, `SETNE`, etc.)

**Hypothesis:** This code defines the mapping between high-level Go operations and low-level x86 instructions, along with constraints on register usage for the SSA backend of the Go compiler.

**Example:** Let's take the `ADDL` operation.

```go
{
	name:         "ADDL",
	argLen:       2,
	commutative:  true,
	clobberFlags: true,
	asm:          x86.AADDL,
	reg: regInfo{
		inputs: []inputInfo{
			{1, 239}, // AX CX DX BX BP SI DI
			{0, 255}, // AX CX DX BX SP BP SI DI
		},
		outputs: []outputInfo{
			{0, 239}, // AX CX DX BX BP SI DI
		},
	},
},
```

This describes the "ADDL" operation (add long/32-bit integer).
- It takes 2 arguments (`argLen: 2`).
- It's commutative (`commutative: true`).
- It modifies the CPU flags (`clobberFlags: true`).
- The corresponding assembly instruction is `x86.AADDL`.
- Input argument 0 can be in any of the registers AX, CX, DX, BX, SP, BP, SI, DI (mask 255).
- Input argument 1 can be in any of the registers AX, CX, DX, BX, BP, SI, DI (mask 239).
- The output is stored in the same register as input argument 0, and that register must be one of AX, CX, DX, BX, BP, SI, DI.

**Illustrative Go code (at SSA level, not directly written by a programmer):**

```go
// Hypothetical SSA representation
v1 = Local("a", int32)  // Assume variable 'a' is assigned to SSA value v1
v2 = Local("b", int32)  // Assume variable 'b' is assigned to SSA value v2
v3 = ADDL v1, v2
Store v3, Local("c", int32) // Store the result in variable 'c'
```

During the compilation process, the `ADDL` SSA operation would be translated into the x86 `ADDL` instruction, respecting the register constraints defined in the `opGen.go` file.

**归纳一下它的功能:**

This section of `opGen.go` defines the properties of various x86 assembly instructions used by the Go compiler's SSA backend. It specifies the instruction's name within the SSA framework, the corresponding assembly mnemonic, the number and types of its arguments (including auxiliary values), whether the operation is commutative, whether it clobbers CPU flags, which registers can be used for input and output arguments, and any side effects like memory reads or writes. In essence, it provides a detailed specification of each supported x86 operation for the compiler's code generation phase.

Based on the provided Go code snippet from `go/src/cmd/compile/internal/ssa/opGen.go`, specifically section 2 of 18, its primary function is to **define a set of supported operations for the x86 architecture within the Go compiler's Static Single Assignment (SSA) intermediate representation.**

Each entry in the array describes a specific operation. Let's break down the common fields:

*   **`name`**:  The symbolic name of the operation within the SSA framework (e.g., "ADDSSload", "ADDL", "MOVLstore").
*   **`auxType`**:  Specifies the type of auxiliary information associated with the operation, if any (e.g., `auxSymOff` for symbol and offset, `auxInt32` for an integer constant).
*   **`argLen`**: The number of arguments the operation takes.
*   **`resultInArg0`**: A boolean indicating whether the result of the operation is stored back into the register of the first argument.
*   **`faultOnNilArg1`**: A boolean indicating whether the operation will cause a fault if the second argument is a nil pointer.
*   **`symEffect`**:  Indicates if the operation has side effects related to symbols (e.g., `SymRead` for reading from memory, `SymWrite` for writing to memory, `SymAddr` for taking the address of a symbol).
*   **`asm`**: The corresponding x86 assembly instruction mnemonic (e.g., `x86.AADDSS`, `x86.AMOVL`).
*   **`reg`**: A struct containing information about register usage:
    *   **`inputs`**: A slice of `inputInfo` structs, where each specifies the allowed register classes for a particular input argument. The integer value represents a bitmask where each bit corresponds to a specific register.
    *   **`outputs`**: A slice of `outputInfo` structs, specifying the allowed register classes for the output of the operation.
    *   **`clobbers`**: Indicates which registers are modified (clobbered) by the operation, beyond the output register.
*   **`commutative`**: A boolean indicating if the order of the arguments doesn't affect the result (e.g., addition, multiplication).
*   **`clobberFlags`**: A boolean indicating if the operation modifies the CPU flags register.
*   **`call`**: A boolean indicating if the operation represents a function call.
*   **`tailCall`**: A boolean indicating if the operation is a tail call.
*   **`nilCheck`**: A boolean indicating if the operation performs a nil check.
*   **`zeroWidth`**: A boolean indicating if the operation has zero width (doesn't produce a value).
*   **`rematerializeable`**: A boolean indicating if the operation's result can be recomputed instead of being stored in a register.
*   **`scale`**: An integer representing the scaling factor for indexed addressing modes.

**In summary, this section of `opGen.go` serves as a machine-readable specification of how high-level Go operations are translated into low-level x86 instructions at the SSA level. It details the instruction's syntax, side effects, and constraints on register allocation.**

**Example and Code Reasoning:**

Let's take the `ADDL` operation as an example:

```go
{
	name:         "ADDL",
	argLen:       2,
	commutative:  true,
	clobberFlags: true,
	asm:          x86.AADDL,
	reg: regInfo{
		inputs: []inputInfo{
			{1, 239}, // AX CX DX BX BP SI DI
			{0, 255}, // AX CX DX BX SP BP SI DI
		},
		outputs: []outputInfo{
			{0, 239}, // AX CX DX BX BP SI DI
		},
	},
},
```

**Reasoning:**

*   **`name: "ADDL"`**: This is the SSA name for a 32-bit integer addition.
*   **`argLen: 2`**: It takes two input arguments.
*   **`commutative: true`**: The order of the operands doesn't matter (a + b == b + a).
*   **`clobberFlags: true`**: The `ADDL` instruction modifies the CPU flags register (e.g., zero flag, carry flag).
*   **`asm: x86.AADDL`**: The corresponding x86 assembly instruction is `ADDL`.
*   **`reg`**: Defines register constraints:
    *   **`inputs`**:
        *   `{1, 239}`: The second input argument (index 1) can reside in registers AX, CX, DX, BX, BP, SI, DI. The decimal value 239 is a bitmask where the bits corresponding to these registers are set.
        *   `{0, 255}`: The first input argument (index 0) can reside in registers AX, CX, DX, BX, SP, BP, SI, DI.
    *   **`outputs`**:
        *   `{0, 239}`: The output of the addition will be placed in the same register as the first input argument, and that register must be one of AX, CX, DX, BX, BP, SI, DI.

**Hypothetical Go Code (at SSA level):**

```go
// Assume v1 and v2 are SSA values representing two 32-bit integers.
// The actual Go code that would lead to this SSA might be something like:
// a := 10
// b := 20
// c := a + b

v3 = ADDL v1, v2
// v3 now holds the result of the addition.
```

During the compilation process, when the Go compiler encounters the `ADDL` SSA operation, it uses the information from this `opGen.go` entry to generate the correct x86 `ADDL` instruction, ensuring that the operands are in compatible registers and understanding that the flags register will be modified.

**归纳一下它的功能 (Summary of its Function):**

This part of `opGen.go` systematically enumerates and defines the properties of low-level x86 instructions as they are utilized within the Go compiler's SSA intermediate representation. It acts as a crucial bridge between the architecture-independent SSA form and the target-specific x86 assembly language. This detailed specification enables the compiler to perform tasks like register allocation, instruction selection, and optimization in a machine-aware manner.

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共18部分，请归纳一下它的功能
```

### 源代码
```go
791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "ADDSSload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AADDSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:           "ADDSDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AADDSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:           "SUBSSload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ASUBSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:           "SUBSDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ASUBSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:           "MULSSload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AMULSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:           "MULSDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AMULSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:           "DIVSSload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ADIVSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:           "DIVSDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ADIVSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:         "ADDL",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 239}, // AX CX DX BX BP SI DI
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ADDLconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ADDLcarry",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ADDLconstcarry",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		asm:          x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ADCL",
		argLen:       3,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AADCL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ADCLconst",
		auxType:      auxInt32,
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AADCL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SUBL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASUBL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SUBLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASUBL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SUBLcarry",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.ASUBL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SUBLconstcarry",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		asm:          x86.ASUBL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SBBL",
		argLen:       3,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASBBL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SBBLconst",
		auxType:      auxInt32,
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASBBL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "MULL",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AIMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "MULLconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          x86.AIMUL3L,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "MULLU",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
			clobbers: 4, // DX
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // AX
			},
		},
	},
	{
		name:         "HMULL",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AIMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "HMULLU",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "MULLQU",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
			outputs: []outputInfo{
				{0, 4}, // DX
				{1, 1}, // AX
			},
		},
	},
	{
		name:         "AVGLU",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "DIVL",
		auxType:      auxBool,
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AIDIVL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 251}, // AX CX BX SP BP SI DI
			},
			clobbers: 4, // DX
			outputs: []outputInfo{
				{0, 1}, // AX
			},
		},
	},
	{
		name:         "DIVW",
		auxType:      auxBool,
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AIDIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 251}, // AX CX BX SP BP SI DI
			},
			clobbers: 4, // DX
			outputs: []outputInfo{
				{0, 1}, // AX
			},
		},
	},
	{
		name:         "DIVLU",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.ADIVL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 251}, // AX CX BX SP BP SI DI
			},
			clobbers: 4, // DX
			outputs: []outputInfo{
				{0, 1}, // AX
			},
		},
	},
	{
		name:         "DIVWU",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.ADIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 251}, // AX CX BX SP BP SI DI
			},
			clobbers: 4, // DX
			outputs: []outputInfo{
				{0, 1}, // AX
			},
		},
	},
	{
		name:         "MODL",
		auxType:      auxBool,
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AIDIVL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 251}, // AX CX BX SP BP SI DI
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "MODW",
		auxType:      auxBool,
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AIDIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 251}, // AX CX BX SP BP SI DI
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "MODLU",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.ADIVL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 251}, // AX CX BX SP BP SI DI
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "MODWU",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.ADIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},   // AX
				{1, 251}, // AX CX BX SP BP SI DI
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "ANDL",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ANDLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ORL",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ORLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "XORL",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AXORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "XORLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AXORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "CMPL",
		argLen: 2,
		asm:    x86.ACMPL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:   "CMPW",
		argLen: 2,
		asm:    x86.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:   "CMPB",
		argLen: 2,
		asm:    x86.ACMPB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:    "CMPLconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     x86.ACMPL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:    "CMPWconst",
		auxType: auxInt16,
		argLen:  1,
		asm:     x86.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:    "CMPBconst",
		auxType: auxInt8,
		argLen:  1,
		asm:     x86.ACMPB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:           "CMPLload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "CMPWload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "CMPBload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "CMPLconstload",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "CMPWconstload",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "CMPBconstload",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:   "UCOMISS",
		argLen: 2,
		asm:    x86.AUCOMISS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:   "UCOMISD",
		argLen: 2,
		asm:    x86.AUCOMISD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:        "TESTL",
		argLen:      2,
		commutative: true,
		asm:         x86.ATESTL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:        "TESTW",
		argLen:      2,
		commutative: true,
		asm:         x86.ATESTW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:        "TESTB",
		argLen:      2,
		commutative: true,
		asm:         x86.ATESTB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
				{1, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:    "TESTLconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     x86.ATESTL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:    "TESTWconst",
		auxType: auxInt16,
		argLen:  1,
		asm:     x86.ATESTW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:    "TESTBconst",
		auxType: auxInt8,
		argLen:  1,
		asm:     x86.ATESTB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:         "SHLL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHLL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SHLLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHLL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SHRL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SHRW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SHRB",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SHRLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SHRWconst",
		auxType:      auxInt16,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SHRBconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SARL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SARW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SARB",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SARLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SARWconst",
		auxType:      auxInt16,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SARBconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ROLL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ROLW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ROLB",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},   // CX
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ROLLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "ROLWconst",
		auxType:      auxInt16,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239},   // AX CX DX BX BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239},   // AX CX DX BX BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:           "MULLload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AIMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239},   // AX CX DX BX BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239},   // AX CX DX BX BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239},   // AX CX DX BX BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239},   // AX CX DX BX BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239},   // AX CX DX BX BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239},   // AX CX DX BX BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "MULLloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		clobberFlags: true,
		symEffect:    SymRead,
		asm:          x86.AIMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239},   // AX CX DX BX BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239},   // AX CX DX BX BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239},   // AX CX DX BX BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239},   // AX CX DX BX BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{1, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "BSFW",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ABSFW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "LoweredCtz32",
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:            "LoweredCtz64",
		argLen:          2,
		resultNotInArgs: true,
		clobberFlags:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
				{1, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "BSRW",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ABSRW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SQRTSD",
		argLen: 1,
		asm:    x86.ASQRTSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:   "SQRTSS",
		argLen: 1,
		asm:    x86.ASQRTSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:   "SBBLcarrymask",
		argLen: 1,
		asm:    x86.ASBBL,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETEQ",
		argLen: 1,
		asm:    x86.ASETEQ,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETNE",
		argLen: 1,
		asm:    x86.ASETNE,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETL",
		argLen: 1,
		asm:    x86.ASETLT,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETLE",
		argLen: 1,
		asm:    x86.ASETLE,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETG",
		argLen: 1,
		asm:    x86.ASETGT,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETGE",
		argLen: 1,
		asm:    x86.ASETGE,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETB",
		argLen: 1,
		asm:    x86.ASETCS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETBE",
		argLen: 1,
		asm:    x86.ASETLS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETA",
		argLen: 1,
		asm:    x86.ASETHI,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETAE",
		argLen: 1,
		asm:    x86.ASETCC,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETO",
		argLen: 1,
		asm:    x86.ASETOS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SETEQF",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ASETEQ,
		reg: regInfo{
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 238}, // CX DX BX BP SI DI
			},
		},
	},
	{
		name:         "SETNEF",
		argLen:       1,
		clobberFlags: true,
		asm:          x86.ASETNE,
		reg: regInfo{
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 238}, // CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETORD",
		argLen: 1,
		asm:    x86.ASETPC,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETNAN",
		argLen: 1,
		asm:    x86.ASETPS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETGF",
		argLen: 1,
		asm:    x86.ASETHI,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "SETGEF",
		argLen: 1,
		asm:    x86.ASETCC,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "MOVBLSX",
		argLen: 1,
		asm:    x86.AMOVBLSX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "MOVBLZX",
		argLen: 1,
		asm:    x86.AMOVBLZX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "MOVWLSX",
		argLen: 1,
		asm:    x86.AMOVWLSX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "MOVWLZX",
		argLen: 1,
		asm:    x86.AMOVWLZX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "CVTTSD2SL",
		argLen: 1,
		asm:    x86.ACVTTSD2SL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "CVTTSS2SL",
		argLen: 1,
		asm:    x86.ACVTTSS2SL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "CVTSL2SS",
		argLen: 1,
		asm:    x86.ACVTSL2SS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:   "CVTSL2SD",
		argLen: 1,
		asm:    x86.ACVTSL2SD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:   "CVTSD2SS",
		argLen: 1,
		asm:    x86.ACVTSD2SS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:   "CVTSS2SD",
		argLen: 1,
		asm:    x86.ACVTSS2SD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
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
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
				{1, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:              "LEAL",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:        "LEAL1",
		auxType:     auxSymOff,
		argLen:      2,
		commutative: true,
		symEffect:   SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:      "LEAL2",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:      "LEAL4",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:      "LEAL8",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:           "MOVBLSXload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVBLSX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:           "MOVWLSXload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVWLSX,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "ADDLconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "ANDLconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "ORLconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "XORLconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AXORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:      "MOVWloadidx2",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVWLZX,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:      "MOVLloadidx4",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:      "MOVWstoreidx2",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:      "MOVLstoreidx4",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{2, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
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
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:      "MOVBstoreconstidx1",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymWrite,
		asm:       x86.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:      "MOVWstoreconstidx1",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymWrite,
		asm:       x86.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:      "MOVWstoreconstidx2",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymWrite,
		asm:       x86.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:      "MOVLstoreconstidx1",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymWrite,
		asm:       x86.AMOVL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:      "MOVLstoreconstidx4",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymWrite,
		asm:       x86.AMOVL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 255},   // AX CX DX BX SP BP SI DI
				{0, 65791}, // AX CX DX BX SP BP SI DI SB
			},
		},
	},
	{
		name:           "DUFFZERO",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 128}, // DI
				{1, 1},   // AX
			},
			clobbers: 130, // CX DI
		},
	},
	{
		name:           "REPSTOSL",
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
		argLen:       1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			clobbers: 65519, // AX CX DX BX BP SI DI X0 X1 X2 X3 X4 X5 X6 X7
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
			clobbers: 65519, // AX CX DX BX BP SI DI X0 X1 X2 X3 X4 X5 X6 X7
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
				{1, 4},   // DX
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
			clobbers: 65519, // AX CX DX BX BP SI DI X0 X1 X2 X3 X4 X5 X6 X7
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
				{0, 239}, // AX CX DX BX BP SI DI
			},
			clobbers: 65519, // AX CX DX BX BP SI DI X0 X1 X2 X3 X4 X5 X6 X7
		},
	},
	{
		name:           "DUFFCOPY",
		auxType:        auxInt64,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 128}, // DI
				{1, 64},  // SI
			},
			clobbers: 194, // CX SI DI
		},
	},
	{
		name:           "REPMOVSL",
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
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
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
				{0, 255}, // AX CX DX BX SP BP SI DI
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 65280, // X0 X1 X2 X3 X4 X5 X6 X7
			outputs: []outputInfo{
				{0, 128}, // DI
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
		name:    "LoweredPanicExtendA",
		auxType: auxInt64,
		argLen:  4,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 64}, // SI
				{1, 4},  // DX
				{2, 8},  // BX
			},
		},
	},
	{
		name:    "LoweredPanicExtendB",
		auxType: auxInt64,
		argLen:  4,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 64}, // SI
				{1, 2},  // CX
				{2, 4},  // DX
			},
		},
	},
	{
		name:    "LoweredPanicExtendC",
		auxType: auxInt64,
		argLen:  4,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 64}, // SI
				{1, 1},  // AX
				{2, 2},  // CX
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
		name:    "MOVSSconst1",
		auxType: auxFloat32,
		argLen:  0,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:    "MOVSDconst1",
		auxType: auxFloat64,
		argLen:  0,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
		},
	},
	{
		name:   "MOVSSconst2",
		argLen: 1,
		asm:    x86.AMOVSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},
	{
		name:   "MOVSDconst2",
		argLen: 1,
		asm:    x86.AMOVSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 239}, // AX CX DX BX BP SI DI
			},
			outputs: []outputInfo{
				{0, 65280}, // X0 X1 X2 X3 X4 X5 X6 X7
			},
		},
	},

	{
		name:         "ADDSS",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          x86.AADDSS,
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
		name:         "ADDSD",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          x86.AADDSD,
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
		name:         "SUBSS",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.ASUBSS,
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
		name:         "SUBSD",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.ASUBSD,
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
		name:         "MULSS",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          x86.AMULSS,
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
		name:         "MULSD",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          x86.AMULSD,
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
		name:         "DIVSS",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.ADIVSS,
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
		name:         "DIVSD",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.ADIVSD,
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
		name:           "MOVSSload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVSS,
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
		name:           "MOVSDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.AMOVSD,
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
		name:              "MOVSSconst",
		auxType:           auxFloat32,
		argLen:            0,
		rematerializeable: true,
		asm:               x86.AMOVSS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:              "MOVSDconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               x86.AMOVSD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:      "MOVSSloadidx1",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVSS,
		scale:     1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:      "MOVSSloadidx4",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVSS,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:      "MOVSDloadidx1",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVSD,
		scale:     1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:      "MOVSDloadidx8",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.AMOVSD,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
			outputs: []output
```