Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request is to understand the functionality of the provided Go code, which is part of an ARM64 assembler. The key is to identify the data structures and their purpose within the context of assembly language.

2. **Initial Scan for Key Types:**  Quickly look for prominent type definitions. The code defines `Op`, `Inst`, `Args`, and `Arg`. This immediately suggests we're dealing with representing assembly instructions.

3. **`Op` (Opcode):**
    * It's a `uint16`. This suggests a numerical representation for opcodes.
    * `String()` method:  It converts the `Op` to a string, likely the mnemonic (e.g., "ADD", "MOV"). The comment about `tables.go` is crucial – the actual mapping of numbers to strings is likely elsewhere.
    * *Functionality:* Represents the operation to be performed by the instruction.

4. **`Inst` (Instruction):**
    * Contains `Op`, `Enc` (raw encoding), and `Args`. This confirms the code is representing a single assembly instruction.
    * `String()` method:  Combines the opcode string with the string representations of the arguments.
    * *Functionality:*  Represents a complete ARM64 instruction.

5. **`Args` (Arguments):**
    * An array of `Arg` with a fixed size of 5. This suggests a maximum of 5 arguments per instruction. The use of `nil` for fewer arguments is important.
    * *Functionality:* Holds the operands of the instruction.

6. **`Arg` (Argument Interface):**
    * An interface with `isArg()` and `String()` methods. This indicates a variety of concrete types can represent different kinds of arguments (registers, immediate values, memory addresses, etc.).

7. **Concrete `Arg` Types (Registers):**
    * A large `Reg` type defined as `uint16` with constants like `W0`, `X0`, `SP`, `WSP`. This clearly defines the ARM64 register set. The distinction between `W` (32-bit) and `X` (64-bit) registers is evident. The aliasing of `WZR`/`XZR` with `WSP`/`SP` is a specific ARM64 detail.
    * `String()` method: Converts `Reg` values to their standard assembly syntax (e.g., "W0", "X29", "SP").
    * *Functionality:* Represents an ARM64 register.

8. **Concrete `Arg` Types (Immediate Values):**
    * `ImmShift`, `Imm`, `Imm64`, etc. These structures represent different forms of immediate values (constants) that can be used as operands. The `String()` methods handle formatting these values in assembly syntax (hex, decimal, with optional shifts).
    * *Functionality:* Represents constant values.

9. **Concrete `Arg` Types (Memory Addressing):**
    * `MemImmediate`, `MemExtend`. These structures represent different ways of specifying memory locations. The `AddrMode` enum helps distinguish addressing modes (offset, pre/post-indexing). The `String()` methods generate the corresponding assembly syntax (e.g., `[X1]`, `[X2, #8]`, `[X3, W4, SXTW #2]`).
    * *Functionality:* Represents memory operands.

10. **Concrete `Arg` Types (Other):**
    * `PCRel` (program counter relative addressing), `Cond` (condition codes), `Systemreg`, `Imm_fp`, `Arrangement`, `RegisterWithArrangement`, `RegisterWithArrangementAndIndex`, `Imm_hint`, `Imm_clrex`, `Imm_dcps`, `Imm_c`, `Imm_option`, `Imm_prfop`, `Pstatefield`. These cover other specific types of operands or instruction modifiers in ARM64 assembly. The names themselves are often hints about their purpose.

11. **`sysOp` and related types:** This section deals with system instructions, which have a specific encoding structure. The `sysInstFields` and `sysInstsAttrs` map likely define the different system instructions and their mnemonics.

12. **Inferring the Overall Function:** Based on the identified types and their methods, the primary function of this code is to represent and format ARM64 assembly instructions. It's a core part of an assembler or disassembler.

13. **Code Example (Assembly):**  Choose a simple ARM64 instruction and construct the corresponding `Inst` struct. This helps solidify understanding. Start with basic register moves or arithmetic operations.

14. **Code Example (Go):** Show how to create and print an `Inst` struct. This demonstrates how the data structures are used.

15. **Command-Line Arguments (If Applicable):** This particular snippet doesn't seem to handle command-line arguments directly. It's a data structure definition. If the parent project were analyzed, command-line argument handling would likely be found in the main execution entry point.

16. **Common Mistakes:** Think about how someone using these structures might misuse them. For example, incorrect register numbers or attempting to create invalid instruction combinations. Focus on errors related to the *data representation*, not necessarily the assembly process itself.

17. **Refine and Organize:**  Structure the answer logically, starting with the high-level purpose and then drilling down into the details of each type. Use clear headings and bullet points to improve readability. Provide concise explanations of each component.

By following these steps, we can systematically analyze the code snippet and provide a comprehensive explanation of its functionality, along with relevant examples and potential pitfalls. The key is to recognize the patterns and data structures commonly used in assembler/disassembler implementations.
这段代码是 Go 语言中 `go/src/cmd/vendor/golang.org/x/arch/arm64/arm64asm/inst.go` 文件的一部分，它定义了用于表示和操作 ARM64 汇编指令的数据结构。 它的主要功能是：

**1. 定义 ARM64 汇编指令的抽象表示：**

* **`Op` 类型:**  表示 ARM64 指令的操作码（opcode）。它是一个 `uint16` 类型，并且定义了一个 `String()` 方法，可以将操作码转换为其对应的字符串助记符（例如 "ADD", "MOV"）。实际的 `Op` 值在 `tables.go` 文件中定义。
* **`Inst` 类型:** 表示一个完整的 ARM64 指令。它包含：
    * `Op`: 指令的操作码。
    * `Enc`: 指令的原始编码位。
    * `Args`: 指令的参数列表。
    它也定义了一个 `String()` 方法，可以将整个指令转换为字符串形式，包括操作码和参数。
* **`Args` 类型:**  是一个 `[5]Arg` 类型的数组，用于存储指令的参数。如果指令的参数少于 5 个，则数组的剩余元素为 `nil`。
* **`Arg` 接口:**  定义了指令参数的通用接口。所有具体的参数类型都必须实现 `isArg()` 和 `String()` 方法。

**2. 定义各种 ARM64 汇编指令参数的类型：**

代码中定义了多种实现了 `Arg` 接口的具体类型，用于表示 ARM64 指令中可能出现的各种参数：

* **寄存器:**
    * `Reg`: 表示一个通用寄存器，包括 W0-W30, X0-X30, WZR, XZR 以及向量寄存器 B0-B31, H0-H31, S0-S31, D0-D31, Q0-Q31, V0-V31。`W` 开头的表示 32 位寄存器，`X` 开头的表示 64 位寄存器。`WZR` 和 `XZR` 是零寄存器，同时也可以用作栈指针 `WSP` 和 `SP`。
    * `RegSP`:  类似 `Reg`，但将 `X31/W31` 视为 `SP/WSP`。
* **立即数:**
    * `ImmShift`:  带可选移位的立即数。
    * `Imm`: 32 位整型立即数。
    * `Imm64`: 64 位整型立即数。
    * `Imm_hint`, `Imm_clrex`, `Imm_dcps`, `Imm_c`, `Imm_option`, `Imm_prfop`:  特定指令使用的立即数类型。
    * `Imm_fp`: 浮点数立即数。
* **内存地址:**
    * `MemImmediate`:  基于寄存器和立即数偏移的内存地址。支持不同的寻址模式 (`AddrPostIndex`, `AddrPreIndex`, `AddrOffset`, `AddrPostReg`)。
    * `MemExtend`: 基于寄存器和扩展寄存器偏移的内存地址。允许指定扩展类型 (`uxtb`, `uxth`, `uxtw`, `uxtx`, `sxtb`, `sxth`, `sxtw`, `sxtx`) 和可选的移位量。
    * `PCRel`:  程序计数器相对偏移地址。
* **条件码:**
    * `Cond`:  表示条件码，用于条件执行指令。
* **系统寄存器:**
    * `Systemreg`:  表示系统寄存器。
* **带排列的寄存器:**
    * `RegisterWithArrangement`:  表示带有数据排列的向量寄存器 (例如 `V0.B`, `V1.8H`)，用于 SIMD 指令。
    * `RegisterWithArrangementAndIndex`: 表示带有数据排列和索引的向量寄存器 (例如 `V2.S[0]`)。
* **其他:**
    * `Pstatefield`:  表示 `PSTATE` (处理器状态) 字段。
    * `sysOp` 和 `sysInstFields`: 用于表示系统指令及其字段。

**推理它是什么 Go 语言功能的实现：**

从路径 `go/src/cmd/vendor/golang.org/x/arch/arm64/arm64asm/inst.go` 可以推断，这是 Go 语言工具链中用于处理 ARM64 汇编代码的一部分。 具体来说，它很可能被用于：

* **汇编器 (Assembler):** 将 ARM64 汇编代码转换为机器码。
* **反汇编器 (Disassembler):** 将 ARM64 机器码转换为汇编代码。
* **其他与 ARM64 架构相关的工具:**  例如，用于分析、模拟或调试 ARM64 代码的工具。

**Go 代码举例说明:**

假设我们要表示 ARM64 的 `ADD W0, W1, W2` 指令（将 W1 和 W2 的值相加，结果存储到 W0）。 我们可以使用以下 Go 代码：

```go
package main

import (
	"fmt"
	"golang.org/x/arch/arm64/arm64asm"
)

func main() {
	inst := arm64asm.Inst{
		Op: arm64asm.ADD, // 假设 ADD 常量在 tables.go 中定义
		Args: arm64asm.Args{
			arm64asm.Reg(arm64asm.W0),
			arm64asm.Reg(arm64asm.W1),
			arm64asm.Reg(arm64asm.W2),
		},
	}
	fmt.Println(inst.String()) // 输出: ADD W0, W1, W2
}
```

**假设的输入与输出：**

* **假设输入:**  一个表示 ARM64 `MOV X0, #0x10` 指令的数据结构。
* **Go 代码:**
  ```go
  package main

  import (
  	"fmt"
  	"golang.org/x/arch/arm64/arm64asm"
  )

  func main() {
  	inst := arm64asm.Inst{
  		Op: arm64asm.MOV, // 假设 MOV 常量在 tables.go 中定义
  		Args: arm64asm.Args{
  			arm64asm.Reg(arm64asm.X0),
  			arm64asm.Imm{Imm: 0x10},
  			nil, nil, nil,
  		},
  	}
  	fmt.Println(inst.String())
  }
  ```
* **预期输出:**
  ```
  MOV X0, #0x10
  ```

**命令行参数的具体处理：**

这段代码本身主要定义数据结构，不太可能直接处理命令行参数。 命令行参数的处理通常发生在调用这些数据结构的上层代码中，例如汇编器或反汇编器的入口函数。

例如，一个 ARM64 汇编器可能会接收包含汇编代码的文件路径作为命令行参数：

```bash
go tool asm -arch=arm64 input.s output.o
```

在这个例子中，`input.s` 就是一个命令行参数，汇编器会读取这个文件，解析其中的汇编指令，并使用 `arm64asm.Inst` 等数据结构来表示这些指令。

**使用者易犯错的点：**

1. **错误的寄存器编号:**  错误地使用寄存器常量，例如将 `arm64asm.W100` 当作有效寄存器。 由于 `Reg` 类型是 `uint16`，超出定义的范围不会直接报错，但会在 `String()` 方法中输出 `Reg(错误的值)`，导致生成的汇编代码不正确。

   ```go
   inst := arm64asm.Inst{
       Op: arm64asm.ADD,
       Args: arm64asm.Args{
           arm64asm.Reg(1000), // 错误的寄存器编号
           arm64asm.Reg(arm64asm.W1),
           arm64asm.Reg(arm64asm.W2),
       },
   }
   fmt.Println(inst.String()) // 输出: ADD Reg(1000), W1, W2
   ```

2. **立即数格式错误:**  对于需要特定格式的立即数，如果格式不正确，可能会导致解析错误或生成错误的机器码。例如，`ImmShift` 需要指定移位类型和移位量。

   ```go
   inst := arm64asm.Inst{
       Op: arm64asm.MOV,
       Args: arm64asm.Args{
           arm64asm.Reg(arm64asm.X0),
           arm64asm.ImmShift{imm: 0x10}, // 缺少移位信息
           nil, nil, nil,
       },
   }
   fmt.Println(inst.String()) // 输出: MOV #0x10
   ```
   虽然输出了 `#0x10`，但在某些需要显式移位的情况下，这可能是错误的。

3. **寻址模式使用错误:**  对于内存访问指令，错误地使用寻址模式或提供不匹配的参数会导致错误。

   ```go
   inst := arm64asm.Inst{
       Op: arm64asm.LDR, // 假设 LDR 是加载指令
       Args: arm64asm.Args{
           arm64asm.Reg(arm64asm.X0),
           arm64asm.MemImmediate{Base: arm64asm.SP, Mode: arm64asm.AddrPreIndex}, // 缺少立即数偏移
           nil, nil, nil,
       },
   }
   fmt.Println(inst.String()) // 输出: LDR SP
   ```
   这里 `AddrPreIndex` 通常需要一个立即数偏移量，但没有提供。

理解这些数据结构及其关系对于编写和理解处理 ARM64 汇编代码的 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/arm64/arm64asm/inst.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm64asm

import (
	"fmt"
	"strings"
)

// An Op is an ARM64 opcode.
type Op uint16

// NOTE: The actual Op values are defined in tables.go.
// They are chosen to simplify instruction decoding and
// are not a dense packing from 0 to N, although the
// density is high, probably at least 90%.

func (op Op) String() string {
	if op >= Op(len(opstr)) || opstr[op] == "" {
		return fmt.Sprintf("Op(%d)", int(op))
	}
	return opstr[op]
}

// An Inst is a single instruction.
type Inst struct {
	Op   Op     // Opcode mnemonic
	Enc  uint32 // Raw encoding bits.
	Args Args   // Instruction arguments, in ARM manual order.
}

func (i Inst) String() string {
	var args []string
	for _, arg := range i.Args {
		if arg == nil {
			break
		}
		args = append(args, arg.String())
	}
	return i.Op.String() + " " + strings.Join(args, ", ")
}

// An Args holds the instruction arguments.
// If an instruction has fewer than 5 arguments,
// the final elements in the array are nil.
type Args [5]Arg

// An Arg is a single instruction argument, one of these types:
// Reg, RegSP, ImmShift, RegExtshiftAmount, PCRel, MemImmediate,
// MemExtend, Imm, Imm64, Imm_hint, Imm_clrex, Imm_dcps, Cond,
// Imm_c, Imm_option, Imm_prfop, Pstatefield, Systemreg, Imm_fp
// RegisterWithArrangement, RegisterWithArrangementAndIndex.
type Arg interface {
	isArg()
	String() string
}

// A Reg is a single register.
// The zero value denotes W0, not the absence of a register.
type Reg uint16

const (
	W0 Reg = iota
	W1
	W2
	W3
	W4
	W5
	W6
	W7
	W8
	W9
	W10
	W11
	W12
	W13
	W14
	W15
	W16
	W17
	W18
	W19
	W20
	W21
	W22
	W23
	W24
	W25
	W26
	W27
	W28
	W29
	W30
	WZR

	X0
	X1
	X2
	X3
	X4
	X5
	X6
	X7
	X8
	X9
	X10
	X11
	X12
	X13
	X14
	X15
	X16
	X17
	X18
	X19
	X20
	X21
	X22
	X23
	X24
	X25
	X26
	X27
	X28
	X29
	X30
	XZR

	B0
	B1
	B2
	B3
	B4
	B5
	B6
	B7
	B8
	B9
	B10
	B11
	B12
	B13
	B14
	B15
	B16
	B17
	B18
	B19
	B20
	B21
	B22
	B23
	B24
	B25
	B26
	B27
	B28
	B29
	B30
	B31

	H0
	H1
	H2
	H3
	H4
	H5
	H6
	H7
	H8
	H9
	H10
	H11
	H12
	H13
	H14
	H15
	H16
	H17
	H18
	H19
	H20
	H21
	H22
	H23
	H24
	H25
	H26
	H27
	H28
	H29
	H30
	H31

	S0
	S1
	S2
	S3
	S4
	S5
	S6
	S7
	S8
	S9
	S10
	S11
	S12
	S13
	S14
	S15
	S16
	S17
	S18
	S19
	S20
	S21
	S22
	S23
	S24
	S25
	S26
	S27
	S28
	S29
	S30
	S31

	D0
	D1
	D2
	D3
	D4
	D5
	D6
	D7
	D8
	D9
	D10
	D11
	D12
	D13
	D14
	D15
	D16
	D17
	D18
	D19
	D20
	D21
	D22
	D23
	D24
	D25
	D26
	D27
	D28
	D29
	D30
	D31

	Q0
	Q1
	Q2
	Q3
	Q4
	Q5
	Q6
	Q7
	Q8
	Q9
	Q10
	Q11
	Q12
	Q13
	Q14
	Q15
	Q16
	Q17
	Q18
	Q19
	Q20
	Q21
	Q22
	Q23
	Q24
	Q25
	Q26
	Q27
	Q28
	Q29
	Q30
	Q31

	V0
	V1
	V2
	V3
	V4
	V5
	V6
	V7
	V8
	V9
	V10
	V11
	V12
	V13
	V14
	V15
	V16
	V17
	V18
	V19
	V20
	V21
	V22
	V23
	V24
	V25
	V26
	V27
	V28
	V29
	V30
	V31

	WSP = WZR // These are different registers with the same encoding.
	SP  = XZR // These are different registers with the same encoding.
)

func (Reg) isArg() {}

func (r Reg) String() string {
	switch {
	case r == WZR:
		return "WZR"
	case r == XZR:
		return "XZR"
	case W0 <= r && r <= W30:
		return fmt.Sprintf("W%d", int(r-W0))
	case X0 <= r && r <= X30:
		return fmt.Sprintf("X%d", int(r-X0))

	case B0 <= r && r <= B31:
		return fmt.Sprintf("B%d", int(r-B0))
	case H0 <= r && r <= H31:
		return fmt.Sprintf("H%d", int(r-H0))
	case S0 <= r && r <= S31:
		return fmt.Sprintf("S%d", int(r-S0))
	case D0 <= r && r <= D31:
		return fmt.Sprintf("D%d", int(r-D0))
	case Q0 <= r && r <= Q31:
		return fmt.Sprintf("Q%d", int(r-Q0))

	case V0 <= r && r <= V31:
		return fmt.Sprintf("V%d", int(r-V0))
	default:
		return fmt.Sprintf("Reg(%d)", int(r))
	}
}

// A RegSP represent a register and X31/W31 is regarded as SP/WSP.
type RegSP Reg

func (RegSP) isArg() {}

func (r RegSP) String() string {
	switch Reg(r) {
	case WSP:
		return "WSP"
	case SP:
		return "SP"
	default:
		return Reg(r).String()
	}
}

type ImmShift struct {
	imm   uint16
	shift uint8
}

func (ImmShift) isArg() {}

func (is ImmShift) String() string {
	if is.shift == 0 {
		return fmt.Sprintf("#%#x", is.imm)
	}
	if is.shift < 128 {
		return fmt.Sprintf("#%#x, LSL #%d", is.imm, is.shift)
	}
	return fmt.Sprintf("#%#x, MSL #%d", is.imm, is.shift-128)
}

type ExtShift uint8

const (
	_ ExtShift = iota
	uxtb
	uxth
	uxtw
	uxtx
	sxtb
	sxth
	sxtw
	sxtx
	lsl
	lsr
	asr
	ror
)

func (extShift ExtShift) String() string {
	switch extShift {
	case uxtb:
		return "UXTB"

	case uxth:
		return "UXTH"

	case uxtw:
		return "UXTW"

	case uxtx:
		return "UXTX"

	case sxtb:
		return "SXTB"

	case sxth:
		return "SXTH"

	case sxtw:
		return "SXTW"

	case sxtx:
		return "SXTX"

	case lsl:
		return "LSL"

	case lsr:
		return "LSR"

	case asr:
		return "ASR"

	case ror:
		return "ROR"
	}
	return ""
}

type RegExtshiftAmount struct {
	reg       Reg
	extShift  ExtShift
	amount    uint8
	show_zero bool
}

func (RegExtshiftAmount) isArg() {}

func (rea RegExtshiftAmount) String() string {
	buf := rea.reg.String()
	if rea.extShift != ExtShift(0) {
		buf += ", " + rea.extShift.String()
		if rea.amount != 0 {
			buf += fmt.Sprintf(" #%d", rea.amount)
		} else {
			if rea.show_zero == true {
				buf += fmt.Sprintf(" #%d", rea.amount)
			}
		}
	}
	return buf
}

// A PCRel describes a memory address (usually a code label)
// as a distance relative to the program counter.
type PCRel int64

func (PCRel) isArg() {}

func (r PCRel) String() string {
	return fmt.Sprintf(".%+#x", uint64(r))
}

// An AddrMode is an ARM addressing mode.
type AddrMode uint8

const (
	_             AddrMode = iota
	AddrPostIndex          // [R], X - use address R, set R = R + X
	AddrPreIndex           // [R, X]! - use address R + X, set R = R + X
	AddrOffset             // [R, X] - use address R + X
	AddrPostReg            // [Rn], Rm - - use address Rn, set Rn = Rn + Rm
)

// A MemImmediate is a memory reference made up of a base R and immediate X.
// The effective memory address is R or R+X depending on AddrMode.
type MemImmediate struct {
	Base RegSP
	Mode AddrMode
	imm  int32
}

func (MemImmediate) isArg() {}

func (m MemImmediate) String() string {
	R := m.Base.String()
	X := fmt.Sprintf("#%d", m.imm)

	switch m.Mode {
	case AddrOffset:
		if X == "#0" {
			return fmt.Sprintf("[%s]", R)
		}
		return fmt.Sprintf("[%s,%s]", R, X)
	case AddrPreIndex:
		return fmt.Sprintf("[%s,%s]!", R, X)
	case AddrPostIndex:
		return fmt.Sprintf("[%s],%s", R, X)
	case AddrPostReg:
		post := Reg(X0) + Reg(m.imm)
		postR := post.String()
		return fmt.Sprintf("[%s], %s", R, postR)
	}
	return fmt.Sprintf("unimplemented!")
}

// A MemExtend is a memory reference made up of a base R and index expression X.
// The effective memory address is R or R+X depending on Index, Extend and Amount.
type MemExtend struct {
	Base   RegSP
	Index  Reg
	Extend ExtShift
	// Amount indicates the index shift amount (but also see ShiftMustBeZero field below).
	Amount uint8
	// Refer to ARM reference manual, for byte load/store(register), the index
	// shift amount must be 0, encoded in "S" as 0 if omitted, or as 1 if present.
	// a.ShiftMustBeZero is set true indicates the index shift amount must be 0.
	// In GNU syntax, a #0 shift amount is printed if Amount is 1 but ShiftMustBeZero
	// is true; #0 is not printed if Amount is 0 and ShiftMustBeZero is true.
	// Both cases represent shift by 0 bit.
	ShiftMustBeZero bool
}

func (MemExtend) isArg() {}

func (m MemExtend) String() string {
	Rbase := m.Base.String()
	RIndex := m.Index.String()
	if m.ShiftMustBeZero {
		if m.Amount != 0 {
			return fmt.Sprintf("[%s,%s,%s #0]", Rbase, RIndex, m.Extend.String())
		} else {
			if m.Extend != lsl {
				return fmt.Sprintf("[%s,%s,%s]", Rbase, RIndex, m.Extend.String())
			} else {
				return fmt.Sprintf("[%s,%s]", Rbase, RIndex)
			}
		}
	} else {
		if m.Amount != 0 {
			return fmt.Sprintf("[%s,%s,%s #%d]", Rbase, RIndex, m.Extend.String(), m.Amount)
		} else {
			if m.Extend != lsl {
				return fmt.Sprintf("[%s,%s,%s]", Rbase, RIndex, m.Extend.String())
			} else {
				return fmt.Sprintf("[%s,%s]", Rbase, RIndex)
			}
		}
	}
}

// An Imm is an integer constant.
type Imm struct {
	Imm     uint32
	Decimal bool
}

func (Imm) isArg() {}

func (i Imm) String() string {
	if !i.Decimal {
		return fmt.Sprintf("#%#x", i.Imm)
	} else {
		return fmt.Sprintf("#%d", i.Imm)
	}
}

type Imm64 struct {
	Imm     uint64
	Decimal bool
}

func (Imm64) isArg() {}

func (i Imm64) String() string {
	if !i.Decimal {
		return fmt.Sprintf("#%#x", i.Imm)
	} else {
		return fmt.Sprintf("#%d", i.Imm)
	}
}

// An Imm_hint is an integer constant for HINT instruction.
type Imm_hint uint8

func (Imm_hint) isArg() {}

func (i Imm_hint) String() string {
	return fmt.Sprintf("#%#x", uint32(i))
}

// An Imm_clrex is an integer constant for CLREX instruction.
type Imm_clrex uint8

func (Imm_clrex) isArg() {}

func (i Imm_clrex) String() string {
	if i == 15 {
		return ""
	}
	return fmt.Sprintf("#%#x", uint32(i))
}

// An Imm_dcps is an integer constant for DCPS[123] instruction.
type Imm_dcps uint16

func (Imm_dcps) isArg() {}

func (i Imm_dcps) String() string {
	if i == 0 {
		return ""
	}
	return fmt.Sprintf("#%#x", uint32(i))
}

// Standard conditions.
type Cond struct {
	Value  uint8
	Invert bool
}

func (Cond) isArg() {}

func (c Cond) String() string {
	cond31 := c.Value >> 1
	invert := bool((c.Value & 1) == 1)
	invert = (invert != c.Invert)
	switch cond31 {
	case 0:
		if invert {
			return "NE"
		} else {
			return "EQ"
		}
	case 1:
		if invert {
			return "CC"
		} else {
			return "CS"
		}
	case 2:
		if invert {
			return "PL"
		} else {
			return "MI"
		}
	case 3:
		if invert {
			return "VC"
		} else {
			return "VS"
		}
	case 4:
		if invert {
			return "LS"
		} else {
			return "HI"
		}
	case 5:
		if invert {
			return "LT"
		} else {
			return "GE"
		}
	case 6:
		if invert {
			return "LE"
		} else {
			return "GT"
		}
	case 7:
		return "AL"
	}
	return ""
}

// An Imm_c is an integer constant for SYS/SYSL/TLBI instruction.
type Imm_c uint8

func (Imm_c) isArg() {}

func (i Imm_c) String() string {
	return fmt.Sprintf("C%d", uint8(i))
}

// An Imm_option is an integer constant for DMB/DSB/ISB instruction.
type Imm_option uint8

func (Imm_option) isArg() {}

func (i Imm_option) String() string {
	switch uint8(i) {
	case 15:
		return "SY"
	case 14:
		return "ST"
	case 13:
		return "LD"
	case 11:
		return "ISH"
	case 10:
		return "ISHST"
	case 9:
		return "ISHLD"
	case 7:
		return "NSH"
	case 6:
		return "NSHST"
	case 5:
		return "NSHLD"
	case 3:
		return "OSH"
	case 2:
		return "OSHST"
	case 1:
		return "OSHLD"
	}
	return fmt.Sprintf("#%#02x", uint8(i))
}

// An Imm_prfop is an integer constant for PRFM instruction.
type Imm_prfop uint8

func (Imm_prfop) isArg() {}

func (i Imm_prfop) String() string {
	prf_type := (i >> 3) & (1<<2 - 1)
	prf_target := (i >> 1) & (1<<2 - 1)
	prf_policy := i & 1
	var result string

	switch prf_type {
	case 0:
		result = "PLD"
	case 1:
		result = "PLI"
	case 2:
		result = "PST"
	case 3:
		return fmt.Sprintf("#%#02x", uint8(i))
	}
	switch prf_target {
	case 0:
		result += "L1"
	case 1:
		result += "L2"
	case 2:
		result += "L3"
	case 3:
		return fmt.Sprintf("#%#02x", uint8(i))
	}
	if prf_policy == 0 {
		result += "KEEP"
	} else {
		result += "STRM"
	}
	return result
}

type Pstatefield uint8

const (
	SPSel Pstatefield = iota
	DAIFSet
	DAIFClr
)

func (Pstatefield) isArg() {}

func (p Pstatefield) String() string {
	switch p {
	case SPSel:
		return "SPSel"
	case DAIFSet:
		return "DAIFSet"
	case DAIFClr:
		return "DAIFClr"
	default:
		return "unimplemented"
	}
}

type Systemreg struct {
	op0 uint8
	op1 uint8
	cn  uint8
	cm  uint8
	op2 uint8
}

func (Systemreg) isArg() {}

func (s Systemreg) String() string {
	return fmt.Sprintf("S%d_%d_C%d_C%d_%d",
		s.op0, s.op1, s.cn, s.cm, s.op2)
}

// An Imm_fp is a signed floating-point constant.
type Imm_fp struct {
	s   uint8
	exp int8
	pre uint8
}

func (Imm_fp) isArg() {}

func (i Imm_fp) String() string {
	var s, pre, numerator, denominator int16
	var result float64
	if i.s == 0 {
		s = 1
	} else {
		s = -1
	}
	pre = s * int16(16+i.pre)
	if i.exp > 0 {
		numerator = (pre << uint8(i.exp))
		denominator = 16
	} else {
		numerator = pre
		denominator = (16 << uint8(-1*i.exp))
	}
	result = float64(numerator) / float64(denominator)
	return fmt.Sprintf("#%.18e", result)
}

type Arrangement uint8

const (
	_ Arrangement = iota
	ArrangementB
	Arrangement8B
	Arrangement16B
	ArrangementH
	Arrangement4H
	Arrangement8H
	ArrangementS
	Arrangement2S
	Arrangement4S
	ArrangementD
	Arrangement1D
	Arrangement2D
	Arrangement1Q
)

func (a Arrangement) String() (result string) {
	switch a {
	case ArrangementB:
		result = ".B"
	case Arrangement8B:
		result = ".8B"
	case Arrangement16B:
		result = ".16B"
	case ArrangementH:
		result = ".H"
	case Arrangement4H:
		result = ".4H"
	case Arrangement8H:
		result = ".8H"
	case ArrangementS:
		result = ".S"
	case Arrangement2S:
		result = ".2S"
	case Arrangement4S:
		result = ".4S"
	case ArrangementD:
		result = ".D"
	case Arrangement1D:
		result = ".1D"
	case Arrangement2D:
		result = ".2D"
	case Arrangement1Q:
		result = ".1Q"
	}
	return
}

// Register with arrangement: <Vd>.<T>, { <Vt>.8B, <Vt2>.8B},
type RegisterWithArrangement struct {
	r   Reg
	a   Arrangement
	cnt uint8
}

func (RegisterWithArrangement) isArg() {}

func (r RegisterWithArrangement) String() string {
	result := r.r.String()
	result += r.a.String()
	if r.cnt > 0 {
		result = "{" + result
		if r.cnt == 2 {
			r1 := V0 + Reg((uint16(r.r)-uint16(V0)+1)&31)
			result += ", " + r1.String() + r.a.String()
		} else if r.cnt > 2 {
			if (uint16(r.cnt) + ((uint16(r.r) - uint16(V0)) & 31)) > 32 {
				for i := 1; i < int(r.cnt); i++ {
					cur := V0 + Reg((uint16(r.r)-uint16(V0)+uint16(i))&31)
					result += ", " + cur.String() + r.a.String()
				}
			} else {
				r1 := V0 + Reg((uint16(r.r)-uint16(V0)+uint16(r.cnt)-1)&31)
				result += "-" + r1.String() + r.a.String()
			}
		}
		result += "}"
	}
	return result
}

// Register with arrangement and index:
//
//	<Vm>.<Ts>[<index>],
//	{ <Vt>.B, <Vt2>.B }[<index>].
type RegisterWithArrangementAndIndex struct {
	r     Reg
	a     Arrangement
	index uint8
	cnt   uint8
}

func (RegisterWithArrangementAndIndex) isArg() {}

func (r RegisterWithArrangementAndIndex) String() string {
	result := r.r.String()
	result += r.a.String()
	if r.cnt > 0 {
		result = "{" + result
		if r.cnt == 2 {
			r1 := V0 + Reg((uint16(r.r)-uint16(V0)+1)&31)
			result += ", " + r1.String() + r.a.String()
		} else if r.cnt > 2 {
			if (uint16(r.cnt) + ((uint16(r.r) - uint16(V0)) & 31)) > 32 {
				for i := 1; i < int(r.cnt); i++ {
					cur := V0 + Reg((uint16(r.r)-uint16(V0)+uint16(i))&31)
					result += ", " + cur.String() + r.a.String()
				}
			} else {
				r1 := V0 + Reg((uint16(r.r)-uint16(V0)+uint16(r.cnt)-1)&31)
				result += "-" + r1.String() + r.a.String()
			}
		}
		result += "}"
	}
	return fmt.Sprintf("%s[%d]", result, r.index)
}

type sysOp struct {
	op          sysInstFields
	r           Reg
	hasOperand2 bool
}

func (s sysOp) isArg() {}

func (s sysOp) String() string {
	result := s.op.String()
	// If s.hasOperand2 is false, the value in the register
	// specified by s.r is ignored.
	if s.hasOperand2 {
		result += ", " + s.r.String()
	}
	return result
}

type sysInstFields struct {
	op1 uint8
	cn  uint8
	cm  uint8
	op2 uint8
}

type sysInstAttrs struct {
	typ         sys
	name        string
	hasOperand2 bool
}

func (s sysInstFields) isArg() {}

func (s sysInstFields) getAttrs() sysInstAttrs {
	attrs, ok := sysInstsAttrs[sysInstFields{s.op1, s.cn, s.cm, s.op2}]
	if !ok {
		return sysInstAttrs{typ: sys_SYS}
	}
	return attrs
}

func (s sysInstFields) String() string {
	return s.getAttrs().name
}

func (s sysInstFields) getType() sys {
	return s.getAttrs().typ
}

var sysInstsAttrs = map[sysInstFields]sysInstAttrs{
	sysInstFields{0, 8, 3, 0}:  {sys_TLBI, "VMALLE1IS", false},
	sysInstFields{0, 8, 3, 1}:  {sys_TLBI, "VAE1IS", true},
	sysInstFields{0, 8, 3, 2}:  {sys_TLBI, "ASIDE1IS", true},
	sysInstFields{0, 8, 3, 3}:  {sys_TLBI, "VAAE1IS", true},
	sysInstFields{0, 8, 3, 5}:  {sys_TLBI, "VALE1IS", true},
	sysInstFields{0, 8, 3, 7}:  {sys_TLBI, "VAALE1IS", true},
	sysInstFields{0, 8, 7, 0}:  {sys_TLBI, "VMALLE1", false},
	sysInstFields{0, 8, 7, 1}:  {sys_TLBI, "VAE1", true},
	sysInstFields{0, 8, 7, 2}:  {sys_TLBI, "ASIDE1", true},
	sysInstFields{0, 8, 7, 3}:  {sys_TLBI, "VAAE1", true},
	sysInstFields{0, 8, 7, 5}:  {sys_TLBI, "VALE1", true},
	sysInstFields{0, 8, 7, 7}:  {sys_TLBI, "VAALE1", true},
	sysInstFields{4, 8, 0, 1}:  {sys_TLBI, "IPAS2E1IS", true},
	sysInstFields{4, 8, 0, 5}:  {sys_TLBI, "IPAS2LE1IS", true},
	sysInstFields{4, 8, 3, 0}:  {sys_TLBI, "ALLE2IS", false},
	sysInstFields{4, 8, 3, 1}:  {sys_TLBI, "VAE2IS", true},
	sysInstFields{4, 8, 3, 4}:  {sys_TLBI, "ALLE1IS", false},
	sysInstFields{4, 8, 3, 5}:  {sys_TLBI, "VALE2IS", true},
	sysInstFields{4, 8, 3, 6}:  {sys_TLBI, "VMALLS12E1IS", false},
	sysInstFields{4, 8, 4, 1}:  {sys_TLBI, "IPAS2E1", true},
	sysInstFields{4, 8, 4, 5}:  {sys_TLBI, "IPAS2LE1", true},
	sysInstFields{4, 8, 7, 0}:  {sys_TLBI, "ALLE2", false},
	sysInstFields{4, 8, 7, 1}:  {sys_TLBI, "VAE2", true},
	sysInstFields{4, 8, 7, 4}:  {sys_TLBI, "ALLE1", false},
	sysInstFields{4, 8, 7, 5}:  {sys_TLBI, "VALE2", true},
	sysInstFields{4, 8, 7, 6}:  {sys_TLBI, "VMALLS12E1", false},
	sysInstFields{6, 8, 3, 0}:  {sys_TLBI, "ALLE3IS", false},
	sysInstFields{6, 8, 3, 1}:  {sys_TLBI, "VAE3IS", true},
	sysInstFields{6, 8, 3, 5}:  {sys_TLBI, "VALE3IS", true},
	sysInstFields{6, 8, 7, 0}:  {sys_TLBI, "ALLE3", false},
	sysInstFields{6, 8, 7, 1}:  {sys_TLBI, "VAE3", true},
	sysInstFields{6, 8, 7, 5}:  {sys_TLBI, "VALE3", true},
	sysInstFields{0, 8, 1, 0}:  {sys_TLBI, "VMALLE1OS", false},
	sysInstFields{0, 8, 1, 1}:  {sys_TLBI, "VAE1OS", true},
	sysInstFields{0, 8, 1, 2}:  {sys_TLBI, "ASIDE1OS", true},
	sysInstFields{0, 8, 1, 3}:  {sys_TLBI, "VAAE1OS", true},
	sysInstFields{0, 8, 1, 5}:  {sys_TLBI, "VALE1OS", true},
	sysInstFields{0, 8, 1, 7}:  {sys_TLBI, "VAALE1OS", true},
	sysInstFields{0, 8, 2, 1}:  {sys_TLBI, "RVAE1IS", true},
	sysInstFields{0, 8, 2, 3}:  {sys_TLBI, "RVAAE1IS", true},
	sysInstFields{0, 8, 2, 5}:  {sys_TLBI, "RVALE1IS", true},
	sysInstFields{0, 8, 2, 7}:  {sys_TLBI, "RVAALE1IS", true},
	sysInstFields{0, 8, 5, 1}:  {sys_TLBI, "RVAE1OS", true},
	sysInstFields{0, 8, 5, 3}:  {sys_TLBI, "RVAAE1OS", true},
	sysInstFields{0, 8, 5, 5}:  {sys_TLBI, "RVALE1OS", true},
	sysInstFields{0, 8, 5, 7}:  {sys_TLBI, "RVAALE1OS", true},
	sysInstFields{0, 8, 6, 1}:  {sys_TLBI, "RVAE1", true},
	sysInstFields{0, 8, 6, 3}:  {sys_TLBI, "RVAAE1", true},
	sysInstFields{0, 8, 6, 5}:  {sys_TLBI, "RVALE1", true},
	sysInstFields{0, 8, 6, 7}:  {sys_TLBI, "RVAALE1", true},
	sysInstFields{4, 8, 0, 2}:  {sys_TLBI, "RIPAS2E1IS", true},
	sysInstFields{4, 8, 0, 6}:  {sys_TLBI, "RIPAS2LE1IS", true},
	sysInstFields{4, 8, 1, 0}:  {sys_TLBI, "ALLE2OS", false},
	sysInstFields{4, 8, 1, 1}:  {sys_TLBI, "VAE2OS", true},
	sysInstFields{4, 8, 1, 4}:  {sys_TLBI, "ALLE1OS", false},
	sysInstFields{4, 8, 1, 5}:  {sys_TLBI, "VALE2OS", true},
	sysInstFields{4, 8, 1, 6}:  {sys_TLBI, "VMALLS12E1OS", false},
	sysInstFields{4, 8, 2, 1}:  {sys_TLBI, "RVAE2IS", true},
	sysInstFields{4, 8, 2, 5}:  {sys_TLBI, "RVALE2IS", true},
	sysInstFields{4, 8, 4, 0}:  {sys_TLBI, "IPAS2E1OS", true},
	sysInstFields{4, 8, 4, 2}:  {sys_TLBI, "RIPAS2E1", true},
	sysInstFields{4, 8, 4, 3}:  {sys_TLBI, "RIPAS2E1OS", true},
	sysInstFields{4, 8, 4, 4}:  {sys_TLBI, "IPAS2LE1OS", true},
	sysInstFields{4, 8, 4, 6}:  {sys_TLBI, "RIPAS2LE1", true},
	sysInstFields{4, 8, 4, 7}:  {sys_TLBI, "RIPAS2LE1OS", true},
	sysInstFields{4, 8, 5, 1}:  {sys_TLBI, "RVAE2OS", true},
	sysInstFields{4, 8, 5, 5}:  {sys_TLBI, "RVALE2OS", true},
	sysInstFields{4, 8, 6, 1}:  {sys_TLBI, "RVAE2", true},
	sysInstFields{4, 8, 6, 5}:  {sys_TLBI, "RVALE2", true},
	sysInstFields{6, 8, 1, 0}:  {sys_TLBI, "ALLE3OS", false},
	sysInstFields{6, 8, 1, 1}:  {sys_TLBI, "VAE3OS", true},
	sysInstFields{6, 8, 1, 5}:  {sys_TLBI, "VALE3OS", true},
	sysInstFields{6, 8, 2, 1}:  {sys_TLBI, "RVAE3IS", true},
	sysInstFields{6, 8, 2, 5}:  {sys_TLBI, "RVALE3IS", true},
	sysInstFields{6, 8, 5, 1}:  {sys_TLBI, "RVAE3OS", true},
	sysInstFields{6, 8, 5, 5}:  {sys_TLBI, "RVALE3OS", true},
	sysInstFields{6, 8, 6, 1}:  {sys_TLBI, "RVAE3", true},
	sysInstFields{6, 8, 6, 5}:  {sys_TLBI, "RVALE3", true},
	sysInstFields{0, 7, 6, 1}:  {sys_DC, "IVAC", true},
	sysInstFields{0, 7, 6, 2}:  {sys_DC, "ISW", true},
	sysInstFields{0, 7, 10, 2}: {sys_DC, "CSW", true},
	sysInstFields{0, 7, 14, 2}: {sys_DC, "CISW", true},
	sysInstFields{3, 7, 4, 1}:  {sys_DC, "ZVA", true},
	sysInstFields{3, 7, 10, 1}: {sys_DC, "CVAC", true},
	sysInstFields{3, 7, 11, 1}: {sys_DC, "CVAU", true},
	sysInstFields{3, 7, 14, 1}: {sys_DC, "CIVAC", true},
	sysInstFields{0, 7, 6, 3}:  {sys_DC, "IGVAC", true},
	sysInstFields{0, 7, 6, 4}:  {sys_DC, "IGSW", true},
	sysInstFields{0, 7, 6, 5}:  {sys_DC, "IGDVAC", true},
	sysInstFields{0, 7, 6, 6}:  {sys_DC, "IGDSW", true},
	sysInstFields{0, 7, 10, 4}: {sys_DC, "CGSW", true},
	sysInstFields{0, 7, 10, 6}: {sys_DC, "CGDSW", true},
	sysInstFields{0, 7, 14, 4}: {sys_DC, "CIGSW", true},
	sysInstFields{0, 7, 14, 6}: {sys_DC, "CIGDSW", true},
	sysInstFields{3, 7, 4, 3}:  {sys_DC, "GVA", true},
	sysInstFields{3, 7, 4, 4}:  {sys_DC, "GZVA", true},
	sysInstFields{3, 7, 10, 3}: {sys_DC, "CGVAC", true},
	sysInstFields{3, 7, 10, 5}: {sys_DC, "CGDVAC", true},
	sysInstFields{3, 7, 12, 3}: {sys_DC, "CGVAP", true},
	sysInstFields{3, 7, 12, 5}: {sys_DC, "CGDVAP", true},
	sysInstFields{3, 7, 13, 3}: {sys_DC, "CGVADP", true},
	sysInstFields{3, 7, 13, 5}: {sys_DC, "CGDVADP", true},
	sysInstFields{3, 7, 14, 3}: {sys_DC, "CIGVAC", true},
	sysInstFields{3, 7, 14, 5}: {sys_DC, "CIGDVAC", true},
	sysInstFields{3, 7, 12, 1}: {sys_DC, "CVAP", true},
	sysInstFields{3, 7, 13, 1}: {sys_DC, "CVADP", true},
}

"""



```