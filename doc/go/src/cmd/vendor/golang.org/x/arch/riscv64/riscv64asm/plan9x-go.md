Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding of the Goal:**

The core task is to analyze a Go function `GoSyntax` within the `riscv64asm` package. The function's purpose is to convert a RISC-V instruction (`Inst`) into its Plan 9 assembly syntax. Key inputs are the instruction itself, the program counter (`pc`), a symbol resolution function (`symname`), and a reader for the text segment (`text`).

**2. Deconstructing the Function `GoSyntax`:**

* **Input Analysis:** Identify the types and roles of the input parameters: `Inst`, `uint64` (pc), `func(uint64) (string, uint64)` (symname), `io.ReaderAt` (text). Notice the `symname` function is crucial for handling symbolic addresses.

* **Core Logic - Iterating Through Arguments:** The code iterates through the `inst.Args` and calls `plan9Arg` for each. This suggests `plan9Arg` is responsible for formatting individual arguments.

* **Opcode Handling (the `switch` statement):**  A large `switch` statement operates on `inst.Op`. This immediately signals that different RISC-V instructions require special formatting or have Plan 9 equivalents. Start noticing patterns:
    * **Atomic Instructions:** The `AMO...` and `SC...` cases have a specific operand swap.
    * **Immediate Instructions:** `ADDI`, `ADDIW`, `ANDI` have special cases for immediate values of 0 or 255, often being translated to `MOV` or other instructions.
    * **Branch Instructions:** `BEQ`, `BGE`, `BLT`, `BNE`, `BLTU`, `BGEU` have variations based on comparisons with zero and operand order changes.
    * **CSR Instructions:** `CSRRW` and `CSRRS` handle Control and Status Register operations, with specific Plan 9 mnemonics.
    * **Load/Store Instructions:** `LD`, `SD`, `LB`, `SB`, etc., are often translated to `MOV` with size suffixes.
    * **Floating-Point Instructions:** `FMADD...`, `FMSUB...`, `FSGNJ...`, etc., involve operand reordering.
    * **Jump Instructions:** `JAL`, `JALR` have special cases for `X0` and `X1` registers, translating to `JMP`, `CALL`, or `RET`.

* **Post-Processing:** After the `switch`, the code reverses the order of arguments and removes suffixes like `.AQRL`, `.AQ`, and `.RL` from the opcode.

* **Output:** The function returns a `string` representing the Plan 9 assembly syntax.

**3. Deconstructing the Function `plan9Arg`:**

* **Input:** Takes an `Inst` pointer, `pc`, `symname`, and a single `Arg` interface.
* **Argument Type Handling (the `switch` statement):**  Another `switch` statement handles different types of instruction arguments:
    * `Uimm` (Unsigned Immediate): Formatted with a `$`.
    * `Simm` (Signed Immediate):  Has logic to check if it represents a symbolic address relative to the PC. If so, format it as `symbol(SB)` or `offset(PC)`. Otherwise, format as `$`.
    * `Reg` (Register): Formatted as `Xn` or `Fn`.
    * `RegOffset` (Register with Offset): Formatted as `offset(Xn)` or `(Xn)` if the offset is zero.
    * `AmoReg` (Atomic Memory Operation Register): Formatted as `(Xn)`.
    * `default`:  Converts the argument to uppercase string.

**4. Identifying the Go Feature:**

The code is clearly part of an assembler or disassembler for the RISC-V 64-bit architecture. Specifically, it's focused on *disassembly* – converting machine code instructions into a human-readable assembly language format. The reference to "Plan 9" indicates a specific assembly syntax convention.

**5. Code Examples and Reasoning:**

Now, let's create examples to illustrate the transformations:

* **Simple ADD Immediate:**  A basic case to show the translation.
* **Load from Memory:** Demonstrates the handling of `RegOffset` and the translation to `MOV`.
* **Branch Equal Zero:** Shows the special case for comparisons with zero.
* **Jump to Label:** Illustrates the symbolic address handling using `symname`.

For each example:
    * **Input `Inst`:** Construct a representative `Inst` value, including the opcode and arguments.
    * **Assumptions:** Specify assumptions for `pc` and the behavior of `symname`.
    * **Expected Output:** Manually determine the expected Plan 9 syntax based on the code logic.

**6. Command-Line Arguments (If Applicable):**

In this specific code snippet, there's no direct handling of command-line arguments. The `GoSyntax` function is called programmatically. If this were part of a larger assembler/disassembler tool, the command-line argument processing would likely occur in the `main` function or a dedicated argument parsing library. We should explain this.

**7. Common Mistakes:**

Analyze the code for potential pitfalls for users:

* **Incorrect `symname` Implementation:**  If the provided `symname` function doesn't accurately map addresses to symbols, the disassembled output will have incorrect symbolic labels. Provide an example.
* **Understanding Plan 9 Syntax Differences:** Emphasize that the output follows Plan 9 conventions, which might differ from other RISC-V assembly syntaxes (like GNU AS).

**8. Review and Refine:**

Read through the analysis, examples, and explanations. Ensure clarity, accuracy, and completeness. Are there any edge cases or subtleties in the code that need further explanation?  Is the reasoning easy to follow?

This structured approach helps to thoroughly understand the code's functionality, identify the relevant Go features, provide illustrative examples, and highlight potential areas of confusion for users. The key is to systematically break down the code, understand the purpose of each part, and then synthesize that understanding into a coherent explanation.
这是 `go/src/cmd/vendor/golang.org/x/arch/riscv64/riscv64asm/plan9x.go` 文件中 `GoSyntax` 函数的实现。这个函数的主要功能是将 RISC-V 64位指令 (类型为 `Inst`) 转换为 Plan 9 汇编器的语法表示。

以下是 `GoSyntax` 函数的详细功能分解：

**1. 指令到 Plan 9 汇编语法的转换:**

   -  `GoSyntax` 接收一个 `Inst` 类型的 RISC-V 指令，以及一些辅助信息，如程序计数器 (`pc`)、符号表查询函数 (`symname`) 和用于读取代码段的 `io.ReaderAt`。
   -  它根据 RISC-V 指令的操作码 (`inst.Op`) 和操作数 (`inst.Args`)，将其转换为符合 Plan 9 汇编器语法的字符串。
   -  Plan 9 汇编语法在指令助记符和操作数顺序上可能与其他汇编语法（如 GNU AS）有所不同。

**2. 处理符号名:**

   -  `symname` 函数允许将指令中使用的地址解析为符号名。这对于理解跳转目标和数据访问非常重要。
   -  如果提供了 `symname` 函数，`GoSyntax` 会在处理 PC 相对地址时调用它，以尝试将地址转换为符号名。
   -  如果 `symname` 为 `nil`，则会使用一个默认的匿名函数，该函数总是返回空字符串和 0。

**3. 处理 PC 相对地址:**

   -  对于跳转指令和某些加载/存储指令，目标地址通常是相对于程序计数器的偏移量。
   -  `GoSyntax` 使用 `pc` 和 `symname` 来将这些相对地址转换为绝对地址，并尝试解析为符号名。
   -  如果成功解析为符号名，则使用 `symbol(SB)` 的格式，否则使用 `offset(PC)` 的格式。

**4. 指令特定语法的调整:**

   -  `GoSyntax` 中有一个大的 `switch` 语句，针对不同的 RISC-V 指令进行特定的语法调整，以符合 Plan 9 的习惯。
   -  例如：
      -  原子操作指令 (`AMOADD_D` 等) 的操作数顺序被调整。
      -  `ADDI` 指令在立即数为 0 时被转换为 `MOV`。
      -  分支指令 (`BEQ`, `BGE` 等) 在与零比较时有特殊的助记符 (`BEQZ`, `BGEZ` 等)。
      -  CSR 读写指令 (`CSRRW`, `CSRRS`) 被转换为 Plan 9 中对应的 `FSCSR`, `FRCSR` 等。
      -  加载/存储指令 (`LD`, `SD`, `LB`, `SB` 等) 的助记符被简化为 `MOV`，并通过后缀表示数据大小 (`B`, `H`, `W`, `D`)。
      -  部分指令的操作数顺序会被反转，以将目标操作数放在最后。

**5. `plan9Arg` 函数:**

   -  `plan9Arg` 是一个辅助函数，用于将单个指令操作数 (`Arg` 接口类型) 转换为 Plan 9 汇编语法的字符串表示。
   -  它处理不同类型的操作数，如立即数 (`Uimm`, `Simm`)、寄存器 (`Reg`) 和寄存器偏移 (`RegOffset`)。
   -  对于立即数，它会根据上下文（例如，是否是分支指令的偏移量）选择不同的格式。
   -  对于寄存器，它会将其转换为 `Xn` (通用寄存器) 或 `Fn` (浮点寄存器) 的格式。

**可以推理出它是一个 RISC-V 汇编器的反汇编功能实现。**  它将机器码指令转换回可读的汇编代码，并使用特定的 Plan 9 汇编语法风格。

**Go 代码举例说明:**

假设我们有以下 RISC-V 指令：将寄存器 `X1` 的值加 5 并存储到 `X2` 中。

```go
package main

import (
	"fmt"
	"go/src/cmd/vendor/golang.org/x/arch/riscv64/riscv64asm"
	"strings"
)

func main() {
	inst := riscv64asm.Inst{
		Op: riscv64asm.ADDI,
		Args: []riscv64asm.Arg{
			riscv64asm.Reg(2), // X2
			riscv64asm.Reg(1), // X1
			riscv64asm.Simm{Imm: 5},
		},
	}

	pc := uint64(0x1000) // 假设指令的地址是 0x1000
	symname := func(addr uint64) (string, uint64) {
		// 简单的符号表查找示例
		if addr == 0x2000 {
			return "my_variable", 0x2000
		}
		return "", 0
	}

	// 这里我们不需要实际的 text reader，因为这个例子中没有涉及 PC 相对加载
	var text strings.Reader

	plan9Syntax := riscv64asm.GoSyntax(inst, pc, symname, &text)
	fmt.Println(plan9Syntax) // 输出: MOV X1, $5, X2
}
```

**假设的输入与输出:**

- **输入 `inst`:**  一个 `riscv64asm.Inst` 结构体，表示 `ADDI X2, X1, 5` 指令。
- **输入 `pc`:** `0x1000` (指令的程序计数器)。
- **输入 `symname`:**  一个简单的符号表查找函数。
- **输入 `text`:**  一个空的 `strings.Reader`，因为本例中不涉及 PC 相对加载。
- **输出 `plan9Syntax`:**  字符串 `"MOV X1, $5, X2"`。  注意 Plan 9 语法将 `ADDI` 转换为 `MOV`，并将目标寄存器放在最后。

**涉及命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。它是一个用于指令格式化的函数。如果这个函数被用在一个完整的反汇编器中，那么命令行参数的处理会在调用 `GoSyntax` 的代码中进行。

例如，一个反汇编器可能会接受一个包含机器码的文件路径作为命令行参数，然后读取文件，解码指令，并使用 `GoSyntax` 将其转换为汇编代码。

**使用者易犯错的点:**

1. **不理解 Plan 9 汇编语法:**  使用者可能习惯于 GNU AS 等其他汇编语法，而 Plan 9 在指令助记符和操作数顺序上有所不同。例如，`ADDI rd, rs1, imm` 在 Plan 9 中会被转换为 `MOV rs1, $imm, rd`。

   ```go
   // RISC-V 汇编: addi x2, x1, 10
   inst := riscv64asm.Inst{
       Op: riscv64asm.ADDI,
       Args: []riscv64asm.Arg{riscv64asm.Reg(2), riscv64asm.Reg(1), riscv64asm.Simm{Imm: 10}},
   }
   // Plan 9 汇编: MOV X1, $10, X2
   ```

2. **符号表处理不当:**  如果 `symname` 函数的实现不正确，或者没有提供必要的符号信息，则反汇编输出可能无法正确显示符号名，导致理解困难。

   ```go
   // 假设一个跳转指令，目标地址应该是一个符号
   inst := riscv64asm.Inst{
       Op: riscv64asm.JAL,
       Args: []riscv64asm.Arg{riscv64asm.Reg(1), riscv64asm.Simm{Imm: 0x100}}, // 相对地址偏移
   }
   pc := uint64(0x1000)

   // 如果 symname 没有正确解析地址 0x1100 (0x1000 + 0x100)，则会显示偏移
   symnameWithoutSymbol := func(addr uint64) (string, uint64) { return "", 0 }
   var text strings.Reader
   fmt.Println(riscv64asm.GoSyntax(inst, pc, symnameWithoutSymbol, &text)) // 可能输出: JMP 256(PC), X1

   // 如果 symname 正确解析
   symnameWithSymbol := func(addr uint64) (string, uint64) {
       if addr == 0x1100 {
           return "target_label", 0x1100
       }
       return "", 0
   }
   fmt.Println(riscv64asm.GoSyntax(inst, pc, symnameWithSymbol, &text)) // 可能输出: JMP target_label(SB), X1
   ```

3. **对 PC 相对地址的理解偏差:**  使用者可能不清楚 `GoSyntax` 如何处理 PC 相对地址，以及 `symname` 函数在其中的作用。如果 `symname` 返回的基地址不正确，可能会导致计算出的符号地址错误。

总而言之，`GoSyntax` 函数是 RISC-V 反汇编过程中的一个关键部分，它负责将机器指令翻译成人类可读的 Plan 9 汇编表示。理解 Plan 9 语法以及符号表处理对于正确使用和解释其输出至关重要。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/riscv64/riscv64asm/plan9x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package riscv64asm

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// GoSyntax returns the Go assembler syntax for the instruction.
// The syntax was originally defined by Plan 9.
// The pc is the program counter of the instruction, used for
// expanding PC-relative addresses into absolute ones.
// The symname function queries the symbol table for the program
// being disassembled. Given a target address it returns the name
// and base address of the symbol containing the target, if any;
// otherwise it returns "", 0.
// The reader text should read from the text segment using text addresses
// as offsets; it is used to display pc-relative loads as constant loads.
func GoSyntax(inst Inst, pc uint64, symname func(uint64) (string, uint64), text io.ReaderAt) string {
	if symname == nil {
		symname = func(uint64) (string, uint64) { return "", 0 }
	}

	var args []string
	for _, a := range inst.Args {
		if a == nil {
			break
		}
		args = append(args, plan9Arg(&inst, pc, symname, a))
	}

	op := inst.Op.String()

	switch inst.Op {

	case AMOADD_D, AMOADD_D_AQ, AMOADD_D_RL, AMOADD_D_AQRL, AMOADD_W, AMOADD_W_AQ,
		AMOADD_W_RL, AMOADD_W_AQRL, AMOAND_D, AMOAND_D_AQ, AMOAND_D_RL, AMOAND_D_AQRL,
		AMOAND_W, AMOAND_W_AQ, AMOAND_W_RL, AMOAND_W_AQRL, AMOMAXU_D, AMOMAXU_D_AQ,
		AMOMAXU_D_RL, AMOMAXU_D_AQRL, AMOMAXU_W, AMOMAXU_W_AQ, AMOMAXU_W_RL, AMOMAXU_W_AQRL,
		AMOMAX_D, AMOMAX_D_AQ, AMOMAX_D_RL, AMOMAX_D_AQRL, AMOMAX_W, AMOMAX_W_AQ, AMOMAX_W_RL,
		AMOMAX_W_AQRL, AMOMINU_D, AMOMINU_D_AQ, AMOMINU_D_RL, AMOMINU_D_AQRL, AMOMINU_W,
		AMOMINU_W_AQ, AMOMINU_W_RL, AMOMINU_W_AQRL, AMOMIN_D, AMOMIN_D_AQ, AMOMIN_D_RL,
		AMOMIN_D_AQRL, AMOMIN_W, AMOMIN_W_AQ, AMOMIN_W_RL, AMOMIN_W_AQRL, AMOOR_D, AMOOR_D_AQ,
		AMOOR_D_RL, AMOOR_D_AQRL, AMOOR_W, AMOOR_W_AQ, AMOOR_W_RL, AMOOR_W_AQRL, AMOSWAP_D,
		AMOSWAP_D_AQ, AMOSWAP_D_RL, AMOSWAP_D_AQRL, AMOSWAP_W, AMOSWAP_W_AQ, AMOSWAP_W_RL,
		AMOSWAP_W_AQRL, AMOXOR_D, AMOXOR_D_AQ, AMOXOR_D_RL, AMOXOR_D_AQRL, AMOXOR_W,
		AMOXOR_W_AQ, AMOXOR_W_RL, AMOXOR_W_AQRL, SC_D, SC_D_AQ, SC_D_RL, SC_D_AQRL,
		SC_W, SC_W_AQ, SC_W_RL, SC_W_AQRL:
		// Atomic instructions have special operand order.
		args[2], args[1] = args[1], args[2]

	case ADDI:
		if inst.Args[2].(Simm).Imm == 0 {
			op = "MOV"
			args = args[:len(args)-1]
		}

	case ADDIW:
		if inst.Args[2].(Simm).Imm == 0 {
			op = "MOVW"
			args = args[:len(args)-1]
		}

	case ANDI:
		if inst.Args[2].(Simm).Imm == 255 {
			op = "MOVBU"
			args = args[:len(args)-1]
		}

	case BEQ:
		if inst.Args[1].(Reg) == X0 {
			op = "BEQZ"
			args[1] = args[2]
			args = args[:len(args)-1]
		}
		for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
			args[i], args[j] = args[j], args[i]
		}

	case BGE:
		if inst.Args[1].(Reg) == X0 {
			op = "BGEZ"
			args[1] = args[2]
			args = args[:len(args)-1]
		}
		for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
			args[i], args[j] = args[j], args[i]
		}

	case BLT:
		if inst.Args[1].(Reg) == X0 {
			op = "BLTZ"
			args[1] = args[2]
			args = args[:len(args)-1]
		}
		for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
			args[i], args[j] = args[j], args[i]
		}

	case BNE:
		if inst.Args[1].(Reg) == X0 {
			op = "BNEZ"
			args[1] = args[2]
			args = args[:len(args)-1]
		}
		for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
			args[i], args[j] = args[j], args[i]
		}

	case BLTU, BGEU:
		for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
			args[i], args[j] = args[j], args[i]
		}

	case CSRRW:
		switch inst.Args[1].(CSR) {
		case FCSR:
			op = "FSCSR"
			args[1] = args[2]
			args = args[:len(args)-1]
		case FFLAGS:
			op = "FSFLAGS"
			args[1] = args[2]
			args = args[:len(args)-1]
		case FRM:
			op = "FSRM"
			args[1] = args[2]
			args = args[:len(args)-1]
		case CYCLE:
			if inst.Args[0].(Reg) == X0 && inst.Args[2].(Reg) == X0 {
				op = "UNIMP"
				args = nil
			}
		}

	case CSRRS:
		if inst.Args[2].(Reg) == X0 {
			switch inst.Args[1].(CSR) {
			case FCSR:
				op = "FRCSR"
				args = args[:len(args)-2]
			case FFLAGS:
				op = "FRFLAGS"
				args = args[:len(args)-2]
			case FRM:
				op = "FRRM"
				args = args[:len(args)-2]
			case CYCLE:
				op = "RDCYCLE"
				args = args[:len(args)-2]
			case CYCLEH:
				op = "RDCYCLEH"
				args = args[:len(args)-2]
			case INSTRET:
				op = "RDINSTRET"
				args = args[:len(args)-2]
			case INSTRETH:
				op = "RDINSTRETH"
				args = args[:len(args)-2]
			case TIME:
				op = "RDTIME"
				args = args[:len(args)-2]
			case TIMEH:
				op = "RDTIMEH"
				args = args[:len(args)-2]
			}
		}

	// Fence instruction in plan9 doesn't have any operands.
	case FENCE:
		args = nil

	case FMADD_D, FMADD_H, FMADD_Q, FMADD_S, FMSUB_D, FMSUB_H,
		FMSUB_Q, FMSUB_S, FNMADD_D, FNMADD_H, FNMADD_Q, FNMADD_S,
		FNMSUB_D, FNMSUB_H, FNMSUB_Q, FNMSUB_S:
		args[1], args[3] = args[3], args[1]

	case FSGNJ_S:
		if inst.Args[2] == inst.Args[1] {
			op = "MOVF"
			args = args[:len(args)-1]
		}

	case FSGNJ_D:
		if inst.Args[2] == inst.Args[1] {
			op = "MOVD"
			args = args[:len(args)-1]
		}

	case FSGNJX_S:
		if inst.Args[2] == inst.Args[1] {
			op = "FABSS"
			args = args[:len(args)-1]
		}

	case FSGNJX_D:
		if inst.Args[2] == inst.Args[1] {
			op = "FABSD"
			args = args[:len(args)-1]
		}

	case FSGNJN_S:
		if inst.Args[2] == inst.Args[1] {
			op = "FNEGS"
			args = args[:len(args)-1]
		}

	case FSGNJN_D:
		if inst.Args[2] == inst.Args[1] {
			op = "FNESD"
			args = args[:len(args)-1]
		}

	case LD, SD:
		op = "MOV"
		if inst.Op == SD {
			args[0], args[1] = args[1], args[0]
		}

	case LB, SB:
		op = "MOVB"
		if inst.Op == SB {
			args[0], args[1] = args[1], args[0]
		}

	case LH, SH:
		op = "MOVH"
		if inst.Op == SH {
			args[0], args[1] = args[1], args[0]
		}

	case LW, SW:
		op = "MOVW"
		if inst.Op == SW {
			args[0], args[1] = args[1], args[0]
		}

	case LBU:
		op = "MOVBU"

	case LHU:
		op = "MOVHU"

	case LWU:
		op = "MOVWU"

	case FLW, FSW:
		op = "MOVF"
		if inst.Op == FLW {
			args[0], args[1] = args[1], args[0]
		}

	case FLD, FSD:
		op = "MOVD"
		if inst.Op == FLD {
			args[0], args[1] = args[1], args[0]
		}

	case SUB:
		if inst.Args[1].(Reg) == X0 {
			op = "NEG"
			args[1] = args[2]
			args = args[:len(args)-1]
		}

	case XORI:
		if inst.Args[2].(Simm).String() == "-1" {
			op = "NOT"
			args = args[:len(args)-1]
		}

	case SLTIU:
		if inst.Args[2].(Simm).Imm == 1 {
			op = "SEQZ"
			args = args[:len(args)-1]
		}

	case SLTU:
		if inst.Args[1].(Reg) == X0 {
			op = "SNEZ"
			args[1] = args[2]
			args = args[:len(args)-1]
		}

	case JAL:
		if inst.Args[0].(Reg) == X0 {
			op = "JMP"
			args[0] = args[1]
			args = args[:len(args)-1]
		} else if inst.Args[0].(Reg) == X1 {
			op = "CALL"
			args[0] = args[1]
			args = args[:len(args)-1]
		} else {
			args[0], args[1] = args[1], args[0]
		}

	case JALR:
		if inst.Args[0].(Reg) == X0 {
			if inst.Args[1].(RegOffset).OfsReg == X1 && inst.Args[1].(RegOffset).Ofs.Imm == 0 {
				op = "RET"
				args = nil
				break
			}
			op = "JMP"
			args[0] = args[1]
			args = args[:len(args)-1]
		} else if inst.Args[0].(Reg) == X1 {
			op = "CALL"
			args[0] = args[1]
			args = args[:len(args)-1]
		} else {
			args[0], args[1] = args[1], args[0]
		}
	}

	// Reverse args, placing dest last.
	for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
		args[i], args[j] = args[j], args[i]
	}

	// Change to plan9 opcode format
	// Atomic instructions do not have reorder suffix, so remove them
	op = strings.Replace(op, ".AQRL", "", -1)
	op = strings.Replace(op, ".AQ", "", -1)
	op = strings.Replace(op, ".RL", "", -1)
	op = strings.Replace(op, ".", "", -1)

	if args != nil {
		op += " " + strings.Join(args, ", ")
	}

	return op
}

func plan9Arg(inst *Inst, pc uint64, symname func(uint64) (string, uint64), arg Arg) string {
	switch a := arg.(type) {
	case Uimm:
		return fmt.Sprintf("$%d", uint32(a.Imm))

	case Simm:
		imm, _ := strconv.Atoi(a.String())
		if a.Width == 13 || a.Width == 21 {
			addr := int64(pc) + int64(imm)
			if s, base := symname(uint64(addr)); s != "" && uint64(addr) == base {
				return fmt.Sprintf("%s(SB)", s)
			}
			return fmt.Sprintf("%d(PC)", imm/4)
		}
		return fmt.Sprintf("$%d", int32(imm))

	case Reg:
		if a <= 31 {
			return fmt.Sprintf("X%d", a)
		} else {
			return fmt.Sprintf("F%d", a-32)
		}

	case RegOffset:
		if a.Ofs.Imm == 0 {
			return fmt.Sprintf("(X%d)", a.OfsReg)
		} else {
			return fmt.Sprintf("%s(X%d)", a.Ofs.String(), a.OfsReg)
		}

	case AmoReg:
		return fmt.Sprintf("(X%d)", a.reg)

	default:
		return strings.ToUpper(arg.String())
	}
}
```