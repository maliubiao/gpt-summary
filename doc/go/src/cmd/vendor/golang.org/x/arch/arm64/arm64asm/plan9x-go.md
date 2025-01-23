Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understanding the Goal:** The core request is to understand the *functionality* of the `plan9x.go` file. This immediately signals that we need to look at the exposed functions and their purpose. The file path hints at assembly generation for ARM64 using Plan 9 syntax.

2. **Identifying the Key Function:**  The most prominent function in the code is `GoSyntax`. Its name and signature (`func GoSyntax(inst Inst, pc uint64, symname func(uint64) (string, uint64), text io.ReaderAt) string`) strongly suggest it's responsible for converting an instruction (`Inst`) into its string representation in Go assembler syntax (specifically Plan 9). The other parameters likely provide context needed for this conversion.

3. **Analyzing `GoSyntax`'s Logic:**

   * **Input Processing:** The function takes an `Inst`, program counter (`pc`), a symbol resolution function (`symname`), and a text reader (`text`). The `symname` and `text` parameters are for handling PC-relative addresses and potentially constant loading.

   * **Argument Handling:**  The code iterates through `inst.Args`, calling `plan9Arg` for each non-nil argument. This suggests `plan9Arg` is responsible for formatting individual instruction arguments.

   * **Opcode Formatting:**  `inst.Op.String()` gets the base opcode name. The code then uses a `switch` statement on `inst.Op` to handle various instruction-specific formatting needs. This is the core of the syntax conversion.

   * **Instruction-Specific Cases:** The `switch` statement has numerous `case` blocks for different ARM64 instructions (e.g., `LDR`, `BL`, `MOV`, `STP`). Each case modifies the opcode and/or arguments to match the Plan 9 syntax. This requires knowledge of ARM64 assembly and the Plan 9 conventions. For example:
      * `CALL` for `BL` and `BLR`.
      * `JMP` for unconditional `B` and `BR`.
      * Adding suffixes like `.W` and `.P` based on addressing modes.
      * Handling register naming (e.g., `RSP`, `ZR`, `F0`, `V0`).
      * Reordering arguments for certain instructions.

   * **Special Cases:** There are specific cases for handling conditional branches, PC-relative loads, and floating-point instructions.

   * **Suffixes:**  The code handles opcode suffixes based on addressing modes (e.g., `.W`, `.P`) and data sizes (e.g., `W`, `D`, `S`).

   * **Final Formatting:** The arguments are joined with commas, and the final string is constructed.

4. **Analyzing `plan9Arg`:** This function takes a single `Arg` and formats it according to its type:

   * **Immediate Values (`Imm`, `Imm64`, `ImmShift`):** Formatted with a `$`.
   * **PC-Relative Addresses (`PCRel`):**  Attempts to resolve symbols using `symname`; otherwise, formats as `offset(PC)`.
   * **Registers (`Reg`, `RegSP`):** Formatted as `R` or `F`/`V` prefixes as needed, and special cases for `RSP` and `ZR`.
   * **Memory Operands (`MemImmediate`, `MemExtend`):**  Formats base registers, offsets, and indexed registers.
   * **Conditions (`Cond`):**  Maps some conditions to Plan 9 equivalents.
   * **Other Argument Types:**  Formats them with `$`.

5. **Identifying Helper Data Structures:**

   * **`noSuffixOpSet`:** A list of opcodes that don't require a `W` suffix even when operating on 32-bit registers.
   * **`fOpsWithoutFPrefix`:** A map of floating-point opcodes that don't have an `F` prefix in Plan 9 syntax.

6. **Inferring the Overall Function:** Based on the code, the primary purpose of this file is to provide a function (`GoSyntax`) that translates ARM64 instructions (represented by the `Inst` type) into their equivalent string representation in the Go assembler syntax, which is based on the Plan 9 assembler.

7. **Constructing Examples:**  Based on the analysis, we can create examples demonstrating how `GoSyntax` would format different ARM64 instructions with various operands. This requires choosing different instruction types, register types, immediate values, and memory addressing modes.

8. **Considering Command-Line Arguments:** The code itself doesn't directly process command-line arguments. However, *the tool that uses this code* (likely the Go assembler or disassembler) would handle command-line arguments. So, the focus here shifts to how a user might *indirectly* interact with this code via the assembler/disassembler.

9. **Identifying Potential Mistakes:**  Think about the complexities of assembly syntax and common errors:

   * **Incorrect Register Names:** Using the wrong register prefix (e.g., `X` instead of `R`).
   * **Incorrect Immediate Formatting:** Forgetting the `$`.
   * **Misunderstanding Addressing Modes:** Not using the correct syntax for offsets or indexed addressing.
   * **Incorrectly Representing PC-Relative Addresses:** Not understanding when the `symname` function is used.

10. **Review and Refine:**  Read through the explanation to ensure it's clear, accurate, and covers all the key aspects of the code. Double-check the examples and the explanation of command-line arguments.

This systematic approach, starting with the overall goal and drilling down into the functions and data structures, allows for a comprehensive understanding of the code's functionality. The key is to connect the code to its purpose within the larger Go toolchain.
这段代码是Go语言中 `go/src/cmd/vendor/golang.org/x/arch/arm64/arm64asm/plan9x.go` 文件的一部分，它主要负责将 ARM64 汇编指令 **转换为 Plan 9 风格的汇编语法**。  Plan 9 是一个操作系统，Go 语言的汇编器早期借鉴了 Plan 9 的汇编语法。

以下是它的主要功能：

1. **`GoSyntax(inst Inst, pc uint64, symname func(uint64) (string, uint64), text io.ReaderAt) string` 函数:**
   - 这是核心函数，接收一个 `Inst` 类型的 ARM64 指令，以及一些辅助信息，并返回该指令的 Plan 9 汇编语法字符串。
   - `inst`:  代表要转换的 ARM64 汇编指令。
   - `pc`:  指令的程序计数器 (Program Counter)，用于计算 PC 相对地址的绝对地址。
   - `symname`:  一个函数，用于查询符号表。给定一个地址，它返回包含该地址的符号名和基地址（如果存在）。这用于将 PC 相对地址转换为符号引用。
   - `text`:  一个 `io.ReaderAt` 接口，用于读取代码段的内容。用于将 PC 相对加载指令显示为常量加载。
   - 函数内部，它会遍历指令的参数 (`inst.Args`)，并调用 `plan9Arg` 函数将每个参数转换为 Plan 9 语法。
   - 针对不同的指令类型 (`inst.Op`)，会进行特殊的格式化处理，例如：
     - 将 `BL` 指令转换为 `CALL`。
     - 将条件分支指令 `B` 加上条件码前缀。
     - 根据操作数类型添加指令后缀，如 `W` 表示 32 位操作。
     - 特殊处理加载和存储指令的寻址模式后缀（`.W`, `.P`）。
     - 调整部分指令的操作数顺序以符合 Plan 9 语法。
     - 处理浮点指令的前缀和后缀。

2. **`plan9Arg(inst *Inst, pc uint64, symname func(uint64) (string, uint64), arg Arg) string` 函数:**
   - 这个函数负责将单个指令参数 (`Arg` 类型) 转换为 Plan 9 汇编语法的字符串表示。
   - 它根据参数的不同类型 (`Imm`, `Reg`, `MemImmediate` 等) 进行不同的格式化。
   - 例如：
     - 立即数 (`Imm`) 会加上 `$` 前缀。
     - 寄存器 (`Reg`) 会转换为 `R` 或 `F`/`V` 前缀的形式 (例如 `R0`, `F0`, `V0`)。
     - PC 相对地址 (`PCRel`) 会尝试使用 `symname` 解析为符号引用，否则显示为 `offset(PC)`。
     - 内存操作数 (`MemImmediate`, `MemExtend`) 会格式化为 `offset(BaseReg)` 或 `(BaseReg, IndexReg)` 的形式。

3. **`noSuffixOpSet` 变量:**
   - 这是一个字符串切片，包含一些不需要添加 "W" 后缀的指令助记符。即使这些指令操作的是 32 位寄存器，也不需要显式地添加 "W" 后缀。这通常是一些特殊用途的指令。

4. **`fOpsWithoutFPrefix` 变量:**
   - 这是一个 `map`，存储了一些浮点指令，在 Plan 9 语法中不需要 "F" 前缀。

**功能推断：Go 语言汇编器/反汇编器的一部分**

这个文件很明显是 Go 语言工具链中处理汇编代码的一部分。更具体地说，它很可能是 **Go 汇编器或反汇编器** 的一部分，负责将机器码或内部指令表示转换为用户可读的汇编代码。

**Go 代码示例**

虽然我们不能直接调用 `GoSyntax` 并获得汇编代码（因为我们需要先有 `Inst` 类型的指令），但我们可以模拟一个场景，假设我们有一个代表 ARM64 加载指令的 `Inst` 结构体，并使用 `GoSyntax` 将其转换为 Plan 9 汇编。

```go
package main

import (
	"fmt"
	"go/src/cmd/vendor/golang.org/x/arch/arm64/arm64asm"
	"io"
	"strings"
)

func main() {
	// 假设我们有一个代表 LDR 指令的 Inst 结构体 (实际创建会更复杂)
	inst := arm64asm.Inst{
		Op: arm64asm.LDR,
		Args: []arm64asm.Arg{
			arm64asm.Reg(1), // 目标寄存器 R1
			arm64asm.MemImmediate{
				Base: arm64asm.Reg(2), // 基址寄存器 R2
				Imm:  16,              // 偏移量 16
				Mode: arm64asm.AddrOffset,
			},
			nil, // 剩余参数为空
		},
	}

	pc := uint64(0x1000) // 假设程序计数器为 0x1000

	// 一个简单的 symname 函数示例
	symname := func(addr uint64) (string, uint64) {
		if addr == 0x2000 {
			return "globalVar", 0x2000
		}
		return "", 0
	}

	// 一个空的 text reader 示例 (这里我们不演示 PC 相对加载)
	var text strings.Reader

	plan9Syntax := arm64asm.GoSyntax(inst, pc, symname, &text)
	fmt.Println(plan9Syntax) // 输出: MOVD (R2)+16, R1
}
```

**假设的输入与输出：**

- **输入 `inst`:**  代表 ARM64 `LDR` 指令，将内存地址 `[R2 + 16]` 的值加载到 `R1`。
- **输入 `pc`:** `0x1000`。
- **输入 `symname`:**  一个简单的符号解析函数。
- **输入 `text`:**  一个空的 `io.ReaderAt`。
- **输出 `plan9Syntax`:**  `MOVD (R2)+16, R1`  (这是 Plan 9 风格的 `LDR` 指令表示，注意操作数顺序)。

**涉及命令行参数的具体处理**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在调用此代码的更上层程序中，例如 `go tool asm` (Go 汇编器) 或 `go tool objdump` (用于查看目标文件的工具)。

- **`go tool asm` (Go 汇编器):**  可能会接收包含汇编代码的文件作为输入，然后使用类似 `GoSyntax` 的函数将这些代码转换为机器码。
- **`go tool objdump`:** 可能会接收编译后的目标文件，然后使用类似的反向过程（基于 `Inst` 结构体）和 `GoSyntax` 将机器码反汇编成 Plan 9 风格的汇编代码进行展示。

**使用者易犯错的点**

对于使用 Go 汇编的开发者来说，理解 Plan 9 汇编语法与常见的 Intel 或 GNU 汇编语法的差异是容易出错的点：

1. **操作数顺序：** Plan 9 汇编的操作数顺序通常是 **源操作数在前，目标操作数在后**，这与很多其他汇编器相反。例如，`MOV 源, 目标`。在上面的 `LDR` 示例中，可以看到内存地址 `(R2)+16` 在前，目标寄存器 `R1` 在后。

   **易错示例：**  如果开发者习惯了 `MOV R1, (R2)+16` 的语法，可能会错误地写成 `MOVD R1, (R2)+16`，这在 Plan 9 汇编中是错误的。

2. **立即数前缀：**  立即数需要使用 `$` 前缀。

   **易错示例：**  忘记在立即数前加 `$`，例如写成 `MOV R1, 10` 而不是 `MOV R1, $10`。

3. **寄存器命名：** Go 汇编使用 `R` 前缀表示通用寄存器，`F` 前缀表示浮点寄存器，`V` 前缀表示向量寄存器。

   **易错示例：**  使用 `Xn` (常见的 ARM 汇编语法) 代替 `Rn`。

4. **PC 相对地址的表示：**  PC 相对地址通常表示为 `offset(PC)` 或符号名加上 `(SB)` 后缀。

   **易错示例：**  直接使用绝对地址，而不是 PC 相对的表示。

5. **寻址模式的表示：**  不同的寻址模式有特定的语法，例如 `(Rbase)`，`(Rbase)+offset`，`(Rbase, Rindex)` 等。

   **易错示例：**  混淆不同的寻址模式语法。

了解这些差异对于编写和理解 Go 汇编代码至关重要。这段 `plan9x.go` 代码正是 Go 工具链中负责处理这种语法转换的关键部分。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/arm64/arm64asm/plan9x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm64asm

import (
	"fmt"
	"io"
	"sort"
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
	case LDR, LDRB, LDRH, LDRSB, LDRSH, LDRSW:
		// Check for PC-relative load.
		if offset, ok := inst.Args[1].(PCRel); ok {
			addr := pc + uint64(offset)
			if _, ok := inst.Args[0].(Reg); !ok {
				break
			}
			if s, base := symname(addr); s != "" && addr == base {
				args[1] = fmt.Sprintf("$%s(SB)", s)
			}
		}
	}

	// Move addressing mode into opcode suffix.
	suffix := ""
	switch inst.Op {
	case LDR, LDRB, LDRH, LDRSB, LDRSH, LDRSW, STR, STRB, STRH, STUR, STURB, STURH, LD1, ST1:
		switch mem := inst.Args[1].(type) {
		case MemImmediate:
			switch mem.Mode {
			case AddrOffset:
				// no suffix
			case AddrPreIndex:
				suffix = ".W"
			case AddrPostIndex, AddrPostReg:
				suffix = ".P"
			}
		}

	case STP, LDP:
		switch mem := inst.Args[2].(type) {
		case MemImmediate:
			switch mem.Mode {
			case AddrOffset:
				// no suffix
			case AddrPreIndex:
				suffix = ".W"
			case AddrPostIndex:
				suffix = ".P"
			}
		}
	}

	switch inst.Op {
	case BL:
		return "CALL " + args[0]

	case BLR:
		r := inst.Args[0].(Reg)
		regno := uint16(r) & 31
		return fmt.Sprintf("CALL (R%d)", regno)

	case RET:
		if r, ok := inst.Args[0].(Reg); ok && r == X30 {
			return "RET"
		}

	case B:
		if cond, ok := inst.Args[0].(Cond); ok {
			return "B" + cond.String() + " " + args[1]
		}
		return "JMP" + " " + args[0]

	case BR:
		r := inst.Args[0].(Reg)
		regno := uint16(r) & 31
		return fmt.Sprintf("JMP (R%d)", regno)

	case MOV:
		rno := -1
		switch a := inst.Args[0].(type) {
		case Reg:
			rno = int(a)
		case RegSP:
			rno = int(a)
		case RegisterWithArrangementAndIndex:
			op = "VMOV"
		case RegisterWithArrangement:
			op = "VMOV"
		}
		if rno >= 0 && rno <= int(WZR) {
			op = "MOVW"
		} else if rno >= int(X0) && rno <= int(XZR) {
			op = "MOVD"
		}
		if _, ok := inst.Args[1].(RegisterWithArrangementAndIndex); ok {
			op = "VMOV"
		}

	case LDR, LDUR:
		var rno uint16
		if r, ok := inst.Args[0].(Reg); ok {
			rno = uint16(r)
		} else {
			rno = uint16(inst.Args[0].(RegSP))
		}
		if rno <= uint16(WZR) {
			op = "MOVWU" + suffix
		} else if rno >= uint16(B0) && rno <= uint16(B31) {
			op = "FMOVB" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else if rno >= uint16(H0) && rno <= uint16(H31) {
			op = "FMOVH" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else if rno >= uint16(S0) && rno <= uint16(S31) {
			op = "FMOVS" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else if rno >= uint16(D0) && rno <= uint16(D31) {
			op = "FMOVD" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else if rno >= uint16(Q0) && rno <= uint16(Q31) {
			op = "FMOVQ" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else {
			op = "MOVD" + suffix
		}

	case LDRB:
		op = "MOVBU" + suffix

	case LDRH:
		op = "MOVHU" + suffix

	case LDRSW:
		op = "MOVW" + suffix

	case LDRSB:
		if r, ok := inst.Args[0].(Reg); ok {
			rno := uint16(r)
			if rno <= uint16(WZR) {
				op = "MOVBW" + suffix
			} else {
				op = "MOVB" + suffix
			}
		}
	case LDRSH:
		if r, ok := inst.Args[0].(Reg); ok {
			rno := uint16(r)
			if rno <= uint16(WZR) {
				op = "MOVHW" + suffix
			} else {
				op = "MOVH" + suffix
			}
		}
	case STR, STUR:
		var rno uint16
		if r, ok := inst.Args[0].(Reg); ok {
			rno = uint16(r)
		} else {
			rno = uint16(inst.Args[0].(RegSP))
		}
		if rno <= uint16(WZR) {
			op = "MOVW" + suffix
		} else if rno >= uint16(B0) && rno <= uint16(B31) {
			op = "FMOVB" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else if rno >= uint16(H0) && rno <= uint16(H31) {
			op = "FMOVH" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else if rno >= uint16(S0) && rno <= uint16(S31) {
			op = "FMOVS" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else if rno >= uint16(D0) && rno <= uint16(D31) {
			op = "FMOVD" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else if rno >= uint16(Q0) && rno <= uint16(Q31) {
			op = "FMOVQ" + suffix
			args[0] = fmt.Sprintf("F%d", rno&31)
		} else {
			op = "MOVD" + suffix
		}
		args[0], args[1] = args[1], args[0]

	case STRB, STURB:
		op = "MOVB" + suffix
		args[0], args[1] = args[1], args[0]

	case STRH, STURH:
		op = "MOVH" + suffix
		args[0], args[1] = args[1], args[0]

	case TBNZ, TBZ:
		args[0], args[1], args[2] = args[2], args[0], args[1]

	case MADD, MSUB, SMADDL, SMSUBL, UMADDL, UMSUBL:
		if r, ok := inst.Args[0].(Reg); ok {
			rno := uint16(r)
			if rno <= uint16(WZR) {
				op += "W"
			}
		}
		args[2], args[3] = args[3], args[2]
	case STLR:
		if r, ok := inst.Args[0].(Reg); ok {
			rno := uint16(r)
			if rno <= uint16(WZR) {
				op += "W"
			}
		}
		args[0], args[1] = args[1], args[0]

	case STLRB, STLRH:
		args[0], args[1] = args[1], args[0]

	case STLXR, STXR:
		if r, ok := inst.Args[1].(Reg); ok {
			rno := uint16(r)
			if rno <= uint16(WZR) {
				op += "W"
			}
		}
		args[1], args[2] = args[2], args[1]

	case STLXRB, STLXRH, STXRB, STXRH:
		args[1], args[2] = args[2], args[1]

	case BFI, BFXIL, SBFIZ, SBFX, UBFIZ, UBFX:
		if r, ok := inst.Args[0].(Reg); ok {
			rno := uint16(r)
			if rno <= uint16(WZR) {
				op += "W"
			}
		}
		args[1], args[2], args[3] = args[3], args[1], args[2]

	case LDAXP, LDXP:
		if r, ok := inst.Args[0].(Reg); ok {
			rno := uint16(r)
			if rno <= uint16(WZR) {
				op += "W"
			}
		}
		args[0] = fmt.Sprintf("(%s, %s)", args[0], args[1])
		args[1] = args[2]
		return op + " " + args[1] + ", " + args[0]

	case STP, LDP:
		args[0] = fmt.Sprintf("(%s, %s)", args[0], args[1])
		args[1] = args[2]

		rno, ok := inst.Args[0].(Reg)
		if !ok {
			rno = Reg(inst.Args[0].(RegSP))
		}
		if rno <= WZR {
			op = op + "W"
		} else if rno >= S0 && rno <= S31 {
			op = "F" + op + "S"
		} else if rno >= D0 && rno <= D31 {
			op = "F" + op + "D"
		} else if rno >= Q0 && rno <= Q31 {
			op = "F" + op + "Q"
		}
		op = op + suffix
		if inst.Op.String() == "STP" {
			return op + " " + args[0] + ", " + args[1]
		} else {
			return op + " " + args[1] + ", " + args[0]
		}

	case STLXP, STXP:
		if r, ok := inst.Args[1].(Reg); ok {
			rno := uint16(r)
			if rno <= uint16(WZR) {
				op += "W"
			}
		}
		args[1] = fmt.Sprintf("(%s, %s)", args[1], args[2])
		args[2] = args[3]
		return op + " " + args[1] + ", " + args[2] + ", " + args[0]

	case FCCMP, FCCMPE:
		args[0], args[1] = args[1], args[0]
		fallthrough

	case FCMP, FCMPE:
		if _, ok := inst.Args[1].(Imm); ok {
			args[1] = "$(0.0)"
		}
		fallthrough

	case FADD, FSUB, FMUL, FNMUL, FDIV, FMAX, FMIN, FMAXNM, FMINNM, FCSEL, FMADD, FMSUB, FNMADD, FNMSUB:
		if strings.HasSuffix(op, "MADD") || strings.HasSuffix(op, "MSUB") {
			args[2], args[3] = args[3], args[2]
		}
		if r, ok := inst.Args[0].(Reg); ok {
			rno := uint16(r)
			if rno >= uint16(S0) && rno <= uint16(S31) {
				op = fmt.Sprintf("%sS", op)
			} else if rno >= uint16(D0) && rno <= uint16(D31) {
				op = fmt.Sprintf("%sD", op)
			}
		}

	case FCVT:
		for i := 1; i >= 0; i-- {
			if r, ok := inst.Args[i].(Reg); ok {
				rno := uint16(r)
				if rno >= uint16(H0) && rno <= uint16(H31) {
					op = fmt.Sprintf("%sH", op)
				} else if rno >= uint16(S0) && rno <= uint16(S31) {
					op = fmt.Sprintf("%sS", op)
				} else if rno >= uint16(D0) && rno <= uint16(D31) {
					op = fmt.Sprintf("%sD", op)
				}
			}
		}

	case FABS, FNEG, FSQRT, FRINTN, FRINTP, FRINTM, FRINTZ, FRINTA, FRINTX, FRINTI:
		if r, ok := inst.Args[1].(Reg); ok {
			rno := uint16(r)
			if rno >= uint16(S0) && rno <= uint16(S31) {
				op = fmt.Sprintf("%sS", op)
			} else if rno >= uint16(D0) && rno <= uint16(D31) {
				op = fmt.Sprintf("%sD", op)
			}
		}

	case FCVTZS, FCVTZU, SCVTF, UCVTF:
		if _, ok := inst.Args[2].(Imm); !ok {
			for i := 1; i >= 0; i-- {
				if r, ok := inst.Args[i].(Reg); ok {
					rno := uint16(r)
					if rno >= uint16(S0) && rno <= uint16(S31) {
						op = fmt.Sprintf("%sS", op)
					} else if rno >= uint16(D0) && rno <= uint16(D31) {
						op = fmt.Sprintf("%sD", op)
					} else if rno <= uint16(WZR) {
						op += "W"
					}
				}
			}
		}

	case FMOV:
		for i := 0; i <= 1; i++ {
			if r, ok := inst.Args[i].(Reg); ok {
				rno := uint16(r)
				if rno >= uint16(S0) && rno <= uint16(S31) {
					op = fmt.Sprintf("%sS", op)
					break
				} else if rno >= uint16(D0) && rno <= uint16(D31) {
					op = fmt.Sprintf("%sD", op)
					break
				}
			}
		}

	case SYSL:
		op1 := int(inst.Args[1].(Imm).Imm)
		cn := int(inst.Args[2].(Imm_c))
		cm := int(inst.Args[3].(Imm_c))
		op2 := int(inst.Args[4].(Imm).Imm)
		sysregno := int32(op1<<16 | cn<<12 | cm<<8 | op2<<5)
		args[1] = fmt.Sprintf("$%d", sysregno)
		return op + " " + args[1] + ", " + args[0]

	case CBNZ, CBZ:
		if r, ok := inst.Args[0].(Reg); ok {
			rno := uint16(r)
			if rno <= uint16(WZR) {
				op += "W"
			}
		}
		args[0], args[1] = args[1], args[0]

	case ADR, ADRP:
		addr := int64(inst.Args[1].(PCRel))
		args[1] = fmt.Sprintf("%d(PC)", addr)

	case MSR:
		args[0] = inst.Args[0].String()

	case ST1:
		op = fmt.Sprintf("V%s", op) + suffix
		args[0], args[1] = args[1], args[0]

	case LD1:
		op = fmt.Sprintf("V%s", op) + suffix

	case UMOV:
		op = "VMOV"
	case NOP:
		op = "NOOP"

	default:
		index := sort.SearchStrings(noSuffixOpSet, op)
		if !(index < len(noSuffixOpSet) && noSuffixOpSet[index] == op) {
			rno := -1
			switch a := inst.Args[0].(type) {
			case Reg:
				rno = int(a)
			case RegSP:
				rno = int(a)
			case RegisterWithArrangement:
				op = fmt.Sprintf("V%s", op)
			}

			if rno >= int(B0) && rno <= int(Q31) && !strings.HasPrefix(op, "F") {
				op = fmt.Sprintf("V%s", op)
			}
			if rno >= 0 && rno <= int(WZR) {
				// Add "w" to opcode suffix.
				op += "W"
			}
		}
		op = op + suffix
	}

	// conditional instructions, replace args.
	if _, ok := inst.Args[3].(Cond); ok {
		if _, ok := inst.Args[2].(Reg); ok {
			args[1], args[2] = args[2], args[1]
		} else {
			args[0], args[2] = args[2], args[0]
		}
	}
	// Reverse args, placing dest last.
	for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
		args[i], args[j] = args[j], args[i]
	}

	if args != nil {
		op += " " + strings.Join(args, ", ")
	}

	return op
}

// No need add "W" to opcode suffix.
// Opcode must be inserted in ascending order.
var noSuffixOpSet = strings.Fields(`
AESD
AESE
AESIMC
AESMC
CRC32B
CRC32CB
CRC32CH
CRC32CW
CRC32CX
CRC32H
CRC32W
CRC32X
LDARB
LDARH
LDAXRB
LDAXRH
LDTRH
LDXRB
LDXRH
SHA1C
SHA1H
SHA1M
SHA1P
SHA1SU0
SHA1SU1
SHA256H
SHA256H2
SHA256SU0
SHA256SU1
`)

// floating point instructions without "F" prefix.
var fOpsWithoutFPrefix = map[Op]bool{
	LDP: true,
	STP: true,
}

func plan9Arg(inst *Inst, pc uint64, symname func(uint64) (string, uint64), arg Arg) string {
	switch a := arg.(type) {
	case Imm:
		return fmt.Sprintf("$%d", uint32(a.Imm))

	case Imm64:
		return fmt.Sprintf("$%d", int64(a.Imm))

	case ImmShift:
		if a.shift == 0 {
			return fmt.Sprintf("$%d", a.imm)
		}
		return fmt.Sprintf("$(%d<<%d)", a.imm, a.shift)

	case PCRel:
		addr := int64(pc) + int64(a)
		if s, base := symname(uint64(addr)); s != "" && uint64(addr) == base {
			return fmt.Sprintf("%s(SB)", s)
		}
		return fmt.Sprintf("%d(PC)", a/4)

	case Reg:
		regenum := uint16(a)
		regno := uint16(a) & 31

		if regenum >= uint16(B0) && regenum <= uint16(Q31) {
			if strings.HasPrefix(inst.Op.String(), "F") || strings.HasSuffix(inst.Op.String(), "CVTF") || fOpsWithoutFPrefix[inst.Op] {
				// FP registers are the same ones as SIMD registers
				// Print Fn for scalar variant to align with assembler (e.g., FCVT, SCVTF, UCVTF, etc.)
				return fmt.Sprintf("F%d", regno)
			} else {
				// Print Vn to align with assembler (e.g., SHA256H)
				return fmt.Sprintf("V%d", regno)
			}

		}
		return plan9gpr(a)

	case RegSP:
		regno := uint16(a) & 31
		if regno == 31 {
			return "RSP"
		}
		return fmt.Sprintf("R%d", regno)

	case RegExtshiftAmount:
		reg := plan9gpr(a.reg)
		extshift := ""
		amount := ""
		if a.extShift != ExtShift(0) {
			switch a.extShift {
			default:
				extshift = "." + a.extShift.String()

			case lsl:
				extshift = "<<"
				amount = fmt.Sprintf("%d", a.amount)
				return reg + extshift + amount

			case lsr:
				extshift = ">>"
				amount = fmt.Sprintf("%d", a.amount)
				return reg + extshift + amount

			case asr:
				extshift = "->"
				amount = fmt.Sprintf("%d", a.amount)
				return reg + extshift + amount
			case ror:
				extshift = "@>"
				amount = fmt.Sprintf("%d", a.amount)
				return reg + extshift + amount
			}
			if a.amount != 0 {
				amount = fmt.Sprintf("<<%d", a.amount)
			}
		}
		return reg + extshift + amount

	case MemImmediate:
		off := ""
		base := ""
		regno := uint16(a.Base) & 31
		if regno == 31 {
			base = "(RSP)"
		} else {
			base = fmt.Sprintf("(R%d)", regno)
		}
		if a.imm != 0 && a.Mode != AddrPostReg {
			off = fmt.Sprintf("%d", a.imm)
		} else if a.Mode == AddrPostReg {
			postR := fmt.Sprintf("(R%d)", a.imm)
			return base + postR
		}
		return off + base

	case MemExtend:
		base := ""
		index := ""
		regno := uint16(a.Base) & 31
		if regno == 31 {
			base = "(RSP)"
		} else {
			base = fmt.Sprintf("(R%d)", regno)
		}
		indexreg := plan9gpr(a.Index)

		if a.Extend == lsl {
			// Refer to ARM reference manual, for byte load/store(register), the index
			// shift amount must be 0, encoded in "S" as 0 if omitted, or as 1 if present.
			// a.Amount indicates the index shift amount, encoded in "S" field.
			// a.ShiftMustBeZero is set true indicates the index shift amount must be 0.
			// When a.ShiftMustBeZero is true, GNU syntax prints "[Xn, Xm lsl #0]" if "S"
			// equals to 1, or prints "[Xn, Xm]" if "S" equals to 0.
			if a.Amount != 0 && !a.ShiftMustBeZero {
				index = fmt.Sprintf("(%s<<%d)", indexreg, a.Amount)
			} else if a.ShiftMustBeZero && a.Amount == 1 {
				// When a.ShiftMustBeZero is ture, Go syntax prints "(Rm<<0)" if "a.Amount"
				// equals to 1.
				index = fmt.Sprintf("(%s<<0)", indexreg)
			} else {
				index = fmt.Sprintf("(%s)", indexreg)
			}
		} else {
			if a.Amount != 0 && !a.ShiftMustBeZero {
				index = fmt.Sprintf("(%s.%s<<%d)", indexreg, a.Extend.String(), a.Amount)
			} else {
				index = fmt.Sprintf("(%s.%s)", indexreg, a.Extend.String())
			}
		}

		return base + index

	case Cond:
		switch arg.String() {
		case "CS":
			return "HS"
		case "CC":
			return "LO"
		}

	case Imm_clrex:
		return fmt.Sprintf("$%d", uint32(a))

	case Imm_dcps:
		return fmt.Sprintf("$%d", uint32(a))

	case Imm_option:
		return fmt.Sprintf("$%d", uint8(a))

	case Imm_hint:
		return fmt.Sprintf("$%d", uint8(a))

	case Imm_fp:
		var s, pre, numerator, denominator int16
		var result float64
		if a.s == 0 {
			s = 1
		} else {
			s = -1
		}
		pre = s * int16(16+a.pre)
		if a.exp > 0 {
			numerator = (pre << uint8(a.exp))
			denominator = 16
		} else {
			numerator = pre
			denominator = (16 << uint8(-1*a.exp))
		}
		result = float64(numerator) / float64(denominator)
		return strings.TrimRight(fmt.Sprintf("$%f", result), "0")

	case RegisterWithArrangement:
		result := a.r.String()
		arrange := a.a.String()
		c := []rune(arrange)
		switch len(c) {
		case 3:
			c[1], c[2] = c[2], c[1] // .8B -> .B8
		case 4:
			c[1], c[2], c[3] = c[3], c[1], c[2] // 16B -> B16
		}
		arrange = string(c)
		result += arrange
		if a.cnt > 0 {
			result = "[" + result
			for i := 1; i < int(a.cnt); i++ {
				cur := V0 + Reg((uint16(a.r)-uint16(V0)+uint16(i))&31)
				result += ", " + cur.String() + arrange
			}
			result += "]"
		}
		return result

	case RegisterWithArrangementAndIndex:
		result := a.r.String()
		arrange := a.a.String()
		result += arrange
		if a.cnt > 1 {
			result = "[" + result
			for i := 1; i < int(a.cnt); i++ {
				cur := V0 + Reg((uint16(a.r)-uint16(V0)+uint16(i))&31)
				result += ", " + cur.String() + arrange
			}
			result += "]"
		}
		return fmt.Sprintf("%s[%d]", result, a.index)

	case Systemreg:
		return fmt.Sprintf("$%d", uint32(a.op0&1)<<14|uint32(a.op1&7)<<11|uint32(a.cn&15)<<7|uint32(a.cm&15)<<3|uint32(a.op2)&7)

	case Imm_prfop:
		if strings.Contains(a.String(), "#") {
			return fmt.Sprintf("$%d", a)
		}
	case sysOp:
		result := a.op.String()
		if a.r != 0 {
			result += ", " + plan9gpr(a.r)
		}
		return result
	}

	return strings.ToUpper(arg.String())
}

// Convert a general-purpose register to plan9 assembly format.
func plan9gpr(r Reg) string {
	regno := uint16(r) & 31
	if regno == 31 {
		return "ZR"
	}
	return fmt.Sprintf("R%d", regno)
}
```