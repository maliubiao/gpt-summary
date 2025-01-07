Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The core request is to understand the functionality of the given Go code, specifically the `plan9x.go` file within the `loong64asm` package. The prompt also asks for examples, potential pitfalls, and connections to Go language features.

2. **Identify the Core Function:** The first step is to locate the primary function. In this case, it's clearly `GoSyntax`. The documentation comment immediately tells us it's about converting an instruction (`Inst`) into its Plan 9 assembler syntax. This is the central piece of functionality.

3. **Analyze `GoSyntax` Step-by-Step:**

   * **Input:**  The function takes an `Inst`, a program counter `pc`, and a `symname` function. The `symname` function is crucial for resolving addresses to symbolic names. The code handles the case where `symname` is nil by providing a default no-op function.

   * **Basic Handling:** The code checks for a zero instruction (`inst.Op == 0`). This signifies either a `WORD $0` or an unknown instruction.

   * **Argument Processing:**  The code iterates through the instruction's arguments (`inst.Args`) and calls `plan9Arg` to format each argument. This suggests `plan9Arg` is responsible for translating the internal representation of arguments into assembler syntax.

   * **Opcode Lookup:**  It retrieves the opcode string from `plan9OpMap`. This map is likely the core translation table between the internal `Op` type and the Plan 9 assembler mnemonics.

   * **Instruction-Specific Logic:** This is the most complex part. The `switch inst.Op` block handles various LoongArch64 instructions and applies specific formatting rules. This indicates that the generic Plan 9 syntax needs adjustments for certain instructions. Examples:
      * `BSTRPICK`: Rearranging operands and potentially changing the opcode to `MOVHU`.
      * Branch instructions (`BCNEZ`, `BCEQZ`, `BEQ`, `BNE`, etc.): Simplifying the syntax based on register values (e.g., `JMP` if branching to the same register).
      * `JIRL`: Special handling for `RET` and `JMP`.
      * Load/Store instructions (`LD_`, `ST_`, `LDX_`, `STX_`): Formatting memory operands with offsets.
      * Atomic memory operations (`AMADD_`, `AMCAS_`, etc.): Specific formatting for these instructions.
      * Default case: Reversing arguments and handling special cases based on the number of arguments and specific opcodes like `SUB_W`, `ADDI_W`, `ORI`, `ANDI`, `SLL_W`, `OR`.

   * **Output:** The function returns the formatted assembler string.

4. **Analyze `plan9Arg`:**

   * **Purpose:** This function converts individual instruction arguments into their Plan 9 assembler representation.

   * **Type Switching:** It uses a `switch a := arg.(type)` to handle different argument types (`Reg`, `Fcsr`, `Fcc`, `Uimm`, `Simm16`, `Simm32`, `OffsetSimm`, `SaSimm`, `CodeSimm`).

   * **Formatting:** Each case formats the argument appropriately (e.g., `R%d` for registers, `$%d` for immediates, `%d(PC)` for PC-relative offsets). The handling of `OffsetSimm` for branch instructions demonstrates the use of the `symname` function to display symbolic labels.

5. **Analyze Helper Functions:**

   * `signumConvInt32`:  Performs sign extension of an integer based on the provided width.
   * `offsConvInt32`:  Similar to `signumConvInt32` but adds 2 to the width, likely related to byte addressing and instruction alignment.

6. **Analyze `plan9OpMap`:**

   * **Purpose:** This is a simple map that translates `Op` constants (internal representation of opcodes) to their Plan 9 assembler string representations. It covers a wide range of LoongArch64 instructions, including integer, floating-point, and atomic operations.

7. **Connect to Go Features:**

   * **Interfaces:** The `Arg` interface and the type switch in `plan9Arg` are clear examples of Go's interface mechanism for handling different argument types uniformly.
   * **String Manipulation:** The code heavily uses `fmt.Sprintf` and `strings.Join` for building the output string.
   * **Maps:**  `plan9OpMap` is a fundamental use of Go's map data structure for efficient lookup.
   * **Functions as Values:** The `symname func(uint64) (string, uint64)` parameter demonstrates passing a function as an argument.

8. **Identify Potential Pitfalls:**

   * **Incorrect `symname` Implementation:**  If the provided `symname` function is incorrect or incomplete, the symbolic representation of addresses will be wrong.
   * **Misunderstanding Plan 9 Syntax:** Users need to be familiar with Plan 9 assembler syntax to interpret the output correctly. The differences from other assembler syntaxes (like GNU AS) could be confusing.

9. **Construct Examples:**

   * Choose a few representative instructions and manually trace their conversion using the `GoSyntax` function. Include different argument types and illustrate the instruction-specific logic. Show both the input `Inst` and the resulting assembler string. Demonstrate the `symname` functionality.

10. **Organize and Refine:** Structure the answer logically, starting with the overall functionality and then diving into the details of each function and data structure. Use clear and concise language. Include code formatting for readability. Double-check for accuracy and completeness.

This step-by-step process, focusing on understanding the purpose of each component and how they interact, is key to deciphering the functionality of the provided code. The decomposition into smaller pieces makes the analysis more manageable.
`go/src/cmd/vendor/golang.org/x/arch/loong64/loong64asm/plan9x.go` 这个文件实现了将 LoongArch 64 位架构的机器指令（`Inst` 类型）转换为 Plan 9 汇编语法的字符串表示形式。

以下是其主要功能点的详细说明：

**1. 指令到 Plan 9 汇编语法的转换 (`GoSyntax` 函数):**

   - **核心功能:** `GoSyntax` 函数接收一个 `Inst` 类型的指令、指令的程序计数器地址 (`pc`) 以及一个用于查询符号表的函数 (`symname`)，然后返回该指令对应的 Plan 9 汇编语法的字符串。
   - **符号表查询:** `symname` 函数允许将 PC 相对地址扩展为绝对地址，并尝试将这些地址解析为符号名称。这使得汇编输出更具可读性，尤其是对于跳转和调用指令的目标地址。
   - **处理特殊指令:**  `GoSyntax` 内部包含针对特定 LoongArch64 指令的特殊处理逻辑，以生成更符合 Plan 9 汇编习惯的输出。例如，它会将某些特定的寄存器操作转换为更简洁的助记符 (例如，`BEQ R0, R0, label` 转换为 `JMP label`)。
   - **默认处理:** 对于没有特殊处理的指令，它会根据指令的操作码和操作数生成通用的 Plan 9 汇编语法。
   - **处理空指令:** 如果 `inst.Op` 和 `inst.Enc` 都是 0，则返回 `"WORD $0"`，表示一个字大小的零值。如果 `inst.Op` 为 0 但 `inst.Enc` 不为 0，则返回 `"?"`，表示未知的指令。

**2. 操作数到 Plan 9 汇编语法的转换 (`plan9Arg` 函数):**

   - **类型判断:** `plan9Arg` 函数接收一个 `Arg` 类型的操作数，并通过类型断言判断其具体类型（例如，寄存器 `Reg`、立即数 `Uimm`、偏移量 `OffsetSimm` 等）。
   - **格式化:** 根据操作数的类型，将其格式化为 Plan 9 汇编语法。例如，通用寄存器 `R0` 到 `R31` 表示为 `R0` 到 `R31`，浮点寄存器表示为 `F0` 到 `F31`，立即数前面加 `$` 符号，偏移量表示为 `offset(PC)` 或 `symbol(SB)`。
   - **PC 相对地址处理:** 对于 `OffsetSimm` 类型的操作数（通常用于跳转和分支指令），如果 `symname` 函数能找到对应的符号，则会将其格式化为 `symbol(SB)`，否则格式化为 `offset(PC)`。

**3. 操作码到 Plan 9 汇编助记符的映射 (`plan9OpMap` 变量):**

   - **存储映射关系:** `plan9OpMap` 是一个 `map[Op]string` 类型的变量，用于存储 LoongArch64 的 `Op` 枚举值到对应的 Plan 9 汇编助记符的映射关系。例如，`ADD_W` 映射到 `"ADD"`，`MOV_D` 映射到 `"MOVV"`。
   - **提供翻译:** `GoSyntax` 函数使用 `plan9OpMap` 来查找指令的操作码对应的汇编助记符。

**4. 辅助函数 (`signumConvInt32`, `offsConvInt32`):**

   - **符号扩展:** `signumConvInt32` 函数用于对有符号立即数进行符号扩展，将其扩展为 32 位有符号整数。
   - **偏移量转换:** `offsConvInt32` 函数用于将偏移量转换为带符号的 32 位整数，它在 `signumConvInt32` 的基础上对宽度进行了一些调整。

**可以推理出它是什么 Go 语言功能的实现：**

这个文件是 Go 语言汇编器或反汇编器的一部分，专门用于处理 LoongArch 64 位架构。它负责将机器指令翻译成人类可读的汇编代码，这对于调试、性能分析和理解底层代码执行过程非常重要。

**Go 代码举例说明:**

假设我们有一个 LoongArch64 的指令，其内部表示如下：

```go
package main

import (
	"fmt"
	"golang.org/x/arch/loong64/loong64asm"
)

func main() {
	inst := loong64asm.Inst{
		Op: loong64asm.ADD_D, // ADDV 指令
		Args: []loong64asm.Arg{
			loong64asm.Reg(10), // 目标寄存器 R10
			loong64asm.Reg(20), // 源寄存器 1 R20
			loong64asm.Reg(21), // 源寄存器 2 R21
		},
	}
	pc := uint64(0x1000) // 假设指令地址为 0x1000
	symname := func(addr uint64) (string, uint64) {
		if addr == 0x2000 {
			return "target_label", 0x2000
		}
		return "", 0
	}

	asm := loong64asm.GoSyntax(inst, pc, symname)
	fmt.Println(asm) // 输出: ADDV R20, R21, R10
}
```

**假设的输入与输出:**

* **输入 `inst`:**  表示 `ADDV R10, R20, R21` 指令的 `loong64asm.Inst` 结构体。
* **输入 `pc`:**  `0x1000`，表示该指令在内存中的地址。
* **输入 `symname`:**  一个简单的符号表查询函数，当地址为 `0x2000` 时返回符号 `"target_label"`。
* **输出 `asm`:** 字符串 `"ADDV R20, R21, R10"`，这是该指令的 Plan 9 汇编表示。

**涉及命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是一个库文件，供其他工具（如汇编器或反汇编器）使用。这些工具可能会接收包含机器码或汇编代码的文件作为输入，并使用此文件中的 `GoSyntax` 函数将机器码转换为 Plan 9 汇编语法进行显示或进一步处理。

例如，一个假设的反汇编器可能会有如下的命令行处理逻辑：

```go
// 假设的反汇编器
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"golang.org/x/arch/loong64/loong64asm"
)

func main() {
	inputFile := flag.String("input", "", "Input binary file")
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Usage: disassembler -input <binary_file>")
		return
	}

	f, err := os.Open(*inputFile)
	if err != nil {
		fmt.Println("Error opening input file:", err)
		return
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	pc := uint64(0) // 假设起始地址为 0

	// 一个简化的符号表，实际的反汇编器会更复杂
	symname := func(addr uint64) (string, uint64) {
		// ... 实现符号表查找逻辑 ...
		return "", 0
	}

	for {
		var instruction uint32
		err := binary.Read(reader, binary.LittleEndian, &instruction)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Error reading instruction:", err)
			return
		}

		inst, err := loong64asm.Decode(instruction) // 假设有 Decode 函数将 uint32 解码为 Inst
		if err != nil {
			fmt.Printf("Error decoding instruction at 0x%x: %v\n", pc, err)
			return
		}

		asm := loong64asm.GoSyntax(inst, pc, symname)
		fmt.Printf("0x%x:\t%s\n", pc, asm)
		pc += 4 // 假设指令长度固定为 4 字节
	}
}
```

在这个例子中，`-input` 命令行参数指定了要反汇编的二进制文件。反汇编器读取二进制数据，将其解码为 `loong64asm.Inst`，然后使用 `loong64asm.GoSyntax` 将其转换为汇编代码。

**使用者易犯错的点:**

1. **`symname` 函数的实现不正确:**  如果使用者提供的 `symname` 函数不能正确地解析符号，那么输出的汇编代码中，跳转和调用指令的目标地址可能无法显示为符号，降低可读性。例如，总是返回空字符串会导致所有地址都显示为数字偏移量。

   ```go
   // 错误的 symname 实现
   badSymname := func(addr uint64) (string, uint64) {
       return "", 0 // 总是返回空
   }

   // ... 调用 GoSyntax 时使用 badSymname ...
   ```

2. **对 Plan 9 汇编语法的误解:**  Plan 9 的汇编语法与其他汇编语法（例如 GNU AS）有所不同。使用者可能会对寄存器表示、操作数顺序等感到困惑。例如，Plan 9 汇编中，目标操作数通常放在最后。

   ```assembly
   // Plan 9 语法
   ADD R1, R2, R3  // R3 = R1 + R2

   // GNU AS 语法 (可能)
   add R3, R1, R2  // R3 = R1 + R2
   ```

3. **假设指令长度固定:** 在实际的反汇编过程中，LoongArch64 的指令长度是固定的（4 字节），但在其他架构中，指令长度可能不同。如果使用者错误地假设指令长度，会导致程序计数器 (`pc`) 的更新不正确，从而影响后续指令的解析和符号查找。

总而言之，`go/src/cmd/vendor/golang.org/x/arch/loong64/loong64asm/plan9x.go` 提供了将 LoongArch64 机器指令转换为 Plan 9 汇编语法的功能，这对于理解和调试底层代码至关重要。正确使用 `symname` 函数并了解 Plan 9 汇编语法是避免常见错误的关键。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/loong64/loong64asm/plan9x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package loong64asm

import (
	"fmt"
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
func GoSyntax(inst Inst, pc uint64, symname func(uint64) (string, uint64)) string {
	if symname == nil {
		symname = func(uint64) (string, uint64) { return "", 0 }
	}
	if inst.Op == 0 && inst.Enc == 0 {
		return "WORD $0"
	} else if inst.Op == 0 {
		return "?"
	}

	var args []string
	for _, a := range inst.Args {
		if a == nil {
			break
		}
		args = append(args, plan9Arg(&inst, pc, symname, a))
	}

	var op string = plan9OpMap[inst.Op]
	if op == "" {
		op = "Unknown " + inst.Op.String()
	}

	switch inst.Op {
	case BSTRPICK_W, BSTRPICK_D, BSTRINS_W, BSTRINS_D:
		msbw, lsbw := inst.Args[2].(Uimm), inst.Args[3].(Uimm)
		if inst.Op == BSTRPICK_D && msbw.Imm == 15 && lsbw.Imm == 0 {
			op = "MOVHU"
			args = append(args[1:2], args[0:1]...)
		} else {
			args[0], args[2], args[3] = args[2], args[3], args[0]
		}

	case BCNEZ, BCEQZ:
		args = args[1:2]

	case BEQ, BNE:
		rj := inst.Args[0].(Reg)
		rd := inst.Args[1].(Reg)
		if rj == rd && inst.Op == BEQ {
			op = "JMP"
			args = args[2:]
		} else if rj == R0 {
			args = args[1:]
		} else if rd == R0 {
			args = append(args[:1], args[2:]...)
		}

	case BEQZ, BNEZ:
		if inst.Args[0].(Reg) == R0 && inst.Op == BEQ {
			op = "JMP"
			args = args[1:]
		}

	case BLT, BLTU, BGE, BGEU:
		rj := inst.Args[0].(Reg)
		rd := inst.Args[1].(Reg)
		if rj == rd && (inst.Op == BGE || inst.Op == BGEU) {
			op = "JMP"
			args = args[2:]
		} else if rj == R0 {
			switch inst.Op {
			case BGE:
				op = "BLEZ"
			case BLT:
				op = "BGTZ"
			}
			args = args[1:]
		} else if rd == R0 {
			if !strings.HasSuffix(op, "U") {
				op += "Z"
			}
			args = append(args[:1], args[2:]...)
		}

	case JIRL:
		rd := inst.Args[0].(Reg)
		rj := inst.Args[1].(Reg)
		regno := uint16(rj) & 31
		off := inst.Args[2].(OffsetSimm).Imm
		if rd == R0 && rj == R1 && off == 0 {
			return fmt.Sprintf("RET")
		} else if rd == R0 && off == 0 {
			return fmt.Sprintf("JMP (R%d)", regno)
		} else if rd == R0 {
			return fmt.Sprintf("JMP %d(R%d)", off, regno)
		}
		return fmt.Sprintf("CALL (R%d)", regno)

	case LD_B, LD_H, LD_W, LD_D, LD_BU, LD_HU, LD_WU, LL_W, LL_D,
		ST_B, ST_H, ST_W, ST_D, SC_W, SC_D, FLD_S, FLD_D, FST_S, FST_D:
		var off int32
		switch a := inst.Args[2].(type) {
		case Simm16:
			off = signumConvInt32(int32(a.Imm), a.Width)
		case Simm32:
			off = signumConvInt32(int32(a.Imm), a.Width) >> 2
		}
		Iop := strings.ToUpper(inst.Op.String())
		if strings.HasPrefix(Iop, "L") || strings.HasPrefix(Iop, "FL") {
			return fmt.Sprintf("%s %d(%s), %s", op, off, args[1], args[0])
		}
		return fmt.Sprintf("%s %s, %d(%s)", op, args[0], off, args[1])

	case LDX_B, LDX_H, LDX_W, LDX_D, LDX_BU, LDX_HU, LDX_WU, FLDX_S, FLDX_D,
		STX_B, STX_H, STX_W, STX_D, FSTX_S, FSTX_D:
		Iop := strings.ToUpper(inst.Op.String())
		if strings.HasPrefix(Iop, "L") || strings.HasPrefix(Iop, "FL") {
			return fmt.Sprintf("%s (%s)(%s), %s", op, args[1], args[2], args[0])
		}
		return fmt.Sprintf("%s %s, (%s)(%s)", op, args[0], args[1], args[2])

	case AMADD_B, AMADD_D, AMADD_DB_B, AMADD_DB_D, AMADD_DB_H, AMADD_DB_W, AMADD_H,
		AMADD_W, AMAND_D, AMAND_DB_D, AMAND_DB_W, AMAND_W, AMCAS_B, AMCAS_D, AMCAS_DB_B,
		AMCAS_DB_D, AMCAS_DB_H, AMCAS_DB_W, AMCAS_H, AMCAS_W, AMMAX_D, AMMAX_DB_D,
		AMMAX_DB_DU, AMMAX_DB_W, AMMAX_DB_WU, AMMAX_DU, AMMAX_W, AMMAX_WU, AMMIN_D,
		AMMIN_DB_D, AMMIN_DB_DU, AMMIN_DB_W, AMMIN_DB_WU, AMMIN_DU, AMMIN_W, AMMIN_WU,
		AMOR_D, AMOR_DB_D, AMOR_DB_W, AMOR_W, AMSWAP_B, AMSWAP_D, AMSWAP_DB_B, AMSWAP_DB_D,
		AMSWAP_DB_H, AMSWAP_DB_W, AMSWAP_H, AMSWAP_W, AMXOR_D, AMXOR_DB_D, AMXOR_DB_W, AMXOR_W:
		return fmt.Sprintf("%s %s, (%s), %s", op, args[1], args[2], args[0])

	default:
		// Reverse args, placing dest last
		for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
			args[i], args[j] = args[j], args[i]
		}
		switch len(args) { // Special use cases
		case 0, 1:
			if inst.Op != B && inst.Op != BL {
				return op
			}

		case 3:
			switch a0 := inst.Args[0].(type) {
			case Reg:
				rj := inst.Args[1].(Reg)
				if a0 == rj && a0 != R0 {
					args = args[0:2]
				}
			}
			switch inst.Op {
			case SUB_W, SUB_D, ADDI_W, ADDI_D, ORI:
				rj := inst.Args[1].(Reg)
				if rj == R0 {
					args = append(args[0:1], args[2:]...)
					if inst.Op == SUB_W {
						op = "NEGW"
					} else if inst.Op == SUB_D {
						op = "NEGV"
					} else {
						op = "MOVW"
					}
				}

			case ANDI:
				ui12 := inst.Args[2].(Uimm)
				if ui12.Imm == uint32(0xff) {
					op = "MOVBU"
					args = args[1:]
				} else if ui12.Imm == 0 && inst.Args[0].(Reg) == R0 && inst.Args[1].(Reg) == R0 {
					return "NOOP"
				}

			case SLL_W, OR:
				rk := inst.Args[2].(Reg)
				if rk == R0 {
					args = args[1:]
					if inst.Op == SLL_W {
						op = "MOVW"
					} else {
						op = "MOVV"
					}
				}
			}
		}
	}

	if args != nil {
		op += " " + strings.Join(args, ", ")
	}
	return op
}

func plan9Arg(inst *Inst, pc uint64, symname func(uint64) (string, uint64), arg Arg) string {
	// Reg:			gpr[0, 31] and fpr[0, 31]
	// Fcsr:		fcsr[0, 3]
	// Fcc:			fcc[0, 7]
	// Uimm:		unsigned integer constant
	// Simm16:		si16
	// Simm32:		si32
	// OffsetSimm:	si32
	switch a := arg.(type) {
	case Reg:
		regenum := uint16(a)
		regno := uint16(a) & 0x1f
		// General-purpose register
		if regenum >= uint16(R0) && regenum <= uint16(R31) {
			return fmt.Sprintf("R%d", regno)
		} else { // Float point register
			return fmt.Sprintf("F%d", regno)
		}

	case Fcsr:
		regno := uint8(a) & 0x1f
		return fmt.Sprintf("FCSR%d", regno)

	case Fcc:
		regno := uint8(a) & 0x1f
		return fmt.Sprintf("FCC%d", regno)

	case Uimm:
		return fmt.Sprintf("$%d", a.Imm)

	case Simm16:
		si16 := signumConvInt32(int32(a.Imm), a.Width)
		return fmt.Sprintf("$%d", si16)

	case Simm32:
		si32 := signumConvInt32(a.Imm, a.Width)
		return fmt.Sprintf("$%d", si32)

	case OffsetSimm:
		offs := offsConvInt32(a.Imm, a.Width)
		if inst.Op == B || inst.Op == BL {
			addr := int64(pc) + int64(a.Imm)
			if s, base := symname(uint64(addr)); s != "" && uint64(addr) == base {
				return fmt.Sprintf("%s(SB)", s)
			}
		}
		return fmt.Sprintf("%d(PC)", offs>>2)

	case SaSimm:
		return fmt.Sprintf("$%d", a)

	case CodeSimm:
		return fmt.Sprintf("$%d", a)

	}
	return strings.ToUpper(arg.String())
}

func signumConvInt32(imm int32, width uint8) int32 {
	active := uint32(1<<width) - 1
	signum := uint32(imm) & active
	if ((signum >> (width - 1)) & 0x1) == 1 {
		signum |= ^active
	}
	return int32(signum)
}

func offsConvInt32(imm int32, width uint8) int32 {
	relWidth := width + 2
	return signumConvInt32(imm, relWidth)
}

var plan9OpMap = map[Op]string{
	ADD_W:       "ADD",
	ADD_D:       "ADDV",
	SUB_W:       "SUB",
	SUB_D:       "SUBV",
	ADDI_W:      "ADD",
	ADDI_D:      "ADDV",
	LU12I_W:     "LU12IW",
	LU32I_D:     "LU32ID",
	LU52I_D:     "LU52ID",
	SLT:         "SGT",
	SLTU:        "SGTU",
	SLTI:        "SGT",
	SLTUI:       "SGTU",
	PCADDU12I:   "PCADDU12I",
	PCALAU12I:   "PCALAU12I",
	AND:         "AND",
	OR:          "OR",
	NOR:         "NOR",
	XOR:         "XOR",
	ANDI:        "AND",
	ORI:         "OR",
	XORI:        "XOR",
	MUL_W:       "MUL",
	MULH_W:      "MULH",
	MULH_WU:     "MULHU",
	MUL_D:       "MULV",
	MULH_D:      "MULHV",
	MULH_DU:     "MULHVU",
	DIV_W:       "DIV",
	DIV_WU:      "DIVU",
	DIV_D:       "DIVV",
	DIV_DU:      "DIVVU",
	MOD_W:       "REM",
	MOD_WU:      "REMU",
	MOD_D:       "REMV",
	MOD_DU:      "REMVU",
	SLL_W:       "SLL",
	SRL_W:       "SRL",
	SRA_W:       "SRA",
	ROTR_W:      "ROTR",
	SLL_D:       "SLLV",
	SRL_D:       "SRLV",
	SRA_D:       "SRAV",
	ROTR_D:      "ROTRV",
	SLLI_W:      "SLL",
	SRLI_W:      "SRL",
	SRAI_W:      "SRA",
	ROTRI_W:     "ROTR",
	SLLI_D:      "SLLV",
	SRLI_D:      "SRLV",
	SRAI_D:      "SRAV",
	ROTRI_D:     "ROTRV",
	EXT_W_B:     "?",
	EXT_W_H:     "?",
	BITREV_W:    "BITREVW",
	BITREV_D:    "BITREVV",
	CLO_W:       "CLOW",
	CLO_D:       "CLOV",
	CLZ_W:       "CLZW",
	CLZ_D:       "CLZV",
	CTO_W:       "CTOW",
	CTO_D:       "CTOV",
	CTZ_W:       "CTZW",
	CTZ_D:       "CTZV",
	REVB_2H:     "REVB2H",
	REVB_2W:     "REVB2W",
	REVB_4H:     "REVB4H",
	REVB_D:      "REVBV",
	BSTRPICK_W:  "BSTRPICKW",
	BSTRPICK_D:  "BSTRPICKV",
	BSTRINS_W:   "BSTRINSW",
	BSTRINS_D:   "BSTRINSV",
	MASKEQZ:     "MASKEQZ",
	MASKNEZ:     "MASKNEZ",
	BCNEZ:       "BFPT",
	BCEQZ:       "BFPF",
	BEQ:         "BEQ",
	BNE:         "BNE",
	BEQZ:        "BEQ",
	BNEZ:        "BNE",
	BLT:         "BLT",
	BLTU:        "BLTU",
	BGE:         "BGE",
	BGEU:        "BGEU",
	B:           "JMP",
	BL:          "CALL",
	LD_B:        "MOVB",
	LD_H:        "MOVH",
	LD_W:        "MOVW",
	LD_D:        "MOVV",
	LD_BU:       "MOVBU",
	LD_HU:       "MOVHU",
	LD_WU:       "MOVWU",
	ST_B:        "MOVB",
	ST_H:        "MOVH",
	ST_W:        "MOVW",
	ST_D:        "MOVV",
	LDX_B:       "MOVB",
	LDX_BU:      "MOVBU",
	LDX_D:       "MOVV",
	LDX_H:       "MOVH",
	LDX_HU:      "MOVHU",
	LDX_W:       "MOVW",
	LDX_WU:      "MOVWU",
	STX_B:       "MOVB",
	STX_D:       "MOVV",
	STX_H:       "MOVH",
	STX_W:       "MOVW",
	AMADD_B:     "AMADDB",
	AMADD_D:     "AMADDV",
	AMADD_DB_B:  "AMADDDBB",
	AMADD_DB_D:  "AMADDDBV",
	AMADD_DB_H:  "AMADDDBH",
	AMADD_DB_W:  "AMADDDBW",
	AMADD_H:     "AMADDH",
	AMADD_W:     "AMADDW",
	AMAND_D:     "AMANDV",
	AMAND_DB_D:  "AMANDDBV",
	AMAND_DB_W:  "AMANDDBW",
	AMAND_W:     "AMANDW",
	AMCAS_B:     "AMCASB",
	AMCAS_D:     "AMCASV",
	AMCAS_DB_B:  "AMCASDBB",
	AMCAS_DB_D:  "AMCASDBV",
	AMCAS_DB_H:  "AMCASDBH",
	AMCAS_DB_W:  "AMCASDBW",
	AMCAS_H:     "AMCASH",
	AMCAS_W:     "AMCASW",
	AMMAX_D:     "AMMAXV",
	AMMAX_DB_D:  "AMMAXDBV",
	AMMAX_DB_DU: "AMMAXDBVU",
	AMMAX_DB_W:  "AMMAXDBW",
	AMMAX_DB_WU: "AMMAXDBWU",
	AMMAX_DU:    "AMMAXVU",
	AMMAX_W:     "AMMAXW",
	AMMAX_WU:    "AMMAXWU",
	AMMIN_D:     "AMMINV",
	AMMIN_DB_D:  "AMMINDBV",
	AMMIN_DB_DU: "AMMINDBVU",
	AMMIN_DB_W:  "AMMINDBW",
	AMMIN_DB_WU: "AMMINDBWU",
	AMMIN_DU:    "AMMINVU",
	AMMIN_W:     "AMMINW",
	AMMIN_WU:    "AMMINWU",
	AMOR_D:      "AMORV",
	AMOR_DB_D:   "AMORDBV",
	AMOR_DB_W:   "AMORDBW",
	AMOR_W:      "AMORW",
	AMSWAP_B:    "AMSWAPB",
	AMSWAP_D:    "AMSWAPV",
	AMSWAP_DB_B: "AMSWAPDBB",
	AMSWAP_DB_D: "AMSWAPDBV",
	AMSWAP_DB_H: "AMSWAPDBH",
	AMSWAP_DB_W: "AMSWAPDBW",
	AMSWAP_H:    "AMSWAPH",
	AMSWAP_W:    "AMSWAPW",
	AMXOR_D:     "AMXORV",
	AMXOR_DB_D:  "AMXORDBV",
	AMXOR_DB_W:  "AMXORDBW",
	AMXOR_W:     "AMXORW",
	LL_W:        "LL",
	LL_D:        "LLV",
	SC_W:        "SC",
	SC_D:        "SCV",
	CRCC_W_B_W:  "CRCCWBW",
	CRCC_W_D_W:  "CRCCWVW",
	CRCC_W_H_W:  "CRCCWHW",
	CRCC_W_W_W:  "CRCCWWW",
	CRC_W_B_W:   "CRCWBW",
	CRC_W_D_W:   "CRCWVW",
	CRC_W_H_W:   "CRCWHW",
	CRC_W_W_W:   "CRCWWW",
	DBAR:        "DBAR",
	SYSCALL:     "SYSCALL",
	BREAK:       "BREAK",
	RDTIMEL_W:   "RDTIMELW",
	RDTIMEH_W:   "RDTIMEHW",
	RDTIME_D:    "RDTIMED",
	CPUCFG:      "CPUCFG",

	// Floating-point instructions
	FADD_S:       "ADDF",
	FADD_D:       "ADDD",
	FSUB_S:       "SUBF",
	FSUB_D:       "SUBD",
	FMUL_S:       "MULF",
	FMUL_D:       "MULD",
	FDIV_S:       "DIVF",
	FDIV_D:       "DIVD",
	FMSUB_S:      "FMSUBF",
	FMSUB_D:      "FMSUBD",
	FMADD_S:      "FMADDF",
	FMADD_D:      "FMADDD",
	FNMADD_S:     "FNMADDF",
	FNMADD_D:     "FNMADDD",
	FNMSUB_S:     "FNMSUBF",
	FNMSUB_D:     "FNMSUBD",
	FABS_S:       "ABSF",
	FABS_D:       "ABSD",
	FNEG_S:       "NEGF",
	FNEG_D:       "NEGD",
	FSQRT_S:      "SQRTF",
	FSQRT_D:      "SQRTD",
	FCOPYSIGN_S:  "FCOPYSGF",
	FCOPYSIGN_D:  "FCOPYSGD",
	FMAX_S:       "FMAXF",
	FMAX_D:       "FMAXD",
	FMIN_S:       "FMINF",
	FMIN_D:       "FMIND",
	FCLASS_S:     "FCLASSF",
	FCLASS_D:     "FCLASSD",
	FCMP_CEQ_S:   "CMPEQF",
	FCMP_CEQ_D:   "CMPEQD",
	FCMP_SLE_S:   "CMPGEF",
	FCMP_SLE_D:   "CMPGED",
	FCMP_SLT_S:   "CMPGTF",
	FCMP_SLT_D:   "CMPGTD",
	FCVT_D_S:     "MOVFD",
	FCVT_S_D:     "MOVDF",
	FFINT_S_W:    "FFINTFW",
	FFINT_S_L:    "FFINTFV",
	FFINT_D_W:    "FFINTDW",
	FFINT_D_L:    "FFINTDV",
	FTINTRM_L_D:  "FTINTRMVD",
	FTINTRM_L_S:  "FTINTRMVF",
	FTINTRM_W_D:  "FTINTRMWD",
	FTINTRM_W_S:  "FTINTRMWF",
	FTINTRNE_L_D: "FTINTRNEVD",
	FTINTRNE_L_S: "FTINTRNEVF",
	FTINTRNE_W_D: "FTINTRNEWD",
	FTINTRNE_W_S: "FTINTRNEWF",
	FTINTRP_L_D:  "FTINTRPVD",
	FTINTRP_L_S:  "FTINTRPVF",
	FTINTRP_W_D:  "FTINTRPWD",
	FTINTRP_W_S:  "FTINTRPWF",
	FTINTRZ_L_D:  "FTINTRZVD",
	FTINTRZ_L_S:  "FTINTRZVF",
	FTINTRZ_W_D:  "FTINTRZWD",
	FTINTRZ_W_S:  "FTINTRZWF",
	FTINT_L_D:    "FTINTVD",
	FTINT_L_S:    "FTINTVF",
	FTINT_W_D:    "FTINTWD",
	FTINT_W_S:    "FTINTWF",
	FRINT_S:      "FRINTS",
	FRINT_D:      "FRINTD",
	FMOV_S:       "MOVF",
	FMOV_D:       "MOVD",
	MOVGR2FR_W:   "MOVW",
	MOVGR2FR_D:   "MOVV",
	MOVFR2GR_S:   "MOVW",
	MOVFR2GR_D:   "MOVV",
	MOVGR2CF:     "MOVV",
	MOVCF2GR:     "MOVV",
	MOVFCSR2GR:   "MOVV",
	MOVGR2FCSR:   "MOVV",
	MOVFR2CF:     "MOVV",
	MOVCF2FR:     "MOVV",
	FLD_S:        "MOVF",
	FLD_D:        "MOVD",
	FST_S:        "MOVF",
	FST_D:        "MOVD",
	FLDX_S:       "MOVF",
	FLDX_D:       "MOVD",
	FSTX_S:       "MOVF",
	FSTX_D:       "MOVD",
}

"""



```