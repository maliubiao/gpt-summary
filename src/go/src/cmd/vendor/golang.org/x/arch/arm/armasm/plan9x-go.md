Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The core request is to understand the *functionality* of the `plan9x.go` file. This means figuring out what it does, how it achieves it, and its role within the larger Go ecosystem. The filename and package name (`armasm`) strongly suggest it's related to ARM assembly. The `plan9x` part hints at a specific assembly syntax.

2. **Identify Key Functions:**  Start by looking at the exported functions (those with capital letters). The most prominent one is `GoSyntax`. This is likely the main entry point for whatever this code does.

3. **Analyze `GoSyntax`:**
    * **Signature:** `func GoSyntax(inst Inst, pc uint64, symname func(uint64) (string, uint64), text io.ReaderAt) string`
    * **Inputs:**
        * `inst Inst`: An `Inst` struct, likely representing a single ARM instruction.
        * `pc uint64`:  Program Counter. Crucial for resolving relative addresses.
        * `symname func(...)`: A function to resolve addresses to symbol names. This is standard for disassemblers.
        * `text io.ReaderAt`:  Allows reading from the code segment. Important for loading constants.
    * **Output:** `string`: The function returns a string, strongly suggesting it's producing a textual representation of the instruction.
    * **Logic:**
        * It iterates through `inst.Args` to process each argument.
        * It calls `plan9Arg` to convert individual arguments to Plan 9 syntax.
        * It handles special cases for `RET` instructions and PC-relative loads, potentially reading data from `text`.
        * It adjusts the opcode suffix based on addressing modes.
        * It reverses the order of arguments (destination last).
        * It has special logic for `MLA` and `STREX` like instructions.
        * It calls `fpTrans` for floating-point instructions.
        * It performs final transformations for `LDR`, `STR`, and other instructions, essentially mapping them to `MOV` variants in Plan 9 syntax.
        * Finally, it combines the opcode and arguments into a formatted string.

4. **Analyze Supporting Functions:**
    * **`plan9Arg`:**  Handles the conversion of different argument types (`Imm`, `Mem`, `Reg`, etc.) to Plan 9 syntax. It has logic for register lists and shifted registers.
    * **`memOpTrans`:**  Specifically converts memory operands from a more generic representation to Plan 9's syntax, including suffixes like `.W`, `.P`, and `.U`.
    * **`fpTrans`:**  Deals with the conversion of floating-point instructions. It uses a lookup table (`fpInst`) to map GNU-style FP instructions to their Plan 9 equivalents. It also handles register name transformations (e.g., `D0` to `F0`, `S0` to `F0`).

5. **Identify Data Structures:**
    * **`Inst`:**  Represents an instruction. Its exact structure isn't shown in the snippet, but it must contain the opcode (`Op`) and a slice of arguments (`Args`).
    * **`Arg`:** An interface for different types of instruction arguments (registers, immediates, memory operands, etc.).
    * **`Mem`:**  Represents a memory operand, with fields like `Base`, `Offset`, `Index`, `Sign`, `Mode`, `Shift`, and `Count`.
    * **`Reg`, `Imm`, `PCRel`, `RegList`, `RegShift`, `RegShiftReg`, `Endian`:**  Specific types that implement the `Arg` interface.
    * **`Op`:** Represents the instruction opcode.
    * **`goFPInfo`:**  A struct used in `fpTrans` to define the mapping between GNU and Plan 9 FP instructions.

6. **Infer Overall Functionality:** Based on the analysis of the functions and data structures, the primary function of this code is to **convert ARM assembly instructions from a generic representation to Plan 9 assembly syntax**. This is a crucial step in disassembling ARM code when targeting Go's Plan 9 assembler.

7. **Illustrative Go Code Example:** To demonstrate its use, you need a hypothetical `Inst` structure. Since we don't have its definition, we need to make assumptions based on how it's used in `GoSyntax`. The example should show how to create an `Inst`, call `GoSyntax`, and what the expected output would be. It should cover a few common ARM instructions.

8. **Code Reasoning Example:**  Choose a specific piece of logic within `GoSyntax` (like the PC-relative load handling) and trace its execution with a concrete input `Inst`. Explain the conditions, the steps taken, and the resulting output.

9. **Command-Line Argument Handling:**  Since the code doesn't directly interact with command-line arguments, it's important to state that clearly. The responsibility of feeding the instructions to `GoSyntax` lies with other parts of the Go toolchain (like a disassembler).

10. **Common Mistakes:** Think about how a *user* of this code (likely another part of the Go assembler/disassembler) might misuse it. The prominent point is the necessity of providing the `text` reader when dealing with PC-relative loads. Forgetting this will lead to incorrect disassembly.

11. **Review and Refine:** Read through the entire analysis, ensuring clarity, accuracy, and completeness. Make sure the examples are clear and the explanations are easy to understand. For instance, initially, I might just say "it converts to Plan 9 syntax," but refining it to "converts ARM assembly instructions to Plan 9 assembly syntax" is more precise. Similarly, initially, I might not explicitly mention that the `Inst` struct is assumed, but acknowledging this makes the explanation more robust.
这段Go语言代码文件 `plan9x.go` 的主要功能是将 ARM 汇编指令从一种内部表示形式转换为 Plan 9 汇编器的语法格式。Plan 9 是一个Unix-like的操作系统，Go语言的早期开发深受其影响，其汇编器也保留了一些Plan 9的风格。

以下是代码的具体功能点：

1. **`GoSyntax(inst Inst, pc uint64, symname func(uint64) (string, uint64), text io.ReaderAt) string` 函数：**
   - **核心功能：** 将一个 `Inst` 类型的 ARM 汇编指令转换为 Plan 9 汇编语法的字符串表示。
   - **参数：**
     - `inst Inst`:  代表要转换的 ARM 汇编指令，包含操作码和操作数等信息。虽然代码中没有给出 `Inst` 的具体定义，但可以推断它至少包含 `Op`（操作码）和 `Args`（操作数切片）字段。
     - `pc uint64`:  当前指令的程序计数器 (Program Counter)，用于计算 PC 相对地址。
     - `symname func(uint64) (string, uint64)`:  一个函数，用于根据给定的内存地址查找符号名。它返回包含该地址的符号的名称和基地址。这对于将内存地址转换为更易读的符号表示非常重要。
     - `text io.ReaderAt`:  一个可以读取代码段的 `io.ReaderAt` 接口。用于在处理 PC 相对加载指令时，读取内存中的实际值，以便将其显示为常量。
   - **返回值：**  指令的 Plan 9 汇编语法字符串。
   - **实现细节：**
     - 遍历指令的操作数，并调用 `plan9Arg` 函数将每个操作数转换为 Plan 9 语法。
     - 特殊处理 `RET` 指令，将其格式化为 `RET` 后跟偏移量。
     - 检测 PC 相对加载指令 (例如 `LDR`)，如果提供了 `text` 阅读器，则读取内存中的值，并将其显示为常量或符号。
     - 调用 `memOpTrans` 函数将内存操作数的 GNU 风格转换为 Plan 9 风格，并添加 `.W`, `.P`, `.U` 等后缀。
     - 调整操作数的顺序，将目标操作数放在最后。
     - 特殊处理类似 `MLA` (Multiply Accumulate) 和 `STREX` (Store Exclusive) 的指令的操作数顺序。
     - 调用 `fpTrans` 函数处理浮点数指令的语法转换。
     - 将一些 `LDR/STR` 类的指令转换为 `MOV` 类的指令，并添加相应的后缀。

2. **`plan9Arg(inst *Inst, pc uint64, symname func(uint64) (string, uint64), arg Arg) string` 函数：**
   - **功能：** 将单个操作数 (`Arg` 接口类型) 转换为 Plan 9 汇编语法的字符串表示。
   - **参数：**
     - `inst *Inst`: 指令的指针。
     - `pc uint64`: 程序计数器。
     - `symname func(uint64) (string, uint64)`: 符号查找函数。
     - `arg Arg`: 要转换的操作数。虽然代码中没有给出 `Arg` 的具体定义，但根据使用方式可以推断出其可能的实现类型，如 `Imm` (立即数), `Mem` (内存操作数), `Reg` (寄存器) 等。
   - **返回值：** 操作数的 Plan 9 汇编语法字符串。
   - **实现细节：**
     - 根据操作数的类型进行不同的格式化：
       - `Imm`:  格式化为 `$value`。
       - `PCRel`: PC 相对地址，根据 `symname` 查找符号名，格式化为 `symbol(SB)` 或 `$address`。
       - `Reg`: 格式化为 `R数字` (例如 `R0`)。
       - `RegList`: 寄存器列表，格式化为 `[Rstart-Rend]` 的形式。
       - `RegShift`, `RegShiftReg`: 带移位的寄存器，格式化为 `Rbase<<$shift` 等形式。

3. **`memOpTrans(mem Mem) (string, string)` 函数：**
   - **功能：** 将内存操作数 (`Mem` 类型) 的表示形式转换为 Plan 9 语法，并返回相关的后缀。
   - **参数：**
     - `mem Mem`: 要转换的内存操作数。虽然代码中没有给出 `Mem` 的具体定义，但可以推断它包含诸如基址寄存器、偏移量、索引寄存器、移位等信息。
   - **返回值：**
     - Plan 9 语法的内存操作数字符串 (例如 `0xff0(R6)` 或 `(R2)(R0@>1)`)。
     - 寻址模式后缀 (例如 `.W`, `.P`, `.U`)。
   - **实现细节：**
     - 根据 `mem.Mode` 确定后缀 (例如 `AddrPreIndex` 对应 `.W`)。
     - 格式化偏移量、基址寄存器和索引寄存器。

4. **`fpTrans(inst *Inst, op string, args []string) (string, []string)` 函数：**
   - **功能：**  专门用于将浮点数指令从一种通用表示转换为 Plan 9 汇编语法。
   - **参数：**
     - `inst *Inst`:  浮点数指令的指针。
     - `op string`:  指令的原始操作码字符串。
     - `args []string`: 指令的原始操作数字符串切片。
   - **返回值：**
     - Plan 9 语法的操作码字符串。
     - Plan 9 语法的操作数字符串切片。
   - **实现细节：**
     - 使用一个 `fpInst` 的查找表，该表定义了 GNU 风格的浮点数指令名称和对应的 Plan 9 风格名称以及操作数的转换规则。
     - 移除 GNU 风格的后缀 (如 `.F32`, `.F64`)。
     - 根据 `fpInst` 中的信息，将 GNU 风格的操作码转换为 Plan 9 风格 (例如 `VADD` 转换为 `ADDF`)。
     - 转换浮点寄存器的名称 (例如 `S0` 转换为 `F0`, `D0` 转换为 `F0`)。

**`fpInst` 变量：**

- 一个 `goFPInfo` 类型的切片，存储了浮点数指令的转换信息。每个 `goFPInfo` 结构体包含了：
  - `op Op`:  指令的操作码。
  - `transArgs []int`: 需要转换的操作数索引。
  - `gnuName string`: GNU 汇编器中的指令名称。
  - `goName string`: Plan 9 汇编器中的指令名称。

**推理 Go 语言功能实现：**

这段代码是 Go 语言 `cmd/vendor/golang.org/x/arch/arm/armasm` 包的一部分，该包负责处理 ARM 架构的汇编操作。更具体地说，`plan9x.go` 实现了将 ARM 汇编指令反汇编成 Plan 9 汇编语法的过程。这通常用于调试、分析或者在需要生成 Plan 9 汇编代码的场景中。

**Go 代码示例：**

假设我们有一个表示 ARM `ADD R0, R1, R2` 指令的 `Inst` 结构体：

```go
package main

import (
	"fmt"
	"go/src/cmd/vendor/golang.org/x/arch/arm/armasm"
	"io"
)

// 假设的 Inst 和 Arg 定义，实际定义在 armasm 包中
type Inst struct {
	Op   armasm.Op
	Args []armasm.Arg
}

type Reg uint

const (
	R0 Reg = 0
	R1 Reg = 1
	R2 Reg = 2
)

type Arg interface {
	String() string
}

type RegArg Reg

func (r RegArg) String() string {
	return fmt.Sprintf("R%d", r)
}

func main() {
	inst := Inst{
		Op: armasm.ADD_EQ, // 假设 ADD_EQ 代表 ADD 指令
		Args: []armasm.Arg{RegArg(R0), RegArg(R1), RegArg(R2)},
	}

	pc := uint64(0x1000) // 假设程序计数器为 0x1000

	// 一个简单的符号查找函数
	symname := func(addr uint64) (string, uint64) {
		return "", 0
	}

	var text io.ReaderAt // 这里不需要读取内存，所以可以为 nil

	plan9Syntax := armasm.GoSyntax(inst, pc, symname, text)
	fmt.Println(plan9Syntax) // 输出: ADD R1, R2, R0
}
```

**假设的输入与输出：**

- **假设输入 ( `Inst` 结构体 ):**  表示 ARM 指令 `LDR R0, [R1, #4]`
  ```go
  inst := Inst{
      Op: armasm.LDR_EQ, // 假设 LDR_EQ 代表 LDR 指令
      Args: []armasm.Arg{
          RegArg(R0),
          MemArg{Base: RegArg(R1), Offset: 4, Mode: armasm.AddrOffset},
      },
  }
  ```
- **假设输出 ( `GoSyntax` 返回的字符串 ):** `MOVW (R1)+4, R0` (Plan 9 语法)

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它是一个库文件，提供将 ARM 汇编指令转换为 Plan 9 语法的函数。实际使用这个库的工具（例如反汇编器）可能会处理命令行参数，以指定要反汇编的文件、起始地址等。

**使用者易犯错的点：**

1. **忘记提供 `text io.ReaderAt` 参数：**  当处理包含 PC 相对加载指令的代码时，如果 `GoSyntax` 函数的 `text` 参数为 `nil`，则无法读取内存中的值，导致 PC 相对加载指令无法正确显示为常量或符号，而是显示为简单的地址。

   **错误示例：**

   ```go
   // ... (假设 inst 是一个 LDR PC 相对加载指令)
   plan9Syntax := armasm.GoSyntax(inst, pc, symname, nil) // text 为 nil
   fmt.Println(plan9Syntax) // 可能输出: MOVW $0xsomeaddress, R0  而不是期望的 MOVW $symbol(SB), R0 或 MOVW $0xvalue, R0
   ```

   **正确示例：**

   ```go
   // ... (假设 inst 是一个 LDR PC 相对加载指令，并且 textReader 是一个有效的 io.ReaderAt)
   plan9Syntax := armasm.GoSyntax(inst, pc, symname, textReader)
   fmt.Println(plan9Syntax) // 可能输出: MOVW $symbol(SB), R0 或 MOVW $0xvalue, R0
   ```

总而言之，`plan9x.go` 是 Go 语言 `armasm` 包中用于将 ARM 汇编指令转换为 Plan 9 汇编语法表示的关键部分，它服务于反汇编和代码分析等目的。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/arm/armasm/plan9x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package armasm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
)

// GoSyntax returns the Go assembler syntax for the instruction.
// The syntax was originally defined by Plan 9.
// The pc is the program counter of the instruction, used for expanding
// PC-relative addresses into absolute ones.
// The symname function queries the symbol table for the program
// being disassembled. Given a target address it returns the name and base
// address of the symbol containing the target, if any; otherwise it returns "", 0.
// The reader r should read from the text segment using text addresses
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

	switch inst.Op &^ 15 {
	case LDR_EQ, LDRB_EQ, LDRH_EQ, LDRSB_EQ, LDRSH_EQ, VLDR_EQ:
		// Check for RET
		reg, _ := inst.Args[0].(Reg)
		mem, _ := inst.Args[1].(Mem)
		if inst.Op&^15 == LDR_EQ && reg == R15 && mem.Base == SP && mem.Sign == 0 && mem.Mode == AddrPostIndex {
			return fmt.Sprintf("RET%s #%d", op[3:], mem.Offset)
		}

		// Check for PC-relative load.
		if mem.Base == PC && mem.Sign == 0 && mem.Mode == AddrOffset && text != nil {
			addr := uint32(pc) + 8 + uint32(mem.Offset)
			buf := make([]byte, 8)
			switch inst.Op &^ 15 {
			case LDRB_EQ, LDRSB_EQ:
				if _, err := text.ReadAt(buf[:1], int64(addr)); err != nil {
					break
				}
				args[1] = fmt.Sprintf("$%#x", buf[0])

			case LDRH_EQ, LDRSH_EQ:
				if _, err := text.ReadAt(buf[:2], int64(addr)); err != nil {
					break
				}
				args[1] = fmt.Sprintf("$%#x", binary.LittleEndian.Uint16(buf))

			case LDR_EQ:
				if _, err := text.ReadAt(buf[:4], int64(addr)); err != nil {
					break
				}
				x := binary.LittleEndian.Uint32(buf)
				if s, base := symname(uint64(x)); s != "" && uint64(x) == base {
					args[1] = fmt.Sprintf("$%s(SB)", s)
				} else {
					args[1] = fmt.Sprintf("$%#x", x)
				}

			case VLDR_EQ:
				switch {
				case strings.HasPrefix(args[0], "D"): // VLDR.F64
					if _, err := text.ReadAt(buf, int64(addr)); err != nil {
						break
					}
					args[1] = fmt.Sprintf("$%f", math.Float64frombits(binary.LittleEndian.Uint64(buf)))
				case strings.HasPrefix(args[0], "S"): // VLDR.F32
					if _, err := text.ReadAt(buf[:4], int64(addr)); err != nil {
						break
					}
					args[1] = fmt.Sprintf("$%f", math.Float32frombits(binary.LittleEndian.Uint32(buf)))
				default:
					panic(fmt.Sprintf("wrong FP register: %v", inst))
				}
			}
		}
	}

	// Move addressing mode into opcode suffix.
	suffix := ""
	switch inst.Op &^ 15 {
	case PLD, PLI, PLD_W:
		if mem, ok := inst.Args[0].(Mem); ok {
			args[0], suffix = memOpTrans(mem)
		} else {
			panic(fmt.Sprintf("illegal instruction: %v", inst))
		}
	case LDR_EQ, LDRB_EQ, LDRSB_EQ, LDRH_EQ, LDRSH_EQ, STR_EQ, STRB_EQ, STRH_EQ, VLDR_EQ, VSTR_EQ, LDREX_EQ, LDREXH_EQ, LDREXB_EQ:
		if mem, ok := inst.Args[1].(Mem); ok {
			args[1], suffix = memOpTrans(mem)
		} else {
			panic(fmt.Sprintf("illegal instruction: %v", inst))
		}
	case SWP_EQ, SWP_B_EQ, STREX_EQ, STREXB_EQ, STREXH_EQ:
		if mem, ok := inst.Args[2].(Mem); ok {
			args[2], suffix = memOpTrans(mem)
		} else {
			panic(fmt.Sprintf("illegal instruction: %v", inst))
		}
	}

	// Reverse args, placing dest last.
	for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
		args[i], args[j] = args[j], args[i]
	}
	// For MLA-like instructions, the addend is the third operand.
	switch inst.Op &^ 15 {
	case SMLAWT_EQ, SMLAWB_EQ, MLA_EQ, MLA_S_EQ, MLS_EQ, SMMLA_EQ, SMMLS_EQ, SMLABB_EQ, SMLATB_EQ, SMLABT_EQ, SMLATT_EQ, SMLAD_EQ, SMLAD_X_EQ, SMLSD_EQ, SMLSD_X_EQ:
		args = []string{args[1], args[2], args[0], args[3]}
	}
	// For STREX like instructions, the memory operands comes first.
	switch inst.Op &^ 15 {
	case STREX_EQ, STREXB_EQ, STREXH_EQ, SWP_EQ, SWP_B_EQ:
		args = []string{args[1], args[0], args[2]}
	}

	// special process for FP instructions
	op, args = fpTrans(&inst, op, args)

	// LDR/STR like instructions -> MOV like
	switch inst.Op &^ 15 {
	case MOV_EQ:
		op = "MOVW" + op[3:]
	case LDR_EQ, MSR_EQ, MRS_EQ:
		op = "MOVW" + op[3:] + suffix
	case VMRS_EQ, VMSR_EQ:
		op = "MOVW" + op[4:] + suffix
	case LDRB_EQ, UXTB_EQ:
		op = "MOVBU" + op[4:] + suffix
	case LDRSB_EQ:
		op = "MOVBS" + op[5:] + suffix
	case SXTB_EQ:
		op = "MOVBS" + op[4:] + suffix
	case LDRH_EQ, UXTH_EQ:
		op = "MOVHU" + op[4:] + suffix
	case LDRSH_EQ:
		op = "MOVHS" + op[5:] + suffix
	case SXTH_EQ:
		op = "MOVHS" + op[4:] + suffix
	case STR_EQ:
		op = "MOVW" + op[3:] + suffix
		args[0], args[1] = args[1], args[0]
	case STRB_EQ:
		op = "MOVB" + op[4:] + suffix
		args[0], args[1] = args[1], args[0]
	case STRH_EQ:
		op = "MOVH" + op[4:] + suffix
		args[0], args[1] = args[1], args[0]
	case VSTR_EQ:
		args[0], args[1] = args[1], args[0]
	default:
		op = op + suffix
	}

	if args != nil {
		op += " " + strings.Join(args, ", ")
	}

	return op
}

// assembler syntax for the various shifts.
// @x> is a lie; the assembler uses @> 0
// instead of @x> 1, but i wanted to be clear that it
// was a different operation (rotate right extended, not rotate right).
var plan9Shift = []string{"<<", ">>", "->", "@>", "@x>"}

func plan9Arg(inst *Inst, pc uint64, symname func(uint64) (string, uint64), arg Arg) string {
	switch a := arg.(type) {
	case Endian:

	case Imm:
		return fmt.Sprintf("$%d", uint32(a))

	case Mem:

	case PCRel:
		addr := uint32(pc) + 8 + uint32(a)
		if s, base := symname(uint64(addr)); s != "" && uint64(addr) == base {
			return fmt.Sprintf("%s(SB)", s)
		}
		return fmt.Sprintf("%#x", addr)

	case Reg:
		if a < 16 {
			return fmt.Sprintf("R%d", int(a))
		}

	case RegList:
		var buf bytes.Buffer
		start := -2
		end := -2
		fmt.Fprintf(&buf, "[")
		flush := func() {
			if start >= 0 {
				if buf.Len() > 1 {
					fmt.Fprintf(&buf, ",")
				}
				if start == end {
					fmt.Fprintf(&buf, "R%d", start)
				} else {
					fmt.Fprintf(&buf, "R%d-R%d", start, end)
				}
				start = -2
				end = -2
			}
		}
		for i := 0; i < 16; i++ {
			if a&(1<<uint(i)) != 0 {
				if i == end+1 {
					end++
					continue
				}
				start = i
				end = i
			} else {
				flush()
			}
		}
		flush()
		fmt.Fprintf(&buf, "]")
		return buf.String()

	case RegShift:
		return fmt.Sprintf("R%d%s$%d", int(a.Reg), plan9Shift[a.Shift], int(a.Count))

	case RegShiftReg:
		return fmt.Sprintf("R%d%sR%d", int(a.Reg), plan9Shift[a.Shift], int(a.RegCount))
	}
	return strings.ToUpper(arg.String())
}

// convert memory operand from GNU syntax to Plan 9 syntax, for example,
// [r5] -> (R5)
// [r6, #4080] -> 0xff0(R6)
// [r2, r0, ror #1] -> (R2)(R0@>1)
// inst [r2, -r0, ror #1] -> INST.U (R2)(R0@>1)
// input:
//
//	a memory operand
//
// return values:
//
//	corresponding memory operand in Plan 9 syntax
//	.W/.P/.U suffix
func memOpTrans(mem Mem) (string, string) {
	suffix := ""
	switch mem.Mode {
	case AddrOffset, AddrLDM:
		// no suffix
	case AddrPreIndex, AddrLDM_WB:
		suffix = ".W"
	case AddrPostIndex:
		suffix = ".P"
	}
	off := ""
	if mem.Offset != 0 {
		off = fmt.Sprintf("%#x", mem.Offset)
	}
	base := fmt.Sprintf("(R%d)", int(mem.Base))
	index := ""
	if mem.Sign != 0 {
		sign := ""
		if mem.Sign < 0 {
			suffix += ".U"
		}
		shift := ""
		if mem.Count != 0 {
			shift = fmt.Sprintf("%s%d", plan9Shift[mem.Shift], mem.Count)
		}
		index = fmt.Sprintf("(%sR%d%s)", sign, int(mem.Index), shift)
	}
	return off + base + index, suffix
}

type goFPInfo struct {
	op        Op
	transArgs []int  // indexes of arguments which need transformation
	gnuName   string // instruction name in GNU syntax
	goName    string // instruction name in Plan 9 syntax
}

var fpInst []goFPInfo = []goFPInfo{
	{VADD_EQ_F32, []int{2, 1, 0}, "VADD", "ADDF"},
	{VADD_EQ_F64, []int{2, 1, 0}, "VADD", "ADDD"},
	{VSUB_EQ_F32, []int{2, 1, 0}, "VSUB", "SUBF"},
	{VSUB_EQ_F64, []int{2, 1, 0}, "VSUB", "SUBD"},
	{VMUL_EQ_F32, []int{2, 1, 0}, "VMUL", "MULF"},
	{VMUL_EQ_F64, []int{2, 1, 0}, "VMUL", "MULD"},
	{VNMUL_EQ_F32, []int{2, 1, 0}, "VNMUL", "NMULF"},
	{VNMUL_EQ_F64, []int{2, 1, 0}, "VNMUL", "NMULD"},
	{VMLA_EQ_F32, []int{2, 1, 0}, "VMLA", "MULAF"},
	{VMLA_EQ_F64, []int{2, 1, 0}, "VMLA", "MULAD"},
	{VMLS_EQ_F32, []int{2, 1, 0}, "VMLS", "MULSF"},
	{VMLS_EQ_F64, []int{2, 1, 0}, "VMLS", "MULSD"},
	{VNMLA_EQ_F32, []int{2, 1, 0}, "VNMLA", "NMULAF"},
	{VNMLA_EQ_F64, []int{2, 1, 0}, "VNMLA", "NMULAD"},
	{VNMLS_EQ_F32, []int{2, 1, 0}, "VNMLS", "NMULSF"},
	{VNMLS_EQ_F64, []int{2, 1, 0}, "VNMLS", "NMULSD"},
	{VDIV_EQ_F32, []int{2, 1, 0}, "VDIV", "DIVF"},
	{VDIV_EQ_F64, []int{2, 1, 0}, "VDIV", "DIVD"},
	{VNEG_EQ_F32, []int{1, 0}, "VNEG", "NEGF"},
	{VNEG_EQ_F64, []int{1, 0}, "VNEG", "NEGD"},
	{VABS_EQ_F32, []int{1, 0}, "VABS", "ABSF"},
	{VABS_EQ_F64, []int{1, 0}, "VABS", "ABSD"},
	{VSQRT_EQ_F32, []int{1, 0}, "VSQRT", "SQRTF"},
	{VSQRT_EQ_F64, []int{1, 0}, "VSQRT", "SQRTD"},
	{VCMP_EQ_F32, []int{1, 0}, "VCMP", "CMPF"},
	{VCMP_EQ_F64, []int{1, 0}, "VCMP", "CMPD"},
	{VCMP_E_EQ_F32, []int{1, 0}, "VCMP.E", "CMPF"},
	{VCMP_E_EQ_F64, []int{1, 0}, "VCMP.E", "CMPD"},
	{VLDR_EQ, []int{1}, "VLDR", "MOV"},
	{VSTR_EQ, []int{1}, "VSTR", "MOV"},
	{VMOV_EQ_F32, []int{1, 0}, "VMOV", "MOVF"},
	{VMOV_EQ_F64, []int{1, 0}, "VMOV", "MOVD"},
	{VMOV_EQ_32, []int{1, 0}, "VMOV", "MOVW"},
	{VMOV_EQ, []int{1, 0}, "VMOV", "MOVW"},
	{VCVT_EQ_F64_F32, []int{1, 0}, "VCVT", "MOVFD"},
	{VCVT_EQ_F32_F64, []int{1, 0}, "VCVT", "MOVDF"},
	{VCVT_EQ_F32_U32, []int{1, 0}, "VCVT", "MOVWF.U"},
	{VCVT_EQ_F32_S32, []int{1, 0}, "VCVT", "MOVWF"},
	{VCVT_EQ_S32_F32, []int{1, 0}, "VCVT", "MOVFW"},
	{VCVT_EQ_U32_F32, []int{1, 0}, "VCVT", "MOVFW.U"},
	{VCVT_EQ_F64_U32, []int{1, 0}, "VCVT", "MOVWD.U"},
	{VCVT_EQ_F64_S32, []int{1, 0}, "VCVT", "MOVWD"},
	{VCVT_EQ_S32_F64, []int{1, 0}, "VCVT", "MOVDW"},
	{VCVT_EQ_U32_F64, []int{1, 0}, "VCVT", "MOVDW.U"},
}

// convert FP instructions from GNU syntax to Plan 9 syntax, for example,
// vadd.f32 s0, s3, s4 -> ADDF F0, S3, F2
// vsub.f64 d0, d2, d4 -> SUBD F0, F2, F4
// vldr s2, [r11] -> MOVF (R11), F1
// inputs: instruction name and arguments in GNU syntax
// return values: corresponding instruction name and arguments in Plan 9 syntax
func fpTrans(inst *Inst, op string, args []string) (string, []string) {
	for _, fp := range fpInst {
		if inst.Op&^15 == fp.op {
			// remove gnu syntax suffixes
			op = strings.Replace(op, ".F32", "", -1)
			op = strings.Replace(op, ".F64", "", -1)
			op = strings.Replace(op, ".S32", "", -1)
			op = strings.Replace(op, ".U32", "", -1)
			op = strings.Replace(op, ".32", "", -1)
			// compose op name
			if fp.op == VLDR_EQ || fp.op == VSTR_EQ {
				switch {
				case strings.HasPrefix(args[fp.transArgs[0]], "D"):
					op = "MOVD" + op[len(fp.gnuName):]
				case strings.HasPrefix(args[fp.transArgs[0]], "S"):
					op = "MOVF" + op[len(fp.gnuName):]
				default:
					panic(fmt.Sprintf("wrong FP register: %v", inst))
				}
			} else {
				op = fp.goName + op[len(fp.gnuName):]
			}
			// transform registers
			for ix, ri := range fp.transArgs {
				switch {
				case strings.HasSuffix(args[ri], "[1]"): // MOVW Rx, Dy[1]
					break
				case strings.HasSuffix(args[ri], "[0]"): // Dx[0] -> Fx
					args[ri] = strings.Replace(args[ri], "[0]", "", -1)
					fallthrough
				case strings.HasPrefix(args[ri], "D"): // Dx -> Fx
					args[ri] = "F" + args[ri][1:]
				case strings.HasPrefix(args[ri], "S"):
					if inst.Args[ix].(Reg)&1 == 0 { // Sx -> Fy, y = x/2, if x is even
						args[ri] = fmt.Sprintf("F%d", (inst.Args[ix].(Reg)-S0)/2)
					}
				case strings.HasPrefix(args[ri], "$"): // CMPF/CMPD $0, Fx
					break
				case strings.HasPrefix(args[ri], "R"): // MOVW Rx, Dy[1]
					break
				default:
					panic(fmt.Sprintf("wrong FP register: %v", inst))
				}
			}
			break
		}
	}
	return op, args
}

"""



```