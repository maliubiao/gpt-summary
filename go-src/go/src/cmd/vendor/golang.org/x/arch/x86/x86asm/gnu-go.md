Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Goal:** The request asks for the functionality of the Go code in `gnu.go`, which seems to be related to converting x86 assembly instructions into GNU assembler syntax (AT&T syntax).

2. **Identify the Main Function:** The `GNUSyntax` function is the entry point and clearly responsible for the conversion. This will be the focus of my analysis.

3. **Break Down `GNUSyntax` Functionality:** I'll go through the `GNUSyntax` function section by section, noting what each part does:

    * **Preamble:**  Notes about GNU/AT&T syntax and that the `inst` is a value copy.
    * **Symbol Lookup:** Handles the case where no symbol lookup function is provided.
    * **Opcode Adjustments (Switch Statement):**  This is a series of `case` statements modifying the `inst.Op` based on certain conditions. I need to understand *why* these adjustments are happening. The comments provide clues (e.g., "libopcodes swaps").
    * **Implicit Arguments (Switch Statement):**  This part adds arguments to the instruction that are not explicitly present in the encoding but are part of the GNU syntax. I need to see which instructions have these implicit arguments.
    * **Prefix Adjustments (Switch Statement):** This is about controlling which prefixes are displayed in the GNU syntax. The comments explain the logic (display non-implicit prefixes). I need to pay attention to the specific cases where this logic is overridden.
    * **XACQUIRE/XRELEASE Adjustment:** This section deals with how `REP` prefixes are treated in the context of `XACQUIRE` and `XRELEASE`.
    * **Opcode Determination:** Converts the `inst.Op` to a string and checks for alternative GNU mnemonics.
    * **Opcode Suffix Determination:**  This is a crucial part. The code checks if a size suffix (like `l`, `w`, `b`, `q`) is needed based on the operands. I need to understand the conditions under which the suffix is omitted or added.
    * **Special Case Opcodes (Switch Statement):** Handles specific instructions with unique GNU syntax requirements (e.g., `INT 3`, `CMPPS`).
    * **Argument Formatting:**  Calls the `gnuArg` function to format individual arguments.
    * **Argument Reversal:**  Reverses the order of arguments for most instructions, as per AT&T syntax.
    * **Prefix String Building:**  Constructs the prefix part of the output string, handling implicit prefixes and special cases.
    * **Final Assembly:** Combines the prefix, opcode, and formatted arguments into the final GNU assembly string.

4. **Analyze Helper Functions:** I'll briefly examine the purpose of other functions:

    * `gnuArg`:  Formats a single instruction argument into GNU syntax. Handles registers, memory operands (including segment prefixes and symbol lookups), relative addresses, and immediate values.
    * `countPrefix`, `markLastImplicit`, `unmarkImplicit`: Functions for manipulating instruction prefixes.
    * `byteSizeSuffix`, `argBytes`, `regBytes`:  Functions for determining operand sizes.
    * `isFloat`, `isFloatInt`:  Helper functions to identify floating-point instructions.
    * `gccRegName`, `gnuOp`, `cmppsOps`, `pclmulqOps`: Data structures (arrays and maps) containing GNU-specific names and strings.

5. **Infer the Go Functionality:** Based on the code and function names, it's clear this code is part of a package for working with x86 assembly instructions, specifically for *disassembling* or *formatting* instructions into the GNU assembler syntax.

6. **Provide Code Examples:**  I'll choose representative instructions and demonstrate how `GNUSyntax` would convert them, including:

    * A simple instruction with register operands.
    * An instruction with a memory operand.
    * An instruction with an immediate operand.
    * An instruction that requires a size suffix.
    * An instruction with a prefix.
    * An instruction with a relative jump target.

7. **Explain Command-Line Parameter Handling (if any):**  In this specific code, there's no direct command-line parameter handling. The input is a structured `Inst` object. I'll clarify this.

8. **Identify Potential User Errors:** I'll consider common mistakes users might make when *using* this code or the larger assembly processing package it belongs to. Examples include:

    * Incorrectly assuming Intel syntax.
    * Not understanding the implications of prefixes.
    * Misinterpreting operand sizes if not explicitly specified in the GNU syntax.

9. **Structure the Output:**  I'll organize my findings into clear sections as requested: Functionality, Go Functionality, Code Examples, Command-Line Parameters, and Potential Errors.

10. **Review and Refine:** I'll read through my answer to ensure accuracy, clarity, and completeness, making sure it directly addresses all aspects of the prompt. I'll double-check the code examples and explanations. For instance, I initially focused heavily on the syntax conversion itself. I realized I needed to explicitly state that this is likely part of a *disassembler* or assembler component.

By following these steps, I can systematically analyze the code and provide a comprehensive and accurate answer to the request.
这段Go语言代码是 `go/src/cmd/vendor/golang.org/x/arch/x86/x86asm/gnu.go` 文件的一部分，它的主要功能是将一个已经解码的 x86 汇编指令 (`Inst` 结构体) 转换为 GNU 汇编器的语法 (也称为 AT&T 语法) 的字符串表示形式。

**功能列表:**

1. **指令到 GNU 语法的转换:**  核心功能是将 `Inst` 结构体表示的指令转换为符合 GNU 汇编器语法的字符串。这包括：
    * **操作码 (Opcode) 的转换:** 将内部表示的操作码名称转换为 GNU 汇编器使用的名称 (例如 `MOV` 保持不变，但 `CBW` 变为 `cbtw`)。
    * **操作数 (Operands) 的转换:** 将指令的操作数 (寄存器、内存地址、立即数、相对地址) 转换为 GNU 汇编器的表示形式 (例如，寄存器名前加 `%`，内存地址用括号括起来，立即数前加 `$`)。
    * **前缀 (Prefixes) 的处理:**  处理指令的前缀，并按照 GNU 汇编器的规则进行显示或省略。
    * **后缀 (Suffixes) 的添加:** 根据操作数的大小和指令类型，添加操作码后缀 (如 `b`, `w`, `l`, `q`) 来明确数据大小。
    * **特殊指令的处理:**  针对一些特殊的 x86 指令，进行特定的语法调整以符合 GNU 汇编器的习惯。

2. **符号名称查找:**  允许提供一个 `symname` 函数，用于将内存地址转换为符号名称。如果提供了该函数，那么在表示内存地址或立即数时，会尝试使用符号名称来提高可读性。

3. **模拟 GNU 汇编器的特性:**  代码中包含一些逻辑，用于模拟 GNU 汇编器在指令显示方面的特殊性，例如：
    * **某些操作码的调整:** 例如 `FSUBR`/`FSUB` 和 `FDIVR`/`FDIV` 的顺序调整。
    * **隐式操作数的添加:**  对于某些指令 (如 `MONITOR`, `MWAIT`)，添加 GNU 汇编器中约定的隐式操作数。
    * **前缀显示的控制:**  根据 GNU 汇编器的规则，决定哪些前缀应该显示，哪些应该被认为是隐式的而不显示。

**Go 语言功能实现推断和代码示例:**

这个代码片段很可能被用于一个 x86 汇编语言的反汇编器或者一个将某种中间表示转换为汇编代码的工具中。它负责将解码后的机器指令以人类可读的 GNU 汇编格式呈现出来。

**示例代码:**

假设我们有一个解码后的 `Inst` 结构体，表示 `MOV EAX, 0x10` 这条指令。

```go
package main

import (
	"fmt"
	"go/src/cmd/vendor/golang.org/x/arch/x86/x86asm"
)

func main() {
	inst := x86asm.Inst{
		Op:     x86asm.MOV,
		Args: []x86asm.Arg{
			x86asm.EAX,
			x86asm.Imm(0x10),
		},
		MemBytes: 4, // 假设是 32 位操作
	}

	// 一个简单的符号查找函数，这里没有实际的符号
	symname := func(addr uint64) (string, uint64) {
		return "", 0
	}

	gnuSyntax := x86asm.GNUSyntax(inst, 0, symname)
	fmt.Println(gnuSyntax) // 输出: movl $0x10,%eax
}
```

**假设的输入与输出:**

* **输入 `Inst` 结构体 (示例 1):**
  ```go
  x86asm.Inst{
      Op: x86asm.ADD,
      Args: []x86asm.Arg{
          x86asm.Reg(x86asm.EBX),
          x86asm.Imm(5),
      },
      MemBytes: 4,
  }
  ```
* **输出字符串 (示例 1):**
  ```
  addl $0x5,%ebx
  ```

* **输入 `Inst` 结构体 (示例 2，包含内存操作数):**
  ```go
  x86asm.Inst{
      Op: x86asm.MOV,
      Args: []x86asm.Arg{
          x86asm.Mem{Base: x86asm.EBX, Disp: 8},
          x86asm.EAX,
      },
      MemBytes: 4,
  }
  ```
* **输出字符串 (示例 2):**
  ```
  movl %eax,8(%ebx)
  ```

* **输入 `Inst` 结构体 (示例 3，使用符号名称):**
  ```go
  x86asm.Inst{
      Op: x86asm.JMP,
      Args: []x86asm.Arg{
          x86asm.Rel(100), // 相对跳转 100 字节
      },
      Len: 5, // 假设指令长度为 5 字节
  }
  ```
* **输出字符串 (示例 3，假设在地址 0 解码，并且地址 105 有符号 "target_label"):**
  ```
  jmp target_label
  ```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它的输入是已经解码的 `Inst` 结构体，这些结构体可能是由其他代码 (例如反汇编器) 从二进制文件中解析出来的。如果这个文件所在的包被一个命令行工具使用，那么命令行参数的处理逻辑会在调用 `GNUSyntax` 函数之前的代码中。

例如，一个反汇编器的命令行工具可能会接收一个二进制文件路径作为参数，然后读取文件内容，解码其中的指令，并使用 `GNUSyntax` 将解码后的指令转换为 GNU 汇编语法输出到终端或文件。

**使用者易犯错的点:**

1. **假设使用 Intel 语法:**  使用者可能会错误地认为输出是 Intel 语法，这与 GNU 语法在操作数顺序、寄存器表示等方面有明显的不同。例如，Intel 语法是 `MOV EAX, 10h`，而 GNU 语法是 `movl $0x10, %eax`。

2. **不理解操作码后缀的含义:**  GNU 汇编器使用后缀 (如 `b`, `w`, `l`, `q`) 来表示操作数的大小。使用者可能不清楚这些后缀的意义，导致理解指令的操作数大小出错。

   **错误示例:** 看到 `movl $0x10, %eax`，错误地认为移动的是 16 位数据，因为看到了 `%eax` (实际上 `l` 后缀表示 32 位)。

3. **忽略前缀的影响:**  某些前缀会影响指令的行为，但在 GNU 语法中可能不会显式地全部显示出来 (部分前缀被认为是隐式的)。使用者需要了解哪些前缀可能被省略以及它们的含义。

   **错误示例:**  `rep movsb` 在内部可能对应多个前缀，但 `GNUSyntax` 可能会根据规则省略某些前缀的显示。使用者如果只看输出的字符串，可能会遗漏某些关键信息。

4. **混淆立即数和内存地址:**  GNU 语法使用 `$` 前缀表示立即数，没有 `$` 前缀且使用括号括起来表示内存地址。使用者可能会混淆这两种表示方式。

   **错误示例:**  看到 `movl 0x10, %eax`，可能会误认为是将内存地址 `0x10` 的内容移动到 `%eax`，而实际上如果意图是立即数，则应该是 `movl $0x10, %eax`。

总而言之，这段代码的核心作用是将 x86 汇编指令以 GNU 汇编器的风格进行格式化输出，它是构建反汇编器或汇编代码生成工具的重要组成部分。使用者需要了解 GNU 汇编器的语法规则，才能正确理解和使用这段代码的输出结果。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/x86/x86asm/gnu.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86asm

import (
	"fmt"
	"strings"
)

// GNUSyntax returns the GNU assembler syntax for the instruction, as defined by GNU binutils.
// This general form is often called “AT&T syntax” as a reference to AT&T System V Unix.
func GNUSyntax(inst Inst, pc uint64, symname SymLookup) string {
	// Rewrite instruction to mimic GNU peculiarities.
	// Note that inst has been passed by value and contains
	// no pointers, so any changes we make here are local
	// and will not propagate back out to the caller.

	if symname == nil {
		symname = func(uint64) (string, uint64) { return "", 0 }
	}

	// Adjust opcode [sic].
	switch inst.Op {
	case FDIV, FDIVR, FSUB, FSUBR, FDIVP, FDIVRP, FSUBP, FSUBRP:
		// DC E0, DC F0: libopcodes swaps FSUBR/FSUB and FDIVR/FDIV, at least
		// if you believe the Intel manual is correct (the encoding is irregular as given;
		// libopcodes uses the more regular expected encoding).
		// TODO(rsc): Test to ensure Intel manuals are correct and report to libopcodes maintainers?
		// NOTE: iant thinks this is deliberate, but we can't find the history.
		_, reg1 := inst.Args[0].(Reg)
		_, reg2 := inst.Args[1].(Reg)
		if reg1 && reg2 && (inst.Opcode>>24 == 0xDC || inst.Opcode>>24 == 0xDE) {
			switch inst.Op {
			case FDIV:
				inst.Op = FDIVR
			case FDIVR:
				inst.Op = FDIV
			case FSUB:
				inst.Op = FSUBR
			case FSUBR:
				inst.Op = FSUB
			case FDIVP:
				inst.Op = FDIVRP
			case FDIVRP:
				inst.Op = FDIVP
			case FSUBP:
				inst.Op = FSUBRP
			case FSUBRP:
				inst.Op = FSUBP
			}
		}

	case MOVNTSD:
		// MOVNTSD is F2 0F 2B /r.
		// MOVNTSS is F3 0F 2B /r (supposedly; not in manuals).
		// Usually inner prefixes win for display,
		// so that F3 F2 0F 2B 11 is REP MOVNTSD
		// and F2 F3 0F 2B 11 is REPN MOVNTSS.
		// Libopcodes always prefers MOVNTSS regardless of prefix order.
		if countPrefix(&inst, 0xF3) > 0 {
			found := false
			for i := len(inst.Prefix) - 1; i >= 0; i-- {
				switch inst.Prefix[i] & 0xFF {
				case 0xF3:
					if !found {
						found = true
						inst.Prefix[i] |= PrefixImplicit
					}
				case 0xF2:
					inst.Prefix[i] &^= PrefixImplicit
				}
			}
			inst.Op = MOVNTSS
		}
	}

	// Add implicit arguments.
	switch inst.Op {
	case MONITOR:
		inst.Args[0] = EDX
		inst.Args[1] = ECX
		inst.Args[2] = EAX
		if inst.AddrSize == 16 {
			inst.Args[2] = AX
		}

	case MWAIT:
		if inst.Mode == 64 {
			inst.Args[0] = RCX
			inst.Args[1] = RAX
		} else {
			inst.Args[0] = ECX
			inst.Args[1] = EAX
		}
	}

	// Adjust which prefixes will be displayed.
	// The rule is to display all the prefixes not implied by
	// the usual instruction display, that is, all the prefixes
	// except the ones with PrefixImplicit set.
	// However, of course, there are exceptions to the rule.
	switch inst.Op {
	case CRC32:
		// CRC32 has a mandatory F2 prefix.
		// If there are multiple F2s and no F3s, the extra F2s do not print.
		// (And Decode has already marked them implicit.)
		// However, if there is an F3 anywhere, then the extra F2s do print.
		// If there are multiple F2 prefixes *and* an (ignored) F3,
		// then libopcodes prints the extra F2s as REPNs.
		if countPrefix(&inst, 0xF2) > 1 {
			unmarkImplicit(&inst, 0xF2)
			markLastImplicit(&inst, 0xF2)
		}

		// An unused data size override should probably be shown,
		// to distinguish DATA16 CRC32B from plain CRC32B,
		// but libopcodes always treats the final override as implicit
		// and the others as explicit.
		unmarkImplicit(&inst, PrefixDataSize)
		markLastImplicit(&inst, PrefixDataSize)

	case CVTSI2SD, CVTSI2SS:
		if !isMem(inst.Args[1]) {
			markLastImplicit(&inst, PrefixDataSize)
		}

	case CVTSD2SI, CVTSS2SI, CVTTSD2SI, CVTTSS2SI,
		ENTER, FLDENV, FNSAVE, FNSTENV, FRSTOR, LGDT, LIDT, LRET,
		POP, PUSH, RET, SGDT, SIDT, SYSRET, XBEGIN:
		markLastImplicit(&inst, PrefixDataSize)

	case LOOP, LOOPE, LOOPNE, MONITOR:
		markLastImplicit(&inst, PrefixAddrSize)

	case MOV:
		// The 16-bit and 32-bit forms of MOV Sreg, dst and MOV src, Sreg
		// cannot be distinguished when src or dst refers to memory, because
		// Sreg is always a 16-bit value, even when we're doing a 32-bit
		// instruction. Because the instruction tables distinguished these two,
		// any operand size prefix has been marked as used (to decide which
		// branch to take). Unmark it, so that it will show up in disassembly,
		// so that the reader can tell the size of memory operand.
		// up with the same arguments
		dst, _ := inst.Args[0].(Reg)
		src, _ := inst.Args[1].(Reg)
		if ES <= src && src <= GS && isMem(inst.Args[0]) || ES <= dst && dst <= GS && isMem(inst.Args[1]) {
			unmarkImplicit(&inst, PrefixDataSize)
		}

	case MOVDQU:
		if countPrefix(&inst, 0xF3) > 1 {
			unmarkImplicit(&inst, 0xF3)
			markLastImplicit(&inst, 0xF3)
		}

	case MOVQ2DQ:
		markLastImplicit(&inst, PrefixDataSize)

	case SLDT, SMSW, STR, FXRSTOR, XRSTOR, XSAVE, XSAVEOPT, CMPXCHG8B:
		if isMem(inst.Args[0]) {
			unmarkImplicit(&inst, PrefixDataSize)
		}

	case SYSEXIT:
		unmarkImplicit(&inst, PrefixDataSize)
	}

	if isCondJmp[inst.Op] || isLoop[inst.Op] || inst.Op == JCXZ || inst.Op == JECXZ || inst.Op == JRCXZ {
		if countPrefix(&inst, PrefixCS) > 0 && countPrefix(&inst, PrefixDS) > 0 {
			for i, p := range inst.Prefix {
				switch p & 0xFFF {
				case PrefixPN, PrefixPT:
					inst.Prefix[i] &= 0xF0FF // cut interpretation bits, producing original segment prefix
				}
			}
		}
	}

	// XACQUIRE/XRELEASE adjustment.
	if inst.Op == MOV {
		// MOV into memory is a candidate for turning REP into XRELEASE.
		// However, if the REP is followed by a REPN, that REPN blocks the
		// conversion.
		haveREPN := false
		for i := len(inst.Prefix) - 1; i >= 0; i-- {
			switch inst.Prefix[i] &^ PrefixIgnored {
			case PrefixREPN:
				haveREPN = true
			case PrefixXRELEASE:
				if haveREPN {
					inst.Prefix[i] = PrefixREP
				}
			}
		}
	}

	// We only format the final F2/F3 as XRELEASE/XACQUIRE.
	haveXA := false
	haveXR := false
	for i := len(inst.Prefix) - 1; i >= 0; i-- {
		switch inst.Prefix[i] &^ PrefixIgnored {
		case PrefixXRELEASE:
			if !haveXR {
				haveXR = true
			} else {
				inst.Prefix[i] = PrefixREP
			}

		case PrefixXACQUIRE:
			if !haveXA {
				haveXA = true
			} else {
				inst.Prefix[i] = PrefixREPN
			}
		}
	}

	// Determine opcode.
	op := strings.ToLower(inst.Op.String())
	if alt := gnuOp[inst.Op]; alt != "" {
		op = alt
	}

	// Determine opcode suffix.
	// Libopcodes omits the suffix if the width of the operation
	// can be inferred from a register arguments. For example,
	// add $1, %ebx has no suffix because you can tell from the
	// 32-bit register destination that it is a 32-bit add,
	// but in addl $1, (%ebx), the destination is memory, so the
	// size is not evident without the l suffix.
	needSuffix := true
SuffixLoop:
	for i, a := range inst.Args {
		if a == nil {
			break
		}
		switch a := a.(type) {
		case Reg:
			switch inst.Op {
			case MOVSX, MOVZX:
				continue

			case SHL, SHR, RCL, RCR, ROL, ROR, SAR:
				if i == 1 {
					// shift count does not tell us operand size
					continue
				}

			case CRC32:
				// The source argument does tell us operand size,
				// but libopcodes still always puts a suffix on crc32.
				continue

			case PUSH, POP:
				// Even though segment registers are 16-bit, push and pop
				// can save/restore them from 32-bit slots, so they
				// do not imply operand size.
				if ES <= a && a <= GS {
					continue
				}

			case CVTSI2SD, CVTSI2SS:
				// The integer register argument takes priority.
				if X0 <= a && a <= X15 {
					continue
				}
			}

			if AL <= a && a <= R15 || ES <= a && a <= GS || X0 <= a && a <= X15 || M0 <= a && a <= M7 {
				needSuffix = false
				break SuffixLoop
			}
		}
	}

	if needSuffix {
		switch inst.Op {
		case CMPXCHG8B, FLDCW, FNSTCW, FNSTSW, LDMXCSR, LLDT, LMSW, LTR, PCLMULQDQ,
			SETA, SETAE, SETB, SETBE, SETE, SETG, SETGE, SETL, SETLE, SETNE, SETNO, SETNP, SETNS, SETO, SETP, SETS,
			SLDT, SMSW, STMXCSR, STR, VERR, VERW:
			// For various reasons, libopcodes emits no suffix for these instructions.

		case CRC32:
			op += byteSizeSuffix(argBytes(&inst, inst.Args[1]))

		case LGDT, LIDT, SGDT, SIDT:
			op += byteSizeSuffix(inst.DataSize / 8)

		case MOVZX, MOVSX:
			// Integer size conversions get two suffixes.
			op = op[:4] + byteSizeSuffix(argBytes(&inst, inst.Args[1])) + byteSizeSuffix(argBytes(&inst, inst.Args[0]))

		case LOOP, LOOPE, LOOPNE:
			// Add w suffix to indicate use of CX register instead of ECX.
			if inst.AddrSize == 16 {
				op += "w"
			}

		case CALL, ENTER, JMP, LCALL, LEAVE, LJMP, LRET, RET, SYSRET, XBEGIN:
			// Add w suffix to indicate use of 16-bit target.
			// Exclude JMP rel8.
			if inst.Opcode>>24 == 0xEB {
				break
			}
			if inst.DataSize == 16 && inst.Mode != 16 {
				markLastImplicit(&inst, PrefixDataSize)
				op += "w"
			} else if inst.Mode == 64 {
				op += "q"
			}

		case FRSTOR, FNSAVE, FNSTENV, FLDENV:
			// Add s suffix to indicate shortened FPU state (I guess).
			if inst.DataSize == 16 {
				op += "s"
			}

		case PUSH, POP:
			if markLastImplicit(&inst, PrefixDataSize) {
				op += byteSizeSuffix(inst.DataSize / 8)
			} else if inst.Mode == 64 {
				op += "q"
			} else {
				op += byteSizeSuffix(inst.MemBytes)
			}

		default:
			if isFloat(inst.Op) {
				// I can't explain any of this, but it's what libopcodes does.
				switch inst.MemBytes {
				default:
					if (inst.Op == FLD || inst.Op == FSTP) && isMem(inst.Args[0]) {
						op += "t"
					}
				case 4:
					if isFloatInt(inst.Op) {
						op += "l"
					} else {
						op += "s"
					}
				case 8:
					if isFloatInt(inst.Op) {
						op += "ll"
					} else {
						op += "l"
					}
				}
				break
			}

			op += byteSizeSuffix(inst.MemBytes)
		}
	}

	// Adjust special case opcodes.
	switch inst.Op {
	case 0:
		if inst.Prefix[0] != 0 {
			return strings.ToLower(inst.Prefix[0].String())
		}

	case INT:
		if inst.Opcode>>24 == 0xCC {
			inst.Args[0] = nil
			op = "int3"
		}

	case CMPPS, CMPPD, CMPSD_XMM, CMPSS:
		imm, ok := inst.Args[2].(Imm)
		if ok && 0 <= imm && imm < 8 {
			inst.Args[2] = nil
			op = cmppsOps[imm] + op[3:]
		}

	case PCLMULQDQ:
		imm, ok := inst.Args[2].(Imm)
		if ok && imm&^0x11 == 0 {
			inst.Args[2] = nil
			op = pclmulqOps[(imm&0x10)>>3|(imm&1)]
		}

	case XLATB:
		if markLastImplicit(&inst, PrefixAddrSize) {
			op = "xlat" // not xlatb
		}
	}

	// Build list of argument strings.
	var (
		usedPrefixes bool     // segment prefixes consumed by Mem formatting
		args         []string // formatted arguments
	)
	for i, a := range inst.Args {
		if a == nil {
			break
		}
		switch inst.Op {
		case MOVSB, MOVSW, MOVSD, MOVSQ, OUTSB, OUTSW, OUTSD:
			if i == 0 {
				usedPrefixes = true // disable use of prefixes for first argument
			} else {
				usedPrefixes = false
			}
		}
		if a == Imm(1) && (inst.Opcode>>24)&^1 == 0xD0 {
			continue
		}
		args = append(args, gnuArg(&inst, pc, symname, a, &usedPrefixes))
	}

	// The default is to print the arguments in reverse Intel order.
	// A few instructions inhibit this behavior.
	switch inst.Op {
	case BOUND, LCALL, ENTER, LJMP:
		// no reverse
	default:
		// reverse args
		for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
			args[i], args[j] = args[j], args[i]
		}
	}

	// Build prefix string.
	// Must be after argument formatting, which can turn off segment prefixes.
	var (
		prefix       = "" // output string
		numAddr      = 0
		numData      = 0
		implicitData = false
	)
	for _, p := range inst.Prefix {
		if p&0xFF == PrefixDataSize && p&PrefixImplicit != 0 {
			implicitData = true
		}
	}
	for _, p := range inst.Prefix {
		if p == 0 || p.IsVEX() {
			break
		}
		if p&PrefixImplicit != 0 {
			continue
		}
		switch p &^ (PrefixIgnored | PrefixInvalid) {
		default:
			if p.IsREX() {
				if p&0xFF == PrefixREX {
					prefix += "rex "
				} else {
					prefix += "rex." + p.String()[4:] + " "
				}
				break
			}
			prefix += strings.ToLower(p.String()) + " "

		case PrefixPN:
			op += ",pn"
			continue

		case PrefixPT:
			op += ",pt"
			continue

		case PrefixAddrSize, PrefixAddr16, PrefixAddr32:
			// For unknown reasons, if the addr16 prefix is repeated,
			// libopcodes displays all but the last as addr32, even though
			// the addressing form used in a memory reference is clearly
			// still 16-bit.
			n := 32
			if inst.Mode == 32 {
				n = 16
			}
			numAddr++
			if countPrefix(&inst, PrefixAddrSize) > numAddr {
				n = inst.Mode
			}
			prefix += fmt.Sprintf("addr%d ", n)
			continue

		case PrefixData16, PrefixData32:
			if implicitData && countPrefix(&inst, PrefixDataSize) > 1 {
				// Similar to the addr32 logic above, but it only kicks in
				// when something used the data size prefix (one is implicit).
				n := 16
				if inst.Mode == 16 {
					n = 32
				}
				numData++
				if countPrefix(&inst, PrefixDataSize) > numData {
					if inst.Mode == 16 {
						n = 16
					} else {
						n = 32
					}
				}
				prefix += fmt.Sprintf("data%d ", n)
				continue
			}
			prefix += strings.ToLower(p.String()) + " "
		}
	}

	// Finally! Put it all together.
	text := prefix + op
	if args != nil {
		text += " "
		// Indirect call/jmp gets a star to distinguish from direct jump address.
		if (inst.Op == CALL || inst.Op == JMP || inst.Op == LJMP || inst.Op == LCALL) && (isMem(inst.Args[0]) || isReg(inst.Args[0])) {
			text += "*"
		}
		text += strings.Join(args, ",")
	}
	return text
}

// gnuArg returns the GNU syntax for the argument x from the instruction inst.
// If *usedPrefixes is false and x is a Mem, then the formatting
// includes any segment prefixes and sets *usedPrefixes to true.
func gnuArg(inst *Inst, pc uint64, symname SymLookup, x Arg, usedPrefixes *bool) string {
	if x == nil {
		return "<nil>"
	}
	switch x := x.(type) {
	case Reg:
		switch inst.Op {
		case CVTSI2SS, CVTSI2SD, CVTSS2SI, CVTSD2SI, CVTTSD2SI, CVTTSS2SI:
			if inst.DataSize == 16 && EAX <= x && x <= R15L {
				x -= EAX - AX
			}

		case IN, INSB, INSW, INSD, OUT, OUTSB, OUTSW, OUTSD:
			// DX is the port, but libopcodes prints it as if it were a memory reference.
			if x == DX {
				return "(%dx)"
			}
		case VMOVDQA, VMOVDQU, VMOVNTDQA, VMOVNTDQ:
			return strings.Replace(gccRegName[x], "xmm", "ymm", -1)
		}
		return gccRegName[x]
	case Mem:
		if s, disp := memArgToSymbol(x, pc, inst.Len, symname); s != "" {
			suffix := ""
			if disp != 0 {
				suffix = fmt.Sprintf("%+d", disp)
			}
			return fmt.Sprintf("%s%s", s, suffix)
		}
		seg := ""
		var haveCS, haveDS, haveES, haveFS, haveGS, haveSS bool
		switch x.Segment {
		case CS:
			haveCS = true
		case DS:
			haveDS = true
		case ES:
			haveES = true
		case FS:
			haveFS = true
		case GS:
			haveGS = true
		case SS:
			haveSS = true
		}
		switch inst.Op {
		case INSB, INSW, INSD, STOSB, STOSW, STOSD, STOSQ, SCASB, SCASW, SCASD, SCASQ:
			// These do not accept segment prefixes, at least in the GNU rendering.
		default:
			if *usedPrefixes {
				break
			}
			for i := len(inst.Prefix) - 1; i >= 0; i-- {
				p := inst.Prefix[i] &^ PrefixIgnored
				if p == 0 {
					continue
				}
				switch p {
				case PrefixCS:
					if !haveCS {
						haveCS = true
						inst.Prefix[i] |= PrefixImplicit
					}
				case PrefixDS:
					if !haveDS {
						haveDS = true
						inst.Prefix[i] |= PrefixImplicit
					}
				case PrefixES:
					if !haveES {
						haveES = true
						inst.Prefix[i] |= PrefixImplicit
					}
				case PrefixFS:
					if !haveFS {
						haveFS = true
						inst.Prefix[i] |= PrefixImplicit
					}
				case PrefixGS:
					if !haveGS {
						haveGS = true
						inst.Prefix[i] |= PrefixImplicit
					}
				case PrefixSS:
					if !haveSS {
						haveSS = true
						inst.Prefix[i] |= PrefixImplicit
					}
				}
			}
			*usedPrefixes = true
		}
		if haveCS {
			seg += "%cs:"
		}
		if haveDS {
			seg += "%ds:"
		}
		if haveSS {
			seg += "%ss:"
		}
		if haveES {
			seg += "%es:"
		}
		if haveFS {
			seg += "%fs:"
		}
		if haveGS {
			seg += "%gs:"
		}
		disp := ""
		if x.Disp != 0 {
			disp = fmt.Sprintf("%#x", x.Disp)
		}
		if x.Scale == 0 || x.Index == 0 && x.Scale == 1 && (x.Base == ESP || x.Base == RSP || x.Base == 0 && inst.Mode == 64) {
			if x.Base == 0 {
				return seg + disp
			}
			return fmt.Sprintf("%s%s(%s)", seg, disp, gccRegName[x.Base])
		}
		base := gccRegName[x.Base]
		if x.Base == 0 {
			base = ""
		}
		index := gccRegName[x.Index]
		if x.Index == 0 {
			if inst.AddrSize == 64 {
				index = "%riz"
			} else {
				index = "%eiz"
			}
		}
		if AX <= x.Base && x.Base <= DI {
			// 16-bit addressing - no scale
			return fmt.Sprintf("%s%s(%s,%s)", seg, disp, base, index)
		}
		return fmt.Sprintf("%s%s(%s,%s,%d)", seg, disp, base, index, x.Scale)
	case Rel:
		if pc == 0 {
			return fmt.Sprintf(".%+#x", int64(x))
		} else {
			addr := pc + uint64(inst.Len) + uint64(x)
			if s, base := symname(addr); s != "" && addr == base {
				return fmt.Sprintf("%s", s)
			} else {
				addr := pc + uint64(inst.Len) + uint64(x)
				return fmt.Sprintf("%#x", addr)
			}
		}
	case Imm:
		if s, base := symname(uint64(x)); s != "" {
			suffix := ""
			if uint64(x) != base {
				suffix = fmt.Sprintf("%+d", uint64(x)-base)
			}
			return fmt.Sprintf("$%s%s", s, suffix)
		}
		if inst.Mode == 32 {
			return fmt.Sprintf("$%#x", uint32(x))
		}
		return fmt.Sprintf("$%#x", int64(x))
	}
	return x.String()
}

var gccRegName = [...]string{
	0:    "REG0",
	AL:   "%al",
	CL:   "%cl",
	BL:   "%bl",
	DL:   "%dl",
	AH:   "%ah",
	CH:   "%ch",
	BH:   "%bh",
	DH:   "%dh",
	SPB:  "%spl",
	BPB:  "%bpl",
	SIB:  "%sil",
	DIB:  "%dil",
	R8B:  "%r8b",
	R9B:  "%r9b",
	R10B: "%r10b",
	R11B: "%r11b",
	R12B: "%r12b",
	R13B: "%r13b",
	R14B: "%r14b",
	R15B: "%r15b",
	AX:   "%ax",
	CX:   "%cx",
	BX:   "%bx",
	DX:   "%dx",
	SP:   "%sp",
	BP:   "%bp",
	SI:   "%si",
	DI:   "%di",
	R8W:  "%r8w",
	R9W:  "%r9w",
	R10W: "%r10w",
	R11W: "%r11w",
	R12W: "%r12w",
	R13W: "%r13w",
	R14W: "%r14w",
	R15W: "%r15w",
	EAX:  "%eax",
	ECX:  "%ecx",
	EDX:  "%edx",
	EBX:  "%ebx",
	ESP:  "%esp",
	EBP:  "%ebp",
	ESI:  "%esi",
	EDI:  "%edi",
	R8L:  "%r8d",
	R9L:  "%r9d",
	R10L: "%r10d",
	R11L: "%r11d",
	R12L: "%r12d",
	R13L: "%r13d",
	R14L: "%r14d",
	R15L: "%r15d",
	RAX:  "%rax",
	RCX:  "%rcx",
	RDX:  "%rdx",
	RBX:  "%rbx",
	RSP:  "%rsp",
	RBP:  "%rbp",
	RSI:  "%rsi",
	RDI:  "%rdi",
	R8:   "%r8",
	R9:   "%r9",
	R10:  "%r10",
	R11:  "%r11",
	R12:  "%r12",
	R13:  "%r13",
	R14:  "%r14",
	R15:  "%r15",
	IP:   "%ip",
	EIP:  "%eip",
	RIP:  "%rip",
	F0:   "%st",
	F1:   "%st(1)",
	F2:   "%st(2)",
	F3:   "%st(3)",
	F4:   "%st(4)",
	F5:   "%st(5)",
	F6:   "%st(6)",
	F7:   "%st(7)",
	M0:   "%mm0",
	M1:   "%mm1",
	M2:   "%mm2",
	M3:   "%mm3",
	M4:   "%mm4",
	M5:   "%mm5",
	M6:   "%mm6",
	M7:   "%mm7",
	X0:   "%xmm0",
	X1:   "%xmm1",
	X2:   "%xmm2",
	X3:   "%xmm3",
	X4:   "%xmm4",
	X5:   "%xmm5",
	X6:   "%xmm6",
	X7:   "%xmm7",
	X8:   "%xmm8",
	X9:   "%xmm9",
	X10:  "%xmm10",
	X11:  "%xmm11",
	X12:  "%xmm12",
	X13:  "%xmm13",
	X14:  "%xmm14",
	X15:  "%xmm15",
	CS:   "%cs",
	SS:   "%ss",
	DS:   "%ds",
	ES:   "%es",
	FS:   "%fs",
	GS:   "%gs",
	GDTR: "%gdtr",
	IDTR: "%idtr",
	LDTR: "%ldtr",
	MSW:  "%msw",
	TASK: "%task",
	CR0:  "%cr0",
	CR1:  "%cr1",
	CR2:  "%cr2",
	CR3:  "%cr3",
	CR4:  "%cr4",
	CR5:  "%cr5",
	CR6:  "%cr6",
	CR7:  "%cr7",
	CR8:  "%cr8",
	CR9:  "%cr9",
	CR10: "%cr10",
	CR11: "%cr11",
	CR12: "%cr12",
	CR13: "%cr13",
	CR14: "%cr14",
	CR15: "%cr15",
	DR0:  "%db0",
	DR1:  "%db1",
	DR2:  "%db2",
	DR3:  "%db3",
	DR4:  "%db4",
	DR5:  "%db5",
	DR6:  "%db6",
	DR7:  "%db7",
	TR0:  "%tr0",
	TR1:  "%tr1",
	TR2:  "%tr2",
	TR3:  "%tr3",
	TR4:  "%tr4",
	TR5:  "%tr5",
	TR6:  "%tr6",
	TR7:  "%tr7",
}

var gnuOp = map[Op]string{
	CBW:       "cbtw",
	CDQ:       "cltd",
	CMPSD:     "cmpsl",
	CMPSD_XMM: "cmpsd",
	CWD:       "cwtd",
	CWDE:      "cwtl",
	CQO:       "cqto",
	INSD:      "insl",
	IRET:      "iretw",
	IRETD:     "iret",
	IRETQ:     "iretq",
	LODSB:     "lods",
	LODSD:     "lods",
	LODSQ:     "lods",
	LODSW:     "lods",
	MOVSD:     "movsl",
	MOVSD_XMM: "movsd",
	OUTSD:     "outsl",
	POPA:      "popaw",
	POPAD:     "popa",
	POPF:      "popfw",
	POPFD:     "popf",
	PUSHA:     "pushaw",
	PUSHAD:    "pusha",
	PUSHF:     "pushfw",
	PUSHFD:    "pushf",
	SCASB:     "scas",
	SCASD:     "scas",
	SCASQ:     "scas",
	SCASW:     "scas",
	STOSB:     "stos",
	STOSD:     "stos",
	STOSQ:     "stos",
	STOSW:     "stos",
	XLATB:     "xlat",
}

var cmppsOps = []string{
	"cmpeq",
	"cmplt",
	"cmple",
	"cmpunord",
	"cmpneq",
	"cmpnlt",
	"cmpnle",
	"cmpord",
}

var pclmulqOps = []string{
	"pclmullqlqdq",
	"pclmulhqlqdq",
	"pclmullqhqdq",
	"pclmulhqhqdq",
}

func countPrefix(inst *Inst, target Prefix) int {
	n := 0
	for _, p := range inst.Prefix {
		if p&0xFF == target&0xFF {
			n++
		}
	}
	return n
}

func markLastImplicit(inst *Inst, prefix Prefix) bool {
	for i := len(inst.Prefix) - 1; i >= 0; i-- {
		p := inst.Prefix[i]
		if p&0xFF == prefix {
			inst.Prefix[i] |= PrefixImplicit
			return true
		}
	}
	return false
}

func unmarkImplicit(inst *Inst, prefix Prefix) {
	for i := len(inst.Prefix) - 1; i >= 0; i-- {
		p := inst.Prefix[i]
		if p&0xFF == prefix {
			inst.Prefix[i] &^= PrefixImplicit
		}
	}
}

func byteSizeSuffix(b int) string {
	switch b {
	case 1:
		return "b"
	case 2:
		return "w"
	case 4:
		return "l"
	case 8:
		return "q"
	}
	return ""
}

func argBytes(inst *Inst, arg Arg) int {
	if isMem(arg) {
		return inst.MemBytes
	}
	return regBytes(arg)
}

func isFloat(op Op) bool {
	switch op {
	case FADD, FCOM, FCOMP, FDIV, FDIVR, FIADD, FICOM, FICOMP, FIDIV, FIDIVR, FILD, FIMUL, FIST, FISTP, FISTTP, FISUB, FISUBR, FLD, FMUL, FST, FSTP, FSUB, FSUBR:
		return true
	}
	return false
}

func isFloatInt(op Op) bool {
	switch op {
	case FIADD, FICOM, FICOMP, FIDIV, FIDIVR, FILD, FIMUL, FIST, FISTP, FISTTP, FISUB, FISUBR:
		return true
	}
	return false
}

"""



```