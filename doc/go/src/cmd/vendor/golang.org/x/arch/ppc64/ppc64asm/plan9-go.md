Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for the functionality of the `plan9.go` file, specifically focusing on the `GoSyntax` function. It also requests examples, considerations for errors, and understanding the larger context if possible.

**2. Initial Reading and Identifying Key Components:**

The first step is to read through the code to get a general sense of what's happening. I immediately noticed:

* **Package Name:** `ppc64asm` - This tells me it's related to assembly for the PowerPC 64-bit architecture.
* **Imports:** `fmt` and `strings` - These are standard Go libraries for formatting and string manipulation, respectively.
* **`GoSyntax` Function:** This is the central function being analyzed. It takes an `Inst`, `pc`, and a `symname` function as input and returns a string. This strongly suggests it's responsible for generating the assembly syntax.
* **`plan9Arg` Function:** This function is called within `GoSyntax` and seems to handle the formatting of individual arguments. The name "plan9Arg" suggests a specific assembly syntax (Plan 9 assembler).
* **`plan9OpMap`:**  This is a map that translates `Op` values to strings, further reinforcing the idea of assembly syntax generation.
* **Helper Functions:**  `reverseMiddleOps`, `reverseOperandOrder`, `revCondMap`, `condName` - These suggest logic for handling different instruction formats and conditional codes.

**3. Deeper Analysis of `GoSyntax`:**

* **Input Parameters:**
    * `inst Inst`: This likely represents a single assembly instruction. I'd look for the definition of `Inst` elsewhere in the codebase.
    * `pc uint64`: Program counter. Essential for resolving relative addresses.
    * `symname func(uint64) (string, uint64)`: A function to look up symbol names. This is crucial for making assembly human-readable.
* **Core Logic:**
    * Handles null instructions.
    * Iterates through the arguments of the instruction, calling `plan9Arg` to format each one.
    * Looks up the instruction's opcode in `plan9OpMap`.
    * Uses a `switch` statement on `inst.Op` to handle different instruction formats and operand orderings. This is the most complex part.
* **Specific Cases in the `switch`:**
    * Standard instructions: dst, sA, sB, ... with possible operand reversal.
    * Special instructions like `PASTECC`, `SYNC`, `ISEL`.
    * Store instructions (`STB`, `STW`, etc.):  Memory operand at the end.
    * Compare instructions (`FCMPU`, `CMPD`, etc.):  Handles condition register output.
    * `LIS`:  A special case translation to `ADDIS`.
    * Indexed store/load instructions: Specific formatting for memory addressing.
    * Branch instructions (`BCLR`, `BC`, etc.):  Complex logic for handling conditional branches and return.

**4. Analyzing `plan9Arg`:**

* **Purpose:**  Formats a single argument of an instruction according to Plan 9 syntax.
* **Argument Types:** Handles different argument types like `Reg`, `CondReg`, `Imm`, `SpReg`, `PCRel`, `Label`, and `Offset`.
* **Offset Handling:**  Specifically looks for `Offset` followed by a `Reg` and formats it as `offset(register)`.
* **Register Naming:** Converts `Reg` to uppercase (e.g., `R1` to `R1`). Has a special case for `R30` becoming `g`.
* **Conditional Register Formatting:**  Formats `CondReg` based on the specific condition code.
* **Immediate Values:**  Adds a `$` prefix to immediate values.
* **PC-Relative Addresses:** Uses the `symname` function to resolve addresses to symbolic names.

**5. Understanding the Helper Functions:**

* `reverseMiddleOps` and `reverseOperandOrder`: These control the order of operands for certain instructions, highlighting variations in assembly syntax.
* `revCondMap` and `condName`:  Used for formatting conditional branch instructions, providing more human-readable mnemonics.

**6. Inferring the Overall Functionality:**

Based on the analysis, it's clear that this code is a component of an assembler or disassembler for the PowerPC 64-bit architecture. Specifically, the `GoSyntax` function is responsible for taking a raw instruction representation and formatting it into a human-readable assembly language string using the Plan 9 syntax.

**7. Developing Examples and Identifying Potential Issues:**

* **Examples:**  I would choose different instruction types (arithmetic, memory access, branches) and manually simulate the `GoSyntax` function's behavior with hypothetical inputs to generate the expected output. This requires understanding the basic structure of PPC64 instructions.
* **Potential Errors:** I'd think about edge cases, like:
    * Incorrectly formatted instructions in the input `Inst`.
    * Missing symbol information (the `symname` function returning empty strings).
    * Misinterpreting instruction semantics, leading to incorrect formatting.
    *  Assumptions about operand order that might not hold for all instructions.

**8. Considering the Larger Context:**

The package path `go/src/cmd/vendor/golang.org/x/arch/ppc64/ppc64asm/plan9.go` strongly suggests this code is part of the Go compiler toolchain (`cmd`) and is responsible for handling PowerPC 64-bit architecture (`ppc64`) within the assembler (`ppc64asm`). The `vendor` directory indicates it's a vendored dependency. The `plan9.go` filename signifies the specific Plan 9 assembler syntax.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Is this just a simple string formatter?"  **Correction:** No, the logic for handling different instruction types and operand orders is complex.
* **Initial thought:** "Why Plan 9 syntax?" **Refinement:**  Plan 9 is an operating system with its own assembler syntax. Go's assembler has its own syntax, and this likely bridges the gap or provides a way to represent instructions in that specific syntax.
* **Realization:** The `symname` function is crucial for making the output meaningful, especially for branches and function calls. Without it, addresses would just be raw numbers.

By following these steps, I can systematically analyze the code and generate a comprehensive explanation of its functionality, examples, and potential issues.
这段代码是 Go 语言中 `golang.org/x/arch/ppc64/ppc64asm` 包的一部分，负责将 PowerPC 64 位架构的指令 ( `Inst` ) 转换为 **Plan 9 汇编语法** 的字符串表示。

**功能概览:**

1. **指令格式化:** `GoSyntax` 函数接收一个 `Inst` 类型的指令，程序计数器 (`pc`) 和一个符号表查询函数 (`symname`)，然后返回该指令的 Plan 9 汇编语法字符串。
2. **符号解析:** 利用 `symname` 函数将 PC 相对地址解析为带有符号名称的地址，增强可读性。
3. **特殊指令处理:**  针对不同的 PowerPC 指令类型，代码进行了特殊的处理，以符合 Plan 9 汇编的约定。例如，操作数的顺序、助记符的转换等。
4. **默认处理:** 对于未明确定义的指令，会将其操作码转换为大写字符串并添加 "CC" 后缀（如果原始操作码以 "." 结尾）。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言汇编器（assembler）或反汇编器（disassembler）中用于 **指令格式化输出** 的一部分。它专注于将机器码指令转化为人类可读的汇编代码。由于使用了 "Plan 9" 命名，可以推断它是为了支持生成符合 Plan 9 操作系统汇编语法的代码，或者用于解析 Plan 9 风格的汇编代码。

**Go 代码示例说明:**

假设我们有一个 `Inst` 类型的变量 `instruction`，代表一个 PowerPC 64 位的加法指令，并且程序计数器 `pc` 的值为 `0x1000`。

```go
package main

import (
	"fmt"
	"golang.org/x/arch/ppc64/ppc64asm"
)

func main() {
	// 假设 instruction 代表 ADD R3, R4, R5 指令
	instruction := ppc64asm.Inst{
		Op: ppc64asm.ADD,
		Args: []ppc64asm.Arg{
			ppc64asm.Reg(ppc64asm.R3),
			ppc64asm.Reg(ppc64asm.R4),
			ppc64asm.Reg(ppc64asm.R5),
		},
	}
	pc := uint64(0x1000)

	// 一个简单的 symname 函数示例，这里总是返回空字符串和 0
	symname := func(addr uint64) (string, uint64) {
		return "", 0
	}

	assembly := ppc64asm.GoSyntax(instruction, pc, symname)
	fmt.Println(assembly) // 输出: ADD R4,R5,R3
}
```

**假设的输入与输出 (基于上面的例子):**

**输入:**

* `inst`: `ppc64asm.Inst{Op: ppc64asm.ADD, Args: []ppc64asm.Arg{ppc64asm.Reg(ppc64asm.R3), ppc64asm.Reg(ppc64asm.R4), ppc64asm.Reg(ppc64asm.R5)}}`
* `pc`: `0x1000`
* `symname`: (一个始终返回空字符串和 0 的函数)

**输出:**

* `"ADD R4,R5,R3"`

**代码推理:**

在 `GoSyntax` 函数中，对于 `ADD` 指令，它会进入 `default` 分支的 `case 3`，并且 `reverseOperandOrder(inst.Op)` 返回 `true` (因为 `ADD` 在 `reverseOperandOrder` 中)，因此会按照 `op + " " + args[2] + "," + args[1] + "," + args[0]` 的格式输出，即 "ADD R5,R4,R3"。  注意，由于 `plan9Arg` 中对于 `Reg` 类型的参数会转换为大写字符串，所以输出的寄存器是 `R3`, `R4`, `R5`。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它的输入是已经解析好的 `Inst` 结构体和程序计数器等信息。这些信息可能来源于一个解析二进制文件或汇编源代码的工具，该工具可能会处理命令行参数来指定输入文件、输出格式等。

**使用者易犯错的点:**

1. **对 Plan 9 汇编语法的误解:**  Plan 9 汇编语法与 GNU 汇编语法（通常用于 Linux）有所不同，例如操作数顺序。使用者可能会期望得到 GNU 风格的输出，但实际上得到的是 Plan 9 风格。例如，对于加法指令，GNU 语法通常是 `add destination, source1, source2`，而 Plan 9 可能是 `add source1, source2, destination`。

   **示例：**

   ```go
   // GNU 汇编期望: add r3, r4, r5
   // Plan 9 汇编输出: ADD R4,R5,R3
   ```

2. **符号表查询函数的实现不正确:** `symname` 函数的正确实现对于将 PC 相对地址转换为符号地址至关重要。如果 `symname` 函数返回错误的信息，那么输出的汇编代码中地址可能无法正确解析为符号。

   **示例：** 如果一个跳转指令的目标地址 `0x2000` 实际上对应于符号 `my_function`，但 `symname(0x2000)` 却返回 `"", 0`，那么输出的汇编代码将显示 `BR $0x2000` 而不是更具可读性的 `CALL my_function(SB)`（假设 `BL` 指令）。

3. **依赖于特定的指令集和约定:** 这段代码是针对 PowerPC 64 位架构和 Plan 9 汇编语法的。如果用于处理其他架构或汇编语法的指令，将会产生错误的输出。

总而言之，这段代码的核心功能是将 PowerPC 64 位指令以 Plan 9 汇编语法的形式呈现出来，方便开发者理解和调试底层代码。理解 Plan 9 汇编的约定和正确实现符号表查询是使用这段代码的关键。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/ppc64/ppc64asm/plan9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ppc64asm

import (
	"fmt"
	"strings"
)

// GoSyntax returns the Go assembler syntax for the instruction.
// The pc is the program counter of the first instruction, used for expanding
// PC-relative addresses into absolute ones.
// The symname function queries the symbol table for the program
// being disassembled. It returns the name and base address of the symbol
// containing the target, if any; otherwise it returns "", 0.
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
	for i, a := range inst.Args[:] {
		if a == nil {
			break
		}
		if s := plan9Arg(&inst, i, pc, a, symname); s != "" {
			args = append(args, s)
		}
	}
	var op string
	op = plan9OpMap[inst.Op]
	if op == "" {
		op = strings.ToUpper(inst.Op.String())
		if op[len(op)-1] == '.' {
			op = op[:len(op)-1] + "CC"
		}
	}
	// laid out the instruction
	switch inst.Op {
	default: // dst, sA, sB, ...
		switch len(args) {
		case 0:
			return op
		case 1:
			return fmt.Sprintf("%s %s", op, args[0])
		case 2:
			if inst.Op == COPY || inst.Op == PASTECC {
				return op + " " + args[0] + "," + args[1]
			}
			return op + " " + args[1] + "," + args[0]
		case 3:
			if reverseOperandOrder(inst.Op) {
				return op + " " + args[2] + "," + args[1] + "," + args[0]
			}
		case 4:
			if reverseMiddleOps(inst.Op) {
				return op + " " + args[1] + "," + args[3] + "," + args[2] + "," + args[0]
			}
		}
		args = append(args, args[0])
		return op + " " + strings.Join(args[1:], ",")
	case PASTECC:
		// paste. has two input registers, and an L field, unlike other 3 operand instructions.
		return op + " " + args[0] + "," + args[1] + "," + args[2]
	case SYNC:
		if args[0] == "$1" {
			return "LWSYNC"
		}
		return "HWSYNC"

	case ISEL:
		return "ISEL " + args[3] + "," + args[1] + "," + args[2] + "," + args[0]

	// store instructions always have the memory operand at the end, no need to reorder
	// indexed stores handled separately
	case STB, STBU,
		STH, STHU,
		STW, STWU,
		STD, STDU,
		STFD, STFDU,
		STFS, STFSU,
		STQ, HASHST, HASHSTP:
		return op + " " + strings.Join(args, ",")

	case FCMPU, FCMPO, CMPD, CMPDI, CMPLD, CMPLDI, CMPW, CMPWI, CMPLW, CMPLWI:
		crf := int(inst.Args[0].(CondReg) - CR0)
		cmpstr := op + " " + args[1] + "," + args[2]
		if crf != 0 { // print CRx as the final operand if not implied (i.e BF != 0)
			cmpstr += "," + args[0]
		}
		return cmpstr

	case LIS:
		return "ADDIS $0," + args[1] + "," + args[0]
	// store instructions with index registers
	case STBX, STBUX, STHX, STHUX, STWX, STWUX, STDX, STDUX,
		STHBRX, STWBRX, STDBRX, STSWX, STFIWX:
		return "MOV" + op[2:len(op)-1] + " " + args[0] + ",(" + args[2] + ")(" + args[1] + ")"

	case STDCXCC, STWCXCC, STHCXCC, STBCXCC:
		return op + " " + args[0] + ",(" + args[2] + ")(" + args[1] + ")"

	case STXVX, STXVD2X, STXVW4X, STXVH8X, STXVB16X, STXSDX, STVX, STVXL, STVEBX, STVEHX, STVEWX, STXSIWX, STFDX, STFDUX, STFDPX, STFSX, STFSUX:
		return op + " " + args[0] + ",(" + args[2] + ")(" + args[1] + ")"

	case STXV:
		return op + " " + args[0] + "," + args[1]

	case STXVL, STXVLL:
		return op + " " + args[0] + "," + args[1] + "," + args[2]

	case LWAX, LWAUX, LWZX, LHZX, LBZX, LDX, LHAX, LHAUX, LDARX, LWARX, LHARX, LBARX, LFDX, LFDUX, LFSX, LFSUX, LDBRX, LWBRX, LHBRX, LDUX, LWZUX, LHZUX, LBZUX:
		if args[1] == "0" {
			return op + " (" + args[2] + ")," + args[0]
		}
		return op + " (" + args[2] + ")(" + args[1] + ")," + args[0]

	case LXVX, LXVD2X, LXVW4X, LXVH8X, LXVB16X, LVX, LVXL, LVSR, LVSL, LVEBX, LVEHX, LVEWX, LXSDX, LXSIWAX:
		return op + " (" + args[2] + ")(" + args[1] + ")," + args[0]

	case LXV:
		return op + " " + args[1] + "," + args[0]

	case LXVL, LXVLL:
		return op + " " + args[1] + "," + args[2] + "," + args[0]

	case DCBT, DCBTST, DCBZ, DCBST, ICBI:
		if args[0] == "0" || args[0] == "R0" {
			return op + " (" + args[1] + ")"
		}
		return op + " (" + args[1] + ")(" + args[0] + ")"

	// branch instructions needs additional handling
	case BCLR:
		if int(inst.Args[0].(Imm))&20 == 20 { // unconditional
			return "RET"
		}
		return op + " " + strings.Join(args, ", ")
	case BC:
		bo := int(inst.Args[0].(Imm))
		bi := int(inst.Args[1].(CondReg) - Cond0LT)
		bcname := condName[((bo&0x8)>>1)|(bi&0x3)]
		if bo&0x17 == 4 { // jump only a CR bit set/unset, no hints (at bits) set.
			if bi >= 4 {
				return fmt.Sprintf("B%s CR%d,%s", bcname, bi>>2, args[2])
			} else {
				return fmt.Sprintf("B%s %s", bcname, args[2])
			}
		}
		return op + " " + strings.Join(args, ",")
	case BCCTR:
		if int(inst.Args[0].(Imm))&20 == 20 { // unconditional
			return "BR (CTR)"
		}
		return op + " " + strings.Join(args, ", ")
	case BCCTRL:
		if int(inst.Args[0].(Imm))&20 == 20 { // unconditional
			return "BL (CTR)"
		}
		return op + " " + strings.Join(args, ",")
	case BCA, BCL, BCLA, BCLRL, BCTAR, BCTARL:
		return op + " " + strings.Join(args, ",")
	}
}

// plan9Arg formats arg (which is the argIndex's arg in inst) according to Plan 9 rules.
//
// NOTE: because Plan9Syntax is the only caller of this func, and it receives a copy
// of inst, it's ok to modify inst.Args here.
func plan9Arg(inst *Inst, argIndex int, pc uint64, arg Arg, symname func(uint64) (string, uint64)) string {
	// special cases for load/store instructions
	if _, ok := arg.(Offset); ok {
		if argIndex+1 == len(inst.Args) || inst.Args[argIndex+1] == nil {
			panic(fmt.Errorf("wrong table: offset not followed by register"))
		}
	}
	switch arg := arg.(type) {
	case Reg:
		if isLoadStoreOp(inst.Op) && argIndex == 1 && arg == R0 {
			return "0"
		}
		if arg == R30 {
			return "g"
		}
		return strings.ToUpper(arg.String())
	case CondReg:
		// This op is left as its numerical value, not mapped onto CR + condition
		if inst.Op == ISEL {
			return fmt.Sprintf("$%d", (arg - Cond0LT))
		}
		bit := [4]string{"LT", "GT", "EQ", "SO"}[(arg-Cond0LT)%4]
		if arg <= Cond0SO {
			return bit
		} else if arg > Cond0SO && arg <= Cond7SO {
			return fmt.Sprintf("CR%d%s", int(arg-Cond0LT)/4, bit)
		} else {
			return fmt.Sprintf("CR%d", int(arg-CR0))
		}
	case Imm:
		return fmt.Sprintf("$%d", arg)
	case SpReg:
		switch arg {
		case 8:
			return "LR"
		case 9:
			return "CTR"
		}
		return fmt.Sprintf("SPR(%d)", int(arg))
	case PCRel:
		addr := pc + uint64(int64(arg))
		s, base := symname(addr)
		if s != "" && addr == base {
			return fmt.Sprintf("%s(SB)", s)
		}
		if inst.Op == BL && s != "" && (addr-base) == 8 {
			// When decoding an object built for PIE, a CALL targeting
			// a global entry point will be adjusted to the local entry
			// if any. For now, assume any symname+8 PC is a local call.
			return fmt.Sprintf("%s+%d(SB)", s, addr-base)
		}
		return fmt.Sprintf("%#x", addr)
	case Label:
		return fmt.Sprintf("%#x", int(arg))
	case Offset:
		reg := inst.Args[argIndex+1].(Reg)
		removeArg(inst, argIndex+1)
		if reg == R0 {
			return fmt.Sprintf("%d(0)", int(arg))
		}
		return fmt.Sprintf("%d(R%d)", int(arg), reg-R0)
	}
	return fmt.Sprintf("???(%v)", arg)
}

func reverseMiddleOps(op Op) bool {
	switch op {
	case FMADD, FMADDCC, FMADDS, FMADDSCC, FMSUB, FMSUBCC, FMSUBS, FMSUBSCC, FNMADD, FNMADDCC, FNMADDS, FNMADDSCC, FNMSUB, FNMSUBCC, FNMSUBS, FNMSUBSCC, FSEL, FSELCC:
		return true
	}
	return false
}

func reverseOperandOrder(op Op) bool {
	switch op {
	// Special case for SUBF, SUBFC: not reversed
	case ADD, ADDC, ADDE, ADDCC, ADDCCC:
		return true
	case MULLW, MULLWCC, MULHW, MULHWCC, MULLD, MULLDCC, MULHD, MULHDCC, MULLWO, MULLWOCC, MULHWU, MULHWUCC, MULLDO, MULLDOCC:
		return true
	case DIVD, DIVDCC, DIVDU, DIVDUCC, DIVDE, DIVDECC, DIVDEU, DIVDEUCC, DIVDO, DIVDOCC, DIVDUO, DIVDUOCC:
		return true
	case MODUD, MODSD, MODUW, MODSW:
		return true
	case FADD, FADDS, FSUB, FSUBS, FMUL, FMULS, FDIV, FDIVS, FMADD, FMADDS, FMSUB, FMSUBS, FNMADD, FNMADDS, FNMSUB, FNMSUBS, FMULSCC:
		return true
	case FADDCC, FADDSCC, FSUBCC, FMULCC, FDIVCC, FDIVSCC:
		return true
	case OR, ORCC, ORC, ORCCC, AND, ANDCC, ANDC, ANDCCC, XOR, XORCC, NAND, NANDCC, EQV, EQVCC, NOR, NORCC:
		return true
	case SLW, SLWCC, SLD, SLDCC, SRW, SRAW, SRWCC, SRAWCC, SRD, SRDCC, SRAD, SRADCC:
		return true
	}
	return false
}

// revCondMap maps a conditional register bit to its inverse, if possible.
var revCondMap = map[string]string{
	"LT": "GE", "GT": "LE", "EQ": "NE",
}

// Lookup table to map BI[0:1] and BO[3] to an extended mnemonic for CR ops.
// Bits 0-1 map to a bit with a CR field, and bit 2 selects the inverted (0)
// or regular (1) extended mnemonic.
var condName = []string{
	"GE",
	"LE",
	"NE",
	"NSO",
	"LT",
	"GT",
	"EQ",
	"SO",
}

// plan9OpMap maps an Op to its Plan 9 mnemonics, if different than its GNU mnemonics.
var plan9OpMap = map[Op]string{
	LWARX:     "LWAR",
	LDARX:     "LDAR",
	LHARX:     "LHAR",
	LBARX:     "LBAR",
	LWAX:      "MOVW",
	LHAX:      "MOVH",
	LWAUX:     "MOVWU",
	LHAU:      "MOVHU",
	LHAUX:     "MOVHU",
	LDX:       "MOVD",
	LDUX:      "MOVDU",
	LWZX:      "MOVWZ",
	LWZUX:     "MOVWZU",
	LHZX:      "MOVHZ",
	LHZUX:     "MOVHZU",
	LBZX:      "MOVBZ",
	LBZUX:     "MOVBZU",
	LDBRX:     "MOVDBR",
	LWBRX:     "MOVWBR",
	LHBRX:     "MOVHBR",
	MCRF:      "MOVFL",
	XORI:      "XOR",
	ORI:       "OR",
	ANDICC:    "ANDCC",
	ANDC:      "ANDN",
	ANDCCC:    "ANDNCC",
	ADDEO:     "ADDEV",
	ADDEOCC:   "ADDEVCC",
	ADDO:      "ADDV",
	ADDOCC:    "ADDVCC",
	ADDMEO:    "ADDMEV",
	ADDMEOCC:  "ADDMEVCC",
	ADDCO:     "ADDCV",
	ADDCOCC:   "ADDCVCC",
	ADDZEO:    "ADDZEV",
	ADDZEOCC:  "ADDZEVCC",
	SUBFME:    "SUBME",
	SUBFMECC:  "SUBMECC",
	SUBFZE:    "SUBZE",
	SUBFZECC:  "SUBZECC",
	SUBFZEO:   "SUBZEV",
	SUBFZEOCC: "SUBZEVCC",
	SUBF:      "SUB",
	SUBFC:     "SUBC",
	SUBFCC:    "SUBCC",
	SUBFCCC:   "SUBCCC",
	ORC:       "ORN",
	ORCCC:     "ORNCC",
	MULLWO:    "MULLWV",
	MULLWOCC:  "MULLWVCC",
	MULLDO:    "MULLDV",
	MULLDOCC:  "MULLDVCC",
	DIVDO:     "DIVDV",
	DIVDOCC:   "DIVDVCC",
	DIVDUO:    "DIVDUV",
	DIVDUOCC:  "DIVDUVCC",
	ADDI:      "ADD",
	MULLI:     "MULLD",
	SRADI:     "SRAD",
	STBCXCC:   "STBCCC",
	STWCXCC:   "STWCCC",
	STDCXCC:   "STDCCC",
	LI:        "MOVD",
	LBZ:       "MOVBZ", STB: "MOVB",
	LBZU: "MOVBZU", STBU: "MOVBU",
	LHZ: "MOVHZ", LHA: "MOVH", STH: "MOVH",
	LHZU: "MOVHZU", STHU: "MOVHU",
	LWZ: "MOVWZ", LWA: "MOVW", STW: "MOVW",
	LWZU: "MOVWZU", STWU: "MOVWU",
	LD: "MOVD", STD: "MOVD",
	LDU: "MOVDU", STDU: "MOVDU",
	LFD: "FMOVD", STFD: "FMOVD",
	LFS: "FMOVS", STFS: "FMOVS",
	LFDX: "FMOVD", STFDX: "FMOVD",
	LFDU: "FMOVDU", STFDU: "FMOVDU",
	LFDUX: "FMOVDU", STFDUX: "FMOVDU",
	LFSX: "FMOVS", STFSX: "FMOVS",
	LFSU: "FMOVSU", STFSU: "FMOVSU",
	LFSUX: "FMOVSU", STFSUX: "FMOVSU",
	CMPD: "CMP", CMPDI: "CMP",
	CMPW: "CMPW", CMPWI: "CMPW",
	CMPLD: "CMPU", CMPLDI: "CMPU",
	CMPLW: "CMPWU", CMPLWI: "CMPWU",
	MTSPR: "MOVD", MFSPR: "MOVD", // the width is ambiguous for SPRs
	B:  "BR",
	BL: "CALL",
}

"""



```