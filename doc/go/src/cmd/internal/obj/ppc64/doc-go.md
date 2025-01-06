Response: The user wants to understand the functionality of the provided Go assembly documentation for the PPC64 architecture. I need to extract the key features and explain them concisely. The documentation focuses on the differences between Go assembly syntax and native PPC64 assembly syntax. I should enumerate these differences and provide examples where possible.

Here's a breakdown of the information presented in the document:

1. **Purpose of the package:** It's an assembler for PPC64, translating Go assembly into PPC64 machine code.
2. **Key differences between Go and PPC64 assembly:**
    * Operand ordering.
    * Handling of constants.
    * Setting condition codes.
    * Load and store instructions.
    * Compare instructions.
    * Branch instructions.
    * Alignment directive (`PCALIGN`).
    * Shift instructions.
3. **Register naming conventions in Go assembly.**
4. **Impact of `GOPPC64 >= power10` on generated assembly.**

I will organize my answer based on these points, providing Go code examples where appropriate and explaining the purpose of each difference. For the `PCALIGN` directive, I'll describe its function and the changes introduced in Go 1.21. For the `GOPPC64` flag, I'll explain how it affects the generation of instructions for constants and symbolic references.
这段 `doc.go` 文件是 Go 语言 `cmd/internal/obj/ppc64` 包的一部分，它主要的功能是**作为 PPC64 汇编器的用户文档**。它旨在帮助 Go 开发者理解如何编写针对 PPC64 架构的汇编代码，并特别强调了 Go 汇编语法和原生 PPC64 汇编语法之间的差异。

以下是它列举的一些主要功能和概念：

**1. 解释了 Go 汇编器针对 PPC64 架构的实现：**

   - 声明了该包实现了将 Go 汇编代码转换为 Power ISA 3.0B 定义的 PPC64 指令的功能。
   - 提到 Go 的 `objdump -gnu` 功能可以并排显示 Go 汇编和生成的 PPC64 汇编，有助于理解转换过程。

**2. 详细阐述了 Go 汇编和 PPC64 汇编在语法上的主要差异，并提供了示例：**

   - **操作数顺序 (Operand ordering):**
     - Go 汇编的目标操作数在最右边，而 PPC64 汇编的目标操作数在最左边。
     - 其他操作数的顺序在数学/逻辑运算指令中通常是相反的，但在向量指令或多操作数指令中通常相同，除了目标操作数的位置不同。
     ```go
     // Go assembly:
     // ADD R3, R4, R5
     //
     // PPC64 assembly:
     // add r5, r4, r3
     ```

   - **常量操作数 (Constant operands):**
     - Go 汇编中使用 `$` 前缀表示常量。如果指令有立即数版本，Go 汇编器会尽可能使用立即数。
     ```go
     // Go assembly:
     // ADD $1, R3, R4
     //
     // PPC64 assembly:
     // addi r4, r3, 1
     ```

   - **设置条件码的操作码 (Opcodes setting condition codes):**
     - PPC64 汇编中，可以通过在指令末尾添加 `.` 来设置条件码。
     - Go 汇编通过在操作码末尾添加 `CC` 来表示。
     ```go
     // Go assembly:
     // ANDCC R3, R4, R5
     //
     // PPC64 assembly:
     // and. r5, r3, r4 (set CR0)
     ```

   - **内存加载和存储 (Loads and stores from memory):**
     - Go 汇编中，以 `MOV` 开头的操作码表示加载或存储。目标是内存则为存储，目标是寄存器且源是内存则为加载。
     - `MOV{B,H,W,D}` 指定了字节、半字、字、双字的大小。
     - `Z` 后缀表示零扩展加载，省略则表示符号扩展。
     - `U` 后缀表示更新基址寄存器。
     - `BR` 后缀表示字节反转加载/存储。
     ```go
     // 假设 R3 寄存器中存储着内存地址 0x1000
     // 假设内存地址 0x1000 存储着双字值 0x123456789ABCDEF0

     // Go assembly (加载):
     // MOVD (R3), R4
     //
     // PPC64 assembly:
     // ld r4, 0(r3)
     //
     // 输出 (假设执行后): R4 寄存器的值为 0x123456789ABCDEF0

     // Go assembly (存储):
     // MOVD R4, (R3)
     //
     // PPC64 assembly:
     // std r4, 0(r3)
     //
     // 假设执行前 R4 寄存器的值为 0xFFFFFFFFFFFFFFFF
     // 输出 (假设执行后): 内存地址 0x1000 存储的值变为 0xFFFFFFFFFFFFFFFF
     ```

   - **比较 (Compares):**
     - Go 汇编中，比较指令的目标操作数是条件寄存器，因此剩余操作数顺序与 PPC64 汇编相同。当使用 CR0 时，可以省略。
     ```go
     // Go assembly:
     // CMP R3, R4
     //
     // PPC64 assembly:
     // cmp r3, r4 (CR0 assumed)

     // Go assembly:
     // CMP R3, R4, CR1
     //
     // PPC64 assembly:
     // cmp cr1, r3, r4
     ```

   - **分支 (Branches):**
     - 解释了 `BC` 指令及其常用操作数，以及一些扩展的易于使用的分支操作码。
     ```go
     // 假设 target 是一个代码标签
     // 假设 CR0 的 LT 位已设置

     // Go assembly:
     // BC 12, 0, target
     //
     // PPC64 assembly:
     // blt cr0, target
     //
     // 如果 CR0 的 LT 位已设置，则跳转到 target

     // Go assembly:
     // BLT target
     //
     // PPC64 assembly:
     // blt target (cr0 default)
     //
     // 如果 CR0 的 LT 位已设置，则跳转到 target
     ```

   - **对齐指令 (Align directive):**
     - 介绍了 `PCALIGN` 指令，用于指示接下来的指令应该按照指定的值对齐，常用于优化循环性能。
     - 提到了 Go 1.12 和 Go 1.21 中对 `PCALIGN` 行为的更改。

   - **移位指令 (Shift instructions):**
     - 解释了简单标量移位指令的移位计数的限制，以及 Go 编译器如何处理超出限制的情况。
     - 提到了 Go 汇编中一些非简单移位指令的操作数与 PPC64 汇编的映射关系，以及推荐使用更新的直接映射 PPC64 操作码的做法。
     ```go
     // 假设 R3 寄存器的值为 0xFFFFFFFF

     // Go assembly:
     // SRAD $8, R3, R4
     //
     // PPC64 assembly:
     // sradi r4, r3, 8
     //
     // 执行后 R4 的值为 0xFFFFFF

     // Go assembly:
     // RLDICL $0, R4, $15, R6
     //
     // PPC64 assembly:
     // rldicl r6, r4, 0, 15
     //
     // 这条指令会将 R4 寄存器的值循环左移 0 位，然后清空第 16 位到第 63 位，结果存入 R6
     ```

**3. 列举了 Go 汇编中特殊寄存器的用法和命名约定：**

   - 指出了一些用户汇编代码不应该修改的特殊寄存器 (R0, R1, R2, R13, R30)。
   - 提供了通用寄存器 (Rn)、浮点寄存器 (Fn)、向量寄存器 (Vn)、向量标量寄存器 (VSn)、计数寄存器 (CTR)、链接寄存器 (LR)、条件寄存器 (CR) 和条件寄存器字段 (CRn) 的命名规则。

**4. 阐述了 `GOPPC64 >= power10` 对 Go 汇编的影响：**

   - 当使用 `GOPPC64=power10` 或更高版本编译时，对于需要多个机器指令来模拟 32 位常量或符号引用的 `MOV*`、`FMOV*` 和 `ADD` 操作码，会使用带前缀的指令来实现。
   - 建议希望精细控制生成机器码的用户使用显式转换为单个 PPC64 机器指令的 Go 汇编操作码。
   ```go
   // 假设 mypackage 包中定义了一个名为 foo 的全局变量

   // GOPPC64 <= power9
   // Go assembly:
   // MOVD mypackage·foo(SB), R3
   //
   // PPC64 assembly:
   // addis r2, r3, ...
   // ld    r3, r3, ...

   // GOPPC64 >= power10
   // Go assembly:
   // MOVD mypackage·foo(SB), R3
   //
   // PPC64 assembly:
   // pld r3, ...
   ```

**使用者易犯错的点 (通过文档内容推断):**

- **操作数顺序混淆：**  在 Go 汇编和 PPC64 汇编之间切换时，容易搞错目标操作数的位置和其他操作数的顺序，尤其是在数学/逻辑运算指令中。
- **对常量表示的理解不足：** 不清楚何时以及如何使用 `$` 前缀来表示常量，可能导致汇编错误。
- **条件码设置的混淆：**  不理解 Go 汇编中如何通过 `CC` 后缀来设置条件码，以及它与 PPC64 汇编中 `.` 后缀的对应关系。
- **内存操作指令的用法：** 对 `MOV` 指令的不同变体 (B, H, W, D, Z, U, BR) 的含义和使用场景不够清晰，容易导致加载或存储错误的数据大小或地址。
- **分支指令的参数理解：**  对 `BC` 指令的操作数 `op1` 和 `op2` 的含义理解不足，可能导致分支逻辑错误。
- **`PCALIGN` 的使用限制和效果：**  不清楚 `PCALIGN` 指令支持的对齐值和 Go 版本的限制，或者不明白其对性能的潜在影响。
- **特殊寄存器的误用：**  在汇编代码中意外修改了 Go 运行时依赖的特殊寄存器 (如 R0, R1, R2, R13, R30)，可能导致程序崩溃或行为异常。
- **不了解 `GOPPC64` 的影响：** 在不同的 `GOPPC64` 环境下，相同的 Go 汇编代码可能生成不同的机器码，如果不了解这一点，可能会导致意外的行为或性能问题。

总而言之，这份文档是 PPC64 架构下编写 Go 汇编代码的重要参考，它详细解释了 Go 汇编器的行为、语法以及与原生 PPC64 汇编的差异，帮助开发者避免常见的错误并更好地理解生成的机器码。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/ppc64/doc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package ppc64 implements a PPC64 assembler that assembles Go asm into
the corresponding PPC64 instructions as defined by the Power ISA 3.0B.

This document provides information on how to write code in Go assembler
for PPC64, focusing on the differences between Go and PPC64 assembly language.
It assumes some knowledge of PPC64 assembler. The original implementation of
PPC64 in Go defined many opcodes that are different from PPC64 opcodes, but
updates to the Go assembly language used mnemonics that are mostly similar if not
identical to the PPC64 mneumonics, such as VMX and VSX instructions. Not all detail
is included here; refer to the Power ISA document if interested in more detail.

Starting with Go 1.15 the Go objdump supports the -gnu option, which provides a
side by side view of the Go assembler and the PPC64 assembler output. This is
extremely helpful in determining what final PPC64 assembly is generated from the
corresponding Go assembly.

In the examples below, the Go assembly is on the left, PPC64 assembly on the right.

1. Operand ordering

In Go asm, the last operand (right) is the target operand, but with PPC64 asm,
the first operand (left) is the target. The order of the remaining operands is
not consistent: in general opcodes with 3 operands that perform math or logical
operations have their operands in reverse order. Opcodes for vector instructions
and those with more than 3 operands usually have operands in the same order except
for the target operand, which is first in PPC64 asm and last in Go asm.

Example:

	ADD R3, R4, R5		<=>	add r5, r4, r3

2. Constant operands

In Go asm, an operand that starts with '$' indicates a constant value. If the
instruction using the constant has an immediate version of the opcode, then an
immediate value is used with the opcode if possible.

Example:

	ADD $1, R3, R4		<=> 	addi r4, r3, 1

3. Opcodes setting condition codes

In PPC64 asm, some instructions other than compares have variations that can set
the condition code where meaningful. This is indicated by adding '.' to the end
of the PPC64 instruction. In Go asm, these instructions have 'CC' at the end of
the opcode. The possible settings of the condition code depend on the instruction.
CR0 is the default for fixed-point instructions; CR1 for floating point; CR6 for
vector instructions.

Example:

	ANDCC R3, R4, R5		<=>	and. r5, r3, r4 (set CR0)

4. Loads and stores from memory

In Go asm, opcodes starting with 'MOV' indicate a load or store. When the target
is a memory reference, then it is a store; when the target is a register and the
source is a memory reference, then it is a load.

MOV{B,H,W,D} variations identify the size as byte, halfword, word, doubleword.

Adding 'Z' to the opcode for a load indicates zero extend; if omitted it is sign extend.
Adding 'U' to a load or store indicates an update of the base register with the offset.
Adding 'BR' to an opcode indicates byte-reversed load or store, or the order opposite
of the expected endian order. If 'BR' is used then zero extend is assumed.

Memory references n(Ra) indicate the address in Ra + n. When used with an update form
of an opcode, the value in Ra is incremented by n.

Memory references (Ra+Rb) or (Ra)(Rb) indicate the address Ra + Rb, used by indexed
loads or stores. Both forms are accepted. When used with an update then the base register
is updated by the value in the index register.

Examples:

	MOVD (R3), R4		<=>	ld r4,0(r3)
	MOVW (R3), R4		<=>	lwa r4,0(r3)
	MOVWZU 4(R3), R4		<=>	lwzu r4,4(r3)
	MOVWZ (R3+R5), R4		<=>	lwzx r4,r3,r5
	MOVHZ  (R3), R4		<=>	lhz r4,0(r3)
	MOVHU 2(R3), R4		<=>	lhau r4,2(r3)
	MOVBZ (R3), R4		<=>	lbz r4,0(r3)

	MOVD R4,(R3)		<=>	std r4,0(r3)
	MOVW R4,(R3)		<=>	stw r4,0(r3)
	MOVW R4,(R3+R5)		<=>	stwx r4,r3,r5
	MOVWU R4,4(R3)		<=>	stwu r4,4(r3)
	MOVH R4,2(R3)		<=>	sth r4,2(r3)
	MOVBU R4,(R3)(R5)		<=>	stbux r4,r3,r5

4. Compares

When an instruction does a compare or other operation that might
result in a condition code, then the resulting condition is set
in a field of the condition register. The condition register consists
of 8 4-bit fields named CR0 - CR7. When a compare instruction
identifies a CR then the resulting condition is set in that field
to be read by a later branch or isel instruction. Within these fields,
bits are set to indicate less than, greater than, or equal conditions.

Once an instruction sets a condition, then a subsequent branch, isel or
other instruction can read the condition field and operate based on the
bit settings.

Examples:

	CMP R3, R4			<=>	cmp r3, r4	(CR0 assumed)
	CMP R3, R4, CR1		<=>	cmp cr1, r3, r4

Note that the condition register is the target operand of compare opcodes, so
the remaining operands are in the same order for Go asm and PPC64 asm.
When CR0 is used then it is implicit and does not need to be specified.

5. Branches

Many branches are represented as a form of the BC instruction. There are
other extended opcodes to make it easier to see what type of branch is being
used.

The following is a brief description of the BC instruction and its commonly
used operands.

BC op1, op2, op3

	  op1: type of branch
	      16 -> bctr (branch on ctr)
	      12 -> bcr  (branch if cr bit is set)
	      8  -> bcr+bctr (branch on ctr and cr values)
		4  -> bcr != 0 (branch if specified cr bit is not set)

		There are more combinations but these are the most common.

	  op2: condition register field and condition bit

		This contains an immediate value indicating which condition field
		to read and what bits to test. Each field is 4 bits long with CR0
	      at bit 0, CR1 at bit 4, etc. The value is computed as 4*CR+condition
	      with these condition values:

	      0 -> LT
	      1 -> GT
	      2 -> EQ
	      3 -> OVG

		Thus 0 means test CR0 for LT, 5 means CR1 for GT, 30 means CR7 for EQ.

	  op3: branch target

Examples:

	BC 12, 0, target		<=>	blt cr0, target
	BC 12, 2, target		<=>	beq cr0, target
	BC 12, 5, target		<=>	bgt cr1, target
	BC 12, 30, target		<=>	beq cr7, target
	BC 4, 6, target		<=>	bne cr1, target
	BC 4, 1, target		<=>	ble cr1, target

	The following extended opcodes are available for ease of use and readability:

	BNE CR2, target		<=>	bne cr2, target
	BEQ CR4, target		<=>	beq cr4, target
	BLT target			<=>	blt target (cr0 default)
	BGE CR7, target		<=>	bge cr7, target

Refer to the ISA for more information on additional values for the BC instruction,
how to handle OVG information, and much more.

5. Align directive

Starting with Go 1.12, Go asm supports the PCALIGN directive, which indicates
that the next instruction should be aligned to the specified value. Currently
8 and 16 are the only supported values, and a maximum of 2 NOPs will be added
to align the code. That means in the case where the code is aligned to 4 but
PCALIGN $16 is at that location, the code will only be aligned to 8 to avoid
adding 3 NOPs.

The purpose of this directive is to improve performance for cases like loops
where better alignment (8 or 16 instead of 4) might be helpful. This directive
exists in PPC64 assembler and is frequently used by PPC64 assembler writers.

PCALIGN $16
PCALIGN $8

By default, functions in Go are aligned to 16 bytes, as is the case in all
other compilers for PPC64. If there is a PCALIGN directive requesting alignment
greater than 16, then the alignment of the containing function must be
promoted to that same alignment or greater.

The behavior of PCALIGN is changed in Go 1.21 to be more straightforward to
ensure the alignment required for some instructions in power10. The acceptable
values are 8, 16, 32 and 64, and the use of those values will always provide the
specified alignment.

6. Shift instructions

The simple scalar shifts on PPC64 expect a shift count that fits in 5 bits for
32-bit values or 6 bit for 64-bit values. If the shift count is a constant value
greater than the max then the assembler sets it to the max for that size (31 for
32 bit values, 63 for 64 bit values). If the shift count is in a register, then
only the low 5 or 6 bits of the register will be used as the shift count. The
Go compiler will add appropriate code to compare the shift value to achieve the
correct result, and the assembler does not add extra checking.

Examples:

	SRAD $8,R3,R4		=>	sradi r4,r3,8
	SRD $8,R3,R4		=>	rldicl r4,r3,56,8
	SLD $8,R3,R4		=>	rldicr r4,r3,8,55
	SRAW $16,R4,R5		=>	srawi r5,r4,16
	SRW $40,R4,R5		=>	rlwinm r5,r4,0,0,31
	SLW $12,R4,R5		=>	rlwinm r5,r4,12,0,19

Some non-simple shifts have operands in the Go assembly which don't map directly
onto operands in the PPC64 assembly. When an operand in a shift instruction in the
Go assembly is a bit mask, that mask is represented as a start and end bit in the
PPC64 assembly instead of a mask. See the ISA for more detail on these types of shifts.
Here are a few examples:

	RLWMI $7,R3,$65535,R6 	=>	rlwimi r6,r3,7,16,31
	RLDMI $0,R4,$7,R6 		=>	rldimi r6,r4,0,61

More recently, Go opcodes were added which map directly onto the PPC64 opcodes. It is
recommended to use the newer opcodes to avoid confusion.

	RLDICL $0,R4,$15,R6		=>	rldicl r6,r4,0,15
	RLDICR $0,R4,$15,R6		=>	rldicr r6.r4,0,15

# Register naming

1. Special register usage in Go asm

The following registers should not be modified by user Go assembler code.

	R0: Go code expects this register to contain the value 0.
	R1: Stack pointer
	R2: TOC pointer when compiled with -shared or -dynlink (a.k.a position independent code)
	R13: TLS pointer
	R30: g (goroutine)

Register names:

	Rn is used for general purpose registers. (0-31)
	Fn is used for floating point registers. (0-31)
	Vn is used for vector registers. Slot 0 of Vn overlaps with Fn. (0-31)
	VSn is used for vector-scalar registers. V0-V31 overlap with VS32-VS63. (0-63)
	CTR represents the count register.
	LR represents the link register.
	CR represents the condition register
	CRn represents a condition register field. (0-7)
	CRnLT represents CR bit 0 of CR field n. (0-7)
	CRnGT represents CR bit 1 of CR field n. (0-7)
	CRnEQ represents CR bit 2 of CR field n. (0-7)
	CRnSO represents CR bit 3 of CR field n. (0-7)

# GOPPC64 >= power10 and its effects on Go asm

When GOPPC64=power10 is used to compile a Go program for ppc64le/linux, MOV*, FMOV*, and ADD
opcodes which would require 2 or more machine instructions to emulate a 32 bit constant, or
symbolic reference are implemented using prefixed instructions.

A user who wishes granular control over the generated machine code is advised to use Go asm
opcodes which explicitly translate to one PPC64 machine instruction. Most common opcodes
are supported.

Some examples of how pseudo-op assembly changes with GOPPC64:

	Go asm                       GOPPC64 <= power9          GOPPC64 >= power10
	MOVD mypackage·foo(SB), R3   addis r2, r3, ...          pld r3, ...
	                             ld    r3, r3, ...

	MOVD 131072(R3), R4          addis r31, r4, 2           pld r4, 131072(r3)
	                             ld    r4, 0(R3)

	ADD $131073, R3              lis  r31, 2                paddi r3, r3, 131073
	                             addi r31, 1
	                             add  r3,r31,r3

	MOVD $131073, R3             lis  r3, 2                 pli r3, 131073
	                             addi r3, 1

	MOVD $mypackage·foo(SB), R3  addis r2, r3, ...          pla r3, ...
	                             addi  r3, r3, ...
*/
package ppc64

"""



```