Response: My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the `doc.go` file's purpose, which is to document the Go assembler for the ARM64 architecture. The key is to extract the functionalities described in the comments.

2. **Identify Key Sections:**  The document is clearly structured around "Instruction mnemonics mapping rules", "Register mapping rules", and "Argument mapping rules". These become the main categories of my summary.

3. **Process Each Section - Instruction Mappings:**
    * **Rule 1 (Width Suffixes):** The core idea is that Go uses suffixes (like `W`) instead of different register names (like `w` vs. `x`). I need to provide examples showing the Go syntax and its GNU ARM64 equivalent.
    * **Rule 2 (Post/Pre-increment):** The `.P` and `.W` suffixes are the key. Examples illustrating the syntax and the corresponding GNU ARM64 instructions are needed.
    * **Rule 3 (MOV as Load/Store):** This rule describes how `MOV` is overloaded for various load and store operations, differentiating by size and signedness. I need to list the Go `MOV` variants and their GNU ARM64 equivalents.
    * **Rule 4 (Conditions as Suffixes):**  Go puts condition codes directly into the instruction mnemonic (e.g., `BLT`). A simple example will suffice.
    * **Rule 5 (V Prefix for Floating-Point/SIMD):**  The `V` prefix is used for most floating-point and SIMD instructions (with exceptions). Examples illustrating the prefix are important.
    * **Rule 6 (PCALIGN Directive):** This is a significant feature. I need to explain its purpose (instruction and function alignment), the syntax (`PCALIGN $value`), the allowed range of values, and how it affects function alignment with examples. The interaction with `NOFRAME` and `NOSPLIT` is also crucial.
    * **Rule 7 (Large Constants to Vector Registers):**  `VMOVQ`, `VMOVD`, `VMOVS` are used for this. The syntax for 128-bit constants (two 64-bit operands) is a key detail to include in the examples.
    * **Rule 8 (Shifted 16-bit Immediates):**  `MOVK`, `MOVZ`, `MOVN` are used. The syntax with the `<<shift` notation and the restrictions on zero shifts are important to mention, along with examples.
    * **Special Cases:**  These are exceptions to the general rules. I need to list each special case with its Go and GNU ARM64 equivalents.

4. **Process Each Section - Register Mappings:**  This is relatively straightforward. List the key differences: `Rn`, `ZR`, `RSP`, and `Fn`/`Vn`.

5. **Process Each Section - Argument Mappings:**
    * **Rule 1 (Operand Order):** The general rule is reversed order, but there are exceptions. Provide examples of the reversed order.
    * **Special Cases:** This is the bulk of this section, listing instructions where the argument order is *not* reversed. For each case, provide examples of the Go and GNU ARM64 syntax. I need to carefully extract each listed instruction type.
    * **Rule 2 (Expressions for Special Arguments):** Explain the syntax for immediates (`$`), shifted immediates (`<<`), shifted registers (`>>`, `->`, `@>`), extended registers, memory references, register pairs, and vector arrangements. Provide examples for each.

6. **Infer Go Language Feature:** The `doc.go` file describes the **Go assembler for the ARM64 architecture**. This is a fundamental part of the Go toolchain that allows developers to write low-level code, often for performance-critical sections or when interacting directly with hardware.

7. **Provide Go Code Example:** Since this is about the *assembler*, not standard Go code, a direct Go code example is not the most appropriate. Instead, I should illustrate how the assembly instructions *would be used* within a Go function. This means showing a Go function that uses inline assembly (via the `asm` package). The example should demonstrate some of the mapping rules, like register naming and instruction mnemonics. I need to provide an input, the assembly instructions, and the expected output.

8. **Address Command-Line Arguments:**  The `doc.go` file itself *doesn't* handle command-line arguments. This file documents the assembler's syntax. However, the *assembler tool* (`go tool asm`) does. I need to briefly explain this distinction and then list relevant command-line flags for the assembler, focusing on those related to architecture and input/output.

9. **Identify Common Mistakes:** The `doc.go` highlights several potential issues. I should focus on the most prominent ones:
    * **Incorrect operand order:**  This is a major source of confusion due to the reversed order in many instructions. Provide an example of a reversed instruction and the correct order.
    * **Forgetting width suffixes:**  Emphasize the need for suffixes like `W` for 32-bit operations.
    * **Incorrectly using `NOP` vs. `NOOP`:** Explain the difference.
    * **Zero shift errors with `MOVK`, `MOVZ`, `MOVN`:** Highlight this specific restriction.

10. **Review and Refine:**  Finally, I need to review my answer for clarity, accuracy, and completeness, ensuring it directly addresses all parts of the request. I should double-check the examples for correctness and make sure the explanation is easy to understand. I should also make sure I haven't included information that isn't explicitly in the `doc.go` file.
`go/src/cmd/internal/obj/arm64/doc.go` 这个文件是 Go 语言工具链中 `arm64` 架构的汇编器文档。它主要的功能是解释 Go 汇编语言在 ARM64 架构上的语法规则，以及如何将这些规则映射到底层的 ARM64 机器指令。

以下是 `doc.go` 文件列举的一些关键功能点：

1. **指令助记符映射规则 (Instructions mnemonics mapping rules):**  详细说明了 Go 汇编指令如何对应到 GNU ARM64 汇编指令。这包括：
    * **宽度后缀:** Go 使用指令名称的宽度后缀 (如 `W` 表示 32 位) 而不是不同的寄存器名称。
    * **自增后缀:** `.P` 和 `.W` 后缀表示后自增和前自增寻址模式。
    * **MOV 指令的用途:** Go 使用 `MOV` 指令作为加载和存储操作的通用指令，并根据操作数大小和类型使用不同的变体 (如 `MOVD`, `MOVW`, `MOVBU` 等)。
    * **条件码后缀:** Go 将条件码添加到操作码后缀中 (如 `BLT`)。
    * **浮点和 SIMD 指令前缀:** 大部分浮点和 SIMD 指令使用 `V` 前缀。
    * **Align 指令:** 介绍了 `PCALIGN` 指令，用于指定指令的对齐方式，并影响函数的对齐。
    * **移动大常数到向量寄存器:** 说明了 `VMOVQ`, `VMOVD`, `VMOVS` 指令用于将大常数加载到向量寄存器。
    * **移动可选择移位的 16 位立即数:**  介绍了 `MOVK`, `MOVZ`, `MOVN` 指令及其语法。
    * **特殊情况:** 列举了一些不符合通用映射规则的特殊指令。

2. **寄存器映射规则 (Register mapping rules):**  解释了 Go 汇编中寄存器的命名规则：
    * 通用寄存器命名为 `Rn`。
    * 零寄存器为 `ZR`，栈指针为 `RSP`。
    * 浮点指令中的 `Bn`, `Hn`, `Dn`, `Sn`, `Qn` 寄存器在 Go 汇编中写成 `Fn`，SIMD 指令中写成 `Vn`。

3. **参数映射规则 (Argument mapping rules):**  描述了指令操作数的排列顺序：
    * **通常情况下，操作数按照从左到右赋值的顺序出现，这与 GNU ARM64 语法相反。**
    * **特殊情况:** 列举了一些操作数顺序与 GNU ARM64 语法相同的指令。
    * **特殊参数的表达式:**  介绍了立即数、可选择移位的立即数和寄存器、扩展寄存器、内存引用和寄存器对的表示方法。

**Go 语言功能的实现：Go 汇编器**

这个 `doc.go` 文件实际上是 Go 语言中 **汇编器** 功能的一部分文档。Go 语言允许开发者在某些性能关键的场景下，直接编写汇编代码来优化程序。`go tool asm` 命令用于编译汇编源文件。

**Go 代码示例 (使用 inline assembly):**

虽然 `doc.go` 描述的是汇编语法，但我们可以用 Go 的 inline assembly 功能来展示这些规则的应用。

```go
package main

import "fmt"
import "unsafe"

//go:noinline
func add(a, b int64) int64 {
	var result int64
	// 使用 Go 汇编 (inline assembly)
	// 输入: a 在 R0, b 在 R1
	// 输出: result 在 R0
	asm(`
		ADD R1, R0, R1  // R1 = R0 + R1  (GNU: add x1, x0, x1)
		MOV R1, %[out]  // 将 R1 的值移动到输出变量 (GNU: mov %[out], x1)
	`,
		// 输出参数
		out: "=r"(result),
		// 输入参数
		AX: a,
		BX: b,
	)
	return result
}

func main() {
	x := int64(10)
	y := int64(5)
	sum := add(x, y)
	fmt.Printf("%d + %d = %d\n", x, y, sum)
}
```

**假设的输入与输出:**

* **输入:** `a = 10`, `b = 5`
* **输出:** `sum = 15`

**代码推理:**

上面的 `add` 函数使用了 Go 的 inline assembly 特性。`asm` 反引号内的字符串是 ARM64 汇编指令。

* `ADD R1, R0, R1`:  这行汇编指令将寄存器 `R0` (对应输入参数 `a`) 和 `R1` (对应输入参数 `b`) 的值相加，结果存储在 `R1` 中。根据文档，Go 的 `ADD` 指令的参数顺序是目标寄存器在最后。
* `MOV R1, %[out]`: 这行指令将 `R1` 寄存器的值移动到 Go 变量 `result` 对应的内存位置。 `%[out]` 是一个占位符，由 `asm` 函数的参数指定。

**命令行参数的具体处理:**

`doc.go` 文件本身不处理命令行参数。处理 Go 汇编的命令行工具是 `go tool asm`。  一些常用的参数包括：

* **`-o <outfile>`:**  指定输出的目标文件。
* **`-D <name>=<value>`:** 定义符号，可以在汇编代码中使用。
* **`-I <directory>`:**  添加头文件搜索路径。
* **`-S`:**  打印汇编输出到标准输出，而不是生成目标文件。
* **`-trimpath`:**  从记录的源文件路径中删除前缀，用于构建可重现的构建。
* **`<infile>`:**  指定输入的汇编源文件。

例如，编译一个名为 `myasm.s` 的 ARM64 汇编文件，生成目标文件 `myasm.o`：

```bash
go tool asm -o myasm.o myasm.s
```

**使用者易犯错的点:**

1. **操作数顺序错误:**  Go 汇编的参数顺序通常与 GNU ARM64 语法相反，这是最容易犯错的地方。例如，在 GNU ARM64 中 `add x0, x1, x2` 表示 `x0 = x1 + x2`，而在 Go 汇编中，对应的可能是 `ADD R2, R1, R0`，表示 `R0 = R1 + R2`。

   **错误示例:**

   ```assembly
   // 错误的 Go 汇编 (假设想实现 R0 = R1 + R2)
   ADD R0, R1, R2
   ```

   **正确示例:**

   ```assembly
   // 正确的 Go 汇编
   ADD R2, R1, R0
   ```

2. **忘记宽度后缀:**  在处理不同大小的数据时，必须使用正确的宽度后缀。例如，操作 32 位寄存器时应使用 `ADDW` 等。

   **错误示例:**

   ```assembly
   // 假设 R0 和 R1 是 32 位寄存器，但没有使用宽度后缀
   ADD R0, R1, R2 // 可能导致类型不匹配或错误的结果
   ```

   **正确示例:**

   ```assembly
   ADDW R0, R1, R2
   ```

3. **混淆 `NOP` 和 `NOOP`:**  `NOP` 是一个零宽度的伪指令，而 `NOOP` 是 ARM64 的硬件 NOP 指令 (相当于 `HINT $0`)。如果想插入硬件级别的空操作，应该使用 `NOOP`。

   **错误示例:**

   ```assembly
   NOP // 在需要硬件 NOP 的场景下使用了伪指令 NOP
   ```

   **正确示例:**

   ```assembly
   NOOP
   ```

4. **`MOVK`, `MOVZ`, `MOVN` 指令的零移位错误:**  Go 汇编器目前不支持 `MOVK`, `MOVZ`, `MOVN` 指令的零移位。

   **错误示例:**

   ```assembly
   MOVK $0, R10 // 汇编器会报错
   MOVK $(0<<16), R10 // 汇编器也会报错
   ```

总而言之，`go/src/cmd/internal/obj/arm64/doc.go` 是理解 Go 语言在 ARM64 架构上进行底层编程的关键文档，它定义了汇编语法和映射规则，帮助开发者编写高效的汇编代码。理解这些规则是避免常见错误并充分利用硬件性能的基础。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/arm64/doc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package arm64 implements an ARM64 assembler. Go assembly syntax is different from GNU ARM64
syntax, but we can still follow the general rules to map between them.

# Instructions mnemonics mapping rules

1. Most instructions use width suffixes of instruction names to indicate operand width rather than
using different register names.

Examples:

	ADC R24, R14, R12          <=>     adc x12, x14, x24
	ADDW R26->24, R21, R15     <=>     add w15, w21, w26, asr #24
	FCMPS F2, F3               <=>     fcmp s3, s2
	FCMPD F2, F3               <=>     fcmp d3, d2
	FCVTDH F2, F3              <=>     fcvt h3, d2

2. Go uses .P and .W suffixes to indicate post-increment and pre-increment.

Examples:

	MOVD.P -8(R10), R8         <=>      ldr x8, [x10],#-8
	MOVB.W 16(R16), R10        <=>      ldrsb x10, [x16,#16]!
	MOVBU.W 16(R16), R10       <=>      ldrb x10, [x16,#16]!

3. Go uses a series of MOV instructions as load and store.

64-bit variant ldr, str, stur => MOVD;
32-bit variant str, stur, ldrsw => MOVW;
32-bit variant ldr => MOVWU;
ldrb => MOVBU; ldrh => MOVHU;
ldrsb, sturb, strb => MOVB;
ldrsh, sturh, strh =>  MOVH.

4. Go moves conditions into opcode suffix, like BLT.

5. Go adds a V prefix for most floating-point and SIMD instructions, except cryptographic extension
instructions and floating-point(scalar) instructions.

Examples:

	VADD V5.H8, V18.H8, V9.H8         <=>      add v9.8h, v18.8h, v5.8h
	VLD1.P (R6)(R11), [V31.D1]        <=>      ld1 {v31.1d}, [x6], x11
	VFMLA V29.S2, V20.S2, V14.S2      <=>      fmla v14.2s, v20.2s, v29.2s
	AESD V22.B16, V19.B16             <=>      aesd v19.16b, v22.16b
	SCVTFWS R3, F16                   <=>      scvtf s17, w6

6. Align directive

Go asm supports the PCALIGN directive, which indicates that the next instruction should be aligned
to a specified boundary by padding with NOOP instruction. The alignment value supported on arm64
must be a power of 2 and in the range of [8, 2048].

Examples:

	PCALIGN $16
	MOVD $2, R0          // This instruction is aligned with 16 bytes.
	PCALIGN $1024
	MOVD $3, R1          // This instruction is aligned with 1024 bytes.

PCALIGN also changes the function alignment. If a function has one or more PCALIGN directives,
its address will be aligned to the same or coarser boundary, which is the maximum of all the
alignment values.

In the following example, the function Add is aligned with 128 bytes.

Examples:

	TEXT ·Add(SB),$40-16
	MOVD $2, R0
	PCALIGN $32
	MOVD $4, R1
	PCALIGN $128
	MOVD $8, R2
	RET

On arm64, functions in Go are aligned to 16 bytes by default, we can also use PCALIGN to set the
function alignment. The functions that need to be aligned are preferably using NOFRAME and NOSPLIT
to avoid the impact of the prologues inserted by the assembler, so that the function address will
have the same alignment as the first hand-written instruction.

In the following example, PCALIGN at the entry of the function Add will align its address to 2048 bytes.

Examples:

	TEXT ·Add(SB),NOSPLIT|NOFRAME,$0
	  PCALIGN $2048
	  MOVD $1, R0
	  MOVD $1, R1
	  RET

7. Move large constants to vector registers.

Go asm uses VMOVQ/VMOVD/VMOVS to move 128-bit, 64-bit and 32-bit constants into vector registers, respectively.
And for a 128-bit integer, it take two 64-bit operands, for the low and high parts separately.

Examples:

	VMOVS $0x11223344, V0
	VMOVD $0x1122334455667788, V1
	VMOVQ $0x1122334455667788, $0x99aabbccddeeff00, V2   // V2=0x99aabbccddeeff001122334455667788

8. Move an optionally-shifted 16-bit immediate value to a register.

The instructions are MOVK(W), MOVZ(W) and MOVN(W), the assembly syntax is "op $(uimm16<<shift), <Rd>". The <uimm16>
is the 16-bit unsigned immediate, in the range 0 to 65535; For the 32-bit variant, the <shift> is 0 or 16, for the
64-bit variant, the <shift> is 0, 16, 32 or 48.

The current Go assembler does not accept zero shifts, such as "op $0, Rd" and "op $(0<<(16|32|48)), Rd" instructions.

Examples:

	MOVK $(10<<32), R20     <=>      movk x20, #10, lsl #32
	MOVZW $(20<<16), R8     <=>      movz w8, #20, lsl #16
	MOVK $(0<<16), R10 will be reported as an error by the assembler.

Special Cases.

(1) umov is written as VMOV.

(2) br is renamed JMP, blr is renamed CALL.

(3) No need to add "W" suffix: LDARB, LDARH, LDAXRB, LDAXRH, LDTRH, LDXRB, LDXRH.

(4) In Go assembly syntax, NOP is a zero-width pseudo-instruction serves generic purpose, nothing
related to real ARM64 instruction. NOOP serves for the hardware nop instruction. NOOP is an alias of
HINT $0.

Examples:

	VMOV V13.B[1], R20      <=>      mov x20, v13.b[1]
	VMOV V13.H[1], R20      <=>      mov w20, v13.h[1]
	JMP (R3)                <=>      br x3
	CALL (R17)              <=>      blr x17
	LDAXRB (R19), R16       <=>      ldaxrb w16, [x19]
	NOOP                    <=>      nop

# Register mapping rules

1. All basic register names are written as Rn.

2. Go uses ZR as the zero register and RSP as the stack pointer.

3. Bn, Hn, Dn, Sn and Qn instructions are written as Fn in floating-point instructions and as Vn
in SIMD instructions.

# Argument mapping rules

1. The operands appear in left-to-right assignment order.

Go reverses the arguments of most instructions.

Examples:

	ADD R11.SXTB<<1, RSP, R25      <=>      add x25, sp, w11, sxtb #1
	VADD V16, V19, V14             <=>      add d14, d19, d16

Special Cases.

(1) Argument order is the same as in the GNU ARM64 syntax: cbz, cbnz and some store instructions,
such as str, stur, strb, sturb, strh, sturh stlr, stlrb. stlrh, st1.

Examples:

	MOVD R29, 384(R19)    <=>    str x29, [x19,#384]
	MOVB.P R30, 30(R4)    <=>    strb w30, [x4],#30
	STLRH R21, (R19)      <=>    stlrh w21, [x19]

(2) MADD, MADDW, MSUB, MSUBW, SMADDL, SMSUBL, UMADDL, UMSUBL <Rm>, <Ra>, <Rn>, <Rd>

Examples:

	MADD R2, R30, R22, R6       <=>    madd x6, x22, x2, x30
	SMSUBL R10, R3, R17, R27    <=>    smsubl x27, w17, w10, x3

(3) FMADDD, FMADDS, FMSUBD, FMSUBS, FNMADDD, FNMADDS, FNMSUBD, FNMSUBS <Fm>, <Fa>, <Fn>, <Fd>

Examples:

	FMADDD F30, F20, F3, F29    <=>    fmadd d29, d3, d30, d20
	FNMSUBS F7, F25, F7, F22    <=>    fnmsub s22, s7, s7, s25

(4) BFI, BFXIL, SBFIZ, SBFX, UBFIZ, UBFX $<lsb>, <Rn>, $<width>, <Rd>

Examples:

	BFIW $16, R20, $6, R0      <=>    bfi w0, w20, #16, #6
	UBFIZ $34, R26, $5, R20    <=>    ubfiz x20, x26, #34, #5

(5) FCCMPD, FCCMPS, FCCMPED, FCCMPES <cond>, Fm. Fn, $<nzcv>

Examples:

	FCCMPD AL, F8, F26, $0     <=>    fccmp d26, d8, #0x0, al
	FCCMPS VS, F29, F4, $4     <=>    fccmp s4, s29, #0x4, vs
	FCCMPED LE, F20, F5, $13   <=>    fccmpe d5, d20, #0xd, le
	FCCMPES NE, F26, F10, $0   <=>    fccmpe s10, s26, #0x0, ne

(6) CCMN, CCMNW, CCMP, CCMPW <cond>, <Rn>, $<imm>, $<nzcv>

Examples:

	CCMP MI, R22, $12, $13     <=>    ccmp x22, #0xc, #0xd, mi
	CCMNW AL, R1, $11, $8      <=>    ccmn w1, #0xb, #0x8, al

(7) CCMN, CCMNW, CCMP, CCMPW <cond>, <Rn>, <Rm>, $<nzcv>

Examples:

	CCMN VS, R13, R22, $10     <=>    ccmn x13, x22, #0xa, vs
	CCMPW HS, R19, R14, $11    <=>    ccmp w19, w14, #0xb, cs

(9) CSEL, CSELW, CSNEG, CSNEGW, CSINC, CSINCW <cond>, <Rn>, <Rm>, <Rd> ;
FCSELD, FCSELS <cond>, <Fn>, <Fm>, <Fd>

Examples:

	CSEL GT, R0, R19, R1        <=>    csel x1, x0, x19, gt
	CSNEGW GT, R7, R17, R8      <=>    csneg w8, w7, w17, gt
	FCSELD EQ, F15, F18, F16    <=>    fcsel d16, d15, d18, eq

(10) TBNZ, TBZ $<imm>, <Rt>, <label>

(11) STLXR, STLXRW, STXR, STXRW, STLXRB, STLXRH, STXRB, STXRH  <Rf>, (<Rn|RSP>), <Rs>

Examples:

	STLXR ZR, (R15), R16    <=>    stlxr w16, xzr, [x15]
	STXRB R9, (R21), R19    <=>    stxrb w19, w9, [x21]

(12) STLXP, STLXPW, STXP, STXPW (<Rf1>, <Rf2>), (<Rn|RSP>), <Rs>

Examples:

	STLXP (R17, R19), (R4), R5      <=>    stlxp w5, x17, x19, [x4]
	STXPW (R30, R25), (R22), R13    <=>    stxp w13, w30, w25, [x22]

2. Expressions for special arguments.

#<immediate> is written as $<immediate>.

Optionally-shifted immediate.

Examples:

	ADD $(3151<<12), R14, R20     <=>    add x20, x14, #0xc4f, lsl #12
	ADDW $1864, R25, R6           <=>    add w6, w25, #0x748

Optionally-shifted registers are written as <Rm>{<shift><amount>}.
The <shift> can be <<(lsl), >>(lsr), ->(asr), @>(ror).

Examples:

	ADD R19>>30, R10, R24     <=>    add x24, x10, x19, lsr #30
	ADDW R26->24, R21, R15    <=>    add w15, w21, w26, asr #24

Extended registers are written as <Rm>{.<extend>{<<<amount>}}.
<extend> can be UXTB, UXTH, UXTW, UXTX, SXTB, SXTH, SXTW or SXTX.

Examples:

	ADDS R19.UXTB<<4, R9, R26     <=>    adds x26, x9, w19, uxtb #4
	ADDSW R14.SXTX, R14, R6       <=>    adds w6, w14, w14, sxtx

Memory references: [<Xn|SP>{,#0}] is written as (Rn|RSP), a base register and an immediate
offset is written as imm(Rn|RSP), a base register and an offset register is written as (Rn|RSP)(Rm).

Examples:

	LDAR (R22), R9                  <=>    ldar x9, [x22]
	LDP 28(R17), (R15, R23)         <=>    ldp x15, x23, [x17,#28]
	MOVWU (R4)(R12<<2), R8          <=>    ldr w8, [x4, x12, lsl #2]
	MOVD (R7)(R11.UXTW<<3), R25     <=>    ldr x25, [x7,w11,uxtw #3]
	MOVBU (R27)(R23), R14           <=>    ldrb w14, [x27,x23]

Register pairs are written as (Rt1, Rt2).

Examples:

	LDP.P -240(R11), (R12, R26)    <=>    ldp x12, x26, [x11],#-240

Register with arrangement and register with arrangement and index.

Examples:

	VADD V5.H8, V18.H8, V9.H8                     <=>    add v9.8h, v18.8h, v5.8h
	VLD1 (R2), [V21.B16]                          <=>    ld1 {v21.16b}, [x2]
	VST1.P V9.S[1], (R16)(R21)                    <=>    st1 {v9.s}[1], [x16], x28
	VST1.P [V13.H8, V14.H8, V15.H8], (R3)(R14)    <=>    st1 {v13.8h-v15.8h}, [x3], x14
	VST1.P [V14.D1, V15.D1], (R7)(R23)            <=>    st1 {v14.1d, v15.1d}, [x7], x23
*/
package arm64

"""



```