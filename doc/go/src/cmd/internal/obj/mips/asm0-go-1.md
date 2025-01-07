Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, specifically within the context of MIPS assembly generation. It also requests examples and potential pitfalls. The "Part 2" aspect suggests it's a continuation of a larger file.

2. **Initial Code Scan - Identify Key Structures and Functions:**  A quick scan reveals several key elements:
    * **Helper Functions:** `OP_RRR`, `OP_IRR`, `OP_SRR`, `OP_FRRR`, `OP_JMP`, `OP_VI10`, `OP_VMI10`. These clearly construct MIPS instruction words by combining opcodes and register/immediate values.
    * **`ctxt0` struct and its methods:**  The `asmout` method is the core of this snippet. The `vregoff`, `regoff`, `oprrr`, and `opirr` methods are used within `asmout`.
    * **Constants and Variables:**  `REGZERO`, `REGTMP`, `REGSB`, and various MIPS assembly mnemonics (like `AADDU`, `AOR`, `ASLL`) suggest this code is dealing with MIPS architecture specifics.
    * **`switch` statement in `asmout`:** This is the main dispatch mechanism, handling different instruction encoding formats based on `o.type_`.

3. **Focus on the Core Functionality: `asmout`:**  This function takes a `obj.Prog` (representing a Go intermediate representation instruction), an `Optab` (likely containing instruction type information), and an output slice `[]uint32` to store the generated machine code.

4. **Analyze the `switch` cases in `asmout` - Instruction Encoding Logic:**  Each `case` corresponds to a different MIPS instruction format or a pseudo-operation. By examining the code within each case, we can deduce how different Go instructions are translated into MIPS machine code. Key observations:
    * **Register-Register Operations (case 2, 9, 32, 33):** Use `OP_RRR`.
    * **Immediate/Register Operations (case 3, 4, 7, 8, 10, 13, 15, 16):** Use `OP_IRR` or `OP_SRR`. Immediate values are often masked and shifted.
    * **Jump Instructions (case 6, 11, 18):** Use `OP_JMP` or rely on PC-relative addressing. Relocation information is added.
    * **Memory Access (case 7, 8, 27, 28, 35, 36, 50, 51, 53, 54):** Combine immediate calculations with register operands. Relocations are important for addresses.
    * **Floating-Point Operations (case 30, 31, 32, 33, 34, 41, 42, 47, 48):** Use `OP_FRRR` and specific opcodes for floating-point instructions.
    * **Vector/MSA Instructions (case 56, 57, 58):** Use `OP_VI10` and `OP_VMI10`.
    * **Multi-Instruction Sequences (case 10, 19, 23, 25, 26, 27, 28, 34, 35, 36, 50, 51, 52, 53, 54, 55):** Some Go instructions require multiple MIPS instructions to implement (e.g., loading a large constant).
    * **Pseudo-operations (case 0):** Do nothing.
    * **Relocations (case 50, 51, 52, 53, 54, 55):** Crucial for handling addresses of global variables, functions, and TLS.

5. **Analyze Helper Functions:** Understand the purpose of `oprrr` and `opirr`. These functions map Go assembly mnemonics to their corresponding MIPS opcode values. `vregoff` and `regoff` are for calculating offsets from addresses.

6. **Infer Overall Functionality:** Based on the code's structure and the operations within `asmout`, it's clear that this code is responsible for translating Go's intermediate representation of MIPS assembly instructions into actual machine code.

7. **Develop Examples:**  Choose representative cases from the `switch` statement and construct simple Go code snippets that would trigger those cases. Think about different operand types (registers, immediates, memory addresses, function calls).

8. **Identify Potential Pitfalls:** Consider areas where developers using this code (or the broader compiler) might make mistakes. Look for:
    * **Limited Immediate Ranges:**  Branches and immediate operands have size limitations.
    * **Register Usage:** Certain registers are reserved or have special purposes.
    * **Instruction Sequencing:** Some operations require specific instruction sequences.
    * **Relocation Issues:** Incorrectly handling addresses can lead to runtime errors.

9. **Address Specific Requirements:**
    * **Part 2 Summary:**  Synthesize the findings from the analysis to summarize the overall purpose.
    * **Code Examples:** Provide concrete Go code snippets.
    * **Input/Output for Code Reasoning:** Illustrate how specific inputs to `asmout` would result in particular MIPS instruction sequences.
    * **Command-Line Arguments:** If the code handled command-line arguments (which this snippet doesn't), detail their usage.
    * **User Errors:** Provide examples of common mistakes.

10. **Structure the Answer:** Organize the information logically with clear headings and explanations. Use formatting (like code blocks) to enhance readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the `Optab` directly contains the machine code.
* **Correction:**  The `Optab` seems to primarily define the *type* of instruction, guiding the logic in the `switch` statement on how to construct the machine code.
* **Initial thought:**  Focus only on simple cases.
* **Refinement:**  Include more complex cases involving immediates, memory access, and function calls to demonstrate the full range of functionality.
* **Initial thought:**  Ignore helper functions.
* **Refinement:**  Realize that understanding helper functions like `oprrr` and `opirr` is crucial for understanding how opcodes are determined.

By following this systematic approach, combining code analysis with an understanding of the MIPS architecture, and iteratively refining the understanding, we can arrive at a comprehensive explanation of the code's functionality.
这是 `go/src/cmd/internal/obj/mips/asm0.go` 文件的一部分，负责将 Go 语言的中间表示（`obj.Prog`）转换为 MIPS 架构的机器码。这是汇编过程的核心部分，它根据指令的类型和操作数，生成相应的 MIPS 指令。

**功能归纳:**

这部分代码的主要功能是定义了将 Go 语言的 MIPS 汇编指令表示形式 (`obj.Prog`) 编码成实际 MIPS 机器码的 `asmout` 函数，以及一些辅助函数用于生成 MIPS 指令的不同部分（操作码、寄存器、立即数等）。

**具体功能分解:**

1. **指令编码核心 (`asmout` 函数):**
   - 接收一个 `obj.Prog` 类型的指令 `p`，一个 `Optab` 类型的操作码表条目 `o`，以及一个用于存储生成机器码的 `uint32` 切片 `out`。
   - 根据 `o.type_` (指令类型) 使用 `switch` 语句分发到不同的编码逻辑。
   - 每个 `case` 分支处理一种或多种具有相似编码格式的 MIPS 指令。
   - 调用 `OP_RRR`, `OP_IRR`, `OP_SRR`, `OP_FRRR`, `OP_JMP`, `OP_VI10`, `OP_VMI10` 等辅助函数来构建 32 位的 MIPS 指令字。这些函数负责将操作码、寄存器号和立即数等字段组合成最终的指令。
   - 处理伪指令（`case 0`，例如 `NOP`）。
   - 处理寄存器到寄存器的移动 (`case 1`)，通常转换为 `OR` 指令。
   - 处理算术和逻辑运算 (`case 2`, `4`, `9`, `10`, `23`, `25`)，根据操作数类型选择合适的 `OP_RRR` 或 `OP_IRR`。
   - 处理内存访问指令 (`case 3`, `7`, `8`, `27`, `28`, `35`, `36`)，计算偏移地址并编码。
   - 处理分支指令 (`case 6`, `11`)，计算分支目标地址的偏移量，并处理延迟槽。
   - 处理立即数加载指令 (`case 19`, `24`)，可能需要使用 `LUI` 和 `OR` 指令组合加载大立即数。
   - 处理 `HI`/`LO` 寄存器的访问 (`case 20`, `21`)，用于乘法和除法结果。
   - 处理浮点运算指令 (`case 32`, `33`)，使用 `OP_FRRR` 并设置相应的浮点操作码。
   - 处理浮点寄存器和通用寄存器之间的移动 (`case 30`, `31`, `47`, `48`)。
   - 处理原子操作和内存屏障 (`case 49`)。
   - **处理重定位 (`case 50`, `51`, `52`, `53`, `54`, `55`):** 这是非常重要的部分，用于处理需要运行时才能确定的地址，例如全局变量、函数地址和 TLS 变量。它会生成加载地址的指令，并添加重定位信息，以便链接器在最终生成可执行文件时填充正确的地址。
   - 处理向量/MSA 指令 (`case 56`, `57`, `58`)，使用 `OP_VI10` 和 `OP_VMI10` 并根据数据格式进行编码。

2. **辅助的指令构建函数 (`OP_RRR`, `OP_IRR`, 等):**
   - 这些函数接收操作码和寄存器/立即数值，并将它们按照 MIPS 指令格式的要求组合成一个 32 位的整数。
   - 例如，`OP_RRR` 用于构建 R 型指令（寄存器-寄存器操作），将操作码和三个寄存器号放入正确的位域。`OP_IRR` 用于构建 I 型指令（立即数操作），包含操作码、立即数和两个寄存器号。

3. **辅助的地址和偏移量计算函数 (`vregoff`, `regoff`):**
   - `regoff` 函数用于计算操作数中的偏移量，例如 `12(R1)` 中的 `12`。它会被 `asmout` 函数调用，以获取内存访问指令中的偏移量。

4. **操作码查找函数 (`oprrr`, `opirr`):**
   - 这些函数根据 Go 汇编指令的助记符（例如 `ADD`, `OR`, `BEQ`）返回对应的 MIPS 操作码。`oprrr` 用于 R 型指令，`opirr` 用于 I 型指令。

5. **向量/MSA 辅助函数 (`twobitdf`, `lsoffset`):**
   - `twobitdf` 函数用于获取 MSA 指令中数据格式的两位编码。
   - `lsoffset` 函数用于检查 MSA 加载/存储指令的偏移量是否是数据大小的倍数。

**推断 Go 语言功能实现 (需要结合上下文，仅从这段代码推断):**

从这段代码来看，它主要关注于将 Go 语言的汇编指令转换为机器码。很难直接推理出特定的 *高级* Go 语言功能的实现，因为它处于编译器的底层。但是，可以推断出它与以下方面相关：

- **函数调用:** `case 11` 中处理 `JAL` (Jump and Link) 指令，这通常用于函数调用。
- **条件分支:** `case 6` 中处理 `BEQ` 等条件分支指令，这对应于 Go 语言中的 `if` 语句或循环结构。
- **内存访问:**  多个 `case` 处理 `MOV` 指令的不同形式，涉及到从内存加载数据和将数据存储到内存，这对应于 Go 语言中变量的读取和写入。
- **常量加载:** `case 3`, `19`, `24` 处理加载常量到寄存器，对应 Go 语言中常量和字面量的使用。
- **浮点运算:** `case 32`, `33` 等处理浮点运算，对应 Go 语言中的 `float32` 和 `float64` 类型的操作。
- **原子操作:**  `case 49` 的 `undef` 可能与原子操作相关，虽然这里只是生成一个 `trap` 指令，但通常原子操作需要特定的指令序列。
- **Go 运行时支持:** 重定位的处理 (`case 50` 到 `55`) 表明了对 Go 运行时环境的支持，例如访问全局变量和线程本地存储 (TLS)。
- **向量/SIMD 指令:** `case 56`, `57`, `58` 表明对 MIPS MSA (SIMD) 扩展的支持。

**Go 代码示例 (假设):**

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	x := 10
	y := 20
	z := add(x, y)
	println(z)
}
```

当编译这段代码时，`asmout` 函数会被调用来生成 `add` 函数内部的加法操作和 `main` 函数中的变量赋值、函数调用等对应的 MIPS 机器码。例如，`a + b` 可能会被编码成类似 `ADDU $t0, $a0, $a1` 的 MIPS 指令（实际使用的寄存器可能不同）。`add(x, y)` 的调用会涉及到 `JAL` 指令。

**代码推理示例:**

**假设输入:**

一个 `obj.Prog` 结构体 `p`，代表 Go 汇编指令 `ADD R1, R2, R3` (将 R1 和 R2 的值相加，结果存入 R3)。
一个 `Optab` 结构体 `o`，其 `o.type_` 为 `2` (对应于 `add/sub r1,[r2],r3` 的指令类型)。

**预期输出:**

`out[0]` 将包含 MIPS 指令 `0x01234020` (假设 `ADD` 的操作码是 `000000`，R1 是寄存器 1，R2 是寄存器 2，R3 是寄存器 3，并且位域排列符合 MIPS R 型指令格式)。

**`asmout` 函数中的处理:**

在 `case 2` 分支中，`o1 = OP_RRR(c.oprrr(p.As), p.From.Reg, r, p.To.Reg)` 会被执行。

- `c.oprrr(p.As)` (其中 `p.As` 是 `AADD`) 会返回 `ADD` 指令的 MIPS 操作码。
- `p.From.Reg` 是 `R1`。
- `r` 是 `p.Reg`，即 `R2`。
- `p.To.Reg` 是 `R3`。

`OP_RRR` 函数会将这些值组合成最终的 32 位指令。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的其他阶段，例如词法分析、语法分析和中间代码生成。`asm0.go` 的任务是接收已经处理好的中间表示，并将其转换为机器码。

**使用者易犯错的点:**

由于 `asm0.go` 是编译器的一部分，直接的使用者是 Go 编译器的开发者，而不是一般的 Go 语言开发者。编译器开发者在编写或修改这部分代码时可能犯的错误包括：

- **MIPS 指令格式理解错误:**  错误地排列指令中的位域，导致生成的机器码不正确。例如，寄存器号或立即数放置的位置错误。
- **操作码映射错误:** 在 `oprrr` 和 `opirr` 函数中将 Go 汇编指令错误地映射到 MIPS 操作码。
- **立即数范围处理不当:**  MIPS 的立即数有位数限制，如果生成的立即数超出范围，需要使用多条指令来加载。
- **分支目标地址计算错误:**  计算分支指令的偏移量时出现错误，导致程序跳转到错误的位置。特别是短分支指令的范围有限。
- **延迟槽处理错误:** MIPS 的部分分支指令有延迟槽，即分支指令后的一条指令总是会被执行，无论分支是否发生。需要正确处理延迟槽的填充。
- **重定位信息添加错误:** 对于需要运行时才能确定的地址，如果没有正确添加重定位信息，链接器将无法填充正确的地址。例如，忘记添加 `R_ADDRMIPS` 或 `R_CALLMIPS` 类型的重定位。
- **MSA 指令编码错误:**  对于向量/MSA 指令，数据格式和偏移量的计算需要特别注意。例如，偏移量必须是数据大小的倍数。

总之，`go/src/cmd/internal/obj/mips/asm0.go` 的这部分代码是 MIPS 后端代码生成的核心，负责将 Go 语言的汇编指令翻译成可执行的机器码。它的正确性直接关系到最终生成程序的正确性。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/mips/asm0.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
, r3 int16) uint32 {
	return op | uint32(r1&31)<<16 | uint32(r2&31)<<21 | uint32(r3&31)<<11
}

func OP_IRR(op uint32, i uint32, r2 int16, r3 int16) uint32 {
	return op | i&0xFFFF | uint32(r2&31)<<21 | uint32(r3&31)<<16
}

func OP_SRR(op uint32, s uint32, r2 int16, r3 int16) uint32 {
	return op | (s&31)<<6 | uint32(r2&31)<<16 | uint32(r3&31)<<11
}

func OP_FRRR(op uint32, r1 int16, r2 int16, r3 int16) uint32 {
	return op | uint32(r1&31)<<16 | uint32(r2&31)<<11 | uint32(r3&31)<<6
}

func OP_JMP(op uint32, i uint32) uint32 {
	return op | i&0x3FFFFFF
}

func OP_VI10(op uint32, df uint32, s10 int32, wd uint32, minor uint32) uint32 {
	return 0x1e<<26 | (op&7)<<23 | (df&3)<<21 | uint32(s10&0x3FF)<<11 | (wd&31)<<6 | minor&0x3F
}

func OP_VMI10(s10 int32, rs uint32, wd uint32, minor uint32, df uint32) uint32 {
	return 0x1e<<26 | uint32(s10&0x3FF)<<16 | (rs&31)<<11 | (wd&31)<<6 | (minor&15)<<2 | df&3
}

func (c *ctxt0) asmout(p *obj.Prog, o *Optab, out []uint32) {
	o1 := uint32(0)
	o2 := uint32(0)
	o3 := uint32(0)
	o4 := uint32(0)

	add := AADDU

	if c.ctxt.Arch.Family == sys.MIPS64 {
		add = AADDVU
	}
	switch o.type_ {
	default:
		c.ctxt.Diag("unknown type %d %v", o.type_)
		prasm(p)

	case 0: /* pseudo ops */
		break

	case 1: /* mov r1,r2 ==> OR r1,r0,r2 */
		a := AOR
		if p.As == AMOVW && c.ctxt.Arch.Family == sys.MIPS64 {
			// on MIPS64, most of the 32-bit instructions have unpredictable behavior,
			// but SLL is special that the result is always sign-extended to 64-bit.
			a = ASLL
		}
		o1 = OP_RRR(c.oprrr(a), p.From.Reg, REGZERO, p.To.Reg)

	case 2: /* add/sub r1,[r2],r3 */
		r := p.Reg
		if p.As == ANEGW || p.As == ANEGV {
			r = REGZERO
		}
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o1 = OP_RRR(c.oprrr(p.As), p.From.Reg, r, p.To.Reg)

	case 3: /* mov $soreg, r ==> or/add $i,o,r */
		a := add
		if o.a1 == C_ANDCON {
			a = AOR
		}
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(a), uint32(v), r, p.To.Reg)

	case 4: /* add $scon,[r1],r2 */
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(p.As), uint32(v), r, p.To.Reg)

	case 5: /* syscall */
		o1 = c.oprrr(p.As)

	case 6: /* beq r1,[r2],sbra */
		v := int32(0)
		if p.To.Target() == nil {
			v = int32(-4) >> 2
		} else {
			v = int32(p.To.Target().Pc-p.Pc-4) >> 2
		}
		if (v<<16)>>16 != v {
			c.ctxt.Diag("short branch too far\n%v", p)
		}
		o1 = OP_IRR(c.opirr(p.As), uint32(v), p.From.Reg, p.Reg)
		// for ABFPT and ABFPF only: always fill delay slot with 0
		// see comments in func preprocess for details.
		o2 = 0

	case 7: /* mov r, soreg ==> sw o(r) */
		r := p.To.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.To)
		o1 = OP_IRR(c.opirr(p.As), uint32(v), r, p.From.Reg)

	case 8: /* mov soreg, r ==> lw o(r) */
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(-p.As), uint32(v), r, p.To.Reg)

	case 9: /* sll r1,[r2],r3 */
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o1 = OP_RRR(c.oprrr(p.As), r, p.From.Reg, p.To.Reg)

	case 10: /* add $con,[r1],r2 ==> mov $con, t; add t,[r1],r2 */
		v := c.regoff(&p.From)
		a := AOR
		if v < 0 {
			a = AADDU
		}
		o1 = OP_IRR(c.opirr(a), uint32(v), obj.REG_NONE, REGTMP)
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o2 = OP_RRR(c.oprrr(p.As), REGTMP, r, p.To.Reg)

	case 11: /* jmp lbra */
		v := int32(0)
		if c.aclass(&p.To) == C_SBRA && p.To.Sym == nil && p.As == AJMP {
			// use PC-relative branch for short branches
			// BEQ	R0, R0, sbra
			if p.To.Target() == nil {
				v = int32(-4) >> 2
			} else {
				v = int32(p.To.Target().Pc-p.Pc-4) >> 2
			}
			if (v<<16)>>16 == v {
				o1 = OP_IRR(c.opirr(ABEQ), uint32(v), REGZERO, REGZERO)
				break
			}
		}
		if p.To.Target() == nil {
			v = int32(p.Pc) >> 2
		} else {
			v = int32(p.To.Target().Pc) >> 2
		}
		o1 = OP_JMP(c.opirr(p.As), uint32(v))
		if p.To.Sym == nil {
			p.To.Sym = c.cursym.Func().Text.From.Sym
			p.To.Offset = p.To.Target().Pc
		}
		typ := objabi.R_JMPMIPS
		if p.As == AJAL {
			typ = objabi.R_CALLMIPS
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: typ,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

	case 12: /* movbs r,r */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		v := 16
		if p.As == AMOVB {
			v = 24
		}
		o1 = OP_SRR(c.opirr(ASLL), uint32(v), p.From.Reg, p.To.Reg)
		o2 = OP_SRR(c.opirr(ASRA), uint32(v), p.To.Reg, p.To.Reg)

	case 13: /* movbu r,r */
		if p.As == AMOVBU {
			o1 = OP_IRR(c.opirr(AAND), uint32(0xff), p.From.Reg, p.To.Reg)
		} else {
			o1 = OP_IRR(c.opirr(AAND), uint32(0xffff), p.From.Reg, p.To.Reg)
		}

	case 14: /* movwu r,r */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = OP_SRR(c.opirr(-ASLLV), 0, p.From.Reg, p.To.Reg)
		o2 = OP_SRR(c.opirr(-ASRLV), 0, p.To.Reg, p.To.Reg)

	case 15: /* teq $c r,r */
		r := p.Reg
		if r == obj.REG_NONE {
			r = REGZERO
		}
		v := c.regoff(&p.From)
		/* only use 10 bits of trap code */
		o1 = OP_IRR(c.opirr(p.As), (uint32(v)&0x3FF)<<6, r, p.To.Reg)

	case 16: /* sll $c,[r1],r2 */
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		v := c.regoff(&p.From)

		/* OP_SRR will use only the low 5 bits of the shift value */
		if v >= 32 && vshift(p.As) {
			o1 = OP_SRR(c.opirr(-p.As), uint32(v-32), r, p.To.Reg)
		} else {
			o1 = OP_SRR(c.opirr(p.As), uint32(v), r, p.To.Reg)
		}

	case 17:
		o1 = OP_RRR(c.oprrr(p.As), REGZERO, p.From.Reg, p.To.Reg)

	case 18: /* jmp [r1],0(r2) */
		r := p.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		o1 = OP_RRR(c.oprrr(p.As), obj.REG_NONE, p.To.Reg, r)
		if p.As == obj.ACALL {
			c.cursym.AddRel(c.ctxt, obj.Reloc{
				Type: objabi.R_CALLIND,
				Off:  int32(c.pc),
			})
		}

	case 19: /* mov $lcon,r ==> lu+or */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, p.To.Reg)
		o2 = OP_IRR(c.opirr(AOR), uint32(v), p.To.Reg, p.To.Reg)

	case 20: /* mov lo/hi,r */
		a := OP(2, 0) /* mfhi */
		if p.From.Reg == REG_LO {
			a = OP(2, 2) /* mflo */
		}
		o1 = OP_RRR(a, REGZERO, REGZERO, p.To.Reg)

	case 21: /* mov r,lo/hi */
		a := OP(2, 1) /* mthi */
		if p.To.Reg == REG_LO {
			a = OP(2, 3) /* mtlo */
		}
		o1 = OP_RRR(a, REGZERO, p.From.Reg, REGZERO)

	case 22: /* mul r1,r2 [r3]*/
		if p.To.Reg != obj.REG_NONE {
			r := p.Reg
			if r == obj.REG_NONE {
				r = p.To.Reg
			}
			a := SP(3, 4) | 2 /* mul */
			o1 = OP_RRR(a, p.From.Reg, r, p.To.Reg)
		} else {
			o1 = OP_RRR(c.oprrr(p.As), p.From.Reg, p.Reg, REGZERO)
		}

	case 23: /* add $lcon,r1,r2 ==> lu+or+add */
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, REGTMP)
		o2 = OP_IRR(c.opirr(AOR), uint32(v), REGTMP, REGTMP)
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o3 = OP_RRR(c.oprrr(p.As), REGTMP, r, p.To.Reg)

	case 24: /* mov $ucon,r ==> lu r */
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, p.To.Reg)

	case 25: /* add/and $ucon,[r1],r2 ==> lu $con,t; add t,[r1],r2 */
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, REGTMP)
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o2 = OP_RRR(c.oprrr(p.As), REGTMP, r, p.To.Reg)

	case 26: /* mov $lsext/auto/oreg,r ==> lu+or+add */
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, REGTMP)
		o2 = OP_IRR(c.opirr(AOR), uint32(v), REGTMP, REGTMP)
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		o3 = OP_RRR(c.oprrr(add), REGTMP, r, p.To.Reg)

	case 27: /* mov [sl]ext/auto/oreg,fr ==> lwc1 o(r) */
		a := -AMOVF
		if p.As == AMOVD {
			a = -AMOVD
		}
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.From)
		switch o.size {
		case 12:
			o1 = OP_IRR(c.opirr(ALUI), uint32((v+1<<15)>>16), REGZERO, REGTMP)
			o2 = OP_RRR(c.oprrr(add), r, REGTMP, REGTMP)
			o3 = OP_IRR(c.opirr(a), uint32(v), REGTMP, p.To.Reg)

		case 4:
			o1 = OP_IRR(c.opirr(a), uint32(v), r, p.To.Reg)
		}

	case 28: /* mov fr,[sl]ext/auto/oreg ==> swc1 o(r) */
		a := AMOVF
		if p.As == AMOVD {
			a = AMOVD
		}
		r := p.To.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.To)
		switch o.size {
		case 12:
			o1 = OP_IRR(c.opirr(ALUI), uint32((v+1<<15)>>16), REGZERO, REGTMP)
			o2 = OP_RRR(c.oprrr(add), r, REGTMP, REGTMP)
			o3 = OP_IRR(c.opirr(a), uint32(v), REGTMP, p.From.Reg)

		case 4:
			o1 = OP_IRR(c.opirr(a), uint32(v), r, p.From.Reg)
		}

	case 30: /* movw r,fr */
		a := SP(2, 1) | (4 << 21) /* mtc1 */
		o1 = OP_RRR(a, p.From.Reg, obj.REG_NONE, p.To.Reg)

	case 31: /* movw fr,r */
		a := SP(2, 1) | (0 << 21) /* mtc1 */
		o1 = OP_RRR(a, p.To.Reg, obj.REG_NONE, p.From.Reg)

	case 32: /* fadd fr1,[fr2],fr3 */
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o1 = OP_FRRR(c.oprrr(p.As), p.From.Reg, r, p.To.Reg)

	case 33: /* fabs fr1, fr3 */
		o1 = OP_FRRR(c.oprrr(p.As), obj.REG_NONE, p.From.Reg, p.To.Reg)

	case 34: /* mov $con,fr ==> or/add $i,t; mov t,fr */
		a := AADDU
		if o.a1 == C_ANDCON {
			a = AOR
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(a), uint32(v), obj.REG_NONE, REGTMP)
		o2 = OP_RRR(SP(2, 1)|(4<<21), REGTMP, obj.REG_NONE, p.To.Reg) /* mtc1 */

	case 35: /* mov r,lext/auto/oreg ==> sw o(REGTMP) */
		r := p.To.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.To)
		o1 = OP_IRR(c.opirr(ALUI), uint32((v+1<<15)>>16), REGZERO, REGTMP)
		o2 = OP_RRR(c.oprrr(add), r, REGTMP, REGTMP)
		o3 = OP_IRR(c.opirr(p.As), uint32(v), REGTMP, p.From.Reg)

	case 36: /* mov lext/auto/oreg,r ==> lw o(REGTMP) */
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32((v+1<<15)>>16), REGZERO, REGTMP)
		o2 = OP_RRR(c.oprrr(add), r, REGTMP, REGTMP)
		o3 = OP_IRR(c.opirr(-p.As), uint32(v), REGTMP, p.To.Reg)

	case 37: /* movw r,mr */
		a := SP(2, 0) | (4 << 21) /* mtc0 */
		if p.As == AMOVV {
			a = SP(2, 0) | (5 << 21) /* dmtc0 */
		}
		o1 = OP_RRR(a, p.From.Reg, obj.REG_NONE, p.To.Reg)

	case 38: /* movw mr,r */
		a := SP(2, 0) | (0 << 21) /* mfc0 */
		if p.As == AMOVV {
			a = SP(2, 0) | (1 << 21) /* dmfc0 */
		}
		o1 = OP_RRR(a, p.To.Reg, obj.REG_NONE, p.From.Reg)

	case 40: /* word */
		o1 = uint32(c.regoff(&p.From))

	case 41: /* movw f,fcr */
		o1 = OP_RRR(SP(2, 1)|(6<<21), p.From.Reg, obj.REG_NONE, p.To.Reg) /* mtcc1 */

	case 42: /* movw fcr,r */
		o1 = OP_RRR(SP(2, 1)|(2<<21), p.To.Reg, obj.REG_NONE, p.From.Reg) /* mfcc1 */

	case 47: /* movv r,fr */
		a := SP(2, 1) | (5 << 21) /* dmtc1 */
		o1 = OP_RRR(a, p.From.Reg, obj.REG_NONE, p.To.Reg)

	case 48: /* movv fr,r */
		a := SP(2, 1) | (1 << 21) /* dmtc1 */
		o1 = OP_RRR(a, p.To.Reg, obj.REG_NONE, p.From.Reg)

	case 49: /* undef */
		o1 = 52 /* trap -- teq r0, r0 */

	/* relocation operations */
	case 50: /* mov r,addr ==> lu + add REGSB, REGTMP + sw o(REGTMP) */
		o1 = OP_IRR(c.opirr(ALUI), 0, REGZERO, REGTMP)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSU,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

		o2 = OP_IRR(c.opirr(p.As), 0, REGTMP, p.From.Reg)
		off := int32(c.pc + 4)
		if o.size == 12 {
			o3 = o2
			o2 = OP_RRR(c.oprrr(AADDVU), REGSB, REGTMP, REGTMP)
			off += 4
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPS,
			Off:  off,
			Siz:  4,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

	case 51: /* mov addr,r ==> lu + add REGSB, REGTMP + lw o(REGTMP) */
		o1 = OP_IRR(c.opirr(ALUI), 0, REGZERO, REGTMP)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSU,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

		o2 = OP_IRR(c.opirr(-p.As), 0, REGTMP, p.To.Reg)
		off := int32(c.pc + 4)
		if o.size == 12 {
			o3 = o2
			o2 = OP_RRR(c.oprrr(AADDVU), REGSB, REGTMP, REGTMP)
			off += 4
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPS,
			Off:  off,
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 52: /* mov $lext, r ==> lu + add REGSB, r + add */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = OP_IRR(c.opirr(ALUI), 0, REGZERO, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSU,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

		o2 = OP_IRR(c.opirr(add), 0, p.To.Reg, p.To.Reg)
		off := int32(c.pc + 4)
		if o.size == 12 {
			o3 = o2
			o2 = OP_RRR(c.oprrr(AADDVU), REGSB, p.To.Reg, p.To.Reg)
			off += 4
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPS,
			Off:  off,
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 53: /* mov r, tlsvar ==> rdhwr + sw o(r3) */
		// clobbers R3 !
		// load thread pointer with RDHWR, R3 is used for fast kernel emulation on Linux
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = (037<<26 + 073) | (29 << 11) | (3 << 16) // rdhwr $29, r3
		o2 = OP_IRR(c.opirr(p.As), 0, REG_R3, p.From.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSTLS,
			Off:  int32(c.pc + 4),
			Siz:  4,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

	case 54: /* mov tlsvar, r ==> rdhwr + lw o(r3) */
		// clobbers R3 !
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = (037<<26 + 073) | (29 << 11) | (3 << 16) // rdhwr $29, r3
		o2 = OP_IRR(c.opirr(-p.As), 0, REG_R3, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSTLS,
			Off:  int32(c.pc + 4),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 55: /* mov $tlsvar, r ==> rdhwr + add */
		// clobbers R3 !
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = (037<<26 + 073) | (29 << 11) | (3 << 16) // rdhwr $29, r3
		o2 = OP_IRR(c.opirr(add), 0, REG_R3, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSTLS,
			Off:  int32(c.pc + 4),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 56: /* vmov{b,h,w,d} $scon, wr */

		v := c.regoff(&p.From)
		o1 = OP_VI10(110, c.twobitdf(p.As), v, uint32(p.To.Reg), 7)

	case 57: /* vld $soreg, wr */
		v := c.lsoffset(p.As, c.regoff(&p.From))
		o1 = OP_VMI10(v, uint32(p.From.Reg), uint32(p.To.Reg), 8, c.twobitdf(p.As))

	case 58: /* vst wr, $soreg */
		v := c.lsoffset(p.As, c.regoff(&p.To))
		o1 = OP_VMI10(v, uint32(p.To.Reg), uint32(p.From.Reg), 9, c.twobitdf(p.As))

	case 59:
		o1 = OP_RRR(c.oprrr(p.As), p.From.Reg, REGZERO, p.To.Reg)
	}

	out[0] = o1
	out[1] = o2
	out[2] = o3
	out[3] = o4
}

func (c *ctxt0) vregoff(a *obj.Addr) int64 {
	c.instoffset = 0
	c.aclass(a)
	return c.instoffset
}

func (c *ctxt0) regoff(a *obj.Addr) int32 {
	return int32(c.vregoff(a))
}

func (c *ctxt0) oprrr(a obj.As) uint32 {
	switch a {
	case AADD:
		return OP(4, 0)
	case AADDU:
		return OP(4, 1)
	case ASGT:
		return OP(5, 2)
	case ASGTU:
		return OP(5, 3)
	case AAND:
		return OP(4, 4)
	case AOR:
		return OP(4, 5)
	case AXOR:
		return OP(4, 6)
	case ASUB:
		return OP(4, 2)
	case ASUBU, ANEGW:
		return OP(4, 3)
	case ANOR:
		return OP(4, 7)
	case ASLL:
		return OP(0, 4)
	case ASRL:
		return OP(0, 6)
	case ASRA:
		return OP(0, 7)
	case AROTR:
		return OP(8, 6)
	case ASLLV:
		return OP(2, 4)
	case ASRLV:
		return OP(2, 6)
	case ASRAV:
		return OP(2, 7)
	case AROTRV:
		return OP(10, 6)
	case AADDV:
		return OP(5, 4)
	case AADDVU:
		return OP(5, 5)
	case ASUBV:
		return OP(5, 6)
	case ASUBVU, ANEGV:
		return OP(5, 7)
	case AREM,
		ADIV:
		return OP(3, 2)
	case AREMU,
		ADIVU:
		return OP(3, 3)
	case AMUL:
		return OP(3, 0)
	case AMULU:
		return OP(3, 1)
	case AREMV,
		ADIVV:
		return OP(3, 6)
	case AREMVU,
		ADIVVU:
		return OP(3, 7)
	case AMULV:
		return OP(3, 4)
	case AMULVU:
		return OP(3, 5)

	case AJMP:
		return OP(1, 0)
	case AJAL:
		return OP(1, 1)

	case ABREAK:
		return OP(1, 5)
	case ASYSCALL:
		return OP(1, 4)
	case ATLBP:
		return MMU(1, 0)
	case ATLBR:
		return MMU(0, 1)
	case ATLBWI:
		return MMU(0, 2)
	case ATLBWR:
		return MMU(0, 6)
	case ARFE:
		return MMU(2, 0)

	case ADIVF:
		return FPF(0, 3)
	case ADIVD:
		return FPD(0, 3)
	case AMULF:
		return FPF(0, 2)
	case AMULD:
		return FPD(0, 2)
	case ASUBF:
		return FPF(0, 1)
	case ASUBD:
		return FPD(0, 1)
	case AADDF:
		return FPF(0, 0)
	case AADDD:
		return FPD(0, 0)
	case ATRUNCFV:
		return FPF(1, 1)
	case ATRUNCDV:
		return FPD(1, 1)
	case ATRUNCFW:
		return FPF(1, 5)
	case ATRUNCDW:
		return FPD(1, 5)
	case AMOVFV:
		return FPF(4, 5)
	case AMOVDV:
		return FPD(4, 5)
	case AMOVVF:
		return FPV(4, 0)
	case AMOVVD:
		return FPV(4, 1)
	case AMOVFW:
		return FPF(4, 4)
	case AMOVDW:
		return FPD(4, 4)
	case AMOVWF:
		return FPW(4, 0)
	case AMOVDF:
		return FPD(4, 0)
	case AMOVWD:
		return FPW(4, 1)
	case AMOVFD:
		return FPF(4, 1)
	case AABSF:
		return FPF(0, 5)
	case AABSD:
		return FPD(0, 5)
	case AMOVF:
		return FPF(0, 6)
	case AMOVD:
		return FPD(0, 6)
	case ANEGF:
		return FPF(0, 7)
	case ANEGD:
		return FPD(0, 7)
	case ACMPEQF:
		return FPF(6, 2)
	case ACMPEQD:
		return FPD(6, 2)
	case ACMPGTF:
		return FPF(7, 4)
	case ACMPGTD:
		return FPD(7, 4)
	case ACMPGEF:
		return FPF(7, 6)
	case ACMPGED:
		return FPD(7, 6)

	case ASQRTF:
		return FPF(0, 4)
	case ASQRTD:
		return FPD(0, 4)

	case ASYNC:
		return OP(1, 7)
	case ANOOP:
		return 0

	case ACMOVN:
		return OP(1, 3)
	case ACMOVZ:
		return OP(1, 2)
	case ACMOVT:
		return OP(0, 1) | (1 << 16)
	case ACMOVF:
		return OP(0, 1) | (0 << 16)
	case ACLO:
		return SP(3, 4) | OP(4, 1)
	case ACLZ:
		return SP(3, 4) | OP(4, 0)
	case AMADD:
		return SP(3, 4) | OP(0, 0)
	case AMSUB:
		return SP(3, 4) | OP(0, 4)
	case AWSBH:
		return SP(3, 7) | OP(20, 0)
	case ADSBH:
		return SP(3, 7) | OP(20, 4)
	case ADSHD:
		return SP(3, 7) | OP(44, 4)
	case ASEB:
		return SP(3, 7) | OP(132, 0)
	case ASEH:
		return SP(3, 7) | OP(196, 0)
	}

	if a < 0 {
		c.ctxt.Diag("bad rrr opcode -%v", -a)
	} else {
		c.ctxt.Diag("bad rrr opcode %v", a)
	}
	return 0
}

func (c *ctxt0) opirr(a obj.As) uint32 {
	switch a {
	case AADD:
		return SP(1, 0)
	case AADDU:
		return SP(1, 1)
	case ASGT:
		return SP(1, 2)
	case ASGTU:
		return SP(1, 3)
	case AAND:
		return SP(1, 4)
	case AOR:
		return SP(1, 5)
	case AXOR:
		return SP(1, 6)
	case ALUI:
		return SP(1, 7)
	case ASLL:
		return OP(0, 0)
	case ASRL:
		return OP(0, 2)
	case ASRA:
		return OP(0, 3)
	case AROTR:
		return OP(0, 2) | 1<<21
	case AADDV:
		return SP(3, 0)
	case AADDVU:
		return SP(3, 1)

	case AJMP:
		return SP(0, 2)
	case AJAL,
		obj.ADUFFZERO,
		obj.ADUFFCOPY:
		return SP(0, 3)
	case ABEQ:
		return SP(0, 4)
	case -ABEQ:
		return SP(2, 4) /* likely */
	case ABNE:
		return SP(0, 5)
	case -ABNE:
		return SP(2, 5) /* likely */
	case ABGEZ:
		return SP(0, 1) | BCOND(0, 1)
	case -ABGEZ:
		return SP(0, 1) | BCOND(0, 3) /* likely */
	case ABGEZAL:
		return SP(0, 1) | BCOND(2, 1)
	case -ABGEZAL:
		return SP(0, 1) | BCOND(2, 3) /* likely */
	case ABGTZ:
		return SP(0, 7)
	case -ABGTZ:
		return SP(2, 7) /* likely */
	case ABLEZ:
		return SP(0, 6)
	case -ABLEZ:
		return SP(2, 6) /* likely */
	case ABLTZ:
		return SP(0, 1) | BCOND(0, 0)
	case -ABLTZ:
		return SP(0, 1) | BCOND(0, 2) /* likely */
	case ABLTZAL:
		return SP(0, 1) | BCOND(2, 0)
	case -ABLTZAL:
		return SP(0, 1) | BCOND(2, 2) /* likely */
	case ABFPT:
		return SP(2, 1) | (257 << 16)
	case -ABFPT:
		return SP(2, 1) | (259 << 16) /* likely */
	case ABFPF:
		return SP(2, 1) | (256 << 16)
	case -ABFPF:
		return SP(2, 1) | (258 << 16) /* likely */

	case AMOVB,
		AMOVBU:
		return SP(5, 0)
	case AMOVH,
		AMOVHU:
		return SP(5, 1)
	case AMOVW,
		AMOVWU:
		return SP(5, 3)
	case AMOVV:
		return SP(7, 7)
	case AMOVF:
		return SP(7, 1)
	case AMOVD:
		return SP(7, 5)
	case AMOVWL:
		return SP(5, 2)
	case AMOVWR:
		return SP(5, 6)
	case AMOVVL:
		return SP(5, 4)
	case AMOVVR:
		return SP(5, 5)

	case ABREAK:
		return SP(5, 7)

	case -AMOVWL:
		return SP(4, 2)
	case -AMOVWR:
		return SP(4, 6)
	case -AMOVVL:
		return SP(3, 2)
	case -AMOVVR:
		return SP(3, 3)
	case -AMOVB:
		return SP(4, 0)
	case -AMOVBU:
		return SP(4, 4)
	case -AMOVH:
		return SP(4, 1)
	case -AMOVHU:
		return SP(4, 5)
	case -AMOVW:
		return SP(4, 3)
	case -AMOVWU:
		return SP(4, 7)
	case -AMOVV:
		return SP(6, 7)
	case -AMOVF:
		return SP(6, 1)
	case -AMOVD:
		return SP(6, 5)

	case ASLLV:
		return OP(7, 0)
	case ASRLV:
		return OP(7, 2)
	case ASRAV:
		return OP(7, 3)
	case AROTRV:
		return OP(7, 2) | 1<<21
	case -ASLLV:
		return OP(7, 4)
	case -ASRLV:
		return OP(7, 6)
	case -ASRAV:
		return OP(7, 7)
	case -AROTRV:
		return OP(7, 6) | 1<<21

	case ATEQ:
		return OP(6, 4)
	case ATNE:
		return OP(6, 6)
	case -ALL:
		return SP(6, 0)
	case -ALLV:
		return SP(6, 4)
	case ASC:
		return SP(7, 0)
	case ASCV:
		return SP(7, 4)
	}

	if a < 0 {
		c.ctxt.Diag("bad irr opcode -%v", -a)
	} else {
		c.ctxt.Diag("bad irr opcode %v", a)
	}
	return 0
}

func vshift(a obj.As) bool {
	switch a {
	case ASLLV,
		ASRLV,
		ASRAV,
		AROTRV:
		return true
	}
	return false
}

// MSA Two-bit Data Format Field Encoding
func (c *ctxt0) twobitdf(a obj.As) uint32 {
	switch a {
	case AVMOVB:
		return 0
	case AVMOVH:
		return 1
	case AVMOVW:
		return 2
	case AVMOVD:
		return 3
	default:
		c.ctxt.Diag("unsupported data format %v", a)
	}
	return 0
}

// MSA Load/Store offset have to be multiple of size of data format
func (c *ctxt0) lsoffset(a obj.As, o int32) int32 {
	var mod int32
	switch a {
	case AVMOVB:
		mod = 1
	case AVMOVH:
		mod = 2
	case AVMOVW:
		mod = 4
	case AVMOVD:
		mod = 8
	default:
		c.ctxt.Diag("unsupported instruction:%v", a)
	}

	if o%mod != 0 {
		c.ctxt.Diag("invalid offset for %v: %d is not a multiple of %d", a, o, mod)
	}

	return o / mod
}

"""




```