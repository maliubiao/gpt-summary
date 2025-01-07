Response:
My thinking process to arrive at the summary and analysis of the `asm7.go` code goes like this:

1. **Understand the Goal:** The core request is to analyze a Go file (`asm7.go`) which is part of the ARM64 assembler within the Go compiler. The analysis should cover functionality, potential Go feature implementation, code inference with examples, command-line argument handling (if applicable), common user errors, and a summary of the file's purpose (since it's part of a larger set).

2. **Initial Code Scan (Keywords and Structure):**  I start by quickly scanning the code for key terms and structural patterns:
    * **Function Names:** `assemble`, `ctxt7`, `addrRelocType`, `oprrr`, `opirr`, `opbit`, `opxrrr`, `opimm`, `opbra`, `opbrr`, `op0`, `opload`, `opstore`, `olsr12u`, `olsr9s`, `opstr`, `opldr`, `olsxrr`, `opldrr`, `opstrr`, `oaddi`, `oaddi12`, `omovlit`, `brdist`. These function names strongly suggest the code is involved in instruction encoding. The `op...` prefix hints at "operation" encoding for different instruction formats.
    * **Data Structures/Constants:**  Look for global variables, maps, or constants. The presence of `atomicCASP` and `sysInstFields` suggests data lookup tables related to specific instruction types.
    * **Control Flow:** Identify `switch` statements, especially those operating on `p.As` (instruction opcode). This confirms the code is handling different ARM64 instructions.
    * **Bit Manipulation:**  Observe the extensive use of bitwise operations (`<<`, `>>`, `|`, `&`). This is characteristic of assembler code that constructs machine code instructions bit by bit.
    * **Error Handling:**  Look for calls to `c.ctxt.Diag`, which indicates error reporting within the assembler.
    * **Comments:**  While the provided snippet has few comments, in a real scenario, I'd look for comments explaining the logic.

3. **Function-Level Analysis (Reverse Engineering):**  I then analyze the purpose of individual functions based on their names and operations:
    * `assemble`: This is likely the main entry point for assembling a single instruction. It dispatches to other functions based on instruction type.
    * `ctxt7`: This likely represents the context or state of the assembler during the assembly process.
    * `addrRelocType`: This function seems to determine the relocation type needed for address operands, likely when dealing with memory access.
    * `oprrr`: "Operation Register-Register-Register." Encodes instructions with three register operands.
    * `opirr`: "Operation Immediate-Register-Register" (or similar). Encodes instructions with an immediate value and two register operands.
    * `opbit`:  Encodes bit manipulation instructions.
    * `opxrrr`: Encodes instructions involving extended register operands.
    * `opimm`: Encodes instructions with immediate operands.
    * `opbra`:  Encodes branch instructions.
    * `opbrr`: Encodes branch instructions that target registers.
    * `op0`:  Encodes instructions with no operands (or implicit operands).
    * `opload`/`opstore`: Encode load and store instructions, respectively.
    * `olsr12u`/`olsr9s`: Handle immediate offsets for load/store instructions.
    * `olsxrr`:  Handles register offsets for load/store.
    * `opldrr`/`opstrr`: Specifically encode load/store with register offsets.
    * `oaddi`/`oaddi12`: Encode addition/subtraction with immediate values.
    * `omovlit`: Handles loading literal values from the constant pool.
    * `brdist`: Calculates the displacement for branch instructions.

4. **Inferring Go Feature Implementation:** Based on the function names and the types of instructions being encoded, I can infer the Go features these instructions support. For example:
    * Arithmetic operations (`ADD`, `SUB`, `MUL`, `DIV`, `AND`, `OR`, `XOR`): Supported by `oprrr`, `opirr`, `opxrrr`.
    * Comparisons (`CMP`, `CMN`): Handled similarly.
    * Data movement (`MOV` - register and immediate): Covered by various `op...` functions.
    * Load and store operations (`LDR`, `STR`): Implemented by `opload`, `opstore`, and related functions.
    * Branching (`B`, `BL`, conditional branches): Implemented by `opbra` and `opbrr`.
    * Atomic operations (`CASP`):  Explicitly handled in case 106 of `assemble`.
    * SIMD/NEON instructions (those starting with `V` like `VADD`, `VEOR`):  Encoded in various `op...` functions.
    * System instructions (`TLBI`, `DC`, `MSR`, `MRS`): Handled in case 107 and `opirr`.
    * Floating-point operations (`FADD`, `FSUB`, `FMUL`, `FDIV`, `FCVT`):  Encoded within `oprrr`.

5. **Code Inference and Examples:**  For specific instruction types, I can provide examples of how the code encodes them. This involves:
    * **Identifying the relevant `case` in the `assemble` function.**
    * **Mapping the Go assembly syntax to the code.**
    * **Illustrating how operands are extracted and combined into the instruction encoding.**
    * **Providing hypothetical input and output values to demonstrate the encoding process.**  This is crucial for clarifying the bit manipulation.

6. **Command-Line Arguments:** I carefully examine the code for any explicit handling of command-line arguments. In this snippet, there's no direct argument parsing. However, I understand that this code is part of a larger compiler, so command-line arguments would be handled at a higher level (e.g., in the `go` tool or compiler driver). Therefore, I note that the snippet itself doesn't handle them but that the broader context does.

7. **Common User Errors:**  I consider common mistakes someone writing ARM64 assembly might make, and how this code handles them:
    * **Incorrect register usage:** The code checks for valid register numbers and arrangements, issuing diagnostics if they are wrong.
    * **Out-of-range immediate values:** The code checks immediate values against allowed ranges for various instructions.
    * **Misaligned memory access:** Although not explicitly shown in the snippet, other parts of the assembler (or even the architecture) would handle alignment issues.
    * **Incorrect conditional code usage:**  The `opbra` function demonstrates how conditional codes are encoded.

8. **Summarization:**  Finally, I synthesize the information gathered to provide a concise summary of the file's functionality. Since this is part 6 of 7, I also consider its role within the larger assembler. The key point is that `asm7.go` is responsible for the core instruction encoding logic for a significant subset of ARM64 instructions.

**Self-Correction/Refinement During the Process:**

* **Initial Overestimation:** I might initially think a certain function handles more instructions than it actually does. Careful examination of the `switch` statements helps refine this.
* **Operand Interpretation:**  Understanding how operands like offsets, immediate values, and registers are extracted from the `obj.Prog` structure requires careful tracing of the code.
* **Bit Field Mapping:**  Figuring out which bits in the instruction encoding correspond to which operands often involves looking up ARM64 instruction set documentation or relying on comments (if available). The code uses named constants (like `S64`, `OPDP2`) which are helpful clues.
* **Contextual Awareness:**  Remembering that this is *part* of a larger system is important for understanding why certain aspects (like argument parsing) are not present in this specific file.
这是 `go/src/cmd/internal/obj/arm64/asm7.go` 文件的第六部分，主要负责将 Go 汇编语言的指令编码成 ARM64 机器码。它包含了多种指令类型的编码逻辑，并且依赖于之前部分定义的常量和数据结构。

**功能归纳：**

这部分 `asm7.go` 的核心功能是 **将 Go 汇编器解析后的中间表示 (`obj.Prog`) 转换为 ARM64 机器码的二进制表示**。它针对不同的 ARM64 指令格式和操作码，实现了相应的编码逻辑。具体来说，它包含了以下几个方面的功能：

1. **处理多种指令类型:**  代码中大量的 `case` 语句表明它支持编码多种 ARM64 指令，包括：
    * **数据处理指令:**  例如算术运算 (ADD, SUB, MUL, DIV)、逻辑运算 (AND, OR, XOR)、位操作 (移位、旋转) 等。
    * **向量指令 (SIMD/NEON):**  以 `V` 开头的指令，例如向量加法 (`VADD`)、向量异或 (`VEOR`) 等。
    * **加载/存储指令:**  从内存加载数据到寄存器 (`LDR`)，或将寄存器数据存储到内存 (`STR`)。
    * **分支指令:**  无条件分支 (`B`)、条件分支 (`BEQ`, `BNE`)、子程序调用 (`BL`)、返回 (`RET`) 等。
    * **原子操作指令:** 例如 `CASP` (比较并交换对)。
    * **系统指令:** 例如缓存维护 (`DC`)、TLB 操作 (`TLBI`) 等。
    * **浮点运算指令:**  例如浮点加法 (`FADD`)、浮点乘法 (`FMUL`)、浮点转换 (`FCVT`) 等。
2. **根据指令格式进行编码:**  不同的 ARM64 指令有不同的编码格式。代码中的 `oprrr`、`opirr`、`opbit` 等函数分别处理不同格式的指令：
    * `oprrr`: 处理寄存器-寄存器-寄存器 (Rm op Rn -> Rd) 类型的指令。
    * `opirr`: 处理立即数-寄存器-寄存器 (imm op Rn -> Rd) 或 立即数 -> Rd 类型的指令。
    * `opbit`: 处理位操作指令。
    * `opxrrr`: 处理带有扩展寄存器的加减指令。
    * `opimm`: 处理带有立即数的指令。
    * `opbra`: 处理分支指令。
    * `opbrr`: 处理寄存器分支指令。
    * `opload`/`opstore`: 处理加载和存储指令的不同变体。
3. **处理操作数:**  代码从 `obj.Prog` 结构体中提取指令的操作数 (寄存器、立即数、内存地址等)，并根据指令格式将其编码到机器码的相应位域中。
4. **处理立即数和偏移量:**  代码会检查立即数和偏移量是否在有效范围内，并将其编码到指令中。对于超出范围的情况，会报告错误。
5. **处理条件码:**  对于条件分支指令，代码会将条件码编码到指令中。
6. **处理向量操作:**  代码支持向量指令的编码，并根据向量寄存器的排布 (`ARNG`) 和数据类型进行处理。
7. **生成机器码:**  最终，每个指令会被编码成一个或多个 32 位的字 (`uint32`)，存储在 `out` 数组中。

**Go 语言功能实现示例 (推理):**

假设我们想实现一个简单的加法指令 `ADD X0, X1, X2` (将 X1 和 X2 的值相加，结果存储到 X0)。根据代码中的 `oprrr` 函数，我们可以推断出其编码过程：

```go
// 假设 p 是表示 ADD X0, X1, X2 的 obj.Prog
p := &obj.Prog{
    As: obj.AADD,
    Reg: REG_X1, // Rn
    From: obj.Addr{Type: obj.TYPE_REG, Reg: REG_X2}, // Rm
    To:   obj.Addr{Type: obj.TYPE_REG, Reg: REG_X0}, // Rd
}

c := &ctxt7{} // 初始化 ctxt7

// 调用 oprrr 函数进行编码
o1 := c.oprrr(p, obj.AADD)

// 假设 REG_X0 = 0, REG_X1 = 1, REG_X2 = 2
// 根据 oprrr 函数中的定义：return S64 | 0<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 0<<21 | 0<<10
// S64 宏定义了 64 位操作相关的位

// 需要设置 Rm, Rn, Rd 的值到 o1 中
rm := int(p.From.Reg) & 31 // 2
rn := int(p.Reg) & 31    // 1
rd := int(p.To.Reg) & 31      // 0

o1 |= uint32(rm) << 16
o1 |= uint32(rn) << 5
o1 |= uint32(rd)

// 最终的 o1 的值将是 ADD X0, X1, X2 指令的机器码
// 具体的值需要参考 ARM64 指令集手册
fmt.Printf("%08X\n", o1)
```

**假设输入与输出:**

* **输入 (obj.Prog):**  表示 `ADD X0, X1, X2` 指令的 `obj.Prog` 结构体，如上所示。
* **输出 (uint32):**  `ADD X0, X1, X2` 指令的 ARM64 机器码，例如 `0B000010` (十六进制)。  （实际值需要查阅 ARM64 指令集手册精确计算）。

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在更上层的 Go 编译器的入口点，例如 `go/src/cmd/compile/internal/gc/main.go`。  `asm7.go` 只是接收已经解析好的指令中间表示进行编码。

**易犯错的点 (使用者):**

这里的 "使用者" 指的是 Go 汇编语言的开发者。他们容易犯的错误可能包括：

1. **寄存器编号错误:** 使用了不存在的寄存器编号，或者在指令中使用了不允许的寄存器。例如，`CASE 101` 中对寄存器列表的长度进行了校验，如果数量不符合要求，会报错。
2. **立即数超出范围:** 某些指令的立即数有取值范围限制。例如，`oaddi12` 函数会检查立即数是否是 12 位有符号数。
3. **操作数类型不匹配:**  某些向量指令对操作数的排布 (`ARNG`) 有特定的要求。例如，`CASE 102` 中的 `vushll` 指令，会对操作数的排布进行检查。
4. **条件码使用错误:**  条件分支指令使用了错误的条件码。
5. **内存寻址方式错误:**  加载/存储指令使用了不支持的内存寻址方式。

**示例 (易犯错的点):**

假设用户想使用 `vushll` 指令，将一个 8 字节的向量左移一个量并放入一个 16 字节的向量中，可能会错误地使用不匹配的向量排布：

```assembly
// 错误示例
VUSHL.8H V0.B, V1.B, #3  // 尝试将 V1 的 8 个字节左移，结果放入 V0 的 8 个半字中 (错误)
```

这段代码 (`CASE 102`) 会检测到 `pack(0, ARNG_8B, ARNG_8H)` 的情况，并根据预定义的允许的排布组合进行校验。如果排布不匹配，会调用 `c.ctxt.Diag` 报告错误 "operand mismatch"。

**总结 `asm7.go` 的功能 (第 6 部分):**

作为 Go ARM64 汇编器的第六部分，`asm7.go` 的主要职责是 **实现将 Go 汇编语言指令转换为 ARM64 机器码的核心编码逻辑**。它通过一系列函数，针对不同的指令格式和操作码，将指令的操作数、立即数、条件码等信息编码成最终的二进制机器码。这部分代码是连接 Go 汇编器前端 (解析) 和后端 (生成机器码) 的关键环节，确保了 Go 程序能够在 ARM64 架构上正确执行。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/arm64/asm7.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共7部分，请归纳一下它的功能

"""
n = 1 // two register
		case 0x6:
			len = 2 // three registers
		case 0x2:
			len = 3 // four registers
		default:
			c.ctxt.Diag("invalid register numbers in ARM64 register list: %v", p)
		}
		var op uint32
		switch p.As {
		case AVTBL:
			op = 0
		case AVTBX:
			op = 1
		}
		o1 = q<<30 | 0xe<<24 | len<<13 | op<<12
		o1 |= (uint32(rf&31) << 16) | uint32(offset&31)<<5 | uint32(rt&31)

	case 102: /* vushll, vushll2, vuxtl, vuxtl2 */
		o1 = c.opirr(p, p.As)
		rf := p.Reg
		af := uint8((p.Reg >> 5) & 15)
		at := uint8((p.To.Reg >> 5) & 15)
		shift := int(p.From.Offset)
		if p.As == AVUXTL || p.As == AVUXTL2 {
			rf = p.From.Reg
			af = uint8((p.From.Reg >> 5) & 15)
			shift = 0
		}

		Q := (o1 >> 30) & 1
		var immh, width uint8
		switch pack(Q, af, at) {
		case pack(0, ARNG_8B, ARNG_8H):
			immh, width = 1, 8
		case pack(1, ARNG_16B, ARNG_8H):
			immh, width = 1, 8
		case pack(0, ARNG_4H, ARNG_4S):
			immh, width = 2, 16
		case pack(1, ARNG_8H, ARNG_4S):
			immh, width = 2, 16
		case pack(0, ARNG_2S, ARNG_2D):
			immh, width = 4, 32
		case pack(1, ARNG_4S, ARNG_2D):
			immh, width = 4, 32
		default:
			c.ctxt.Diag("operand mismatch: %v\n", p)
		}
		if !(0 <= shift && shift <= int(width-1)) {
			c.ctxt.Diag("shift amount out of range: %v\n", p)
		}
		o1 |= uint32(immh)<<19 | uint32(shift)<<16 | uint32(rf&31)<<5 | uint32(p.To.Reg&31)

	case 103: /* VEOR3/VBCAX Va.B16, Vm.B16, Vn.B16, Vd.B16 */
		ta := (p.From.Reg >> 5) & 15
		tm := (p.Reg >> 5) & 15
		td := (p.To.Reg >> 5) & 15
		tn := ((p.GetFrom3().Reg) >> 5) & 15

		if ta != tm || ta != tn || ta != td || ta != ARNG_16B {
			c.ctxt.Diag("invalid arrangement: %v", p)
			break
		}

		o1 = c.oprrr(p, p.As)
		ra := int(p.From.Reg)
		rm := int(p.Reg)
		rn := int(p.GetFrom3().Reg)
		rd := int(p.To.Reg)
		o1 |= uint32(rm&31)<<16 | uint32(ra&31)<<10 | uint32(rn&31)<<5 | uint32(rd)&31

	case 104: /* vxar $imm4, Vm.<T>, Vn.<T>, Vd.<T> */
		af := ((p.GetFrom3().Reg) >> 5) & 15
		at := (p.To.Reg >> 5) & 15
		a := (p.Reg >> 5) & 15
		index := int(p.From.Offset)

		if af != a || af != at {
			c.ctxt.Diag("invalid arrangement: %v", p)
			break
		}

		if af != ARNG_2D {
			c.ctxt.Diag("invalid arrangement, should be D2: %v", p)
			break
		}

		if index < 0 || index > 63 {
			c.ctxt.Diag("illegal offset: %v", p)
		}

		o1 = c.opirr(p, p.As)
		rf := (p.GetFrom3().Reg) & 31
		rt := (p.To.Reg) & 31
		r := (p.Reg) & 31

		o1 |= (uint32(r&31) << 16) | (uint32(index&63) << 10) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 105: /* vuaddw{2} Vm.<Tb>, Vn.<Ta>, Vd.<Ta> */
		af := uint8((p.From.Reg >> 5) & 15)
		at := uint8((p.To.Reg >> 5) & 15)
		a := uint8((p.Reg >> 5) & 15)
		if at != a {
			c.ctxt.Diag("invalid arrangement: %v", p)
			break
		}

		var Q, size uint32
		if p.As == AVUADDW2 {
			Q = 1
		}
		switch pack(Q, at, af) {
		case pack(0, ARNG_8H, ARNG_8B), pack(1, ARNG_8H, ARNG_16B):
			size = 0
		case pack(0, ARNG_4S, ARNG_4H), pack(1, ARNG_4S, ARNG_8H):
			size = 1
		case pack(0, ARNG_2D, ARNG_2S), pack(1, ARNG_2D, ARNG_4S):
			size = 2
		default:
			c.ctxt.Diag("operand mismatch: %v\n", p)
		}

		o1 = c.oprrr(p, p.As)
		rf := int((p.From.Reg) & 31)
		rt := int((p.To.Reg) & 31)
		r := int((p.Reg) & 31)
		o1 |= ((Q & 1) << 30) | ((size & 3) << 22) | (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	case 106: // CASPx (Rs, Rs+1), (Rb), (Rt, Rt+1)
		rs := p.From.Reg
		rt := p.GetTo2().Reg
		rb := p.To.Reg
		rs1 := int16(p.From.Offset)
		rt1 := int16(p.GetTo2().Offset)

		enc, ok := atomicCASP[p.As]
		if !ok {
			c.ctxt.Diag("invalid CASP-like atomic instructions: %v\n", p)
		}
		// for CASPx-like instructions, Rs<0> != 1 && Rt<0> != 1
		switch {
		case rs&1 != 0:
			c.ctxt.Diag("source register pair must start from even register: %v\n", p)
			break
		case rt&1 != 0:
			c.ctxt.Diag("destination register pair must start from even register: %v\n", p)
			break
		case rs != rs1-1:
			c.ctxt.Diag("source register pair must be contiguous: %v\n", p)
			break
		case rt != rt1-1:
			c.ctxt.Diag("destination register pair must be contiguous: %v\n", p)
			break
		}
		// rt can't be sp.
		if rt == REG_RSP {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}
		o1 |= enc | uint32(rs&31)<<16 | uint32(rb&31)<<5 | uint32(rt&31)

	case 107: /* tlbi, dc */
		op, ok := sysInstFields[SpecialOperand(p.From.Offset)]
		if !ok || (p.As == ATLBI && op.cn != 8) || (p.As == ADC && op.cn != 7) {
			c.ctxt.Diag("illegal argument: %v\n", p)
			break
		}
		o1 = c.opirr(p, p.As)
		if op.hasOperand2 {
			if p.To.Reg == obj.REG_NONE {
				c.ctxt.Diag("missing register at operand 2: %v\n", p)
			}
			o1 |= uint32(p.To.Reg & 0x1F)
		} else {
			if p.To.Reg != obj.REG_NONE || p.Reg != obj.REG_NONE {
				c.ctxt.Diag("extraneous register at operand 2: %v\n", p)
			}
			o1 |= uint32(0x1F)
		}
		o1 |= uint32(SYSARG4(int(op.op1), int(op.cn), int(op.cm), int(op.op2)))
	}
	out[0] = o1
	out[1] = o2
	out[2] = o3
	out[3] = o4
	out[4] = o5

	return int(o.size(c.ctxt, p) / 4)
}

func (c *ctxt7) addrRelocType(p *obj.Prog) objabi.RelocType {
	switch movesize(p.As) {
	case 0:
		return objabi.R_ARM64_PCREL_LDST8
	case 1:
		return objabi.R_ARM64_PCREL_LDST16
	case 2:
		return objabi.R_ARM64_PCREL_LDST32
	case 3:
		return objabi.R_ARM64_PCREL_LDST64
	default:
		c.ctxt.Diag("use R_ADDRARM64 relocation type for: %v\n", p)
	}
	return -1
}

/*
 * basic Rm op Rn -> Rd (using shifted register with 0)
 * also op Rn -> Rt
 * also Rm*Rn op Ra -> Rd
 * also Vm op Vn -> Vd
 */
func (c *ctxt7) oprrr(p *obj.Prog, a obj.As) uint32 {
	switch a {
	case AADC:
		return S64 | 0<<30 | 0<<29 | 0xd0<<21 | 0<<10

	case AADCW:
		return S32 | 0<<30 | 0<<29 | 0xd0<<21 | 0<<10

	case AADCS:
		return S64 | 0<<30 | 1<<29 | 0xd0<<21 | 0<<10

	case AADCSW:
		return S32 | 0<<30 | 1<<29 | 0xd0<<21 | 0<<10

	case ANGC, ASBC:
		return S64 | 1<<30 | 0<<29 | 0xd0<<21 | 0<<10

	case ANGCS, ASBCS:
		return S64 | 1<<30 | 1<<29 | 0xd0<<21 | 0<<10

	case ANGCW, ASBCW:
		return S32 | 1<<30 | 0<<29 | 0xd0<<21 | 0<<10

	case ANGCSW, ASBCSW:
		return S32 | 1<<30 | 1<<29 | 0xd0<<21 | 0<<10

	case AADD:
		return S64 | 0<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 0<<21 | 0<<10

	case AADDW:
		return S32 | 0<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 0<<21 | 0<<10

	case ACMN, AADDS:
		return S64 | 0<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 0<<21 | 0<<10

	case ACMNW, AADDSW:
		return S32 | 0<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 0<<21 | 0<<10

	case ASUB:
		return S64 | 1<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 0<<21 | 0<<10

	case ASUBW:
		return S32 | 1<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 0<<21 | 0<<10

	case ACMP, ASUBS:
		return S64 | 1<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 0<<21 | 0<<10

	case ACMPW, ASUBSW:
		return S32 | 1<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 0<<21 | 0<<10

	case AAND:
		return S64 | 0<<29 | 0xA<<24

	case AANDW:
		return S32 | 0<<29 | 0xA<<24

	case AMOVD, AORR:
		return S64 | 1<<29 | 0xA<<24

		//	case AMOVW:
	case AMOVWU, AORRW:
		return S32 | 1<<29 | 0xA<<24

	case AEOR:
		return S64 | 2<<29 | 0xA<<24

	case AEORW:
		return S32 | 2<<29 | 0xA<<24

	case AANDS, ATST:
		return S64 | 3<<29 | 0xA<<24

	case AANDSW, ATSTW:
		return S32 | 3<<29 | 0xA<<24

	case ABIC:
		return S64 | 0<<29 | 0xA<<24 | 1<<21

	case ABICW:
		return S32 | 0<<29 | 0xA<<24 | 1<<21

	case ABICS:
		return S64 | 3<<29 | 0xA<<24 | 1<<21

	case ABICSW:
		return S32 | 3<<29 | 0xA<<24 | 1<<21

	case AEON:
		return S64 | 2<<29 | 0xA<<24 | 1<<21

	case AEONW:
		return S32 | 2<<29 | 0xA<<24 | 1<<21

	case AMVN, AORN:
		return S64 | 1<<29 | 0xA<<24 | 1<<21

	case AMVNW, AORNW:
		return S32 | 1<<29 | 0xA<<24 | 1<<21

	case AASR:
		return S64 | OPDP2(10) /* also ASRV */

	case AASRW:
		return S32 | OPDP2(10)

	case ALSL:
		return S64 | OPDP2(8)

	case ALSLW:
		return S32 | OPDP2(8)

	case ALSR:
		return S64 | OPDP2(9)

	case ALSRW:
		return S32 | OPDP2(9)

	case AROR:
		return S64 | OPDP2(11)

	case ARORW:
		return S32 | OPDP2(11)

	case ACCMN:
		return S64 | 0<<30 | 1<<29 | 0xD2<<21 | 0<<11 | 0<<10 | 0<<4 /* cond<<12 | nzcv<<0 */

	case ACCMNW:
		return S32 | 0<<30 | 1<<29 | 0xD2<<21 | 0<<11 | 0<<10 | 0<<4

	case ACCMP:
		return S64 | 1<<30 | 1<<29 | 0xD2<<21 | 0<<11 | 0<<10 | 0<<4 /* imm5<<16 | cond<<12 | nzcv<<0 */

	case ACCMPW:
		return S32 | 1<<30 | 1<<29 | 0xD2<<21 | 0<<11 | 0<<10 | 0<<4

	case ACRC32B:
		return S32 | OPDP2(16)

	case ACRC32H:
		return S32 | OPDP2(17)

	case ACRC32W:
		return S32 | OPDP2(18)

	case ACRC32X:
		return S64 | OPDP2(19)

	case ACRC32CB:
		return S32 | OPDP2(20)

	case ACRC32CH:
		return S32 | OPDP2(21)

	case ACRC32CW:
		return S32 | OPDP2(22)

	case ACRC32CX:
		return S64 | OPDP2(23)

	case ACSEL:
		return S64 | 0<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 0<<10

	case ACSELW:
		return S32 | 0<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 0<<10

	case ACSET:
		return S64 | 0<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 1<<10

	case ACSETW:
		return S32 | 0<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 1<<10

	case ACSETM:
		return S64 | 1<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 0<<10

	case ACSETMW:
		return S32 | 1<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 0<<10

	case ACINC, ACSINC:
		return S64 | 0<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 1<<10

	case ACINCW, ACSINCW:
		return S32 | 0<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 1<<10

	case ACINV, ACSINV:
		return S64 | 1<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 0<<10

	case ACINVW, ACSINVW:
		return S32 | 1<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 0<<10

	case ACNEG, ACSNEG:
		return S64 | 1<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 1<<10

	case ACNEGW, ACSNEGW:
		return S32 | 1<<30 | 0<<29 | 0xD4<<21 | 0<<11 | 1<<10

	case AMUL, AMADD:
		return S64 | 0<<29 | 0x1B<<24 | 0<<21 | 0<<15

	case AMULW, AMADDW:
		return S32 | 0<<29 | 0x1B<<24 | 0<<21 | 0<<15

	case AMNEG, AMSUB:
		return S64 | 0<<29 | 0x1B<<24 | 0<<21 | 1<<15

	case AMNEGW, AMSUBW:
		return S32 | 0<<29 | 0x1B<<24 | 0<<21 | 1<<15

	case AMRS:
		return SYSOP(1, 2, 0, 0, 0, 0, 0)

	case AMSR:
		return SYSOP(0, 2, 0, 0, 0, 0, 0)

	case ANEG:
		return S64 | 1<<30 | 0<<29 | 0xB<<24 | 0<<21

	case ANEGW:
		return S32 | 1<<30 | 0<<29 | 0xB<<24 | 0<<21

	case ANEGS:
		return S64 | 1<<30 | 1<<29 | 0xB<<24 | 0<<21

	case ANEGSW:
		return S32 | 1<<30 | 1<<29 | 0xB<<24 | 0<<21

	case AREM, ASDIV:
		return S64 | OPDP2(3)

	case AREMW, ASDIVW:
		return S32 | OPDP2(3)

	case ASMULL, ASMADDL:
		return OPDP3(1, 0, 1, 0)

	case ASMNEGL, ASMSUBL:
		return OPDP3(1, 0, 1, 1)

	case ASMULH:
		return OPDP3(1, 0, 2, 0)

	case AUMULL, AUMADDL:
		return OPDP3(1, 0, 5, 0)

	case AUMNEGL, AUMSUBL:
		return OPDP3(1, 0, 5, 1)

	case AUMULH:
		return OPDP3(1, 0, 6, 0)

	case AUREM, AUDIV:
		return S64 | OPDP2(2)

	case AUREMW, AUDIVW:
		return S32 | OPDP2(2)

	case AAESE:
		return 0x4E<<24 | 2<<20 | 8<<16 | 4<<12 | 2<<10

	case AAESD:
		return 0x4E<<24 | 2<<20 | 8<<16 | 5<<12 | 2<<10

	case AAESMC:
		return 0x4E<<24 | 2<<20 | 8<<16 | 6<<12 | 2<<10

	case AAESIMC:
		return 0x4E<<24 | 2<<20 | 8<<16 | 7<<12 | 2<<10

	case ASHA1C:
		return 0x5E<<24 | 0<<12

	case ASHA1P:
		return 0x5E<<24 | 1<<12

	case ASHA1M:
		return 0x5E<<24 | 2<<12

	case ASHA1SU0:
		return 0x5E<<24 | 3<<12

	case ASHA256H:
		return 0x5E<<24 | 4<<12

	case ASHA256H2:
		return 0x5E<<24 | 5<<12

	case ASHA256SU1:
		return 0x5E<<24 | 6<<12

	case ASHA1H:
		return 0x5E<<24 | 2<<20 | 8<<16 | 0<<12 | 2<<10

	case ASHA1SU1:
		return 0x5E<<24 | 2<<20 | 8<<16 | 1<<12 | 2<<10

	case ASHA256SU0:
		return 0x5E<<24 | 2<<20 | 8<<16 | 2<<12 | 2<<10

	case ASHA512H:
		return 0xCE<<24 | 3<<21 | 8<<12

	case ASHA512H2:
		return 0xCE<<24 | 3<<21 | 8<<12 | 4<<8

	case ASHA512SU1:
		return 0xCE<<24 | 3<<21 | 8<<12 | 8<<8

	case ASHA512SU0:
		return 0xCE<<24 | 3<<22 | 8<<12

	case AFCVTZSD:
		return FPCVTI(1, 0, 1, 3, 0)

	case AFCVTZSDW:
		return FPCVTI(0, 0, 1, 3, 0)

	case AFCVTZSS:
		return FPCVTI(1, 0, 0, 3, 0)

	case AFCVTZSSW:
		return FPCVTI(0, 0, 0, 3, 0)

	case AFCVTZUD:
		return FPCVTI(1, 0, 1, 3, 1)

	case AFCVTZUDW:
		return FPCVTI(0, 0, 1, 3, 1)

	case AFCVTZUS:
		return FPCVTI(1, 0, 0, 3, 1)

	case AFCVTZUSW:
		return FPCVTI(0, 0, 0, 3, 1)

	case ASCVTFD:
		return FPCVTI(1, 0, 1, 0, 2)

	case ASCVTFS:
		return FPCVTI(1, 0, 0, 0, 2)

	case ASCVTFWD:
		return FPCVTI(0, 0, 1, 0, 2)

	case ASCVTFWS:
		return FPCVTI(0, 0, 0, 0, 2)

	case AUCVTFD:
		return FPCVTI(1, 0, 1, 0, 3)

	case AUCVTFS:
		return FPCVTI(1, 0, 0, 0, 3)

	case AUCVTFWD:
		return FPCVTI(0, 0, 1, 0, 3)

	case AUCVTFWS:
		return FPCVTI(0, 0, 0, 0, 3)

	case AFADDS:
		return FPOP2S(0, 0, 0, 2)

	case AFADDD:
		return FPOP2S(0, 0, 1, 2)

	case AFSUBS:
		return FPOP2S(0, 0, 0, 3)

	case AFSUBD:
		return FPOP2S(0, 0, 1, 3)

	case AFMADDD:
		return FPOP3S(0, 0, 1, 0, 0)

	case AFMADDS:
		return FPOP3S(0, 0, 0, 0, 0)

	case AFMSUBD:
		return FPOP3S(0, 0, 1, 0, 1)

	case AFMSUBS:
		return FPOP3S(0, 0, 0, 0, 1)

	case AFNMADDD:
		return FPOP3S(0, 0, 1, 1, 0)

	case AFNMADDS:
		return FPOP3S(0, 0, 0, 1, 0)

	case AFNMSUBD:
		return FPOP3S(0, 0, 1, 1, 1)

	case AFNMSUBS:
		return FPOP3S(0, 0, 0, 1, 1)

	case AFMULS:
		return FPOP2S(0, 0, 0, 0)

	case AFMULD:
		return FPOP2S(0, 0, 1, 0)

	case AFDIVS:
		return FPOP2S(0, 0, 0, 1)

	case AFDIVD:
		return FPOP2S(0, 0, 1, 1)

	case AFMAXS:
		return FPOP2S(0, 0, 0, 4)

	case AFMINS:
		return FPOP2S(0, 0, 0, 5)

	case AFMAXD:
		return FPOP2S(0, 0, 1, 4)

	case AFMIND:
		return FPOP2S(0, 0, 1, 5)

	case AFMAXNMS:
		return FPOP2S(0, 0, 0, 6)

	case AFMAXNMD:
		return FPOP2S(0, 0, 1, 6)

	case AFMINNMS:
		return FPOP2S(0, 0, 0, 7)

	case AFMINNMD:
		return FPOP2S(0, 0, 1, 7)

	case AFNMULS:
		return FPOP2S(0, 0, 0, 8)

	case AFNMULD:
		return FPOP2S(0, 0, 1, 8)

	case AFCMPS:
		return FPCMP(0, 0, 0, 0, 0)

	case AFCMPD:
		return FPCMP(0, 0, 1, 0, 0)

	case AFCMPES:
		return FPCMP(0, 0, 0, 0, 16)

	case AFCMPED:
		return FPCMP(0, 0, 1, 0, 16)

	case AFCCMPS:
		return FPCCMP(0, 0, 0, 0)

	case AFCCMPD:
		return FPCCMP(0, 0, 1, 0)

	case AFCCMPES:
		return FPCCMP(0, 0, 0, 1)

	case AFCCMPED:
		return FPCCMP(0, 0, 1, 1)

	case AFCSELS:
		return 0x1E<<24 | 0<<22 | 1<<21 | 3<<10

	case AFCSELD:
		return 0x1E<<24 | 1<<22 | 1<<21 | 3<<10

	case AFMOVS:
		return FPOP1S(0, 0, 0, 0)

	case AFABSS:
		return FPOP1S(0, 0, 0, 1)

	case AFNEGS:
		return FPOP1S(0, 0, 0, 2)

	case AFSQRTS:
		return FPOP1S(0, 0, 0, 3)

	case AFCVTSD:
		return FPOP1S(0, 0, 0, 5)

	case AFCVTSH:
		return FPOP1S(0, 0, 0, 7)

	case AFRINTNS:
		return FPOP1S(0, 0, 0, 8)

	case AFRINTPS:
		return FPOP1S(0, 0, 0, 9)

	case AFRINTMS:
		return FPOP1S(0, 0, 0, 10)

	case AFRINTZS:
		return FPOP1S(0, 0, 0, 11)

	case AFRINTAS:
		return FPOP1S(0, 0, 0, 12)

	case AFRINTXS:
		return FPOP1S(0, 0, 0, 14)

	case AFRINTIS:
		return FPOP1S(0, 0, 0, 15)

	case AFMOVD:
		return FPOP1S(0, 0, 1, 0)

	case AFABSD:
		return FPOP1S(0, 0, 1, 1)

	case AFNEGD:
		return FPOP1S(0, 0, 1, 2)

	case AFSQRTD:
		return FPOP1S(0, 0, 1, 3)

	case AFCVTDS:
		return FPOP1S(0, 0, 1, 4)

	case AFCVTDH:
		return FPOP1S(0, 0, 1, 7)

	case AFRINTND:
		return FPOP1S(0, 0, 1, 8)

	case AFRINTPD:
		return FPOP1S(0, 0, 1, 9)

	case AFRINTMD:
		return FPOP1S(0, 0, 1, 10)

	case AFRINTZD:
		return FPOP1S(0, 0, 1, 11)

	case AFRINTAD:
		return FPOP1S(0, 0, 1, 12)

	case AFRINTXD:
		return FPOP1S(0, 0, 1, 14)

	case AFRINTID:
		return FPOP1S(0, 0, 1, 15)

	case AFCVTHS:
		return FPOP1S(0, 0, 3, 4)

	case AFCVTHD:
		return FPOP1S(0, 0, 3, 5)

	case AVADD:
		return 7<<25 | 1<<21 | 1<<15 | 1<<10

	case AVSUB:
		return 0x17<<25 | 1<<21 | 1<<15 | 1<<10

	case AVADDP:
		return 7<<25 | 1<<21 | 1<<15 | 15<<10

	case AVAND:
		return 7<<25 | 1<<21 | 7<<10

	case AVBCAX:
		return 0xCE<<24 | 1<<21

	case AVCMEQ:
		return 1<<29 | 0x71<<21 | 0x23<<10

	case AVCNT:
		return 0xE<<24 | 0x10<<17 | 5<<12 | 2<<10

	case AVZIP1:
		return 0xE<<24 | 3<<12 | 2<<10

	case AVZIP2:
		return 0xE<<24 | 1<<14 | 3<<12 | 2<<10

	case AVEOR:
		return 1<<29 | 0x71<<21 | 7<<10

	case AVEOR3:
		return 0xCE << 24

	case AVORR:
		return 7<<25 | 5<<21 | 7<<10

	case AVREV16:
		return 3<<26 | 2<<24 | 1<<21 | 3<<11

	case AVRAX1:
		return 0xCE<<24 | 3<<21 | 1<<15 | 3<<10

	case AVREV32:
		return 11<<26 | 2<<24 | 1<<21 | 1<<11

	case AVREV64:
		return 3<<26 | 2<<24 | 1<<21 | 1<<11

	case AVMOV:
		return 7<<25 | 5<<21 | 7<<10

	case AVADDV:
		return 7<<25 | 3<<20 | 3<<15 | 7<<11

	case AVUADDLV:
		return 1<<29 | 7<<25 | 3<<20 | 7<<11

	case AVFMLA:
		return 7<<25 | 0<<23 | 1<<21 | 3<<14 | 3<<10

	case AVFMLS:
		return 7<<25 | 1<<23 | 1<<21 | 3<<14 | 3<<10

	case AVPMULL, AVPMULL2:
		return 0xE<<24 | 1<<21 | 0x38<<10

	case AVRBIT:
		return 0x2E<<24 | 1<<22 | 0x10<<17 | 5<<12 | 2<<10

	case AVLD1, AVLD2, AVLD3, AVLD4:
		return 3<<26 | 1<<22

	case AVLD1R, AVLD3R:
		return 0xD<<24 | 1<<22

	case AVLD2R, AVLD4R:
		return 0xD<<24 | 3<<21

	case AVBIF:
		return 1<<29 | 7<<25 | 7<<21 | 7<<10

	case AVBIT:
		return 1<<29 | 0x75<<21 | 7<<10

	case AVBSL:
		return 1<<29 | 0x73<<21 | 7<<10

	case AVCMTST:
		return 0xE<<24 | 1<<21 | 0x23<<10

	case AVUMAX:
		return 1<<29 | 7<<25 | 1<<21 | 0x19<<10

	case AVUMIN:
		return 1<<29 | 7<<25 | 1<<21 | 0x1b<<10

	case AVUZP1:
		return 7<<25 | 3<<11

	case AVUZP2:
		return 7<<25 | 1<<14 | 3<<11

	case AVUADDW, AVUADDW2:
		return 0x17<<25 | 1<<21 | 1<<12

	case AVTRN1:
		return 7<<25 | 5<<11

	case AVTRN2:
		return 7<<25 | 1<<14 | 5<<11
	}

	c.ctxt.Diag("%v: bad rrr %d %v", p, a, a)
	return 0
}

/*
 * imm -> Rd
 * imm op Rn -> Rd
 */
func (c *ctxt7) opirr(p *obj.Prog, a obj.As) uint32 {
	switch a {
	/* op $addcon, Rn, Rd */
	case AMOVD, AADD:
		return S64 | 0<<30 | 0<<29 | 0x11<<24

	case ACMN, AADDS:
		return S64 | 0<<30 | 1<<29 | 0x11<<24

	case AMOVW, AADDW:
		return S32 | 0<<30 | 0<<29 | 0x11<<24

	case ACMNW, AADDSW:
		return S32 | 0<<30 | 1<<29 | 0x11<<24

	case ASUB:
		return S64 | 1<<30 | 0<<29 | 0x11<<24

	case ACMP, ASUBS:
		return S64 | 1<<30 | 1<<29 | 0x11<<24

	case ASUBW:
		return S32 | 1<<30 | 0<<29 | 0x11<<24

	case ACMPW, ASUBSW:
		return S32 | 1<<30 | 1<<29 | 0x11<<24

		/* op $imm(SB), Rd; op label, Rd */
	case AADR:
		return 0<<31 | 0x10<<24

	case AADRP:
		return 1<<31 | 0x10<<24

		/* op $bimm, Rn, Rd */
	case AAND, ABIC:
		return S64 | 0<<29 | 0x24<<23

	case AANDW, ABICW:
		return S32 | 0<<29 | 0x24<<23 | 0<<22

	case AORR, AORN:
		return S64 | 1<<29 | 0x24<<23

	case AORRW, AORNW:
		return S32 | 1<<29 | 0x24<<23 | 0<<22

	case AEOR, AEON:
		return S64 | 2<<29 | 0x24<<23

	case AEORW, AEONW:
		return S32 | 2<<29 | 0x24<<23 | 0<<22

	case AANDS, ABICS, ATST:
		return S64 | 3<<29 | 0x24<<23

	case AANDSW, ABICSW, ATSTW:
		return S32 | 3<<29 | 0x24<<23 | 0<<22

	case AASR:
		return S64 | 0<<29 | 0x26<<23 /* alias of SBFM */

	case AASRW:
		return S32 | 0<<29 | 0x26<<23 | 0<<22

		/* op $width, $lsb, Rn, Rd */
	case ABFI:
		return S64 | 2<<29 | 0x26<<23 | 1<<22
		/* alias of BFM */

	case ABFIW:
		return S32 | 2<<29 | 0x26<<23 | 0<<22

		/* op $imms, $immr, Rn, Rd */
	case ABFM:
		return S64 | 1<<29 | 0x26<<23 | 1<<22

	case ABFMW:
		return S32 | 1<<29 | 0x26<<23 | 0<<22

	case ASBFM:
		return S64 | 0<<29 | 0x26<<23 | 1<<22

	case ASBFMW:
		return S32 | 0<<29 | 0x26<<23 | 0<<22

	case AUBFM:
		return S64 | 2<<29 | 0x26<<23 | 1<<22

	case AUBFMW:
		return S32 | 2<<29 | 0x26<<23 | 0<<22

	case ABFXIL:
		return S64 | 1<<29 | 0x26<<23 | 1<<22 /* alias of BFM */

	case ABFXILW:
		return S32 | 1<<29 | 0x26<<23 | 0<<22

	case AEXTR:
		return S64 | 0<<29 | 0x27<<23 | 1<<22 | 0<<21

	case AEXTRW:
		return S32 | 0<<29 | 0x27<<23 | 0<<22 | 0<<21

	case ACBNZ:
		return S64 | 0x1A<<25 | 1<<24

	case ACBNZW:
		return S32 | 0x1A<<25 | 1<<24

	case ACBZ:
		return S64 | 0x1A<<25 | 0<<24

	case ACBZW:
		return S32 | 0x1A<<25 | 0<<24

	case ACCMN:
		return S64 | 0<<30 | 1<<29 | 0xD2<<21 | 1<<11 | 0<<10 | 0<<4 /* imm5<<16 | cond<<12 | nzcv<<0 */

	case ACCMNW:
		return S32 | 0<<30 | 1<<29 | 0xD2<<21 | 1<<11 | 0<<10 | 0<<4

	case ACCMP:
		return S64 | 1<<30 | 1<<29 | 0xD2<<21 | 1<<11 | 0<<10 | 0<<4 /* imm5<<16 | cond<<12 | nzcv<<0 */

	case ACCMPW:
		return S32 | 1<<30 | 1<<29 | 0xD2<<21 | 1<<11 | 0<<10 | 0<<4

	case AMOVK:
		return S64 | 3<<29 | 0x25<<23

	case AMOVKW:
		return S32 | 3<<29 | 0x25<<23

	case AMOVN:
		return S64 | 0<<29 | 0x25<<23

	case AMOVNW:
		return S32 | 0<<29 | 0x25<<23

	case AMOVZ:
		return S64 | 2<<29 | 0x25<<23

	case AMOVZW:
		return S32 | 2<<29 | 0x25<<23

	case AMSR:
		return SYSOP(0, 0, 0, 4, 0, 0, 0x1F) /* MSR (immediate) */

	case AAT,
		ADC,
		AIC,
		ATLBI,
		ASYS:
		return SYSOP(0, 1, 0, 0, 0, 0, 0)

	case ASYSL:
		return SYSOP(1, 1, 0, 0, 0, 0, 0)

	case ATBZ:
		return 0x36 << 24

	case ATBNZ:
		return 0x37 << 24

	case ADSB:
		return SYSOP(0, 0, 3, 3, 0, 4, 0x1F)

	case ADMB:
		return SYSOP(0, 0, 3, 3, 0, 5, 0x1F)

	case AISB:
		return SYSOP(0, 0, 3, 3, 0, 6, 0x1F)

	case AHINT:
		return SYSOP(0, 0, 3, 2, 0, 0, 0x1F)

	case AVEXT:
		return 0x2E<<24 | 0<<23 | 0<<21 | 0<<15

	case AVUSHR:
		return 0x5E<<23 | 1<<10

	case AVSHL:
		return 0x1E<<23 | 21<<10

	case AVSRI:
		return 0x5E<<23 | 17<<10

	case AVSLI:
		return 0x5E<<23 | 21<<10

	case AVUSHLL, AVUXTL:
		return 1<<29 | 15<<24 | 0x29<<10

	case AVUSHLL2, AVUXTL2:
		return 3<<29 | 15<<24 | 0x29<<10

	case AVXAR:
		return 0xCE<<24 | 1<<23

	case AVUSRA:
		return 1<<29 | 15<<24 | 5<<10

	case APRFM:
		return 0xf9<<24 | 2<<22
	}

	c.ctxt.Diag("%v: bad irr %v", p, a)
	return 0
}

func (c *ctxt7) opbit(p *obj.Prog, a obj.As) uint32 {
	switch a {
	case ACLS:
		return S64 | OPBIT(5)

	case ACLSW:
		return S32 | OPBIT(5)

	case ACLZ:
		return S64 | OPBIT(4)

	case ACLZW:
		return S32 | OPBIT(4)

	case ARBIT:
		return S64 | OPBIT(0)

	case ARBITW:
		return S32 | OPBIT(0)

	case AREV:
		return S64 | OPBIT(3)

	case AREVW:
		return S32 | OPBIT(2)

	case AREV16:
		return S64 | OPBIT(1)

	case AREV16W:
		return S32 | OPBIT(1)

	case AREV32:
		return S64 | OPBIT(2)

	default:
		c.ctxt.Diag("bad bit op\n%v", p)
		return 0
	}
}

/*
 * add/subtract sign or zero-extended register
 */
func (c *ctxt7) opxrrr(p *obj.Prog, a obj.As, rd, rn, rm int16, extend bool) uint32 {
	extension := uint32(0)
	if !extend {
		if isADDop(a) {
			extension = LSL0_64
		}
		if isADDWop(a) {
			extension = LSL0_32
		}
	}

	var op uint32

	switch a {
	case AADD:
		op = S64 | 0<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 1<<21 | extension

	case AADDW:
		op = S32 | 0<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 1<<21 | extension

	case ACMN, AADDS:
		op = S64 | 0<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 1<<21 | extension

	case ACMNW, AADDSW:
		op = S32 | 0<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 1<<21 | extension

	case ASUB:
		op = S64 | 1<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 1<<21 | extension

	case ASUBW:
		op = S32 | 1<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 1<<21 | extension

	case ACMP, ASUBS:
		op = S64 | 1<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 1<<21 | extension

	case ACMPW, ASUBSW:
		op = S32 | 1<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 1<<21 | extension

	default:
		c.ctxt.Diag("bad opxrrr %v\n%v", a, p)
		return 0
	}

	op |= uint32(rm&0x1f)<<16 | uint32(rn&0x1f)<<5 | uint32(rd&0x1f)

	return op
}

func (c *ctxt7) opimm(p *obj.Prog, a obj.As) uint32 {
	switch a {
	case ASVC:
		return 0xD4<<24 | 0<<21 | 1 /* imm16<<5 */

	case AHVC:
		return 0xD4<<24 | 0<<21 | 2

	case ASMC:
		return 0xD4<<24 | 0<<21 | 3

	case ABRK:
		return 0xD4<<24 | 1<<21 | 0

	case AHLT:
		return 0xD4<<24 | 2<<21 | 0

	case ADCPS1:
		return 0xD4<<24 | 5<<21 | 1

	case ADCPS2:
		return 0xD4<<24 | 5<<21 | 2

	case ADCPS3:
		return 0xD4<<24 | 5<<21 | 3

	case ACLREX:
		return SYSOP(0, 0, 3, 3, 0, 2, 0x1F)
	}

	c.ctxt.Diag("%v: bad imm %v", p, a)
	return 0
}

func (c *ctxt7) brdist(p *obj.Prog, preshift int, flen int, shift int) int64 {
	v := int64(0)
	t := int64(0)
	var q *obj.Prog
	if p.To.Type == obj.TYPE_BRANCH {
		q = p.To.Target()
	} else if p.From.Type == obj.TYPE_BRANCH { // adr, adrp
		q = p.From.Target()
	}
	if q == nil {
		// TODO: don't use brdist for this case, as it isn't a branch.
		// (Calls from omovlit, and maybe adr/adrp opcodes as well.)
		q = p.Pool
	}
	if q != nil {
		v = (q.Pc >> uint(preshift)) - (c.pc >> uint(preshift))
		if (v & ((1 << uint(shift)) - 1)) != 0 {
			c.ctxt.Diag("misaligned label\n%v", p)
		}
		v >>= uint(shift)
		t = int64(1) << uint(flen-1)
		if v < -t || v >= t {
			c.ctxt.Diag("branch too far %#x vs %#x [%p]\n%v\n%v", v, t, c.blitrl, p, q)
			panic("branch too far")
		}
	}

	return v & ((t << 1) - 1)
}

/*
 * pc-relative branches
 */
func (c *ctxt7) opbra(p *obj.Prog, a obj.As) uint32 {
	switch a {
	case ABEQ:
		return OPBcc(0x0)

	case ABNE:
		return OPBcc(0x1)

	case ABCS:
		return OPBcc(0x2)

	case ABHS:
		return OPBcc(0x2)

	case ABCC:
		return OPBcc(0x3)

	case ABLO:
		return OPBcc(0x3)

	case ABMI:
		return OPBcc(0x4)

	case ABPL:
		return OPBcc(0x5)

	case ABVS:
		return OPBcc(0x6)

	case ABVC:
		return OPBcc(0x7)

	case ABHI:
		return OPBcc(0x8)

	case ABLS:
		return OPBcc(0x9)

	case ABGE:
		return OPBcc(0xa)

	case ABLT:
		return OPBcc(0xb)

	case ABGT:
		return OPBcc(0xc)

	case ABLE:
		return OPBcc(0xd) /* imm19<<5 | cond */

	case AB:
		return 0<<31 | 5<<26 /* imm26 */

	case obj.ADUFFZERO, obj.ADUFFCOPY, ABL:
		return 1<<31 | 5<<26
	}

	c.ctxt.Diag("%v: bad bra %v", p, a)
	return 0
}

func (c *ctxt7) opbrr(p *obj.Prog, a obj.As) uint32 {
	switch a {
	case ABL:
		return OPBLR(1) /* BLR */

	case AB:
		return OPBLR(0) /* BR */

	case obj.ARET:
		return OPBLR(2) /* RET */
	}

	c.ctxt.Diag("%v: bad brr %v", p, a)
	return 0
}

func (c *ctxt7) op0(p *obj.Prog, a obj.As) uint32 {
	switch a {
	case ADRPS:
		return 0x6B<<25 | 5<<21 | 0x1F<<16 | 0x1F<<5

	case AERET:
		return 0x6B<<25 | 4<<21 | 0x1F<<16 | 0<<10 | 0x1F<<5

	case ANOOP:
		return SYSHINT(0)

	case AYIELD:
		return SYSHINT(1)

	case AWFE:
		return SYSHINT(2)

	case AWFI:
		return SYSHINT(3)

	case ASEV:
		return SYSHINT(4)

	case ASEVL:
		return SYSHINT(5)
	}

	c.ctxt.Diag("%v: bad op0 %v", p, a)
	return 0
}

/*
 * register offset
 */
func (c *ctxt7) opload(p *obj.Prog, a obj.As) uint32 {
	switch a {
	case ALDAR:
		return LDSTX(3, 1, 1, 0, 1) | 0x1F<<10

	case ALDARW:
		return LDSTX(2, 1, 1, 0, 1) | 0x1F<<10

	case ALDARB:
		return LDSTX(0, 1, 1, 0, 1) | 0x1F<<10

	case ALDARH:
		return LDSTX(1, 1, 1, 0, 1) | 0x1F<<10

	case ALDAXP:
		return LDSTX(3, 0, 1, 1, 1)

	case ALDAXPW:
		return LDSTX(2, 0, 1, 1, 1)

	case ALDAXR:
		return LDSTX(3, 0, 1, 0, 1) | 0x1F<<10

	case ALDAXRW:
		return LDSTX(2, 0, 1, 0, 1) | 0x1F<<10

	case ALDAXRB:
		return LDSTX(0, 0, 1, 0, 1) | 0x1F<<10

	case ALDAXRH:
		return LDSTX(1, 0, 1, 0, 1) | 0x1F<<10

	case ALDXR:
		return LDSTX(3, 0, 1, 0, 0) | 0x1F<<10

	case ALDXRB:
		return LDSTX(0, 0, 1, 0, 0) | 0x1F<<10

	case ALDXRH:
		return LDSTX(1, 0, 1, 0, 0) | 0x1F<<10

	case ALDXRW:
		return LDSTX(2, 0, 1, 0, 0) | 0x1F<<10

	case ALDXP:
		return LDSTX(3, 0, 1, 1, 0)

	case ALDXPW:
		return LDSTX(2, 0, 1, 1, 0)
	}

	c.ctxt.Diag("bad opload %v\n%v", a, p)
	return 0
}

func (c *ctxt7) opstore(p *obj.Prog, a obj.As) uint32 {
	switch a {
	case ASTLR:
		return LDSTX(3, 1, 0, 0, 1) | 0x1F<<10

	case ASTLRB:
		return LDSTX(0, 1, 0, 0, 1) | 0x1F<<10

	case ASTLRH:
		return LDSTX(1, 1, 0, 0, 1) | 0x1F<<10

	case ASTLRW:
		return LDSTX(2, 1, 0, 0, 1) | 0x1F<<10

	case ASTLXP:
		return LDSTX(3, 0, 0, 1, 1)

	case ASTLXPW:
		return LDSTX(2, 0, 0, 1, 1)

	case ASTLXR:
		return LDSTX(3, 0, 0, 0, 1) | 0x1F<<10

	case ASTLXRB:
		return LDSTX(0, 0, 0, 0, 1) | 0x1F<<10

	case ASTLXRH:
		return LDSTX(1, 0, 0, 0, 1) | 0x1F<<10

	case ASTLXRW:
		return LDSTX(2, 0, 0, 0, 1) | 0x1F<<10

	case ASTXR:
		return LDSTX(3, 0, 0, 0, 0) | 0x1F<<10

	case ASTXRB:
		return LDSTX(0, 0, 0, 0, 0) | 0x1F<<10

	case ASTXRH:
		return LDSTX(1, 0, 0, 0, 0) | 0x1F<<10

	case ASTXP:
		return LDSTX(3, 0, 0, 1, 0)

	case ASTXPW:
		return LDSTX(2, 0, 0, 1, 0)

	case ASTXRW:
		return LDSTX(2, 0, 0, 0, 0) | 0x1F<<10
	}

	c.ctxt.Diag("bad opstore %v\n%v", a, p)
	return 0
}

/*
 * load/store register (scaled 12-bit unsigned immediate) C3.3.13
 *	these produce 64-bit values (when there's an option)
 */
func (c *ctxt7) olsr12u(p *obj.Prog, o uint32, v int32, rn, rt int16) uint32 {
	if v < 0 || v >= (1<<12) {
		c.ctxt.Diag("offset out of range: %d\n%v", v, p)
	}
	o |= uint32(v&0xFFF) << 10
	o |= uint32(rn&31) << 5
	o |= uint32(rt & 31)
	o |= 1 << 24
	return o
}

/*
 * load/store register (unscaled 9-bit signed immediate) C3.3.12
 */
func (c *ctxt7) olsr9s(p *obj.Prog, o uint32, v int32, rn, rt int16) uint32 {
	if v < -256 || v > 255 {
		c.ctxt.Diag("offset out of range: %d\n%v", v, p)
	}
	o |= uint32((v & 0x1FF) << 12)
	o |= uint32(rn&31) << 5
	o |= uint32(rt & 31)
	return o
}

// store(immediate)
// scaled 12-bit unsigned immediate offset.
// unscaled 9-bit signed immediate offset.
// pre/post-indexed store.
// and the 12-bit and 9-bit are distinguished in olsr12u and oslr9s.
func (c *ctxt7) opstr(p *obj.Prog, a obj.As) uint32 {
	enc := c.opldr(p, a)
	switch p.As {
	case AFMOVQ:
		enc = enc &^ (1 << 22)
	default:
		enc = LD2STR(enc)
	}
	return enc
}

// load(immediate)
// scaled 12-bit unsigned immediate offset.
// unscaled 9-bit signed immediate offset.
// pre/post-indexed load.
// and the 12-bit and 9-bit are distinguished in olsr12u and oslr9s.
func (c *ctxt7) opldr(p *obj.Prog, a obj.As) uint32 {
	switch a {
	case AMOVD:
		return LDSTR(3, 0, 1) /* simm9<<12 | Rn<<5 | Rt */

	case AMOVW:
		return LDSTR(2, 0, 2)

	case AMOVWU:
		return LDSTR(2, 0, 1)

	case AMOVH:
		return LDSTR(1, 0, 2)

	case AMOVHU:
		return LDSTR(1, 0, 1)

	case AMOVB:
		return LDSTR(0, 0, 2)

	case AMOVBU:
		return LDSTR(0, 0, 1)

	case AFMOVS, AVMOVS:
		return LDSTR(2, 1, 1)

	case AFMOVD, AVMOVD:
		return LDSTR(3, 1, 1)

	case AFMOVQ, AVMOVQ:
		return LDSTR(0, 1, 3)
	}

	c.ctxt.Diag("bad opldr %v\n%v", a, p)
	return 0
}

// olsxrr attaches register operands to a load/store opcode supplied in o.
// The result either encodes a load of r from (r1+r2) or a store of r to (r1+r2).
func (c *ctxt7) olsxrr(p *obj.Prog, o int32, r int, r1 int, r2 int) uint32 {
	o |= int32(r1&31) << 5
	o |= int32(r2&31) << 16
	o |= int32(r & 31)
	return uint32(o)
}

// opldrr returns the ARM64 opcode encoding corresponding to the obj.As opcode
// for load instruction with register offset.
// The offset register can be (Rn)(Rm.UXTW<<2) or (Rn)(Rm<<2) or (Rn)(Rm).
func (c *ctxt7) opldrr(p *obj.Prog, a obj.As, extension bool) uint32 {
	OptionS := uint32(0x1a)
	if extension {
		OptionS = uint32(0) // option value and S value have been encoded into p.From.Offset.
	}
	switch a {
	case AMOVD:
		return OptionS<<10 | 0x3<<21 | 0x1f<<27
	case AMOVW:
		return OptionS<<10 | 0x5<<21 | 0x17<<27
	case AMOVWU:
		return OptionS<<10 | 0x3<<21 | 0x17<<27
	case AMOVH:
		return OptionS<<10 | 0x5<<21 | 0x0f<<27
	case AMOVHU:
		return OptionS<<10 | 0x3<<21 | 0x0f<<27
	case AMOVB:
		return OptionS<<10 | 0x5<<21 | 0x07<<27
	case AMOVBU:
		return OptionS<<10 | 0x3<<21 | 0x07<<27
	case AFMOVS:
		return OptionS<<10 | 0x3<<21 | 0x17<<27 | 1<<26
	case AFMOVD:
		return OptionS<<10 | 0x3<<21 | 0x1f<<27 | 1<<26
	}
	c.ctxt.Diag("bad opldrr %v\n%v", a, p)
	return 0
}

// opstrr returns the ARM64 opcode encoding corresponding to the obj.As opcode
// for store instruction with register offset.
// The offset register can be (Rn)(Rm.UXTW<<2) or (Rn)(Rm<<2) or (Rn)(Rm).
func (c *ctxt7) opstrr(p *obj.Prog, a obj.As, extension bool) uint32 {
	OptionS := uint32(0x1a)
	if extension {
		OptionS = uint32(0) // option value and S value have been encoded into p.To.Offset.
	}
	switch a {
	case AMOVD:
		return OptionS<<10 | 0x1<<21 | 0x1f<<27
	case AMOVW, AMOVWU:
		return OptionS<<10 | 0x1<<21 | 0x17<<27
	case AMOVH, AMOVHU:
		return OptionS<<10 | 0x1<<21 | 0x0f<<27
	case AMOVB, AMOVBU:
		return OptionS<<10 | 0x1<<21 | 0x07<<27
	case AFMOVS:
		return OptionS<<10 | 0x1<<21 | 0x17<<27 | 1<<26
	case AFMOVD:
		return OptionS<<10 | 0x1<<21 | 0x1f<<27 | 1<<26
	}
	c.ctxt.Diag("bad opstrr %v\n%v", a, p)
	return 0
}

func (c *ctxt7) oaddi(p *obj.Prog, a obj.As, v int32, rd, rn int16) uint32 {
	op := c.opirr(p, a)

	if (v & 0xFFF000) != 0 {
		if v&0xFFF != 0 {
			c.ctxt.Diag("%v misuses oaddi", p)
		}
		v >>= 12
		op |= 1 << 22
	}

	op |= (uint32(v&0xFFF) << 10) | (uint32(rn&31) << 5) | uint32(rd&31)

	return op
}

func (c *ctxt7) oaddi12(p *obj.Prog, v int32, rd, rn int16) uint32 {
	if v < -4095 || v > 4095 {
		c.ctxt.Diag("%v is not a 12 bit immediate: %v", v, p)
		return 0
	}
	a := AADD
	if v < 0 {
		a = ASUB
		v = -v
	}
	return c.oaddi(p, a, v, rd, rn)
}

/*
 * load a literal value into dr
 */
func (c *ctxt7) omovlit(as obj.As, p *obj.Prog, a *obj.Addr, dr int) uint32 {
	var o1 int32
	if p.Pool == nil { /* not in literal pool */
		c.aclass(a)
		c.ctxt.Logf("omovlit add %d (%#x)\n", c.instoffset, uint64(c.instoffset))

		/* TODO: could be clever, and use general constant builder */
		o1 = int32(c.opirr(p, AADD))

		v := int32(c.instoffset)
		if v != 0 && (v&0xFFF) == 0 {
			v >>= 12
			o1 |= 1 << 22 /* shift, by 12 */
		}

		o1 |= ((v & 0xFFF) << 10) | (REGZERO & 31 << 5) | int32(dr&31)
	} else {
		fp, w := 0, 0
		switch as {
		case AFMOVS, AVMOV
"""




```