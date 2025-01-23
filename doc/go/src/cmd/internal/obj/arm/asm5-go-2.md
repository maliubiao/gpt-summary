Response:
Let's break down the thought process for analyzing the provided Go code snippet from `asm5.go`.

**1. Initial Understanding and Context:**

* **Identify the file:** The path `go/src/cmd/internal/obj/arm/asm5.go` immediately tells us this is part of the Go compiler toolchain, specifically the assembler for the ARM architecture (likely a 32-bit variant based on the `asm5`). The `internal/obj` part signifies it's not intended for direct external use.
* **Recognize the purpose:** Assemblers translate assembly language instructions into machine code. This file likely contains functions that handle the encoding of ARM instructions.
* **Notice the naming conventions:**  Functions like `asmins`, `ctxt5`, `oprrr`, `olr`, etc., are strong indicators of assembler-specific logic. The `ctxt5` likely represents the "context" or state of the assembler during the assembly process.

**2. High-Level Functionality Scan:**

* **Instruction Encoding:** The code is filled with bitwise operations and magic numbers (e.g., `0x1b << 20`, `0xf9f`). These strongly suggest the encoding of different ARM instruction formats. The `case` statements within `asmins` further reinforce this, with each case likely corresponding to a specific instruction or instruction pattern.
* **Operand Handling:**  The code accesses fields like `p.From`, `p.To`, `p.Reg`, `p.From.Reg`, `p.From.Offset`. This indicates it's processing the operands of assembly instructions.
* **Error Checking:**  Calls to `c.ctxt.Diag` suggest the code performs error checking during the assembly process (e.g., "offset must be zero in STREX", "source register must be even in STREXD").
* **Instruction-Specific Logic:** The numerous `case` statements and the variations in bitwise operations within them indicate that different ARM instructions require different encoding schemes.

**3. Deeper Dive into Key Functions (Iterative Process):**

* **`asmins(ctxt *Link, cursym *Symbol, p *Prog)`:** This function seems to be the central dispatcher. It takes a `Prog` (likely representing a single assembly instruction) and uses a `switch` statement based on `p.Optab` to determine how to encode it. This confirms the instruction encoding role.
* **`c.oprrr(p *obj.Prog, a obj.As, sc int) uint32`:** The name suggests "opcode register-register-register."  The bitwise operations and the `switch` statement based on `a` (likely representing the assembly opcode) further point to encoding instructions with register operands. The `sc` parameter probably relates to condition codes or status flags.
* **`c.olr(v int32, b int, r int, sc int) uint32`:**  The name might suggest "opcode load-register" or something similar. The parameters `v` (value/offset), `b` (base register), and `r` (destination register) fit the pattern of load/store instructions. The bit manipulation looks like setting specific bits in the instruction encoding.
* **`c.mov(p *obj.Prog) uint32` and `c.movxt(p *obj.Prog) uint32`:** These likely handle different forms of the `MOV` (move) instruction, potentially with different operand types or extensions.
* **`c.aclass(a *obj.Addr)`:** This function seems to classify the type of operand (immediate, register, memory address, etc.). The `instoffset` suggests it's used to extract immediate values or offsets.

**4. Inferring Go Feature Implementation:**

* **Atomic Operations (STREX/LDREX):** Cases 91 and 92 handle `ALDREXD/B` and `ASTREXD/B`. The "exclusive load/store" terminology is a strong indicator of atomic operations, used for synchronization in concurrent programming.
* **Memory Access (LDR/STR variants):** Cases involving `MOV` with addresses (`movb/movh/movhu addr,R` and `movh/movhu R,addr`) likely correspond to loading and storing data of different sizes (byte, half-word) from memory.
* **Prefetch (PLD):** Case 95 explicitly handles the `PLD` instruction, which is used for prefetching data into the cache to improve performance.
* **Undefined Instruction (UNDEF):** Case 96 implements a deliberate "undefined instruction," useful for debugging or signaling an error state that should never be reached.
* **Bit Manipulation (CLZ, MULW, MULAW, etc.):** Cases 97, 98, and 99 handle instructions like `CLZ` (count leading zeros) and various multiplication instructions, which are common bit manipulation operations.
* **Division (divhw):** Case 105 implements a division instruction.
* **Memory Barriers (DMB):** Case 110 handles `DMB` (Data Memory Barrier), which is crucial for ensuring memory ordering in multi-core systems.

**5. Constructing Go Examples (Hypothetical):**

Based on the identified features, construct illustrative Go code snippets. Since this is low-level assembler code, the Go examples will likely involve operations that map closely to these instructions. For atomics, use `sync/atomic`. For memory access, use pointers and dereferencing. For bit manipulation, use bitwise operators.

**6. Considering Command-Line Arguments (If Applicable):**

Examine the code for any direct interaction with command-line arguments. In this snippet, there's no explicit parsing of command-line arguments. This is expected as this code is part of the assembler itself, which is invoked with assembly source files as input.

**7. Identifying Common Mistakes (Based on Error Messages):**

Look for calls to `c.ctxt.Diag` and analyze the error messages. This provides clues about what mistakes users might make when writing assembly code that this assembler processes (e.g., incorrect offsets for `STREX`, using the same register as source and destination).

**8. Summarizing Functionality (The Final Step):**

Synthesize the findings into a concise summary of the code's role and the Go language features it helps implement. Emphasize the core purpose of instruction encoding and its connection to various low-level operations.

**Self-Correction/Refinement during the process:**

* **Initial Misinterpretations:**  You might initially misinterpret some of the magic numbers or bitwise operations. Double-checking ARM architecture documentation or related assembler code can help clarify their meaning.
* **Overgeneralization:** Avoid making overly broad statements. Focus on the specific instructions and patterns handled in the provided code snippet.
* **Lack of Specificity:** If the code handles a particular variant of an instruction (e.g., a specific addressing mode), mention it.

By following these steps, you can effectively analyze and understand the functionality of the given Go code snippet and its relation to Go language features.
好的，让我们来归纳一下这段 `go/src/cmd/internal/obj/arm/asm5.go` 代码片段的功能，这是第三部分，也是最后一部分。

**核心功能归纳：**

这段代码是 Go 语言 ARM 架构的汇编器实现的一部分，主要负责将 ARM 汇编指令编码成机器码。具体来说，这段代码处理了多种 ARM 指令的编码逻辑，涵盖了数据传输、原子操作、内存屏障、位操作、乘除法运算以及浮点运算等。

**更详细的功能点：**

* **原子操作指令编码 (`LDREXB`, `LDREXD`, `STREXB`, `STREXD`)：**  负责将 ARM 的独占加载和独占存储指令编码成机器码，用于实现并发环境下的原子操作。
* **加载和存储指令编码（`MOV` 变种）：** 处理将内存地址的值加载到寄存器，或者将寄存器的值存储到内存地址的指令编码，包括字节、半字和字的加载和存储，并区分有符号和无符号扩展。
* **预取指令编码 (`PLD`)：**  负责将预取数据指令编码成机器码，用于提高程序执行效率。
* **未定义指令编码 (`UNDEF`)：**  将一个故意触发未定义指令异常的指令编码成机器码，通常用于调试或标记不应到达的代码区域。
* **位操作指令编码 (`CLZ`)：**  负责将计算前导零的指令编码成机器码。
* **乘法指令编码 (`MULW`, `MULAW` 等）：** 处理各种乘法指令的编码，包括 32 位乘法、带累加的乘法等。
* **除法指令编码 (`divhw`)：**  负责将除法指令编码成机器码。
* **内存屏障指令编码 (`DMB`)：**  负责将数据内存屏障指令编码成机器码，用于保证多核处理器系统中内存操作的顺序性。
* **`MOV` 指令的多种变体编码：** 实现了 `MOV` 指令的不同形式的编码，包括立即数移动、寄存器移动以及带移位的移动等。
* **浮点运算指令编码：**  涵盖了单精度和双精度浮点数的加减乘除、绝对值、取反、比较、类型转换等运算指令的编码。
* **条件分支指令编码：** 负责将带有不同条件码的分支指令 (`BEQ`, `BNE`, `BCS` 等) 编码成机器码。
* **加载和存储指令的寻址模式编码：** 处理基址寄存器加偏移量的寻址模式，包括立即数偏移和寄存器偏移。
* **特殊的 `MOV` 指令编码 (`omvs`, `omvr`, `omvl`)：**  针对特定的 `MOV` 指令形式进行了优化或特殊处理，例如加载小立即数、加载取反的立即数以及从文字池加载数据。
* **浮点零值和特定浮点数的快速加载优化：**  尝试将浮点零值和某些特定模式的浮点数直接编码到指令中，以提高效率。

**与之前部分的关系：**

这段代码与之前的部分共同构成了完整的 ARM 汇编器指令编码逻辑。不同的部分可能负责处理不同指令类型或指令格式的编码。例如，可能第一部分处理的是基本的算术和逻辑运算指令，第二部分处理的是跳转和控制流指令，而这第三部分则侧重于原子操作、内存访问、位操作、乘除法以及浮点运算等更复杂的指令。

**总结来说，这段代码是 Go 语言 ARM 汇编器的核心组成部分，负责将高级的汇编指令翻译成底层的机器码，使得程序能够在 ARM 架构的处理器上执行。它涵盖了多种重要的 ARM 指令，并包含了一些针对性能的优化策略。**

### 提示词
```
这是路径为go/src/cmd/internal/obj/arm/asm5.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
= 0x1b << 20
		case ALDREXB:
			o1 = 0x1d << 20
		}
		o1 |= 0xf9f
		o1 |= (uint32(p.From.Reg) & 15) << 16
		o1 |= (uint32(p.To.Reg) & 15) << 12
		o1 |= ((uint32(p.Scond) & C_SCOND) ^ C_SCOND_XOR) << 28

	case 92: /* strexd/strexb reg,oreg,reg */
		c.aclass(&p.From)

		if c.instoffset != 0 {
			c.ctxt.Diag("offset must be zero in STREX")
		}
		if p.To.Reg == p.From.Reg || p.To.Reg == p.Reg || (p.As == ASTREXD && p.To.Reg == p.Reg+1) {
			c.ctxt.Diag("cannot use same register as both source and destination: %v", p)
		}

		switch p.As {
		case ASTREXD:
			if p.Reg&1 != 0 {
				c.ctxt.Diag("source register must be even in STREXD: %v", p)
			}
			o1 = 0x1a << 20
		case ASTREXB:
			o1 = 0x1c << 20
		}
		o1 |= 0xf90
		o1 |= (uint32(p.From.Reg) & 15) << 16
		o1 |= (uint32(p.Reg) & 15) << 0
		o1 |= (uint32(p.To.Reg) & 15) << 12
		o1 |= ((uint32(p.Scond) & C_SCOND) ^ C_SCOND_XOR) << 28

	case 93: /* movb/movh/movhu addr,R -> ldrsb/ldrsh/ldrh */
		o1 = c.omvl(p, &p.From, REGTMP)

		if o1 == 0 {
			break
		}
		o2 = c.olhr(0, REGTMP, int(p.To.Reg), int(p.Scond))
		if p.As == AMOVB || p.As == AMOVBS {
			o2 ^= 1<<5 | 1<<6
		} else if p.As == AMOVH || p.As == AMOVHS {
			o2 ^= (1 << 6)
		}
		if o.flag&LPCREL != 0 {
			o3 = o2
			o2 = c.oprrr(p, AADD, int(p.Scond)) | REGTMP&15 | (REGPC&15)<<16 | (REGTMP&15)<<12
		}

	case 94: /* movh/movhu R,addr -> strh */
		o1 = c.omvl(p, &p.To, REGTMP)

		if o1 == 0 {
			break
		}
		o2 = c.oshr(int(p.From.Reg), 0, REGTMP, int(p.Scond))
		if o.flag&LPCREL != 0 {
			o3 = o2
			o2 = c.oprrr(p, AADD, int(p.Scond)) | REGTMP&15 | (REGPC&15)<<16 | (REGTMP&15)<<12
		}

	case 95: /* PLD off(reg) */
		o1 = 0xf5d0f000

		o1 |= (uint32(p.From.Reg) & 15) << 16
		if p.From.Offset < 0 {
			o1 &^= (1 << 23)
			o1 |= uint32((-p.From.Offset) & 0xfff)
		} else {
			o1 |= uint32(p.From.Offset & 0xfff)
		}

	// This is supposed to be something that stops execution.
	// It's not supposed to be reached, ever, but if it is, we'd
	// like to be able to tell how we got there. Assemble as
	// 0xf7fabcfd which is guaranteed to raise undefined instruction
	// exception.
	case 96: /* UNDEF */
		o1 = 0xf7fabcfd

	case 97: /* CLZ Rm, Rd */
		o1 = c.oprrr(p, p.As, int(p.Scond))

		o1 |= (uint32(p.To.Reg) & 15) << 12
		o1 |= (uint32(p.From.Reg) & 15) << 0

	case 98: /* MULW{T,B} Rs, Rm, Rd */
		o1 = c.oprrr(p, p.As, int(p.Scond))

		o1 |= (uint32(p.To.Reg) & 15) << 16
		o1 |= (uint32(p.From.Reg) & 15) << 8
		o1 |= (uint32(p.Reg) & 15) << 0

	case 99: /* MULAW{T,B} Rs, Rm, Rn, Rd */
		o1 = c.oprrr(p, p.As, int(p.Scond))

		o1 |= (uint32(p.To.Reg) & 15) << 16
		o1 |= (uint32(p.From.Reg) & 15) << 8
		o1 |= (uint32(p.Reg) & 15) << 0
		o1 |= uint32((p.To.Offset & 15) << 12)

	case 105: /* divhw r,[r,]r */
		o1 = c.oprrr(p, p.As, int(p.Scond))
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		r := int(p.Reg)
		if r == 0 {
			r = rt
		}
		o1 |= (uint32(rf)&15)<<8 | (uint32(r)&15)<<0 | (uint32(rt)&15)<<16

	case 110: /* dmb [mbop | $con] */
		o1 = 0xf57ff050
		mbop := uint32(0)

		switch c.aclass(&p.From) {
		case C_SPR:
			for _, f := range mbOp {
				if f.reg == p.From.Reg {
					mbop = f.enc
					break
				}
			}
		case C_RCON:
			for _, f := range mbOp {
				enc := uint32(c.instoffset)
				if f.enc == enc {
					mbop = enc
					break
				}
			}
		case C_NONE:
			mbop = 0xf
		}

		if mbop == 0 {
			c.ctxt.Diag("illegal mb option:\n%v", p)
		}
		o1 |= mbop
	}

	out[0] = o1
	out[1] = o2
	out[2] = o3
	out[3] = o4
	out[4] = o5
	out[5] = o6
}

func (c *ctxt5) movxt(p *obj.Prog) uint32 {
	o1 := ((uint32(p.Scond) & C_SCOND) ^ C_SCOND_XOR) << 28
	switch p.As {
	case AMOVB, AMOVBS:
		o1 |= 0x6af<<16 | 0x7<<4
	case AMOVH, AMOVHS:
		o1 |= 0x6bf<<16 | 0x7<<4
	case AMOVBU:
		o1 |= 0x6ef<<16 | 0x7<<4
	case AMOVHU:
		o1 |= 0x6ff<<16 | 0x7<<4
	default:
		c.ctxt.Diag("illegal combination: %v", p)
	}
	switch p.From.Offset &^ 0xf {
	// only 0/8/16/24 bits rotation is accepted
	case SHIFT_RR, SHIFT_RR | 8<<7, SHIFT_RR | 16<<7, SHIFT_RR | 24<<7:
		o1 |= uint32(p.From.Offset) & 0xc0f
	default:
		c.ctxt.Diag("illegal shift: %v", p)
	}
	o1 |= (uint32(p.To.Reg) & 15) << 12
	return o1
}

func (c *ctxt5) mov(p *obj.Prog) uint32 {
	c.aclass(&p.From)
	o1 := c.oprrr(p, p.As, int(p.Scond))
	o1 |= uint32(p.From.Offset)
	rt := int(p.To.Reg)
	if p.To.Type == obj.TYPE_NONE {
		rt = 0
	}
	r := int(p.Reg)
	if p.As == AMOVW || p.As == AMVN {
		r = 0
	} else if r == 0 {
		r = rt
	}
	o1 |= (uint32(r)&15)<<16 | (uint32(rt)&15)<<12
	return o1
}

func (c *ctxt5) oprrr(p *obj.Prog, a obj.As, sc int) uint32 {
	o := ((uint32(sc) & C_SCOND) ^ C_SCOND_XOR) << 28
	if sc&C_SBIT != 0 {
		o |= 1 << 20
	}
	switch a {
	case ADIVHW:
		return o | 0x71<<20 | 0xf<<12 | 0x1<<4
	case ADIVUHW:
		return o | 0x73<<20 | 0xf<<12 | 0x1<<4
	case AMMUL:
		return o | 0x75<<20 | 0xf<<12 | 0x1<<4
	case AMULS:
		return o | 0x6<<20 | 0x9<<4
	case AMMULA:
		return o | 0x75<<20 | 0x1<<4
	case AMMULS:
		return o | 0x75<<20 | 0xd<<4
	case AMULU, AMUL:
		return o | 0x0<<21 | 0x9<<4
	case AMULA:
		return o | 0x1<<21 | 0x9<<4
	case AMULLU:
		return o | 0x4<<21 | 0x9<<4
	case AMULL:
		return o | 0x6<<21 | 0x9<<4
	case AMULALU:
		return o | 0x5<<21 | 0x9<<4
	case AMULAL:
		return o | 0x7<<21 | 0x9<<4
	case AAND:
		return o | 0x0<<21
	case AEOR:
		return o | 0x1<<21
	case ASUB:
		return o | 0x2<<21
	case ARSB:
		return o | 0x3<<21
	case AADD:
		return o | 0x4<<21
	case AADC:
		return o | 0x5<<21
	case ASBC:
		return o | 0x6<<21
	case ARSC:
		return o | 0x7<<21
	case ATST:
		return o | 0x8<<21 | 1<<20
	case ATEQ:
		return o | 0x9<<21 | 1<<20
	case ACMP:
		return o | 0xa<<21 | 1<<20
	case ACMN:
		return o | 0xb<<21 | 1<<20
	case AORR:
		return o | 0xc<<21

	case AMOVB, AMOVH, AMOVW:
		if sc&(C_PBIT|C_WBIT) != 0 {
			c.ctxt.Diag("invalid .P/.W suffix: %v", p)
		}
		return o | 0xd<<21
	case ABIC:
		return o | 0xe<<21
	case AMVN:
		return o | 0xf<<21
	case ASLL:
		return o | 0xd<<21 | 0<<5
	case ASRL:
		return o | 0xd<<21 | 1<<5
	case ASRA:
		return o | 0xd<<21 | 2<<5
	case ASWI:
		return o | 0xf<<24

	case AADDD:
		return o | 0xe<<24 | 0x3<<20 | 0xb<<8 | 0<<4
	case AADDF:
		return o | 0xe<<24 | 0x3<<20 | 0xa<<8 | 0<<4
	case ASUBD:
		return o | 0xe<<24 | 0x3<<20 | 0xb<<8 | 4<<4
	case ASUBF:
		return o | 0xe<<24 | 0x3<<20 | 0xa<<8 | 4<<4
	case AMULD:
		return o | 0xe<<24 | 0x2<<20 | 0xb<<8 | 0<<4
	case AMULF:
		return o | 0xe<<24 | 0x2<<20 | 0xa<<8 | 0<<4
	case ANMULD:
		return o | 0xe<<24 | 0x2<<20 | 0xb<<8 | 0x4<<4
	case ANMULF:
		return o | 0xe<<24 | 0x2<<20 | 0xa<<8 | 0x4<<4
	case AMULAD:
		return o | 0xe<<24 | 0xb<<8
	case AMULAF:
		return o | 0xe<<24 | 0xa<<8
	case AMULSD:
		return o | 0xe<<24 | 0xb<<8 | 0x4<<4
	case AMULSF:
		return o | 0xe<<24 | 0xa<<8 | 0x4<<4
	case ANMULAD:
		return o | 0xe<<24 | 0x1<<20 | 0xb<<8 | 0x4<<4
	case ANMULAF:
		return o | 0xe<<24 | 0x1<<20 | 0xa<<8 | 0x4<<4
	case ANMULSD:
		return o | 0xe<<24 | 0x1<<20 | 0xb<<8
	case ANMULSF:
		return o | 0xe<<24 | 0x1<<20 | 0xa<<8
	case AFMULAD:
		return o | 0xe<<24 | 0xa<<20 | 0xb<<8
	case AFMULAF:
		return o | 0xe<<24 | 0xa<<20 | 0xa<<8
	case AFMULSD:
		return o | 0xe<<24 | 0xa<<20 | 0xb<<8 | 0x4<<4
	case AFMULSF:
		return o | 0xe<<24 | 0xa<<20 | 0xa<<8 | 0x4<<4
	case AFNMULAD:
		return o | 0xe<<24 | 0x9<<20 | 0xb<<8 | 0x4<<4
	case AFNMULAF:
		return o | 0xe<<24 | 0x9<<20 | 0xa<<8 | 0x4<<4
	case AFNMULSD:
		return o | 0xe<<24 | 0x9<<20 | 0xb<<8
	case AFNMULSF:
		return o | 0xe<<24 | 0x9<<20 | 0xa<<8
	case ADIVD:
		return o | 0xe<<24 | 0x8<<20 | 0xb<<8 | 0<<4
	case ADIVF:
		return o | 0xe<<24 | 0x8<<20 | 0xa<<8 | 0<<4
	case ASQRTD:
		return o | 0xe<<24 | 0xb<<20 | 1<<16 | 0xb<<8 | 0xc<<4
	case ASQRTF:
		return o | 0xe<<24 | 0xb<<20 | 1<<16 | 0xa<<8 | 0xc<<4
	case AABSD:
		return o | 0xe<<24 | 0xb<<20 | 0<<16 | 0xb<<8 | 0xc<<4
	case AABSF:
		return o | 0xe<<24 | 0xb<<20 | 0<<16 | 0xa<<8 | 0xc<<4
	case ANEGD:
		return o | 0xe<<24 | 0xb<<20 | 1<<16 | 0xb<<8 | 0x4<<4
	case ANEGF:
		return o | 0xe<<24 | 0xb<<20 | 1<<16 | 0xa<<8 | 0x4<<4
	case ACMPD:
		return o | 0xe<<24 | 0xb<<20 | 4<<16 | 0xb<<8 | 0xc<<4
	case ACMPF:
		return o | 0xe<<24 | 0xb<<20 | 4<<16 | 0xa<<8 | 0xc<<4

	case AMOVF:
		return o | 0xe<<24 | 0xb<<20 | 0<<16 | 0xa<<8 | 4<<4
	case AMOVD:
		return o | 0xe<<24 | 0xb<<20 | 0<<16 | 0xb<<8 | 4<<4

	case AMOVDF:
		return o | 0xe<<24 | 0xb<<20 | 7<<16 | 0xa<<8 | 0xc<<4 | 1<<8 // dtof
	case AMOVFD:
		return o | 0xe<<24 | 0xb<<20 | 7<<16 | 0xa<<8 | 0xc<<4 | 0<<8 // dtof

	case AMOVWF:
		if sc&C_UBIT == 0 {
			o |= 1 << 7 /* signed */
		}
		return o | 0xe<<24 | 0xb<<20 | 8<<16 | 0xa<<8 | 4<<4 | 0<<18 | 0<<8 // toint, double

	case AMOVWD:
		if sc&C_UBIT == 0 {
			o |= 1 << 7 /* signed */
		}
		return o | 0xe<<24 | 0xb<<20 | 8<<16 | 0xa<<8 | 4<<4 | 0<<18 | 1<<8 // toint, double

	case AMOVFW:
		if sc&C_UBIT == 0 {
			o |= 1 << 16 /* signed */
		}
		return o | 0xe<<24 | 0xb<<20 | 8<<16 | 0xa<<8 | 4<<4 | 1<<18 | 0<<8 | 1<<7 // toint, double, trunc

	case AMOVDW:
		if sc&C_UBIT == 0 {
			o |= 1 << 16 /* signed */
		}
		return o | 0xe<<24 | 0xb<<20 | 8<<16 | 0xa<<8 | 4<<4 | 1<<18 | 1<<8 | 1<<7 // toint, double, trunc

	case -AMOVWF: // copy WtoF
		return o | 0xe<<24 | 0x0<<20 | 0xb<<8 | 1<<4

	case -AMOVFW: // copy FtoW
		return o | 0xe<<24 | 0x1<<20 | 0xb<<8 | 1<<4

	case -ACMP: // cmp imm
		return o | 0x3<<24 | 0x5<<20

	case ABFX:
		return o | 0x3d<<21 | 0x5<<4

	case ABFXU:
		return o | 0x3f<<21 | 0x5<<4

	case ABFC:
		return o | 0x3e<<21 | 0x1f

	case ABFI:
		return o | 0x3e<<21 | 0x1<<4

	case AXTAB:
		return o | 0x6a<<20 | 0x7<<4

	case AXTAH:
		return o | 0x6b<<20 | 0x7<<4

	case AXTABU:
		return o | 0x6e<<20 | 0x7<<4

	case AXTAHU:
		return o | 0x6f<<20 | 0x7<<4

		// CLZ doesn't support .nil
	case ACLZ:
		return o&(0xf<<28) | 0x16f<<16 | 0xf1<<4

	case AREV:
		return o&(0xf<<28) | 0x6bf<<16 | 0xf3<<4

	case AREV16:
		return o&(0xf<<28) | 0x6bf<<16 | 0xfb<<4

	case AREVSH:
		return o&(0xf<<28) | 0x6ff<<16 | 0xfb<<4

	case ARBIT:
		return o&(0xf<<28) | 0x6ff<<16 | 0xf3<<4

	case AMULWT:
		return o&(0xf<<28) | 0x12<<20 | 0xe<<4

	case AMULWB:
		return o&(0xf<<28) | 0x12<<20 | 0xa<<4

	case AMULBB:
		return o&(0xf<<28) | 0x16<<20 | 0x8<<4

	case AMULAWT:
		return o&(0xf<<28) | 0x12<<20 | 0xc<<4

	case AMULAWB:
		return o&(0xf<<28) | 0x12<<20 | 0x8<<4

	case AMULABB:
		return o&(0xf<<28) | 0x10<<20 | 0x8<<4

	case ABL: // BLX REG
		return o&(0xf<<28) | 0x12fff3<<4
	}

	c.ctxt.Diag("%v: bad rrr %d", p, a)
	return 0
}

func (c *ctxt5) opbra(p *obj.Prog, a obj.As, sc int) uint32 {
	sc &= C_SCOND
	sc ^= C_SCOND_XOR
	if a == ABL || a == obj.ADUFFZERO || a == obj.ADUFFCOPY {
		return uint32(sc)<<28 | 0x5<<25 | 0x1<<24
	}
	if sc != 0xe {
		c.ctxt.Diag("%v: .COND on bcond instruction", p)
	}
	switch a {
	case ABEQ:
		return 0x0<<28 | 0x5<<25
	case ABNE:
		return 0x1<<28 | 0x5<<25
	case ABCS:
		return 0x2<<28 | 0x5<<25
	case ABHS:
		return 0x2<<28 | 0x5<<25
	case ABCC:
		return 0x3<<28 | 0x5<<25
	case ABLO:
		return 0x3<<28 | 0x5<<25
	case ABMI:
		return 0x4<<28 | 0x5<<25
	case ABPL:
		return 0x5<<28 | 0x5<<25
	case ABVS:
		return 0x6<<28 | 0x5<<25
	case ABVC:
		return 0x7<<28 | 0x5<<25
	case ABHI:
		return 0x8<<28 | 0x5<<25
	case ABLS:
		return 0x9<<28 | 0x5<<25
	case ABGE:
		return 0xa<<28 | 0x5<<25
	case ABLT:
		return 0xb<<28 | 0x5<<25
	case ABGT:
		return 0xc<<28 | 0x5<<25
	case ABLE:
		return 0xd<<28 | 0x5<<25
	case AB:
		return 0xe<<28 | 0x5<<25
	}

	c.ctxt.Diag("%v: bad bra %v", p, a)
	return 0
}

func (c *ctxt5) olr(v int32, b int, r int, sc int) uint32 {
	o := ((uint32(sc) & C_SCOND) ^ C_SCOND_XOR) << 28
	if sc&C_PBIT == 0 {
		o |= 1 << 24
	}
	if sc&C_UBIT == 0 {
		o |= 1 << 23
	}
	if sc&C_WBIT != 0 {
		o |= 1 << 21
	}
	o |= 1<<26 | 1<<20
	if v < 0 {
		if sc&C_UBIT != 0 {
			c.ctxt.Diag(".U on neg offset")
		}
		v = -v
		o ^= 1 << 23
	}

	if v >= 1<<12 || v < 0 {
		c.ctxt.Diag("literal span too large: %d (R%d)\n%v", v, b, c.printp)
	}
	o |= uint32(v)
	o |= (uint32(b) & 15) << 16
	o |= (uint32(r) & 15) << 12
	return o
}

func (c *ctxt5) olhr(v int32, b int, r int, sc int) uint32 {
	o := ((uint32(sc) & C_SCOND) ^ C_SCOND_XOR) << 28
	if sc&C_PBIT == 0 {
		o |= 1 << 24
	}
	if sc&C_WBIT != 0 {
		o |= 1 << 21
	}
	o |= 1<<23 | 1<<20 | 0xb<<4
	if v < 0 {
		v = -v
		o ^= 1 << 23
	}

	if v >= 1<<8 || v < 0 {
		c.ctxt.Diag("literal span too large: %d (R%d)\n%v", v, b, c.printp)
	}
	o |= uint32(v)&0xf | (uint32(v)>>4)<<8 | 1<<22
	o |= (uint32(b) & 15) << 16
	o |= (uint32(r) & 15) << 12
	return o
}

func (c *ctxt5) osr(a obj.As, r int, v int32, b int, sc int) uint32 {
	o := c.olr(v, b, r, sc) ^ (1 << 20)
	if a != AMOVW {
		o |= 1 << 22
	}
	return o
}

func (c *ctxt5) oshr(r int, v int32, b int, sc int) uint32 {
	o := c.olhr(v, b, r, sc) ^ (1 << 20)
	return o
}

func (c *ctxt5) osrr(r int, i int, b int, sc int) uint32 {
	return c.olr(int32(i), b, r, sc) ^ (1<<25 | 1<<20)
}

func (c *ctxt5) oshrr(r int, i int, b int, sc int) uint32 {
	return c.olhr(int32(i), b, r, sc) ^ (1<<22 | 1<<20)
}

func (c *ctxt5) olrr(i int, b int, r int, sc int) uint32 {
	return c.olr(int32(i), b, r, sc) ^ (1 << 25)
}

func (c *ctxt5) olhrr(i int, b int, r int, sc int) uint32 {
	return c.olhr(int32(i), b, r, sc) ^ (1 << 22)
}

func (c *ctxt5) ofsr(a obj.As, r int, v int32, b int, sc int, p *obj.Prog) uint32 {
	o := ((uint32(sc) & C_SCOND) ^ C_SCOND_XOR) << 28
	if sc&C_PBIT == 0 {
		o |= 1 << 24
	}
	if sc&C_WBIT != 0 {
		o |= 1 << 21
	}
	o |= 6<<25 | 1<<24 | 1<<23 | 10<<8
	if v < 0 {
		v = -v
		o ^= 1 << 23
	}

	if v&3 != 0 {
		c.ctxt.Diag("odd offset for floating point op: %d\n%v", v, p)
	} else if v >= 1<<10 || v < 0 {
		c.ctxt.Diag("literal span too large: %d\n%v", v, p)
	}
	o |= (uint32(v) >> 2) & 0xFF
	o |= (uint32(b) & 15) << 16
	o |= (uint32(r) & 15) << 12

	switch a {
	default:
		c.ctxt.Diag("bad fst %v", a)
		fallthrough

	case AMOVD:
		o |= 1 << 8
		fallthrough

	case AMOVF:
		break
	}

	return o
}

// MOVW $"lower 16-bit", Reg
func (c *ctxt5) omvs(p *obj.Prog, a *obj.Addr, dr int) uint32 {
	o1 := ((uint32(p.Scond) & C_SCOND) ^ C_SCOND_XOR) << 28
	o1 |= 0x30 << 20
	o1 |= (uint32(dr) & 15) << 12
	o1 |= uint32(a.Offset) & 0x0fff
	o1 |= (uint32(a.Offset) & 0xf000) << 4
	return o1
}

// MVN $C_NCON, Reg -> MOVW $C_RCON, Reg
func (c *ctxt5) omvr(p *obj.Prog, a *obj.Addr, dr int) uint32 {
	o1 := c.oprrr(p, AMOVW, int(p.Scond))
	o1 |= (uint32(dr) & 15) << 12
	v := immrot(^uint32(a.Offset))
	if v == 0 {
		c.ctxt.Diag("%v: missing literal", p)
		return 0
	}
	o1 |= uint32(v)
	return o1
}

func (c *ctxt5) omvl(p *obj.Prog, a *obj.Addr, dr int) uint32 {
	var o1 uint32
	if p.Pool == nil {
		c.aclass(a)
		v := immrot(^uint32(c.instoffset))
		if v == 0 {
			c.ctxt.Diag("%v: missing literal", p)
			return 0
		}

		o1 = c.oprrr(p, AMVN, int(p.Scond)&C_SCOND)
		o1 |= uint32(v)
		o1 |= (uint32(dr) & 15) << 12
	} else {
		v := int32(p.Pool.Pc - p.Pc - 8)
		o1 = c.olr(v, REGPC, dr, int(p.Scond)&C_SCOND)
	}

	return o1
}

func (c *ctxt5) chipzero5(e float64) int {
	// We use GOARM.Version=7 and !GOARM.SoftFloat to gate the use of VFPv3 vmov (imm) instructions.
	if buildcfg.GOARM.Version < 7 || buildcfg.GOARM.SoftFloat || math.Float64bits(e) != 0 {
		return -1
	}
	return 0
}

func (c *ctxt5) chipfloat5(e float64) int {
	// We use GOARM.Version=7 and !GOARM.SoftFloat to gate the use of VFPv3 vmov (imm) instructions.
	if buildcfg.GOARM.Version < 7 || buildcfg.GOARM.SoftFloat {
		return -1
	}

	ei := math.Float64bits(e)
	l := uint32(ei)
	h := uint32(ei >> 32)

	if l != 0 || h&0xffff != 0 {
		return -1
	}
	h1 := h & 0x7fc00000
	if h1 != 0x40000000 && h1 != 0x3fc00000 {
		return -1
	}
	n := 0

	// sign bit (a)
	if h&0x80000000 != 0 {
		n |= 1 << 7
	}

	// exp sign bit (b)
	if h1 == 0x3fc00000 {
		n |= 1 << 6
	}

	// rest of exp and mantissa (cd-efgh)
	n |= int((h >> 16) & 0x3f)

	//print("match %.8lux %.8lux %d\n", l, h, n);
	return n
}

func nocache(p *obj.Prog) {
	p.Optab = 0
	p.From.Class = 0
	if p.GetFrom3() != nil {
		p.GetFrom3().Class = 0
	}
	p.To.Class = 0
}
```