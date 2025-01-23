Response:
Let's break down the thought process for analyzing this Go code snippet and generating the response.

**1. Understanding the Goal:**

The core request is to understand the functionality of the provided Go code snippet, specifically within the context of the `asm9.go` file, which hints at assembly generation for the PowerPC 64-bit architecture. The request also asks for concrete examples, potential pitfalls, and a summary of the functionality of *this specific part* of the code.

**2. Initial Code Scan and High-Level Observations:**

* **Function `asmout`:** The primary function is `asmout`. This immediately suggests it's responsible for emitting assembly instructions.
* **Input `p *obj.Prog`:** The function takes a pointer to an `obj.Prog`. This strongly indicates it's processing a single assembly instruction at a time. `obj.Prog` is likely a structure representing a generic assembly instruction.
* **`c *ctxt9`:**  The function also takes a pointer to a `ctxt9` struct. The `ctxt` prefix often signifies a "context" object, holding state relevant to the compilation/assembly process. The "9" likely refers to the specific assembler being used (perhaps a historical artifact or versioning).
* **`o *Optab`:**  Another input is `o *Optab`. "Optab" strongly suggests an "opcode table." This table likely maps assembly mnemonics (like `AADD`, `AMOV`) to their internal representations and properties.
* **`out []uint32`:** The function writes to an `out` slice of `uint32`. This is a strong clue that the output is machine code, represented as a sequence of 32-bit words.
* **Large `switch` statement on `o.type`:**  The core logic resides within a large `switch` statement based on `o.type`. This suggests different instruction encoding schemes or operand types are handled differently. Each `case` likely corresponds to a specific group or format of instructions.
* **Helper functions like `vregoff`, `regoff`, `oprrr`, `opirr`, etc.:** The code calls numerous helper functions. Their names strongly suggest their purpose: `vregoff` (virtual register offset), `regoff` (register offset), `oprrr` (opcode register-register-register), `opirr` (opcode immediate-register-register). This pattern reinforces the idea of instruction encoding and operand extraction.

**3. Deeper Dive into Specific Cases (Selective Examination):**

It's not feasible to analyze every single `case` in detail during the initial understanding phase. Instead, focus on a few representative cases:

* **Case 1 (Branch Instructions):**  The code calculates offsets and sets bits in `o1`. The checks for `p.To.Type == obj.TYPE_BRANCH` and `obj.Framepointer_REG` point to handling branch instructions and potentially stack frame management.
* **Case 2 (Immediate Instructions):**  This case appears to handle instructions with immediate (constant) values. The masking and shifting operations (`uint32(v) & 0xFFFF`) suggest extracting and encoding immediate operands.
* **Case 21 (Move Immediate to Register):** This case looks straightforward – moving an immediate value to a register. The different instructions (`AMOVD`, `AMOVF`, etc.) indicate handling different data types.
* **Cases involving `c.cursym.AddRel`:**  These cases strongly suggest handling relocations – situations where the final address of a symbol isn't known until link time. This is common when dealing with global variables or function calls across compilation units.
* **Cases with `pfxload` and `pfxstore`:** The "pfx" prefix likely refers to "prefixed" instructions, potentially specific to newer PowerPC architectures or extensions.

**4. Connecting the Dots and Forming Hypotheses:**

Based on the observations, we can start formulating hypotheses about the code's functionality:

* **Assembly Emission:** The primary goal is to translate a high-level representation of an assembly instruction (`obj.Prog`) into its raw machine code representation (`uint32` values).
* **Instruction Encoding:** The large `switch` statement and helper functions are responsible for the detailed encoding of different instruction formats.
* **Operand Extraction:** Functions like `vregoff` and `regoff` extract operand values from the `obj.Addr` structures.
* **Relocation Handling:** The calls to `c.cursym.AddRel` handle cases where addresses need to be resolved later by the linker.
* **Architecture-Specific Logic:** The code is specific to the PowerPC 64-bit architecture, as evidenced by the file path and the instruction mnemonics.

**5. Addressing Specific Parts of the Request:**

* **Functionality Listing:** Based on the hypotheses, list the key functionalities: instruction encoding, operand handling, relocation, architecture-specific handling.
* **Go Code Example:**  Choose a relatively simple `case` (like `case 21`) and construct a corresponding Go code snippet that might generate such an instruction. Make reasonable assumptions about the input `obj.Prog`.
* **Input/Output:**  For the example, specify the assumed input `obj.Prog` and the expected output machine code.
* **Command-Line Arguments:** Scan the code for any direct interaction with command-line arguments. If none are apparent (as in this snippet), state that.
* **Common Mistakes:**  Think about common errors in assembly programming, such as incorrect operand types, out-of-range immediates, or incorrect addressing modes. Relate these to the code's logic.
* **Summary:** Synthesize the main functionalities identified earlier into a concise summary.

**6. Iteration and Refinement:**

Review the generated response. Ensure the explanations are clear, the examples are relevant, and the overall understanding of the code is accurate. For instance, initially, I might not have fully grasped the "prefixed" instruction concept. A closer look at the `pfxload/store` functions and their corresponding relocation types would clarify this.

By following this thought process, combining code analysis with an understanding of assembly language and compiler/assembler concepts, one can effectively decipher the functionality of such code snippets. The key is to start with high-level observations and gradually drill down into more specific details, forming and refining hypotheses along the way.
这是 `go/src/cmd/internal/obj/ppc64/asm9.go` 文件中 `asmout` 函数的一部分，其主要功能是将抽象的汇编指令 (`obj.Prog`) 转换为实际的机器码 (一系列的 `uint32`)。

**功能归纳 (针对提供的代码片段):**

这部分代码主要负责处理以下几种 PowerPC64 架构的指令编码：

* **带有掩码的移位指令 (Shift with Mask):**  处理例如 `RLLW`, `RLLWCC`, `RLL`, `RLLCC` 等指令，这些指令涉及到对寄存器进行循环左移，并通过掩码来选择结果的哪些位写入目标寄存器。  代码会检查掩码的有效性。
* **带有移位计数的指令 (Shift with Count):** 处理例如 `ARLDIMI`, `ARLDIMICC` 等指令，这些指令使用立即数作为移位计数。
* **双字 (Dword) 数据加载/存储:**  处理将 64 位立即数加载到寄存器的操作。需要根据目标系统的字节序 (大端或小端) 调整机器码的顺序。如果源操作数是一个符号，则会添加一个 `R_ADDR` 类型的重定位信息。
* **浮点数乘法 (fmul):** 处理浮点数乘法指令，可以指定第三个源操作数寄存器，如果未指定则使用目标寄存器。
* **浮点数绝对值/移动 (fabs, fmr):** 处理浮点数绝对值和移动指令。
* **浮点数 FMA (FMADDx):** 处理浮点数融合乘加/减指令。
* **移动立即数到内存 (mov r, lext/lauto/loreg):** 处理将一个可能包含偏移的地址加载到寄存器，然后将寄存器的值存储到内存的操作。  它会处理前缀指令 (pfxstore) 的情况，并检查 DS-Form 存储指令的偏移量是否是 4 的倍数。
* **移动内存到寄存器 (mov b/bz/h/hz lext/lauto/lreg, r):** 处理从内存加载数据到寄存器的操作，支持字节、半字等不同大小，并支持符号扩展。也会处理前缀指令 (pfxload) 的情况。
* **单字 (Word) 数据加载:**  处理将一个 32 位立即数加载到寄存器的操作。
* **带索引的存储字 (stswi):** 处理带索引的存储字指令，第三个操作数作为位移量。
* **带索引的加载字 (lswi):** 处理带索引的加载字指令，第三个操作数作为位移量。
* **数据缓存操作指令 (data cache instructions):** 处理例如 `dcbf`, `dcbi`, `dcbst`, `dcbt`, `dcbtst`, `dcbz` 等数据缓存操作指令。
* **索引存储 (indexed store):** 处理例如 `stbx`, `stex`, `sthx`, `stwx`, `stdx` 等索引存储指令。
* **索引加载 (indexed load):** 处理例如 `lbzx`, `lhzx`, `lwzx`, `ldx`, `lbar`, `lhar`, `lwar`, `ldar` 等索引加载指令，并支持带有排他访问提示 (Exclusive Access Hint) 的指令。
* **简单操作指令 (plain op):** 处理一些不需要额外操作数的简单指令。
* **寄存器到寄存器操作 (op Ra, Rd; also op [Ra,] Rd):** 处理一些只有一个或两个寄存器操作数的指令。
* **寄存器操作 (op Rs, Ra):** 处理一些只有一个或两个寄存器操作数的指令。
* **寄存器操作或立即数操作 (op Rb; op $n, Rb):** 处理对单个寄存器进行操作的指令，或者使用立即数作为操作数的指令。
* **求余数指令 (rem[u] r1[,r2],r3):** 处理有符号和无符号的求余数指令，需要生成多个机器码指令来实现。
* **设置 FPSCR 位 (mtfsbNx cr(n)):** 处理设置浮点状态控制寄存器 (FPSCR) 中特定位的指令。
* **读取 FPSCR (mffsX ,fr1):** 处理读取浮点状态控制寄存器 (FPSCR) 的指令。
* **寄存器到寄存器操作 (op Rb, Rd):** 处理两个寄存器之间的操作指令。
* **带移位的算术右移 (sra $sh,[s,]a; srd $sh,[s,]a):** 处理带立即数移位量的算术右移指令。
* **带移位的逻辑左/右移 (slw $sh,[s,]a -> rlwinm ...):** 处理带立即数移位量的逻辑左/右移指令，会根据不同的指令类型生成 `rlwinm` 指令。
* **逻辑与运算 (logical $andcon,[s],a):** 处理带立即数的逻辑与运算指令。
* **陷阱指令 (tw to,a,b):** 处理根据条件触发陷阱的指令，操作数可以是寄存器或立即数。
* **带移位和掩码的循环移位 (clrlslwi $sh,s,$mask,a):** 处理一种特定的循环移位指令，会映射到 `rlwinm` 指令。
* **带移位和掩码的循环移位 (rlwimi/rlwnm/rlwinm [$sh,b],s,[$mask or mb,me],a):** 处理多种形式的循环移位指令，包括使用立即数移位或寄存器移位，以及使用掩码来控制写入。

**Go 代码示例 (以带有掩码的移位指令 RLLW 为例):**

假设我们有一个要执行的 RLLW 指令，其汇编表示可能如下：

```assembly
RLLW R3, R4, 10, 0, 20  // R3 = R4 << 10, 结果的第 0 到 20 位写入 R3
```

在 Go 代码中，对应的 `obj.Prog` 结构体可能包含以下信息 (简化表示)：

```go
p := &obj.Prog{
    As: obj.ARLLW,
    To: obj.Addr{Type: obj.TYPE_REG, Reg: objabi.REG_R3},
    Reg: objabi.REG_R4,
    From: obj.Addr{Type: obj.TYPE_CONST, Offset: 10}, // 移位量
    RestArgs: []obj.Addr{
        {Type: obj.TYPE_CONST, Offset: 0},  // mb (mask begin)
        {Type: obj.TYPE_CONST, Offset: 20}, // me (mask end)
    },
}
```

假设 `c.opirr(p.As)` 返回 `OP_RLWINM` 的操作码，`uint32(p.To.Reg)` 为 3，`uint32(p.Reg)` 为 4，`uint32(p.From.Offset)` 为 10，`mb` 为 0，`me` 为 20。

输出的机器码 `o1` 将会是：

```
o1 = OP_RLW(OP_RLWINM, 3, 4, 10, 0, 20)
```

这会生成一个 32 位的机器码，其各个位段会被设置为对应的值，表示将寄存器 R4 循环左移 10 位，并将结果的第 0 到 20 位写入寄存器 R3。

**假设的输入与输出 (针对 RLLW 指令):**

**输入 `p *obj.Prog` (简化):**

```go
&obj.Prog{
    As: obj.ARLLW,
    To: obj.Addr{Type: obj.TYPE_REG, Reg: objabi.REG_R3},
    Reg: objabi.REG_R4,
    From: obj.Addr{Type: obj.TYPE_CONST, Offset: 10},
    RestArgs: []obj.Addr{
        {Type: obj.TYPE_CONST, Offset: 0},
        {Type: obj.TYPE_CONST, Offset: 20},
    },
}
```

**输出 `out []uint32`:**

`out[0]` 的值将是一个表示 `RLLW R3, R4, 10, 0, 20` 指令的 32 位机器码，其二进制表示会根据 PowerPC64 的指令格式进行编码。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在更上层的代码中，用于控制编译和汇编的流程。这些参数会影响到 `ctxt9` 结构体的初始化以及其他相关的配置。

**使用者易犯错的点 (以掩码移位指令为例):**

* **掩码值不合法:**  对于带有掩码的移位指令，掩码的起始位 (`mb`) 和结束位 (`me`) 必须是合法的，且 `mb <= me`。如果 `decodeMask64(d)` 返回 `!valid`，则说明掩码值不正确，这通常是因为提供的立即数无法构成一个连续的掩码。例如，提供一个不连续的位掩码给指令会导致错误。

**示例:**

假设用户尝试使用一个不合法的掩码值：

```assembly
RLLW R3, R4, 10, 1, 5 // 合法
RLLW R3, R4, 10, 1, 0 // 不合法，me < mb
```

在这种情况下，`decodeMask64` 函数会检测到 `me < mb`，从而设置 `valid` 为 `false`，`asmout` 函数会调用 `c.ctxt.Diag` 报告错误 "invalid mask for shift"。

总而言之，这段代码是 PowerPC64 汇编器中负责将特定类型的汇编指令转换为机器码的关键部分，它根据指令的类型和操作数进行不同的编码处理，并进行一些基本的错误检查。

### 提示词
```
这是路径为go/src/cmd/internal/obj/ppc64/asm9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```go
decodeMask64(d)
			if me != (63-sh) || !valid {
				c.ctxt.Diag("invalid mask for shift: %x %x (shift %d)\n%v", uint64(d), me, sh, p)
			}
			o1 = AOP_MD(c.opirr(p.As), uint32(p.To.Reg), uint32(p.Reg), sh, mb)

		// Opcodes with shift count operands.
		case ARLDIMI, ARLDIMICC:
			o1 = AOP_MD(c.opirr(p.As), uint32(p.To.Reg), uint32(p.Reg), sh, uint32(d))
		}

	case 31: /* dword */
		d := c.vregoff(&p.From)

		if c.ctxt.Arch.ByteOrder == binary.BigEndian {
			o1 = uint32(d >> 32)
			o2 = uint32(d)
		} else {
			o1 = uint32(d)
			o2 = uint32(d >> 32)
		}

		if p.From.Sym != nil {
			c.cursym.AddRel(c.ctxt, obj.Reloc{
				Type: objabi.R_ADDR,
				Off:  int32(c.pc),
				Siz:  8,
				Sym:  p.From.Sym,
				Add:  p.From.Offset,
			})
			o2 = 0
			o1 = o2
		}

	case 32: /* fmul frc,fra,frd */
		r := int(p.Reg)

		if r == 0 {
			r = int(p.To.Reg)
		}
		o1 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(r), 0) | (uint32(p.From.Reg)&31)<<6

	case 33: /* fabs [frb,]frd; fmr. frb,frd */
		r := int(p.From.Reg)

		if oclass(&p.From) == C_NONE {
			r = int(p.To.Reg)
		}
		o1 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), 0, uint32(r))

	case 34: /* FMADDx fra,frb,frc,frt (t=a*c±b) */
		o1 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg)) | (uint32(p.GetFrom3().Reg)&31)<<6

	case 35: /* mov r,lext/lauto/loreg ==> cau $(v>>16),sb,r'; store o(r') */
		v := c.regoff(&p.To)
		r := int(p.To.Reg)
		// Offsets in DS form stores must be a multiple of 4
		if o.ispfx {
			o1, o2 = pfxstore(p.As, p.From.Reg, int16(r), PFX_R_ABS)
			o1 |= uint32((v >> 16) & 0x3FFFF)
			o2 |= uint32(v & 0xFFFF)
		} else {
			inst := c.opstore(p.As)
			if c.opform(inst) == DS_FORM && v&0x3 != 0 {
				log.Fatalf("invalid offset for DS form load/store %v", p)
			}
			o1 = AOP_IRR(OP_ADDIS, REGTMP, uint32(r), uint32(high16adjusted(v)))
			o2 = AOP_IRR(inst, uint32(p.From.Reg), REGTMP, uint32(v))
		}

	case 36: /* mov b/bz/h/hz lext/lauto/lreg,r ==> lbz+extsb/lbz/lha/lhz etc */
		v := c.regoff(&p.From)
		r := int(p.From.Reg)

		if o.ispfx {
			o1, o2 = pfxload(p.As, p.To.Reg, int16(r), PFX_R_ABS)
			o1 |= uint32((v >> 16) & 0x3FFFF)
			o2 |= uint32(v & 0xFFFF)
		} else {
			if o.a6 == C_REG {
				// Reuse the base register when loading a GPR (C_REG) to avoid
				// using REGTMP (R31) when possible.
				o1 = AOP_IRR(OP_ADDIS, uint32(p.To.Reg), uint32(r), uint32(high16adjusted(v)))
				o2 = AOP_IRR(c.opload(p.As), uint32(p.To.Reg), uint32(p.To.Reg), uint32(v))
			} else {
				o1 = AOP_IRR(OP_ADDIS, uint32(REGTMP), uint32(r), uint32(high16adjusted(v)))
				o2 = AOP_IRR(c.opload(p.As), uint32(p.To.Reg), uint32(REGTMP), uint32(v))
			}
		}

		// Sign extend MOVB if needed
		o3 = LOP_RRR(OP_EXTSB, uint32(p.To.Reg), uint32(p.To.Reg), 0)

	case 40: /* word */
		o1 = uint32(c.regoff(&p.From))

	case 41: /* stswi */
		if p.To.Type == obj.TYPE_MEM && p.To.Index == 0 && p.To.Offset != 0 {
			c.ctxt.Diag("Invalid addressing mode used in index type instruction: %v", p.As)
		}

		o1 = AOP_RRR(c.opirr(p.As), uint32(p.From.Reg), uint32(p.To.Reg), 0) | (uint32(c.regoff(p.GetFrom3()))&0x7F)<<11

	case 42: /* lswi */
		if p.From.Type == obj.TYPE_MEM && p.From.Index == 0 && p.From.Offset != 0 {
			c.ctxt.Diag("Invalid addressing mode used in index type instruction: %v", p.As)
		}
		o1 = AOP_RRR(c.opirr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), 0) | (uint32(c.regoff(p.GetFrom3()))&0x7F)<<11

	case 43: /* data cache instructions: op (Ra+[Rb]), [th|l] */
		/* TH field for dcbt/dcbtst: */
		/* 0 = Block access - program will soon access EA. */
		/* 8-15 = Stream access - sequence of access (data stream). See section 4.3.2 of the ISA for details. */
		/* 16 = Block access - program will soon make a transient access to EA. */
		/* 17 = Block access - program will not access EA for a long time. */

		/* L field for dcbf: */
		/* 0 = invalidates the block containing EA in all processors. */
		/* 1 = same as 0, but with limited scope (i.e. block in the current processor will not be reused soon). */
		/* 3 = same as 1, but with even more limited scope (i.e. block in the current processor primary cache will not be reused soon). */
		if p.To.Type == obj.TYPE_NONE {
			o1 = AOP_RRR(c.oprrr(p.As), 0, uint32(p.From.Index), uint32(p.From.Reg))
		} else {
			th := c.regoff(&p.To)
			o1 = AOP_RRR(c.oprrr(p.As), uint32(th), uint32(p.From.Index), uint32(p.From.Reg))
		}

	case 44: /* indexed store */
		o1 = AOP_RRR(c.opstorex(p.As), uint32(p.From.Reg), uint32(p.To.Index), uint32(p.To.Reg))

	case 45: /* indexed load */
		switch p.As {
		/* The assembler accepts a 4-operand l*arx instruction. The fourth operand is an Exclusive Access Hint (EH) */
		/* The EH field can be used as a lock acquire/release hint as follows: */
		/* 0 = Atomic Update (fetch-and-operate or similar algorithm) */
		/* 1 = Exclusive Access (lock acquire and release) */
		case ALBAR, ALHAR, ALWAR, ALDAR:
			if p.From3Type() != obj.TYPE_NONE {
				eh := int(c.regoff(p.GetFrom3()))
				if eh > 1 {
					c.ctxt.Diag("illegal EH field\n%v", p)
				}
				o1 = AOP_RRRI(c.oploadx(p.As), uint32(p.To.Reg), uint32(p.From.Index), uint32(p.From.Reg), uint32(eh))
			} else {
				o1 = AOP_RRR(c.oploadx(p.As), uint32(p.To.Reg), uint32(p.From.Index), uint32(p.From.Reg))
			}
		default:
			o1 = AOP_RRR(c.oploadx(p.As), uint32(p.To.Reg), uint32(p.From.Index), uint32(p.From.Reg))
		}
	case 46: /* plain op */
		o1 = c.oprrr(p.As)

	case 47: /* op Ra, Rd; also op [Ra,] Rd */
		r := int(p.From.Reg)

		if r == 0 {
			r = int(p.To.Reg)
		}
		o1 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(r), 0)

	case 48: /* op Rs, Ra */
		r := int(p.From.Reg)

		if r == 0 {
			r = int(p.To.Reg)
		}
		o1 = LOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(r), 0)

	case 49: /* op Rb; op $n, Rb */
		if p.From.Type != obj.TYPE_REG { /* tlbie $L, rB */
			v := c.regoff(&p.From) & 1
			o1 = AOP_RRR(c.oprrr(p.As), 0, 0, uint32(p.To.Reg)) | uint32(v)<<21
		} else {
			o1 = AOP_RRR(c.oprrr(p.As), 0, 0, uint32(p.From.Reg))
		}

	case 50: /* rem[u] r1[,r2],r3 */
		r := int(p.Reg)

		if r == 0 {
			r = int(p.To.Reg)
		}
		v := c.oprrr(p.As)
		t := v & (1<<10 | 1) /* OE|Rc */
		o1 = AOP_RRR(v&^t, REGTMP, uint32(r), uint32(p.From.Reg))
		o2 = AOP_RRR(OP_MULLW, REGTMP, REGTMP, uint32(p.From.Reg))
		o3 = AOP_RRR(OP_SUBF|t, uint32(p.To.Reg), REGTMP, uint32(r))
		if p.As == AREMU {
			o4 = o3

			/* Clear top 32 bits */
			o3 = OP_RLW(OP_RLDIC, REGTMP, REGTMP, 0, 0, 0) | 1<<5
		}

	case 51: /* remd[u] r1[,r2],r3 */
		r := int(p.Reg)

		if r == 0 {
			r = int(p.To.Reg)
		}
		v := c.oprrr(p.As)
		t := v & (1<<10 | 1) /* OE|Rc */
		o1 = AOP_RRR(v&^t, REGTMP, uint32(r), uint32(p.From.Reg))
		o2 = AOP_RRR(OP_MULLD, REGTMP, REGTMP, uint32(p.From.Reg))
		o3 = AOP_RRR(OP_SUBF|t, uint32(p.To.Reg), REGTMP, uint32(r))
		/* cases 50,51: removed; can be reused. */

		/* cases 50,51: removed; can be reused. */

	case 52: /* mtfsbNx cr(n) */
		v := c.regoff(&p.From) & 31

		o1 = AOP_RRR(c.oprrr(p.As), uint32(v), 0, 0)

	case 53: /* mffsX ,fr1 */
		o1 = AOP_RRR(OP_MFFS, uint32(p.To.Reg), 0, 0)

	case 55: /* op Rb, Rd */
		o1 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), 0, uint32(p.From.Reg))

	case 56: /* sra $sh,[s,]a; srd $sh,[s,]a */
		v := c.regoff(&p.From)

		r := int(p.Reg)
		if r == 0 {
			r = int(p.To.Reg)
		}
		o1 = AOP_RRR(c.opirr(p.As), uint32(r), uint32(p.To.Reg), uint32(v)&31)
		if (p.As == ASRAD || p.As == ASRADCC) && (v&0x20 != 0) {
			o1 |= 1 << 1 /* mb[5] */
		}

	case 57: /* slw $sh,[s,]a -> rlwinm ... */
		v := c.regoff(&p.From)

		r := int(p.Reg)
		if r == 0 {
			r = int(p.To.Reg)
		}

		/*
			 * Let user (gs) shoot himself in the foot.
			 * qc has already complained.
			 *
			if(v < 0 || v > 31)
				ctxt->diag("illegal shift %ld\n%v", v, p);
		*/
		if v < 0 {
			v = 0
		} else if v > 32 {
			v = 32
		}
		var mask [2]uint8
		switch p.As {
		case AROTLW:
			mask[0], mask[1] = 0, 31
		case ASRW, ASRWCC:
			mask[0], mask[1] = uint8(v), 31
			v = 32 - v
		default:
			mask[0], mask[1] = 0, uint8(31-v)
		}
		o1 = OP_RLW(OP_RLWINM, uint32(p.To.Reg), uint32(r), uint32(v), uint32(mask[0]), uint32(mask[1]))
		if p.As == ASLWCC || p.As == ASRWCC {
			o1 |= 1 // set the condition code
		}

	case 58: /* logical $andcon,[s],a */
		v := c.regoff(&p.From)

		r := int(p.Reg)
		if r == 0 {
			r = int(p.To.Reg)
		}
		o1 = LOP_IRR(c.opirr(p.As), uint32(p.To.Reg), uint32(r), uint32(v))

	case 60: /* tw to,a,b */
		r := int(c.regoff(&p.From) & 31)

		o1 = AOP_RRR(c.oprrr(p.As), uint32(r), uint32(p.Reg), uint32(p.To.Reg))

	case 61: /* tw to,a,$simm */
		r := int(c.regoff(&p.From) & 31)

		v := c.regoff(&p.To)
		o1 = AOP_IRR(c.opirr(p.As), uint32(r), uint32(p.Reg), uint32(v))

	case 62: /* clrlslwi $sh,s,$mask,a */
		v := c.regoff(&p.From)
		n := c.regoff(p.GetFrom3())
		// This is an extended mnemonic described in the ISA C.8.2
		// clrlslwi ra,rs,b,n -> rlwinm ra,rs,n,b-n,31-n
		// It maps onto rlwinm which is directly generated here.
		if n > v || v >= 32 {
			c.ctxt.Diag("Invalid n or b for CLRLSLWI: %x %x\n%v", v, n, p)
		}

		o1 = OP_RLW(OP_RLWINM, uint32(p.To.Reg), uint32(p.Reg), uint32(n), uint32(v-n), uint32(31-n))

	case 63: /* rlwimi/rlwnm/rlwinm [$sh,b],s,[$mask or mb,me],a*/
		var mb, me uint32
		if len(p.RestArgs) == 1 { // Mask needs decomposed into mb and me.
			var valid bool
			// Note, optab rules ensure $mask is a 32b constant.
			mb, me, valid = decodeMask32(uint32(p.RestArgs[0].Addr.Offset))
			if !valid {
				c.ctxt.Diag("cannot generate mask #%x\n%v", uint64(p.RestArgs[0].Addr.Offset), p)
			}
		} else { // Otherwise, mask is already passed as mb and me in RestArgs.
			mb, me = uint32(p.RestArgs[0].Addr.Offset), uint32(p.RestArgs[1].Addr.Offset)
		}
		if p.From.Type == obj.TYPE_CONST {
			o1 = OP_RLW(c.opirr(p.As), uint32(p.To.Reg), uint32(p.Reg), uint32(p.From.Offset), mb, me)
		} else {
			o1 = OP_RLW(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.Reg), uint32(p.From.Reg), mb, me)
		}

	case 64: /* mtfsf fr[, $m] {,fpcsr} */
		var v int32
		if p.From3Type() != obj.TYPE_NONE {
			v = c.regoff(p.GetFrom3()) & 255
		} else {
			v = 255
		}
		o1 = OP_MTFSF | uint32(v)<<17 | uint32(p.From.Reg)<<11

	case 65: /* MOVFL $imm,FPSCR(n) => mtfsfi crfd,imm */
		if p.To.Reg == 0 {
			c.ctxt.Diag("must specify FPSCR(n)\n%v", p)
		}
		o1 = OP_MTFSFI | (uint32(p.To.Reg)&15)<<23 | (uint32(c.regoff(&p.From))&31)<<12

	case 66: /* mov spr,r1; mov r1,spr */
		var r int
		var v int32
		if REG_R0 <= p.From.Reg && p.From.Reg <= REG_R31 {
			r = int(p.From.Reg)
			v = int32(p.To.Reg)
			o1 = OPVCC(31, 467, 0, 0) /* mtspr */
		} else {
			r = int(p.To.Reg)
			v = int32(p.From.Reg)
			o1 = OPVCC(31, 339, 0, 0) /* mfspr */
		}

		o1 = AOP_RRR(o1, uint32(r), 0, 0) | (uint32(v)&0x1f)<<16 | ((uint32(v)>>5)&0x1f)<<11

	case 67: /* mcrf crfD,crfS */
		if p.From.Reg == REG_CR || p.To.Reg == REG_CR {
			c.ctxt.Diag("CR argument must be a conditional register field (CR0-CR7)\n%v", p)
		}
		o1 = AOP_RRR(OP_MCRF, ((uint32(p.To.Reg) & 7) << 2), ((uint32(p.From.Reg) & 7) << 2), 0)

	case 68: /* mfcr rD; mfocrf CRM,rD */
		o1 = AOP_RRR(OP_MFCR, uint32(p.To.Reg), 0, 0) /*  form, whole register */
		if p.From.Reg != REG_CR {
			v := uint32(1) << uint(7-(p.From.Reg&7)) /* CR(n) */
			o1 |= 1<<20 | v<<12                      /* new form, mfocrf */
		}

	case 69: /* mtcrf CRM,rS, mtocrf CRx,rS */
		var v uint32
		if p.To.Reg == REG_CR {
			v = 0xff
		} else if p.To.Offset != 0 { // MOVFL gpr, constant
			v = uint32(p.To.Offset)
		} else { // p.To.Reg == REG_CRx
			v = 1 << uint(7-(p.To.Reg&7))
		}
		// Use mtocrf form if only one CR field moved.
		if bits.OnesCount32(v) == 1 {
			v |= 1 << 8
		}

		o1 = AOP_RRR(OP_MTCRF, uint32(p.From.Reg), 0, 0) | uint32(v)<<12

	case 70: /* cmp* r,r,cr or cmp*i r,i,cr or fcmp f,f,cr or cmpeqb r,r */
		r := uint32(p.Reg&7) << 2
		if p.To.Type == obj.TYPE_CONST {
			o1 = AOP_IRR(c.opirr(p.As), r, uint32(p.From.Reg), uint32(uint16(p.To.Offset)))
		} else {
			o1 = AOP_RRR(c.oprrr(p.As), r, uint32(p.From.Reg), uint32(p.To.Reg))
		}

	case 72: /* slbmte (Rb+Rs -> slb[Rb]) -> Rs, Rb */
		o1 = AOP_RRR(c.oprrr(p.As), uint32(p.From.Reg), 0, uint32(p.To.Reg))

	case 73: /* mcrfs crfD,crfS */
		if p.From.Type != obj.TYPE_REG || p.From.Reg != REG_FPSCR || p.To.Type != obj.TYPE_REG || p.To.Reg < REG_CR0 || REG_CR7 < p.To.Reg {
			c.ctxt.Diag("illegal FPSCR/CR field number\n%v", p)
		}
		o1 = AOP_RRR(OP_MCRFS, ((uint32(p.To.Reg) & 7) << 2), ((0 & 7) << 2), 0)

	case 77: /* syscall $scon, syscall Rx */
		if p.From.Type == obj.TYPE_CONST {
			if p.From.Offset > BIG || p.From.Offset < -BIG {
				c.ctxt.Diag("illegal syscall, sysnum too large: %v", p)
			}
			o1 = AOP_IRR(OP_ADDI, REGZERO, REGZERO, uint32(p.From.Offset))
		} else if p.From.Type == obj.TYPE_REG {
			o1 = LOP_RRR(OP_OR, REGZERO, uint32(p.From.Reg), uint32(p.From.Reg))
		} else {
			c.ctxt.Diag("illegal syscall: %v", p)
			o1 = 0x7fe00008 // trap always
		}

		o2 = c.oprrr(p.As)
		o3 = AOP_RRR(c.oprrr(AXOR), REGZERO, REGZERO, REGZERO) // XOR R0, R0

	case 78: /* undef */
		o1 = 0 /* "An instruction consisting entirely of binary 0s is guaranteed
		   always to be an illegal instruction."  */

	/* relocation operations */
	case 74:
		v := c.vregoff(&p.To)
		// Offsets in DS form stores must be a multiple of 4
		inst := c.opstore(p.As)

		// Can't reuse base for store instructions.
		var rel obj.Reloc
		o1, o2, rel = c.symbolAccess(p.To.Sym, v, p.From.Reg, inst, false)

		// Rewrite as a prefixed store if supported.
		if o.ispfx {
			o1, o2 = pfxstore(p.As, p.From.Reg, REG_R0, PFX_R_PCREL)
			rel.Type = objabi.R_ADDRPOWER_PCREL34
		} else if c.opform(inst) == DS_FORM && v&0x3 != 0 {
			log.Fatalf("invalid offset for DS form load/store %v", p)
		}
		c.cursym.AddRel(c.ctxt, rel)

	case 75: // 32 bit offset symbol loads (got/toc/addr)
		v := p.From.Offset

		// Offsets in DS form loads must be a multiple of 4
		inst := c.opload(p.As)
		var rel obj.Reloc
		switch p.From.Name {
		case obj.NAME_GOTREF, obj.NAME_TOCREF:
			if v != 0 {
				c.ctxt.Diag("invalid offset for GOT/TOC access %v", p)
			}
			o1 = AOP_IRR(OP_ADDIS, uint32(p.To.Reg), REG_R2, 0)
			o2 = AOP_IRR(inst, uint32(p.To.Reg), uint32(p.To.Reg), 0)
			rel.Off = int32(c.pc)
			rel.Siz = 8
			rel.Sym = p.From.Sym
			switch p.From.Name {
			case obj.NAME_GOTREF:
				rel.Type = objabi.R_ADDRPOWER_GOT
			case obj.NAME_TOCREF:
				rel.Type = objabi.R_ADDRPOWER_TOCREL_DS
			}
		default:
			reuseBaseReg := o.a6 == C_REG
			// Reuse To.Reg as base register if it is a GPR.
			o1, o2, rel = c.symbolAccess(p.From.Sym, v, p.To.Reg, inst, reuseBaseReg)
		}

		// Convert to prefixed forms if supported.
		if o.ispfx {
			switch rel.Type {
			case objabi.R_ADDRPOWER, objabi.R_ADDRPOWER_DS,
				objabi.R_ADDRPOWER_TOCREL, objabi.R_ADDRPOWER_TOCREL_DS:
				o1, o2 = pfxload(p.As, p.To.Reg, REG_R0, PFX_R_PCREL)
				rel.Type = objabi.R_ADDRPOWER_PCREL34
			case objabi.R_POWER_TLS_IE:
				o1, o2 = pfxload(p.As, p.To.Reg, REG_R0, PFX_R_PCREL)
				rel.Type = objabi.R_POWER_TLS_IE_PCREL34
			case objabi.R_ADDRPOWER_GOT:
				o1, o2 = pfxload(p.As, p.To.Reg, REG_R0, PFX_R_PCREL)
				rel.Type = objabi.R_ADDRPOWER_GOT_PCREL34
			default:
				// We've failed to convert a TOC-relative relocation to a PC-relative one.
				log.Fatalf("Unable convert TOC-relative relocation %v to PC-relative", rel.Type)
			}
		} else if c.opform(inst) == DS_FORM && v&0x3 != 0 {
			log.Fatalf("invalid offset for DS form load/store %v", p)
		}
		c.cursym.AddRel(c.ctxt, rel)

		o3 = LOP_RRR(OP_EXTSB, uint32(p.To.Reg), uint32(p.To.Reg), 0)

	case 79:
		if p.From.Offset != 0 {
			c.ctxt.Diag("invalid offset against tls var %v", p)
		}
		var typ objabi.RelocType
		if !o.ispfx {
			o1 = AOP_IRR(OP_ADDIS, uint32(p.To.Reg), REG_R13, 0)
			o2 = AOP_IRR(OP_ADDI, uint32(p.To.Reg), uint32(p.To.Reg), 0)
			typ = objabi.R_POWER_TLS_LE
		} else {
			o1, o2 = pfxadd(p.To.Reg, REG_R13, PFX_R_ABS, 0)
			typ = objabi.R_POWER_TLS_LE_TPREL34
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: typ,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
		})

	case 80:
		if p.From.Offset != 0 {
			c.ctxt.Diag("invalid offset against tls var %v", p)
		}
		typ := objabi.R_POWER_TLS_IE
		if !o.ispfx {
			o1 = AOP_IRR(OP_ADDIS, uint32(p.To.Reg), REG_R2, 0)
			o2 = AOP_IRR(c.opload(AMOVD), uint32(p.To.Reg), uint32(p.To.Reg), 0)
		} else {
			o1, o2 = pfxload(p.As, p.To.Reg, REG_R0, PFX_R_PCREL)
			typ = objabi.R_POWER_TLS_IE_PCREL34
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: typ,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
		})
		o3 = AOP_RRR(OP_ADD, uint32(p.To.Reg), uint32(p.To.Reg), REG_R13)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_POWER_TLS,
			Off:  int32(c.pc) + 8,
			Siz:  4,
			Sym:  p.From.Sym,
		})

	case 82: /* vector instructions, VX-form and VC-form */
		if p.From.Type == obj.TYPE_REG {
			/* reg reg none OR reg reg reg */
			/* 3-register operand order: VRA, VRB, VRT */
			/* 2-register operand order: VRA, VRT */
			o1 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg))
		} else if p.From3Type() == obj.TYPE_CONST {
			/* imm imm reg reg */
			/* operand order: SIX, VRA, ST, VRT */
			six := int(c.regoff(&p.From))
			st := int(c.regoff(p.GetFrom3()))
			o1 = AOP_IIRR(c.opiirr(p.As), uint32(p.To.Reg), uint32(p.Reg), uint32(st), uint32(six))
		} else if p.From3Type() == obj.TYPE_NONE && p.Reg != 0 {
			/* imm reg reg */
			/* operand order: UIM, VRB, VRT */
			uim := int(c.regoff(&p.From))
			o1 = AOP_VIRR(c.opirr(p.As), uint32(p.To.Reg), uint32(p.Reg), uint32(uim))
		} else {
			/* imm reg */
			/* operand order: SIM, VRT */
			sim := int(c.regoff(&p.From))
			o1 = AOP_IR(c.opirr(p.As), uint32(p.To.Reg), uint32(sim))
		}

	case 83: /* vector instructions, VA-form */
		if p.From.Type == obj.TYPE_REG {
			/* reg reg reg reg */
			/* 4-register operand order: VRA, VRB, VRC, VRT */
			o1 = AOP_RRRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg), uint32(p.GetFrom3().Reg))
		} else if p.From.Type == obj.TYPE_CONST {
			/* imm reg reg reg */
			/* operand order: SHB, VRA, VRB, VRT */
			shb := int(c.regoff(&p.From))
			o1 = AOP_IRRR(c.opirrr(p.As), uint32(p.To.Reg), uint32(p.Reg), uint32(p.GetFrom3().Reg), uint32(shb))
		}

	case 84: // ISEL BC,RA,RB,RT -> isel rt,ra,rb,bc
		bc := c.vregoff(&p.From)
		if o.a1 == C_CRBIT {
			// CR bit is encoded as a register, not a constant.
			bc = int64(p.From.Reg)
		}

		// rt = To.Reg, ra = p.Reg, rb = p.From3.Reg
		o1 = AOP_ISEL(OP_ISEL, uint32(p.To.Reg), uint32(p.Reg), uint32(p.GetFrom3().Reg), uint32(bc))

	case 85: /* vector instructions, VX-form */
		/* reg none reg */
		/* 2-register operand order: VRB, VRT */
		o1 = AOP_RR(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg))

	case 86: /* VSX indexed store, XX1-form */
		/* reg reg reg */
		/* 3-register operand order: XT, (RB)(RA*1) */
		o1 = AOP_XX1(c.opstorex(p.As), uint32(p.From.Reg), uint32(p.To.Index), uint32(p.To.Reg))

	case 87: /* VSX indexed load, XX1-form */
		/* reg reg reg */
		/* 3-register operand order: (RB)(RA*1), XT */
		o1 = AOP_XX1(c.oploadx(p.As), uint32(p.To.Reg), uint32(p.From.Index), uint32(p.From.Reg))

	case 88: /* VSX mfvsr* instructions, XX1-form XS,RA */
		o1 = AOP_XX1(c.oprrr(p.As), uint32(p.From.Reg), uint32(p.To.Reg), uint32(p.Reg))

	case 89: /* VSX instructions, XX2-form */
		/* reg none reg OR reg imm reg */
		/* 2-register operand order: XB, XT or XB, UIM, XT*/
		uim := int(c.regoff(p.GetFrom3()))
		o1 = AOP_XX2(c.oprrr(p.As), uint32(p.To.Reg), uint32(uim), uint32(p.From.Reg))

	case 90: /* VSX instructions, XX3-form */
		if p.From3Type() == obj.TYPE_NONE {
			/* reg reg reg */
			/* 3-register operand order: XA, XB, XT */
			o1 = AOP_XX3(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg))
		} else if p.From3Type() == obj.TYPE_CONST {
			/* reg reg reg imm */
			/* operand order: XA, XB, DM, XT */
			dm := int(c.regoff(p.GetFrom3()))
			o1 = AOP_XX3I(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg), uint32(dm))
		}

	case 91: /* VSX instructions, XX4-form */
		/* reg reg reg reg */
		/* 3-register operand order: XA, XB, XC, XT */
		o1 = AOP_XX4(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg), uint32(p.GetFrom3().Reg))

	case 92: /* X-form instructions, 3-operands */
		if p.To.Type == obj.TYPE_CONST {
			/* imm reg reg */
			xf := int32(p.From.Reg)
			if REG_F0 <= xf && xf <= REG_F31 {
				/* operand order: FRA, FRB, BF */
				bf := int(c.regoff(&p.To)) << 2
				o1 = AOP_RRR(c.opirr(p.As), uint32(bf), uint32(p.From.Reg), uint32(p.Reg))
			} else {
				/* operand order: RA, RB, L */
				l := int(c.regoff(&p.To))
				o1 = AOP_RRR(c.opirr(p.As), uint32(l), uint32(p.From.Reg), uint32(p.Reg))
			}
		} else if p.From3Type() == obj.TYPE_CONST {
			/* reg reg imm */
			/* operand order: RB, L, RA */
			l := int(c.regoff(p.GetFrom3()))
			o1 = AOP_RRR(c.opirr(p.As), uint32(l), uint32(p.To.Reg), uint32(p.From.Reg))
		} else if p.To.Type == obj.TYPE_REG {
			cr := int32(p.To.Reg)
			if REG_CR0 <= cr && cr <= REG_CR7 {
				/* cr reg reg */
				/* operand order: RA, RB, BF */
				bf := (int(p.To.Reg) & 7) << 2
				o1 = AOP_RRR(c.opirr(p.As), uint32(bf), uint32(p.From.Reg), uint32(p.Reg))
			} else if p.From.Type == obj.TYPE_CONST {
				/* reg imm */
				/* operand order: L, RT */
				l := int(c.regoff(&p.From))
				o1 = AOP_RRR(c.opirr(p.As), uint32(p.To.Reg), uint32(l), uint32(p.Reg))
			} else {
				switch p.As {
				case ACOPY, APASTECC:
					o1 = AOP_RRR(c.opirr(p.As), uint32(1), uint32(p.From.Reg), uint32(p.To.Reg))
				default:
					/* reg reg reg */
					/* operand order: RS, RB, RA */
					o1 = AOP_RRR(c.oprrr(p.As), uint32(p.From.Reg), uint32(p.To.Reg), uint32(p.Reg))
				}
			}
		}

	case 93: /* X-form instructions, 2-operands */
		if p.To.Type == obj.TYPE_CONST {
			/* imm reg */
			/* operand order: FRB, BF */
			bf := int(c.regoff(&p.To)) << 2
			o1 = AOP_RR(c.opirr(p.As), uint32(bf), uint32(p.From.Reg))
		} else if p.Reg == 0 {
			/* popcnt* r,r, X-form */
			/* operand order: RS, RA */
			o1 = AOP_RRR(c.oprrr(p.As), uint32(p.From.Reg), uint32(p.To.Reg), uint32(p.Reg))
		}

	case 94: /* Z23-form instructions, 4-operands */
		/* reg reg reg imm */
		/* operand order: RA, RB, CY, RT */
		cy := int(c.regoff(p.GetFrom3()))
		o1 = AOP_Z23I(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg), uint32(cy))

	case 96: /* VSX load, DQ-form */
		/* reg imm reg */
		/* operand order: (RA)(DQ), XT */
		dq := int16(c.regoff(&p.From))
		if (dq & 15) != 0 {
			c.ctxt.Diag("invalid offset for DQ form load/store %v", dq)
		}
		o1 = AOP_DQ(c.opload(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(dq))

	case 97: /* VSX store, DQ-form */
		/* reg imm reg */
		/* operand order: XT, (RA)(DQ) */
		dq := int16(c.regoff(&p.To))
		if (dq & 15) != 0 {
			c.ctxt.Diag("invalid offset for DQ form load/store %v", dq)
		}
		o1 = AOP_DQ(c.opstore(p.As), uint32(p.From.Reg), uint32(p.To.Reg), uint32(dq))
	case 98: /* VSX indexed load or load with length (also left-justified), x-form */
		/* vsreg, reg, reg */
		o1 = AOP_XX1(c.opload(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg))
	case 99: /* VSX store with length (also left-justified) x-form */
		/* reg, reg, vsreg */
		o1 = AOP_XX1(c.opstore(p.As), uint32(p.From.Reg), uint32(p.Reg), uint32(p.To.Reg))
	case 100: /* VSX X-form XXSPLTIB */
		if p.From.Type == obj.TYPE_CONST {
			/* imm reg */
			uim := int(c.regoff(&p.From))
			/* imm reg */
			/* Use AOP_XX1 form with 0 for one of the registers. */
			o1 = AOP_XX1(c.oprrr(p.As), uint32(p.To.Reg), uint32(0), uint32(uim))
		} else {
			c.ctxt.Diag("invalid ops for %v", p.As)
		}
	case 101:
		o1 = AOP_XX2(c.oprrr(p.As), uint32(p.To.Reg), uint32(0), uint32(p.From.Reg))

	case 104: /* VSX mtvsr* instructions, XX1-form RA,RB,XT */
		o1 = AOP_XX1(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg))

	case 106: /* MOVD spr, soreg */
		v := int32(p.From.Reg)
		o1 = OPVCC(31, 339, 0, 0) /* mfspr */
		o1 = AOP_RRR(o1, uint32(REGTMP), 0, 0) | (uint32(v)&0x1f)<<16 | ((uint32(v)>>5)&0x1f)<<11
		so := c.regoff(&p.To)
		o2 = AOP_IRR(c.opstore(AMOVD), uint32(REGTMP), uint32(p.To.Reg), uint32(so))
		if so&0x3 != 0 {
			log.Fatalf("invalid offset for DS form load/store %v", p)
		}
		if p.To.Reg == REGTMP {
			log.Fatalf("SPR move to memory will clobber R31 %v", p)
		}

	case 107: /* MOVD soreg, spr */
		v := int32(p.From.Reg)
		so := c.regoff(&p.From)
		o1 = AOP_IRR(c.opload(AMOVD), uint32(REGTMP), uint32(v), uint32(so))
		o2 = OPVCC(31, 467, 0, 0) /* mtspr */
		v = int32(p.To.Reg)
		o2 = AOP_RRR(o2, uint32(REGTMP), 0, 0) | (uint32(v)&0x1f)<<16 | ((uint32(v)>>5)&0x1f)<<11
		if so&0x3 != 0 {
			log.Fatalf("invalid offset for DS form load/store %v", p)
		}

	case 108: /* mov r, xoreg ==> stwx rx,ry */
		r := int(p.To.Reg)
		o1 = AOP_RRR(c.opstorex(p.As), uint32(p.From.Reg), uint32(p.To.Index), uint32(r))

	case 109: /* mov xoreg, r ==> lbzx/lhzx/lwzx rx,ry, lbzx rx,ry + extsb r,r */
		r := int(p.From.Reg)

		o1 = AOP_RRR(c.oploadx(p.As), uint32(p.To.Reg), uint32(p.From.Index), uint32(r))
		// Sign extend MOVB operations. This is ignored for other cases (o.size == 4).
		o2 = LOP_RRR(OP_EXTSB, uint32(p.To.Reg), uint32(p.To.Reg), 0)

	case 110: /* SETB creg, rt */
		bfa := uint32(p.From.Reg) << 2
		rt := uint32(p.To.Reg)
		o1 = LOP_RRR(OP_SETB, bfa, rt, 0)
	}

	out[0] = o1
	out[1] = o2
	out[2] = o3
	out[3] = o4
	out[4] = o5
}

func (c *ctxt9) vregoff(a *obj.Addr) int64 {
	c.instoffset = 0
	if a != nil {
		c.aclass(a)
	}
	return c.instoffset
}

func (c *ctxt9) regoff(a *obj.Addr) int32 {
	return int32(c.vregoff(a))
}

func (c *ctxt9) oprrr(a obj.As) uint32 {
	switch a {
	case AADD:
		return OPVCC(31, 266, 0, 0)
	case AADDCC:
		return OPVCC(31, 266, 0, 1)
	case AADDV:
		return OPVCC(31, 266, 1, 0)
	case AADDVCC:
		return OPVCC(31, 266, 1, 1)
	case AADDC:
		return OPVCC(31, 10, 0, 0)
	case AADDCCC:
		return OPVCC(31, 10, 0, 1)
	case AADDCV:
		return OPVCC(31, 10, 1, 0)
	case AADDCVCC:
		return OPVCC(31, 10, 1, 1)
	case AADDE:
		return OPVCC(31, 138, 0, 0)
	case AADDECC:
		return OPVCC(31, 138, 0, 1)
	case AADDEV:
		return OPVCC(31, 138, 1, 0)
	case AADDEVCC:
		return OPVCC(31, 138, 1, 1)
	case AADDME:
		return OPVCC(31, 234, 0, 0)
	case AADDMECC:
		return OPVCC(31, 234, 0, 1)
	case AADDMEV:
		return OPVCC(31, 234, 1, 0)
	case AADDMEVCC:
		return OPVCC(31, 234, 1, 1)
	case AADDZE:
		return OPVCC(31, 202, 0, 0)
	case AADDZECC:
		return OPVCC(31, 202, 0, 1)
	case AADDZEV:
		return OPVCC(31, 202, 1, 0)
	case AADDZEVCC:
		return OPVCC(31, 202, 1, 1)
	case AADDEX:
		return OPVCC(31, 170, 0, 0) /* addex - v3.0b */

	case AAND:
		return OPVCC(31, 28, 0, 0)
	case AANDCC:
		return OPVCC(31, 28, 0, 1)
	case AANDN:
		return OPVCC(31, 60, 0, 0)
	case AANDNCC:
		return OPVCC(31, 60, 0, 1)

	case ACMP:
		return OPVCC(31, 0, 0, 0) | 1<<21 /* L=1 */
	case ACMPU:
		return OPVCC(31, 32, 0, 0) | 1<<21
	case ACMPW:
		return OPVCC(31, 0, 0, 0) /* L=0 */
	case ACMPWU:
		return OPVCC(31, 32, 0, 0)
	case ACMPB:
		return OPVCC(31, 508, 0, 0) /* cmpb - v2.05 */
	case ACMPEQB:
		return OPVCC(31, 224, 0, 0) /* cmpeqb - v3.00 */

	case ACNTLZW:
		return OPVCC(31, 26, 0, 0)
	case ACNTLZWCC:
		return OPVCC(31, 26, 0, 1)
	case ACNTLZD:
		return OPVCC(31, 58, 0, 0)
	case ACNTLZDCC:
		return OPVCC(31, 58, 0, 1)

	case ACRAND:
		return OPVCC(19, 257, 0, 0)
	case ACRANDN:
		return OPVCC(19, 129, 0, 0)
	case ACREQV:
		return OPVCC(19, 289, 0, 0)
	case ACRNAND:
		return OPVCC(19, 225, 0, 0)
	case ACRNOR:
		return OPVCC(19, 33, 0, 0)
	case ACROR:
		return OPVCC(19, 449, 0, 0)
	case ACRORN:
		return OPVCC(19, 417, 0, 0)
	case ACRXOR:
		return OPVCC(19, 193, 0, 0)

	case ADADD:
		return OPVCC(59, 2, 0, 0)
	case ADDIV:
		return OPVCC(59, 546, 0, 0)
	case ADMUL:
		return OPVCC(59, 34, 0, 0)
	case ADSUB:
		return OPVCC(59, 514, 0, 0)
	case ADADDQ:
		return OPVCC(63, 2, 0, 0)
	case ADDIVQ:
		return OPVCC(63, 546, 0, 0)
	case ADMULQ:
		return OPVCC(63, 34, 0, 0)
	case ADSUBQ:
		return OPVCC(63, 514, 0, 0)
	case ADCMPU:
		return OPVCC(59, 642, 0, 0)
	case ADCMPUQ:
		return OPVCC(63, 642, 0, 0)
	case ADCMPO:
		return OPVCC(59, 130, 0, 0)
	case ADCMPOQ:
		return OPVCC(63, 130, 0, 0)

	case ADCBF:
		return OPVCC(31, 86, 0, 0)
	case ADCBI:
		return OPVCC(31, 470, 0, 0)
	case ADCBST:
		return OPVCC(31, 54, 0, 0)
	case ADCBT:
		return OPVCC(31, 278, 0, 0)
	case ADCBTST:
		return OPVCC(31, 246, 0, 0)
	case ADCBZ:
		return OPVCC(31, 1014, 0, 0)

	case AMODUD:
		return OPVCC(31, 265, 0, 0) /* modud - v3.0 */
	case AMODUW:
		return OPVCC(31, 267, 0, 0) /* moduw - v3.0 */
	case AMODSD:
		return OPVCC(31, 777, 0, 0) /* modsd - v3.0 */
	case AMODSW:
		return OPVCC(31, 779, 0, 0) /* modsw - v3.0 */

	case ADIVW, AREM:
		return OPVCC(31, 491, 0, 0)

	case ADIVWCC:
		return OPVCC(31, 491, 0, 1)

	case ADIVWV:
		return OPVCC(31, 491, 1, 0)

	case ADIVWVCC:
		return OPVCC(31, 491, 1, 1)

	case ADIVWU, AREMU:
		return OPVCC(31, 459, 0, 0)

	case ADIVWUCC:
		return OPVCC(31, 459, 0, 1)

	case ADIVWUV:
		return OPVCC(31, 459, 1, 0)

	case ADIVWUVCC:
		return OPVCC(31, 459, 1, 1)

	case ADIVD, AREMD:
		return OPVCC(31, 489, 0, 0)

	case ADIVDCC:
		return OPVCC(31, 489, 0, 1)

	case ADIVDE:
		return OPVCC(31, 425, 0, 0)

	case ADIVDECC:
		return OPVCC(31, 425, 0, 1)

	case ADIVDEU:
		return OPVCC(31, 393, 0, 0)

	case ADIVDEUCC:
		return OPVCC(31, 393, 0, 1)

	case ADIVDV:
		return OPVCC(31, 489, 1, 0)

	case ADIVDVCC:
		return OPVCC(31, 489, 1, 1)

	case ADIVDU, AREMDU:
		return OPVCC(31, 457, 0, 0)

	case ADIVDUCC:
		return OPVCC(31, 457, 0, 1)

	case ADIVDUV:
		return OPVCC(31, 457, 1, 0)

	case ADIVDUVCC:
		return OPVCC(31, 457, 1, 1)

	case AEIEIO:
		return OPVCC(31, 854, 0, 0)

	case AEQV:
		return OPVCC(31, 284, 0, 0)
	case AEQVCC:
		return OPVCC(31, 284, 0, 1)

	case AEXTSB:
		return OPVCC(31, 954, 0, 0)
	case AEXTSBCC:
		return OPVCC(31, 954, 0, 1)
	case AEXTSH:
		return OPVCC(31, 922, 0, 0)
	case AEXTSHCC:
		return OPVCC(31, 922, 0, 1)
	case AEXTSW:
		return OPVCC(31, 986, 0, 0)
	case AEXTSWCC:
		return OPVCC(31, 986, 0, 1)

	case AFABS:
		return OPVCC(63, 264, 0, 0)
	case AFABSCC:
		return OPVCC(63, 264, 0, 1)
	case AFADD:
		return OPVCC(63, 21, 0, 0)
	case AFADDCC:
		return OPVCC(63, 21, 0, 1)
	case AFADDS:
		return OPVCC(59, 21, 0, 0)
	case AFADDSCC:
		return OPVCC(59, 21, 0, 1)
	case AFCMPO:
		return OPVCC(63, 32, 0, 0)
	case AFCMPU:
		return OPVCC(63, 0, 0, 0)
	case AFCFID:
		return OPVCC(63, 846, 0, 0)
	case AFCFIDCC:
		return OPVCC(63, 846, 0, 1)
	case AFCFIDU:
		return OPVCC(63, 974, 0, 0)
	case AFCFIDUCC:
		return OPVCC(63, 974, 0, 1)
	case AFCFIDS:
		return OPVCC(59, 846, 0, 0)
	case AFCFIDSCC:
		return OPVCC(59, 846, 0, 1)
	case AFCTIW:
		return OPVCC(63, 14, 0, 0)
	case AFCTIWCC:
		return OPVCC(63, 14, 0, 1)
	case AFCTIWZ:
		return OPVCC(63, 15, 0, 0)
	case AFCTIWZCC:
		return OPVCC(63, 15, 0, 1)
	case AFCTID:
		return OPVCC(63, 814, 0, 0)
	case AFCTIDCC:
		return OPVCC(63, 814, 0, 1)
	case AFCTIDZ:
		return OPVCC(63, 815, 0, 0)
	case AFCTIDZCC:
		return OPVCC(63, 815, 0, 1)
	case AFDIV:
		return OPVCC(63, 18, 0, 0)
	case AFDIVCC:
		return OPVCC(63, 18, 0, 1)
	case AFDIVS:
		return OPVCC(59, 18, 0, 0)
	case AFDIVSCC:
		return OPVCC(59, 18, 0, 1)
	case AFMADD:
		return OPVCC(63, 29, 0, 0)
	case AFMADDCC:
		return OPVCC(63, 29, 0, 1)
	case AFMADDS:
		return OPVCC(59, 29, 0, 0)
	case AFMADDSCC:
		return OPVCC(59, 29, 0, 1)

	case AFMOVS, AFMOVD:
		return OPVCC(63, 72, 0, 0) /* load */
	case AFMOVDCC:
		return OPVCC(63, 72, 0, 1)
	case AFMSUB:
		return OPVCC(63, 28, 0, 0)
	case AFMSUBCC:
		return OPVCC(63, 28, 0, 1)
	case AFMSUBS:
		return OPVCC(59, 28, 0, 0)
	case AFMSUBSCC:
		return OPVCC(59, 28, 0, 1)
	case AFMUL:
		return OPVCC(63, 25, 0, 0)
	case AFMULCC:
		return OPVCC(63, 25, 0, 1)
	case AFMULS:
		return OPVCC(59, 25, 0, 0)
	case AFMULSCC:
		return OPVCC(59, 25, 0, 1)
	case AFNABS:
		return OPVCC(63, 136, 0, 0)
	case AFNABSCC:
		return OPVCC(63, 136, 0, 1)
	case AFNEG:
		return OPVCC(63, 40, 0, 0)
	case AFNEGCC:
		return OPVCC(63, 40, 0, 1)
	case AFNMADD:
		return OPVCC(63, 31, 0, 0)
	case AFNMADDCC:
		return OPVCC(63, 31, 0, 1)
	case AFNMADDS:
		return OPVCC(59, 31, 0, 0)
	case AFNMADDSCC:
		return OPVCC(59, 31, 0, 1)
	case AFNMSUB:
		return OPVCC(63, 30, 0, 0)
	case AFNMSUBCC:
		return OPVCC(63, 30, 0, 1)
	case AFNMSUBS:
		return OPVCC(59, 30, 0, 0)
	case AFNMSUBSCC:
		return OPVCC(59, 30, 0, 1)
	case AFCPSGN:
		return OPVCC(63, 8, 0, 0)
	case AFCPSGNCC:
		return OPVCC(63, 8, 0, 1)
	case AFRES:
		return OPVCC(59, 24, 0, 0)
	case AFRESCC:
		return OPVCC(59, 24, 0, 1)
	case AFRIM:
		return OPVCC(63, 488, 0, 0)
	case AFRIMCC:
		return OPVCC(63, 488, 0, 1)
	case AFRIP:
		return OPVCC(63, 456, 0, 0)
	case AFRIPCC:
		return OPVCC(63, 456, 0, 1)
	case AFRIZ:
		return OPVC
```