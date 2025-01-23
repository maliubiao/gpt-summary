Response: The user wants to understand the functionality of the provided Go code snippet, which is part of the assembler for the s390x architecture in the Go compiler.

To achieve this, I need to:

1. **Identify the core function:** The code is a large `switch` statement handling different assembly opcodes (`p.As`). This suggests it's responsible for translating Go assembly instructions into machine code.
2. **Analyze each case:**  Each `case` corresponds to a specific assembly instruction or a group of related instructions. I need to understand what each instruction does in terms of registers, memory, and operations.
3. **Infer the overall purpose:** Based on the individual instruction handling, I can deduce the broader role of this code within the Go compiler.
4. **Provide examples:** Where possible, I should give Go code snippets that would result in the generation of these assembly instructions. This will help illustrate the connection between Go code and the low-level assembly.
5. **Address specific points:** The user asked about reasoning, examples, input/output, command-line arguments (though this part of the code doesn't seem to directly handle them), and common mistakes. I'll focus on the functionalities and potential inferences.
6. **Summarize the functionality:**  Finally, I need to synthesize the information into a concise summary.

**High-level plan:**

- Go through each `case` in the `switch` statement.
- For each case, describe the corresponding assembly instruction's purpose.
- If possible, provide a simple Go code example that would generate such an instruction.
- Note any assumptions made during the inference process.
- Avoid speculating on command-line arguments since the code doesn't show that.
- Summarize the overall functionality.
这是 `go/src/cmd/internal/obj/s390x/asmz.go` 文件的第三部分，它延续了前两部分的工作，负责将 s390x 架构的 Go 汇编指令转换为机器码。

**归纳一下它的功能：**

这部分代码主要负责处理 `asmz.scond()` 函数中 `switch p.Type` 为 1 到 126 的各种汇编指令。它根据不同的指令类型和操作数，调用相应的 `z...` 函数来生成对应的机器码字节。这些 `z...` 函数根据指令格式（如 RR, RX, RXY, RI 等）和操作数类型，将操作码和操作数编码到字节数组 `asm` 中。

**具体功能分解：**

这部分代码涵盖了大量的 s390x 汇编指令，可以大致分类为以下功能：

* **算术运算指令 (Arithmetic Operations):** 包括加法 (ADD, ADDW, ADDC)，减法 (SUB, SUBW, SUBC, SUBE)，乘法 (MULLW, MULLD)。
* **逻辑运算指令 (Logical Operations):** 包括与 (AND, ANDW)，或 (OR, ORW)，异或 (XOR, XORW)。
* **位操作指令 (Bit Manipulation):** 包括各种旋转和移位操作 (RNSBG, RXSBG, ROSBG, RISBG)。
* **分支指令 (Branch Instructions):**  包括无条件跳转 (BR, BL)，条件跳转 (BRC, BRCL)，基于寄存器的跳转 (BCR, BASR)，以及各种比较并跳转指令 (CRJ, CGRJ, CLRJ, CLGRJ, CIJ, CGIJ, CLIJ, CLGIJ)。
* **数据移动指令 (Data Movement Instructions):** 包括寄存器之间的数据移动 (LGR, LR, EAR, SAR)，立即数加载到寄存器 (LGFI, AFI, MVGHI, MVHI, MVHHI, MVI)，内存到寄存器 (LG, LGF, LLGF, LGH, LLGH, LGB, LLGC, LD, LE)，寄存器到内存 (STG, STY, STHY, STCY, STD, STE)，以及条件移动指令 (LOCGR)。
* **比较指令 (Comparison Instructions):** 包括寄存器与寄存器比较 (CGR, CLGR, CR, CLR)，寄存器与立即数比较 (CGHI, CLGFI, CHI, CLFI)。
* **浮点运算指令 (Floating-point Operations):** 包括浮点数加减乘除 (ADBR, AEBR, DDBR, DEBR, MDBR, MEEBR, SDBR, SEBR)，绝对值 (LPDBR, LNDBR)，取反 (LCDFR, LCEBR)，加载 (LEDBR, LDEBR)，平方根 (SQDBR, SQEBR)，乘加/乘减 (MADBR, MAEBR, MSDBR, MSEBR)，以及浮点数转换指令 (CEFBRA, CDFBRA, CEGBRA, CDGBRA, CELFBR, CDLFBR, CELGBR, CDLGBR, CFEBRA, CFDBRA, CGEBRA, CGDBRA, CLFEBR, CLFDBR, CLGEBR, CLGDBR)。
* **向量寄存器操作指令 (Vector Register Operations):**  包括向量的加载、存储、算术运算、逻辑运算、比较、移位、旋转等各种指令 (例如 VRX, VRV, VRS, VRRa, VRRb, VRRc, VRRd, VRRe, VRIa, VRIb, VRIc, VRId, VRIe)。
* **其他指令:** 包括系统调用 (SVC)，设置程序掩码 (SPM)，插入程序掩码 (IPM)，比较和交换 (CS, CSG)，存储时钟 (STCK, STCKC, STCKE, STCKF)，以及用于加密和解密的指令 (KM, KMC, KLMD, KIMD, KDSA, KMA, KMCTR)。

**可以推理出它是什么 Go 语言功能的实现：**

这部分代码是 Go 编译器中将 s390x 架构的汇编代码转换为机器码的核心部分。当 Go 代码被编译时，编译器会将部分操作转换为汇编指令，而 `asmz.go` 中的代码则负责将这些汇编指令翻译成 CPU 可以执行的二进制代码。

**Go 代码举例说明：**

假设我们有以下简单的 Go 代码：

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	x := 10
	y := 20
	z := add(x, y)
	_ = z
}
```

编译这段代码后，`add` 函数可能会生成类似以下的 s390x 汇编指令 (简化版，实际可能更复杂)：

```assembly
// 在 s390x 架构上，参数通常通过寄存器传递
MOVQ a, R3 // 假设 a 在寄存器中
MOVQ b, R4 // 假设 b 在寄存器中
ADD  R3, R4  // 将 R4 的值加到 R3
MOVQ R3, ret // 将结果移动到返回寄存器
```

`asmz.go` 的这部分代码就会处理 `ADD R3, R4` 这条指令。根据 `p.As` (在这里是 `AADD`)，代码会进入相应的 `case AADD:` 分支，并根据操作数 (R3 和 R4) 调用 `zRR(op_AGR, uint32(p.From.Reg), uint32(p.To.Reg), asm)` 或类似的函数来生成 `ADD` 指令的机器码。

**带上假设的输入与输出的推理：**

假设输入的汇编指令结构 `p` 代表 `ADD R3, R4`：

* `p.As = AADD`
* `p.To.Type = obj.TYPE_REG`, `p.To.Reg = REG_R3`
* `p.From.Type = obj.TYPE_REG`, `p.From.Reg = REG_R4`

输出 (追加到 `asm` 字节数组) 将是 `ADD` 指令对应的机器码。查阅 s390x 指令集手册，`AGR` 指令 (Add Logical Register) 的操作码是 `0x1A`，假设 R3 对应机器码 `0x3`，R4 对应 `0x4`，那么 `zRR(op_AGR, 3, 4, asm)` 会将 `0x1A34` 追加到 `asm`。

**涉及命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。命令行参数的处理通常在 Go 编译器的其他部分，例如 `go tool compile` 的入口点。这些参数会影响编译过程，例如选择目标架构、优化级别等，但具体的汇编指令到机器码的翻译过程是由 `asmz.go` 这样的文件负责。

**功能总结:**

总而言之，`go/src/cmd/internal/obj/s390x/asmz.go` 的这部分代码是 Go 编译器中 s390x 架构汇编器的一个关键组成部分，负责将抽象的汇编指令转换为可以直接在 s390x 处理器上执行的二进制机器码。它通过一个庞大的 `switch` 结构，针对不同的指令类型进行特定的编码处理，确保了 Go 语言程序能够正确地编译并在 s390x 架构上运行。

### 提示词
```
这是路径为go/src/cmd/internal/obj/s390x/asmz.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
case AADDW:
			opx = op_A
			opxy = op_AY
		case AMULLW:
			opx = op_MS
			opxy = op_MSY
		case AMULLD:
			opxy = op_MSG
		case ASUB:
			opxy = op_SG
		case ASUBC:
			opxy = op_SLG
		case ASUBE:
			opxy = op_SLBG
		case ASUBW:
			opx = op_S
			opxy = op_SY
		case AAND:
			opxy = op_NG
		case AANDW:
			opx = op_N
			opxy = op_NY
		case AOR:
			opxy = op_OG
		case AORW:
			opx = op_O
			opxy = op_OY
		case AXOR:
			opxy = op_XG
		case AXORW:
			opx = op_X
			opxy = op_XY
		}
		if opx != 0 && 0 <= d2 && d2 < DISP12 {
			zRX(opx, uint32(r1), uint32(x2), uint32(b2), uint32(d2), asm)
		} else {
			zRXY(opxy, uint32(r1), uint32(x2), uint32(b2), uint32(d2), asm)
		}

	case 13: // rotate, followed by operation
		r1 := p.To.Reg
		r2 := p.RestArgs[2].Reg
		i3 := uint8(p.From.Offset)        // start
		i4 := uint8(p.RestArgs[0].Offset) // end
		i5 := uint8(p.RestArgs[1].Offset) // rotate amount
		switch p.As {
		case ARNSBGT, ARXSBGT, AROSBGT:
			i3 |= 0x80 // test-results
		case ARISBGZ, ARISBGNZ, ARISBHGZ, ARISBLGZ:
			i4 |= 0x80 // zero-remaining-bits
		}
		var opcode uint32
		switch p.As {
		case ARNSBG, ARNSBGT:
			opcode = op_RNSBG
		case ARXSBG, ARXSBGT:
			opcode = op_RXSBG
		case AROSBG, AROSBGT:
			opcode = op_ROSBG
		case ARISBG, ARISBGZ:
			opcode = op_RISBG
		case ARISBGN, ARISBGNZ:
			opcode = op_RISBGN
		case ARISBHG, ARISBHGZ:
			opcode = op_RISBHG
		case ARISBLG, ARISBLGZ:
			opcode = op_RISBLG
		}
		zRIE(_f, uint32(opcode), uint32(r1), uint32(r2), 0, uint32(i3), uint32(i4), 0, uint32(i5), asm)

	case 15: // br/bl (reg)
		r := p.To.Reg
		if p.As == ABCL || p.As == ABL {
			zRR(op_BASR, uint32(REG_LR), uint32(r), asm)
		} else {
			zRR(op_BCR, uint32(Always), uint32(r), asm)
		}

	case 16: // conditional branch
		v := int32(0)
		if p.To.Target() != nil {
			v = int32((p.To.Target().Pc - p.Pc) >> 1)
		}
		mask := uint32(c.branchMask(p))
		if p.To.Sym == nil && int32(int16(v)) == v {
			zRI(op_BRC, mask, uint32(v), asm)
		} else {
			zRIL(_c, op_BRCL, mask, uint32(v), asm)
		}
		if p.To.Sym != nil {
			c.addrilreloc(p.To.Sym, p.To.Offset)
		}

	case 17: // move on condition
		m3 := uint32(c.branchMask(p))
		zRRF(op_LOCGR, m3, 0, uint32(p.To.Reg), uint32(p.From.Reg), asm)

	case 18: // br/bl reg
		if p.As == ABL {
			zRR(op_BASR, uint32(REG_LR), uint32(p.To.Reg), asm)
		} else {
			zRR(op_BCR, uint32(Always), uint32(p.To.Reg), asm)
		}

	case 19: // mov $sym+n(SB) reg
		d := c.vregoff(&p.From)
		zRIL(_b, op_LARL, uint32(p.To.Reg), 0, asm)
		if d&1 != 0 {
			zRX(op_LA, uint32(p.To.Reg), uint32(p.To.Reg), 0, 1, asm)
			d -= 1
		}
		c.addrilreloc(p.From.Sym, d)

	case 21: // subtract $constant [reg] reg
		v := c.vregoff(&p.From)
		r := p.Reg
		if r == 0 {
			r = p.To.Reg
		}
		switch p.As {
		case ASUB:
			zRIL(_a, op_LGFI, uint32(regtmp(p)), uint32(v), asm)
			zRRF(op_SLGRK, uint32(regtmp(p)), 0, uint32(p.To.Reg), uint32(r), asm)
		case ASUBC:
			if r != p.To.Reg {
				zRRE(op_LGR, uint32(p.To.Reg), uint32(r), asm)
			}
			zRIL(_a, op_SLGFI, uint32(p.To.Reg), uint32(v), asm)
		case ASUBW:
			if r != p.To.Reg {
				zRR(op_LR, uint32(p.To.Reg), uint32(r), asm)
			}
			zRIL(_a, op_SLFI, uint32(p.To.Reg), uint32(v), asm)
		}

	case 22: // add/multiply $constant [reg] reg
		v := c.vregoff(&p.From)
		r := p.Reg
		if r == 0 {
			r = p.To.Reg
		}
		var opri, opril, oprie uint32
		switch p.As {
		case AADD:
			opri = op_AGHI
			opril = op_AGFI
			oprie = op_AGHIK
		case AADDC:
			opril = op_ALGFI
			oprie = op_ALGHSIK
		case AADDW:
			opri = op_AHI
			opril = op_AFI
			oprie = op_AHIK
		case AMULLW:
			opri = op_MHI
			opril = op_MSFI
		case AMULLD:
			opri = op_MGHI
			opril = op_MSGFI
		}
		if r != p.To.Reg && (oprie == 0 || int64(int16(v)) != v) {
			switch p.As {
			case AADD, AADDC, AMULLD:
				zRRE(op_LGR, uint32(p.To.Reg), uint32(r), asm)
			case AADDW, AMULLW:
				zRR(op_LR, uint32(p.To.Reg), uint32(r), asm)
			}
			r = p.To.Reg
		}
		if opri != 0 && r == p.To.Reg && int64(int16(v)) == v {
			zRI(opri, uint32(p.To.Reg), uint32(v), asm)
		} else if oprie != 0 && int64(int16(v)) == v {
			zRIE(_d, oprie, uint32(p.To.Reg), uint32(r), uint32(v), 0, 0, 0, 0, asm)
		} else {
			zRIL(_a, opril, uint32(p.To.Reg), uint32(v), asm)
		}

	case 23: // 64-bit logical op $constant reg
		// TODO(mundaym): merge with case 24.
		v := c.vregoff(&p.From)
		switch p.As {
		default:
			c.ctxt.Diag("%v is not supported", p)
		case AAND:
			if v >= 0 { // needs zero extend
				zRIL(_a, op_LGFI, regtmp(p), uint32(v), asm)
				zRRE(op_NGR, uint32(p.To.Reg), regtmp(p), asm)
			} else if int64(int16(v)) == v {
				zRI(op_NILL, uint32(p.To.Reg), uint32(v), asm)
			} else { //  r.To.Reg & 0xffffffff00000000 & uint32(v)
				zRIL(_a, op_NILF, uint32(p.To.Reg), uint32(v), asm)
			}
		case AOR:
			if int64(uint32(v)) != v { // needs sign extend
				zRIL(_a, op_LGFI, regtmp(p), uint32(v), asm)
				zRRE(op_OGR, uint32(p.To.Reg), regtmp(p), asm)
			} else if int64(uint16(v)) == v {
				zRI(op_OILL, uint32(p.To.Reg), uint32(v), asm)
			} else {
				zRIL(_a, op_OILF, uint32(p.To.Reg), uint32(v), asm)
			}
		case AXOR:
			if int64(uint32(v)) != v { // needs sign extend
				zRIL(_a, op_LGFI, regtmp(p), uint32(v), asm)
				zRRE(op_XGR, uint32(p.To.Reg), regtmp(p), asm)
			} else {
				zRIL(_a, op_XILF, uint32(p.To.Reg), uint32(v), asm)
			}
		}

	case 24: // 32-bit logical op $constant reg
		v := c.vregoff(&p.From)
		switch p.As {
		case AANDW:
			if uint32(v&0xffff0000) == 0xffff0000 {
				zRI(op_NILL, uint32(p.To.Reg), uint32(v), asm)
			} else if uint32(v&0x0000ffff) == 0x0000ffff {
				zRI(op_NILH, uint32(p.To.Reg), uint32(v)>>16, asm)
			} else {
				zRIL(_a, op_NILF, uint32(p.To.Reg), uint32(v), asm)
			}
		case AORW:
			if uint32(v&0xffff0000) == 0 {
				zRI(op_OILL, uint32(p.To.Reg), uint32(v), asm)
			} else if uint32(v&0x0000ffff) == 0 {
				zRI(op_OILH, uint32(p.To.Reg), uint32(v)>>16, asm)
			} else {
				zRIL(_a, op_OILF, uint32(p.To.Reg), uint32(v), asm)
			}
		case AXORW:
			zRIL(_a, op_XILF, uint32(p.To.Reg), uint32(v), asm)
		}

	case 25: // load on condition (register)
		m3 := uint32(c.branchMask(p))
		var opcode uint32
		switch p.As {
		case ALOCR:
			opcode = op_LOCR
		case ALOCGR:
			opcode = op_LOCGR
		}
		zRRF(opcode, m3, 0, uint32(p.To.Reg), uint32(p.Reg), asm)

	case 26: // MOVD $offset(base)(index), reg
		v := c.regoff(&p.From)
		r := p.From.Reg
		if r == 0 {
			r = REGSP
		}
		i := p.From.Index
		if v >= 0 && v < DISP12 {
			zRX(op_LA, uint32(p.To.Reg), uint32(r), uint32(i), uint32(v), asm)
		} else if v >= -DISP20/2 && v < DISP20/2 {
			zRXY(op_LAY, uint32(p.To.Reg), uint32(r), uint32(i), uint32(v), asm)
		} else {
			zRIL(_a, op_LGFI, regtmp(p), uint32(v), asm)
			zRX(op_LA, uint32(p.To.Reg), uint32(r), regtmp(p), uint32(i), asm)
		}

	case 31: // dword
		wd := uint64(c.vregoff(&p.From))
		*asm = append(*asm,
			uint8(wd>>56),
			uint8(wd>>48),
			uint8(wd>>40),
			uint8(wd>>32),
			uint8(wd>>24),
			uint8(wd>>16),
			uint8(wd>>8),
			uint8(wd))

	case 32: // float op freg freg
		var opcode uint32
		switch p.As {
		default:
			c.ctxt.Diag("invalid opcode")
		case AFADD:
			opcode = op_ADBR
		case AFADDS:
			opcode = op_AEBR
		case AFDIV:
			opcode = op_DDBR
		case AFDIVS:
			opcode = op_DEBR
		case AFMUL:
			opcode = op_MDBR
		case AFMULS:
			opcode = op_MEEBR
		case AFSUB:
			opcode = op_SDBR
		case AFSUBS:
			opcode = op_SEBR
		}
		zRRE(opcode, uint32(p.To.Reg), uint32(p.From.Reg), asm)

	case 33: // float op [freg] freg
		r := p.From.Reg
		if oclass(&p.From) == C_NONE {
			r = p.To.Reg
		}
		var opcode uint32
		switch p.As {
		default:
		case AFABS:
			opcode = op_LPDBR
		case AFNABS:
			opcode = op_LNDBR
		case ALPDFR:
			opcode = op_LPDFR
		case ALNDFR:
			opcode = op_LNDFR
		case AFNEG:
			opcode = op_LCDFR
		case AFNEGS:
			opcode = op_LCEBR
		case ALEDBR:
			opcode = op_LEDBR
		case ALDEBR:
			opcode = op_LDEBR
		case AFSQRT:
			opcode = op_SQDBR
		case AFSQRTS:
			opcode = op_SQEBR
		}
		zRRE(opcode, uint32(p.To.Reg), uint32(r), asm)

	case 34: // float multiply-add freg freg freg
		var opcode uint32
		switch p.As {
		default:
			c.ctxt.Diag("invalid opcode")
		case AFMADD:
			opcode = op_MADBR
		case AFMADDS:
			opcode = op_MAEBR
		case AFMSUB:
			opcode = op_MSDBR
		case AFMSUBS:
			opcode = op_MSEBR
		}
		zRRD(opcode, uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg), asm)

	case 35: // mov reg mem (no relocation)
		d2 := c.regoff(&p.To)
		b2 := p.To.Reg
		if b2 == 0 {
			b2 = REGSP
		}
		x2 := p.To.Index
		if d2 < -DISP20/2 || d2 >= DISP20/2 {
			zRIL(_a, op_LGFI, regtmp(p), uint32(d2), asm)
			if x2 != 0 {
				zRX(op_LA, regtmp(p), regtmp(p), uint32(x2), 0, asm)
			}
			x2 = int16(regtmp(p))
			d2 = 0
		}
		// Emits an RX instruction if an appropriate one exists and the displacement fits in 12 bits. Otherwise use an RXY instruction.
		if op, ok := c.zopstore12(p.As); ok && isU12(d2) {
			zRX(op, uint32(p.From.Reg), uint32(x2), uint32(b2), uint32(d2), asm)
		} else {
			zRXY(c.zopstore(p.As), uint32(p.From.Reg), uint32(x2), uint32(b2), uint32(d2), asm)
		}

	case 36: // mov mem reg (no relocation)
		d2 := c.regoff(&p.From)
		b2 := p.From.Reg
		if b2 == 0 {
			b2 = REGSP
		}
		x2 := p.From.Index
		if d2 < -DISP20/2 || d2 >= DISP20/2 {
			zRIL(_a, op_LGFI, regtmp(p), uint32(d2), asm)
			if x2 != 0 {
				zRX(op_LA, regtmp(p), regtmp(p), uint32(x2), 0, asm)
			}
			x2 = int16(regtmp(p))
			d2 = 0
		}
		// Emits an RX instruction if an appropriate one exists and the displacement fits in 12 bits. Otherwise use an RXY instruction.
		if op, ok := c.zopload12(p.As); ok && isU12(d2) {
			zRX(op, uint32(p.To.Reg), uint32(x2), uint32(b2), uint32(d2), asm)
		} else {
			zRXY(c.zopload(p.As), uint32(p.To.Reg), uint32(x2), uint32(b2), uint32(d2), asm)
		}

	case 40: // word/byte
		wd := uint32(c.regoff(&p.From))
		if p.As == AWORD { //WORD
			*asm = append(*asm, uint8(wd>>24), uint8(wd>>16), uint8(wd>>8), uint8(wd))
		} else { //BYTE
			*asm = append(*asm, uint8(wd))
		}

	case 41: // branch on count
		r1 := p.From.Reg
		ri2 := (p.To.Target().Pc - p.Pc) >> 1
		if int64(int16(ri2)) != ri2 {
			c.ctxt.Diag("branch target too far away")
		}
		var opcode uint32
		switch p.As {
		case ABRCT:
			opcode = op_BRCT
		case ABRCTG:
			opcode = op_BRCTG
		}
		zRI(opcode, uint32(r1), uint32(ri2), asm)

	case 47: // negate [reg] reg
		r := p.From.Reg
		if r == 0 {
			r = p.To.Reg
		}
		switch p.As {
		case ANEG:
			zRRE(op_LCGR, uint32(p.To.Reg), uint32(r), asm)
		case ANEGW:
			zRRE(op_LCGFR, uint32(p.To.Reg), uint32(r), asm)
		}

	case 48: // floating-point round to integer
		m3 := c.vregoff(&p.From)
		if 0 > m3 || m3 > 7 {
			c.ctxt.Diag("mask (%v) must be in the range [0, 7]", m3)
		}
		var opcode uint32
		switch p.As {
		case AFIEBR:
			opcode = op_FIEBR
		case AFIDBR:
			opcode = op_FIDBR
		}
		zRRF(opcode, uint32(m3), 0, uint32(p.To.Reg), uint32(p.Reg), asm)

	case 49: // copysign
		zRRF(op_CPSDR, uint32(p.From.Reg), 0, uint32(p.To.Reg), uint32(p.Reg), asm)

	case 50: // load and test
		var opcode uint32
		switch p.As {
		case ALTEBR:
			opcode = op_LTEBR
		case ALTDBR:
			opcode = op_LTDBR
		}
		zRRE(opcode, uint32(p.To.Reg), uint32(p.From.Reg), asm)

	case 51: // test data class (immediate only)
		var opcode uint32
		switch p.As {
		case ATCEB:
			opcode = op_TCEB
		case ATCDB:
			opcode = op_TCDB
		}
		d2 := c.regoff(&p.To)
		zRXE(opcode, uint32(p.From.Reg), 0, 0, uint32(d2), 0, asm)

	case 62: // equivalent of Mul64 in math/bits
		zRRE(op_MLGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)

	case 66:
		zRR(op_BCR, uint32(Never), 0, asm)

	case 67: // fmov $0 freg
		var opcode uint32
		switch p.As {
		case AFMOVS:
			opcode = op_LZER
		case AFMOVD:
			opcode = op_LZDR
		}
		zRRE(opcode, uint32(p.To.Reg), 0, asm)

	case 68: // movw areg reg
		zRRE(op_EAR, uint32(p.To.Reg), uint32(p.From.Reg-REG_AR0), asm)

	case 69: // movw reg areg
		zRRE(op_SAR, uint32(p.To.Reg-REG_AR0), uint32(p.From.Reg), asm)

	case 70: // cmp reg reg
		if p.As == ACMPW || p.As == ACMPWU {
			zRR(c.zoprr(p.As), uint32(p.From.Reg), uint32(p.To.Reg), asm)
		} else {
			zRRE(c.zoprre(p.As), uint32(p.From.Reg), uint32(p.To.Reg), asm)
		}

	case 71: // cmp reg $constant
		v := c.vregoff(&p.To)
		switch p.As {
		case ACMP, ACMPW:
			if int64(int32(v)) != v {
				c.ctxt.Diag("%v overflows an int32", v)
			}
		case ACMPU, ACMPWU:
			if int64(uint32(v)) != v {
				c.ctxt.Diag("%v overflows a uint32", v)
			}
		}
		if p.As == ACMP && int64(int16(v)) == v {
			zRI(op_CGHI, uint32(p.From.Reg), uint32(v), asm)
		} else if p.As == ACMPW && int64(int16(v)) == v {
			zRI(op_CHI, uint32(p.From.Reg), uint32(v), asm)
		} else {
			zRIL(_a, c.zopril(p.As), uint32(p.From.Reg), uint32(v), asm)
		}

	case 72: // mov $constant mem
		v := c.regoff(&p.From)
		d := c.regoff(&p.To)
		r := p.To.Reg
		if p.To.Index != 0 {
			c.ctxt.Diag("cannot use index register")
		}
		if r == 0 {
			r = REGSP
		}
		var opcode uint32
		switch p.As {
		case AMOVD:
			opcode = op_MVGHI
		case AMOVW, AMOVWZ:
			opcode = op_MVHI
		case AMOVH, AMOVHZ:
			opcode = op_MVHHI
		case AMOVB, AMOVBZ:
			opcode = op_MVI
		}
		if d < 0 || d >= DISP12 {
			if r == int16(regtmp(p)) {
				c.ctxt.Diag("displacement must be in range [0, 4096) to use %v", r)
			}
			if d >= -DISP20/2 && d < DISP20/2 {
				if opcode == op_MVI {
					opcode = op_MVIY
				} else {
					zRXY(op_LAY, uint32(regtmp(p)), 0, uint32(r), uint32(d), asm)
					r = int16(regtmp(p))
					d = 0
				}
			} else {
				zRIL(_a, op_LGFI, regtmp(p), uint32(d), asm)
				zRX(op_LA, regtmp(p), regtmp(p), uint32(r), 0, asm)
				r = int16(regtmp(p))
				d = 0
			}
		}
		switch opcode {
		case op_MVI:
			zSI(opcode, uint32(v), uint32(r), uint32(d), asm)
		case op_MVIY:
			zSIY(opcode, uint32(v), uint32(r), uint32(d), asm)
		default:
			zSIL(opcode, uint32(r), uint32(d), uint32(v), asm)
		}

	case 73: //Illegal opcode with SIGTRAP Exception
		zE(op_BRRK, asm)

	case 74: // mov reg addr (including relocation)
		i2 := c.regoff(&p.To)
		switch p.As {
		case AMOVD:
			zRIL(_b, op_STGRL, uint32(p.From.Reg), 0, asm)
		case AMOVW, AMOVWZ: // The zero extension doesn't affect store instructions
			zRIL(_b, op_STRL, uint32(p.From.Reg), 0, asm)
		case AMOVH, AMOVHZ: // The zero extension doesn't affect store instructions
			zRIL(_b, op_STHRL, uint32(p.From.Reg), 0, asm)
		case AMOVB, AMOVBZ: // The zero extension doesn't affect store instructions
			zRIL(_b, op_LARL, regtmp(p), 0, asm)
			adj := uint32(0) // adjustment needed for odd addresses
			if i2&1 != 0 {
				i2 -= 1
				adj = 1
			}
			zRX(op_STC, uint32(p.From.Reg), 0, regtmp(p), adj, asm)
		case AFMOVD:
			zRIL(_b, op_LARL, regtmp(p), 0, asm)
			zRX(op_STD, uint32(p.From.Reg), 0, regtmp(p), 0, asm)
		case AFMOVS:
			zRIL(_b, op_LARL, regtmp(p), 0, asm)
			zRX(op_STE, uint32(p.From.Reg), 0, regtmp(p), 0, asm)
		}
		c.addrilreloc(p.To.Sym, int64(i2))

	case 75: // mov addr reg (including relocation)
		i2 := c.regoff(&p.From)
		switch p.As {
		case AMOVD:
			if i2&1 != 0 {
				zRIL(_b, op_LARL, regtmp(p), 0, asm)
				zRXY(op_LG, uint32(p.To.Reg), regtmp(p), 0, 1, asm)
				i2 -= 1
			} else {
				zRIL(_b, op_LGRL, uint32(p.To.Reg), 0, asm)
			}
		case AMOVW:
			zRIL(_b, op_LGFRL, uint32(p.To.Reg), 0, asm)
		case AMOVWZ:
			zRIL(_b, op_LLGFRL, uint32(p.To.Reg), 0, asm)
		case AMOVH:
			zRIL(_b, op_LGHRL, uint32(p.To.Reg), 0, asm)
		case AMOVHZ:
			zRIL(_b, op_LLGHRL, uint32(p.To.Reg), 0, asm)
		case AMOVB, AMOVBZ:
			zRIL(_b, op_LARL, regtmp(p), 0, asm)
			adj := uint32(0) // adjustment needed for odd addresses
			if i2&1 != 0 {
				i2 -= 1
				adj = 1
			}
			switch p.As {
			case AMOVB:
				zRXY(op_LGB, uint32(p.To.Reg), 0, regtmp(p), adj, asm)
			case AMOVBZ:
				zRXY(op_LLGC, uint32(p.To.Reg), 0, regtmp(p), adj, asm)
			}
		case AFMOVD:
			zRIL(_a, op_LARL, regtmp(p), 0, asm)
			zRX(op_LD, uint32(p.To.Reg), 0, regtmp(p), 0, asm)
		case AFMOVS:
			zRIL(_a, op_LARL, regtmp(p), 0, asm)
			zRX(op_LE, uint32(p.To.Reg), 0, regtmp(p), 0, asm)
		}
		c.addrilreloc(p.From.Sym, int64(i2))

	case 76: // set program mask
		zRR(op_SPM, uint32(p.From.Reg), 0, asm)

	case 77: // syscall $constant
		if p.From.Offset > 255 || p.From.Offset < 1 {
			c.ctxt.Diag("illegal system call; system call number out of range: %v", p)
			zE(op_TRAP2, asm) // trap always
		} else {
			zI(op_SVC, uint32(p.From.Offset), asm)
		}

	case 78: // undef
		// "An instruction consisting entirely of binary 0s is guaranteed
		// always to be an illegal instruction."
		*asm = append(*asm, 0, 0, 0, 0)

	case 79: // compare and swap reg reg reg
		v := c.regoff(&p.To)
		if v < 0 {
			v = 0
		}
		if p.As == ACS {
			zRS(op_CS, uint32(p.From.Reg), uint32(p.Reg), uint32(p.To.Reg), uint32(v), asm)
		} else if p.As == ACSG {
			zRSY(op_CSG, uint32(p.From.Reg), uint32(p.Reg), uint32(p.To.Reg), uint32(v), asm)
		}

	case 80: // sync
		zRR(op_BCR, 14, 0, asm) // fast-BCR-serialization

	case 81: // float to fixed and fixed to float moves (no conversion)
		switch p.As {
		case ALDGR:
			zRRE(op_LDGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		case ALGDR:
			zRRE(op_LGDR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		}

	case 82: // fixed to float conversion
		var opcode uint32
		switch p.As {
		default:
			log.Fatalf("unexpected opcode %v", p.As)
		case ACEFBRA:
			opcode = op_CEFBRA
		case ACDFBRA:
			opcode = op_CDFBRA
		case ACEGBRA:
			opcode = op_CEGBRA
		case ACDGBRA:
			opcode = op_CDGBRA
		case ACELFBR:
			opcode = op_CELFBR
		case ACDLFBR:
			opcode = op_CDLFBR
		case ACELGBR:
			opcode = op_CELGBR
		case ACDLGBR:
			opcode = op_CDLGBR
		}
		// set immediate operand M3 to 0 to use the default BFP rounding mode
		// (usually round to nearest, ties to even)
		// TODO(mundaym): should this be fixed at round to nearest, ties to even?
		// M4 is reserved and must be 0
		zRRF(opcode, 0, 0, uint32(p.To.Reg), uint32(p.From.Reg), asm)

	case 83: // float to fixed conversion
		var opcode uint32
		switch p.As {
		default:
			log.Fatalf("unexpected opcode %v", p.As)
		case ACFEBRA:
			opcode = op_CFEBRA
		case ACFDBRA:
			opcode = op_CFDBRA
		case ACGEBRA:
			opcode = op_CGEBRA
		case ACGDBRA:
			opcode = op_CGDBRA
		case ACLFEBR:
			opcode = op_CLFEBR
		case ACLFDBR:
			opcode = op_CLFDBR
		case ACLGEBR:
			opcode = op_CLGEBR
		case ACLGDBR:
			opcode = op_CLGDBR
		}
		// set immediate operand M3 to 5 for rounding toward zero (required by Go spec)
		// M4 is reserved and must be 0
		zRRF(opcode, 5, 0, uint32(p.To.Reg), uint32(p.From.Reg), asm)

	case 84: // storage-and-storage operations $length mem mem
		l := c.regoff(&p.From)
		if l < 1 || l > 256 {
			c.ctxt.Diag("number of bytes (%v) not in range [1,256]", l)
		}
		if p.GetFrom3().Index != 0 || p.To.Index != 0 {
			c.ctxt.Diag("cannot use index reg")
		}
		b1 := p.To.Reg
		b2 := p.GetFrom3().Reg
		if b1 == 0 {
			b1 = REGSP
		}
		if b2 == 0 {
			b2 = REGSP
		}
		d1 := c.regoff(&p.To)
		d2 := c.regoff(p.GetFrom3())
		if d1 < 0 || d1 >= DISP12 {
			if b2 == int16(regtmp(p)) {
				c.ctxt.Diag("regtmp(p) conflict")
			}
			if b1 != int16(regtmp(p)) {
				zRRE(op_LGR, regtmp(p), uint32(b1), asm)
			}
			zRIL(_a, op_AGFI, regtmp(p), uint32(d1), asm)
			if d1 == d2 && b1 == b2 {
				d2 = 0
				b2 = int16(regtmp(p))
			}
			d1 = 0
			b1 = int16(regtmp(p))
		}
		if d2 < 0 || d2 >= DISP12 {
			if b1 == REGTMP2 {
				c.ctxt.Diag("REGTMP2 conflict")
			}
			if b2 != REGTMP2 {
				zRRE(op_LGR, REGTMP2, uint32(b2), asm)
			}
			zRIL(_a, op_AGFI, REGTMP2, uint32(d2), asm)
			d2 = 0
			b2 = REGTMP2
		}
		var opcode uint32
		switch p.As {
		default:
			c.ctxt.Diag("unexpected opcode %v", p.As)
		case AMVC:
			opcode = op_MVC
		case AMVCIN:
			opcode = op_MVCIN
		case ACLC:
			opcode = op_CLC
			// swap operand order for CLC so that it matches CMP
			b1, b2 = b2, b1
			d1, d2 = d2, d1
		case AXC:
			opcode = op_XC
		case AOC:
			opcode = op_OC
		case ANC:
			opcode = op_NC
		}
		zSS(_a, opcode, uint32(l-1), 0, uint32(b1), uint32(d1), uint32(b2), uint32(d2), asm)

	case 85: // load address relative long
		v := c.regoff(&p.From)
		if p.From.Sym == nil {
			if (v & 1) != 0 {
				c.ctxt.Diag("cannot use LARL with odd offset: %v", v)
			}
		} else {
			c.addrilreloc(p.From.Sym, int64(v))
			v = 0
		}
		zRIL(_b, op_LARL, uint32(p.To.Reg), uint32(v>>1), asm)

	case 86: // load address
		d := c.vregoff(&p.From)
		x := p.From.Index
		b := p.From.Reg
		if b == 0 {
			b = REGSP
		}
		switch p.As {
		case ALA:
			zRX(op_LA, uint32(p.To.Reg), uint32(x), uint32(b), uint32(d), asm)
		case ALAY:
			zRXY(op_LAY, uint32(p.To.Reg), uint32(x), uint32(b), uint32(d), asm)
		}

	case 87: // execute relative long
		v := c.vregoff(&p.From)
		if p.From.Sym == nil {
			if v&1 != 0 {
				c.ctxt.Diag("cannot use EXRL with odd offset: %v", v)
			}
		} else {
			c.addrilreloc(p.From.Sym, v)
			v = 0
		}
		zRIL(_b, op_EXRL, uint32(p.To.Reg), uint32(v>>1), asm)

	case 88: // store clock
		var opcode uint32
		switch p.As {
		case ASTCK:
			opcode = op_STCK
		case ASTCKC:
			opcode = op_STCKC
		case ASTCKE:
			opcode = op_STCKE
		case ASTCKF:
			opcode = op_STCKF
		}
		v := c.vregoff(&p.To)
		r := p.To.Reg
		if r == 0 {
			r = REGSP
		}
		zS(opcode, uint32(r), uint32(v), asm)

	case 89: // compare and branch reg reg
		var v int32
		if p.To.Target() != nil {
			v = int32((p.To.Target().Pc - p.Pc) >> 1)
		}

		// Some instructions take a mask as the first argument.
		r1, r2 := p.From.Reg, p.Reg
		if p.From.Type == obj.TYPE_CONST {
			r1, r2 = p.Reg, p.RestArgs[0].Reg
		}
		m3 := uint32(c.branchMask(p))

		var opcode uint32
		switch p.As {
		case ACRJ:
			// COMPARE AND BRANCH RELATIVE (32)
			opcode = op_CRJ
		case ACGRJ, ACMPBEQ, ACMPBGE, ACMPBGT, ACMPBLE, ACMPBLT, ACMPBNE:
			// COMPARE AND BRANCH RELATIVE (64)
			opcode = op_CGRJ
		case ACLRJ:
			// COMPARE LOGICAL AND BRANCH RELATIVE (32)
			opcode = op_CLRJ
		case ACLGRJ, ACMPUBEQ, ACMPUBGE, ACMPUBGT, ACMPUBLE, ACMPUBLT, ACMPUBNE:
			// COMPARE LOGICAL AND BRANCH RELATIVE (64)
			opcode = op_CLGRJ
		}

		if int32(int16(v)) != v {
			// The branch is too far for one instruction so crack
			// `CMPBEQ x, y, target` into:
			//
			//     CMPBNE x, y, 2(PC)
			//     BR     target
			//
			// Note that the instruction sequence MUST NOT clobber
			// the condition code.
			m3 ^= 0xe // invert 3-bit mask
			zRIE(_b, opcode, uint32(r1), uint32(r2), uint32(sizeRIE+sizeRIL)/2, 0, 0, m3, 0, asm)
			zRIL(_c, op_BRCL, uint32(Always), uint32(v-sizeRIE/2), asm)
		} else {
			zRIE(_b, opcode, uint32(r1), uint32(r2), uint32(v), 0, 0, m3, 0, asm)
		}

	case 90: // compare and branch reg $constant
		var v int32
		if p.To.Target() != nil {
			v = int32((p.To.Target().Pc - p.Pc) >> 1)
		}

		// Some instructions take a mask as the first argument.
		r1, i2 := p.From.Reg, p.RestArgs[0].Offset
		if p.From.Type == obj.TYPE_CONST {
			r1 = p.Reg
		}
		m3 := uint32(c.branchMask(p))

		var opcode uint32
		switch p.As {
		case ACIJ:
			opcode = op_CIJ
		case ACGIJ, ACMPBEQ, ACMPBGE, ACMPBGT, ACMPBLE, ACMPBLT, ACMPBNE:
			opcode = op_CGIJ
		case ACLIJ:
			opcode = op_CLIJ
		case ACLGIJ, ACMPUBEQ, ACMPUBGE, ACMPUBGT, ACMPUBLE, ACMPUBLT, ACMPUBNE:
			opcode = op_CLGIJ
		}
		if int32(int16(v)) != v {
			// The branch is too far for one instruction so crack
			// `CMPBEQ x, $0, target` into:
			//
			//     CMPBNE x, $0, 2(PC)
			//     BR     target
			//
			// Note that the instruction sequence MUST NOT clobber
			// the condition code.
			m3 ^= 0xe // invert 3-bit mask
			zRIE(_c, opcode, uint32(r1), m3, uint32(sizeRIE+sizeRIL)/2, 0, 0, 0, uint32(i2), asm)
			zRIL(_c, op_BRCL, uint32(Always), uint32(v-sizeRIE/2), asm)
		} else {
			zRIE(_c, opcode, uint32(r1), m3, uint32(v), 0, 0, 0, uint32(i2), asm)
		}

	case 91: // test under mask (immediate)
		var opcode uint32
		switch p.As {
		case ATMHH:
			opcode = op_TMHH
		case ATMHL:
			opcode = op_TMHL
		case ATMLH:
			opcode = op_TMLH
		case ATMLL:
			opcode = op_TMLL
		}
		zRI(opcode, uint32(p.From.Reg), uint32(c.vregoff(&p.To)), asm)

	case 92: // insert program mask
		zRRE(op_IPM, uint32(p.From.Reg), 0, asm)

	case 93: // GOT lookup
		v := c.vregoff(&p.To)
		if v != 0 {
			c.ctxt.Diag("invalid offset against GOT slot %v", p)
		}
		zRIL(_b, op_LGRL, uint32(p.To.Reg), 0, asm)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_GOTPCREL,
			Off:  int32(c.pc + 2),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  2 + 4,
		})

	case 94: // TLS local exec model
		zRIL(_b, op_LARL, regtmp(p), (sizeRIL+sizeRXY+sizeRI)>>1, asm)
		zRXY(op_LG, uint32(p.To.Reg), regtmp(p), 0, 0, asm)
		zRI(op_BRC, 0xF, (sizeRI+8)>>1, asm)
		*asm = append(*asm, 0, 0, 0, 0, 0, 0, 0, 0)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_TLS_LE,
			Off:  int32(c.pc + sizeRIL + sizeRXY + sizeRI),
			Siz:  8,
			Sym:  p.From.Sym,
		})

	case 95: // TLS initial exec model
		// Assembly                   | Relocation symbol    | Done Here?
		// --------------------------------------------------------------
		// ear  %r11, %a0             |                      |
		// sllg %r11, %r11, 32        |                      |
		// ear  %r11, %a1             |                      |
		// larl %r10, <var>@indntpoff | R_390_TLS_IEENT      | Y
		// lg   %r10, 0(%r10)         | R_390_TLS_LOAD (tag) | Y
		// la   %r10, 0(%r10, %r11)   |                      |
		// --------------------------------------------------------------

		// R_390_TLS_IEENT
		zRIL(_b, op_LARL, regtmp(p), 0, asm)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_TLS_IE,
			Off:  int32(c.pc + 2),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  2 + 4,
		})

		// R_390_TLS_LOAD
		zRXY(op_LGF, uint32(p.To.Reg), regtmp(p), 0, 0, asm)
		// TODO(mundaym): add R_390_TLS_LOAD relocation here
		// not strictly required but might allow the linker to optimize

	case 96: // clear macro
		length := c.vregoff(&p.From)
		offset := c.vregoff(&p.To)
		reg := p.To.Reg
		if reg == 0 {
			reg = REGSP
		}
		if length <= 0 {
			c.ctxt.Diag("cannot CLEAR %d bytes, must be greater than 0", length)
		}
		for length > 0 {
			if offset < 0 || offset >= DISP12 {
				if offset >= -DISP20/2 && offset < DISP20/2 {
					zRXY(op_LAY, regtmp(p), uint32(reg), 0, uint32(offset), asm)
				} else {
					if reg != int16(regtmp(p)) {
						zRRE(op_LGR, regtmp(p), uint32(reg), asm)
					}
					zRIL(_a, op_AGFI, regtmp(p), uint32(offset), asm)
				}
				reg = int16(regtmp(p))
				offset = 0
			}
			size := length
			if size > 256 {
				size = 256
			}

			switch size {
			case 1:
				zSI(op_MVI, 0, uint32(reg), uint32(offset), asm)
			case 2:
				zSIL(op_MVHHI, uint32(reg), uint32(offset), 0, asm)
			case 4:
				zSIL(op_MVHI, uint32(reg), uint32(offset), 0, asm)
			case 8:
				zSIL(op_MVGHI, uint32(reg), uint32(offset), 0, asm)
			default:
				zSS(_a, op_XC, uint32(size-1), 0, uint32(reg), uint32(offset), uint32(reg), uint32(offset), asm)
			}

			length -= size
			offset += size
		}

	case 97: // store multiple
		rstart := p.From.Reg
		rend := p.Reg
		offset := c.regoff(&p.To)
		reg := p.To.Reg
		if reg == 0 {
			reg = REGSP
		}
		if offset < -DISP20/2 || offset >= DISP20/2 {
			if reg != int16(regtmp(p)) {
				zRRE(op_LGR, regtmp(p), uint32(reg), asm)
			}
			zRIL(_a, op_AGFI, regtmp(p), uint32(offset), asm)
			reg = int16(regtmp(p))
			offset = 0
		}
		switch p.As {
		case ASTMY:
			if offset >= 0 && offset < DISP12 {
				zRS(op_STM, uint32(rstart), uint32(rend), uint32(reg), uint32(offset), asm)
			} else {
				zRSY(op_STMY, uint32(rstart), uint32(rend), uint32(reg), uint32(offset), asm)
			}
		case ASTMG:
			zRSY(op_STMG, uint32(rstart), uint32(rend), uint32(reg), uint32(offset), asm)
		}

	case 98: // load multiple
		rstart := p.Reg
		rend := p.To.Reg
		offset := c.regoff(&p.From)
		reg := p.From.Reg
		if reg == 0 {
			reg = REGSP
		}
		if offset < -DISP20/2 || offset >= DISP20/2 {
			if reg != int16(regtmp(p)) {
				zRRE(op_LGR, regtmp(p), uint32(reg), asm)
			}
			zRIL(_a, op_AGFI, regtmp(p), uint32(offset), asm)
			reg = int16(regtmp(p))
			offset = 0
		}
		switch p.As {
		case ALMY:
			if offset >= 0 && offset < DISP12 {
				zRS(op_LM, uint32(rstart), uint32(rend), uint32(reg), uint32(offset), asm)
			} else {
				zRSY(op_LMY, uint32(rstart), uint32(rend), uint32(reg), uint32(offset), asm)
			}
		case ALMG:
			zRSY(op_LMG, uint32(rstart), uint32(rend), uint32(reg), uint32(offset), asm)
		}

	case 99: // interlocked load and op
		if p.To.Index != 0 {
			c.ctxt.Diag("cannot use indexed address")
		}
		offset := c.regoff(&p.To)
		if offset < -DISP20/2 || offset >= DISP20/2 {
			c.ctxt.Diag("%v does not fit into 20-bit signed integer", offset)
		}
		var opcode uint32
		switch p.As {
		case ALAA:
			opcode = op_LAA
		case ALAAG:
			opcode = op_LAAG
		case ALAAL:
			opcode = op_LAAL
		case ALAALG:
			opcode = op_LAALG
		case ALAN:
			opcode = op_LAN
		case ALANG:
			opcode = op_LANG
		case ALAX:
			opcode = op_LAX
		case ALAXG:
			opcode = op_LAXG
		case ALAO:
			opcode = op_LAO
		case ALAOG:
			opcode = op_LAOG
		}
		zRSY(opcode, uint32(p.Reg), uint32(p.From.Reg), uint32(p.To.Reg), uint32(offset), asm)

	case 100: // VRX STORE
		op, m3, _ := vop(p.As)
		v1 := p.From.Reg
		if p.Reg != 0 {
			m3 = uint32(c.vregoff(&p.From))
			v1 = p.Reg
		}
		b2 := p.To.Reg
		if b2 == 0 {
			b2 = REGSP
		}
		d2 := uint32(c.vregoff(&p.To))
		zVRX(op, uint32(v1), uint32(p.To.Index), uint32(b2), d2, m3, asm)

	case 101: // VRX LOAD
		op, m3, _ := vop(p.As)
		src := &p.From
		if p.GetFrom3() != nil {
			m3 = uint32(c.vregoff(&p.From))
			src = p.GetFrom3()
		}
		b2 := src.Reg
		if b2 == 0 {
			b2 = REGSP
		}
		d2 := uint32(c.vregoff(src))
		zVRX(op, uint32(p.To.Reg), uint32(src.Index), uint32(b2), d2, m3, asm)

	case 102: // VRV SCATTER
		op, _, _ := vop(p.As)
		m3 := uint32(c.vregoff(&p.From))
		b2 := p.To.Reg
		if b2 == 0 {
			b2 = REGSP
		}
		d2 := uint32(c.vregoff(&p.To))
		zVRV(op, uint32(p.Reg), uint32(p.To.Index), uint32(b2), d2, m3, asm)

	case 103: // VRV GATHER
		op, _, _ := vop(p.As)
		m3 := uint32(c.vregoff(&p.From))
		b2 := p.GetFrom3().Reg
		if b2 == 0 {
			b2 = REGSP
		}
		d2 := uint32(c.vregoff(p.GetFrom3()))
		zVRV(op, uint32(p.To.Reg), uint32(p.GetFrom3().Index), uint32(b2), d2, m3, asm)

	case 104: // VRS SHIFT/ROTATE and LOAD GR FROM VR ELEMENT
		op, m4, _ := vop(p.As)
		fr := p.Reg
		if fr == 0 {
			fr = p.To.Reg
		}
		bits := uint32(c.vregoff(&p.From))
		zVRS(op, uint32(p.To.Reg), uint32(fr), uint32(p.From.Reg), bits, m4, asm)

	case 105: // VRS STORE MULTIPLE
		op, _, _ := vop(p.As)
		offset := uint32(c.vregoff(&p.To))
		reg := p.To.Reg
		if reg == 0 {
			reg = REGSP
		}
		zVRS(op, uint32(p.From.Reg), uint32(p.Reg), uint32(reg), offset, 0, asm)

	case 106: // VRS LOAD MULTIPLE
		op, _, _ := vop(p.As)
		offset := uint32(c.vregoff(&p.From))
		reg := p.From.Reg
		if reg == 0 {
			reg = REGSP
		}
		zVRS(op, uint32(p.Reg), uint32(p.To.Reg), uint32(reg), offset, 0, asm)

	case 107: // VRS STORE WITH LENGTH
		op, _, _ := vop(p.As)
		offset := uint32(c.vregoff(&p.To))
		reg := p.To.Reg
		if reg == 0 {
			reg = REGSP
		}
		zVRS(op, uint32(p.Reg), uint32(p.From.Reg), uint32(reg), offset, 0, asm)

	case 108: // VRS LOAD WITH LENGTH
		op, _, _ := vop(p.As)
		offset := uint32(c.vregoff(p.GetFrom3()))
		reg := p.GetFrom3().Reg
		if reg == 0 {
			reg = REGSP
		}
		zVRS(op, uint32(p.To.Reg), uint32(p.From.Reg), uint32(reg), offset, 0, asm)

	case 109: // VRI-a
		op, m3, _ := vop(p.As)
		i2 := uint32(c.vregoff(&p.From))
		if p.GetFrom3() != nil {
			m3 = uint32(c.vregoff(&p.From))
			i2 = uint32(c.vregoff(p.GetFrom3()))
		}
		switch p.As {
		case AVZERO:
			i2 = 0
		case AVONE:
			i2 = 0xffff
		}
		zVRIa(op, uint32(p.To.Reg), i2, m3, asm)

	case 110:
		op, m4, _ := vop(p.As)
		i2 := uint32(c.vregoff(&p.From))
		i3 := uint32(c.vregoff(p.GetFrom3()))
		zVRIb(op, uint32(p.To.Reg), i2, i3, m4, asm)

	case 111:
		op, m4, _ := vop(p.As)
		i2 := uint32(c.vregoff(&p.From))
		zVRIc(op, uint32(p.To.Reg), uint32(p.Reg), i2, m4, asm)

	case 112:
		op, m5, _ := vop(p.As)
		i4 := uint32(c.vregoff(&p.From))
		zVRId(op, uint32(p.To.Reg), uint32(p.Reg), uint32(p.GetFrom3().Reg), i4, m5, asm)

	case 113:
		op, m4, _ := vop(p.As)
		m5 := singleElementMask(p.As)
		i3 := uint32(c.vregoff(&p.From))
		zVRIe(op, uint32(p.To.Reg), uint32(p.Reg), i3, m5, m4, asm)

	case 114: // VRR-a
		op, m3, m5 := vop(p.As)
		m4 := singleElementMask(p.As)
		zVRRa(op, uint32(p.To.Reg), uint32(p.From.Reg), m5, m4, m3, asm)

	case 115: // VRR-a COMPARE
		op, m3, m5 := vop(p.As)
		m4 := singleElementMask(p.As)
		zVRRa(op, uint32(p.From.Reg), uint32(p.To.Reg), m5, m4, m3, asm)

	case 117: // VRR-b
		op, m4, m5 := vop(p.As)
		zVRRb(op, uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg), m5, m4, asm)

	case 118: // VRR-c
		op, m4, m6 := vop(p.As)
		m5 := singleElementMask(p.As)
		v3 := p.Reg
		if v3 == 0 {
			v3 = p.To.Reg
		}
		zVRRc(op, uint32(p.To.Reg), uint32(p.From.Reg), uint32(v3), m6, m5, m4, asm)

	case 119: // VRR-c SHIFT/ROTATE/DIVIDE/SUB (rhs value on the left, like SLD, DIV etc.)
		op, m4, m6 := vop(p.As)
		m5 := singleElementMask(p.As)
		v2 := p.Reg
		if v2 == 0 {
			v2 = p.To.Reg
		}
		zVRRc(op, uint32(p.To.Reg), uint32(v2), uint32(p.From.Reg), m6, m5, m4, asm)

	case 120: // VRR-d
		op, m6, m5 := vop(p.As)
		v1 := uint32(p.To.Reg)
		v2 := uint32(p.From.Reg)
		v3 := uint32(p.Reg)
		v4 := uint32(p.GetFrom3().Reg)
		zVRRd(op, v1, v2, v3, m6, m5, v4, asm)

	case 121: // VRR-e
		op, m6, _ := vop(p.As)
		m5 := singleElementMask(p.As)
		v1 := uint32(p.To.Reg)
		v2 := uint32(p.From.Reg)
		v3 := uint32(p.Reg)
		v4 := uint32(p.GetFrom3().Reg)
		zVRRe(op, v1, v2, v3, m6, m5, v4, asm)

	case 122: // VRR-f LOAD VRS FROM GRS DISJOINT
		op, _, _ := vop(p.As)
		zVRRf(op, uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg), asm)

	case 123: // VPDI $m4, V2, V3, V1
		op, _, _ := vop(p.As)
		m4 := c.regoff(&p.From)
		zVRRc(op, uint32(p.To.Reg), uint32(p.Reg), uint32(p.GetFrom3().Reg), 0, 0, uint32(m4), asm)

	case 124:
		var opcode uint32
		switch p.As {
		default:
			c.ctxt.Diag("unexpected opcode %v", p.As)
		case AKM, AKMC, AKLMD:
			if p.From.Reg == REG_R0 {
				c.ctxt.Diag("input must not be R0 in %v", p)
			}
			if p.From.Reg&1 != 0 {
				c.ctxt.Diag("input must be even register in %v", p)
			}
			if p.To.Reg == REG_R0 {
				c.ctxt.Diag("second argument must not be R0 in %v", p)
			}
			if p.To.Reg&1 != 0 {
				c.ctxt.Diag("second argument must be even register in %v", p)
			}
			if p.As == AKM {
				opcode = op_KM
			} else if p.As == AKMC {
				opcode = op_KMC
			} else {
				opcode = op_KLMD
			}
		case AKIMD:
			if p.To.Reg == REG_R0 {
				c.ctxt.Diag("second argument must not be R0 in %v", p)
			}
			if p.To.Reg&1 != 0 {
				c.ctxt.Diag("second argument must be even register in %v", p)
			}
			opcode = op_KIMD
		}
		zRRE(opcode, uint32(p.From.Reg), uint32(p.To.Reg), asm)

	case 125: // KDSA sign and verify
		if p.To.Reg == REG_R0 {
			c.ctxt.Diag("second argument must not be R0 in %v", p)
		}
		if p.To.Reg&1 != 0 {
			c.ctxt.Diag("second argument must be an even register in %v", p)
		}
		zRRE(op_KDSA, uint32(p.From.Reg), uint32(p.To.Reg), asm)

	case 126: // KMA and KMCTR - CIPHER MESSAGE WITH AUTHENTICATION; CIPHER MESSAGE WITH COUNTER
		var opcode uint32
		switch p.As {
		default:
			c.ctxt.Diag("unexpected opcode %v", p.As)
		case AKMA, AKMCTR:
			if p.From.Reg == REG_R0 {
				c.ctxt.Diag("input argument must not be R0 in %v", p)
			}
			if p.From.Reg&1 != 0 {
				c.ctxt.Diag("input argument must be even register in %v", p)
			}
			if p.To.Reg == REG_R0 {
				c.ctxt.Diag("output argument must not be R0 in %v", p)
			}
			if p.To.Reg&1 != 0 {
				c.ctxt.Diag("output argument must be an even register in %v", p)
			}
			if p.Reg == REG_R0 {
				c.ctxt.Diag("third argument must not be R0 in %v", p)
			}
			if p.Reg&1 != 0 {
				c.ctxt.Diag("third argument must be even register in %v", p)
			}
			if p.As == AKMA {
				opcode = op_KMA
			} else if p.As == AKMCTR {
				opcode = op_KMCTR
			}
		}
		zRRF(opcode, uint32(p.Reg), 0, uint32(p.From.Reg), uint32(p.To.Reg), asm)
	}
}

func (c *ctxtz) vregoff(a *obj.Addr) int64 {
	c.instoffset = 0
	if a != nil {
		c.aclass(a)
	}
	return c.instoffset
}

func (c *ctxtz) regoff(a *obj.Addr) int32 {
	return int32(c.vregoff(a))
}

// find if the displacement is within 12 bit.
func isU12(displacement int32) bool {
	return displacement >= 0 && displacement < DISP12
}

// zopload12 returns the RX op with 12 bit displacement for the given load.
func (c *ctxtz) zopload12(a obj.As) (uint32, bool) {
	switch a {
	case AFMOVD:
		return op_LD, true
	case AFMOVS:
		return op_LE, true
	}
	return 0, false
}

// zopload returns the RXY op for the given load.
func (c *ctxtz) zopload(a obj.As) uint32 {
	switch a {
	// fixed point load
	case AMOVD:
		return op_LG
	case AMOVW:
		return op_LGF
	case AMOVWZ:
		return op_LLGF
	case AMOVH:
		return op_LGH
	case AMOVHZ:
		return op_LLGH
	case AMOVB:
		return op_LGB
	case AMOVBZ:
		return op_LLGC

	// floating point load
	case AFMOVD:
		return op_LDY
	case AFMOVS:
		return op_LEY

	// byte reversed load
	case AMOVDBR:
		return op_LRVG
	case AMOVWBR:
		return op_LRV
	case AMOVHBR:
		return op_LRVH
	}

	c.ctxt.Diag("unknown store opcode %v", a)
	return 0
}

// zopstore12 returns the RX op with 12 bit displacement for the given store.
func (c *ctxtz) zopstore12(a obj.As) (uint32, bool) {
	switch a {
	case AFMOVD:
		return op_STD, true
	case AFMOVS:
		return op_STE, true
	case AMOVW, AMOVWZ:
		return op_ST, true
	case AMOVH, AMOVHZ:
		return op_STH, true
	case AMOVB, AMOVBZ:
		return op_STC, true
	}
	return 0, false
}

// zopstore returns the RXY op for the given store.
func (c *ctxtz) zopstore(a obj.As) uint32 {
	switch a {
	// fixed point store
	case AMOVD:
		return op_STG
	case AMOVW, AMOVWZ:
		return op_STY
	case AMOVH, AMOVHZ:
		return op_STHY
	case AMOVB, AMOVBZ:
		return op_STCY

	// floating point store
	case AFMOVD:
		return op_STDY
	case AFMOVS:
		return op_STEY

	// byte reversed store
	case AMOVDBR:
		return op_STRVG
	case AMOVWBR:
		return op_STRV
	case AMOVHBR:
		return op_STRVH
	}

	c.ctxt.Diag("unknown store opcode %v", a)
	return 0
}

// zoprre returns the RRE op for the given a.
func (c *ctxtz) zoprre(a obj.As) uint32 {
	switch a {
	case ACMP:
		return op_CGR
	case ACMPU:
		return op_CLGR
	case AFCMPO: //ordered
		return op_KDBR
	case AFCMPU: //unordered
		return op_CDBR
	case ACEBR:
		return op_CEBR
	}
	c.ctxt.Diag("unknown rre opcode %v", a)
	return 0
}

// zoprr returns the RR op for the given a.
func (c *ctxtz) zoprr(a obj.As) uint32 {
	switch a {
	case ACMPW:
		return op_CR
	case ACMPWU:
		return op_CLR
	}
	c.ctxt.Diag("unknown rr opcode %v", a)
	return 0
}

// zopril returns the RIL op for the given a.
func (c *ctxtz) zopril(a obj.As) uint32 {
	switch a {
	case ACMP:
		return op_CGFI
	case ACMPU:
		return op_CLGFI
	case ACMPW:
		return op_CFI
	case ACMPWU:
		return op_CLFI
	}
	c.ctxt.Diag("unknown ril opcode %v", a)
	return 0
}

// z instructions sizes
const (
	sizeE    = 2
	sizeI    = 2
	sizeIE   = 4
	sizeMII  = 6
	sizeRI   = 4
	sizeRI1  = 4
	sizeRI2  = 4
	sizeRI3  = 4
	sizeRIE  = 6
	sizeRIE1 = 6
	sizeRIE2 = 6
	sizeRIE3 = 6
	sizeRIE4 = 6
	sizeRIE5 = 6
	sizeRIE6 = 6
	sizeRIL  = 6
	sizeRIL1 = 6
	sizeRIL2 = 6
	sizeRIL3 = 6
	sizeRIS  = 6
	sizeRR   = 2
	sizeRRD  = 4
	sizeRRE  = 4
	sizeRRF  = 4
	sizeRRF1 = 4
	sizeRRF2 = 4
	sizeRRF3 = 4
	sizeRRF4 = 4
	sizeRRF5 = 4
	sizeRRR  = 2
	sizeRRS  = 6
	sizeRS   = 4
	sizeRS1  = 4
	sizeRS2  = 4
	sizeRSI  = 4
	sizeRSL  = 6
	sizeRSY  = 6
	sizeRSY1 = 6
	sizeRSY2 = 6
	sizeRX   = 4
	sizeRX1  = 4
	sizeRX2  = 4
	sizeRXE  = 6
	sizeRXF  = 6
	sizeRXY  = 6
	sizeRXY1 = 6
	sizeRXY2 = 6
	sizeS    = 4
	sizeSI   = 4
	sizeSIL  = 6
	sizeSIY  = 6
	sizeSMI  = 6
	sizeSS   = 6
	sizeSS1  = 6
	sizeSS2  = 6
	sizeSS3  = 6
	sizeSS4  = 6
	sizeSS5  = 6
	sizeSS6  = 6
	sizeSSE  = 6
	sizeSSF  = 6
)

// instruction format variations
type form int

const (
	_a form = iota
	_b
	_c
	_d
	_e
	_f
)

func zE(op uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8), uint8(op))
}

func zI(op, i1 uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8), uint8(i1))
}

func zMII(op, m1, ri2, ri3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(m1)<<4)|uint8((ri2>>8)&0x0F),
		uint8(ri2),
		uint8(ri3>>16),
		uint8(ri3>>8),
		uint8(ri3))
}

func zRI(op, r1_m1, i2_ri2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1_m1)<<4)|(uint8(op)&0x0F),
		uint8(i2_ri2>>8),
		uint8(i2_ri2))
}

// Expected argument values for the instruction formats.
//
// Format    a1  a2   a3  a4  a5  a6  a7
// ------------------------------------
// a         r1,  0,  i2,  0,  0, m3,  0
// b         r1, r2, ri4,  0,  0, m3,  0
// c         r1, m3, ri4,  0,  0,  0, i2
// d         r1, r3,  i2,  0,  0,  0,  0
// e         r1, r3, ri2,  0,  0,  0,  0
// f         r1, r2,   0, i3, i4,  0, i5
// g         r1, m3,  i2,  0,  0,  0,  0
func zRIE(f form, op, r1, r2_m3_r3, i2_ri4_ri2, i3, i4, m3, i2_i5 uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8), uint8(r1)<<4|uint8(r2_m3_r3&0x0F))

	switch f {
	default:
		*asm = append(*asm, uint8(i2_ri4_ri2>>8), uint8(i2_ri4_ri2))
	case _f:
		*asm = append(*asm, uint8(i3), uint8(i4))
	}

	switch f {
	case _a, _b:
		*asm = append(*asm, uint8(m3)<<4)
	default:
		*asm = append(*asm, uint8(i2_i5))
	}

	*asm = append(*asm, uint8(op))
}

func zRIL(f form, op, r1_m1, i2_ri2 uint32, asm *[]byte) {
	if f == _a || f == _b {
		r1_m1 = r1_m1 - obj.RBaseS390X // this is a register base
	}
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1_m1)<<4)|(uint8(op)&0x0F),
		uint8(i2_ri2>>24),
		uint8(i2_ri2>>16),
		uint8(i2_ri2>>8),
		uint8(i2_ri2))
}

func zRIS(op, r1, m3, b4, d4, i2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(m3&0x0F),
		(uint8(b4)<<4)|(uint8(d4>>8)&0x0F),
		uint8(d4),
		uint8(i2),
		uint8(op))
}

func zRR(op, r1, r2 uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8), (uint8(r1)<<4)|uint8(r2&0x0F))
}

func zRRD(op, r1, r3, r2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		uint8(r1)<<4,
		(uint8(r3)<<4)|uint8(r2&0x0F))
}

func zRRE(op, r1, r2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		0,
		(uint8(r1)<<4)|uint8(r2&0x0F))
}

func zRRF(op, r3_m3, m4, r1, r2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		(uint8(r3_m3)<<4)|uint8(m4&0x0F),
		(uint8(r1)<<4)|uint8(r2&0x0F))
}

func zRRS(op, r1, r2, b4, d4, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(r2&0x0F),
		(uint8(b4)<<4)|uint8((d4>>8)&0x0F),
		uint8(d4),
		uint8(m3)<<4,
		uint8(op))
}

func zRS(op, r1, r3_m3, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(r3_m3&0x0F),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func zRSI(op, r1, r3, ri2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(r3&0x0F),
		uint8(ri2>>8),
		uint8(ri2))
}

func zRSL(op, l1, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(l1),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2),
		uint8(op))
}

func zRSY(op, r1, r3_m3, b2, d2 uint32, asm *[]byte) {
	dl2 := uint16(d2) & 0x0FFF
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(r3_m3&0x0F),
		(uint8(b2)<<4)|(uint8(dl2>>8)&0x0F),
		uint8(dl2),
		uint8(d2>>12),
		uint8(op))
}

func zRX(op, r1_m1, x2, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1_m1)<<4)|uint8(x2&0x0F),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func zRXE(op, r1, x2, b2, d2, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(x2&0x0F),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2),
		uint8(m3)<<4,
		uint8(op))
}

func zRXF(op, r3, x2, b2, d2, m1 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r3)<<4)|uint8(x2&0x0F),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2),
		uint8(m1)<<4,
		uint8(op))
}

func zRXY(op, r1_m1, x2, b2, d2 uint32, asm *[]byte) {
	dl2 := uint16(d2) & 0x0FFF
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1_m1)<<4)|uint8(x2&0x0F),
		(uint8(b2)<<4)|(uint8(dl2>>8)&0x0F),
		uint8(dl2),
		uint8(d2>>12),
		uint8(op))
}

func zS(op, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func zSI(op, i2, b1, d1 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(i2),
		(uint8(b1)<<4)|uint8((d1>>8)&0x0F),
		uint8(d1))
}

func zSIL(op, b1, d1, i2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		(uint8(b1)<<4)|uint8((d1>>8)&0x0F),
		uint8(d1),
		uint8(i2>>8),
		uint8(i2))
}

func zSIY(op, i2, b1, d1 uint32, asm *[]byte) {
	dl1 := uint16(d1) & 0x0FFF
	*asm = append(*asm,
		uint8(op>>8),
		uint8(i2),
		(uint8(b1)<<4)|(uint8(dl1>>8)&0x0F),
		uint8(dl1),
		uint8(d1>>12),
		uint8(op))
}

func zSMI(op, m1, b3, d3, ri2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(m1)<<4,
		(uint8(b3)<<4)|uint8((d3>>8)&0x0F),
		uint8(d3),
		uint8(ri2>>8),
		uint8(ri2))
}

// Expected argument values for the instruction formats.
//
// Format    a1  a2  a3  a4  a5  a6
// -------------------------------
// a         l1,  0, b1, d1, b2, d2
// b         l1, l2, b1, d1, b2, d2
// c         l1, i3, b1, d1, b2, d2
// d         r1, r3, b1, d1, b2, d2
// e         r1, r3, b2, d2, b4, d4
// f          0, l2, b1, d1, b2, d2
func zSS(f form, op, l1_r1, l2_i3_r3, b1_b2, d1_d2, b2_b4, d2_d4 uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8))

	switch f {
	case _a:
		*asm = append(*asm, uint8(l1_r1))
	case _b, _c, _d, _e:
		*asm = append(*asm, (uint8(l1_r1)<<4)|uint8(l2_i3_r3&0x0F))
	case _f:
		*asm = append(*asm, uint8(l2_i3_r3))
	}

	*asm = append(*asm,
		(uint8(b1_b2)<<4)|uint8((d1_d2>>8)&0x0F),
		uint8(d1_d2),
		(uint8(b2_b4)<<4)|uint8((d2_d4>>8)&0x0F),
		uint8(d2_d4))
}

func zSSE(op, b1, d1, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		(uint8(b1)<<4)|uint8((d1>>8)&0x0F),
		uint8(d1),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func zSSF(op, r3, b1, d1, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r3)<<4)|(uint8(op)&0x0F),
		(uint8(b1)<<4)|uint8((d1>>8)&0x0F),
		uint8(d1),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func rxb(va, vb, vc, vd uint32) uint8 {
	mask := uint8(0)
	if va >= REG_V16 && va <= REG_V31 {
		mask |= 0x8
	}
	if vb >= REG_V16 && vb <= REG_V31 {
		mask |= 0x4
	}
	if vc >= REG_V16 && vc <= REG_V31 {
		mask |= 0x2
	}
	if vd >= REG_V16 && vd <= REG_V31 {
		mask |= 0x1
	}
	return mask
}

func zVRX(op, v1, x2, b2, d2, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(x2)&0xf),
		(uint8(b2)<<4)|(uint8(d2>>8)&0xf),
		uint8(d2),
		(uint8(m3)<<4)|rxb(v1, 0, 0, 0),
		uint8(op))
}

func zVRV(op, v1, v2, b2, d2, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		(uint8(b2)<<4)|(uint8(d2>>8)&0xf),
		uint8(d2),
		(uint8(m3)<<4)|rxb(v1, v2, 0, 0),
		uint8(op))
}

func zVRS(op, v1, v3_r3, b2, d2, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v3_r3)&0xf),
		(uint8(b2)<<4)|(uint8(d2>>8)&0xf),
		uint8(d2),
		(uint8(m4)<<4)|rxb(v1, v3_r3, 0, 0),
		uint8(op))
}

func zVRRa(op, v1, v2, m5, m4, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		0,
		(uint8(m5)<<4)|(uint8(m4)&0xf),
		(uint8(m3)<<4)|rxb(v1, v2, 0, 0),
		uint8(op))
}

func zVRRb(op, v1, v2, v3, m5, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		uint8(v3)<<4,
		uint8(m5)<<4,
		(uint8(m4)<<4)|rxb(v1, v2, v3, 0),
		uint8(op))
}

func zVRRc(op, v1, v2, v3, m6, m5, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		uint8(v3)<<4,
		(uint8(m6)<<4)|(uint8(m5)&0xf),
		(uint8(m4)<<4)|rxb(v1, v2, v3, 0),
		uint8(op))
}

func zVRRd(op, v1, v2, v3, m5, m6, v4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		(uint8(v3)<<4)|(uint8(m5)&0xf),
		uint8(m6)<<4,
		(uint8(v4)<<4)|rxb(v1, v2, v3, v4),
		uint8(op))
}

func zVRRe(op, v1, v2, v3, m6, m5, v4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		(uint8(v3)<<4)|(uint8(m6)&0xf),
		uint8(m5),
		(uint8(v4)<<4)|rxb(v1, v2, v3, v4),
		uint8(op))
}

func zVRRf(op, v1, r2, r3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(r2)&0xf),
		uint8(r3)<<4,
		0,
		rxb(v1, 0, 0, 0),
		uint8(op))
}

func zVRIa(op, v1, i2, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(v1)<<4,
		uint8(i2>>8),
		uint8(i2),
		(uint8(m3)<<4)|rxb(v1, 0, 0, 0),
		uint8(op))
}

func zVRIb(op, v1, i2, i3, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(v1)<<4,
		uint8(i2),
		uint8(i3),
		(uint8(m4)<<4)|rxb(v1, 0, 0, 0),
		uint8(op))
}

func zVRIc(op, v1, v3, i2, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v3)&0xf),
		uint8(i2>>8),
		uint8(i2),
		(uint8(m4)<<4)|rxb(v1, v3, 0, 0),
		uint8(op))
}

func zVRId(op, v1, v2, v3, i4, m5 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		uint8(v3)<<4,
		uint8(i4),
		(uint8(m5)<<4)|rxb(v1, v2, v3, 0),
		uint8(op))
}

func zVRIe(op, v1, v2, i3, m5, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		uint8(i3>>4),
		(uint8(i3)<<4)|(uint8(m5)&0xf),
		(uint8(m4)<<4)|rxb(v1, v2, 0, 0),
		uint8(op))
}
```