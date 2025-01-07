Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `asmz.go` file for the s390x architecture in the Go compiler.

The code consists of a large `switch` statement that handles different instruction opcodes (`p.As`). Each `case` within the `switch` corresponds to a specific s390x assembly instruction or a category of instructions. The code then translates these high-level Go assembler instructions into the actual byte sequences that the s390x processor can understand.

To summarize, I need to identify the primary function of this code and list the types of operations it performs.

**High-level plan:**

1. State the overall function of the code.
2. Categorize the types of instructions handled by the `switch` statement.
这是 `go/src/cmd/internal/obj/s390x/asmz.go` 文件中处理汇编指令生成机器码的一部分代码。它的主要功能是将 Go 汇编器解析后的指令 `p` 转换为 s390x 架构的机器码，并将其添加到 `asm` byte 数组中。

具体来说，这段代码通过一个大的 `switch` 语句，根据不同的指令类型 (`p.As`) 执行相应的机器码生成逻辑。

**归纳其功能如下：**

这段代码负责将多种 s390x 架构的汇编指令翻译成对应的机器码。它针对不同的指令类型，例如算术运算、逻辑运算、数据移动、分支跳转、浮点运算、向量运算等，使用不同的编码方式和辅助函数 (`zRX`, `zRXY`, `zRI`, `zRIL` 等) 来生成正确的机器码字节序列。 这段代码是 Go 编译器中将架构无关的汇编指令转化为特定架构机器码的关键组成部分。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/s390x/asmz.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共6部分，请归纳一下它的功能

"""
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
		zVRRc(op, uint32(p.To.Reg), uint32(p.From.Reg), uint32(v3), m6, m5, m4,
"""




```