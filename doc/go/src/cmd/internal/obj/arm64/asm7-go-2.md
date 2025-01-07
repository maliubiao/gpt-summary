Response: 
Prompt: 
```
这是路径为go/src/cmd/internal/obj/arm64/asm7.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共4部分，请归纳一下它的功能

"""
rf, rt)

		case ASXTHW:
			o1 = c.opbfm(p, ASBFMW, 0, 15, rf, rt)

		case AUXTBW:
			o1 = c.opbfm(p, AUBFMW, 0, 7, rf, rt)

		case AUXTHW:
			o1 = c.opbfm(p, AUBFMW, 0, 15, rf, rt)

		default:
			c.ctxt.Diag("bad sxt %v", as)
			break
		}

	case 46: /* cls */
		o1 = c.opbit(p, p.As)

		o1 |= uint32(p.From.Reg&31) << 5
		o1 |= uint32(p.To.Reg & 31)

	case 47: // SWPx/LDADDx/LDCLRx/LDEORx/LDORx/CASx Rs, (Rb), Rt
		rs := p.From.Reg
		rt := p.RegTo2
		rb := p.To.Reg

		// rt can't be sp.
		if rt == REG_RSP {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}

		o1 = atomicLDADD[p.As] | atomicSWP[p.As]
		o1 |= uint32(rs&31)<<16 | uint32(rb&31)<<5 | uint32(rt&31)

	case 48: /* ADD $C_ADDCON2, Rm, Rd */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		op := c.opirr(p, p.As)
		if op&Sbit != 0 {
			c.ctxt.Diag("can not break addition/subtraction when S bit is set", p)
		}
		rt, r := p.To.Reg, p.Reg
		if r == obj.REG_NONE {
			r = rt
		}
		o1 = c.oaddi(p, p.As, c.regoff(&p.From)&0x000fff, rt, r)
		o2 = c.oaddi(p, p.As, c.regoff(&p.From)&0xfff000, rt, rt)

	case 49: /* op Vm.<T>, Vn, Vd */
		o1 = c.oprrr(p, p.As)
		cf := c.aclass(&p.From)
		af := (p.From.Reg >> 5) & 15
		sz := ARNG_4S
		if p.As == ASHA512H || p.As == ASHA512H2 {
			sz = ARNG_2D
		}
		if cf == C_ARNG && af != int16(sz) {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= uint32(p.From.Reg&31)<<16 | uint32(p.Reg&31)<<5 | uint32(p.To.Reg&31)

	case 50: /* sys/sysl */
		o1 = c.opirr(p, p.As)

		if (p.From.Offset &^ int64(SYSARG4(0x7, 0xF, 0xF, 0x7))) != 0 {
			c.ctxt.Diag("illegal SYS argument\n%v", p)
		}
		o1 |= uint32(p.From.Offset)
		if p.To.Type == obj.TYPE_REG {
			o1 |= uint32(p.To.Reg & 31)
		} else {
			o1 |= 0x1F
		}

	case 51: /* dmb */
		o1 = c.opirr(p, p.As)

		if p.From.Type == obj.TYPE_CONST {
			o1 |= uint32((p.From.Offset & 0xF) << 8)
		}

	case 52: /* hint */
		o1 = c.opirr(p, p.As)

		o1 |= uint32((p.From.Offset & 0x7F) << 5)

	case 53: /* and/or/eor/bic/tst/... $bitcon, Rn, Rd */
		a := p.As
		rt := int(p.To.Reg)
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		r := int(p.Reg)
		if r == obj.REG_NONE {
			r = rt
		}
		if r == REG_RSP {
			c.ctxt.Diag("illegal source register: %v", p)
			break
		}
		mode := 64
		v := uint64(p.From.Offset)
		switch p.As {
		case AANDW, AORRW, AEORW, AANDSW, ATSTW:
			mode = 32
		case ABIC, AORN, AEON, ABICS:
			v = ^v
		case ABICW, AORNW, AEONW, ABICSW:
			v = ^v
			mode = 32
		}
		o1 = c.opirr(p, a)
		o1 |= bitconEncode(v, mode) | uint32(r&31)<<5 | uint32(rt&31)

	case 54: /* floating point arith */
		o1 = c.oprrr(p, p.As)
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		r := int(p.Reg)
		if (o1&(0x1F<<24)) == (0x1E<<24) && (o1&(1<<11)) == 0 { /* monadic */
			r = rf
			rf = 0
		} else if r == obj.REG_NONE {
			r = rt
		}
		o1 |= (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	case 55: /* floating-point constant */
		var rf int
		o1 = 0xf<<25 | 1<<21 | 1<<12
		rf = c.chipfloat7(p.From.Val.(float64))
		if rf < 0 {
			c.ctxt.Diag("invalid floating-point immediate\n%v", p)
		}
		if p.As == AFMOVD {
			o1 |= 1 << 22
		}
		o1 |= (uint32(rf&0xff) << 13) | uint32(p.To.Reg&31)

	case 56: /* floating point compare */
		o1 = c.oprrr(p, p.As)

		var rf int
		if p.From.Type == obj.TYPE_FCONST {
			o1 |= 8 /* zero */
			rf = 0
		} else {
			rf = int(p.From.Reg)
		}
		rt := int(p.Reg)
		o1 |= uint32(rf&31)<<16 | uint32(rt&31)<<5

	case 57: /* floating point conditional compare */
		o1 = c.oprrr(p, p.As)

		cond := SpecialOperand(p.From.Offset)
		if cond < SPOP_EQ || cond > SPOP_NV {
			c.ctxt.Diag("invalid condition\n%v", p)
		} else {
			cond -= SPOP_EQ
		}

		nzcv := int(p.To.Offset)
		if nzcv&^0xF != 0 {
			c.ctxt.Diag("implausible condition\n%v", p)
		}
		rf := int(p.Reg)
		if p.GetFrom3() == nil || p.GetFrom3().Reg < REG_F0 || p.GetFrom3().Reg > REG_F31 {
			c.ctxt.Diag("illegal FCCMP\n%v", p)
			break
		}
		rt := int(p.GetFrom3().Reg)
		o1 |= uint32(rf&31)<<16 | uint32(cond&15)<<12 | uint32(rt&31)<<5 | uint32(nzcv)

	case 58: /* ldar/ldarb/ldarh/ldaxp/ldxp/ldaxr/ldxr */
		o1 = c.opload(p, p.As)

		o1 |= 0x1F << 16
		o1 |= uint32(p.From.Reg&31) << 5
		if p.As == ALDXP || p.As == ALDXPW || p.As == ALDAXP || p.As == ALDAXPW {
			if int(p.To.Reg) == int(p.To.Offset) {
				c.ctxt.Diag("constrained unpredictable behavior: %v", p)
			}
			o1 |= uint32(p.To.Offset&31) << 10
		} else {
			o1 |= 0x1F << 10
		}
		o1 |= uint32(p.To.Reg & 31)

	case 59: /* stxr/stlxr/stxp/stlxp */
		s := p.RegTo2
		n := p.To.Reg
		t := p.From.Reg
		if isSTLXRop(p.As) {
			if s == t || (s == n && n != REGSP) {
				c.ctxt.Diag("constrained unpredictable behavior: %v", p)
			}
		} else if isSTXPop(p.As) {
			t2 := int16(p.From.Offset)
			if (s == t || s == t2) || (s == n && n != REGSP) {
				c.ctxt.Diag("constrained unpredictable behavior: %v", p)
			}
		}
		if s == REG_RSP {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}
		o1 = c.opstore(p, p.As)

		if p.RegTo2 != obj.REG_NONE {
			o1 |= uint32(p.RegTo2&31) << 16
		} else {
			o1 |= 0x1F << 16
		}
		if isSTXPop(p.As) {
			o1 |= uint32(p.From.Offset&31) << 10
		}
		o1 |= uint32(p.To.Reg&31)<<5 | uint32(p.From.Reg&31)

	case 60: /* adrp label,r */
		d := c.brdist(p, 12, 21, 0)

		o1 = ADR(1, uint32(d), uint32(p.To.Reg))

	case 61: /* adr label, r */
		d := c.brdist(p, 0, 21, 0)

		o1 = ADR(0, uint32(d), uint32(p.To.Reg))

	case 62: /* op $movcon, [R], R -> mov $movcon, REGTMP + op REGTMP, [R], R */
		if p.Reg == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v\n", p)
		}
		if p.To.Reg == REG_RSP && isADDSop(p.As) {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}
		lsl0 := LSL0_64
		if isADDWop(p.As) || isANDWop(p.As) {
			o1 = c.omovconst(AMOVW, p, &p.From, REGTMP)
			lsl0 = LSL0_32
		} else {
			o1 = c.omovconst(AMOVD, p, &p.From, REGTMP)
		}

		rt, r, rf := p.To.Reg, p.Reg, int16(REGTMP)
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		if r == obj.REG_NONE {
			r = rt
		}
		if rt == REGSP || r == REGSP {
			o2 = c.opxrrr(p, p.As, rt, r, rf, false)
			o2 |= uint32(lsl0)
		} else {
			o2 = c.oprrr(p, p.As)
			o2 |= uint32(rf&31) << 16 /* shift is 0 */
			o2 |= uint32(r&31) << 5
			o2 |= uint32(rt & 31)
		}

	case 63: /* op Vm.<t>, Vn.<T>, Vd.<T> */
		o1 |= c.oprrr(p, p.As)
		af := (p.From.Reg >> 5) & 15
		at := (p.To.Reg >> 5) & 15
		ar := (p.Reg >> 5) & 15
		sz := ARNG_4S
		if p.As == ASHA512SU1 {
			sz = ARNG_2D
		}
		if af != at || af != ar || af != int16(sz) {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= uint32(p.From.Reg&31)<<16 | uint32(p.Reg&31)<<5 | uint32(p.To.Reg&31)

	/* reloc ops */
	case 64: /* movT R,addr -> adrp + movT R, (REGTMP) */
		if p.From.Reg == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v\n", p)
		}
		o1 = ADR(1, 0, REGTMP)
		var typ objabi.RelocType
		// For unaligned access, fall back to adrp + add + movT R, (REGTMP).
		if o.size(c.ctxt, p) != 8 {
			o2 = c.opirr(p, AADD) | REGTMP&31<<5 | REGTMP&31
			o3 = c.olsr12u(p, c.opstr(p, p.As), 0, REGTMP, p.From.Reg)
			typ = objabi.R_ADDRARM64
		} else {
			o2 = c.olsr12u(p, c.opstr(p, p.As), 0, REGTMP, p.From.Reg)
			typ = c.addrRelocType(p)
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: typ,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

	case 65: /* movT addr,R -> adrp + movT (REGTMP), R */
		o1 = ADR(1, 0, REGTMP)
		var typ objabi.RelocType
		// For unaligned access, fall back to adrp + add + movT (REGTMP), R.
		if o.size(c.ctxt, p) != 8 {
			o2 = c.opirr(p, AADD) | REGTMP&31<<5 | REGTMP&31
			o3 = c.olsr12u(p, c.opldr(p, p.As), 0, REGTMP, p.To.Reg)
			typ = objabi.R_ADDRARM64
		} else {
			o2 = c.olsr12u(p, c.opldr(p, p.As), 0, REGTMP, p.To.Reg)
			typ = c.addrRelocType(p)
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: typ,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 66: /* ldp O(R)!, (r1, r2); ldp (R)O!, (r1, r2) */
		rf, rt1, rt2 := p.From.Reg, p.To.Reg, int16(p.To.Offset)
		if rf == obj.REG_NONE {
			rf = o.param
		}
		if rf == obj.REG_NONE {
			c.ctxt.Diag("invalid ldp source: %v\n", p)
		}
		v := c.regoff(&p.From)
		o1 = c.opldpstp(p, o, v, rf, rt1, rt2, 1)

	case 67: /* stp (r1, r2), O(R)!; stp (r1, r2), (R)O! */
		rt, rf1, rf2 := p.To.Reg, p.From.Reg, int16(p.From.Offset)
		if rt == obj.REG_NONE {
			rt = o.param
		}
		if rt == obj.REG_NONE {
			c.ctxt.Diag("invalid stp destination: %v\n", p)
		}
		v := c.regoff(&p.To)
		o1 = c.opldpstp(p, o, v, rt, rf1, rf2, 0)

	case 68: /* movT $vconaddr(SB), reg -> adrp + add + reloc */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		if p.As == AMOVW {
			c.ctxt.Diag("invalid load of 32-bit address: %v", p)
		}
		o1 = ADR(1, 0, uint32(p.To.Reg))
		o2 = c.opirr(p, AADD) | uint32(p.To.Reg&31)<<5 | uint32(p.To.Reg&31)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRARM64,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 69: /* LE model movd $tlsvar, reg -> movz reg, 0 + reloc */
		o1 = c.opirr(p, AMOVZ)
		o1 |= uint32(p.To.Reg & 31)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ARM64_TLS_LE,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.From.Sym,
		})
		if p.From.Offset != 0 {
			c.ctxt.Diag("invalid offset on MOVW $tlsvar")
		}

	case 70: /* IE model movd $tlsvar, reg -> adrp REGTMP, 0; ldr reg, [REGTMP, #0] + relocs */
		o1 = ADR(1, 0, REGTMP)
		o2 = c.olsr12u(p, c.opldr(p, AMOVD), 0, REGTMP, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ARM64_TLS_IE,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
		})
		if p.From.Offset != 0 {
			c.ctxt.Diag("invalid offset on MOVW $tlsvar")
		}

	case 71: /* movd sym@GOT, reg -> adrp REGTMP, #0; ldr reg, [REGTMP, #0] + relocs */
		o1 = ADR(1, 0, REGTMP)
		o2 = c.olsr12u(p, c.opldr(p, AMOVD), 0, REGTMP, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ARM64_GOTPCREL,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
		})

	case 72: /* vaddp/vand/vcmeq/vorr/vadd/veor/vfmla/vfmls/vbit/vbsl/vcmtst/vsub/vbif/vuzip1/vuzip2/vrax1 Vm.<T>, Vn.<T>, Vd.<T> */
		af := int((p.From.Reg >> 5) & 15)
		af3 := int((p.Reg >> 5) & 15)
		at := int((p.To.Reg >> 5) & 15)
		if af != af3 || af != at {
			c.ctxt.Diag("operand mismatch: %v", p)
			break
		}
		o1 = c.oprrr(p, p.As)
		rf := int((p.From.Reg) & 31)
		rt := int((p.To.Reg) & 31)
		r := int((p.Reg) & 31)

		Q := 0
		size := 0
		switch af {
		case ARNG_16B:
			Q = 1
			size = 0
		case ARNG_2D:
			Q = 1
			size = 3
		case ARNG_2S:
			Q = 0
			size = 2
		case ARNG_4H:
			Q = 0
			size = 1
		case ARNG_4S:
			Q = 1
			size = 2
		case ARNG_8B:
			Q = 0
			size = 0
		case ARNG_8H:
			Q = 1
			size = 1
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		switch p.As {
		case AVORR, AVAND, AVEOR, AVBIT, AVBSL, AVBIF:
			if af != ARNG_16B && af != ARNG_8B {
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
		case AVFMLA, AVFMLS:
			if af != ARNG_2D && af != ARNG_2S && af != ARNG_4S {
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
		case AVUMAX, AVUMIN:
			if af == ARNG_2D {
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
		}
		switch p.As {
		case AVAND, AVEOR:
			size = 0
		case AVBSL:
			size = 1
		case AVORR, AVBIT, AVBIF:
			size = 2
		case AVFMLA, AVFMLS:
			if af == ARNG_2D {
				size = 1
			} else {
				size = 0
			}
		case AVRAX1:
			if af != ARNG_2D {
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
			size = 0
			Q = 0
		}

		o1 |= (uint32(Q&1) << 30) | (uint32(size&3) << 22) | (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	case 73: /* vmov V.<T>[index], R */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		imm5 := 0
		o1 = 7<<25 | 0xf<<10
		index := int(p.From.Index)
		switch (p.From.Reg >> 5) & 15 {
		case ARNG_B:
			c.checkindex(p, index, 15)
			imm5 |= 1
			imm5 |= index << 1
		case ARNG_H:
			c.checkindex(p, index, 7)
			imm5 |= 2
			imm5 |= index << 2
		case ARNG_S:
			c.checkindex(p, index, 3)
			imm5 |= 4
			imm5 |= index << 3
		case ARNG_D:
			c.checkindex(p, index, 1)
			imm5 |= 8
			imm5 |= index << 4
			o1 |= 1 << 30
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= (uint32(imm5&0x1f) << 16) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 74:
		//	add $O, R, Rtmp or sub $O, R, Rtmp
		//	ldp (Rtmp), (R1, R2)
		rf, rt1, rt2 := p.From.Reg, p.To.Reg, int16(p.To.Offset)
		if rf == obj.REG_NONE {
			rf = o.param
		}
		if rf == obj.REG_NONE {
			c.ctxt.Diag("invalid ldp source: %v", p)
		}
		v := c.regoff(&p.From)
		o1 = c.oaddi12(p, v, REGTMP, rf)
		o2 = c.opldpstp(p, o, 0, REGTMP, rt1, rt2, 1)

	case 75:
		// If offset L fits in a 24 bit unsigned immediate:
		//	add $lo, R, Rtmp
		//	add $hi, Rtmp, Rtmp
		//	ldr (Rtmp), R
		// Otherwise, use constant pool:
		//	mov $L, Rtmp (from constant pool)
		//	add Rtmp, R, Rtmp
		//	ldp (Rtmp), (R1, R2)
		rf, rt1, rt2 := p.From.Reg, p.To.Reg, int16(p.To.Offset)
		if rf == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset load: %v", p)
		}
		if rf == obj.REG_NONE {
			rf = o.param
		}
		if rf == obj.REG_NONE {
			c.ctxt.Diag("invalid ldp source: %v", p)
		}

		v := c.regoff(&p.From)
		if v >= -4095 && v <= 4095 {
			c.ctxt.Diag("%v: bad type for offset %d (should be add/sub+ldp)", p, v)
		}

		hi, lo, err := splitImm24uScaled(v, 0)
		if err != nil {
			goto loadpairusepool
		}
		if p.Pool != nil {
			c.ctxt.Diag("%v: unused constant in pool (%v)\n", p, v)
		}
		o1 = c.oaddi(p, AADD, lo, REGTMP, int16(rf))
		o2 = c.oaddi(p, AADD, hi, REGTMP, REGTMP)
		o3 = c.opldpstp(p, o, 0, REGTMP, rt1, rt2, 1)
		break

	loadpairusepool:
		if p.Pool == nil {
			c.ctxt.Diag("%v: constant is not in pool", p)
		}
		if rf == REGTMP || p.From.Reg == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset load: %v", p)
		}
		o1 = c.omovlit(AMOVD, p, &p.From, REGTMP)
		o2 = c.opxrrr(p, AADD, REGTMP, rf, REGTMP, false)
		o3 = c.opldpstp(p, o, 0, REGTMP, rt1, rt2, 1)

	case 76:
		//	add $O, R, Rtmp or sub $O, R, Rtmp
		//	stp (R1, R2), (Rtmp)
		rt, rf1, rf2 := p.To.Reg, p.From.Reg, int16(p.From.Offset)
		if rf1 == REGTMP || rf2 == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v", p)
		}
		if rt == obj.REG_NONE {
			rt = o.param
		}
		if rt == obj.REG_NONE {
			c.ctxt.Diag("invalid stp destination: %v", p)
		}
		v := c.regoff(&p.To)
		o1 = c.oaddi12(p, v, REGTMP, rt)
		o2 = c.opldpstp(p, o, 0, REGTMP, rf1, rf2, 0)

	case 77:
		// If offset L fits in a 24 bit unsigned immediate:
		//	add $lo, R, Rtmp
		//	add $hi, Rtmp, Rtmp
		//	stp (R1, R2), (Rtmp)
		// Otherwise, use constant pool:
		//	mov $L, Rtmp (from constant pool)
		//	add Rtmp, R, Rtmp
		//	stp (R1, R2), (Rtmp)
		rt, rf1, rf2 := p.To.Reg, p.From.Reg, int16(p.From.Offset)
		if rt == REGTMP || rf1 == REGTMP || rf2 == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset store: %v", p)
		}
		if rt == obj.REG_NONE {
			rt = o.param
		}
		if rt == obj.REG_NONE {
			c.ctxt.Diag("invalid stp destination: %v", p)
		}

		v := c.regoff(&p.To)
		if v >= -4095 && v <= 4095 {
			c.ctxt.Diag("%v: bad type for offset %d (should be add/sub+stp)", p, v)
		}

		hi, lo, err := splitImm24uScaled(v, 0)
		if err != nil {
			goto storepairusepool
		}
		if p.Pool != nil {
			c.ctxt.Diag("%v: unused constant in pool (%v)\n", p, v)
		}
		o1 = c.oaddi(p, AADD, lo, REGTMP, int16(rt))
		o2 = c.oaddi(p, AADD, hi, REGTMP, REGTMP)
		o3 = c.opldpstp(p, o, 0, REGTMP, rf1, rf2, 0)
		break

	storepairusepool:
		if p.Pool == nil {
			c.ctxt.Diag("%v: constant is not in pool", p)
		}
		if rt == REGTMP || p.From.Reg == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset store: %v", p)
		}
		o1 = c.omovlit(AMOVD, p, &p.To, REGTMP)
		o2 = c.opxrrr(p, AADD, REGTMP, rt, REGTMP, false)
		o3 = c.opldpstp(p, o, 0, REGTMP, rf1, rf2, 0)

	case 78: /* vmov R, V.<T>[index] */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		imm5 := 0
		o1 = 1<<30 | 7<<25 | 7<<10
		index := int(p.To.Index)
		switch (p.To.Reg >> 5) & 15 {
		case ARNG_B:
			c.checkindex(p, index, 15)
			imm5 |= 1
			imm5 |= index << 1
		case ARNG_H:
			c.checkindex(p, index, 7)
			imm5 |= 2
			imm5 |= index << 2
		case ARNG_S:
			c.checkindex(p, index, 3)
			imm5 |= 4
			imm5 |= index << 3
		case ARNG_D:
			c.checkindex(p, index, 1)
			imm5 |= 8
			imm5 |= index << 4
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= (uint32(imm5&0x1f) << 16) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 79: /* vdup Vn.<T>[index], Vd.<T> */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		o1 = 7<<25 | 1<<10
		var imm5, Q int
		index := int(p.From.Index)
		switch (p.To.Reg >> 5) & 15 {
		case ARNG_16B:
			c.checkindex(p, index, 15)
			Q = 1
			imm5 = 1
			imm5 |= index << 1
		case ARNG_2D:
			c.checkindex(p, index, 1)
			Q = 1
			imm5 = 8
			imm5 |= index << 4
		case ARNG_2S:
			c.checkindex(p, index, 3)
			Q = 0
			imm5 = 4
			imm5 |= index << 3
		case ARNG_4H:
			c.checkindex(p, index, 7)
			Q = 0
			imm5 = 2
			imm5 |= index << 2
		case ARNG_4S:
			c.checkindex(p, index, 3)
			Q = 1
			imm5 = 4
			imm5 |= index << 3
		case ARNG_8B:
			c.checkindex(p, index, 15)
			Q = 0
			imm5 = 1
			imm5 |= index << 1
		case ARNG_8H:
			c.checkindex(p, index, 7)
			Q = 1
			imm5 = 2
			imm5 |= index << 2
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= (uint32(Q&1) << 30) | (uint32(imm5&0x1f) << 16)
		o1 |= (uint32(rf&31) << 5) | uint32(rt&31)

	case 80: /* vmov/vdup V.<T>[index], Vn */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		imm5 := 0
		index := int(p.From.Index)
		switch p.As {
		case AVMOV, AVDUP:
			o1 = 1<<30 | 15<<25 | 1<<10
			switch (p.From.Reg >> 5) & 15 {
			case ARNG_B:
				c.checkindex(p, index, 15)
				imm5 |= 1
				imm5 |= index << 1
			case ARNG_H:
				c.checkindex(p, index, 7)
				imm5 |= 2
				imm5 |= index << 2
			case ARNG_S:
				c.checkindex(p, index, 3)
				imm5 |= 4
				imm5 |= index << 3
			case ARNG_D:
				c.checkindex(p, index, 1)
				imm5 |= 8
				imm5 |= index << 4
			default:
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
		default:
			c.ctxt.Diag("unsupported op %v", p.As)
		}
		o1 |= (uint32(imm5&0x1f) << 16) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 81: /* vld[1-4]|vld[1-4]r (Rn), [Vt1.<T>, Vt2.<T>, ...] */
		c.checkoffset(p, p.As)
		r := int(p.From.Reg)
		o1 = c.oprrr(p, p.As)
		if o.scond == C_XPOST {
			o1 |= 1 << 23
			if p.From.Index == 0 {
				// immediate offset variant
				o1 |= 0x1f << 16
			} else {
				// register offset variant
				if isRegShiftOrExt(&p.From) {
					c.ctxt.Diag("invalid extended register op: %v\n", p)
				}
				o1 |= uint32(p.From.Index&0x1f) << 16
			}
		}
		o1 |= uint32(p.To.Offset)
		// cmd/asm/internal/arch/arm64.go:ARM64RegisterListOffset
		// add opcode(bit 12-15) for vld1, mask it off if it's not vld1
		o1 = c.maskOpvldvst(p, o1)
		o1 |= uint32(r&31) << 5

	case 82: /* vmov/vdup Rn, Vd.<T> */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		o1 = 7<<25 | 3<<10
		var imm5, Q uint32
		switch (p.To.Reg >> 5) & 15 {
		case ARNG_16B:
			Q = 1
			imm5 = 1
		case ARNG_2D:
			Q = 1
			imm5 = 8
		case ARNG_2S:
			Q = 0
			imm5 = 4
		case ARNG_4H:
			Q = 0
			imm5 = 2
		case ARNG_4S:
			Q = 1
			imm5 = 4
		case ARNG_8B:
			Q = 0
			imm5 = 1
		case ARNG_8H:
			Q = 1
			imm5 = 2
		default:
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		o1 |= (Q & 1 << 30) | (imm5 & 0x1f << 16)
		o1 |= (uint32(rf&31) << 5) | uint32(rt&31)

	case 83: /* vmov Vn.<T>, Vd.<T> */
		af := int((p.From.Reg >> 5) & 15)
		at := int((p.To.Reg >> 5) & 15)
		if af != at {
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		o1 = c.oprrr(p, p.As)
		rf := int((p.From.Reg) & 31)
		rt := int((p.To.Reg) & 31)

		var Q, size uint32
		switch af {
		case ARNG_8B:
			Q = 0
			size = 0
		case ARNG_16B:
			Q = 1
			size = 0
		case ARNG_4H:
			Q = 0
			size = 1
		case ARNG_8H:
			Q = 1
			size = 1
		case ARNG_2S:
			Q = 0
			size = 2
		case ARNG_4S:
			Q = 1
			size = 2
		default:
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}

		if (p.As == AVMOV || p.As == AVRBIT || p.As == AVCNT) && (af != ARNG_16B && af != ARNG_8B) {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if p.As == AVREV32 && (af == ARNG_2S || af == ARNG_4S) {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if p.As == AVREV16 && af != ARNG_8B && af != ARNG_16B {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if p.As == AVMOV {
			o1 |= uint32(rf&31) << 16
		}

		if p.As == AVRBIT {
			size = 1
		}

		o1 |= (Q&1)<<30 | (size&3)<<22 | uint32(rf&31)<<5 | uint32(rt&31)

	case 84: /* vst[1-4] [Vt1.<T>, Vt2.<T>, ...], (Rn) */
		c.checkoffset(p, p.As)
		r := int(p.To.Reg)
		o1 = 3 << 26
		if o.scond == C_XPOST {
			o1 |= 1 << 23
			if p.To.Index == 0 {
				// immediate offset variant
				o1 |= 0x1f << 16
			} else {
				// register offset variant
				if isRegShiftOrExt(&p.To) {
					c.ctxt.Diag("invalid extended register: %v\n", p)
				}
				o1 |= uint32(p.To.Index&31) << 16
			}
		}
		o1 |= uint32(p.From.Offset)
		// cmd/asm/internal/arch/arm64.go:ARM64RegisterListOffset
		// add opcode(bit 12-15) for vst1, mask it off if it's not vst1
		o1 = c.maskOpvldvst(p, o1)
		o1 |= uint32(r&31) << 5

	case 85: /* vaddv/vuaddlv Vn.<T>, Vd*/
		af := int((p.From.Reg >> 5) & 15)
		o1 = c.oprrr(p, p.As)
		rf := int((p.From.Reg) & 31)
		rt := int((p.To.Reg) & 31)
		Q := 0
		size := 0
		switch af {
		case ARNG_8B:
			Q = 0
			size = 0
		case ARNG_16B:
			Q = 1
			size = 0
		case ARNG_4H:
			Q = 0
			size = 1
		case ARNG_8H:
			Q = 1
			size = 1
		case ARNG_4S:
			Q = 1
			size = 2
		default:
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		o1 |= (uint32(Q&1) << 30) | (uint32(size&3) << 22) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 86: /* vmovi $imm8, Vd.<T>*/
		at := int((p.To.Reg >> 5) & 15)
		r := int(p.From.Offset)
		if r > 255 || r < 0 {
			c.ctxt.Diag("immediate constant out of range: %v\n", p)
		}
		rt := int((p.To.Reg) & 31)
		Q := 0
		switch at {
		case ARNG_8B:
			Q = 0
		case ARNG_16B:
			Q = 1
		default:
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		o1 = 0xf<<24 | 0xe<<12 | 1<<10
		o1 |= (uint32(Q&1) << 30) | (uint32((r>>5)&7) << 16) | (uint32(r&0x1f) << 5) | uint32(rt&31)

	case 87: /* stp (r,r), addr(SB) -> adrp + add + stp */
		rf1, rf2 := p.From.Reg, int16(p.From.Offset)
		if rf1 == REGTMP || rf2 == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v", p)
		}
		o1 = ADR(1, 0, REGTMP)
		o2 = c.opirr(p, AADD) | REGTMP&31<<5 | REGTMP&31
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRARM64,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})
		o3 = c.opldpstp(p, o, 0, REGTMP, rf1, rf2, 0)

	case 88: /* ldp addr(SB), (r,r) -> adrp + add + ldp */
		rt1, rt2 := p.To.Reg, int16(p.To.Offset)
		o1 = ADR(1, 0, REGTMP)
		o2 = c.opirr(p, AADD) | REGTMP&31<<5 | REGTMP&31
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRARM64,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})
		o3 = c.opldpstp(p, o, 0, REGTMP, rt1, rt2, 1)

	case 89: /* vadd/vsub Vm, Vn, Vd */
		switch p.As {
		case AVADD:
			o1 = 5<<28 | 7<<25 | 7<<21 | 1<<15 | 1<<10

		case AVSUB:
			o1 = 7<<28 | 7<<25 | 7<<21 | 1<<15 | 1<<10

		default:
			c.ctxt.Diag("bad opcode: %v\n", p)
			break
		}

		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		r := int(p.Reg)
		if r == obj.REG_NONE {
			r = rt
		}
		o1 |= (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	// This is supposed to be something that stops execution.
	// It's not supposed to be reached, ever, but if it is, we'd
	// like to be able to tell how we got there. Assemble as
	// UDF which is guaranteed to raise the undefined instruction
	// exception.
	case 90:
		o1 = 0x0

	case 91: /* prfm imm(Rn), <prfop | $imm5> */
		imm := uint32(p.From.Offset)
		r := p.From.Reg
		var v uint32
		var ok bool
		if p.To.Type == obj.TYPE_CONST {
			v = uint32(p.To.Offset)
			ok = v <= 31
		} else {
			v, ok = prfopfield[SpecialOperand(p.To.Offset)]
		}
		if !ok {
			c.ctxt.Diag("illegal prefetch operation:\n%v", p)
		}

		o1 = c.opirr(p, p.As)
		o1 |= (uint32(r&31) << 5) | (uint32((imm>>3)&0xfff) << 10) | (uint32(v & 31))

	case 92: /* vmov Vn.<T>[index], Vd.<T>[index] */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		imm4 := 0
		imm5 := 0
		o1 = 3<<29 | 7<<25 | 1<<10
		index1 := int(p.To.Index)
		index2 := int(p.From.Index)
		if ((p.To.Reg >> 5) & 15) != ((p.From.Reg >> 5) & 15) {
			c.ctxt.Diag("operand mismatch: %v", p)
		}
		switch (p.To.Reg >> 5) & 15 {
		case ARNG_B:
			c.checkindex(p, index1, 15)
			c.checkindex(p, index2, 15)
			imm5 |= 1
			imm5 |= index1 << 1
			imm4 |= index2
		case ARNG_H:
			c.checkindex(p, index1, 7)
			c.checkindex(p, index2, 7)
			imm5 |= 2
			imm5 |= index1 << 2
			imm4 |= index2 << 1
		case ARNG_S:
			c.checkindex(p, index1, 3)
			c.checkindex(p, index2, 3)
			imm5 |= 4
			imm5 |= index1 << 3
			imm4 |= index2 << 2
		case ARNG_D:
			c.checkindex(p, index1, 1)
			c.checkindex(p, index2, 1)
			imm5 |= 8
			imm5 |= index1 << 4
			imm4 |= index2 << 3
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= (uint32(imm5&0x1f) << 16) | (uint32(imm4&0xf) << 11) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 93: /* vpmull{2} Vm.<Tb>, Vn.<Tb>, Vd.<Ta> */
		af := uint8((p.From.Reg >> 5) & 15)
		at := uint8((p.To.Reg >> 5) & 15)
		a := uint8((p.Reg >> 5) & 15)
		if af != a {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		var Q, size uint32
		if p.As == AVPMULL2 {
			Q = 1
		}
		switch pack(Q, at, af) {
		case pack(0, ARNG_8H, ARNG_8B), pack(1, ARNG_8H, ARNG_16B):
			size = 0
		case pack(0, ARNG_1Q, ARNG_1D), pack(1, ARNG_1Q, ARNG_2D):
			size = 3
		default:
			c.ctxt.Diag("operand mismatch: %v\n", p)
		}

		o1 = c.oprrr(p, p.As)
		rf := int((p.From.Reg) & 31)
		rt := int((p.To.Reg) & 31)
		r := int((p.Reg) & 31)
		o1 |= ((Q & 1) << 30) | ((size & 3) << 22) | (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	case 94: /* vext $imm4, Vm.<T>, Vn.<T>, Vd.<T> */
		af := int(((p.GetFrom3().Reg) >> 5) & 15)
		at := int((p.To.Reg >> 5) & 15)
		a := int((p.Reg >> 5) & 15)
		index := int(p.From.Offset)

		if af != a || af != at {
			c.ctxt.Diag("invalid arrangement: %v", p)
			break
		}

		var Q uint32
		var b int
		if af == ARNG_8B {
			Q = 0
			b = 7
		} else if af == ARNG_16B {
			Q = 1
			b = 15
		} else {
			c.ctxt.Diag("invalid arrangement, should be B8 or B16: %v", p)
			break
		}

		if index < 0 || index > b {
			c.ctxt.Diag("illegal offset: %v", p)
		}

		o1 = c.opirr(p, p.As)
		rf := int((p.GetFrom3().Reg) & 31)
		rt := int((p.To.Reg) & 31)
		r := int((p.Reg) & 31)

		o1 |= ((Q & 1) << 30) | (uint32(r&31) << 16) | (uint32(index&15) << 11) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 95: /* vushr/vshl/vsri/vsli/vusra $shift, Vn.<T>, Vd.<T> */
		at := int((p.To.Reg >> 5) & 15)
		af := int((p.Reg >> 5) & 15)
		shift := int(p.From.Offset)

		if af != at {
			c.ctxt.Diag("invalid arrangement on op Vn.<T>, Vd.<T>: %v", p)
		}

		var Q uint32
		var imax, esize int

		switch af {
		case ARNG_8B, ARNG_4H, ARNG_2S:
			Q = 0
		case ARNG_16B, ARNG_8H, ARNG_4S, ARNG_2D:
			Q = 1
		default:
			c.ctxt.Diag("invalid arrangement on op Vn.<T>, Vd.<T>: %v", p)
		}

		switch af {
		case ARNG_8B, ARNG_16B:
			imax = 15
			esize = 8
		case ARNG_4H, ARNG_8H:
			imax = 31
			esize = 16
		case ARNG_2S, ARNG_4S:
			imax = 63
			esize = 32
		case ARNG_2D:
			imax = 127
			esize = 64
		}

		imm := 0
		switch p.As {
		case AVUSHR, AVSRI, AVUSRA:
			imm = esize*2 - shift
			if imm < esize || imm > imax {
				c.ctxt.Diag("shift out of range: %v", p)
			}
		case AVSHL, AVSLI:
			imm = esize + shift
			if imm > imax {
				c.ctxt.Diag("shift out of range: %v", p)
			}
		default:
			c.ctxt.Diag("invalid instruction %v\n", p)
		}

		o1 = c.opirr(p, p.As)
		rt := int((p.To.Reg) & 31)
		rf := int((p.Reg) & 31)

		o1 |= ((Q & 1) << 30) | (uint32(imm&0x7f) << 16) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 96: /* vst1 Vt1.<T>[index], offset(Rn) */
		af := int((p.From.Reg >> 5) & 15)
		rt := int((p.From.Reg) & 31)
		rf := int((p.To.Reg) & 31)
		r := int(p.To.Index & 31)
		index := int(p.From.Index)
		offset := c.regoff(&p.To)

		if o.scond == C_XPOST {
			if (p.To.Index != 0) && (offset != 0) {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			if p.To.Index == 0 && offset == 0 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
		}

		if offset != 0 {
			r = 31
		}

		var Q, S, size int
		var opcode uint32
		switch af {
		case ARNG_B:
			c.checkindex(p, index, 15)
			if o.scond == C_XPOST && offset != 0 && offset != 1 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 3
			S = (index >> 2) & 1
			size = index & 3
			opcode = 0
		case ARNG_H:
			c.checkindex(p, index, 7)
			if o.scond == C_XPOST && offset != 0 && offset != 2 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 2
			S = (index >> 1) & 1
			size = (index & 1) << 1
			opcode = 2
		case ARNG_S:
			c.checkindex(p, index, 3)
			if o.scond == C_XPOST && offset != 0 && offset != 4 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 1
			S = index & 1
			size = 0
			opcode = 4
		case ARNG_D:
			c.checkindex(p, index, 1)
			if o.scond == C_XPOST && offset != 0 && offset != 8 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index
			S = 0
			size = 1
			opcode = 4
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if o.scond == C_XPOST {
			o1 |= 27 << 23
		} else {
			o1 |= 26 << 23
		}

		o1 |= (uint32(Q&1) << 30) | (uint32(r&31) << 16) | ((opcode & 7) << 13) | (uint32(S&1) << 12) | (uint32(size&3) << 10) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 97: /* vld1 offset(Rn), vt.<T>[index] */
		at := int((p.To.Reg >> 5) & 15)
		rt := int((p.To.Reg) & 31)
		rf := int((p.From.Reg) & 31)
		r := int(p.From.Index & 31)
		index := int(p.To.Index)
		offset := c.regoff(&p.From)

		if o.scond == C_XPOST {
			if (p.From.Index != 0) && (offset != 0) {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			if p.From.Index == 0 && offset == 0 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
		}

		if offset != 0 {
			r = 31
		}

		Q := 0
		S := 0
		size := 0
		var opcode uint32
		switch at {
		case ARNG_B:
			c.checkindex(p, index, 15)
			if o.scond == C_XPOST && offset != 0 && offset != 1 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 3
			S = (index >> 2) & 1
			size = index & 3
			opcode = 0
		case ARNG_H:
			c.checkindex(p, index, 7)
			if o.scond == C_XPOST && offset != 0 && offset != 2 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 2
			S = (index >> 1) & 1
			size = (index & 1) << 1
			opcode = 2
		case ARNG_S:
			c.checkindex(p, index, 3)
			if o.scond == C_XPOST && offset != 0 && offset != 4 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 1
			S = index & 1
			size = 0
			opcode = 4
		case ARNG_D:
			c.checkindex(p, index, 1)
			if o.scond == C_XPOST && offset != 0 && offset != 8 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index
			S = 0
			size = 1
			opcode = 4
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if o.scond == C_XPOST {
			o1 |= 110 << 21
		} else {
			o1 |= 106 << 21
		}

		o1 |= (uint32(Q&1) << 30) | (uint32(r&31) << 16) | ((opcode & 7) << 13) | (uint32(S&1) << 12) | (uint32(size&3) << 10) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 98: /* MOVD (Rn)(Rm.SXTW[<<amount]),Rd */
		if isRegShiftOrExt(&p.From) {
			// extended or shifted offset register.
			c.checkShiftAmount(p, &p.From)

			o1 = c.opldrr(p, p.As, true)
			o1 |= c.encRegShiftOrExt(p, &p.From, p.From.Index) /* includes reg, op, etc */
		} else {
			// (Rn)(Rm), no extension or shift.
			o1 = c.opldrr(p, p.As, false)
			o1 |= uint32(p.From.Index&31) << 16
		}
		o1 |= uint32(p.From.Reg&31) << 5
		rt := int(p.To.Reg)
		o1 |= uint32(rt & 31)

	case 99: /* MOVD Rt, (Rn)(Rm.SXTW[<<amount]) */
		if isRegShiftOrExt(&p.To) {
			// extended or shifted offset register.
			c.checkShiftAmount(p, &p.To)

			o1 = c.opstrr(p, p.As, true)
			o1 |= c.encRegShiftOrExt(p, &p.To, p.To.Index) /* includes reg, op, etc */
		} else {
			// (Rn)(Rm), no extension or shift.
			o1 = c.opstrr(p, p.As, false)
			o1 |= uint32(p.To.Index&31) << 16
		}
		o1 |= uint32(p.To.Reg&31) << 5
		rf := int(p.From.Reg)
		o1 |= uint32(rf & 31)

	case 100: /* VTBL/VTBX Vn.<T>, [Vt1.<T>, Vt2.<T>, ...], Vd.<T> */
		af := int((p.From.Reg >> 5) & 15)
		at := int((p.To.Reg >> 5) & 15)
		if af != at {
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		var q, len uint32
		switch af {
		case ARNG_8B:
			q = 0
		case ARNG_16B:
			q = 1
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		offset := int(p.GetFrom3().Offset)
		opcode := (offset >> 12) & 15
		switch opcode {
		case 0x7:
			len = 0 // one register
		case 0xa:
			len = 1 // two register
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