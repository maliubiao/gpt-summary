Response: 
Prompt: 
```
这是路径为go/src/cmd/internal/obj/ppc64/asm9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共3部分，请归纳一下它的功能

"""
(AMOVWZ, r0) /* Same as above, but zero extended */

		case AVCLZLSBB:
			opset(AVCTZLSBB, r0)

		case AADD,
			AADDIS,
			AANDCC, /* and. Rb,Rs,Ra; andi. $uimm,Rs,Ra */
			AANDISCC,
			AFMOVSX,
			AFMOVSZ,
			ALSW,
			AMOVD,  /* load/store/move 64-bit values, including 32-bit literals with/without sign-extension */
			AMOVB,  /* macro: move byte with sign extension */
			AMOVBU, /* macro: move byte with sign extension & update */
			AMOVFL,
			/* op $s[,r2],r3; op r1[,r2],r3; no cc/v */
			ASUBC, /* op r1,$s,r3; op r1[,r2],r3 */
			ASTSW,
			ASLBMTE,
			AWORD,
			ADWORD,
			ADARN,
			AVMSUMUDM,
			AADDEX,
			ACMPEQB,
			ACLRLSLWI,
			AMTVSRDD,
			APNOP,
			AISEL,
			ASETB,
			obj.ANOP,
			obj.ATEXT,
			obj.AUNDEF,
			obj.AFUNCDATA,
			obj.APCALIGN,
			obj.APCDATA,
			obj.ADUFFZERO,
			obj.ADUFFCOPY:
			break
		}
	}
}

func OPVXX1(o uint32, xo uint32, oe uint32) uint32 {
	return o<<26 | xo<<1 | oe<<11
}

func OPVXX2(o uint32, xo uint32, oe uint32) uint32 {
	return o<<26 | xo<<2 | oe<<11
}

func OPVXX2VA(o uint32, xo uint32, oe uint32) uint32 {
	return o<<26 | xo<<2 | oe<<16
}

func OPVXX3(o uint32, xo uint32, oe uint32) uint32 {
	return o<<26 | xo<<3 | oe<<11
}

func OPVXX4(o uint32, xo uint32, oe uint32) uint32 {
	return o<<26 | xo<<4 | oe<<11
}

func OPDQ(o uint32, xo uint32, oe uint32) uint32 {
	return o<<26 | xo | oe<<4
}

func OPVX(o uint32, xo uint32, oe uint32, rc uint32) uint32 {
	return o<<26 | xo | oe<<11 | rc&1
}

func OPVC(o uint32, xo uint32, oe uint32, rc uint32) uint32 {
	return o<<26 | xo | oe<<11 | (rc&1)<<10
}

func OPVCC(o uint32, xo uint32, oe uint32, rc uint32) uint32 {
	return o<<26 | xo<<1 | oe<<10 | rc&1
}

func OPCC(o uint32, xo uint32, rc uint32) uint32 {
	return OPVCC(o, xo, 0, rc)
}

/* Generate MD-form opcode */
func OPMD(o, xo, rc uint32) uint32 {
	return o<<26 | xo<<2 | rc&1
}

/* the order is dest, a/s, b/imm for both arithmetic and logical operations. */
func AOP_RRR(op uint32, d uint32, a uint32, b uint32) uint32 {
	return op | (d&31)<<21 | (a&31)<<16 | (b&31)<<11
}

/* VX-form 2-register operands, r/none/r */
func AOP_RR(op uint32, d uint32, a uint32) uint32 {
	return op | (d&31)<<21 | (a&31)<<11
}

/* VA-form 4-register operands */
func AOP_RRRR(op uint32, d uint32, a uint32, b uint32, c uint32) uint32 {
	return op | (d&31)<<21 | (a&31)<<16 | (b&31)<<11 | (c&31)<<6
}

func AOP_IRR(op uint32, d uint32, a uint32, simm uint32) uint32 {
	return op | (d&31)<<21 | (a&31)<<16 | simm&0xFFFF
}

/* VX-form 2-register + UIM operands */
func AOP_VIRR(op uint32, d uint32, a uint32, simm uint32) uint32 {
	return op | (d&31)<<21 | (simm&0xFFFF)<<16 | (a&31)<<11
}

/* VX-form 2-register + ST + SIX operands */
func AOP_IIRR(op uint32, d uint32, a uint32, sbit uint32, simm uint32) uint32 {
	return op | (d&31)<<21 | (a&31)<<16 | (sbit&1)<<15 | (simm&0xF)<<11
}

/* VA-form 3-register + SHB operands */
func AOP_IRRR(op uint32, d uint32, a uint32, b uint32, simm uint32) uint32 {
	return op | (d&31)<<21 | (a&31)<<16 | (b&31)<<11 | (simm&0xF)<<6
}

/* VX-form 1-register + SIM operands */
func AOP_IR(op uint32, d uint32, simm uint32) uint32 {
	return op | (d&31)<<21 | (simm&31)<<16
}

/* XX1-form 3-register operands, 1 VSR operand */
func AOP_XX1(op uint32, r uint32, a uint32, b uint32) uint32 {
	return op | (r&31)<<21 | (a&31)<<16 | (b&31)<<11 | (r&32)>>5
}

/* XX2-form 3-register operands, 2 VSR operands */
func AOP_XX2(op uint32, xt uint32, a uint32, xb uint32) uint32 {
	return op | (xt&31)<<21 | (a&3)<<16 | (xb&31)<<11 | (xb&32)>>4 | (xt&32)>>5
}

/* XX3-form 3 VSR operands */
func AOP_XX3(op uint32, xt uint32, xa uint32, xb uint32) uint32 {
	return op | (xt&31)<<21 | (xa&31)<<16 | (xb&31)<<11 | (xa&32)>>3 | (xb&32)>>4 | (xt&32)>>5
}

/* XX3-form 3 VSR operands + immediate */
func AOP_XX3I(op uint32, xt uint32, xa uint32, xb uint32, c uint32) uint32 {
	return op | (xt&31)<<21 | (xa&31)<<16 | (xb&31)<<11 | (c&3)<<8 | (xa&32)>>3 | (xb&32)>>4 | (xt&32)>>5
}

/* XX4-form, 4 VSR operands */
func AOP_XX4(op uint32, xt uint32, xa uint32, xb uint32, xc uint32) uint32 {
	return op | (xt&31)<<21 | (xa&31)<<16 | (xb&31)<<11 | (xc&31)<<6 | (xc&32)>>2 | (xa&32)>>3 | (xb&32)>>4 | (xt&32)>>5
}

/* DQ-form, VSR register, register + offset operands */
func AOP_DQ(op uint32, xt uint32, a uint32, b uint32) uint32 {
	/* The EA for this instruction form is (RA) + DQ << 4, where DQ is a 12-bit signed integer. */
	/* In order to match the output of the GNU objdump (and make the usage in Go asm easier), the */
	/* instruction is called using the sign extended value (i.e. a valid offset would be -32752 or 32752, */
	/* not -2047 or 2047), so 'b' needs to be adjusted to the expected 12-bit DQ value. Bear in mind that */
	/* bits 0 to 3 in 'dq' need to be zero, otherwise this will generate an illegal instruction. */
	/* If in doubt how this instruction form is encoded, refer to ISA 3.0b, pages 492 and 507. */
	dq := b >> 4
	return op | (xt&31)<<21 | (a&31)<<16 | (dq&4095)<<4 | (xt&32)>>2
}

/* Z23-form, 3-register operands + CY field */
func AOP_Z23I(op uint32, d uint32, a uint32, b uint32, c uint32) uint32 {
	return op | (d&31)<<21 | (a&31)<<16 | (b&31)<<11 | (c&3)<<9
}

/* X-form, 3-register operands + EH field */
func AOP_RRRI(op uint32, d uint32, a uint32, b uint32, c uint32) uint32 {
	return op | (d&31)<<21 | (a&31)<<16 | (b&31)<<11 | (c & 1)
}

func LOP_RRR(op uint32, a uint32, s uint32, b uint32) uint32 {
	return op | (s&31)<<21 | (a&31)<<16 | (b&31)<<11
}

func LOP_IRR(op uint32, a uint32, s uint32, uimm uint32) uint32 {
	return op | (s&31)<<21 | (a&31)<<16 | uimm&0xFFFF
}

func OP_BR(op uint32, li uint32, aa uint32) uint32 {
	return op | li&0x03FFFFFC | aa<<1
}

func OP_BC(op uint32, bo uint32, bi uint32, bd uint32, aa uint32) uint32 {
	return op | (bo&0x1F)<<21 | (bi&0x1F)<<16 | bd&0xFFFC | aa<<1
}

func OP_BCR(op uint32, bo uint32, bi uint32) uint32 {
	return op | (bo&0x1F)<<21 | (bi&0x1F)<<16
}

func OP_RLW(op uint32, a uint32, s uint32, sh uint32, mb uint32, me uint32) uint32 {
	return op | (s&31)<<21 | (a&31)<<16 | (sh&31)<<11 | (mb&31)<<6 | (me&31)<<1
}

func AOP_EXTSWSLI(op uint32, a uint32, s uint32, sh uint32) uint32 {
	return op | (a&31)<<21 | (s&31)<<16 | (sh&31)<<11 | ((sh&32)>>5)<<1
}

func AOP_ISEL(op uint32, t uint32, a uint32, b uint32, bc uint32) uint32 {
	return op | (t&31)<<21 | (a&31)<<16 | (b&31)<<11 | (bc&0x1F)<<6
}

/* MD-form 2-register, 2 6-bit immediate operands */
func AOP_MD(op uint32, a uint32, s uint32, sh uint32, m uint32) uint32 {
	return op | (s&31)<<21 | (a&31)<<16 | (sh&31)<<11 | ((sh&32)>>5)<<1 | (m&31)<<6 | ((m&32)>>5)<<5
}

/* MDS-form 3-register, 1 6-bit immediate operands. rsh argument is a register. */
func AOP_MDS(op, to, from, rsh, m uint32) uint32 {
	return AOP_MD(op, to, from, rsh&31, m)
}

func AOP_PFX_00_8LS(r, ie uint32) uint32 {
	return 1<<26 | 0<<24 | 0<<23 | (r&1)<<20 | (ie & 0x3FFFF)
}
func AOP_PFX_10_MLS(r, ie uint32) uint32 {
	return 1<<26 | 2<<24 | 0<<23 | (r&1)<<20 | (ie & 0x3FFFF)
}

const (
	/* each rhs is OPVCC(_, _, _, _) */
	OP_ADD      = 31<<26 | 266<<1 | 0<<10 | 0
	OP_ADDI     = 14<<26 | 0<<1 | 0<<10 | 0
	OP_ADDIS    = 15<<26 | 0<<1 | 0<<10 | 0
	OP_ANDI     = 28<<26 | 0<<1 | 0<<10 | 0
	OP_EXTSB    = 31<<26 | 954<<1 | 0<<10 | 0
	OP_EXTSH    = 31<<26 | 922<<1 | 0<<10 | 0
	OP_EXTSW    = 31<<26 | 986<<1 | 0<<10 | 0
	OP_ISEL     = 31<<26 | 15<<1 | 0<<10 | 0
	OP_MCRF     = 19<<26 | 0<<1 | 0<<10 | 0
	OP_MCRFS    = 63<<26 | 64<<1 | 0<<10 | 0
	OP_MCRXR    = 31<<26 | 512<<1 | 0<<10 | 0
	OP_MFCR     = 31<<26 | 19<<1 | 0<<10 | 0
	OP_MFFS     = 63<<26 | 583<<1 | 0<<10 | 0
	OP_MFSPR    = 31<<26 | 339<<1 | 0<<10 | 0
	OP_MFSR     = 31<<26 | 595<<1 | 0<<10 | 0
	OP_MFSRIN   = 31<<26 | 659<<1 | 0<<10 | 0
	OP_MTCRF    = 31<<26 | 144<<1 | 0<<10 | 0
	OP_MTFSF    = 63<<26 | 711<<1 | 0<<10 | 0
	OP_MTFSFI   = 63<<26 | 134<<1 | 0<<10 | 0
	OP_MTSPR    = 31<<26 | 467<<1 | 0<<10 | 0
	OP_MTSR     = 31<<26 | 210<<1 | 0<<10 | 0
	OP_MTSRIN   = 31<<26 | 242<<1 | 0<<10 | 0
	OP_MULLW    = 31<<26 | 235<<1 | 0<<10 | 0
	OP_MULLD    = 31<<26 | 233<<1 | 0<<10 | 0
	OP_OR       = 31<<26 | 444<<1 | 0<<10 | 0
	OP_ORI      = 24<<26 | 0<<1 | 0<<10 | 0
	OP_ORIS     = 25<<26 | 0<<1 | 0<<10 | 0
	OP_XORI     = 26<<26 | 0<<1 | 0<<10 | 0
	OP_XORIS    = 27<<26 | 0<<1 | 0<<10 | 0
	OP_RLWINM   = 21<<26 | 0<<1 | 0<<10 | 0
	OP_RLWNM    = 23<<26 | 0<<1 | 0<<10 | 0
	OP_SUBF     = 31<<26 | 40<<1 | 0<<10 | 0
	OP_RLDIC    = 30<<26 | 4<<1 | 0<<10 | 0
	OP_RLDICR   = 30<<26 | 2<<1 | 0<<10 | 0
	OP_RLDICL   = 30<<26 | 0<<1 | 0<<10 | 0
	OP_RLDCL    = 30<<26 | 8<<1 | 0<<10 | 0
	OP_EXTSWSLI = 31<<26 | 445<<2
	OP_SETB     = 31<<26 | 128<<1
)

func pfxadd(rt, ra int16, r uint32, imm32 int64) (uint32, uint32) {
	return AOP_PFX_10_MLS(r, uint32(imm32>>16)), AOP_IRR(14<<26, uint32(rt), uint32(ra), uint32(imm32))
}

func pfxload(a obj.As, reg int16, base int16, r uint32) (uint32, uint32) {
	switch a {
	case AMOVH:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(42<<26, uint32(reg), uint32(base), 0)
	case AMOVW:
		return AOP_PFX_00_8LS(r, 0), AOP_IRR(41<<26, uint32(reg), uint32(base), 0)
	case AMOVD:
		return AOP_PFX_00_8LS(r, 0), AOP_IRR(57<<26, uint32(reg), uint32(base), 0)
	case AMOVBZ, AMOVB:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(34<<26, uint32(reg), uint32(base), 0)
	case AMOVHZ:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(40<<26, uint32(reg), uint32(base), 0)
	case AMOVWZ:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(32<<26, uint32(reg), uint32(base), 0)
	case AFMOVS:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(48<<26, uint32(reg), uint32(base), 0)
	case AFMOVD:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(50<<26, uint32(reg), uint32(base), 0)
	}
	log.Fatalf("Error no pfxload for %v\n", a)
	return 0, 0
}

func pfxstore(a obj.As, reg int16, base int16, r uint32) (uint32, uint32) {
	switch a {
	case AMOVD:
		return AOP_PFX_00_8LS(r, 0), AOP_IRR(61<<26, uint32(reg), uint32(base), 0)
	case AMOVBZ, AMOVB:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(38<<26, uint32(reg), uint32(base), 0)
	case AMOVHZ, AMOVH:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(44<<26, uint32(reg), uint32(base), 0)
	case AMOVWZ, AMOVW:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(36<<26, uint32(reg), uint32(base), 0)
	case AFMOVS:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(52<<26, uint32(reg), uint32(base), 0)
	case AFMOVD:
		return AOP_PFX_10_MLS(r, 0), AOP_IRR(54<<26, uint32(reg), uint32(base), 0)
	}
	log.Fatalf("Error no pfxstore for %v\n", a)
	return 0, 0
}

func oclass(a *obj.Addr) int {
	return int(a.Class) - 1
}

const (
	D_FORM = iota
	DS_FORM
)

// This function determines when a non-indexed load or store is D or
// DS form for use in finding the size of the offset field in the instruction.
// The size is needed when setting the offset value in the instruction
// and when generating relocation for that field.
// DS form instructions include: ld, ldu, lwa, std, stdu.  All other
// loads and stores with an offset field are D form.  This function should
// only be called with the same opcodes as are handled by opstore and opload.
func (c *ctxt9) opform(insn uint32) int {
	switch insn {
	default:
		c.ctxt.Diag("bad insn in loadform: %x", insn)
	case OPVCC(58, 0, 0, 0), // ld
		OPVCC(58, 0, 0, 1),        // ldu
		OPVCC(58, 0, 0, 0) | 1<<1, // lwa
		OPVCC(62, 0, 0, 0),        // std
		OPVCC(62, 0, 0, 1):        //stdu
		return DS_FORM
	case OP_ADDI, // add
		OPVCC(32, 0, 0, 0), // lwz
		OPVCC(33, 0, 0, 0), // lwzu
		OPVCC(34, 0, 0, 0), // lbz
		OPVCC(35, 0, 0, 0), // lbzu
		OPVCC(40, 0, 0, 0), // lhz
		OPVCC(41, 0, 0, 0), // lhzu
		OPVCC(42, 0, 0, 0), // lha
		OPVCC(43, 0, 0, 0), // lhau
		OPVCC(46, 0, 0, 0), // lmw
		OPVCC(48, 0, 0, 0), // lfs
		OPVCC(49, 0, 0, 0), // lfsu
		OPVCC(50, 0, 0, 0), // lfd
		OPVCC(51, 0, 0, 0), // lfdu
		OPVCC(36, 0, 0, 0), // stw
		OPVCC(37, 0, 0, 0), // stwu
		OPVCC(38, 0, 0, 0), // stb
		OPVCC(39, 0, 0, 0), // stbu
		OPVCC(44, 0, 0, 0), // sth
		OPVCC(45, 0, 0, 0), // sthu
		OPVCC(47, 0, 0, 0), // stmw
		OPVCC(52, 0, 0, 0), // stfs
		OPVCC(53, 0, 0, 0), // stfsu
		OPVCC(54, 0, 0, 0), // stfd
		OPVCC(55, 0, 0, 0): // stfdu
		return D_FORM
	}
	return 0
}

// Encode instructions and create relocation for accessing s+d according to the
// instruction op with source or destination (as appropriate) register reg.
// The caller must call c.cursym.AddRel(c.ctxt, rel) when finished editing rel.
func (c *ctxt9) symbolAccess(s *obj.LSym, d int64, reg int16, op uint32, reuse bool) (o1, o2 uint32, rel obj.Reloc) {
	if c.ctxt.Headtype == objabi.Haix {
		// Every symbol access must be made via a TOC anchor.
		c.ctxt.Diag("symbolAccess called for %s", s.Name)
	}
	var base uint32
	form := c.opform(op)
	if c.ctxt.Flag_shared {
		base = REG_R2
	} else {
		base = REG_R0
	}
	// If reg can be reused when computing the symbol address,
	// use it instead of REGTMP.
	if !reuse {
		o1 = AOP_IRR(OP_ADDIS, REGTMP, base, 0)
		o2 = AOP_IRR(op, uint32(reg), REGTMP, 0)
	} else {
		o1 = AOP_IRR(OP_ADDIS, uint32(reg), base, 0)
		o2 = AOP_IRR(op, uint32(reg), uint32(reg), 0)
	}
	var typ objabi.RelocType
	if c.ctxt.Flag_shared {
		switch form {
		case D_FORM:
			typ = objabi.R_ADDRPOWER_TOCREL
		case DS_FORM:
			typ = objabi.R_ADDRPOWER_TOCREL_DS
		}
	} else {
		switch form {
		case D_FORM:
			typ = objabi.R_ADDRPOWER
		case DS_FORM:
			typ = objabi.R_ADDRPOWER_DS
		}
	}
	rel = obj.Reloc{
		Type: typ,
		Off:  int32(c.pc),
		Siz:  8,
		Sym:  s,
		Add:  d,
	}
	return
}

// Determine the mask begin (mb) and mask end (me) values
// for a valid word rotate mask. A valid 32 bit mask is of
// the form 1+0*1+ or 0*1+0*.
//
// Note, me is inclusive.
func decodeMask32(mask uint32) (mb, me uint32, valid bool) {
	mb = uint32(bits.LeadingZeros32(mask))
	me = uint32(32 - bits.TrailingZeros32(mask))
	mbn := uint32(bits.LeadingZeros32(^mask))
	men := uint32(32 - bits.TrailingZeros32(^mask))
	// Check for a wrapping mask (e.g bits at 0 and 31)
	if mb == 0 && me == 32 {
		// swap the inverted values
		mb, me = men, mbn
	}

	// Validate mask is of the binary form 1+0*1+ or 0*1+0*
	// Isolate rightmost 1 (if none 0) and add.
	v := mask
	vp := (v & -v) + v
	// Likewise, check for the wrapping (inverted) case.
	vn := ^v
	vpn := (vn & -vn) + vn
	return mb, (me - 1) & 31, (v&vp == 0 || vn&vpn == 0) && v != 0
}

// Decompose a mask of contiguous bits into a begin (mb) and
// end (me) value.
//
// 64b mask values cannot wrap on any valid PPC64 instruction.
// Only masks of the form 0*1+0* are valid.
//
// Note, me is inclusive.
func decodeMask64(mask int64) (mb, me uint32, valid bool) {
	m := uint64(mask)
	mb = uint32(bits.LeadingZeros64(m))
	me = uint32(64 - bits.TrailingZeros64(m))
	valid = ((m&-m)+m)&m == 0 && m != 0
	return mb, (me - 1) & 63, valid
}

// Load the lower 16 bits of a constant into register r.
func loadl16(r int, d int64) uint32 {
	v := uint16(d)
	if v == 0 {
		// Avoid generating "ori r,r,0", r != 0. Instead, generate the architecturally preferred nop.
		// For example, "ori r31,r31,0" is a special execution serializing nop on Power10 called "exser".
		return NOP
	}
	return LOP_IRR(OP_ORI, uint32(r), uint32(r), uint32(v))
}

// Load the upper 16 bits of a 32b constant into register r.
func loadu32(r int, d int64) uint32 {
	v := int32(d >> 16)
	if isuint32(uint64(d)) {
		return LOP_IRR(OP_ORIS, uint32(r), REGZERO, uint32(v))
	}
	return AOP_IRR(OP_ADDIS, uint32(r), REGZERO, uint32(v))
}

func high16adjusted(d int32) uint16 {
	if d&0x8000 != 0 {
		return uint16((d >> 16) + 1)
	}
	return uint16(d >> 16)
}

func asmout(c *ctxt9, p *obj.Prog, o *Optab, out *[5]uint32) {
	o1 := uint32(0)
	o2 := uint32(0)
	o3 := uint32(0)
	o4 := uint32(0)
	o5 := uint32(0)

	//print("%v => case %d\n", p, o->type);
	switch o.type_ {
	default:
		c.ctxt.Diag("unknown type %d", o.type_)
		prasm(p)

	case 0: /* pseudo ops */
		break

	case 2: /* int/cr/fp op Rb,[Ra],Rd */
		r := int(p.Reg)

		if r == 0 {
			r = int(p.To.Reg)
		}
		o1 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(r), uint32(p.From.Reg))

	case 3: /* mov $soreg/16con, r ==> addi/ori $i,reg',r */
		d := c.vregoff(&p.From)

		v := int32(d)
		r := int(p.From.Reg)

		if r0iszero != 0 /*TypeKind(100016)*/ && p.To.Reg == 0 && (r != 0 || v != 0) {
			c.ctxt.Diag("literal operation on R0\n%v", p)
		}
		if int64(int16(d)) == d {
			// MOVD $int16, Ry  or  MOVD $offset(Rx), Ry
			o1 = AOP_IRR(uint32(OP_ADDI), uint32(p.To.Reg), uint32(r), uint32(v))
		} else {
			// MOVD $uint16, Ry
			if int64(uint16(d)) != d || (r != 0 && r != REGZERO) {
				c.ctxt.Diag("Rule expects a uint16 constant load. got:\n%v", p)
			}
			o1 = LOP_IRR(uint32(OP_ORI), uint32(p.To.Reg), uint32(0), uint32(v))
		}

	case 4: /* add/mul $scon,[r1],r2 */
		v := c.regoff(&p.From)

		r := int(p.Reg)
		if r == 0 {
			r = int(p.To.Reg)
		}
		if r0iszero != 0 /*TypeKind(100016)*/ && p.To.Reg == 0 {
			c.ctxt.Diag("literal operation on R0\n%v", p)
		}
		if int32(int16(v)) != v {
			log.Fatalf("mishandled instruction %v", p)
		}
		o1 = AOP_IRR(c.opirr(p.As), uint32(p.To.Reg), uint32(r), uint32(v))

	case 5: /* syscall */
		o1 = c.oprrr(p.As)

	case 6: /* logical op Rb,[Rs,]Ra; no literal */
		r := int(p.Reg)

		if r == 0 {
			r = int(p.To.Reg)
		}
		// AROTL and AROTLW are extended mnemonics, which map to RLDCL and RLWNM.
		switch p.As {
		case AROTL:
			o1 = AOP_MD(OP_RLDCL, uint32(p.To.Reg), uint32(r), uint32(p.From.Reg), uint32(0))
		case AROTLW:
			o1 = OP_RLW(OP_RLWNM, uint32(p.To.Reg), uint32(r), uint32(p.From.Reg), 0, 31)
		default:
			if p.As == AOR && p.From.Type == obj.TYPE_CONST && p.From.Offset == 0 {
				// Compile "OR $0, Rx, Ry" into ori. If Rx == Ry == 0, this is the preferred
				// hardware no-op. This happens because $0 matches C_REG before C_ZCON.
				o1 = LOP_IRR(OP_ORI, uint32(p.To.Reg), uint32(r), 0)
			} else {
				o1 = LOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(r), uint32(p.From.Reg))
			}
		}

	case 7: /* mov r, soreg ==> stw o(r) */
		r := int(p.To.Reg)
		v := c.regoff(&p.To)
		if int32(int16(v)) != v {
			log.Fatalf("mishandled instruction %v", p)
		}
		// Offsets in DS form stores must be a multiple of 4
		inst := c.opstore(p.As)
		if c.opform(inst) == DS_FORM && v&0x3 != 0 {
			log.Fatalf("invalid offset for DS form load/store %v", p)
		}
		o1 = AOP_IRR(inst, uint32(p.From.Reg), uint32(r), uint32(v))

	case 8: /* mov soreg, r ==> lbz/lhz/lwz o(r), lbz o(r) + extsb r,r */
		r := int(p.From.Reg)
		v := c.regoff(&p.From)
		if int32(int16(v)) != v {
			log.Fatalf("mishandled instruction %v", p)
		}
		// Offsets in DS form loads must be a multiple of 4
		inst := c.opload(p.As)
		if c.opform(inst) == DS_FORM && v&0x3 != 0 {
			log.Fatalf("invalid offset for DS form load/store %v", p)
		}
		o1 = AOP_IRR(inst, uint32(p.To.Reg), uint32(r), uint32(v))

		// Sign extend MOVB operations. This is ignored for other cases (o.size == 4).
		o2 = LOP_RRR(OP_EXTSB, uint32(p.To.Reg), uint32(p.To.Reg), 0)

	case 9: /* RLDC Ra, $sh, $mb, Rb */
		sh := uint32(p.RestArgs[0].Addr.Offset) & 0x3F
		mb := uint32(p.RestArgs[1].Addr.Offset) & 0x3F
		o1 = AOP_RRR(c.opirr(p.As), uint32(p.From.Reg), uint32(p.To.Reg), (uint32(sh) & 0x1F))
		o1 |= (sh & 0x20) >> 4 // sh[5] is placed in bit 1.
		o1 |= (mb & 0x1F) << 6 // mb[0:4] is placed in bits 6-10.
		o1 |= (mb & 0x20)      // mb[5] is placed in bit 5

	case 10: /* sub Ra,[Rb],Rd => subf Rd,Ra,Rb */
		r := int(p.Reg)

		if r == 0 {
			r = int(p.To.Reg)
		}
		o1 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), uint32(r))

	case 11: /* br/bl bra */
		v := int32(0)

		if p.To.Target() != nil {
			v = int32(p.To.Target().Pc - p.Pc)
			if v&03 != 0 {
				c.ctxt.Diag("odd branch target address\n%v", p)
				v &^= 03
			}

			if v < -(1<<25) || v >= 1<<24 {
				c.ctxt.Diag("branch too far\n%v", p)
			}
		}

		o1 = OP_BR(c.opirr(p.As), uint32(v), 0)
		if p.To.Sym != nil {
			v += int32(p.To.Offset)
			if v&03 != 0 {
				c.ctxt.Diag("odd branch target address\n%v", p)
				v &^= 03
			}
			c.cursym.AddRel(c.ctxt, obj.Reloc{
				Type: objabi.R_CALLPOWER,
				Off:  int32(c.pc),
				Siz:  4,
				Sym:  p.To.Sym,
				Add:  int64(v),
			})
		}
		o2 = NOP // nop, sometimes overwritten by ld r2, 24(r1) when dynamic linking

	case 13: /* mov[bhwd]{z,} r,r */
		// This needs to handle "MOV* $0, Rx".  This shows up because $0 also
		// matches C_REG if r0iszero. This happens because C_REG sorts before C_U16CON
		// TODO: fix the above behavior and cleanup this exception.
		if p.From.Type == obj.TYPE_CONST {
			o1 = LOP_IRR(OP_ADDI, REGZERO, uint32(p.To.Reg), 0)
			break
		}
		if p.To.Type == obj.TYPE_CONST {
			c.ctxt.Diag("cannot move into constant 0\n%v", p)
		}

		switch p.As {
		case AMOVB:
			o1 = LOP_RRR(OP_EXTSB, uint32(p.To.Reg), uint32(p.From.Reg), 0)
		case AMOVBZ:
			o1 = OP_RLW(OP_RLWINM, uint32(p.To.Reg), uint32(p.From.Reg), 0, 24, 31)
		case AMOVH:
			o1 = LOP_RRR(OP_EXTSH, uint32(p.To.Reg), uint32(p.From.Reg), 0)
		case AMOVHZ:
			o1 = OP_RLW(OP_RLWINM, uint32(p.To.Reg), uint32(p.From.Reg), 0, 16, 31)
		case AMOVW:
			o1 = LOP_RRR(OP_EXTSW, uint32(p.To.Reg), uint32(p.From.Reg), 0)
		case AMOVWZ:
			o1 = OP_RLW(OP_RLDIC, uint32(p.To.Reg), uint32(p.From.Reg), 0, 0, 0) | 1<<5 /* MB=32 */
		case AMOVD:
			o1 = LOP_RRR(OP_OR, uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.From.Reg))
		default:
			c.ctxt.Diag("internal: bad register move/truncation\n%v", p)
		}

	case 14: /* rldc[lr] Rb,Rs,$mask,Ra -- left, right give different masks */
		r := uint32(p.Reg)

		if r == 0 {
			r = uint32(p.To.Reg)
		}
		d := c.vregoff(p.GetFrom3())
		switch p.As {

		// These opcodes expect a mask operand that has to be converted into the
		// appropriate operand.  The way these were defined, not all valid masks are possible.
		// Left here for compatibility in case they were used or generated.
		case ARLDCL, ARLDCLCC:
			mb, me, valid := decodeMask64(d)
			if me != 63 || !valid {
				c.ctxt.Diag("invalid mask for rotate: %x (end != bit 63)\n%v", uint64(d), p)
			}
			o1 = AOP_MDS(c.oprrr(p.As), uint32(p.To.Reg), r, uint32(p.From.Reg), mb)

		case ARLDCR, ARLDCRCC:
			mb, me, valid := decodeMask64(d)
			if mb != 0 || !valid {
				c.ctxt.Diag("invalid mask for rotate: %x (start != 0)\n%v", uint64(d), p)
			}
			o1 = AOP_MDS(c.oprrr(p.As), uint32(p.To.Reg), r, uint32(p.From.Reg), me)

		// These opcodes use a shift count like the ppc64 asm, no mask conversion done
		case ARLDICR, ARLDICRCC:
			me := uint32(d)
			sh := c.regoff(&p.From)
			if me < 0 || me > 63 || sh > 63 {
				c.ctxt.Diag("Invalid me or sh for RLDICR: %x %x\n%v", int(d), sh, p)
			}
			o1 = AOP_MD(c.oprrr(p.As), uint32(p.To.Reg), r, uint32(sh), me)

		case ARLDICL, ARLDICLCC, ARLDIC, ARLDICCC:
			mb := uint32(d)
			sh := c.regoff(&p.From)
			if mb < 0 || mb > 63 || sh > 63 {
				c.ctxt.Diag("Invalid mb or sh for RLDIC, RLDICL: %x %x\n%v", mb, sh, p)
			}
			o1 = AOP_MD(c.oprrr(p.As), uint32(p.To.Reg), r, uint32(sh), mb)

		case ACLRLSLDI:
			// This is an extended mnemonic defined in the ISA section C.8.1
			// clrlsldi ra,rs,b,n --> rldic ra,rs,n,b-n
			// It maps onto RLDIC so is directly generated here based on the operands from
			// the clrlsldi.
			n := int32(d)
			b := c.regoff(&p.From)
			if n > b || b > 63 {
				c.ctxt.Diag("Invalid n or b for CLRLSLDI: %x %x\n%v", n, b, p)
			}
			o1 = AOP_MD(OP_RLDIC, uint32(p.To.Reg), uint32(r), uint32(n), uint32(b)-uint32(n))

		default:
			c.ctxt.Diag("unexpected op in rldc case\n%v", p)
		}

	case 16: /* bc bo,bi,bra */
		a := 0

		r := int(p.Reg)

		if p.From.Type == obj.TYPE_CONST {
			a = int(c.regoff(&p.From))
		} else if p.From.Type == obj.TYPE_REG {
			if r != 0 {
				c.ctxt.Diag("unexpected register setting for branch with CR: %d\n", r)
			}
			// BI values for the CR
			switch p.From.Reg {
			case REG_CR0:
				r = BI_CR0
			case REG_CR1:
				r = BI_CR1
			case REG_CR2:
				r = BI_CR2
			case REG_CR3:
				r = BI_CR3
			case REG_CR4:
				r = BI_CR4
			case REG_CR5:
				r = BI_CR5
			case REG_CR6:
				r = BI_CR6
			case REG_CR7:
				r = BI_CR7
			default:
				c.ctxt.Diag("unrecognized register: expecting CR\n")
			}
		}
		v := int32(0)
		if p.To.Target() != nil {
			v = int32(p.To.Target().Pc - p.Pc)
		}
		if v&03 != 0 {
			c.ctxt.Diag("odd branch target address\n%v", p)
			v &^= 03
		}

		if v < -(1<<16) || v >= 1<<15 {
			c.ctxt.Diag("branch too far\n%v", p)
		}
		o1 = OP_BC(c.opirr(p.As), uint32(a), uint32(r), uint32(v), 0)

	case 17:
		var bo int32
		bi := int(p.Reg)

		if p.From.Reg == REG_CR {
			c.ctxt.Diag("unrecognized register: expected CR0-CR7\n")
		}
		bi = int(p.From.Reg&0x7) * 4

		bo = BO_BCR

		switch p.As {
		case ABLT:
			bi += BI_LT
		case ABGT:
			bi += BI_GT
		case ABEQ:
			bi += BI_EQ
		case ABNE:
			bo = BO_NOTBCR
			bi += BI_EQ
		case ABLE:
			bo = BO_NOTBCR
			bi += BI_GT
		case ABGE:
			bo = BO_NOTBCR
			bi += BI_LT
		case ABVS:
			bi += BI_FU
		case ABVC:
			bo = BO_NOTBCR
			bi += BI_FU
		default:
			c.ctxt.Diag("unexpected instruction: expecting BGT, BEQ, BNE, BLE, BGE, BVS, BVC \n%v", p)

		}
		if oclass(&p.To) == C_LR {
			o1 = OPVCC(19, 16, 0, 0)
		} else {
			c.ctxt.Diag("bad optab entry (17): %d\n%v", p.To.Class, p)
		}

		o1 = OP_BCR(o1, uint32(bo), uint32(bi))

	case 18: /* br/bl (lr/ctr); bc/bcl bo,bi,(lr/ctr) */
		var v int32
		var bh uint32 = 0
		if p.As == ABC || p.As == ABCL {
			v = c.regoff(&p.From) & 31
		} else {
			v = 20 /* unconditional */
		}
		r := int(p.Reg)
		if r == 0 {
			r = 0
		}
		switch oclass(&p.To) {
		case C_CTR:
			o1 = OPVCC(19, 528, 0, 0)

		case C_LR:
			o1 = OPVCC(19, 16, 0, 0)

		default:
			c.ctxt.Diag("bad optab entry (18): %d\n%v", p.To.Class, p)
			v = 0
		}

		// Insert optional branch hint for bclr[l]/bcctr[l]
		if p.From3Type() != obj.TYPE_NONE {
			bh = uint32(p.GetFrom3().Offset)
			if bh == 2 || bh > 3 {
				log.Fatalf("BH must be 0,1,3 for %v", p)
			}
			o1 |= bh << 11
		}

		if p.As == ABL || p.As == ABCL {
			o1 |= 1
		}
		o1 = OP_BCR(o1, uint32(v), uint32(r))

	case 19: /* mov $lcon,r ==> cau+or */
		d := c.vregoff(&p.From)
		if o.ispfx {
			o1, o2 = pfxadd(p.To.Reg, REG_R0, PFX_R_ABS, d)
		} else {
			o1 = loadu32(int(p.To.Reg), d)
			o2 = LOP_IRR(OP_ORI, uint32(p.To.Reg), uint32(p.To.Reg), uint32(int32(d)))
		}

	case 20: /* add $ucon,,r | addis $addcon,r,r */
		v := c.regoff(&p.From)

		r := int(p.Reg)
		if r == 0 {
			r = int(p.To.Reg)
		}
		o1 = AOP_IRR(c.opirr(p.As), uint32(p.To.Reg), uint32(r), uint32(v))

	case 21: /* or $u32con,rx[,ry] => oris + ori (similar for xor) */
		var opu, opl uint32
		r := uint32(p.Reg)
		if r == 0 {
			r = uint32(p.To.Reg)
		}
		switch p.As {
		case AOR:
			opu, opl = OP_ORIS, OP_ORI
		case AXOR:
			opu, opl = OP_XORIS, OP_XORI
		default:
			c.ctxt.Diag("unhandled opcode.\n%v", p)
		}
		o1 = LOP_IRR(opu, uint32(p.To.Reg), r, uint32(p.From.Offset>>16))
		o2 = LOP_IRR(opl, uint32(p.To.Reg), uint32(p.To.Reg), uint32(p.From.Offset)&0xFFFF)

	case 22: /* add $lcon/$andcon,r1,r2 ==> oris+ori+add/ori+add, add $s34con,r1 ==> addis+ori+slw+ori+add */
		if p.To.Reg == REGTMP || p.Reg == REGTMP {
			c.ctxt.Diag("can't synthesize large constant\n%v", p)
		}
		d := c.vregoff(&p.From)
		r := int(p.Reg)
		if r == 0 {
			r = int(p.To.Reg)
		}
		if p.From.Sym != nil {
			c.ctxt.Diag("%v is not supported", p)
		}
		if o.ispfx {
			o1, o2 = pfxadd(int16(p.To.Reg), int16(r), PFX_R_ABS, d)
		} else if o.size == 8 {
			o1 = LOP_IRR(OP_ORI, REGTMP, REGZERO, uint32(int32(d)))          // tmp = uint16(d)
			o2 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), REGTMP, uint32(r)) // to = tmp + from
		} else if o.size == 12 {
			// Note, o1 is ADDIS if d is negative, ORIS otherwise.
			o1 = loadu32(REGTMP, d)                                          // tmp = d & 0xFFFF0000
			o2 = loadl16(REGTMP, d)                                          // tmp |= d & 0xFFFF
			o3 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), REGTMP, uint32(r)) // to = from + tmp
		} else {
			// For backwards compatibility with GOPPC64 < 10, generate 34b constants in register.
			o1 = LOP_IRR(OP_ADDIS, REGZERO, REGTMP, uint32(d>>32)) // tmp = sign_extend((d>>32)&0xFFFF0000)
			o2 = loadl16(REGTMP, int64(d>>16))                     // tmp |= (d>>16)&0xFFFF
			o3 = AOP_MD(OP_RLDICR, REGTMP, REGTMP, 16, 63-16)      // tmp <<= 16
			o4 = loadl16(REGTMP, int64(uint16(d)))                 // tmp |= d&0xFFFF
			o5 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), REGTMP, uint32(r))
		}

	case 23: /* and $lcon/$addcon,r1,r2 ==> oris+ori+and/addi+and */
		if p.To.Reg == REGTMP || p.Reg == REGTMP {
			c.ctxt.Diag("can't synthesize large constant\n%v", p)
		}
		d := c.vregoff(&p.From)
		r := int(p.Reg)
		if r == 0 {
			r = int(p.To.Reg)
		}

		// With S16CON operand, generate 2 instructions using ADDI for signed value,
		// with 32CON operand generate 3 instructions.
		if o.size == 8 {
			o1 = LOP_IRR(OP_ADDI, REGZERO, REGTMP, uint32(int32(d)))
			o2 = LOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), REGTMP, uint32(r))
		} else {
			o1 = loadu32(REGTMP, d)
			o2 = loadl16(REGTMP, d)
			o3 = LOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), REGTMP, uint32(r))
		}
		if p.From.Sym != nil {
			c.ctxt.Diag("%v is not supported", p)
		}

	case 24: /* lfd fA,float64(0) -> xxlxor xsA,xsaA,xsaA + fneg for -0 */
		o1 = AOP_XX3I(c.oprrr(AXXLXOR), uint32(p.To.Reg), uint32(p.To.Reg), uint32(p.To.Reg), uint32(0))
		// This is needed for -0.
		if o.size == 8 {
			o2 = AOP_RRR(c.oprrr(AFNEG), uint32(p.To.Reg), 0, uint32(p.To.Reg))
		}

	case 25:
		/* sld[.] $sh,rS,rA -> rldicr[.] $sh,rS,mask(0,63-sh),rA; srd[.] -> rldicl */
		v := c.regoff(&p.From)

		if v < 0 {
			v = 0
		} else if v > 63 {
			v = 63
		}
		r := int(p.Reg)
		if r == 0 {
			r = int(p.To.Reg)
		}
		var a int
		op := uint32(0)
		switch p.As {
		case ASLD, ASLDCC:
			a = int(63 - v)
			op = OP_RLDICR

		case ASRD, ASRDCC:
			a = int(v)
			v = 64 - v
			op = OP_RLDICL
		case AROTL:
			a = int(0)
			op = OP_RLDICL
		case AEXTSWSLI, AEXTSWSLICC:
			a = int(v)
		default:
			c.ctxt.Diag("unexpected op in sldi case\n%v", p)
			a = 0
			o1 = 0
		}

		if p.As == AEXTSWSLI || p.As == AEXTSWSLICC {
			o1 = AOP_EXTSWSLI(OP_EXTSWSLI, uint32(r), uint32(p.To.Reg), uint32(v))

		} else {
			o1 = AOP_MD(op, uint32(p.To.Reg), uint32(r), uint32(v), uint32(a))
		}
		if p.As == ASLDCC || p.As == ASRDCC || p.As == AEXTSWSLICC {
			o1 |= 1 // Set the condition code bit
		}

	case 26: /* mov $lsext/auto/oreg,,r2 ==> addis+addi */
		v := c.vregoff(&p.From)
		r := int(p.From.Reg)
		var rel *obj.Reloc

		switch p.From.Name {
		case obj.NAME_EXTERN, obj.NAME_STATIC:
			// Load a 32 bit constant, or relocation depending on if a symbol is attached
			var rel1 obj.Reloc
			o1, o2, rel1 = c.symbolAccess(p.From.Sym, v, p.To.Reg, OP_ADDI, true)
			rel = &rel1
		default:
			// Add a 32 bit offset to a register.
			o1 = AOP_IRR(OP_ADDIS, uint32(p.To.Reg), uint32(r), uint32(high16adjusted(int32(v))))
			o2 = AOP_IRR(OP_ADDI, uint32(p.To.Reg), uint32(p.To.Reg), uint32(v))
		}

		if o.ispfx {
			if rel == nil {
				o1, o2 = pfxadd(int16(p.To.Reg), int16(r), PFX_R_ABS, v)
			} else {
				o1, o2 = pfxadd(int16(p.To.Reg), REG_R0, PFX_R_PCREL, 0)
				rel.Type = objabi.R_ADDRPOWER_PCREL34
			}
		}
		if rel != nil {
			c.cursym.AddRel(c.ctxt, *rel)
		}

	case 27: /* subc ra,$simm,rd => subfic rd,ra,$simm */
		v := c.regoff(p.GetFrom3())

		r := int(p.From.Reg)
		o1 = AOP_IRR(c.opirr(p.As), uint32(p.To.Reg), uint32(r), uint32(v))

	case 28: /* subc r1,$lcon,r2 ==> cau+or+subfc */
		if p.To.Reg == REGTMP || p.From.Reg == REGTMP {
			c.ctxt.Diag("can't synthesize large constant\n%v", p)
		}
		v := c.vregoff(p.GetFrom3())
		o1 = AOP_IRR(OP_ADDIS, REGTMP, REGZERO, uint32(v)>>16)
		o2 = loadl16(REGTMP, v)
		o3 = AOP_RRR(c.oprrr(p.As), uint32(p.To.Reg), uint32(p.From.Reg), REGTMP)
		if p.From.Sym != nil {
			c.ctxt.Diag("%v is not supported", p)
		}

	case 29: /* rldic[lr]? $sh,s,$mask,a -- left, right, plain give different masks */
		sh := uint32(c.regoff(&p.From))
		d := c.vregoff(p.GetFrom3())
		mb, me, valid := decodeMask64(d)
		var a uint32
		switch p.As {
		case ARLDC, ARLDCCC:
			a = mb
			if me != (63-sh) || !valid {
				c.ctxt.Diag("invalid mask for shift: %016x (mb=%d,me=%d) (shift %d)\n%v", uint64(d), mb, me, sh, p)
			}

		case ARLDCL, ARLDCLCC:
			a = mb
			if mb != 63 || !valid {
				c.ctxt.Diag("invalid mask for shift: %016x (mb=%d,me=%d) (shift %d)\n%v", uint64(d), mb, me, sh, p)
			}

		case ARLDCR, ARLDCRCC:
			a = me
			if mb != 0 || !valid {
				c.ctxt.Diag("invalid mask for shift: %016x (mb=%d,me=%d) (shift %d)\n%v", uint64(d), mb, me, sh, p)
			}

		default:
			c.ctxt.Diag("unexpected op in rldic case\n%v", p)
		}
		o1 = AOP_MD(c.opirr(p.As), uint32(p.To.Reg), uint32(p.Reg), sh, a)

	case 30: /* rldimi $sh,s,$mask,a */
		sh := uint32(c.regoff(&p.From))
		d := c.vregoff(p.GetFrom3())

		// Original opcodes had mask operands which had to be converted to a shift count as expected by
		// the ppc64 asm.
		switch p.As {
		case ARLDMI, ARLDMICC:
			mb, me, valid := decodeMask64(d)
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
"""




```