Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第5部分，共7部分，请归纳一下它的功能

"""
 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULLDload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MULLD x (LGDR <t> y))
	for {
		t := v.Type
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr1 := v_1
		if v_2.Op != OpS390XFMOVDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XMULLD)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLDload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (MULLDload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XMULLDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (MULLDload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (MULLDload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XMULLDload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMULLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLW x (MOVDconst [c]))
	// result: (MULLWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XMULLWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MULLW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (MULLWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XMULLWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (MULLW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (MULLWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWZload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XMULLWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XMULLWconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULLWconst <t> x [c])
	// cond: isPowerOfTwo(c&(c-1))
	// result: (ADDW (SLWconst <t> x [uint8(log32(c&(c-1)))]) (SLWconst <t> x [uint8(log32(c&^(c-1)))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c & (c - 1))) {
			break
		}
		v.reset(OpS390XADDW)
		v0 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(c & (c - 1))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(c &^ (c - 1))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLWconst <t> x [c])
	// cond: isPowerOfTwo(c+(c&^(c-1)))
	// result: (SUBW (SLWconst <t> x [uint8(log32(c+(c&^(c-1))))]) (SLWconst <t> x [uint8(log32(c&^(c-1)))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c + (c &^ (c - 1)))) {
			break
		}
		v.reset(OpS390XSUBW)
		v0 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(c + (c &^ (c - 1)))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(c &^ (c - 1))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLWconst <t> x [c])
	// cond: isPowerOfTwo(-c+(-c&^(-c-1)))
	// result: (SUBW (SLWconst <t> x [uint8(log32(-c&^(-c-1)))]) (SLWconst <t> x [uint8(log32(-c+(-c&^(-c-1))))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(-c + (-c &^ (-c - 1)))) {
			break
		}
		v.reset(OpS390XSUBW)
		v0 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(-c &^ (-c - 1))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(-c + (-c &^ (-c - 1)))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c*int32(d))])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c * int32(d)))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMULLWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (MULLWload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XMULLWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (MULLWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (MULLWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XMULLWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XNEG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEG (MOVDconst [c]))
	// result: (MOVDconst [-c])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(-c)
		return true
	}
	// match: (NEG (ADDconst [c] (NEG x)))
	// cond: c != -(1<<31)
	// result: (ADDconst [-c] x)
	for {
		if v_0.Op != OpS390XADDconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XNEG {
			break
		}
		x := v_0_0.Args[0]
		if !(c != -(1 << 31)) {
			break
		}
		v.reset(OpS390XADDconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XNEGW(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGW (MOVDconst [c]))
	// result: (MOVDconst [int64(int32(-c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(-c)))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XNOT(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NOT x)
	// result: (XOR (MOVDconst [-1]) x)
	for {
		x := v_0
		v.reset(OpS390XXOR)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(-1)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueS390X_OpS390XNOTW(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NOTW x)
	// result: (XORWconst [-1] x)
	for {
		x := v_0
		v.reset(OpS390XXORWconst)
		v.AuxInt = int32ToAuxInt(-1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpS390XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (OR x (MOVDconst [c]))
	// cond: isU32Bit(c)
	// result: (ORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isU32Bit(c)) {
				continue
			}
			v.reset(OpS390XORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (OR (MOVDconst [-1<<63]) (LGDR <t> x))
	// result: (LGDR <t> (LNDFR <x.Type> x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0.AuxInt) != -1<<63 || v_1.Op != OpS390XLGDR {
				continue
			}
			t := v_1.Type
			x := v_1.Args[0]
			v.reset(OpS390XLGDR)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpS390XLNDFR, x.Type)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (OR (RISBGZ (LGDR x) {r}) (LGDR (LPDFR <t> y)))
	// cond: r == s390x.NewRotateParams(0, 0, 0)
	// result: (LGDR (CPSDR <t> y x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XRISBGZ {
				continue
			}
			r := auxToS390xRotateParams(v_0.Aux)
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XLGDR {
				continue
			}
			x := v_0_0.Args[0]
			if v_1.Op != OpS390XLGDR {
				continue
			}
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpS390XLPDFR {
				continue
			}
			t := v_1_0.Type
			y := v_1_0.Args[0]
			if !(r == s390x.NewRotateParams(0, 0, 0)) {
				continue
			}
			v.reset(OpS390XLGDR)
			v0 := b.NewValue0(v.Pos, OpS390XCPSDR, t)
			v0.AddArg2(y, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (OR (RISBGZ (LGDR x) {r}) (MOVDconst [c]))
	// cond: c >= 0 && r == s390x.NewRotateParams(0, 0, 0)
	// result: (LGDR (CPSDR <x.Type> (FMOVDconst <x.Type> [math.Float64frombits(uint64(c))]) x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XRISBGZ {
				continue
			}
			r := auxToS390xRotateParams(v_0.Aux)
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XLGDR {
				continue
			}
			x := v_0_0.Args[0]
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c >= 0 && r == s390x.NewRotateParams(0, 0, 0)) {
				continue
			}
			v.reset(OpS390XLGDR)
			v0 := b.NewValue0(v.Pos, OpS390XCPSDR, x.Type)
			v1 := b.NewValue0(v.Pos, OpS390XFMOVDconst, x.Type)
			v1.AuxInt = float64ToAuxInt(math.Float64frombits(uint64(c)))
			v0.AddArg2(v1, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (OR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c|d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XMOVDconst)
			v.AuxInt = int64ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (OR x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (OR <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ORload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVDload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XORload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XORW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORW x (MOVDconst [c]))
	// result: (ORWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XORWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ORW x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ORW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ORWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XORWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (ORW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ORWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWZload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XORWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XORWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORWconst [c] x)
	// cond: int32(c)==0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(int32(c) == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ORWconst [c] _)
	// cond: int32(c)==-1
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if !(int32(c) == -1) {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c)|d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c) | d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XORWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (ORWload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XORWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (ORWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (ORWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XORWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ORconst [-1] _)
	// result: (MOVDconst [-1])
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c|d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c | d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XORload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (OR x (LGDR <t> y))
	for {
		t := v.Type
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr1 := v_1
		if v_2.Op != OpS390XFMOVDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XOR)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (ORload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (ORload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XORload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (ORload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (ORload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XORload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XRISBGZ(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (RISBGZ (MOVWZreg x) {r})
	// cond: r.InMerge(0xffffffff) != nil
	// result: (RISBGZ x {*r.InMerge(0xffffffff)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XMOVWZreg {
			break
		}
		x := v_0.Args[0]
		if !(r.InMerge(0xffffffff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.InMerge(0xffffffff))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (MOVHZreg x) {r})
	// cond: r.InMerge(0x0000ffff) != nil
	// result: (RISBGZ x {*r.InMerge(0x0000ffff)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XMOVHZreg {
			break
		}
		x := v_0.Args[0]
		if !(r.InMerge(0x0000ffff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.InMerge(0x0000ffff))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (MOVBZreg x) {r})
	// cond: r.InMerge(0x000000ff) != nil
	// result: (RISBGZ x {*r.InMerge(0x000000ff)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XMOVBZreg {
			break
		}
		x := v_0.Args[0]
		if !(r.InMerge(0x000000ff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.InMerge(0x000000ff))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (SLDconst x [c]) {r})
	// cond: r.InMerge(^uint64(0)<<c) != nil
	// result: (RISBGZ x {(*r.InMerge(^uint64(0)<<c)).RotateLeft(c)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XSLDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		if !(r.InMerge(^uint64(0)<<c) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*r.InMerge(^uint64(0) << c)).RotateLeft(c))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (SRDconst x [c]) {r})
	// cond: r.InMerge(^uint64(0)>>c) != nil
	// result: (RISBGZ x {(*r.InMerge(^uint64(0)>>c)).RotateLeft(-c)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XSRDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		if !(r.InMerge(^uint64(0)>>c) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*r.InMerge(^uint64(0) >> c)).RotateLeft(-c))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (RISBGZ x {y}) {z})
	// cond: z.InMerge(y.OutMask()) != nil
	// result: (RISBGZ x {(*z.InMerge(y.OutMask())).RotateLeft(y.Amount)})
	for {
		z := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		y := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(z.InMerge(y.OutMask()) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*z.InMerge(y.OutMask())).RotateLeft(y.Amount))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r.End == 63 && r.Start == -r.Amount&63
	// result: (SRDconst x [-r.Amount&63])
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r.End == 63 && r.Start == -r.Amount&63) {
			break
		}
		v.reset(OpS390XSRDconst)
		v.AuxInt = uint8ToAuxInt(-r.Amount & 63)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r.Start == 0 && r.End == 63-r.Amount
	// result: (SLDconst x [r.Amount])
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r.Start == 0 && r.End == 63-r.Amount) {
			break
		}
		v.reset(OpS390XSLDconst)
		v.AuxInt = uint8ToAuxInt(r.Amount)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (SRADconst x [c]) {r})
	// cond: r.Start == r.End && (r.Start+r.Amount)&63 <= c
	// result: (RISBGZ x {s390x.NewRotateParams(r.Start, r.Start, -r.Start&63)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XSRADconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		if !(r.Start == r.End && (r.Start+r.Amount)&63 <= c) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(r.Start, r.Start, -r.Start&63))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r == s390x.NewRotateParams(56, 63, 0)
	// result: (MOVBZreg x)
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r == s390x.NewRotateParams(56, 63, 0)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r == s390x.NewRotateParams(48, 63, 0)
	// result: (MOVHZreg x)
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r == s390x.NewRotateParams(48, 63, 0)) {
			break
		}
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r == s390x.NewRotateParams(32, 63, 0)
	// result: (MOVWZreg x)
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r == s390x.NewRotateParams(32, 63, 0)) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (LGDR <t> x) {r})
	// cond: r == s390x.NewRotateParams(1, 63, 0)
	// result: (LGDR <t> (LPDFR <x.Type> x))
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XLGDR {
			break
		}
		t := v_0.Type
		x := v_0.Args[0]
		if !(r == s390x.NewRotateParams(1, 63, 0)) {
			break
		}
		v.reset(OpS390XLGDR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpS390XLPDFR, x.Type)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XRLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RLL x (MOVDconst [c]))
	// result: (RLLconst x [uint8(c&31)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XRLLconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XRLLG(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RLLG x (MOVDconst [c]))
	// result: (RISBGZ x {s390x.NewRotateParams(0, 63, uint8(c&63))})
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(0, 63, uint8(c&63)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSLD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SLD x (MOVDconst [c]))
	// result: (SLDconst x [uint8(c&63)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XSLDconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SLD x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (AND (MOVDconst [c]) y))
	// result: (SLD x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSLD)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SLD x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVWreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVHreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVBreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVWZreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVHZreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVBZreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSLDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLDconst (SRDconst x [c]) [d])
	// result: (RISBGZ x {s390x.NewRotateParams(uint8(max(0, int8(c-d))), 63-d, uint8(int8(d-c)&63))})
	for {
		d := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XSRDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(uint8(max(0, int8(c-d))), 63-d, uint8(int8(d-c)&63)))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst (RISBGZ x {r}) [c])
	// cond: s390x.NewRotateParams(0, 63-c, c).InMerge(r.OutMask()) != nil
	// result: (RISBGZ x {(*s390x.NewRotateParams(0, 63-c, c).InMerge(r.OutMask())).RotateLeft(r.Amount)})
	for {
		c := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(s390x.NewRotateParams(0, 63-c, c).InMerge(r.OutMask()) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*s390x.NewRotateParams(0, 63-c, c).InMerge(r.OutMask())).RotateLeft(r.Amount))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SLW x (MOVDconst [c]))
	// cond: c&32 == 0
	// result: (SLWconst x [uint8(c&31)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 == 0) {
			break
		}
		v.reset(OpS390XSLWconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SLW _ (MOVDconst [c]))
	// cond: c&32 != 0
	// result: (MOVDconst [0])
	for {
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 != 0) {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SLW x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (AND (MOVDconst [c]) y))
	// result: (SLW x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSLW)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SLW x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVWreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVHreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVBreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVWZreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVHZreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVBZreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSLWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLWconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRAD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SRAD x (MOVDconst [c]))
	// result: (SRADconst x [uint8(c&63)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XSRADconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SRAD x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (AND (MOVDconst [c]) y))
	// result: (SRAD x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSRAD)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SRAD x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVWreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVHreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVBreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVWZreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVHZreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVBZreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRADconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRADconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SRADconst [c] (MOVDconst [d]))
	// result: (MOVDconst [d>>uint64(c)])
	for {
		c := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(d >> uint64(c))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRAW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SRAW x (MOVDconst [c]))
	// cond: c&32 == 0
	// result: (SRAWconst x [uint8(c&31)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 == 0) {
			break
		}
		v.reset(OpS390XSRAWconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SRAW x (MOVDconst [c]))
	// cond: c&32 != 0
	// result: (SRAWconst x [31])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 != 0) {
			break
		}
		v.reset(OpS390XSRAWconst)
		v.AuxInt = uint8ToAuxInt(31)
		v.AddArg(x)
		return true
	}
	// match: (SRAW x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (AND (MOVDconst [c]) y))
	// result: (SRAW x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSRAW)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SRAW x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVWreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVHreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVBreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVWZreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVHZreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVBZreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRAWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRAWconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SRAWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(int32(d))>>uint64(c)])
	for {
		c := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(d)) >> uint64(c))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SRD x (MOVDconst [c]))
	// result: (SRDconst x [uint8(c&63)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XSRDconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SRD x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (AND (MOVDconst [c]) y))
	// result: (SRD x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSRD)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SRD x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVWreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVHreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVBreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVWZreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVHZreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVBZreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRDconst (SLDconst x [c]) [d])
	// result: (RISBGZ x {s390x.NewRotateParams(d, uint8(min(63, int8(63-c+d))), uint8(int8(c-d)&63))})
	for {
		d := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XSLDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(d, uint8(min(63, int8(63-c+d))), uint8(int8(c-d)&63)))
		v.AddArg(x)
		return true
	}
	// match: (SRDconst (RISBGZ x {r}) [c])
	// cond: s390x.NewRotateParams(c, 63, -c&63).InMerge(r.OutMask()) != nil
	// result: (RISBGZ x {(*s390x.NewRotateParams(c, 63, -c&63).InMerge(r.OutMask())).RotateLeft(r.Amount)})
	for {
		c := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(s390x.NewRotateParams(c, 63, -c&63).InMerge(r.OutMask()) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*s390x.NewRotateParams(c, 63, -c&63).InMerge(r.OutMask())).RotateLeft(r.Amount))
		v.AddArg(x)
		return true
	}
	// match: (SRDconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SRW x (MOVDconst [c]))
	// cond: c&32 == 0
	// result: (SRWconst x [uint8(c&31)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 == 0) {
			break
		}
		v.reset(OpS390XSRWconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SRW _ (MOVDconst [c]))
	// cond: c&32 != 0
	// result: (MOVDconst [0])
	for {
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 != 0) {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRW x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (AND (MOVDconst [c]) y))
	// result: (SRW x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSRW)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SRW x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVWreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVHreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVBreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVWZreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVHZreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVBZreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRWconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSTM2(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (STM2 [i] {s} p w2 w3 x:(STM2 [i-8] {s} p w0 w1 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-8) && setPos(v, x.Pos) && clobber(x)
	// result: (STM4 [i-8] {s} p w0 w1 w2 w3 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w2 := v_1
		w3 := v_2
		x := v_3
		if x.Op != OpS390XSTM2 || auxIntToInt32(x.AuxInt) != i-8 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[3]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		w1 := x.Args[2]
		if !(x.Uses == 1 && is20Bit(int64(i)-8) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTM4)
		v.AuxInt = int32ToAuxInt(i - 8)
		v.Aux = symToAux(s)
		v.AddArg6(p, w0, w1, w2, w3, mem)
		return true
	}
	// match: (STM2 [i] {s} p (SRDconst [32] x) x mem)
	// result: (MOVDstore [i] {s} p x mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		if v_1.Op != OpS390XSRDconst || auxIntToUint8(v_1.AuxInt) != 32 {
			break
		}
		x := v_1.Args[0]
		if x != v_2 {
			break
		}
		mem := v_3
		v.reset(OpS390XMOVDstore)
		v.AuxInt = int32ToAuxInt(i)
		v.Aux = symToAux(s)
		v.AddArg3(p, x, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSTMG2(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (STMG2 [i] {s} p w2 w3 x:(STMG2 [i-16] {s} p w0 w1 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-16) && setPos(v, x.Pos) && clobber(x)
	// result: (STMG4 [i-16] {s} p w0 w1 w2 w3 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w2 := v_1
		w3 := v_2
		x := v_3
		if x.Op != OpS390XSTMG2 || auxIntToInt32(x.AuxInt) != i-16 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[3]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		w1 := x.Args[2]
		if !(x.Uses == 1 && is20Bit(int64(i)-16) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTMG4)
		v.AuxInt = int32ToAuxInt(i - 16)
		v.Aux = symToAux(s)
		v.AddArg6(p, w0, w1, w2, w3, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUB x (MOVDconst [c]))
	// cond: is32Bit(c)
	// result: (SUBconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpS390XSUBconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (SUB (MOVDconst [c]) x)
	// cond: is32Bit(c)
	// result: (NEG (SUBconst <v.Type> x [int32(c)]))
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpS390XNEG)
		v0 := b.NewValue0(v.Pos, OpS390XSUBconst, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUB x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUB <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (SUBload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		x := v_0
		g := v_1
		if g.Op != OpS390XMOVDload {
			break
		}
		off := auxIntToInt32(g.AuxInt)
		sym := auxToSym(g.Aux)
		mem := g.Args[1]
		ptr := g.Args[0]
		if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
			break
		}
		v.reset(OpS390XSUBload)
		v.Type = t
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBE x y (FlagGT))
	// result: (SUBC x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpS390XFlagGT {
			break
		}
		v.reset(OpS390XSUBC)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBE x y (FlagOV))
	// result: (SUBC x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpS390XFlagOV {
			break
		}
		v.reset(OpS390XSUBC)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBE x y (Select1 (SUBC (MOVDconst [0]) (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) c))))))
	// result: (SUBE x y c)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpS390XSUBC {
			break
		}
		_ = v_2_0.Args[1]
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_2_0_0.AuxInt) != 0 {
			break
		}
		v_2_0_1 := v_2_0.Args[1]
		if v_2_0_1.Op != OpS390XNEG {
			break
		}
		v_2_0_1_0 := v_2_0_1.Args[0]
		if v_2_0_1_0.Op != OpSelect0 {
			break
		}
		v_2_0_1_0_0 := v_2_0_1_0.Args[0]
		if v_2_0_1_0_0.Op != OpS390XSUBE {
			break
		}
		c := v_2_0_1_0_0.Args[2]
		v_2_0_1_0_0_0 := v_2_0_1_0_0.Args[0]
		if v_2_0_1_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_2_0_1_0_0_0.AuxInt) != 0 {
			break
		}
		v_2_0_1_0_0_1 := v_2_0_1_0_0.Args[1]
		if v_2_0_1_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_2_0_1_0_0_1.AuxInt) != 0 {
			break
		}
		v.reset(OpS390XSUBE)
		v.AddArg3(x, y, c)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBW x (MOVDconst [c]))
	// result: (SUBWconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XSUBWconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (SUBW (MOVDconst [c]) x)
	// result: (NEGW (SUBWconst <v.Type> x [int32(c)]))
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpS390XNEGW)
		v0 := b.NewValue0(v.Pos, OpS390XSUBWconst, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBW x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUBW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (SUBWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		x := v_0
		g := v_1
		if g.Op != OpS390XMOVWload {
			break
		}
		off := auxIntToInt32(g.AuxInt)
		sym := auxToSym(g.Aux)
		mem := g.Args[1]
		ptr := g.Args[0]
		if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
			break
		}
		v.reset(OpS390XSUBWload)
		v.Type = t
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (SUBW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (SUBWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		x := v_0
		g := v_1
		if g.Op != OpS390XMOVWZload {
			break
		}
		off := auxIntToInt32(g.AuxInt)
		sym := auxToSym(g.Aux)
		mem := g.Args[1]
		ptr := g.Args[0]
		if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
			break
		}
		v.reset(OpS390XSUBWload)
		v.Type = t
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBWconst [c] x)
	// cond: int32(c) == 0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(int32(c) == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SUBWconst [c] x)
	// result: (ADDWconst [-int32(c)] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		v.reset(OpS390XADDWconst)
		v.AuxInt = int32ToAuxInt(-int32(c))
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpS390XSUBWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (SUBWload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XSUBWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (SUBWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (SUBWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XSUBWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBconst [c] x)
	// cond: c != -(1<<31)
	// result: (ADDconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c != -(1 << 31)) {
			break
		}
		v.reset(OpS390XADDconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (SUBconst (MOVDconst [d]) [c])
	// result: (MOVDconst [d-int64(c)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(d - int64(c))
		return true
	}
	// match: (SUBconst (SUBconst x [d]) [c])
	// cond: is32Bit(-int64(c)-int64(d))
	// result: (ADDconst [-c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-int64(c) - int64(d))) {
			break
		}
		v.reset(OpS390XADDconst)
		v.AuxInt = int32ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (SUB x (LGDR <t> y))
	for {
		t := v.Type
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr1 := v_1
		if v_2.Op != OpS390XFMOVDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XSUB)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SUBload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (SUBload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XSUBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (SUBload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (SUBload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XSUBload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSumBytes2(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SumBytes2 x)
	// result: (ADDW (SRWconst <typ.UInt8> x [8]) x)
	for {
		x := v_0
		v.reset(OpS390XADDW)
		v0 := b.NewValue0(v.Pos, OpS390XSRWconst, typ.UInt8)
		v0.AuxInt = uint8ToAuxInt(8)
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueS390X_OpS390XSumBytes4(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SumBytes4 x)
	// result: (SumBytes2 (ADDW <typ.UInt16> (SRWconst <typ.UInt16> x [16]) x))
	for {
		x := v_0
		v.reset(OpS390XSumBytes2)
		v0 := b.NewValue0(v.Pos, OpS390XADDW, typ.UInt16)
		v1 := b.NewValue0(v.Pos, OpS390XSRWconst, typ.UInt16)
		v1.AuxInt = uint8ToAuxInt(16)
		v1.AddArg(x)
		v0.AddArg2(v1, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpS390XSumBytes8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SumBytes8 x)
	// result: (SumBytes4 (ADDW <typ.UInt32> (SRDconst <typ.UInt32> x [32]) x))
	for {
		x := v_0
		v.reset(OpS390XSumBytes4)
		v0 := b.NewValue0(v.Pos, OpS390XADDW, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpS390XSRDconst, typ.UInt32)
		v1.AuxInt = uint8ToAuxInt(32)
		v1.AddArg(x)
		v0.AddArg2(v1, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpS390XXOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVDconst [c]))
	// cond: isU32Bit(c)
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isU32Bit(c)) {
				continue
			}
			v.reset(OpS390XXORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c^d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XMOVDconst)
			v.AuxInt = int64ToAuxInt(c ^ d)
			return true
		}
		break
	}
	// match: (XOR x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XOR <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (XORload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVDload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XXORload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XXORW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORW x (MOVDconst [c]))
	// result: (XORWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XXORWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XORW x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XORW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (XORWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XXORWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (XORW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (XORWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWZload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XXORWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XXORWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORWconst [c] x)
	// cond: int32(c)==0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(int32(c) == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (XORWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c)^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.Au
"""




```