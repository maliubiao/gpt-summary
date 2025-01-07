Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第6部分，共12部分，请归纳一下它的功能

"""
tore [off] {sym} ptr y _))
	// result: (MULSS x (MOVLi2f y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVLstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64MULSS)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLi2f, typ.Float32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64NEGL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGL (NEGL x))
	// result: x
	for {
		if v_0.Op != OpAMD64NEGL {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (NEGL s:(SUBL x y))
	// cond: s.Uses == 1
	// result: (SUBL y x)
	for {
		s := v_0
		if s.Op != OpAMD64SUBL {
			break
		}
		y := s.Args[1]
		x := s.Args[0]
		if !(s.Uses == 1) {
			break
		}
		v.reset(OpAMD64SUBL)
		v.AddArg2(y, x)
		return true
	}
	// match: (NEGL (MOVLconst [c]))
	// result: (MOVLconst [-c])
	for {
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(-c)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64NEGQ(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGQ (NEGQ x))
	// result: x
	for {
		if v_0.Op != OpAMD64NEGQ {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (NEGQ s:(SUBQ x y))
	// cond: s.Uses == 1
	// result: (SUBQ y x)
	for {
		s := v_0
		if s.Op != OpAMD64SUBQ {
			break
		}
		y := s.Args[1]
		x := s.Args[0]
		if !(s.Uses == 1) {
			break
		}
		v.reset(OpAMD64SUBQ)
		v.AddArg2(y, x)
		return true
	}
	// match: (NEGQ (MOVQconst [c]))
	// result: (MOVQconst [-c])
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(-c)
		return true
	}
	// match: (NEGQ (ADDQconst [c] (NEGQ x)))
	// cond: c != -(1<<31)
	// result: (ADDQconst [-c] x)
	for {
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAMD64NEGQ {
			break
		}
		x := v_0_0.Args[0]
		if !(c != -(1 << 31)) {
			break
		}
		v.reset(OpAMD64ADDQconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64NOTL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NOTL (MOVLconst [c]))
	// result: (MOVLconst [^c])
	for {
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(^c)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64NOTQ(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NOTQ (MOVQconst [c]))
	// result: (MOVQconst [^c])
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(^c)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORL (SHLL (MOVLconst [1]) y) x)
	// result: (BTSL x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64SHLL {
				continue
			}
			y := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.reset(OpAMD64BTSL)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ORL x (MOVLconst [c]))
	// result: (ORLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpAMD64ORLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ORL x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ORL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ORLload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVLload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64ORLload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORLconst [c] (ORLconst [d] x))
	// result: (ORLconst [c | d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ORLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64ORLconst)
		v.AuxInt = int32ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	// match: (ORLconst [c] x)
	// cond: c==0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ORLconst [c] _)
	// cond: c==-1
	// result: (MOVLconst [-1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if !(c == -1) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(-1)
		return true
	}
	// match: (ORLconst [c] (MOVLconst [d]))
	// result: (MOVLconst [c|d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(c | d)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORLconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORLconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (ORLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2)) {
			break
		}
		v.reset(OpAMD64ORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (ORLconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (ORLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ORLload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ORLload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64ORLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ORLload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ORLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ORLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: ( ORLload x [off] {sym} ptr (MOVSSstore [off] {sym} ptr y _))
	// result: ( ORL x (MOVLf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSSstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64ORL)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLf2i, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORLmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ORLmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64ORLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (ORLmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ORLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ORLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORQ (SHLQ (MOVQconst [1]) y) x)
	// result: (BTSQ x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64SHLQ {
				continue
			}
			y := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.reset(OpAMD64BTSQ)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ORQ (MOVQconst [c]) x)
	// cond: isUint64PowerOfTwo(c) && uint64(c) >= 1<<31
	// result: (BTSQconst [int8(log64(c))] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			x := v_1
			if !(isUint64PowerOfTwo(c) && uint64(c) >= 1<<31) {
				continue
			}
			v.reset(OpAMD64BTSQconst)
			v.AuxInt = int8ToAuxInt(int8(log64(c)))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ORQ x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (ORQconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpAMD64ORQconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ORQ x (MOVLconst [c]))
	// result: (ORQconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpAMD64ORQconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ORQ (SHRQ lo bits) (SHLQ hi (NEGQ bits)))
	// result: (SHRDQ lo hi bits)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64SHRQ {
				continue
			}
			bits := v_0.Args[1]
			lo := v_0.Args[0]
			if v_1.Op != OpAMD64SHLQ {
				continue
			}
			_ = v_1.Args[1]
			hi := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpAMD64NEGQ || bits != v_1_1.Args[0] {
				continue
			}
			v.reset(OpAMD64SHRDQ)
			v.AddArg3(lo, hi, bits)
			return true
		}
		break
	}
	// match: (ORQ (SHLQ lo bits) (SHRQ hi (NEGQ bits)))
	// result: (SHLDQ lo hi bits)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64SHLQ {
				continue
			}
			bits := v_0.Args[1]
			lo := v_0.Args[0]
			if v_1.Op != OpAMD64SHRQ {
				continue
			}
			_ = v_1.Args[1]
			hi := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpAMD64NEGQ || bits != v_1_1.Args[0] {
				continue
			}
			v.reset(OpAMD64SHLDQ)
			v.AddArg3(lo, hi, bits)
			return true
		}
		break
	}
	// match: (ORQ (SHRXQ lo bits) (SHLXQ hi (NEGQ bits)))
	// result: (SHRDQ lo hi bits)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64SHRXQ {
				continue
			}
			bits := v_0.Args[1]
			lo := v_0.Args[0]
			if v_1.Op != OpAMD64SHLXQ {
				continue
			}
			_ = v_1.Args[1]
			hi := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpAMD64NEGQ || bits != v_1_1.Args[0] {
				continue
			}
			v.reset(OpAMD64SHRDQ)
			v.AddArg3(lo, hi, bits)
			return true
		}
		break
	}
	// match: (ORQ (SHLXQ lo bits) (SHRXQ hi (NEGQ bits)))
	// result: (SHLDQ lo hi bits)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64SHLXQ {
				continue
			}
			bits := v_0.Args[1]
			lo := v_0.Args[0]
			if v_1.Op != OpAMD64SHRXQ {
				continue
			}
			_ = v_1.Args[1]
			hi := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpAMD64NEGQ || bits != v_1_1.Args[0] {
				continue
			}
			v.reset(OpAMD64SHLDQ)
			v.AddArg3(lo, hi, bits)
			return true
		}
		break
	}
	// match: (ORQ (MOVQconst [c]) (MOVQconst [d]))
	// result: (MOVQconst [c|d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpAMD64MOVQconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpAMD64MOVQconst)
			v.AuxInt = int64ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (ORQ x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ORQ x l:(MOVQload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ORQload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVQload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64ORQload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORQconst [c] (ORQconst [d] x))
	// result: (ORQconst [c | d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ORQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64ORQconst)
		v.AuxInt = int32ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	// match: (ORQconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ORQconst [-1] _)
	// result: (MOVQconst [-1])
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [int64(c)|d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(c) | d)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORQconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORQconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (ORQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2)) {
			break
		}
		v.reset(OpAMD64ORQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (ORQconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (ORQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ORQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ORQload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ORQload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64ORQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ORQload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ORQload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ORQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: ( ORQload x [off] {sym} ptr (MOVSDstore [off] {sym} ptr y _))
	// result: ( ORQ x (MOVQf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64ORQ)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQf2i, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ORQmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORQmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ORQmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64ORQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (ORQmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ORQmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ORQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ROLB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROLB x (NEGQ y))
	// result: (RORB x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64RORB)
		v.AddArg2(x, y)
		return true
	}
	// match: (ROLB x (NEGL y))
	// result: (RORB x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64RORB)
		v.AddArg2(x, y)
		return true
	}
	// match: (ROLB x (MOVQconst [c]))
	// result: (ROLBconst [int8(c&7) ] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64ROLBconst)
		v.AuxInt = int8ToAuxInt(int8(c & 7))
		v.AddArg(x)
		return true
	}
	// match: (ROLB x (MOVLconst [c]))
	// result: (ROLBconst [int8(c&7) ] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64ROLBconst)
		v.AuxInt = int8ToAuxInt(int8(c & 7))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ROLBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ROLBconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ROLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROLL x (NEGQ y))
	// result: (RORL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64RORL)
		v.AddArg2(x, y)
		return true
	}
	// match: (ROLL x (NEGL y))
	// result: (RORL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64RORL)
		v.AddArg2(x, y)
		return true
	}
	// match: (ROLL x (MOVQconst [c]))
	// result: (ROLLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64ROLLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (ROLL x (MOVLconst [c]))
	// result: (ROLLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64ROLLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ROLLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ROLLconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ROLQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROLQ x (NEGQ y))
	// result: (RORQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64RORQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (ROLQ x (NEGL y))
	// result: (RORQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64RORQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (ROLQ x (MOVQconst [c]))
	// result: (ROLQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64ROLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (ROLQ x (MOVLconst [c]))
	// result: (ROLQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64ROLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ROLQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ROLQconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ROLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROLW x (NEGQ y))
	// result: (RORW x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64RORW)
		v.AddArg2(x, y)
		return true
	}
	// match: (ROLW x (NEGL y))
	// result: (RORW x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64RORW)
		v.AddArg2(x, y)
		return true
	}
	// match: (ROLW x (MOVQconst [c]))
	// result: (ROLWconst [int8(c&15)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64ROLWconst)
		v.AuxInt = int8ToAuxInt(int8(c & 15))
		v.AddArg(x)
		return true
	}
	// match: (ROLW x (MOVLconst [c]))
	// result: (ROLWconst [int8(c&15)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64ROLWconst)
		v.AuxInt = int8ToAuxInt(int8(c & 15))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ROLWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ROLWconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64RORB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RORB x (NEGQ y))
	// result: (ROLB x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64ROLB)
		v.AddArg2(x, y)
		return true
	}
	// match: (RORB x (NEGL y))
	// result: (ROLB x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64ROLB)
		v.AddArg2(x, y)
		return true
	}
	// match: (RORB x (MOVQconst [c]))
	// result: (ROLBconst [int8((-c)&7) ] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64ROLBconst)
		v.AuxInt = int8ToAuxInt(int8((-c) & 7))
		v.AddArg(x)
		return true
	}
	// match: (RORB x (MOVLconst [c]))
	// result: (ROLBconst [int8((-c)&7) ] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64ROLBconst)
		v.AuxInt = int8ToAuxInt(int8((-c) & 7))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64RORL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RORL x (NEGQ y))
	// result: (ROLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64ROLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (RORL x (NEGL y))
	// result: (ROLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64ROLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (RORL x (MOVQconst [c]))
	// result: (ROLLconst [int8((-c)&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64ROLLconst)
		v.AuxInt = int8ToAuxInt(int8((-c) & 31))
		v.AddArg(x)
		return true
	}
	// match: (RORL x (MOVLconst [c]))
	// result: (ROLLconst [int8((-c)&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64ROLLconst)
		v.AuxInt = int8ToAuxInt(int8((-c) & 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64RORQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RORQ x (NEGQ y))
	// result: (ROLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64ROLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (RORQ x (NEGL y))
	// result: (ROLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64ROLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (RORQ x (MOVQconst [c]))
	// result: (ROLQconst [int8((-c)&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64ROLQconst)
		v.AuxInt = int8ToAuxInt(int8((-c) & 63))
		v.AddArg(x)
		return true
	}
	// match: (RORQ x (MOVLconst [c]))
	// result: (ROLQconst [int8((-c)&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64ROLQconst)
		v.AuxInt = int8ToAuxInt(int8((-c) & 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64RORW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RORW x (NEGQ y))
	// result: (ROLW x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64ROLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (RORW x (NEGL y))
	// result: (ROLW x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64ROLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (RORW x (MOVQconst [c]))
	// result: (ROLWconst [int8((-c)&15)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64ROLWconst)
		v.AuxInt = int8ToAuxInt(int8((-c) & 15))
		v.AddArg(x)
		return true
	}
	// match: (RORW x (MOVLconst [c]))
	// result: (ROLWconst [int8((-c)&15)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64ROLWconst)
		v.AuxInt = int8ToAuxInt(int8((-c) & 15))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SARB x (MOVQconst [c]))
	// result: (SARBconst [int8(min(int64(c)&31,7))] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SARBconst)
		v.AuxInt = int8ToAuxInt(int8(min(int64(c)&31, 7)))
		v.AddArg(x)
		return true
	}
	// match: (SARB x (MOVLconst [c]))
	// result: (SARBconst [int8(min(int64(c)&31,7))] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SARBconst)
		v.AuxInt = int8ToAuxInt(int8(min(int64(c)&31, 7)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SARBconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SARBconst [c] (MOVQconst [d]))
	// result: (MOVQconst [int64(int8(d))>>uint64(c)])
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(int8(d)) >> uint64(c))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SARL x (MOVQconst [c]))
	// result: (SARLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SARLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SARL x (MOVLconst [c]))
	// result: (SARLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SARLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SARL x (ADDQconst [c] y))
	// cond: c & 31 == 0
	// result: (SARL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SARL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SARL x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 31 == 0
	// result: (SARL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SARL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SARL x (ANDQconst [c] y))
	// cond: c & 31 == 31
	// result: (SARL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SARL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SARL x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 31 == 31
	// result: (SARL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SARL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SARL x (ADDLconst [c] y))
	// cond: c & 31 == 0
	// result: (SARL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SARL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SARL x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 31 == 0
	// result: (SARL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SARL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SARL x (ANDLconst [c] y))
	// cond: c & 31 == 31
	// result: (SARL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SARL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SARL x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 31 == 31
	// result: (SARL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SARL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SARL l:(MOVLload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SARXLload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SARXLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SARLconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SARLconst [c] (MOVQconst [d]))
	// result: (MOVQconst [int64(int32(d))>>uint64(c)])
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(int32(d)) >> uint64(c))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SARQ x (MOVQconst [c]))
	// result: (SARQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SARQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SARQ x (MOVLconst [c]))
	// result: (SARQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SARQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SARQ x (ADDQconst [c] y))
	// cond: c & 63 == 0
	// result: (SARQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SARQ x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 63 == 0
	// result: (SARQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SARQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SARQ x (ANDQconst [c] y))
	// cond: c & 63 == 63
	// result: (SARQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SARQ x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 63 == 63
	// result: (SARQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SARQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SARQ x (ADDLconst [c] y))
	// cond: c & 63 == 0
	// result: (SARQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SARQ x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 63 == 0
	// result: (SARQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SARQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SARQ x (ANDLconst [c] y))
	// cond: c & 63 == 63
	// result: (SARQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SARQ x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 63 == 63
	// result: (SARQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SARQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SARQ l:(MOVQload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SARXQload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SARXQload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SARQconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SARQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [d>>uint64(c)])
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(d >> uint64(c))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SARW x (MOVQconst [c]))
	// result: (SARWconst [int8(min(int64(c)&31,15))] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SARWconst)
		v.AuxInt = int8ToAuxInt(int8(min(int64(c)&31, 15)))
		v.AddArg(x)
		return true
	}
	// match: (SARW x (MOVLconst [c]))
	// result: (SARWconst [int8(min(int64(c)&31,15))] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SARWconst)
		v.AuxInt = int8ToAuxInt(int8(min(int64(c)&31, 15)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SARWconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SARWconst [c] (MOVQconst [d]))
	// result: (MOVQconst [int64(int16(d))>>uint64(c)])
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(int16(d)) >> uint64(c))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARXLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SARXLload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SARLconst [int8(c&31)] (MOVLload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SARLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SARXQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SARXQload [off] {sym} ptr (MOVQconst [c]) mem)
	// result: (SARQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SARQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	// match: (SARXQload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SARQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SARQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SBBLcarrymask(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SBBLcarrymask (FlagEQ))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SBBLcarrymask (FlagLT_ULT))
	// result: (MOVLconst [-1])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(-1)
		return true
	}
	// match: (SBBLcarrymask (FlagLT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SBBLcarrymask (FlagGT_ULT))
	// result: (MOVLconst [-1])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(-1)
		return true
	}
	// match: (SBBLcarrymask (FlagGT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SBBQ(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SBBQ x (MOVQconst [c]) borrow)
	// cond: is32Bit(c)
	// result: (SBBQconst x [int32(c)] borrow)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		borrow := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpAMD64SBBQconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(x, borrow)
		return true
	}
	// match: (SBBQ x y (FlagEQ))
	// result: (SUBQborrow x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64SUBQborrow)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SBBQcarrymask(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SBBQcarrymask (FlagEQ))
	// result: (MOVQconst [0])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SBBQcarrymask (FlagLT_ULT))
	// result: (MOVQconst [-1])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (SBBQcarrymask (FlagLT_UGT))
	// result: (MOVQconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SBBQcarrymask (FlagGT_ULT))
	// result: (MOVQconst [-1])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (SBBQcarrymask (FlagGT_UGT))
	// result: (MOVQconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SBBQconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SBBQconst x [c] (FlagEQ))
	// result: (SUBQconstborrow x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64SUBQconstborrow)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETA(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SETA (InvertFlags x))
	// result: (SETB x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETB)
		v.AddArg(x)
		return true
	}
	// match: (SETA (FlagEQ))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETA (FlagLT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETA (FlagLT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETA (FlagGT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETA (FlagGT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETAE(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SETAE (TESTQ x x))
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAMD64TESTQ {
			break
		}
		x := v_0.Args[1]
		if x != v_0.Args[0] {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (SETAE (TESTL x x))
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAMD64TESTL {
			break
		}
		x := v_0.Args[1]
		if x != v_0.Args[0] {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (SETAE (TESTW x x))
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAMD64TESTW {
			break
		}
		x := v_0.Args[1]
		if x != v_0.Args[0] {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (SETAE (TESTB x x))
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAMD64TESTB {
			break
		}
		x := v_0.Args[1]
		if x != v_0.Args[0] {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (SETAE (InvertFlags x))
	// result: (SETBE x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETBE)
		v.AddArg(x)
		return true
	}
	// match: (SETAE (FlagEQ))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETAE (FlagLT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETAE (FlagLT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETAE (FlagGT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETAE (FlagGT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETAEstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETAEstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETBEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETBEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETAEstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETAEstore [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SETAEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETAEstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETAEstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SETAEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETAEstore [off] {sym} ptr (FlagEQ) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagEQ {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETAEstore [off] {sym} ptr (FlagLT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETAEstore [off] {sym} ptr (FlagLT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETAEstore [off] {sym} ptr (FlagGT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETAEstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETAstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETAstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETAstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETAstore [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SETAstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETAstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETAstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SETAstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETAstore [off] {sym} ptr (FlagEQ) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagEQ {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETAstore [off] {sym} ptr (FlagLT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETAstore [off] {sym} ptr (FlagLT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETAstore [off] {sym} ptr (FlagGT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETAstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETB(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SETB (TESTQ x x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpAMD64TESTQ {
			break
		}
		x := v_0.Args[1]
		if x != v_0.Args[0] {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (SETB (TESTL x x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpAMD64TESTL {
			break
		}
		x := v_0.Args[1]
		if x != v_0.Args[0] {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (SETB (TESTW x x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpAMD64TESTW {
			break
		}
		x := v_0.Args[1]
		if x != v_0.Args[0] {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (SETB (TESTB x x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpAMD64TESTB {
			break
		}
		x := v_0.Args[1]
		if x != v_0.Args[0] {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (SETB (BTLconst [0] x))
	// result: (ANDLconst [1] x)
	for {
		if v_0.Op != OpAMD64BTLconst || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(x)
		return true
	}
	// match: (SETB (BTQconst [0] x))
	// result: (ANDQconst [1] x)
	for {
		if v_0.Op != OpAMD64BTQconst || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDQconst)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(x)
		return true
	}
	// match: (SETB (InvertFlags x))
	// result: (SETA x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETA)
		v.AddArg(x)
		return true
	}
	// match: (SETB (FlagEQ))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETB (FlagLT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETB (FlagLT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETB (FlagGT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETB (FlagGT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETBE(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SETBE (InvertFlags x))
	// result: (SETAE x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETAE)
		v.AddArg(x)
		return true
	}
	// match: (SETBE (FlagEQ))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETBE (FlagLT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETBE (FlagLT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETBE (FlagGT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETBE (FlagGT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETBEstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETBEstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETAEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETAEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETBEstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETBEstore [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SETBEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETBEstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETBEstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SETBEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETBEstore [off] {sym} ptr (FlagEQ) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagEQ {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETBEstore [off] {sym} ptr (FlagLT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(p
"""




```