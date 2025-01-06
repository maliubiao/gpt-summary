Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第9部分，共12部分，请归纳一下它的功能

"""
}
	return false
}
func rewriteValueAMD64_OpAMD64TESTWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TESTWconst [-1] x)
	// cond: x.Op != OpAMD64MOVLconst
	// result: (TESTW x x)
	for {
		if auxIntToInt16(v.AuxInt) != -1 {
			break
		}
		x := v_0
		if !(x.Op != OpAMD64MOVLconst) {
			break
		}
		v.reset(OpAMD64TESTW)
		v.AddArg2(x, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XADDLlock(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XADDLlock [off1] {sym} val (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XADDLlock [off1+off2] {sym} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XADDLlock)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XADDQlock(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XADDQlock [off1] {sym} val (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XADDQlock [off1+off2] {sym} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XADDQlock)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XCHGL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XCHGL [off1] {sym} val (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XCHGL [off1+off2] {sym} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XCHGL)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, ptr, mem)
		return true
	}
	// match: (XCHGL [off1] {sym1} val (LEAQ [off2] {sym2} ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && ptr.Op != OpSB
	// result: (XCHGL [off1+off2] {mergeSym(sym1,sym2)} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpAMD64XCHGL)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XCHGQ(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XCHGQ [off1] {sym} val (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XCHGQ [off1+off2] {sym} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XCHGQ)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, ptr, mem)
		return true
	}
	// match: (XCHGQ [off1] {sym1} val (LEAQ [off2] {sym2} ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && ptr.Op != OpSB
	// result: (XCHGQ [off1+off2] {mergeSym(sym1,sym2)} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpAMD64XCHGQ)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORL (SHLL (MOVLconst [1]) y) x)
	// result: (BTCL x y)
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
			v.reset(OpAMD64BTCL)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XORL x (MOVLconst [c]))
	// result: (XORLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpAMD64XORLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XORL x x)
	// result: (MOVLconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (XORL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (XORLload x [off] {sym} ptr mem)
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
			v.reset(OpAMD64XORLload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (XORL x (ADDLconst [-1] x))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (BLSMSKL x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDLconst || auxIntToInt32(v_1.AuxInt) != -1 || x != v_1.Args[0] || !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpAMD64BLSMSKL)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORLconst [1] (SETNE x))
	// result: (SETEQ x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETNE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETEQ)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETEQ x))
	// result: (SETNE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETEQ {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETNE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETL x))
	// result: (SETGE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETL {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETGE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETGE x))
	// result: (SETL x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETGE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETL)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETLE x))
	// result: (SETG x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETLE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETG)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETG x))
	// result: (SETLE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETG {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETLE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETB x))
	// result: (SETAE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETB {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETAE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETAE x))
	// result: (SETB x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETAE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETB)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETBE x))
	// result: (SETA x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETBE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETA)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETA x))
	// result: (SETBE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETA {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETBE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [c] (XORLconst [d] x))
	// result: (XORLconst [c ^ d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64XORLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64XORLconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [c] x)
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
	// match: (XORLconst [c] (MOVLconst [d]))
	// result: (MOVLconst [c^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORLconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORLconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (XORLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
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
		v.reset(OpAMD64XORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (XORLconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (XORLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpAMD64XORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (XORLload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORLload [off1+off2] {sym} val base mem)
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
		v.reset(OpAMD64XORLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (XORLload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (XORLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
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
		v.reset(OpAMD64XORLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (XORLload x [off] {sym} ptr (MOVSSstore [off] {sym} ptr y _))
	// result: (XORL x (MOVLf2i y))
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
		v.reset(OpAMD64XORL)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLf2i, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORLmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORLmodify [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64XORLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (XORLmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (XORLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64XORLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORQ (SHLQ (MOVQconst [1]) y) x)
	// result: (BTCQ x y)
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
			v.reset(OpAMD64BTCQ)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XORQ (MOVQconst [c]) x)
	// cond: isUint64PowerOfTwo(c) && uint64(c) >= 1<<31
	// result: (BTCQconst [int8(log64(c))] x)
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
			v.reset(OpAMD64BTCQconst)
			v.AuxInt = int8ToAuxInt(int8(log64(c)))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XORQ x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (XORQconst [int32(c)] x)
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
			v.reset(OpAMD64XORQconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XORQ x x)
	// result: (MOVQconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XORQ x l:(MOVQload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (XORQload x [off] {sym} ptr mem)
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
			v.reset(OpAMD64XORQload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (XORQ x (ADDQconst [-1] x))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (BLSMSKQ x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDQconst || auxIntToInt32(v_1.AuxInt) != -1 || x != v_1.Args[0] || !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpAMD64BLSMSKQ)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORQconst [c] (XORQconst [d] x))
	// result: (XORQconst [c ^ d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64XORQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64XORQconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	// match: (XORQconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (XORQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [int64(c)^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(c) ^ d)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORQconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (XORQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
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
		v.reset(OpAMD64XORQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (XORQconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (XORQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpAMD64XORQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (XORQload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORQload [off1+off2] {sym} val base mem)
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
		v.reset(OpAMD64XORQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (XORQload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (XORQload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
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
		v.reset(OpAMD64XORQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (XORQload x [off] {sym} ptr (MOVSDstore [off] {sym} ptr y _))
	// result: (XORQ x (MOVQf2i y))
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
		v.reset(OpAMD64XORQ)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQf2i, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORQmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORQmodify [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64XORQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (XORQmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (XORQmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64XORQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (LEAQ {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpAMD64LEAQ)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAdd32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicAdd32 ptr val mem)
	// result: (AddTupleFirst32 val (XADDLlock val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64AddTupleFirst32)
		v0 := b.NewValue0(v.Pos, OpAMD64XADDLlock, types.NewTuple(typ.UInt32, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg2(val, v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAdd64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicAdd64 ptr val mem)
	// result: (AddTupleFirst64 val (XADDQlock val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64AddTupleFirst64)
		v0 := b.NewValue0(v.Pos, OpAMD64XADDQlock, types.NewTuple(typ.UInt64, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg2(val, v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAnd32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicAnd32 ptr val mem)
	// result: (ANDLlock ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64ANDLlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAnd32value(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicAnd32value ptr val mem)
	// result: (LoweredAtomicAnd32 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64LoweredAtomicAnd32)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAnd64value(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicAnd64value ptr val mem)
	// result: (LoweredAtomicAnd64 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64LoweredAtomicAnd64)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAnd8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicAnd8 ptr val mem)
	// result: (ANDBlock ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64ANDBlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicCompareAndSwap32(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicCompareAndSwap32 ptr old new_ mem)
	// result: (CMPXCHGLlock ptr old new_ mem)
	for {
		ptr := v_0
		old := v_1
		new_ := v_2
		mem := v_3
		v.reset(OpAMD64CMPXCHGLlock)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicCompareAndSwap64(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicCompareAndSwap64 ptr old new_ mem)
	// result: (CMPXCHGQlock ptr old new_ mem)
	for {
		ptr := v_0
		old := v_1
		new_ := v_2
		mem := v_3
		v.reset(OpAMD64CMPXCHGQlock)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicExchange32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicExchange32 ptr val mem)
	// result: (XCHGL val ptr mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64XCHGL)
		v.AddArg3(val, ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicExchange64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicExchange64 ptr val mem)
	// result: (XCHGQ val ptr mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64XCHGQ)
		v.AddArg3(val, ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicExchange8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicExchange8 ptr val mem)
	// result: (XCHGB val ptr mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64XCHGB)
		v.AddArg3(val, ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicLoad32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad32 ptr mem)
	// result: (MOVLatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVLatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicLoad64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad64 ptr mem)
	// result: (MOVQatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVQatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicLoad8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad8 ptr mem)
	// result: (MOVBatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVBatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicLoadPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoadPtr ptr mem)
	// result: (MOVQatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVQatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicOr32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicOr32 ptr val mem)
	// result: (ORLlock ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64ORLlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicOr32value(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicOr32value ptr val mem)
	// result: (LoweredAtomicOr32 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64LoweredAtomicOr32)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicOr64value(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicOr64value ptr val mem)
	// result: (LoweredAtomicOr64 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64LoweredAtomicOr64)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicOr8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicOr8 ptr val mem)
	// result: (ORBlock ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64ORBlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicStore32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicStore32 ptr val mem)
	// result: (Select1 (XCHGL <types.NewTuple(typ.UInt32,types.TypeMem)> val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpAMD64XCHGL, types.NewTuple(typ.UInt32, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicStore64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicStore64 ptr val mem)
	// result: (Select1 (XCHGQ <types.NewTuple(typ.UInt64,types.TypeMem)> val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpAMD64XCHGQ, types.NewTuple(typ.UInt64, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicStore8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicStore8 ptr val mem)
	// result: (Select1 (XCHGB <types.NewTuple(typ.UInt8,types.TypeMem)> val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpAMD64XCHGB, types.NewTuple(typ.UInt8, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicStorePtrNoWB(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicStorePtrNoWB ptr val mem)
	// result: (Select1 (XCHGQ <types.NewTuple(typ.BytePtr,types.TypeMem)> val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpAMD64XCHGQ, types.NewTuple(typ.BytePtr, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpBitLen16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen16 x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSRL (LEAL1 <typ.UInt32> [1] (MOVWQZX <typ.UInt32> x) (MOVWQZX <typ.UInt32> x)))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSRL)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL1, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVWQZX, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, v1)
		v.AddArg(v0)
		return true
	}
	// match: (BitLen16 <t> x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (NEGQ (ADDQconst <t> [-32] (LZCNTL (MOVWQZX <x.Type> x))))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64ADDQconst, t)
		v0.AuxInt = int32ToAuxInt(-32)
		v1 := b.NewValue0(v.Pos, OpAMD64LZCNTL, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpAMD64MOVWQZX, x.Type)
		v2.AddArg(x)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen32 x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (Select0 (BSRQ (LEAQ1 <typ.UInt64> [1] (MOVLQZX <typ.UInt64> x) (MOVLQZX <typ.UInt64> x))))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64BSRQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpAMD64LEAQ1, typ.UInt64)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpAMD64MOVLQZX, typ.UInt64)
		v2.AddArg(x)
		v1.AddArg2(v2, v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (BitLen32 <t> x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (NEGQ (ADDQconst <t> [-32] (LZCNTL x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64ADDQconst, t)
		v0.AuxInt = int32ToAuxInt(-32)
		v1 := b.NewValue0(v.Pos, OpAMD64LZCNTL, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpBitLen64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen64 <t> x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (ADDQconst [1] (CMOVQEQ <t> (Select0 <t> (BSRQ x)) (MOVQconst <t> [-1]) (Select1 <types.TypeFlags> (BSRQ x))))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64ADDQconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpAMD64CMOVQEQ, t)
		v1 := b.NewValue0(v.Pos, OpSelect0, t)
		v2 := b.NewValue0(v.Pos, OpAMD64BSRQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2.AddArg(x)
		v1.AddArg(v2)
		v3 := b.NewValue0(v.Pos, OpAMD64MOVQconst, t)
		v3.AuxInt = int64ToAuxInt(-1)
		v4 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v4.AddArg(v2)
		v0.AddArg3(v1, v3, v4)
		v.AddArg(v0)
		return true
	}
	// match: (BitLen64 <t> x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (NEGQ (ADDQconst <t> [-64] (LZCNTQ x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64ADDQconst, t)
		v0.AuxInt = int32ToAuxInt(-64)
		v1 := b.NewValue0(v.Pos, OpAMD64LZCNTQ, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpBitLen8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen8 x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSRL (LEAL1 <typ.UInt32> [1] (MOVBQZX <typ.UInt32> x) (MOVBQZX <typ.UInt32> x)))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSRL)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL1, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVBQZX, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, v1)
		v.AddArg(v0)
		return true
	}
	// match: (BitLen8 <t> x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (NEGQ (ADDQconst <t> [-32] (LZCNTL (MOVBQZX <x.Type> x))))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64ADDQconst, t)
		v0.AuxInt = int32ToAuxInt(-32)
		v1 := b.NewValue0(v.Pos, OpAMD64LZCNTL, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpAMD64MOVBQZX, x.Type)
		v2.AddArg(x)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpBswap16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Bswap16 x)
	// result: (ROLWconst [8] x)
	for {
		x := v_0
		v.reset(OpAMD64ROLWconst)
		v.AuxInt = int8ToAuxInt(8)
		v.AddArg(x)
		return true
	}
}
func rewriteValueAMD64_OpCeil(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ceil x)
	// result: (ROUNDSD [2] x)
	for {
		x := v_0
		v.reset(OpAMD64ROUNDSD)
		v.AuxInt = int8ToAuxInt(2)
		v.AddArg(x)
		return true
	}
}
func rewriteValueAMD64_OpCondSelect(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CondSelect <t> x y (SETEQ cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQEQ y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQ {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQEQ)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQNE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQNE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETL cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQLT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETL {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQLT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETG cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQGT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETG {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQGT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETLE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQLE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETLE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQLE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQGE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQGE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETA cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQHI y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETA {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQHI)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETB cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQCS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETB {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQCS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETAE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQCC y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETAE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQCC)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETBE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQLS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETBE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQLS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQF cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQEQF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQF {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQEQF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNEF cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQNEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNEF {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQNEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGF cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQGTF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGF {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQGTF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGEF cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQGEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGEF {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQGEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQ cond))
	// cond: is32BitInt(t)
	// result: (CMOVLEQ y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQ {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLEQ)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLNE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLNE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETL cond))
	// cond: is32BitInt(t)
	// result: (CMOVLLT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETL {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLLT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETG cond))
	// cond: is32BitInt(t)
	// result: (CMOVLGT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETG {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLGT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETLE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLLE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETLE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLLE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLGE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLGE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETA cond))
	// cond: is32BitInt(t)
	// result: (CMOVLHI y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETA {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLHI)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETB cond))
	// cond: is32BitInt(t)
	// result: (CMOVLCS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETB {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLCS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETAE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLCC y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETAE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLCC)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETBE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLLS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETBE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLLS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQF cond))
	// cond: is32BitInt(t)
	// result: (CMOVLEQF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQF {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLEQF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNEF cond))
	// cond: is32BitInt(t)
	// result: (CMOVLNEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNEF {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLNEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGF cond))
	// cond: is32BitInt(t)
	// result: (CMOVLGTF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGF {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLGTF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGEF cond))
	// cond: is32BitInt(t)
	// result: (CMOVLGEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGEF {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLGEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQ cond))
	// cond: is16BitInt(t)
	// result: (CMOVWEQ y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQ {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWEQ)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWNE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWNE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETL cond))
	// cond: is16BitInt(t)
	// result: (CMOVWLT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETL {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWLT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETG cond))
	// cond: is16BitInt(t)
	// result: (CMOVWGT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETG {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWGT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETLE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWLE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETLE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWLE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWGE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWGE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETA cond))
	// cond: is16BitInt(t)
	// result: (CMOVWHI y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETA {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWHI)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETB cond))
	// cond: is16BitInt(t)
	// result: (CMOVWCS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETB {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWCS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETAE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWCC y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETAE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWCC)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETBE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWLS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETBE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWLS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQF cond))
	// cond: is16BitInt(t)
	// result: (CMOVWEQF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQF {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWEQF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNEF cond))
	// cond: is16BitInt(t)
	// result: (CMOVWNEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNEF {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWNEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGF cond))
	// cond: is16BitInt(t)
	// result: (CMOVWGTF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGF {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWGTF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGEF cond))
	// cond: is16BitInt(t)
	// result: (CMOVWGEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGEF {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWGEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 1
	// result: (CondSelect <t> x y (MOVBQZX <typ.UInt64> check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 1) {
			break
		}
		v.reset(OpCondSelect)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64MOVBQZX, typ.UInt64)
		v0.AddArg(check)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 2
	// result: (CondSelect <t> x y (MOVWQZX <typ.UInt64> check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 2) {
			break
		}
		v.reset(OpCondSelect)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64MOVWQZX, typ.UInt64)
		v0.AddArg(check)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 4
	// result: (CondSelect <t> x y (MOVLQZX <typ.UInt64> check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 4) {
			break
		}
		v.reset(OpCondSelect)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLQZX, typ.UInt64)
		v0.AddArg(check)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 8 && (is64BitInt(t) || isPtr(t))
	// result: (CMOVQNE y x (CMPQconst [0] check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 8 && (is64BitInt(t) || isPtr(t))) {
			break
		}
		v.reset(OpAMD64CMOVQNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(check)
		v.AddArg3(y, x, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 8 && is32BitInt(t)
	// result: (CMOVLNE y x (CMPQconst [0] check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 8 && is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(check)
		v.AddArg3(y, x, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 8 && is16BitInt(t)
	// result: (CMOVWNE y x (CMPQconst [0] check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 8 && is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(check)
		v.AddArg3(y, x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpConst16(v *Value) bool {
	// match: (Const16 [c])
	// result: (MOVLconst [int32(c)])
	for {
		c := auxIntToInt16(v.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
}
func rewriteValueAMD64_OpConst8(v *Value) bool {
	// match: (Const8 [c])
	// result: (MOVLconst [int32(c)])
	for {
		c := auxIntToInt8(v.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
}
func rewriteValueAMD64_OpConstBool(v *Value) bool {
	// match: (ConstBool [c])
	// result: (MOVLconst [b2i32(c)])
	for {
		c := auxIntToBool(v.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(b2i32(c))
		return true
	}
}
func rewriteValueAMD64_OpConstNil(v *Value) bool {
	// match: (ConstNil )
	// result: (MOVQconst [0])
	for {
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValueAMD64_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz16 x)
	// result: (BSFL (ORLconst <typ.UInt32> [1<<16] x))
	for {
		x := v_0
		v.reset(OpAMD64BSFL)
		v0 := b.NewValue0(v.Pos, OpAMD64ORLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(1 << 16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpCtz16NonZero(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ctz16NonZero x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTL)
		v.AddArg(x)
		return true
	}
	// match: (Ctz16NonZero x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSFL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSFL)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz32 x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTL)
		v.AddArg(x)
		return true
	}
	// match: (Ctz32 x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (Select0 (BSFQ (BTSQconst <typ.UInt64> [32] x)))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64BSFQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpAMD64BTSQconst, typ.UInt64)
		v1.AuxInt = int8ToAuxInt(32)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz32NonZero(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ctz32NonZero x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTL)
		v.AddArg(x)
		return true
	}
	// match: (Ctz32NonZero x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSFL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSFL)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz64 x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTQ x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTQ)
		v.AddArg(x)
		return true
	}
	// match: (Ctz64 <t> x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (CMOVQEQ (Select0 <t> (BSFQ x)) (MOVQconst <t> [64]) (Select1 <types.TypeFlags> (BSFQ x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64CMOVQEQ)
		v0 := b.NewValue0(v.Pos, OpSelect0, t)
		v1 := b.NewValue0(v.Pos, OpAMD64BSFQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1.AddArg(x)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpAMD64MOVQconst, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz64NonZero(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz64NonZero x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTQ x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTQ)
		v.AddArg(x)
		return true
	}
	// match: (Ctz64NonZero x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (Select0 (BSFQ x))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64BSFQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz8 x)
	// result: (BSFL (ORLconst <typ.UInt32> [1<<8 ] x))
	for {
		x := v_0
		v.reset(OpAMD64BSFL)
		v0 := b.NewValue0(v.Pos, OpAMD64ORLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(1 << 8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpCtz8NonZero(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ctz8NonZero x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTL)
		v.AddArg(x)
		return true
	}
	// match: (Ctz8NonZero x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSFL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSFL)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 [a] x y)
	// result: (Select0 (DIVW [a] x y))
	for {
		a := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVW, types.NewTuple(typ.Int16, typ.Int16))
		v0.AuxInt = boolToAuxInt(a)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (Select0 (DIVWU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVWU, types.NewTuple(typ.UInt16, typ.UInt16))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32 [a] x y)
	// result: (Select0 (DIVL [a] x y))
	for {
		a := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVL, types.NewTuple(typ.Int32, typ.Int32))
		v0.AuxInt = boolToAuxInt(a)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32u x y)
	// result: (Select0 (DIVLU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVLU, types.NewTuple(typ.UInt32, typ.UInt32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div64 [a] x y)
	// result: (Select0 (DIVQ [a] x y))
	for {
		a := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVQ, types.NewTuple(typ.Int64, typ.Int64))
		v0.AuxInt = boolToAuxInt(a)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div64u x y)
	// result: (Select0 (DIVQU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVQU, types.NewTuple(typ.UInt64, typ.UInt64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (Select0 (DIVW (SignExt8to16 x) (SignExt8to16 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVW, types.NewTuple(typ.Int16, typ.Int16))
		v1 := b.NewValue0(v.Pos, OpSignExt8to16, typ.Int16)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to16, typ.Int16)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (Select0 (DIVWU (ZeroExt8to16 x) (ZeroExt8to16 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVWU, types.NewTuple(typ.UInt16, typ.UInt16))
		v1 := b.NewValue0(v.Pos, OpZeroExt8to16, typ.UInt16)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to16, typ.UInt16)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq16 x y)
	// result: (SETEQ (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32 x y)
	// result: (SETEQ (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (SETEQF (UCOMISS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQF)
		v0 := b.NewValue0(v.Pos, OpAMD64UCOMISS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64 x y)
	// result: (SETEQ (CMPQ x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQ, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (SETEQF (UCOMISD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQF)
		v0 := b.NewValue0(v.Pos, OpAMD64UCOMISD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq8 x y)
	// result: (SETEQ (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqB x y)
	// result: (SETEQ (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqPtr x y)
	// result: (SETEQ (CMPQ x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQ, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpFMA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMA x y z)
	// result: (VFMADD231SD z x y)
	for {
		x := v_0
		y := v_1
		z := v_2
		v.reset(OpAMD64VFMADD231SD)
		v.AddArg3(z, x, y)
		return true
	}
}
func rewriteValueAMD64_OpFloor(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Floor x)
	// result: (ROUNDSD [1] x)
	for {
		x := v_0
		v.reset(OpAMD64ROUNDSD)
		v.AuxInt = int8ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueAMD64_OpGetG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GetG mem)
	// cond: v.Block.Func.OwnAux.Fn.ABI() != obj.ABIInternal
	// result: (LoweredGetG mem)
	for {
		mem := v_0
		if !(v.Block.Func.OwnAux.Fn.ABI() != obj.ABIInternal) {
			break
		}
		v.reset(OpAMD64LoweredGetG)
		v.AddArg(mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpHasCPUFeature(v *Value) bool {
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (HasCPUFeature {s})
	// result: (SETNE (CMPLconst [0] (LoweredHasCPUFeature {s})))
	for {
		s := auxToSym(v.Aux)
		v.reset(OpAMD64SETNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpAMD64LoweredHasCPUFeature, typ.UInt64)
		v1.Aux = symToAux(s)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsInBounds idx len)
	// result: (SETB (CMPQ idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpAMD64SETB)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQ, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsNonNil p)
	// result: (SETNE (TESTQ p p))
	for {
		p := v_0
		v.reset(OpAMD64SETNE)
		v0 := b.NewValue0(v.Pos, OpAMD64TESTQ, types.TypeFlags)
		v0.AddArg2(p, p)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsSliceInBounds idx len)
	// result: (SETBE (CMPQ idx len))
	f
"""




```