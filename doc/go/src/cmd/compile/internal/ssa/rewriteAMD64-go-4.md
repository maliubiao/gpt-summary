Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第5部分，共12部分，请归纳一下它的功能

"""
rgs[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVQload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVQload [off] {sym} ptr (MOVSDstore [off] {sym} ptr val _))
	// result: (MOVQf2i val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVSDstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpAMD64MOVQf2i)
		v.AddArg(val)
		return true
	}
	// match: (MOVQload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVQconst [int64(read64(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(read64(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVQstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVQstore [off1] {sym} (ADDQconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVQstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVQstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVQstore [off] {sym} ptr (MOVQconst [c]) mem)
	// cond: validVal(c)
	// result: (MOVQstoreconst [makeValAndOff(int32(c),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(validVal(c)) {
			break
		}
		v.reset(OpAMD64MOVQstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVQstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64MOVQstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVQstore {sym} [off] ptr y:(ADDQload x [off] {sym} ptr mem) mem)
	// cond: y.Uses==1 && clobber(y)
	// result: (ADDQmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ADDQload || auxIntToInt32(y.AuxInt) != off || auxToSym(y.Aux) != sym {
			break
		}
		mem := y.Args[2]
		x := y.Args[0]
		if ptr != y.Args[1] || mem != v_2 || !(y.Uses == 1 && clobber(y)) {
			break
		}
		v.reset(OpAMD64ADDQmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVQstore {sym} [off] ptr y:(ANDQload x [off] {sym} ptr mem) mem)
	// cond: y.Uses==1 && clobber(y)
	// result: (ANDQmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ANDQload || auxIntToInt32(y.AuxInt) != off || auxToSym(y.Aux) != sym {
			break
		}
		mem := y.Args[2]
		x := y.Args[0]
		if ptr != y.Args[1] || mem != v_2 || !(y.Uses == 1 && clobber(y)) {
			break
		}
		v.reset(OpAMD64ANDQmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVQstore {sym} [off] ptr y:(ORQload x [off] {sym} ptr mem) mem)
	// cond: y.Uses==1 && clobber(y)
	// result: (ORQmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ORQload || auxIntToInt32(y.AuxInt) != off || auxToSym(y.Aux) != sym {
			break
		}
		mem := y.Args[2]
		x := y.Args[0]
		if ptr != y.Args[1] || mem != v_2 || !(y.Uses == 1 && clobber(y)) {
			break
		}
		v.reset(OpAMD64ORQmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVQstore {sym} [off] ptr y:(XORQload x [off] {sym} ptr mem) mem)
	// cond: y.Uses==1 && clobber(y)
	// result: (XORQmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64XORQload || auxIntToInt32(y.AuxInt) != off || auxToSym(y.Aux) != sym {
			break
		}
		mem := y.Args[2]
		x := y.Args[0]
		if ptr != y.Args[1] || mem != v_2 || !(y.Uses == 1 && clobber(y)) {
			break
		}
		v.reset(OpAMD64XORQmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVQstore {sym} [off] ptr y:(ADDQ l:(MOVQload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (ADDQmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ADDQ {
			break
		}
		_ = y.Args[1]
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			l := y_0
			if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
				continue
			}
			mem := l.Args[1]
			if ptr != l.Args[0] {
				continue
			}
			x := y_1
			if mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
				continue
			}
			v.reset(OpAMD64ADDQmodify)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(ptr, x, mem)
			return true
		}
		break
	}
	// match: (MOVQstore {sym} [off] ptr y:(SUBQ l:(MOVQload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (SUBQmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SUBQ {
			break
		}
		x := y.Args[1]
		l := y.Args[0]
		if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		if ptr != l.Args[0] || mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
			break
		}
		v.reset(OpAMD64SUBQmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVQstore {sym} [off] ptr y:(ANDQ l:(MOVQload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (ANDQmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ANDQ {
			break
		}
		_ = y.Args[1]
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			l := y_0
			if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
				continue
			}
			mem := l.Args[1]
			if ptr != l.Args[0] {
				continue
			}
			x := y_1
			if mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
				continue
			}
			v.reset(OpAMD64ANDQmodify)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(ptr, x, mem)
			return true
		}
		break
	}
	// match: (MOVQstore {sym} [off] ptr y:(ORQ l:(MOVQload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (ORQmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ORQ {
			break
		}
		_ = y.Args[1]
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			l := y_0
			if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
				continue
			}
			mem := l.Args[1]
			if ptr != l.Args[0] {
				continue
			}
			x := y_1
			if mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
				continue
			}
			v.reset(OpAMD64ORQmodify)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(ptr, x, mem)
			return true
		}
		break
	}
	// match: (MOVQstore {sym} [off] ptr y:(XORQ l:(MOVQload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (XORQmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64XORQ {
			break
		}
		_ = y.Args[1]
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			l := y_0
			if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
				continue
			}
			mem := l.Args[1]
			if ptr != l.Args[0] {
				continue
			}
			x := y_1
			if mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
				continue
			}
			v.reset(OpAMD64XORQmodify)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(ptr, x, mem)
			return true
		}
		break
	}
	// match: (MOVQstore {sym} [off] ptr x:(BTSQconst [c] l:(MOVQload {sym} [off] ptr mem)) mem)
	// cond: x.Uses == 1 && l.Uses == 1 && clobber(x, l)
	// result: (BTSQconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		x := v_1
		if x.Op != OpAMD64BTSQconst {
			break
		}
		c := auxIntToInt8(x.AuxInt)
		l := x.Args[0]
		if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		if ptr != l.Args[0] || mem != v_2 || !(x.Uses == 1 && l.Uses == 1 && clobber(x, l)) {
			break
		}
		v.reset(OpAMD64BTSQconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstore {sym} [off] ptr x:(BTRQconst [c] l:(MOVQload {sym} [off] ptr mem)) mem)
	// cond: x.Uses == 1 && l.Uses == 1 && clobber(x, l)
	// result: (BTRQconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		x := v_1
		if x.Op != OpAMD64BTRQconst {
			break
		}
		c := auxIntToInt8(x.AuxInt)
		l := x.Args[0]
		if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		if ptr != l.Args[0] || mem != v_2 || !(x.Uses == 1 && l.Uses == 1 && clobber(x, l)) {
			break
		}
		v.reset(OpAMD64BTRQconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstore {sym} [off] ptr x:(BTCQconst [c] l:(MOVQload {sym} [off] ptr mem)) mem)
	// cond: x.Uses == 1 && l.Uses == 1 && clobber(x, l)
	// result: (BTCQconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		x := v_1
		if x.Op != OpAMD64BTCQconst {
			break
		}
		c := auxIntToInt8(x.AuxInt)
		l := x.Args[0]
		if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		if ptr != l.Args[0] || mem != v_2 || !(x.Uses == 1 && l.Uses == 1 && clobber(x, l)) {
			break
		}
		v.reset(OpAMD64BTCQconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstore [off] {sym} ptr a:(ADDQconst [c] l:(MOVQload [off] {sym} ptr2 mem)) mem)
	// cond: isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)
	// result: (ADDQconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		a := v_1
		if a.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		l := a.Args[0]
		if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		ptr2 := l.Args[0]
		if mem != v_2 || !(isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)) {
			break
		}
		v.reset(OpAMD64ADDQconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstore [off] {sym} ptr a:(ANDQconst [c] l:(MOVQload [off] {sym} ptr2 mem)) mem)
	// cond: isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)
	// result: (ANDQconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		a := v_1
		if a.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		l := a.Args[0]
		if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		ptr2 := l.Args[0]
		if mem != v_2 || !(isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)) {
			break
		}
		v.reset(OpAMD64ANDQconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstore [off] {sym} ptr a:(ORQconst [c] l:(MOVQload [off] {sym} ptr2 mem)) mem)
	// cond: isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)
	// result: (ORQconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		a := v_1
		if a.Op != OpAMD64ORQconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		l := a.Args[0]
		if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		ptr2 := l.Args[0]
		if mem != v_2 || !(isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)) {
			break
		}
		v.reset(OpAMD64ORQconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstore [off] {sym} ptr a:(XORQconst [c] l:(MOVQload [off] {sym} ptr2 mem)) mem)
	// cond: isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)
	// result: (XORQconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		a := v_1
		if a.Op != OpAMD64XORQconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		l := a.Args[0]
		if l.Op != OpAMD64MOVQload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		ptr2 := l.Args[0]
		if mem != v_2 || !(isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)) {
			break
		}
		v.reset(OpAMD64XORQconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstore [off] {sym} ptr (MOVQf2i val) mem)
	// result: (MOVSDstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQf2i {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVSDstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVQstore [i] {s} p x:(BSWAPQ w) mem)
	// cond: x.Uses == 1 && buildcfg.GOAMD64 >= 3
	// result: (MOVBEQstore [i] {s} p w mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		x := v_1
		if x.Op != OpAMD64BSWAPQ {
			break
		}
		w := x.Args[0]
		mem := v_2
		if !(x.Uses == 1 && buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64MOVBEQstore)
		v.AuxInt = int32ToAuxInt(i)
		v.Aux = symToAux(s)
		v.AddArg3(p, w, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVQstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVQstoreconst [sc] {s} (ADDQconst [off] ptr) mem)
	// cond: ValAndOff(sc).canAdd32(off)
	// result: (MOVQstoreconst [ValAndOff(sc).addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVQstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstoreconst [sc] {sym1} (LEAQ [off] {sym2} ptr) mem)
	// cond: canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)
	// result: (MOVQstoreconst [ValAndOff(sc).addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVQstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstoreconst [c] {s} p1 x:(MOVQstoreconst [a] {s} p0 mem))
	// cond: config.useSSE && x.Uses == 1 && sequentialAddresses(p0, p1, int64(a.Off()+8-c.Off())) && a.Val() == 0 && c.Val() == 0 && setPos(v, x.Pos) && clobber(x)
	// result: (MOVOstoreconst [makeValAndOff(0,a.Off())] {s} p0 mem)
	for {
		c := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		p1 := v_0
		x := v_1
		if x.Op != OpAMD64MOVQstoreconst {
			break
		}
		a := auxIntToValAndOff(x.AuxInt)
		if auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[1]
		p0 := x.Args[0]
		if !(config.useSSE && x.Uses == 1 && sequentialAddresses(p0, p1, int64(a.Off()+8-c.Off())) && a.Val() == 0 && c.Val() == 0 && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, a.Off()))
		v.Aux = symToAux(s)
		v.AddArg2(p0, mem)
		return true
	}
	// match: (MOVQstoreconst [a] {s} p0 x:(MOVQstoreconst [c] {s} p1 mem))
	// cond: config.useSSE && x.Uses == 1 && sequentialAddresses(p0, p1, int64(a.Off()+8-c.Off())) && a.Val() == 0 && c.Val() == 0 && setPos(v, x.Pos) && clobber(x)
	// result: (MOVOstoreconst [makeValAndOff(0,a.Off())] {s} p0 mem)
	for {
		a := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		p0 := v_0
		x := v_1
		if x.Op != OpAMD64MOVQstoreconst {
			break
		}
		c := auxIntToValAndOff(x.AuxInt)
		if auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[1]
		p1 := x.Args[0]
		if !(config.useSSE && x.Uses == 1 && sequentialAddresses(p0, p1, int64(a.Off()+8-c.Off())) && a.Val() == 0 && c.Val() == 0 && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, a.Off()))
		v.Aux = symToAux(s)
		v.AddArg2(p0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVSDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVSDload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVSDload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVSDload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVSDload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVSDload [off] {sym} ptr (MOVQstore [off] {sym} ptr val _))
	// result: (MOVQi2f val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpAMD64MOVQi2f)
		v.AddArg(val)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVSDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVSDstore [off1] {sym} (ADDQconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVSDstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVSDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVSDstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVSDstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64MOVSDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVSDstore [off] {sym} ptr (MOVQi2f val) mem)
	// result: (MOVQstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQi2f {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVQstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVSDstore [off] {sym} ptr (MOVSDconst [f]) mem)
	// cond: f == f
	// result: (MOVQstore [off] {sym} ptr (MOVQconst [int64(math.Float64bits(f))]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVSDconst {
			break
		}
		f := auxIntToFloat64(v_1.AuxInt)
		mem := v_2
		if !(f == f) {
			break
		}
		v.reset(OpAMD64MOVQstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(int64(math.Float64bits(f)))
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVSSload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVSSload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVSSload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVSSload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVSSload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVSSload [off] {sym} ptr (MOVLstore [off] {sym} ptr val _))
	// result: (MOVLi2f val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpAMD64MOVLi2f)
		v.AddArg(val)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVSSstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVSSstore [off1] {sym} (ADDQconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVSSstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVSSstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVSSstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVSSstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64MOVSSstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVSSstore [off] {sym} ptr (MOVLi2f val) mem)
	// result: (MOVLstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLi2f {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVLstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVSSstore [off] {sym} ptr (MOVSSconst [f]) mem)
	// cond: f == f
	// result: (MOVLstore [off] {sym} ptr (MOVLconst [int32(math.Float32bits(f))]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVSSconst {
			break
		}
		f := auxIntToFloat32(v_1.AuxInt)
		mem := v_2
		if !(f == f) {
			break
		}
		v.reset(OpAMD64MOVLstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(int32(math.Float32bits(f)))
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVWQSX(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVWQSX x:(MOVWload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWQSXload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVWload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVWQSXload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWQSX x:(MOVLload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWQSXload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVWQSXload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWQSX x:(MOVQload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWQSXload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVWQSXload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWQSX (ANDLconst [c] x))
	// cond: c & 0x8000 == 0
	// result: (ANDLconst [c & 0x7fff] x)
	for {
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c&0x8000 == 0) {
			break
		}
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(c & 0x7fff)
		v.AddArg(x)
		return true
	}
	// match: (MOVWQSX (MOVWQSX x))
	// result: (MOVWQSX x)
	for {
		if v_0.Op != OpAMD64MOVWQSX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVWQSX)
		v.AddArg(x)
		return true
	}
	// match: (MOVWQSX (MOVBQSX x))
	// result: (MOVBQSX x)
	for {
		if v_0.Op != OpAMD64MOVBQSX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVBQSX)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVWQSXload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWQSXload [off] {sym} ptr (MOVWstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVWQSX x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVWstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpAMD64MOVWQSX)
		v.AddArg(x)
		return true
	}
	// match: (MOVWQSXload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVWQSXload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVWQSXload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVWQZX(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVWQZX x:(MOVWload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVWload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVWload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWQZX x:(MOVLload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVWload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWQZX x:(MOVQload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVWload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWQZX (ANDLconst [c] x))
	// result: (ANDLconst [c & 0xffff] x)
	for {
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(c & 0xffff)
		v.AddArg(x)
		return true
	}
	// match: (MOVWQZX (MOVWQZX x))
	// result: (MOVWQZX x)
	for {
		if v_0.Op != OpAMD64MOVWQZX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVWQZX)
		v.AddArg(x)
		return true
	}
	// match: (MOVWQZX (MOVBQZX x))
	// result: (MOVBQZX x)
	for {
		if v_0.Op != OpAMD64MOVBQZX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVBQZX)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWload [off] {sym} ptr (MOVWstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVWQZX x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVWstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpAMD64MOVWQZX)
		v.AddArg(x)
		return true
	}
	// match: (MOVWload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVWload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVWload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVWload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVLconst [int32(read16(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(int32(read16(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstore [off] {sym} ptr (MOVWQSX x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVWQSX {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWQZX x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVWQZX {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym} (ADDQconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVWstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (MOVWstoreconst [makeValAndOff(int32(int16(c)),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64MOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int16(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVQconst [c]) mem)
	// result: (MOVWstoreconst [makeValAndOff(int32(int16(c)),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64MOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int16(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVWstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVWstore [i] {s} p x:(ROLWconst [8] w) mem)
	// cond: x.Uses == 1 && buildcfg.GOAMD64 >= 3
	// result: (MOVBEWstore [i] {s} p w mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		x := v_1
		if x.Op != OpAMD64ROLWconst || auxIntToInt8(x.AuxInt) != 8 {
			break
		}
		w := x.Args[0]
		mem := v_2
		if !(x.Uses == 1 && buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64MOVBEWstore)
		v.AuxInt = int32ToAuxInt(i)
		v.Aux = symToAux(s)
		v.AddArg3(p, w, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVWstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreconst [sc] {s} (ADDQconst [off] ptr) mem)
	// cond: ValAndOff(sc).canAdd32(off)
	// result: (MOVWstoreconst [ValAndOff(sc).addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstoreconst [sc] {sym1} (LEAQ [off] {sym2} ptr) mem)
	// cond: canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)
	// result: (MOVWstoreconst [ValAndOff(sc).addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MULL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULL x (MOVLconst [c]))
	// result: (MULLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpAMD64MULLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64MULLconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULLconst [c] (MULLconst [d] x))
	// result: (MULLconst [c * d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MULLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64MULLconst)
		v.AuxInt = int32ToAuxInt(c * d)
		v.AddArg(x)
		return true
	}
	// match: (MULLconst [-9] x)
	// result: (NEGL (LEAL8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != -9 {
			break
		}
		x := v_0
		v.reset(OpAMD64NEGL)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULLconst [-5] x)
	// result: (NEGL (LEAL4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != -5 {
			break
		}
		x := v_0
		v.reset(OpAMD64NEGL)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULLconst [-3] x)
	// result: (NEGL (LEAL2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != -3 {
			break
		}
		x := v_0
		v.reset(OpAMD64NEGL)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULLconst [-1] x)
	// result: (NEGL x)
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.reset(OpAMD64NEGL)
		v.AddArg(x)
		return true
	}
	// match: (MULLconst [ 0] _)
	// result: (MOVLconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (MULLconst [ 1] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 1 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (MULLconst [ 3] x)
	// result: (LEAL2 x x)
	for {
		if auxIntToInt32(v.AuxInt) != 3 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL2)
		v.AddArg2(x, x)
		return true
	}
	// match: (MULLconst [ 5] x)
	// result: (LEAL4 x x)
	for {
		if auxIntToInt32(v.AuxInt) != 5 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL4)
		v.AddArg2(x, x)
		return true
	}
	// match: (MULLconst [ 7] x)
	// result: (LEAL2 x (LEAL2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 7 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL2)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLconst [ 9] x)
	// result: (LEAL8 x x)
	for {
		if auxIntToInt32(v.AuxInt) != 9 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL8)
		v.AddArg2(x, x)
		return true
	}
	// match: (MULLconst [11] x)
	// result: (LEAL2 x (LEAL4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 11 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL2)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLconst [13] x)
	// result: (LEAL4 x (LEAL2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 13 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL4)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLconst [19] x)
	// result: (LEAL2 x (LEAL8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 19 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL2)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLconst [21] x)
	// result: (LEAL4 x (LEAL4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 21 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL4)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLconst [25] x)
	// result: (LEAL8 x (LEAL2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 25 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLconst [27] x)
	// result: (LEAL8 (LEAL2 <v.Type> x x) (LEAL2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 27 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(v0, v0)
		return true
	}
	// match: (MULLconst [37] x)
	// result: (LEAL4 x (LEAL8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 37 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL4)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLconst [41] x)
	// result: (LEAL8 x (LEAL4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 41 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLconst [45] x)
	// result: (LEAL8 (LEAL4 <v.Type> x x) (LEAL4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 45 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(v0, v0)
		return true
	}
	// match: (MULLconst [73] x)
	// result: (LEAL8 x (LEAL8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 73 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLconst [81] x)
	// result: (LEAL8 (LEAL8 <v.Type> x x) (LEAL8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 81 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAL8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(v0, v0)
		return true
	}
	// match: (MULLconst [c] x)
	// cond: isPowerOfTwo(int64(c)+1) && c >= 15
	// result: (SUBL (SHLLconst <v.Type> [int8(log64(int64(c)+1))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(int64(c)+1) && c >= 15) {
			break
		}
		v.reset(OpAMD64SUBL)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLLconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log64(int64(c) + 1)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULLconst [c] x)
	// cond: isPowerOfTwo(c-1) && c >= 17
	// result: (LEAL1 (SHLLconst <v.Type> [int8(log32(c-1))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c-1) && c >= 17) {
			break
		}
		v.reset(OpAMD64LEAL1)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLLconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log32(c - 1)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULLconst [c] x)
	// cond: isPowerOfTwo(c-2) && c >= 34
	// result: (LEAL2 (SHLLconst <v.Type> [int8(log32(c-2))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c-2) && c >= 34) {
			break
		}
		v.reset(OpAMD64LEAL2)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLLconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log32(c - 2)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULLconst [c] x)
	// cond: isPowerOfTwo(c-4) && c >= 68
	// result: (LEAL4 (SHLLconst <v.Type> [int8(log32(c-4))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c-4) && c >= 68) {
			break
		}
		v.reset(OpAMD64LEAL4)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLLconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log32(c - 4)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULLconst [c] x)
	// cond: isPowerOfTwo(c-8) && c >= 136
	// result: (LEAL8 (SHLLconst <v.Type> [int8(log32(c-8))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c-8) && c >= 136) {
			break
		}
		v.reset(OpAMD64LEAL8)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLLconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log32(c - 8)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULLconst [c] x)
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (SHLLconst [int8(log32(c/3))] (LEAL2 <v.Type> x x))
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c%3 == 0 && isPowerOfTwo(c/3)) {
			break
		}
		v.reset(OpAMD64SHLLconst)
		v.AuxInt = int8ToAuxInt(int8(log32(c / 3)))
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULLconst [c] x)
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (SHLLconst [int8(log32(c/5))] (LEAL4 <v.Type> x x))
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c%5 == 0 && isPowerOfTwo(c/5)) {
			break
		}
		v.reset(OpAMD64SHLLconst)
		v.AuxInt = int8ToAuxInt(int8(log32(c / 5)))
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULLconst [c] x)
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (SHLLconst [int8(log32(c/9))] (LEAL8 <v.Type> x x))
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c%9 == 0 && isPowerOfTwo(c/9)) {
			break
		}
		v.reset(OpAMD64SHLLconst)
		v.AuxInt = int8ToAuxInt(int8(log32(c / 9)))
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULLconst [c] (MOVLconst [d]))
	// result: (MOVLconst [c*d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(c * d)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MULQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULQ x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (MULQconst [int32(c)] x)
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
			v.reset(OpAMD64MULQconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64MULQconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULQconst [c] (MULQconst [d] x))
	// cond: is32Bit(int64(c)*int64(d))
	// result: (MULQconst [c * d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MULQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(int64(c) * int64(d))) {
			break
		}
		v.reset(OpAMD64MULQconst)
		v.AuxInt = int32ToAuxInt(c * d)
		v.AddArg(x)
		return true
	}
	// match: (MULQconst [-9] x)
	// result: (NEGQ (LEAQ8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != -9 {
			break
		}
		x := v_0
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULQconst [-5] x)
	// result: (NEGQ (LEAQ4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != -5 {
			break
		}
		x := v_0
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULQconst [-3] x)
	// result: (NEGQ (LEAQ2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != -3 {
			break
		}
		x := v_0
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULQconst [-1] x)
	// result: (NEGQ x)
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.reset(OpAMD64NEGQ)
		v.AddArg(x)
		return true
	}
	// match: (MULQconst [ 0] _)
	// result: (MOVQconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MULQconst [ 1] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 1 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (MULQconst [ 3] x)
	// result: (LEAQ2 x x)
	for {
		if auxIntToInt32(v.AuxInt) != 3 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ2)
		v.AddArg2(x, x)
		return true
	}
	// match: (MULQconst [ 5] x)
	// result: (LEAQ4 x x)
	for {
		if auxIntToInt32(v.AuxInt) != 5 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ4)
		v.AddArg2(x, x)
		return true
	}
	// match: (MULQconst [ 7] x)
	// result: (LEAQ2 x (LEAQ2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 7 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ2)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULQconst [ 9] x)
	// result: (LEAQ8 x x)
	for {
		if auxIntToInt32(v.AuxInt) != 9 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ8)
		v.AddArg2(x, x)
		return true
	}
	// match: (MULQconst [11] x)
	// result: (LEAQ2 x (LEAQ4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 11 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ2)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULQconst [13] x)
	// result: (LEAQ4 x (LEAQ2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 13 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ4)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULQconst [19] x)
	// result: (LEAQ2 x (LEAQ8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 19 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ2)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULQconst [21] x)
	// result: (LEAQ4 x (LEAQ4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 21 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ4)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULQconst [25] x)
	// result: (LEAQ8 x (LEAQ2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 25 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULQconst [27] x)
	// result: (LEAQ8 (LEAQ2 <v.Type> x x) (LEAQ2 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 27 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(v0, v0)
		return true
	}
	// match: (MULQconst [37] x)
	// result: (LEAQ4 x (LEAQ8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 37 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ4)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULQconst [41] x)
	// result: (LEAQ8 x (LEAQ4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 41 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULQconst [45] x)
	// result: (LEAQ8 (LEAQ4 <v.Type> x x) (LEAQ4 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 45 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(v0, v0)
		return true
	}
	// match: (MULQconst [73] x)
	// result: (LEAQ8 x (LEAQ8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 73 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULQconst [81] x)
	// result: (LEAQ8 (LEAQ8 <v.Type> x x) (LEAQ8 <v.Type> x x))
	for {
		if auxIntToInt32(v.AuxInt) != 81 {
			break
		}
		x := v_0
		v.reset(OpAMD64LEAQ8)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg2(v0, v0)
		return true
	}
	// match: (MULQconst [c] x)
	// cond: isPowerOfTwo(int64(c)+1) && c >= 15
	// result: (SUBQ (SHLQconst <v.Type> [int8(log64(int64(c)+1))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(int64(c)+1) && c >= 15) {
			break
		}
		v.reset(OpAMD64SUBQ)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLQconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log64(int64(c) + 1)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULQconst [c] x)
	// cond: isPowerOfTwo(c-1) && c >= 17
	// result: (LEAQ1 (SHLQconst <v.Type> [int8(log32(c-1))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c-1) && c >= 17) {
			break
		}
		v.reset(OpAMD64LEAQ1)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLQconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log32(c - 1)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULQconst [c] x)
	// cond: isPowerOfTwo(c-2) && c >= 34
	// result: (LEAQ2 (SHLQconst <v.Type> [int8(log32(c-2))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c-2) && c >= 34) {
			break
		}
		v.reset(OpAMD64LEAQ2)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLQconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log32(c - 2)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULQconst [c] x)
	// cond: isPowerOfTwo(c-4) && c >= 68
	// result: (LEAQ4 (SHLQconst <v.Type> [int8(log32(c-4))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c-4) && c >= 68) {
			break
		}
		v.reset(OpAMD64LEAQ4)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLQconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log32(c - 4)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULQconst [c] x)
	// cond: isPowerOfTwo(c-8) && c >= 136
	// result: (LEAQ8 (SHLQconst <v.Type> [int8(log32(c-8))] x) x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c-8) && c >= 136) {
			break
		}
		v.reset(OpAMD64LEAQ8)
		v0 := b.NewValue0(v.Pos, OpAMD64SHLQconst, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(log32(c - 8)))
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	// match: (MULQconst [c] x)
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (SHLQconst [int8(log32(c/3))] (LEAQ2 <v.Type> x x))
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c%3 == 0 && isPowerOfTwo(c/3)) {
			break
		}
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(log32(c / 3)))
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ2, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULQconst [c] x)
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (SHLQconst [int8(log32(c/5))] (LEAQ4 <v.Type> x x))
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c%5 == 0 && isPowerOfTwo(c/5)) {
			break
		}
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(log32(c / 5)))
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ4, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULQconst [c] x)
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (SHLQconst [int8(log32(c/9))] (LEAQ8 <v.Type> x x))
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c%9 == 0 && isPowerOfTwo(c/9)) {
			break
		}
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(log32(c / 9)))
		v0 := b.NewValue0(v.Pos, OpAMD64LEAQ8, v.Type)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
	// match: (MULQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [int64(c)*d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(c) * d)
		return true
	}
	// match: (MULQconst [c] (NEGQ x))
	// cond: c != -(1<<31)
	// result: (MULQconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64NEGQ {
			break
		}
		x := v_0.Args[0]
		if !(c != -(1 << 31)) {
			break
		}
		v.reset(OpAMD64MULQconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MULSD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULSD x l:(MOVSDload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (MULSDload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVSDload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64MULSDload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64MULSDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MULSDload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MULSDload [off1+off2] {sym} val base mem)
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
		v.reset(OpAMD64MULSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (MULSDload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MULSDload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
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
		v.reset(OpAMD64MULSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (MULSDload x [off] {sym} ptr (MOVQstore [off] {sym} ptr y _))
	// result: (MULSD x (MOVQi2f y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVQstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64MULSD)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQi2f, typ.Float64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MULSS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULSS x l:(MOVSSload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (MULSSload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVSSload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64MULSSload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64MULSSload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MULSSload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MULSSload [off1+off2] {sym} val base mem)
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
		v.reset(OpAMD64MULSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (MULSSload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MULSSload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
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
		v.reset(OpAMD64MULSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (MULSSload x [off] {sym} ptr (MOVLs
"""




```