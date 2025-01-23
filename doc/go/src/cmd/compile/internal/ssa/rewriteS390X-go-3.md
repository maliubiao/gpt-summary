Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
clobberIfDead(e)
	// result: (MOVBZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg e:(MOVHreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg e:(MOVWreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg e:(MOVBZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg e:(MOVHZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg e:(MOVWZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg x:(MOVBZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 1)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBZload || !(!x.Type.IsSigned() || x.Type.Size() > 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBZreg <t> x:(MOVBload [o] {s} p mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBZload <t> [o] {s} p mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XMOVBload {
			break
		}
		o := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVBZload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(o)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (MOVBZreg x:(Arg <t>))
	// cond: !t.IsSigned() && t.Size() == 1
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(!t.IsSigned() && t.Size() == 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBZreg (MOVDconst [c]))
	// result: (MOVDconst [int64( uint8(c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		return true
	}
	// match: (MOVBZreg x:(LOCGR (MOVDconst [c]) (MOVDconst [d]) _))
	// cond: int64(uint8(c)) == c && int64(uint8(d)) == d && (!x.Type.IsSigned() || x.Type.Size() > 1)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XLOCGR {
			break
		}
		_ = x.Args[1]
		x_0 := x.Args[0]
		if x_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(x_0.AuxInt)
		x_1 := x.Args[1]
		if x_1.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(x_1.AuxInt)
		if !(int64(uint8(c)) == c && int64(uint8(d)) == d && (!x.Type.IsSigned() || x.Type.Size() > 1)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBZreg (RISBGZ x {r}))
	// cond: r.OutMerge(0x000000ff) != nil
	// result: (RISBGZ x {*r.OutMerge(0x000000ff)})
	for {
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(r.OutMerge(0x000000ff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.OutMerge(0x000000ff))
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg (ANDWconst [m] x))
	// result: (MOVWZreg (ANDWconst <typ.UInt32> [int32( uint8(m))] x))
	for {
		if v_0.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpS390XMOVWZreg)
		v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(int32(uint8(m)))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVBload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBload [off] {sym} ptr1 (MOVBstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MOVBreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XMOVBstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVBload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off1] {sym1} (MOVDaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpS390XMOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVBreg e:(MOVBreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg e:(MOVHreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg e:(MOVWreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg e:(MOVBZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg e:(MOVHZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg e:(MOVWZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg x:(MOVBload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBreg <t> x:(MOVBZload [o] {s} p mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBload <t> [o] {s} p mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XMOVBZload {
			break
		}
		o := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVBload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(o)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (MOVBreg x:(Arg <t>))
	// cond: t.IsSigned() && t.Size() == 1
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(t.IsSigned() && t.Size() == 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBreg (MOVDconst [c]))
	// result: (MOVDconst [int64( int8(c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int8(c)))
		return true
	}
	// match: (MOVBreg (ANDWconst [m] x))
	// cond: int8(m) >= 0
	// result: (MOVWZreg (ANDWconst <typ.UInt32> [int32( uint8(m))] x))
	for {
		if v_0.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(int8(m) >= 0) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(int32(uint8(m)))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstore [off] {sym} ptr (MOVBreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBZreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVBstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVDconst [c]) mem)
	// cond: is20Bit(int64(off)) && ptr.Op != OpSB
	// result: (MOVBstoreconst [makeValAndOff(int32(int8(c)),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is20Bit(int64(off)) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpS390XMOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int8(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym1} (MOVDaddr [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
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
		v.reset(OpS390XMOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVBstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstoreconst [sc] {s} (ADDconst [off] ptr) mem)
	// cond: is20Bit(sc.Off64()+int64(off))
	// result: (MOVBstoreconst [sc.addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is20Bit(sc.Off64() + int64(off))) {
			break
		}
		v.reset(OpS390XMOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstoreconst [sc] {sym1} (MOVDaddr [off] {sym2} ptr) mem)
	// cond: ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)
	// result: (MOVBstoreconst [sc.addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)) {
			break
		}
		v.reset(OpS390XMOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVDBR(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVDBR x:(MOVDload [off] {sym} ptr mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVDBRload [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpS390XMOVDload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVDBRload, typ.UInt64)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDBR x:(MOVDloadidx [off] {sym} ptr idx mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVDBRloadidx [off] {sym} ptr idx mem)
	for {
		x := v_0
		if x.Op != OpS390XMOVDloadidx {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpS390XMOVDBRloadidx, typ.Int64)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVDaddridx(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDaddridx [c] {s} (ADDconst [d] x) y)
	// cond: is20Bit(int64(c)+int64(d))
	// result: (MOVDaddridx [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		y := v_1
		if !(is20Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpS390XMOVDaddridx)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (MOVDaddridx [c] {s} x (ADDconst [d] y))
	// cond: is20Bit(int64(c)+int64(d))
	// result: (MOVDaddridx [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(is20Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpS390XMOVDaddridx)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (MOVDaddridx [off1] {sym1} (MOVDaddr [off2] {sym2} x) y)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB
	// result: (MOVDaddridx [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB) {
			break
		}
		v.reset(OpS390XMOVDaddridx)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, y)
		return true
	}
	// match: (MOVDaddridx [off1] {sym1} x (MOVDaddr [off2] {sym2} y))
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && y.Op != OpSB
	// result: (MOVDaddridx [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		y := v_1.Args[0]
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && y.Op != OpSB) {
			break
		}
		v.reset(OpS390XMOVDaddridx)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDload [off] {sym} ptr1 (MOVDstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: x
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XMOVDstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVDload [off] {sym} ptr1 (FMOVDstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (LGDR x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XFMOVDstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XLGDR)
		v.AddArg(x)
		return true
	}
	// match: (MOVDload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVDload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%8 == 0 && (off1+off2)%8 == 0))
	// result: (MOVDload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%8 == 0 && (off1+off2)%8 == 0))) {
			break
		}
		v.reset(OpS390XMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVDstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} ptr (MOVDconst [c]) mem)
	// cond: is16Bit(c) && isU12Bit(int64(off)) && ptr.Op != OpSB
	// result: (MOVDstoreconst [makeValAndOff(int32(c),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is16Bit(c) && isU12Bit(int64(off)) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpS390XMOVDstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%8 == 0 && (off1+off2)%8 == 0))
	// result: (MOVDstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%8 == 0 && (off1+off2)%8 == 0))) {
			break
		}
		v.reset(OpS390XMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVDstore [i] {s} p w1 x:(MOVDstore [i-8] {s} p w0 mem))
	// cond: p.Op != OpSB && x.Uses == 1 && is20Bit(int64(i)-8) && setPos(v, x.Pos) && clobber(x)
	// result: (STMG2 [i-8] {s} p w0 w1 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w1 := v_1
		x := v_2
		if x.Op != OpS390XMOVDstore || auxIntToInt32(x.AuxInt) != i-8 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[2]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		if !(p.Op != OpSB && x.Uses == 1 && is20Bit(int64(i)-8) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTMG2)
		v.AuxInt = int32ToAuxInt(i - 8)
		v.Aux = symToAux(s)
		v.AddArg4(p, w0, w1, mem)
		return true
	}
	// match: (MOVDstore [i] {s} p w2 x:(STMG2 [i-16] {s} p w0 w1 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-16) && setPos(v, x.Pos) && clobber(x)
	// result: (STMG3 [i-16] {s} p w0 w1 w2 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w2 := v_1
		x := v_2
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
		v.reset(OpS390XSTMG3)
		v.AuxInt = int32ToAuxInt(i - 16)
		v.Aux = symToAux(s)
		v.AddArg5(p, w0, w1, w2, mem)
		return true
	}
	// match: (MOVDstore [i] {s} p w3 x:(STMG3 [i-24] {s} p w0 w1 w2 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-24) && setPos(v, x.Pos) && clobber(x)
	// result: (STMG4 [i-24] {s} p w0 w1 w2 w3 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w3 := v_1
		x := v_2
		if x.Op != OpS390XSTMG3 || auxIntToInt32(x.AuxInt) != i-24 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[4]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		w1 := x.Args[2]
		w2 := x.Args[3]
		if !(x.Uses == 1 && is20Bit(int64(i)-24) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTMG4)
		v.AuxInt = int32ToAuxInt(i - 24)
		v.Aux = symToAux(s)
		v.AddArg6(p, w0, w1, w2, w3, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} ptr r:(MOVDBR x) mem)
	// cond: r.Uses == 1
	// result: (MOVDBRstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		r := v_1
		if r.Op != OpS390XMOVDBR {
			break
		}
		x := r.Args[0]
		mem := v_2
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpS390XMOVDBRstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVDstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstoreconst [sc] {s} (ADDconst [off] ptr) mem)
	// cond: isU12Bit(sc.Off64()+int64(off))
	// result: (MOVDstoreconst [sc.addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU12Bit(sc.Off64() + int64(off))) {
			break
		}
		v.reset(OpS390XMOVDstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDstoreconst [sc] {sym1} (MOVDaddr [off] {sym2} ptr) mem)
	// cond: ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)
	// result: (MOVDstoreconst [sc.addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)) {
			break
		}
		v.reset(OpS390XMOVDstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVDstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstoreidx [off] {sym} ptr idx r:(MOVDBR x) mem)
	// cond: r.Uses == 1
	// result: (MOVDBRstoreidx [off] {sym} ptr idx x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		r := v_2
		if r.Op != OpS390XMOVDBR {
			break
		}
		x := r.Args[0]
		mem := v_3
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpS390XMOVDBRstoreidx)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHZload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHZload [off] {sym} ptr1 (MOVHstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MOVHZreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XMOVHstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVHZload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVHZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHZload [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))
	// result: (MOVHZload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))) {
			break
		}
		v.reset(OpS390XMOVHZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHZreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVHZreg e:(MOVBZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg e:(MOVHreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg e:(MOVWreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg e:(MOVHZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg e:(MOVWZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg x:(MOVBZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 1)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBZload || !(!x.Type.IsSigned() || x.Type.Size() > 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg x:(MOVHZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 2)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVHZload || !(!x.Type.IsSigned() || x.Type.Size() > 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg <t> x:(MOVHload [o] {s} p mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVHZload <t> [o] {s} p mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XMOVHload {
			break
		}
		o := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVHZload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(o)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (MOVHZreg x:(Arg <t>))
	// cond: !t.IsSigned() && t.Size() <= 2
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(!t.IsSigned() && t.Size() <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint16(c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		return true
	}
	// match: (MOVHZreg (RISBGZ x {r}))
	// cond: r.OutMerge(0x0000ffff) != nil
	// result: (RISBGZ x {*r.OutMerge(0x0000ffff)})
	for {
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(r.OutMerge(0x0000ffff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.OutMerge(0x0000ffff))
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg (ANDWconst [m] x))
	// result: (MOVWZreg (ANDWconst <typ.UInt32> [int32(uint16(m))] x))
	for {
		if v_0.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpS390XMOVWZreg)
		v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(int32(uint16(m)))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHload [off] {sym} ptr1 (MOVHstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MOVHreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XMOVHstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVHload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))
	// result: (MOVHload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))) {
			break
		}
		v.reset(OpS390XMOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVHreg e:(MOVBreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg e:(MOVHreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg e:(MOVWreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg e:(MOVHZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg e:(MOVWZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg x:(MOVHload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVHload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg x:(MOVBZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 1)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBZload || !(!x.Type.IsSigned() || x.Type.Size() > 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg <t> x:(MOVHZload [o] {s} p mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVHload <t> [o] {s} p mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XMOVHZload {
			break
		}
		o := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVHload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(o)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (MOVHreg x:(Arg <t>))
	// cond: t.IsSigned() && t.Size() <= 2
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(t.IsSigned() && t.Size() <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int16(c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int16(c)))
		return true
	}
	// match: (MOVHreg (ANDWconst [m] x))
	// cond: int16(m) >= 0
	// result: (MOVWZreg (ANDWconst <typ.UInt32> [int32(uint16(m))] x))
	for {
		if v_0.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(int16(m) >= 0) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(int32(uint16(m)))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVHZreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVHstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVDconst [c]) mem)
	// cond: isU12Bit(int64(off)) && ptr.Op != OpSB
	// result: (MOVHstoreconst [makeValAndOff(int32(int16(c)),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(isU12Bit(int64(off)) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int16(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))
	// result: (MOVHstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))) {
			break
		}
		v.reset(OpS390XMOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (Bswap16 val) mem)
	// result: (MOVHBRstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpBswap16 {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVHBRstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreconst [sc] {s} (ADDconst [off] ptr) mem)
	// cond: isU12Bit(sc.Off64()+int64(off))
	// result: (MOVHstoreconst [sc.addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU12Bit(sc.Off64() + int64(off))) {
			break
		}
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstoreconst [sc] {sym1} (MOVDaddr [off] {sym2} ptr) mem)
	// cond: ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)
	// result: (MOVHstoreconst [sc.addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)) {
			break
		}
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreidx [off] {sym} ptr idx (Bswap16 val) mem)
	// result: (MOVHBRstoreidx [off] {sym} ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		if v_2.Op != OpBswap16 {
			break
		}
		val := v_2.Args[0]
		mem := v_3
		v.reset(OpS390XMOVHBRstoreidx)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWBR(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVWBR x:(MOVWZload [off] {sym} ptr mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVWZreg (MOVWBRload [off] {sym} ptr mem))
	for {
		x := v_0
		if x.Op != OpS390XMOVWZload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVWZreg, typ.UInt64)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpS390XMOVWBRload, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg2(ptr, mem)
		v0.AddArg(v1)
		return true
	}
	// match: (MOVWBR x:(MOVWZloadidx [off] {sym} ptr idx mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVWZreg (MOVWBRloadidx [off] {sym} ptr idx mem))
	for {
		x := v_0
		if x.Op != OpS390XMOVWZloadidx {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpS390XMOVWZreg, typ.UInt64)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVWBRloadidx, typ.Int32)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg3(ptr, idx, mem)
		v0.AddArg(v1)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWZload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWZload [off] {sym} ptr1 (MOVWstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MOVWZreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XMOVWstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVWZload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVWZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWZload [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))
	// result: (MOVWZload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))) {
			break
		}
		v.reset(OpS390XMOVWZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWZreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVWZreg e:(MOVBZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg e:(MOVHZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg e:(MOVWreg x))
	// cond: clobberIfDead(e)
	// result: (MOVWZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg e:(MOVWZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVWZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg x:(MOVBZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 1)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBZload || !(!x.Type.IsSigned() || x.Type.Size() > 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVHZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 2)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVHZload || !(!x.Type.IsSigned() || x.Type.Size() > 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVWZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 4)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVWZload || !(!x.Type.IsSigned() || x.Type.Size() > 4) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg <t> x:(MOVWload [o] {s} p mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWZload <t> [o] {s} p mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XMOVWload {
			break
		}
		o := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVWZload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(o)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (MOVWZreg x:(Arg <t>))
	// cond: !t.IsSigned() && t.Size() <= 4
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(!t.IsSigned() && t.Size() <= 4) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint32(c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	// match: (MOVWZreg (RISBGZ x {r}))
	// cond: r.OutMerge(0xffffffff) != nil
	// result: (RISBGZ x {*r.OutMerge(0xffffffff)})
	for {
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(r.OutMerge(0xffffffff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.OutMerge(0xffffffff))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWload [off] {sym} ptr1 (MOVWstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MOVWreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XMOVWstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVWload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))
	// result: (MOVWload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))) {
			break
		}
		v.reset(OpS390XMOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVWreg e:(MOVBreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg e:(MOVHreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg e:(MOVWreg x))
	// cond: clobberIfDead(e)
	// result: (MOVWreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg e:(MOVWZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVWreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVHload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVHload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVWload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVWload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVBZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 1)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBZload || !(!x.Type.IsSigned() || x.Type.Size() > 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVHZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 2)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVHZload || !(!x.Type.IsSigned() || x.Type.Size() > 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg <t> x:(MOVWZload [o] {s} p mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWload <t> [o] {s} p mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XMOVWZload {
			break
		}
		o := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVWload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(o)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (MOVWreg x:(Arg <t>))
	// cond: t.IsSigned() && t.Size() <= 4
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(t.IsSigned() && t.Size() <= 4) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int32(c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(c)))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWZreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVWstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVDconst [c]) mem)
	// cond: is16Bit(c) && isU12Bit(int64(off)) && ptr.Op != OpSB
	// result: (MOVWstoreconst [makeValAndOff(int32(c),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is16Bit(c) && isU12Bit(int64(off)) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))
	// result: (MOVWstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))) {
			break
		}
		v.reset(OpS390XMOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVWstore [i] {s} p w1 x:(MOVWstore [i-4] {s} p w0 mem))
	// cond: p.Op != OpSB && x.Uses == 1 && is20Bit(int64(i)-4) && setPos(v, x.Pos) && clobber(x)
	// result: (STM2 [i-4] {s} p w0 w1 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w1 := v_1
		x := v_2
		if x.Op != OpS390XMOVWstore || auxIntToInt32(x.AuxInt) != i-4 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[2]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		if !(p.Op != OpSB && x.Uses == 1 && is20Bit(int64(i)-4) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTM2)
		v.AuxInt = int32ToAuxInt(i - 4)
		v.Aux = symToAux(s)
		v.AddArg4(p, w0, w1, mem)
		return true
	}
	// match: (MOVWstore [i] {s} p w2 x:(STM2 [i-8] {s} p w0 w1 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-8) && setPos(v, x.Pos) && clobber(x)
	// result: (STM3 [i-8] {s} p w0 w1 w2 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w2 := v_1
		x := v_2
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
		v.reset(OpS390XSTM3)
		v.AuxInt = int32ToAuxInt(i - 8)
		v.Aux = symToAux(s)
		v.AddArg5(p, w0, w1, w2, mem)
		return true
	}
	// match: (MOVWstore [i] {s} p w3 x:(STM3 [i-12] {s} p w0 w1 w2 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-12) && setPos(v, x.Pos) && clobber(x)
	// result: (STM4 [i-12] {s} p w0 w1 w2 w3 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w3 := v_1
		x := v_2
		if x.Op != OpS390XSTM3 || auxIntToInt32(x.AuxInt) != i-12 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[4]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		w1 := x.Args[2]
		w2 := x.Args[3]
		if !(x.Uses == 1 && is20Bit(int64(i)-12) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTM4)
		v.AuxInt = int32ToAuxInt(i - 12)
		v.Aux = symToAux(s)
		v.AddArg6(p, w0, w1, w2, w3, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr r:(MOVWBR x) mem)
	// cond: r.Uses == 1
	// result: (MOVWBRstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		r := v_1
		if r.Op != OpS390XMOVWBR {
			break
		}
		x := r.Args[0]
		mem := v_2
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpS390XMOVWBRstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreconst [sc] {s} (ADDconst [off] ptr) mem)
	// cond: isU12Bit(sc.Off64()+int64(off))
	// result: (MOVWstoreconst [sc.addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU12Bit(sc.Off64() + int64(off))) {
			break
		}
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstoreconst [sc] {sym1} (MOVDaddr [off] {sym2} ptr) mem)
	// cond: ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)
	// result: (MOVWstoreconst [sc.addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)) {
			break
		}
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreidx [off] {sym} ptr idx r:(MOVWBR x) mem)
	// cond: r.Uses == 1
	// result: (MOVWBRstoreidx [off] {sym} ptr idx x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		r := v_2
		if r.Op != OpS390XMOVWBR {
			break
		}
		x := r.Args[0]
		mem := v_3
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpS390XMOVWBRstoreidx)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMULLD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLD x (MOVDconst [c]))
	// cond: is32Bit(c)
	// result: (MULLDconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpS390XMULLDconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MULLD <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (MULLDload <t> [off] {sym} x ptr mem)
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
			v.reset(OpS390XMULLDload)
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
func rewriteValueS390X_OpS390XMULLDconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULLDconst <t> x [c])
	// cond: isPowerOfTwo(c&(c-1))
	// result: (ADD (SLDconst <t> x [uint8(log32(c&(c-1)))]) (SLDconst <t> x [uint8(log32(c&^(c-1)))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c & (c - 1))) {
			break
		}
		v.reset(OpS390XADD)
		v0 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(c & (c - 1))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(c &^ (c - 1))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLDconst <t> x [c])
	// cond: isPowerOfTwo(c+(c&^(c-1)))
	// result: (SUB (SLDconst <t> x [uint8(log32(c+(c&^(c-1))))]) (SLDconst <t> x [uint8(log32(c&^(c-1)))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c + (c &^ (c - 1)))) {
			break
		}
		v.reset(OpS390XSUB)
		v0 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(c + (c &^ (c - 1)))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(c &^ (c - 1))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLDconst <t> x [c])
	// cond: isPowerOfTwo(-c+(-c&^(-c-1)))
	// result: (SUB (SLDconst <t> x [uint8(log32(-c&^(-c-1)))]) (SLDconst <t> x [uint8(log32(-c+(-c&^(-c-1))))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(-c + (-c &^ (-c - 1)))) {
			break
		}
		v.reset(OpS390XSUB)
		v0 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(-c &^ (-c - 1))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(-c + (-c &^ (-c - 1)))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLDconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c)*d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c) * d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMULLDload(v *Value) bool {
	v_2
```