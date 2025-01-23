Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
nt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueS390X_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x16 x y)
	// result: (SRAW (MOVBreg x) (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst (MOVHZreg y) [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v1.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x32 x y)
	// result: (SRAW (MOVBreg x) (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst y [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v1.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x64 x y)
	// result: (SRAW (MOVBreg x) (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPUconst y [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v1.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x8 x y)
	// result: (SRAW (MOVBreg x) (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst (MOVBZreg y) [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v1.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpS390XADD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADD x (MOVDconst <t> [c]))
	// cond: is32Bit(c) && !t.IsPtr()
	// result: (ADDconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			t := v_1.Type
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c) && !t.IsPtr()) {
				continue
			}
			v.reset(OpS390XADDconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADD idx (MOVDaddr [c] {s} ptr))
	// cond: ptr.Op != OpSB
	// result: (MOVDaddridx [c] {s} ptr idx)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			idx := v_0
			if v_1.Op != OpS390XMOVDaddr {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			s := auxToSym(v_1.Aux)
			ptr := v_1.Args[0]
			if !(ptr.Op != OpSB) {
				continue
			}
			v.reset(OpS390XMOVDaddridx)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(ptr, idx)
			return true
		}
		break
	}
	// match: (ADD x (NEG y))
	// result: (SUB x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XNEG {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpS390XSUB)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADD <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ADDload <t> [off] {sym} x ptr mem)
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
			v.reset(OpS390XADDload)
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
func rewriteValueS390X_OpS390XADDC(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDC x (MOVDconst [c]))
	// cond: is16Bit(c)
	// result: (ADDCconst x [int16(c)])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is16Bit(c)) {
				continue
			}
			v.reset(OpS390XADDCconst)
			v.AuxInt = int16ToAuxInt(int16(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XADDE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDE x y (FlagEQ))
	// result: (ADDC x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpS390XFlagEQ {
			break
		}
		v.reset(OpS390XADDC)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDE x y (FlagLT))
	// result: (ADDC x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpS390XFlagLT {
			break
		}
		v.reset(OpS390XADDC)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDE x y (Select1 (ADDCconst [-1] (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) c)))))
	// result: (ADDE x y c)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpS390XADDCconst || auxIntToInt16(v_2_0.AuxInt) != -1 {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpSelect0 {
			break
		}
		v_2_0_0_0 := v_2_0_0.Args[0]
		if v_2_0_0_0.Op != OpS390XADDE {
			break
		}
		c := v_2_0_0_0.Args[2]
		v_2_0_0_0_0 := v_2_0_0_0.Args[0]
		if v_2_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_2_0_0_0_0.AuxInt) != 0 {
			break
		}
		v_2_0_0_0_1 := v_2_0_0_0.Args[1]
		if v_2_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_2_0_0_0_1.AuxInt) != 0 {
			break
		}
		v.reset(OpS390XADDE)
		v.AddArg3(x, y, c)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XADDW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDW x (MOVDconst [c]))
	// result: (ADDWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XADDWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADDW x (NEGW y))
	// result: (SUBW x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XNEGW {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpS390XSUBW)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ADDWload <t> [off] {sym} x ptr mem)
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
			v.reset(OpS390XADDWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (ADDW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ADDWload <t> [off] {sym} x ptr mem)
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
			v.reset(OpS390XADDWload)
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
func rewriteValueS390X_OpS390XADDWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDWconst [c] x)
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
	// match: (ADDWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c)+d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c) + d)
		return true
	}
	// match: (ADDWconst [c] (ADDWconst [d] x))
	// result: (ADDWconst [int32(c+d)] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XADDWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpS390XADDWconst)
		v.AuxInt = int32ToAuxInt(int32(c + d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XADDWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (ADDWload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XADDWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (ADDWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (ADDWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XADDWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XADDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDconst [c] (MOVDaddr [d] {s} x:(SB)))
	// cond: ((c+d)&1 == 0) && is32Bit(int64(c)+int64(d))
	// result: (MOVDaddr [c+d] {s} x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		if x.Op != OpSB || !(((c+d)&1 == 0) && is32Bit(int64(c)+int64(d))) {
			break
		}
		v.reset(OpS390XMOVDaddr)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [c] (MOVDaddr [d] {s} x))
	// cond: x.Op != OpSB && is20Bit(int64(c)+int64(d))
	// result: (MOVDaddr [c+d] {s} x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		if !(x.Op != OpSB && is20Bit(int64(c)+int64(d))) {
			break
		}
		v.reset(OpS390XMOVDaddr)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [c] (MOVDaddridx [d] {s} x y))
	// cond: is20Bit(int64(c)+int64(d))
	// result: (MOVDaddridx [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDaddridx {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is20Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpS390XMOVDaddridx)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ADDconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c)+d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c) + d)
		return true
	}
	// match: (ADDconst [c] (ADDconst [d] x))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (ADDconst [c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpS390XADDconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XADDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (ADD x (LGDR <t> y))
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
		v.reset(OpS390XADD)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (ADDload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (ADDload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XADDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (ADDload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (ADDload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XADDload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XAND(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AND x (MOVDconst [c]))
	// cond: s390x.NewRotateParams(0, 63, 0).OutMerge(uint64(c)) != nil
	// result: (RISBGZ x {*s390x.NewRotateParams(0, 63, 0).OutMerge(uint64(c))})
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(s390x.NewRotateParams(0, 63, 0).OutMerge(uint64(c)) != nil) {
				continue
			}
			v.reset(OpS390XRISBGZ)
			v.Aux = s390xRotateParamsToAux(*s390x.NewRotateParams(0, 63, 0).OutMerge(uint64(c)))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND x (MOVDconst [c]))
	// cond: is32Bit(c) && c < 0
	// result: (ANDconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c) && c < 0) {
				continue
			}
			v.reset(OpS390XANDconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND x (MOVDconst [c]))
	// cond: is32Bit(c) && c >= 0
	// result: (MOVWZreg (ANDWconst <typ.UInt32> [int32(c)] x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c) && c >= 0) {
				continue
			}
			v.reset(OpS390XMOVWZreg)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c&d])
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
			v.AuxInt = int64ToAuxInt(c & d)
			return true
		}
		break
	}
	// match: (AND x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (AND <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ANDload <t> [off] {sym} x ptr mem)
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
			v.reset(OpS390XANDload)
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
func rewriteValueS390X_OpS390XANDW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDW x (MOVDconst [c]))
	// result: (ANDWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XANDWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ANDW x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ANDW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ANDWload <t> [off] {sym} x ptr mem)
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
			v.reset(OpS390XANDWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (ANDW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ANDWload <t> [off] {sym} x ptr mem)
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
			v.reset(OpS390XANDWload)
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
func rewriteValueS390X_OpS390XANDWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDWconst [c] (ANDWconst [d] x))
	// result: (ANDWconst [c&d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XANDWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpS390XANDWconst)
		v.AuxInt = int32ToAuxInt(c & d)
		v.AddArg(x)
		return true
	}
	// match: (ANDWconst [0x00ff] x)
	// result: (MOVBZreg x)
	for {
		if auxIntToInt32(v.AuxInt) != 0x00ff {
			break
		}
		x := v_0
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (ANDWconst [0xffff] x)
	// result: (MOVHZreg x)
	for {
		if auxIntToInt32(v.AuxInt) != 0xffff {
			break
		}
		x := v_0
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (ANDWconst [c] _)
	// cond: int32(c)==0
	// result: (MOVDconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if !(int32(c) == 0) {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (ANDWconst [c] x)
	// cond: int32(c)==-1
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(int32(c) == -1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ANDWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c)&d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c) & d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XANDWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (ANDWload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XANDWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (ANDWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (ANDWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XANDWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XANDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDconst [c] (ANDconst [d] x))
	// result: (ANDconst [c&d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpS390XANDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpS390XANDconst)
		v.AuxInt = int64ToAuxInt(c & d)
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [0] _)
	// result: (MOVDconst [0])
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (ANDconst [-1] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ANDconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c&d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c & d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XANDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ANDload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (AND x (LGDR <t> y))
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
		v.reset(OpS390XAND)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (ANDload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (ANDload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XANDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (ANDload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (ANDload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XANDload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XCMP(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMP x (MOVDconst [c]))
	// cond: is32Bit(c)
	// result: (CMPconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpS390XCMPconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (CMP (MOVDconst [c]) x)
	// cond: is32Bit(c)
	// result: (InvertFlags (CMPconst x [int32(c)]))
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMP y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XCMP, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XCMPU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPU x (MOVDconst [c]))
	// cond: isU32Bit(c)
	// result: (CMPUconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isU32Bit(c)) {
			break
		}
		v.reset(OpS390XCMPUconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPU (MOVDconst [c]) x)
	// cond: isU32Bit(c)
	// result: (InvertFlags (CMPUconst x [int32(c)]))
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(isU32Bit(c)) {
			break
		}
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPU x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPU y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XCMPU, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XCMPUconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPUconst (MOVDconst [x]) [y])
	// cond: uint64(x)==uint64(y)
	// result: (FlagEQ)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint64(x) == uint64(y)) {
			break
		}
		v.reset(OpS390XFlagEQ)
		return true
	}
	// match: (CMPUconst (MOVDconst [x]) [y])
	// cond: uint64(x)<uint64(y)
	// result: (FlagLT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint64(x) < uint64(y)) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPUconst (MOVDconst [x]) [y])
	// cond: uint64(x)>uint64(y)
	// result: (FlagGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint64(x) > uint64(y)) {
			break
		}
		v.reset(OpS390XFlagGT)
		return true
	}
	// match: (CMPUconst (SRDconst _ [c]) [n])
	// cond: c > 0 && c < 64 && (1<<uint(64-c)) <= uint64(n)
	// result: (FlagLT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XSRDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		if !(c > 0 && c < 64 && (1<<uint(64-c)) <= uint64(n)) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPUconst (RISBGZ x {r}) [c])
	// cond: r.OutMask() < uint64(uint32(c))
	// result: (FlagLT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		if !(r.OutMask() < uint64(uint32(c))) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPUconst (MOVWZreg x) [c])
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWZreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPUconst x:(MOVHreg _) [c])
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XMOVHreg {
			break
		}
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPUconst x:(MOVHZreg _) [c])
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XMOVHZreg {
			break
		}
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPUconst x:(MOVBreg _) [c])
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XMOVBreg {
			break
		}
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPUconst x:(MOVBZreg _) [c])
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XMOVBZreg {
			break
		}
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPUconst (MOVWZreg x:(ANDWconst [m] _)) [c])
	// cond: int32(m) >= 0
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWZreg {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(x.AuxInt)
		if !(int32(m) >= 0) {
			break
		}
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPUconst (MOVWreg x:(ANDWconst [m] _)) [c])
	// cond: int32(m) >= 0
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWreg {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(x.AuxInt)
		if !(int32(m) >= 0) {
			break
		}
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XCMPW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPW x (MOVDconst [c]))
	// result: (CMPWconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XCMPWconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPW (MOVDconst [c]) x)
	// result: (InvertFlags (CMPWconst x [int32(c)]))
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XCMPWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPW x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPW y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPW x (MOVWreg y))
	// result: (CMPW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XCMPW)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPW x (MOVWZreg y))
	// result: (CMPW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XCMPW)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPW (MOVWreg x) y)
	// result: (CMPW x y)
	for {
		if v_0.Op != OpS390XMOVWreg {
			break
		}
		x := v_0.Args[0]
		y := v_1
		v.reset(OpS390XCMPW)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPW (MOVWZreg x) y)
	// result: (CMPW x y)
	for {
		if v_0.Op != OpS390XMOVWZreg {
			break
		}
		x := v_0.Args[0]
		y := v_1
		v.reset(OpS390XCMPW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XCMPWU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPWU x (MOVDconst [c]))
	// result: (CMPWUconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPWU (MOVDconst [c]) x)
	// result: (InvertFlags (CMPWUconst x [int32(c)]))
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPWU x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPWU y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XCMPWU, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPWU x (MOVWreg y))
	// result: (CMPWU x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XCMPWU)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPWU x (MOVWZreg y))
	// result: (CMPWU x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XCMPWU)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPWU (MOVWreg x) y)
	// result: (CMPWU x y)
	for {
		if v_0.Op != OpS390XMOVWreg {
			break
		}
		x := v_0.Args[0]
		y := v_1
		v.reset(OpS390XCMPWU)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPWU (MOVWZreg x) y)
	// result: (CMPWU x y)
	for {
		if v_0.Op != OpS390XMOVWZreg {
			break
		}
		x := v_0.Args[0]
		y := v_1
		v.reset(OpS390XCMPWU)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XCMPWUconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPWUconst (MOVDconst [x]) [y])
	// cond: uint32(x)==uint32(y)
	// result: (FlagEQ)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint32(x) == uint32(y)) {
			break
		}
		v.reset(OpS390XFlagEQ)
		return true
	}
	// match: (CMPWUconst (MOVDconst [x]) [y])
	// cond: uint32(x)<uint32(y)
	// result: (FlagLT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint32(x) < uint32(y)) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPWUconst (MOVDconst [x]) [y])
	// cond: uint32(x)>uint32(y)
	// result: (FlagGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint32(x) > uint32(y)) {
			break
		}
		v.reset(OpS390XFlagGT)
		return true
	}
	// match: (CMPWUconst (MOVBZreg _) [c])
	// cond: 0xff < c
	// result: (FlagLT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVBZreg || !(0xff < c) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPWUconst (MOVHZreg _) [c])
	// cond: 0xffff < c
	// result: (FlagLT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVHZreg || !(0xffff < c) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPWUconst (SRWconst _ [c]) [n])
	// cond: c > 0 && c < 32 && (1<<uint(32-c)) <= uint32(n)
	// result: (FlagLT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XSRWconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		if !(c > 0 && c < 32 && (1<<uint(32-c)) <= uint32(n)) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPWUconst (ANDWconst _ [m]) [n])
	// cond: uint32(m) < uint32(n)
	// result: (FlagLT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(uint32(m) < uint32(n)) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPWUconst (MOVWreg x) [c])
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPWUconst (MOVWZreg x) [c])
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWZreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XCMPWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPWconst (MOVDconst [x]) [y])
	// cond: int32(x)==int32(y)
	// result: (FlagEQ)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(int32(x) == int32(y)) {
			break
		}
		v.reset(OpS390XFlagEQ)
		return true
	}
	// match: (CMPWconst (MOVDconst [x]) [y])
	// cond: int32(x)<int32(y)
	// result: (FlagLT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(int32(x) < int32(y)) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPWconst (MOVDconst [x]) [y])
	// cond: int32(x)>int32(y)
	// result: (FlagGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(int32(x) > int32(y)) {
			break
		}
		v.reset(OpS390XFlagGT)
		return true
	}
	// match: (CMPWconst (MOVBZreg _) [c])
	// cond: 0xff < c
	// result: (FlagLT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVBZreg || !(0xff < c) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPWconst (MOVHZreg _) [c])
	// cond: 0xffff < c
	// result: (FlagLT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVHZreg || !(0xffff < c) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPWconst (SRWconst _ [c]) [n])
	// cond: c > 0 && n < 0
	// result: (FlagGT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XSRWconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		if !(c > 0 && n < 0) {
			break
		}
		v.reset(OpS390XFlagGT)
		return true
	}
	// match: (CMPWconst (ANDWconst _ [m]) [n])
	// cond: int32(m) >= 0 && int32(m) < int32(n)
	// result: (FlagLT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(int32(m) >= 0 && int32(m) < int32(n)) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPWconst x:(SRWconst _ [c]) [n])
	// cond: c > 0 && n >= 0
	// result: (CMPWUconst x [n])
	for {
		n := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XSRWconst {
			break
		}
		c := auxIntToUint8(x.AuxInt)
		if !(c > 0 && n >= 0) {
			break
		}
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(x)
		return true
	}
	// match: (CMPWconst (MOVWreg x) [c])
	// result: (CMPWconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XCMPWconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPWconst (MOVWZreg x) [c])
	// result: (CMPWconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWZreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XCMPWconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XCMPconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPconst (MOVDconst [x]) [y])
	// cond: x==int64(y)
	// result: (FlagEQ)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x == int64(y)) {
			break
		}
		v.reset(OpS390XFlagEQ)
		return true
	}
	// match: (CMPconst (MOVDconst [x]) [y])
	// cond: x<int64(y)
	// result: (FlagLT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x < int64(y)) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPconst (MOVDconst [x]) [y])
	// cond: x>int64(y)
	// result: (FlagGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x > int64(y)) {
			break
		}
		v.reset(OpS390XFlagGT)
		return true
	}
	// match: (CMPconst (SRDconst _ [c]) [n])
	// cond: c > 0 && n < 0
	// result: (FlagGT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XSRDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		if !(c > 0 && n < 0) {
			break
		}
		v.reset(OpS390XFlagGT)
		return true
	}
	// match: (CMPconst (RISBGZ x {r}) [c])
	// cond: c > 0 && r.OutMask() < uint64(c)
	// result: (FlagLT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		if !(c > 0 && r.OutMask() < uint64(c)) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (CMPconst (MOVWreg x) [c])
	// result: (CMPWconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XCMPWconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPconst x:(MOVHreg _) [c])
	// result: (CMPWconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XMOVHreg {
			break
		}
		v.reset(OpS390XCMPWconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPconst x:(MOVHZreg _) [c])
	// result: (CMPWconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XMOVHZreg {
			break
		}
		v.reset(OpS390XCMPWconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPconst x:(MOVBreg _) [c])
	// result: (CMPWconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XMOVBreg {
			break
		}
		v.reset(OpS390XCMPWconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPconst x:(MOVBZreg _) [c])
	// result: (CMPWconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XMOVBZreg {
			break
		}
		v.reset(OpS390XCMPWconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPconst (MOVWZreg x:(ANDWconst [m] _)) [c])
	// cond: int32(m) >= 0 && c >= 0
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWZreg {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(x.AuxInt)
		if !(int32(m) >= 0 && c >= 0) {
			break
		}
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPconst (MOVWreg x:(ANDWconst [m] _)) [c])
	// cond: int32(m) >= 0 && c >= 0
	// result: (CMPWUconst x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVWreg {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(x.AuxInt)
		if !(int32(m) >= 0 && c >= 0) {
			break
		}
		v.reset(OpS390XCMPWUconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPconst x:(SRDconst _ [c]) [n])
	// cond: c > 0 && n >= 0
	// result: (CMPUconst x [n])
	for {
		n := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpS390XSRDconst {
			break
		}
		c := auxIntToUint8(x.AuxInt)
		if !(c > 0 && n >= 0) {
			break
		}
		v.reset(OpS390XCMPUconst)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XCPSDR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CPSDR y (FMOVDconst [c]))
	// cond: !math.Signbit(c)
	// result: (LPDFR y)
	for {
		y := v_0
		if v_1.Op != OpS390XFMOVDconst {
			break
		}
		c := auxIntToFloat64(v_1.AuxInt)
		if !(!math.Signbit(c)) {
			break
		}
		v.reset(OpS390XLPDFR)
		v.AddArg(y)
		return true
	}
	// match: (CPSDR y (FMOVDconst [c]))
	// cond: math.Signbit(c)
	// result: (LNDFR y)
	for {
		y := v_0
		if v_1.Op != OpS390XFMOVDconst {
			break
		}
		c := auxIntToFloat64(v_1.AuxInt)
		if !(math.Signbit(c)) {
			break
		}
		v.reset(OpS390XLNDFR)
		v.AddArg(y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XFCMP(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (FCMP x (FMOVDconst [0.0]))
	// result: (LTDBR x)
	for {
		x := v_0
		if v_1.Op != OpS390XFMOVDconst || auxIntToFloat64(v_1.AuxInt) != 0.0 {
			break
		}
		v.reset(OpS390XLTDBR)
		v.AddArg(x)
		return true
	}
	// match: (FCMP (FMOVDconst [0.0]) x)
	// result: (InvertFlags (LTDBR <v.Type> x))
	for {
		if v_0.Op != OpS390XFMOVDconst || auxIntToFloat64(v_0.AuxInt) != 0.0 {
			break
		}
		x := v_1
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XLTDBR, v.Type)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XFCMPS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (FCMPS x (FMOVSconst [0.0]))
	// result: (LTEBR x)
	for {
		x := v_0
		if v_1.Op != OpS390XFMOVSconst || auxIntToFloat32(v_1.AuxInt) != 0.0 {
			break
		}
		v.reset(OpS390XLTEBR)
		v.AddArg(x)
		return true
	}
	// match: (FCMPS (FMOVSconst [0.0]) x)
	// result: (InvertFlags (LTEBR <v.Type> x))
	for {
		if v_0.Op != OpS390XFMOVSconst || auxIntToFloat32(v_0.AuxInt) != 0.0 {
			break
		}
		x := v_1
		v.reset(OpS390XInvertFlags)
		v0 := b.NewValue0(v.Pos, OpS390XLTEBR, v.Type)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XFMOVDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVDload [off] {sym} ptr1 (MOVDstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (LDGR x)
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
		v.reset(OpS390XLDGR)
		v.AddArg(x)
		return true
	}
	// match: (FMOVDload [off] {sym} ptr1 (FMOVDstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: x
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
		v.copyOf(x)
		return true
	}
	// match: (FMOVDload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (FMOVDload [off1+off2] {sym} ptr mem)
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
		v.reset(OpS390XFMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVDload [off1] {sym1} (MOVDaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (FMOVDload [off1+off2] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpS390XFMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XFMOVDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVDstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (FMOVDstore [off1+off2] {sym} ptr val mem)
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
		v.reset(OpS390XFMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVDstore [off1] {sym1} (MOVDaddr [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (FMOVDstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpS390XFMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XFMOVSload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVSload [off] {sym} ptr1 (FMOVSstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: x
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XFMOVSstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
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
	// match: (FMOVSload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (FMOVSload [off1+off2] {sym} ptr mem)
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
		v.reset(OpS390XFMOVSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVSload [off1] {sym1} (MOVDaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (FMOVSload [off1+off2] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpS390XFMOVSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XFMOVSstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVSstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (FMOVSstore [off1+off2] {sym} ptr val mem)
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
		v.reset(OpS390XFMOVSstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVSstore [off1] {sym1} (MOVDaddr [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (FMOVSstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpS390XFMOVSstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XFNEG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FNEG (LPDFR x))
	// result: (LNDFR x)
	for {
		if v_0.Op != OpS390XLPDFR {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XLNDFR)
		v.AddArg(x)
		return true
	}
	// match: (FNEG (LNDFR x))
	// result: (LPDFR x)
	for {
		if v_0.Op != OpS390XLNDFR {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XLPDFR)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XFNEGS(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FNEGS (LPDFR x))
	// result: (LNDFR x)
	for {
		if v_0.Op != OpS390XLPDFR {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XLNDFR)
		v.AddArg(x)
		return true
	}
	// match: (FNEGS (LNDFR x))
	// result: (LPDFR x)
	for {
		if v_0.Op != OpS390XLNDFR {
			break
		}
		x := v_0.Args[0]
		v.reset(OpS390XLPDFR)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XLDGR(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (LDGR <t> (RISBGZ x {r}))
	// cond: r == s390x.NewRotateParams(1, 63, 0)
	// result: (LPDFR (LDGR <t> x))
	for {
		t := v.Type
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(r == s390x.NewRotateParams(1, 63, 0)) {
			break
		}
		v.reset(OpS390XLPDFR)
		v0 := b.NewValue0(v.Pos, OpS390XLDGR, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (LDGR <t> (OR (MOVDconst [-1<<63]) x))
	// result: (LNDFR (LDGR <t> x))
	for {
		t := v.Type
		if v_0.Op != OpS390XOR {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0.AuxInt) != -1<<63 {
				continue
			}
			x := v_0_1
			v.reset(OpS390XLNDFR)
			v0 := b.NewValue0(v.Pos, OpS390XLDGR, t)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (LDGR <t> x:(ORload <t1> [off] {sym} (MOVDconst [-1<<63]) ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (LNDFR <t> (LDGR <t> (MOVDload <t1> [off] {sym} ptr mem)))
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XORload {
			break
		}
		t1 := x.Type
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[2]
		x_0 := x.Args[0]
		if x_0.Op != OpS390XMOVDconst || auxIntToInt64(x_0.AuxInt) != -1<<63 {
			break
		}
		ptr := x.Args[1]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XLNDFR, t)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpS390XLDGR, t)
		v2 := b.NewValue0(x.Pos, OpS390XMOVDload, t1)
		v2.AuxInt = int32ToAuxInt(off)
		v2.Aux = symToAux(sym)
		v2.AddArg2(ptr, mem)
		v1.AddArg(v2)
		v0.AddArg(v1)
		return true
	}
	// match: (LDGR (LGDR x))
	// result: x
	for {
		if v_0.Op != OpS390XLGDR {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XLEDBR(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LEDBR (LPDFR (LDEBR x)))
	// result: (LPDFR x)
	for {
		if v_0.Op != OpS390XLPDFR {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XLDEBR {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpS390XLPDFR)
		v.AddArg(x)
		return true
	}
	// match: (LEDBR (LNDFR (LDEBR x)))
	// result: (LNDFR x)
	for {
		if v_0.Op != OpS390XLNDFR {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XLDEBR {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpS390XLNDFR)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XLGDR(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LGDR (LDGR x))
	// result: x
	for {
		if v_0.Op != OpS390XLDGR {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XLOCGR(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LOCGR {c} x y (InvertFlags cmp))
	// result: (LOCGR {c.ReverseComparison()} x y cmp)
	for {
		c := auxToS390xCCMask(v.Aux)
		x := v_0
		y := v_1
		if v_2.Op != OpS390XInvertFlags {
			break
		}
		cmp := v_2.Args[0]
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(c.ReverseComparison())
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (LOCGR {c} _ x (FlagEQ))
	// cond: c&s390x.Equal != 0
	// result: x
	for {
		c := auxToS390xCCMask(v.Aux)
		x := v_1
		if v_2.Op != OpS390XFlagEQ || !(c&s390x.Equal != 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (LOCGR {c} _ x (FlagLT))
	// cond: c&s390x.Less != 0
	// result: x
	for {
		c := auxToS390xCCMask(v.Aux)
		x := v_1
		if v_2.Op != OpS390XFlagLT || !(c&s390x.Less != 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (LOCGR {c} _ x (FlagGT))
	// cond: c&s390x.Greater != 0
	// result: x
	for {
		c := auxToS390xCCMask(v.Aux)
		x := v_1
		if v_2.Op != OpS390XFlagGT || !(c&s390x.Greater != 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (LOCGR {c} _ x (FlagOV))
	// cond: c&s390x.Unordered != 0
	// result: x
	for {
		c := auxToS390xCCMask(v.Aux)
		x := v_1
		if v_2.Op != OpS390XFlagOV || !(c&s390x.Unordered != 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (LOCGR {c} x _ (FlagEQ))
	// cond: c&s390x.Equal == 0
	// result: x
	for {
		c := auxToS390xCCMask(v.Aux)
		x := v_0
		if v_2.Op != OpS390XFlagEQ || !(c&s390x.Equal == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (LOCGR {c} x _ (FlagLT))
	// cond: c&s390x.Less == 0
	// result: x
	for {
		c := auxToS390xCCMask(v.Aux)
		x := v_0
		if v_2.Op != OpS390XFlagLT || !(c&s390x.Less == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (LOCGR {c} x _ (FlagGT))
	// cond: c&s390x.Greater == 0
	// result: x
	for {
		c := auxToS390xCCMask(v.Aux)
		x := v_0
		if v_2.Op != OpS390XFlagGT || !(c&s390x.Greater == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (LOCGR {c} x _ (FlagOV))
	// cond: c&s390x.Unordered == 0
	// result: x
	for {
		c := auxToS390xCCMask(v.Aux)
		x := v_0
		if v_2.Op != OpS390XFlagOV || !(c&s390x.Unordered == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XLTDBR(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (LTDBR (Select0 x:(FADD _ _)))
	// cond: b == x.Block
	// result: (Select1 x)
	for {
		if v_0.Op != OpSelect0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpS390XFADD || !(b == x.Block) {
			break
		}
		v.reset(OpSelect1)
		v.AddArg(x)
		return true
	}
	// match: (LTDBR (Select0 x:(FSUB _ _)))
	// cond: b == x.Block
	// result: (Select1 x)
	for {
		if v_0.Op != OpSelect0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpS390XFSUB || !(b == x.Block) {
			break
		}
		v.reset(OpSelect1)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XLTEBR(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (LTEBR (Select0 x:(FADDS _ _)))
	// cond: b == x.Block
	// result: (Select1 x)
	for {
		if v_0.Op != OpSelect0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpS390XFADDS || !(b == x.Block) {
			break
		}
		v.reset(OpSelect1)
		v.AddArg(x)
		return true
	}
	// match: (LTEBR (Select0 x:(FSUBS _ _)))
	// cond: b == x.Block
	// result: (Select1 x)
	for {
		if v_0.Op != OpSelect0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpS390XFSUBS || !(b == x.Block) {
			break
		}
		v.reset(OpSelect1)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XLoweredRound32F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LoweredRound32F x:(FMOVSconst))
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XFMOVSconst {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XLoweredRound64F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LoweredRound64F x:(FMOVDconst))
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XFMOVDconst {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVBZload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBZload [off] {sym} ptr1 (MOVBstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MOVBZreg x)
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
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVBZload [off1+off2] {sym} ptr mem)
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
		v.reset(OpS390XMOVBZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBZload [off1] {sym1} (MOVDaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBZload [off1+off2] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpS390XMOVBZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVBZreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVBZreg e:(MOVBreg x))
	// cond:
```