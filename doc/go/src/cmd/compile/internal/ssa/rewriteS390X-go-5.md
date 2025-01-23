Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
xInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c) ^ d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XXORWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (XORWload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XXORWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (XORWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (XORWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XXORWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XXORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (XORconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c^d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XXORload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (XOR x (LGDR <t> y))
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
		v.reset(OpS390XXOR)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (XORload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (XORload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XXORload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (XORload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (XORload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XXORload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADDE x y (Select1 <types.TypeFlags> (ADDCconst c [-1]))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpS390XADDE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpS390XADDCconst, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2.AuxInt = int16ToAuxInt(-1)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Sub64borrow x y c))
	// result: (Select0 <typ.UInt64> (SUBE x y (Select1 <types.TypeFlags> (SUBC (MOVDconst [0]) c))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpS390XSUBE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpS390XSUBC, types.NewTuple(typ.UInt64, types.TypeFlags))
		v3 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v2.AddArg2(v3, c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 <t> (AddTupleFirst32 val tuple))
	// result: (ADDW val (Select0 <t> tuple))
	for {
		t := v.Type
		if v_0.Op != OpS390XAddTupleFirst32 {
			break
		}
		tuple := v_0.Args[1]
		val := v_0.Args[0]
		v.reset(OpS390XADDW)
		v0 := b.NewValue0(v.Pos, OpSelect0, t)
		v0.AddArg(tuple)
		v.AddArg2(val, v0)
		return true
	}
	// match: (Select0 <t> (AddTupleFirst64 val tuple))
	// result: (ADD val (Select0 <t> tuple))
	for {
		t := v.Type
		if v_0.Op != OpS390XAddTupleFirst64 {
			break
		}
		tuple := v_0.Args[1]
		val := v_0.Args[0]
		v.reset(OpS390XADD)
		v0 := b.NewValue0(v.Pos, OpSelect0, t)
		v0.AddArg(tuple)
		v.AddArg2(val, v0)
		return true
	}
	// match: (Select0 (ADDCconst (MOVDconst [c]) [d]))
	// result: (MOVDconst [c+int64(d)])
	for {
		if v_0.Op != OpS390XADDCconst {
			break
		}
		d := auxIntToInt16(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c + int64(d))
		return true
	}
	// match: (Select0 (SUBC (MOVDconst [c]) (MOVDconst [d])))
	// result: (MOVDconst [c-d])
	for {
		if v_0.Op != OpS390XSUBC {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0_1.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c - d)
		return true
	}
	// match: (Select0 (FADD (FMUL y z) x))
	// cond: x.Block.Func.useFMA(v)
	// result: (FMADD x y z)
	for {
		if v_0.Op != OpS390XFADD {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpS390XFMUL {
				continue
			}
			z := v_0_0.Args[1]
			y := v_0_0.Args[0]
			x := v_0_1
			if !(x.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpS390XFMADD)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (Select0 (FSUB (FMUL y z) x))
	// cond: x.Block.Func.useFMA(v)
	// result: (FMSUB x y z)
	for {
		if v_0.Op != OpS390XFSUB {
			break
		}
		x := v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XFMUL {
			break
		}
		z := v_0_0.Args[1]
		y := v_0_0.Args[0]
		if !(x.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpS390XFMSUB)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (Select0 (FADDS (FMULS y z) x))
	// cond: x.Block.Func.useFMA(v)
	// result: (FMADDS x y z)
	for {
		if v_0.Op != OpS390XFADDS {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpS390XFMULS {
				continue
			}
			z := v_0_0.Args[1]
			y := v_0_0.Args[0]
			x := v_0_1
			if !(x.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpS390XFMADDS)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (Select0 (FSUBS (FMULS y z) x))
	// cond: x.Block.Func.useFMA(v)
	// result: (FMSUBS x y z)
	for {
		if v_0.Op != OpS390XFSUBS {
			break
		}
		x := v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XFMULS {
			break
		}
		z := v_0_0.Args[1]
		y := v_0_0.Args[0]
		if !(x.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpS390XFMSUBS)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueS390X_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADDE (MOVDconst [0]) (MOVDconst [0]) (Select1 <types.TypeFlags> (ADDE x y (Select1 <types.TypeFlags> (ADDCconst c [-1]))))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpS390XADDE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XADDE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v4 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v5 := b.NewValue0(v.Pos, OpS390XADDCconst, types.NewTuple(typ.UInt64, types.TypeFlags))
		v5.AuxInt = int16ToAuxInt(-1)
		v5.AddArg(c)
		v4.AddArg(v5)
		v3.AddArg3(x, y, v4)
		v2.AddArg(v3)
		v0.AddArg3(v1, v1, v2)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Sub64borrow x y c))
	// result: (NEG (Select0 <typ.UInt64> (SUBE (MOVDconst [0]) (MOVDconst [0]) (Select1 <types.TypeFlags> (SUBE x y (Select1 <types.TypeFlags> (SUBC (MOVDconst [0]) c)))))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpS390XNEG)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpS390XSUBE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v4 := b.NewValue0(v.Pos, OpS390XSUBE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v5 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v6 := b.NewValue0(v.Pos, OpS390XSUBC, types.NewTuple(typ.UInt64, types.TypeFlags))
		v6.AddArg2(v2, c)
		v5.AddArg(v6)
		v4.AddArg3(x, y, v5)
		v3.AddArg(v4)
		v1.AddArg3(v2, v2, v3)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (AddTupleFirst32 _ tuple))
	// result: (Select1 tuple)
	for {
		if v_0.Op != OpS390XAddTupleFirst32 {
			break
		}
		tuple := v_0.Args[1]
		v.reset(OpSelect1)
		v.AddArg(tuple)
		return true
	}
	// match: (Select1 (AddTupleFirst64 _ tuple))
	// result: (Select1 tuple)
	for {
		if v_0.Op != OpS390XAddTupleFirst64 {
			break
		}
		tuple := v_0.Args[1]
		v.reset(OpSelect1)
		v.AddArg(tuple)
		return true
	}
	// match: (Select1 (ADDCconst (MOVDconst [c]) [d]))
	// cond: uint64(c+int64(d)) >= uint64(c) && c+int64(d) == 0
	// result: (FlagEQ)
	for {
		if v_0.Op != OpS390XADDCconst {
			break
		}
		d := auxIntToInt16(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		if !(uint64(c+int64(d)) >= uint64(c) && c+int64(d) == 0) {
			break
		}
		v.reset(OpS390XFlagEQ)
		return true
	}
	// match: (Select1 (ADDCconst (MOVDconst [c]) [d]))
	// cond: uint64(c+int64(d)) >= uint64(c) && c+int64(d) != 0
	// result: (FlagLT)
	for {
		if v_0.Op != OpS390XADDCconst {
			break
		}
		d := auxIntToInt16(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		if !(uint64(c+int64(d)) >= uint64(c) && c+int64(d) != 0) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (Select1 (SUBC (MOVDconst [c]) (MOVDconst [d])))
	// cond: uint64(d) <= uint64(c) && c-d == 0
	// result: (FlagGT)
	for {
		if v_0.Op != OpS390XSUBC {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0_1.AuxInt)
		if !(uint64(d) <= uint64(c) && c-d == 0) {
			break
		}
		v.reset(OpS390XFlagGT)
		return true
	}
	// match: (Select1 (SUBC (MOVDconst [c]) (MOVDconst [d])))
	// cond: uint64(d) <= uint64(c) && c-d != 0
	// result: (FlagOV)
	for {
		if v_0.Op != OpS390XSUBC {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0_1.AuxInt)
		if !(uint64(d) <= uint64(c) && c-d != 0) {
			break
		}
		v.reset(OpS390XFlagOV)
		return true
	}
	return false
}
func rewriteValueS390X_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRADconst (NEG <t> x) [63])
	for {
		t := v.Type
		x := v_0
		v.reset(OpS390XSRADconst)
		v.AuxInt = uint8ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpS390XNEG, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && t.IsFloat()
	// result: (FMOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && t.IsFloat()) {
			break
		}
		v.reset(OpS390XFMOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && t.IsFloat()
	// result: (FMOVSstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && t.IsFloat()) {
			break
		}
		v.reset(OpS390XFMOVSstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && !t.IsFloat()
	// result: (MOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && !t.IsFloat()) {
			break
		}
		v.reset(OpS390XMOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && !t.IsFloat()
	// result: (MOVWstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && !t.IsFloat()) {
			break
		}
		v.reset(OpS390XMOVWstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 2
	// result: (MOVHstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 2) {
			break
		}
		v.reset(OpS390XMOVHstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 1
	// result: (MOVBstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 1) {
			break
		}
		v.reset(OpS390XMOVBstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpSub32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Sub32F x y)
	// result: (Select0 (FSUBS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpS390XFSUBS, types.NewTuple(typ.Float32, types.TypeFlags))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpSub64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Sub64F x y)
	// result: (Select0 (FSUB x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpS390XFSUB, types.NewTuple(typ.Float64, types.TypeFlags))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpTrunc(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc x)
	// result: (FIDBR [5] x)
	for {
		x := v_0
		v.reset(OpS390XFIDBR)
		v.AuxInt = int8ToAuxInt(5)
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpZero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Zero [0] _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_1
		v.copyOf(mem)
		return true
	}
	// match: (Zero [1] destptr mem)
	// result: (MOVBstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [2] destptr mem)
	// result: (MOVHstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [4] destptr mem)
	// result: (MOVWstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [8] destptr mem)
	// result: (MOVDstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVDstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [3] destptr mem)
	// result: (MOVBstoreconst [makeValAndOff(0,2)] destptr (MOVHstoreconst [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 2))
		v0 := b.NewValue0(v.Pos, OpS390XMOVHstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [5] destptr mem)
	// result: (MOVBstoreconst [makeValAndOff(0,4)] destptr (MOVWstoreconst [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v0 := b.NewValue0(v.Pos, OpS390XMOVWstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [6] destptr mem)
	// result: (MOVHstoreconst [makeValAndOff(0,4)] destptr (MOVWstoreconst [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v0 := b.NewValue0(v.Pos, OpS390XMOVWstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [7] destptr mem)
	// result: (MOVWstoreconst [makeValAndOff(0,3)] destptr (MOVWstoreconst [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 3))
		v0 := b.NewValue0(v.Pos, OpS390XMOVWstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s > 0 && s <= 1024
	// result: (CLEAR [makeValAndOff(int32(s), 0)] destptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s > 0 && s <= 1024) {
			break
		}
		v.reset(OpS390XCLEAR)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(s), 0))
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s > 1024
	// result: (LoweredZero [s%256] destptr (ADDconst <destptr.Type> destptr [(int32(s)/256)*256]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s > 1024) {
			break
		}
		v.reset(OpS390XLoweredZero)
		v.AuxInt = int64ToAuxInt(s % 256)
		v0 := b.NewValue0(v.Pos, OpS390XADDconst, destptr.Type)
		v0.AuxInt = int32ToAuxInt((int32(s) / 256) * 256)
		v0.AddArg(destptr)
		v.AddArg3(destptr, v0, mem)
		return true
	}
	return false
}
func rewriteBlockS390X(b *Block) bool {
	typ := &b.Func.Config.Types
	switch b.Kind {
	case BlockS390XBRC:
		// match: (BRC {c} x:(CMP _ _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMP {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPW _ _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPW {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPU _ _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPU {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPWU _ _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPWU {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPconst _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPWconst _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPUconst _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPWUconst _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMP x y) yes no)
		// result: (CGRJ {c&^s390x.Unordered} x y yes no)
		for b.Controls[0].Op == OpS390XCMP {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl2(BlockS390XCGRJ, x, y)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPW x y) yes no)
		// result: (CRJ {c&^s390x.Unordered} x y yes no)
		for b.Controls[0].Op == OpS390XCMPW {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl2(BlockS390XCRJ, x, y)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPU x y) yes no)
		// result: (CLGRJ {c&^s390x.Unordered} x y yes no)
		for b.Controls[0].Op == OpS390XCMPU {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl2(BlockS390XCLGRJ, x, y)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPWU x y) yes no)
		// result: (CLRJ {c&^s390x.Unordered} x y yes no)
		for b.Controls[0].Op == OpS390XCMPWU {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl2(BlockS390XCLRJ, x, y)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPconst x [y]) yes no)
		// cond: y == int32( int8(y))
		// result: (CGIJ {c&^s390x.Unordered} x [ int8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(int8(y))) {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPWconst x [y]) yes no)
		// cond: y == int32( int8(y))
		// result: (CIJ {c&^s390x.Unordered} x [ int8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(int8(y))) {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPUconst x [y]) yes no)
		// cond: y == int32(uint8(y))
		// result: (CLGIJ {c&^s390x.Unordered} x [uint8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(uint8(y))) {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPWUconst x [y]) yes no)
		// cond: y == int32(uint8(y))
		// result: (CLIJ {c&^s390x.Unordered} x [uint8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(uint8(y))) {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {s390x.Less} (CMPconst x [ 128]) yes no)
		// result: (CGIJ {s390x.LessOrEqual} x [ 127] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 128 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(127)
			b.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
			return true
		}
		// match: (BRC {s390x.Less} (CMPWconst x [ 128]) yes no)
		// result: (CIJ {s390x.LessOrEqual} x [ 127] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 128 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(127)
			b.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
			return true
		}
		// match: (BRC {s390x.LessOrEqual} (CMPconst x [-129]) yes no)
		// result: (CGIJ {s390x.Less} x [-128] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != -129 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.LessOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(-128)
			b.Aux = s390xCCMaskToAux(s390x.Less)
			return true
		}
		// match: (BRC {s390x.LessOrEqual} (CMPWconst x [-129]) yes no)
		// result: (CIJ {s390x.Less} x [-128] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != -129 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.LessOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(-128)
			b.Aux = s390xCCMaskToAux(s390x.Less)
			return true
		}
		// match: (BRC {s390x.Greater} (CMPconst x [-129]) yes no)
		// result: (CGIJ {s390x.GreaterOrEqual} x [-128] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != -129 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(-128)
			b.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
			return true
		}
		// match: (BRC {s390x.Greater} (CMPWconst x [-129]) yes no)
		// result: (CIJ {s390x.GreaterOrEqual} x [-128] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != -129 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(-128)
			b.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
			return true
		}
		// match: (BRC {s390x.GreaterOrEqual} (CMPconst x [ 128]) yes no)
		// result: (CGIJ {s390x.Greater} x [ 127] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 128 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(127)
			b.Aux = s390xCCMaskToAux(s390x.Greater)
			return true
		}
		// match: (BRC {s390x.GreaterOrEqual} (CMPWconst x [ 128]) yes no)
		// result: (CIJ {s390x.Greater} x [ 127] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 128 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(127)
			b.Aux = s390xCCMaskToAux(s390x.Greater)
			return true
		}
		// match: (BRC {s390x.Less} (CMPWUconst x [256]) yes no)
		// result: (CLIJ {s390x.LessOrEqual} x [255] yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 256 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(255)
			b.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
			return true
		}
		// match: (BRC {s390x.Less} (CMPUconst x [256]) yes no)
		// result: (CLGIJ {s390x.LessOrEqual} x [255] yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 256 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(255)
			b.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
			return true
		}
		// match: (BRC {s390x.GreaterOrEqual} (CMPWUconst x [256]) yes no)
		// result: (CLIJ {s390x.Greater} x [255] yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 256 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(255)
			b.Aux = s390xCCMaskToAux(s390x.Greater)
			return true
		}
		// match: (BRC {s390x.GreaterOrEqual} (CMPUconst x [256]) yes no)
		// result: (CLGIJ {s390x.Greater} x [255] yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 256 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(255)
			b.Aux = s390xCCMaskToAux(s390x.Greater)
			return true
		}
		// match: (BRC {c} (CMPconst x [y]) yes no)
		// cond: y == int32(uint8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)
		// result: (CLGIJ {c} x [uint8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(uint8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)) {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (BRC {c} (CMPWconst x [y]) yes no)
		// cond: y == int32(uint8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)
		// result: (CLIJ {c} x [uint8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(uint8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)) {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (BRC {c} (CMPUconst x [y]) yes no)
		// cond: y == int32( int8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)
		// result: (CGIJ {c} x [ int8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(int8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)) {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (BRC {c} (CMPWUconst x [y]) yes no)
		// cond: y == int32( int8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)
		// result: (CIJ {c} x [ int8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(int8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)) {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (BRC {c} (InvertFlags cmp) yes no)
		// result: (BRC {c.ReverseComparison()} cmp yes no)
		for b.Controls[0].Op == OpS390XInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl(BlockS390XBRC, cmp)
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (BRC {c} (FlagEQ) yes no)
		// cond: c&s390x.Equal != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XFlagEQ {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (BRC {c} (FlagLT) yes no)
		// cond: c&s390x.Less != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XFlagLT {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (BRC {c} (FlagGT) yes no)
		// cond: c&s390x.Greater != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XFlagGT {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (BRC {c} (FlagOV) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XFlagOV {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (BRC {c} (FlagEQ) yes no)
		// cond: c&s390x.Equal == 0
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XFlagEQ {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (BRC {c} (FlagLT) yes no)
		// cond: c&s390x.Less == 0
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XFlagLT {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (BRC {c} (FlagGT) yes no)
		// cond: c&s390x.Greater == 0
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XFlagGT {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (BRC {c} (FlagOV) yes no)
		// cond: c&s390x.Unordered == 0
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XFlagOV {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockS390XCGIJ:
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal != 0 && int64(x) == int64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal != 0 && int64(x) == int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less != 0 && int64(x) < int64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less != 0 && int64(x) < int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater != 0 && int64(x) > int64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater != 0 && int64(x) > int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal == 0 && int64(x) == int64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal == 0 && int64(x) == int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less == 0 && int64(x) < int64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less == 0 && int64(x) < int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater == 0 && int64(x) > int64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater == 0 && int64(x) > int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CGIJ {s390x.Equal} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.NoCarry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.NoCarry)
			return true
		}
		// match: (CGIJ {s390x.Equal} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [1])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CGIJ {s390x.LessOrGreater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CGIJ {s390x.LessOrGreater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [1])
		// result: (BRC {s390x.NoCarry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.NoCarry)
			return true
		}
		// match: (CGIJ {s390x.Greater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CGIJ {s390x.Equal} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.NoBorrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.NoBorrow)
			return true
		}
		// match: (CGIJ {s390x.Equal} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [1])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
		// match: (CGIJ {s390x.LessOrGreater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
		// match: (CGIJ {s390x.LessOrGreater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [1])
		// result: (BRC {s390x.NoBorrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.NoBorrow)
			return true
		}
		// match: (CGIJ {s390x.Greater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
	case BlockS390XCGRJ:
		// match: (CGRJ {c} x (MOVDconst [y]) yes no)
		// cond: is8Bit(y)
		// result: (CGIJ {c} x [ int8(y)] yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(is8Bit(y)) {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CGRJ {c} (MOVDconst [x]) y yes no)
		// cond: is8Bit(x)
		// result: (CGIJ {c.ReverseComparison()} y [ int8(x)] yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(is8Bit(x)) {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, y)
			b.AuxInt = int8ToAuxInt(int8(x))
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CGRJ {c} x (MOVDconst [y]) yes no)
		// cond: !is8Bit(y) && is32Bit(y)
		// result: (BRC {c} (CMPconst x [int32(y)]) yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(!is8Bit(y) && is32Bit(y)) {
				break
			}
			v0 := b.NewValue0(x.Pos, OpS390XCMPconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(y))
			v0.AddArg(x)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CGRJ {c} (MOVDconst [x]) y yes no)
		// cond: !is8Bit(x) && is32Bit(x)
		// result: (BRC {c.ReverseComparison()} (CMPconst y [int32(x)]) yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(!is8Bit(x) && is32Bit(x)) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpS390XCMPconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(x))
			v0.AddArg(y)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CGRJ {c} x y yes no)
		// cond: x == y && c&s390x.Equal != 0
		// result: (First yes no)
		for {
			x := b.Controls[0]
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(x == y && c&s390x.Equal != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CGRJ {c} x y yes no)
		// cond: x == y && c&s390x.Equal == 0
		// result: (First no yes)
		for {
			x := b.Controls[0]
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(x == y && c&s390x.Equal == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockS390XCIJ:
		// match: (CIJ {c} (MOVWreg x) [y] yes no)
		// result: (CIJ {c} x [y] yes no)
		for b.Controls[0].Op == OpS390XMOVWreg {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(y)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CIJ {c} (MOVWZreg x) [y] yes no)
		// result: (CIJ {c} x [y] yes no)
		for b.Controls[0].Op == OpS390XMOVWZreg {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(y)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal != 0 && int32(x) == int32(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal != 0 && int32(x) == int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less != 0 && int32(x) < int32(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less != 0 && int32(x) < int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater != 0 && int32(x) > int32(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater != 0 && int32(x) > int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal == 0 && int32(x) == int32(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal == 0 && int32(x) == int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less == 0 && int32(x) < int32(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less == 0 && int32(x) < int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater == 0 && int32(x) > int32(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater == 0 && int32(x) > int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockS390XCLGIJ:
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal != 0 && uint64(x) == uint64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal != 0 && uint64(x) == uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less != 0 && uint64(x) < uint64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less != 0 && uint64(x) < uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater != 0 && uint64(x) > uint64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater != 0 && uint64(x) > uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal == 0 && uint64(x) == uint64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal == 0 && uint64(x) == uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less == 0 && uint64(x) < uint64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less == 0 && uint64(x) < uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater == 0 && uint64(x) > uint64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater == 0 && uint64(x) > uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLGIJ {s390x.GreaterOrEqual} _ [0] yes no)
		// result: (First yes no)
		for {
			if auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLGIJ {s390x.Less} _ [0] yes no)
		// result: (First no yes)
		for {
			if auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLGIJ {s390x.Equal} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.NoCarry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.NoCarry)
			return true
		}
		// match: (CLGIJ {s390x.Equal} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [1])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CLGIJ {s390x.LessOrGreater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CLGIJ {s390x.LessOrGreater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [1])
		// result: (BRC {s390x.NoCarry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.NoCarry)
			return true
		}
		// match: (CLGIJ {s390x.Greater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CLGIJ {s390x.Equal} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.NoBorrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.NoBorrow)
			return true
		}
		// match: (CLGIJ {s390x.Equal} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [1])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
		// match: (CLGIJ {s390x.LessOrGreater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
		// match: (CLGIJ {s390x.LessOrGreater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [1])
		// result: (BRC {s390x.NoBorrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.NoBorrow)
			return true
		}
		// match: (CLGIJ {s390x.Greater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
	case BlockS390XCLGRJ:
		// match: (CLGRJ {c} x (MOVDconst [y]) yes no)
		// cond: isU8Bit(y)
		// result: (CLGIJ {c} x [uint8(y)] yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(isU8Bit(y)) {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CLGRJ {c} (MOVDconst [x]) y yes no)
		// cond: isU8Bit(x)
		// result: (CLGIJ {c.ReverseComparison()} y [uint8(x)] yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(isU8Bit(x)) {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, y)
			b.AuxInt = uint8ToAuxInt(uint8(x))
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CLGRJ {c} x (MOVDconst [y]) yes no)
		// cond: !isU8Bit(y) && isU32Bit(y)
		// result: (BRC {c} (CMPUconst x [int32(y)]) yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(!isU8Bit(y) && isU32Bit(y)) {
				break
			}
			v0 := b.NewValue0(x.Pos, OpS390XCMPUconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(y))
			v0.AddArg(x)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CLGRJ {c} (MOVDconst [x]
```