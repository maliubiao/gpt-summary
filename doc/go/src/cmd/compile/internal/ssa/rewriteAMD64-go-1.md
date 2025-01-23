Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共12部分，请归纳一下它的功能
```

### 源代码
```go
t64(off2)) && canMergeSym(sym1, sym2)
	// result: (ADDSSload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
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
		v.reset(OpAMD64ADDSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDSSload x [off] {sym} ptr (MOVLstore [off] {sym} ptr y _))
	// result: (ADDSS x (MOVLi2f y))
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
		v.reset(OpAMD64ADDSS)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLi2f, typ.Float32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ANDL (NOTL (SHLL (MOVLconst [1]) y)) x)
	// result: (BTRL x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64NOTL {
				continue
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SHLL {
				continue
			}
			y := v_0_0.Args[1]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0_0_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.reset(OpAMD64BTRL)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ANDL x (MOVLconst [c]))
	// result: (ANDLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpAMD64ANDLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ANDL x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ANDL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ANDLload x [off] {sym} ptr mem)
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
			v.reset(OpAMD64ANDLload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (ANDL x (NOTL y))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (ANDNL x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64NOTL {
				continue
			}
			y := v_1.Args[0]
			if !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpAMD64ANDNL)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ANDL x (NEGL x))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (BLSIL x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64NEGL || x != v_1.Args[0] || !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpAMD64BLSIL)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ANDL <t> x (ADDLconst [-1] x))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (Select0 <t> (BLSRL x))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDLconst || auxIntToInt32(v_1.AuxInt) != -1 || x != v_1.Args[0] || !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpSelect0)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpAMD64BLSRL, types.NewTuple(typ.UInt32, types.TypeFlags))
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDLconst [c] (ANDLconst [d] x))
	// result: (ANDLconst [c & d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(c & d)
		v.AddArg(x)
		return true
	}
	// match: (ANDLconst [ 0xFF] x)
	// result: (MOVBQZX x)
	for {
		if auxIntToInt32(v.AuxInt) != 0xFF {
			break
		}
		x := v_0
		v.reset(OpAMD64MOVBQZX)
		v.AddArg(x)
		return true
	}
	// match: (ANDLconst [0xFFFF] x)
	// result: (MOVWQZX x)
	for {
		if auxIntToInt32(v.AuxInt) != 0xFFFF {
			break
		}
		x := v_0
		v.reset(OpAMD64MOVWQZX)
		v.AddArg(x)
		return true
	}
	// match: (ANDLconst [c] _)
	// cond: c==0
	// result: (MOVLconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if !(c == 0) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (ANDLconst [c] x)
	// cond: c==-1
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c == -1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ANDLconst [c] (MOVLconst [d]))
	// result: (MOVLconst [c&d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(c & d)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDLconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDLconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (ANDLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
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
		v.reset(OpAMD64ANDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (ANDLconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (ANDLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpAMD64ANDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ANDLload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ANDLload [off1+off2] {sym} val base mem)
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
		v.reset(OpAMD64ANDLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ANDLload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ANDLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
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
		v.reset(OpAMD64ANDLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ANDLload x [off] {sym} ptr (MOVSSstore [off] {sym} ptr y _))
	// result: (ANDL x (MOVLf2i y))
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
		v.reset(OpAMD64ANDL)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLf2i, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDLmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ANDLmodify [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64ANDLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (ANDLmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ANDLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64ANDLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDNL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDNL x (SHLL (MOVLconst [1]) y))
	// result: (BTRL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64SHLL {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_1_0.AuxInt) != 1 {
			break
		}
		v.reset(OpAMD64BTRL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDNQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDNQ x (SHLQ (MOVQconst [1]) y))
	// result: (BTRQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64SHLQ {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_1_0.AuxInt) != 1 {
			break
		}
		v.reset(OpAMD64BTRQ)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ANDQ (NOTQ (SHLQ (MOVQconst [1]) y)) x)
	// result: (BTRQ x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64NOTQ {
				continue
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SHLQ {
				continue
			}
			y := v_0_0.Args[1]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_0_0_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.reset(OpAMD64BTRQ)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ANDQ (MOVQconst [c]) x)
	// cond: isUint64PowerOfTwo(^c) && uint64(^c) >= 1<<31
	// result: (BTRQconst [int8(log64(^c))] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			x := v_1
			if !(isUint64PowerOfTwo(^c) && uint64(^c) >= 1<<31) {
				continue
			}
			v.reset(OpAMD64BTRQconst)
			v.AuxInt = int8ToAuxInt(int8(log64(^c)))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ANDQ x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (ANDQconst [int32(c)] x)
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
			v.reset(OpAMD64ANDQconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ANDQ x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ANDQ x l:(MOVQload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ANDQload x [off] {sym} ptr mem)
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
			v.reset(OpAMD64ANDQload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (ANDQ x (NOTQ y))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (ANDNQ x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64NOTQ {
				continue
			}
			y := v_1.Args[0]
			if !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpAMD64ANDNQ)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ANDQ x (NEGQ x))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (BLSIQ x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64NEGQ || x != v_1.Args[0] || !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpAMD64BLSIQ)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ANDQ <t> x (ADDQconst [-1] x))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (Select0 <t> (BLSRQ x))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDQconst || auxIntToInt32(v_1.AuxInt) != -1 || x != v_1.Args[0] || !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpSelect0)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpAMD64BLSRQ, types.NewTuple(typ.UInt64, types.TypeFlags))
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDQconst [c] (ANDQconst [d] x))
	// result: (ANDQconst [c & d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ANDQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64ANDQconst)
		v.AuxInt = int32ToAuxInt(c & d)
		v.AddArg(x)
		return true
	}
	// match: (ANDQconst [ 0xFF] x)
	// result: (MOVBQZX x)
	for {
		if auxIntToInt32(v.AuxInt) != 0xFF {
			break
		}
		x := v_0
		v.reset(OpAMD64MOVBQZX)
		v.AddArg(x)
		return true
	}
	// match: (ANDQconst [0xFFFF] x)
	// result: (MOVWQZX x)
	for {
		if auxIntToInt32(v.AuxInt) != 0xFFFF {
			break
		}
		x := v_0
		v.reset(OpAMD64MOVWQZX)
		v.AddArg(x)
		return true
	}
	// match: (ANDQconst [0] _)
	// result: (MOVQconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (ANDQconst [-1] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ANDQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [int64(c)&d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(c) & d)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDQconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDQconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (ANDQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
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
		v.reset(OpAMD64ANDQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (ANDQconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (ANDQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpAMD64ANDQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ANDQload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ANDQload [off1+off2] {sym} val base mem)
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
		v.reset(OpAMD64ANDQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ANDQload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ANDQload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
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
		v.reset(OpAMD64ANDQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ANDQload x [off] {sym} ptr (MOVSDstore [off] {sym} ptr y _))
	// result: (ANDQ x (MOVQf2i y))
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
		v.reset(OpAMD64ANDQ)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQf2i, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ANDQmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDQmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ANDQmodify [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64ANDQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (ANDQmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ANDQmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64ANDQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64BSFQ(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (BSFQ (ORQconst <t> [1<<8] (MOVBQZX x)))
	// result: (BSFQ (ORQconst <t> [1<<8] x))
	for {
		if v_0.Op != OpAMD64ORQconst {
			break
		}
		t := v_0.Type
		if auxIntToInt32(v_0.AuxInt) != 1<<8 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAMD64MOVBQZX {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpAMD64BSFQ)
		v0 := b.NewValue0(v.Pos, OpAMD64ORQconst, t)
		v0.AuxInt = int32ToAuxInt(1 << 8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (BSFQ (ORQconst <t> [1<<16] (MOVWQZX x)))
	// result: (BSFQ (ORQconst <t> [1<<16] x))
	for {
		if v_0.Op != OpAMD64ORQconst {
			break
		}
		t := v_0.Type
		if auxIntToInt32(v_0.AuxInt) != 1<<16 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAMD64MOVWQZX {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpAMD64BSFQ)
		v0 := b.NewValue0(v.Pos, OpAMD64ORQconst, t)
		v0.AuxInt = int32ToAuxInt(1 << 16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64BSWAPL(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BSWAPL (BSWAPL p))
	// result: p
	for {
		if v_0.Op != OpAMD64BSWAPL {
			break
		}
		p := v_0.Args[0]
		v.copyOf(p)
		return true
	}
	// match: (BSWAPL x:(MOVLload [i] {s} p mem))
	// cond: x.Uses == 1 && buildcfg.GOAMD64 >= 3
	// result: @x.Block (MOVBELload [i] {s} p mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVLload {
			break
		}
		i := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && buildcfg.GOAMD64 >= 3) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBELload, typ.UInt32)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(i)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (BSWAPL x:(MOVBELload [i] {s} p mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVLload [i] {s} p mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVBELload {
			break
		}
		i := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVLload, typ.UInt32)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(i)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64BSWAPQ(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BSWAPQ (BSWAPQ p))
	// result: p
	for {
		if v_0.Op != OpAMD64BSWAPQ {
			break
		}
		p := v_0.Args[0]
		v.copyOf(p)
		return true
	}
	// match: (BSWAPQ x:(MOVQload [i] {s} p mem))
	// cond: x.Uses == 1 && buildcfg.GOAMD64 >= 3
	// result: @x.Block (MOVBEQload [i] {s} p mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVQload {
			break
		}
		i := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && buildcfg.GOAMD64 >= 3) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBEQload, typ.UInt64)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(i)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (BSWAPQ x:(MOVBEQload [i] {s} p mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVQload [i] {s} p mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVBEQload {
			break
		}
		i := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVQload, typ.UInt64)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(i)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64BTCQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (BTCQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [d^(1<<uint32(c))])
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(d ^ (1 << uint32(c)))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64BTLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (BTLconst [c] (SHRQconst [d] x))
	// cond: (c+d)<64
	// result: (BTQconst [c+d] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64SHRQconst {
			break
		}
		d := auxIntToInt8(v_0.AuxInt)
		x := v_0.Args[0]
		if !((c + d) < 64) {
			break
		}
		v.reset(OpAMD64BTQconst)
		v.AuxInt = int8ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (BTLconst [c] (SHLQconst [d] x))
	// cond: c>d
	// result: (BTLconst [c-d] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64SHLQconst {
			break
		}
		d := auxIntToInt8(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > d) {
			break
		}
		v.reset(OpAMD64BTLconst)
		v.AuxInt = int8ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	// match: (BTLconst [0] s:(SHRQ x y))
	// result: (BTQ y x)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		s := v_0
		if s.Op != OpAMD64SHRQ {
			break
		}
		y := s.Args[1]
		x := s.Args[0]
		v.reset(OpAMD64BTQ)
		v.AddArg2(y, x)
		return true
	}
	// match: (BTLconst [c] (SHRLconst [d] x))
	// cond: (c+d)<32
	// result: (BTLconst [c+d] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64SHRLconst {
			break
		}
		d := auxIntToInt8(v_0.AuxInt)
		x := v_0.Args[0]
		if !((c + d) < 32) {
			break
		}
		v.reset(OpAMD64BTLconst)
		v.AuxInt = int8ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (BTLconst [c] (SHLLconst [d] x))
	// cond: c>d
	// result: (BTLconst [c-d] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64SHLLconst {
			break
		}
		d := auxIntToInt8(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > d) {
			break
		}
		v.reset(OpAMD64BTLconst)
		v.AuxInt = int8ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	// match: (BTLconst [0] s:(SHRL x y))
	// result: (BTL y x)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		s := v_0
		if s.Op != OpAMD64SHRL {
			break
		}
		y := s.Args[1]
		x := s.Args[0]
		v.reset(OpAMD64BTL)
		v.AddArg2(y, x)
		return true
	}
	// match: (BTLconst [0] s:(SHRXL x y))
	// result: (BTL y x)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		s := v_0
		if s.Op != OpAMD64SHRXL {
			break
		}
		y := s.Args[1]
		x := s.Args[0]
		v.reset(OpAMD64BTL)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64BTQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (BTQconst [c] (SHRQconst [d] x))
	// cond: (c+d)<64
	// result: (BTQconst [c+d] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64SHRQconst {
			break
		}
		d := auxIntToInt8(v_0.AuxInt)
		x := v_0.Args[0]
		if !((c + d) < 64) {
			break
		}
		v.reset(OpAMD64BTQconst)
		v.AuxInt = int8ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (BTQconst [c] (SHLQconst [d] x))
	// cond: c>d
	// result: (BTQconst [c-d] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64SHLQconst {
			break
		}
		d := auxIntToInt8(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > d) {
			break
		}
		v.reset(OpAMD64BTQconst)
		v.AuxInt = int8ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	// match: (BTQconst [0] s:(SHRQ x y))
	// result: (BTQ y x)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		s := v_0
		if s.Op != OpAMD64SHRQ {
			break
		}
		y := s.Args[1]
		x := s.Args[0]
		v.reset(OpAMD64BTQ)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64BTRQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (BTRQconst [c] (BTSQconst [c] x))
	// result: (BTRQconst [c] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64BTSQconst || auxIntToInt8(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64BTRQconst)
		v.AuxInt = int8ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (BTRQconst [c] (BTCQconst [c] x))
	// result: (BTRQconst [c] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64BTCQconst || auxIntToInt8(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64BTRQconst)
		v.AuxInt = int8ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (BTRQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [d&^(1<<uint32(c))])
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(d &^ (1 << uint32(c)))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64BTSQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (BTSQconst [c] (BTRQconst [c] x))
	// result: (BTSQconst [c] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64BTRQconst || auxIntToInt8(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64BTSQconst)
		v.AuxInt = int8ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (BTSQconst [c] (BTCQconst [c] x))
	// result: (BTSQconst [c] x)
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64BTCQconst || auxIntToInt8(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64BTSQconst)
		v.AuxInt = int8ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (BTSQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [d|(1<<uint32(c))])
	for {
		c := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(d | (1 << uint32(c)))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLCC(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVLCC x y (InvertFlags cond))
	// result: (CMOVLLS x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLLS)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLCC _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLCC _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLCC y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLCC y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLCC _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLCS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVLCS x y (InvertFlags cond))
	// result: (CMOVLHI x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLHI)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLCS y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLCS y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLCS _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLCS _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLCS y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLEQ(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMOVLEQ x y (InvertFlags cond))
	// result: (CMOVLEQ x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLEQ)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLEQ _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLEQ y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLEQ y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLEQ y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLEQ y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLEQ x y (TESTQ s:(Select0 blsr:(BLSRQ _)) s))
	// result: (CMOVLEQ x y (Select1 <types.TypeFlags> blsr))
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64TESTQ {
			break
		}
		_ = v_2.Args[1]
		v_2_0 := v_2.Args[0]
		v_2_1 := v_2.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_2_0, v_2_1 = _i0+1, v_2_1, v_2_0 {
			s := v_2_0
			if s.Op != OpSelect0 {
				continue
			}
			blsr := s.Args[0]
			if blsr.Op != OpAMD64BLSRQ || s != v_2_1 {
				continue
			}
			v.reset(OpAMD64CMOVLEQ)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg3(x, y, v0)
			return true
		}
		break
	}
	// match: (CMOVLEQ x y (TESTL s:(Select0 blsr:(BLSRL _)) s))
	// result: (CMOVLEQ x y (Select1 <types.TypeFlags> blsr))
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64TESTL {
			break
		}
		_ = v_2.Args[1]
		v_2_0 := v_2.Args[0]
		v_2_1 := v_2.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_2_0, v_2_1 = _i0+1, v_2_1, v_2_0 {
			s := v_2_0
			if s.Op != OpSelect0 {
				continue
			}
			blsr := s.Args[0]
			if blsr.Op != OpAMD64BLSRL || s != v_2_1 {
				continue
			}
			v.reset(OpAMD64CMOVLEQ)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg3(x, y, v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLGE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVLGE x y (InvertFlags cond))
	// result: (CMOVLLE x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLLE)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLGE _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLGE _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLGE _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLGE y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLGE y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLGT(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVLGT x y (InvertFlags cond))
	// result: (CMOVLLT x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLLT)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLGT y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLGT _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLGT _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLGT y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLGT y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLHI(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVLHI x y (InvertFlags cond))
	// result: (CMOVLCS x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLCS)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLHI y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLHI _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLHI y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLHI y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLHI _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLLE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVLLE x y (InvertFlags cond))
	// result: (CMOVLGE x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLGE)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLLE _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLLE y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLLE y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLLE _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLLE _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLLS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVLLS x y (InvertFlags cond))
	// result: (CMOVLCC x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLCC)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLLS _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLLS y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLLS _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLLS _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLLS y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLLT(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVLLT x y (InvertFlags cond))
	// result: (CMOVLGT x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLGT)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLLT y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLLT y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLLT y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLLT _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLLT _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVLNE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMOVLNE x y (InvertFlags cond))
	// result: (CMOVLNE x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVLNE)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVLNE y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVLNE _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLNE _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLNE _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLNE _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVLNE x y (TESTQ s:(Select0 blsr:(BLSRQ _)) s))
	// result: (CMOVLNE x y (Select1 <types.TypeFlags> blsr))
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64TESTQ {
			break
		}
		_ = v_2.Args[1]
		v_2_0 := v_2.Args[0]
		v_2_1 := v_2.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_2_0, v_2_1 = _i0+1, v_2_1, v_2_0 {
			s := v_2_0
			if s.Op != OpSelect0 {
				continue
			}
			blsr := s.Args[0]
			if blsr.Op != OpAMD64BLSRQ || s != v_2_1 {
				continue
			}
			v.reset(OpAMD64CMOVLNE)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg3(x, y, v0)
			return true
		}
		break
	}
	// match: (CMOVLNE x y (TESTL s:(Select0 blsr:(BLSRL _)) s))
	// result: (CMOVLNE x y (Select1 <types.TypeFlags> blsr))
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64TESTL {
			break
		}
		_ = v_2.Args[1]
		v_2_0 := v_2.Args[0]
		v_2_1 := v_2.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_2_0, v_2_1 = _i0+1, v_2_1, v_2_0 {
			s := v_2_0
			if s.Op != OpSelect0 {
				continue
			}
			blsr := s.Args[0]
			if blsr.Op != OpAMD64BLSRL || s != v_2_1 {
				continue
			}
			v.reset(OpAMD64CMOVLNE)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg3(x, y, v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQCC(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVQCC x y (InvertFlags cond))
	// result: (CMOVQLS x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQLS)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQCC _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQCC _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQCC y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQCC y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQCC _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQCS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVQCS x y (InvertFlags cond))
	// result: (CMOVQHI x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQHI)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQCS y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQCS y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQCS _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQCS _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQCS y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQEQ(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMOVQEQ x y (InvertFlags cond))
	// result: (CMOVQEQ x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQEQ)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQEQ _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQEQ y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQEQ y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQEQ y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQEQ y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQEQ x _ (Select1 (BSFQ (ORQconst [c] _))))
	// cond: c != 0
	// result: x
	for {
		x := v_0
		if v_2.Op != OpSelect1 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpAMD64BSFQ {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpAMD64ORQconst {
			break
		}
		c := auxIntToInt32(v_2_0_0.AuxInt)
		if !(c != 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQEQ x _ (Select1 (BSRQ (ORQconst [c] _))))
	// cond: c != 0
	// result: x
	for {
		x := v_0
		if v_2.Op != OpSelect1 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpAMD64BSRQ {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpAMD64ORQconst {
			break
		}
		c := auxIntToInt32(v_2_0_0.AuxInt)
		if !(c != 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQEQ x y (TESTQ s:(Select0 blsr:(BLSRQ _)) s))
	// result: (CMOVQEQ x y (Select1 <types.TypeFlags> blsr))
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64TESTQ {
			break
		}
		_ = v_2.Args[1]
		v_2_0 := v_2.Args[0]
		v_2_1 := v_2.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_2_0, v_2_1 = _i0+1, v_2_1, v_2_0 {
			s := v_2_0
			if s.Op != OpSelect0 {
				continue
			}
			blsr := s.Args[0]
			if blsr.Op != OpAMD64BLSRQ || s != v_2_1 {
				continue
			}
			v.reset(OpAMD64CMOVQEQ)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg3(x, y, v0)
			return true
		}
		break
	}
	// match: (CMOVQEQ x y (TESTL s:(Select0 blsr:(BLSRL _)) s))
	// result: (CMOVQEQ x y (Select1 <types.TypeFlags> blsr))
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64TESTL {
			break
		}
		_ = v_2.Args[1]
		v_2_0 := v_2.Args[0]
		v_2_1 := v_2.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_2_0, v_2_1 = _i0+1, v_2_1, v_2_0 {
			s := v_2_0
			if s.Op != OpSelect0 {
				continue
			}
			blsr := s.Args[0]
			if blsr.Op != OpAMD64BLSRL || s != v_2_1 {
				continue
			}
			v.reset(OpAMD64CMOVQEQ)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg3(x, y, v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQGE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVQGE x y (InvertFlags cond))
	// result: (CMOVQLE x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQLE)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQGE _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQGE _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQGE _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQGE y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQGE y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQGT(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVQGT x y (InvertFlags cond))
	// result: (CMOVQLT x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQLT)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQGT y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQGT _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQGT _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQGT y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQGT y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQHI(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVQHI x y (InvertFlags cond))
	// result: (CMOVQCS x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQCS)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQHI y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQHI _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQHI y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQHI y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQHI _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQLE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVQLE x y (InvertFlags cond))
	// result: (CMOVQGE x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQGE)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQLE _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQLE y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQLE y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQLE _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQLE _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQLS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVQLS x y (InvertFlags cond))
	// result: (CMOVQCC x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQCC)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQLS _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQLS y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQLS _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQLS _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQLS y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQLT(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVQLT x y (InvertFlags cond))
	// result: (CMOVQGT x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQGT)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQLT y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQLT y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQLT y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQLT _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQLT _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVQNE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMOVQNE x y (InvertFlags cond))
	// result: (CMOVQNE x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVQNE)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVQNE y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVQNE _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQNE _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQNE _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQNE _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVQNE x y (TESTQ s:(Select0 blsr:(BLSRQ _)) s))
	// result: (CMOVQNE x y (Select1 <types.TypeFlags> blsr))
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64TESTQ {
			break
		}
		_ = v_2.Args[1]
		v_2_0 := v_2.Args[0]
		v_2_1 := v_2.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_2_0, v_2_1 = _i0+1, v_2_1, v_2_0 {
			s := v_2_0
			if s.Op != OpSelect0 {
				continue
			}
			blsr := s.Args[0]
			if blsr.Op != OpAMD64BLSRQ || s != v_2_1 {
				continue
			}
			v.reset(OpAMD64CMOVQNE)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg3(x, y, v0)
			return true
		}
		break
	}
	// match: (CMOVQNE x y (TESTL s:(Select0 blsr:(BLSRL _)) s))
	// result: (CMOVQNE x y (Select1 <types.TypeFlags> blsr))
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64TESTL {
			break
		}
		_ = v_2.Args[1]
		v_2_0 := v_2.Args[0]
		v_2_1 := v_2.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_2_0, v_2_1 = _i0+1, v_2_1, v_2_0 {
			s := v_2_0
			if s.Op != OpSelect0 {
				continue
			}
			blsr := s.Args[0]
			if blsr.Op != OpAMD64BLSRL || s != v_2_1 {
				continue
			}
			v.reset(OpAMD64CMOVQNE)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg3(x, y, v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVWCC(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWCC x y (InvertFlags cond))
	// result: (CMOVWLS x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWLS)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWCC _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWCC _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWCC y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWCC y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWCC _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVWCS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWCS x y (InvertFlags cond))
	// result: (CMOVWHI x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWHI)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWCS y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWCS y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWCS _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWCS _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWCS y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVWEQ(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWEQ x y (InvertFlags cond))
	// result: (CMOVWEQ x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWEQ)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWEQ _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWEQ y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWEQ y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWEQ y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWEQ y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVWGE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWGE x y (InvertFlags cond))
	// result: (CMOVWLE x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWLE)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWGE _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWGE _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWGE _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWGE y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWGE y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVWGT(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWGT x y (InvertFlags cond))
	// result: (CMOVWLT x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWLT)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWGT y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWGT _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWGT _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWGT y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWGT y _ (FlagLT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVWHI(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWHI x y (InvertFlags cond))
	// result: (CMOVWCS x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWCS)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWHI y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWHI _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWHI y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWHI y _ (FlagLT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWHI _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVWLE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWLE x y (InvertFlags cond))
	// result: (CMOVWGE x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWGE)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWLE _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWLE y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWLE y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWLE _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWLE _ x (FlagLT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMOVWLS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 :=
```