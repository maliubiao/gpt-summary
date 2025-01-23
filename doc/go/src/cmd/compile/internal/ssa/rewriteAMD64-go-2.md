Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共12部分，请归纳一下它的功能
```

### 源代码
```go
v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWLS x y (InvertFlags cond))
	// result: (CMOVWCC x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWCC)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWLS _ x (FlagEQ))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWLS y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWLS _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWLS _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWLS y _ (FlagLT_UGT))
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
func rewriteValueAMD64_OpAMD64CMOVWLT(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWLT x y (InvertFlags cond))
	// result: (CMOVWGT x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWGT)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWLT y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWLT y _ (FlagGT_UGT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWLT y _ (FlagGT_ULT))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWLT _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWLT _ x (FlagLT_UGT))
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
func rewriteValueAMD64_OpAMD64CMOVWNE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWNE x y (InvertFlags cond))
	// result: (CMOVWNE x y cond)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64InvertFlags {
			break
		}
		cond := v_2.Args[0]
		v.reset(OpAMD64CMOVWNE)
		v.AddArg3(x, y, cond)
		return true
	}
	// match: (CMOVWNE y _ (FlagEQ))
	// result: y
	for {
		y := v_0
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CMOVWNE _ x (FlagGT_UGT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWNE _ x (FlagGT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWNE _ x (FlagLT_ULT))
	// result: x
	for {
		x := v_1
		if v_2.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWNE _ x (FlagLT_UGT))
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
func rewriteValueAMD64_OpAMD64CMPB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPB x (MOVLconst [c]))
	// result: (CMPBconst x [int8(c)])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64CMPBconst)
		v.AuxInt = int8ToAuxInt(int8(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPB (MOVLconst [c]) x)
	// result: (InvertFlags (CMPBconst x [int8(c)]))
	for {
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPBconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPB x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPB y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPB, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPB l:(MOVBload {sym} [off] ptr mem) x)
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (CMPBload {sym} [off] ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVBload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64CMPBload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (CMPB x l:(MOVBload {sym} [off] ptr mem))
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (InvertFlags (CMPBload {sym} [off] ptr x mem))
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVBload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(l.Pos, OpAMD64CMPBload, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, x, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPBconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)==y
	// result: (FlagEQ)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) == y) {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)<y && uint8(x)<uint8(y)
	// result: (FlagLT_ULT)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) < y && uint8(x) < uint8(y)) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)<y && uint8(x)>uint8(y)
	// result: (FlagLT_UGT)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) < y && uint8(x) > uint8(y)) {
			break
		}
		v.reset(OpAMD64FlagLT_UGT)
		return true
	}
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)>y && uint8(x)<uint8(y)
	// result: (FlagGT_ULT)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) > y && uint8(x) < uint8(y)) {
			break
		}
		v.reset(OpAMD64FlagGT_ULT)
		return true
	}
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)>y && uint8(x)>uint8(y)
	// result: (FlagGT_UGT)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) > y && uint8(x) > uint8(y)) {
			break
		}
		v.reset(OpAMD64FlagGT_UGT)
		return true
	}
	// match: (CMPBconst (ANDLconst _ [m]) [n])
	// cond: 0 <= int8(m) && int8(m) < n
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= int8(m) && int8(m) < n) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPBconst a:(ANDL x y) [0])
	// cond: a.Uses == 1
	// result: (TESTB x y)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpAMD64ANDL {
			break
		}
		y := a.Args[1]
		x := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpAMD64TESTB)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPBconst a:(ANDLconst [c] x) [0])
	// cond: a.Uses == 1
	// result: (TESTBconst [int8(c)] x)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		x := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpAMD64TESTBconst)
		v.AuxInt = int8ToAuxInt(int8(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPBconst x [0])
	// result: (TESTB x x)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.reset(OpAMD64TESTB)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPBconst l:(MOVBload {sym} [off] ptr mem) [c])
	// cond: l.Uses == 1 && clobber(l)
	// result: @l.Block (CMPBconstload {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		c := auxIntToInt8(v.AuxInt)
		l := v_0
		if l.Op != OpAMD64MOVBload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		b = l.Block
		v0 := b.NewValue0(l.Pos, OpAMD64CMPBconstload, types.TypeFlags)
		v.copyOf(v0)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPBconstload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPBconstload [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (CMPBconstload [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
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
		v.reset(OpAMD64CMPBconstload)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (CMPBconstload [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (CMPBconstload [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpAMD64CMPBconstload)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPBload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPBload [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (CMPBload [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64CMPBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (CMPBload [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (CMPBload [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64CMPBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (CMPBload {sym} [off] ptr (MOVLconst [c]) mem)
	// result: (CMPBconstload {sym} [makeValAndOff(int32(int8(c)),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64CMPBconstload)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int8(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPL x (MOVLconst [c]))
	// result: (CMPLconst x [c])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64CMPLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPL (MOVLconst [c]) x)
	// result: (InvertFlags (CMPLconst x [c]))
	for {
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPL x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPL y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPL, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPL l:(MOVLload {sym} [off] ptr mem) x)
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (CMPLload {sym} [off] ptr x mem)
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
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64CMPLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (CMPL x l:(MOVLload {sym} [off] ptr mem))
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (InvertFlags (CMPLload {sym} [off] ptr x mem))
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(l.Pos, OpAMD64CMPLload, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, x, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPLconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x==y
	// result: (FlagEQ)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x == y) {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x<y && uint32(x)<uint32(y)
	// result: (FlagLT_ULT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x < y && uint32(x) < uint32(y)) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x<y && uint32(x)>uint32(y)
	// result: (FlagLT_UGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x < y && uint32(x) > uint32(y)) {
			break
		}
		v.reset(OpAMD64FlagLT_UGT)
		return true
	}
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x>y && uint32(x)<uint32(y)
	// result: (FlagGT_ULT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x > y && uint32(x) < uint32(y)) {
			break
		}
		v.reset(OpAMD64FlagGT_ULT)
		return true
	}
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x>y && uint32(x)>uint32(y)
	// result: (FlagGT_UGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x > y && uint32(x) > uint32(y)) {
			break
		}
		v.reset(OpAMD64FlagGT_UGT)
		return true
	}
	// match: (CMPLconst (SHRLconst _ [c]) [n])
	// cond: 0 <= n && 0 < c && c <= 32 && (1<<uint64(32-c)) <= uint64(n)
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64SHRLconst {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if !(0 <= n && 0 < c && c <= 32 && (1<<uint64(32-c)) <= uint64(n)) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPLconst (ANDLconst _ [m]) [n])
	// cond: 0 <= m && m < n
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= m && m < n) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPLconst a:(ANDL x y) [0])
	// cond: a.Uses == 1
	// result: (TESTL x y)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpAMD64ANDL {
			break
		}
		y := a.Args[1]
		x := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpAMD64TESTL)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPLconst a:(ANDLconst [c] x) [0])
	// cond: a.Uses == 1
	// result: (TESTLconst [c] x)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		x := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpAMD64TESTLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPLconst x [0])
	// result: (TESTL x x)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.reset(OpAMD64TESTL)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPLconst l:(MOVLload {sym} [off] ptr mem) [c])
	// cond: l.Uses == 1 && clobber(l)
	// result: @l.Block (CMPLconstload {sym} [makeValAndOff(c,off)] ptr mem)
	for {
		c := auxIntToInt32(v.AuxInt)
		l := v_0
		if l.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		b = l.Block
		v0 := b.NewValue0(l.Pos, OpAMD64CMPLconstload, types.TypeFlags)
		v.copyOf(v0)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(c, off))
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPLconstload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPLconstload [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (CMPLconstload [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
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
		v.reset(OpAMD64CMPLconstload)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (CMPLconstload [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (CMPLconstload [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpAMD64CMPLconstload)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPLload [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (CMPLload [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64CMPLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (CMPLload [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (CMPLload [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64CMPLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (CMPLload {sym} [off] ptr (MOVLconst [c]) mem)
	// result: (CMPLconstload {sym} [makeValAndOff(c,off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64CMPLconstload)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(c, off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPQ x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (CMPQconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpAMD64CMPQconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPQ (MOVQconst [c]) x)
	// cond: is32Bit(c)
	// result: (InvertFlags (CMPQconst x [int32(c)]))
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPQ x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPQ y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQ, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPQ (MOVQconst [x]) (MOVQconst [y]))
	// cond: x==y
	// result: (FlagEQ)
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		if !(x == y) {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (CMPQ (MOVQconst [x]) (MOVQconst [y]))
	// cond: x<y && uint64(x)<uint64(y)
	// result: (FlagLT_ULT)
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		if !(x < y && uint64(x) < uint64(y)) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPQ (MOVQconst [x]) (MOVQconst [y]))
	// cond: x<y && uint64(x)>uint64(y)
	// result: (FlagLT_UGT)
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		if !(x < y && uint64(x) > uint64(y)) {
			break
		}
		v.reset(OpAMD64FlagLT_UGT)
		return true
	}
	// match: (CMPQ (MOVQconst [x]) (MOVQconst [y]))
	// cond: x>y && uint64(x)<uint64(y)
	// result: (FlagGT_ULT)
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		if !(x > y && uint64(x) < uint64(y)) {
			break
		}
		v.reset(OpAMD64FlagGT_ULT)
		return true
	}
	// match: (CMPQ (MOVQconst [x]) (MOVQconst [y]))
	// cond: x>y && uint64(x)>uint64(y)
	// result: (FlagGT_UGT)
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		if !(x > y && uint64(x) > uint64(y)) {
			break
		}
		v.reset(OpAMD64FlagGT_UGT)
		return true
	}
	// match: (CMPQ l:(MOVQload {sym} [off] ptr mem) x)
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (CMPQload {sym} [off] ptr x mem)
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
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64CMPQload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (CMPQ x l:(MOVQload {sym} [off] ptr mem))
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (InvertFlags (CMPQload {sym} [off] ptr x mem))
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(l.Pos, OpAMD64CMPQload, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, x, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPQconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPQconst (MOVQconst [x]) [y])
	// cond: x==int64(y)
	// result: (FlagEQ)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x == int64(y)) {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (CMPQconst (MOVQconst [x]) [y])
	// cond: x<int64(y) && uint64(x)<uint64(int64(y))
	// result: (FlagLT_ULT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x < int64(y) && uint64(x) < uint64(int64(y))) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPQconst (MOVQconst [x]) [y])
	// cond: x<int64(y) && uint64(x)>uint64(int64(y))
	// result: (FlagLT_UGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x < int64(y) && uint64(x) > uint64(int64(y))) {
			break
		}
		v.reset(OpAMD64FlagLT_UGT)
		return true
	}
	// match: (CMPQconst (MOVQconst [x]) [y])
	// cond: x>int64(y) && uint64(x)<uint64(int64(y))
	// result: (FlagGT_ULT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x > int64(y) && uint64(x) < uint64(int64(y))) {
			break
		}
		v.reset(OpAMD64FlagGT_ULT)
		return true
	}
	// match: (CMPQconst (MOVQconst [x]) [y])
	// cond: x>int64(y) && uint64(x)>uint64(int64(y))
	// result: (FlagGT_UGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x > int64(y) && uint64(x) > uint64(int64(y))) {
			break
		}
		v.reset(OpAMD64FlagGT_UGT)
		return true
	}
	// match: (CMPQconst (MOVBQZX _) [c])
	// cond: 0xFF < c
	// result: (FlagLT_ULT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVBQZX || !(0xFF < c) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPQconst (MOVWQZX _) [c])
	// cond: 0xFFFF < c
	// result: (FlagLT_ULT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVWQZX || !(0xFFFF < c) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPQconst (SHRQconst _ [c]) [n])
	// cond: 0 <= n && 0 < c && c <= 64 && (1<<uint64(64-c)) <= uint64(n)
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64SHRQconst {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if !(0 <= n && 0 < c && c <= 64 && (1<<uint64(64-c)) <= uint64(n)) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPQconst (ANDQconst _ [m]) [n])
	// cond: 0 <= m && m < n
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ANDQconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= m && m < n) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPQconst (ANDLconst _ [m]) [n])
	// cond: 0 <= m && m < n
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= m && m < n) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPQconst a:(ANDQ x y) [0])
	// cond: a.Uses == 1
	// result: (TESTQ x y)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpAMD64ANDQ {
			break
		}
		y := a.Args[1]
		x := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpAMD64TESTQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPQconst a:(ANDQconst [c] x) [0])
	// cond: a.Uses == 1
	// result: (TESTQconst [c] x)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		x := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpAMD64TESTQconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPQconst x [0])
	// result: (TESTQ x x)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.reset(OpAMD64TESTQ)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPQconst l:(MOVQload {sym} [off] ptr mem) [c])
	// cond: l.Uses == 1 && clobber(l)
	// result: @l.Block (CMPQconstload {sym} [makeValAndOff(c,off)] ptr mem)
	for {
		c := auxIntToInt32(v.AuxInt)
		l := v_0
		if l.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		b = l.Block
		v0 := b.NewValue0(l.Pos, OpAMD64CMPQconstload, types.TypeFlags)
		v.copyOf(v0)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(c, off))
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPQconstload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPQconstload [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (CMPQconstload [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
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
		v.reset(OpAMD64CMPQconstload)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (CMPQconstload [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (CMPQconstload [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpAMD64CMPQconstload)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPQload [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (CMPQload [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64CMPQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (CMPQload [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (CMPQload [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64CMPQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (CMPQload {sym} [off] ptr (MOVQconst [c]) mem)
	// cond: validVal(c)
	// result: (CMPQconstload {sym} [makeValAndOff(int32(c),off)] ptr mem)
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
		v.reset(OpAMD64CMPQconstload)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPW x (MOVLconst [c]))
	// result: (CMPWconst x [int16(c)])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64CMPWconst)
		v.AuxInt = int16ToAuxInt(int16(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPW (MOVLconst [c]) x)
	// result: (InvertFlags (CMPWconst x [int16(c)]))
	for {
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPWconst, types.TypeFlags)
		v0.AuxInt = int16ToAuxInt(int16(c))
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
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPW, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPW l:(MOVWload {sym} [off] ptr mem) x)
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (CMPWload {sym} [off] ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVWload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64CMPWload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (CMPW x l:(MOVWload {sym} [off] ptr mem))
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (InvertFlags (CMPWload {sym} [off] ptr x mem))
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVWload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64InvertFlags)
		v0 := b.NewValue0(l.Pos, OpAMD64CMPWload, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, x, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPWconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)==y
	// result: (FlagEQ)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) == y) {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)<y && uint16(x)<uint16(y)
	// result: (FlagLT_ULT)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) < y && uint16(x) < uint16(y)) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)<y && uint16(x)>uint16(y)
	// result: (FlagLT_UGT)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) < y && uint16(x) > uint16(y)) {
			break
		}
		v.reset(OpAMD64FlagLT_UGT)
		return true
	}
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)>y && uint16(x)<uint16(y)
	// result: (FlagGT_ULT)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) > y && uint16(x) < uint16(y)) {
			break
		}
		v.reset(OpAMD64FlagGT_ULT)
		return true
	}
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)>y && uint16(x)>uint16(y)
	// result: (FlagGT_UGT)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) > y && uint16(x) > uint16(y)) {
			break
		}
		v.reset(OpAMD64FlagGT_UGT)
		return true
	}
	// match: (CMPWconst (ANDLconst _ [m]) [n])
	// cond: 0 <= int16(m) && int16(m) < n
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt16(v.AuxInt)
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= int16(m) && int16(m) < n) {
			break
		}
		v.reset(OpAMD64FlagLT_ULT)
		return true
	}
	// match: (CMPWconst a:(ANDL x y) [0])
	// cond: a.Uses == 1
	// result: (TESTW x y)
	for {
		if auxIntToInt16(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpAMD64ANDL {
			break
		}
		y := a.Args[1]
		x := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpAMD64TESTW)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPWconst a:(ANDLconst [c] x) [0])
	// cond: a.Uses == 1
	// result: (TESTWconst [int16(c)] x)
	for {
		if auxIntToInt16(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		x := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpAMD64TESTWconst)
		v.AuxInt = int16ToAuxInt(int16(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPWconst x [0])
	// result: (TESTW x x)
	for {
		if auxIntToInt16(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.reset(OpAMD64TESTW)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPWconst l:(MOVWload {sym} [off] ptr mem) [c])
	// cond: l.Uses == 1 && clobber(l)
	// result: @l.Block (CMPWconstload {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		c := auxIntToInt16(v.AuxInt)
		l := v_0
		if l.Op != OpAMD64MOVWload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		b = l.Block
		v0 := b.NewValue0(l.Pos, OpAMD64CMPWconstload, types.TypeFlags)
		v.copyOf(v0)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPWconstload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPWconstload [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (CMPWconstload [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
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
		v.reset(OpAMD64CMPWconstload)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (CMPWconstload [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (CMPWconstload [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
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
		v.reset(OpAMD64CMPWconstload)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPWload [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (CMPWload [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64CMPWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (CMPWload [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (CMPWload [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64CMPWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (CMPWload {sym} [off] ptr (MOVLconst [c]) mem)
	// result: (CMPWconstload {sym} [makeValAndOff(int32(int16(c)),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64CMPWconstload)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int16(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPXCHGLlock(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPXCHGLlock [off1] {sym} (ADDQconst [off2] ptr) old new_ mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (CMPXCHGLlock [off1+off2] {sym} ptr old new_ mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		old := v_1
		new_ := v_2
		mem := v_3
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64CMPXCHGLlock)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64CMPXCHGQlock(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPXCHGQlock [off1] {sym} (ADDQconst [off2] ptr) old new_ mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (CMPXCHGQlock [off1+off2] {sym} ptr old new_ mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		old := v_1
		new_ := v_2
		mem := v_3
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64CMPXCHGQlock)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64DIVSD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIVSD x l:(MOVSDload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (DIVSDload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVSDload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64DIVSDload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64DIVSDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIVSDload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (DIVSDload [off1+off2] {sym} val base mem)
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
		v.reset(OpAMD64DIVSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (DIVSDload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (DIVSDload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
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
		v.reset(OpAMD64DIVSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64DIVSS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIVSS x l:(MOVSSload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (DIVSSload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVSSload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64DIVSSload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64DIVSSload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIVSSload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (DIVSSload [off1+off2] {sym} val base mem)
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
		v.reset(OpAMD64DIVSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (DIVSSload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (DIVSSload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
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
		v.reset(OpAMD64DIVSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64HMULL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (HMULL x y)
	// cond: !x.rematerializeable() && y.rematerializeable()
	// result: (HMULL y x)
	for {
		x := v_0
		y := v_1
		if !(!x.rematerializeable() && y.rematerializeable()) {
			break
		}
		v.reset(OpAMD64HMULL)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64HMULLU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (HMULLU x y)
	// cond: !x.rematerializeable() && y.rematerializeable()
	// result: (HMULLU y x)
	for {
		x := v_0
		y := v_1
		if !(!x.rematerializeable() && y.rematerializeable()) {
			break
		}
		v.reset(OpAMD64HMULLU)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64HMULQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (HMULQ x y)
	// cond: !x.rematerializeable() && y.rematerializeable()
	// result: (HMULQ y x)
	for {
		x := v_0
		y := v_1
		if !(!x.rematerializeable() && y.rematerializeable()) {
			break
		}
		v.reset(OpAMD64HMULQ)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64HMULQU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (HMULQU x y)
	// cond: !x.rematerializeable() && y.rematerializeable()
	// result: (HMULQU y x)
	for {
		x := v_0
		y := v_1
		if !(!x.rematerializeable() && y.rematerializeable()) {
			break
		}
		v.reset(OpAMD64HMULQU)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LEAL [c] {s} (ADDLconst [d] x))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAL [c+d] {s} x)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAL)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg(x)
		return true
	}
	// match: (LEAL [c] {s} (ADDL x y))
	// cond: x.Op != OpSB && y.Op != OpSB
	// result: (LEAL1 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDL {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if !(x.Op != OpSB && y.Op != OpSB) {
				continue
			}
			v.reset(OpAMD64LEAL1)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAL1(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LEAL1 [c] {s} (ADDLconst [d] x) y)
	// cond: is32Bit(int64(c)+int64(d)) && x.Op != OpSB
	// result: (LEAL1 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64ADDLconst {
				continue
			}
			d := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			y := v_1
			if !(is32Bit(int64(c)+int64(d)) && x.Op != OpSB) {
				continue
			}
			v.reset(OpAMD64LEAL1)
			v.AuxInt = int32ToAuxInt(c + d)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAL1 [c] {s} x (SHLLconst [1] y))
	// result: (LEAL2 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLLconst || auxIntToInt8(v_1.AuxInt) != 1 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAL2)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAL1 [c] {s} x (SHLLconst [2] y))
	// result: (LEAL4 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLLconst || auxIntToInt8(v_1.AuxInt) != 2 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAL4)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAL1 [c] {s} x (SHLLconst [3] y))
	// result: (LEAL8 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLLconst || auxIntToInt8(v_1.AuxInt) != 3 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAL8)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAL2(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LEAL2 [c] {s} (ADDLconst [d] x) y)
	// cond: is32Bit(int64(c)+int64(d)) && x.Op != OpSB
	// result: (LEAL2 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(c)+int64(d)) && x.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAL2)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAL2 [c] {s} x (ADDLconst [d] y))
	// cond: is32Bit(int64(c)+2*int64(d)) && y.Op != OpSB
	// result: (LEAL2 [c+2*d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(is32Bit(int64(c)+2*int64(d)) && y.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAL2)
		v.AuxInt = int32ToAuxInt(c + 2*d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAL2 [c] {s} x (SHLLconst [1] y))
	// result: (LEAL4 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64SHLLconst || auxIntToInt8(v_1.AuxInt) != 1 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64LEAL4)
		v.AuxInt = int32ToAuxInt(c)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAL2 [c] {s} x (SHLLconst [2] y))
	// result: (LEAL8 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64SHLLconst || auxIntToInt8(v_1.AuxInt) != 2 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64LEAL8)
		v.AuxInt = int32ToAuxInt(c)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAL4(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LEAL4 [c] {s} (ADDLconst [d] x) y)
	// cond: is32Bit(int64(c)+int64(d)) && x.Op != OpSB
	// result: (LEAL4 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(c)+int64(d)) && x.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAL4)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAL4 [c] {s} x (ADDLconst [d] y))
	// cond: is32Bit(int64(c)+4*int64(d)) && y.Op != OpSB
	// result: (LEAL4 [c+4*d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(is32Bit(int64(c)+4*int64(d)) && y.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAL4)
		v.AuxInt = int32ToAuxInt(c + 4*d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAL4 [c] {s} x (SHLLconst [1] y))
	// result: (LEAL8 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64SHLLconst || auxIntToInt8(v_1.AuxInt) != 1 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64LEAL8)
		v.AuxInt = int32ToAuxInt(c)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAL8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LEAL8 [c] {s} (ADDLconst [d] x) y)
	// cond: is32Bit(int64(c)+int64(d)) && x.Op != OpSB
	// result: (LEAL8 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(c)+int64(d)) && x.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAL8)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAL8 [c] {s} x (ADDLconst [d] y))
	// cond: is32Bit(int64(c)+8*int64(d)) && y.Op != OpSB
	// result: (LEAL8 [c+8*d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(is32Bit(int64(c)+8*int64(d)) && y.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAL8)
		v.AuxInt = int32ToAuxInt(c + 8*d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAQ(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LEAQ [c] {s} (ADDQconst [d] x))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAQ [c+d] {s} x)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg(x)
		return true
	}
	// match: (LEAQ [c] {s} (ADDQ x y))
	// cond: x.Op != OpSB && y.Op != OpSB
	// result: (LEAQ1 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQ {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if !(x.Op != OpSB && y.Op != OpSB) {
				continue
			}
			v.reset(OpAMD64LEAQ1)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAQ [off1] {sym1} (LEAQ [off2] {sym2} x))
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (LEAQ [off1+off2] {mergeSym(sym1,sym2)} x)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg(x)
		return true
	}
	// match: (LEAQ [off1] {sym1} (LEAQ1 [off2] {sym2} x y))
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (LEAQ1 [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ1 {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64LEAQ1)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ [off1] {sym1} (LEAQ2 [off2] {sym2} x y))
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (LEAQ2 [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ2 {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64LEAQ2)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ [off1] {sym1} (LEAQ4 [off2] {sym2} x y))
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (LEAQ4 [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ4 {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64LEAQ4)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ [off1] {sym1} (LEAQ8 [off2] {sym2} x y))
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (LEAQ8 [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ8 {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64LEAQ8)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAQ1(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LEAQ1 [c] {s} (ADDQconst [d] x) y)
	// cond: is32Bit(int64(c)+int64(d)) && x.Op != OpSB
	// result: (LEAQ1 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64ADDQconst {
				continue
			}
			d := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			y := v_1
			if !(is32Bit(int64(c)+int64(d)) && x.Op != OpSB) {
				continue
			}
			v.reset(OpAMD64LEAQ1)
			v.AuxInt = int32ToAuxInt(c + d)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAQ1 [c] {s} x (SHLQconst [1] y))
	// result: (LEAQ2 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLQconst || auxIntToInt8(v_1.AuxInt) != 1 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAQ2)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAQ1 [c] {s} x (SHLQconst [2] y))
	// result: (LEAQ4 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLQconst || auxIntToInt8(v_1.AuxInt) != 2 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAQ4)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAQ1 [c] {s} x (SHLQconst [3] y))
	// result: (LEAQ8 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLQconst || auxIntToInt8(v_1.AuxInt) != 3 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAQ8)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAQ1 [off1] {sym1} (LEAQ [off2] {sym2} x) y)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB
	// result: (LEAQ1 [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64LEAQ {
				continue
			}
			off2 := auxIntToInt32(v_0.AuxInt)
			sym2 := auxToSym(v_0.Aux)
			x := v_0.Args[0]
			y := v_1
			if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB) {
				continue
			}
			v.reset(OpAMD64LEAQ1)
			v.AuxInt = int32ToAuxInt(off1 + off2)
			v.Aux = symToAux(mergeSym(sym1, sym2))
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAQ1 [off1] {sym1} x (LEAQ1 [off2] {sym2} y y))
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (LEAQ2 [off1+off2] {mergeSym(sym1, sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64LEAQ1 {
				continue
			}
			off2 := auxIntToInt32(v_1.AuxInt)
			sym2 := auxToSym(v_1.Aux)
			y := v_1.Args[1]
			if y != v_1.Args[0] || !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
				continue
			}
			v.reset(OpAMD64LEAQ2)
			v.AuxInt = int32ToAuxInt(off1 + off2)
			v.Aux = symToAux(mergeSym(sym1, sym2))
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (LEAQ1 [off1] {sym1} x (LEAQ1 [off2] {sym2} x y))
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (LEAQ2 [off1+off2] {mergeSym(sym1, sym2)} y x)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64LEAQ1 {
				continue
			}
			off2 := auxIntToInt32(v_1.AuxInt)
			sym2 := auxToSym(v_1.Aux)
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				y := v_1_1
				if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
					continue
				}
				v.reset(OpAMD64LEAQ2)
				v.AuxInt = int32ToAuxInt(off1 + off2)
				v.Aux = symToAux(mergeSym(sym1, sym2))
				v.AddArg2(y, x)
				return true
			}
		}
		break
	}
	// match: (LEAQ1 [0] x y)
	// cond: v.Aux == nil
	// result: (ADDQ x y)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		y := v_1
		if !(v.Aux == nil) {
			break
		}
```