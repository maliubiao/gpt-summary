Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共6部分，请归纳一下它的功能

"""
1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64FMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVDload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (FMOVDload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64FMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64FMOVDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVDstore [off] {sym} ptr (MTVSRD x) mem)
	// result: (MOVDstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MTVSRD {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVDstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (FMOVDstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (FMOVDstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64FMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVDstore [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (FMOVDstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64FMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64FMOVSload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVSload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (FMOVSload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64FMOVSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVSload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (FMOVSload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64FMOVSload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64FMOVSstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVSstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (FMOVSstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64FMOVSstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVSstore [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (FMOVSstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64FMOVSstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64FNEG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FNEG (FABS x))
	// result: (FNABS x)
	for {
		if v_0.Op != OpPPC64FABS {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64FNABS)
		v.AddArg(x)
		return true
	}
	// match: (FNEG (FNABS x))
	// result: (FABS x)
	for {
		if v_0.Op != OpPPC64FNABS {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64FABS)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64FSQRT(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FSQRT (FMOVDconst [x]))
	// cond: x >= 0
	// result: (FMOVDconst [math.Sqrt(x)])
	for {
		if v_0.Op != OpPPC64FMOVDconst {
			break
		}
		x := auxIntToFloat64(v_0.AuxInt)
		if !(x >= 0) {
			break
		}
		v.reset(OpPPC64FMOVDconst)
		v.AuxInt = float64ToAuxInt(math.Sqrt(x))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64FSUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FSUB (FMUL x y) z)
	// cond: x.Block.Func.useFMA(v)
	// result: (FMSUB x y z)
	for {
		if v_0.Op != OpPPC64FMUL {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			z := v_1
			if !(x.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpPPC64FMSUB)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64FSUBS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FSUBS (FMULS x y) z)
	// cond: x.Block.Func.useFMA(v)
	// result: (FMSUBS x y z)
	for {
		if v_0.Op != OpPPC64FMULS {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			z := v_1
			if !(x.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpPPC64FMSUBS)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64FTRUNC(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FTRUNC (FMOVDconst [x]))
	// result: (FMOVDconst [math.Trunc(x)])
	for {
		if v_0.Op != OpPPC64FMOVDconst {
			break
		}
		x := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpPPC64FMOVDconst)
		v.AuxInt = float64ToAuxInt(math.Trunc(x))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64GreaterEqual(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterEqual (FlagEQ))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (GreaterEqual (FlagLT))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (GreaterEqual (FlagGT))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (GreaterEqual (InvertFlags x))
	// result: (LessEqual x)
	for {
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64LessEqual)
		v.AddArg(x)
		return true
	}
	// match: (GreaterEqual cmp)
	// result: (SETBCR [0] cmp)
	for {
		cmp := v_0
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(cmp)
		return true
	}
}
func rewriteValuePPC64_OpPPC64GreaterThan(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterThan (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (GreaterThan (FlagLT))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (GreaterThan (FlagGT))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (GreaterThan (InvertFlags x))
	// result: (LessThan x)
	for {
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64LessThan)
		v.AddArg(x)
		return true
	}
	// match: (GreaterThan cmp)
	// result: (SETBC [1] cmp)
	for {
		cmp := v_0
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(cmp)
		return true
	}
}
func rewriteValuePPC64_OpPPC64ISEL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ISEL [6] x y (CMPconst [0] (ANDconst [1] (SETBC [c] cmp))))
	// result: (ISEL [c] x y cmp)
	for {
		if auxIntToInt32(v.AuxInt) != 6 {
			break
		}
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64CMPconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64ANDconst || auxIntToInt64(v_2_0.AuxInt) != 1 {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpPPC64SETBC {
			break
		}
		c := auxIntToInt32(v_2_0_0.AuxInt)
		cmp := v_2_0_0.Args[0]
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (ISEL [6] x y (CMPconst [0] (SETBC [c] cmp)))
	// result: (ISEL [c] x y cmp)
	for {
		if auxIntToInt32(v.AuxInt) != 6 {
			break
		}
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64CMPconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64SETBC {
			break
		}
		c := auxIntToInt32(v_2_0.AuxInt)
		cmp := v_2_0.Args[0]
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (ISEL [6] x y (CMPWconst [0] (SETBC [c] cmp)))
	// result: (ISEL [c] x y cmp)
	for {
		if auxIntToInt32(v.AuxInt) != 6 {
			break
		}
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64CMPWconst || auxIntToInt32(v_2.AuxInt) != 0 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64SETBC {
			break
		}
		c := auxIntToInt32(v_2_0.AuxInt)
		cmp := v_2_0.Args[0]
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (ISEL [6] x y (CMPconst [0] (SETBCR [c] cmp)))
	// result: (ISEL [c+4] x y cmp)
	for {
		if auxIntToInt32(v.AuxInt) != 6 {
			break
		}
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64CMPconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64SETBCR {
			break
		}
		c := auxIntToInt32(v_2_0.AuxInt)
		cmp := v_2_0.Args[0]
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(c + 4)
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (ISEL [6] x y (CMPWconst [0] (SETBCR [c] cmp)))
	// result: (ISEL [c+4] x y cmp)
	for {
		if auxIntToInt32(v.AuxInt) != 6 {
			break
		}
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64CMPWconst || auxIntToInt32(v_2.AuxInt) != 0 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64SETBCR {
			break
		}
		c := auxIntToInt32(v_2_0.AuxInt)
		cmp := v_2_0.Args[0]
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(c + 4)
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (ISEL [2] x _ (FlagEQ))
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 2 {
			break
		}
		x := v_0
		if v_2.Op != OpPPC64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ISEL [2] _ y (FlagLT))
	// result: y
	for {
		if auxIntToInt32(v.AuxInt) != 2 {
			break
		}
		y := v_1
		if v_2.Op != OpPPC64FlagLT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ISEL [2] _ y (FlagGT))
	// result: y
	for {
		if auxIntToInt32(v.AuxInt) != 2 {
			break
		}
		y := v_1
		if v_2.Op != OpPPC64FlagGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ISEL [6] _ y (FlagEQ))
	// result: y
	for {
		if auxIntToInt32(v.AuxInt) != 6 {
			break
		}
		y := v_1
		if v_2.Op != OpPPC64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ISEL [6] x _ (FlagLT))
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 6 {
			break
		}
		x := v_0
		if v_2.Op != OpPPC64FlagLT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ISEL [6] x _ (FlagGT))
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 6 {
			break
		}
		x := v_0
		if v_2.Op != OpPPC64FlagGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ISEL [0] _ y (FlagEQ))
	// result: y
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		y := v_1
		if v_2.Op != OpPPC64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ISEL [0] _ y (FlagGT))
	// result: y
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		y := v_1
		if v_2.Op != OpPPC64FlagGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ISEL [0] x _ (FlagLT))
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		if v_2.Op != OpPPC64FlagLT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ISEL [5] _ x (FlagEQ))
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 5 {
			break
		}
		x := v_1
		if v_2.Op != OpPPC64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ISEL [5] _ x (FlagLT))
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 5 {
			break
		}
		x := v_1
		if v_2.Op != OpPPC64FlagLT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ISEL [5] y _ (FlagGT))
	// result: y
	for {
		if auxIntToInt32(v.AuxInt) != 5 {
			break
		}
		y := v_0
		if v_2.Op != OpPPC64FlagGT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ISEL [1] _ y (FlagEQ))
	// result: y
	for {
		if auxIntToInt32(v.AuxInt) != 1 {
			break
		}
		y := v_1
		if v_2.Op != OpPPC64FlagEQ {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ISEL [1] _ y (FlagLT))
	// result: y
	for {
		if auxIntToInt32(v.AuxInt) != 1 {
			break
		}
		y := v_1
		if v_2.Op != OpPPC64FlagLT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ISEL [1] x _ (FlagGT))
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 1 {
			break
		}
		x := v_0
		if v_2.Op != OpPPC64FlagGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ISEL [4] x _ (FlagEQ))
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 4 {
			break
		}
		x := v_0
		if v_2.Op != OpPPC64FlagEQ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ISEL [4] x _ (FlagGT))
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 4 {
			break
		}
		x := v_0
		if v_2.Op != OpPPC64FlagGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ISEL [4] _ y (FlagLT))
	// result: y
	for {
		if auxIntToInt32(v.AuxInt) != 4 {
			break
		}
		y := v_1
		if v_2.Op != OpPPC64FlagLT {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ISEL [n] x y (InvertFlags bool))
	// cond: n%4 == 0
	// result: (ISEL [n+1] x y bool)
	for {
		n := auxIntToInt32(v.AuxInt)
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_2.Args[0]
		if !(n%4 == 0) {
			break
		}
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(n + 1)
		v.AddArg3(x, y, bool)
		return true
	}
	// match: (ISEL [n] x y (InvertFlags bool))
	// cond: n%4 == 1
	// result: (ISEL [n-1] x y bool)
	for {
		n := auxIntToInt32(v.AuxInt)
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_2.Args[0]
		if !(n%4 == 1) {
			break
		}
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(n - 1)
		v.AddArg3(x, y, bool)
		return true
	}
	// match: (ISEL [n] x y (InvertFlags bool))
	// cond: n%4 == 2
	// result: (ISEL [n] x y bool)
	for {
		n := auxIntToInt32(v.AuxInt)
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_2.Args[0]
		if !(n%4 == 2) {
			break
		}
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg3(x, y, bool)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64LessEqual(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessEqual (FlagEQ))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (LessEqual (FlagLT))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (LessEqual (FlagGT))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (LessEqual (InvertFlags x))
	// result: (GreaterEqual x)
	for {
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64GreaterEqual)
		v.AddArg(x)
		return true
	}
	// match: (LessEqual cmp)
	// result: (SETBCR [1] cmp)
	for {
		cmp := v_0
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(cmp)
		return true
	}
}
func rewriteValuePPC64_OpPPC64LessThan(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessThan (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (LessThan (FlagLT))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (LessThan (FlagGT))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (LessThan (InvertFlags x))
	// result: (GreaterThan x)
	for {
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64GreaterThan)
		v.AddArg(x)
		return true
	}
	// match: (LessThan cmp)
	// result: (SETBC [0] cmp)
	for {
		cmp := v_0
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(cmp)
		return true
	}
}
func rewriteValuePPC64_OpPPC64MFVSRD(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MFVSRD (FMOVDconst [c]))
	// result: (MOVDconst [int64(math.Float64bits(c))])
	for {
		if v_0.Op != OpPPC64FMOVDconst {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(math.Float64bits(c)))
		return true
	}
	// match: (MFVSRD x:(FMOVDload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVDload [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpPPC64FMOVDload {
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
		v0 := b.NewValue0(x.Pos, OpPPC64MOVDload, typ.Int64)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVBZload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBZload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVBZload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVBZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBZload [off1] {sym} (ADDconst [off2] x) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVBZload [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVBZload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVBZload [0] {sym} p:(ADD ptr idx) mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVBZloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		mem := v_1
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVBZloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVBZloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBZloadidx ptr (MOVDconst [c]) mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVBZload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVBZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBZloadidx (MOVDconst [c]) ptr mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVBZload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVBZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVBZreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVBZreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0xFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0xFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVBZreg (SRWconst [c] (MOVBZreg x)))
	// result: (SRWconst [c] (MOVBZreg x))
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVBZreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVBZreg (SRWconst [c] x))
	// cond: x.Type.Size() == 8
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() == 8) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg (SRDconst [c] x))
	// cond: c>=56
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 56) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg (SRWconst [c] x))
	// cond: c>=24
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 24) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg y:(MOVBZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVBZreg (MOVBreg x))
	// result: (MOVBZreg x)
	for {
		if v_0.Op != OpPPC64MOVBreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64MOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg (SRWconst x [s]))
	// cond: mergePPC64AndSrwi(0xFF,s) != 0
	// result: (RLWINM [mergePPC64AndSrwi(0xFF,s)] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		s := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64AndSrwi(0xFF, s) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndSrwi(0xFF, s))
		v.AddArg(x)
		return true
	}
	// match: (MOVBZreg (RLWINM [r] y))
	// cond: mergePPC64AndRlwinm(0xFF,r) != 0
	// result: (RLWINM [mergePPC64AndRlwinm(0xFF,r)] y)
	for {
		if v_0.Op != OpPPC64RLWINM {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if !(mergePPC64AndRlwinm(0xFF, r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndRlwinm(0xFF, r))
		v.AddArg(y)
		return true
	}
	// match: (MOVBZreg (OR <t> x (MOVWZreg y)))
	// result: (MOVBZreg (OR <t> x y))
	for {
		if v_0.Op != OpPPC64OR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVWZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVBZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64OR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVBZreg (XOR <t> x (MOVWZreg y)))
	// result: (MOVBZreg (XOR <t> x y))
	for {
		if v_0.Op != OpPPC64XOR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVWZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVBZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64XOR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVBZreg (AND <t> x (MOVWZreg y)))
	// result: (MOVBZreg (AND <t> x y))
	for {
		if v_0.Op != OpPPC64AND {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVWZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVBZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64AND, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVBZreg (OR <t> x (MOVHZreg y)))
	// result: (MOVBZreg (OR <t> x y))
	for {
		if v_0.Op != OpPPC64OR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVHZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVBZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64OR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVBZreg (XOR <t> x (MOVHZreg y)))
	// result: (MOVBZreg (XOR <t> x y))
	for {
		if v_0.Op != OpPPC64XOR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVHZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVBZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64XOR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVBZreg (AND <t> x (MOVHZreg y)))
	// result: (MOVBZreg (AND <t> x y))
	for {
		if v_0.Op != OpPPC64AND {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVHZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVBZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64AND, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVBZreg (OR <t> x (MOVBZreg y)))
	// result: (MOVBZreg (OR <t> x y))
	for {
		if v_0.Op != OpPPC64OR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVBZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVBZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64OR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVBZreg (XOR <t> x (MOVBZreg y)))
	// result: (MOVBZreg (XOR <t> x y))
	for {
		if v_0.Op != OpPPC64XOR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVBZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVBZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64XOR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVBZreg (AND <t> x (MOVBZreg y)))
	// result: (MOVBZreg (AND <t> x y))
	for {
		if v_0.Op != OpPPC64AND {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVBZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVBZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64AND, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVBZreg z:(ANDconst [c] (MOVBZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		z_0 := z.Args[0]
		if z_0.Op != OpPPC64MOVBZload {
			break
		}
		v.copyOf(z)
		return true
	}
	// match: (MOVBZreg z:(AND y (MOVBZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64AND {
			break
		}
		_ = z.Args[1]
		z_0 := z.Args[0]
		z_1 := z.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
			if z_1.Op != OpPPC64MOVBZload {
				continue
			}
			v.copyOf(z)
			return true
		}
		break
	}
	// match: (MOVBZreg x:(MOVBZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBZreg x:(MOVBZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBZreg x:(Select0 (LoweredAtomicLoad8 _ _)))
	// result: x
	for {
		x := v_0
		if x.Op != OpSelect0 {
			break
		}
		x_0 := x.Args[0]
		if x_0.Op != OpPPC64LoweredAtomicLoad8 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBZreg x:(Arg <t>))
	// cond: is8BitInt(t) && !t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(is8BitInt(t) && !t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBZreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint8(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVBreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0x7F
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0x7F) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVBreg (SRAWconst [c] (MOVBreg x)))
	// result: (SRAWconst [c] (MOVBreg x))
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVBreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVBreg (SRAWconst [c] x))
	// cond: x.Type.Size() == 8
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() == 8) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SRDconst [c] x))
	// cond: c>56
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > 56) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SRDconst [c] x))
	// cond: c==56
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c == 56) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SRADconst [c] x))
	// cond: c>=56
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRADconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 56) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SRWconst [c] x))
	// cond: c>24
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > 24) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SRWconst [c] x))
	// cond: c==24
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c == 24) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SRAWconst [c] x))
	// cond: c>=24
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 24) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg y:(MOVBreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVBreg (MOVBZreg x))
	// result: (MOVBreg x)
	for {
		if v_0.Op != OpPPC64MOVBZreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64MOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg x:(Arg <t>))
	// cond: is8BitInt(t) && t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(is8BitInt(t) && t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int8(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int8(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVBstore [off1] {sym} (ADDconst [off2] x) val mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVBstore [off1+int32(off2)] {sym} x val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(x, val, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVBstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVBstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpPPC64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstore [0] {sym} p:(ADD ptr idx) val mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVBstoreidx ptr idx val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVBstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVBreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVBstore)
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
		if v_1.Op != OpPPC64MOVBZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVHZreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVWZreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (SRWconst (MOVHreg x) [c]) mem)
	// cond: c <= 8
	// result: (MOVBstore [off] {sym} ptr (SRWconst <typ.UInt32> x [c]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpPPC64MOVHreg {
			break
		}
		x := v_1_0.Args[0]
		mem := v_2
		if !(c <= 8) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpPPC64SRWconst, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (SRWconst (MOVHZreg x) [c]) mem)
	// cond: c <= 8
	// result: (MOVBstore [off] {sym} ptr (SRWconst <typ.UInt32> x [c]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_1_0.Args[0]
		mem := v_2
		if !(c <= 8) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpPPC64SRWconst, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (SRWconst (MOVWreg x) [c]) mem)
	// cond: c <= 24
	// result: (MOVBstore [off] {sym} ptr (SRWconst <typ.UInt32> x [c]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpPPC64MOVWreg {
			break
		}
		x := v_1_0.Args[0]
		mem := v_2
		if !(c <= 24) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpPPC64SRWconst, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (SRWconst (MOVWZreg x) [c]) mem)
	// cond: c <= 24
	// result: (MOVBstore [off] {sym} ptr (SRWconst <typ.UInt32> x [c]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_1_0.Args[0]
		mem := v_2
		if !(c <= 24) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpPPC64SRWconst, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVBstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVBstoreidx ptr (MOVDconst [c]) val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVBstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstoreidx (MOVDconst [c]) ptr val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVBstore [int32(c)] ptr val mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		val := v_2
		mem := v_3
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVBreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVBreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVBZreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVBZreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVHreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVHreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVHZreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVWreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVWZreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (SRWconst (MOVHreg x) [c]) mem)
	// cond: c <= 8
	// result: (MOVBstoreidx ptr idx (SRWconst <typ.UInt32> x [c]) mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64MOVHreg {
			break
		}
		x := v_2_0.Args[0]
		mem := v_3
		if !(c <= 8) {
			break
		}
		v.reset(OpPPC64MOVBstoreidx)
		v0 := b.NewValue0(v.Pos, OpPPC64SRWconst, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg4(ptr, idx, v0, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (SRWconst (MOVHZreg x) [c]) mem)
	// cond: c <= 8
	// result: (MOVBstoreidx ptr idx (SRWconst <typ.UInt32> x [c]) mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_2_0.Args[0]
		mem := v_3
		if !(c <= 8) {
			break
		}
		v.reset(OpPPC64MOVBstoreidx)
		v0 := b.NewValue0(v.Pos, OpPPC64SRWconst, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg4(ptr, idx, v0, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (SRWconst (MOVWreg x) [c]) mem)
	// cond: c <= 24
	// result: (MOVBstoreidx ptr idx (SRWconst <typ.UInt32> x [c]) mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64MOVWreg {
			break
		}
		x := v_2_0.Args[0]
		mem := v_3
		if !(c <= 24) {
			break
		}
		v.reset(OpPPC64MOVBstoreidx)
		v0 := b.NewValue0(v.Pos, OpPPC64SRWconst, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg4(ptr, idx, v0, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (SRWconst (MOVWZreg x) [c]) mem)
	// cond: c <= 24
	// result: (MOVBstoreidx ptr idx (SRWconst <typ.UInt32> x [c]) mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_2_0.Args[0]
		mem := v_3
		if !(c <= 24) {
			break
		}
		v.reset(OpPPC64MOVBstoreidx)
		v0 := b.NewValue0(v.Pos, OpPPC64SRWconst, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg4(ptr, idx, v0, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVBstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstorezero [off1] {sym} (ADDconst [off2] x) mem)
	// cond: ((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1)+off2)))
	// result: (MOVBstorezero [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1) + off2))) {
			break
		}
		v.reset(OpPPC64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVBstorezero [off1] {sym1} p:(MOVDaddr [off2] {sym2} x) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVBstorezero [off1+off2] {mergeSym(sym1,sym2)} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		x := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVDaddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVDaddr {sym} [n] p:(ADD x y))
	// cond: sym == nil && n == 0
	// result: p
	for {
		n := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		if !(sym == nil && n == 0) {
			break
		}
		v.copyOf(p)
		return true
	}
	// match: (MOVDaddr {sym} [n] ptr)
	// cond: sym == nil && n == 0 && (ptr.Op == OpArgIntReg || ptr.Op == OpPhi)
	// result: ptr
	for {
		n := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if !(sym == nil && n == 0 && (ptr.Op == OpArgIntReg || ptr.Op == OpPhi)) {
			break
		}
		v.copyOf(ptr)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDload [off] {sym} ptr (FMOVDstore [off] {sym} ptr x _))
	// result: (MFVSRD x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64FMOVDstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpPPC64MFVSRD)
		v.AddArg(x)
		return true
	}
	// match: (MOVDload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVDload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off1] {sym} (ADDconst [off2] x) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVDload [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVDload [0] {sym} p:(ADD ptr idx) mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVDloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		mem := v_1
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVDloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVDloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDloadidx ptr (MOVDconst [c]) mem)
	// cond: ((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVDload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVDload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDloadidx (MOVDconst [c]) ptr mem)
	// cond: ((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVDload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVDload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVDstore [off] {sym} ptr (MFVSRD x) mem)
	// result: (FMOVDstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MFVSRD {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64FMOVDstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym} (ADDconst [off2] x) val mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVDstore [off1+int32(off2)] {sym} x val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(x, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVDstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVDstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpPPC64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDstore [0] {sym} p:(ADD ptr idx) val mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVDstoreidx ptr idx val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVDstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} ptr r:(BRD val) mem)
	// cond: r.Uses == 1
	// result: (MOVDBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		r := v_1
		if r.Op != OpPPC64BRD {
			break
		}
		val := r.Args[0]
		mem := v_2
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVDBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} ptr (Bswap64 val) mem)
	// result: (MOVDBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpBswap64 {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVDBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVDstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstoreidx ptr (MOVDconst [c]) val mem)
	// cond: ((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVDstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstoreidx (MOVDconst [c]) ptr val mem)
	// cond: ((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVDstore [int32(c)] ptr val mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		val := v_2
		mem := v_3
		if !((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstoreidx ptr idx r:(BRD val) mem)
	// cond: r.Uses == 1
	// result: (MOVDBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		r := v_2
		if r.Op != OpPPC64BRD {
			break
		}
		val := r.Args[0]
		mem := v_3
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVDBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVDstoreidx ptr idx (Bswap64 val) mem)
	// result: (MOVDBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpBswap64 {
			break
		}
		val := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVDBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVDstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstorezero [off1] {sym} (ADDconst [off2] x) mem)
	// cond: ((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1)+off2)))
	// result: (MOVDstorezero [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1) + off2))) {
			break
		}
		v.reset(OpPPC64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVDstorezero [off1] {sym1} p:(MOVDaddr [off2] {sym2} x) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVDstorezero [off1+off2] {mergeSym(sym1,sym2)} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		x := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHBRstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHBRstore ptr (MOVHreg x) mem)
	// result: (MOVHBRstore ptr x mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHBRstore)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHBRstore ptr (MOVHZreg x) mem)
	// result: (MOVHBRstore ptr x mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHBRstore)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHBRstore ptr (MOVWreg x) mem)
	// result: (MOVHBRstore ptr x mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHBRstore)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHBRstore ptr (MOVWZreg x) mem)
	// result: (MOVHBRstore ptr x mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHBRstore)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHZload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHZload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVHZload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVHZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHZload [off1] {sym} (ADDconst [off2] x) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVHZload [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVHZload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVHZload [0] {sym} p:(ADD ptr idx) mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVHZloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		mem := v_1
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVHZloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHZloadidx(v *V
"""




```