Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第5部分，共10部分，请归纳一下它的功能

"""
ARM64_OpARM64MOVHstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHstorezero [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstorezero [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHstorezero [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstorezero [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHstorezeroidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVHstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHstorezero [off] {sym} (ADDshiftLL [1] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHstorezeroidx2 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVHstorezeroidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHstorezeroidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstorezeroidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVHstorezero [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstorezeroidx (MOVDconst [c]) idx mem)
	// cond: is32Bit(c)
	// result: (MOVHstorezero [int32(c)] idx mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(idx, mem)
		return true
	}
	// match: (MOVHstorezeroidx ptr (SLLconst [1] idx) mem)
	// result: (MOVHstorezeroidx2 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVHstorezeroidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHstorezeroidx ptr (ADD idx idx) mem)
	// result: (MOVHstorezeroidx2 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64ADD {
			break
		}
		idx := v_1.Args[1]
		if idx != v_1.Args[0] {
			break
		}
		mem := v_2
		v.reset(OpARM64MOVHstorezeroidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHstorezeroidx (SLLconst [1] idx) ptr mem)
	// result: (MOVHstorezeroidx2 ptr idx mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARM64MOVHstorezeroidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHstorezeroidx (ADD idx idx) ptr mem)
	// result: (MOVHstorezeroidx2 ptr idx mem)
	for {
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		if idx != v_0.Args[0] {
			break
		}
		ptr := v_1
		mem := v_2
		v.reset(OpARM64MOVHstorezeroidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHstorezeroidx2(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstorezeroidx2 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<1)
	// result: (MOVHstorezero [int32(c<<1)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 1)) {
			break
		}
		v.reset(OpARM64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(int32(c << 1))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVQstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVQstorezero [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVQstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVQstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQstorezero [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVQstorezero [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVQstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWUload [off] {sym} ptr (FMOVSstore [off] {sym} ptr val _))
	// result: (FMOVSfpgp val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64FMOVSstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpARM64FMOVSfpgp)
		v.AddArg(val)
		return true
	}
	// match: (MOVWUload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWUload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVWUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWUload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWUloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVWUloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWUload [off] {sym} (ADDshiftLL [2] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWUloadidx4 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVWUloadidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWUload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWUload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVWUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWUload [off] {sym} ptr (MOVWstorezero [off2] {sym2} ptr2 _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVDconst [0])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVWstorezero {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVWUload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVDconst [int64(read32(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(read32(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWUloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWUloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVWUload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWUloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVWUload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWUloadidx ptr (SLLconst [2] idx) mem)
	// result: (MOVWUloadidx4 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 2 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVWUloadidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWUloadidx (SLLconst [2] idx) ptr mem)
	// result: (MOVWUloadidx4 ptr idx mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARM64MOVWUloadidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWUloadidx ptr idx (MOVWstorezeroidx ptr2 idx2 _))
	// cond: (isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2))
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWstorezeroidx {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWUloadidx4(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWUloadidx4 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<2)
	// result: (MOVWUload [int32(c)<<2] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 2)) {
			break
		}
		v.reset(OpARM64MOVWUload)
		v.AuxInt = int32ToAuxInt(int32(c) << 2)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWUloadidx4 ptr idx (MOVWstorezeroidx4 ptr2 idx2 _))
	// cond: isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWstorezeroidx4 {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWUreg (ANDconst [c] x))
	// result: (ANDconst [c&(1<<32-1)] x)
	for {
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(c & (1<<32 - 1))
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint32(c))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	// match: (MOVWUreg x)
	// cond: v.Type.Size() <= 4
	// result: x
	for {
		x := v_0
		if !(v.Type.Size() <= 4) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWUreg (SLLconst [lc] x))
	// cond: lc >= 32
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		if !(lc >= 32) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVWUreg (SLLconst [lc] x))
	// cond: lc < 32
	// result: (UBFIZ [armBFAuxInt(lc, 32-lc)] x)
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < 32) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, 32-lc))
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg (SRLconst [rc] x))
	// cond: rc < 32
	// result: (UBFX [armBFAuxInt(rc, 32)] x)
	for {
		if v_0.Op != OpARM64SRLconst {
			break
		}
		rc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(rc < 32) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 32))
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg (UBFX [bfc] x))
	// cond: bfc.width() <= 32
	// result: (UBFX [bfc] x)
	for {
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(bfc.width() <= 32) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVWloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWload [off] {sym} (ADDshiftLL [2] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWloadidx4 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVWloadidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off] {sym} ptr (MOVWstorezero [off2] {sym2} ptr2 _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVDconst [0])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVWstorezero {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVWload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVWload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWloadidx ptr (SLLconst [2] idx) mem)
	// result: (MOVWloadidx4 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 2 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVWloadidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWloadidx (SLLconst [2] idx) ptr mem)
	// result: (MOVWloadidx4 ptr idx mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARM64MOVWloadidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWloadidx ptr idx (MOVWstorezeroidx ptr2 idx2 _))
	// cond: (isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2))
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWstorezeroidx {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWloadidx4(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWloadidx4 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<2)
	// result: (MOVWload [int32(c)<<2] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 2)) {
			break
		}
		v.reset(OpARM64MOVWload)
		v.AuxInt = int32ToAuxInt(int32(c) << 2)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWloadidx4 ptr idx (MOVWstorezeroidx4 ptr2 idx2 _))
	// cond: isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWstorezeroidx4 {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int32(c))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(c)))
		return true
	}
	// match: (MOVWreg x)
	// cond: v.Type.Size() <= 4
	// result: x
	for {
		x := v_0
		if !(v.Type.Size() <= 4) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg <t> (ANDconst x [c]))
	// cond: uint64(c) & uint64(0xffffffff80000000) == 0
	// result: (ANDconst <t> x [c])
	for {
		t := v.Type
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(uint64(c)&uint64(0xffffffff80000000) == 0) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (SLLconst [lc] x))
	// cond: lc < 32
	// result: (SBFIZ [armBFAuxInt(lc, 32-lc)] x)
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < 32) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, 32-lc))
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (SBFX [bfc] x))
	// cond: bfc.width() <= 32
	// result: (SBFX [bfc] x)
	for {
		if v_0.Op != OpARM64SBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(bfc.width() <= 32) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWstore [off] {sym} ptr (FMOVSfpgp val) mem)
	// result: (FMOVSstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64FMOVSfpgp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64FMOVSstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} (ADD ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVWstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} (ADDshiftLL [2] ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWstoreidx4 ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVWstoreidx4)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVWstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpARM64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWUreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreidx ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVWstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstoreidx (MOVDconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVWstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr (SLLconst [2] idx) val mem)
	// result: (MOVWstoreidx4 ptr idx val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 2 {
			break
		}
		idx := v_1.Args[0]
		val := v_2
		mem := v_3
		v.reset(OpARM64MOVWstoreidx4)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx (SLLconst [2] idx) ptr val mem)
	// result: (MOVWstoreidx4 ptr idx val mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARM64MOVWstoreidx4)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (MOVDconst [0]) mem)
	// result: (MOVWstorezeroidx ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpARM64MOVWstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (MOVWreg x) mem)
	// result: (MOVWstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVWstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (MOVWUreg x) mem)
	// result: (MOVWstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWUreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVWstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWstoreidx4(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreidx4 ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c<<2)
	// result: (MOVWstore [int32(c)<<2] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c << 2)) {
			break
		}
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(int32(c) << 2)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstoreidx4 ptr idx (MOVDconst [0]) mem)
	// result: (MOVWstorezeroidx4 ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpARM64MOVWstorezeroidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWstoreidx4 ptr idx (MOVWreg x) mem)
	// result: (MOVWstoreidx4 ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVWstoreidx4)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVWstoreidx4 ptr idx (MOVWUreg x) mem)
	// result: (MOVWstoreidx4 ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWUreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVWstoreidx4)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWstorezero [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstorezero [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWstorezero [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstorezero [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWstorezeroidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVWstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWstorezero [off] {sym} (ADDshiftLL [2] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWstorezeroidx4 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVWstorezeroidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWstorezeroidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstorezeroidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVWstorezero [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstorezeroidx (MOVDconst [c]) idx mem)
	// cond: is32Bit(c)
	// result: (MOVWstorezero [int32(c)] idx mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(idx, mem)
		return true
	}
	// match: (MOVWstorezeroidx ptr (SLLconst [2] idx) mem)
	// result: (MOVWstorezeroidx4 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 2 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVWstorezeroidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWstorezeroidx (SLLconst [2] idx) ptr mem)
	// result: (MOVWstorezeroidx4 ptr idx mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARM64MOVWstorezeroidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVWstorezeroidx4(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstorezeroidx4 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<2)
	// result: (MOVWstorezero [int32(c<<2)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 2)) {
			break
		}
		v.reset(OpARM64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(int32(c << 2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MSUB(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MSUB a x (MOVDconst [-1]))
	// result: (ADD a x)
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != -1 {
			break
		}
		v.reset(OpARM64ADD)
		v.AddArg2(a, x)
		return true
	}
	// match: (MSUB a _ (MOVDconst [0]))
	// result: a
	for {
		a := v_0
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		v.copyOf(a)
		return true
	}
	// match: (MSUB a x (MOVDconst [1]))
	// result: (SUB a x)
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 1 {
			break
		}
		v.reset(OpARM64SUB)
		v.AddArg2(a, x)
		return true
	}
	// match: (MSUB a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (SUBshiftLL a x [log64(c)])
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c))
		v.AddArg2(a, x)
		return true
	}
	// match: (MSUB a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c-1) && c>=3
	// result: (SUB a (ADDshiftLL <x.Type> x x [log64(c-1)]))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(isPowerOfTwo(c-1) && c >= 3) {
			break
		}
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(log64(c - 1))
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c+1) && c>=7
	// result: (ADD a (SUBshiftLL <x.Type> x x [log64(c+1)]))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(isPowerOfTwo(c+1) && c >= 7) {
			break
		}
		v.reset(OpARM64ADD)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(log64(c + 1))
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a x (MOVDconst [c]))
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (ADDshiftLL a (SUBshiftLL <x.Type> x x [2]) [log64(c/3)])
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(c%3 == 0 && isPowerOfTwo(c/3)) {
			break
		}
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 3))
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(2)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a x (MOVDconst [c]))
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (SUBshiftLL a (ADDshiftLL <x.Type> x x [2]) [log64(c/5)])
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(c%5 == 0 && isPowerOfTwo(c/5)) {
			break
		}
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 5))
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(2)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a x (MOVDconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (ADDshiftLL a (SUBshiftLL <x.Type> x x [3]) [log64(c/7)])
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(c%7 == 0 && isPowerOfTwo(c/7)) {
			break
		}
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 7))
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(3)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a x (MOVDconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (SUBshiftLL a (ADDshiftLL <x.Type> x x [3]) [log64(c/9)])
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(c%9 == 0 && isPowerOfTwo(c/9)) {
			break
		}
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 9))
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(3)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a (MOVDconst [-1]) x)
	// result: (ADD a x)
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != -1 {
			break
		}
		x := v_2
		v.reset(OpARM64ADD)
		v.AddArg2(a, x)
		return true
	}
	// match: (MSUB a (MOVDconst [0]) _)
	// result: a
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(a)
		return true
	}
	// match: (MSUB a (MOVDconst [1]) x)
	// result: (SUB a x)
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		x := v_2
		v.reset(OpARM64SUB)
		v.AddArg2(a, x)
		return true
	}
	// match: (MSUB a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c)
	// result: (SUBshiftLL a x [log64(c)])
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c))
		v.AddArg2(a, x)
		return true
	}
	// match: (MSUB a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c-1) && c>=3
	// result: (SUB a (ADDshiftLL <x.Type> x x [log64(c-1)]))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(isPowerOfTwo(c-1) && c >= 3) {
			break
		}
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(log64(c - 1))
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c+1) && c>=7
	// result: (ADD a (SUBshiftLL <x.Type> x x [log64(c+1)]))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(isPowerOfTwo(c+1) && c >= 7) {
			break
		}
		v.reset(OpARM64ADD)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(log64(c + 1))
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a (MOVDconst [c]) x)
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (ADDshiftLL a (SUBshiftLL <x.Type> x x [2]) [log64(c/3)])
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(c%3 == 0 && isPowerOfTwo(c/3)) {
			break
		}
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 3))
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(2)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a (MOVDconst [c]) x)
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (SUBshiftLL a (ADDshiftLL <x.Type> x x [2]) [log64(c/5)])
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(c%5 == 0 && isPowerOfTwo(c/5)) {
			break
		}
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 5))
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(2)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a (MOVDconst [c]) x)
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (ADDshiftLL a (SUBshiftLL <x.Type> x x [3]) [log64(c/7)])
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(c%7 == 0 && isPowerOfTwo(c/7)) {
			break
		}
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 7))
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(3)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB a (MOVDconst [c]) x)
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (SUBshiftLL a (ADDshiftLL <x.Type> x x [3]) [log64(c/9)])
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(c%9 == 0 && isPowerOfTwo(c/9)) {
			break
		}
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 9))
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(3)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MSUB (MOVDconst [c]) x y)
	// result: (ADDconst [c] (MNEG <x.Type> x y))
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64MNEG, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (MSUB a (MOVDconst [c]) (MOVDconst [d]))
	// result: (SUBconst [c*d] a)
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_2.AuxInt)
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c * d)
		v.AddArg(a)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MSUBW(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MSUBW a x (MOVDconst [c]))
	// cond: int32(c)==-1
	// result: (MOVWUreg (ADD <a.Type> a x))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(int32(c) == -1) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64ADD, a.Type)
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a _ (MOVDconst [c]))
	// cond: int32(c)==0
	// result: (MOVWUreg a)
	for {
		a := v_0
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(int32(c) == 0) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v.AddArg(a)
		return true
	}
	// match: (MSUBW a x (MOVDconst [c]))
	// cond: int32(c)==1
	// result: (MOVWUreg (SUB <a.Type> a x))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(int32(c) == 1) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, a.Type)
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a x [log64(c)]))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c))
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c-1) && int32(c)>=3
	// result: (MOVWUreg (SUB <a.Type> a (ADDshiftLL <x.Type> x x [log64(c-1)])))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(isPowerOfTwo(c-1) && int32(c) >= 3) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, a.Type)
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(log64(c - 1))
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c+1) && int32(c)>=7
	// result: (MOVWUreg (ADD <a.Type> a (SUBshiftLL <x.Type> x x [log64(c+1)])))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(isPowerOfTwo(c+1) && int32(c) >= 7) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64ADD, a.Type)
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(log64(c + 1))
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a x (MOVDconst [c]))
	// cond: c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a (SUBshiftLL <x.Type> x x [2]) [log64(c/3)]))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 3))
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a x (MOVDconst [c]))
	// cond: c%5 == 0 && isPowerOfTwo(c/5) && is32Bit(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a (ADDshiftLL <x.Type> x x [2]) [log64(c/5)]))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(c%5 == 0 && isPowerOfTwo(c/5) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 5))
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a x (MOVDconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a (SUBshiftLL <x.Type> x x [3]) [log64(c/7)]))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 7))
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a x (MOVDconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a (ADDshiftLL <x.Type> x x [3]) [log64(c/9)]))
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_2.AuxInt)
		if !(c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 9))
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) x)
	// cond: int32(c)==-1
	// result: (MOVWUreg (ADD <a.Type> a x))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(int32(c) == -1) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64ADD, a.Type)
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) _)
	// cond: int32(c)==0
	// result: (MOVWUreg a)
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(int32(c) == 0) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v.AddArg(a)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) x)
	// cond: int32(c)==1
	// result: (MOVWUreg (SUB <a.Type> a x))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(int32(c) == 1) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, a.Type)
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a x [log64(c)]))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c))
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c-1) && int32(c)>=3
	// result: (MOVWUreg (SUB <a.Type> a (ADDshiftLL <x.Type> x x [log64(c-1)])))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(isPowerOfTwo(c-1) && int32(c) >= 3) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, a.Type)
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(log64(c - 1))
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c+1) && int32(c)>=7
	// result: (MOVWUreg (ADD <a.Type> a (SUBshiftLL <x.Type> x x [log64(c+1)])))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(isPowerOfTwo(c+1) && int32(c) >= 7) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64ADD, a.Type)
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(log64(c + 1))
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) x)
	// cond: c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a (SUBshiftLL <x.Type> x x [2]) [log64(c/3)]))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 3))
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) x)
	// cond: c%5 == 0 && isPowerOfTwo(c/5) && is32Bit(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a (ADDshiftLL <x.Type> x x [2]) [log64(c/5)]))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(c%5 == 0 && isPowerOfTwo(c/5) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 5))
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) x)
	// cond: c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a (SUBshiftLL <x.Type> x x [3]) [log64(c/7)]))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 7))
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) x)
	// cond: c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a (ADDshiftLL <x.Type> x x [3]) [log64(c/9)]))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		x := v_2
		if !(c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 9))
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW (MOVDconst [c]) x y)
	// result: (MOVWUreg (ADDconst <x.Type> [c] (MNEGW <x.Type> x y)))
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64ADDconst, x.Type)
		v0.AuxInt = int64ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARM64MNEGW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (MSUBW a (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVWUreg (SUBconst <a.Type> [c*d] a))
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if v_2.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_2.AuxInt)
		v.reset(OpARM64MOVWUreg)
		v0 := b.NewValue0(v.Pos, OpARM64SUBconst, a.Type)
		v0.AuxInt = int64ToAuxInt(c * d)
		v0.AddArg(a)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MUL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MUL (NEG x) y)
	// result: (MNEG x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64NEG {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			v.reset(OpARM64MNEG)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (MUL x (MOVDconst [-1]))
	// result: (NEG x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != -1 {
				continue
			}
			v.reset(OpARM64NEG)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MUL _ (MOVDconst [0]))
	// result: (MOVDconst [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
				continue
			}
			v.reset(OpARM64MOVDconst)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (MUL x (MOVDconst [1]))
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (MUL x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (SLLconst [log64(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpARM64SLLconst)
			v.AuxInt = int64ToAuxInt(log64(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MUL x (MOVDconst [c]))
	// cond: isPowerOfTwo(c-1) && c >= 3
	// result: (ADDshiftLL x x [log64(c-1)])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isPowerOfTwo(c-1) && c >= 3) {
				continue
			}
			v.reset(OpARM64ADDshiftLL)
			v.AuxInt = int64ToAuxInt(log64(c - 1))
			v.AddArg2(x, x)
			return true
		}
		break
	}
	// match: (MUL x (MOVDconst [c]))
	// cond: isPowerOfTwo(c+1) && c >= 7
	// result: (ADDshiftLL (NEG <x.Type> x) x [log64(c+1)])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isPowerOfTwo(c+1) && c >= 7) {
				continue
			}
			v.reset(OpARM64ADDshiftLL)
			v.AuxInt = int64ToAuxInt(log64(c + 1))
			v0 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v0.AddArg(x)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	// match: (MUL x (MOVDconst [c]))
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (SLLconst [log64(c/3)] (ADDshiftLL <x.Type> x x [1]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%3 == 0 && isPowerOfTwo(c/3)) {
				continue
			}
			v.reset(OpARM64SLLconst)
			v.AuxInt = int64ToAuxInt(log64(c / 3))
			v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v0.AuxInt = int64ToAuxInt(1)
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MUL x (MOVDconst [c]))
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (SLLconst [log64(c/5)] (ADDshiftLL <x.Type> x x [2]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%5 == 0 && isPowerOfTwo(c/5)) {
				continue
			}
			v.reset(OpARM64SLLconst)
			v.AuxInt = int64ToAuxInt(log64(c / 5))
			v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v0.AuxInt = int64ToAuxInt(2)
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MUL x (MOVDconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (SLLconst [log64(c/7)] (ADDshiftLL <x.Type> (NEG <x.Type> x) x [3]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%7 == 0 && isPowerOfTwo(c/7)) {
				continue
			}
			v.reset(OpARM64SLLconst)
			v.AuxInt = int64ToAuxInt(log64(c / 7))
			v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v0.AuxInt = int64ToAuxInt(3)
			v1 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v1.AddArg(x)
			v0.AddArg2(v1, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MUL x (MOVDconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (SLLconst [log64(c/9)] (ADDshiftLL <x.Type> x x [3]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%9 == 0 && isPowerOfTwo(c/9)) {
				continue
			}
			v.reset(OpARM64SLLconst)
			v.AuxInt = int64ToAuxInt(log64(c / 9))
			v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v0.AuxInt = int64ToAuxInt(3)
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MUL (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64MOVDconst)
			v.AuxInt = int64ToAuxInt(c * d)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64MULW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULW (NEG x) y)
	// result: (MNEGW x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64NEG {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			v.reset(OpARM64MNEGW)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: int32(c)==-1
	// result: (MOVWUreg (NEG <x.Type> x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(int32(c) == -1) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW _ (MOVDconst [c]))
	// cond: int32(c)==0
	// result: (MOVDconst [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(int32(c) == 0) {
				continue
			}
			v.reset(OpARM64MOVDconst)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: int32(c)==1
	// result: (MOVWUreg x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(int32(c) == 1) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (MOVWUreg (SLLconst <x.Type> [log64(c)] x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c))
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c-1) && int32(c) >= 3
	// result: (MOVWUreg (ADDshiftLL <x.Type> x x [log64(c-1)]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isPowerOfTwo(c-1) && int32(c) >= 3) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c - 1))
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c+1) && int32(c) >= 7
	// result: (MOVWUreg (ADDshiftLL <x.Type> (NEG <x.Type> x) x [log64(c+1)]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isPowerOfTwo(c+1) && int32(c) >= 7) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c + 1))
			v1 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v1.AddArg(x)
			v0.AddArg2(v1, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)
	// result: (MOVWUreg (SLLconst <x.Type> [log64(c/3)] (ADDshiftLL <x.Type> x x [1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c / 3))
			v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(1)
			v1.AddArg2(x, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: c%5 == 0 && isPowerOfTwo(c/5) && is32Bit(c)
	// result: (MOVWUreg (SLLconst <x.Type> [log64(c/5)] (ADDshiftLL <x.Type> x x [2])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%5 == 0 && isPowerOfTwo(c/5) && is32Bit(c)) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c / 5))
			v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v1.AuxInt =
"""




```