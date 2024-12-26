Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共8部分，请归纳一下它的功能

"""
}
		v.reset(OpARMMOVHloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVHloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHloadidx ptr idx (MOVHstoreidx ptr2 idx x _))
	// cond: isSamePtr(ptr, ptr2)
	// result: (MOVHreg x)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARMMOVHstoreidx {
			break
		}
		x := v_2.Args[2]
		ptr2 := v_2.Args[0]
		if idx != v_2.Args[1] || !(isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARMMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHloadidx ptr (MOVWconst [c]) mem)
	// result: (MOVHload [c] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpARMMOVHload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHloadidx (MOVWconst [c]) ptr mem)
	// result: (MOVHload [c] ptr mem)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		v.reset(OpARMMOVHload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHreg x:(MOVBload _ _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBload {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUload _ _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBUload {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHload _ _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVHload {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (ANDconst [c] x))
	// cond: c & 0x8000 == 0
	// result: (ANDconst [c&0x7fff] x)
	for {
		if v_0.Op != OpARMANDconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c&0x8000 == 0) {
			break
		}
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c & 0x7fff)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBreg _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBreg {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUreg _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBUreg {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHreg _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVHreg {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (MOVWconst [c]))
	// result: (MOVWconst [int32(int16(c))])
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(int16(c)))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVHstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// result: (MOVHstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym} (SUBconst [off2] ptr) val mem)
	// result: (MOVHstore [off1-off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVHstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVHUreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [0] {sym} (ADD ptr idx) val mem)
	// cond: sym == nil
	// result: (MOVHstoreidx ptr idx val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVHstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVHstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreidx ptr (MOVWconst [c]) val mem)
	// result: (MOVHstore [c] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		val := v_2
		mem := v_3
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstoreidx (MOVWconst [c]) ptr val mem)
	// result: (MOVHstore [c] ptr val mem)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWload [off1] {sym} (ADDconst [off2] ptr) mem)
	// result: (MOVWload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off1] {sym} (SUBconst [off2] ptr) mem)
	// result: (MOVWload [off1-off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVWload)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVWload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off] {sym} ptr (MOVWstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: x
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVWstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWload [0] {sym} (ADD ptr idx) mem)
	// cond: sym == nil
	// result: (MOVWloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVWloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWload [0] {sym} (ADDshiftLL ptr idx [c]) mem)
	// cond: sym == nil
	// result: (MOVWloadshiftLL ptr idx [c] mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDshiftLL {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVWloadshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWload [0] {sym} (ADDshiftRL ptr idx [c]) mem)
	// cond: sym == nil
	// result: (MOVWloadshiftRL ptr idx [c] mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDshiftRL {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVWloadshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWload [0] {sym} (ADDshiftRA ptr idx [c]) mem)
	// cond: sym == nil
	// result: (MOVWloadshiftRA ptr idx [c] mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDshiftRA {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVWloadshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVWconst [int32(read32(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(read32(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWloadidx ptr idx (MOVWstoreidx ptr2 idx x _))
	// cond: isSamePtr(ptr, ptr2)
	// result: x
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARMMOVWstoreidx {
			break
		}
		x := v_2.Args[2]
		ptr2 := v_2.Args[0]
		if idx != v_2.Args[1] || !(isSamePtr(ptr, ptr2)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWloadidx ptr (MOVWconst [c]) mem)
	// result: (MOVWload [c] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpARMMOVWload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWloadidx (MOVWconst [c]) ptr mem)
	// result: (MOVWload [c] ptr mem)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		v.reset(OpARMMOVWload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWloadidx ptr (SLLconst idx [c]) mem)
	// result: (MOVWloadshiftLL ptr idx [c] mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARMMOVWloadshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWloadidx (SLLconst idx [c]) ptr mem)
	// result: (MOVWloadshiftLL ptr idx [c] mem)
	for {
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARMMOVWloadshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWloadidx ptr (SRLconst idx [c]) mem)
	// result: (MOVWloadshiftRL ptr idx [c] mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARMMOVWloadshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWloadidx (SRLconst idx [c]) ptr mem)
	// result: (MOVWloadshiftRL ptr idx [c] mem)
	for {
		if v_0.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARMMOVWloadshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWloadidx ptr (SRAconst idx [c]) mem)
	// result: (MOVWloadshiftRA ptr idx [c] mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARMMOVWloadshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVWloadidx (SRAconst idx [c]) ptr mem)
	// result: (MOVWloadshiftRA ptr idx [c] mem)
	for {
		if v_0.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARMMOVWloadshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWloadshiftLL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWloadshiftLL ptr idx [c] (MOVWstoreshiftLL ptr2 idx [d] x _))
	// cond: c==d && isSamePtr(ptr, ptr2)
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARMMOVWstoreshiftLL {
			break
		}
		d := auxIntToInt32(v_2.AuxInt)
		x := v_2.Args[2]
		ptr2 := v_2.Args[0]
		if idx != v_2.Args[1] || !(c == d && isSamePtr(ptr, ptr2)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWloadshiftLL ptr (MOVWconst [c]) [d] mem)
	// result: (MOVWload [int32(uint32(c)<<uint64(d))] ptr mem)
	for {
		d := auxIntToInt32(v.AuxInt)
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpARMMOVWload)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) << uint64(d)))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWloadshiftRA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWloadshiftRA ptr idx [c] (MOVWstoreshiftRA ptr2 idx [d] x _))
	// cond: c==d && isSamePtr(ptr, ptr2)
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARMMOVWstoreshiftRA {
			break
		}
		d := auxIntToInt32(v_2.AuxInt)
		x := v_2.Args[2]
		ptr2 := v_2.Args[0]
		if idx != v_2.Args[1] || !(c == d && isSamePtr(ptr, ptr2)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWloadshiftRA ptr (MOVWconst [c]) [d] mem)
	// result: (MOVWload [c>>uint64(d)] ptr mem)
	for {
		d := auxIntToInt32(v.AuxInt)
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpARMMOVWload)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWloadshiftRL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWloadshiftRL ptr idx [c] (MOVWstoreshiftRL ptr2 idx [d] x _))
	// cond: c==d && isSamePtr(ptr, ptr2)
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARMMOVWstoreshiftRL {
			break
		}
		d := auxIntToInt32(v_2.AuxInt)
		x := v_2.Args[2]
		ptr2 := v_2.Args[0]
		if idx != v_2.Args[1] || !(c == d && isSamePtr(ptr, ptr2)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWloadshiftRL ptr (MOVWconst [c]) [d] mem)
	// result: (MOVWload [int32(uint32(c)>>uint64(d))] ptr mem)
	for {
		d := auxIntToInt32(v.AuxInt)
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpARMMOVWload)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWnop(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWnop (MOVWconst [c]))
	// result: (MOVWconst [c])
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWreg x)
	// cond: x.Uses == 1
	// result: (MOVWnop x)
	for {
		x := v_0
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARMMOVWnop)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (MOVWconst [c]))
	// result: (MOVWconst [c])
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// result: (MOVWstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym} (SUBconst [off2] ptr) val mem)
	// result: (MOVWstore [off1-off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVWstore)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVWstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [0] {sym} (ADD ptr idx) val mem)
	// cond: sym == nil
	// result: (MOVWstoreidx ptr idx val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVWstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstore [0] {sym} (ADDshiftLL ptr idx [c]) val mem)
	// cond: sym == nil
	// result: (MOVWstoreshiftLL ptr idx [c] val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDshiftLL {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVWstoreshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstore [0] {sym} (ADDshiftRL ptr idx [c]) val mem)
	// cond: sym == nil
	// result: (MOVWstoreshiftRL ptr idx [c] val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDshiftRL {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVWstoreshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstore [0] {sym} (ADDshiftRA ptr idx [c]) val mem)
	// cond: sym == nil
	// result: (MOVWstoreshiftRA ptr idx [c] val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDshiftRA {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVWstoreshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreidx ptr (MOVWconst [c]) val mem)
	// result: (MOVWstore [c] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstore)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstoreidx (MOVWconst [c]) ptr val mem)
	// result: (MOVWstore [c] ptr val mem)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstore)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr (SLLconst idx [c]) val mem)
	// result: (MOVWstoreshiftLL ptr idx [c] val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		idx := v_1.Args[0]
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstoreshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx (SLLconst idx [c]) ptr val mem)
	// result: (MOVWstoreshiftLL ptr idx [c] val mem)
	for {
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[0]
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstoreshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr (SRLconst idx [c]) val mem)
	// result: (MOVWstoreshiftRL ptr idx [c] val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		idx := v_1.Args[0]
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstoreshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx (SRLconst idx [c]) ptr val mem)
	// result: (MOVWstoreshiftRL ptr idx [c] val mem)
	for {
		if v_0.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[0]
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstoreshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr (SRAconst idx [c]) val mem)
	// result: (MOVWstoreshiftRA ptr idx [c] val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		idx := v_1.Args[0]
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstoreshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx (SRAconst idx [c]) ptr val mem)
	// result: (MOVWstoreshiftRA ptr idx [c] val mem)
	for {
		if v_0.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		idx := v_0.Args[0]
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstoreshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWstoreshiftLL(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreshiftLL ptr (MOVWconst [c]) [d] val mem)
	// result: (MOVWstore [int32(uint32(c)<<uint64(d))] ptr val mem)
	for {
		d := auxIntToInt32(v.AuxInt)
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstore)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) << uint64(d)))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWstoreshiftRA(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreshiftRA ptr (MOVWconst [c]) [d] val mem)
	// result: (MOVWstore [c>>uint64(d)] ptr val mem)
	for {
		d := auxIntToInt32(v.AuxInt)
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstore)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVWstoreshiftRL(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreshiftRL ptr (MOVWconst [c]) [d] val mem)
	// result: (MOVWstore [int32(uint32(c)>>uint64(d))] ptr val mem)
	for {
		d := auxIntToInt32(v.AuxInt)
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		val := v_2
		mem := v_3
		v.reset(OpARMMOVWstore)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMUL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MUL x (MOVWconst [c]))
	// cond: int32(c) == -1
	// result: (RSBconst [0] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(int32(c) == -1) {
				continue
			}
			v.reset(OpARMRSBconst)
			v.AuxInt = int32ToAuxInt(0)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MUL _ (MOVWconst [0]))
	// result: (MOVWconst [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_1.Op != OpARMMOVWconst || auxIntToInt32(v_1.AuxInt) != 0 {
				continue
			}
			v.reset(OpARMMOVWconst)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	// match: (MUL x (MOVWconst [1]))
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst || auxIntToInt32(v_1.AuxInt) != 1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (MUL x (MOVWconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (SLLconst [int32(log32(c))] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpARMSLLconst)
			v.AuxInt = int32ToAuxInt(int32(log32(c)))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MUL x (MOVWconst [c]))
	// cond: isPowerOfTwo(c-1) && c >= 3
	// result: (ADDshiftLL x x [int32(log32(c-1))])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(isPowerOfTwo(c-1) && c >= 3) {
				continue
			}
			v.reset(OpARMADDshiftLL)
			v.AuxInt = int32ToAuxInt(int32(log32(c - 1)))
			v.AddArg2(x, x)
			return true
		}
		break
	}
	// match: (MUL x (MOVWconst [c]))
	// cond: isPowerOfTwo(c+1) && c >= 7
	// result: (RSBshiftLL x x [int32(log32(c+1))])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(isPowerOfTwo(c+1) && c >= 7) {
				continue
			}
			v.reset(OpARMRSBshiftLL)
			v.AuxInt = int32ToAuxInt(int32(log32(c + 1)))
			v.AddArg2(x, x)
			return true
		}
		break
	}
	// match: (MUL x (MOVWconst [c]))
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (SLLconst [int32(log32(c/3))] (ADDshiftLL <x.Type> x x [1]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(c%3 == 0 && isPowerOfTwo(c/3)) {
				continue
			}
			v.reset(OpARMSLLconst)
			v.AuxInt = int32ToAuxInt(int32(log32(c / 3)))
			v0 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
			v0.AuxInt = int32ToAuxInt(1)
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MUL x (MOVWconst [c]))
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (SLLconst [int32(log32(c/5))] (ADDshiftLL <x.Type> x x [2]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(c%5 == 0 && isPowerOfTwo(c/5)) {
				continue
			}
			v.reset(OpARMSLLconst)
			v.AuxInt = int32ToAuxInt(int32(log32(c / 5)))
			v0 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
			v0.AuxInt = int32ToAuxInt(2)
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MUL x (MOVWconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (SLLconst [int32(log32(c/7))] (RSBshiftLL <x.Type> x x [3]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(c%7 == 0 && isPowerOfTwo(c/7)) {
				continue
			}
			v.reset(OpARMSLLconst)
			v.AuxInt = int32ToAuxInt(int32(log32(c / 7)))
			v0 := b.NewValue0(v.Pos, OpARMRSBshiftLL, x.Type)
			v0.AuxInt = int32ToAuxInt(3)
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MUL x (MOVWconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (SLLconst [int32(log32(c/9))] (ADDshiftLL <x.Type> x x [3]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(c%9 == 0 && isPowerOfTwo(c/9)) {
				continue
			}
			v.reset(OpARMSLLconst)
			v.AuxInt = int32ToAuxInt(int32(log32(c / 9)))
			v0 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
			v0.AuxInt = int32ToAuxInt(3)
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MUL (MOVWconst [c]) (MOVWconst [d]))
	// result: (MOVWconst [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMMOVWconst)
			v.AuxInt = int32ToAuxInt(c * d)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMMULA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULA x (MOVWconst [c]) a)
	// cond: c == -1
	// result: (SUB a x)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c == -1) {
			break
		}
		v.reset(OpARMSUB)
		v.AddArg2(a, x)
		return true
	}
	// match: (MULA _ (MOVWconst [0]) a)
	// result: a
	for {
		if v_1.Op != OpARMMOVWconst || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		a := v_2
		v.copyOf(a)
		return true
	}
	// match: (MULA x (MOVWconst [1]) a)
	// result: (ADD x a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst || auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		a := v_2
		v.reset(OpARMADD)
		v.AddArg2(x, a)
		return true
	}
	// match: (MULA x (MOVWconst [c]) a)
	// cond: isPowerOfTwo(c)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c))] x) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c)))
		v0.AddArg(x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA x (MOVWconst [c]) a)
	// cond: isPowerOfTwo(c-1) && c >= 3
	// result: (ADD (ADDshiftLL <x.Type> x x [int32(log32(c-1))]) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(isPowerOfTwo(c-1) && c >= 3) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c - 1)))
		v0.AddArg2(x, x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA x (MOVWconst [c]) a)
	// cond: isPowerOfTwo(c+1) && c >= 7
	// result: (ADD (RSBshiftLL <x.Type> x x [int32(log32(c+1))]) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(isPowerOfTwo(c+1) && c >= 7) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMRSBshiftLL, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c + 1)))
		v0.AddArg2(x, x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA x (MOVWconst [c]) a)
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c/3))] (ADDshiftLL <x.Type> x x [1])) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c%3 == 0 && isPowerOfTwo(c/3)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 3)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(1)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA x (MOVWconst [c]) a)
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c/5))] (ADDshiftLL <x.Type> x x [2])) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c%5 == 0 && isPowerOfTwo(c/5)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 5)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA x (MOVWconst [c]) a)
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c/7))] (RSBshiftLL <x.Type> x x [3])) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c%7 == 0 && isPowerOfTwo(c/7)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 7)))
		v1 := b.NewValue0(v.Pos, OpARMRSBshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA x (MOVWconst [c]) a)
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c/9))] (ADDshiftLL <x.Type> x x [3])) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c%9 == 0 && isPowerOfTwo(c/9)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 9)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA (MOVWconst [c]) x a)
	// cond: c == -1
	// result: (SUB a x)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c == -1) {
			break
		}
		v.reset(OpARMSUB)
		v.AddArg2(a, x)
		return true
	}
	// match: (MULA (MOVWconst [0]) _ a)
	// result: a
	for {
		if v_0.Op != OpARMMOVWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		a := v_2
		v.copyOf(a)
		return true
	}
	// match: (MULA (MOVWconst [1]) x a)
	// result: (ADD x a)
	for {
		if v_0.Op != OpARMMOVWconst || auxIntToInt32(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		a := v_2
		v.reset(OpARMADD)
		v.AddArg2(x, a)
		return true
	}
	// match: (MULA (MOVWconst [c]) x a)
	// cond: isPowerOfTwo(c)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c))] x) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c)))
		v0.AddArg(x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA (MOVWconst [c]) x a)
	// cond: isPowerOfTwo(c-1) && c >= 3
	// result: (ADD (ADDshiftLL <x.Type> x x [int32(log32(c-1))]) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(isPowerOfTwo(c-1) && c >= 3) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c - 1)))
		v0.AddArg2(x, x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA (MOVWconst [c]) x a)
	// cond: isPowerOfTwo(c+1) && c >= 7
	// result: (ADD (RSBshiftLL <x.Type> x x [int32(log32(c+1))]) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(isPowerOfTwo(c+1) && c >= 7) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMRSBshiftLL, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c + 1)))
		v0.AddArg2(x, x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA (MOVWconst [c]) x a)
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c/3))] (ADDshiftLL <x.Type> x x [1])) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c%3 == 0 && isPowerOfTwo(c/3)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 3)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(1)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA (MOVWconst [c]) x a)
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c/5))] (ADDshiftLL <x.Type> x x [2])) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c%5 == 0 && isPowerOfTwo(c/5)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 5)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA (MOVWconst [c]) x a)
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c/7))] (RSBshiftLL <x.Type> x x [3])) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c%7 == 0 && isPowerOfTwo(c/7)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 7)))
		v1 := b.NewValue0(v.Pos, OpARMRSBshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA (MOVWconst [c]) x a)
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (ADD (SLLconst <x.Type> [int32(log32(c/9))] (ADDshiftLL <x.Type> x x [3])) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c%9 == 0 && isPowerOfTwo(c/9)) {
			break
		}
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 9)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULA (MOVWconst [c]) (MOVWconst [d]) a)
	// result: (ADDconst [c*d] a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		a := v_2
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c * d)
		v.AddArg(a)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMULD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULD (NEGD x) y)
	// cond: buildcfg.GOARM.Version >= 6
	// result: (NMULD x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARMNEGD {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			if !(buildcfg.GOARM.Version >= 6) {
				continue
			}
			v.reset(OpARMNMULD)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMMULF(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULF (NEGF x) y)
	// cond: buildcfg.GOARM.Version >= 6
	// result: (NMULF x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARMNEGF {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			if !(buildcfg.GOARM.Version >= 6) {
				continue
			}
			v.reset(OpARMNMULF)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMMULS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULS x (MOVWconst [c]) a)
	// cond: c == -1
	// result: (ADD a x)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c == -1) {
			break
		}
		v.reset(OpARMADD)
		v.AddArg2(a, x)
		return true
	}
	// match: (MULS _ (MOVWconst [0]) a)
	// result: a
	for {
		if v_1.Op != OpARMMOVWconst || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		a := v_2
		v.copyOf(a)
		return true
	}
	// match: (MULS x (MOVWconst [1]) a)
	// result: (RSB x a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst || auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		a := v_2
		v.reset(OpARMRSB)
		v.AddArg2(x, a)
		return true
	}
	// match: (MULS x (MOVWconst [c]) a)
	// cond: isPowerOfTwo(c)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c))] x) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c)))
		v0.AddArg(x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS x (MOVWconst [c]) a)
	// cond: isPowerOfTwo(c-1) && c >= 3
	// result: (RSB (ADDshiftLL <x.Type> x x [int32(log32(c-1))]) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(isPowerOfTwo(c-1) && c >= 3) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c - 1)))
		v0.AddArg2(x, x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS x (MOVWconst [c]) a)
	// cond: isPowerOfTwo(c+1) && c >= 7
	// result: (RSB (RSBshiftLL <x.Type> x x [int32(log32(c+1))]) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(isPowerOfTwo(c+1) && c >= 7) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMRSBshiftLL, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c + 1)))
		v0.AddArg2(x, x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS x (MOVWconst [c]) a)
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c/3))] (ADDshiftLL <x.Type> x x [1])) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c%3 == 0 && isPowerOfTwo(c/3)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 3)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(1)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS x (MOVWconst [c]) a)
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c/5))] (ADDshiftLL <x.Type> x x [2])) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c%5 == 0 && isPowerOfTwo(c/5)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 5)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS x (MOVWconst [c]) a)
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c/7))] (RSBshiftLL <x.Type> x x [3])) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c%7 == 0 && isPowerOfTwo(c/7)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 7)))
		v1 := b.NewValue0(v.Pos, OpARMRSBshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS x (MOVWconst [c]) a)
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c/9))] (ADDshiftLL <x.Type> x x [3])) a)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		a := v_2
		if !(c%9 == 0 && isPowerOfTwo(c/9)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 9)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS (MOVWconst [c]) x a)
	// cond: c == -1
	// result: (ADD a x)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c == -1) {
			break
		}
		v.reset(OpARMADD)
		v.AddArg2(a, x)
		return true
	}
	// match: (MULS (MOVWconst [0]) _ a)
	// result: a
	for {
		if v_0.Op != OpARMMOVWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		a := v_2
		v.copyOf(a)
		return true
	}
	// match: (MULS (MOVWconst [1]) x a)
	// result: (RSB x a)
	for {
		if v_0.Op != OpARMMOVWconst || auxIntToInt32(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		a := v_2
		v.reset(OpARMRSB)
		v.AddArg2(x, a)
		return true
	}
	// match: (MULS (MOVWconst [c]) x a)
	// cond: isPowerOfTwo(c)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c))] x) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c)))
		v0.AddArg(x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS (MOVWconst [c]) x a)
	// cond: isPowerOfTwo(c-1) && c >= 3
	// result: (RSB (ADDshiftLL <x.Type> x x [int32(log32(c-1))]) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(isPowerOfTwo(c-1) && c >= 3) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c - 1)))
		v0.AddArg2(x, x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS (MOVWconst [c]) x a)
	// cond: isPowerOfTwo(c+1) && c >= 7
	// result: (RSB (RSBshiftLL <x.Type> x x [int32(log32(c+1))]) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(isPowerOfTwo(c+1) && c >= 7) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMRSBshiftLL, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c + 1)))
		v0.AddArg2(x, x)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS (MOVWconst [c]) x a)
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c/3))] (ADDshiftLL <x.Type> x x [1])) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c%3 == 0 && isPowerOfTwo(c/3)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 3)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(1)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS (MOVWconst [c]) x a)
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c/5))] (ADDshiftLL <x.Type> x x [2])) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c%5 == 0 && isPowerOfTwo(c/5)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 5)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS (MOVWconst [c]) x a)
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c/7))] (RSBshiftLL <x.Type> x x [3])) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c%7 == 0 && isPowerOfTwo(c/7)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 7)))
		v1 := b.NewValue0(v.Pos, OpARMRSBshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS (MOVWconst [c]) x a)
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (RSB (SLLconst <x.Type> [int32(log32(c/9))] (ADDshiftLL <x.Type> x x [3])) a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		a := v_2
		if !(c%9 == 0 && isPowerOfTwo(c/9)) {
			break
		}
		v.reset(OpARMRSB)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(int32(log32(c / 9)))
		v1 := b.NewValue0(v.Pos, OpARMADDshiftLL, x.Type)
		v1.AuxInt = int32ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg(v1)
		v.AddArg2(v0, a)
		return true
	}
	// match: (MULS (MOVWconst [c]) (MOVWconst [d]) a)
	// result: (SUBconst [c*d] a)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		a := v_2
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c * d)
		v.AddArg(a)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMVN(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVN (MOVWconst [c]))
	// result: (MOVWconst [^c])
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(^c)
		return true
	}
	// match: (MVN (SLLconst [c] x))
	// result: (MVNshiftLL x [c])
	for {
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMMVNshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MVN (SRLconst [c] x))
	// result: (MVNshiftRL x [c])
	for {
		if v_0.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMMVNshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MVN (SRAconst [c] x))
	// result: (MVNshiftRA x [c])
	for {
		if v_0.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMMVNshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MVN (SLL x y))
	// result: (MVNshiftLLreg x y)
	for {
		if v_0.Op != OpARMSLL {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARMMVNshiftLLreg)
		v.AddArg2(x, y)
		return true
	}
	// match: (MVN (SRL x y))
	// result: (MVNshiftRLreg x y)
	for {
		if v_0.Op != OpARMSRL {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARMMVNshiftRLreg)
		v.AddArg2(x, y)
		return true
	}
	// match: (MVN (SRA x y))
	// result: (MVNshiftRAreg x y)
	for {
		if v_0.Op != OpARMSRA {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARMMVNshiftRAreg)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMVNshiftLL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftLL (MOVWconst [c]) [d])
	// result: (MOVWconst [^(c<<uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(^(c << uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMVNshiftLLreg(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MVNshiftLLreg x (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (MVNshiftLL x [c])
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMMVNshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMVNshiftRA(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftRA (MOVWconst [c]) [d])
	// result: (MOVWconst [int32(c)>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(c) >> uint64(d))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMVNshiftRAreg(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MVNshiftRAreg x (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (MVNshiftRA x [c])
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMMVNshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMVNshiftRL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftRL (MOVWconst [c]) [d])
	// result: (MOVWconst [^int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(^int32(uint32(c) >> uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMVNshiftRLreg(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MVNshiftRLreg x (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (MVNshiftRL x [c])
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMMVNshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMNEGD(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGD (MULD x y))
	// cond: buildcfg.GOARM.Version >= 6
	// result: (NMULD x y)
	for {
		if v_0.Op != OpARMMULD {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMNMULD)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMNEGF(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGF (MULF x y))
	// cond: buildcfg.GOARM.Version >= 6
	// result: (NMULF x y)
	for {
		if v_0.Op != OpARMMULF {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMNMULF)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMNMULD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NMULD (NEGD x) y)
	// result: (MULD x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARMNEGD {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			v.reset(OpARMMULD)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMNMULF(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NMULF (NEGF x) y)
	// result: (MULF x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARMNEGF {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			v.reset(OpARMMULF)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMNotEqual(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NotEqual (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.ne())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.ne()))
		return true
	}
	// match: (NotEqual (InvertFlags x))
	// result: (NotEqual x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMNotEqual)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (OR x (MOVWconst [c]))
	// result: (ORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMORconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (OR x (SLLconst [c] y))
	// result: (ORshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMORshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (OR x (SRLconst [c] y))
	// result: (ORshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMORshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (OR x (SRAconst [c] y))
	// result: (ORshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMORshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (OR x (SLL y z))
	// result: (ORshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMORshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (OR x (SRL y z))
	// result: (ORshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMORshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (OR x (SRA y z))
	// result: (ORshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMORshiftRAreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (OR x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ORconst [c] _)
	// cond: int32(c)==-1
	// result: (MOVWconst [-1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if !(int32(c) == -1) {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(-1)
		return true
	}
	// match: (ORconst [c] (MOVWconst [d]))
	// result: (MOVWconst [c|d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c | d)
		return true
	}
	// match: (ORconst [c] (ORconst [d] x))
	// result: (ORconst [c|d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMORconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMORshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ORshiftLL (MOVWconst [c]) x [d])
	// result: (ORconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftLL x (MOVWconst [c]) [d])
	// result: (ORconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftLL <typ.UInt16> [8] (BFXU <typ.UInt16> [int32(armBFAuxInt(8, 8))] x) x)
	// result: (REV16 x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt32(v.AuxInt) != 8 || v_0.Op != OpARMBFXU || v_0.Type != typ.UInt16 || auxIntToInt32(v_0.AuxInt) != int32(armBFAuxInt(8, 8)) {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMREV16)
		v.AddArg(x)
		return true
	}
	// match: (ORshiftLL <typ.UInt16> [8] (SRLconst <typ.UInt16> [24] (SLLconst [16] x)) x)
	// cond: buildcfg.GOARM.Version>=6
	// result: (REV16 x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt32(v.AuxInt) != 8 || v_0.Op != OpARMSRLconst || v_0.Type != typ.UInt16 || auxIntToInt32(v_0.AuxInt) != 24 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARMSLLconst || auxIntToInt32(v_0_0.AuxInt) != 16 {
			break
		}
		x := v_0_0.Args[0]
		if x != v_1 || !(buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMREV16)
		v.AddArg(x)
		return true
	}
	// match: (ORshiftLL y:(SLLconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt32(v.AuxInt)
		y := v_0
		if y.Op != OpARMSLLconst || auxIntToInt32(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMORshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftLLreg (MOVWconst [c]) x y)
	// result: (ORconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ORshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMORshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMORshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRA (MOVWconst [c]) x [d])
	// result: (ORconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRA x (MOVWconst [c]) [d])
	// result: (ORconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftRA y:(SRAconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt32(v.AuxInt)
		y := v_0
		if y.Op != OpARMSRAconst || auxIntToInt32(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMORshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRAreg (MOVWconst [c]) x y)
	// result: (ORconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ORshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMORshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMORshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRL (MOVWconst [c]) x [d])
	// result: (ORconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddAr
"""




```