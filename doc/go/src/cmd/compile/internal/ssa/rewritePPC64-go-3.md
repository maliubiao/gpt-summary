Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```go
alue) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHZloadidx ptr (MOVDconst [c]) mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHZload [int32(c)] ptr mem)
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
		v.reset(OpPPC64MOVHZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHZloadidx (MOVDconst [c]) ptr mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHZload [int32(c)] ptr mem)
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
		v.reset(OpPPC64MOVHZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHZreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVHZreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0xFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0xFFFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHZreg (SRWconst [c] (MOVBZreg x)))
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
	// match: (MOVHZreg (SRWconst [c] (MOVHZreg x)))
	// result: (SRWconst [c] (MOVHZreg x))
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVHZreg (SRWconst [c] x))
	// cond: x.Type.Size() <= 16
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() <= 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg (SRDconst [c] x))
	// cond: c>=48
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 48) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg (SRWconst [c] x))
	// cond: c>=16
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg (RLWINM [r] y))
	// cond: mergePPC64AndRlwinm(0xFFFF,r) != 0
	// result: (RLWINM [mergePPC64AndRlwinm(0xFFFF,r)] y)
	for {
		if v_0.Op != OpPPC64RLWINM {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if !(mergePPC64AndRlwinm(0xFFFF, r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndRlwinm(0xFFFF, r))
		v.AddArg(y)
		return true
	}
	// match: (MOVHZreg y:(MOVHZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHZreg y:(MOVBZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHZreg y:(MOVHBRload _ _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHBRload {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHZreg y:(MOVHreg x))
	// result: (MOVHZreg x)
	for {
		y := v_0
		if y.Op != OpPPC64MOVHreg {
			break
		}
		x := y.Args[0]
		v.reset(OpPPC64MOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg (OR <t> x (MOVWZreg y)))
	// result: (MOVHZreg (OR <t> x y))
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
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64OR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (XOR <t> x (MOVWZreg y)))
	// result: (MOVHZreg (XOR <t> x y))
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
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64XOR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (AND <t> x (MOVWZreg y)))
	// result: (MOVHZreg (AND <t> x y))
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
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64AND, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (OR <t> x (MOVHZreg y)))
	// result: (MOVHZreg (OR <t> x y))
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
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64OR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (XOR <t> x (MOVHZreg y)))
	// result: (MOVHZreg (XOR <t> x y))
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
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64XOR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (AND <t> x (MOVHZreg y)))
	// result: (MOVHZreg (AND <t> x y))
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
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64AND, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg z:(ANDconst [c] (MOVBZload ptr x)))
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
	// match: (MOVHZreg z:(AND y (MOVHZload ptr x)))
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
			if z_1.Op != OpPPC64MOVHZload {
				continue
			}
			v.copyOf(z)
			return true
		}
		break
	}
	// match: (MOVHZreg z:(ANDconst [c] (MOVHZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		z_0 := z.Args[0]
		if z_0.Op != OpPPC64MOVHZload {
			break
		}
		v.copyOf(z)
		return true
	}
	// match: (MOVHZreg x:(MOVBZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg x:(MOVBZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg x:(MOVHZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg x:(MOVHZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg x:(Arg <t>))
	// cond: (is8BitInt(t) || is16BitInt(t)) && !t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !((is8BitInt(t) || is16BitInt(t)) && !t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint16(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVHload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
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
		v.reset(OpPPC64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off1] {sym} (ADDconst [off2] x) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVHload [off1+int32(off2)] {sym} x mem)
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
		v.reset(OpPPC64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVHload [0] {sym} p:(ADD ptr idx) mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVHloadidx ptr idx mem)
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
		v.reset(OpPPC64MOVHloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHloadidx ptr (MOVDconst [c]) mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHload [int32(c)] ptr mem)
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
		v.reset(OpPPC64MOVHload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHloadidx (MOVDconst [c]) ptr mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHload [int32(c)] ptr mem)
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
		v.reset(OpPPC64MOVHload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVHreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0x7FFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0x7FFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHreg (SRAWconst [c] (MOVBreg x)))
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
	// match: (MOVHreg (SRAWconst [c] (MOVHreg x)))
	// result: (SRAWconst [c] (MOVHreg x))
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVHreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVHreg (SRAWconst [c] x))
	// cond: x.Type.Size() <= 16
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() <= 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRDconst [c] x))
	// cond: c>48
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > 48) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRDconst [c] x))
	// cond: c==48
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c == 48) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRADconst [c] x))
	// cond: c>=48
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRADconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 48) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRWconst [c] x))
	// cond: c>16
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRAWconst [c] x))
	// cond: c>=16
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRWconst [c] x))
	// cond: c==16
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c == 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg y:(MOVHreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHreg y:(MOVBreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHreg y:(MOVHZreg x))
	// result: (MOVHreg x)
	for {
		y := v_0
		if y.Op != OpPPC64MOVHZreg {
			break
		}
		x := y.Args[0]
		v.reset(OpPPC64MOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg x:(MOVHloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg x:(Arg <t>))
	// cond: (is8BitInt(t) || is16BitInt(t)) && t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !((is8BitInt(t) || is16BitInt(t)) && t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int16(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int16(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVHstore [off1] {sym} (ADDconst [off2] x) val mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVHstore [off1+int32(off2)] {sym} x val mem)
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
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(x, val, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVHstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
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
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVHstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpPPC64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstore [0] {sym} p:(ADD ptr idx) val mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVHstoreidx ptr idx val mem)
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
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHstore)
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
		if v_1.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVWZreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr r:(BRH val) mem)
	// cond: r.Uses == 1
	// result: (MOVHBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		r := v_1
		if r.Op != OpPPC64BRH {
			break
		}
		val := r.Args[0]
		mem := v_2
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVHBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (Bswap16 val) mem)
	// result: (MOVHBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpBswap16 {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreidx ptr (MOVDconst [c]) val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHstore [int32(c)] ptr val mem)
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
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstoreidx (MOVDconst [c]) ptr val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHstore [int32(c)] ptr val mem)
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
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVHreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVHreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVHZreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVWreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVWZreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx r:(BRH val) mem)
	// cond: r.Uses == 1
	// result: (MOVHBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		r := v_2
		if r.Op != OpPPC64BRH {
			break
		}
		val := r.Args[0]
		mem := v_3
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVHBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (Bswap16 val) mem)
	// result: (MOVHBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpBswap16 {
			break
		}
		val := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstorezero [off1] {sym} (ADDconst [off2] x) mem)
	// cond: ((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1)+off2)))
	// result: (MOVHstorezero [off1+int32(off2)] {sym} x mem)
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
		v.reset(OpPPC64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVHstorezero [off1] {sym1} p:(MOVDaddr [off2] {sym2} x) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVHstorezero [off1+off2] {mergeSym(sym1,sym2)} x mem)
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
		v.reset(OpPPC64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWBRstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWBRstore ptr (MOVWreg x) mem)
	// result: (MOVWBRstore ptr x mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWBRstore)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWBRstore ptr (MOVWZreg x) mem)
	// result: (MOVWBRstore ptr x mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWBRstore)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWZload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWZload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVWZload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
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
		v.reset(OpPPC64MOVWZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWZload [off1] {sym} (ADDconst [off2] x) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVWZload [off1+int32(off2)] {sym} x mem)
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
		v.reset(OpPPC64MOVWZload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVWZload [0] {sym} p:(ADD ptr idx) mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVWZloadidx ptr idx mem)
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
		v.reset(OpPPC64MOVWZloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWZloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWZloadidx ptr (MOVDconst [c]) mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWZload [int32(c)] ptr mem)
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
		v.reset(OpPPC64MOVWZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWZloadidx (MOVDconst [c]) ptr mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWZload [int32(c)] ptr mem)
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
		v.reset(OpPPC64MOVWZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWZreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVWZreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0xFFFFFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0xFFFFFFFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(AND (MOVDconst [c]) _))
	// cond: uint64(c) <= 0xFFFFFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64AND {
			break
		}
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			if y_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(y_0.AuxInt)
			if !(uint64(c) <= 0xFFFFFFFF) {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (MOVWZreg (SRWconst [c] (MOVBZreg x)))
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
	// match: (MOVWZreg (SRWconst [c] (MOVHZreg x)))
	// result: (SRWconst [c] (MOVHZreg x))
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWZreg (SRWconst [c] (MOVWZreg x)))
	// result: (SRWconst [c] (MOVWZreg x))
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWZreg (SRWconst [c] x))
	// cond: x.Type.Size() <= 32
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() <= 32) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg (SRDconst [c] x))
	// cond: c>=32
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 32) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg (RLWINM [r] y))
	// cond: mergePPC64MovwzregRlwinm(r) != 0
	// result: (RLWINM [mergePPC64MovwzregRlwinm(r)] y)
	for {
		if v_0.Op != OpPPC64RLWINM {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if !(mergePPC64MovwzregRlwinm(r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64MovwzregRlwinm(r))
		v.AddArg(y)
		return true
	}
	// match: (MOVWZreg w:(SLWconst u))
	// result: w
	for {
		w := v_0
		if w.Op != OpPPC64SLWconst {
			break
		}
		v.copyOf(w)
		return true
	}
	// match: (MOVWZreg y:(MOVWZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVWZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVHZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVBZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVHBRload _ _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHBRload {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVWBRload _ _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVWBRload {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVWreg x))
	// result: (MOVWZreg x)
	for {
		y := v_0
		if y.Op != OpPPC64MOVWreg {
			break
		}
		x := y.Args[0]
		v.reset(OpPPC64MOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg (OR <t> x (MOVWZreg y)))
	// result: (MOVWZreg (OR <t> x y))
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
			v.reset(OpPPC64MOVWZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64OR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVWZreg (XOR <t> x (MOVWZreg y)))
	// result: (MOVWZreg (XOR <t> x y))
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
			v.reset(OpPPC64MOVWZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64XOR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVWZreg (AND <t> x (MOVWZreg y)))
	// result: (MOVWZreg (AND <t> x y))
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
			v.reset(OpPPC64MOVWZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64AND, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVWZreg z:(ANDconst [c] (MOVBZload ptr x)))
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
	// match: (MOVWZreg z:(AND y (MOVWZload ptr x)))
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
			if z_1.Op != OpPPC64MOVWZload {
				continue
			}
			v.copyOf(z)
			return true
		}
		break
	}
	// match: (MOVWZreg z:(ANDconst [c] (MOVHZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		z_0 := z.Args[0]
		if z_0.Op != OpPPC64MOVHZload {
			break
		}
		v.copyOf(z)
		return true
	}
	// match: (MOVWZreg z:(ANDconst [c] (MOVWZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		z_0 := z.Args[0]
		if z_0.Op != OpPPC64MOVWZload {
			break
		}
		v.copyOf(z)
		return true
	}
	// match: (MOVWZreg x:(MOVBZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVBZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVHZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVHZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVWZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVWZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVWZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVWZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(Select0 (LoweredAtomicLoad32 _ _)))
	// result: x
	for {
		x := v_0
		if x.Op != OpSelect0 {
			break
		}
		x_0 := x.Args[0]
		if x_0.Op != OpPPC64LoweredAtomicLoad32 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(Arg <t>))
	// cond: (is8BitInt(t) || is16BitInt(t) || is32BitInt(t)) && !t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !((is8BitInt(t) || is16BitInt(t) || is32BitInt(t)) && !t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint32(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVWload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
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
		v.reset(OpPPC64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off1] {sym} (ADDconst [off2] x) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVWload [off1+int32(off2)] {sym} x mem)
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
		v.reset(OpPPC64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVWload [0] {sym} p:(ADD ptr idx) mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVWloadidx ptr idx mem)
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
		v.reset(OpPPC64MOVWloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWloadidx ptr (MOVDconst [c]) mem)
	// cond: ((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWload [int32(c)] ptr mem)
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
		v.reset(OpPPC64MOVWload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWloadidx (MOVDconst [c]) ptr mem)
	// cond: ((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWload [int32(c)] ptr mem)
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
		v.reset(OpPPC64MOVWload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVWreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0xFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0xFFFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWreg y:(AND (MOVDconst [c]) _))
	// cond: uint64(c) <= 0x7FFFFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64AND {
			break
		}
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			if y_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(y_0.AuxInt)
			if !(uint64(c) <= 0x7FFFFFFF) {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (MOVWreg (SRAWconst [c] (MOVBreg x)))
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
	// match: (MOVWreg (SRAWconst [c] (MOVHreg x)))
	// result: (SRAWconst [c] (MOVHreg x))
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVHreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWreg (SRAWconst [c] (MOVWreg x)))
	// result: (SRAWconst [c] (MOVWreg x))
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVWreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWreg (SRAWconst [c] x))
	// cond: x.Type.Size() <= 32
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() <= 32) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (SRDconst [c] x))
	// cond: c>32
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > 32) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (SRADconst [c] x))
	// cond: c>=32
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRADconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 32) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (SRDconst [c] x))
	// cond: c==32
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c == 32) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg y:(MOVWreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVWreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWreg y:(MOVHreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWreg y:(MOVBreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWreg y:(MOVWZreg x))
	// result: (MOVWreg x)
	for {
		y := v_0
		if y.Op != OpPPC64MOVWZreg {
			break
		}
		x := y.Args[0]
		v.reset(OpPPC64MOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVHloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVWload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVWload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVWloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVWloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(Arg <t>))
	// cond: (is8BitInt(t) || is16BitInt(t) || is32BitInt(t)) && t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !((is8BitInt(t) || is16BitInt(t) || is32BitInt(t)) && t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int32(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVWstore [off1] {sym} (ADDconst [off2] x) val mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVWstore [off1+int32(off2)] {sym} x val mem)
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
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(x, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVWstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
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
		v.reset(OpPPC64MOVWstore)
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
		if v_1.Op != OpPPC64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpPPC64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstore [0] {sym} p:(ADD ptr idx) val mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVWstoreidx ptr idx val mem)
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
		v.reset(OpPPC64MOVWstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWstore)
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
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr r:(BRW val) mem)
	// cond: r.Uses == 1
	// result: (MOVWBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		r := v_1
		if r.Op != OpPPC64BRW {
			break
		}
		val := r.Args[0]
		mem := v_2
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVWBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (Bswap32 val) mem)
	// result: (MOVWBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpBswap32 {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreidx ptr (MOVDconst [c]) val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWstore [int32(c)] ptr val mem)
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
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstoreidx (MOVDconst [c]) ptr val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWstore [int32(c)] ptr val mem)
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
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (MOVWreg x) mem)
	// result: (MOVWstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVWstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (MOVWZreg x) mem)
	// result: (MOVWstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVWstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx r:(BRW val) mem)
	// cond: r.Uses == 1
	// result: (MOVWBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		r := v_2
		if r.Op != OpPPC64BRW {
			break
		}
		val := r.Args[0]
		mem := v_3
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVWBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (Bswap32 val) mem)
	// result: (MOVWBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpBswap32 {
			break
		}
		val := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVWBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstorezero [off1] {sym} (ADDconst [off2] x) mem)
	// cond: ((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1)+off2)))
	// result: (MOVWstorezero [off1+int32(off2)] {sym} x mem)
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
		v.reset(OpPPC64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVWstorezero [off1] {sym1} p:(MOVDaddr [off2] {sym2} x) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVWstorezero [off1+off2] {mergeSym(sym1,sym2)} x mem)
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
		v.reset(OpPPC64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MTVSRD(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MTVSRD (MOVDconst [c]))
	// cond: !math.IsNaN(math.Float64frombits(uint64(c)))
	// result: (FMOVDconst [math.Float64frombits(uint64(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if !(!math.IsNaN(math.Float64frombits(uint64(c)))) {
			break
		}
		v.reset(OpPPC64FMOVDconst)
		v.AuxInt = float64ToAuxInt(math.Float64frombits(uint64(c)))
		return true
	}
	// match: (MTVSRD x:(MOVDload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (FMOVDload [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVDload {
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
		v0 := b.NewValue0(x.Pos, OpPPC64FMOVDload, typ.Float64)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MULLD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLD x (MOVDconst [c]))
	// cond: is16Bit(c)
	// result: (MULLDconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is16Bit(c)) {
				continue
			}
			v.reset(OpPPC64MULLDconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64MULLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLW x (MOVDconst [c]))
	// cond: is16Bit(c)
	// result: (MULLWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is16Bit(c)) {
				continue
			}
			v.reset(OpPPC64MULLWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64NEG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEG (ADDconst [c] x))
	// cond: is32Bit(-c)
	// result: (SUBFCconst [-c] x)
	for {
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c)) {
			break
		}
		v.reset(OpPPC64SUBFCconst)
		v.AuxInt = int64ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (NEG (SUBFCconst [c] x))
	// cond: is32Bit(-c)
	// result: (ADDconst [-c] x)
	for {
		if v_0.Op != OpPPC64SUBFCconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c)) {
			break
		}
		v.reset(OpPPC64ADDconst)
		v.AuxInt = int64ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (NEG (SUB x y))
	// result: (SUB y x)
	for {
		if v_0.Op != OpPPC64SUB {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64SUB)
		v.AddArg2(y, x)
		return true
	}
	// match: (NEG (NEG x))
	// result: x
	for {
		if v_0.Op != OpPPC64NEG {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64NOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NOR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [^(c|d)])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpPPC64MOVDconst)
			v.AuxInt = int64ToAuxInt(^(c | d))
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64NotEqual(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NotEqual (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (NotEqual (FlagLT))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (NotEqual (FlagGT))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (NotEqual (InvertFlags x))
	// result: (NotEqual x)
	for {
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64NotEqual)
		v.AddArg(x)
		return true
	}
	// match: (NotEqual cmp)
	// result: (SETBCR [2] cmp)
	for {
		cmp := v_0
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v.AddArg(cmp)
		return true
	}
}
func rewriteValuePPC64_OpPPC64OR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (OR x (NOR y y))
	// result: (ORN x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64NOR {
				continue
			}
			y := v_1.Args[1]
			if y != v_1.Args[0] {
				continue
			}
			v.reset(OpPPC64ORN)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (OR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c|d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpPPC64MOVDconst)
			v.AuxInt = int64ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (OR x (MOVDconst [c]))
	// cond: isU32Bit(c)
	// result: (ORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isU32Bit(c)) {
				continue
			}
			v.reset(OpPPC64ORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64ORN(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORN x (MOVDconst [-1]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst || auxIntToInt64(v_1.AuxInt) != -1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ORN (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c|^d])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(c | ^d)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64ORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORconst [c] (ORconst [d] x))
	// result: (ORconst [c|d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpPPC64ORconst)
		v.AuxInt = int64ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	// match: (ORconst [-1] _)
	// result: (MOVDconst [-1])
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64RLWINM(v *Value) bool {
	v_0 := v.Args[0]
	// match: (RLWINM [r] (MOVHZreg u))
	// cond: mergePPC64RlwinmAnd(r,0xFFFF) != 0
	// result: (RLWINM [mergePPC64RlwinmAnd(r,0xFFFF)] u)
	for {
		r := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVHZreg {
			break
		}
		u := v_0.Args[0]
		if !(mergePPC64RlwinmAnd(r, 0xFFFF) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64RlwinmAnd(r, 0xFFFF))
		v.AddArg(u)
		return true
	}
	// match: (RLWINM [r] (ANDconst [a] u))
	// cond: mergePPC64RlwinmAnd(r,uint32(a)) != 0
	// result: (RLWINM [mergePPC64RlwinmAnd(r,uint32(a))] u)
	for {
		r := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		a := auxIntToInt64(v_0.AuxInt)
		u := v_0.Args[0]
		if !(mergePPC64RlwinmAnd(r, uint32(a)) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64RlwinmAnd(r, uint32(a)))
		v.AddArg(u)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64ROTL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROTL x (MOVDconst [c]))
	// result: (ROTLconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64ROTLconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64ROTLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROTLW x (MOVDconst [c]))
	// result: (ROTLWconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64ROTLWconst)
		v.AuxInt = int64ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64ROTLWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ROTLWconst [r] (AND (MOVDconst [m]) x))
	// cond: isPPC64WordRotateMask(m)
	// result: (RLWINM [encodePPC64RotateMask(r,rotateLeft32(m,r),32)] x)
	for {
		r := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64AND {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0_0.AuxInt)
			x := v_0_1
			if !(isPPC64WordRotateMask(m)) {
				continue
			}
			v.reset(OpPPC64RLWINM)
			v.AuxInt = int64ToAuxInt(encodePPC64RotateMask(r, rotateLeft32(m, r), 32))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ROTLWconst [r] (ANDconst [m] x))
	// cond: isPPC64WordRotateMask(m)
	// result: (RLWINM [encodePPC64RotateMask(r,rotateLeft32(m,r),32)] x)
	for {
		r := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isPPC64WordRotateMask(m)) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(encodePPC64RotateMask(r, rotateLeft32(m, r), 32))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SETBC(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETBC [0] (FlagLT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBC [0] (FlagGT))
	// result: (MOVDconst
```