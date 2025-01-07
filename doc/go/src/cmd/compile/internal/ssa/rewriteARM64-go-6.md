Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第7部分，共10部分，请归纳一下它的功能

"""
	v.AddArg(x)
		return true
	}
	// match: (SUBshiftLL (SLLconst x [c]) x [c])
	// result: (MOVDconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUBshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBshiftRA x (MOVDconst [c]) [d])
	// result: (SUBconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (SUBshiftRA (SRAconst x [c]) x [c])
	// result: (MOVDconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRAconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUBshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBshiftRL x (MOVDconst [c]) [d])
	// result: (SUBconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (SUBshiftRL (SRLconst x [c]) x [c])
	// result: (MOVDconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TST(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (TST x (MOVDconst [c]))
	// result: (TSTconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64TSTconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TST x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (TSTshiftLL x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SLLconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64TSTshiftLL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (TST x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (TSTshiftRL x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SRLconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64TSTshiftRL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (TST x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (TSTshiftRA x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SRAconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64TSTshiftRA)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (TST x0 x1:(RORconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (TSTshiftRO x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64RORconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64TSTshiftRO)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64TSTW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (TSTW x (MOVDconst [c]))
	// result: (TSTWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64TSTWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64TSTWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TSTWconst (MOVDconst [x]) [y])
	// result: (FlagConstant [logicFlags32(int32(x)&y)])
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(logicFlags32(int32(x) & y))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TSTconst (MOVDconst [x]) [y])
	// result: (FlagConstant [logicFlags64(x&y)])
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(logicFlags64(x & y))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftLL (MOVDconst [c]) x [d])
	// result: (TSTconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftLL x (MOVDconst [c]) [d])
	// result: (TSTconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRA (MOVDconst [c]) x [d])
	// result: (TSTconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRAconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRA x (MOVDconst [c]) [d])
	// result: (TSTconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRL (MOVDconst [c]) x [d])
	// result: (TSTconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRL x (MOVDconst [c]) [d])
	// result: (TSTconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTshiftRO(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRO (MOVDconst [c]) x [d])
	// result: (TSTconst [c] (RORconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64RORconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRO x (MOVDconst [c]) [d])
	// result: (TSTconst x [rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(rotateRight64(c, d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UBFIZ(v *Value) bool {
	v_0 := v.Args[0]
	// match: (UBFIZ [bfc] (SLLconst [sc] x))
	// cond: sc < bfc.width()
	// result: (UBFIZ [armBFAuxInt(bfc.lsb()+sc, bfc.width()-sc)] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.width()) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()+sc, bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UBFX(v *Value) bool {
	v_0 := v.Args[0]
	// match: (UBFX [bfc] (ANDconst [c] x))
	// cond: isARM64BFMask(0, c, 0) && bfc.lsb() + bfc.width() <= arm64BFWidth(c, 0)
	// result: (UBFX [bfc] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isARM64BFMask(0, c, 0) && bfc.lsb()+bfc.width() <= arm64BFWidth(c, 0)) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] e:(MOVWUreg x))
	// cond: e.Uses == 1 && bfc.lsb() < 32
	// result: (UBFX [armBFAuxInt(bfc.lsb(), min(bfc.width(), 32-bfc.lsb()))] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		e := v_0
		if e.Op != OpARM64MOVWUreg {
			break
		}
		x := e.Args[0]
		if !(e.Uses == 1 && bfc.lsb() < 32) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb(), min(bfc.width(), 32-bfc.lsb())))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] e:(MOVHUreg x))
	// cond: e.Uses == 1 && bfc.lsb() < 16
	// result: (UBFX [armBFAuxInt(bfc.lsb(), min(bfc.width(), 16-bfc.lsb()))] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		e := v_0
		if e.Op != OpARM64MOVHUreg {
			break
		}
		x := e.Args[0]
		if !(e.Uses == 1 && bfc.lsb() < 16) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb(), min(bfc.width(), 16-bfc.lsb())))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] e:(MOVBUreg x))
	// cond: e.Uses == 1 && bfc.lsb() < 8
	// result: (UBFX [armBFAuxInt(bfc.lsb(), min(bfc.width(), 8-bfc.lsb()))] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		e := v_0
		if e.Op != OpARM64MOVBUreg {
			break
		}
		x := e.Args[0]
		if !(e.Uses == 1 && bfc.lsb() < 8) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb(), min(bfc.width(), 8-bfc.lsb())))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] (SRLconst [sc] x))
	// cond: sc+bfc.width()+bfc.lsb() < 64
	// result: (UBFX [armBFAuxInt(bfc.lsb()+sc, bfc.width())] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SRLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc+bfc.width()+bfc.lsb() < 64) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()+sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] (SLLconst [sc] x))
	// cond: sc == bfc.lsb()
	// result: (ANDconst [1<<uint(bfc.width())-1] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc == bfc.lsb()) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(1<<uint(bfc.width()) - 1)
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] (SLLconst [sc] x))
	// cond: sc < bfc.lsb()
	// result: (UBFX [armBFAuxInt(bfc.lsb()-sc, bfc.width())] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.lsb()) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()-sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] (SLLconst [sc] x))
	// cond: sc > bfc.lsb() && sc < bfc.lsb()+bfc.width()
	// result: (UBFIZ [armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc)] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc > bfc.lsb() && sc < bfc.lsb()+bfc.width()) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UDIV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (UDIV x (MOVDconst [1]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (UDIV x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (SRLconst [log64(c)] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(log64(c))
		v.AddArg(x)
		return true
	}
	// match: (UDIV (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint64(c)/uint64(d))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) / uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UDIVW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (UDIVW x (MOVDconst [c]))
	// cond: uint32(c)==1
	// result: (MOVWUreg x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) == 1) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v.AddArg(x)
		return true
	}
	// match: (UDIVW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c) && is32Bit(c)
	// result: (SRLconst [log64(c)] (MOVWUreg <v.Type> x))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(log64(c))
		v0 := b.NewValue0(v.Pos, OpARM64MOVWUreg, v.Type)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (UDIVW (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint32(c)/uint32(d))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c) / uint32(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UMOD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (UMOD <typ.UInt64> x y)
	// result: (MSUB <typ.UInt64> x y (UDIV <typ.UInt64> x y))
	for {
		if v.Type != typ.UInt64 {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64MSUB)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpARM64UDIV, typ.UInt64)
		v0.AddArg2(x, y)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (UMOD _ (MOVDconst [1]))
	// result: (MOVDconst [0])
	for {
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (UMOD x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (ANDconst [c-1] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(c - 1)
		v.AddArg(x)
		return true
	}
	// match: (UMOD (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint64(c)%uint64(d))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) % uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UMODW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (UMODW <typ.UInt32> x y)
	// result: (MSUBW <typ.UInt32> x y (UDIVW <typ.UInt32> x y))
	for {
		if v.Type != typ.UInt32 {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64MSUBW)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, OpARM64UDIVW, typ.UInt32)
		v0.AddArg2(x, y)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (UMODW _ (MOVDconst [c]))
	// cond: uint32(c)==1
	// result: (MOVDconst [0])
	for {
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) == 1) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (UMODW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c) && is32Bit(c)
	// result: (ANDconst [c-1] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(c - 1)
		v.AddArg(x)
		return true
	}
	// match: (UMODW (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint32(c)%uint32(d))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c) % uint32(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVDconst [c]))
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64XORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XOR x (MVN y))
	// result: (EON x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MVN {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpARM64EON)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (XORshiftLL x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SLLconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64XORshiftLL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (XOR x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (XORshiftRL x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SRLconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64XORshiftRL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (XOR x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (XORshiftRA x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SRAconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64XORshiftRA)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (XOR x0 x1:(RORconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (XORshiftRO x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64RORconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64XORshiftRO)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64XORconst(v *Value) bool {
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
	// match: (XORconst [-1] x)
	// result: (MVN x)
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.reset(OpARM64MVN)
		v.AddArg(x)
		return true
	}
	// match: (XORconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c^d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		return true
	}
	// match: (XORconst [c] (XORconst [d] x))
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64XORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64XORshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (XORshiftLL (MOVDconst [c]) x [d])
	// result: (XORconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftLL x (MOVDconst [c]) [d])
	// result: (XORconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL (SLLconst x [c]) x [c])
	// result: (MOVDconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XORshiftLL <typ.UInt16> [8] (UBFX <typ.UInt16> [armBFAuxInt(8, 8)] x) x)
	// result: (REV16W x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt64(v.AuxInt) != 8 || v_0.Op != OpARM64UBFX || v_0.Type != typ.UInt16 || auxIntToArm64BitField(v_0.AuxInt) != armBFAuxInt(8, 8) {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64REV16W)
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL [8] (UBFX [armBFAuxInt(8, 24)] (ANDconst [c1] x)) (ANDconst [c2] x))
	// cond: uint32(c1) == 0xff00ff00 && uint32(c2) == 0x00ff00ff
	// result: (REV16W x)
	for {
		if auxIntToInt64(v.AuxInt) != 8 || v_0.Op != OpARM64UBFX || auxIntToArm64BitField(v_0.AuxInt) != armBFAuxInt(8, 24) {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARM64ANDconst {
			break
		}
		c1 := auxIntToInt64(v_0_0.AuxInt)
		x := v_0_0.Args[0]
		if v_1.Op != OpARM64ANDconst {
			break
		}
		c2 := auxIntToInt64(v_1.AuxInt)
		if x != v_1.Args[0] || !(uint32(c1) == 0xff00ff00 && uint32(c2) == 0x00ff00ff) {
			break
		}
		v.reset(OpARM64REV16W)
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL [8] (SRLconst [8] (ANDconst [c1] x)) (ANDconst [c2] x))
	// cond: (uint64(c1) == 0xff00ff00ff00ff00 && uint64(c2) == 0x00ff00ff00ff00ff)
	// result: (REV16 x)
	for {
		if auxIntToInt64(v.AuxInt) != 8 || v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != 8 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARM64ANDconst {
			break
		}
		c1 := auxIntToInt64(v_0_0.AuxInt)
		x := v_0_0.Args[0]
		if v_1.Op != OpARM64ANDconst {
			break
		}
		c2 := auxIntToInt64(v_1.AuxInt)
		if x != v_1.Args[0] || !(uint64(c1) == 0xff00ff00ff00ff00 && uint64(c2) == 0x00ff00ff00ff00ff) {
			break
		}
		v.reset(OpARM64REV16)
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL [8] (SRLconst [8] (ANDconst [c1] x)) (ANDconst [c2] x))
	// cond: (uint64(c1) == 0xff00ff00 && uint64(c2) == 0x00ff00ff)
	// result: (REV16 (ANDconst <x.Type> [0xffffffff] x))
	for {
		if auxIntToInt64(v.AuxInt) != 8 || v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != 8 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARM64ANDconst {
			break
		}
		c1 := auxIntToInt64(v_0_0.AuxInt)
		x := v_0_0.Args[0]
		if v_1.Op != OpARM64ANDconst {
			break
		}
		c2 := auxIntToInt64(v_1.AuxInt)
		if x != v_1.Args[0] || !(uint64(c1) == 0xff00ff00 && uint64(c2) == 0x00ff00ff) {
			break
		}
		v.reset(OpARM64REV16)
		v0 := b.NewValue0(v.Pos, OpARM64ANDconst, x.Type)
		v0.AuxInt = int64ToAuxInt(0xffffffff)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftLL [c] (SRLconst x [64-c]) x2)
	// result: (EXTRconst [64-c] x2 x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != 64-c {
			break
		}
		x := v_0.Args[0]
		x2 := v_1
		v.reset(OpARM64EXTRconst)
		v.AuxInt = int64ToAuxInt(64 - c)
		v.AddArg2(x2, x)
		return true
	}
	// match: (XORshiftLL <t> [c] (UBFX [bfc] x) x2)
	// cond: c < 32 && t.Size() == 4 && bfc == armBFAuxInt(32-c, c)
	// result: (EXTRWconst [32-c] x2 x)
	for {
		t := v.Type
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		x2 := v_1
		if !(c < 32 && t.Size() == 4 && bfc == armBFAuxInt(32-c, c)) {
			break
		}
		v.reset(OpARM64EXTRWconst)
		v.AuxInt = int64ToAuxInt(32 - c)
		v.AddArg2(x2, x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64XORshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRA (MOVDconst [c]) x [d])
	// result: (XORconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRAconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRA x (MOVDconst [c]) [d])
	// result: (XORconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRA (SRAconst x [c]) x [c])
	// result: (MOVDconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRAconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64XORshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRL (MOVDconst [c]) x [d])
	// result: (XORconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRL x (MOVDconst [c]) [d])
	// result: (XORconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRL (SRLconst x [c]) x [c])
	// result: (MOVDconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64XORshiftRO(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRO (MOVDconst [c]) x [d])
	// result: (XORconst [c] (RORconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64RORconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRO x (MOVDconst [c]) [d])
	// result: (XORconst x [rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(rotateRight64(c, d))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRO (RORconst x [c]) x [c])
	// result: (MOVDconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64RORconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVDaddr {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpARM64MOVDaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueARM64_OpAvg64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg64u <t> x y)
	// result: (ADD (SRLconst <t> (SUB <t> x y) [1]) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpARM64ADD)
		v0 := b.NewValue0(v.Pos, OpARM64SRLconst, t)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpARM64SUB, t)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueARM64_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen32 x)
	// result: (SUB (MOVDconst [32]) (CLZW <typ.Int> x))
	for {
		x := v_0
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(32)
		v1 := b.NewValue0(v.Pos, OpARM64CLZW, typ.Int)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpBitLen64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen64 x)
	// result: (SUB (MOVDconst [64]) (CLZ <typ.Int> x))
	for {
		x := v_0
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(64)
		v1 := b.NewValue0(v.Pos, OpARM64CLZ, typ.Int)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpBitRev16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitRev16 x)
	// result: (SRLconst [48] (RBIT <typ.UInt64> x))
	for {
		x := v_0
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(48)
		v0 := b.NewValue0(v.Pos, OpARM64RBIT, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpBitRev8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitRev8 x)
	// result: (SRLconst [56] (RBIT <typ.UInt64> x))
	for {
		x := v_0
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(56)
		v0 := b.NewValue0(v.Pos, OpARM64RBIT, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpCondSelect(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CondSelect x y boolval)
	// cond: flagArg(boolval) != nil
	// result: (CSEL [boolval.Op] x y flagArg(boolval))
	for {
		x := v_0
		y := v_1
		boolval := v_2
		if !(flagArg(boolval) != nil) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(boolval.Op)
		v.AddArg3(x, y, flagArg(boolval))
		return true
	}
	// match: (CondSelect x y boolval)
	// cond: flagArg(boolval) == nil
	// result: (CSEL [OpARM64NotEqual] x y (TSTWconst [1] boolval))
	for {
		x := v_0
		y := v_1
		boolval := v_2
		if !(flagArg(boolval) == nil) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(1)
		v0.AddArg(boolval)
		v.AddArg3(x, y, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueARM64_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueARM64_OpConst32F(v *Value) bool {
	// match: (Const32F [val])
	// result: (FMOVSconst [float64(val)])
	for {
		val := auxIntToFloat32(v.AuxInt)
		v.reset(OpARM64FMOVSconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueARM64_OpConst64(v *Value) bool {
	// match: (Const64 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt64(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueARM64_OpConst64F(v *Value) bool {
	// match: (Const64F [val])
	// result: (FMOVDconst [float64(val)])
	for {
		val := auxIntToFloat64(v.AuxInt)
		v.reset(OpARM64FMOVDconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueARM64_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueARM64_OpConstBool(v *Value) bool {
	// match: (ConstBool [t])
	// result: (MOVDconst [b2i(t)])
	for {
		t := auxIntToBool(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(t))
		return true
	}
}
func rewriteValueARM64_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVDconst [0])
	for {
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValueARM64_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz16 <t> x)
	// result: (CLZW <t> (RBITW <typ.UInt32> (ORconst <typ.UInt32> [0x10000] x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64CLZW)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64RBITW, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpARM64ORconst, typ.UInt32)
		v1.AuxInt = int64ToAuxInt(0x10000)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Ctz32 <t> x)
	// result: (CLZW (RBITW <t> x))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64CLZW)
		v0 := b.NewValue0(v.Pos, OpARM64RBITW, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpCtz64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Ctz64 <t> x)
	// result: (CLZ (RBIT <t> x))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64CLZ)
		v0 := b.NewValue0(v.Pos, OpARM64RBIT, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz8 <t> x)
	// result: (CLZW <t> (RBITW <typ.UInt32> (ORconst <typ.UInt32> [0x100] x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64CLZW)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64RBITW, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpARM64ORconst, typ.UInt32)
		v1.AuxInt = int64ToAuxInt(0x100)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 [false] x y)
	// result: (DIVW (SignExt16to32 x) (SignExt16to32 y))
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64DIVW)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (UDIVW (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64UDIVW)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div32 [false] x y)
	// result: (DIVW x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64DIVW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div64 [false] x y)
	// result: (DIV x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64DIV)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (DIVW (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64DIVW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (UDIVW (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64UDIVW)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (Equal (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32 x y)
	// result: (Equal (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (Equal (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64 x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (Equal (FCMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (Equal (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (XOR (MOVDconst [1]) (XOR <typ.Bool> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64XOR)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpARM64XOR, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqPtr x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpFMA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMA x y z)
	// result: (FMADDD z x y)
	for {
		x := v_0
		y := v_1
		z := v_2
		v.reset(OpARM64FMADDD)
		v.AddArg3(z, x, y)
		return true
	}
}
func rewriteValueARM64_OpHmul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32 x y)
	// result: (SRAconst (MULL <typ.Int64> x y) [32])
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64SRAconst)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARM64MULL, typ.Int64)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpHmul32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32u x y)
	// result: (SRAconst (UMULL <typ.UInt64> x y) [32])
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64SRAconst)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARM64UMULL, typ.UInt64)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsInBounds idx len)
	// result: (LessThanU (CMP idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsNonNil ptr)
	// result: (NotEqual (CMPconst [0] ptr))
	for {
		ptr := v_0
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(0)
		v0.AddArg(ptr)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsSliceInBounds idx len)
	// result: (LessEqualU (CMP idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (LessEqual (CMPW (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x zero:(MOVDconst [0]))
	// result: (Eq16 x zero)
	for {
		x := v_0
		zero := v_1
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		v.reset(OpEq16)
		v.AddArg2(x, zero)
		return true
	}
	// match: (Leq16U (MOVDconst [1]) x)
	// result: (Neq16 (MOVDconst [0]) x)
	for {
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq16)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq16U x y)
	// result: (LessEqualU (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32 x y)
	// result: (LessEqual (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (LessEqualF (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualF)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32U x zero:(MOVDconst [0]))
	// result: (Eq32 x zero)
	for {
		x := v_0
		zero := v_1
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		v.reset(OpEq32)
		v.AddArg2(x, zero)
		return true
	}
	// match: (Leq32U (MOVDconst [1]) x)
	// result: (Neq32 (MOVDconst [0]) x)
	for {
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq32)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq32U x y)
	// result: (LessEqualU (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64 x y)
	// result: (LessEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (LessEqualF (FCMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualF)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64U x zero:(MOVDconst [0]))
	// result: (Eq64 x zero)
	for {
		x := v_0
		zero := v_1
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		v.reset(OpEq64)
		v.AddArg2(x, zero)
		return true
	}
	// match: (Leq64U (MOVDconst [1]) x)
	// result: (Neq64 (MOVDconst [0]) x)
	for {
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq64)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq64U x y)
	// result: (LessEqualU (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (LessEqual (CMPW (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x zero:(MOVDconst [0]))
	// result: (Eq8 x zero)
	for {
		x := v_0
		zero := v_1
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		v.reset(OpEq8)
		v.AddArg2(x, zero)
		return true
	}
	// match: (Leq8U (MOVDconst [1]) x)
	// result: (Neq8 (MOVDconst [0]) x)
	for {
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq8U x y)
	// result: (LessEqualU (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (LessThan (CMPW (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U zero:(MOVDconst [0]) x)
	// result: (Neq16 zero x)
	for {
		zero := v_0
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpNeq16)
		v.AddArg2(zero, x)
		return true
	}
	// match: (Less16U x (MOVDconst [1]))
	// result: (Eq16 x (MOVDconst [0]))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq16)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less16U x y)
	// result: (LessThanU (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32 x y)
	// result: (LessThan (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (LessThanF (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanF)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32U zero:(MOVDconst [0]) x)
	// result: (Neq32 zero x)
	for {
		zero := v_0
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpNeq32)
		v.AddArg2(zero, x)
		return true
	}
	// match: (Less32U x (MOVDconst [1]))
	// result: (Eq32 x (MOVDconst [0]))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq32)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less32U x y)
	// result: (LessThanU (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64 x y)
	// result: (LessThan (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (LessThanF (FCMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanF)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less64U zero:(MOVDconst [0]) x)
	// result: (Neq64 zero x)
	for {
		zero := v_0
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpNeq64)
		v.AddArg2(zero, x)
		return true
	}
	// match: (Less64U x (MOVDconst [1]))
	// result: (Eq64 x (MOVDconst [0]))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq64)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less64U x y)
	// result: (LessThanU (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (LessThan (CMPW (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U zero:(MOVDconst [0]) x)
	// result: (Neq8 zero x)
	for {
		zero := v_0
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpNeq8)
		v.AddArg2(zero, x)
		return true
	}
	// match: (Less8U x (MOVDconst [1]))
	// result: (Eq8 x (MOVDconst [0]))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less8U x y)
	// result: (LessThanU (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Load <t> ptr mem)
	// cond: t.IsBoolean()
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsBoolean()) {
			break
		}
		v.reset(OpARM64MOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && t.IsSigned())
	// result: (MOVBload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpARM64MOVBload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && !t.IsSigned())
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpARM64MOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && t.IsSigned())
	// result: (MOVHload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpARM64MOVHload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && !t.IsSigned())
	// result: (MOVHUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpARM64MOVHUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) && t.IsSigned())
	// result: (MOVWload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpARM64MOVWload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) && !t.IsSigned())
	// result: (MOVWUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpARM64MOVWUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (MOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpARM64MOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (FMOVSload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpARM64FMOVSload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (FMOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpARM64FMOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVDaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpARM64MOVDaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVDaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpARM64MOVDaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessT
"""




```