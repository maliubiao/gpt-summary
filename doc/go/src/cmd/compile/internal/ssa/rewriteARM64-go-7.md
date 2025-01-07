Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第8部分，共10部分，请归纳一下它的功能

"""
hanU)
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
func rewriteValueARM64_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x32 <t> x y)
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
	// match: (Lsh32x32 <t> x y)
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
func rewriteValueARM64_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x64 <t> x y)
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
	// match: (Lsh32x64 <t> x y)
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
func rewriteValueARM64_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 <t> x y)
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
	// match: (Lsh32x8 <t> x y)
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
func rewriteValueARM64_OpLsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x16 <t> x y)
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
	// match: (Lsh64x16 <t> x y)
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
func rewriteValueARM64_OpLsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x32 <t> x y)
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
	// match: (Lsh64x32 <t> x y)
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
func rewriteValueARM64_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh64x64 <t> x y)
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
	// match: (Lsh64x64 <t> x y)
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
func rewriteValueARM64_OpLsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x8 <t> x y)
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
	// match: (Lsh64x8 <t> x y)
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
func rewriteValueARM64_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 <t> x y)
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
	// match: (Lsh8x16 <t> x y)
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
func rewriteValueARM64_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 <t> x y)
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
	// match: (Lsh8x32 <t> x y)
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
func rewriteValueARM64_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x64 <t> x y)
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
	// match: (Lsh8x64 <t> x y)
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
func rewriteValueARM64_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 <t> x y)
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
	// match: (Lsh8x8 <t> x y)
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
func rewriteValueARM64_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (MODW (SignExt16to32 x) (SignExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64MODW)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (UMODW (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64UMODW)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod32 x y)
	// result: (MODW x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64MODW)
		v.AddArg2(x, y)
		return true
	}
}
func rewriteValueARM64_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod64 x y)
	// result: (MOD x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64MOD)
		v.AddArg2(x, y)
		return true
	}
}
func rewriteValueARM64_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (MODW (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64MODW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (UMODW (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64UMODW)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Move [0] _ _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.copyOf(mem)
		return true
	}
	// match: (Move [1] dst src mem)
	// result: (MOVBstore dst (MOVBUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVBUload, typ.UInt8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVHstore dst (MOVHUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVHUload, typ.UInt16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBUload [2] src mem) (MOVHstore dst (MOVHUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARM64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVHUload, typ.UInt16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVWstore dst (MOVWUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [5] dst src mem)
	// result: (MOVBstore [4] dst (MOVBUload [4] src mem) (MOVWstore dst (MOVWUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpARM64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [6] dst src mem)
	// result: (MOVHstore [4] dst (MOVHUload [4] src mem) (MOVWstore dst (MOVWUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpARM64MOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [7] dst src mem)
	// result: (MOVWstore [3] dst (MOVWUload [3] src mem) (MOVWstore dst (MOVWUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] dst src mem)
	// result: (MOVDstore dst (MOVDload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [9] dst src mem)
	// result: (MOVBstore [8] dst (MOVBUload [8] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 9 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [10] dst src mem)
	// result: (MOVHstore [8] dst (MOVHUload [8] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 10 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [11] dst src mem)
	// result: (MOVDstore [3] dst (MOVDload [3] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 11 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [12] dst src mem)
	// result: (MOVWstore [8] dst (MOVWUload [8] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [13] dst src mem)
	// result: (MOVDstore [5] dst (MOVDload [5] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 13 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(5)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(5)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [14] dst src mem)
	// result: (MOVDstore [6] dst (MOVDload [6] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 14 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(6)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [15] dst src mem)
	// result: (MOVDstore [7] dst (MOVDload [7] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 15 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(7)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [16] dst src mem)
	// result: (STP dst (Select0 <typ.UInt64> (LDP src mem)) (Select1 <typ.UInt64> (LDP src mem)) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64STP)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v1.AddArg2(src, mem)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2.AddArg(v1)
		v.AddArg4(dst, v0, v2, mem)
		return true
	}
	// match: (Move [32] dst src mem)
	// result: (STP [16] dst (Select0 <typ.UInt64> (LDP [16] src mem)) (Select1 <typ.UInt64> (LDP [16] src mem)) (STP dst (Select0 <typ.UInt64> (LDP src mem)) (Select1 <typ.UInt64> (LDP src mem)) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v1.AuxInt = int32ToAuxInt(16)
		v1.AddArg2(src, mem)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v5 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v5.AddArg2(src, mem)
		v4.AddArg(v5)
		v6 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v6.AddArg(v5)
		v3.AddArg4(dst, v4, v6, mem)
		v.AddArg4(dst, v0, v2, v3)
		return true
	}
	// match: (Move [48] dst src mem)
	// result: (STP [32] dst (Select0 <typ.UInt64> (LDP [32] src mem)) (Select1 <typ.UInt64> (LDP [32] src mem)) (STP [16] dst (Select0 <typ.UInt64> (LDP [16] src mem)) (Select1 <typ.UInt64> (LDP [16] src mem)) (STP dst (Select0 <typ.UInt64> (LDP src mem)) (Select1 <typ.UInt64> (LDP src mem)) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 48 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v1.AuxInt = int32ToAuxInt(32)
		v1.AddArg2(src, mem)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(16)
		v4 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v5 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v5.AuxInt = int32ToAuxInt(16)
		v5.AddArg2(src, mem)
		v4.AddArg(v5)
		v6 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v6.AddArg(v5)
		v7 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v8 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v9 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v9.AddArg2(src, mem)
		v8.AddArg(v9)
		v10 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v10.AddArg(v9)
		v7.AddArg4(dst, v8, v10, mem)
		v3.AddArg4(dst, v4, v6, v7)
		v.AddArg4(dst, v0, v2, v3)
		return true
	}
	// match: (Move [64] dst src mem)
	// result: (STP [48] dst (Select0 <typ.UInt64> (LDP [48] src mem)) (Select1 <typ.UInt64> (LDP [48] src mem)) (STP [32] dst (Select0 <typ.UInt64> (LDP [32] src mem)) (Select1 <typ.UInt64> (LDP [32] src mem)) (STP [16] dst (Select0 <typ.UInt64> (LDP [16] src mem)) (Select1 <typ.UInt64> (LDP [16] src mem)) (STP dst (Select0 <typ.UInt64> (LDP src mem)) (Select1 <typ.UInt64> (LDP src mem)) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 64 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(48)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v1.AuxInt = int32ToAuxInt(48)
		v1.AddArg2(src, mem)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(32)
		v4 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v5 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v5.AuxInt = int32ToAuxInt(32)
		v5.AddArg2(src, mem)
		v4.AddArg(v5)
		v6 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v6.AddArg(v5)
		v7 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v7.AuxInt = int32ToAuxInt(16)
		v8 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v9 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v9.AuxInt = int32ToAuxInt(16)
		v9.AddArg2(src, mem)
		v8.AddArg(v9)
		v10 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v10.AddArg(v9)
		v11 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v12 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v13 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v13.AddArg2(src, mem)
		v12.AddArg(v13)
		v14 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v14.AddArg(v13)
		v11.AddArg4(dst, v12, v14, mem)
		v7.AddArg4(dst, v8, v10, v11)
		v3.AddArg4(dst, v4, v6, v7)
		v.AddArg4(dst, v0, v2, v3)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%16 != 0 && s%16 <= 8 && s > 16
	// result: (Move [8] (OffPtr <dst.Type> dst [s-8]) (OffPtr <src.Type> src [s-8]) (Move [s-s%16] dst src mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%16 != 0 && s%16 <= 8 && s > 16) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpOffPtr, dst.Type)
		v0.AuxInt = int64ToAuxInt(s - 8)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpOffPtr, src.Type)
		v1.AuxInt = int64ToAuxInt(s - 8)
		v1.AddArg(src)
		v2 := b.NewValue0(v.Pos, OpMove, types.TypeMem)
		v2.AuxInt = int64ToAuxInt(s - s%16)
		v2.AddArg3(dst, src, mem)
		v.AddArg3(v0, v1, v2)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%16 != 0 && s%16 > 8 && s > 16
	// result: (Move [16] (OffPtr <dst.Type> dst [s-16]) (OffPtr <src.Type> src [s-16]) (Move [s-s%16] dst src mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%16 != 0 && s%16 > 8 && s > 16) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpOffPtr, dst.Type)
		v0.AuxInt = int64ToAuxInt(s - 16)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpOffPtr, src.Type)
		v1.AuxInt = int64ToAuxInt(s - 16)
		v1.AddArg(src)
		v2 := b.NewValue0(v.Pos, OpMove, types.TypeMem)
		v2.AuxInt = int64ToAuxInt(s - s%16)
		v2.AddArg3(dst, src, mem)
		v.AddArg3(v0, v1, v2)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 64 && s <= 16*64 && s%16 == 0 && !config.noDuffDevice && logLargeCopy(v, s)
	// result: (DUFFCOPY [8 * (64 - s/16)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 64 && s <= 16*64 && s%16 == 0 && !config.noDuffDevice && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpARM64DUFFCOPY)
		v.AuxInt = int64ToAuxInt(8 * (64 - s/16))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%16 == 0 && (s > 16*64 || config.noDuffDevice) && logLargeCopy(v, s)
	// result: (LoweredMove dst src (ADDconst <src.Type> src [s-16]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%16 == 0 && (s > 16*64 || config.noDuffDevice) && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpARM64LoweredMove)
		v0 := b.NewValue0(v.Pos, OpARM64ADDconst, src.Type)
		v0.AuxInt = int64ToAuxInt(s - 16)
		v0.AddArg(src)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (NotEqual (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
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
func rewriteValueARM64_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32 x y)
	// result: (NotEqual (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32F x y)
	// result: (NotEqual (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64 x y)
	// result: (NotEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64F x y)
	// result: (NotEqual (FCMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (NotEqual (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
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
func rewriteValueARM64_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (NeqPtr x y)
	// result: (NotEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Not x)
	// result: (XOR (MOVDconst [1]) x)
	for {
		x := v_0
		v.reset(OpARM64XOR)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueARM64_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr [off] ptr:(SP))
	// cond: is32Bit(off)
	// result: (MOVDaddr [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if ptr.Op != OpSP || !(is32Bit(off)) {
			break
		}
		v.reset(OpARM64MOVDaddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// result: (ADDconst [off] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(off)
		v.AddArg(ptr)
		return true
	}
}
func rewriteValueARM64_OpPanicBounds(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 0
	// result: (LoweredPanicBoundsA [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 0) {
			break
		}
		v.reset(OpARM64LoweredPanicBoundsA)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 1
	// result: (LoweredPanicBoundsB [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 1) {
			break
		}
		v.reset(OpARM64LoweredPanicBoundsB)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 2
	// result: (LoweredPanicBoundsC [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 2) {
			break
		}
		v.reset(OpARM64LoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpPopCount16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount16 <t> x)
	// result: (FMOVDfpgp <t> (VUADDLV <typ.Float64> (VCNT <typ.Float64> (FMOVDgpfp <typ.Float64> (ZeroExt16to64 x)))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64FMOVDfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64VUADDLV, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpARM64VCNT, typ.Float64)
		v2 := b.NewValue0(v.Pos, OpARM64FMOVDgpfp, typ.Float64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(x)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpPopCount32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount32 <t> x)
	// result: (FMOVDfpgp <t> (VUADDLV <typ.Float64> (VCNT <typ.Float64> (FMOVDgpfp <typ.Float64> (ZeroExt32to64 x)))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64FMOVDfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64VUADDLV, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpARM64VCNT, typ.Float64)
		v2 := b.NewValue0(v.Pos, OpARM64FMOVDgpfp, typ.Float64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(x)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpPopCount64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount64 <t> x)
	// result: (FMOVDfpgp <t> (VUADDLV <typ.Float64> (VCNT <typ.Float64> (FMOVDgpfp <typ.Float64> x))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64FMOVDfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64VUADDLV, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpARM64VCNT, typ.Float64)
		v2 := b.NewValue0(v.Pos, OpARM64FMOVDgpfp, typ.Float64)
		v2.AddArg(x)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpPrefetchCache(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PrefetchCache addr mem)
	// result: (PRFM [0] addr mem)
	for {
		addr := v_0
		mem := v_1
		v.reset(OpARM64PRFM)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg2(addr, mem)
		return true
	}
}
func rewriteValueARM64_OpPrefetchCacheStreamed(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PrefetchCacheStreamed addr mem)
	// result: (PRFM [1] addr mem)
	for {
		addr := v_0
		mem := v_1
		v.reset(OpARM64PRFM)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg2(addr, mem)
		return true
	}
}
func rewriteValueARM64_OpPubBarrier(v *Value) bool {
	v_0 := v.Args[0]
	// match: (PubBarrier mem)
	// result: (DMB [0xe] mem)
	for {
		mem := v_0
		v.reset(OpARM64DMB)
		v.AuxInt = int64ToAuxInt(0xe)
		v.AddArg(mem)
		return true
	}
}
func rewriteValueARM64_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVDconst [c]))
	// result: (Or16 (Lsh16x64 <t> x (MOVDconst [c&15])) (Rsh16Ux64 <t> x (MOVDconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v3 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (RotateLeft16 <t> x y)
	// result: (RORW <t> (ORshiftLL <typ.UInt32> (ZeroExt16to32 x) (ZeroExt16to32 x) [16]) (NEG <typ.Int64> y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpARM64RORW)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64ORshiftLL, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(16)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, v1)
		v2 := b.NewValue0(v.Pos, OpARM64NEG, typ.Int64)
		v2.AddArg(y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM64_OpRotateLeft32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RotateLeft32 x y)
	// result: (RORW x (NEG <y.Type> y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64RORW)
		v0 := b.NewValue0(v.Pos, OpARM64NEG, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM64_OpRotateLeft64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RotateLeft64 x y)
	// result: (ROR x (NEG <y.Type> y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64ROR)
		v0 := b.NewValue0(v.Pos, OpARM64NEG, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM64_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVDconst [c]))
	// result: (Or8 (Lsh8x64 <t> x (MOVDconst [c&7])) (Rsh8Ux64 <t> x (MOVDconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v3 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (RotateLeft8 <t> x y)
	// result: (OR <t> (SLL <t> x (ANDconst <typ.Int64> [7] y)) (SRL <t> (ZeroExt8to64 x) (ANDconst <typ.Int64> [7] (NEG <typ.Int64> y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpARM64OR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v1 := b.NewValue0(v.Pos, OpARM64ANDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(7)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpARM64ANDconst, typ.Int64)
		v4.AuxInt = int64ToAuxInt(7)
		v5 := b.NewValue0(v.Pos, OpARM64NEG, typ.Int64)
		v5.AddArg(y)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM64_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt16to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt16to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt16to64 x) y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt16to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x16 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt16to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x32 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt32to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x64 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] y)))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x8 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt8to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt32to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt32to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt32to64 x) y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt32to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32x16 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt32to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt16to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32x32 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt32to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt32to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32x64 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt32to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] y)))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32x8 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt32to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt8to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
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
func rewriteValueARM64_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
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
func rewriteValueARM64_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64Ux64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> x y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
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
func rewriteValueARM64_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
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
func rewriteValueARM64_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x16 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA x (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt16to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v0.AuxInt = opToAuxInt(OpARM64LessThanU)
		v1 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x32 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA x (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt32to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v0.AuxInt = opToAuxInt(OpARM64Le
"""




```