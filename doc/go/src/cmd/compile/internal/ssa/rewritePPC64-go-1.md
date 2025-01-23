Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```go
v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0x00F0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x16 <t> x y)
	// result: (ISEL [2] (SLW <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFE0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFE0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x32 <t> x y)
	// result: (ISEL [0] (SLW <t> x y) (MOVDconst [0]) (CMPWUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x64 x (MOVDconst [c]))
	// cond: uint64(c) < 32
	// result: (SLWconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(OpPPC64SLWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Lsh32x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x64 <t> x y)
	// result: (ISEL [0] (SLW <t> x y) (MOVDconst [0]) (CMPUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x8 <t> x y)
	// result: (ISEL [2] (SLW <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00E0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00E0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpLsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x16 <t> x y)
	// result: (ISEL [2] (SLD <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFC0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFC0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpLsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x32 <t> x y)
	// result: (ISEL [0] (SLD <t> x y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x64 x (MOVDconst [c]))
	// cond: uint64(c) < 64
	// result: (SLDconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 64) {
			break
		}
		v.reset(OpPPC64SLDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Lsh64x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x64 <t> x y)
	// result: (ISEL [0] (SLD <t> x y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpLsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x8 <t> x y)
	// result: (ISEL [2] (SLD <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00C0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00C0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x16 <t> x y)
	// result: (ISEL [2] (SLD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFF8] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x32 <t> x y)
	// result: (ISEL [0] (SLD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPWUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x64 x (MOVDconst [c]))
	// cond: uint64(c) < 8
	// result: (SLWconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(OpPPC64SLWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Lsh8x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x64 <t> x y)
	// result: (ISEL [0] (SLD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x8 <t> x y)
	// result: (ISEL [2] (SLD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00F8] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0x00F8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpMax32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Max32F x y)
	// cond: buildcfg.GOPPC64 >= 9
	// result: (XSMAXJDP x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64XSMAXJDP)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValuePPC64_OpMax64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Max64F x y)
	// cond: buildcfg.GOPPC64 >= 9
	// result: (XSMAXJDP x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64XSMAXJDP)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValuePPC64_OpMin32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Min32F x y)
	// cond: buildcfg.GOPPC64 >= 9
	// result: (XSMINJDP x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64XSMINJDP)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValuePPC64_OpMin64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Min64F x y)
	// cond: buildcfg.GOPPC64 >= 9
	// result: (XSMINJDP x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64XSMINJDP)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValuePPC64_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (Mod32 (SignExt16to32 x) (SignExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuePPC64_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (Mod32u (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuePPC64_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32 x y)
	// cond: buildcfg.GOPPC64 >= 9
	// result: (MODSW x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64MODSW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Mod32 x y)
	// cond: buildcfg.GOPPC64 <= 8
	// result: (SUB x (MULLW y (DIVW x y)))
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 <= 8) {
			break
		}
		v.reset(OpPPC64SUB)
		v0 := b.NewValue0(v.Pos, OpPPC64MULLW, typ.Int32)
		v1 := b.NewValue0(v.Pos, OpPPC64DIVW, typ.Int32)
		v1.AddArg2(x, y)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32u x y)
	// cond: buildcfg.GOPPC64 >= 9
	// result: (MODUW x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64MODUW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Mod32u x y)
	// cond: buildcfg.GOPPC64 <= 8
	// result: (SUB x (MULLW y (DIVWU x y)))
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 <= 8) {
			break
		}
		v.reset(OpPPC64SUB)
		v0 := b.NewValue0(v.Pos, OpPPC64MULLW, typ.Int32)
		v1 := b.NewValue0(v.Pos, OpPPC64DIVWU, typ.Int32)
		v1.AddArg2(x, y)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod64 x y)
	// cond: buildcfg.GOPPC64 >=9
	// result: (MODSD x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64MODSD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Mod64 x y)
	// cond: buildcfg.GOPPC64 <=8
	// result: (SUB x (MULLD y (DIVD x y)))
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 <= 8) {
			break
		}
		v.reset(OpPPC64SUB)
		v0 := b.NewValue0(v.Pos, OpPPC64MULLD, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpPPC64DIVD, typ.Int64)
		v1.AddArg2(x, y)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpMod64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod64u x y)
	// cond: buildcfg.GOPPC64 >= 9
	// result: (MODUD x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64MODUD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Mod64u x y)
	// cond: buildcfg.GOPPC64 <= 8
	// result: (SUB x (MULLD y (DIVDU x y)))
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GOPPC64 <= 8) {
			break
		}
		v.reset(OpPPC64SUB)
		v0 := b.NewValue0(v.Pos, OpPPC64MULLD, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpPPC64DIVDU, typ.Int64)
		v1.AddArg2(x, y)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (Mod32 (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuePPC64_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (Mod32u (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuePPC64_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
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
	// result: (MOVBstore dst (MOVBZload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpPPC64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZload, typ.UInt8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVHstore dst (MOVHZload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpPPC64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZload, typ.UInt16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVWstore dst (MOVWZload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpPPC64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWZload, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [8] {t} dst src mem)
	// result: (MOVDstore dst (MOVDload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpPPC64MOVDstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDload, typ.Int64)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBZload [2] src mem) (MOVHstore dst (MOVHload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVHload, typ.Int16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [5] dst src mem)
	// result: (MOVBstore [4] dst (MOVBZload [4] src mem) (MOVWstore dst (MOVWZload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVWZload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [6] dst src mem)
	// result: (MOVHstore [4] dst (MOVHZload [4] src mem) (MOVWstore dst (MOVWZload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVWZload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [7] dst src mem)
	// result: (MOVBstore [6] dst (MOVBZload [6] src mem) (MOVHstore [4] dst (MOVHZload [4] src mem) (MOVWstore dst (MOVWZload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpPPC64MOVBstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(6)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVHZload, typ.UInt16)
		v2.AuxInt = int32ToAuxInt(4)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpPPC64MOVWstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpPPC64MOVWZload, typ.UInt32)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 8 && buildcfg.GOPPC64 <= 8 && logLargeCopy(v, s)
	// result: (LoweredMove [s] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 8 && buildcfg.GOPPC64 <= 8 && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpPPC64LoweredMove)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 8 && s <= 64 && buildcfg.GOPPC64 >= 9
	// result: (LoweredQuadMoveShort [s] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 8 && s <= 64 && buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64LoweredQuadMoveShort)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 8 && buildcfg.GOPPC64 >= 9 && logLargeCopy(v, s)
	// result: (LoweredQuadMove [s] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 8 && buildcfg.GOPPC64 >= 9 && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpPPC64LoweredQuadMove)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg3(dst, src, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// cond: x.Type.IsSigned() && y.Type.IsSigned()
	// result: (NotEqual (CMPW (SignExt16to32 x) (SignExt16to32 y)))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			y := v_1
			if !(x.Type.IsSigned() && y.Type.IsSigned()) {
				continue
			}
			v.reset(OpPPC64NotEqual)
			v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
			v1.AddArg(x)
			v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
			v2.AddArg(y)
			v0.AddArg2(v1, v2)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Neq16 x y)
	// result: (NotEqual (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64NotEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32 x y)
	// result: (NotEqual (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64NotEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32F x y)
	// result: (NotEqual (FCMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64NotEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64FCMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64 x y)
	// result: (NotEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64NotEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64F x y)
	// result: (NotEqual (FCMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64NotEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64FCMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// cond: x.Type.IsSigned() && y.Type.IsSigned()
	// result: (NotEqual (CMPW (SignExt8to32 x) (SignExt8to32 y)))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			y := v_1
			if !(x.Type.IsSigned() && y.Type.IsSigned()) {
				continue
			}
			v.reset(OpPPC64NotEqual)
			v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
			v1.AddArg(x)
			v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
			v2.AddArg(y)
			v0.AddArg2(v1, v2)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Neq8 x y)
	// result: (NotEqual (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64NotEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (NeqPtr x y)
	// result: (NotEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64NotEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not x)
	// result: (XORconst [1] x)
	for {
		x := v_0
		v.reset(OpPPC64XORconst)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (OffPtr [off] ptr)
	// result: (ADD (MOVDconst <typ.Int64> [off]) ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpPPC64ADD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v0.AuxInt = int64ToAuxInt(off)
		v.AddArg2(v0, ptr)
		return true
	}
}
func rewriteValuePPC64_OpPPC64ADD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADD l:(MULLD x y) z)
	// cond: buildcfg.GOPPC64 >= 9 && l.Uses == 1 && clobber(l)
	// result: (MADDLD x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			l := v_0
			if l.Op != OpPPC64MULLD {
				continue
			}
			y := l.Args[1]
			x := l.Args[0]
			z := v_1
			if !(buildcfg.GOPPC64 >= 9 && l.Uses == 1 && clobber(l)) {
				continue
			}
			v.reset(OpPPC64MADDLD)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (ADD x (MOVDconst <t> [c]))
	// cond: is32Bit(c) && !t.IsPtr()
	// result: (ADDconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			t := v_1.Type
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c) && !t.IsPtr()) {
				continue
			}
			v.reset(OpPPC64ADDconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64ADDC(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDC x (MOVDconst [y]))
	// cond: is16Bit(y)
	// result: (ADDCconst [y] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			y := auxIntToInt64(v_1.AuxInt)
			if !(is16Bit(y)) {
				continue
			}
			v.reset(OpPPC64ADDCconst)
			v.AuxInt = int64ToAuxInt(y)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64ADDE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ADDE x y (Select1 <typ.UInt64> (ADDCconst (MOVDconst [0]) [-1])))
	// result: (ADDC x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 || v_2.Type != typ.UInt64 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64ADDCconst || auxIntToInt64(v_2_0.AuxInt) != -1 {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpPPC64MOVDconst || auxIntToInt64(v_2_0_0.AuxInt) != 0 {
			break
		}
		v.reset(OpPPC64ADDC)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDE (MOVDconst [0]) y c)
	// result: (ADDZE y c)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			y := v_1
			c := v_2
			v.reset(OpPPC64ADDZE)
			v.AddArg2(y, c)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64ADDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDconst [c] (ADDconst [d] x))
	// cond: is32Bit(c+d)
	// result: (ADDconst [c+d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c + d)) {
			break
		}
		v.reset(OpPPC64ADDconst)
		v.AuxInt = int64ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ADDconst [c] (MOVDaddr [d] {sym} x))
	// cond: is32Bit(c+int64(d))
	// result: (MOVDaddr [int32(c+int64(d))] {sym} x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVDaddr {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		if !(is32Bit(c + int64(d))) {
			break
		}
		v.reset(OpPPC64MOVDaddr)
		v.AuxInt = int32ToAuxInt(int32(c + int64(d)))
		v.Aux = symToAux(sym)
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [c] x:(SP))
	// cond: is32Bit(c)
	// result: (MOVDaddr [int32(c)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if x.Op != OpSP || !(is32Bit(c)) {
			break
		}
		v.reset(OpPPC64MOVDaddr)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [c] (SUBFCconst [d] x))
	// cond: is32Bit(c+d)
	// result: (SUBFCconst [c+d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64SUBFCconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c + d)) {
			break
		}
		v.reset(OpPPC64SUBFCconst)
		v.AuxInt = int64ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64AND(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AND (MOVDconst [m]) (ROTLWconst [r] x))
	// cond: isPPC64WordRotateMask(m)
	// result: (RLWINM [encodePPC64RotateMask(r,m,32)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64ROTLWconst {
				continue
			}
			r := auxIntToInt64(v_1.AuxInt)
			x := v_1.Args[0]
			if !(isPPC64WordRotateMask(m)) {
				continue
			}
			v.reset(OpPPC64RLWINM)
			v.AuxInt = int64ToAuxInt(encodePPC64RotateMask(r, m, 32))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [m]) (ROTLW x r))
	// cond: isPPC64WordRotateMask(m)
	// result: (RLWNM [encodePPC64RotateMask(0,m,32)] x r)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64ROTLW {
				continue
			}
			r := v_1.Args[1]
			x := v_1.Args[0]
			if !(isPPC64WordRotateMask(m)) {
				continue
			}
			v.reset(OpPPC64RLWNM)
			v.AuxInt = int64ToAuxInt(encodePPC64RotateMask(0, m, 32))
			v.AddArg2(x, r)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [m]) (SRWconst x [s]))
	// cond: mergePPC64RShiftMask(m,s,32) == 0
	// result: (MOVDconst [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64SRWconst {
				continue
			}
			s := auxIntToInt64(v_1.AuxInt)
			if !(mergePPC64RShiftMask(m, s, 32) == 0) {
				continue
			}
			v.reset(OpPPC64MOVDconst)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [m]) (SRWconst x [s]))
	// cond: mergePPC64AndSrwi(m,s) != 0
	// result: (RLWINM [mergePPC64AndSrwi(m,s)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64SRWconst {
				continue
			}
			s := auxIntToInt64(v_1.AuxInt)
			x := v_1.Args[0]
			if !(mergePPC64AndSrwi(m, s) != 0) {
				continue
			}
			v.reset(OpPPC64RLWINM)
			v.AuxInt = int64ToAuxInt(mergePPC64AndSrwi(m, s))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [m]) (SRDconst x [s]))
	// cond: mergePPC64AndSrdi(m,s) != 0
	// result: (RLWINM [mergePPC64AndSrdi(m,s)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64SRDconst {
				continue
			}
			s := auxIntToInt64(v_1.AuxInt)
			x := v_1.Args[0]
			if !(mergePPC64AndSrdi(m, s) != 0) {
				continue
			}
			v.reset(OpPPC64RLWINM)
			v.AuxInt = int64ToAuxInt(mergePPC64AndSrdi(m, s))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [m]) (SLDconst x [s]))
	// cond: mergePPC64AndSldi(m,s) != 0
	// result: (RLWINM [mergePPC64AndSldi(m,s)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64SLDconst {
				continue
			}
			s := auxIntToInt64(v_1.AuxInt)
			x := v_1.Args[0]
			if !(mergePPC64AndSldi(m, s) != 0) {
				continue
			}
			v.reset(OpPPC64RLWINM)
			v.AuxInt = int64ToAuxInt(mergePPC64AndSldi(m, s))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND x (NOR y y))
	// result: (ANDN x y)
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
			v.reset(OpPPC64ANDN)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c&d])
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
			v.AuxInt = int64ToAuxInt(c & d)
			return true
		}
		break
	}
	// match: (AND x (MOVDconst [-1]))
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst || auxIntToInt64(v_1.AuxInt) != -1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (AND x (MOVDconst [c]))
	// cond: isU16Bit(c)
	// result: (ANDconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isU16Bit(c)) {
				continue
			}
			v.reset(OpPPC64ANDconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [c]) y:(MOVWZreg _))
	// cond: c&0xFFFFFFFF == 0xFFFFFFFF
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			y := v_1
			if y.Op != OpPPC64MOVWZreg || !(c&0xFFFFFFFF == 0xFFFFFFFF) {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [0xFFFFFFFF]) y:(MOVWreg x))
	// result: (MOVWZreg x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst || auxIntToInt64(v_0.AuxInt) != 0xFFFFFFFF {
				continue
			}
			y := v_1
			if y.Op != OpPPC64MOVWreg {
				continue
			}
			x := y.Args[0]
			v.reset(OpPPC64MOVWZreg)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND (MOVDconst [c]) x:(MOVBZload _ _))
	// result: (ANDconst [c&0xFF] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			x := v_1
			if x.Op != OpPPC64MOVBZload {
				continue
			}
			v.reset(OpPPC64ANDconst)
			v.AuxInt = int64ToAuxInt(c & 0xFF)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64ANDN(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDN (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c&^d])
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
		v.AuxInt = int64ToAuxInt(c &^ d)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64ANDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDconst [m] (ROTLWconst [r] x))
	// cond: isPPC64WordRotateMask(m)
	// result: (RLWINM [encodePPC64RotateMask(r,m,32)] x)
	for {
		m := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ROTLWconst {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isPPC64WordRotateMask(m)) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(encodePPC64RotateMask(r, m, 32))
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [m] (ROTLW x r))
	// cond: isPPC64WordRotateMask(m)
	// result: (RLWNM [encodePPC64RotateMask(0,m,32)] x r)
	for {
		m := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ROTLW {
			break
		}
		r := v_0.Args[1]
		x := v_0.Args[0]
		if !(isPPC64WordRotateMask(m)) {
			break
		}
		v.reset(OpPPC64RLWNM)
		v.AuxInt = int64ToAuxInt(encodePPC64RotateMask(0, m, 32))
		v.AddArg2(x, r)
		return true
	}
	// match: (ANDconst [m] (SRWconst x [s]))
	// cond: mergePPC64RShiftMask(m,s,32) == 0
	// result: (MOVDconst [0])
	for {
		m := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		s := auxIntToInt64(v_0.AuxInt)
		if !(mergePPC64RShiftMask(m, s, 32) == 0) {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (ANDconst [m] (SRWconst x [s]))
	// cond: mergePPC64AndSrwi(m,s) != 0
	// result: (RLWINM [mergePPC64AndSrwi(m,s)] x)
	for {
		m := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		s := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64AndSrwi(m, s) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndSrwi(m, s))
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [m] (SRDconst x [s]))
	// cond: mergePPC64AndSrdi(m,s) != 0
	// result: (RLWINM [mergePPC64AndSrdi(m,s)] x)
	for {
		m := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		s := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64AndSrdi(m, s) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndSrdi(m, s))
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [m] (SLDconst x [s]))
	// cond: mergePPC64AndSldi(m,s) != 0
	// result: (RLWINM [mergePPC64AndSldi(m,s)] x)
	for {
		m := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64SLDconst {
			break
		}
		s := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64AndSldi(m, s) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndSldi(m, s))
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [c] (ANDconst [d] x))
	// result: (ANDconst [c&d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpPPC64ANDconst)
		v.AuxInt = int64ToAuxInt(c & d)
		v.AddArg(x)
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
	// match: (ANDconst [0] _)
	// result: (MOVDconst [0])
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (ANDconst [c] y:(MOVBZreg _))
	// cond: c&0xFF == 0xFF
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpPPC64MOVBZreg || !(c&0xFF == 0xFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ANDconst [0xFF] (MOVBreg x))
	// result: (MOVBZreg x)
	for {
		if auxIntToInt64(v.AuxInt) != 0xFF || v_0.Op != OpPPC64MOVBreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64MOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [c] y:(MOVHZreg _))
	// cond: c&0xFFFF == 0xFFFF
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpPPC64MOVHZreg || !(c&0xFFFF == 0xFFFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ANDconst [0xFFFF] (MOVHreg x))
	// result: (MOVHZreg x)
	for {
		if auxIntToInt64(v.AuxInt) != 0xFFFF || v_0.Op != OpPPC64MOVHreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64MOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [c] (MOVBZreg x))
	// result: (ANDconst [c&0xFF] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVBZreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64ANDconst)
		v.AuxInt = int64ToAuxInt(c & 0xFF)
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [c] (MOVHZreg x))
	// result: (ANDconst [c&0xFFFF] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64ANDconst)
		v.AuxInt = int64ToAuxInt(c & 0xFFFF)
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [c] (MOVWZreg x))
	// result: (ANDconst [c&0xFFFFFFFF] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64ANDconst)
		v.AuxInt = int64ToAuxInt(c & 0xFFFFFFFF)
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [m] (RLWINM [r] y))
	// cond: mergePPC64AndRlwinm(uint32(m),r) != 0
	// result: (RLWINM [mergePPC64AndRlwinm(uint32(m),r)] y)
	for {
		m := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64RLWINM {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if !(mergePPC64AndRlwinm(uint32(m), r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndRlwinm(uint32(m), r))
		v.AddArg(y)
		return true
	}
	// match: (ANDconst [1] z:(SRADconst [63] x))
	// cond: z.Uses == 1
	// result: (SRDconst [63] x)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		z := v_0
		if z.Op != OpPPC64SRADconst || auxIntToInt64(z.AuxInt) != 63 {
			break
		}
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64BRD(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BRD x:(MOVDload [off] {sym} ptr mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVDBRload (MOVDaddr <ptr.Type> [off] {sym} ptr) mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVDload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpPPC64MOVDBRload, typ.UInt64)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpPPC64MOVDaddr, ptr.Type)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (BRD x:(MOVDloadidx ptr idx mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVDBRloadidx ptr idx mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVDloadidx {
			break
		}
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDBRloadidx, typ.Int64)
		v.copyOf(v0)
		v0.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64BRH(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BRH x:(MOVHZload [off] {sym} ptr mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVHBRload (MOVDaddr <ptr.Type> [off] {sym} ptr) mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpPPC64MOVHBRload, typ.UInt16)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpPPC64MOVDaddr, ptr.Type)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (BRH x:(MOVHZloadidx ptr idx mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVHBRloadidx ptr idx mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZloadidx {
			break
		}
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHBRloadidx, typ.Int16)
		v.copyOf(v0)
		v0.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64BRW(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BRW x:(MOVWZload [off] {sym} ptr mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVWBRload (MOVDaddr <ptr.Type> [off] {sym} ptr) mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVWZload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpPPC64MOVWBRload, typ.UInt32)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpPPC64MOVDaddr, ptr.Type)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (BRW x:(MOVWZloadidx ptr idx mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVWBRloadidx ptr idx mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVWZloadidx {
			break
		}
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWBRloadidx, typ.Int32)
		v.copyOf(v0)
		v0.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64CLRLSLDI(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CLRLSLDI [c] (SRWconst [s] x))
	// cond: mergePPC64ClrlsldiSrw(int64(c),s) != 0
	// result: (RLWINM [mergePPC64ClrlsldiSrw(int64(c),s)] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		s := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64ClrlsldiSrw(int64(c), s) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64ClrlsldiSrw(int64(c), s))
		v.AddArg(x)
		return true
	}
	// match: (CLRLSLDI [c] (SRDconst [s] x))
	// cond: mergePPC64ClrlsldiSrd(int64(c),s) != 0
	// result: (RLWINM [mergePPC64ClrlsldiSrd(int64(c),s)] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		s := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64ClrlsldiSrd(int64(c), s) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64ClrlsldiSrd(int64(c), s))
		v.AddArg(x)
		return true
	}
	// match: (CLRLSLDI [c] i:(RLWINM [s] x))
	// cond: mergePPC64ClrlsldiRlwinm(c,s) != 0
	// result: (RLWINM [mergePPC64ClrlsldiRlwinm(c,s)] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		i := v_0
		if i.Op != OpPPC64RLWINM {
			break
		}
		s := auxIntToInt64(i.AuxInt)
		x := i.Args[0]
		if !(mergePPC64ClrlsldiRlwinm(c, s) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64ClrlsldiRlwinm(c, s))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64CMP(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMP x (MOVDconst [c]))
	// cond: is16Bit(c)
	// result: (CMPconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is16Bit(c)) {
			break
		}
		v.reset(OpPPC64CMPconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMP (MOVDconst [c]) y)
	// cond: is16Bit(c)
	// result: (InvertFlags (CMPconst y [c]))
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(is16Bit(c)) {
			break
		}
		v.reset(OpPPC64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
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
		v.reset(OpPPC64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpPPC64CMP, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64CMPU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPU x (MOVDconst [c]))
	// cond: isU16Bit(c)
	// result: (CMPUconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isU16Bit(c)) {
			break
		}
		v.reset(OpPPC64CMPUconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPU (MOVDconst [c]) y)
	// cond: isU16Bit(c)
	// result: (InvertFlags (CMPUconst y [c]))
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(isU16Bit(c)) {
			break
		}
		v.reset(OpPPC64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
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
		v.reset(OpPPC64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPU, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64CMPUconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPUconst [d] (ANDconst z [c]))
	// cond: uint64(d) > uint64(c)
	// result: (FlagLT)
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if !(uint64(d) > uint64(c)) {
			break
		}
		v.reset(OpPPC64FlagLT)
		return true
	}
	// match: (CMPUconst (MOVDconst [x]) [y])
	// cond: x==y
	// result: (FlagEQ)
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x == y) {
			break
		}
		v.reset(OpPPC64FlagEQ)
		return true
	}
	// match: (CMPUconst (MOVDconst [x]) [y])
	// cond: uint64(x)<uint64(y)
	// result: (FlagLT)
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint64(x) < uint64(y)) {
			break
		}
		v.reset(OpPPC64FlagLT)
		return true
	}
	// match: (CMPUconst (MOVDconst [x]) [y])
	// cond: uint64(x)>uint64(y)
	// result: (FlagGT)
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint64(x) > uint64(y)) {
			break
		}
		v.reset(OpPPC64FlagGT)
		return true
	}
	// match: (CMPUconst [0] a:(ANDconst [n] z))
	// result: (CMPconst [0] a)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpPPC64ANDconst {
			break
		}
		v.reset(OpPPC64CMPconst)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg(a)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64CMPW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPW x (MOVWreg y))
	// result: (CMPW x y)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64CMPW)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPW (MOVWreg x) y)
	// result: (CMPW x y)
	for {
		if v_0.Op != OpPPC64MOVWreg {
			break
		}
		x := v_0.Args[0]
		y := v_1
		v.reset(OpPPC64CMPW)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPW x (MOVDconst [c]))
	// cond: is16Bit(c)
	// result: (CMPWconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is16Bit(c)) {
			break
		}
		v.reset(OpPPC64CMPWconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPW (MOVDconst [c]) y)
	// cond: is16Bit(c)
	// result: (InvertFlags (CMPWconst y [int32(c)]))
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(is16Bit(c)) {
			break
		}
		v.reset(OpPPC64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
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
		v.reset(OpPPC64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64CMPWU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPWU x (MOVWZreg y))
	// result: (CMPWU x y)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64CMPWU)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPWU (MOVWZreg x) y)
	// result: (CMPWU x y)
	for {
		if v_0.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_0.Args[0]
		y := v_1
		v.reset(OpPPC64CMPWU)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPWU x (MOVDconst [c]))
	// cond: isU16Bit(c)
	// result: (CMPWUconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isU16Bit(c)) {
			break
		}
		v.reset(OpPPC64CMPWUconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPWU (MOVDconst [c]) y)
	// cond: isU16Bit(c)
	// result: (InvertFlags (CMPWUconst y [int32(c)]))
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(isU16Bit(c)) {
			break
		}
		v.reset(OpPPC64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
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
		v.reset(OpPPC64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPWU, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64CMPWUconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPWUconst [d] (ANDconst z [c]))
	// cond: uint64(d) > uint64(c)
	// result: (FlagLT)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if !(uint64(d) > uint64(c)) {
			break
		}
		v.reset(OpPPC64FlagLT)
		return true
	}
	// match: (CMPWUconst (MOVDconst [x]) [y])
	// cond: int32(x)==int32(y)
	// result: (FlagEQ)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(int32(x) == int32(y)) {
			break
		}
		v.reset(OpPPC64FlagEQ)
		return true
	}
	// match: (CMPWUconst (MOVDconst [x]) [y])
	// cond: uint32(x)<uint32(y)
	// result: (FlagLT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint32(x) < uint32(y)) {
			break
		}
		v.reset(OpPPC64FlagLT)
		return true
	}
	// match: (CMPWUconst (MOVDconst [x]) [y])
	// cond: uint32(x)>uint32(y)
	// result: (FlagGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(uint32(x) > uint32(y)) {
			break
		}
		v.reset(OpPPC64FlagGT)
		return true
	}
	// match: (CMPWUconst [0] a:(ANDconst [n] z))
	// result: (CMPconst [0] a)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpPPC64ANDconst {
			break
		}
		v.reset(OpPPC64CMPconst)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg(a)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64CMPWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPWconst (MOVDconst [x]) [y])
	// cond: int32(x)==int32(y)
	// result: (FlagEQ)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(int32(x) == int32(y)) {
			break
		}
		v.reset(OpPPC64FlagEQ)
		return true
	}
	// match: (CMPWconst (MOVDconst [x]) [y])
	// cond: int32(x)<int32(y)
	// result: (FlagLT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(int32(x) < int32(y)) {
			break
		}
		v.reset(OpPPC64FlagLT)
		return true
	}
	// match: (CMPWconst (MOVDconst [x]) [y])
	// cond: int32(x)>int32(y)
	// result: (FlagGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(int32(x) > int32(y)) {
			break
		}
		v.reset(OpPPC64FlagGT)
		return true
	}
	// match: (CMPWconst [0] a:(ANDconst [n] z))
	// result: (CMPconst [0] a)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		a := v_0
		if a.Op != OpPPC64ANDconst {
			break
		}
		v.reset(OpPPC64CMPconst)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg(a)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64CMPconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPconst (MOVDconst [x]) [y])
	// cond: x==y
	// result: (FlagEQ)
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x == y) {
			break
		}
		v.reset(OpPPC64FlagEQ)
		return true
	}
	// match: (CMPconst (MOVDconst [x]) [y])
	// cond: x<y
	// result: (FlagLT)
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x < y) {
			break
		}
		v.reset(OpPPC64FlagLT)
		return true
	}
	// match: (CMPconst (MOVDconst [x]) [y])
	// cond: x>y
	// result: (FlagGT)
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x > y) {
			break
		}
		v.reset(OpPPC64FlagGT)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64Equal(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Equal (FlagEQ))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (Equal (FlagLT))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Equal (FlagGT))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Equal (InvertFlags x))
	// result: (Equal x)
	for {
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64Equal)
		v.AddArg(x)
		return true
	}
	// match: (Equal cmp)
	// result: (SETBC [2] cmp)
	for {
		cmp := v_0
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(2)
		v.AddArg(cmp)
		return true
	}
}
func rewriteValuePPC64_OpPPC64FABS(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FABS (FMOVDconst [x]))
	// result: (FMOVDconst [math.Abs(x)])
	for {
		if v_0.Op != OpPPC64FMOVDconst {
			break
		}
		x := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpPPC64FMOVDconst)
		v.AuxInt = float64ToAuxInt(math.Abs(x))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64FADD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FADD (FMUL x y) z)
	// cond: x.Block.Func.useFMA(v)
	// result: (FMADD x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64FMUL {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				y := v_0_1
				z := v_1
				if !(x.Block.Func.useFMA(v)) {
					continue
				}
				v.reset(OpPPC64FMADD)
				v.AddArg3(x, y, z)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64FADDS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FADDS (FMULS x y) z)
	// cond: x.Block.Func.useFMA(v)
	// result: (FMADDS x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64FMULS {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				y := v_0_1
				z := v_1
				if !(x.Block.Func.useFMA(v)) {
					continue
				}
				v.reset(OpPPC64FMADDS)
				v.AddArg3(x, y, z)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64FCEIL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FCEIL (FMOVDconst [x]))
	// result: (FMOVDconst [math.Ceil(x)])
	for {
		if v_0.Op != OpPPC64FMOVDconst {
			break
		}
		x := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpPPC64FMOVDconst)
		v.AuxInt = float64ToAuxInt(math.Ceil(x))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64FFLOOR(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FFLOOR (FMOVDconst [x]))
	// result: (FMOVDconst [math.Floor(x)])
	for {
		if v_0.Op != OpPPC64FMOVDconst {
			break
		}
		x := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpPPC64FMOVDconst)
		v.AuxInt = float64ToAuxInt(math.Floor(x))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64FGreaterEqual(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (FGreaterEqual cmp)
	// result: (OR (SETBC [2] cmp) (SETBC [1] cmp))
	for {
		cmp := v_0
		v.reset(OpPPC64OR)
		v0 := b.NewValue0(v.Pos, OpPPC64SETBC, typ.Int32)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg(cmp)
		v1 := b.NewValue0(v.Pos, OpPPC64SETBC, typ.Int32)
		v1.AuxInt = int32ToAuxInt(1)
		v1.AddArg(cmp)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuePPC64_OpPPC64FGreaterThan(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FGreaterThan cmp)
	// result: (SETBC [1] cmp)
	for {
		cmp := v_0
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(cmp)
		return true
	}
}
func rewriteValuePPC64_OpPPC64FLessEqual(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (FLessEqual cmp)
	// result: (OR (SETBC [2] cmp) (SETBC [0] cmp))
	for {
		cmp := v_0
		v.reset(OpPPC64OR)
		v0 := b.NewValue0(v.Pos, OpPPC64SETBC, typ.Int32)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg(cmp)
		v1 := b.NewValue0(v.Pos, OpPPC64SETBC, typ.Int32)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg(cmp)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuePPC64_OpPPC64FLessThan(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FLessThan cmp)
	// result: (SETBC [0] cmp)
	for {
		cmp := v_0
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(cmp)
		return true
	}
}
func rewriteValuePPC64_OpPPC64FMOVDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVDload [off] {sym} ptr (MOVDstore [off] {sym} ptr x _))
	// result: (MTVSRD x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVDstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpPPC64MTVSRD)
		v.AddArg(x)
		return true
	}
	// match: (FMOVDload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (FMOVDload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym
```