Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpS390XMOVDaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueS390X_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x16 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPWUconst (MOVHZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x32 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x64 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x8 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPWUconst (MOVBZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh32x16(v *Value) bool {
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
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x16 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPWUconst (MOVHZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh32x32(v *Value) bool {
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
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x32 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x64 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh32x8(v *Value) bool {
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
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x8 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPWUconst (MOVBZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh64x16(v *Value) bool {
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
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x16 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLD <t> x y) (MOVDconst [0]) (CMPWUconst (MOVHZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh64x32(v *Value) bool {
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
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x32 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLD <t> x y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x64 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLD <t> x y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh64x8(v *Value) bool {
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
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x8 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLD <t> x y) (MOVDconst [0]) (CMPWUconst (MOVBZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x16 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPWUconst (MOVHZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x32 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x64 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x8 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SLW <t> x y) (MOVDconst [0]) (CMPWUconst (MOVBZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (MODW (MOVHreg x) (MOVHreg y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XMODW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (MODWU (MOVHZreg x) (MOVHZreg y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XMODWU)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32 x y)
	// result: (MODW (MOVWreg x) y)
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XMODW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVWreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueS390X_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32u x y)
	// result: (MODWU (MOVWZreg x) y)
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XMODWU)
		v0 := b.NewValue0(v.Pos, OpS390XMOVWZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueS390X_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod64 x y)
	// result: (MODD x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XMODD)
		v.AddArg2(x, y)
		return true
	}
}
func rewriteValueS390X_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (MODW (MOVBreg x) (MOVBreg y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XMODW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (MODWU (MOVBZreg x) (MOVBZreg y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XMODWU)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpMove(v *Value) bool {
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
		v.reset(OpS390XMOVBstore)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZload, typ.UInt8)
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
		v.reset(OpS390XMOVHstore)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHZload, typ.UInt16)
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
		v.reset(OpS390XMOVWstore)
		v0 := b.NewValue0(v.Pos, OpS390XMOVWZload, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
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
		v.reset(OpS390XMOVDstore)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDload, typ.UInt64)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [16] dst src mem)
	// result: (MOVDstore [8] dst (MOVDload [8] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpS390XMOVDstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [24] dst src mem)
	// result: (MOVDstore [16] dst (MOVDload [16] src mem) (MOVDstore [8] dst (MOVDload [8] src mem) (MOVDstore dst (MOVDload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 24 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpS390XMOVDstore)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(16)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDload, typ.UInt64)
		v2.AuxInt = int32ToAuxInt(8)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpS390XMOVDstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpS390XMOVDload, typ.UInt64)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBZload [2] src mem) (MOVHstore dst (MOVHZload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpS390XMOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpS390XMOVHZload, typ.UInt16)
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
		v.reset(OpS390XMOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpS390XMOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpS390XMOVWZload, typ.UInt32)
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
		v.reset(OpS390XMOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHZload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpS390XMOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpS390XMOVWZload, typ.UInt32)
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
		v.reset(OpS390XMOVBstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(6)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpS390XMOVHZload, typ.UInt16)
		v2.AuxInt = int32ToAuxInt(4)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpS390XMOVWstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpS390XMOVWZload, typ.UInt32)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 0 && s <= 256 && logLargeCopy(v, s)
	// result: (MVC [makeValAndOff(int32(s), 0)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 0 && s <= 256 && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpS390XMVC)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(s), 0))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 256 && s <= 512 && logLargeCopy(v, s)
	// result: (MVC [makeValAndOff(int32(s)-256, 256)] dst src (MVC [makeValAndOff(256, 0)] dst src mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 256 && s <= 512 && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpS390XMVC)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(s)-256, 256))
		v0 := b.NewValue0(v.Pos, OpS390XMVC, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(256, 0))
		v0.AddArg3(dst, src, mem)
		v.AddArg3(dst, src, v0)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 512 && s <= 768 && logLargeCopy(v, s)
	// result: (MVC [makeValAndOff(int32(s)-512, 512)] dst src (MVC [makeValAndOff(256, 256)] dst src (MVC [makeValAndOff(256, 0)] dst src mem)))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 512 && s <= 768 && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpS390XMVC)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(s)-512, 512))
		v0 := b.NewValue0(v.Pos, OpS390XMVC, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(256, 256))
		v1 := b.NewValue0(v.Pos, OpS390XMVC, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(256, 0))
		v1.AddArg3(dst, src, mem)
		v0.AddArg3(dst, src, v1)
		v.AddArg3(dst, src, v0)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 768 && s <= 1024 && logLargeCopy(v, s)
	// result: (MVC [makeValAndOff(int32(s)-768, 768)] dst src (MVC [makeValAndOff(256, 512)] dst src (MVC [makeValAndOff(256, 256)] dst src (MVC [makeValAndOff(256, 0)] dst src mem))))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 768 && s <= 1024 && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpS390XMVC)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(s)-768, 768))
		v0 := b.NewValue0(v.Pos, OpS390XMVC, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(256, 512))
		v1 := b.NewValue0(v.Pos, OpS390XMVC, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(256, 256))
		v2 := b.NewValue0(v.Pos, OpS390XMVC, types.TypeMem)
		v2.AuxInt = valAndOffToAuxInt(makeValAndOff(256, 0))
		v2.AddArg3(dst, src, mem)
		v1.AddArg3(dst, src, v2)
		v0.AddArg3(dst, src, v1)
		v.AddArg3(dst, src, v0)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 1024 && logLargeCopy(v, s)
	// result: (LoweredMove [s%256] dst src (ADD <src.Type> src (MOVDconst [(s/256)*256])) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 1024 && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpS390XLoweredMove)
		v.AuxInt = int64ToAuxInt(s % 256)
		v0 := b.NewValue0(v.Pos, OpS390XADD, src.Type)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt((s / 256) * 256)
		v0.AddArg2(src, v1)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (LOCGR {s390x.NotEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVHreg x) (MOVHreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.NotEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32 x y)
	// result: (LOCGR {s390x.NotEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.NotEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32F x y)
	// result: (LOCGR {s390x.NotEqual} (MOVDconst [0]) (MOVDconst [1]) (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.NotEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XFCMPS, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq64 x y)
	// result: (LOCGR {s390x.NotEqual} (MOVDconst [0]) (MOVDconst [1]) (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.NotEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq64F x y)
	// result: (LOCGR {s390x.NotEqual} (MOVDconst [0]) (MOVDconst [1]) (FCMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.NotEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XFCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (LOCGR {s390x.NotEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVBreg x) (MOVBreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.NotEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpNeqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqB x y)
	// result: (LOCGR {s390x.NotEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVBreg x) (MOVBreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.NotEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqPtr x y)
	// result: (LOCGR {s390x.NotEqual} (MOVDconst [0]) (MOVDconst [1]) (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.NotEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not x)
	// result: (XORWconst [1] x)
	for {
		x := v_0
		v.reset(OpS390XXORWconst)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (OffPtr [off] ptr:(SP))
	// result: (MOVDaddr [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if ptr.Op != OpSP {
			break
		}
		v.reset(OpS390XMOVDaddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// cond: is32Bit(off)
	// result: (ADDconst [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if !(is32Bit(off)) {
			break
		}
		v.reset(OpS390XADDconst)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// result: (ADD (MOVDconst [off]) ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpS390XADD)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(off)
		v.AddArg2(v0, ptr)
		return true
	}
}
func rewriteValueS390X_OpPanicBounds(v *Value) bool {
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
		v.reset(OpS390XLoweredPanicBoundsA)
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
		v.reset(OpS390XLoweredPanicBoundsB)
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
		v.reset(OpS390XLoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpPopCount16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount16 x)
	// result: (MOVBZreg (SumBytes2 (POPCNT <typ.UInt16> x)))
	for {
		x := v_0
		v.reset(OpS390XMOVBZreg)
		v0 := b.NewValue0(v.Pos, OpS390XSumBytes2, typ.UInt8)
		v1 := b.NewValue0(v.Pos, OpS390XPOPCNT, typ.UInt16)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpPopCount32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount32 x)
	// result: (MOVBZreg (SumBytes4 (POPCNT <typ.UInt32> x)))
	for {
		x := v_0
		v.reset(OpS390XMOVBZreg)
		v0 := b.NewValue0(v.Pos, OpS390XSumBytes4, typ.UInt8)
		v1 := b.NewValue0(v.Pos, OpS390XPOPCNT, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpPopCount64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount64 x)
	// result: (MOVBZreg (SumBytes8 (POPCNT <typ.UInt64> x)))
	for {
		x := v_0
		v.reset(OpS390XMOVBZreg)
		v0 := b.NewValue0(v.Pos, OpS390XSumBytes8, typ.UInt8)
		v1 := b.NewValue0(v.Pos, OpS390XPOPCNT, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpPopCount8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount8 x)
	// result: (POPCNT (MOVBZreg x))
	for {
		x := v_0
		v.reset(OpS390XPOPCNT)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVDconst [c]))
	// result: (Or16 (Lsh16x64 <t> x (MOVDconst [c&15])) (Rsh16Ux64 <t> x (MOVDconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v3 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueS390X_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVDconst [c]))
	// result: (Or8 (Lsh8x64 <t> x (MOVDconst [c&7])) (Rsh8Ux64 <t> x (MOVDconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v3 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueS390X_OpRound(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Round x)
	// result: (FIDBR [1] x)
	for {
		x := v_0
		v.reset(OpS390XFIDBR)
		v.AuxInt = int8ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpRoundToEven(v *Value) bool {
	v_0 := v.Args[0]
	// match: (RoundToEven x)
	// result: (FIDBR [4] x)
	for {
		x := v_0
		v.reset(OpS390XFIDBR)
		v.AuxInt = int8ToAuxInt(4)
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux16 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPWUconst (MOVHZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueS390X_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux32 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueS390X_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux64 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueS390X_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux8 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPWUconst (MOVBZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueS390X_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x16 x y)
	// result: (SRAW (MOVHreg x) (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst (MOVHZreg y) [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v1.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x32 x y)
	// result: (SRAW (MOVHreg x) (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst y [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v1.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x64 x y)
	// result: (SRAW (MOVHreg x) (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPUconst y [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v1.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x8 x y)
	// result: (SRAW (MOVHreg x) (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst (MOVBZreg y) [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v1.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux16 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> x y) (MOVDconst [0]) (CMPWUconst (MOVHZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux32 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> x y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux64 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> x y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux8 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> x y) (MOVDconst [0]) (CMPWUconst (MOVBZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x16 x y)
	// result: (SRAW x (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst (MOVHZreg y) [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v0.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueS390X_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x32 x y)
	// result: (SRAW x (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst y [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v0.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueS390X_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x64 x y)
	// result: (SRAW x (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPUconst y [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v0.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueS390X_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x8 x y)
	// result: (SRAW x (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst (MOVBZreg y) [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAW)
		v0 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v0.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueS390X_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux16 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRD <t> x y) (MOVDconst [0]) (CMPWUconst (MOVHZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux32 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRD <t> x y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux64 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRD <t> x y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux8 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRD <t> x y) (MOVDconst [0]) (CMPWUconst (MOVBZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x16 x y)
	// result: (SRAD x (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst (MOVHZreg y) [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAD)
		v0 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v0.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueS390X_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x32 x y)
	// result: (SRAD x (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst y [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAD)
		v0 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v0.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueS390X_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x64 x y)
	// result: (SRAD x (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPUconst y [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAD)
		v0 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v0.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueS390X_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x8 x y)
	// result: (SRAD x (LOCGR {s390x.GreaterOrEqual} <y.Type> y (MOVDconst <y.Type> [63]) (CMPWUconst (MOVBZreg y) [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRAD)
		v0 := b.NewValue0(v.Pos, OpS390XLOCGR, y.Type)
		v0.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueS390X_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux16 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPWUconst (MOVHZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueS390X_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux32 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpS390XCMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueS390X_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux64 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpS390XCMPUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueS390X_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpS390XSRW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux8 <t> x y)
	// result: (LOCGR {s390x.GreaterOrEqual} <t> (SRW <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPWUconst (MOVBZreg y) [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Type = t
		v.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XSRW, t)
		v1 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UI
```