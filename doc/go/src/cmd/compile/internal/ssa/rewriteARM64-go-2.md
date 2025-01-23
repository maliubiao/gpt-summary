Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共10部分，请归纳一下它的功能
```

### 源代码
```go
v_0.Args[0]
			y := v_1
			v.reset(OpARM64FNMULD)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64FMULS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMULS (FNEGS x) y)
	// result: (FNMULS x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64FNEGS {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			v.reset(OpARM64FNMULS)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64FNEGD(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FNEGD (FMULD x y))
	// result: (FNMULD x y)
	for {
		if v_0.Op != OpARM64FMULD {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64FNMULD)
		v.AddArg2(x, y)
		return true
	}
	// match: (FNEGD (FNMULD x y))
	// result: (FMULD x y)
	for {
		if v_0.Op != OpARM64FNMULD {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64FMULD)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FNEGS(v *Value) bool {
	v_0 := v.Args[0]
	// match: (FNEGS (FMULS x y))
	// result: (FNMULS x y)
	for {
		if v_0.Op != OpARM64FMULS {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64FNMULS)
		v.AddArg2(x, y)
		return true
	}
	// match: (FNEGS (FNMULS x y))
	// result: (FMULS x y)
	for {
		if v_0.Op != OpARM64FNMULS {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64FMULS)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FNMULD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FNMULD (FNEGD x) y)
	// result: (FMULD x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64FNEGD {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			v.reset(OpARM64FMULD)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64FNMULS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FNMULS (FNEGS x) y)
	// result: (FMULS x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64FNEGS {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			v.reset(OpARM64FMULS)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64FSUBD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FSUBD a (FMULD x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMSUBD a x y)
	for {
		a := v_0
		if v_1.Op != OpARM64FMULD {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpARM64FMSUBD)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (FSUBD (FMULD x y) a)
	// cond: a.Block.Func.useFMA(v)
	// result: (FNMSUBD a x y)
	for {
		if v_0.Op != OpARM64FMULD {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		a := v_1
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpARM64FNMSUBD)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (FSUBD a (FNMULD x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMADDD a x y)
	for {
		a := v_0
		if v_1.Op != OpARM64FNMULD {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpARM64FMADDD)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (FSUBD (FNMULD x y) a)
	// cond: a.Block.Func.useFMA(v)
	// result: (FNMADDD a x y)
	for {
		if v_0.Op != OpARM64FNMULD {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		a := v_1
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpARM64FNMADDD)
		v.AddArg3(a, x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FSUBS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FSUBS a (FMULS x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMSUBS a x y)
	for {
		a := v_0
		if v_1.Op != OpARM64FMULS {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpARM64FMSUBS)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (FSUBS (FMULS x y) a)
	// cond: a.Block.Func.useFMA(v)
	// result: (FNMSUBS a x y)
	for {
		if v_0.Op != OpARM64FMULS {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		a := v_1
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpARM64FNMSUBS)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (FSUBS a (FNMULS x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMADDS a x y)
	for {
		a := v_0
		if v_1.Op != OpARM64FNMULS {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpARM64FMADDS)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (FSUBS (FNMULS x y) a)
	// cond: a.Block.Func.useFMA(v)
	// result: (FNMADDS a x y)
	for {
		if v_0.Op != OpARM64FNMULS {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		a := v_1
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpARM64FNMADDS)
		v.AddArg3(a, x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64GreaterEqual(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (GreaterEqual (CMPconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (GreaterEqual (TST x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TST, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPWconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (GreaterEqual (TSTWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPWconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (GreaterEqual (TSTW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (GreaterEqual (TSTconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (GreaterEqualNoov (CMNconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqualNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMNconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPWconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (GreaterEqualNoov (CMNWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqualNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMNWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (GreaterEqualNoov (CMN x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64ADD {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqualNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPWconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (GreaterEqualNoov (CMNW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64ADD {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqualNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPconst [0] z:(MADD a x y)))
	// cond: z.Uses == 1
	// result: (GreaterEqualNoov (CMN a (MUL <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MADD {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqualNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPconst [0] z:(MSUB a x y)))
	// cond: z.Uses == 1
	// result: (GreaterEqualNoov (CMP a (MUL <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MSUB {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqualNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPWconst [0] z:(MADDW a x y)))
	// cond: z.Uses == 1
	// result: (GreaterEqualNoov (CMNW a (MULW <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MADDW {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqualNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (CMPWconst [0] z:(MSUBW a x y)))
	// cond: z.Uses == 1
	// result: (GreaterEqualNoov (CMPW a (MULW <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MSUBW {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterEqualNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterEqual (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.ge())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.ge()))
		return true
	}
	// match: (GreaterEqual (InvertFlags x))
	// result: (LessEqual x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64LessEqual)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64GreaterEqualF(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterEqualF (InvertFlags x))
	// result: (LessEqualF x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64LessEqualF)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64GreaterEqualNoov(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (GreaterEqualNoov (InvertFlags x))
	// result: (CSINC [OpARM64NotEqual] (LessThanNoov <typ.Bool> x) (MOVDconst [0]) x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64CSINC)
		v.AuxInt = opToAuxInt(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64LessThanNoov, typ.Bool)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg3(v0, v1, x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64GreaterEqualU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterEqualU (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.uge())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.uge()))
		return true
	}
	// match: (GreaterEqualU (InvertFlags x))
	// result: (LessEqualU x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64LessEqualU)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64GreaterThan(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (GreaterThan (CMPconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (GreaterThan (TST x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterThan)
		v0 := b.NewValue0(v.Pos, OpARM64TST, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterThan (CMPWconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (GreaterThan (TSTWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterThan)
		v0 := b.NewValue0(v.Pos, OpARM64TSTWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterThan (CMPWconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (GreaterThan (TSTW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterThan)
		v0 := b.NewValue0(v.Pos, OpARM64TSTW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterThan (CMPconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (GreaterThan (TSTconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64GreaterThan)
		v0 := b.NewValue0(v.Pos, OpARM64TSTconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (GreaterThan (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.gt())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.gt()))
		return true
	}
	// match: (GreaterThan (InvertFlags x))
	// result: (LessThan x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64LessThan)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64GreaterThanF(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterThanF (InvertFlags x))
	// result: (LessThanF x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64LessThanF)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64GreaterThanU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterThanU (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.ugt())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.ugt()))
		return true
	}
	// match: (GreaterThanU (InvertFlags x))
	// result: (LessThanU x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64LessThanU)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64LDP(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (LDP [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (LDP [off1+int32(off2)] {sym} ptr mem)
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
		v.reset(OpARM64LDP)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (LDP [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (LDP [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
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
		v.reset(OpARM64LDP)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64LessEqual(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (LessEqual (CMPconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (LessEqual (TST x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TST, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (LessEqual (CMPWconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (LessEqual (TSTWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (LessEqual (CMPWconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (LessEqual (TSTW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (LessEqual (CMPconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (LessEqual (TSTconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (LessEqual (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.le())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.le()))
		return true
	}
	// match: (LessEqual (InvertFlags x))
	// result: (GreaterEqual x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64GreaterEqual)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64LessEqualF(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessEqualF (InvertFlags x))
	// result: (GreaterEqualF x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64GreaterEqualF)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64LessEqualU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessEqualU (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.ule())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.ule()))
		return true
	}
	// match: (LessEqualU (InvertFlags x))
	// result: (GreaterEqualU x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64GreaterEqualU)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64LessThan(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (LessThan (CMPconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (LessThan (TST x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64TST, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPWconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (LessThan (TSTWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64TSTWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPWconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (LessThan (TSTW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64TSTW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (LessThan (TSTconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64TSTconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (LessThanNoov (CMNconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThanNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMNconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPWconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (LessThanNoov (CMNWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThanNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMNWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (LessThanNoov (CMN x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64ADD {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThanNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPWconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (LessThanNoov (CMNW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64ADD {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThanNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPconst [0] z:(MADD a x y)))
	// cond: z.Uses == 1
	// result: (LessThanNoov (CMN a (MUL <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MADD {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThanNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPconst [0] z:(MSUB a x y)))
	// cond: z.Uses == 1
	// result: (LessThanNoov (CMP a (MUL <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MSUB {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThanNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPWconst [0] z:(MADDW a x y)))
	// cond: z.Uses == 1
	// result: (LessThanNoov (CMNW a (MULW <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MADDW {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThanNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (CMPWconst [0] z:(MSUBW a x y)))
	// cond: z.Uses == 1
	// result: (LessThanNoov (CMPW a (MULW <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MSUBW {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64LessThanNoov)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (LessThan (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.lt())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.lt()))
		return true
	}
	// match: (LessThan (InvertFlags x))
	// result: (GreaterThan x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64GreaterThan)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64LessThanF(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessThanF (InvertFlags x))
	// result: (GreaterThanF x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64GreaterThanF)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64LessThanNoov(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LessThanNoov (InvertFlags x))
	// result: (CSEL0 [OpARM64NotEqual] (GreaterEqualNoov <typ.Bool> x) x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64CSEL0)
		v.AuxInt = opToAuxInt(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64GreaterEqualNoov, typ.Bool)
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64LessThanU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessThanU (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.ult())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.ult()))
		return true
	}
	// match: (LessThanU (InvertFlags x))
	// result: (GreaterThanU x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64GreaterThanU)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MADD(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MADD a x (MOVDconst [-1]))
	// result: (SUB a x)
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != -1 {
			break
		}
		v.reset(OpARM64SUB)
		v.AddArg2(a, x)
		return true
	}
	// match: (MADD a _ (MOVDconst [0]))
	// result: a
	for {
		a := v_0
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		v.copyOf(a)
		return true
	}
	// match: (MADD a x (MOVDconst [1]))
	// result: (ADD a x)
	for {
		a := v_0
		x := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 1 {
			break
		}
		v.reset(OpARM64ADD)
		v.AddArg2(a, x)
		return true
	}
	// match: (MADD a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (ADDshiftLL a x [log64(c)])
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
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c))
		v.AddArg2(a, x)
		return true
	}
	// match: (MADD a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c-1) && c>=3
	// result: (ADD a (ADDshiftLL <x.Type> x x [log64(c-1)]))
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
		v.reset(OpARM64ADD)
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(log64(c - 1))
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c+1) && c>=7
	// result: (SUB a (SUBshiftLL <x.Type> x x [log64(c+1)]))
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
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(log64(c + 1))
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a x (MOVDconst [c]))
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (SUBshiftLL a (SUBshiftLL <x.Type> x x [2]) [log64(c/3)])
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
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 3))
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(2)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a x (MOVDconst [c]))
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (ADDshiftLL a (ADDshiftLL <x.Type> x x [2]) [log64(c/5)])
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
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 5))
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(2)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a x (MOVDconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (SUBshiftLL a (SUBshiftLL <x.Type> x x [3]) [log64(c/7)])
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
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 7))
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(3)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a x (MOVDconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (ADDshiftLL a (ADDshiftLL <x.Type> x x [3]) [log64(c/9)])
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
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 9))
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(3)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a (MOVDconst [-1]) x)
	// result: (SUB a x)
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != -1 {
			break
		}
		x := v_2
		v.reset(OpARM64SUB)
		v.AddArg2(a, x)
		return true
	}
	// match: (MADD a (MOVDconst [0]) _)
	// result: a
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(a)
		return true
	}
	// match: (MADD a (MOVDconst [1]) x)
	// result: (ADD a x)
	for {
		a := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		x := v_2
		v.reset(OpARM64ADD)
		v.AddArg2(a, x)
		return true
	}
	// match: (MADD a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c)
	// result: (ADDshiftLL a x [log64(c)])
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
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c))
		v.AddArg2(a, x)
		return true
	}
	// match: (MADD a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c-1) && c>=3
	// result: (ADD a (ADDshiftLL <x.Type> x x [log64(c-1)]))
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
		v.reset(OpARM64ADD)
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(log64(c - 1))
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c+1) && c>=7
	// result: (SUB a (SUBshiftLL <x.Type> x x [log64(c+1)]))
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
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(log64(c + 1))
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a (MOVDconst [c]) x)
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (SUBshiftLL a (SUBshiftLL <x.Type> x x [2]) [log64(c/3)])
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
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 3))
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(2)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a (MOVDconst [c]) x)
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (ADDshiftLL a (ADDshiftLL <x.Type> x x [2]) [log64(c/5)])
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
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 5))
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(2)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a (MOVDconst [c]) x)
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (SUBshiftLL a (SUBshiftLL <x.Type> x x [3]) [log64(c/7)])
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
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 7))
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(3)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD a (MOVDconst [c]) x)
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (ADDshiftLL a (ADDshiftLL <x.Type> x x [3]) [log64(c/9)])
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
		v.reset(OpARM64ADDshiftLL)
		v.AuxInt = int64ToAuxInt(log64(c / 9))
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v0.AuxInt = int64ToAuxInt(3)
		v0.AddArg2(x, x)
		v.AddArg2(a, v0)
		return true
	}
	// match: (MADD (MOVDconst [c]) x y)
	// result: (ADDconst [c] (MUL <x.Type> x y))
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (MADD a (MOVDconst [c]) (MOVDconst [d]))
	// result: (ADDconst [c*d] a)
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
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c * d)
		v.AddArg(a)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MADDW(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MADDW a x (MOVDconst [c]))
	// cond: int32(c)==-1
	// result: (MOVWUreg (SUB <a.Type> a x))
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
		v0 := b.NewValue0(v.Pos, OpARM64SUB, a.Type)
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a _ (MOVDconst [c]))
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
	// match: (MADDW a x (MOVDconst [c]))
	// cond: int32(c)==1
	// result: (MOVWUreg (ADD <a.Type> a x))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADD, a.Type)
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a x [log64(c)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c))
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c-1) && int32(c)>=3
	// result: (MOVWUreg (ADD <a.Type> a (ADDshiftLL <x.Type> x x [log64(c-1)])))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADD, a.Type)
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(log64(c - 1))
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a x (MOVDconst [c]))
	// cond: isPowerOfTwo(c+1) && int32(c)>=7
	// result: (MOVWUreg (SUB <a.Type> a (SUBshiftLL <x.Type> x x [log64(c+1)])))
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
		v0 := b.NewValue0(v.Pos, OpARM64SUB, a.Type)
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(log64(c + 1))
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a x (MOVDconst [c]))
	// cond: c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a (SUBshiftLL <x.Type> x x [2]) [log64(c/3)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 3))
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a x (MOVDconst [c]))
	// cond: c%5 == 0 && isPowerOfTwo(c/5) && is32Bit(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a (ADDshiftLL <x.Type> x x [2]) [log64(c/5)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 5))
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a x (MOVDconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a (SUBshiftLL <x.Type> x x [3]) [log64(c/7)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 7))
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a x (MOVDconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a (ADDshiftLL <x.Type> x x [3]) [log64(c/9)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 9))
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) x)
	// cond: int32(c)==-1
	// result: (MOVWUreg (SUB <a.Type> a x))
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
		v0 := b.NewValue0(v.Pos, OpARM64SUB, a.Type)
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) _)
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
	// match: (MADDW a (MOVDconst [c]) x)
	// cond: int32(c)==1
	// result: (MOVWUreg (ADD <a.Type> a x))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADD, a.Type)
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a x [log64(c)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c))
		v0.AddArg2(a, x)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c-1) && int32(c)>=3
	// result: (MOVWUreg (ADD <a.Type> a (ADDshiftLL <x.Type> x x [log64(c-1)])))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADD, a.Type)
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(log64(c - 1))
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) x)
	// cond: isPowerOfTwo(c+1) && int32(c)>=7
	// result: (MOVWUreg (SUB <a.Type> a (SUBshiftLL <x.Type> x x [log64(c+1)])))
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
		v0 := b.NewValue0(v.Pos, OpARM64SUB, a.Type)
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(log64(c + 1))
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) x)
	// cond: c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a (SUBshiftLL <x.Type> x x [2]) [log64(c/3)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 3))
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) x)
	// cond: c%5 == 0 && isPowerOfTwo(c/5) && is32Bit(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a (ADDshiftLL <x.Type> x x [2]) [log64(c/5)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 5))
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(2)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) x)
	// cond: c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)
	// result: (MOVWUreg (SUBshiftLL <a.Type> a (SUBshiftLL <x.Type> x x [3]) [log64(c/7)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 7))
		v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) x)
	// cond: c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)
	// result: (MOVWUreg (ADDshiftLL <a.Type> a (ADDshiftLL <x.Type> x x [3]) [log64(c/9)]))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, a.Type)
		v0.AuxInt = int64ToAuxInt(log64(c / 9))
		v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
		v1.AuxInt = int64ToAuxInt(3)
		v1.AddArg2(x, x)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW (MOVDconst [c]) x y)
	// result: (MOVWUreg (ADDconst <x.Type> [c] (MULW <x.Type> x y)))
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
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (MADDW a (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVWUreg (ADDconst <a.Type> [c*d] a))
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
		v0 := b.NewValue0(v.Pos, OpARM64ADDconst, a.Type)
		v0.AuxInt = int64ToAuxInt(c * d)
		v0.AddArg(a)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MNEG(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MNEG x (MOVDconst [-1]))
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != -1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (MNEG _ (MOVDconst [0]))
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
	// match: (MNEG x (MOVDconst [1]))
	// result: (NEG x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
				continue
			}
			v.reset(OpARM64NEG)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MNEG x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (NEG (SLLconst <x.Type> [log64(c)] x))
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
			v.reset(OpARM64NEG)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c))
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEG x (MOVDconst [c]))
	// cond: isPowerOfTwo(c-1) && c >= 3
	// result: (NEG (ADDshiftLL <x.Type> x x [log64(c-1)]))
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
			v.reset(OpARM64NEG)
			v0 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c - 1))
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEG x (MOVDconst [c]))
	// cond: isPowerOfTwo(c+1) && c >= 7
	// result: (NEG (ADDshiftLL <x.Type> (NEG <x.Type> x) x [log64(c+1)]))
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
			v.reset(OpARM64NEG)
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
	// match: (MNEG x (MOVDconst [c]))
	// cond: c%3 == 0 && isPowerOfTwo(c/3)
	// result: (SLLconst <x.Type> [log64(c/3)] (SUBshiftLL <x.Type> x x [2]))
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
			v.Type = x.Type
			v.AuxInt = int64ToAuxInt(log64(c / 3))
			v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
			v0.AuxInt = int64ToAuxInt(2)
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEG x (MOVDconst [c]))
	// cond: c%5 == 0 && isPowerOfTwo(c/5)
	// result: (NEG (SLLconst <x.Type> [log64(c/5)] (ADDshiftLL <x.Type> x x [2])))
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
			v.reset(OpARM64NEG)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c / 5))
			v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(2)
			v1.AddArg2(x, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEG x (MOVDconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7)
	// result: (SLLconst <x.Type> [log64(c/7)] (SUBshiftLL <x.Type> x x [3]))
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
			v.Type = x.Type
			v.AuxInt = int64ToAuxInt(log64(c / 7))
			v0 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
			v0.AuxInt = int64ToAuxInt(3)
			v0.AddArg2(x, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEG x (MOVDconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9)
	// result: (NEG (SLLconst <x.Type> [log64(c/9)] (ADDshiftLL <x.Type> x x [3])))
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
			v.reset(OpARM64NEG)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c / 9))
			v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(3)
			v1.AddArg2(x, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEG (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [-c*d])
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
			v.AuxInt = int64ToAuxInt(-c * d)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64MNEGW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MNEGW x (MOVDconst [c]))
	// cond: int32(c)==-1
	// result: (MOVWUreg x)
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
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MNEGW _ (MOVDconst [c]))
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
	// match: (MNEGW x (MOVDconst [c]))
	// cond: int32(c)==1
	// result: (MOVWUreg (NEG <x.Type> x))
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
			v0 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEGW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (NEG (SLLconst <x.Type> [log64(c)] x))
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
			v.reset(OpARM64NEG)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c))
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEGW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c-1) && int32(c) >= 3
	// result: (MOVWUreg (NEG <x.Type> (ADDshiftLL <x.Type> x x [log64(c-1)])))
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
			v0 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(log64(c - 1))
			v1.AddArg2(x, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEGW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c+1) && int32(c) >= 7
	// result: (MOVWUreg (NEG <x.Type> (ADDshiftLL <x.Type> (NEG <x.Type> x) x [log64(c+1)])))
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
			v0 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(log64(c + 1))
			v2 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v2.AddArg(x)
			v1.AddArg2(v2, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEGW x (MOVDconst [c]))
	// cond: c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)
	// result: (MOVWUreg (SLLconst <x.Type> [log64(c/3)] (SUBshiftLL <x.Type> x x [2])))
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
			v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(2)
			v1.AddArg2(x, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEGW x (MOVDconst [c]))
	// cond: c%5 == 0 && isPowerOfTwo(c/5) && is32Bit(c)
	// result: (MOVWUreg (NEG <x.Type> (SLLconst <x.Type> [log64(c/5)] (ADDshiftLL <x.Type> x x [2]))))
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
			v0 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v1 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v1.AuxInt = int64ToAuxInt(log64(c / 5))
			v2 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v2.AuxInt = int64ToAuxInt(2)
			v2.AddArg2(x, x)
			v1.AddArg(v2)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEGW x (MOVDconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)
	// result: (MOVWUreg (SLLconst <x.Type> [log64(c/7)] (SUBshiftLL <x.Type> x x [3])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c / 7))
			v1 := b.NewValue0(v.Pos, OpARM64SUBshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(3)
			v1.AddArg2(x, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEGW x (MOVDconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)
	// result: (MOVWUreg (NEG <x.Type> (SLLconst <x.Type> [log64(c/9)] (ADDshiftLL <x.Type> x x [3]))))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v1 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v1.AuxInt = int64ToAuxInt(log64(c / 9))
			v2 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v2.AuxInt = int64ToAuxInt(3)
			v2.AddArg2(x, x)
			v1.AddArg(v2)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MNEGW (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [int64(uint32(-c*d))])
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
			v.AuxInt = int64ToAuxInt(int64(uint32(-c * d)))
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64MOD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOD (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [c%d])
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
		v.AuxInt = int64ToAuxInt(c % d)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MODW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MODW (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint32(int32(c)%int32(d)))])
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
		v.AuxInt = int64ToAuxInt(int64(uint32(int32(c) % int32(d))))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBUload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBUload [off1+int32(off2)] {sym} ptr mem)
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
		v.reset(OpARM64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBUloadidx ptr idx mem)
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
		v.reset(OpARM64MOVBUloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVBUload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBUload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
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
		v.reset(OpARM64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off] {sym} ptr (MOVBstorezero [off2] {sym2} ptr2 _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVDconst [0])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVBstorezero {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Au
```