Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第6部分，共10部分，请归纳一下它的功能
```

### 源代码
```go
int64ToAuxInt(2)
			v1.AddArg2(x, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)
	// result: (MOVWUreg (SLLconst <x.Type> [log64(c/7)] (ADDshiftLL <x.Type> (NEG <x.Type> x) x [3])))
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
			v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(3)
			v2 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v2.AddArg(x)
			v1.AddArg2(v2, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)
	// result: (MOVWUreg (SLLconst <x.Type> [log64(c/9)] (ADDshiftLL <x.Type> x x [3])))
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
	// match: (MULW (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [int64(uint32(c*d))])
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
			v.AuxInt = int64ToAuxInt(int64(uint32(c * d)))
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64MVN(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVN (XOR x y))
	// result: (EON x y)
	for {
		if v_0.Op != OpARM64XOR {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64EON)
		v.AddArg2(x, y)
		return true
	}
	// match: (MVN (MOVDconst [c]))
	// result: (MOVDconst [^c])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^c)
		return true
	}
	// match: (MVN x:(SLLconst [c] y))
	// cond: clobberIfDead(x)
	// result: (MVNshiftLL [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64MVNshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (MVN x:(SRLconst [c] y))
	// cond: clobberIfDead(x)
	// result: (MVNshiftRL [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64MVNshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (MVN x:(SRAconst [c] y))
	// cond: clobberIfDead(x)
	// result: (MVNshiftRA [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64MVNshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (MVN x:(RORconst [c] y))
	// cond: clobberIfDead(x)
	// result: (MVNshiftRO [c] y)
	for {
		x := v_0
		if x.Op != OpARM64RORconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64MVNshiftRO)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MVNshiftLL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftLL (MOVDconst [c]) [d])
	// result: (MOVDconst [^int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) << uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MVNshiftRA(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftRA (MOVDconst [c]) [d])
	// result: (MOVDconst [^(c>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^(c >> uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MVNshiftRL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftRL (MOVDconst [c]) [d])
	// result: (MOVDconst [^int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) >> uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MVNshiftRO(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftRO (MOVDconst [c]) [d])
	// result: (MOVDconst [^rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^rotateRight64(c, d))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NEG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEG (MUL x y))
	// result: (MNEG x y)
	for {
		if v_0.Op != OpARM64MUL {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64MNEG)
		v.AddArg2(x, y)
		return true
	}
	// match: (NEG (MULW x y))
	// cond: v.Type.Size() <= 4
	// result: (MNEGW x y)
	for {
		if v_0.Op != OpARM64MULW {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(v.Type.Size() <= 4) {
			break
		}
		v.reset(OpARM64MNEGW)
		v.AddArg2(x, y)
		return true
	}
	// match: (NEG (NEG x))
	// result: x
	for {
		if v_0.Op != OpARM64NEG {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (NEG (MOVDconst [c]))
	// result: (MOVDconst [-c])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-c)
		return true
	}
	// match: (NEG x:(SLLconst [c] y))
	// cond: clobberIfDead(x)
	// result: (NEGshiftLL [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64NEGshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (NEG x:(SRLconst [c] y))
	// cond: clobberIfDead(x)
	// result: (NEGshiftRL [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64NEGshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (NEG x:(SRAconst [c] y))
	// cond: clobberIfDead(x)
	// result: (NEGshiftRA [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64NEGshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NEGshiftLL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGshiftLL (MOVDconst [c]) [d])
	// result: (MOVDconst [-int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-int64(uint64(c) << uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NEGshiftRA(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGshiftRA (MOVDconst [c]) [d])
	// result: (MOVDconst [-(c>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-(c >> uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NEGshiftRL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGshiftRL (MOVDconst [c]) [d])
	// result: (MOVDconst [-int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-int64(uint64(c) >> uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NotEqual(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (NotEqual (CMPconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (TST x y))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TST, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (NotEqual (TSTWconst [int32(c)] y))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (TSTW x y))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (NotEqual (TSTconst [c] y))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMP x z:(NEG y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMN x y))
	for {
		if v_0.Op != OpARM64CMP {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		z := v_0.Args[1]
		if z.Op != OpARM64NEG {
			break
		}
		y := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPW x z:(NEG y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMNW x y))
	for {
		if v_0.Op != OpARM64CMPW {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		z := v_0.Args[1]
		if z.Op != OpARM64NEG {
			break
		}
		y := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (NotEqual (CMNconst [c] y))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (NotEqual (CMNWconst [int32(c)] y))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMN x y))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMNW x y))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] z:(MADD a x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMN a (MUL <x.Type> x y)))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] z:(MSUB a x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMP a (MUL <x.Type> x y)))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] z:(MADDW a x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMNW a (MULW <x.Type> x y)))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] z:(MSUBW a x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMPW a (MULW <x.Type> x y)))
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.ne())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.ne()))
		return true
	}
	// match: (NotEqual (InvertFlags x))
	// result: (NotEqual x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64NotEqual)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64OR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (OR x (MOVDconst [c]))
	// result: (ORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64ORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
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
	// match: (OR x (MVN y))
	// result: (ORN x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MVN {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpARM64ORN)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (OR x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORshiftLL x0 y [c])
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
			v.reset(OpARM64ORshiftLL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (OR x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORshiftRL x0 y [c])
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
			v.reset(OpARM64ORshiftRL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (OR x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORshiftRA x0 y [c])
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
			v.reset(OpARM64ORshiftRA)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (OR x0 x1:(RORconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORshiftRO x0 y [c])
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
			v.reset(OpARM64ORshiftRO)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (OR (UBFIZ [bfc] x) (ANDconst [ac] y))
	// cond: ac == ^((1<<uint(bfc.width())-1) << uint(bfc.lsb()))
	// result: (BFI [bfc] y x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64UBFIZ {
				continue
			}
			bfc := auxIntToArm64BitField(v_0.AuxInt)
			x := v_0.Args[0]
			if v_1.Op != OpARM64ANDconst {
				continue
			}
			ac := auxIntToInt64(v_1.AuxInt)
			y := v_1.Args[0]
			if !(ac == ^((1<<uint(bfc.width()) - 1) << uint(bfc.lsb()))) {
				continue
			}
			v.reset(OpARM64BFI)
			v.AuxInt = arm64BitFieldToAuxInt(bfc)
			v.AddArg2(y, x)
			return true
		}
		break
	}
	// match: (OR (UBFX [bfc] x) (ANDconst [ac] y))
	// cond: ac == ^(1<<uint(bfc.width())-1)
	// result: (BFXIL [bfc] y x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64UBFX {
				continue
			}
			bfc := auxIntToArm64BitField(v_0.AuxInt)
			x := v_0.Args[0]
			if v_1.Op != OpARM64ANDconst {
				continue
			}
			ac := auxIntToInt64(v_1.AuxInt)
			y := v_1.Args[0]
			if !(ac == ^(1<<uint(bfc.width()) - 1)) {
				continue
			}
			v.reset(OpARM64BFXIL)
			v.AuxInt = arm64BitFieldToAuxInt(bfc)
			v.AddArg2(y, x)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64ORN(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORN x (MOVDconst [c]))
	// result: (ORconst [^c] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^c)
		v.AddArg(x)
		return true
	}
	// match: (ORN x x)
	// result: (MOVDconst [-1])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORN x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORNshiftLL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64ORNshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (ORN x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORNshiftRL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64ORNshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (ORN x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORNshiftRA x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64ORNshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (ORN x0 x1:(RORconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORNshiftRO x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64RORconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64ORNshiftRO)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORNshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORNshiftLL x (MOVDconst [c]) [d])
	// result: (ORconst x [^int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORNshiftLL (SLLconst x [c]) x [c])
	// result: (MOVDconst [-1])
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
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORNshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORNshiftRA x (MOVDconst [c]) [d])
	// result: (ORconst x [^(c>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^(c >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORNshiftRA (SRAconst x [c]) x [c])
	// result: (MOVDconst [-1])
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
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORNshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORNshiftRL x (MOVDconst [c]) [d])
	// result: (ORconst x [^int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORNshiftRL (SRLconst x [c]) x [c])
	// result: (MOVDconst [-1])
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
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORNshiftRO(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORNshiftRO x (MOVDconst [c]) [d])
	// result: (ORconst x [^rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^rotateRight64(c, d))
		v.AddArg(x)
		return true
	}
	// match: (ORNshiftRO (RORconst x [c]) x [c])
	// result: (MOVDconst [-1])
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
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORconst(v *Value) bool {
	v_0 := v.Args[0]
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
	// match: (ORconst [-1] _)
	// result: (MOVDconst [-1])
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c|d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(c | d)
		return true
	}
	// match: (ORconst [c] (ORconst [d] x))
	// result: (ORconst [c|d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	// match: (ORconst [c1] (ANDconst [c2] x))
	// cond: c2|c1 == ^0
	// result: (ORconst [c1] x)
	for {
		c1 := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c2|c1 == ^0) {
			break
		}
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c1)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ORshiftLL (MOVDconst [c]) x [d])
	// result: (ORconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftLL x (MOVDconst [c]) [d])
	// result: (ORconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftLL y:(SLLconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpARM64SLLconst || auxIntToInt64(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ORshiftLL <typ.UInt16> [8] (UBFX <typ.UInt16> [armBFAuxInt(8, 8)] x) x)
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
	// match: (ORshiftLL [8] (UBFX [armBFAuxInt(8, 24)] (ANDconst [c1] x)) (ANDconst [c2] x))
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
	// match: (ORshiftLL [8] (SRLconst [8] (ANDconst [c1] x)) (ANDconst [c2] x))
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
	// match: (ORshiftLL [8] (SRLconst [8] (ANDconst [c1] x)) (ANDconst [c2] x))
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
	// match: ( ORshiftLL [c] (SRLconst x [64-c]) x2)
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
	// match: ( ORshiftLL <t> [c] (UBFX [bfc] x) x2)
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
	// match: (ORshiftLL [s] (ANDconst [xc] x) (ANDconst [yc] y))
	// cond: xc == ^(yc << s) && yc & (yc+1) == 0 && yc > 0 && s+log64(yc+1) <= 64
	// result: (BFI [armBFAuxInt(s, log64(yc+1))] x y)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		xc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if v_1.Op != OpARM64ANDconst {
			break
		}
		yc := auxIntToInt64(v_1.AuxInt)
		y := v_1.Args[0]
		if !(xc == ^(yc<<s) && yc&(yc+1) == 0 && yc > 0 && s+log64(yc+1) <= 64) {
			break
		}
		v.reset(OpARM64BFI)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(s, log64(yc+1)))
		v.AddArg2(x, y)
		return true
	}
	// match: (ORshiftLL [sc] (UBFX [bfc] x) (SRLconst [sc] y))
	// cond: sc == bfc.width()
	// result: (BFXIL [bfc] y x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if v_1.Op != OpARM64SRLconst || auxIntToInt64(v_1.AuxInt) != sc {
			break
		}
		y := v_1.Args[0]
		if !(sc == bfc.width()) {
			break
		}
		v.reset(OpARM64BFXIL)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRA (MOVDconst [c]) x [d])
	// result: (ORconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRAconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRA x (MOVDconst [c]) [d])
	// result: (ORconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftRA y:(SRAconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpARM64SRAconst || auxIntToInt64(y.AuxInt) != c {
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
func rewriteValueARM64_OpARM64ORshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRL (MOVDconst [c]) x [d])
	// result: (ORconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRL x (MOVDconst [c]) [d])
	// result: (ORconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftRL y:(SRLconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpARM64SRLconst || auxIntToInt64(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ORshiftRL [rc] (ANDconst [ac] x) (SLLconst [lc] y))
	// cond: lc > rc && ac == ^((1<<uint(64-lc)-1) << uint64(lc-rc))
	// result: (BFI [armBFAuxInt(lc-rc, 64-lc)] x y)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		ac := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if v_1.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_1.AuxInt)
		y := v_1.Args[0]
		if !(lc > rc && ac == ^((1<<uint(64-lc)-1)<<uint64(lc-rc))) {
			break
		}
		v.reset(OpARM64BFI)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc-rc, 64-lc))
		v.AddArg2(x, y)
		return true
	}
	// match: (ORshiftRL [rc] (ANDconst [ac] y) (SLLconst [lc] x))
	// cond: lc < rc && ac == ^((1<<uint(64-rc)-1))
	// result: (BFXIL [armBFAuxInt(rc-lc, 64-rc)] y x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		ac := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if v_1.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_1.AuxInt)
		x := v_1.Args[0]
		if !(lc < rc && ac == ^(1<<uint(64-rc)-1)) {
			break
		}
		v.reset(OpARM64BFXIL)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc-lc, 64-rc))
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORshiftRO(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRO (MOVDconst [c]) x [d])
	// result: (ORconst [c] (RORconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64RORconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRO x (MOVDconst [c]) [d])
	// result: (ORconst x [rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(rotateRight64(c, d))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftRO y:(RORconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpARM64RORconst || auxIntToInt64(y.AuxInt) != c {
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
func rewriteValueARM64_OpARM64REV(v *Value) bool {
	v_0 := v.Args[0]
	// match: (REV (REV p))
	// result: p
	for {
		if v_0.Op != OpARM64REV {
			break
		}
		p := v_0.Args[0]
		v.copyOf(p)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64REVW(v *Value) bool {
	v_0 := v.Args[0]
	// match: (REVW (REVW p))
	// result: p
	for {
		if v_0.Op != OpARM64REVW {
			break
		}
		p := v_0.Args[0]
		v.copyOf(p)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ROR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROR x (MOVDconst [c]))
	// result: (RORconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64RORconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64RORW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RORW x (MOVDconst [c]))
	// result: (RORWconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64RORWconst)
		v.AuxInt = int64ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SBCSflags(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SBCSflags x y (Select1 <types.TypeFlags> (NEGSflags (NEG <typ.UInt64> (NGCzerocarry <typ.UInt64> bo)))))
	// result: (SBCSflags x y bo)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 || v_2.Type != types.TypeFlags {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpARM64NEGSflags {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpARM64NEG || v_2_0_0.Type != typ.UInt64 {
			break
		}
		v_2_0_0_0 := v_2_0_0.Args[0]
		if v_2_0_0_0.Op != OpARM64NGCzerocarry || v_2_0_0_0.Type != typ.UInt64 {
			break
		}
		bo := v_2_0_0_0.Args[0]
		v.reset(OpARM64SBCSflags)
		v.AddArg3(x, y, bo)
		return true
	}
	// match: (SBCSflags x y (Select1 <types.TypeFlags> (NEGSflags (MOVDconst [0]))))
	// result: (SUBSflags x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 || v_2.Type != types.TypeFlags {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpARM64NEGSflags {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpARM64MOVDconst || auxIntToInt64(v_2_0_0.AuxInt) != 0 {
			break
		}
		v.reset(OpARM64SUBSflags)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SBFX(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SBFX [bfc] s:(SLLconst [sc] x))
	// cond: s.Uses == 1 && sc <= bfc.lsb()
	// result: (SBFX [armBFAuxInt(bfc.lsb() - sc, bfc.width())] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		s := v_0
		if s.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(s.AuxInt)
		x := s.Args[0]
		if !(s.Uses == 1 && sc <= bfc.lsb()) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()-sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (SBFX [bfc] s:(SLLconst [sc] x))
	// cond: s.Uses == 1 && sc > bfc.lsb()
	// result: (SBFIZ [armBFAuxInt(sc - bfc.lsb(), bfc.width() - (sc-bfc.lsb()))] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		s := v_0
		if s.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(s.AuxInt)
		x := s.Args[0]
		if !(s.Uses == 1 && sc > bfc.lsb()) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc-bfc.lsb(), bfc.width()-(sc-bfc.lsb())))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLL x (MOVDconst [c]))
	// result: (SLLconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SLLconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	// match: (SLL x (ANDconst [63] y))
	// result: (SLL x y)
	for {
		x := v_0
		if v_1.Op != OpARM64ANDconst || auxIntToInt64(v_1.AuxInt) != 63 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpARM64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SLLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLLconst [c] (MOVDconst [d]))
	// result: (MOVDconst [d<<uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(d << uint64(c))
		return true
	}
	// match: (SLLconst [c] (SRLconst [c] x))
	// cond: 0 < c && c < 64
	// result: (ANDconst [^(1<<uint(c)-1)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if !(0 < c && c < 64) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(^(1<<uint(c) - 1))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVWreg x))
	// result: (SBFIZ [armBFAuxInt(lc, min(32, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(32, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVHreg x))
	// result: (SBFIZ [armBFAuxInt(lc, min(16, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(16, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVBreg x))
	// result: (SBFIZ [armBFAuxInt(lc, min(8, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(8, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVWUreg x))
	// result: (UBFIZ [armBFAuxInt(lc, min(32, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWUreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(32, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVHUreg x))
	// result: (UBFIZ [armBFAuxInt(lc, min(16, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHUreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(16, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVBUreg x))
	// result: (UBFIZ [armBFAuxInt(lc, min(8, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBUreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(8, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [sc] (ANDconst [ac] x))
	// cond: isARM64BFMask(sc, ac, 0)
	// result: (UBFIZ [armBFAuxInt(sc, arm64BFWidth(ac, 0))] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		ac := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isARM64BFMask(sc, ac, 0)) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc, arm64BFWidth(ac, 0)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [sc] (UBFIZ [bfc] x))
	// cond: sc+bfc.width()+bfc.lsb() < 64
	// result: (UBFIZ [armBFAuxInt(bfc.lsb()+sc, bfc.width())] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc+bfc.width()+bfc.lsb() < 64) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()+sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRA x (MOVDconst [c]))
	// result: (SRAconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SRAconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	// match: (SRA x (ANDconst [63] y))
	// result: (SRA x y)
	for {
		x := v_0
		if v_1.Op != OpARM64ANDconst || auxIntToInt64(v_1.AuxInt) != 63 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpARM64SRA)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SRAconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRAconst [c] (MOVDconst [d]))
	// result: (MOVDconst [d>>uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(d >> uint64(c))
		return true
	}
	// match: (SRAconst [rc] (SLLconst [lc] x))
	// cond: lc > rc
	// result: (SBFIZ [armBFAuxInt(lc-rc, 64-lc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc > rc) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc-rc, 64-lc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [rc] (SLLconst [lc] x))
	// cond: lc <= rc
	// result: (SBFX [armBFAuxInt(rc-lc, 64-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc <= rc) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc-lc, 64-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [rc] (MOVWreg x))
	// cond: rc < 32
	// result: (SBFX [armBFAuxInt(rc, 32-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 32) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 32-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [rc] (MOVHreg x))
	// cond: rc < 16
	// result: (SBFX [armBFAuxInt(rc, 16-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 16) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 16-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [rc] (MOVBreg x))
	// cond: rc < 8
	// result: (SBFX [armBFAuxInt(rc, 8-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 8) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 8-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [sc] (SBFIZ [bfc] x))
	// cond: sc < bfc.lsb()
	// result: (SBFIZ [armBFAuxInt(bfc.lsb()-sc, bfc.width())] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.lsb()) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()-sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [sc] (SBFIZ [bfc] x))
	// cond: sc >= bfc.lsb() && sc < bfc.lsb()+bfc.width()
	// result: (SBFX [armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc)] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc >= bfc.lsb() && sc < bfc.lsb()+bfc.width()) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRL x (MOVDconst [c]))
	// result: (SRLconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	// match: (SRL x (ANDconst [63] y))
	// result: (SRL x y)
	for {
		x := v_0
		if v_1.Op != OpARM64ANDconst || auxIntToInt64(v_1.AuxInt) != 63 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpARM64SRL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SRLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRLconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(uint64(d)>>uint64(c))])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(d) >> uint64(c)))
		return true
	}
	// match: (SRLconst [c] (SLLconst [c] x))
	// cond: 0 < c && c < 64
	// result: (ANDconst [1<<uint(64-c)-1] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if !(0 < c && c < 64) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(1<<uint(64-c) - 1)
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (MOVWUreg x))
	// cond: rc >= 32
	// result: (MOVDconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWUreg {
			break
		}
		if !(rc >= 32) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLconst [rc] (MOVHUreg x))
	// cond: rc >= 16
	// result: (MOVDconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHUreg {
			break
		}
		if !(rc >= 16) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLconst [rc] (MOVBUreg x))
	// cond: rc >= 8
	// result: (MOVDconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBUreg {
			break
		}
		if !(rc >= 8) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLconst [rc] (SLLconst [lc] x))
	// cond: lc > rc
	// result: (UBFIZ [armBFAuxInt(lc-rc, 64-lc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc > rc) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc-rc, 64-lc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (SLLconst [lc] x))
	// cond: lc < rc
	// result: (UBFX [armBFAuxInt(rc-lc, 64-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < rc) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc-lc, 64-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (MOVWUreg x))
	// cond: rc < 32
	// result: (UBFX [armBFAuxInt(rc, 32-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 32) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 32-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (MOVHUreg x))
	// cond: rc < 16
	// result: (UBFX [armBFAuxInt(rc, 16-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 16) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 16-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (MOVBUreg x))
	// cond: rc < 8
	// result: (UBFX [armBFAuxInt(rc, 8-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 8) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 8-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (ANDconst [ac] x))
	// cond: isARM64BFMask(sc, ac, sc)
	// result: (UBFX [armBFAuxInt(sc, arm64BFWidth(ac, sc))] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		ac := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isARM64BFMask(sc, ac, sc)) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc, arm64BFWidth(ac, sc)))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (UBFX [bfc] x))
	// cond: sc < bfc.width()
	// result: (UBFX [armBFAuxInt(bfc.lsb()+sc, bfc.width()-sc)] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.width()) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()+sc, bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (UBFIZ [bfc] x))
	// cond: sc == bfc.lsb()
	// result: (ANDconst [1<<uint(bfc.width())-1] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc == bfc.lsb()) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(1<<uint(bfc.width()) - 1)
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (UBFIZ [bfc] x))
	// cond: sc < bfc.lsb()
	// result: (UBFIZ [armBFAuxInt(bfc.lsb()-sc, bfc.width())] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.lsb()) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()-sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (UBFIZ [bfc] x))
	// cond: sc > bfc.lsb() && sc < bfc.lsb()+bfc.width()
	// result: (UBFX [armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc)] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc > bfc.lsb() && sc < bfc.lsb()+bfc.width()) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64STP(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (STP [off1] {sym} (ADDconst [off2] ptr) val1 val2 mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (STP [off1+int32(off2)] {sym} ptr val1 val2 mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val1 := v_1
		val2 := v_2
		mem := v_3
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg4(ptr, val1, val2, mem)
		return true
	}
	// match: (STP [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) val1 val2 mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (STP [off1+off2] {mergeSym(sym1,sym2)} ptr val1 val2 mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val1 := v_1
		val2 := v_2
		mem := v_3
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg4(ptr, val1, val2, mem)
		return true
	}
	// match: (STP [off] {sym} ptr (MOVDconst [0]) (MOVDconst [0]) mem)
	// result: (MOVQstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 || v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpARM64MOVQstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUB x (MOVDconst [c]))
	// result: (SUBconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUB a l:(MUL x y))
	// cond: l.Uses==1 && clobber(l)
	// result: (MSUB a x y)
	for {
		a := v_0
		l := v_1
		if l.Op != OpARM64MUL {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		v.reset(OpARM64MSUB)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUB a l:(MNEG x y))
	// cond: l.Uses==1 && clobber(l)
	// result: (MADD a x y)
	for {
		a := v_0
		l := v_1
		if l.Op != OpARM64MNEG {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		v.reset(OpARM64MADD)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUB a l:(MULW x y))
	// cond: v.Type.Size() <= 4 && l.Uses==1 && clobber(l)
	// result: (MSUBW a x y)
	for {
		a := v_0
		l := v_1
		if l.Op != OpARM64MULW {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(v.Type.Size() <= 4 && l.Uses == 1 && clobber(l)) {
			break
		}
		v.reset(OpARM64MSUBW)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUB a l:(MNEGW x y))
	// cond: v.Type.Size() <= 4 && l.Uses==1 && clobber(l)
	// result: (MADDW a x y)
	for {
		a := v_0
		l := v_1
		if l.Op != OpARM64MNEGW {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(v.Type.Size() <= 4 && l.Uses == 1 && clobber(l)) {
			break
		}
		v.reset(OpARM64MADDW)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUB a p:(ADDconst [c] m:(MUL _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (SUBconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MUL || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(ADDconst [c] m:(MULW _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (SUBconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MULW || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(ADDconst [c] m:(MNEG _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (SUBconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MNEG || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(ADDconst [c] m:(MNEGW _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (SUBconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MNEGW || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(SUBconst [c] m:(MUL _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (ADDconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64SUBconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MUL || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(SUBconst [c] m:(MULW _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (ADDconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64SUBconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MULW || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(SUBconst [c] m:(MNEG _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (ADDconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64SUBconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MNEG || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(SUBconst [c] m:(MNEGW _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (ADDconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64SUBconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MNEGW || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB x x)
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
	// match: (SUB x (SUB y z))
	// result: (SUB (ADD <v.Type> x z) y)
	for {
		x := v_0
		if v_1.Op != OpARM64SUB {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64ADD, v.Type)
		v0.AddArg2(x, z)
		v.AddArg2(v0, y)
		return true
	}
	// match: (SUB (SUB x y) z)
	// result: (SUB x (ADD <y.Type> y z))
	for {
		if v_0.Op != OpARM64SUB {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		z := v_1
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64ADD, y.Type)
		v0.AddArg2(y, z)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SUB x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (SUBshiftLL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (SUB x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (SUBshiftRL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64SUBshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (SUB x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (SUBshiftRA x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64SUBshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBconst [c] (MOVDconst [d]))
	// result: (MOVDconst [d-c])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(d - c)
		return true
	}
	// match: (SUBconst [c] (SUBconst [d] x))
	// result: (ADDconst [-c-d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SUBconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	// match: (SUBconst [c] (ADDconst [d] x))
	// result: (ADDconst [-c+d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(-c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUBshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBshiftLL x (MOVDconst [c]) [d])
	// result: (SUBconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
```