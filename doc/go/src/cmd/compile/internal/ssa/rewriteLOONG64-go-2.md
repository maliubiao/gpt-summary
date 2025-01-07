Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteLOONG64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共4部分，请归纳一下它的功能

"""
// match: (ORconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c|d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c | d)
		return true
	}
	// match: (ORconst [c] (ORconst [d] x))
	// cond: is32Bit(c|d)
	// result: (ORconst [c|d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c | d)) {
			break
		}
		v.reset(OpLOONG64ORconst)
		v.AuxInt = int64ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64REMV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (REMV (MOVVconst [c]) (MOVVconst [d]))
	// cond: d != 0
	// result: (MOVVconst [c%d])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c % d)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64REMVU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (REMVU _ (MOVVconst [1]))
	// result: (MOVVconst [0])
	for {
		if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (REMVU x (MOVVconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (ANDconst [c-1] x)
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpLOONG64ANDconst)
		v.AuxInt = int64ToAuxInt(c - 1)
		v.AddArg(x)
		return true
	}
	// match: (REMVU (MOVVconst [c]) (MOVVconst [d]))
	// cond: d != 0
	// result: (MOVVconst [int64(uint64(c)%uint64(d))])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) % uint64(d)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64ROTR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROTR x (MOVVconst [c]))
	// result: (ROTRconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64ROTRconst)
		v.AuxInt = int64ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64ROTRV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROTRV x (MOVVconst [c]))
	// result: (ROTRVconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64ROTRVconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SGT(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SGT (MOVVconst [c]) (NEGV (SUBVconst [d] x)))
	// cond: is32Bit(d-c)
	// result: (SGT x (MOVVconst [d-c]))
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64NEGV {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpLOONG64SUBVconst {
			break
		}
		d := auxIntToInt64(v_1_0.AuxInt)
		x := v_1_0.Args[0]
		if !(is32Bit(d - c)) {
			break
		}
		v.reset(OpLOONG64SGT)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(d - c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SGT (MOVVconst [c]) x)
	// cond: is32Bit(c)
	// result: (SGTconst [c] x)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64SGTconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SGT x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SGTU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SGTU (MOVVconst [c]) x)
	// cond: is32Bit(c)
	// result: (SGTUconst [c] x)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64SGTUconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SGTU x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SGTUconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SGTUconst [c] (MOVVconst [d]))
	// cond: uint64(c)>uint64(d)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(uint64(c) > uint64(d)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (MOVVconst [d]))
	// cond: uint64(c)<=uint64(d)
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(uint64(c) <= uint64(d)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTUconst [c] (MOVBUreg _))
	// cond: 0xff < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg || !(0xff < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (MOVHUreg _))
	// cond: 0xffff < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg || !(0xffff < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (ANDconst [m] _))
	// cond: uint64(m) < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		if !(uint64(m) < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (SRLVconst _ [d]))
	// cond: 0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64SRLVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SGTconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SGTconst [c] (MOVVconst [d]))
	// cond: c>d
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(c > d) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVVconst [d]))
	// cond: c<=d
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(c <= d) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVBreg _))
	// cond: 0x7f < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBreg || !(0x7f < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVBreg _))
	// cond: c <= -0x80
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBreg || !(c <= -0x80) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVBUreg _))
	// cond: 0xff < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg || !(0xff < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVBUreg _))
	// cond: c < 0
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg || !(c < 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVHreg _))
	// cond: 0x7fff < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHreg || !(0x7fff < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVHreg _))
	// cond: c <= -0x8000
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHreg || !(c <= -0x8000) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVHUreg _))
	// cond: 0xffff < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg || !(0xffff < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVHUreg _))
	// cond: c < 0
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg || !(c < 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVWUreg _))
	// cond: c < 0
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVWUreg || !(c < 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (ANDconst [m] _))
	// cond: 0 <= m && m < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		if !(0 <= m && m < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (SRLVconst _ [d]))
	// cond: 0 <= c && 0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64SRLVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(0 <= c && 0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SLLV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLLV _ (MOVVconst [c]))
	// cond: uint64(c)>=64
	// result: (MOVVconst [0])
	for {
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SLLV x (MOVVconst [c]))
	// result: (SLLVconst x [c])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64SLLVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SLLVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLLVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [d<<uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(d << uint64(c))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SRAV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRAV x (MOVVconst [c]))
	// cond: uint64(c)>=64
	// result: (SRAVconst x [63])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpLOONG64SRAVconst)
		v.AuxInt = int64ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	// match: (SRAV x (MOVVconst [c]))
	// result: (SRAVconst x [c])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64SRAVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SRAVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRAVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [d>>uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(d >> uint64(c))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SRLV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRLV _ (MOVVconst [c]))
	// cond: uint64(c)>=64
	// result: (MOVVconst [0])
	for {
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLV x (MOVVconst [c]))
	// result: (SRLVconst x [c])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64SRLVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SRLVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRLVconst [rc] (SLLVconst [lc] x))
	// cond: lc <= rc
	// result: (BSTRPICKV [rc-lc + ((64-lc)-1)<<6] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64SLLVconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc <= rc) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc - lc + ((64-lc)-1)<<6)
		v.AddArg(x)
		return true
	}
	// match: (SRLVconst [rc] (MOVWUreg x))
	// cond: rc < 32
	// result: (BSTRPICKV [rc + 31<<6] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVWUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 32) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc + 31<<6)
		v.AddArg(x)
		return true
	}
	// match: (SRLVconst [rc] (MOVHUreg x))
	// cond: rc < 16
	// result: (BSTRPICKV [rc + 15<<6] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 16) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc + 15<<6)
		v.AddArg(x)
		return true
	}
	// match: (SRLVconst [rc] (MOVBUreg x))
	// cond: rc < 8
	// result: (BSTRPICKV [rc + 7<<6] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 8) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc + 7<<6)
		v.AddArg(x)
		return true
	}
	// match: (SRLVconst [rc] (MOVWUreg x))
	// cond: rc >= 32
	// result: (MOVVconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVWUreg {
			break
		}
		if !(rc >= 32) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLVconst [rc] (MOVHUreg x))
	// cond: rc >= 16
	// result: (MOVVconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg {
			break
		}
		if !(rc >= 16) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLVconst [rc] (MOVBUreg x))
	// cond: rc >= 8
	// result: (MOVVconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg {
			break
		}
		if !(rc >= 8) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [int64(uint64(d)>>uint64(c))])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(d) >> uint64(c)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SUBD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBD (MULD x y) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FMSUBD x y z)
	for {
		if v_0.Op != OpLOONG64MULD {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		z := v_1
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FMSUBD)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBD z (MULD x y))
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMSUBD x y z)
	for {
		z := v_0
		if v_1.Op != OpLOONG64MULD {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FNMSUBD)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBD z (NEGD (MULD x y)))
	// cond: z.Block.Func.useFMA(v)
	// result: (FMADDD x y z)
	for {
		z := v_0
		if v_1.Op != OpLOONG64NEGD {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpLOONG64MULD {
			break
		}
		y := v_1_0.Args[1]
		x := v_1_0.Args[0]
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FMADDD)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBD (NEGD (MULD x y)) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMADDD x y z)
	for {
		if v_0.Op != OpLOONG64NEGD {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpLOONG64MULD {
			break
		}
		y := v_0_0.Args[1]
		x := v_0_0.Args[0]
		z := v_1
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FNMADDD)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SUBF(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBF (MULF x y) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FMSUBF x y z)
	for {
		if v_0.Op != OpLOONG64MULF {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		z := v_1
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FMSUBF)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBF z (MULF x y))
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMSUBF x y z)
	for {
		z := v_0
		if v_1.Op != OpLOONG64MULF {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FNMSUBF)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBF z (NEGF (MULF x y)))
	// cond: z.Block.Func.useFMA(v)
	// result: (FMADDF x y z)
	for {
		z := v_0
		if v_1.Op != OpLOONG64NEGF {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpLOONG64MULF {
			break
		}
		y := v_1_0.Args[1]
		x := v_1_0.Args[0]
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FMADDF)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBF (NEGF (MULF x y)) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMADDF x y z)
	for {
		if v_0.Op != OpLOONG64NEGF {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpLOONG64MULF {
			break
		}
		y := v_0_0.Args[1]
		x := v_0_0.Args[0]
		z := v_1
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FNMADDF)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SUBV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBV x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (SUBVconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64SUBVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUBV x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUBV (MOVVconst [0]) x)
	// result: (NEGV x)
	for {
		if v_0.Op != OpLOONG64MOVVconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpLOONG64NEGV)
		v.AddArg(x)
		return true
	}
	// match: (SUBV (MOVVconst [c]) (NEGV (SUBVconst [d] x)))
	// result: (ADDVconst [c-d] x)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64NEGV {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpLOONG64SUBVconst {
			break
		}
		d := auxIntToInt64(v_1_0.AuxInt)
		x := v_1_0.Args[0]
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SUBVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBVconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [d-c])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(d - c)
		return true
	}
	// match: (SUBVconst [c] (SUBVconst [d] x))
	// cond: is32Bit(-c-d)
	// result: (ADDVconst [-c-d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64SUBVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c - d)) {
			break
		}
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	// match: (SUBVconst [c] (ADDVconst [d] x))
	// cond: is32Bit(-c+d)
	// result: (ADDVconst [-c+d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c + d)) {
			break
		}
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(-c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpLOONG64XORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64XORconst(v *Value) bool {
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
	// result: (NORconst [0] x)
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.reset(OpLOONG64NORconst)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg(x)
		return true
	}
	// match: (XORconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c^d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		return true
	}
	// match: (XORconst [c] (XORconst [d] x))
	// cond: is32Bit(c^d)
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64XORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c ^ d)) {
			break
		}
		v.reset(OpLOONG64XORconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (XOR (MOVVconst [1]) (SGT (SignExt16to64 x) (SignExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGT, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (XOR (MOVVconst [1]) (SGTU (ZeroExt16to64 x) (ZeroExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32 x y)
	// result: (XOR (MOVVconst [1]) (SGT (SignExt32to64 x) (SignExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGT, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (FPFlagTrue (CMPGEF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPGEF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32U x y)
	// result: (XOR (MOVVconst [1]) (SGTU (ZeroExt32to64 x) (ZeroExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64 x y)
	// result: (XOR (MOVVconst [1]) (SGT x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGT, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (FPFlagTrue (CMPGED y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPGED, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpLeq64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64U x y)
	// result: (XOR (MOVVconst [1]) (SGTU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (XOR (MOVVconst [1]) (SGT (SignExt8to64 x) (SignExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGT, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (XOR (MOVVconst [1]) (SGTU (ZeroExt8to64 x) (ZeroExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (SGT (SignExt16to64 y) (SignExt16to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGT)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (SGTU (ZeroExt16to64 y) (ZeroExt16to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32 x y)
	// result: (SGT (SignExt32to64 y) (SignExt32to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGT)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (FPFlagTrue (CMPGTF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPGTF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32U x y)
	// result: (SGTU (ZeroExt32to64 y) (ZeroExt32to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less64 x y)
	// result: (SGT y x)
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGT)
		v.AddArg2(y, x)
		return true
	}
}
func rewriteValueLOONG64_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (FPFlagTrue (CMPGTD y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPGTD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpLess64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less64U x y)
	// result: (SGTU y x)
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v.AddArg2(y, x)
		return true
	}
}
func rewriteValueLOONG64_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (SGT (SignExt8to64 y) (SignExt8to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGT)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (SGTU (ZeroExt8to64 y) (ZeroExt8to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLoad(v *Value) bool {
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
		v.reset(OpLOONG64MOVBUload)
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
		v.reset(OpLOONG64MOVBload)
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
		v.reset(OpLOONG64MOVBUload)
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
		v.reset(OpLOONG64MOVHload)
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
		v.reset(OpLOONG64MOVHUload)
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
		v.reset(OpLOONG64MOVWload)
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
		v.reset(OpLOONG64MOVWUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (MOVVload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpLOONG64MOVVload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (MOVFload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpLOONG64MOVFload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (MOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpLOONG64MOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVVaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpLOONG64MOVVaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVVaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpLOONG64MOVVaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x64 <t> x y)
	// result: (MASKEQZ (SLLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x32 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x64 <t> x y)
	// result: (MASKEQZ (SLLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x16 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x32 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x64 <t> x y)
	// result: (MASKEQZ (SLLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x8 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x64 <t> x y)
	// result: (MASKEQZ (SLLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (REMV (SignExt16to64 x) (SignExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (REMVU (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMVU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32 x y)
	// result: (REMV (SignExt32to64 x) (SignExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32u x y)
	// result: (REMVU (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMVU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod64 x y)
	// result: (REMV x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMV)
		v.AddArg2(x, y)
		return true
	}
}
func rewriteValueLOONG64_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (REMV (SignExt8to64 x) (SignExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (REMVU (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMVU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMove(v *Value) bool {
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
		v.reset(OpLOONG64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVBUload, typ.UInt8)
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
		v.reset(OpLOONG64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVHUload, typ.UInt16)
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
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVHUload, typ.UInt16)
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
		v.reset(OpLOONG64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
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
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
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
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
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
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] dst src mem)
	// result: (MOVVstore dst (MOVVload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [9] dst src mem)
	// result: (MOVBstore [8] dst (MOVBUload [8] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 9 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [10] dst src mem)
	// result: (MOVHstore [8] dst (MOVHUload [8] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 10 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [11] dst src mem)
	// result: (MOVWstore [7] dst (MOVWload [7] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 11 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVWload, typ.Int32)
		v0.AuxInt = int32ToAuxInt(7)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [12] dst src mem)
	// result: (MOVWstore [8] dst (MOVWUload [8] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [13] dst src mem)
	// result: (MOVVstore [5] dst (MOVVload [5] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 13 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(5)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(5)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [14] dst src mem)
	// result: (MOVVstore [6] dst (MOVVload [6] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 14 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(6)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [15] dst src mem)
	// result: (MOVVstore [7] dst (MOVVload [7] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 15 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(7)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [16] dst src mem)
	// result: (MOVVstore [8] dst (MOVVload [8] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%8 != 0 && s > 16
	// result: (Move [s%8] (OffPtr <dst.Type> dst [s-s%8]) (OffPtr <src.Type> src [s-s%8]) (Move [s-s%8] dst src mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%8 != 0 && s > 16) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(s % 8)
		v0 := b.NewValue0(v.Pos, OpOffPtr, dst.Type)
		v0.AuxInt = int64ToAuxInt(s - s%8)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpOffPtr, src.Type)
		v1.AuxInt = int64ToAuxInt(s - s%8)
		v1.AddArg(src)
		v2 := b.NewValue0(v.Pos, OpMove, types.TypeMem)
		v2.AuxInt = int64ToAuxInt(s - s%8)
		v2.AddArg3(dst, src, mem)
		v.AddArg3(v0, v1, v2)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%8 == 0 && s > 16 && s <= 8*128 && !config.noDuffDevice && logLargeCopy(v, s)
	// result: (DUFFCOPY [16 * (128 - s/8)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%8 == 0 && s > 16 && s <= 8*128 && !config.noDuffDevice && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpLOONG64DUFFCOPY)
		v.AuxInt = int64ToAuxInt(16 * (128 - s/8))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%8 == 0 && s > 1024 && logLargeCopy(v, s)
	// result: (LoweredMove dst src (ADDVconst <src.Type> src [s-8]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%8 == 0 && s > 1024 && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpLOONG64LoweredMove)
		v0 := b.NewValue0(v.Pos, OpLOONG64ADDVconst, src.Type)
		v0.AuxInt = int64ToAuxInt(s - 8)
		v0.AddArg(src)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (SGTU (XOR (ZeroExt16to32 x) (ZeroExt16to64 y)) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32 x y)
	// result: (SGTU (XOR (ZeroExt32to64 x) (ZeroExt32to64 y)) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32F x y)
	// result: (FPFlagFalse (CMPEQF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagFalse)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPEQF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq64 x y)
	// result: (SGTU (XOR x y) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64F x y)
	// result: (FPFlagFalse (CMPEQD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagFalse)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPEQD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (SGTU (XOR (ZeroExt8to64 x) (ZeroExt8to64 y)) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqPtr x y)
	// result: (SGTU (XOR x y) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not x)
	// result: (XORconst [1] x)
	for {
		x := v_0
		v.reset(OpLOONG64XORconst)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueLOONG64_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr [off] ptr:(SP))
	// result: (MOVVaddr [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if ptr.Op != OpSP {
			break
		}
		v.reset(OpLOONG64MOVVaddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// result: (ADDVconst [off] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(off)
		v.AddArg(ptr)
		return true
	}
}
func rewriteValueLOONG64_OpPanicBounds(v *Value) bool {
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
		v.reset(OpLOONG64LoweredPanicBoundsA)
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
		v.reset(OpLOONG64LoweredPanicBoundsB)
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
		v.reset(OpLOONG64LoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_Op
"""




```