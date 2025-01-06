Response:

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第7部分，共13部分，请归纳一下它的功能

"""
ddArg2(x, v0)
		return true
	}
	// match: (Lsh8x64 (Rsh8Ux64 (Lsh8x64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Lsh8x64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpRsh8Ux64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpLsh8x64 {
			break
		}
		_ = v_0_0.Args[1]
		x := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c1 := auxIntToInt64(v_0_0_1.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c2 := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		c3 := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)) {
			break
		}
		v.reset(OpLsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh8x64 (And8 (Rsh8x64 <t> x (Const64 <t2> [c])) (Const8 [d])) (Const64 [e]))
	// cond: c >= e
	// result: (And8 (Rsh8x64 <t> x (Const64 <t2> [c-e])) (Const8 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh8x64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c >= e) {
				continue
			}
			v.reset(OpAnd8)
			v0 := b.NewValue0(v.Pos, OpRsh8x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(c - e)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, t)
			v2.AuxInt = int8ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh8x64 (And8 (Rsh8Ux64 <t> x (Const64 <t2> [c])) (Const8 [d])) (Const64 [e]))
	// cond: c >= e
	// result: (And8 (Rsh8Ux64 <t> x (Const64 <t2> [c-e])) (Const8 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh8Ux64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c >= e) {
				continue
			}
			v.reset(OpAnd8)
			v0 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(c - e)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, t)
			v2.AuxInt = int8ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh8x64 (And8 (Rsh8x64 <t> x (Const64 <t2> [c])) (Const8 [d])) (Const64 [e]))
	// cond: c < e
	// result: (And8 (Lsh8x64 <t> x (Const64 <t2> [e-c])) (Const8 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh8x64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c < e) {
				continue
			}
			v.reset(OpAnd8)
			v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(e - c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, t)
			v2.AuxInt = int8ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh8x64 (And8 (Rsh8Ux64 <t> x (Const64 <t2> [c])) (Const8 [d])) (Const64 [e]))
	// cond: c < e
	// result: (And8 (Lsh8x64 <t> x (Const64 <t2> [e-c])) (Const8 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh8Ux64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c < e) {
				continue
			}
			v.reset(OpAnd8)
			v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(e - c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, t)
			v2.AuxInt = int8ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x8 <t> x (Const8 [c]))
	// result: (Lsh8x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpLsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh8x8 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Mod16 (Const16 [c]) (Const16 [d]))
	// cond: d != 0
	// result: (Const16 [c % d])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst16 {
			break
		}
		d := auxIntToInt16(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(c % d)
		return true
	}
	// match: (Mod16 <t> n (Const16 [c]))
	// cond: isNonNegative(n) && isPowerOfTwo(c)
	// result: (And16 n (Const16 <t> [c-1]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(isNonNegative(n) && isPowerOfTwo(c)) {
			break
		}
		v.reset(OpAnd16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(c - 1)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod16 <t> n (Const16 [c]))
	// cond: c < 0 && c != -1<<15
	// result: (Mod16 <t> n (Const16 <t> [-c]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(c < 0 && c != -1<<15) {
			break
		}
		v.reset(OpMod16)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(-c)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod16 <t> x (Const16 [c]))
	// cond: x.Op != OpConst16 && (c > 0 || c == -1<<15)
	// result: (Sub16 x (Mul16 <t> (Div16 <t> x (Const16 <t> [c])) (Const16 <t> [c])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(x.Op != OpConst16 && (c > 0 || c == -1<<15)) {
			break
		}
		v.reset(OpSub16)
		v0 := b.NewValue0(v.Pos, OpMul16, t)
		v1 := b.NewValue0(v.Pos, OpDiv16, t)
		v2 := b.NewValue0(v.Pos, OpConst16, t)
		v2.AuxInt = int16ToAuxInt(c)
		v1.AddArg2(x, v2)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Mod16u (Const16 [c]) (Const16 [d]))
	// cond: d != 0
	// result: (Const16 [int16(uint16(c) % uint16(d))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst16 {
			break
		}
		d := auxIntToInt16(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(uint16(c) % uint16(d)))
		return true
	}
	// match: (Mod16u <t> n (Const16 [c]))
	// cond: isPowerOfTwo(c)
	// result: (And16 n (Const16 <t> [c-1]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpAnd16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(c - 1)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod16u <t> x (Const16 [c]))
	// cond: x.Op != OpConst16 && c > 0 && umagicOK16(c)
	// result: (Sub16 x (Mul16 <t> (Div16u <t> x (Const16 <t> [c])) (Const16 <t> [c])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(x.Op != OpConst16 && c > 0 && umagicOK16(c)) {
			break
		}
		v.reset(OpSub16)
		v0 := b.NewValue0(v.Pos, OpMul16, t)
		v1 := b.NewValue0(v.Pos, OpDiv16u, t)
		v2 := b.NewValue0(v.Pos, OpConst16, t)
		v2.AuxInt = int16ToAuxInt(c)
		v1.AddArg2(x, v2)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Mod32 (Const32 [c]) (Const32 [d]))
	// cond: d != 0
	// result: (Const32 [c % d])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(c % d)
		return true
	}
	// match: (Mod32 <t> n (Const32 [c]))
	// cond: isNonNegative(n) && isPowerOfTwo(c)
	// result: (And32 n (Const32 <t> [c-1]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(isNonNegative(n) && isPowerOfTwo(c)) {
			break
		}
		v.reset(OpAnd32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(c - 1)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod32 <t> n (Const32 [c]))
	// cond: c < 0 && c != -1<<31
	// result: (Mod32 <t> n (Const32 <t> [-c]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c < 0 && c != -1<<31) {
			break
		}
		v.reset(OpMod32)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(-c)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod32 <t> x (Const32 [c]))
	// cond: x.Op != OpConst32 && (c > 0 || c == -1<<31)
	// result: (Sub32 x (Mul32 <t> (Div32 <t> x (Const32 <t> [c])) (Const32 <t> [c])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(x.Op != OpConst32 && (c > 0 || c == -1<<31)) {
			break
		}
		v.reset(OpSub32)
		v0 := b.NewValue0(v.Pos, OpMul32, t)
		v1 := b.NewValue0(v.Pos, OpDiv32, t)
		v2 := b.NewValue0(v.Pos, OpConst32, t)
		v2.AuxInt = int32ToAuxInt(c)
		v1.AddArg2(x, v2)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Mod32u (Const32 [c]) (Const32 [d]))
	// cond: d != 0
	// result: (Const32 [int32(uint32(c) % uint32(d))])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) % uint32(d)))
		return true
	}
	// match: (Mod32u <t> n (Const32 [c]))
	// cond: isPowerOfTwo(c)
	// result: (And32 n (Const32 <t> [c-1]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpAnd32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(c - 1)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod32u <t> x (Const32 [c]))
	// cond: x.Op != OpConst32 && c > 0 && umagicOK32(c)
	// result: (Sub32 x (Mul32 <t> (Div32u <t> x (Const32 <t> [c])) (Const32 <t> [c])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(x.Op != OpConst32 && c > 0 && umagicOK32(c)) {
			break
		}
		v.reset(OpSub32)
		v0 := b.NewValue0(v.Pos, OpMul32, t)
		v1 := b.NewValue0(v.Pos, OpDiv32u, t)
		v2 := b.NewValue0(v.Pos, OpConst32, t)
		v2.AuxInt = int32ToAuxInt(c)
		v1.AddArg2(x, v2)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Mod64 (Const64 [c]) (Const64 [d]))
	// cond: d != 0
	// result: (Const64 [c % d])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(c % d)
		return true
	}
	// match: (Mod64 <t> n (Const64 [c]))
	// cond: isNonNegative(n) && isPowerOfTwo(c)
	// result: (And64 n (Const64 <t> [c-1]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isNonNegative(n) && isPowerOfTwo(c)) {
			break
		}
		v.reset(OpAnd64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c - 1)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod64 n (Const64 [-1<<63]))
	// cond: isNonNegative(n)
	// result: n
	for {
		n := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != -1<<63 || !(isNonNegative(n)) {
			break
		}
		v.copyOf(n)
		return true
	}
	// match: (Mod64 <t> n (Const64 [c]))
	// cond: c < 0 && c != -1<<63
	// result: (Mod64 <t> n (Const64 <t> [-c]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c < 0 && c != -1<<63) {
			break
		}
		v.reset(OpMod64)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(-c)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod64 <t> x (Const64 [c]))
	// cond: x.Op != OpConst64 && (c > 0 || c == -1<<63)
	// result: (Sub64 x (Mul64 <t> (Div64 <t> x (Const64 <t> [c])) (Const64 <t> [c])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(x.Op != OpConst64 && (c > 0 || c == -1<<63)) {
			break
		}
		v.reset(OpSub64)
		v0 := b.NewValue0(v.Pos, OpMul64, t)
		v1 := b.NewValue0(v.Pos, OpDiv64, t)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(c)
		v1.AddArg2(x, v2)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMod64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Mod64u (Const64 [c]) (Const64 [d]))
	// cond: d != 0
	// result: (Const64 [int64(uint64(c) % uint64(d))])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) % uint64(d)))
		return true
	}
	// match: (Mod64u <t> n (Const64 [c]))
	// cond: isPowerOfTwo(c)
	// result: (And64 n (Const64 <t> [c-1]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpAnd64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c - 1)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod64u <t> n (Const64 [-1<<63]))
	// result: (And64 n (Const64 <t> [1<<63-1]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != -1<<63 {
			break
		}
		v.reset(OpAnd64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(1<<63 - 1)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod64u <t> x (Const64 [c]))
	// cond: x.Op != OpConst64 && c > 0 && umagicOK64(c)
	// result: (Sub64 x (Mul64 <t> (Div64u <t> x (Const64 <t> [c])) (Const64 <t> [c])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(x.Op != OpConst64 && c > 0 && umagicOK64(c)) {
			break
		}
		v.reset(OpSub64)
		v0 := b.NewValue0(v.Pos, OpMul64, t)
		v1 := b.NewValue0(v.Pos, OpDiv64u, t)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(c)
		v1.AddArg2(x, v2)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Mod8 (Const8 [c]) (Const8 [d]))
	// cond: d != 0
	// result: (Const8 [c % d])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst8 {
			break
		}
		d := auxIntToInt8(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(c % d)
		return true
	}
	// match: (Mod8 <t> n (Const8 [c]))
	// cond: isNonNegative(n) && isPowerOfTwo(c)
	// result: (And8 n (Const8 <t> [c-1]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(isNonNegative(n) && isPowerOfTwo(c)) {
			break
		}
		v.reset(OpAnd8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(c - 1)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod8 <t> n (Const8 [c]))
	// cond: c < 0 && c != -1<<7
	// result: (Mod8 <t> n (Const8 <t> [-c]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(c < 0 && c != -1<<7) {
			break
		}
		v.reset(OpMod8)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(-c)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod8 <t> x (Const8 [c]))
	// cond: x.Op != OpConst8 && (c > 0 || c == -1<<7)
	// result: (Sub8 x (Mul8 <t> (Div8 <t> x (Const8 <t> [c])) (Const8 <t> [c])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(x.Op != OpConst8 && (c > 0 || c == -1<<7)) {
			break
		}
		v.reset(OpSub8)
		v0 := b.NewValue0(v.Pos, OpMul8, t)
		v1 := b.NewValue0(v.Pos, OpDiv8, t)
		v2 := b.NewValue0(v.Pos, OpConst8, t)
		v2.AuxInt = int8ToAuxInt(c)
		v1.AddArg2(x, v2)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Mod8u (Const8 [c]) (Const8 [d]))
	// cond: d != 0
	// result: (Const8 [int8(uint8(c) % uint8(d))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst8 {
			break
		}
		d := auxIntToInt8(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(int8(uint8(c) % uint8(d)))
		return true
	}
	// match: (Mod8u <t> n (Const8 [c]))
	// cond: isPowerOfTwo(c)
	// result: (And8 n (Const8 <t> [c-1]))
	for {
		t := v.Type
		n := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpAnd8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(c - 1)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Mod8u <t> x (Const8 [c]))
	// cond: x.Op != OpConst8 && c > 0 && umagicOK8( c)
	// result: (Sub8 x (Mul8 <t> (Div8u <t> x (Const8 <t> [c])) (Const8 <t> [c])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(x.Op != OpConst8 && c > 0 && umagicOK8(c)) {
			break
		}
		v.reset(OpSub8)
		v0 := b.NewValue0(v.Pos, OpMul8, t)
		v1 := b.NewValue0(v.Pos, OpDiv8u, t)
		v2 := b.NewValue0(v.Pos, OpConst8, t)
		v2.AuxInt = int8ToAuxInt(c)
		v1.AddArg2(x, v2)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Move {t} [n] dst1 src mem:(Zero {t} [n] dst2 _))
	// cond: isSamePtr(src, dst2)
	// result: (Zero {t} [n] dst1 mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		src := v_1
		mem := v_2
		if mem.Op != OpZero || auxIntToInt64(mem.AuxInt) != n || auxToType(mem.Aux) != t {
			break
		}
		dst2 := mem.Args[0]
		if !(isSamePtr(src, dst2)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v.AddArg2(dst1, mem)
		return true
	}
	// match: (Move {t} [n] dst1 src mem:(VarDef (Zero {t} [n] dst0 _)))
	// cond: isSamePtr(src, dst0)
	// result: (Zero {t} [n] dst1 mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		src := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpZero || auxIntToInt64(mem_0.AuxInt) != n || auxToType(mem_0.Aux) != t {
			break
		}
		dst0 := mem_0.Args[0]
		if !(isSamePtr(src, dst0)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v.AddArg2(dst1, mem)
		return true
	}
	// match: (Move {t} [n] dst (Addr {sym} (SB)) mem)
	// cond: symIsROZero(sym)
	// result: (Zero {t} [n] dst mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		if v_1.Op != OpAddr {
			break
		}
		sym := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		mem := v_2
		if !(symIsROZero(sym)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v.AddArg2(dst, mem)
		return true
	}
	// match: (Move {t1} [n] dst1 src1 store:(Store {t2} op:(OffPtr [o2] dst2) _ mem))
	// cond: isSamePtr(dst1, dst2) && store.Uses == 1 && n >= o2 + t2.Size() && disjoint(src1, n, op, t2.Size()) && clobber(store)
	// result: (Move {t1} [n] dst1 src1 mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst1 := v_0
		src1 := v_1
		store := v_2
		if store.Op != OpStore {
			break
		}
		t2 := auxToType(store.Aux)
		mem := store.Args[2]
		op := store.Args[0]
		if op.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(op.AuxInt)
		dst2 := op.Args[0]
		if !(isSamePtr(dst1, dst2) && store.Uses == 1 && n >= o2+t2.Size() && disjoint(src1, n, op, t2.Size()) && clobber(store)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t1)
		v.AddArg3(dst1, src1, mem)
		return true
	}
	// match: (Move {t} [n] dst1 src1 move:(Move {t} [n] dst2 _ mem))
	// cond: move.Uses == 1 && isSamePtr(dst1, dst2) && disjoint(src1, n, dst2, n) && clobber(move)
	// result: (Move {t} [n] dst1 src1 mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		src1 := v_1
		move := v_2
		if move.Op != OpMove || auxIntToInt64(move.AuxInt) != n || auxToType(move.Aux) != t {
			break
		}
		mem := move.Args[2]
		dst2 := move.Args[0]
		if !(move.Uses == 1 && isSamePtr(dst1, dst2) && disjoint(src1, n, dst2, n) && clobber(move)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v.AddArg3(dst1, src1, mem)
		return true
	}
	// match: (Move {t} [n] dst1 src1 vardef:(VarDef {x} move:(Move {t} [n] dst2 _ mem)))
	// cond: move.Uses == 1 && vardef.Uses == 1 && isSamePtr(dst1, dst2) && disjoint(src1, n, dst2, n) && clobber(move, vardef)
	// result: (Move {t} [n] dst1 src1 (VarDef {x} mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		src1 := v_1
		vardef := v_2
		if vardef.Op != OpVarDef {
			break
		}
		x := auxToSym(vardef.Aux)
		move := vardef.Args[0]
		if move.Op != OpMove || auxIntToInt64(move.AuxInt) != n || auxToType(move.Aux) != t {
			break
		}
		mem := move.Args[2]
		dst2 := move.Args[0]
		if !(move.Uses == 1 && vardef.Uses == 1 && isSamePtr(dst1, dst2) && disjoint(src1, n, dst2, n) && clobber(move, vardef)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v0 := b.NewValue0(v.Pos, OpVarDef, types.TypeMem)
		v0.Aux = symToAux(x)
		v0.AddArg(mem)
		v.AddArg3(dst1, src1, v0)
		return true
	}
	// match: (Move {t} [n] dst1 src1 zero:(Zero {t} [n] dst2 mem))
	// cond: zero.Uses == 1 && isSamePtr(dst1, dst2) && disjoint(src1, n, dst2, n) && clobber(zero)
	// result: (Move {t} [n] dst1 src1 mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		src1 := v_1
		zero := v_2
		if zero.Op != OpZero || auxIntToInt64(zero.AuxInt) != n || auxToType(zero.Aux) != t {
			break
		}
		mem := zero.Args[1]
		dst2 := zero.Args[0]
		if !(zero.Uses == 1 && isSamePtr(dst1, dst2) && disjoint(src1, n, dst2, n) && clobber(zero)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v.AddArg3(dst1, src1, mem)
		return true
	}
	// match: (Move {t} [n] dst1 src1 vardef:(VarDef {x} zero:(Zero {t} [n] dst2 mem)))
	// cond: zero.Uses == 1 && vardef.Uses == 1 && isSamePtr(dst1, dst2) && disjoint(src1, n, dst2, n) && clobber(zero, vardef)
	// result: (Move {t} [n] dst1 src1 (VarDef {x} mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		src1 := v_1
		vardef := v_2
		if vardef.Op != OpVarDef {
			break
		}
		x := auxToSym(vardef.Aux)
		zero := vardef.Args[0]
		if zero.Op != OpZero || auxIntToInt64(zero.AuxInt) != n || auxToType(zero.Aux) != t {
			break
		}
		mem := zero.Args[1]
		dst2 := zero.Args[0]
		if !(zero.Uses == 1 && vardef.Uses == 1 && isSamePtr(dst1, dst2) && disjoint(src1, n, dst2, n) && clobber(zero, vardef)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v0 := b.NewValue0(v.Pos, OpVarDef, types.TypeMem)
		v0.Aux = symToAux(x)
		v0.AddArg(mem)
		v.AddArg3(dst1, src1, v0)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Store {t3} op3:(OffPtr <tt3> [0] p3) d2 _)))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && o2 == t3.Size() && n == t2.Size() + t3.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [0] dst) d2 mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		op2 := mem.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		d2 := mem_2.Args[1]
		op3 := mem_2.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		tt3 := op3.Type
		if auxIntToInt64(op3.AuxInt) != 0 {
			break
		}
		p3 := op3.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && o2 == t3.Size() && n == t2.Size()+t3.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(0)
		v2.AddArg(dst)
		v1.AddArg3(v2, d2, mem)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Store {t3} op3:(OffPtr <tt3> [o3] p3) d2 (Store {t4} op4:(OffPtr <tt4> [0] p4) d3 _))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && o3 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size() + t3.Size() + t4.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [0] dst) d3 mem)))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		op2 := mem.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		op3 := mem_2.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		tt3 := op3.Type
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d2 := mem_2.Args[1]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		d3 := mem_2_2.Args[1]
		op4 := mem_2_2.Args[0]
		if op4.Op != OpOffPtr {
			break
		}
		tt4 := op4.Type
		if auxIntToInt64(op4.AuxInt) != 0 {
			break
		}
		p4 := op4.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && o3 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size()+t3.Size()+t4.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(0)
		v4.AddArg(dst)
		v3.AddArg3(v4, d3, mem)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Store {t3} op3:(OffPtr <tt3> [o3] p3) d2 (Store {t4} op4:(OffPtr <tt4> [o4] p4) d3 (Store {t5} op5:(OffPtr <tt5> [0] p5) d4 _)))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && o4 == t5.Size() && o3-o4 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size() + t3.Size() + t4.Size() + t5.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Store {t5} (OffPtr <tt5> [0] dst) d4 mem))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		op2 := mem.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		op3 := mem_2.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		tt3 := op3.Type
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d2 := mem_2.Args[1]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		_ = mem_2_2.Args[2]
		op4 := mem_2_2.Args[0]
		if op4.Op != OpOffPtr {
			break
		}
		tt4 := op4.Type
		o4 := auxIntToInt64(op4.AuxInt)
		p4 := op4.Args[0]
		d3 := mem_2_2.Args[1]
		mem_2_2_2 := mem_2_2.Args[2]
		if mem_2_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(mem_2_2_2.Aux)
		d4 := mem_2_2_2.Args[1]
		op5 := mem_2_2_2.Args[0]
		if op5.Op != OpOffPtr {
			break
		}
		tt5 := op5.Type
		if auxIntToInt64(op5.AuxInt) != 0 {
			break
		}
		p5 := op5.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && o4 == t5.Size() && o3-o4 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size()+t3.Size()+t4.Size()+t5.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v5.Aux = typeToAux(t5)
		v6 := b.NewValue0(v.Pos, OpOffPtr, tt5)
		v6.AuxInt = int64ToAuxInt(0)
		v6.AddArg(dst)
		v5.AddArg3(v6, d4, mem)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Store {t3} op3:(OffPtr <tt3> [0] p3) d2 _))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && o2 == t3.Size() && n == t2.Size() + t3.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [0] dst) d2 mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		op2 := mem_0.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		d2 := mem_0_2.Args[1]
		op3 := mem_0_2.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		tt3 := op3.Type
		if auxIntToInt64(op3.AuxInt) != 0 {
			break
		}
		p3 := op3.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && o2 == t3.Size() && n == t2.Size()+t3.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(0)
		v2.AddArg(dst)
		v1.AddArg3(v2, d2, mem)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Store {t3} op3:(OffPtr <tt3> [o3] p3) d2 (Store {t4} op4:(OffPtr <tt4> [0] p4) d3 _)))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && o3 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size() + t3.Size() + t4.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [0] dst) d3 mem)))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		op2 := mem_0.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		op3 := mem_0_2.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		tt3 := op3.Type
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		d3 := mem_0_2_2.Args[1]
		op4 := mem_0_2_2.Args[0]
		if op4.Op != OpOffPtr {
			break
		}
		tt4 := op4.Type
		if auxIntToInt64(op4.AuxInt) != 0 {
			break
		}
		p4 := op4.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && o3 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size()+t3.Size()+t4.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(0)
		v4.AddArg(dst)
		v3.AddArg3(v4, d3, mem)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Store {t3} op3:(OffPtr <tt3> [o3] p3) d2 (Store {t4} op4:(OffPtr <tt4> [o4] p4) d3 (Store {t5} op5:(OffPtr <tt5> [0] p5) d4 _))))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && o4 == t5.Size() && o3-o4 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size() + t3.Size() + t4.Size() + t5.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Store {t5} (OffPtr <tt5> [0] dst) d4 mem))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		op2 := mem_0.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		op3 := mem_0_2.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		tt3 := op3.Type
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		_ = mem_0_2_2.Args[2]
		op4 := mem_0_2_2.Args[0]
		if op4.Op != OpOffPtr {
			break
		}
		tt4 := op4.Type
		o4 := auxIntToInt64(op4.AuxInt)
		p4 := op4.Args[0]
		d3 := mem_0_2_2.Args[1]
		mem_0_2_2_2 := mem_0_2_2.Args[2]
		if mem_0_2_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(mem_0_2_2_2.Aux)
		d4 := mem_0_2_2_2.Args[1]
		op5 := mem_0_2_2_2.Args[0]
		if op5.Op != OpOffPtr {
			break
		}
		tt5 := op5.Type
		if auxIntToInt64(op5.AuxInt) != 0 {
			break
		}
		p5 := op5.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && o4 == t5.Size() && o3-o4 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size()+t3.Size()+t4.Size()+t5.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v5.Aux = typeToAux(t5)
		v6 := b.NewValue0(v.Pos, OpOffPtr, tt5)
		v6.AuxInt = int64ToAuxInt(0)
		v6.AddArg(dst)
		v5.AddArg3(v6, d4, mem)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Zero {t3} [n] p3 _)))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && n >= o2 + t2.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Zero {t1} [n] dst mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		op2 := mem.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpZero || auxIntToInt64(mem_2.AuxInt) != n {
			break
		}
		t3 := auxToType(mem_2.Aux)
		p3 := mem_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && n >= o2+t2.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(n)
		v1.Aux = typeToAux(t1)
		v1.AddArg2(dst, mem)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Zero {t4} [n] p4 _))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && n >= o2 + t2.Size() && n >= o3 + t3.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Zero {t1} [n] dst mem)))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		mem_0 := mem.Args[0]
		if mem_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0.Type
		o2 := auxIntToInt64(mem_0.AuxInt)
		p2 := mem_0.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		mem_2_0 := mem_2.Args[0]
		if mem_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_2_0.Type
		o3 := auxIntToInt64(mem_2_0.AuxInt)
		p3 := mem_2_0.Args[0]
		d2 := mem_2.Args[1]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpZero || auxIntToInt64(mem_2_2.AuxInt) != n {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		p4 := mem_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && n >= o2+t2.Size() && n >= o3+t3.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v3.AuxInt = int64ToAuxInt(n)
		v3.Aux = typeToAux(t1)
		v3.AddArg2(dst, mem)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Store {t4} (OffPtr <tt4> [o4] p4) d3 (Zero {t5} [n] p5 _)))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && n >= o2 + t2.Size() && n >= o3 + t3.Size() && n >= o4 + t4.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Zero {t1} [n] dst mem))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		mem_0 := mem.Args[0]
		if mem_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0.Type
		o2 := auxIntToInt64(mem_0.AuxInt)
		p2 := mem_0.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		mem_2_0 := mem_2.Args[0]
		if mem_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_2_0.Type
		o3 := auxIntToInt64(mem_2_0.AuxInt)
		p3 := mem_2_0.Args[0]
		d2 := mem_2.Args[1]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		_ = mem_2_2.Args[2]
		mem_2_2_0 := mem_2_2.Args[0]
		if mem_2_2_0.Op != OpOffPtr {
			break
		}
		tt4 := mem_2_2_0.Type
		o4 := auxIntToInt64(mem_2_2_0.AuxInt)
		p4 := mem_2_2_0.Args[0]
		d3 := mem_2_2.Args[1]
		mem_2_2_2 := mem_2_2.Args[2]
		if mem_2_2_2.Op != OpZero || auxIntToInt64(mem_2_2_2.AuxInt) != n {
			break
		}
		t5 := auxToType(mem_2_2_2.Aux)
		p5 := mem_2_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && n >= o2+t2.Size() && n >= o3+t3.Size() && n >= o4+t4.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v5.AuxInt = int64ToAuxInt(n)
		v5.Aux = typeToAux(t1)
		v5.AddArg2(dst, mem)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Store {t4} (OffPtr <tt4> [o4] p4) d3 (Store {t5} (OffPtr <tt5> [o5] p5) d4 (Zero {t6} [n] p6 _))))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && isSamePtr(p5, p6) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && t6.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && n >= o2 + t2.Size() && n >= o3 + t3.Size() && n >= o4 + t4.Size() && n >= o5 + t5.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Store {t5} (OffPtr <tt5> [o5] dst) d4 (Zero {t1} [n] dst mem)))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		mem_0 := mem.Args[0]
		if mem_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0.Type
		o2 := auxIntToInt64(mem_0.AuxInt)
		p2 := mem_0.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		mem_2_0 := mem_2.Args[0]
		if mem_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_2_0.Type
		o3 := auxIntToInt64(mem_2_0.AuxInt)
		p3 := mem_2_0.Args[0]
		d2 := mem_2.Args[1]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		_ = mem_2_2.Args[2]
		mem_2_2_0 := mem_2_2.Args[0]
		if mem_2_2_0.Op != OpOffPtr {
			break
		}
		tt4 := mem_2_2_0.Type
		o4 := auxIntToInt64(mem_2_2_0.AuxInt)
		p4 := mem_2_2_0.Args[0]
		d3 := mem_2_2.Args[1]
		mem_2_2_2 := mem_2_2.Args[2]
		if mem_2_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(mem_2_2_2.Aux)
		_ = mem_2_2_2.Args[2]
		mem_2_2_2_0 := mem_2_2_2.Args[0]
		if mem_2_2_2_0.Op != OpOffPtr {
			break
		}
		tt5 := mem_2_2_2_0.Type
		o5 := auxIntToInt64(mem_2_2_2_0.AuxInt)
		p5 := mem_2_2_2_0.Args[0]
		d4 := mem_2_2_2.Args[1]
		mem_2_2_2_2 := mem_2_2_2.Args[2]
		if mem_2_2_2_2.Op != OpZero || auxIntToInt64(mem_2_2_2_2.AuxInt) != n {
			break
		}
		t6 := auxToType(mem_2_2_2_2.Aux)
		p6 := mem_2_2_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && isSamePtr(p5, p6) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && t6.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && n >= o2+t2.Size() && n >= o3+t3.Size() && n >= o4+t4.Size() && n >= o5+t5.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v5.Aux = typeToAux(t5)
		v6 := b.NewValue0(v.Pos, OpOffPtr, tt5)
		v6.AuxInt = int64ToAuxInt(o5)
		v6.AddArg(dst)
		v7 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v7.AuxInt = int64ToAuxInt(n)
		v7.Aux = typeToAux(t1)
		v7.AddArg2(dst, mem)
		v5.AddArg3(v6, d4, v7)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Zero {t3} [n] p3 _))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && n >= o2 + t2.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Zero {t1} [n] dst mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		op2 := mem_0.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpZero || auxIntToInt64(mem_0_2.AuxInt) != n {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		p3 := mem_0_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && n >= o2+t2.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(n)
		v1.Aux = typeToAux(t1)
		v1.AddArg2(dst, mem)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Zero {t4} [n] p4 _)))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && n >= o2 + t2.Size() && n >= o3 + t3.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Zero {t1} [n] dst mem)))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		mem_0_0 := mem_0.Args[0]
		if mem_0_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0_0.Type
		o2 := auxIntToInt64(mem_0_0.AuxInt)
		p2 := mem_0_0.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		mem_0_2_0 := mem_0_2.Args[0]
		if mem_0_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_0_2_0.Type
		o3 := auxIntToInt64(mem_0_2_0.AuxInt)
		p3 := mem_0_2_0.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpZero || auxIntToInt64(mem_0_2_2.AuxInt) != n {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		p4 := mem_0_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && n >= o2+t2.Size() && n >= o3+t3.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v3.AuxInt = int64ToAuxInt(n)
		v3.Aux = typeToAux(t1)
		v3.AddArg2(dst, mem)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Store {t4} (OffPtr <tt4> [o4] p4) d3 (Zero {t5} [n] p5 _))))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && n >= o2 + t2.Size() && n >= o3 + t3.Size() && n >= o4 + t4.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Zero {t1} [n] dst mem))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		mem_0_0 := mem_0.Args[0]
		if mem_0_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0_0.Type
		o2 := auxIntToInt64(mem_0_0.AuxInt)
		p2 := mem_0_0.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		mem_0_2_0 := mem_0_2.Args[0]
		if mem_0_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_0_2_0.Type
		o3 := auxIntToInt64(mem_0_2_0.AuxInt)
		p3 := mem_0_2_0.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		_ = mem_0_2_2.Args[2]
		mem_0_2_2_0 := mem_0_2_2.Args[0]
		if mem_0_2_2_0.Op != OpOffPtr {
			break
		}
		tt4 := mem_0_2_2_0.Type
		o4 := auxIntToInt64(mem_0_2_2_0.AuxInt)
		p4 := mem_0_2_2_0.Args[0]
		d3 := mem_0_2_2.Args[1]
		mem_0_2_2_2 := mem_0_2_2.Args[2]
		if mem_0_2_2_2.Op != OpZero || auxIntToInt64(mem_0_2_2_2.AuxInt) != n {
			break
		}
		t5 := auxToType(mem_0_2_2_2.Aux)
		p5 := mem_0_2_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && n >= o2+t2.Size() && n >= o3+t3.Size() && n >= o4+t4.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v5.AuxInt = int64ToAuxInt(n)
		v5.Aux = typeToAux(t1)
		v5.AddArg2(dst, mem)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Store {t4} (OffPtr <tt4> [o4] p4) d3 (Store {t5} (OffPtr <tt5> [o5] p5) d4 (Zero {t6} [n] p6 _)))))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && isSamePtr(p5, p6) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && t6.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && n >= o2 + t2.Size() && n >= o3 + t3.Size() && n >= o4 + t4.Size() && n >= o5 + t5.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Store {t5} (OffPtr <tt5> [o5] dst) d4 (Zero {t1} [n] dst mem)))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		mem_0_0 := mem_0.Args[0]
		if mem_0_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0_0.Type
		o2 := auxIntToInt64(mem_0_0.AuxInt)
		p2 := mem_0_0.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		mem_0_2_0 := mem_0_2.Args[0]
		if mem_0_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_0_2_0.Type
		o3 := auxIntToInt64(mem_0_2_0.AuxInt)
		p3 := mem_0_2_0.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		_ = mem_0_2_2.Args[2]
		mem_0_2_2_0 := mem_0_2_2.Args[0]
		if mem_0_2_2_0.Op != OpOffPtr {
			break
		}
		tt4 := mem_0_2_2_0.Type
		o4 := auxIntToInt64(mem_0_2_2_0.AuxInt)
		p4 := mem_0_2_2_0.Args[0]
		d3 := mem_0_2_2.Args[1]
		mem_0_2_2_2 := mem_0_2_2.Args[2]
		if mem_0_2_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(mem_0_2_2_2.Aux)
		_ = mem_0_2_2_2.Args[2]
		mem_0_2_2_2_0 := mem_0_2_2_2.Args[0]
		if mem_0_2_2_2_0.Op != OpOffPtr {
			break
		}
		tt5 := mem_0_2_2_2_0.Type
		o5 := auxIntToInt64(mem_0_2_2_2_0.AuxInt)
		p5 := mem_0_2_2_2_0.Args[0]
		d4 := mem_0_2_2_2.Args[1]
		mem_0_2_2_2_2 := mem_0_2_2_2.Args[2]
		if mem_0_2_2_2_2.Op != OpZero || auxIntToInt64(mem_0_2_2_2_2.AuxInt) != n {
			break
		}
		t6 := auxToType(mem_0_2_2_2_2.Aux)
		p6 := mem_0_2_2_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && isSamePtr(p5, p6) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && t6.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && n >= o2+t2.Size() && n >= o3+t3.Size() && n >= o4+t4.Size() && n >= o5+t5.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v5.Aux = typeToAux(t5)
		v6 := b.NewValue0(v.Pos, OpOffPtr, tt5)
		v6.AuxInt = int64ToAuxInt(o5)
		v6.AddArg(dst)
		v7 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v7.AuxInt = int64ToAuxInt(n)
		v7.Aux = typeToAux(t1)
		v7.AddArg2(dst, mem)
		v5.AddArg3(v6, d4, v7)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [s] dst tmp1 midmem:(Move {t2} [s] tmp2 src _))
	// cond: t1.Compare(t2) == types.CMPeq && isSamePtr(tmp1, tmp2) && isStackPtr(src) && !isVolatile(src) && disjoint(src, s, tmp2, s) && (disjoint(src, s, dst, s) || isInlinableMemmove(dst, src, s, config))
	// result: (Move {t1} [s] dst src midmem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		tmp1 := v_1
		midmem := v_2
		if midmem.Op != OpMove || auxIntToInt64(midmem.AuxInt) != s {
			break
		}
		t2 := auxToType(midmem.Aux)
		src := midmem.Args[1]
		tmp2 := midmem.Args[0]
		if !(t1.Compare(t2) == types.CMPeq && isSamePtr(tmp1, tmp2) && isStackPtr(src) && !isVolatile(src) && disjoint(src, s, tmp2, s) && (disjoint(src, s, dst, s) || isInlinableMemmove(dst, src, s, config))) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(s)
		v.Aux = typeToAux(t1)
		v.AddArg3(dst, src, midmem)
		return true
	}
	// match: (Move {t1} [s] dst tmp1 midmem:(VarDef (Move {t2} [s] tmp2 src _)))
	// cond: t1.Compare(t2) == types.CMPeq && isSamePtr(tmp1, tmp2) && isStackPtr(src) && !isVolatile(src) && disjoint(src, s, tmp2, s) && (disjoint(src, s, dst, s) || isInlinableMemmove(dst, src, s, config))
	// result: (Move {t1} [s] dst src midmem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		tmp1 := v_1
		midmem := v_2
		if midmem.Op != OpVarDef {
			break
		}
		midmem_0 := midmem.Args[0]
		if midmem_0.Op != OpMove || auxIntToInt64(midmem_0.AuxInt) != s {
			break
		}
		t2 := auxToType(midmem_0.Aux)
		src := midmem_0.Args[1]
		tmp2 := midmem_0.Args[0]
		if !(t1.Compare(t2) == types.CMPeq && isSamePtr(tmp1, tmp2) && isStackPtr(src) && !isVolatile(src) && disjoint(src, s, tmp2, s) && (disjoint(src, s, dst, s) || isInlinableMemmove(dst, src, s, config))) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(s)
		v.Aux = typeToAux(t1)
		v.AddArg3(dst, src, midmem)
		return true
	}
	// match: (Move dst src mem)
	// cond: isSamePtr(dst, src)
	// result: mem
	for {
		dst := v_0
		src := v_1
		mem := v_2
		if !(isSamePtr(dst, src)) {
			break
		}
		v.copyOf(mem)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMul16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul16 (Const16 [c]) (Const16 [d]))
	// result: (Const16 [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1.AuxInt)
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul16 (Const16 [1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul16 (Const16 [-1]) x)
	// result: (Neg16 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpNeg16)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul16 <t> n (Const16 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Lsh16x64 <t> n (Const64 <typ.UInt64> [log16(c)]))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpLsh16x64)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v0.AuxInt = int64ToAuxInt(log16(c))
			v.AddArg2(n, v0)
			return true
		}
		break
	}
	// match: (Mul16 <t> n (Const16 [c]))
	// cond: t.IsSigned() && isPowerOfTwo(-c)
	// result: (Neg16 (Lsh16x64 <t> n (Const64 <typ.UInt64> [log16(-c)])))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1.AuxInt)
			if !(t.IsSigned() && isPowerOfTwo(-c)) {
				continue
			}
			v.reset(OpNeg16)
			v0 := b.NewValue0(v.Pos, OpL
"""




```