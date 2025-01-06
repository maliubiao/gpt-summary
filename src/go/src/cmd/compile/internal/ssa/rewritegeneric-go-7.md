Response:

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第8部分，共13部分，请归纳一下它的功能

"""
sh16x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v1.AuxInt = int64ToAuxInt(log16(-c))
			v0.AddArg2(n, v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Mul16 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Mul16 (Mul16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Mul16 i (Mul16 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul16 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst16 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst16 && x.Op != OpConst16) {
					continue
				}
				v.reset(OpMul16)
				v0 := b.NewValue0(v.Pos, OpMul16, t)
				v0.AddArg2(x, z)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Mul16 (Const16 <t> [c]) (Mul16 (Const16 <t> [d]) x))
	// result: (Mul16 (Const16 <t> [c*d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpMul16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst16 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt16(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpMul16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c * d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul32 (Const32 [c]) (Const32 [d]))
	// result: (Const32 [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul32 (Const32 [1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul32 (Const32 [-1]) x)
	// result: (Neg32 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpNeg32)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul32 <t> n (Const32 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Lsh32x64 <t> n (Const64 <typ.UInt64> [log32(c)]))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpLsh32x64)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v0.AuxInt = int64ToAuxInt(log32(c))
			v.AddArg2(n, v0)
			return true
		}
		break
	}
	// match: (Mul32 <t> n (Const32 [c]))
	// cond: t.IsSigned() && isPowerOfTwo(-c)
	// result: (Neg32 (Lsh32x64 <t> n (Const64 <typ.UInt64> [log32(-c)])))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(t.IsSigned() && isPowerOfTwo(-c)) {
				continue
			}
			v.reset(OpNeg32)
			v0 := b.NewValue0(v.Pos, OpLsh32x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v1.AuxInt = int64ToAuxInt(log32(-c))
			v0.AddArg2(n, v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Mul32 (Const32 <t> [c]) (Add32 <t> (Const32 <t> [d]) x))
	// result: (Add32 (Const32 <t> [c*d]) (Mul32 <t> (Const32 <t> [c]) x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpAdd32 || v_1.Type != t {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt32(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpAdd32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c * d)
				v1 := b.NewValue0(v.Pos, OpMul32, t)
				v2 := b.NewValue0(v.Pos, OpConst32, t)
				v2.AuxInt = int32ToAuxInt(c)
				v1.AddArg2(v2, x)
				v.AddArg2(v0, v1)
				return true
			}
		}
		break
	}
	// match: (Mul32 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Mul32 (Mul32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Mul32 i (Mul32 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul32 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst32 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst32 && x.Op != OpConst32) {
					continue
				}
				v.reset(OpMul32)
				v0 := b.NewValue0(v.Pos, OpMul32, t)
				v0.AddArg2(x, z)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Mul32 (Const32 <t> [c]) (Mul32 (Const32 <t> [d]) x))
	// result: (Mul32 (Const32 <t> [c*d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt32(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpMul32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c * d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mul32F (Const32F [c]) (Const32F [d]))
	// cond: c*d == c*d
	// result: (Const32F [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32F {
				continue
			}
			c := auxIntToFloat32(v_0.AuxInt)
			if v_1.Op != OpConst32F {
				continue
			}
			d := auxIntToFloat32(v_1.AuxInt)
			if !(c*d == c*d) {
				continue
			}
			v.reset(OpConst32F)
			v.AuxInt = float32ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul32F x (Const32F [1]))
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst32F || auxIntToFloat32(v_1.AuxInt) != 1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul32F x (Const32F [-1]))
	// result: (Neg32F x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst32F || auxIntToFloat32(v_1.AuxInt) != -1 {
				continue
			}
			v.reset(OpNeg32F)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul32F x (Const32F [2]))
	// result: (Add32F x x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst32F || auxIntToFloat32(v_1.AuxInt) != 2 {
				continue
			}
			v.reset(OpAdd32F)
			v.AddArg2(x, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul64 (Const64 [1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul64 (Const64 [-1]) x)
	// result: (Neg64 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpNeg64)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul64 <t> n (Const64 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Lsh64x64 <t> n (Const64 <typ.UInt64> [log64(c)]))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpLsh64x64)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v0.AuxInt = int64ToAuxInt(log64(c))
			v.AddArg2(n, v0)
			return true
		}
		break
	}
	// match: (Mul64 <t> n (Const64 [c]))
	// cond: t.IsSigned() && isPowerOfTwo(-c)
	// result: (Neg64 (Lsh64x64 <t> n (Const64 <typ.UInt64> [log64(-c)])))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(t.IsSigned() && isPowerOfTwo(-c)) {
				continue
			}
			v.reset(OpNeg64)
			v0 := b.NewValue0(v.Pos, OpLsh64x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v1.AuxInt = int64ToAuxInt(log64(-c))
			v0.AddArg2(n, v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Mul64 (Const64 <t> [c]) (Add64 <t> (Const64 <t> [d]) x))
	// result: (Add64 (Const64 <t> [c*d]) (Mul64 <t> (Const64 <t> [c]) x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpAdd64 || v_1.Type != t {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt64(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpAdd64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c * d)
				v1 := b.NewValue0(v.Pos, OpMul64, t)
				v2 := b.NewValue0(v.Pos, OpConst64, t)
				v2.AuxInt = int64ToAuxInt(c)
				v1.AddArg2(v2, x)
				v.AddArg2(v0, v1)
				return true
			}
		}
		break
	}
	// match: (Mul64 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Mul64 (Mul64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Mul64 i (Mul64 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul64 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst64 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst64 && x.Op != OpConst64) {
					continue
				}
				v.reset(OpMul64)
				v0 := b.NewValue0(v.Pos, OpMul64, t)
				v0.AddArg2(x, z)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Mul64 (Const64 <t> [c]) (Mul64 (Const64 <t> [d]) x))
	// result: (Mul64 (Const64 <t> [c*d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpMul64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt64(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpMul64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c * d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mul64F (Const64F [c]) (Const64F [d]))
	// cond: c*d == c*d
	// result: (Const64F [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64F {
				continue
			}
			c := auxIntToFloat64(v_0.AuxInt)
			if v_1.Op != OpConst64F {
				continue
			}
			d := auxIntToFloat64(v_1.AuxInt)
			if !(c*d == c*d) {
				continue
			}
			v.reset(OpConst64F)
			v.AuxInt = float64ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul64F x (Const64F [1]))
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst64F || auxIntToFloat64(v_1.AuxInt) != 1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul64F x (Const64F [-1]))
	// result: (Neg64F x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst64F || auxIntToFloat64(v_1.AuxInt) != -1 {
				continue
			}
			v.reset(OpNeg64F)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul64F x (Const64F [2]))
	// result: (Add64F x x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst64F || auxIntToFloat64(v_1.AuxInt) != 2 {
				continue
			}
			v.reset(OpAdd64F)
			v.AddArg2(x, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1.AuxInt)
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul8 (Const8 [1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul8 (Const8 [-1]) x)
	// result: (Neg8 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpNeg8)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul8 <t> n (Const8 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Lsh8x64 <t> n (Const64 <typ.UInt64> [log8(c)]))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpLsh8x64)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v0.AuxInt = int64ToAuxInt(log8(c))
			v.AddArg2(n, v0)
			return true
		}
		break
	}
	// match: (Mul8 <t> n (Const8 [c]))
	// cond: t.IsSigned() && isPowerOfTwo(-c)
	// result: (Neg8 (Lsh8x64 <t> n (Const64 <typ.UInt64> [log8(-c)])))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1.AuxInt)
			if !(t.IsSigned() && isPowerOfTwo(-c)) {
				continue
			}
			v.reset(OpNeg8)
			v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v1.AuxInt = int64ToAuxInt(log8(-c))
			v0.AddArg2(n, v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Mul8 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Mul8 (Mul8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Mul8 i (Mul8 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul8 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst8 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst8 && x.Op != OpConst8) {
					continue
				}
				v.reset(OpMul8)
				v0 := b.NewValue0(v.Pos, OpMul8, t)
				v0.AddArg2(x, z)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Mul8 (Const8 <t> [c]) (Mul8 (Const8 <t> [d]) x))
	// result: (Mul8 (Const8 <t> [c*d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpMul8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst8 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt8(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpMul8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c * d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeg16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neg16 (Const16 [c]))
	// result: (Const16 [-c])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(-c)
		return true
	}
	// match: (Neg16 (Sub16 x y))
	// result: (Sub16 y x)
	for {
		if v_0.Op != OpSub16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSub16)
		v.AddArg2(y, x)
		return true
	}
	// match: (Neg16 (Neg16 x))
	// result: x
	for {
		if v_0.Op != OpNeg16 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Neg16 <t> (Com16 x))
	// result: (Add16 (Const16 <t> [1]) x)
	for {
		t := v.Type
		if v_0.Op != OpCom16 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAdd16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neg32 (Const32 [c]))
	// result: (Const32 [-c])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(-c)
		return true
	}
	// match: (Neg32 (Sub32 x y))
	// result: (Sub32 y x)
	for {
		if v_0.Op != OpSub32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSub32)
		v.AddArg2(y, x)
		return true
	}
	// match: (Neg32 (Neg32 x))
	// result: x
	for {
		if v_0.Op != OpNeg32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Neg32 <t> (Com32 x))
	// result: (Add32 (Const32 <t> [1]) x)
	for {
		t := v.Type
		if v_0.Op != OpCom32 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAdd32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg32F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg32F (Const32F [c]))
	// cond: c != 0
	// result: (Const32F [-c])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		if !(c != 0) {
			break
		}
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(-c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neg64 (Const64 [c]))
	// result: (Const64 [-c])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(-c)
		return true
	}
	// match: (Neg64 (Sub64 x y))
	// result: (Sub64 y x)
	for {
		if v_0.Op != OpSub64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSub64)
		v.AddArg2(y, x)
		return true
	}
	// match: (Neg64 (Neg64 x))
	// result: x
	for {
		if v_0.Op != OpNeg64 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Neg64 <t> (Com64 x))
	// result: (Add64 (Const64 <t> [1]) x)
	for {
		t := v.Type
		if v_0.Op != OpCom64 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAdd64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg64F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg64F (Const64F [c]))
	// cond: c != 0
	// result: (Const64F [-c])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		if !(c != 0) {
			break
		}
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(-c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neg8 (Const8 [c]))
	// result: (Const8 [-c])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(-c)
		return true
	}
	// match: (Neg8 (Sub8 x y))
	// result: (Sub8 y x)
	for {
		if v_0.Op != OpSub8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSub8)
		v.AddArg2(y, x)
		return true
	}
	// match: (Neg8 (Neg8 x))
	// result: x
	for {
		if v_0.Op != OpNeg8 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Neg8 <t> (Com8 x))
	// result: (Add8 (Const8 <t> [1]) x)
	for {
		t := v.Type
		if v_0.Op != OpCom8 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAdd8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Neq16 (Const16 <t> [c]) (Add16 (Const16 <t> [d]) x))
	// result: (Neq16 (Const16 <t> [c-d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpAdd16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst16 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt16(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpNeq16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Neq16 (Const16 [c]) (Const16 [d]))
	// result: (ConstBool [c != d])
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
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (Neq16 n (Lsh16x64 (Rsh16x64 (Add16 <t> n (Rsh16Ux64 <t> (Rsh16x64 <t> n (Const64 <typ.UInt64> [15])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 15 && kbar == 16 - k
	// result: (Neq16 (And16 <t> n (Const16 <t> [1<<uint(k)-1])) (Const16 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpLsh16x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpRsh16x64 {
				continue
			}
			_ = v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAdd16 {
				continue
			}
			t := v_1_0_0.Type
			_ = v_1_0_0.Args[1]
			v_1_0_0_0 := v_1_0_0.Args[0]
			v_1_0_0_1 := v_1_0_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0_0_0, v_1_0_0_1 = _i1+1, v_1_0_0_1, v_1_0_0_0 {
				if n != v_1_0_0_0 || v_1_0_0_1.Op != OpRsh16Ux64 || v_1_0_0_1.Type != t {
					continue
				}
				_ = v_1_0_0_1.Args[1]
				v_1_0_0_1_0 := v_1_0_0_1.Args[0]
				if v_1_0_0_1_0.Op != OpRsh16x64 || v_1_0_0_1_0.Type != t {
					continue
				}
				_ = v_1_0_0_1_0.Args[1]
				if n != v_1_0_0_1_0.Args[0] {
					continue
				}
				v_1_0_0_1_0_1 := v_1_0_0_1_0.Args[1]
				if v_1_0_0_1_0_1.Op != OpConst64 || v_1_0_0_1_0_1.Type != typ.UInt64 || auxIntToInt64(v_1_0_0_1_0_1.AuxInt) != 15 {
					continue
				}
				v_1_0_0_1_1 := v_1_0_0_1.Args[1]
				if v_1_0_0_1_1.Op != OpConst64 || v_1_0_0_1_1.Type != typ.UInt64 {
					continue
				}
				kbar := auxIntToInt64(v_1_0_0_1_1.AuxInt)
				v_1_0_1 := v_1_0.Args[1]
				if v_1_0_1.Op != OpConst64 || v_1_0_1.Type != typ.UInt64 {
					continue
				}
				k := auxIntToInt64(v_1_0_1.AuxInt)
				v_1_1 := v_1.Args[1]
				if v_1_1.Op != OpConst64 || v_1_1.Type != typ.UInt64 || auxIntToInt64(v_1_1.AuxInt) != k || !(k > 0 && k < 15 && kbar == 16-k) {
					continue
				}
				v.reset(OpNeq16)
				v0 := b.NewValue0(v.Pos, OpAnd16, t)
				v1 := b.NewValue0(v.Pos, OpConst16, t)
				v1.AuxInt = int16ToAuxInt(1<<uint(k) - 1)
				v0.AddArg2(n, v1)
				v2 := b.NewValue0(v.Pos, OpConst16, t)
				v2.AuxInt = int16ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	// match: (Neq16 s:(Sub16 x y) (Const16 [0]))
	// cond: s.Uses == 1
	// result: (Neq16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			s := v_0
			if s.Op != OpSub16 {
				continue
			}
			y := s.Args[1]
			x := s.Args[0]
			if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != 0 || !(s.Uses == 1) {
				continue
			}
			v.reset(OpNeq16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Neq16 (And16 <t> x (Const16 <t> [y])) (Const16 <t> [y]))
	// cond: oneBit16(y)
	// result: (Eq16 (And16 <t> x (Const16 <t> [y])) (Const16 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd16 {
				continue
			}
			t := v_0.Type
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst16 || v_0_1.Type != t {
					continue
				}
				y := auxIntToInt16(v_0_1.AuxInt)
				if v_1.Op != OpConst16 || v_1.Type != t || auxIntToInt16(v_1.AuxInt) != y || !(oneBit16(y)) {
					continue
				}
				v.reset(OpEq16)
				v0 := b.NewValue0(v.Pos, OpAnd16, t)
				v1 := b.NewValue0(v.Pos, OpConst16, t)
				v1.AuxInt = int16ToAuxInt(y)
				v0.AddArg2(x, v1)
				v2 := b.NewValue0(v.Pos, OpConst16, t)
				v2.AuxInt = int16ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32 x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Neq32 (Const32 <t> [c]) (Add32 (Const32 <t> [d]) x))
	// result: (Neq32 (Const32 <t> [c-d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpAdd32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt32(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpNeq32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Neq32 (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (Neq32 n (Lsh32x64 (Rsh32x64 (Add32 <t> n (Rsh32Ux64 <t> (Rsh32x64 <t> n (Const64 <typ.UInt64> [31])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 31 && kbar == 32 - k
	// result: (Neq32 (And32 <t> n (Const32 <t> [1<<uint(k)-1])) (Const32 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpLsh32x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpRsh32x64 {
				continue
			}
			_ = v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAdd32 {
				continue
			}
			t := v_1_0_0.Type
			_ = v_1_0_0.Args[1]
			v_1_0_0_0 := v_1_0_0.Args[0]
			v_1_0_0_1 := v_1_0_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0_0_0, v_1_0_0_1 = _i1+1, v_1_0_0_1, v_1_0_0_0 {
				if n != v_1_0_0_0 || v_1_0_0_1.Op != OpRsh32Ux64 || v_1_0_0_1.Type != t {
					continue
				}
				_ = v_1_0_0_1.Args[1]
				v_1_0_0_1_0 := v_1_0_0_1.Args[0]
				if v_1_0_0_1_0.Op != OpRsh32x64 || v_1_0_0_1_0.Type != t {
					continue
				}
				_ = v_1_0_0_1_0.Args[1]
				if n != v_1_0_0_1_0.Args[0] {
					continue
				}
				v_1_0_0_1_0_1 := v_1_0_0_1_0.Args[1]
				if v_1_0_0_1_0_1.Op != OpConst64 || v_1_0_0_1_0_1.Type != typ.UInt64 || auxIntToInt64(v_1_0_0_1_0_1.AuxInt) != 31 {
					continue
				}
				v_1_0_0_1_1 := v_1_0_0_1.Args[1]
				if v_1_0_0_1_1.Op != OpConst64 || v_1_0_0_1_1.Type != typ.UInt64 {
					continue
				}
				kbar := auxIntToInt64(v_1_0_0_1_1.AuxInt)
				v_1_0_1 := v_1_0.Args[1]
				if v_1_0_1.Op != OpConst64 || v_1_0_1.Type != typ.UInt64 {
					continue
				}
				k := auxIntToInt64(v_1_0_1.AuxInt)
				v_1_1 := v_1.Args[1]
				if v_1_1.Op != OpConst64 || v_1_1.Type != typ.UInt64 || auxIntToInt64(v_1_1.AuxInt) != k || !(k > 0 && k < 31 && kbar == 32-k) {
					continue
				}
				v.reset(OpNeq32)
				v0 := b.NewValue0(v.Pos, OpAnd32, t)
				v1 := b.NewValue0(v.Pos, OpConst32, t)
				v1.AuxInt = int32ToAuxInt(1<<uint(k) - 1)
				v0.AddArg2(n, v1)
				v2 := b.NewValue0(v.Pos, OpConst32, t)
				v2.AuxInt = int32ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	// match: (Neq32 s:(Sub32 x y) (Const32 [0]))
	// cond: s.Uses == 1
	// result: (Neq32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			s := v_0
			if s.Op != OpSub32 {
				continue
			}
			y := s.Args[1]
			x := s.Args[0]
			if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != 0 || !(s.Uses == 1) {
				continue
			}
			v.reset(OpNeq32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Neq32 (And32 <t> x (Const32 <t> [y])) (Const32 <t> [y]))
	// cond: oneBit32(y)
	// result: (Eq32 (And32 <t> x (Const32 <t> [y])) (Const32 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd32 {
				continue
			}
			t := v_0.Type
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst32 || v_0_1.Type != t {
					continue
				}
				y := auxIntToInt32(v_0_1.AuxInt)
				if v_1.Op != OpConst32 || v_1.Type != t || auxIntToInt32(v_1.AuxInt) != y || !(oneBit32(y)) {
					continue
				}
				v.reset(OpEq32)
				v0 := b.NewValue0(v.Pos, OpAnd32, t)
				v1 := b.NewValue0(v.Pos, OpConst32, t)
				v1.AuxInt = int32ToAuxInt(y)
				v0.AddArg2(x, v1)
				v2 := b.NewValue0(v.Pos, OpConst32, t)
				v2.AuxInt = int32ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Neq32F (Const32F [c]) (Const32F [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32F {
				continue
			}
			c := auxIntToFloat32(v_0.AuxInt)
			if v_1.Op != OpConst32F {
				continue
			}
			d := auxIntToFloat32(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq64 x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Neq64 (Const64 <t> [c]) (Add64 (Const64 <t> [d]) x))
	// result: (Neq64 (Const64 <t> [c-d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpAdd64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt64(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpNeq64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Neq64 (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (Neq64 n (Lsh64x64 (Rsh64x64 (Add64 <t> n (Rsh64Ux64 <t> (Rsh64x64 <t> n (Const64 <typ.UInt64> [63])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 63 && kbar == 64 - k
	// result: (Neq64 (And64 <t> n (Const64 <t> [1<<uint(k)-1])) (Const64 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpLsh64x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpRsh64x64 {
				continue
			}
			_ = v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAdd64 {
				continue
			}
			t := v_1_0_0.Type
			_ = v_1_0_0.Args[1]
			v_1_0_0_0 := v_1_0_0.Args[0]
			v_1_0_0_1 := v_1_0_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0_0_0, v_1_0_0_1 = _i1+1, v_1_0_0_1, v_1_0_0_0 {
				if n != v_1_0_0_0 || v_1_0_0_1.Op != OpRsh64Ux64 || v_1_0_0_1.Type != t {
					continue
				}
				_ = v_1_0_0_1.Args[1]
				v_1_0_0_1_0 := v_1_0_0_1.Args[0]
				if v_1_0_0_1_0.Op != OpRsh64x64 || v_1_0_0_1_0.Type != t {
					continue
				}
				_ = v_1_0_0_1_0.Args[1]
				if n != v_1_0_0_1_0.Args[0] {
					continue
				}
				v_1_0_0_1_0_1 := v_1_0_0_1_0.Args[1]
				if v_1_0_0_1_0_1.Op != OpConst64 || v_1_0_0_1_0_1.Type != typ.UInt64 || auxIntToInt64(v_1_0_0_1_0_1.AuxInt) != 63 {
					continue
				}
				v_1_0_0_1_1 := v_1_0_0_1.Args[1]
				if v_1_0_0_1_1.Op != OpConst64 || v_1_0_0_1_1.Type != typ.UInt64 {
					continue
				}
				kbar := auxIntToInt64(v_1_0_0_1_1.AuxInt)
				v_1_0_1 := v_1_0.Args[1]
				if v_1_0_1.Op != OpConst64 || v_1_0_1.Type != typ.UInt64 {
					continue
				}
				k := auxIntToInt64(v_1_0_1.AuxInt)
				v_1_1 := v_1.Args[1]
				if v_1_1.Op != OpConst64 || v_1_1.Type != typ.UInt64 || auxIntToInt64(v_1_1.AuxInt) != k || !(k > 0 && k < 63 && kbar == 64-k) {
					continue
				}
				v.reset(OpNeq64)
				v0 := b.NewValue0(v.Pos, OpAnd64, t)
				v1 := b.NewValue0(v.Pos, OpConst64, t)
				v1.AuxInt = int64ToAuxInt(1<<uint(k) - 1)
				v0.AddArg2(n, v1)
				v2 := b.NewValue0(v.Pos, OpConst64, t)
				v2.AuxInt = int64ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	// match: (Neq64 s:(Sub64 x y) (Const64 [0]))
	// cond: s.Uses == 1
	// result: (Neq64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			s := v_0
			if s.Op != OpSub64 {
				continue
			}
			y := s.Args[1]
			x := s.Args[0]
			if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 || !(s.Uses == 1) {
				continue
			}
			v.reset(OpNeq64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Neq64 (And64 <t> x (Const64 <t> [y])) (Const64 <t> [y]))
	// cond: oneBit64(y)
	// result: (Eq64 (And64 <t> x (Const64 <t> [y])) (Const64 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd64 {
				continue
			}
			t := v_0.Type
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst64 || v_0_1.Type != t {
					continue
				}
				y := auxIntToInt64(v_0_1.AuxInt)
				if v_1.Op != OpConst64 || v_1.Type != t || auxIntToInt64(v_1.AuxInt) != y || !(oneBit64(y)) {
					continue
				}
				v.reset(OpEq64)
				v0 := b.NewValue0(v.Pos, OpAnd64, t)
				v1 := b.NewValue0(v.Pos, OpConst64, t)
				v1.AuxInt = int64ToAuxInt(y)
				v0.AddArg2(x, v1)
				v2 := b.NewValue0(v.Pos, OpConst64, t)
				v2.AuxInt = int64ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Neq64F (Const64F [c]) (Const64F [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64F {
				continue
			}
			c := auxIntToFloat64(v_0.AuxInt)
			if v_1.Op != OpConst64F {
				continue
			}
			d := auxIntToFloat64(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Neq8 (Const8 <t> [c]) (Add8 (Const8 <t> [d]) x))
	// result: (Neq8 (Const8 <t> [c-d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpAdd8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst8 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt8(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpNeq8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Neq8 (Const8 [c]) (Const8 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (Neq8 n (Lsh8x64 (Rsh8x64 (Add8 <t> n (Rsh8Ux64 <t> (Rsh8x64 <t> n (Const64 <typ.UInt64> [ 7])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 7 && kbar == 8 - k
	// result: (Neq8 (And8 <t> n (Const8 <t> [1<<uint(k)-1])) (Const8 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpLsh8x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpRsh8x64 {
				continue
			}
			_ = v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAdd8 {
				continue
			}
			t := v_1_0_0.Type
			_ = v_1_0_0.Args[1]
			v_1_0_0_0 := v_1_0_0.Args[0]
			v_1_0_0_1 := v_1_0_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0_0_0, v_1_0_0_1 = _i1+1, v_1_0_0_1, v_1_0_0_0 {
				if n != v_1_0_0_0 || v_1_0_0_1.Op != OpRsh8Ux64 || v_1_0_0_1.Type != t {
					continue
				}
				_ = v_1_0_0_1.Args[1]
				v_1_0_0_1_0 := v_1_0_0_1.Args[0]
				if v_1_0_0_1_0.Op != OpRsh8x64 || v_1_0_0_1_0.Type != t {
					continue
				}
				_ = v_1_0_0_1_0.Args[1]
				if n != v_1_0_0_1_0.Args[0] {
					continue
				}
				v_1_0_0_1_0_1 := v_1_0_0_1_0.Args[1]
				if v_1_0_0_1_0_1.Op != OpConst64 || v_1_0_0_1_0_1.Type != typ.UInt64 || auxIntToInt64(v_1_0_0_1_0_1.AuxInt) != 7 {
					continue
				}
				v_1_0_0_1_1 := v_1_0_0_1.Args[1]
				if v_1_0_0_1_1.Op != OpConst64 || v_1_0_0_1_1.Type != typ.UInt64 {
					continue
				}
				kbar := auxIntToInt64(v_1_0_0_1_1.AuxInt)
				v_1_0_1 := v_1_0.Args[1]
				if v_1_0_1.Op != OpConst64 || v_1_0_1.Type != typ.UInt64 {
					continue
				}
				k := auxIntToInt64(v_1_0_1.AuxInt)
				v_1_1 := v_1.Args[1]
				if v_1_1.Op != OpConst64 || v_1_1.Type != typ.UInt64 || auxIntToInt64(v_1_1.AuxInt) != k || !(k > 0 && k < 7 && kbar == 8-k) {
					continue
				}
				v.reset(OpNeq8)
				v0 := b.NewValue0(v.Pos, OpAnd8, t)
				v1 := b.NewValue0(v.Pos, OpConst8, t)
				v1.AuxInt = int8ToAuxInt(1<<uint(k) - 1)
				v0.AddArg2(n, v1)
				v2 := b.NewValue0(v.Pos, OpConst8, t)
				v2.AuxInt = int8ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	// match: (Neq8 s:(Sub8 x y) (Const8 [0]))
	// cond: s.Uses == 1
	// result: (Neq8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			s := v_0
			if s.Op != OpSub8 {
				continue
			}
			y := s.Args[1]
			x := s.Args[0]
			if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != 0 || !(s.Uses == 1) {
				continue
			}
			v.reset(OpNeq8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Neq8 (And8 <t> x (Const8 <t> [y])) (Const8 <t> [y]))
	// cond: oneBit8(y)
	// result: (Eq8 (And8 <t> x (Const8 <t> [y])) (Const8 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd8 {
				continue
			}
			t := v_0.Type
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst8 || v_0_1.Type != t {
					continue
				}
				y := auxIntToInt8(v_0_1.AuxInt)
				if v_1.Op != OpConst8 || v_1.Type != t || auxIntToInt8(v_1.AuxInt) != y || !(oneBit8(y)) {
					continue
				}
				v.reset(OpEq8)
				v0 := b.NewValue0(v.Pos, OpAnd8, t)
				v1 := b.NewValue0(v.Pos, OpConst8, t)
				v1.AuxInt = int8ToAuxInt(y)
				v0.AddArg2(x, v1)
				v2 := b.NewValue0(v.Pos, OpConst8, t)
				v2.AuxInt = int8ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NeqB (ConstBool [c]) (ConstBool [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstBool {
				continue
			}
			c := auxIntToBool(v_0.AuxInt)
			if v_1.Op != OpConstBool {
				continue
			}
			d := auxIntToBool(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (NeqB (ConstBool [false]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstBool || auxIntToBool(v_0.AuxInt) != false {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (NeqB (ConstBool [true]) x)
	// result: (Not x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstBool || auxIntToBool(v_0.AuxInt) != true {
				continue
			}
			x := v_1
			v.reset(OpNot)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (NeqB (Not x) (Not y))
	// result: (NeqB x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpNot {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpNot {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpNeqB)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeqInter(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqInter x y)
	// result: (NeqPtr (ITab x) (ITab y))
	for {
		x := v_0
		y := v_1
		v.reset(OpNeqPtr)
		v0 := b.NewValue0(v.Pos, OpITab, typ.Uintptr)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpITab, typ.Uintptr)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuegeneric_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NeqPtr x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (NeqPtr (Addr {x} _) (Addr {y} _))
	// result: (ConstBool [x != y])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAddr {
				continue
			}
			x := auxToSym(v_0.Aux)
			if v_1.Op != OpAddr {
				continue
			}
			y := auxToSym(v_1.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y)
			return true
		}
		break
	}
	// match: (NeqPtr (Addr {x} _) (OffPtr [o] (Addr {y} _)))
	// result: (ConstBool [x != y || o != 0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAddr {
				continue
			}
			x := auxToSym(v_0.Aux)
			if v_1.Op != OpOffPtr {
				continue
			}
			o := auxIntToInt64(v_1.AuxInt)
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpAddr {
				continue
			}
			y := auxToSym(v_1_0.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y || o != 0)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr [o1] (Addr {x} _)) (OffPtr [o2] (Addr {y} _)))
	// result: (ConstBool [x != y || o1 != o2])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			o1 := auxIntToInt64(v_0.AuxInt)
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAddr {
				continue
			}
			x := auxToSym(v_0_0.Aux)
			if v_1.Op != OpOffPtr {
				continue
			}
			o2 := auxIntToInt64(v_1.AuxInt)
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpAddr {
				continue
			}
			y := auxToSym(v_1_0.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y || o1 != o2)
			return true
		}
		break
	}
	// match: (NeqPtr (LocalAddr {x} _ _) (LocalAddr {y} _ _))
	// result: (ConstBool [x != y])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLocalAddr {
				continue
			}
			x := auxToSym(v_0.Aux)
			if v_1.Op != OpLocalAddr {
				continue
			}
			y := auxToSym(v_1.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y)
			return true
		}
		break
	}
	// match: (NeqPtr (LocalAddr {x} _ _) (OffPtr [o] (LocalAddr {y} _ _)))
	// result: (ConstBool [x != y || o != 0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLocalAddr {
				continue
			}
			x := auxToSym(v_0.Aux)
			if v_1.Op != OpOffPtr {
				continue
			}
			o := auxIntToInt64(v_1.AuxInt)
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpLocalAddr {
				continue
			}
			y := auxToSym(v_1_0.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y || o != 0)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr [o1] (LocalAddr {x} _ _)) (OffPtr [o2] (LocalAddr {y} _ _)))
	// result: (ConstBool [x != y || o1 != o2])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			o1 := auxIntToInt64(v_0.AuxInt)
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpLocalAddr {
				continue
			}
			x := auxToSym(v_0_0.Aux)
			if v_1.Op != OpOffPtr {
				continue
			}
			o2 := auxIntToInt64(v_1.AuxInt)
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpLocalAddr {
				continue
			}
			y := auxToSym(v_1_0.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y || o1 != o2)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr [o1] p1) p2)
	// cond: isSamePtr(p1, p2)
	// result: (ConstBool [o1 != 0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			o1 := auxIntToInt64(v_0.AuxInt)
			p1 := v_0.Args[0]
			p2 := v_1
			if !(isSamePtr(p1, p2)) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(o1 != 0)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr [o1] p1) (OffPtr [o2] p2))
	// cond: isSamePtr(p1, p2)
	// result: (ConstBool [o1 != o2])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			o1 := auxIntToInt64(v_0.AuxInt)
			p1 := v_0.Args[0]
			if v_1.Op != OpOffPtr {
				continue
			}
			o2 := auxIntToInt64(v_1.AuxInt)
			p2 := v_1.Args[0]
			if !(isSamePtr(p1, p2)) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(o1 != o2)
			return true
		}
		break
	}
	// match: (NeqPtr (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (NeqPtr (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (NeqPtr (Convert (Addr {x} _) _) (Addr {y} _))
	// result: (ConstBool [x!=y])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConvert {
				continue
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAddr {
				continue
			}
			x := auxToSym(v_0_0.Aux)
			if v_1.Op != OpAddr {
				continue
			}
			y := auxToSym(v_1.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y)
			return true
		}
		break
	}
	// match: (NeqPtr (LocalAddr _ _) (Addr _))
	// result: (ConstBool [true])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLocalAddr || v_1.Op != OpAddr {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr (LocalAddr _ _)) (Addr _))
	// result: (ConstBool [true])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpLocalAddr || v_1.Op != OpAddr {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (NeqPtr (LocalAddr _ _) (OffPtr (Addr _)))
	// result: (ConstBool [true])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLocalAddr || v_1.Op != OpOffPtr {
				continue
			}
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpAddr {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr (LocalAddr _ _)) (OffPtr (Addr _)))
	// result: (ConstBool [true])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpLocalAddr || v_1.Op != OpOffPtr {
				continue
			}
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpAddr {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (NeqPtr (AddPtr p1 o1) p2)
	// cond: isSamePtr(p1, p2)
	// result: (IsNonNil o1)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAddPtr {
				continue
			}
			o1 := v_0.Args[1]
			p1 := v_0.Args[0]
			p2 := v_1
			if !(isSamePtr(p1, p2)) {
				continue
			}
			v.reset(OpIsNonNil)
			v.AddArg(o1)
			return true
		}
		break
	}
	// match: (NeqPtr (Const32 [0]) p)
	// result: (IsNonNil p)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
				continue
			}
			p := v_1
			v.reset(OpIsNonNil)
			v.AddArg(p)
			return true
		}
		break
	}
	// match: (NeqPtr (Const64 [0]) p)
	// result: (IsNonNil p)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			p := v_1
			v.reset(OpIsNonNil)
			v.AddArg(p)
			return true
		}
		break
	}
	// match: (NeqPtr (ConstNil) p)
	// result: (IsNonNil p)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstNil {
				continue
			}
			p := v_1
			v.reset(OpIsNonNil)
			v.AddArg(p)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeqSlice(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqSlice x y)
	// result: (NeqPtr (SlicePtr x) (SlicePtr y))
	for {
		x := v_0
		y := v_1
		v.reset(OpNeqPtr)
		v0 := b.NewValue0(v.Pos, OpSlicePtr, typ.BytePtr)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSlicePtr, typ.BytePtr)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuegeneric_OpNilCheck(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	fe := b.Func.fe
	// match: (NilCheck ptr:(GetG mem) mem)
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpGetG {
			break
		}
		mem := ptr.Args[0]
		if mem != v_1 {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(SelectN [0] call:(StaticLECall _ _)) _)
	// cond: isSameCall(call.Aux, "runtime.newobject") && warnRule(fe.Debug_checknil(), v, "removed nil check")
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpSelectN || auxIntToInt64(ptr.AuxInt) != 0 {
			break
		}
		call := ptr.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 || !(isSameCall(call.Aux, "runtime.newobject") && warnRule(fe.Debug_checknil(), v, "removed nil check")) {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(OffPtr (SelectN [0] call:(StaticLECall _ _))) _)
	// cond: isSameCall(call.Aux, "runtime.newobject") && warnRule(fe.Debug_checknil(), v, "removed nil check")
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpOffPtr {
			break
		}
		ptr_0 := ptr.Args[0]
		if ptr_0.Op != OpSelectN || auxIntToInt64(ptr_0.AuxInt) != 0 {
			break
		}
		call := ptr_0.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 || !(isSameCall(call.Aux, "runtime.newobject") && warnRule(fe.Debug_checknil(), v, "removed nil check")) {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(Addr {_} (SB)) _)
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpAddr {
			break
		}
		ptr_0 := ptr.Args[0]
		if ptr_0.Op != OpSB {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(Convert (Addr {_} (SB)) _) _)
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpConvert {
			break
		}
		ptr_0 := ptr.Args[0]
		if ptr_0.Op != OpAddr {
			break
		}
		ptr_0_0 := ptr_0.Args[0]
		if ptr_0_0.Op != OpSB {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(NilCheck _ _) _ )
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpNilCheck {
			break
		}
		v.copyOf(ptr)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not (ConstBool [c]))
	// result: (ConstBool [!c])
	for {
		if v_0.Op != OpConstBool {
			break
		}
		c := auxIntToBool(v_0.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(!c)
		return true
	}
	// match: (Not (Eq64 x y))
	// result: (Neq64 x y)
	for {
		if v_0.Op != OpEq64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq64)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq32 x y))
	// result: (Neq32 x y)
	for {
		if v_0.Op != OpEq32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq32)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq16 x y))
	// result: (Neq16 x y)
	for {
		if v_0.Op != OpEq16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq16)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq8 x y))
	// result: (Neq8 x y)
	for {
		if v_0.Op != OpEq8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq8)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (EqB x y))
	// result: (NeqB x y)
	for {
		if v_0.Op != OpEqB {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeqB)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (EqPtr x y))
	// result: (NeqPtr x y)
	for {
		if v_0.Op != OpEqPtr {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeqPtr)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq64F x y))
	// result: (Neq64F x y)
	for {
		if v_0.Op != OpEq64F {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq64F)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq32F x y))
	// result: (Neq32F x y)
	for {
		if v_0.Op != OpEq32F {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq32F)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq64 x y))
	// result: (Eq64 x y)
	for {
		if v_0.Op != OpNeq64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq64)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq32 x y))
	// result: (Eq32 x y)
	for {
		if v_0.Op != OpNeq32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq32)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq16 x y))
	// result: (Eq16 x y)
	for {
		if v_0.Op != OpNeq16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq16)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq8 x y))
	// result: (Eq8 x y)
	for {
		if v_0.Op != OpNeq8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq8)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (NeqB x y))
	// result: (EqB x y)
	for {
		if v_0.Op != OpNeqB {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEqB)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (NeqPtr x y))
	// result: (EqPtr x y)
	for {
		if v_0.Op != OpNeqPtr {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEqPtr)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq64F x y))
	// result: (Eq64F x y)
	for {
		if v_0.Op != OpNeq64F {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq64F)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq32F x y))
	// result: (Eq32F x y)
	for {
		if v_0.Op != OpNeq32F {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq32F)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Less64 x y))
	// result: (Leq64 y x)
	for {
		if v_0.Op != OpLess64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq64)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less32 x y))
	// result: (Leq32 y x)
	for {
		if v_0.Op != OpLess32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq32)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less16 x y))
	// result: (Leq16 y x)
	for {
		if v_0.Op != OpLess16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq16)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less8 x y))
	// result: (Leq8 y x)
	for {
		if v_0.Op != OpLess8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq8)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less64U x y))
	// result: (Leq64U y x)
	for {
		if v_0.Op != OpLess64U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq64U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less32U x y))
	// result: (Leq32U y x)
	for {
		if v_0.Op != OpLess32U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq32U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less16U x y))
	// result: (Leq16U y x)
	for {
		if v_0.Op != OpLess16U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq16U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less8U x y))
	// result: (Leq8U y x)
	for {
		if v_0.Op != OpLess8U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq8U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq64 x y))
	// result: (Less64 y x)
	for {
		if v_0.Op != OpLeq64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess64)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq32 x y))
	// result: (Less32 y x)
	for {
		if v_0.Op != OpLeq32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess32)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq16 x y))
	// result: (Less16 y x)
	for {
		if v_0.Op != OpLeq16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess16)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq8 x y))
	// result: (Less8 y x)
	for {
		if v_0.Op != OpLeq8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess8)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq64U x y))
	// result: (Less64U y x)
	for {
		if v_0.Op != OpLeq64U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess64U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq32U x y))
	// result: (Less32U y x)
	for {
		if v_0.Op != OpLeq32U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess32U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq16U x y))
	// result: (Less16U y x)
	for {
		if v_0.Op != OpLeq16U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess16U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq8U x y))
	// result: (Less8U y x)
	for {
		if v_0.Op != OpLeq8U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess8U)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr (OffPtr p [y]) [x])
	// result: (OffPtr p [x+y])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpOffPtr {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		p := v_0.Args[0]
		v.reset(OpOffPtr)
		v.AuxInt = int64ToAuxInt(x + y)
		v.AddArg(p)
		return true
	}
	// match: (OffPtr p [0])
	// cond: v.Type.Compare(p.Type) == types.CMPeq
	// result: p
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		p := v_0
		if !(v.Type.Compare(p.Type) == types.CMPeq) {
			break
		}
		v.copyOf(p)
		return true
	}
	return false
}
func rewriteValuegeneric_OpOr16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Or16 (Const16 [c]) (Const16 [d]))
	// result: (Const16 [c|d])
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
			v.AuxInt = int16ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (Or16 <t> (Com16 x) (Com16 y))
	// result: (Com16 (And16 <t> x y))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom16 {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpCom16 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpCom16)
			v0 := b.NewValue0(v.Pos, OpAnd16, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Or16 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Or16 (Const16 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Or16 (Const16 [-1]) _)
	// result: (Const16 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != -1 {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or16 (Com16 x) x)
	// result: (Const16 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom16 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or16 x (Or16 x y))
	// result: (Or16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpOr16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpOr16)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Or16 (And16 x (Const16 [c2])) (Const16 <t> [c1]))
	// cond: ^(c1 | c2) == 0
	// result: (Or16 (Const16 <t> [c1]) x)
	for
"""




```