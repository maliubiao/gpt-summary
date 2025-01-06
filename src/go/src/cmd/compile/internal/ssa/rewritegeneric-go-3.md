Response:

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共13部分，请归纳一下它的功能

"""
ame != "opt" && mul.Uses == 1 && m == int32(1<<15+(umagic16(c).m+1)/2) && s == 16+umagic16(c).s-2 && x.Op != OpConst16 && udivisibleOK16(c)) {
						continue
					}
					v.reset(OpLeq16U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft16, typ.UInt16)
					v1 := b.NewValue0(v.Pos, OpMul16, typ.UInt16)
					v2 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v2.AuxInt = int16ToAuxInt(int16(udivisible16(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v3.AuxInt = int16ToAuxInt(int16(16 - udivisible16(c).k))
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v4.AuxInt = int16ToAuxInt(int16(udivisible16(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq16 x (Mul16 (Const16 [c]) (Trunc32to16 (Rsh32Ux64 (Avg32u (Lsh32x64 (ZeroExt16to32 x) (Const64 [16])) mul:(Mul32 (Const32 [m]) (ZeroExt16to32 x))) (Const64 [s]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(umagic16(c).m) && s == 16+umagic16(c).s-1 && x.Op != OpConst16 && udivisibleOK16(c)
	// result: (Leq16U (RotateLeft16 <typ.UInt16> (Mul16 <typ.UInt16> (Const16 <typ.UInt16> [int16(udivisible16(c).m)]) x) (Const16 <typ.UInt16> [int16(16-udivisible16(c).k)]) ) (Const16 <typ.UInt16> [int16(udivisible16(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst16 {
					continue
				}
				c := auxIntToInt16(v_1_0.AuxInt)
				if v_1_1.Op != OpTrunc32to16 {
					continue
				}
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh32Ux64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				v_1_1_0_0 := v_1_1_0.Args[0]
				if v_1_1_0_0.Op != OpAvg32u {
					continue
				}
				_ = v_1_1_0_0.Args[1]
				v_1_1_0_0_0 := v_1_1_0_0.Args[0]
				if v_1_1_0_0_0.Op != OpLsh32x64 {
					continue
				}
				_ = v_1_1_0_0_0.Args[1]
				v_1_1_0_0_0_0 := v_1_1_0_0_0.Args[0]
				if v_1_1_0_0_0_0.Op != OpZeroExt16to32 || x != v_1_1_0_0_0_0.Args[0] {
					continue
				}
				v_1_1_0_0_0_1 := v_1_1_0_0_0.Args[1]
				if v_1_1_0_0_0_1.Op != OpConst64 || auxIntToInt64(v_1_1_0_0_0_1.AuxInt) != 16 {
					continue
				}
				mul := v_1_1_0_0.Args[1]
				if mul.Op != OpMul32 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst32 {
						continue
					}
					m := auxIntToInt32(mul_0.AuxInt)
					if mul_1.Op != OpZeroExt16to32 || x != mul_1.Args[0] {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(umagic16(c).m) && s == 16+umagic16(c).s-1 && x.Op != OpConst16 && udivisibleOK16(c)) {
						continue
					}
					v.reset(OpLeq16U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft16, typ.UInt16)
					v1 := b.NewValue0(v.Pos, OpMul16, typ.UInt16)
					v2 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v2.AuxInt = int16ToAuxInt(int16(udivisible16(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v3.AuxInt = int16ToAuxInt(int16(16 - udivisible16(c).k))
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v4.AuxInt = int16ToAuxInt(int16(udivisible16(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq16 x (Mul16 (Const16 [c]) (Sub16 (Rsh32x64 mul:(Mul32 (Const32 [m]) (SignExt16to32 x)) (Const64 [s])) (Rsh32x64 (SignExt16to32 x) (Const64 [31]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(smagic16(c).m) && s == 16+smagic16(c).s && x.Op != OpConst16 && sdivisibleOK16(c)
	// result: (Leq16U (RotateLeft16 <typ.UInt16> (Add16 <typ.UInt16> (Mul16 <typ.UInt16> (Const16 <typ.UInt16> [int16(sdivisible16(c).m)]) x) (Const16 <typ.UInt16> [int16(sdivisible16(c).a)]) ) (Const16 <typ.UInt16> [int16(16-sdivisible16(c).k)]) ) (Const16 <typ.UInt16> [int16(sdivisible16(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst16 {
					continue
				}
				c := auxIntToInt16(v_1_0.AuxInt)
				if v_1_1.Op != OpSub16 {
					continue
				}
				_ = v_1_1.Args[1]
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh32x64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				mul := v_1_1_0.Args[0]
				if mul.Op != OpMul32 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst32 {
						continue
					}
					m := auxIntToInt32(mul_0.AuxInt)
					if mul_1.Op != OpSignExt16to32 || x != mul_1.Args[0] {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpRsh32x64 {
						continue
					}
					_ = v_1_1_1.Args[1]
					v_1_1_1_0 := v_1_1_1.Args[0]
					if v_1_1_1_0.Op != OpSignExt16to32 || x != v_1_1_1_0.Args[0] {
						continue
					}
					v_1_1_1_1 := v_1_1_1.Args[1]
					if v_1_1_1_1.Op != OpConst64 || auxIntToInt64(v_1_1_1_1.AuxInt) != 31 || !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(smagic16(c).m) && s == 16+smagic16(c).s && x.Op != OpConst16 && sdivisibleOK16(c)) {
						continue
					}
					v.reset(OpLeq16U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft16, typ.UInt16)
					v1 := b.NewValue0(v.Pos, OpAdd16, typ.UInt16)
					v2 := b.NewValue0(v.Pos, OpMul16, typ.UInt16)
					v3 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v3.AuxInt = int16ToAuxInt(int16(sdivisible16(c).m))
					v2.AddArg2(v3, x)
					v4 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v4.AuxInt = int16ToAuxInt(int16(sdivisible16(c).a))
					v1.AddArg2(v2, v4)
					v5 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v5.AuxInt = int16ToAuxInt(int16(16 - sdivisible16(c).k))
					v0.AddArg2(v1, v5)
					v6 := b.NewValue0(v.Pos, OpConst16, typ.UInt16)
					v6.AuxInt = int16ToAuxInt(int16(sdivisible16(c).max))
					v.AddArg2(v0, v6)
					return true
				}
			}
		}
		break
	}
	// match: (Eq16 n (Lsh16x64 (Rsh16x64 (Add16 <t> n (Rsh16Ux64 <t> (Rsh16x64 <t> n (Const64 <typ.UInt64> [15])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 15 && kbar == 16 - k
	// result: (Eq16 (And16 <t> n (Const16 <t> [1<<uint(k)-1])) (Const16 <t> [0]))
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
				v.reset(OpEq16)
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
	// match: (Eq16 s:(Sub16 x y) (Const16 [0]))
	// cond: s.Uses == 1
	// result: (Eq16 x y)
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
			v.reset(OpEq16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Eq16 (And16 <t> x (Const16 <t> [y])) (Const16 <t> [y]))
	// cond: oneBit16(y)
	// result: (Neq16 (And16 <t> x (Const16 <t> [y])) (Const16 <t> [0]))
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
				v.reset(OpNeq16)
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
func rewriteValuegeneric_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq32 x x)
	// result: (ConstBool [true])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Eq32 (Const32 <t> [c]) (Add32 (Const32 <t> [d]) x))
	// result: (Eq32 (Const32 <t> [c-d]) x)
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
				v.reset(OpEq32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Eq32 (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [c == d])
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
			v.AuxInt = boolToAuxInt(c == d)
			return true
		}
		break
	}
	// match: (Eq32 x (Mul32 (Const32 [c]) (Rsh32Ux64 mul:(Hmul32u (Const32 [m]) x) (Const64 [s])) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(1<<31+umagic32(c).m/2) && s == umagic32(c).s-1 && x.Op != OpConst32 && udivisibleOK32(c)
	// result: (Leq32U (RotateLeft32 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(udivisible32(c).m)]) x) (Const32 <typ.UInt32> [int32(32-udivisible32(c).k)]) ) (Const32 <typ.UInt32> [int32(udivisible32(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 {
					continue
				}
				c := auxIntToInt32(v_1_0.AuxInt)
				if v_1_1.Op != OpRsh32Ux64 {
					continue
				}
				_ = v_1_1.Args[1]
				mul := v_1_1.Args[0]
				if mul.Op != OpHmul32u {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst32 {
						continue
					}
					m := auxIntToInt32(mul_0.AuxInt)
					if x != mul_1 {
						continue
					}
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(1<<31+umagic32(c).m/2) && s == umagic32(c).s-1 && x.Op != OpConst32 && udivisibleOK32(c)) {
						continue
					}
					v.reset(OpLeq32U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft32, typ.UInt32)
					v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
					v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v2.AuxInt = int32ToAuxInt(int32(udivisible32(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v3.AuxInt = int32ToAuxInt(int32(32 - udivisible32(c).k))
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v4.AuxInt = int32ToAuxInt(int32(udivisible32(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq32 x (Mul32 (Const32 [c]) (Rsh32Ux64 mul:(Hmul32u (Const32 <typ.UInt32> [m]) (Rsh32Ux64 x (Const64 [1]))) (Const64 [s])) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(1<<31+(umagic32(c).m+1)/2) && s == umagic32(c).s-2 && x.Op != OpConst32 && udivisibleOK32(c)
	// result: (Leq32U (RotateLeft32 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(udivisible32(c).m)]) x) (Const32 <typ.UInt32> [int32(32-udivisible32(c).k)]) ) (Const32 <typ.UInt32> [int32(udivisible32(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 {
					continue
				}
				c := auxIntToInt32(v_1_0.AuxInt)
				if v_1_1.Op != OpRsh32Ux64 {
					continue
				}
				_ = v_1_1.Args[1]
				mul := v_1_1.Args[0]
				if mul.Op != OpHmul32u {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst32 || mul_0.Type != typ.UInt32 {
						continue
					}
					m := auxIntToInt32(mul_0.AuxInt)
					if mul_1.Op != OpRsh32Ux64 {
						continue
					}
					_ = mul_1.Args[1]
					if x != mul_1.Args[0] {
						continue
					}
					mul_1_1 := mul_1.Args[1]
					if mul_1_1.Op != OpConst64 || auxIntToInt64(mul_1_1.AuxInt) != 1 {
						continue
					}
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(1<<31+(umagic32(c).m+1)/2) && s == umagic32(c).s-2 && x.Op != OpConst32 && udivisibleOK32(c)) {
						continue
					}
					v.reset(OpLeq32U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft32, typ.UInt32)
					v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
					v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v2.AuxInt = int32ToAuxInt(int32(udivisible32(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v3.AuxInt = int32ToAuxInt(int32(32 - udivisible32(c).k))
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v4.AuxInt = int32ToAuxInt(int32(udivisible32(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq32 x (Mul32 (Const32 [c]) (Rsh32Ux64 (Avg32u x mul:(Hmul32u (Const32 [m]) x)) (Const64 [s])) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(umagic32(c).m) && s == umagic32(c).s-1 && x.Op != OpConst32 && udivisibleOK32(c)
	// result: (Leq32U (RotateLeft32 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(udivisible32(c).m)]) x) (Const32 <typ.UInt32> [int32(32-udivisible32(c).k)]) ) (Const32 <typ.UInt32> [int32(udivisible32(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 {
					continue
				}
				c := auxIntToInt32(v_1_0.AuxInt)
				if v_1_1.Op != OpRsh32Ux64 {
					continue
				}
				_ = v_1_1.Args[1]
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpAvg32u {
					continue
				}
				_ = v_1_1_0.Args[1]
				if x != v_1_1_0.Args[0] {
					continue
				}
				mul := v_1_1_0.Args[1]
				if mul.Op != OpHmul32u {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst32 {
						continue
					}
					m := auxIntToInt32(mul_0.AuxInt)
					if x != mul_1 {
						continue
					}
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(umagic32(c).m) && s == umagic32(c).s-1 && x.Op != OpConst32 && udivisibleOK32(c)) {
						continue
					}
					v.reset(OpLeq32U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft32, typ.UInt32)
					v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
					v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v2.AuxInt = int32ToAuxInt(int32(udivisible32(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v3.AuxInt = int32ToAuxInt(int32(32 - udivisible32(c).k))
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v4.AuxInt = int32ToAuxInt(int32(udivisible32(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq32 x (Mul32 (Const32 [c]) (Trunc64to32 (Rsh64Ux64 mul:(Mul64 (Const64 [m]) (ZeroExt32to64 x)) (Const64 [s]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<31+umagic32(c).m/2) && s == 32+umagic32(c).s-1 && x.Op != OpConst32 && udivisibleOK32(c)
	// result: (Leq32U (RotateLeft32 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(udivisible32(c).m)]) x) (Const32 <typ.UInt32> [int32(32-udivisible32(c).k)]) ) (Const32 <typ.UInt32> [int32(udivisible32(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 {
					continue
				}
				c := auxIntToInt32(v_1_0.AuxInt)
				if v_1_1.Op != OpTrunc64to32 {
					continue
				}
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh64Ux64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				mul := v_1_1_0.Args[0]
				if mul.Op != OpMul64 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst64 {
						continue
					}
					m := auxIntToInt64(mul_0.AuxInt)
					if mul_1.Op != OpZeroExt32to64 || x != mul_1.Args[0] {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<31+umagic32(c).m/2) && s == 32+umagic32(c).s-1 && x.Op != OpConst32 && udivisibleOK32(c)) {
						continue
					}
					v.reset(OpLeq32U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft32, typ.UInt32)
					v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
					v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v2.AuxInt = int32ToAuxInt(int32(udivisible32(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v3.AuxInt = int32ToAuxInt(int32(32 - udivisible32(c).k))
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v4.AuxInt = int32ToAuxInt(int32(udivisible32(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq32 x (Mul32 (Const32 [c]) (Trunc64to32 (Rsh64Ux64 mul:(Mul64 (Const64 [m]) (Rsh64Ux64 (ZeroExt32to64 x) (Const64 [1]))) (Const64 [s]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<31+(umagic32(c).m+1)/2) && s == 32+umagic32(c).s-2 && x.Op != OpConst32 && udivisibleOK32(c)
	// result: (Leq32U (RotateLeft32 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(udivisible32(c).m)]) x) (Const32 <typ.UInt32> [int32(32-udivisible32(c).k)]) ) (Const32 <typ.UInt32> [int32(udivisible32(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 {
					continue
				}
				c := auxIntToInt32(v_1_0.AuxInt)
				if v_1_1.Op != OpTrunc64to32 {
					continue
				}
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh64Ux64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				mul := v_1_1_0.Args[0]
				if mul.Op != OpMul64 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst64 {
						continue
					}
					m := auxIntToInt64(mul_0.AuxInt)
					if mul_1.Op != OpRsh64Ux64 {
						continue
					}
					_ = mul_1.Args[1]
					mul_1_0 := mul_1.Args[0]
					if mul_1_0.Op != OpZeroExt32to64 || x != mul_1_0.Args[0] {
						continue
					}
					mul_1_1 := mul_1.Args[1]
					if mul_1_1.Op != OpConst64 || auxIntToInt64(mul_1_1.AuxInt) != 1 {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<31+(umagic32(c).m+1)/2) && s == 32+umagic32(c).s-2 && x.Op != OpConst32 && udivisibleOK32(c)) {
						continue
					}
					v.reset(OpLeq32U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft32, typ.UInt32)
					v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
					v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v2.AuxInt = int32ToAuxInt(int32(udivisible32(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v3.AuxInt = int32ToAuxInt(int32(32 - udivisible32(c).k))
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v4.AuxInt = int32ToAuxInt(int32(udivisible32(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq32 x (Mul32 (Const32 [c]) (Trunc64to32 (Rsh64Ux64 (Avg64u (Lsh64x64 (ZeroExt32to64 x) (Const64 [32])) mul:(Mul64 (Const64 [m]) (ZeroExt32to64 x))) (Const64 [s]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(umagic32(c).m) && s == 32+umagic32(c).s-1 && x.Op != OpConst32 && udivisibleOK32(c)
	// result: (Leq32U (RotateLeft32 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(udivisible32(c).m)]) x) (Const32 <typ.UInt32> [int32(32-udivisible32(c).k)]) ) (Const32 <typ.UInt32> [int32(udivisible32(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 {
					continue
				}
				c := auxIntToInt32(v_1_0.AuxInt)
				if v_1_1.Op != OpTrunc64to32 {
					continue
				}
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh64Ux64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				v_1_1_0_0 := v_1_1_0.Args[0]
				if v_1_1_0_0.Op != OpAvg64u {
					continue
				}
				_ = v_1_1_0_0.Args[1]
				v_1_1_0_0_0 := v_1_1_0_0.Args[0]
				if v_1_1_0_0_0.Op != OpLsh64x64 {
					continue
				}
				_ = v_1_1_0_0_0.Args[1]
				v_1_1_0_0_0_0 := v_1_1_0_0_0.Args[0]
				if v_1_1_0_0_0_0.Op != OpZeroExt32to64 || x != v_1_1_0_0_0_0.Args[0] {
					continue
				}
				v_1_1_0_0_0_1 := v_1_1_0_0_0.Args[1]
				if v_1_1_0_0_0_1.Op != OpConst64 || auxIntToInt64(v_1_1_0_0_0_1.AuxInt) != 32 {
					continue
				}
				mul := v_1_1_0_0.Args[1]
				if mul.Op != OpMul64 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst64 {
						continue
					}
					m := auxIntToInt64(mul_0.AuxInt)
					if mul_1.Op != OpZeroExt32to64 || x != mul_1.Args[0] {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(umagic32(c).m) && s == 32+umagic32(c).s-1 && x.Op != OpConst32 && udivisibleOK32(c)) {
						continue
					}
					v.reset(OpLeq32U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft32, typ.UInt32)
					v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
					v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v2.AuxInt = int32ToAuxInt(int32(udivisible32(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v3.AuxInt = int32ToAuxInt(int32(32 - udivisible32(c).k))
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v4.AuxInt = int32ToAuxInt(int32(udivisible32(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq32 x (Mul32 (Const32 [c]) (Sub32 (Rsh64x64 mul:(Mul64 (Const64 [m]) (SignExt32to64 x)) (Const64 [s])) (Rsh64x64 (SignExt32to64 x) (Const64 [63]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(smagic32(c).m) && s == 32+smagic32(c).s && x.Op != OpConst32 && sdivisibleOK32(c)
	// result: (Leq32U (RotateLeft32 <typ.UInt32> (Add32 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(sdivisible32(c).m)]) x) (Const32 <typ.UInt32> [int32(sdivisible32(c).a)]) ) (Const32 <typ.UInt32> [int32(32-sdivisible32(c).k)]) ) (Const32 <typ.UInt32> [int32(sdivisible32(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 {
					continue
				}
				c := auxIntToInt32(v_1_0.AuxInt)
				if v_1_1.Op != OpSub32 {
					continue
				}
				_ = v_1_1.Args[1]
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh64x64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				mul := v_1_1_0.Args[0]
				if mul.Op != OpMul64 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst64 {
						continue
					}
					m := auxIntToInt64(mul_0.AuxInt)
					if mul_1.Op != OpSignExt32to64 || x != mul_1.Args[0] {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpRsh64x64 {
						continue
					}
					_ = v_1_1_1.Args[1]
					v_1_1_1_0 := v_1_1_1.Args[0]
					if v_1_1_1_0.Op != OpSignExt32to64 || x != v_1_1_1_0.Args[0] {
						continue
					}
					v_1_1_1_1 := v_1_1_1.Args[1]
					if v_1_1_1_1.Op != OpConst64 || auxIntToInt64(v_1_1_1_1.AuxInt) != 63 || !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(smagic32(c).m) && s == 32+smagic32(c).s && x.Op != OpConst32 && sdivisibleOK32(c)) {
						continue
					}
					v.reset(OpLeq32U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft32, typ.UInt32)
					v1 := b.NewValue0(v.Pos, OpAdd32, typ.UInt32)
					v2 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
					v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v3.AuxInt = int32ToAuxInt(int32(sdivisible32(c).m))
					v2.AddArg2(v3, x)
					v4 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v4.AuxInt = int32ToAuxInt(int32(sdivisible32(c).a))
					v1.AddArg2(v2, v4)
					v5 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v5.AuxInt = int32ToAuxInt(int32(32 - sdivisible32(c).k))
					v0.AddArg2(v1, v5)
					v6 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v6.AuxInt = int32ToAuxInt(int32(sdivisible32(c).max))
					v.AddArg2(v0, v6)
					return true
				}
			}
		}
		break
	}
	// match: (Eq32 x (Mul32 (Const32 [c]) (Sub32 (Rsh32x64 mul:(Hmul32 (Const32 [m]) x) (Const64 [s])) (Rsh32x64 x (Const64 [31]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(smagic32(c).m/2) && s == smagic32(c).s-1 && x.Op != OpConst32 && sdivisibleOK32(c)
	// result: (Leq32U (RotateLeft32 <typ.UInt32> (Add32 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(sdivisible32(c).m)]) x) (Const32 <typ.UInt32> [int32(sdivisible32(c).a)]) ) (Const32 <typ.UInt32> [int32(32-sdivisible32(c).k)]) ) (Const32 <typ.UInt32> [int32(sdivisible32(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 {
					continue
				}
				c := auxIntToInt32(v_1_0.AuxInt)
				if v_1_1.Op != OpSub32 {
					continue
				}
				_ = v_1_1.Args[1]
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh32x64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				mul := v_1_1_0.Args[0]
				if mul.Op != OpHmul32 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst32 {
						continue
					}
					m := auxIntToInt32(mul_0.AuxInt)
					if x != mul_1 {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpRsh32x64 {
						continue
					}
					_ = v_1_1_1.Args[1]
					if x != v_1_1_1.Args[0] {
						continue
					}
					v_1_1_1_1 := v_1_1_1.Args[1]
					if v_1_1_1_1.Op != OpConst64 || auxIntToInt64(v_1_1_1_1.AuxInt) != 31 || !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(smagic32(c).m/2) && s == smagic32(c).s-1 && x.Op != OpConst32 && sdivisibleOK32(c)) {
						continue
					}
					v.reset(OpLeq32U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft32, typ.UInt32)
					v1 := b.NewValue0(v.Pos, OpAdd32, typ.UInt32)
					v2 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
					v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v3.AuxInt = int32ToAuxInt(int32(sdivisible32(c).m))
					v2.AddArg2(v3, x)
					v4 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v4.AuxInt = int32ToAuxInt(int32(sdivisible32(c).a))
					v1.AddArg2(v2, v4)
					v5 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v5.AuxInt = int32ToAuxInt(int32(32 - sdivisible32(c).k))
					v0.AddArg2(v1, v5)
					v6 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
					v6.AuxInt = int32ToAuxInt(int32(sdivisible32(c).max))
					v.AddArg2(v0, v6)
					return true
				}
			}
		}
		break
	}
	// match: (Eq32 x (Mul32 (Const32 [c]) (Sub32 (Rsh32x64 (Add32 mul:(Hmul32 (Const32 [m]) x) x) (Const64 [s])) (Rsh32x64 x (Const64 [31]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(smagic32(c).m) && s == smagic32(c).s && x.Op != OpConst32 && sdivisibleOK32(c)
	// result: (Leq32U (RotateLeft32 <typ.UInt32> (Add32 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(sdivisible32(c).m)]) x) (Const32 <typ.UInt32> [int32(sdivisible32(c).a)]) ) (Const32 <typ.UInt32> [int32(32-sdivisible32(c).k)]) ) (Const32 <typ.UInt32> [int32(sdivisible32(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 {
					continue
				}
				c := auxIntToInt32(v_1_0.AuxInt)
				if v_1_1.Op != OpSub32 {
					continue
				}
				_ = v_1_1.Args[1]
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh32x64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				v_1_1_0_0 := v_1_1_0.Args[0]
				if v_1_1_0_0.Op != OpAdd32 {
					continue
				}
				_ = v_1_1_0_0.Args[1]
				v_1_1_0_0_0 := v_1_1_0_0.Args[0]
				v_1_1_0_0_1 := v_1_1_0_0.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, v_1_1_0_0_0, v_1_1_0_0_1 = _i2+1, v_1_1_0_0_1, v_1_1_0_0_0 {
					mul := v_1_1_0_0_0
					if mul.Op != OpHmul32 {
						continue
					}
					_ = mul.Args[1]
					mul_0 := mul.Args[0]
					mul_1 := mul.Args[1]
					for _i3 := 0; _i3 <= 1; _i3, mul_0, mul_1 = _i3+1, mul_1, mul_0 {
						if mul_0.Op != OpConst32 {
							continue
						}
						m := auxIntToInt32(mul_0.AuxInt)
						if x != mul_1 || x != v_1_1_0_0_1 {
							continue
						}
						v_1_1_0_1 := v_1_1_0.Args[1]
						if v_1_1_0_1.Op != OpConst64 {
							continue
						}
						s := auxIntToInt64(v_1_1_0_1.AuxInt)
						v_1_1_1 := v_1_1.Args[1]
						if v_1_1_1.Op != OpRsh32x64 {
							continue
						}
						_ = v_1_1_1.Args[1]
						if x != v_1_1_1.Args[0] {
							continue
						}
						v_1_1_1_1 := v_1_1_1.Args[1]
						if v_1_1_1_1.Op != OpConst64 || auxIntToInt64(v_1_1_1_1.AuxInt) != 31 || !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(smagic32(c).m) && s == smagic32(c).s && x.Op != OpConst32 && sdivisibleOK32(c)) {
							continue
						}
						v.reset(OpLeq32U)
						v0 := b.NewValue0(v.Pos, OpRotateLeft32, typ.UInt32)
						v1 := b.NewValue0(v.Pos, OpAdd32, typ.UInt32)
						v2 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
						v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
						v3.AuxInt = int32ToAuxInt(int32(sdivisible32(c).m))
						v2.AddArg2(v3, x)
						v4 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
						v4.AuxInt = int32ToAuxInt(int32(sdivisible32(c).a))
						v1.AddArg2(v2, v4)
						v5 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
						v5.AuxInt = int32ToAuxInt(int32(32 - sdivisible32(c).k))
						v0.AddArg2(v1, v5)
						v6 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
						v6.AuxInt = int32ToAuxInt(int32(sdivisible32(c).max))
						v.AddArg2(v0, v6)
						return true
					}
				}
			}
		}
		break
	}
	// match: (Eq32 n (Lsh32x64 (Rsh32x64 (Add32 <t> n (Rsh32Ux64 <t> (Rsh32x64 <t> n (Const64 <typ.UInt64> [31])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 31 && kbar == 32 - k
	// result: (Eq32 (And32 <t> n (Const32 <t> [1<<uint(k)-1])) (Const32 <t> [0]))
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
				v.reset(OpEq32)
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
	// match: (Eq32 s:(Sub32 x y) (Const32 [0]))
	// cond: s.Uses == 1
	// result: (Eq32 x y)
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
			v.reset(OpEq32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Eq32 (And32 <t> x (Const32 <t> [y])) (Const32 <t> [y]))
	// cond: oneBit32(y)
	// result: (Neq32 (And32 <t> x (Const32 <t> [y])) (Const32 <t> [0]))
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
				v.reset(OpNeq32)
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
func rewriteValuegeneric_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Eq32F (Const32F [c]) (Const32F [d]))
	// result: (ConstBool [c == d])
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
			v.AuxInt = boolToAuxInt(c == d)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq64 x x)
	// result: (ConstBool [true])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Eq64 (Const64 <t> [c]) (Add64 (Const64 <t> [d]) x))
	// result: (Eq64 (Const64 <t> [c-d]) x)
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
				v.reset(OpEq64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Eq64 (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [c == d])
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
			v.AuxInt = boolToAuxInt(c == d)
			return true
		}
		break
	}
	// match: (Eq64 x (Mul64 (Const64 [c]) (Rsh64Ux64 mul:(Hmul64u (Const64 [m]) x) (Const64 [s])) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<63+umagic64(c).m/2) && s == umagic64(c).s-1 && x.Op != OpConst64 && udivisibleOK64(c)
	// result: (Leq64U (RotateLeft64 <typ.UInt64> (Mul64 <typ.UInt64> (Const64 <typ.UInt64> [int64(udivisible64(c).m)]) x) (Const64 <typ.UInt64> [64-udivisible64(c).k]) ) (Const64 <typ.UInt64> [int64(udivisible64(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 {
					continue
				}
				c := auxIntToInt64(v_1_0.AuxInt)
				if v_1_1.Op != OpRsh64Ux64 {
					continue
				}
				_ = v_1_1.Args[1]
				mul := v_1_1.Args[0]
				if mul.Op != OpHmul64u {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst64 {
						continue
					}
					m := auxIntToInt64(mul_0.AuxInt)
					if x != mul_1 {
						continue
					}
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<63+umagic64(c).m/2) && s == umagic64(c).s-1 && x.Op != OpConst64 && udivisibleOK64(c)) {
						continue
					}
					v.reset(OpLeq64U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft64, typ.UInt64)
					v1 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
					v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v2.AuxInt = int64ToAuxInt(int64(udivisible64(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v3.AuxInt = int64ToAuxInt(64 - udivisible64(c).k)
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v4.AuxInt = int64ToAuxInt(int64(udivisible64(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq64 x (Mul64 (Const64 [c]) (Rsh64Ux64 mul:(Hmul64u (Const64 [m]) (Rsh64Ux64 x (Const64 [1]))) (Const64 [s])) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<63+(umagic64(c).m+1)/2) && s == umagic64(c).s-2 && x.Op != OpConst64 && udivisibleOK64(c)
	// result: (Leq64U (RotateLeft64 <typ.UInt64> (Mul64 <typ.UInt64> (Const64 <typ.UInt64> [int64(udivisible64(c).m)]) x) (Const64 <typ.UInt64> [64-udivisible64(c).k]) ) (Const64 <typ.UInt64> [int64(udivisible64(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 {
					continue
				}
				c := auxIntToInt64(v_1_0.AuxInt)
				if v_1_1.Op != OpRsh64Ux64 {
					continue
				}
				_ = v_1_1.Args[1]
				mul := v_1_1.Args[0]
				if mul.Op != OpHmul64u {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst64 {
						continue
					}
					m := auxIntToInt64(mul_0.AuxInt)
					if mul_1.Op != OpRsh64Ux64 {
						continue
					}
					_ = mul_1.Args[1]
					if x != mul_1.Args[0] {
						continue
					}
					mul_1_1 := mul_1.Args[1]
					if mul_1_1.Op != OpConst64 || auxIntToInt64(mul_1_1.AuxInt) != 1 {
						continue
					}
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<63+(umagic64(c).m+1)/2) && s == umagic64(c).s-2 && x.Op != OpConst64 && udivisibleOK64(c)) {
						continue
					}
					v.reset(OpLeq64U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft64, typ.UInt64)
					v1 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
					v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v2.AuxInt = int64ToAuxInt(int64(udivisible64(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v3.AuxInt = int64ToAuxInt(64 - udivisible64(c).k)
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v4.AuxInt = int64ToAuxInt(int64(udivisible64(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq64 x (Mul64 (Const64 [c]) (Rsh64Ux64 (Avg64u x mul:(Hmul64u (Const64 [m]) x)) (Const64 [s])) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(umagic64(c).m) && s == umagic64(c).s-1 && x.Op != OpConst64 && udivisibleOK64(c)
	// result: (Leq64U (RotateLeft64 <typ.UInt64> (Mul64 <typ.UInt64> (Const64 <typ.UInt64> [int64(udivisible64(c).m)]) x) (Const64 <typ.UInt64> [64-udivisible64(c).k]) ) (Const64 <typ.UInt64> [int64(udivisible64(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 {
					continue
				}
				c := auxIntToInt64(v_1_0.AuxInt)
				if v_1_1.Op != OpRsh64Ux64 {
					continue
				}
				_ = v_1_1.Args[1]
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpAvg64u {
					continue
				}
				_ = v_1_1_0.Args[1]
				if x != v_1_1_0.Args[0] {
					continue
				}
				mul := v_1_1_0.Args[1]
				if mul.Op != OpHmul64u {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst64 {
						continue
					}
					m := auxIntToInt64(mul_0.AuxInt)
					if x != mul_1 {
						continue
					}
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(umagic64(c).m) && s == umagic64(c).s-1 && x.Op != OpConst64 && udivisibleOK64(c)) {
						continue
					}
					v.reset(OpLeq64U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft64, typ.UInt64)
					v1 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
					v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v2.AuxInt = int64ToAuxInt(int64(udivisible64(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v3.AuxInt = int64ToAuxInt(64 - udivisible64(c).k)
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v4.AuxInt = int64ToAuxInt(int64(udivisible64(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq64 x (Mul64 (Const64 [c]) (Sub64 (Rsh64x64 mul:(Hmul64 (Const64 [m]) x) (Const64 [s])) (Rsh64x64 x (Const64 [63]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(smagic64(c).m/2) && s == smagic64(c).s-1 && x.Op != OpConst64 && sdivisibleOK64(c)
	// result: (Leq64U (RotateLeft64 <typ.UInt64> (Add64 <typ.UInt64> (Mul64 <typ.UInt64> (Const64 <typ.UInt64> [int64(sdivisible64(c).m)]) x) (Const64 <typ.UInt64> [int64(sdivisible64(c).a)]) ) (Const64 <typ.UInt64> [64-sdivisible64(c).k]) ) (Const64 <typ.UInt64> [int64(sdivisible64(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 {
					continue
				}
				c := auxIntToInt64(v_1_0.AuxInt)
				if v_1_1.Op != OpSub64 {
					continue
				}
				_ = v_1_1.Args[1]
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh64x64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				mul := v_1_1_0.Args[0]
				if mul.Op != OpHmul64 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst64 {
						continue
					}
					m := auxIntToInt64(mul_0.AuxInt)
					if x != mul_1 {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpRsh64x64 {
						continue
					}
					_ = v_1_1_1.Args[1]
					if x != v_1_1_1.Args[0] {
						continue
					}
					v_1_1_1_1 := v_1_1_1.Args[1]
					if v_1_1_1_1.Op != OpConst64 || auxIntToInt64(v_1_1_1_1.AuxInt) != 63 || !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(smagic64(c).m/2) && s == smagic64(c).s-1 && x.Op != OpConst64 && sdivisibleOK64(c)) {
						continue
					}
					v.reset(OpLeq64U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft64, typ.UInt64)
					v1 := b.NewValue0(v.Pos, OpAdd64, typ.UInt64)
					v2 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
					v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v3.AuxInt = int64ToAuxInt(int64(sdivisible64(c).m))
					v2.AddArg2(v3, x)
					v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v4.AuxInt = int64ToAuxInt(int64(sdivisible64(c).a))
					v1.AddArg2(v2, v4)
					v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v5.AuxInt = int64ToAuxInt(64 - sdivisible64(c).k)
					v0.AddArg2(v1, v5)
					v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
					v6.AuxInt = int64ToAuxInt(int64(sdivisible64(c).max))
					v.AddArg2(v0, v6)
					return true
				}
			}
		}
		break
	}
	// match: (Eq64 x (Mul64 (Const64 [c]) (Sub64 (Rsh64x64 (Add64 mul:(Hmul64 (Const64 [m]) x) x) (Const64 [s])) (Rsh64x64 x (Const64 [63]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(smagic64(c).m) && s == smagic64(c).s && x.Op != OpConst64 && sdivisibleOK64(c)
	// result: (Leq64U (RotateLeft64 <typ.UInt64> (Add64 <typ.UInt64> (Mul64 <typ.UInt64> (Const64 <typ.UInt64> [int64(sdivisible64(c).m)]) x) (Const64 <typ.UInt64> [int64(sdivisible64(c).a)]) ) (Const64 <typ.UInt64> [64-sdivisible64(c).k]) ) (Const64 <typ.UInt64> [int64(sdivisible64(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 {
					continue
				}
				c := auxIntToInt64(v_1_0.AuxInt)
				if v_1_1.Op != OpSub64 {
					continue
				}
				_ = v_1_1.Args[1]
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh64x64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				v_1_1_0_0 := v_1_1_0.Args[0]
				if v_1_1_0_0.Op != OpAdd64 {
					continue
				}
				_ = v_1_1_0_0.Args[1]
				v_1_1_0_0_0 := v_1_1_0_0.Args[0]
				v_1_1_0_0_1 := v_1_1_0_0.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, v_1_1_0_0_0, v_1_1_0_0_1 = _i2+1, v_1_1_0_0_1, v_1_1_0_0_0 {
					mul := v_1_1_0_0_0
					if mul.Op != OpHmul64 {
						continue
					}
					_ = mul.Args[1]
					mul_0 := mul.Args[0]
					mul_1 := mul.Args[1]
					for _i3 := 0; _i3 <= 1; _i3, mul_0, mul_1 = _i3+1, mul_1, mul_0 {
						if mul_0.Op != OpConst64 {
							continue
						}
						m := auxIntToInt64(mul_0.AuxInt)
						if x != mul_1 || x != v_1_1_0_0_1 {
							continue
						}
						v_1_1_0_1 := v_1_1_0.Args[1]
						if v_1_1_0_1.Op != OpConst64 {
							continue
						}
						s := auxIntToInt64(v_1_1_0_1.AuxInt)
						v_1_1_1 := v_1_1.Args[1]
						if v_1_1_1.Op != OpRsh64x64 {
							continue
						}
						_ = v_1_1_1.Args[1]
						if x != v_1_1_1.Args[0] {
							continue
						}
						v_1_1_1_1 := v_1_1_1.Args[1]
						if v_1_1_1_1.Op != OpConst64 || auxIntToInt64(v_1_1_1_1.AuxInt) != 63 || !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(smagic64(c).m) && s == smagic64(c).s && x.Op != OpConst64 && sdivisibleOK64(c)) {
							continue
						}
						v.reset(OpLeq64U)
						v0 := b.NewValue0(v.Pos, OpRotateLeft64, typ.UInt64)
						v1 := b.NewValue0(v.Pos, OpAdd64, typ.UInt64)
						v2 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
						v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
						v3.AuxInt = int64ToAuxInt(int64(sdivisible64(c).m))
						v2.AddArg2(v3, x)
						v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
						v4.AuxInt = int64ToAuxInt(int64(sdivisible64(c).a))
						v1.AddArg2(v2, v4)
						v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
						v5.AuxInt = int64ToAuxInt(64 - sdivisible64(c).k)
						v0.AddArg2(v1, v5)
						v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
						v6.AuxInt = int64ToAuxInt(int64(sdivisible64(c).max))
						v.AddArg2(v0, v6)
						return true
					}
				}
			}
		}
		break
	}
	// match: (Eq64 n (Lsh64x64 (Rsh64x64 (Add64 <t> n (Rsh64Ux64 <t> (Rsh64x64 <t> n (Const64 <typ.UInt64> [63])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 63 && kbar == 64 - k
	// result: (Eq64 (And64 <t> n (Const64 <t> [1<<uint(k)-1])) (Const64 <t> [0]))
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
				v.reset(OpEq64)
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
	// match: (Eq64 s:(Sub64 x y) (Const64 [0]))
	// cond: s.Uses == 1
	// result: (Eq64 x y)
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
			v.reset(OpEq64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Eq64 (And64 <t> x (Const64 <t> [y])) (Const64 <t> [y]))
	// cond: oneBit64(y)
	// result: (Neq64 (And64 <t> x (Const64 <t> [y])) (Const64 <t> [0]))
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
				v.reset(OpNeq64)
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
func rewriteValuegeneric_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Eq64F (Const64F [c]) (Const64F [d]))
	// result: (ConstBool [c == d])
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
			v.AuxInt = boolToAuxInt(c == d)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Eq8 x x)
	// result: (ConstBool [true])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Eq8 (Const8 <t> [c]) (Add8 (Const8 <t> [d]) x))
	// result: (Eq8 (Const8 <t> [c-d]) x)
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
				v.reset(OpEq8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Eq8 (Const8 [c]) (Const8 [d]))
	// result: (ConstBool [c == d])
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
			v.AuxInt = boolToAuxInt(c == d)
			return true
		}
		break
	}
	// match: (Eq8 (Mod8u x (Const8 [c])) (Const8 [0]))
	// cond: x.Op != OpConst8 && udivisibleOK8(c) && !hasSmallRotate(config)
	// result: (Eq32 (Mod32u <typ.UInt32> (ZeroExt8to32 <typ.UInt32> x) (Const32 <typ.UInt32> [int32(uint8(c))])) (Const32 <typ.UInt32> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMod8u {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_1.AuxInt)
			if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != 0 || !(x.Op != OpConst8 && udivisibleOK8(c) && !hasSmallRotate(config)) {
				continue
			}
			v.reset(OpEq32)
			v0 := b.NewValue0(v.Pos, OpMod32u, typ.UInt32)
			v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
			v1.AddArg(x)
			v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
			v2.AuxInt = int32ToAuxInt(int32(uint8(c)))
			v0.AddArg2(v1, v2)
			v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
			v3.AuxInt = int32ToAuxInt(0)
			v.AddArg2(v0, v3)
			return true
		}
		break
	}
	// match: (Eq8 (Mod8 x (Const8 [c])) (Const8 [0]))
	// cond: x.Op != OpConst8 && sdivisibleOK8(c) && !hasSmallRotate(config)
	// result: (Eq32 (Mod32 <typ.Int32> (SignExt8to32 <typ.Int32> x) (Const32 <typ.Int32> [int32(c)])) (Const32 <typ.Int32> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMod8 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_1.AuxInt)
			if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != 0 || !(x.Op != OpConst8 && sdivisibleOK8(c) && !hasSmallRotate(config)) {
				continue
			}
			v.reset(OpEq32)
			v0 := b.NewValue0(v.Pos, OpMod32, typ.Int32)
			v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
			v1.AddArg(x)
			v2 := b.NewValue0(v.Pos, OpConst32, typ.Int32)
			v2.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg2(v1, v2)
			v3 := b.NewValue0(v.Pos, OpConst32, typ.Int32)
			v3.AuxInt = int32ToAuxInt(0)
			v.AddArg2(v0, v3)
			return true
		}
		break
	}
	// match: (Eq8 x (Mul8 (Const8 [c]) (Trunc32to8 (Rsh32Ux64 mul:(Mul32 (Const32 [m]) (ZeroExt8to32 x)) (Const64 [s]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(1<<8+umagic8(c).m) && s == 8+umagic8(c).s && x.Op != OpConst8 && udivisibleOK8(c)
	// result: (Leq8U (RotateLeft8 <typ.UInt8> (Mul8 <typ.UInt8> (Const8 <typ.UInt8> [int8(udivisible8(c).m)]) x) (Const8 <typ.UInt8> [int8(8-udivisible8(c).k)]) ) (Const8 <typ.UInt8> [int8(udivisible8(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst8 {
					continue
				}
				c := auxIntToInt8(v_1_0.AuxInt)
				if v_1_1.Op != OpTrunc32to8 {
					continue
				}
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh32Ux64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				mul := v_1_1_0.Args[0]
				if mul.Op != OpMul32 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst32 {
						continue
					}
					m := auxIntToInt32(mul_0.AuxInt)
					if mul_1.Op != OpZeroExt8to32 || x != mul_1.Args[0] {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(1<<8+umagic8(c).m) && s == 8+umagic8(c).s && x.Op != OpConst8 && udivisibleOK8(c)) {
						continue
					}
					v.reset(OpLeq8U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft8, typ.UInt8)
					v1 := b.NewValue0(v.Pos, OpMul8, typ.UInt8)
					v2 := b.NewValue0(v.Pos, OpConst8, typ.UInt8)
					v2.AuxInt = int8ToAuxInt(int8(udivisible8(c).m))
					v1.AddArg2(v2, x)
					v3 := b.NewValue0(v.Pos, OpConst8, typ.UInt8)
					v3.AuxInt = int8ToAuxInt(int8(8 - udivisible8(c).k))
					v0.AddArg2(v1, v3)
					v4 := b.NewValue0(v.Pos, OpConst8, typ.UInt8)
					v4.AuxInt = int8ToAuxInt(int8(udivisible8(c).max))
					v.AddArg2(v0, v4)
					return true
				}
			}
		}
		break
	}
	// match: (Eq8 x (Mul8 (Const8 [c]) (Sub8 (Rsh32x64 mul:(Mul32 (Const32 [m]) (SignExt8to32 x)) (Const64 [s])) (Rsh32x64 (SignExt8to32 x) (Const64 [31]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(smagic8(c).m) && s == 8+smagic8(c).s && x.Op != OpConst8 && sdivisibleOK8(c)
	// result: (Leq8U (RotateLeft8 <typ.UInt8> (Add8 <typ.UInt8> (Mul8 <typ.UInt8> (Const8 <typ.UInt8> [int8(sdivisible8(c).m)]) x) (Const8 <typ.UInt8> [int8(sdivisible8(c).a)]) ) (Const8 <typ.UInt8> [int8(8-sdivisible8(c).k)]) ) (Const8 <typ.UInt8> [int8(sdivisible8(c).max)]) )
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMul8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst8 {
					continue
				}
				c := auxIntToInt8(v_1_0.AuxInt)
				if v_1_1.Op != OpSub8 {
					continue
				}
				_ = v_1_1.Args[1]
				v_1_1_0 := v_1_1.Args[0]
				if v_1_1_0.Op != OpRsh32x64 {
					continue
				}
				_ = v_1_1_0.Args[1]
				mul := v_1_1_0.Args[0]
				if mul.Op != OpMul32 {
					continue
				}
				_ = mul.Args[1]
				mul_0 := mul.Args[0]
				mul_1 := mul.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, mul_0, mul_1 = _i2+1, mul_1, mul_0 {
					if mul_0.Op != OpConst32 {
						continue
					}
					m := auxIntToInt32(mul_0.AuxInt)
					if mul_1.Op != OpSignExt8to32 || x != mul_1.Args[0] {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					v_1_1_1 := v_1_1.Args[1]
					if v_1_1_1.Op != OpRsh32x64 {
						continue
					}
					_ = v_1_1_1.Args[1]
					v_1_1_1_0 := v_1_1_1.Args[0]
					if v_1_1_1_0.Op != OpSignExt8to32 || x != v_1_1_1_0.Args[0] {
						continue
					}
					v_1_1_1_1 := v_1_1_1.Args[1]
					if v_1_1_1_1.Op != OpConst64 || auxIntToInt64(v_1_1_1_1.AuxInt) != 31 || !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(smagic8(c).m) && s == 8+smagic8(c).s && x.Op != OpConst8 && sdivisibleOK8(c)) {
						continue
					}
					v.reset(OpLeq8U)
					v0 := b.NewValue0(v.Pos, OpRotateLeft8, typ.UInt8)
					v1 := b.NewValue0(v.Pos, OpA
"""




```