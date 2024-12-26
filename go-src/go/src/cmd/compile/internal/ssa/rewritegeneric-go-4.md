Response:

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第5部分，共13部分，请归纳一下它的功能

"""
dd8, typ.UInt8)
					v2 := b.NewValue0(v.Pos, OpMul8, typ.UInt8)
					v3 := b.NewValue0(v.Pos, OpConst8, typ.UInt8)
					v3.AuxInt = int8ToAuxInt(int8(sdivisible8(c).m))
					v2.AddArg2(v3, x)
					v4 := b.NewValue0(v.Pos, OpConst8, typ.UInt8)
					v4.AuxInt = int8ToAuxInt(int8(sdivisible8(c).a))
					v1.AddArg2(v2, v4)
					v5 := b.NewValue0(v.Pos, OpConst8, typ.UInt8)
					v5.AuxInt = int8ToAuxInt(int8(8 - sdivisible8(c).k))
					v0.AddArg2(v1, v5)
					v6 := b.NewValue0(v.Pos, OpConst8, typ.UInt8)
					v6.AuxInt = int8ToAuxInt(int8(sdivisible8(c).max))
					v.AddArg2(v0, v6)
					return true
				}
			}
		}
		break
	}
	// match: (Eq8 n (Lsh8x64 (Rsh8x64 (Add8 <t> n (Rsh8Ux64 <t> (Rsh8x64 <t> n (Const64 <typ.UInt64> [ 7])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 7 && kbar == 8 - k
	// result: (Eq8 (And8 <t> n (Const8 <t> [1<<uint(k)-1])) (Const8 <t> [0]))
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
				v.reset(OpEq8)
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
	// match: (Eq8 s:(Sub8 x y) (Const8 [0]))
	// cond: s.Uses == 1
	// result: (Eq8 x y)
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
			v.reset(OpEq8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Eq8 (And8 <t> x (Const8 <t> [y])) (Const8 <t> [y]))
	// cond: oneBit8(y)
	// result: (Neq8 (And8 <t> x (Const8 <t> [y])) (Const8 <t> [0]))
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
				v.reset(OpNeq8)
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
func rewriteValuegeneric_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (EqB (ConstBool [c]) (ConstBool [d]))
	// result: (ConstBool [c == d])
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
			v.AuxInt = boolToAuxInt(c == d)
			return true
		}
		break
	}
	// match: (EqB (ConstBool [false]) x)
	// result: (Not x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstBool || auxIntToBool(v_0.AuxInt) != false {
				continue
			}
			x := v_1
			v.reset(OpNot)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (EqB (ConstBool [true]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstBool || auxIntToBool(v_0.AuxInt) != true {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpEqInter(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqInter x y)
	// result: (EqPtr (ITab x) (ITab y))
	for {
		x := v_0
		y := v_1
		v.reset(OpEqPtr)
		v0 := b.NewValue0(v.Pos, OpITab, typ.Uintptr)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpITab, typ.Uintptr)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuegeneric_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqPtr x x)
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
	// match: (EqPtr (Addr {x} _) (Addr {y} _))
	// result: (ConstBool [x == y])
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
			v.AuxInt = boolToAuxInt(x == y)
			return true
		}
		break
	}
	// match: (EqPtr (Addr {x} _) (OffPtr [o] (Addr {y} _)))
	// result: (ConstBool [x == y && o == 0])
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
			v.AuxInt = boolToAuxInt(x == y && o == 0)
			return true
		}
		break
	}
	// match: (EqPtr (OffPtr [o1] (Addr {x} _)) (OffPtr [o2] (Addr {y} _)))
	// result: (ConstBool [x == y && o1 == o2])
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
			v.AuxInt = boolToAuxInt(x == y && o1 == o2)
			return true
		}
		break
	}
	// match: (EqPtr (LocalAddr {x} _ _) (LocalAddr {y} _ _))
	// result: (ConstBool [x == y])
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
			v.AuxInt = boolToAuxInt(x == y)
			return true
		}
		break
	}
	// match: (EqPtr (LocalAddr {x} _ _) (OffPtr [o] (LocalAddr {y} _ _)))
	// result: (ConstBool [x == y && o == 0])
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
			v.AuxInt = boolToAuxInt(x == y && o == 0)
			return true
		}
		break
	}
	// match: (EqPtr (OffPtr [o1] (LocalAddr {x} _ _)) (OffPtr [o2] (LocalAddr {y} _ _)))
	// result: (ConstBool [x == y && o1 == o2])
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
			v.AuxInt = boolToAuxInt(x == y && o1 == o2)
			return true
		}
		break
	}
	// match: (EqPtr (OffPtr [o1] p1) p2)
	// cond: isSamePtr(p1, p2)
	// result: (ConstBool [o1 == 0])
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
			v.AuxInt = boolToAuxInt(o1 == 0)
			return true
		}
		break
	}
	// match: (EqPtr (OffPtr [o1] p1) (OffPtr [o2] p2))
	// cond: isSamePtr(p1, p2)
	// result: (ConstBool [o1 == o2])
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
			v.AuxInt = boolToAuxInt(o1 == o2)
			return true
		}
		break
	}
	// match: (EqPtr (Const32 [c]) (Const32 [d]))
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
	// match: (EqPtr (Const64 [c]) (Const64 [d]))
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
	// match: (EqPtr (Convert (Addr {x} _) _) (Addr {y} _))
	// result: (ConstBool [x==y])
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
			v.AuxInt = boolToAuxInt(x == y)
			return true
		}
		break
	}
	// match: (EqPtr (LocalAddr _ _) (Addr _))
	// result: (ConstBool [false])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLocalAddr || v_1.Op != OpAddr {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (EqPtr (OffPtr (LocalAddr _ _)) (Addr _))
	// result: (ConstBool [false])
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
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (EqPtr (LocalAddr _ _) (OffPtr (Addr _)))
	// result: (ConstBool [false])
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
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (EqPtr (OffPtr (LocalAddr _ _)) (OffPtr (Addr _)))
	// result: (ConstBool [false])
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
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (EqPtr (AddPtr p1 o1) p2)
	// cond: isSamePtr(p1, p2)
	// result: (Not (IsNonNil o1))
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
			v.reset(OpNot)
			v0 := b.NewValue0(v.Pos, OpIsNonNil, typ.Bool)
			v0.AddArg(o1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (EqPtr (Const32 [0]) p)
	// result: (Not (IsNonNil p))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
				continue
			}
			p := v_1
			v.reset(OpNot)
			v0 := b.NewValue0(v.Pos, OpIsNonNil, typ.Bool)
			v0.AddArg(p)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (EqPtr (Const64 [0]) p)
	// result: (Not (IsNonNil p))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			p := v_1
			v.reset(OpNot)
			v0 := b.NewValue0(v.Pos, OpIsNonNil, typ.Bool)
			v0.AddArg(p)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (EqPtr (ConstNil) p)
	// result: (Not (IsNonNil p))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstNil {
				continue
			}
			p := v_1
			v.reset(OpNot)
			v0 := b.NewValue0(v.Pos, OpIsNonNil, typ.Bool)
			v0.AddArg(p)
			v.AddArg(v0)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpEqSlice(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqSlice x y)
	// result: (EqPtr (SlicePtr x) (SlicePtr y))
	for {
		x := v_0
		y := v_1
		v.reset(OpEqPtr)
		v0 := b.NewValue0(v.Pos, OpSlicePtr, typ.BytePtr)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSlicePtr, typ.BytePtr)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuegeneric_OpFloor(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Floor (Const64F [c]))
	// result: (Const64F [math.Floor(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(math.Floor(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpIMake(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (IMake _typ (StructMake val))
	// result: (IMake _typ val)
	for {
		_typ := v_0
		if v_1.Op != OpStructMake || len(v_1.Args) != 1 {
			break
		}
		val := v_1.Args[0]
		v.reset(OpIMake)
		v.AddArg2(_typ, val)
		return true
	}
	// match: (IMake _typ (ArrayMake1 val))
	// result: (IMake _typ val)
	for {
		_typ := v_0
		if v_1.Op != OpArrayMake1 {
			break
		}
		val := v_1.Args[0]
		v.reset(OpIMake)
		v.AddArg2(_typ, val)
		return true
	}
	return false
}
func rewriteValuegeneric_OpInterLECall(v *Value) bool {
	// match: (InterLECall [argsize] {auxCall} (Addr {fn} (SB)) ___)
	// result: devirtLECall(v, fn.(*obj.LSym))
	for {
		if len(v.Args) < 1 {
			break
		}
		v_0 := v.Args[0]
		if v_0.Op != OpAddr {
			break
		}
		fn := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB {
			break
		}
		v.copyOf(devirtLECall(v, fn.(*obj.LSym)))
		return true
	}
	return false
}
func rewriteValuegeneric_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (IsInBounds (ZeroExt8to32 _) (Const32 [c]))
	// cond: (1 << 8) <= c
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt8to32 || v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !((1 << 8) <= c) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (ZeroExt8to64 _) (Const64 [c]))
	// cond: (1 << 8) <= c
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt8to64 || v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !((1 << 8) <= c) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (ZeroExt16to32 _) (Const32 [c]))
	// cond: (1 << 16) <= c
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt16to32 || v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !((1 << 16) <= c) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (ZeroExt16to64 _) (Const64 [c]))
	// cond: (1 << 16) <= c
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt16to64 || v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !((1 << 16) <= c) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds x x)
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
	// match: (IsInBounds (And8 (Const8 [c]) _) (Const8 [d]))
	// cond: 0 <= c && c < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAnd8 {
			break
		}
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1.AuxInt)
			if !(0 <= c && c < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (ZeroExt8to16 (And8 (Const8 [c]) _)) (Const16 [d]))
	// cond: 0 <= c && int16(c) < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt8to16 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAnd8 {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0_0, v_0_0_1 = _i0+1, v_0_0_1, v_0_0_0 {
			if v_0_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0_0.AuxInt)
			if v_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1.AuxInt)
			if !(0 <= c && int16(c) < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (ZeroExt8to32 (And8 (Const8 [c]) _)) (Const32 [d]))
	// cond: 0 <= c && int32(c) < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt8to32 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAnd8 {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0_0, v_0_0_1 = _i0+1, v_0_0_1, v_0_0_0 {
			if v_0_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			if !(0 <= c && int32(c) < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (ZeroExt8to64 (And8 (Const8 [c]) _)) (Const64 [d]))
	// cond: 0 <= c && int64(c) < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt8to64 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAnd8 {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0_0, v_0_0_1 = _i0+1, v_0_0_1, v_0_0_0 {
			if v_0_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			if !(0 <= c && int64(c) < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (And16 (Const16 [c]) _) (Const16 [d]))
	// cond: 0 <= c && c < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAnd16 {
			break
		}
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1.AuxInt)
			if !(0 <= c && c < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (ZeroExt16to32 (And16 (Const16 [c]) _)) (Const32 [d]))
	// cond: 0 <= c && int32(c) < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt16to32 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAnd16 {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0_0, v_0_0_1 = _i0+1, v_0_0_1, v_0_0_0 {
			if v_0_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			if !(0 <= c && int32(c) < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (ZeroExt16to64 (And16 (Const16 [c]) _)) (Const64 [d]))
	// cond: 0 <= c && int64(c) < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt16to64 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAnd16 {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0_0, v_0_0_1 = _i0+1, v_0_0_1, v_0_0_0 {
			if v_0_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			if !(0 <= c && int64(c) < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (And32 (Const32 [c]) _) (Const32 [d]))
	// cond: 0 <= c && c < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAnd32 {
			break
		}
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			if !(0 <= c && c < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (ZeroExt32to64 (And32 (Const32 [c]) _)) (Const64 [d]))
	// cond: 0 <= c && int64(c) < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt32to64 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAnd32 {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0_0, v_0_0_1 = _i0+1, v_0_0_1, v_0_0_0 {
			if v_0_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			if !(0 <= c && int64(c) < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (And64 (Const64 [c]) _) (Const64 [d]))
	// cond: 0 <= c && c < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAnd64 {
			break
		}
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			if !(0 <= c && c < d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsInBounds (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [0 <= c && c < d])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(0 <= c && c < d)
		return true
	}
	// match: (IsInBounds (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [0 <= c && c < d])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(0 <= c && c < d)
		return true
	}
	// match: (IsInBounds (Mod32u _ y) y)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpMod32u {
			break
		}
		y := v_0.Args[1]
		if y != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (Mod64u _ y) y)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpMod64u {
			break
		}
		y := v_0.Args[1]
		if y != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (ZeroExt8to64 (Rsh8Ux64 _ (Const64 [c]))) (Const64 [d]))
	// cond: 0 < c && c < 8 && 1<<uint( 8-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt8to64 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh8Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(0 < c && c < 8 && 1<<uint(8-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (ZeroExt8to32 (Rsh8Ux64 _ (Const64 [c]))) (Const32 [d]))
	// cond: 0 < c && c < 8 && 1<<uint( 8-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt8to32 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh8Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_0_1.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		if !(0 < c && c < 8 && 1<<uint(8-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (ZeroExt8to16 (Rsh8Ux64 _ (Const64 [c]))) (Const16 [d]))
	// cond: 0 < c && c < 8 && 1<<uint( 8-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt8to16 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh8Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_0_1.AuxInt)
		if v_1.Op != OpConst16 {
			break
		}
		d := auxIntToInt16(v_1.AuxInt)
		if !(0 < c && c < 8 && 1<<uint(8-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (Rsh8Ux64 _ (Const64 [c])) (Const64 [d]))
	// cond: 0 < c && c < 8 && 1<<uint( 8-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpRsh8Ux64 {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(0 < c && c < 8 && 1<<uint(8-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (ZeroExt16to64 (Rsh16Ux64 _ (Const64 [c]))) (Const64 [d]))
	// cond: 0 < c && c < 16 && 1<<uint(16-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt16to64 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh16Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(0 < c && c < 16 && 1<<uint(16-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (ZeroExt16to32 (Rsh16Ux64 _ (Const64 [c]))) (Const64 [d]))
	// cond: 0 < c && c < 16 && 1<<uint(16-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt16to32 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh16Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(0 < c && c < 16 && 1<<uint(16-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (Rsh16Ux64 _ (Const64 [c])) (Const64 [d]))
	// cond: 0 < c && c < 16 && 1<<uint(16-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpRsh16Ux64 {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(0 < c && c < 16 && 1<<uint(16-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (ZeroExt32to64 (Rsh32Ux64 _ (Const64 [c]))) (Const64 [d]))
	// cond: 0 < c && c < 32 && 1<<uint(32-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpZeroExt32to64 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh32Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(0 < c && c < 32 && 1<<uint(32-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (Rsh32Ux64 _ (Const64 [c])) (Const64 [d]))
	// cond: 0 < c && c < 32 && 1<<uint(32-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpRsh32Ux64 {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(0 < c && c < 32 && 1<<uint(32-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsInBounds (Rsh64Ux64 _ (Const64 [c])) (Const64 [d]))
	// cond: 0 < c && c < 64 && 1<<uint(64-c)-1 < d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpRsh64Ux64 {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(0 < c && c < 64 && 1<<uint(64-c)-1 < d) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	return false
}
func rewriteValuegeneric_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	// match: (IsNonNil (ConstNil))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpConstNil {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (IsNonNil (Const32 [c]))
	// result: (ConstBool [c != 0])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c != 0)
		return true
	}
	// match: (IsNonNil (Const64 [c]))
	// result: (ConstBool [c != 0])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c != 0)
		return true
	}
	// match: (IsNonNil (Addr _) )
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAddr {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsNonNil (Convert (Addr _) _))
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConvert {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAddr {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsNonNil (LocalAddr _ _))
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpLocalAddr {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	return false
}
func rewriteValuegeneric_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (IsSliceInBounds x x)
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
	// match: (IsSliceInBounds (And32 (Const32 [c]) _) (Const32 [d]))
	// cond: 0 <= c && c <= d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAnd32 {
			break
		}
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			if !(0 <= c && c <= d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsSliceInBounds (And64 (Const64 [c]) _) (Const64 [d]))
	// cond: 0 <= c && c <= d
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpAnd64 {
			break
		}
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			if !(0 <= c && c <= d) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (IsSliceInBounds (Const32 [0]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsSliceInBounds (Const64 [0]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (IsSliceInBounds (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [0 <= c && c <= d])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(0 <= c && c <= d)
		return true
	}
	// match: (IsSliceInBounds (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [0 <= c && c <= d])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(0 <= c && c <= d)
		return true
	}
	// match: (IsSliceInBounds (SliceLen x) (SliceCap x))
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpSliceLen {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpSliceCap || x != v_1.Args[0] {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq16 (Const16 [c]) (Const16 [d]))
	// result: (ConstBool [c <= d])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst16 {
			break
		}
		d := auxIntToInt16(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c <= d)
		return true
	}
	// match: (Leq16 (Const16 [0]) (And16 _ (Const16 [c])))
	// cond: c >= 0
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 || v_1.Op != OpAnd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c >= 0) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (Leq16 (Const16 [0]) (Rsh16Ux64 _ (Const64 [c])))
	// cond: c > 0
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 || v_1.Op != OpRsh16Ux64 {
			break
		}
		_ = v_1.Args[1]
		v_1_1 := v_1.Args[1]
		if v_1_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_1.AuxInt)
		if !(c > 0) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq16 x (Const16 <t> [-1]))
	// result: (Less16 x (Const16 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		t := v_1.Type
		if auxIntToInt16(v_1.AuxInt) != -1 {
			break
		}
		v.reset(OpLess16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Leq16 (Const16 <t> [1]) x)
	// result: (Less16 (Const16 <t> [0]) x)
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		if auxIntToInt16(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpLess16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq16 (Const16 [math.MinInt16]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != math.MinInt16 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq16 _ (Const16 [math.MaxInt16]))
	// result: (ConstBool [true])
	for {
		if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != math.MaxInt16 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq16 x c:(Const16 [math.MinInt16]))
	// result: (Eq16 x c)
	for {
		x := v_0
		c := v_1
		if c.Op != OpConst16 || auxIntToInt16(c.AuxInt) != math.MinInt16 {
			break
		}
		v.reset(OpEq16)
		v.AddArg2(x, c)
		return true
	}
	// match: (Leq16 c:(Const16 [math.MaxInt16]) x)
	// result: (Eq16 x c)
	for {
		c := v_0
		if c.Op != OpConst16 || auxIntToInt16(c.AuxInt) != math.MaxInt16 {
			break
		}
		x := v_1
		v.reset(OpEq16)
		v.AddArg2(x, c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq16U (Const16 [c]) (Const16 [d]))
	// result: (ConstBool [uint16(c) <= uint16(d)])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst16 {
			break
		}
		d := auxIntToInt16(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(uint16(c) <= uint16(d))
		return true
	}
	// match: (Leq16U (Const16 <t> [1]) x)
	// result: (Neq16 (Const16 <t> [0]) x)
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		if auxIntToInt16(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq16U (Const16 [0]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq16U _ (Const16 [-1]))
	// result: (ConstBool [true])
	for {
		if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != -1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq16U x c:(Const16 [0]))
	// result: (Eq16 x c)
	for {
		x := v_0
		c := v_1
		if c.Op != OpConst16 || auxIntToInt16(c.AuxInt) != 0 {
			break
		}
		v.reset(OpEq16)
		v.AddArg2(x, c)
		return true
	}
	// match: (Leq16U c:(Const16 [-1]) x)
	// result: (Eq16 x c)
	for {
		c := v_0
		if c.Op != OpConst16 || auxIntToInt16(c.AuxInt) != -1 {
			break
		}
		x := v_1
		v.reset(OpEq16)
		v.AddArg2(x, c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32 (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [c <= d])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c <= d)
		return true
	}
	// match: (Leq32 (Const32 [0]) (And32 _ (Const32 [c])))
	// cond: c >= 0
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 || v_1.Op != OpAnd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c >= 0) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (Leq32 (Const32 [0]) (Rsh32Ux64 _ (Const64 [c])))
	// cond: c > 0
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 || v_1.Op != OpRsh32Ux64 {
			break
		}
		_ = v_1.Args[1]
		v_1_1 := v_1.Args[1]
		if v_1_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_1.AuxInt)
		if !(c > 0) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq32 x (Const32 <t> [-1]))
	// result: (Less32 x (Const32 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		t := v_1.Type
		if auxIntToInt32(v_1.AuxInt) != -1 {
			break
		}
		v.reset(OpLess32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Leq32 (Const32 <t> [1]) x)
	// result: (Less32 (Const32 <t> [0]) x)
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		if auxIntToInt32(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpLess32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq32 (Const32 [math.MinInt32]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != math.MinInt32 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq32 _ (Const32 [math.MaxInt32]))
	// result: (ConstBool [true])
	for {
		if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != math.MaxInt32 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq32 x c:(Const32 [math.MinInt32]))
	// result: (Eq32 x c)
	for {
		x := v_0
		c := v_1
		if c.Op != OpConst32 || auxIntToInt32(c.AuxInt) != math.MinInt32 {
			break
		}
		v.reset(OpEq32)
		v.AddArg2(x, c)
		return true
	}
	// match: (Leq32 c:(Const32 [math.MaxInt32]) x)
	// result: (Eq32 x c)
	for {
		c := v_0
		if c.Op != OpConst32 || auxIntToInt32(c.AuxInt) != math.MaxInt32 {
			break
		}
		x := v_1
		v.reset(OpEq32)
		v.AddArg2(x, c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Leq32F (Const32F [c]) (Const32F [d]))
	// result: (ConstBool [c <= d])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		if v_1.Op != OpConst32F {
			break
		}
		d := auxIntToFloat32(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c <= d)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32U (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [uint32(c) <= uint32(d)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(uint32(c) <= uint32(d))
		return true
	}
	// match: (Leq32U (Const32 <t> [1]) x)
	// result: (Neq32 (Const32 <t> [0]) x)
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		if auxIntToInt32(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq32U (Const32 [0]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq32U _ (Const32 [-1]))
	// result: (ConstBool [true])
	for {
		if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != -1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq32U x c:(Const32 [0]))
	// result: (Eq32 x c)
	for {
		x := v_0
		c := v_1
		if c.Op != OpConst32 || auxIntToInt32(c.AuxInt) != 0 {
			break
		}
		v.reset(OpEq32)
		v.AddArg2(x, c)
		return true
	}
	// match: (Leq32U c:(Const32 [-1]) x)
	// result: (Eq32 x c)
	for {
		c := v_0
		if c.Op != OpConst32 || auxIntToInt32(c.AuxInt) != -1 {
			break
		}
		x := v_1
		v.reset(OpEq32)
		v.AddArg2(x, c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64 (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [c <= d])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c <= d)
		return true
	}
	// match: (Leq64 (Const64 [0]) (And64 _ (Const64 [c])))
	// cond: c >= 0
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 || v_1.Op != OpAnd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= 0) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (Leq64 (Const64 [0]) (Rsh64Ux64 _ (Const64 [c])))
	// cond: c > 0
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 || v_1.Op != OpRsh64Ux64 {
			break
		}
		_ = v_1.Args[1]
		v_1_1 := v_1.Args[1]
		if v_1_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_1.AuxInt)
		if !(c > 0) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq64 x (Const64 <t> [-1]))
	// result: (Less64 x (Const64 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != -1 {
			break
		}
		v.reset(OpLess64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Leq64 (Const64 <t> [1]) x)
	// result: (Less64 (Const64 <t> [0]) x)
	for {
		if v_0.Op != OpConst64 {
			break
		}
		t := v_0.Type
		if auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpLess64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq64 (Const64 [math.MinInt64]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != math.MinInt64 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq64 _ (Const64 [math.MaxInt64]))
	// result: (ConstBool [true])
	for {
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != math.MaxInt64 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq64 x c:(Const64 [math.MinInt64]))
	// result: (Eq64 x c)
	for {
		x := v_0
		c := v_1
		if c.Op != OpConst64 || auxIntToInt64(c.AuxInt) != math.MinInt64 {
			break
		}
		v.reset(OpEq64)
		v.AddArg2(x, c)
		return true
	}
	// match: (Leq64 c:(Const64 [math.MaxInt64]) x)
	// result: (Eq64 x c)
	for {
		c := v_0
		if c.Op != OpConst64 || auxIntToInt64(c.AuxInt) != math.MaxInt64 {
			break
		}
		x := v_1
		v.reset(OpEq64)
		v.AddArg2(x, c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Leq64F (Const64F [c]) (Const64F [d]))
	// result: (ConstBool [c <= d])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		if v_1.Op != OpConst64F {
			break
		}
		d := auxIntToFloat64(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c <= d)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64U (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [uint64(c) <= uint64(d)])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(uint64(c) <= uint64(d))
		return true
	}
	// match: (Leq64U (Const64 <t> [1]) x)
	// result: (Neq64 (Const64 <t> [0]) x)
	for {
		if v_0.Op != OpConst64 {
			break
		}
		t := v_0.Type
		if auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq64U (Const64 [0]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq64U _ (Const64 [-1]))
	// result: (ConstBool [true])
	for {
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != -1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq64U x c:(Const64 [0]))
	// result: (Eq64 x c)
	for {
		x := v_0
		c := v_1
		if c.Op != OpConst64 || auxIntToInt64(c.AuxInt) != 0 {
			break
		}
		v.reset(OpEq64)
		v.AddArg2(x, c)
		return true
	}
	// match: (Leq64U c:(Const64 [-1]) x)
	// result: (Eq64 x c)
	for {
		c := v_0
		if c.Op != OpConst64 || auxIntToInt64(c.AuxInt) != -1 {
			break
		}
		x := v_1
		v.reset(OpEq64)
		v.AddArg2(x, c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq8 (Const8 [c]) (Const8 [d]))
	// result: (ConstBool [c <= d])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst8 {
			break
		}
		d := auxIntToInt8(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c <= d)
		return true
	}
	// match: (Leq8 (Const8 [0]) (And8 _ (Const8 [c])))
	// cond: c >= 0
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 || v_1.Op != OpAnd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c >= 0) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (Leq8 (Const8 [0]) (Rsh8Ux64 _ (Const64 [c])))
	// cond: c > 0
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 || v_1.Op != OpRsh8Ux64 {
			break
		}
		_ = v_1.Args[1]
		v_1_1 := v_1.Args[1]
		if v_1_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_1.AuxInt)
		if !(c > 0) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq8 x (Const8 <t> [-1]))
	// result: (Less8 x (Const8 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		t := v_1.Type
		if auxIntToInt8(v_1.AuxInt) != -1 {
			break
		}
		v.reset(OpLess8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Leq8 (Const8 <t> [1]) x)
	// result: (Less8 (Const8 <t> [0]) x)
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		if auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpLess8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq8 (Const8 [math.MinInt8 ]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != math.MinInt8 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq8 _ (Const8 [math.MaxInt8 ]))
	// result: (ConstBool [true])
	for {
		if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != math.MaxInt8 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq8 x c:(Const8 [math.MinInt8 ]))
	// result: (Eq8 x c)
	for {
		x := v_0
		c := v_1
		if c.Op != OpConst8 || auxIntToInt8(c.AuxInt) != math.MinInt8 {
			break
		}
		v.reset(OpEq8)
		v.AddArg2(x, c)
		return true
	}
	// match: (Leq8 c:(Const8 [math.MaxInt8 ]) x)
	// result: (Eq8 x c)
	for {
		c := v_0
		if c.Op != OpConst8 || auxIntToInt8(c.AuxInt) != math.MaxInt8 {
			break
		}
		x := v_1
		v.reset(OpEq8)
		v.AddArg2(x, c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq8U (Const8 [c]) (Const8 [d]))
	// result: (ConstBool [ uint8(c) <= uint8(d)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst8 {
			break
		}
		d := auxIntToInt8(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(uint8(c) <= uint8(d))
		return true
	}
	// match: (Leq8U (Const8 <t> [1]) x)
	// result: (Neq8 (Const8 <t> [0]) x)
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		if auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq8U (Const8 [0]) _)
	// result: (ConstBool [true])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq8U _ (Const8 [-1]))
	// result: (ConstBool [true])
	for {
		if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != -1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(true)
		return true
	}
	// match: (Leq8U x c:(Const8 [0]))
	// result: (Eq8 x c)
	for {
		x := v_0
		c := v_1
		if c.Op != OpConst8 || auxIntToInt8(c.AuxInt) != 0 {
			break
		}
		v.reset(OpEq8)
		v.AddArg2(x, c)
		return true
	}
	// match: (Leq8U c:(Const8 [-1]) x)
	// result: (Eq8 x c)
	for {
		c := v_0
		if c.Op != OpConst8 || auxIntToInt8(c.AuxInt) != -1 {
			break
		}
		x := v_1
		v.reset(OpEq8)
		v.AddArg2(x, c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less16 (Const16 [c]) (Const16 [d]))
	// result: (ConstBool [c < d])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst16 {
			break
		}
		d := auxIntToInt16(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c < d)
		return true
	}
	// match: (Less16 (Const16 <t> [0]) x)
	// cond: isNonNegative(x)
	// result: (Neq16 (Const16 <t> [0]) x)
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		if auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		if !(isNonNegative(x)) {
			break
		}
		v.reset(OpNeq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less16 x (Const16 <t> [1]))
	// cond: isNonNegative(x)
	// result: (Eq16 (Const16 <t> [0]) x)
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		t := v_1.Type
		if auxIntToInt16(v_1.AuxInt) != 1 || !(isNonNegative(x)) {
			break
		}
		v.reset(OpEq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less16 x (Const16 <t> [1]))
	// result: (Leq16 x (Const16 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		t := v_1.Type
		if auxIntToInt16(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpLeq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less16 (Const16 <t> [-1]) x)
	// result: (Leq16 (Const16 <t> [0]) x)
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		if auxIntToInt16(v_0.AuxInt) != -1 {
			break
		}
		x := v_1
		v.reset(OpLeq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less16 _ (Const16 [math.MinInt16]))
	// result: (ConstBool [false])
	for {
		if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != math.MinInt16 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less16 (Const16 [math.MaxInt16]) _)
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != math.MaxInt16 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less16 x (Const16 <t> [math.MinInt16+1]))
	// result: (Eq16 x (Const16 <t> [math.MinInt16]))
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		t := v_1.Type
		if auxIntToInt16(v_1.AuxInt) != math.MinInt16+1 {
			break
		}
		v.reset(OpEq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(math.MinInt16)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less16 (Const16 <t> [math.MaxInt16-1]) x)
	// result: (Eq16 x (Const16 <t> [math.MaxInt16]))
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		if auxIntToInt16(v_0.AuxInt) != math.MaxInt16-1 {
			break
		}
		x := v_1
		v.reset(OpEq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(math.MaxInt16)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less16U (Const16 [c]) (Const16 [d]))
	// result: (ConstBool [uint16(c) < uint16(d)])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst16 {
			break
		}
		d := auxIntToInt16(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(uint16(c) < uint16(d))
		return true
	}
	// match: (Less16U x (Const16 <t> [1]))
	// result: (Eq16 (Const16 <t> [0]) x)
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		t := v_1.Type
		if auxIntToInt16(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less16U _ (Const16 [0]))
	// result: (ConstBool [false])
	for {
		if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less16U (Const16 [-1]) _)
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != -1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less16U x (Const16 <t> [1]))
	// result: (Eq16 x (Const16 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		t := v_1.Type
		if auxIntToInt16(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less16U (Const16 <t> [-2]) x)
	// result: (Eq16 x (Const16 <t> [-1]))
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		if auxIntToInt16(v_0.AuxInt) != -2 {
			break
		}
		x := v_1
		v.reset(OpEq16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(-1)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32 (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [c < d])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c < d)
		return true
	}
	// match: (Less32 (Const32 <t> [0]) x)
	// cond: isNonNegative(x)
	// result: (Neq32 (Const32 <t> [0]) x)
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		if auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		if !(isNonNegative(x)) {
			break
		}
		v.reset(OpNeq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less32 x (Const32 <t> [1]))
	// cond: isNonNegative(x)
	// result: (Eq32 (Const32 <t> [0]) x)
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		t := v_1.Type
		if auxIntToInt32(v_1.AuxInt) != 1 || !(isNonNegative(x)) {
			break
		}
		v.reset(OpEq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less32 x (Const32 <t> [1]))
	// result: (Leq32 x (Const32 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		t := v_1.Type
		if auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpLeq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less32 (Const32 <t> [-1]) x)
	// result: (Leq32 (Const32 <t> [0]) x)
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		if auxIntToInt32(v_0.AuxInt) != -1 {
			break
		}
		x := v_1
		v.reset(OpLeq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less32 _ (Const32 [math.MinInt32]))
	// result: (ConstBool [false])
	for {
		if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != math.MinInt32 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less32 (Const32 [math.MaxInt32]) _)
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != math.MaxInt32 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less32 x (Const32 <t> [math.MinInt32+1]))
	// result: (Eq32 x (Const32 <t> [math.MinInt32]))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		t := v_1.Type
		if auxIntToInt32(v_1.AuxInt) != math.MinInt32+1 {
			break
		}
		v.reset(OpEq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(math.MinInt32)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less32 (Const32 <t> [math.MaxInt32-1]) x)
	// result: (Eq32 x (Const32 <t> [math.MaxInt32]))
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		if auxIntToInt32(v_0.AuxInt) != math.MaxInt32-1 {
			break
		}
		x := v_1
		v.reset(OpEq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(math.MaxInt32)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less32F (Const32F [c]) (Const32F [d]))
	// result: (ConstBool [c < d])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		if v_1.Op != OpConst32F {
			break
		}
		d := auxIntToFloat32(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c < d)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32U (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [uint32(c) < uint32(d)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(uint32(c) < uint32(d))
		return true
	}
	// match: (Less32U x (Const32 <t> [1]))
	// result: (Eq32 (Const32 <t> [0]) x)
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		t := v_1.Type
		if auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less32U _ (Const32 [0]))
	// result: (ConstBool [false])
	for {
		if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less32U (Const32 [-1]) _)
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != -1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less32U x (Const32 <t> [1]))
	// result: (Eq32 x (Const32 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		t := v_1.Type
		if auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less32U (Const32 <t> [-2]) x)
	// result: (Eq32 x (Const32 <t> [-1]))
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		if auxIntToInt32(v_0.AuxInt) != -2 {
			break
		}
		x := v_1
		v.reset(OpEq32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(-1)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64 (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [c < d])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c < d)
		return true
	}
	// match: (Less64 (Const64 <t> [0]) x)
	// cond: isNonNegative(x)
	// result: (Neq64 (Const64 <t> [0]) x)
	for {
		if v_0.Op 
"""




```