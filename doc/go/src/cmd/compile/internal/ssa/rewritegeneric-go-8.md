Response:

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第9部分，共13部分，请归纳一下它的功能

"""
 {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd16 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst16 {
					continue
				}
				c2 := auxIntToInt16(v_0_1.AuxInt)
				if v_1.Op != OpConst16 {
					continue
				}
				t := v_1.Type
				c1 := auxIntToInt16(v_1.AuxInt)
				if !(^(c1 | c2) == 0) {
					continue
				}
				v.reset(OpOr16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c1)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or16 (Or16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Or16 i (Or16 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOr16 {
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
				v.reset(OpOr16)
				v0 := b.NewValue0(v.Pos, OpOr16, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Or16 (Const16 <t> [c]) (Or16 (Const16 <t> [d]) x))
	// result: (Or16 (Const16 <t> [c|d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpOr16 {
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
				v.reset(OpOr16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c | d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or16 (Lsh16x64 x z:(Const64 <t> [c])) (Rsh16Ux64 x (Const64 [d])))
	// cond: c < 16 && d == 16-c && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh16x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh16Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 16 && d == 16-c && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or16 left:(Lsh16x64 x y) right:(Rsh16Ux64 x (Sub64 (Const64 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or16 left:(Lsh16x32 x y) right:(Rsh16Ux32 x (Sub32 (Const32 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or16 left:(Lsh16x16 x y) right:(Rsh16Ux16 x (Sub16 (Const16 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or16 left:(Lsh16x8 x y) right:(Rsh16Ux8 x (Sub8 (Const8 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or16 right:(Rsh16Ux64 x y) left:(Lsh16x64 x z:(Sub64 (Const64 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or16 right:(Rsh16Ux32 x y) left:(Lsh16x32 x z:(Sub32 (Const32 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or16 right:(Rsh16Ux16 x y) left:(Lsh16x16 x z:(Sub16 (Const16 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or16 right:(Rsh16Ux8 x y) left:(Lsh16x8 x z:(Sub8 (Const8 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpOr32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Or32 (Const32 [c]) (Const32 [d]))
	// result: (Const32 [c|d])
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
			v.AuxInt = int32ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (Or32 <t> (Com32 x) (Com32 y))
	// result: (Com32 (And32 <t> x y))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom32 {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpCom32 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpCom32)
			v0 := b.NewValue0(v.Pos, OpAnd32, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Or32 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Or32 (Const32 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Or32 (Const32 [-1]) _)
	// result: (Const32 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != -1 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or32 (Com32 x) x)
	// result: (Const32 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom32 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or32 x (Or32 x y))
	// result: (Or32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpOr32 {
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
				v.reset(OpOr32)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Or32 (And32 x (Const32 [c2])) (Const32 <t> [c1]))
	// cond: ^(c1 | c2) == 0
	// result: (Or32 (Const32 <t> [c1]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd32 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst32 {
					continue
				}
				c2 := auxIntToInt32(v_0_1.AuxInt)
				if v_1.Op != OpConst32 {
					continue
				}
				t := v_1.Type
				c1 := auxIntToInt32(v_1.AuxInt)
				if !(^(c1 | c2) == 0) {
					continue
				}
				v.reset(OpOr32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c1)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or32 (Or32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Or32 i (Or32 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOr32 {
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
				v.reset(OpOr32)
				v0 := b.NewValue0(v.Pos, OpOr32, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Or32 (Const32 <t> [c]) (Or32 (Const32 <t> [d]) x))
	// result: (Or32 (Const32 <t> [c|d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpOr32 {
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
				v.reset(OpOr32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c | d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or32 (Lsh32x64 x z:(Const64 <t> [c])) (Rsh32Ux64 x (Const64 [d])))
	// cond: c < 32 && d == 32-c && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh32x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh32Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 32 && d == 32-c && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or32 left:(Lsh32x64 x y) right:(Rsh32Ux64 x (Sub64 (Const64 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or32 left:(Lsh32x32 x y) right:(Rsh32Ux32 x (Sub32 (Const32 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or32 left:(Lsh32x16 x y) right:(Rsh32Ux16 x (Sub16 (Const16 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or32 left:(Lsh32x8 x y) right:(Rsh32Ux8 x (Sub8 (Const8 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or32 right:(Rsh32Ux64 x y) left:(Lsh32x64 x z:(Sub64 (Const64 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or32 right:(Rsh32Ux32 x y) left:(Lsh32x32 x z:(Sub32 (Const32 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or32 right:(Rsh32Ux16 x y) left:(Lsh32x16 x z:(Sub16 (Const16 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or32 right:(Rsh32Ux8 x y) left:(Lsh32x8 x z:(Sub8 (Const8 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpOr64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Or64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c|d])
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
			v.AuxInt = int64ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (Or64 <t> (Com64 x) (Com64 y))
	// result: (Com64 (And64 <t> x y))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom64 {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpCom64 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpCom64)
			v0 := b.NewValue0(v.Pos, OpAnd64, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Or64 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Or64 (Const64 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Or64 (Const64 [-1]) _)
	// result: (Const64 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != -1 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or64 (Com64 x) x)
	// result: (Const64 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom64 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or64 x (Or64 x y))
	// result: (Or64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpOr64 {
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
				v.reset(OpOr64)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Or64 (And64 x (Const64 [c2])) (Const64 <t> [c1]))
	// cond: ^(c1 | c2) == 0
	// result: (Or64 (Const64 <t> [c1]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd64 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst64 {
					continue
				}
				c2 := auxIntToInt64(v_0_1.AuxInt)
				if v_1.Op != OpConst64 {
					continue
				}
				t := v_1.Type
				c1 := auxIntToInt64(v_1.AuxInt)
				if !(^(c1 | c2) == 0) {
					continue
				}
				v.reset(OpOr64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c1)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or64 (Or64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Or64 i (Or64 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOr64 {
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
				v.reset(OpOr64)
				v0 := b.NewValue0(v.Pos, OpOr64, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Or64 (Const64 <t> [c]) (Or64 (Const64 <t> [d]) x))
	// result: (Or64 (Const64 <t> [c|d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpOr64 {
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
				v.reset(OpOr64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c | d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or64 (Lsh64x64 x z:(Const64 <t> [c])) (Rsh64Ux64 x (Const64 [d])))
	// cond: c < 64 && d == 64-c && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh64x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh64Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 64 && d == 64-c && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or64 left:(Lsh64x64 x y) right:(Rsh64Ux64 x (Sub64 (Const64 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or64 left:(Lsh64x32 x y) right:(Rsh64Ux32 x (Sub32 (Const32 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or64 left:(Lsh64x16 x y) right:(Rsh64Ux16 x (Sub16 (Const16 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or64 left:(Lsh64x8 x y) right:(Rsh64Ux8 x (Sub8 (Const8 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or64 right:(Rsh64Ux64 x y) left:(Lsh64x64 x z:(Sub64 (Const64 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or64 right:(Rsh64Ux32 x y) left:(Lsh64x32 x z:(Sub32 (Const32 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or64 right:(Rsh64Ux16 x y) left:(Lsh64x16 x z:(Sub16 (Const16 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or64 right:(Rsh64Ux8 x y) left:(Lsh64x8 x z:(Sub8 (Const8 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpOr8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Or8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c|d])
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
			v.AuxInt = int8ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (Or8 <t> (Com8 x) (Com8 y))
	// result: (Com8 (And8 <t> x y))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom8 {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpCom8 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpCom8)
			v0 := b.NewValue0(v.Pos, OpAnd8, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Or8 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Or8 (Const8 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Or8 (Const8 [-1]) _)
	// result: (Const8 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != -1 {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or8 (Com8 x) x)
	// result: (Const8 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom8 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or8 x (Or8 x y))
	// result: (Or8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpOr8 {
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
				v.reset(OpOr8)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Or8 (And8 x (Const8 [c2])) (Const8 <t> [c1]))
	// cond: ^(c1 | c2) == 0
	// result: (Or8 (Const8 <t> [c1]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd8 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst8 {
					continue
				}
				c2 := auxIntToInt8(v_0_1.AuxInt)
				if v_1.Op != OpConst8 {
					continue
				}
				t := v_1.Type
				c1 := auxIntToInt8(v_1.AuxInt)
				if !(^(c1 | c2) == 0) {
					continue
				}
				v.reset(OpOr8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c1)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or8 (Or8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Or8 i (Or8 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOr8 {
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
				v.reset(OpOr8)
				v0 := b.NewValue0(v.Pos, OpOr8, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Or8 (Const8 <t> [c]) (Or8 (Const8 <t> [d]) x))
	// result: (Or8 (Const8 <t> [c|d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpOr8 {
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
				v.reset(OpOr8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c | d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or8 (Lsh8x64 x z:(Const64 <t> [c])) (Rsh8Ux64 x (Const64 [d])))
	// cond: c < 8 && d == 8-c && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh8x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh8Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 8 && d == 8-c && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or8 left:(Lsh8x64 x y) right:(Rsh8Ux64 x (Sub64 (Const64 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or8 left:(Lsh8x32 x y) right:(Rsh8Ux32 x (Sub32 (Const32 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or8 left:(Lsh8x16 x y) right:(Rsh8Ux16 x (Sub16 (Const16 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or8 left:(Lsh8x8 x y) right:(Rsh8Ux8 x (Sub8 (Const8 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or8 right:(Rsh8Ux64 x y) left:(Lsh8x64 x z:(Sub64 (Const64 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or8 right:(Rsh8Ux32 x y) left:(Lsh8x32 x z:(Sub32 (Const32 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or8 right:(Rsh8Ux16 x y) left:(Lsh8x16 x z:(Sub16 (Const16 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or8 right:(Rsh8Ux8 x y) left:(Lsh8x8 x z:(Sub8 (Const8 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpOrB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (OrB (Less64 (Const64 [c]) x) (Less64 x (Const64 [d])))
	// cond: c >= d
	// result: (Less64U (Const64 <x.Type> [c-d]) (Sub64 <x.Type> x (Const64 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess64 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLess64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq64 (Const64 [c]) x) (Less64 x (Const64 [d])))
	// cond: c >= d
	// result: (Leq64U (Const64 <x.Type> [c-d]) (Sub64 <x.Type> x (Const64 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq64 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLess64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less32 (Const32 [c]) x) (Less32 x (Const32 [d])))
	// cond: c >= d
	// result: (Less32U (Const32 <x.Type> [c-d]) (Sub32 <x.Type> x (Const32 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess32 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLess32 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq32 (Const32 [c]) x) (Less32 x (Const32 [d])))
	// cond: c >= d
	// result: (Leq32U (Const32 <x.Type> [c-d]) (Sub32 <x.Type> x (Const32 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq32 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLess32 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLeq32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less16 (Const16 [c]) x) (Less16 x (Const16 [d])))
	// cond: c >= d
	// result: (Less16U (Const16 <x.Type> [c-d]) (Sub16 <x.Type> x (Const16 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess16 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLess16 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLess16U)
			v0 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v0.AuxInt = int16ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq16 (Const16 [c]) x) (Less16 x (Const16 [d])))
	// cond: c >= d
	// result: (Leq16U (Const16 <x.Type> [c-d]) (Sub16 <x.Type> x (Const16 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq16 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLess16 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLeq16U)
			v0 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v0.AuxInt = int16ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less8 (Const8 [c]) x) (Less8 x (Const8 [d])))
	// cond: c >= d
	// result: (Less8U (Const8 <x.Type> [c-d]) (Sub8 <x.Type> x (Const8 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess8 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLess8 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLess8U)
			v0 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v0.AuxInt = int8ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq8 (Const8 [c]) x) (Less8 x (Const8 [d])))
	// cond: c >= d
	// result: (Leq8U (Const8 <x.Type> [c-d]) (Sub8 <x.Type> x (Const8 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq8 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLess8 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLeq8U)
			v0 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v0.AuxInt = int8ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less64 (Const64 [c]) x) (Leq64 x (Const64 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Less64U (Const64 <x.Type> [c-d-1]) (Sub64 <x.Type> x (Const64 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess64 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLeq64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq64 (Const64 [c]) x) (Leq64 x (Const64 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Leq64U (Const64 <x.Type> [c-d-1]) (Sub64 <x.Type> x (Const64 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq64 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLeq64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less32 (Const32 [c]) x) (Leq32 x (Const32 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Less32U (Const32 <x.Type> [c-d-1]) (Sub32 <x.Type> x (Const32 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess32 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLeq32 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq32 (Const32 [c]) x) (Leq32 x (Const32 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Leq32U (Const32 <x.Type> [c-d-1]) (Sub32 <x.Type> x (Const32 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq32 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLeq32 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLeq32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less16 (Const16 [c]) x) (Leq16 x (Const16 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Less16U (Const16 <x.Type> [c-d-1]) (Sub16 <x.Type> x (Const16 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess16 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLeq16 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLess16U)
			v0 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v0.AuxInt = int16ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq16 (Const16 [c]) x) (Leq16 x (Const16 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Leq16U (Const16 <x.Type> [c-d-1]) (Sub16 <x.Type> x (Const16 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq16 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLeq16 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLeq16U)
			v0 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v0.AuxInt = int16ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less8 (Const8 [c]) x) (Leq8 x (Const8 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Less8U (Const8 <x.Type> [c-d-1]) (Sub8 <x.Type> x (Const8 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess8 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLeq8 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLess8U)
			v0 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v0.AuxInt = int8ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq8 (Const8 [c]) x) (Leq8 x (Const8 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Leq8U (Const8 <x.Type> [c-d-1]) (Sub8 <x.Type> x (Const8 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq8 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLeq8 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLeq8U)
			v0 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v0.AuxInt = int8ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less64U (Const64 [c]) x) (Less64U x (Const64 [d])))
	// cond: uint64(c) >= uint64(d)
	// result: (Less64U (Const64 <x.Type> [c-d]) (Sub64 <x.Type> x (Const64 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess64U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLess64U {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(uint64(c) >= uint64(d)) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq64U (Const64 [c]) x) (Less64U x (Const64 [d])))
	// cond: uint64(c) >= uint64(d)
	// result: (Leq64U (Const64 <x.Type> [c-d]) (Sub64 <x.Type> x (Const64 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq64U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLess64U {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(uint64(c) >= uint64(d)) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less32U (Const32 [c]) x) (Less32U x (Const32 [d])))
	// cond: uint32(c) >= uint32(d)
	// result: (Less32U (Const32 <x.Type> [c-d]) (Sub32 <x.Type> x (Const32 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess32U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLess32U {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(uint32(c) >= uint32(d)) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq32U (Co
"""




```