Response:

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add8 left:(Lsh8x32 x y) right:(Rsh8Ux32 x (Sub32 (Const32 [8]) y)))
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
	// match: (Add8 left:(Lsh8x16 x y) right:(Rsh8Ux16 x (Sub16 (Const16 [8]) y)))
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
	// match: (Add8 left:(Lsh8x8 x y) right:(Rsh8Ux8 x (Sub8 (Const8 [8]) y)))
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
	// match: (Add8 right:(Rsh8Ux64 x y) left:(Lsh8x64 x z:(Sub64 (Const64 [8]) y)))
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
	// match: (Add8 right:(Rsh8Ux32 x y) left:(Lsh8x32 x z:(Sub32 (Const32 [8]) y)))
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
	// match: (Add8 right:(Rsh8Ux16 x y) left:(Lsh8x16 x z:(Sub16 (Const16 [8]) y)))
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
	// match: (Add8 right:(Rsh8Ux8 x y) left:(Lsh8x8 x z:(Sub8 (Const8 [8]) y)))
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
func rewriteValuegeneric_OpAddPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AddPtr <t> x (Const64 [c]))
	// result: (OffPtr <t> x [c])
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOffPtr)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (AddPtr <t> x (Const32 [c]))
	// result: (OffPtr <t> x [int64(c)])
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpOffPtr)
		v.Type = t
		v.AuxInt = int64ToAuxInt(int64(c))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpAnd16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (And16 (Const16 [c]) (Const16 [d]))
	// result: (Const16 [c&d])
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
			v.AuxInt = int16ToAuxInt(c & d)
			return true
		}
		break
	}
	// match: (And16 <t> (Com16 x) (Com16 y))
	// result: (Com16 (Or16 <t> x y))
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
			v0 := b.NewValue0(v.Pos, OpOr16, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (And16 (Const16 [m]) (Rsh16Ux64 _ (Const64 [c])))
	// cond: c >= int64(16-ntz16(m))
	// result: (Const16 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			m := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpRsh16Ux64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= int64(16-ntz16(m))) {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And16 (Const16 [m]) (Lsh16x64 _ (Const64 [c])))
	// cond: c >= int64(16-nlz16(m))
	// result: (Const16 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			m := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpLsh16x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= int64(16-nlz16(m))) {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And16 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (And16 (Const16 [-1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (And16 (Const16 [0]) _)
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
	// match: (And16 (Com16 x) x)
	// result: (Const16 [0])
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
			v.AuxInt = int16ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And16 x (And16 x y))
	// result: (And16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAnd16 {
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
				v.reset(OpAnd16)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (And16 (And16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (And16 i (And16 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd16 {
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
				v.reset(OpAnd16)
				v0 := b.NewValue0(v.Pos, OpAnd16, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (And16 (Const16 <t> [c]) (And16 (Const16 <t> [d]) x))
	// result: (And16 (Const16 <t> [c&d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpAnd16 {
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
				v.reset(OpAnd16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c & d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpAnd32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (And32 (Const32 [c]) (Const32 [d]))
	// result: (Const32 [c&d])
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
			v.AuxInt = int32ToAuxInt(c & d)
			return true
		}
		break
	}
	// match: (And32 <t> (Com32 x) (Com32 y))
	// result: (Com32 (Or32 <t> x y))
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
			v0 := b.NewValue0(v.Pos, OpOr32, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (And32 (Const32 [m]) (Rsh32Ux64 _ (Const64 [c])))
	// cond: c >= int64(32-ntz32(m))
	// result: (Const32 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			m := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpRsh32Ux64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= int64(32-ntz32(m))) {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And32 (Const32 [m]) (Lsh32x64 _ (Const64 [c])))
	// cond: c >= int64(32-nlz32(m))
	// result: (Const32 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			m := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpLsh32x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= int64(32-nlz32(m))) {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And32 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (And32 (Const32 [-1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (And32 (Const32 [0]) _)
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
	// match: (And32 (Com32 x) x)
	// result: (Const32 [0])
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
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And32 x (And32 x y))
	// result: (And32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAnd32 {
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
				v.reset(OpAnd32)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (And32 (And32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (And32 i (And32 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd32 {
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
				v.reset(OpAnd32)
				v0 := b.NewValue0(v.Pos, OpAnd32, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (And32 (Const32 <t> [c]) (And32 (Const32 <t> [d]) x))
	// result: (And32 (Const32 <t> [c&d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpAnd32 {
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
				v.reset(OpAnd32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c & d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpAnd64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (And64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c&d])
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
			v.AuxInt = int64ToAuxInt(c & d)
			return true
		}
		break
	}
	// match: (And64 <t> (Com64 x) (Com64 y))
	// result: (Com64 (Or64 <t> x y))
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
			v0 := b.NewValue0(v.Pos, OpOr64, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (And64 (Const64 [m]) (Rsh64Ux64 _ (Const64 [c])))
	// cond: c >= int64(64-ntz64(m))
	// result: (Const64 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			m := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpRsh64Ux64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= int64(64-ntz64(m))) {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And64 (Const64 [m]) (Lsh64x64 _ (Const64 [c])))
	// cond: c >= int64(64-nlz64(m))
	// result: (Const64 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			m := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpLsh64x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= int64(64-nlz64(m))) {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And64 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (And64 (Const64 [-1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (And64 (Const64 [0]) _)
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
	// match: (And64 (Com64 x) x)
	// result: (Const64 [0])
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
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And64 x (And64 x y))
	// result: (And64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAnd64 {
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
				v.reset(OpAnd64)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (And64 (And64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (And64 i (And64 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd64 {
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
				v.reset(OpAnd64)
				v0 := b.NewValue0(v.Pos, OpAnd64, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (And64 (Const64 <t> [c]) (And64 (Const64 <t> [d]) x))
	// result: (And64 (Const64 <t> [c&d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpAnd64 {
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
				v.reset(OpAnd64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c & d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpAnd8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (And8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c&d])
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
			v.AuxInt = int8ToAuxInt(c & d)
			return true
		}
		break
	}
	// match: (And8 <t> (Com8 x) (Com8 y))
	// result: (Com8 (Or8 <t> x y))
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
			v0 := b.NewValue0(v.Pos, OpOr8, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (And8 (Const8 [m]) (Rsh8Ux64 _ (Const64 [c])))
	// cond: c >= int64(8-ntz8(m))
	// result: (Const8 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			m := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpRsh8Ux64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= int64(8-ntz8(m))) {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And8 (Const8 [m]) (Lsh8x64 _ (Const64 [c])))
	// cond: c >= int64(8-nlz8(m))
	// result: (Const8 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			m := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpLsh8x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c >= int64(8-nlz8(m))) {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And8 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (And8 (Const8 [-1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (And8 (Const8 [0]) _)
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
	// match: (And8 (Com8 x) x)
	// result: (Const8 [0])
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
			v.AuxInt = int8ToAuxInt(0)
			return true
		}
		break
	}
	// match: (And8 x (And8 x y))
	// result: (And8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAnd8 {
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
				v.reset(OpAnd8)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (And8 (And8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (And8 i (And8 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd8 {
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
				v.reset(OpAnd8)
				v0 := b.NewValue0(v.Pos, OpAnd8, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (And8 (Const8 <t> [c]) (And8 (Const8 <t> [d]) x))
	// result: (And8 (Const8 <t> [c&d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpAnd8 {
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
				v.reset(OpAnd8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c & d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpAndB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (AndB (Leq64 (Const64 [c]) x) (Less64 x (Const64 [d])))
	// cond: d >= c
	// result: (Less64U (Sub64 <x.Type> x (Const64 <x.Type> [c])) (Const64 <x.Type> [d-c]))
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
			if !(d >= c) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v1.AuxInt = int64ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq64 (Const64 [c]) x) (Leq64 x (Const64 [d])))
	// cond: d >= c
	// result: (Leq64U (Sub64 <x.Type> x (Const64 <x.Type> [c])) (Const64 <x.Type> [d-c]))
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
			if !(d >= c) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v1.AuxInt = int64ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq32 (Const32 [c]) x) (Less32 x (Const32 [d])))
	// cond: d >= c
	// result: (Less32U (Sub32 <x.Type> x (Const32 <x.Type> [c])) (Const32 <x.Type> [d-c]))
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
			if !(d >= c) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v1.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq32 (Const32 [c]) x) (Leq32 x (Const32 [d])))
	// cond: d >= c
	// result: (Leq32U (Sub32 <x.Type> x (Const32 <x.Type> [c])) (Const32 <x.Type> [d-c]))
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
			if !(d >= c) {
				continue
			}
			v.reset(OpLeq32U)
			v0 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v1.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq16 (Const16 [c]) x) (Less16 x (Const16 [d])))
	// cond: d >= c
	// result: (Less16U (Sub16 <x.Type> x (Const16 <x.Type> [c])) (Const16 <x.Type> [d-c]))
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
			if !(d >= c) {
				continue
			}
			v.reset(OpLess16U)
			v0 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v1.AuxInt = int16ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq16 (Const16 [c]) x) (Leq16 x (Const16 [d])))
	// cond: d >= c
	// result: (Leq16U (Sub16 <x.Type> x (Const16 <x.Type> [c])) (Const16 <x.Type> [d-c]))
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
			if !(d >= c) {
				continue
			}
			v.reset(OpLeq16U)
			v0 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v1.AuxInt = int16ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq8 (Const8 [c]) x) (Less8 x (Const8 [d])))
	// cond: d >= c
	// result: (Less8U (Sub8 <x.Type> x (Const8 <x.Type> [c])) (Const8 <x.Type> [d-c]))
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
			if !(d >= c) {
				continue
			}
			v.reset(OpLess8U)
			v0 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v1.AuxInt = int8ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq8 (Const8 [c]) x) (Leq8 x (Const8 [d])))
	// cond: d >= c
	// result: (Leq8U (Sub8 <x.Type> x (Const8 <x.Type> [c])) (Const8 <x.Type> [d-c]))
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
			if !(d >= c) {
				continue
			}
			v.reset(OpLeq8U)
			v0 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v1.AuxInt = int8ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less64 (Const64 [c]) x) (Less64 x (Const64 [d])))
	// cond: d >= c+1 && c+1 > c
	// result: (Less64U (Sub64 <x.Type> x (Const64 <x.Type> [c+1])) (Const64 <x.Type> [d-c-1]))
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
			if !(d >= c+1 && c+1 > c) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v1.AuxInt = int64ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less64 (Const64 [c]) x) (Leq64 x (Const64 [d])))
	// cond: d >= c+1 && c+1 > c
	// result: (Leq64U (Sub64 <x.Type> x (Const64 <x.Type> [c+1])) (Const64 <x.Type> [d-c-1]))
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
			if !(d >= c+1 && c+1 > c) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v1.AuxInt = int64ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less32 (Const32 [c]) x) (Less32 x (Const32 [d])))
	// cond: d >= c+1 && c+1 > c
	// result: (Less32U (Sub32 <x.Type> x (Const32 <x.Type> [c+1])) (Const32 <x.Type> [d-c-1]))
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
			if !(d >= c+1 && c+1 > c) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v1.AuxInt = int32ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less32 (Const32 [c]) x) (Leq32 x (Const32 [d])))
	// cond: d >= c+1 && c+1 > c
	// result: (Leq32U (Sub32 <x.Type> x (Const32 <x.Type> [c+1])) (Const32 <x.Type> [d-c-1]))
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
			if !(d >= c+1 && c+1 > c) {
				continue
			}
			v.reset(OpLeq32U)
			v0 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v1.AuxInt = int32ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less16 (Const16 [c]) x) (Less16 x (Const16 [d])))
	// cond: d >= c+1 && c+1 > c
	// result: (Less16U (Sub16 <x.Type> x (Const16 <x.Type> [c+1])) (Const16 <x.Type> [d-c-1]))
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
			if !(d >= c+1 && c+1 > c) {
				continue
			}
			v.reset(OpLess16U)
			v0 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v1.AuxInt = int16ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less16 (Const16 [c]) x) (Leq16 x (Const16 [d])))
	// cond: d >= c+1 && c+1 > c
	// result: (Leq16U (Sub16 <x.Type> x (Const16 <x.Type> [c+1])) (Const16 <x.Type> [d-c-1]))
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
			if !(d >= c+1 && c+1 > c) {
				continue
			}
			v.reset(OpLeq16U)
			v0 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v1.AuxInt = int16ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less8 (Const8 [c]) x) (Less8 x (Const8 [d])))
	// cond: d >= c+1 && c+1 > c
	// result: (Less8U (Sub8 <x.Type> x (Const8 <x.Type> [c+1])) (Const8 <x.Type> [d-c-1]))
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
			if !(d >= c+1 && c+1 > c) {
				continue
			}
			v.reset(OpLess8U)
			v0 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v1.AuxInt = int8ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less8 (Const8 [c]) x) (Leq8 x (Const8 [d])))
	// cond: d >= c+1 && c+1 > c
	// result: (Leq8U (Sub8 <x.Type> x (Const8 <x.Type> [c+1])) (Const8 <x.Type> [d-c-1]))
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
			if !(d >= c+1 && c+1 > c) {
				continue
			}
			v.reset(OpLeq8U)
			v0 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v1.AuxInt = int8ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq64U (Const64 [c]) x) (Less64U x (Const64 [d])))
	// cond: uint64(d) >= uint64(c)
	// result: (Less64U (Sub64 <x.Type> x (Const64 <x.Type> [c])) (Const64 <x.Type> [d-c]))
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
			if !(uint64(d) >= uint64(c)) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v1.AuxInt = int64ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq64U (Const64 [c]) x) (Leq64U x (Const64 [d])))
	// cond: uint64(d) >= uint64(c)
	// result: (Leq64U (Sub64 <x.Type> x (Const64 <x.Type> [c])) (Const64 <x.Type> [d-c]))
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
			if v_1.Op != OpLeq64U {
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
			if !(uint64(d) >= uint64(c)) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v1.AuxInt = int64ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq32U (Const32 [c]) x) (Less32U x (Const32 [d])))
	// cond: uint32(d) >= uint32(c)
	// result: (Less32U (Sub32 <x.Type> x (Const32 <x.Type> [c])) (Const32 <x.Type> [d-c]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq32U {
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
			if !(uint32(d) >= uint32(c)) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v1.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq32U (Const32 [c]) x) (Leq32U x (Const32 [d])))
	// cond: uint32(d) >= uint32(c)
	// result: (Leq32U (Sub32 <x.Type> x (Const32 <x.Type> [c])) (Const32 <x.Type> [d-c]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq32U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLeq32U {
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
			if !(uint32(d) >= uint32(c)) {
				continue
			}
			v.reset(OpLeq32U)
			v0 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v1.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq16U (Const16 [c]) x) (Less16U x (Const16 [d])))
	// cond: uint16(d) >= uint16(c)
	// result: (Less16U (Sub16 <x.Type> x (Const16 <x.Type> [c])) (Const16 <x.Type> [d-c]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq16U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLess16U {
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
			if !(uint16(d) >= uint16(c)) {
				continue
			}
			v.reset(OpLess16U)
			v0 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v1.AuxInt = int16ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq16U (Const16 [c]) x) (Leq16U x (Const16 [d])))
	// cond: uint16(d) >= uint16(c)
	// result: (Leq16U (Sub16 <x.Type> x (Const16 <x.Type> [c])) (Const16 <x.Type> [d-c]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq16U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLeq16U {
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
			if !(uint16(d) >= uint16(c)) {
				continue
			}
			v.reset(OpLeq16U)
			v0 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v1.AuxInt = int16ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq8U (Const8 [c]) x) (Less8U x (Const8 [d])))
	// cond: uint8(d) >= uint8(c)
	// result: (Less8U (Sub8 <x.Type> x (Const8 <x.Type> [c])) (Const8 <x.Type> [d-c]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq8U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLess8U {
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
			if !(uint8(d) >= uint8(c)) {
				continue
			}
			v.reset(OpLess8U)
			v0 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v1.AuxInt = int8ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Leq8U (Const8 [c]) x) (Leq8U x (Const8 [d])))
	// cond: uint8(d) >= uint8(c)
	// result: (Leq8U (Sub8 <x.Type> x (Const8 <x.Type> [c])) (Const8 <x.Type> [d-c]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq8U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLeq8U {
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
			if !(uint8(d) >= uint8(c)) {
				continue
			}
			v.reset(OpLeq8U)
			v0 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v1.AuxInt = int8ToAuxInt(c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d - c)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less64U (Const64 [c]) x) (Less64U x (Const64 [d])))
	// cond: uint64(d) >= uint64(c+1) && uint64(c+1) > uint64(c)
	// result: (Less64U (Sub64 <x.Type> x (Const64 <x.Type> [c+1])) (Const64 <x.Type> [d-c-1]))
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
			if !(uint64(d) >= uint64(c+1) && uint64(c+1) > uint64(c)) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v1.AuxInt = int64ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less64U (Const64 [c]) x) (Leq64U x (Const64 [d])))
	// cond: uint64(d) >= uint64(c+1) && uint64(c+1) > uint64(c)
	// result: (Leq64U (Sub64 <x.Type> x (Const64 <x.Type> [c+1])) (Const64 <x.Type> [d-c-1]))
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
			if v_1.Op != OpLeq64U {
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
			if !(uint64(d) >= uint64(c+1) && uint64(c+1) > uint64(c)) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v1.AuxInt = int64ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less32U (Const32 [c]) x) (Less32U x (Const32 [d])))
	// cond: uint32(d) >= uint32(c+1) && uint32(c+1) > uint32(c)
	// result: (Less32U (Sub32 <x.Type> x (Const32 <x.Type> [c+1])) (Const32 <x.Type> [d-c-1]))
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
			if !(uint32(d) >= uint32(c+1) && uint32(c+1) > uint32(c)) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v1.AuxInt = int32ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less32U (Const32 [c]) x) (Leq32U x (Const32 [d])))
	// cond: uint32(d) >= uint32(c+1) && uint32(c+1) > uint32(c)
	// result: (Leq32U (Sub32 <x.Type> x (Const32 <x.Type> [c+1])) (Const32 <x.Type> [d-c-1]))
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
			if v_1.Op != OpLeq32U {
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
			if !(uint32(d) >= uint32(c+1) && uint32(c+1) > uint32(c)) {
				continue
			}
			v.reset(OpLeq32U)
			v0 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v1.AuxInt = int32ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less16U (Const16 [c]) x) (Less16U x (Const16 [d])))
	// cond: uint16(d) >= uint16(c+1) && uint16(c+1) > uint16(c)
	// result: (Less16U (Sub16 <x.Type> x (Const16 <x.Type> [c+1])) (Const16 <x.Type> [d-c-1]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess16U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLess16U {
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
			if !(uint16(d) >= uint16(c+1) && uint16(c+1) > uint16(c)) {
				continue
			}
			v.reset(OpLess16U)
			v0 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v1.AuxInt = int16ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less16U (Const16 [c]) x) (Leq16U x (Const16 [d])))
	// cond: uint16(d) >= uint16(c+1) && uint16(c+1) > uint16(c)
	// result: (Leq16U (Sub16 <x.Type> x (Const16 <x.Type> [c+1])) (Const16 <x.Type> [d-c-1]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess16U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLeq16U {
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
			if !(uint16(d) >= uint16(c+1) && uint16(c+1) > uint16(c)) {
				continue
			}
			v.reset(OpLeq16U)
			v0 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v1.AuxInt = int16ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less8U (Const8 [c]) x) (Less8U x (Const8 [d])))
	// cond: uint8(d) >= uint8(c+1) && uint8(c+1) > uint8(c)
	// result: (Less8U (Sub8 <x.Type> x (Const8 <x.Type> [c+1])) (Const8 <x.Type> [d-c-1]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess8U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLess8U {
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
			if !(uint8(d) >= uint8(c+1) && uint8(c+1) > uint8(c)) {
				continue
			}
			v.reset(OpLess8U)
			v0 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v1.AuxInt = int8ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (AndB (Less8U (Const8 [c]) x) (Leq8U x (Const8 [d])))
	// cond: uint8(d) >= uint8(c+1) && uint8(c+1) > uint8(c)
	// result: (Leq8U (Sub8 <x.Type> x (Const8 <x.Type> [c+1])) (Const8 <x.Type> [d-c-1]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess8U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLeq8U {
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
			if !(uint8(d) >= uint8(c+1) && uint8(c+1) > uint8(c)) {
				continue
			}
			v.reset(OpLeq8U)
			v0 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v1 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v1.AuxInt = int8ToAuxInt(c + 1)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d - c - 1)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpArraySelect(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ArraySelect (ArrayMake1 x))
	// result: x
	for {
		if v_0.Op != OpArrayMake1 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (ArraySelect [0] (IData x))
	// result: (IData x)
	for {
		if auxIntToInt64(v.AuxInt) != 0 || v_0.Op != OpIData {
			break
		}
		x := v_0.Args[0]
		v.reset(OpIData)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpBitLen16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (BitLen16 (Const16 [c]))
	// cond: config.PtrSize == 8
	// result: (Const64 [int64(bits.Len16(uint16(c)))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(bits.Len16(uint16(c))))
		return true
	}
	// match: (BitLen16 (Const16 [c]))
	// cond: config.PtrSize == 4
	// result: (Const32 [int32(bits.Len16(uint16(c)))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(bits.Len16(uint16(c))))
		return true
	}
	return false
}
func rewriteValuegeneric_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (BitLen32 (Const32 [c]))
	// cond: config.PtrSize == 8
	// result: (Const64 [int64(bits.Len32(uint32(c)))])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(bits.Len32(uint32(c))))
		return true
	}
	// match: (BitLen32 (Const32 [c]))
	// cond: config.PtrSize == 4
	// result: (Const32 [int32(bits.Len32(uint32(c)))])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(bits.Len32(uint32(c))))
		return true
	}
	return false
}
func rewriteValuegeneric_OpBitLen64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (BitLen64 (Const64 [c]))
	// cond: config.PtrSize == 8
	// result: (Const64 [int64(bits.Len64(uint64(c)))])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(bits.Len64(uint64(c))))
		return true
	}
	// match: (BitLen64 (Const64 [c]))
	// cond: config.PtrSize == 4
	// result: (Const32 [int32(bits.Len64(uint64(c)))])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(bits.Len64(uint64(c))))
		return true
	}
	return false
}
func rewriteValuegeneric_OpBitLen8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (BitLen8 (Const8 [c]))
	// cond: config.PtrSize == 8
	// result: (Const64 [int64(bits.Len8(uint8(c)))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(bits.Len8(uint8(c))))
		return true
	}
	// match: (BitLen8 (Const8 [c]))
	// cond: config.PtrSize == 4
	// result: (Const32 [int32(bits.Len8(uint8(c)))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(bits.Len8(uint8(c))))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCeil(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ceil (Const64F [c]))
	// result: (Const64F [math.Ceil(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(math.Ceil(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCom16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com16 (Com16 x))
	// result: x
	for {
		if v_0.Op != OpCom16 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Com16 (Const16 [c]))
	// result: (Const16 [^c])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(^c)
		return true
	}
	// match: (Com16 (Add16 (Const16 [-1]) x))
	// result: (Neg16 x)
	for {
		if v_0.Op != OpAdd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst16 || auxIntToInt16(v_0_0.AuxInt) != -1 {
				continue
			}
			x := v_0_1
			v.reset(OpNeg16)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpCom32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com32 (Com32 x))
	// result: x
	for {
		if v_0.Op != OpCom32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Com32 (Const32 [c]))
	// result: (Const32 [^c])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(^c)
		return true
	}
	// match: (Com32 (Add32 (Const32 [-1]) x))
	// result: (Neg32 x)
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 || auxIntToInt32(v_0_0.AuxInt) != -1 {
				continue
			}
			x := v_0_1
			v.reset(OpNeg32)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpCom64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com64 (Com64 x))
	// result: x
	for {
		if v_0.Op != OpCom64 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Com64 (Const64 [c]))
	// result: (Const64 [^c])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(^c)
		return true
	}
	// match: (Com64 (Add64 (Const64 [-1]) x))
	// result: (Neg64 x)
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != -1 {
				continue
			}
			x := v_0_1
			v.reset(OpNeg64)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpCom8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com8 (Com8 x))
	// result: x
	for {
		if v_0.Op != OpCom8 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Com8 (Const8 [c]))
	// result: (Const8 [^c])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(^c)
		return true
	}
	// match: (Com8 (Add8 (Const8 [-1]) x))
	// result
```