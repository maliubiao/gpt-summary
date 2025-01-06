Response:

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第10部分，共13部分，请归纳一下它的功能

"""
nst32 [c]) x) (Less32U x (Const32 [d])))
	// cond: uint32(c) >= uint32(d)
	// result: (Leq32U (Const32 <x.Type> [c-d]) (Sub32 <x.Type> x (Const32 <x.Type> [d])))
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
			if !(uint32(c) >= uint32(d)) {
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
	// match: (OrB (Less16U (Const16 [c]) x) (Less16U x (Const16 [d])))
	// cond: uint16(c) >= uint16(d)
	// result: (Less16U (Const16 <x.Type> [c-d]) (Sub16 <x.Type> x (Const16 <x.Type> [d])))
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
			if !(uint16(c) >= uint16(d)) {
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
	// match: (OrB (Leq16U (Const16 [c]) x) (Less16U x (Const16 [d])))
	// cond: uint16(c) >= uint16(d)
	// result: (Leq16U (Const16 <x.Type> [c-d]) (Sub16 <x.Type> x (Const16 <x.Type> [d])))
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
			if !(uint16(c) >= uint16(d)) {
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
	// match: (OrB (Less8U (Const8 [c]) x) (Less8U x (Const8 [d])))
	// cond: uint8(c) >= uint8(d)
	// result: (Less8U (Const8 <x.Type> [c-d]) (Sub8 <x.Type> x (Const8 <x.Type> [d])))
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
			if !(uint8(c) >= uint8(d)) {
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
	// match: (OrB (Leq8U (Const8 [c]) x) (Less8U x (Const8 [d])))
	// cond: uint8(c) >= uint8(d)
	// result: (Leq8U (Const8 <x.Type> [c-d]) (Sub8 <x.Type> x (Const8 <x.Type> [d])))
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
			if !(uint8(c) >= uint8(d)) {
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
	// match: (OrB (Less64U (Const64 [c]) x) (Leq64U x (Const64 [d])))
	// cond: uint64(c) >= uint64(d+1) && uint64(d+1) > uint64(d)
	// result: (Less64U (Const64 <x.Type> [c-d-1]) (Sub64 <x.Type> x (Const64 <x.Type> [d+1])))
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
			if !(uint64(c) >= uint64(d+1) && uint64(d+1) > uint64(d)) {
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
	// match: (OrB (Leq64U (Const64 [c]) x) (Leq64U x (Const64 [d])))
	// cond: uint64(c) >= uint64(d+1) && uint64(d+1) > uint64(d)
	// result: (Leq64U (Const64 <x.Type> [c-d-1]) (Sub64 <x.Type> x (Const64 <x.Type> [d+1])))
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
			if !(uint64(c) >= uint64(d+1) && uint64(d+1) > uint64(d)) {
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
	// match: (OrB (Less32U (Const32 [c]) x) (Leq32U x (Const32 [d])))
	// cond: uint32(c) >= uint32(d+1) && uint32(d+1) > uint32(d)
	// result: (Less32U (Const32 <x.Type> [c-d-1]) (Sub32 <x.Type> x (Const32 <x.Type> [d+1])))
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
			if !(uint32(c) >= uint32(d+1) && uint32(d+1) > uint32(d)) {
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
	// match: (OrB (Leq32U (Const32 [c]) x) (Leq32U x (Const32 [d])))
	// cond: uint32(c) >= uint32(d+1) && uint32(d+1) > uint32(d)
	// result: (Leq32U (Const32 <x.Type> [c-d-1]) (Sub32 <x.Type> x (Const32 <x.Type> [d+1])))
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
			if !(uint32(c) >= uint32(d+1) && uint32(d+1) > uint32(d)) {
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
	// match: (OrB (Less16U (Const16 [c]) x) (Leq16U x (Const16 [d])))
	// cond: uint16(c) >= uint16(d+1) && uint16(d+1) > uint16(d)
	// result: (Less16U (Const16 <x.Type> [c-d-1]) (Sub16 <x.Type> x (Const16 <x.Type> [d+1])))
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
			if !(uint16(c) >= uint16(d+1) && uint16(d+1) > uint16(d)) {
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
	// match: (OrB (Leq16U (Const16 [c]) x) (Leq16U x (Const16 [d])))
	// cond: uint16(c) >= uint16(d+1) && uint16(d+1) > uint16(d)
	// result: (Leq16U (Const16 <x.Type> [c-d-1]) (Sub16 <x.Type> x (Const16 <x.Type> [d+1])))
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
			if !(uint16(c) >= uint16(d+1) && uint16(d+1) > uint16(d)) {
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
	// match: (OrB (Less8U (Const8 [c]) x) (Leq8U x (Const8 [d])))
	// cond: uint8(c) >= uint8(d+1) && uint8(d+1) > uint8(d)
	// result: (Less8U (Const8 <x.Type> [c-d-1]) (Sub8 <x.Type> x (Const8 <x.Type> [d+1])))
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
			if !(uint8(c) >= uint8(d+1) && uint8(d+1) > uint8(d)) {
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
	// match: (OrB (Leq8U (Const8 [c]) x) (Leq8U x (Const8 [d])))
	// cond: uint8(c) >= uint8(d+1) && uint8(d+1) > uint8(d)
	// result: (Leq8U (Const8 <x.Type> [c-d-1]) (Sub8 <x.Type> x (Const8 <x.Type> [d+1])))
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
			if !(uint8(c) >= uint8(d+1) && uint8(d+1) > uint8(d)) {
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
	return false
}
func rewriteValuegeneric_OpPhi(v *Value) bool {
	b := v.Block
	// match: (Phi (Const8 [c]) (Const8 [c]))
	// result: (Const8 [c])
	for {
		if len(v.Args) != 2 {
			break
		}
		_ = v.Args[1]
		v_0 := v.Args[0]
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v_1 := v.Args[1]
		if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != c {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(c)
		return true
	}
	// match: (Phi (Const16 [c]) (Const16 [c]))
	// result: (Const16 [c])
	for {
		if len(v.Args) != 2 {
			break
		}
		_ = v.Args[1]
		v_0 := v.Args[0]
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v_1 := v.Args[1]
		if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != c {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(c)
		return true
	}
	// match: (Phi (Const32 [c]) (Const32 [c]))
	// result: (Const32 [c])
	for {
		if len(v.Args) != 2 {
			break
		}
		_ = v.Args[1]
		v_0 := v.Args[0]
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v_1 := v.Args[1]
		if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != c {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	// match: (Phi (Const64 [c]) (Const64 [c]))
	// result: (Const64 [c])
	for {
		if len(v.Args) != 2 {
			break
		}
		_ = v.Args[1]
		v_0 := v.Args[0]
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_1 := v.Args[1]
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	// match: (Phi <t> nx:(Not x) ny:(Not y))
	// cond: nx.Uses == 1 && ny.Uses == 1
	// result: (Not (Phi <t> x y))
	for {
		if len(v.Args) != 2 {
			break
		}
		t := v.Type
		_ = v.Args[1]
		nx := v.Args[0]
		if nx.Op != OpNot {
			break
		}
		x := nx.Args[0]
		ny := v.Args[1]
		if ny.Op != OpNot {
			break
		}
		y := ny.Args[0]
		if !(nx.Uses == 1 && ny.Uses == 1) {
			break
		}
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpPhi, t)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpPtrIndex(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (PtrIndex <t> ptr idx)
	// cond: config.PtrSize == 4 && is32Bit(t.Elem().Size())
	// result: (AddPtr ptr (Mul32 <typ.Int> idx (Const32 <typ.Int> [int32(t.Elem().Size())])))
	for {
		t := v.Type
		ptr := v_0
		idx := v_1
		if !(config.PtrSize == 4 && is32Bit(t.Elem().Size())) {
			break
		}
		v.reset(OpAddPtr)
		v0 := b.NewValue0(v.Pos, OpMul32, typ.Int)
		v1 := b.NewValue0(v.Pos, OpConst32, typ.Int)
		v1.AuxInt = int32ToAuxInt(int32(t.Elem().Size()))
		v0.AddArg2(idx, v1)
		v.AddArg2(ptr, v0)
		return true
	}
	// match: (PtrIndex <t> ptr idx)
	// cond: config.PtrSize == 8
	// result: (AddPtr ptr (Mul64 <typ.Int> idx (Const64 <typ.Int> [t.Elem().Size()])))
	for {
		t := v.Type
		ptr := v_0
		idx := v_1
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpAddPtr)
		v0 := b.NewValue0(v.Pos, OpMul64, typ.Int)
		v1 := b.NewValue0(v.Pos, OpConst64, typ.Int)
		v1.AuxInt = int64ToAuxInt(t.Elem().Size())
		v0.AddArg2(idx, v1)
		v.AddArg2(ptr, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (RotateLeft16 x (Const16 [c]))
	// cond: c%16 == 0
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(c%16 == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (RotateLeft16 x (And64 y (Const64 [c])))
	// cond: c&15 == 15
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (And32 y (Const32 [c])))
	// cond: c&15 == 15
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (And16 y (Const16 [c])))
	// cond: c&15 == 15
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (And8 y (Const8 [c])))
	// cond: c&15 == 15
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Neg64 (And64 y (Const64 [c]))))
	// cond: c&15 == 15
	// result: (RotateLeft16 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg64 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd64 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_0_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Neg32 (And32 y (Const32 [c]))))
	// cond: c&15 == 15
	// result: (RotateLeft16 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg32 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd32 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_0_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Neg16 (And16 y (Const16 [c]))))
	// cond: c&15 == 15
	// result: (RotateLeft16 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg16 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd16 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_0_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Neg8 (And8 y (Const8 [c]))))
	// cond: c&15 == 15
	// result: (RotateLeft16 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg8 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd8 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_0_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Add64 y (Const64 [c])))
	// cond: c&15 == 0
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&15 == 0) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Add32 y (Const32 [c])))
	// cond: c&15 == 0
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&15 == 0) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Add16 y (Const16 [c])))
	// cond: c&15 == 0
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&15 == 0) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Add8 y (Const8 [c])))
	// cond: c&15 == 0
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&15 == 0) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Sub64 (Const64 [c]) y))
	// cond: c&15 == 0
	// result: (RotateLeft16 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_0.AuxInt)
		if !(c&15 == 0) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 x (Sub32 (Const32 [c]) y))
	// cond: c&15 == 0
	// result: (RotateLeft16 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		if !(c&15 == 0) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 x (Sub16 (Const16 [c]) y))
	// cond: c&15 == 0
	// result: (RotateLeft16 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1_0.AuxInt)
		if !(c&15 == 0) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 x (Sub8 (Const8 [c]) y))
	// cond: c&15 == 0
	// result: (RotateLeft16 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1_0.AuxInt)
		if !(c&15 == 0) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 x (Const64 <t> [c]))
	// cond: config.PtrSize == 4
	// result: (RotateLeft16 x (Const32 <t> [int32(c)]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 (RotateLeft16 x c) d)
	// cond: c.Type.Size() == 8 && d.Type.Size() == 8
	// result: (RotateLeft16 x (Add64 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft16 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 8 && d.Type.Size() == 8) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpAdd64, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 (RotateLeft16 x c) d)
	// cond: c.Type.Size() == 4 && d.Type.Size() == 4
	// result: (RotateLeft16 x (Add32 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft16 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 4 && d.Type.Size() == 4) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpAdd32, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 (RotateLeft16 x c) d)
	// cond: c.Type.Size() == 2 && d.Type.Size() == 2
	// result: (RotateLeft16 x (Add16 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft16 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 2 && d.Type.Size() == 2) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpAdd16, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 (RotateLeft16 x c) d)
	// cond: c.Type.Size() == 1 && d.Type.Size() == 1
	// result: (RotateLeft16 x (Add8 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft16 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 1 && d.Type.Size() == 1) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpAdd8, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRotateLeft32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (RotateLeft32 x (Const32 [c]))
	// cond: c%32 == 0
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c%32 == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (RotateLeft32 x (And64 y (Const64 [c])))
	// cond: c&31 == 31
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (And32 y (Const32 [c])))
	// cond: c&31 == 31
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (And16 y (Const16 [c])))
	// cond: c&31 == 31
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (And8 y (Const8 [c])))
	// cond: c&31 == 31
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Neg64 (And64 y (Const64 [c]))))
	// cond: c&31 == 31
	// result: (RotateLeft32 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg64 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd64 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_0_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Neg32 (And32 y (Const32 [c]))))
	// cond: c&31 == 31
	// result: (RotateLeft32 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg32 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd32 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_0_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Neg16 (And16 y (Const16 [c]))))
	// cond: c&31 == 31
	// result: (RotateLeft32 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg16 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd16 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_0_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Neg8 (And8 y (Const8 [c]))))
	// cond: c&31 == 31
	// result: (RotateLeft32 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg8 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd8 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_0_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Add64 y (Const64 [c])))
	// cond: c&31 == 0
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&31 == 0) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Add32 y (Const32 [c])))
	// cond: c&31 == 0
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&31 == 0) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Add16 y (Const16 [c])))
	// cond: c&31 == 0
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&31 == 0) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Add8 y (Const8 [c])))
	// cond: c&31 == 0
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&31 == 0) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Sub64 (Const64 [c]) y))
	// cond: c&31 == 0
	// result: (RotateLeft32 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_0.AuxInt)
		if !(c&31 == 0) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 x (Sub32 (Const32 [c]) y))
	// cond: c&31 == 0
	// result: (RotateLeft32 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		if !(c&31 == 0) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 x (Sub16 (Const16 [c]) y))
	// cond: c&31 == 0
	// result: (RotateLeft32 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1_0.AuxInt)
		if !(c&31 == 0) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 x (Sub8 (Const8 [c]) y))
	// cond: c&31 == 0
	// result: (RotateLeft32 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1_0.AuxInt)
		if !(c&31 == 0) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 x (Const64 <t> [c]))
	// cond: config.PtrSize == 4
	// result: (RotateLeft32 x (Const32 <t> [int32(c)]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 (RotateLeft32 x c) d)
	// cond: c.Type.Size() == 8 && d.Type.Size() == 8
	// result: (RotateLeft32 x (Add64 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft32 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 8 && d.Type.Size() == 8) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpAdd64, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 (RotateLeft32 x c) d)
	// cond: c.Type.Size() == 4 && d.Type.Size() == 4
	// result: (RotateLeft32 x (Add32 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft32 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 4 && d.Type.Size() == 4) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpAdd32, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 (RotateLeft32 x c) d)
	// cond: c.Type.Size() == 2 && d.Type.Size() == 2
	// result: (RotateLeft32 x (Add16 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft32 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 2 && d.Type.Size() == 2) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpAdd16, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 (RotateLeft32 x c) d)
	// cond: c.Type.Size() == 1 && d.Type.Size() == 1
	// result: (RotateLeft32 x (Add8 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft32 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 1 && d.Type.Size() == 1) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpAdd8, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRotateLeft64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (RotateLeft64 x (Const64 [c]))
	// cond: c%64 == 0
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c%64 == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (RotateLeft64 x (And64 y (Const64 [c])))
	// cond: c&63 == 63
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (And32 y (Const32 [c])))
	// cond: c&63 == 63
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (And16 y (Const16 [c])))
	// cond: c&63 == 63
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (And8 y (Const8 [c])))
	// cond: c&63 == 63
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Neg64 (And64 y (Const64 [c]))))
	// cond: c&63 == 63
	// result: (RotateLeft64 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg64 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd64 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_0_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Neg32 (And32 y (Const32 [c]))))
	// cond: c&63 == 63
	// result: (RotateLeft64 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg32 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd32 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_0_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Neg16 (And16 y (Const16 [c]))))
	// cond: c&63 == 63
	// result: (RotateLeft64 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg16 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd16 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_0_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Neg8 (And8 y (Const8 [c]))))
	// cond: c&63 == 63
	// result: (RotateLeft64 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg8 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd8 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_0_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Add64 y (Const64 [c])))
	// cond: c&63 == 0
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&63 == 0) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Add32 y (Const32 [c])))
	// cond: c&63 == 0
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&63 == 0) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Add16 y (Const16 [c])))
	// cond: c&63 == 0
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&63 == 0) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Add8 y (Const8 [c])))
	// cond: c&63 == 0
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&63 == 0) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Sub64 (Const64 [c]) y))
	// cond: c&63 == 0
	// result: (RotateLeft64 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_0.AuxInt)
		if !(c&63 == 0) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 x (Sub32 (Const32 [c]) y))
	// cond: c&63 == 0
	// result: (RotateLeft64 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		if !(c&63 == 0) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 x (Sub16 (Const16 [c]) y))
	// cond: c&63 == 0
	// result: (RotateLeft64 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1_0.AuxInt)
		if !(c&63 == 0) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 x (Sub8 (Const8 [c]) y))
	// cond: c&63 == 0
	// result: (RotateLeft64 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1_0.AuxInt)
		if !(c&63 == 0) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 x (Const64 <t> [c]))
	// cond: config.PtrSize == 4
	// result: (RotateLeft64 x (Const32 <t> [int32(c)]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 (RotateLeft64 x c) d)
	// cond: c.Type.Size() == 8 && d.Type.Size() == 8
	// result: (RotateLeft64 x (Add64 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft64 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 8 && d.Type.Size() == 8) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpAdd64, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 (RotateLeft64 x c) d)
	// cond: c.Type.Size() == 4 && d.Type.Size() == 4
	// result: (RotateLeft64 x (Add32 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft64 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 4 && d.Type.Size() == 4) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpAdd32, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 (RotateLeft64 x c) d)
	// cond: c.Type.Size() == 2 && d.Type.Size() == 2
	// result: (RotateLeft64 x (Add16 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft64 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 2 && d.Type.Size() == 2) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpAdd16, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 (RotateLeft64 x c) d)
	// cond: c.Type.Size() == 1 && d.Type.Size() == 1
	// result: (RotateLeft64 x (Add8 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft64 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 1 && d.Type.Size() == 1) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpAdd8, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (RotateLeft8 x (Const8 [c]))
	// cond: c%8 == 0
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(c%8 == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (RotateLeft8 x (And64 y (Const64 [c])))
	// cond: c&7 == 7
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (And32 y (Const32 [c])))
	// cond: c&7 == 7
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (And16 y (Const16 [c])))
	// cond: c&7 == 7
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (And8 y (Const8 [c])))
	// cond: c&7 == 7
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Neg64 (And64 y (Const64 [c]))))
	// cond: c&7 == 7
	// result: (RotateLeft8 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg64 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd64 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_0_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Neg32 (And32 y (Const32 [c]))))
	// cond: c&7 == 7
	// result: (RotateLeft8 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg32 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd32 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_0_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Neg16 (And16 y (Const16 [c]))))
	// cond: c&7 == 7
	// result: (RotateLeft8 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg16 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd16 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_0_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Neg8 (And8 y (Const8 [c]))))
	// cond: c&7 == 7
	// result: (RotateLeft8 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg8 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd8 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_0_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Add64 y (Const64 [c])))
	// cond: c&7 == 0
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&7 == 0) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Add32 y (Const32 [c])))
	// cond: c&7 == 0
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&7 == 0) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Add16 y (Const16 [c])))
	// cond: c&7 == 0
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&7 == 0) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Add8 y (Const8 [c])))
	// cond: c&7 == 0
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&7 == 0) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Sub64 (Const64 [c]) y))
	// cond: c&7 == 0
	// result: (RotateLeft8 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_0.AuxInt)
		if !(c&7 == 0) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 x (Sub32 (Const32 [c]) y))
	// cond: c&7 == 0
	// result: (RotateLeft8 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		if !(c&7 == 0) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 x (Sub16 (Const16 [c]) y))
	// cond: c&7 == 0
	// result: (RotateLeft8 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1_0.AuxInt)
		if !(c&7 == 0) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 x (Sub8 (Const8 [c]) y))
	// cond: c&7 == 0
	// result: (RotateLeft8 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1_0.AuxInt)
		if !(c&7 == 0) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 x (Const64 <t> [c]))
	// cond: config.PtrSize == 4
	// result: (RotateLeft8 x (Const32 <t> [int32(c)]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 (RotateLeft8 x c) d)
	// cond: c.Type.Size() == 8 && d.Type.Size() == 8
	// result: (RotateLeft8 x (Add64 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft8 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 8 && d.Type.Size() == 8) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpAdd64, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 (RotateLeft8 x c) d)
	// cond: c.Type.Size() == 4 && d.Type.Size() == 4
	// result: (RotateLeft8 x (Add32 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft8 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 4 && d.Type.Size() == 4) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpAdd32, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 (RotateLeft8 x c) d)
	// cond: c.Type.Size() == 2 && d.Type.Size() == 2
	// result: (RotateLeft8 x (Add16 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft8 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 2 && d.Type.Size() == 2) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpAdd16, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 (RotateLeft8 x c) d)
	// cond: c.Type.Size() == 1 && d.Type.Size() == 1
	// result: (RotateLeft8 x (Add8 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft8 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 1 && d.Type.Size() == 1) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpAdd8, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRound32F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Round32F x:(Const32F))
	// result: x
	for {
		x := v_0
		if x.Op != OpConst32F {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRound64F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Round64F x:(Const64F))
	// result: x
	for {
		x := v_0
		if x.Op != OpConst64F {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRoundToEven(v *Value) bool {
	v_0 := v.Args[0]
	// match: (RoundToEven (Const64F [c]))
	// result: (Const64F [math.RoundToEven(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(math.RoundToEven(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16Ux16 <t> x (Const16 [c]))
	// result: (Rsh16Ux64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux16 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16Ux32 <t> x (Const32 [c]))
	// result: (Rsh16Ux64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux32 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 (Const16 [c]) (Const64 [d]))
	// result: (Const16 [int16(uint16(c) >> uint64(d))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(uint16(c) >> uint64(d)))
		return true
	}
	// match: (Rsh16Ux64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh16Ux64 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Rsh16Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 16
	// result: (Const16 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 16) {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Rsh16Ux64 <t> (Rsh16Ux64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh16Ux64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh16Ux64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(!uaddOvf(c, d)) {
			break
		}
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux64 (Rsh16x64 x _) (Const64 <t> [15]))
	// result: (Rsh16Ux64 x (Const64 <t> [15]))
	for {
		if v_0.Op != OpRsh16x64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 15 {
			break
		}
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(15)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux64 i:(Lsh16x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 16 && i.Uses == 1
	// result: (And16 x (Const16 <v.Type> [int16(^uint16(0)>>c)]))
	for {
		i := v_0
		if i.Op != OpLsh16x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.
"""




```