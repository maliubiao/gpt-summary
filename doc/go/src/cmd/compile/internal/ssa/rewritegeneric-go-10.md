Response:

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第11部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 16 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd16)
		v0 := b.NewValue0(v.Pos, OpConst16, v.Type)
		v0.AuxInt = int16ToAuxInt(int16(^uint16(0) >> c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux64 (Lsh16x64 (Rsh16Ux64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Rsh16Ux64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpLsh16x64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh16Ux64 {
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
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux64 (Lsh16x64 x (Const64 [8])) (Const64 [8]))
	// result: (ZeroExt8to16 (Trunc16to8 <typ.UInt8> x))
	for {
		if v_0.Op != OpLsh16x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 8 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 8 {
			break
		}
		v.reset(OpZeroExt8to16)
		v0 := b.NewValue0(v.Pos, OpTrunc16to8, typ.UInt8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16Ux8 <t> x (Const8 [c]))
	// result: (Rsh16Ux64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux8 (Const16 [0]) _)
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
func rewriteValuegeneric_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16x16 <t> x (Const16 [c]))
	// result: (Rsh16x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x16 (Const16 [0]) _)
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
func rewriteValuegeneric_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16x32 <t> x (Const32 [c]))
	// result: (Rsh16x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x32 (Const16 [0]) _)
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
func rewriteValuegeneric_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 (Const16 [c]) (Const64 [d]))
	// result: (Const16 [c >> uint64(d)])
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
		v.AuxInt = int16ToAuxInt(c >> uint64(d))
		return true
	}
	// match: (Rsh16x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh16x64 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Rsh16x64 <t> (Rsh16x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh16x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh16x64 {
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
		v.reset(OpRsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x64 (Lsh16x64 x (Const64 [8])) (Const64 [8]))
	// result: (SignExt8to16 (Trunc16to8 <typ.Int8> x))
	for {
		if v_0.Op != OpLsh16x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 8 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 8 {
			break
		}
		v.reset(OpSignExt8to16)
		v0 := b.NewValue0(v.Pos, OpTrunc16to8, typ.Int8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16x8 <t> x (Const8 [c]))
	// result: (Rsh16x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x8 (Const16 [0]) _)
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
func rewriteValuegeneric_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux16 <t> x (Const16 [c]))
	// result: (Rsh32Ux64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux16 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux32 <t> x (Const32 [c]))
	// result: (Rsh32Ux64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux32 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 (Const32 [c]) (Const64 [d]))
	// result: (Const32 [int32(uint32(c) >> uint64(d))])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		return true
	}
	// match: (Rsh32Ux64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh32Ux64 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Rsh32Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 32
	// result: (Const32 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 32) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Rsh32Ux64 <t> (Rsh32Ux64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh32Ux64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh32Ux64 {
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
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux64 (Rsh32x64 x _) (Const64 <t> [31]))
	// result: (Rsh32Ux64 x (Const64 <t> [31]))
	for {
		if v_0.Op != OpRsh32x64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 31 {
			break
		}
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(31)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux64 i:(Lsh32x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 32 && i.Uses == 1
	// result: (And32 x (Const32 <v.Type> [int32(^uint32(0)>>c)]))
	for {
		i := v_0
		if i.Op != OpLsh32x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 32 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd32)
		v0 := b.NewValue0(v.Pos, OpConst32, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(^uint32(0) >> c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux64 (Lsh32x64 (Rsh32Ux64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Rsh32Ux64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh32Ux64 {
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
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux64 (Lsh32x64 x (Const64 [24])) (Const64 [24]))
	// result: (ZeroExt8to32 (Trunc32to8 <typ.UInt8> x))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 24 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 24 {
			break
		}
		v.reset(OpZeroExt8to32)
		v0 := b.NewValue0(v.Pos, OpTrunc32to8, typ.UInt8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh32Ux64 (Lsh32x64 x (Const64 [16])) (Const64 [16]))
	// result: (ZeroExt16to32 (Trunc32to16 <typ.UInt16> x))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 16 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 16 {
			break
		}
		v.reset(OpZeroExt16to32)
		v0 := b.NewValue0(v.Pos, OpTrunc32to16, typ.UInt16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux8 <t> x (Const8 [c]))
	// result: (Rsh32Ux64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux8 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x16 <t> x (Const16 [c]))
	// result: (Rsh32x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x16 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x32 <t> x (Const32 [c]))
	// result: (Rsh32x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x32 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x64 (Const32 [c]) (Const64 [d]))
	// result: (Const32 [c >> uint64(d)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		return true
	}
	// match: (Rsh32x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh32x64 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Rsh32x64 <t> (Rsh32x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh32x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh32x64 {
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
		v.reset(OpRsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x64 (Lsh32x64 x (Const64 [24])) (Const64 [24]))
	// result: (SignExt8to32 (Trunc32to8 <typ.Int8> x))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 24 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 24 {
			break
		}
		v.reset(OpSignExt8to32)
		v0 := b.NewValue0(v.Pos, OpTrunc32to8, typ.Int8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh32x64 (Lsh32x64 x (Const64 [16])) (Const64 [16]))
	// result: (SignExt16to32 (Trunc32to16 <typ.Int16> x))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 16 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 16 {
			break
		}
		v.reset(OpSignExt16to32)
		v0 := b.NewValue0(v.Pos, OpTrunc32to16, typ.Int16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x8 <t> x (Const8 [c]))
	// result: (Rsh32x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x8 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64Ux16 <t> x (Const16 [c]))
	// result: (Rsh64Ux64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux16 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64Ux32 <t> x (Const32 [c]))
	// result: (Rsh64Ux64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux32 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [int64(uint64(c) >> uint64(d))])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		return true
	}
	// match: (Rsh64Ux64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh64Ux64 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Rsh64Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 64
	// result: (Const64 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Rsh64Ux64 <t> (Rsh64Ux64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh64Ux64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh64Ux64 {
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
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux64 (Rsh64x64 x _) (Const64 <t> [63]))
	// result: (Rsh64Ux64 x (Const64 <t> [63]))
	for {
		if v_0.Op != OpRsh64x64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 63 {
			break
		}
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(63)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux64 i:(Lsh64x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 64 && i.Uses == 1
	// result: (And64 x (Const64 <v.Type> [int64(^uint64(0)>>c)]))
	for {
		i := v_0
		if i.Op != OpLsh64x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 64 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd64)
		v0 := b.NewValue0(v.Pos, OpConst64, v.Type)
		v0.AuxInt = int64ToAuxInt(int64(^uint64(0) >> c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux64 (Lsh64x64 (Rsh64Ux64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Rsh64Ux64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh64Ux64 {
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
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux64 (Lsh64x64 x (Const64 [56])) (Const64 [56]))
	// result: (ZeroExt8to64 (Trunc64to8 <typ.UInt8> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 56 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 56 {
			break
		}
		v.reset(OpZeroExt8to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to8, typ.UInt8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh64Ux64 (Lsh64x64 x (Const64 [48])) (Const64 [48]))
	// result: (ZeroExt16to64 (Trunc64to16 <typ.UInt16> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 48 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 48 {
			break
		}
		v.reset(OpZeroExt16to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to16, typ.UInt16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh64Ux64 (Lsh64x64 x (Const64 [32])) (Const64 [32]))
	// result: (ZeroExt32to64 (Trunc64to32 <typ.UInt32> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 32 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 32 {
			break
		}
		v.reset(OpZeroExt32to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to32, typ.UInt32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64Ux8 <t> x (Const8 [c]))
	// result: (Rsh64Ux64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux8 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x16 <t> x (Const16 [c]))
	// result: (Rsh64x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x16 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x32 <t> x (Const32 [c]))
	// result: (Rsh64x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x32 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c >> uint64(d)])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		return true
	}
	// match: (Rsh64x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh64x64 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Rsh64x64 <t> (Rsh64x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh64x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh64x64 {
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
		v.reset(OpRsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x64 (Lsh64x64 x (Const64 [56])) (Const64 [56]))
	// result: (SignExt8to64 (Trunc64to8 <typ.Int8> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 56 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 56 {
			break
		}
		v.reset(OpSignExt8to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to8, typ.Int8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh64x64 (Lsh64x64 x (Const64 [48])) (Const64 [48]))
	// result: (SignExt16to64 (Trunc64to16 <typ.Int16> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 48 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 48 {
			break
		}
		v.reset(OpSignExt16to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to16, typ.Int16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh64x64 (Lsh64x64 x (Const64 [32])) (Const64 [32]))
	// result: (SignExt32to64 (Trunc64to32 <typ.Int32> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 32 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 32 {
			break
		}
		v.reset(OpSignExt32to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x8 <t> x (Const8 [c]))
	// result: (Rsh64x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x8 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux16 <t> x (Const16 [c]))
	// result: (Rsh8Ux64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux16 (Const8 [0]) _)
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
func rewriteValuegeneric_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux32 <t> x (Const32 [c]))
	// result: (Rsh8Ux64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux32 (Const8 [0]) _)
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
func rewriteValuegeneric_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 (Const8 [c]) (Const64 [d]))
	// result: (Const8 [int8(uint8(c) >> uint64(d))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(int8(uint8(c) >> uint64(d)))
		return true
	}
	// match: (Rsh8Ux64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh8Ux64 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Rsh8Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 8
	// result: (Const8 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 8) {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Rsh8Ux64 <t> (Rsh8Ux64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh8Ux64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh8Ux64 {
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
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux64 (Rsh8x64 x _) (Const64 <t> [7] ))
	// result: (Rsh8Ux64 x (Const64 <t> [7] ))
	for {
		if v_0.Op != OpRsh8x64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 7 {
			break
		}
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(7)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux64 i:(Lsh8x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 8 && i.Uses == 1
	// result: (And8 x (Const8 <v.Type> [int8 (^uint8 (0)>>c)]))
	for {
		i := v_0
		if i.Op != OpLsh8x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 8 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd8)
		v0 := b.NewValue0(v.Pos, OpConst8, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(^uint8(0) >> c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux64 (Lsh8x64 (Rsh8Ux64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Rsh8Ux64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpLsh8x64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh8Ux64 {
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
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux8 <t> x (Const8 [c]))
	// result: (Rsh8Ux64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux8 (Const8 [0]) _)
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
func rewriteValuegeneric_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x16 <t> x (Const16 [c]))
	// result: (Rsh8x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x16 (Const8 [0]) _)
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
func rewriteValuegeneric_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x32 <t> x (Const32 [c]))
	// result: (Rsh8x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x32 (Const8 [0]) _)
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
func rewriteValuegeneric_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x64 (Const8 [c]) (Const64 [d]))
	// result: (Const8 [c >> uint64(d)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(c >> uint64(d))
		return true
	}
	// match: (Rsh8x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh8x64 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Rsh8x64 <t> (Rsh8x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh8x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh8x64 {
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
		v.reset(OpRsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x8 <t> x (Const8 [c]))
	// result: (Rsh8x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x8 (Const8 [0]) _)
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
func rewriteValuegeneric_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Select0 (Div128u (Const64 [0]) lo y))
	// result: (Div64u lo y)
	for {
		if v_0.Op != OpDiv128u {
			break
		}
		y := v_0.Args[2]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 0 {
			break
		}
		lo := v_0.Args[1]
		v.reset(OpDiv64u)
		v.AddArg2(lo, y)
		return true
	}
	// match: (Select0 (Mul32uover (Const32 [1]) x))
	// result: x
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 || auxIntToInt32(v_0_0.AuxInt) != 1 {
				continue
			}
			x := v_0_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Select0 (Mul64uover (Const64 [1]) x))
	// result: x
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 1 {
				continue
			}
			x := v_0_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Select0 (Mul64uover (Const64 [0]) x))
	// result: (Const64 [0])
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Select0 (Mul32uover (Const32 [0]) x))
	// result: (Const32 [0])
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 || auxIntToInt32(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Select1 (Div128u (Const64 [0]) lo y))
	// result: (Mod64u lo y)
	for {
		if v_0.Op != OpDiv128u {
			break
		}
		y := v_0.Args[2]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 0 {
			break
		}
		lo := v_0.Args[1]
		v.reset(OpMod64u)
		v.AddArg2(lo, y)
		return true
	}
	// match: (Select1 (Mul32uover (Const32 [1]) x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 || auxIntToInt32(v_0_0.AuxInt) != 1 {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (Select1 (Mul64uover (Const64 [1]) x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 1 {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (Select1 (Mul64uover (Const64 [0]) x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (Select1 (Mul32uover (Const32 [0]) x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 || auxIntToInt32(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (SelectN [0] (MakeResult x ___))
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 || v_0.Op != OpMakeResult || len(v_0.Args) < 1 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (SelectN [1] (MakeResult x y ___))
	// result: y
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpMakeResult || len(v_0.Args) < 2 {
			break
		}
		y := v_0.Args[1]
		v.copyOf(y)
		return true
	}
	// match: (SelectN [2] (MakeResult x y z ___))
	// result: z
	for {
		if auxIntToInt64(v.AuxInt) != 2 || v_0.Op != OpMakeResult || len(v_0.Args) < 3 {
			break
		}
		z := v_0.Args[2]
		v.copyOf(z)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} sptr (Const64 [c]) mem))
	// cond: isInlinableMemclr(config, int64(c)) && isSameCall(sym, "runtime.memclrNoHeapPointers") && call.Uses == 1 && clobber(call)
	// result: (Zero {types.Types[types.TUINT8]} [int64(c)] sptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 3 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[2]
		sptr := call.Args[0]
		call_1 := call.Args[1]
		if call_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(call_1.AuxInt)
		if !(isInlinableMemclr(config, int64(c)) && isSameCall(sym, "runtime.memclrNoHeapPointers") && call.Uses == 1 && clobber(call)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(int64(c))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg2(sptr, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} sptr (Const32 [c]) mem))
	// cond: isInlinableMemclr(config, int64(c)) && isSameCall(sym, "runtime.memclrNoHeapPointers") && call.Uses == 1 && clobber(call)
	// result: (Zero {types.Types[types.TUINT8]} [int64(c)] sptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 3 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[2]
		sptr := call.Args[0]
		call_1 := call.Args[1]
		if call_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(call_1.AuxInt)
		if !(isInlinableMemclr(config, int64(c)) && isSameCall(sym, "runtime.memclrNoHeapPointers") && call.Uses == 1 && clobber(call)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(int64(c))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg2(sptr, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} s1:(Store _ (Const64 [sz]) s2:(Store _ src s3:(Store {t} _ dst mem)))))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, int64(sz), config) && clobber(s1, s2, s3, call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpStore {
			break
		}
		_ = s1.Args[2]
		s1_1 := s1.Args[1]
		if s1_1.Op != OpConst64 {
			break
		}
		sz := auxIntToInt64(s1_1.AuxInt)
		s2 := s1.Args[2]
		if s2.Op != OpStore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpStore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, int64(sz), config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} s1:(Store _ (Const32 [sz]) s2:(Store _ src s3:(Store {t} _ dst mem)))))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, int64(sz), config) && clobber(s1, s2, s3, call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpStore {
			break
		}
		_ = s1.Args[2]
		s1_1 := s1.Args[1]
		if s1_1.Op != OpConst32 {
			break
		}
		sz := auxIntToInt32(s1_1.AuxInt)
		s2 := s1.Args[2]
		if s2.Op != OpStore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpStore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, int64(sz), config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} dst src (Const64 [sz]) mem))
	// cond: sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpConst64 {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} dst src (Const32 [sz]) mem))
	// cond: sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpConst32 {
			break
		}
		sz := auxIntToInt32(call_2.AuxInt)
		if !(sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticLECall {sym} dst src (Const64 [sz]) mem))
	// cond: sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticLECall || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpConst64 {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticLECall {sym} dst src (Const32 [sz]) mem))
	// cond: sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticLECall || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpConst32 {
			break
		}
		sz := auxIntToInt32(call_2.AuxInt)
		if !(sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticLECall {sym} a x))
	// cond: needRaceCleanup(sym, call) && clobber(call)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticLECall || len(call.Args) != 2 {
			break
		}
		sym := auxToCall(call.Aux)
		x := call.Args[1]
		if !(needRaceCleanup(sym, call) && clobber(call)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SelectN [0] call:(StaticLECall {sym} x))
	// cond: needRaceCleanup(sym, call) && clobber(call)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticLECall || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		x := call.Args[0]
		if !(needRaceCleanup(sym, call) && clobber(call)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SelectN [1] (StaticCall {sym} _ newLen:(Const64) _ _ _ _))
	// cond: v.Type.IsInteger() && isSameCall(sym, "runtime.growslice")
	// result: newLen
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpStaticCall || len(v_0.Args) != 6 {
			break
		}
		sym := auxToCall(v_0.Aux)
		_ = v_0.Args[1]
		newLen := v_0.Args[1]
		if newLen.Op != OpConst64 || !(v.Type.IsInteger() && isSameCall(sym, "runtime.growslice")) {
			break
		}
		v.copyOf(newLen)
		return true
	}
	// match: (SelectN [1] (StaticCall {sym} _ newLen:(Const32) _ _ _ _))
	// cond: v.Type.IsInteger() && isSameCall(sym, "runtime.growslice")
	// result: newLen
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpStaticCall || len(v_0.Args) != 6 {
			break
		}
		sym := auxToCall(v_0.Aux)
		_ = v_0.Args[1]
		newLen := v_0.Args[1]
		if newLen.Op != OpConst32 || !(v.Type.IsInteger() && isSameCall(sym, "runtime.growslice")) {
			break
		}
		v.copyOf(newLen)
		return true
	}
	// match: (SelectN [0] (StaticLECall {f} x y (SelectN [1] c:(StaticLECall {g} x y mem))))
	// cond: isSameCall(f, "runtime.cmpstring") && isSameCall(g, "runtime.cmpstring")
	// result: @c.Block (SelectN [0] <typ.Int> c)
	for {
		if auxIntToInt64(v.AuxInt) != 0 || v_0.Op != OpStaticLECall || len(v_0.Args) != 3 {
			break
		}
		f := auxToCall(v_0.Aux)
		_ = v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpSelectN || auxIntToInt64(v_0_2.AuxInt) != 1 {
			break
		}
		c := v_0_2.Args[0]
		if c.Op != OpStaticLECall || len(c.Args) != 3 {
			break
		}
		g := auxToCall(c.Aux)
		if x != c.Args[0] || y != c.Args[1] || !(isSameCall(f, "runtime.cmpstring") && isSameCall(g, "runtime.cmpstring")) {
			break
		}
		b = c.Block
		v0 := b.NewValue0(v.Pos, OpSelectN, typ.Int)
		v.copyOf(v0)
		v0.AuxInt = int64ToAuxInt(0)
		v0.AddArg(c)
		return true
	}
	// match: (SelectN [1] c:(StaticLECall {f} _ _ mem))
	// cond: c.Uses == 1 && isSameCall(f, "runtime.cmpstring") && clobber(c)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		c := v_0
		if c.Op != OpStaticLECall || len(c.Args) != 3 {
			break
		}
		f := auxToCall(c.Aux)
		mem := c.Args[2]
		if !(c.Uses == 1 && isSameCall(f, "runtime.cmpstring") && clobber(c)) {
			break
		}
		v.copyOf(mem)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt16to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt16to32 (Const16 [c]))
	// result: (Const32 [int32(c)])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
	// match: (SignExt16to32 (Trunc32to16 x:(Rsh32x64 _ (Const64 [s]))))
	// cond: s >= 16
	// result: x
	for {
		if v_0.Op != OpTrunc32to16 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh32x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 16) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt16to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt16to64 (Const16 [c]))
	// result: (Const64 [int64(c)])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
	// match: (SignExt16to64 (Trunc64to16 x:(Rsh64x64 _ (Const64 [s]))))
	// cond: s >= 48
	// result: x
	for {
		if v_0.Op != OpTrunc64to16 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 48) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt32to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt32to64 (Const32 [c]))
	// result: (Const64 [int64(c)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
	// match: (SignExt32to64 (Trunc64to32 x:(Rsh64x64 _ (Const64 [s]))))
	// cond: s >= 32
	// result: x
	for {
		if v_0.Op != OpTrunc64to32 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 32) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt8to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt8to16 (Const8 [c]))
	// result: (Const16 [int16(c)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(c))
		return true
	}
	// match: (SignExt8to16 (Trunc16to8 x:(Rsh16x64 _ (Const64 [s]))))
	// cond: s >= 8
	// result: x
	for {
		if v_0.Op != OpTrunc16to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh16x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt8to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt8to32 (Const8 [c]))
	// result: (Const32 [int32(c)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
	// match: (SignExt8to32 (Trunc32to8 x:(Rsh32x64 _ (Const64 [s]))))
	// cond: s >= 24
	// result: x
	for {
		if v_0.Op != OpTrunc32to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh32x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 24) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt8to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt8to64 (Const8 [c]))
	// result: (Const64 [int64(c)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
	// match: (SignExt8to64 (Trunc64to8 x:(Rsh64x64 _ (Const64 [s]))))
	// cond: s >= 56
	// result: x
	for {
		if v_0.Op != OpTrunc64to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 56) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSliceCap(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SliceCap (SliceMake _ _ (Const64 <t> [c])))
	// result: (Const64 <t> [c])
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[2]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpConst64 {
			break
		}
		t := v_0_2.Type
		c := auxIntToInt64(v_0_2.AuxInt)
		v.reset(OpConst64)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	// match: (SliceCap (SliceMake _ _ (Const32 <t> [c])))
	// result: (Const32 <t> [c])
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[2]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpConst32 {
			break
		}
		t := v_0_2.Type
		c := auxIntToInt32(v_0_2.AuxInt)
		v.reset(OpConst32)
		v.Type = t
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	// match: (SliceCap (SliceMake _ _ (SliceCap x)))
	// result: (SliceCap x)
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[2]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpSliceCap {
			break
		}
		x := v_0_2.Args[0]
		v.reset(OpSliceCap)
		v.AddArg(x)
		return true
	}
	// match: (SliceCap (SliceMake _ _ (SliceLen x)))
	// result: (SliceLen x)
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[2]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpSliceLen {
			break
		}
		x := v_0_2.Args[0]
		v.reset(OpSliceLen)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSliceLen(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SliceLen (SliceMake _ (Const64 <t> [c]) _))
	// result: (Const64 <t> [c])
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		t := v_0_1.Type
		c := auxIntToInt64(v_0_1.AuxInt)
		v.reset(OpConst64)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	// match: (SliceLen (SliceMake _ (Const32 <t> [c]) _))
	// result: (Const32 <t> [c])
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst32 {
			break
		}
		t := v_0_1.Type
		c := auxIntToInt32(v_0_1.AuxInt)
		v.reset(OpConst32)
		v.Type = t
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	// match: (SliceLen (SliceMake _ (SliceLen x) _))
	// result: (SliceLen x)
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpSliceLen {
			break
		}
		x := v_0_1.Args[0]
		v.reset(OpSliceLen)
		v.AddArg(x)
		return true
	}
	// match: (SliceLen (SelectN [0] (StaticLECall {sym} _ newLen:(Const64) _ _ _ _)))
	// cond: isSameCall(sym, "runtime.growslice")
	// result: newLen
	for {
		if v_0.Op != OpSelectN || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpStaticLECall || len(v_0_0.Args) != 6 {
			break
		}
		sym := auxToCall(v_0_0.Aux)
		_ = v_0_0.Args[1]
		newLen := v_0_0.Args[1]
		if newLen.Op != OpConst64 || !(isSameCall(sym, "runtime.growslice")) {
			break
		}
		v.copyOf(newLen)
		return true
	}
	// match: (SliceLen (SelectN [0] (StaticLECall {sym} _ newLen:(Const32) _ _ _ _)))
	// cond: isSameCall(sym, "runtime.growslice")
	// result: newLen
	for {
		if v_0.Op != OpSelectN || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpStaticLECall || len(v_0_0.Args) != 6 {
			break
		}
		sym := auxToCall(v_0_0.Aux)
		_ = v_0_0.Args[1]
		newLen := v_0_0.Args[1]
		if newLen.Op != OpConst32 || !(isSameCall(sym, "runtime.growslice")) {
			break
		}
		v.copyOf(newLen)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSlicePtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SlicePtr (SliceMake (SlicePtr x) _ _))
	// result: (SlicePtr x)
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSlicePtr {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpSlicePtr)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Slicemask (Const32 [x]))
	// cond: x > 0
	// result: (Const32 [-1])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x > 0) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(-1)
		return true
	}
	// match: (Slicemask (Const32 [0]))
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Slicemask (Const64 [x]))
	// cond: x > 0
	// result: (Const64 [-1])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x > 0) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (Slicemask (Const64 [0]))
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSqrt(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Sqrt (Const64F [c]))
	// cond: !math.IsNaN(math.Sqrt(c))
	// result: (Const64F [math.Sqrt(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		if !(!math.IsNaN(math.Sqrt(c))) {
			break
		}
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(math.Sqrt(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpStaticCall(v *Value) bool {
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (StaticCall {callAux} p q _ mem)
	// cond: isSameCall(callAux, "runtime.memequal") && isSamePtr(p, q)
	// result: (MakeResult (ConstBool <typ.Bool> [true]) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		p := v.Args[0]
		q := v.Args[1]
		if !(isSameCall(callAux, "runtime.memequal") && isSamePtr(p, q)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpConstBool, typ.Bool)
		v0.AuxInt = boolToAuxInt(true)
		v.AddArg2(v0, mem)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStaticLECall(v *Value) bool {
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (StaticLECall {callAux} sptr (Addr {scon} (SB)) (Const64 [1]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon)
	// result: (MakeResult (Eq8 (Load <typ.Int8> sptr mem) (Const8 <typ.Int8> [int8(read8(scon,0))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		sptr := v.Args[0]
		v_1 := v.Args[1]
		if v_1.Op != OpAddr {
			break
		}
		sc
```