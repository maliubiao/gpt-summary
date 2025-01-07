Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteRISCV64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共4部分，请归纳一下它的功能

"""
 mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v2.AuxInt = int32ToAuxInt(1)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpRISCV64MOVBstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [6] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [4] dst (MOVHload [4] src mem) (MOVHstore [2] dst (MOVHload [2] src mem) (MOVHstore dst (MOVHload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpRISCV64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v2.AuxInt = int32ToAuxInt(2)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpRISCV64MOVHstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [12] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [8] dst (MOVWload [8] src mem) (MOVWstore [4] dst (MOVWload [4] src mem) (MOVWstore dst (MOVWload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpRISCV64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVWload, typ.Int32)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVWload, typ.Int32)
		v2.AuxInt = int32ToAuxInt(4)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpRISCV64MOVWstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpRISCV64MOVWload, typ.Int32)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [16] {t} dst src mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVDstore [8] dst (MOVDload [8] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpRISCV64MOVDstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [24] {t} dst src mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVDstore [16] dst (MOVDload [16] src mem) (MOVDstore [8] dst (MOVDload [8] src mem) (MOVDstore dst (MOVDload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 24 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpRISCV64MOVDstore)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v0.AuxInt = int32ToAuxInt(16)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVDstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v2.AuxInt = int32ToAuxInt(8)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpRISCV64MOVDstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [32] {t} dst src mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVDstore [24] dst (MOVDload [24] src mem) (MOVDstore [16] dst (MOVDload [16] src mem) (MOVDstore [8] dst (MOVDload [8] src mem) (MOVDstore dst (MOVDload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpRISCV64MOVDstore)
		v.AuxInt = int32ToAuxInt(24)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v0.AuxInt = int32ToAuxInt(24)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVDstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(16)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v2.AuxInt = int32ToAuxInt(16)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpRISCV64MOVDstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(8)
		v4 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v4.AuxInt = int32ToAuxInt(8)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpRISCV64MOVDstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] {t} dst src mem)
	// cond: s%8 == 0 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice && logLargeCopy(v, s)
	// result: (DUFFCOPY [16 * (128 - s/8)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%8 == 0 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpRISCV64DUFFCOPY)
		v.AuxInt = int64ToAuxInt(16 * (128 - s/8))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] {t} dst src mem)
	// cond: (s <= 16 || logLargeCopy(v, s))
	// result: (LoweredMove [t.Alignment()] dst src (ADDI <src.Type> [s-moveSize(t.Alignment(), config)] src) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s <= 16 || logLargeCopy(v, s)) {
			break
		}
		v.reset(OpRISCV64LoweredMove)
		v.AuxInt = int64ToAuxInt(t.Alignment())
		v0 := b.NewValue0(v.Pos, OpRISCV64ADDI, src.Type)
		v0.AuxInt = int64ToAuxInt(s - moveSize(t.Alignment(), config))
		v0.AddArg(src)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpMul16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul16 x y)
	// result: (MULW (SignExt16to32 x) (SignExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64MULW)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpMul8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul8 x y)
	// result: (MULW (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64MULW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (Not (Eq16 x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpEq16, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32 x y)
	// result: (Not (Eq32 x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpEq32, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq64 x y)
	// result: (Not (Eq64 x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpEq64, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (Not (Eq8 x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpEq8, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpNeqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqB x y)
	// result: (SNEZ (SUB <typ.Bool> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SNEZ)
		v0 := b.NewValue0(v.Pos, OpRISCV64SUB, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqPtr x y)
	// result: (Not (EqPtr x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpEqPtr, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (OffPtr [off] ptr:(SP))
	// cond: is32Bit(off)
	// result: (MOVaddr [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if ptr.Op != OpSP || !(is32Bit(off)) {
			break
		}
		v.reset(OpRISCV64MOVaddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// cond: is32Bit(off)
	// result: (ADDI [off] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if !(is32Bit(off)) {
			break
		}
		v.reset(OpRISCV64ADDI)
		v.AuxInt = int64ToAuxInt(off)
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// result: (ADD (MOVDconst [off]) ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpRISCV64ADD)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(off)
		v.AddArg2(v0, ptr)
		return true
	}
}
func rewriteValueRISCV64_OpPanicBounds(v *Value) bool {
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
		v.reset(OpRISCV64LoweredPanicBoundsA)
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
		v.reset(OpRISCV64LoweredPanicBoundsB)
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
		v.reset(OpRISCV64LoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64ADD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADD (MOVDconst <t> [val]) x)
	// cond: is32Bit(val) && !t.IsPtr()
	// result: (ADDI [val] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpRISCV64MOVDconst {
				continue
			}
			t := v_0.Type
			val := auxIntToInt64(v_0.AuxInt)
			x := v_1
			if !(is32Bit(val) && !t.IsPtr()) {
				continue
			}
			v.reset(OpRISCV64ADDI)
			v.AuxInt = int64ToAuxInt(val)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADD (SLLI [1] x) y)
	// cond: buildcfg.GORISCV64 >= 22
	// result: (SH1ADD x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpRISCV64SLLI || auxIntToInt64(v_0.AuxInt) != 1 {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			if !(buildcfg.GORISCV64 >= 22) {
				continue
			}
			v.reset(OpRISCV64SH1ADD)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADD (SLLI [2] x) y)
	// cond: buildcfg.GORISCV64 >= 22
	// result: (SH2ADD x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpRISCV64SLLI || auxIntToInt64(v_0.AuxInt) != 2 {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			if !(buildcfg.GORISCV64 >= 22) {
				continue
			}
			v.reset(OpRISCV64SH2ADD)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADD (SLLI [3] x) y)
	// cond: buildcfg.GORISCV64 >= 22
	// result: (SH3ADD x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpRISCV64SLLI || auxIntToInt64(v_0.AuxInt) != 3 {
				continue
			}
			x := v_0.Args[0]
			y := v_1
			if !(buildcfg.GORISCV64 >= 22) {
				continue
			}
			v.reset(OpRISCV64SH3ADD)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64ADDI(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDI [c] (MOVaddr [d] {s} x))
	// cond: is32Bit(c+int64(d))
	// result: (MOVaddr [int32(c)+d] {s} x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		if !(is32Bit(c + int64(d))) {
			break
		}
		v.reset(OpRISCV64MOVaddr)
		v.AuxInt = int32ToAuxInt(int32(c) + d)
		v.Aux = symToAux(s)
		v.AddArg(x)
		return true
	}
	// match: (ADDI [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ADDI [x] (MOVDconst [y]))
	// cond: is32Bit(x + y)
	// result: (MOVDconst [x + y])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		if !(is32Bit(x + y)) {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(x + y)
		return true
	}
	// match: (ADDI [x] (ADDI [y] z))
	// cond: is32Bit(x + y)
	// result: (ADDI [x + y] z)
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		z := v_0.Args[0]
		if !(is32Bit(x + y)) {
			break
		}
		v.reset(OpRISCV64ADDI)
		v.AuxInt = int64ToAuxInt(x + y)
		v.AddArg(z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64AND(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AND (MOVDconst [val]) x)
	// cond: is32Bit(val)
	// result: (ANDI [val] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpRISCV64MOVDconst {
				continue
			}
			val := auxIntToInt64(v_0.AuxInt)
			x := v_1
			if !(is32Bit(val)) {
				continue
			}
			v.reset(OpRISCV64ANDI)
			v.AuxInt = int64ToAuxInt(val)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64ANDI(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDI [0] x)
	// result: (MOVDconst [0])
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (ANDI [-1] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ANDI [x] (MOVDconst [y]))
	// result: (MOVDconst [x & y])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(x & y)
		return true
	}
	// match: (ANDI [x] (ANDI [y] z))
	// result: (ANDI [x & y] z)
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64ANDI {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		z := v_0.Args[0]
		v.reset(OpRISCV64ANDI)
		v.AuxInt = int64ToAuxInt(x & y)
		v.AddArg(z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FADDD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FADDD a (FMULD x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMADDD x y a)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpRISCV64FMULD {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpRISCV64FMADDD)
			v.AddArg3(x, y, a)
			return true
		}
		break
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FADDS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FADDS a (FMULS x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMADDS x y a)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpRISCV64FMULS {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpRISCV64FMADDS)
			v.AddArg3(x, y, a)
			return true
		}
		break
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FMADDD(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMADDD neg:(FNEGD x) y z)
	// cond: neg.Uses == 1
	// result: (FNMSUBD x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			neg := v_0
			if neg.Op != OpRISCV64FNEGD {
				continue
			}
			x := neg.Args[0]
			y := v_1
			z := v_2
			if !(neg.Uses == 1) {
				continue
			}
			v.reset(OpRISCV64FNMSUBD)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (FMADDD x y neg:(FNEGD z))
	// cond: neg.Uses == 1
	// result: (FMSUBD x y z)
	for {
		x := v_0
		y := v_1
		neg := v_2
		if neg.Op != OpRISCV64FNEGD {
			break
		}
		z := neg.Args[0]
		if !(neg.Uses == 1) {
			break
		}
		v.reset(OpRISCV64FMSUBD)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FMADDS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMADDS neg:(FNEGS x) y z)
	// cond: neg.Uses == 1
	// result: (FNMSUBS x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			neg := v_0
			if neg.Op != OpRISCV64FNEGS {
				continue
			}
			x := neg.Args[0]
			y := v_1
			z := v_2
			if !(neg.Uses == 1) {
				continue
			}
			v.reset(OpRISCV64FNMSUBS)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (FMADDS x y neg:(FNEGS z))
	// cond: neg.Uses == 1
	// result: (FMSUBS x y z)
	for {
		x := v_0
		y := v_1
		neg := v_2
		if neg.Op != OpRISCV64FNEGS {
			break
		}
		z := neg.Args[0]
		if !(neg.Uses == 1) {
			break
		}
		v.reset(OpRISCV64FMSUBS)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FMSUBD(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMSUBD neg:(FNEGD x) y z)
	// cond: neg.Uses == 1
	// result: (FNMADDD x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			neg := v_0
			if neg.Op != OpRISCV64FNEGD {
				continue
			}
			x := neg.Args[0]
			y := v_1
			z := v_2
			if !(neg.Uses == 1) {
				continue
			}
			v.reset(OpRISCV64FNMADDD)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (FMSUBD x y neg:(FNEGD z))
	// cond: neg.Uses == 1
	// result: (FMADDD x y z)
	for {
		x := v_0
		y := v_1
		neg := v_2
		if neg.Op != OpRISCV64FNEGD {
			break
		}
		z := neg.Args[0]
		if !(neg.Uses == 1) {
			break
		}
		v.reset(OpRISCV64FMADDD)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FMSUBS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMSUBS neg:(FNEGS x) y z)
	// cond: neg.Uses == 1
	// result: (FNMADDS x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			neg := v_0
			if neg.Op != OpRISCV64FNEGS {
				continue
			}
			x := neg.Args[0]
			y := v_1
			z := v_2
			if !(neg.Uses == 1) {
				continue
			}
			v.reset(OpRISCV64FNMADDS)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (FMSUBS x y neg:(FNEGS z))
	// cond: neg.Uses == 1
	// result: (FMADDS x y z)
	for {
		x := v_0
		y := v_1
		neg := v_2
		if neg.Op != OpRISCV64FNEGS {
			break
		}
		z := neg.Args[0]
		if !(neg.Uses == 1) {
			break
		}
		v.reset(OpRISCV64FMADDS)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FNMADDD(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FNMADDD neg:(FNEGD x) y z)
	// cond: neg.Uses == 1
	// result: (FMSUBD x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			neg := v_0
			if neg.Op != OpRISCV64FNEGD {
				continue
			}
			x := neg.Args[0]
			y := v_1
			z := v_2
			if !(neg.Uses == 1) {
				continue
			}
			v.reset(OpRISCV64FMSUBD)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (FNMADDD x y neg:(FNEGD z))
	// cond: neg.Uses == 1
	// result: (FNMSUBD x y z)
	for {
		x := v_0
		y := v_1
		neg := v_2
		if neg.Op != OpRISCV64FNEGD {
			break
		}
		z := neg.Args[0]
		if !(neg.Uses == 1) {
			break
		}
		v.reset(OpRISCV64FNMSUBD)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FNMADDS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FNMADDS neg:(FNEGS x) y z)
	// cond: neg.Uses == 1
	// result: (FMSUBS x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			neg := v_0
			if neg.Op != OpRISCV64FNEGS {
				continue
			}
			x := neg.Args[0]
			y := v_1
			z := v_2
			if !(neg.Uses == 1) {
				continue
			}
			v.reset(OpRISCV64FMSUBS)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (FNMADDS x y neg:(FNEGS z))
	// cond: neg.Uses == 1
	// result: (FNMSUBS x y z)
	for {
		x := v_0
		y := v_1
		neg := v_2
		if neg.Op != OpRISCV64FNEGS {
			break
		}
		z := neg.Args[0]
		if !(neg.Uses == 1) {
			break
		}
		v.reset(OpRISCV64FNMSUBS)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FNMSUBD(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FNMSUBD neg:(FNEGD x) y z)
	// cond: neg.Uses == 1
	// result: (FMADDD x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			neg := v_0
			if neg.Op != OpRISCV64FNEGD {
				continue
			}
			x := neg.Args[0]
			y := v_1
			z := v_2
			if !(neg.Uses == 1) {
				continue
			}
			v.reset(OpRISCV64FMADDD)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (FNMSUBD x y neg:(FNEGD z))
	// cond: neg.Uses == 1
	// result: (FNMADDD x y z)
	for {
		x := v_0
		y := v_1
		neg := v_2
		if neg.Op != OpRISCV64FNEGD {
			break
		}
		z := neg.Args[0]
		if !(neg.Uses == 1) {
			break
		}
		v.reset(OpRISCV64FNMADDD)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FNMSUBS(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FNMSUBS neg:(FNEGS x) y z)
	// cond: neg.Uses == 1
	// result: (FMADDS x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			neg := v_0
			if neg.Op != OpRISCV64FNEGS {
				continue
			}
			x := neg.Args[0]
			y := v_1
			z := v_2
			if !(neg.Uses == 1) {
				continue
			}
			v.reset(OpRISCV64FMADDS)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (FNMSUBS x y neg:(FNEGS z))
	// cond: neg.Uses == 1
	// result: (FNMADDS x y z)
	for {
		x := v_0
		y := v_1
		neg := v_2
		if neg.Op != OpRISCV64FNEGS {
			break
		}
		z := neg.Args[0]
		if !(neg.Uses == 1) {
			break
		}
		v.reset(OpRISCV64FNMADDS)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FSUBD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FSUBD a (FMULD x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FNMSUBD x y a)
	for {
		a := v_0
		if v_1.Op != OpRISCV64FMULD {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpRISCV64FNMSUBD)
		v.AddArg3(x, y, a)
		return true
	}
	// match: (FSUBD (FMULD x y) a)
	// cond: a.Block.Func.useFMA(v)
	// result: (FMSUBD x y a)
	for {
		if v_0.Op != OpRISCV64FMULD {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		a := v_1
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpRISCV64FMSUBD)
		v.AddArg3(x, y, a)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64FSUBS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FSUBS a (FMULS x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FNMSUBS x y a)
	for {
		a := v_0
		if v_1.Op != OpRISCV64FMULS {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpRISCV64FNMSUBS)
		v.AddArg3(x, y, a)
		return true
	}
	// match: (FSUBS (FMULS x y) a)
	// cond: a.Block.Func.useFMA(v)
	// result: (FMSUBS x y a)
	for {
		if v_0.Op != OpRISCV64FMULS {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		a := v_1
		if !(a.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpRISCV64FMSUBS)
		v.AddArg3(x, y, a)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVBUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBUload [off1] {sym1} (MOVaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBUload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVBUload [off1] {sym} (ADDI [off2] base) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVBUload [off1+int32(off2)] {sym} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVBUreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVBUreg x:(FLES _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64FLES {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(FLTS _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64FLTS {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(FEQS _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64FEQS {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(FNES _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64FNES {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(FLED _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64FLED {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(FLTD _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64FLTD {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(FEQD _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64FEQD {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(FNED _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64FNED {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(SEQZ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64SEQZ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(SNEZ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64SNEZ {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(SLT _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64SLT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(SLTU _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64SLTU {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(ANDI [c] y))
	// cond: c >= 0 && int64(uint8(c)) == c
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64ANDI {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		if !(c >= 0 && int64(uint8(c)) == c) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg (ANDI [c] x))
	// cond: c < 0
	// result: (ANDI [int64(uint8(c))] x)
	for {
		if v_0.Op != OpRISCV64ANDI {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c < 0) {
			break
		}
		v.reset(OpRISCV64ANDI)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint8(c))])
	for {
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		return true
	}
	// match: (MOVBUreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(Select0 (LoweredAtomicLoad8 _ _)))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpSelect0 {
			break
		}
		x_0 := x.Args[0]
		if x_0.Op != OpRISCV64LoweredAtomicLoad8 {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(Select0 (LoweredAtomicCas32 _ _ _ _)))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpSelect0 {
			break
		}
		x_0 := x.Args[0]
		if x_0.Op != OpRISCV64LoweredAtomicCas32 {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(Select0 (LoweredAtomicCas64 _ _ _ _)))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpSelect0 {
			break
		}
		x_0 := x.Args[0]
		if x_0.Op != OpRISCV64LoweredAtomicCas64 {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg <t> x:(MOVBload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBUload <t> [off] {sym} ptr mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpRISCV64MOVBload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpRISCV64MOVBUload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVBload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBload [off1] {sym1} (MOVaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVBload [off1] {sym} (ADDI [off2] base) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVBload [off1+int32(off2)] {sym} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVBreg x:(ANDI [c] y))
	// cond: c >= 0 && int64(int8(c)) == c
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64ANDI {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		if !(c >= 0 && int64(int8(c)) == c) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int8(c))])
	for {
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int8(c)))
		return true
	}
	// match: (MOVBreg x:(MOVBload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg x:(MOVBreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg <t> x:(MOVBUload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBload <t> [off] {sym} ptr mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpRISCV64MOVBUload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpRISCV64MOVBload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstore [off1] {sym1} (MOVaddr [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym} (ADDI [off2] base) val mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVBstore [off1+int32(off2)] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVBstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpRISCV64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVBreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBUreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVBUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVHUreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVWUreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVBstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstorezero [off1] {sym1} (MOVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2))
	// result: (MOVBstorezero [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpRISCV64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstorezero [off1] {sym} (ADDI [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVBstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDload [off1] {sym1} (MOVaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVDload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVDload [off1] {sym} (ADDI [off2] base) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVDload [off1+int32(off2)] {sym} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVDnop(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVDnop (MOVDconst [c]))
	// result: (MOVDconst [c])
	for {
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVDreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVDreg x)
	// cond: x.Uses == 1
	// result: (MOVDnop x)
	for {
		x := v_0
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpRISCV64MOVDnop)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstore [off1] {sym1} (MOVaddr [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVDstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym} (ADDI [off2] base) val mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVDstore [off1+int32(off2)] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVDstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpRISCV64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVDstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstorezero [off1] {sym1} (MOVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2))
	// result: (MOVDstorezero [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpRISCV64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDstorezero [off1] {sym} (ADDI [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVDstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVHUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHUload [off1] {sym1} (MOVaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVHUload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVHUload [off1] {sym} (ADDI [off2] base) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVHUload [off1+int32(off2)] {sym} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVHUreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVHUreg x:(ANDI [c] y))
	// cond: c >= 0 && int64(uint16(c)) == c
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64ANDI {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		if !(c >= 0 && int64(uint16(c)) == c) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHUreg (ANDI [c] x))
	// cond: c < 0
	// result: (ANDI [int64(uint16(c))] x)
	for {
		if v_0.Op != OpRISCV64ANDI {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c < 0) {
			break
		}
		v.reset(OpRISCV64ANDI)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint16(c))])
	for {
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		return true
	}
	// match: (MOVHUreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVHUload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVHUreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg <t> x:(MOVHload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVHUload <t> [off] {sym} ptr mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpRISCV64MOVHload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpRISCV64MOVHUload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVHload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHload [off1] {sym1} (MOVaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVHload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVHload [off1] {sym} (ADDI [off2] base) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVHload [off1+int32(off2)] {sym} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVHreg x:(ANDI [c] y))
	// cond: c >= 0 && int64(int16(c)) == c
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64ANDI {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		if !(c >= 0 && int64(int16(c)) == c) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int16(c))])
	for {
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int16(c)))
		return true
	}
	// match: (MOVHreg x:(MOVBload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVHload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVHreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg <t> x:(MOVHUload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVHload <t> [off] {sym} ptr mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpRISCV64MOVHUload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpRISCV64MOVHload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVHstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstore [off1] {sym1} (MOVaddr [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVHstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym} (ADDI [off2] base) val mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVHstore [off1+int32(off2)] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVHstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpRISCV64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVHUreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVWUreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVHstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstorezero [off1] {sym1} (MOVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2))
	// result: (MOVHstorezero [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpRISCV64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstorezero [off1] {sym} (ADDI [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVHstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVWUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWUload [off1] {sym1} (MOVaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVWUload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVWUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVWUload [off1] {sym} (ADDI [off2] base) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVWUload [off1+int32(off2)] {sym} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVWUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVWUreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVWUreg x:(ANDI [c] y))
	// cond: c >= 0 && int64(uint32(c)) == c
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64ANDI {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		if !(c >= 0 && int64(uint32(c)) == c) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWUreg (ANDI [c] x))
	// cond: c < 0
	// result: (AND (MOVDconst [int64(uint32(c))]) x)
	for {
		if v_0.Op != OpRISCV64ANDI {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c < 0) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(v0, x)
		return true
	}
	// match: (MOVWUreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint32(c))])
	for {
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	// match: (MOVWUreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVHUload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVWUload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVHUreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVWUreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg <t> x:(MOVWload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWUload <t> [off] {sym} ptr mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpRISCV64MOVWload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpRISCV64MOVWUload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWload [off1] {sym1} (MOVaddr [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVWload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64MOVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpRISCV64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVWload [off1] {sym} (ADDI [off2] base) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVWload [off1+int32(off2)] {sym} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpRISCV64ADDI {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + off2)) {
			break
		}
		v.reset(OpRISCV64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVWreg x:(ANDI [c] y))
	// cond: c >= 0 && int64(int32(c)) == c
	// result: x
	for {
		x := v_0
		if x.Op != OpRISCV64ANDI {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		if !(c >= 0 && int64(int32(c)) == c) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int32(c))])
	for {
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(c)))
		return true
	}
	// match: (MOVWreg x:(MOVBload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVHload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVHUload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVWload {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(ADDIW _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64ADDIW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(SUBW _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64SUBW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(NEGW _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64NEGW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MULW _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MULW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(DIVW _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64DIVW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(DIVUW _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64DIVUW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(REMW _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64REMW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(REMUW _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64REMUW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(ROLW _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64ROLW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(RORW _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64RORW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(RORIW _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64RORIW {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVBUreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVHreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpRISCV64MOVWreg {
			break
		}
		v.reset(OpRISCV64MOVDreg)
		v.AddArg(
"""




```