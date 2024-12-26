Response:

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共13部分，请归纳一下它的功能

"""
: (Neg8 x)
	for {
		if v_0.Op != OpAdd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst8 || auxIntToInt8(v_0_0.AuxInt) != -1 {
				continue
			}
			x := v_0_1
			v.reset(OpNeg8)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpConstInterface(v *Value) bool {
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ConstInterface)
	// result: (IMake (ConstNil <typ.Uintptr>) (ConstNil <typ.BytePtr>))
	for {
		v.reset(OpIMake)
		v0 := b.NewValue0(v.Pos, OpConstNil, typ.Uintptr)
		v1 := b.NewValue0(v.Pos, OpConstNil, typ.BytePtr)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuegeneric_OpConstSlice(v *Value) bool {
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (ConstSlice)
	// cond: config.PtrSize == 4
	// result: (SliceMake (ConstNil <v.Type.Elem().PtrTo()>) (Const32 <typ.Int> [0]) (Const32 <typ.Int> [0]))
	for {
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpSliceMake)
		v0 := b.NewValue0(v.Pos, OpConstNil, v.Type.Elem().PtrTo())
		v1 := b.NewValue0(v.Pos, OpConst32, typ.Int)
		v1.AuxInt = int32ToAuxInt(0)
		v.AddArg3(v0, v1, v1)
		return true
	}
	// match: (ConstSlice)
	// cond: config.PtrSize == 8
	// result: (SliceMake (ConstNil <v.Type.Elem().PtrTo()>) (Const64 <typ.Int> [0]) (Const64 <typ.Int> [0]))
	for {
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpSliceMake)
		v0 := b.NewValue0(v.Pos, OpConstNil, v.Type.Elem().PtrTo())
		v1 := b.NewValue0(v.Pos, OpConst64, typ.Int)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg3(v0, v1, v1)
		return true
	}
	return false
}
func rewriteValuegeneric_OpConstString(v *Value) bool {
	b := v.Block
	config := b.Func.Config
	fe := b.Func.fe
	typ := &b.Func.Config.Types
	// match: (ConstString {str})
	// cond: config.PtrSize == 4 && str == ""
	// result: (StringMake (ConstNil) (Const32 <typ.Int> [0]))
	for {
		str := auxToString(v.Aux)
		if !(config.PtrSize == 4 && str == "") {
			break
		}
		v.reset(OpStringMake)
		v0 := b.NewValue0(v.Pos, OpConstNil, typ.BytePtr)
		v1 := b.NewValue0(v.Pos, OpConst32, typ.Int)
		v1.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (ConstString {str})
	// cond: config.PtrSize == 8 && str == ""
	// result: (StringMake (ConstNil) (Const64 <typ.Int> [0]))
	for {
		str := auxToString(v.Aux)
		if !(config.PtrSize == 8 && str == "") {
			break
		}
		v.reset(OpStringMake)
		v0 := b.NewValue0(v.Pos, OpConstNil, typ.BytePtr)
		v1 := b.NewValue0(v.Pos, OpConst64, typ.Int)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (ConstString {str})
	// cond: config.PtrSize == 4 && str != ""
	// result: (StringMake (Addr <typ.BytePtr> {fe.StringData(str)} (SB)) (Const32 <typ.Int> [int32(len(str))]))
	for {
		str := auxToString(v.Aux)
		if !(config.PtrSize == 4 && str != "") {
			break
		}
		v.reset(OpStringMake)
		v0 := b.NewValue0(v.Pos, OpAddr, typ.BytePtr)
		v0.Aux = symToAux(fe.StringData(str))
		v1 := b.NewValue0(v.Pos, OpSB, typ.Uintptr)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.Int)
		v2.AuxInt = int32ToAuxInt(int32(len(str)))
		v.AddArg2(v0, v2)
		return true
	}
	// match: (ConstString {str})
	// cond: config.PtrSize == 8 && str != ""
	// result: (StringMake (Addr <typ.BytePtr> {fe.StringData(str)} (SB)) (Const64 <typ.Int> [int64(len(str))]))
	for {
		str := auxToString(v.Aux)
		if !(config.PtrSize == 8 && str != "") {
			break
		}
		v.reset(OpStringMake)
		v0 := b.NewValue0(v.Pos, OpAddr, typ.BytePtr)
		v0.Aux = symToAux(fe.StringData(str))
		v1 := b.NewValue0(v.Pos, OpSB, typ.Uintptr)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.Int)
		v2.AuxInt = int64ToAuxInt(int64(len(str)))
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValuegeneric_OpConvert(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Convert (Add64 (Convert ptr mem) off) mem)
	// result: (AddPtr ptr off)
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConvert {
				continue
			}
			mem := v_0_0.Args[1]
			ptr := v_0_0.Args[0]
			off := v_0_1
			if mem != v_1 {
				continue
			}
			v.reset(OpAddPtr)
			v.AddArg2(ptr, off)
			return true
		}
		break
	}
	// match: (Convert (Add32 (Convert ptr mem) off) mem)
	// result: (AddPtr ptr off)
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConvert {
				continue
			}
			mem := v_0_0.Args[1]
			ptr := v_0_0.Args[0]
			off := v_0_1
			if mem != v_1 {
				continue
			}
			v.reset(OpAddPtr)
			v.AddArg2(ptr, off)
			return true
		}
		break
	}
	// match: (Convert (Convert ptr mem) mem)
	// result: ptr
	for {
		if v_0.Op != OpConvert {
			break
		}
		mem := v_0.Args[1]
		ptr := v_0.Args[0]
		if mem != v_1 {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (Convert a:(Add64 (Add64 (Convert ptr mem) off1) off2) mem)
	// result: (AddPtr ptr (Add64 <a.Type> off1 off2))
	for {
		a := v_0
		if a.Op != OpAdd64 {
			break
		}
		_ = a.Args[1]
		a_0 := a.Args[0]
		a_1 := a.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, a_0, a_1 = _i0+1, a_1, a_0 {
			if a_0.Op != OpAdd64 {
				continue
			}
			_ = a_0.Args[1]
			a_0_0 := a_0.Args[0]
			a_0_1 := a_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, a_0_0, a_0_1 = _i1+1, a_0_1, a_0_0 {
				if a_0_0.Op != OpConvert {
					continue
				}
				mem := a_0_0.Args[1]
				ptr := a_0_0.Args[0]
				off1 := a_0_1
				off2 := a_1
				if mem != v_1 {
					continue
				}
				v.reset(OpAddPtr)
				v0 := b.NewValue0(v.Pos, OpAdd64, a.Type)
				v0.AddArg2(off1, off2)
				v.AddArg2(ptr, v0)
				return true
			}
		}
		break
	}
	// match: (Convert a:(Add32 (Add32 (Convert ptr mem) off1) off2) mem)
	// result: (AddPtr ptr (Add32 <a.Type> off1 off2))
	for {
		a := v_0
		if a.Op != OpAdd32 {
			break
		}
		_ = a.Args[1]
		a_0 := a.Args[0]
		a_1 := a.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, a_0, a_1 = _i0+1, a_1, a_0 {
			if a_0.Op != OpAdd32 {
				continue
			}
			_ = a_0.Args[1]
			a_0_0 := a_0.Args[0]
			a_0_1 := a_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, a_0_0, a_0_1 = _i1+1, a_0_1, a_0_0 {
				if a_0_0.Op != OpConvert {
					continue
				}
				mem := a_0_0.Args[1]
				ptr := a_0_0.Args[0]
				off1 := a_0_1
				off2 := a_1
				if mem != v_1 {
					continue
				}
				v.reset(OpAddPtr)
				v0 := b.NewValue0(v.Pos, OpAdd32, a.Type)
				v0.AddArg2(off1, off2)
				v.AddArg2(ptr, v0)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Ctz16 (Const16 [c]))
	// cond: config.PtrSize == 4
	// result: (Const32 [int32(ntz16(c))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(ntz16(c)))
		return true
	}
	// match: (Ctz16 (Const16 [c]))
	// cond: config.PtrSize == 8
	// result: (Const64 [int64(ntz16(c))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(ntz16(c)))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Ctz32 (Const32 [c]))
	// cond: config.PtrSize == 4
	// result: (Const32 [int32(ntz32(c))])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(ntz32(c)))
		return true
	}
	// match: (Ctz32 (Const32 [c]))
	// cond: config.PtrSize == 8
	// result: (Const64 [int64(ntz32(c))])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(ntz32(c)))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCtz64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Ctz64 (Const64 [c]))
	// cond: config.PtrSize == 4
	// result: (Const32 [int32(ntz64(c))])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(ntz64(c)))
		return true
	}
	// match: (Ctz64 (Const64 [c]))
	// cond: config.PtrSize == 8
	// result: (Const64 [int64(ntz64(c))])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(ntz64(c)))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Ctz8 (Const8 [c]))
	// cond: config.PtrSize == 4
	// result: (Const32 [int32(ntz8(c))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(ntz8(c)))
		return true
	}
	// match: (Ctz8 (Const8 [c]))
	// cond: config.PtrSize == 8
	// result: (Const64 [int64(ntz8(c))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(ntz8(c)))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt32Fto32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt32Fto32 (Const32F [c]))
	// result: (Const32 [int32(c)])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt32Fto64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt32Fto64 (Const32F [c]))
	// result: (Const64 [int64(c)])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt32Fto64F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt32Fto64F (Const32F [c]))
	// result: (Const64F [float64(c)])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(float64(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt32to32F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt32to32F (Const32 [c]))
	// result: (Const32F [float32(c)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(float32(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt32to64F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt32to64F (Const32 [c]))
	// result: (Const64F [float64(c)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(float64(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt64Fto32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt64Fto32 (Const64F [c]))
	// result: (Const32 [int32(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt64Fto32F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt64Fto32F (Const64F [c]))
	// result: (Const32F [float32(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(float32(c))
		return true
	}
	// match: (Cvt64Fto32F sqrt0:(Sqrt (Cvt32Fto64F x)))
	// cond: sqrt0.Uses==1
	// result: (Sqrt32 x)
	for {
		sqrt0 := v_0
		if sqrt0.Op != OpSqrt {
			break
		}
		sqrt0_0 := sqrt0.Args[0]
		if sqrt0_0.Op != OpCvt32Fto64F {
			break
		}
		x := sqrt0_0.Args[0]
		if !(sqrt0.Uses == 1) {
			break
		}
		v.reset(OpSqrt32)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt64Fto64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt64Fto64 (Const64F [c]))
	// result: (Const64 [int64(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt64to32F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt64to32F (Const64 [c]))
	// result: (Const32F [float32(c)])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(float32(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvt64to64F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Cvt64to64F (Const64 [c]))
	// result: (Const64F [float64(c)])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(float64(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpCvtBoolToUint8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CvtBoolToUint8 (ConstBool [false]))
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConstBool || auxIntToBool(v_0.AuxInt) != false {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (CvtBoolToUint8 (ConstBool [true]))
	// result: (Const8 [1])
	for {
		if v_0.Op != OpConstBool || auxIntToBool(v_0.AuxInt) != true {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 (Const16 [c]) (Const16 [d]))
	// cond: d != 0
	// result: (Const16 [c/d])
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
		v.AuxInt = int16ToAuxInt(c / d)
		return true
	}
	// match: (Div16 n (Const16 [c]))
	// cond: isNonNegative(n) && isPowerOfTwo(c)
	// result: (Rsh16Ux64 n (Const64 <typ.UInt64> [log16(c)]))
	for {
		n := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(isNonNegative(n) && isPowerOfTwo(c)) {
			break
		}
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(log16(c))
		v.AddArg2(n, v0)
		return true
	}
	// match: (Div16 <t> n (Const16 [c]))
	// cond: c < 0 && c != -1<<15
	// result: (Neg16 (Div16 <t> n (Const16 <t> [-c])))
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
		v.reset(OpNeg16)
		v0 := b.NewValue0(v.Pos, OpDiv16, t)
		v1 := b.NewValue0(v.Pos, OpConst16, t)
		v1.AuxInt = int16ToAuxInt(-c)
		v0.AddArg2(n, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Div16 <t> x (Const16 [-1<<15]))
	// result: (Rsh16Ux64 (And16 <t> x (Neg16 <t> x)) (Const64 <typ.UInt64> [15]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != -1<<15 {
			break
		}
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpAnd16, t)
		v1 := b.NewValue0(v.Pos, OpNeg16, t)
		v1.AddArg(x)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(15)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Div16 <t> n (Const16 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Rsh16x64 (Add16 <t> n (Rsh16Ux64 <t> (Rsh16x64 <t> n (Const64 <typ.UInt64> [15])) (Const64 <typ.UInt64> [int64(16-log16(c))]))) (Const64 <typ.UInt64> [int64(log16(c))]))
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
		v.reset(OpRsh16x64)
		v0 := b.NewValue0(v.Pos, OpAdd16, t)
		v1 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v2 := b.NewValue0(v.Pos, OpRsh16x64, t)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(15)
		v2.AddArg2(n, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(int64(16 - log16(c)))
		v1.AddArg2(v2, v4)
		v0.AddArg2(n, v1)
		v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(int64(log16(c)))
		v.AddArg2(v0, v5)
		return true
	}
	// match: (Div16 <t> x (Const16 [c]))
	// cond: smagicOK16(c)
	// result: (Sub16 <t> (Rsh32x64 <t> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(smagic16(c).m)]) (SignExt16to32 x)) (Const64 <typ.UInt64> [16+smagic16(c).s])) (Rsh32x64 <t> (SignExt16to32 x) (Const64 <typ.UInt64> [31])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(smagicOK16(c)) {
			break
		}
		v.reset(OpSub16)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpRsh32x64, t)
		v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(int32(smagic16(c).m))
		v3 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v3.AddArg(x)
		v1.AddArg2(v2, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(16 + smagic16(c).s)
		v0.AddArg2(v1, v4)
		v5 := b.NewValue0(v.Pos, OpRsh32x64, t)
		v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(31)
		v5.AddArg2(v3, v6)
		v.AddArg2(v0, v5)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Div16u (Const16 [c]) (Const16 [d]))
	// cond: d != 0
	// result: (Const16 [int16(uint16(c)/uint16(d))])
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
		v.AuxInt = int16ToAuxInt(int16(uint16(c) / uint16(d)))
		return true
	}
	// match: (Div16u n (Const16 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Rsh16Ux64 n (Const64 <typ.UInt64> [log16(c)]))
	for {
		n := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(log16(c))
		v.AddArg2(n, v0)
		return true
	}
	// match: (Div16u x (Const16 [c]))
	// cond: umagicOK16(c) && config.RegSize == 8
	// result: (Trunc64to16 (Rsh64Ux64 <typ.UInt64> (Mul64 <typ.UInt64> (Const64 <typ.UInt64> [int64(1<<16+umagic16(c).m)]) (ZeroExt16to64 x)) (Const64 <typ.UInt64> [16+umagic16(c).s])))
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(umagicOK16(c) && config.RegSize == 8) {
			break
		}
		v.reset(OpTrunc64to16)
		v0 := b.NewValue0(v.Pos, OpRsh64Ux64, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(int64(1<<16 + umagic16(c).m))
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(x)
		v1.AddArg2(v2, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(16 + umagic16(c).s)
		v0.AddArg2(v1, v4)
		v.AddArg(v0)
		return true
	}
	// match: (Div16u x (Const16 [c]))
	// cond: umagicOK16(c) && config.RegSize == 4 && umagic16(c).m&1 == 0
	// result: (Trunc32to16 (Rsh32Ux64 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(1<<15+umagic16(c).m/2)]) (ZeroExt16to32 x)) (Const64 <typ.UInt64> [16+umagic16(c).s-1])))
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(umagicOK16(c) && config.RegSize == 4 && umagic16(c).m&1 == 0) {
			break
		}
		v.reset(OpTrunc32to16)
		v0 := b.NewValue0(v.Pos, OpRsh32Ux64, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(int32(1<<15 + umagic16(c).m/2))
		v3 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v3.AddArg(x)
		v1.AddArg2(v2, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(16 + umagic16(c).s - 1)
		v0.AddArg2(v1, v4)
		v.AddArg(v0)
		return true
	}
	// match: (Div16u x (Const16 [c]))
	// cond: umagicOK16(c) && config.RegSize == 4 && c&1 == 0
	// result: (Trunc32to16 (Rsh32Ux64 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(1<<15+(umagic16(c).m+1)/2)]) (Rsh32Ux64 <typ.UInt32> (ZeroExt16to32 x) (Const64 <typ.UInt64> [1]))) (Const64 <typ.UInt64> [16+umagic16(c).s-2])))
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(umagicOK16(c) && config.RegSize == 4 && c&1 == 0) {
			break
		}
		v.reset(OpTrunc32to16)
		v0 := b.NewValue0(v.Pos, OpRsh32Ux64, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(int32(1<<15 + (umagic16(c).m+1)/2))
		v3 := b.NewValue0(v.Pos, OpRsh32Ux64, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v4.AddArg(x)
		v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(1)
		v3.AddArg2(v4, v5)
		v1.AddArg2(v2, v3)
		v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(16 + umagic16(c).s - 2)
		v0.AddArg2(v1, v6)
		v.AddArg(v0)
		return true
	}
	// match: (Div16u x (Const16 [c]))
	// cond: umagicOK16(c) && config.RegSize == 4 && config.useAvg
	// result: (Trunc32to16 (Rsh32Ux64 <typ.UInt32> (Avg32u (Lsh32x64 <typ.UInt32> (ZeroExt16to32 x) (Const64 <typ.UInt64> [16])) (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(umagic16(c).m)]) (ZeroExt16to32 x))) (Const64 <typ.UInt64> [16+umagic16(c).s-1])))
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(umagicOK16(c) && config.RegSize == 4 && config.useAvg) {
			break
		}
		v.reset(OpTrunc32to16)
		v0 := b.NewValue0(v.Pos, OpRsh32Ux64, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpAvg32u, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpLsh32x64, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(16)
		v2.AddArg2(v3, v4)
		v5 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
		v6 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v6.AuxInt = int32ToAuxInt(int32(umagic16(c).m))
		v5.AddArg2(v6, v3)
		v1.AddArg2(v2, v5)
		v7 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v7.AuxInt = int64ToAuxInt(16 + umagic16(c).s - 1)
		v0.AddArg2(v1, v7)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Div32 (Const32 [c]) (Const32 [d]))
	// cond: d != 0
	// result: (Const32 [c/d])
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
		v.AuxInt = int32ToAuxInt(c / d)
		return true
	}
	// match: (Div32 n (Const32 [c]))
	// cond: isNonNegative(n) && isPowerOfTwo(c)
	// result: (Rsh32Ux64 n (Const64 <typ.UInt64> [log32(c)]))
	for {
		n := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(isNonNegative(n) && isPowerOfTwo(c)) {
			break
		}
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(log32(c))
		v.AddArg2(n, v0)
		return true
	}
	// match: (Div32 <t> n (Const32 [c]))
	// cond: c < 0 && c != -1<<31
	// result: (Neg32 (Div32 <t> n (Const32 <t> [-c])))
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
		v.reset(OpNeg32)
		v0 := b.NewValue0(v.Pos, OpDiv32, t)
		v1 := b.NewValue0(v.Pos, OpConst32, t)
		v1.AuxInt = int32ToAuxInt(-c)
		v0.AddArg2(n, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Div32 <t> x (Const32 [-1<<31]))
	// result: (Rsh32Ux64 (And32 <t> x (Neg32 <t> x)) (Const64 <typ.UInt64> [31]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != -1<<31 {
			break
		}
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpAnd32, t)
		v1 := b.NewValue0(v.Pos, OpNeg32, t)
		v1.AddArg(x)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(31)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Div32 <t> n (Const32 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Rsh32x64 (Add32 <t> n (Rsh32Ux64 <t> (Rsh32x64 <t> n (Const64 <typ.UInt64> [31])) (Const64 <typ.UInt64> [int64(32-log32(c))]))) (Const64 <typ.UInt64> [int64(log32(c))]))
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
		v.reset(OpRsh32x64)
		v0 := b.NewValue0(v.Pos, OpAdd32, t)
		v1 := b.NewValue0(v.Pos, OpRsh32Ux64, t)
		v2 := b.NewValue0(v.Pos, OpRsh32x64, t)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(31)
		v2.AddArg2(n, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(int64(32 - log32(c)))
		v1.AddArg2(v2, v4)
		v0.AddArg2(n, v1)
		v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(int64(log32(c)))
		v.AddArg2(v0, v5)
		return true
	}
	// match: (Div32 <t> x (Const32 [c]))
	// cond: smagicOK32(c) && config.RegSize == 8
	// result: (Sub32 <t> (Rsh64x64 <t> (Mul64 <typ.UInt64> (Const64 <typ.UInt64> [int64(smagic32(c).m)]) (SignExt32to64 x)) (Const64 <typ.UInt64> [32+smagic32(c).s])) (Rsh64x64 <t> (SignExt32to64 x) (Const64 <typ.UInt64> [63])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(smagicOK32(c) && config.RegSize == 8) {
			break
		}
		v.reset(OpSub32)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpRsh64x64, t)
		v1 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(int64(smagic32(c).m))
		v3 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v3.AddArg(x)
		v1.AddArg2(v2, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(32 + smagic32(c).s)
		v0.AddArg2(v1, v4)
		v5 := b.NewValue0(v.Pos, OpRsh64x64, t)
		v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(63)
		v5.AddArg2(v3, v6)
		v.AddArg2(v0, v5)
		return true
	}
	// match: (Div32 <t> x (Const32 [c]))
	// cond: smagicOK32(c) && config.RegSize == 4 && smagic32(c).m&1 == 0 && config.useHmul
	// result: (Sub32 <t> (Rsh32x64 <t> (Hmul32 <t> (Const32 <typ.UInt32> [int32(smagic32(c).m/2)]) x) (Const64 <typ.UInt64> [smagic32(c).s-1])) (Rsh32x64 <t> x (Const64 <typ.UInt64> [31])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(smagicOK32(c) && config.RegSize == 4 && smagic32(c).m&1 == 0 && config.useHmul) {
			break
		}
		v.reset(OpSub32)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpRsh32x64, t)
		v1 := b.NewValue0(v.Pos, OpHmul32, t)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(int32(smagic32(c).m / 2))
		v1.AddArg2(v2, x)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(smagic32(c).s - 1)
		v0.AddArg2(v1, v3)
		v4 := b.NewValue0(v.Pos, OpRsh32x64, t)
		v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(31)
		v4.AddArg2(x, v5)
		v.AddArg2(v0, v4)
		return true
	}
	// match: (Div32 <t> x (Const32 [c]))
	// cond: smagicOK32(c) && config.RegSize == 4 && smagic32(c).m&1 != 0 && config.useHmul
	// result: (Sub32 <t> (Rsh32x64 <t> (Add32 <t> (Hmul32 <t> (Const32 <typ.UInt32> [int32(smagic32(c).m)]) x) x) (Const64 <typ.UInt64> [smagic32(c).s])) (Rsh32x64 <t> x (Const64 <typ.UInt64> [31])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(smagicOK32(c) && config.RegSize == 4 && smagic32(c).m&1 != 0 && config.useHmul) {
			break
		}
		v.reset(OpSub32)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpRsh32x64, t)
		v1 := b.NewValue0(v.Pos, OpAdd32, t)
		v2 := b.NewValue0(v.Pos, OpHmul32, t)
		v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(int32(smagic32(c).m))
		v2.AddArg2(v3, x)
		v1.AddArg2(v2, x)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(smagic32(c).s)
		v0.AddArg2(v1, v4)
		v5 := b.NewValue0(v.Pos, OpRsh32x64, t)
		v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(31)
		v5.AddArg2(x, v6)
		v.AddArg2(v0, v5)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Div32F (Const32F [c]) (Const32F [d]))
	// cond: c/d == c/d
	// result: (Const32F [c/d])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		if v_1.Op != OpConst32F {
			break
		}
		d := auxIntToFloat32(v_1.AuxInt)
		if !(c/d == c/d) {
			break
		}
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(c / d)
		return true
	}
	// match: (Div32F x (Const32F <t> [c]))
	// cond: reciprocalExact32(c)
	// result: (Mul32F x (Const32F <t> [1/c]))
	for {
		x := v_0
		if v_1.Op != OpConst32F {
			break
		}
		t := v_1.Type
		c := auxIntToFloat32(v_1.AuxInt)
		if !(reciprocalExact32(c)) {
			break
		}
		v.reset(OpMul32F)
		v0 := b.NewValue0(v.Pos, OpConst32F, t)
		v0.AuxInt = float32ToAuxInt(1 / c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Div32u (Const32 [c]) (Const32 [d]))
	// cond: d != 0
	// result: (Const32 [int32(uint32(c)/uint32(d))])
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
		v.AuxInt = int32ToAuxInt(int32(uint32(c) / uint32(d)))
		return true
	}
	// match: (Div32u n (Const32 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Rsh32Ux64 n (Const64 <typ.UInt64> [log32(c)]))
	for {
		n := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(log32(c))
		v.AddArg2(n, v0)
		return true
	}
	// match: (Div32u x (Const32 [c]))
	// cond: umagicOK32(c) && config.RegSize == 4 && umagic32(c).m&1 == 0 && config.useHmul
	// result: (Rsh32Ux64 <typ.UInt32> (Hmul32u <typ.UInt32> (Const32 <typ.UInt32> [int32(1<<31+umagic32(c).m/2)]) x) (Const64 <typ.UInt64> [umagic32(c).s-1]))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(umagicOK32(c) && config.RegSize == 4 && umagic32(c).m&1 == 0 && config.useHmul) {
			break
		}
		v.reset(OpRsh32Ux64)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, OpHmul32u, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(int32(1<<31 + umagic32(c).m/2))
		v0.AddArg2(v1, x)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(umagic32(c).s - 1)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Div32u x (Const32 [c]))
	// cond: umagicOK32(c) && config.RegSize == 4 && c&1 == 0 && config.useHmul
	// result: (Rsh32Ux64 <typ.UInt32> (Hmul32u <typ.UInt32> (Const32 <typ.UInt32> [int32(1<<31+(umagic32(c).m+1)/2)]) (Rsh32Ux64 <typ.UInt32> x (Const64 <typ.UInt64> [1]))) (Const64 <typ.UInt64> [umagic32(c).s-2]))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(umagicOK32(c) && config.RegSize == 4 && c&1 == 0 && config.useHmul) {
			break
		}
		v.reset(OpRsh32Ux64)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, OpHmul32u, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(int32(1<<31 + (umagic32(c).m+1)/2))
		v2 := b.NewValue0(v.Pos, OpRsh32Ux64, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(1)
		v2.AddArg2(x, v3)
		v0.AddArg2(v1, v2)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(umagic32(c).s - 2)
		v.AddArg2(v0, v4)
		return true
	}
	// match: (Div32u x (Const32 [c]))
	// cond: umagicOK32(c) && config.RegSize == 4 && config.useAvg && config.useHmul
	// result: (Rsh32Ux64 <typ.UInt32> (Avg32u x (Hmul32u <typ.UInt32> (Const32 <typ.UInt32> [int32(umagic32(c).m)]) x)) (Const64 <typ.UInt64> [umagic32(c).s-1]))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(umagicOK32(c) && config.RegSize == 4 && config.useAvg && config.useHmul) {
			break
		}
		v.reset(OpRsh32Ux64)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, OpAvg32u, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpHmul32u, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(int32(umagic32(c).m))
		v1.AddArg2(v2, x)
		v0.AddArg2(x, v1)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(umagic32(c).s - 1)
		v.AddArg2(v0, v3)
		return true
	}
	// match: (Div32u x (Const32 [c]))
	// cond: umagicOK32(c) && config.RegSize == 8 && umagic32(c).m&1 == 0
	// result: (Trunc64to32 (Rsh64Ux64 <typ.UInt64> (Mul64 <typ.UInt64> (Const64 <typ.UInt64> [int64(1<<31+umagic32(c).m/2)]) (ZeroExt32to64 x)) (Const64 <typ.UInt64> [32+umagic32(c).s-1])))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(umagicOK32(c) && config.RegSize == 8 && umagic32(c).m&1 == 0) {
			break
		}
		v.reset(OpTrunc64to32)
		v0 := b.NewValue0(v.Pos, OpRsh64Ux64, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(int64(1<<31 + umagic32(c).m/2))
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(x)
		v1.AddArg2(v2, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(32 + umagic32(c).s - 1)
		v0.AddArg2(v1, v4)
		v.AddArg(v0)
		return true
	}
	// match: (Div32u x (Const32 [c]))
	// cond: umagicOK32(c) && config.RegSize == 8 && c&1 == 0
	// result: (Trunc64to32 (Rsh64Ux64 <typ.UInt64> (Mul64 <typ.UInt64> (Const64 <typ.UInt64> [int64(1<<31+(umagic32(c).m+1)/2)]) (Rsh64Ux64 <typ.UInt64> (ZeroExt32to64 x) (Const64 <typ.UInt64> [1]))) (Const64 <typ.UInt64> [32+umagic32(c).s-2])))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(umagicOK32(c) && config.RegSize == 8 && c&1 == 0) {
			break
		}
		v.reset(OpTrunc64to32)
		v0 := b.NewValue0(v.Pos, OpRsh64Ux64, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(int64(1<<31 + (umagic32(c).m+1)/2))
		v3 := b.NewValue0(v.Pos, OpRsh64Ux64, typ.UInt64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(x)
		v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(1)
		v3.AddArg2(v4, v5)
		v1.AddArg2(v2, v3)
		v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(32 + umagic32(c).s - 2)
		v0.AddArg2(v1, v6)
		v.AddArg(v0)
		return true
	}
	// match: (Div32u x (Const32 [c]))
	// cond: umagicOK32(c) && config.RegSize == 8 && config.useAvg
	// result: (Trunc64to32 (Rsh64Ux64 <typ.UInt64> (Avg64u (Lsh64x64 <typ.UInt64> (ZeroExt32to64 x) (Const64 <typ.UInt64> [32])) (Mul64 <typ.UInt64> (Const64 <typ.UInt32> [int64(umagic32(c).m)]) (ZeroExt32to64 x))) (Const64 <typ.UInt64> [32+umagic32(c).s-1])))
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(umagicOK32(c) && config.RegSize == 8 && config.useAvg) {
			break
		}
		v.reset(OpTrunc64to32)
		v0 := b.NewValue0(v.Pos, OpRsh64Ux64, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpAvg64u, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpLsh64x64, typ.UInt64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(32)
		v2.AddArg2(v3, v4)
		v5 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
		v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt32)
		v6.AuxInt = int64ToAuxInt(int64(umagic32(c).m))
		v5.AddArg2(v6, v3)
		v1.AddArg2(v2, v5)
		v7 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v7.AuxInt = int64ToAuxInt(32 + umagic32(c).s - 1)
		v0.AddArg2(v1, v7)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Div64 (Const64 [c]) (Const64 [d]))
	// cond: d != 0
	// result: (Const64 [c/d])
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
		v.AuxInt = int64ToAuxInt(c / d)
		return true
	}
	// match: (Div64 n (Const64 [c]))
	// cond: isNonNegative(n) && isPowerOfTwo(c)
	// result: (Rsh64Ux64 n (Const64 <typ.UInt64> [log64(c)]))
	for {
		n := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isNonNegative(n) && isPowerOfTwo(c)) {
			break
		}
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(log64(c))
		v.AddArg2(n, v0)
		return true
	}
	// match: (Div64 n (Const64 [-1<<63]))
	// cond: isNonNegative(n)
	// result: (Const64 [0])
	for {
		n := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != -1<<63 || !(isNonNegative(n)) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Div64 <t> n (Const64 [c]))
	// cond: c < 0 && c != -1<<63
	// result: (Neg64 (Div64 <t> n (Const64 <t> [-c])))
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
		v.reset(OpNeg64)
		v0 := b.NewValue0(v.Pos, OpDiv64, t)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(-c)
		v0.AddArg2(n, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Div64 <t> x (Const64 [-1<<63]))
	// result: (Rsh64Ux64 (And64 <t> x (Neg64 <t> x)) (Const64 <typ.UInt64> [63]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != -1<<63 {
			break
		}
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpAnd64, t)
		v1 := b.NewValue0(v.Pos, OpNeg64, t)
		v1.AddArg(x)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(63)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Div64 <t> n (Const64 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Rsh64x64 (Add64 <t> n (Rsh64Ux64 <t> (Rsh64x64 <t> n (Const64 <typ.UInt64> [63])) (Const64 <typ.UInt64> [int64(64-log64(c))]))) (Const64 <typ.UInt64> [int64(log64(c))]))
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
		v.reset(OpRsh64x64)
		v0 := b.NewValue0(v.Pos, OpAdd64, t)
		v1 := b.NewValue0(v.Pos, OpRsh64Ux64, t)
		v2 := b.NewValue0(v.Pos, OpRsh64x64, t)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(63)
		v2.AddArg2(n, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(int64(64 - log64(c)))
		v1.AddArg2(v2, v4)
		v0.AddArg2(n, v1)
		v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(int64(log64(c)))
		v.AddArg2(v0, v5)
		return true
	}
	// match: (Div64 <t> x (Const64 [c]))
	// cond: smagicOK64(c) && smagic64(c).m&1 == 0 && config.useHmul
	// result: (Sub64 <t> (Rsh64x64 <t> (Hmul64 <t> (Const64 <typ.UInt64> [int64(smagic64(c).m/2)]) x) (Const64 <typ.UInt64> [smagic64(c).s-1])) (Rsh64x64 <t> x (Const64 <typ.UInt64> [63])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(smagicOK64(c) && smagic64(c).m&1 == 0 && config.useHmul) {
			break
		}
		v.reset(OpSub64)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpRsh64x64, t)
		v1 := b.NewValue0(v.Pos, OpHmul64, t)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(int64(smagic64(c).m / 2))
		v1.AddArg2(v2, x)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(smagic64(c).s - 1)
		v0.AddArg2(v1, v3)
		v4 := b.NewValue0(v.Pos, OpRsh64x64, t)
		v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v4.AddArg2(x, v5)
		v.AddArg2(v0, v4)
		return true
	}
	// match: (Div64 <t> x (Const64 [c]))
	// cond: smagicOK64(c) && smagic64(c).m&1 != 0 && config.useHmul
	// result: (Sub64 <t> (Rsh64x64 <t> (Add64 <t> (Hmul64 <t> (Const64 <typ.UInt64> [int64(smagic64(c).m)]) x) x) (Const64 <typ.UInt64> [smagic64(c).s])) (Rsh64x64 <t> x (Const64 <typ.UInt64> [63])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(smagicOK64(c) && smagic64(c).m&1 != 0 && config.useHmul) {
			break
		}
		v.reset(OpSub64)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpRsh64x64, t)
		v1 := b.NewValue0(v.Pos, OpAdd64, t)
		v2 := b.NewValue0(v.Pos, OpHmul64, t)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(int64(smagic64(c).m))
		v2.AddArg2(v3, x)
		v1.AddArg2(v2, x)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(smagic64(c).s)
		v0.AddArg2(v1, v4)
		v5 := b.NewValue0(v.Pos, OpRsh64x64, t)
		v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(63)
		v5.AddArg2(x, v6)
		v.AddArg2(v0, v5)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Div64F (Const64F [c]) (Const64F [d]))
	// cond: c/d == c/d
	// result: (Const64F [c/d])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		if v_1.Op != OpConst64F {
			break
		}
		d := auxIntToFloat64(v_1.AuxInt)
		if !(c/d == c/d) {
			break
		}
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(c / d)
		return true
	}
	// match: (Div64F x (Const64F <t> [c]))
	// cond: reciprocalExact64(c)
	// result: (Mul64F x (Const64F <t> [1/c]))
	for {
		x := v_0
		if v_1.Op != OpConst64F {
			break
		}
		t := v_1.Type
		c := auxIntToFloat64(v_1.AuxInt)
		if !(reciprocalExact64(c)) {
			break
		}
		v.reset(OpMul64F)
		v0 := b.NewValue0(v.Pos, OpConst64F, t)
		v0.AuxInt = float64ToAuxInt(1 / c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Div64u (Const64 [c]) (Const64 [d]))
	// cond: d != 0
	// result: (Const64 [int64(uint64(c)/uint64(d))])
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
		v.AuxInt = int64ToAuxInt(int64(uint64(c) / uint64(d)))
		return true
	}
	// match: (Div64u n (Const64 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Rsh64Ux64 n (Const64 <typ.UInt64> [log64(c)]))
	for {
		n := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(log64(c))
		v.AddArg2(n, v0)
		return true
	}
	// match: (Div64u n (Const64 [-1<<63]))
	// result: (Rsh64Ux64 n (Const64 <typ.UInt64> [63]))
	for {
		n := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != -1<<63 {
			break
		}
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(63)
		v.AddArg2(n, v0)
		return true
	}
	// match: (Div64u x (Const64 [c]))
	// cond: c > 0 && c <= 0xFFFF && umagicOK32(int32(c)) && config.RegSize == 4 && config.useHmul
	// result: (Add64 (Add64 <typ.UInt64> (Add64 <typ.UInt64> (Lsh64x64 <typ.UInt64> (ZeroExt32to64 (Div32u <typ.UInt32> (Trunc64to32 <typ.UInt32> (Rsh64Ux64 <typ.UInt64> x (Const64 <typ.UInt64> [32]))) (Const32 <typ.UInt32> [int32(c)]))) (Const64 <typ.UInt64> [32])) (ZeroExt32to64 (Div32u <typ.UInt32> (Trunc64to32 <typ.UInt32> x) (Const32 <typ.UInt32> [int32(c)])))) (Mul64 <typ.UInt64> (ZeroExt32to64 <typ.UInt64> (Mod32u <typ.UInt32> (Trunc64to32 <typ.UInt32> (Rsh64Ux64 <typ.UInt64> x (Const64 <typ.UInt64> [32]))) (Const32 <typ.UInt32> [int32(c)]))) (Const64 <typ.UInt64> [int64((1<<32)/c)]))) (ZeroExt32to64 (Div32u <typ.UInt32> (Add32 <typ.UInt32> (Mod32u <typ.UInt32> (Trunc64to32 <typ.UInt32> x) (Const32 <typ.UInt32> [int32(c)])) (Mul32 <typ.UInt32> (Mod32u <typ.UInt32> (Trunc64to32 <typ.UInt32> (Rsh64Ux64 <typ.UInt64> x (Const64 <typ.UInt64> [32]))) (Const32 <typ.UInt32> [int32(c)])) (Const32 <typ.UInt32> [int32((1<<32)%c)]))) (Const32 <typ.UInt32> [int32(c)]))))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c > 0 && c <= 0xFFFF && umagicOK32(int32(c)) && config.RegSize == 4 && config.useHmul) {
			break
		}
		v.reset(OpAdd64)
		v0 := b.NewValue0(v.Pos, OpAdd64, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpAdd64, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpLsh64x64, typ.UInt64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4 := b.NewValue0(v.Pos, OpDiv32u, typ.UInt32)
		v5 := b.NewValue0(v.Pos, OpTrunc64to32, typ.UInt32)
		v6 := b.NewValue0(v.Pos, OpRsh64Ux64, typ.UInt64)
		v7 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v7.AuxInt = int64ToAuxInt(32)
		v6.AddArg2(x, v7)
		v5.AddArg(v6)
		v8 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v8.AuxInt = int32ToAuxInt(int32(c))
		v4.AddArg2(v5, v8)
		v3.AddArg(v4)
		v2.AddArg2(v3, v7)
		v9 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v10 := b.NewValue0(v.Pos, OpDiv32u, typ.UInt32)
		v11 := b.NewValue0(v.Pos, OpTrunc64to32, typ.UInt32)
		v11.AddArg(x)
		v10.AddArg2(v11, v8)
		v9.AddArg(v10)
		v1.AddArg2(v2, v9)
		v12 := b.NewValue0(v.Pos, OpMul64, typ.UInt64)
		v13 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v14 := b.NewValue0(v.Pos, OpMod32u, typ.UInt32)
		v14.AddArg2(v5, v8)
		v13.AddArg(v14)
		v15 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v15.AuxInt = int64ToAuxInt(int64((1 << 32) / c))
		v12.AddArg2(v13, v15)
		v0.AddArg2(v1, v12)
		v16 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v17 := b.NewValue0(v.Pos, OpDiv32u, typ.UInt32)
		v18 := b.NewValue0(v.Pos, OpAdd32, typ.UInt32)
		v19 := b.NewValue0(v.Pos, OpMod32u, typ.UInt32)
		v19.AddArg2(v11, v8)
		v20 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
		v21 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v21.AuxInt = int32ToAuxInt(int32((1 << 32) % c))
		v20.AddArg2(v14, v21)
		v18.AddArg2(v19, v20)
		v17.AddArg2(v18, v8)
		v16.AddArg(v17)
		v.AddArg2(v0, v16)
		return true
	}
	// match: (Div64u x (Const64 [c]))
	// cond: umagicOK64(c) && config.RegSize == 8 && umagic64(c).m&1 == 0 && config.useHmul
	// result: (Rsh64Ux64 <typ.UInt64> (Hmul64u <typ.UInt64> (Const64 <typ.UInt64> [int64(1<<63+umagic64(c).m/2)]) x) (Const64 <typ.UInt64> [umagic64(c).s-1]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(umagicOK64(c) && config.RegSize == 8 && umagic64(c).m&1 == 0 && config.useHmul) {
			break
		}
		v.reset(OpRsh64Ux64)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpHmul64u, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(int64(1<<63 + umagic64(c).m/2))
		v0.AddArg2(v1, x)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(umagic64(c).s - 1)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Div64u x (Const64 [c]))
	// cond: umagicOK64(c) && config.RegSize == 8 && c&1 == 0 && config.useHmul
	// result: (Rsh64Ux64 <typ.UInt64> (Hmul64u <typ.UInt64> (Const64 <typ.UInt64> [int64(1<<63+(umagic64(c).m+1)/2)]) (Rsh64Ux64 <typ.UInt64> x (Const64 <typ.UInt64> [1]))) (Const64 <typ.UInt64> [umagic64(c).s-2]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(umagicOK64(c) && config.RegSize == 8 && c&1 == 0 && config.useHmul) {
			break
		}
		v.reset(OpRsh64Ux64)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpHmul64u, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(int64(1<<63 + (umagic64(c).m+1)/2))
		v2 := b.NewValue0(v.Pos, OpRsh64Ux64, typ.UInt64)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(1)
		v2.AddArg2(x, v3)
		v0.AddArg2(v1, v2)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(umagic64(c).s - 2)
		v.AddArg2(v0, v4)
		return true
	}
	// match: (Div64u x (Const64 [c]))
	// cond: umagicOK64(c) && config.RegSize == 8 && config.useAvg && config.useHmul
	// result: (Rsh64Ux64 <typ.UInt64> (Avg64u x (Hmul64u <typ.UInt64> (Const64 <typ.UInt64> [int64(umagic64(c).m)]) x)) (Const64 <typ.UInt64> [umagic64(c).s-1]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(umagicOK64(c) && config.RegSize == 8 && config.useAvg && config.useHmul) {
			break
		}
		v.reset(OpRsh64Ux64)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpAvg64u, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpHmul64u, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(int64(umagic64(c).m))
		v1.AddArg2(v2, x)
		v0.AddArg2(x, v1)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(umagic64(c).s - 1)
		v.AddArg2(v0, v3)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 (Const8 [c]) (Const8 [d]))
	// cond: d != 0
	// result: (Const8 [c/d])
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
		v.AuxInt = int8ToAuxInt(c / d)
		return true
	}
	// match: (Div8 n (Const8 [c]))
	// cond: isNonNegative(n) && isPowerOfTwo(c)
	// result: (Rsh8Ux64 n (Const64 <typ.UInt64> [log8(c)]))
	for {
		n := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(isNonNegative(n) && isPowerOfTwo(c)) {
			break
		}
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(log8(c))
		v.AddArg2(n, v0)
		return true
	}
	// match: (Div8 <t> n (Const8 [c]))
	// cond: c < 0 && c != -1<<7
	// result: (Neg8 (Div8 <t> n (Const8 <t> [-c])))
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
		v.reset(OpNeg8)
		v0 := b.NewValue0(v.Pos, OpDiv8, t)
		v1 := b.NewValue0(v.Pos, OpConst8, t)
		v1.AuxInt = int8ToAuxInt(-c)
		v0.AddArg2(n, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Div8 <t> x (Const8 [-1<<7 ]))
	// result: (Rsh8Ux64 (And8 <t> x (Neg8 <t> x)) (Const64 <typ.UInt64> [7 ]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != -1<<7 {
			break
		}
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpAnd8, t)
		v1 := b.NewValue0(v.Pos, OpNeg8, t)
		v1.AddArg(x)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(7)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Div8 <t> n (Const8 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Rsh8x64 (Add8 <t> n (Rsh8Ux64 <t> (Rsh8x64 <t> n (Const64 <typ.UInt64> [ 7])) (Const64 <typ.UInt64> [int64( 8-log8(c))]))) (Const64 <typ.UInt64> [int64(log8(c))]))
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
		v.reset(OpRsh8x64)
		v0 := b.NewValue0(v.Pos, OpAdd8, t)
		v1 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v2 := b.NewValue0(v.Pos, OpRsh8x64, t)
		v3 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(7)
		v2.AddArg2(n, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(int64(8 - log8(c)))
		v1.AddArg2(v2, v4)
		v0.AddArg2(n, v1)
		v5 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(int64(log8(c)))
		v.AddArg2(v0, v5)
		return true
	}
	// match: (Div8 <t> x (Const8 [c]))
	// cond: smagicOK8(c)
	// result: (Sub8 <t> (Rsh32x64 <t> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(smagic8(c).m)]) (SignExt8to32 x)) (Const64 <typ.UInt64> [8+smagic8(c).s])) (Rsh32x64 <t> (SignExt8to32 x) (Const64 <typ.UInt64> [31])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(smagicOK8(c)) {
			break
		}
		v.reset(OpSub8)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpRsh32x64, t)
		v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(int32(smagic8(c).m))
		v3 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v3.AddArg(x)
		v1.AddArg2(v2, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(8 + smagic8(c).s)
		v0.AddArg2(v1, v4)
		v5 := b.NewValue0(v.Pos, OpRsh32x64, t)
		v6 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(31)
		v5.AddArg2(v3, v6)
		v.AddArg2(v0, v5)
		return true
	}
	return false
}
func rewriteValuegeneric_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u (Const8 [c]) (Const8 [d]))
	// cond: d != 0
	// result: (Const8 [int8(uint8(c)/uint8(d))])
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
		v.AuxInt = int8ToAuxInt(int8(uint8(c) / uint8(d)))
		return true
	}
	// match: (Div8u n (Const8 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Rsh8Ux64 n (Const64 <typ.UInt64> [log8(c)]))
	for {
		n := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(log8(c))
		v.AddArg2(n, v0)
		return true
	}
	// match: (Div8u x (Const8 [c]))
	// cond: umagicOK8(c)
	// result: (Trunc32to8 (Rsh32Ux64 <typ.UInt32> (Mul32 <typ.UInt32> (Const32 <typ.UInt32> [int32(1<<8+umagic8(c).m)]) (ZeroExt8to32 x)) (Const64 <typ.UInt64> [8+umagic8(c).s])))
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(umagicOK8(c)) {
			break
		}
		v.reset(OpTrunc32to8)
		v0 := b.NewValue0(v.Pos, OpRsh32Ux64, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpMul32, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(int32(1<<8 + umagic8(c).m))
		v3 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v3.AddArg(x)
		v1.AddArg2(v2, v3)
		v4 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(8 + umagic8(c).s)
		v0.AddArg2(v1, v4)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Eq16 x x)
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
	// match: (Eq16 (Const16 <t> [c]) (Add16 (Const16 <t> [d]) x))
	// result: (Eq16 (Const16 <t> [c-d]) x)
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
				v.reset(OpEq16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Eq16 (Const16 [c]) (Const16 [d]))
	// result: (ConstBool [c == d])
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
			v.AuxInt = boolToAuxInt(c == d)
			return true
		}
		break
	}
	// match: (Eq16 (Mod16u x (Const16 [c])) (Const16 [0]))
	// cond: x.Op != OpConst16 && udivisibleOK16(c) && !hasSmallRotate(config)
	// result: (Eq32 (Mod32u <typ.UInt32> (ZeroExt16to32 <typ.UInt32> x) (Const32 <typ.UInt32> [int32(uint16(c))])) (Const32 <typ.UInt32> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMod16u {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_1.AuxInt)
			if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != 0 || !(x.Op != OpConst16 && udivisibleOK16(c) && !hasSmallRotate(config)) {
				continue
			}
			v.reset(OpEq32)
			v0 := b.NewValue0(v.Pos, OpMod32u, typ.UInt32)
			v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
			v1.AddArg(x)
			v2 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
			v2.AuxInt = int32ToAuxInt(int32(uint16(c)))
			v0.AddArg2(v1, v2)
			v3 := b.NewValue0(v.Pos, OpConst32, typ.UInt32)
			v3.AuxInt = int32ToAuxInt(0)
			v.AddArg2(v0, v3)
			return true
		}
		break
	}
	// match: (Eq16 (Mod16 x (Const16 [c])) (Const16 [0]))
	// cond: x.Op != OpConst16 && sdivisibleOK16(c) && !hasSmallRotate(config)
	// result: (Eq32 (Mod32 <typ.Int32> (SignExt16to32 <typ.Int32> x) (Const32 <typ.Int32> [int32(c)])) (Const32 <typ.Int32> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMod16 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_1.AuxInt)
			if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != 0 || !(x.Op != OpConst16 && sdivisibleOK16(c) && !hasSmallRotate(config)) {
				continue
			}
			v.reset(OpEq32)
			v0 := b.NewValue0(v.Pos, OpMod32, typ.Int32)
			v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
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
	// match: (Eq16 x (Mul16 (Const16 [c]) (Trunc64to16 (Rsh64Ux64 mul:(Mul64 (Const64 [m]) (ZeroExt16to64 x)) (Const64 [s]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<16+umagic16(c).m) && s == 16+umagic16(c).s && x.Op != OpConst16 && udivisibleOK16(c)
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
				if v_1_1.Op != OpTrunc64to16 {
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
					if mul_1.Op != OpZeroExt16to64 || x != mul_1.Args[0] {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int64(1<<16+umagic16(c).m) && s == 16+umagic16(c).s && x.Op != OpConst16 && udivisibleOK16(c)) {
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
	// match: (Eq16 x (Mul16 (Const16 [c]) (Trunc32to16 (Rsh32Ux64 mul:(Mul32 (Const32 [m]) (ZeroExt16to32 x)) (Const64 [s]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(1<<15+umagic16(c).m/2) && s == 16+umagic16(c).s-1 && x.Op != OpConst16 && udivisibleOK16(c)
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
					if mul_1.Op != OpZeroExt16to32 || x != mul_1.Args[0] {
						continue
					}
					v_1_1_0_1 := v_1_1_0.Args[1]
					if v_1_1_0_1.Op != OpConst64 {
						continue
					}
					s := auxIntToInt64(v_1_1_0_1.AuxInt)
					if !(v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(1<<15+umagic16(c).m/2) && s == 16+umagic16(c).s-1 && x.Op != OpConst16 && udivisibleOK16(c)) {
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
	// match: (Eq16 x (Mul16 (Const16 [c]) (Trunc32to16 (Rsh32Ux64 mul:(Mul32 (Const32 [m]) (Rsh32Ux64 (ZeroExt16to32 x) (Const64 [1]))) (Const64 [s]))) ) )
	// cond: v.Block.Func.pass.name != "opt" && mul.Uses == 1 && m == int32(1<<15+(umagic16(c).m+1)/2) && s == 16+umagic16(c).s-2 && x.Op != OpConst16 && udivisibleOK16(c)
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
					if mul_1.Op != OpRsh32Ux64 {
						continue
					}
					_ = mul_1.Args[1]
					mul_1_0 := mul_1.Args[0]
					if mul_1_0.Op != OpZeroExt16to32 || x != mul_1_0.Args[0] {
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
					if !(v.Block.Func.pass.n
"""




```