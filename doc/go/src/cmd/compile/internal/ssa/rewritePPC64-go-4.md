Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第5部分，共6部分，请归纳一下它的功能

"""
 [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [0] (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [1] (FlagGT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBC [1] (FlagLT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [1] (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [2] (FlagEQ))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBC [2] (FlagLT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [2] (FlagGT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [0] (InvertFlags bool))
	// result: (SETBC [1] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(bool)
		return true
	}
	// match: (SETBC [1] (InvertFlags bool))
	// result: (SETBC [0] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(bool)
		return true
	}
	// match: (SETBC [2] (InvertFlags bool))
	// result: (SETBC [2] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(2)
		v.AddArg(bool)
		return true
	}
	// match: (SETBC [n] (InvertFlags bool))
	// result: (SETBCR [n] bool)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(bool)
		return true
	}
	// match: (SETBC [2] (CMPconst [0] a:(ANDconst [1] _)))
	// result: (XORconst [1] a)
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64ANDconst || auxIntToInt64(a.AuxInt) != 1 {
			break
		}
		v.reset(OpPPC64XORconst)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg(a)
		return true
	}
	// match: (SETBC [2] (CMPconst [0] a:(AND y z)))
	// cond: a.Uses == 1
	// result: (SETBC [2] (Select1 <types.TypeFlags> (ANDCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64AND {
			break
		}
		z := a.Args[1]
		y := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (SETBC [2] (CMPconst [0] o:(OR y z)))
	// cond: o.Uses == 1
	// result: (SETBC [2] (Select1 <types.TypeFlags> (ORCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		o := v_0.Args[0]
		if o.Op != OpPPC64OR {
			break
		}
		z := o.Args[1]
		y := o.Args[0]
		if !(o.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (SETBC [2] (CMPconst [0] a:(XOR y z)))
	// cond: a.Uses == 1
	// result: (SETBC [2] (Select1 <types.TypeFlags> (XORCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64XOR {
			break
		}
		z := a.Args[1]
		y := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SETBCR(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETBCR [0] (FlagLT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBCR [0] (FlagGT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [0] (FlagEQ))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [1] (FlagGT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBCR [1] (FlagLT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [1] (FlagEQ))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [2] (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBCR [2] (FlagLT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [2] (FlagGT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [0] (InvertFlags bool))
	// result: (SETBCR [1] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(bool)
		return true
	}
	// match: (SETBCR [1] (InvertFlags bool))
	// result: (SETBCR [0] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(bool)
		return true
	}
	// match: (SETBCR [2] (InvertFlags bool))
	// result: (SETBCR [2] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v.AddArg(bool)
		return true
	}
	// match: (SETBCR [n] (InvertFlags bool))
	// result: (SETBC [n] bool)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(bool)
		return true
	}
	// match: (SETBCR [2] (CMPconst [0] a:(ANDconst [1] _)))
	// result: a
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64ANDconst || auxIntToInt64(a.AuxInt) != 1 {
			break
		}
		v.copyOf(a)
		return true
	}
	// match: (SETBCR [2] (CMPconst [0] a:(AND y z)))
	// cond: a.Uses == 1
	// result: (SETBCR [2] (Select1 <types.TypeFlags> (ANDCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64AND {
			break
		}
		z := a.Args[1]
		y := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (SETBCR [2] (CMPconst [0] o:(OR y z)))
	// cond: o.Uses == 1
	// result: (SETBCR [2] (Select1 <types.TypeFlags> (ORCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		o := v_0.Args[0]
		if o.Op != OpPPC64OR {
			break
		}
		z := o.Args[1]
		y := o.Args[0]
		if !(o.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (SETBCR [2] (CMPconst [0] a:(XOR y z)))
	// cond: a.Uses == 1
	// result: (SETBCR [2] (Select1 <types.TypeFlags> (XORCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64XOR {
			break
		}
		z := a.Args[1]
		y := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SLD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLD x (MOVDconst [c]))
	// result: (SLDconst [c&63 | (c>>6&1*63)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SLDconst)
		v.AuxInt = int64ToAuxInt(c&63 | (c >> 6 & 1 * 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SLDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLDconst [l] (SRWconst [r] x))
	// cond: mergePPC64SldiSrw(l,r) != 0
	// result: (RLWINM [mergePPC64SldiSrw(l,r)] x)
	for {
		l := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64SldiSrw(l, r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64SldiSrw(l, r))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [s] (RLWINM [r] y))
	// cond: mergePPC64SldiRlwinm(s,r) != 0
	// result: (RLWINM [mergePPC64SldiRlwinm(s,r)] y)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64RLWINM {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if !(mergePPC64SldiRlwinm(s, r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64SldiRlwinm(s, r))
		v.AddArg(y)
		return true
	}
	// match: (SLDconst [c] z:(MOVBZreg x))
	// cond: c < 8 && z.Uses == 1
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,56,63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVBZreg {
			break
		}
		x := z.Args[0]
		if !(c < 8 && z.Uses == 1) {
			break
		}
		v.reset(OpPPC64CLRLSLDI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 56, 63, 64))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [c] z:(MOVHZreg x))
	// cond: c < 16 && z.Uses == 1
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,48,63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVHZreg {
			break
		}
		x := z.Args[0]
		if !(c < 16 && z.Uses == 1) {
			break
		}
		v.reset(OpPPC64CLRLSLDI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 48, 63, 64))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [c] z:(MOVWZreg x))
	// cond: c < 32 && z.Uses == 1
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,32,63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVWZreg {
			break
		}
		x := z.Args[0]
		if !(c < 32 && z.Uses == 1) {
			break
		}
		v.reset(OpPPC64CLRLSLDI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 32, 63, 64))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [c] z:(ANDconst [d] x))
	// cond: z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (64-getPPC64ShiftMaskLength(d))
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,64-getPPC64ShiftMaskLength(d),63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		d := auxIntToInt64(z.AuxInt)
		x := z.Args[0]
		if !(z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (64-getPPC64ShiftMaskLength(d))) {
			break
		}
		v.reset(OpPPC64CLRLSLDI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 64-getPPC64ShiftMaskLength(d), 63, 64))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [c] z:(AND (MOVDconst [d]) x))
	// cond: z.Uses == 1 && isPPC64ValidShiftMask(d) && c<=(64-getPPC64ShiftMaskLength(d))
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,64-getPPC64ShiftMaskLength(d),63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64AND {
			break
		}
		_ = z.Args[1]
		z_0 := z.Args[0]
		z_1 := z.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
			if z_0.Op != OpPPC64MOVDconst {
				continue
			}
			d := auxIntToInt64(z_0.AuxInt)
			x := z_1
			if !(z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (64-getPPC64ShiftMaskLength(d))) {
				continue
			}
			v.reset(OpPPC64CLRLSLDI)
			v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 64-getPPC64ShiftMaskLength(d), 63, 64))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (SLDconst [c] z:(MOVWreg x))
	// cond: c < 32 && buildcfg.GOPPC64 >= 9
	// result: (EXTSWSLconst [c] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVWreg {
			break
		}
		x := z.Args[0]
		if !(c < 32 && buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64EXTSWSLconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLW x (MOVDconst [c]))
	// result: (SLWconst [c&31 | (c>>5&1*31)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SLWconst)
		v.AuxInt = int64ToAuxInt(c&31 | (c >> 5 & 1 * 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SLWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLWconst [s] (MOVWZreg w))
	// result: (SLWconst [s] w)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVWZreg {
			break
		}
		w := v_0.Args[0]
		v.reset(OpPPC64SLWconst)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg(w)
		return true
	}
	// match: (SLWconst [c] z:(MOVBZreg x))
	// cond: z.Uses == 1 && c < 8
	// result: (CLRLSLWI [newPPC64ShiftAuxInt(c,24,31,32)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVBZreg {
			break
		}
		x := z.Args[0]
		if !(z.Uses == 1 && c < 8) {
			break
		}
		v.reset(OpPPC64CLRLSLWI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 24, 31, 32))
		v.AddArg(x)
		return true
	}
	// match: (SLWconst [c] z:(MOVHZreg x))
	// cond: z.Uses == 1 && c < 16
	// result: (CLRLSLWI [newPPC64ShiftAuxInt(c,16,31,32)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVHZreg {
			break
		}
		x := z.Args[0]
		if !(z.Uses == 1 && c < 16) {
			break
		}
		v.reset(OpPPC64CLRLSLWI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 16, 31, 32))
		v.AddArg(x)
		return true
	}
	// match: (SLWconst [c] z:(ANDconst [d] x))
	// cond: z.Uses == 1 && isPPC64ValidShiftMask(d) && c<=(32-getPPC64ShiftMaskLength(d))
	// result: (CLRLSLWI [newPPC64ShiftAuxInt(c,32-getPPC64ShiftMaskLength(d),31,32)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		d := auxIntToInt64(z.AuxInt)
		x := z.Args[0]
		if !(z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (32-getPPC64ShiftMaskLength(d))) {
			break
		}
		v.reset(OpPPC64CLRLSLWI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 32-getPPC64ShiftMaskLength(d), 31, 32))
		v.AddArg(x)
		return true
	}
	// match: (SLWconst [c] z:(AND (MOVDconst [d]) x))
	// cond: z.Uses == 1 && isPPC64ValidShiftMask(d) && c<=(32-getPPC64ShiftMaskLength(d))
	// result: (CLRLSLWI [newPPC64ShiftAuxInt(c,32-getPPC64ShiftMaskLength(d),31,32)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64AND {
			break
		}
		_ = z.Args[1]
		z_0 := z.Args[0]
		z_1 := z.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
			if z_0.Op != OpPPC64MOVDconst {
				continue
			}
			d := auxIntToInt64(z_0.AuxInt)
			x := z_1
			if !(z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (32-getPPC64ShiftMaskLength(d))) {
				continue
			}
			v.reset(OpPPC64CLRLSLWI)
			v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 32-getPPC64ShiftMaskLength(d), 31, 32))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (SLWconst [c] z:(MOVWreg x))
	// cond: c < 32 && buildcfg.GOPPC64 >= 9
	// result: (EXTSWSLconst [c] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVWreg {
			break
		}
		x := z.Args[0]
		if !(c < 32 && buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64EXTSWSLconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRAD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRAD x (MOVDconst [c]))
	// result: (SRADconst [c&63 | (c>>6&1*63)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c&63 | (c >> 6 & 1 * 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRAW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRAW x (MOVDconst [c]))
	// result: (SRAWconst [c&31 | (c>>5&1*31)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c&31 | (c >> 5 & 1 * 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRD x (MOVDconst [c]))
	// result: (SRDconst [c&63 | (c>>6&1*63)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c&63 | (c >> 6 & 1 * 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRW x (MOVDconst [c]))
	// result: (SRWconst [c&31 | (c>>5&1*31)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c&31 | (c >> 5 & 1 * 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRWconst (ANDconst [m] x) [s])
	// cond: mergePPC64RShiftMask(m>>uint(s),s,32) == 0
	// result: (MOVDconst [0])
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		if !(mergePPC64RShiftMask(m>>uint(s), s, 32) == 0) {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRWconst (ANDconst [m] x) [s])
	// cond: mergePPC64AndSrwi(m>>uint(s),s) != 0
	// result: (RLWINM [mergePPC64AndSrwi(m>>uint(s),s)] x)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64AndSrwi(m>>uint(s), s) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndSrwi(m>>uint(s), s))
		v.AddArg(x)
		return true
	}
	// match: (SRWconst (AND (MOVDconst [m]) x) [s])
	// cond: mergePPC64RShiftMask(m>>uint(s),s,32) == 0
	// result: (MOVDconst [0])
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64AND {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0_0.AuxInt)
			if !(mergePPC64RShiftMask(m>>uint(s), s, 32) == 0) {
				continue
			}
			v.reset(OpPPC64MOVDconst)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (SRWconst (AND (MOVDconst [m]) x) [s])
	// cond: mergePPC64AndSrwi(m>>uint(s),s) != 0
	// result: (RLWINM [mergePPC64AndSrwi(m>>uint(s),s)] x)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64AND {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0_0.AuxInt)
			x := v_0_1
			if !(mergePPC64AndSrwi(m>>uint(s), s) != 0) {
				continue
			}
			v.reset(OpPPC64RLWINM)
			v.AuxInt = int64ToAuxInt(mergePPC64AndSrwi(m>>uint(s), s))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64SUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUB x (MOVDconst [c]))
	// cond: is32Bit(-c)
	// result: (ADDconst [-c] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(-c)) {
			break
		}
		v.reset(OpPPC64ADDconst)
		v.AuxInt = int64ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (SUB (MOVDconst [c]) x)
	// cond: is32Bit(c)
	// result: (SUBFCconst [c] x)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpPPC64SUBFCconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SUBE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBE x y (Select1 <typ.UInt64> (SUBCconst (MOVDconst [0]) [0])))
	// result: (SUBC x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 || v_2.Type != typ.UInt64 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64SUBCconst || auxIntToInt64(v_2_0.AuxInt) != 0 {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpPPC64MOVDconst || auxIntToInt64(v_2_0_0.AuxInt) != 0 {
			break
		}
		v.reset(OpPPC64SUBC)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SUBFCconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBFCconst [c] (NEG x))
	// result: (ADDconst [c] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64NEG {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUBFCconst [c] (SUBFCconst [d] x))
	// cond: is32Bit(c-d)
	// result: (ADDconst [c-d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64SUBFCconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c - d)) {
			break
		}
		v.reset(OpPPC64ADDconst)
		v.AuxInt = int64ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	// match: (SUBFCconst [0] x)
	// result: (NEG x)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.reset(OpPPC64NEG)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c^d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpPPC64MOVDconst)
			v.AuxInt = int64ToAuxInt(c ^ d)
			return true
		}
		break
	}
	// match: (XOR x (MOVDconst [c]))
	// cond: isU32Bit(c)
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isU32Bit(c)) {
				continue
			}
			v.reset(OpPPC64XORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64XORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORconst [c] (XORconst [d] x))
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64XORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpPPC64XORconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	// match: (XORconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (XORconst [1] (SETBCR [n] cmp))
	// result: (SETBC [n] cmp)
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpPPC64SETBCR {
			break
		}
		n := auxIntToInt32(v_0.AuxInt)
		cmp := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(cmp)
		return true
	}
	// match: (XORconst [1] (SETBC [n] cmp))
	// result: (SETBCR [n] cmp)
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpPPC64SETBC {
			break
		}
		n := auxIntToInt32(v_0.AuxInt)
		cmp := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(cmp)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPanicBounds(v *Value) bool {
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
		v.reset(OpPPC64LoweredPanicBoundsA)
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
		v.reset(OpPPC64LoweredPanicBoundsB)
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
		v.reset(OpPPC64LoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPopCount16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount16 x)
	// result: (POPCNTW (MOVHZreg x))
	for {
		x := v_0
		v.reset(OpPPC64POPCNTW)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpPopCount32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount32 x)
	// result: (POPCNTW (MOVWZreg x))
	for {
		x := v_0
		v.reset(OpPPC64POPCNTW)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpPopCount8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount8 x)
	// result: (POPCNTB (MOVBZreg x))
	for {
		x := v_0
		v.reset(OpPPC64POPCNTB)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpPrefetchCache(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PrefetchCache ptr mem)
	// result: (DCBT ptr mem [0])
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64DCBT)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpPrefetchCacheStreamed(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PrefetchCacheStreamed ptr mem)
	// result: (DCBT ptr mem [16])
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64DCBT)
		v.AuxInt = int64ToAuxInt(16)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVDconst [c]))
	// result: (Or16 (Lsh16x64 <t> x (MOVDconst [c&15])) (Rsh16Ux64 <t> x (MOVDconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v3 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v3.AuxInt = int64ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValuePPC64_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVDconst [c]))
	// result: (Or8 (Lsh8x64 <t> x (MOVDconst [c&7])) (Rsh8Ux64 <t> x (MOVDconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v3 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v3.AuxInt = int64ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValuePPC64_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux16 <t> x y)
	// result: (ISEL [2] (SRD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFF0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux32 <t> x y)
	// result: (ISEL [0] (SRD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPWUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 16
	// result: (SRWconst (ZeroExt16to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux64 <t> x y)
	// result: (ISEL [0] (SRD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux8 <t> x y)
	// result: (ISEL [2] (SRD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00F0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0x00F0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x16 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVHreg x) y) (SRADconst <t> (MOVHreg x) [15]) (CMPconst [0] (ANDconst [0xFFF0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(15)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x32 <t> x y)
	// result: (ISEL [0] (SRAD <t> (MOVHreg x) y) (SRADconst <t> (MOVHreg x) [15]) (CMPWUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(15)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 x (MOVDconst [c]))
	// cond: uint64(c) >= 16
	// result: (SRAWconst (SignExt16to32 x) [63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16x64 x (MOVDconst [c]))
	// cond: uint64(c) < 16
	// result: (SRAWconst (SignExt16to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x64 <t> x y)
	// result: (ISEL [0] (SRAD <t> (MOVHreg x) y) (SRADconst <t> (MOVHreg x) [15]) (CMPUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(15)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVHreg x) y) (SRADconst <t> (MOVHreg x) [15]) (CMPconst [0] (ANDconst [0x00F0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(15)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0x00F0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux16 <t> x y)
	// result: (ISEL [2] (SRW <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFE0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFE0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux32 <t> x y)
	// result: (ISEL [0] (SRW <t> x y) (MOVDconst [0]) (CMPWUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 32
	// result: (SRWconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Rsh32Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux64 <t> x y)
	// result: (ISEL [0] (SRW <t> x y) (MOVDconst [0]) (CMPUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux8 <t> x y)
	// result: (ISEL [2] (SRW <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00E0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00E0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x16 <t> x y)
	// result: (ISEL [2] (SRAW <t> x y) (SRAWconst <t> x [31]) (CMPconst [0] (ANDconst [0xFFE0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRAWconst, t)
		v1.AuxInt = int64ToAuxInt(31)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFE0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x32 <t> x y)
	// result: (ISEL [0] (SRAW <t> x y) (SRAWconst <t> x [31]) (CMPWUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRAWconst, t)
		v1.AuxInt = int64ToAuxInt(31)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x64 x (MOVDconst [c]))
	// cond: uint64(c) >= 32
	// result: (SRAWconst x [63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 32) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	// match: (Rsh32x64 x (MOVDconst [c]))
	// cond: uint64(c) < 32
	// result: (SRAWconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Rsh32x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x64 <t> x y)
	// result: (ISEL [0] (SRAW <t> x y) (SRAWconst <t> x [31]) (CMPUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRAWconst, t)
		v1.AuxInt = int64ToAuxInt(31)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x8 <t> x y)
	// result: (ISEL [2] (SRAW <t> x y) (SRAWconst <t> x [31]) (CMPconst [0] (ANDconst [0x00E0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRAWconst, t)
		v1.AuxInt = int64ToAuxInt(31)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00E0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux16 <t> x y)
	// result: (ISEL [2] (SRD <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFC0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFC0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux32 <t> x y)
	// result: (ISEL [0] (SRD <t> x y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 64
	// result: (SRDconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 64) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Rsh64Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux64 <t> x y)
	// result: (ISEL [0] (SRD <t> x y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux8 <t> x y)
	// result: (ISEL [2] (SRD <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00C0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00C0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x16 <t> x y)
	// result: (ISEL [2] (SRAD <t> x y) (SRADconst <t> x [63]) (CMPconst [0] (ANDconst [0xFFC0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v1.AuxInt = int64ToAuxInt(63)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFC0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x32 <t> x y)
	// result: (ISEL [0] (SRAD <t> x y) (SRADconst <t> x [63]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v1.AuxInt = int64ToAuxInt(63)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x64 x (MOVDconst [c]))
	// cond: uint64(c) >= 64
	// result: (SRADconst x [63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	// match: (Rsh64x64 x (MOVDconst [c]))
	// cond: uint64(c) < 64
	// result: (SRADconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 64) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Rsh64x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x64 <t> x y)
	// result: (ISEL [0] (SRAD <t> x y) (SRADconst <t> x [63]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v1.AuxInt = int64ToAuxInt(63)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> x y) (SRADconst <t> x [63]) (CMPconst [0] (ANDconst [0x00C0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v1.AuxInt = int64ToAuxInt(63)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00C0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux16 <t> x y)
	// result: (ISEL [2] (SRD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFF8] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux32 <t> x y)
	// result: (ISEL [0] (SRD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPWUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 8
	// result: (SRWconst (ZeroExt8to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux64 <t> x y)
	// result: (ISEL [0] (SRD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux8 <t> x y)
	// result: (ISEL [2] (SRD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00F8] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0x00F8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x16 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPconst [0] (ANDconst [0xFFF8] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(7)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x32 <t> x y)
	// result: (ISEL [0] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPWUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(7)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 x (MOVDconst [c]))
	// cond: uint64(c) >= 8
	// result: (SRAWconst (SignExt8to32 x) [63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 8) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8x64 x (MOVDconst [c]))
	// cond: uint64(c) < 8
	// result: (SRAWconst (SignExt8to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x64 <t> x y)
	// result: (ISEL [0] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(7)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		
"""




```