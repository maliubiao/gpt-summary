Response: The user wants to understand the functionality of the provided Go code snippet, which is part of the SSA rewrite rules for the PPC64 architecture in the Go compiler.

To address this, I will:

1. **Analyze each function:**  `rewriteValuePPC64_OpRsh8x`, `rewriteValuePPC64_OpSelect0`, `rewriteValuePPC64_OpSelect1`, `rewriteValuePPC64_OpSelectN`, `rewriteValuePPC64_OpSlicemask`, `rewriteValuePPC64_OpStore`, `rewriteValuePPC64_OpTrunc16to8` ... `rewriteBlockPPC64`. I'll determine what kind of SSA optimizations they perform.
2. **Provide illustrative Go code examples:**  For some of the more straightforward rewrites, I'll create simple Go code snippets that would potentially trigger those optimizations.
3. **Infer the Go language features:** Based on the identified optimizations, I'll try to deduce the higher-level Go language constructs that are being optimized.
4. **Address command-line arguments (if applicable):** The provided code doesn't seem to directly handle command-line arguments. If it did, I would detail how those arguments influence the rewrite process.
5. **Identify potential pitfalls for users:** I'll look for common mistakes users might make that could prevent these optimizations from being applied (although this might be less relevant for low-level compiler optimizations).
6. **Summarize the overall functionality:**  I'll provide a concise summary of the purpose of this specific part of the Go compiler.
```go
func rewriteValuePPC64_OpRsh8x(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 <t> x y)
	// result: (SRAD <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64SRAD)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh8x8 <t> (Const8 [c]) y)
	// result: (SRADconst <t> [c] y)
	for {
		t := v.Type
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		y := v_1
		v.reset(OpPPC64SRADconst)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (Rsh8x8 <t> x (Const8 [c]))
	// result: (SRADconst <t> x [c&63])
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SRADconst)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	// match: (Rsh8x8 <t> (SRAconst x [c]) y)
	// result: (SRAD <t> x (SUB <y.Type> y (Select0 <y.Type> (ADDconst <y.Type> [-c]))))
	for {
		t := v.Type
		if v_0.Op != OpSRAconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		y := v_1
		v.reset(OpPPC64SRAD)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpPPC64SUB, y.Type)
		v1 := b.NewValue0(v.Pos, OpSelect0, y.Type)
		v2 := b.NewValue0(v.Pos, OpPPC64ADDconst, y.Type)
		v2.AuxInt = int64ToAuxInt(-c)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x8 <t> (SRA x k) y)
	// result: (SRAD <t> x (SUB <y.Type> y (Select0 <y.Type> k)))
	for {
		t := v.Type
		if v_0.Op != OpSRA {
			break
		}
		k := v_0.Args[1]
		x := v_0.Args[0]
		y := v_1
		v.reset(OpPPC64SRAD)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpPPC64SUB, y.Type)
		v1 := b.NewValue0(v.Pos, OpSelect0, y.Type)
		v1.AddArg(k)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x8 <t> x (ADD y z))
	// result: (SRAD <t> x (SUB <y.Type> (ADD <y.Type> y z) (Select0 <y.Type> (ADDconst <y.Type> [-64]))))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpADD {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpPPC64SUB, y.Type)
		v1 := b.NewValue0(v.Pos, OpPPC64ADD, y.Type)
		v1.AddArg2(y, z)
		v2 := b.NewValue0(v.Pos, OpSelect0, y.Type)
		v3 := b.NewValue0(v.Pos, OpPPC64ADDconst, y.Type)
		v3.AuxInt = int64ToAuxInt(-64)
		v2.AddArg(v3)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x8 <t> x (SUB y z))
	// result: (SRAD <t> x (SUB <y.Type> (SUB <y.Type> y z) (Select0 <y.Type> (ADDconst <y.Type> [-64]))))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpSUB {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpPPC64SUB, y.Type)
		v1 := b.NewValue0(v.Pos, OpPPC64SUB, y.Type)
		v1.AddArg2(y, z)
		v2 := b.NewValue0(v.Pos, OpSelect0, y.Type)
		v3 := b.NewValue0(v.Pos, OpPPC64ADDconst, y.Type)
		v3.AuxInt = int64ToAuxInt(-64)
		v2.AddArg(v3)
		v0.AddArg2(v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> x y) (SRADconst <t> x [63]) (CMPconst [64] y))
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
		v2 := b.NewValue0(b.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
	// match: (Rsh8x8 <t> x (MOVBreg y))
	// result: (SRAD <t> x y)
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh8x8 <t> x (MOVHreg y))
	// result: (SRAD <t> x y)
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh8x8 <t> x (MOVWreg y))
	// result: (SRAD <t> x y)
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh8x8 <t> x (MOVBZreg y))
	// result: (SRAD <t> x y)
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh8x8 <t> x (MOVHZreg y))
	// result: (SRAD <t> x y)
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh8x8 <t> x (MOVWZreg y))
	// result: (SRAD <t> x y)
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh8x8 <t> x (ANDconst [c] y))
	// result: (SRAD <t> x y)
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c >= 0) {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh8x8 <t> x (ORconst [c] y))
	// result: (SRAD <t> x y)
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64ORconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c == -1) {
			break
		}
		y := v_1.Args[0]
		v.reset(OpPPC64SRAD)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh8x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> x y) (SRADconst <t> x [63]) (CMP <y.Type> y (MOVDconst [64])))
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
		v2 := b.NewValue0(b.Pos, OpPPC64CMP, types.TypeFlags)
		v3 := b.NewValue0(b.Pos, OpPPC64MOVDconst, typ.Int64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(y, v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	// match: (Rsh8x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPconst [0] (ANDconst <y.Type> [0x07] y)))
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
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, y.Type)
		v4.AuxInt = int64ToAuxInt(0x07)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	// match: (Rsh8x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPconst [0] (ANDconst [0x00F8] y)))
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
		v4.AuxInt = int64ToAuxInt(0x00F8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Mul64uhilo x y))
	// result: (MULHDU x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64MULHDU)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Mul64uover x y))
	// result: (MULLD x y)
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64MULLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADDE x y (Select1 <typ.UInt64> (ADDCconst c [-1]))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpPPC64ADDE, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpPPC64ADDCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v2.AuxInt = int64ToAuxInt(-1)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Sub64borrow x y c))
	// result: (Select0 <typ.UInt64> (SUBE x y (Select1 <typ.UInt64> (SUBCconst c [0]))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpPPC64SUBE, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpPPC64SUBCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v2.AuxInt = int64ToAuxInt(0)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Mul64uhilo x y))
	// result: (MULLD x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64MULLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select1 (Mul64uover x y))
	// result: (SETBCR [2] (CMPconst [0] (MULHDU <x.Type> x y)))
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpPPC64MULHDU, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Add64carry x y c))
	// result: (ADDZEzero (Select1 <typ.UInt64> (ADDE x y (Select1 <typ.UInt64> (ADDCconst c [-1])))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpPPC64ADDZEzero)
		v0 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpPPC64ADDE, types.NewTuple(typ.UInt64, typ.UInt64))
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v3 := b.NewValue0(v.Pos, OpPPC64ADDCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v3.AuxInt = int64ToAuxInt(-1)
		v3.AddArg(c)
		v2.AddArg(v3)
		v1.AddArg3(x, y, v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (ADDCconst n:(ADDZEzero x) [-1]))
	// cond: n.Uses <= 2
	// result: x
	for {
		if v_0.Op != OpPPC64ADDCconst || auxIntToInt64(v_0.AuxInt) != -1 {
			break
		}
		n := v_0.Args[0]
		if n.Op != OpPPC64ADDZEzero {
			break
		}
		x := n.Args[0]
		if !(n.Uses <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Select1 (Sub64borrow x y c))
	// result: (NEG (SUBZEzero (Select1 <typ.UInt64> (SUBE x y (Select1 <typ.UInt64> (SUBCconst c [0]))))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpPPC64NEG)
		v0 := b.NewValue0(v.Pos, OpPPC64SUBZEzero, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpPPC64SUBE, types.NewTuple(typ.UInt64, typ.UInt64))
		v3 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v4 := b.NewValue0(v.Pos, OpPPC64SUBCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v4.AuxInt = int64ToAuxInt(0)
		v4.AddArg(c)
		v3.AddArg(v4)
		v2.AddArg3(x, y, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (SUBCconst n:(NEG (SUBZEzero x)) [0]))
	// cond: n.Uses <= 2
	// result: x
	for {
		if v_0.Op != OpPPC64SUBCconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		n := v_0.Args[0]
		if n.Op != OpPPC64NEG {
			break
		}
		n_0 := n.Args[0]
		if n_0.Op != OpPPC64SUBZEzero {
			break
		}
		x := n_0.Args[0]
		if !(n.Uses <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SelectN [0] call:(CALLstatic {sym} s1:(MOVDstore _ (MOVDconst [sz]) s2:(MOVDstore _ src s3:(MOVDstore {t} _ dst mem)))))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpPPC64CALLstatic || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpPPC64MOVDstore {
			break
		}
		_ = s1.Args[2]
		s1_1 := s1.Args[1]
		if s1_1.Op != OpPPC64MOVDconst {
			break
		}
		sz := auxIntToInt64(s1_1.AuxInt)
		s2 := s1.Args[2]
		if s2.Op != OpPPC64MOVDstore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpPPC64MOVDstore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(CALLstatic {sym} dst src (MOVDconst [sz]) mem))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpPPC64CALLstatic || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpPPC64MOVDconst {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRADconst (NEG <t> x) [63])
	for {
		t := v.Type
		x := v_0
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpPPC64NEG, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && t.IsFloat()
	// result: (FMOVDstore ptr val mem)
	
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```go
v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPconst [0] (ANDconst [0x00F8] y)))
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
		v4.AuxInt = int64ToAuxInt(0x00F8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Mul64uhilo x y))
	// result: (MULHDU x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64MULHDU)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Mul64uover x y))
	// result: (MULLD x y)
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64MULLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADDE x y (Select1 <typ.UInt64> (ADDCconst c [-1]))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpPPC64ADDE, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpPPC64ADDCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v2.AuxInt = int64ToAuxInt(-1)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Sub64borrow x y c))
	// result: (Select0 <typ.UInt64> (SUBE x y (Select1 <typ.UInt64> (SUBCconst c [0]))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpPPC64SUBE, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpPPC64SUBCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v2.AuxInt = int64ToAuxInt(0)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Mul64uhilo x y))
	// result: (MULLD x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64MULLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select1 (Mul64uover x y))
	// result: (SETBCR [2] (CMPconst [0] (MULHDU <x.Type> x y)))
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpPPC64MULHDU, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Add64carry x y c))
	// result: (ADDZEzero (Select1 <typ.UInt64> (ADDE x y (Select1 <typ.UInt64> (ADDCconst c [-1])))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpPPC64ADDZEzero)
		v0 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpPPC64ADDE, types.NewTuple(typ.UInt64, typ.UInt64))
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v3 := b.NewValue0(v.Pos, OpPPC64ADDCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v3.AuxInt = int64ToAuxInt(-1)
		v3.AddArg(c)
		v2.AddArg(v3)
		v1.AddArg3(x, y, v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (ADDCconst n:(ADDZEzero x) [-1]))
	// cond: n.Uses <= 2
	// result: x
	for {
		if v_0.Op != OpPPC64ADDCconst || auxIntToInt64(v_0.AuxInt) != -1 {
			break
		}
		n := v_0.Args[0]
		if n.Op != OpPPC64ADDZEzero {
			break
		}
		x := n.Args[0]
		if !(n.Uses <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Select1 (Sub64borrow x y c))
	// result: (NEG (SUBZEzero (Select1 <typ.UInt64> (SUBE x y (Select1 <typ.UInt64> (SUBCconst c [0]))))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpPPC64NEG)
		v0 := b.NewValue0(v.Pos, OpPPC64SUBZEzero, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpPPC64SUBE, types.NewTuple(typ.UInt64, typ.UInt64))
		v3 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v4 := b.NewValue0(v.Pos, OpPPC64SUBCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v4.AuxInt = int64ToAuxInt(0)
		v4.AddArg(c)
		v3.AddArg(v4)
		v2.AddArg3(x, y, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (SUBCconst n:(NEG (SUBZEzero x)) [0]))
	// cond: n.Uses <= 2
	// result: x
	for {
		if v_0.Op != OpPPC64SUBCconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		n := v_0.Args[0]
		if n.Op != OpPPC64NEG {
			break
		}
		n_0 := n.Args[0]
		if n_0.Op != OpPPC64SUBZEzero {
			break
		}
		x := n_0.Args[0]
		if !(n.Uses <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SelectN [0] call:(CALLstatic {sym} s1:(MOVDstore _ (MOVDconst [sz]) s2:(MOVDstore _ src s3:(MOVDstore {t} _ dst mem)))))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpPPC64CALLstatic || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpPPC64MOVDstore {
			break
		}
		_ = s1.Args[2]
		s1_1 := s1.Args[1]
		if s1_1.Op != OpPPC64MOVDconst {
			break
		}
		sz := auxIntToInt64(s1_1.AuxInt)
		s2 := s1.Args[2]
		if s2.Op != OpPPC64MOVDstore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpPPC64MOVDstore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(CALLstatic {sym} dst src (MOVDconst [sz]) mem))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpPPC64CALLstatic || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpPPC64MOVDconst {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRADconst (NEG <t> x) [63])
	for {
		t := v.Type
		x := v_0
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpPPC64NEG, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && t.IsFloat()
	// result: (FMOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && t.IsFloat()) {
			break
		}
		v.reset(OpPPC64FMOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && t.IsFloat()
	// result: (FMOVSstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && t.IsFloat()) {
			break
		}
		v.reset(OpPPC64FMOVSstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && !t.IsFloat()
	// result: (MOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && !t.IsFloat()) {
			break
		}
		v.reset(OpPPC64MOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && !t.IsFloat()
	// result: (MOVWstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && !t.IsFloat()) {
			break
		}
		v.reset(OpPPC64MOVWstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 2
	// result: (MOVHstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 2) {
			break
		}
		v.reset(OpPPC64MOVHstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 1
	// result: (MOVBstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 1) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpTrunc16to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc16to8 <t> x)
	// cond: t.IsSigned()
	// result: (MOVBreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc16to8 x)
	// result: (MOVBZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVBZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc32to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc32to16 <t> x)
	// cond: t.IsSigned()
	// result: (MOVHreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc32to16 x)
	// result: (MOVHZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVHZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc32to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc32to8 <t> x)
	// cond: t.IsSigned()
	// result: (MOVBreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc32to8 x)
	// result: (MOVBZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVBZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc64to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc64to16 <t> x)
	// cond: t.IsSigned()
	// result: (MOVHreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to16 x)
	// result: (MOVHZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVHZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc64to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc64to32 <t> x)
	// cond: t.IsSigned()
	// result: (MOVWreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to32 x)
	// result: (MOVWZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVWZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc64to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc64to8 <t> x)
	// cond: t.IsSigned()
	// result: (MOVBreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to8 x)
	// result: (MOVBZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVBZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpZero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Zero [0] _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_1
		v.copyOf(mem)
		return true
	}
	// match: (Zero [1] destptr mem)
	// result: (MOVBstorezero destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVBstorezero)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [2] destptr mem)
	// result: (MOVHstorezero destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVHstorezero)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [3] destptr mem)
	// result: (MOVBstorezero [2] destptr (MOVHstorezero destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHstorezero, types.TypeMem)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [4] destptr mem)
	// result: (MOVWstorezero destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVWstorezero)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [5] destptr mem)
	// result: (MOVBstorezero [4] destptr (MOVWstorezero destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWstorezero, types.TypeMem)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [6] destptr mem)
	// result: (MOVHstorezero [4] destptr (MOVWstorezero destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWstorezero, types.TypeMem)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [7] destptr mem)
	// result: (MOVBstorezero [6] destptr (MOVHstorezero [4] destptr (MOVWstorezero destptr mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(4)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVWstorezero, types.TypeMem)
		v1.AddArg2(destptr, mem)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [8] {t} destptr mem)
	// result: (MOVDstorezero destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVDstorezero)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [12] {t} destptr mem)
	// result: (MOVWstorezero [8] destptr (MOVDstorezero [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [16] {t} destptr mem)
	// result: (MOVDstorezero [8] destptr (MOVDstorezero [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [24] {t} destptr mem)
	// result: (MOVDstorezero [16] destptr (MOVDstorezero [8] destptr (MOVDstorezero [0] destptr mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 24 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(8)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg2(destptr, mem)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [32] {t} destptr mem)
	// result: (MOVDstorezero [24] destptr (MOVDstorezero [16] destptr (MOVDstorezero [8] destptr (MOVDstorezero [0] destptr mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(24)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(16)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg2(destptr, mem)
		v1.AddArg2(destptr, v2)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: buildcfg.GOPPC64 <= 8 && s < 64
	// result: (LoweredZeroShort [s] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(buildcfg.GOPPC64 <= 8 && s < 64) {
			break
		}
		v.reset(OpPPC64LoweredZeroShort)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: buildcfg.GOPPC64 <= 8
	// result: (LoweredZero [s] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(buildcfg.GOPPC64 <= 8) {
			break
		}
		v.reset(OpPPC64LoweredZero)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s < 128 && buildcfg.GOPPC64 >= 9
	// result: (LoweredQuadZeroShort [s] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s < 128 && buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64LoweredQuadZeroShort)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: buildcfg.GOPPC64 >= 9
	// result: (LoweredQuadZero [s] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64LoweredQuadZero)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteBlockPPC64(b *Block) bool {
	typ := &b.Func.Config.Types
	switch b.Kind {
	case BlockPPC64EQ:
		// match: (EQ (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (EQ (FlagLT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (InvertFlags cmp) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64EQ, cmp)
			return true
		}
		// match: (EQ (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64XOR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64EQ, v0)
				return true
			}
			break
		}
	case BlockPPC64GE:
		// match: (GE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (FlagLT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GE (FlagGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (InvertFlags cmp) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64LE, cmp)
			return true
		}
		// match: (GE (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (GE (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GE, v0)
				return true
			}
			break
		}
		// match: (GE (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (GE (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GE, v0)
				return true
			}
			break
		}
		// match: (GE (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (GE (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64XOR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GE, v0)
				return true
			}
			break
		}
	case BlockPPC64GT:
		// match: (GT (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagLT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GT (InvertFlags cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64LT, cmp)
			return true
		}
		// match: (GT (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (GT (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GT, v0)
				return true
			}
			break
		}
		// match: (GT (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (GT (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GT, v0)
				return true
			}
			break
		}
		// match: (GT (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (GT (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64XOR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GT, v0)
				return true
			}
			break
		}
	case BlockIf:
		// match: (If (Equal cc) yes no)
		// result: (EQ cc yes no)
		for b.Controls[0].Op == OpPPC64Equal {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64EQ, cc)
			return true
		}
		// match: (If (NotEqual cc) yes no)
		// result: (NE cc yes no)
		for b.Controls[0].Op == OpPPC64NotEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64NE, cc)
			return true
		}
		// match: (If (LessThan cc) yes no)
		// result: (LT cc yes no)
		for b.Controls[0].Op == OpPPC64LessThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64LT, cc)
			return true
		}
		// match: (If (LessEqual cc) yes no)
		// result: (LE cc yes no)
		for b.Controls[0].Op == OpPPC64LessEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64LE, cc)
			return true
		}
		// match: (If (GreaterThan cc) yes no)
		// result: (GT cc yes no)
		for b.Controls[0].Op == OpPPC64GreaterThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64GT, cc)
			return true
		}
		// match: (If (GreaterEqual cc) yes no)
		// result: (GE cc yes no)
		for b.Controls[0].Op == OpPPC64GreaterEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64GE, cc)
			return true
		}
		// match: (If (FLessThan cc) yes no)
		// result: (FLT cc yes no)
		for b.Controls[0].Op == OpPPC64FLessThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64FLT, cc)
			return true
		}
		// match: (If (FLessEqual cc) yes no)
		// result: (FLE cc yes no)
		for b.Controls[0].Op == OpPPC64FLessEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64FLE, cc)
			return true
		}
		// match: (If (FGreaterThan cc) yes no)
		// result: (FGT cc yes no)
		for b.Controls[0].Op == OpPPC64FGreaterThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64FGT, cc)
			return true
		}
		// match: (If (FGreaterEqual cc) yes no)
		// result: (FGE cc yes no)
		for b.Controls[0].Op == OpPPC64FGreaterEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64FGE, cc)
			return true
		}
		// match: (If cond yes no)
		// result: (NE (CMPconst [0] (ANDconst [1] cond)) yes no)
		for {
			cond := b.Controls[0]
			v0 := b.NewValue0(cond.Pos, OpPPC64CMPconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(0)
			v1 := b.NewValue0(cond.Pos, OpPPC64ANDconst, typ.Int)
			v1.AuxInt = int64ToAuxInt(1)
			v1.AddArg(cond)
			v0.AddArg(v1)
			b.resetWithControl(BlockPPC64NE, v0)
			return true
		}
	case BlockPPC64LE:
		// match: (LE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagLT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LE (InvertFlags cmp) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64GE, cmp)
			return true
		}
		// match: (LE (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (LE (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64LE, v0)
				return true
			}
			break
		}
		// match: (LE (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (LE (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64LE, v0)
				return true
			}
			break
		}
		// match: (LE (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (LE (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64XOR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64LE, v0)
				return true
			}
			break
		}
	case BlockPPC64LT:
		// match: (LT (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LT (FlagLT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LT (FlagGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LT (InvertFlags cmp) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64GT, cmp)
			return true
		}
		// match: (LT (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (LT (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64LT, v0)
				return true
			}
			break
		}
		// match: (LT (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (LT (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64LT, v0)
				return true
			}
			break
		}
		// match: (LT (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (LT (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64XOR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64LT, v0)
				return true
			}
			break
		}
	case BlockPPC64NE:
		// match: (NE (CMPconst [0] (ANDconst [1] (Equal cc))) yes no)
		// result: (EQ cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64Equal {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64EQ, cc)
			return true
		}
		// match: (NE (CMPconst [0] (ANDconst [1] (NotEqual cc))) yes no)
		// result: (NE cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64NotEqual {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64NE, cc)
			return true
		}
		// match: (NE (CMPconst [0] (ANDconst [1] (LessThan cc))) yes no)
		// result: (LT cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64LessThan {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64LT, cc)
			return true
		}
		// match: (NE (CMPconst [0] (ANDconst [1] (LessEqual cc))) yes no)
		// result: (LE cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64LessEqual {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64LE, cc)
			return true
		}
		// match: (NE (CMPconst [0] (ANDconst [1] (GreaterThan cc))) yes no)
		// result: (GT cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64GreaterThan {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64GT, cc)
			return true
		}
		// match: (NE (CMPconst [0] (ANDconst [1] (GreaterEqual cc))) yes no)
		// result: (GE cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64GreaterEqual {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64GE, cc)
			return true
		}
		// match: (NE (CMPconst [0] (ANDconst [1] (FLessThan cc))) yes no)
		// result: (FLT cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64FLessThan {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64FLT, cc)
			return true
		}
		// match: (NE (CMPconst [0] (ANDconst [1] (FLessEqual cc))) yes no)
		// result: (FLE cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64FLessEqual {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64FLE, cc)
			return true
		}
		// match: (NE (CMPconst [0] (ANDconst [1] (FGreaterThan cc))) yes no)
		// result: (FGT cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64FGreaterThan {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64FGT, cc)
			return true
		}
		// match: (NE (CMPconst [0] (ANDconst [1] (FGreaterEqual cc))) yes no)
		// result: (FGE cc yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpPPC64ANDconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpPPC64FGreaterEqual {
				break
			}
			cc := v_0_0_0.Args[0]
			b.resetWithControl(BlockPPC64FGE, cc)
			return true
		}
		// match: (NE (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (NE (FlagLT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (NE (FlagGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (NE (InvertFlags cmp) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64NE, cmp)
			return true
		}
		// match: (NE (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (NE (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64NE, v0)
				return true
			}
			break
		}
		// match: (NE (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (NE (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64NE, v0)
				return true
			}
			break
		}
		// match: (NE (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (NE (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64XOR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64NE, v0)
				return true
			}
			break
		}
	}
	return false
}
```