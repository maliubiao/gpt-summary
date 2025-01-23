Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第8部分，共12部分，请归纳一下它的功能
```

### 源代码
```go
h: (SETNEstore [off] {sym} ptr (TESTLconst [c] x) mem)
	// cond: isUint32PowerOfTwo(int64(c))
	// result: (SETBstore [off] {sym} ptr (BTLconst [int8(log32(c))] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		x := v_1.Args[0]
		mem := v_2
		if !(isUint32PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQconst [c] x) mem)
	// cond: isUint64PowerOfTwo(int64(c))
	// result: (SETBstore [off] {sym} ptr (BTQconst [int8(log32(c))] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		x := v_1.Args[0]
		mem := v_2
		if !(isUint64PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQ (MOVQconst [c]) x) mem)
	// cond: isUint64PowerOfTwo(c)
	// result: (SETBstore [off] {sym} ptr (BTQconst [int8(log64(c))] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			x := v_1_1
			mem := v_2
			if !(isUint64PowerOfTwo(c)) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log64(c)))
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (CMPLconst [1] s:(ANDLconst [1] _)) mem)
	// result: (SETEQstore [off] {sym} ptr (CMPLconst [0] s) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64CMPLconst || auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		s := v_1.Args[0]
		if s.Op != OpAMD64ANDLconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		mem := v_2
		v.reset(OpAMD64SETEQstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (CMPQconst [1] s:(ANDQconst [1] _)) mem)
	// result: (SETEQstore [off] {sym} ptr (CMPQconst [0] s) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64CMPQconst || auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		s := v_1.Args[0]
		if s.Op != OpAMD64ANDQconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		mem := v_2
		v.reset(OpAMD64SETEQstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTQconst [63] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHLQconst || auxIntToInt8(z1.AuxInt) != 63 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHRQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTL z1:(SHLLconst [31] (SHRLconst [31] x)) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTLconst [31] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHLLconst || auxIntToInt8(z1.AuxInt) != 31 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHRLconst || auxIntToInt8(z1_0.AuxInt) != 31 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQ z1:(SHRQconst [63] (SHLQconst [63] x)) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTQconst [0] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHLQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTL z1:(SHRLconst [31] (SHLLconst [31] x)) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTLconst [0] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHLLconst || auxIntToInt8(z1_0.AuxInt) != 31 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQ z1:(SHRQconst [63] x) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTQconst [63] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
				continue
			}
			x := z1.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTL z1:(SHRLconst [31] x) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTLconst [31] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
				continue
			}
			x := z1.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETNEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETNEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETNEstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETNEstore [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SETNEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETNEstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETNEstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
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
		v.reset(OpAMD64SETNEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagEQ) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagEQ {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagLT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagLT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagGT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SHLL x (MOVQconst [c]))
	// result: (SHLLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SHLLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHLL x (MOVLconst [c]))
	// result: (SHLLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SHLLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHLL x (ADDQconst [c] y))
	// cond: c & 31 == 0
	// result: (SHLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLL x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 31 == 0
	// result: (SHLL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHLL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLL x (ANDQconst [c] y))
	// cond: c & 31 == 31
	// result: (SHLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLL x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 31 == 31
	// result: (SHLL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHLL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLL x (ADDLconst [c] y))
	// cond: c & 31 == 0
	// result: (SHLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLL x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 31 == 0
	// result: (SHLL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHLL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLL x (ANDLconst [c] y))
	// cond: c & 31 == 31
	// result: (SHLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLL x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 31 == 31
	// result: (SHLL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHLL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLL l:(MOVLload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SHLXLload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SHLXLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHLLconst [1] (SHRLconst [1] x))
	// result: (ANDLconst [-2] x)
	for {
		if auxIntToInt8(v.AuxInt) != 1 || v_0.Op != OpAMD64SHRLconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(-2)
		v.AddArg(x)
		return true
	}
	// match: (SHLLconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SHLLconst [d] (MOVLconst [c]))
	// result: (MOVLconst [c << uint64(d)])
	for {
		d := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SHLQ x (MOVQconst [c]))
	// result: (SHLQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SHLQ x (MOVLconst [c]))
	// result: (SHLQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SHLQ x (ADDQconst [c] y))
	// cond: c & 63 == 0
	// result: (SHLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLQ x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 63 == 0
	// result: (SHLQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLQ x (ANDQconst [c] y))
	// cond: c & 63 == 63
	// result: (SHLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLQ x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 63 == 63
	// result: (SHLQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLQ x (ADDLconst [c] y))
	// cond: c & 63 == 0
	// result: (SHLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLQ x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 63 == 0
	// result: (SHLQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLQ x (ANDLconst [c] y))
	// cond: c & 63 == 63
	// result: (SHLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLQ x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 63 == 63
	// result: (SHLQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLQ l:(MOVQload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SHLXQload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SHLXQload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHLQconst [1] (SHRQconst [1] x))
	// result: (ANDQconst [-2] x)
	for {
		if auxIntToInt8(v.AuxInt) != 1 || v_0.Op != OpAMD64SHRQconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDQconst)
		v.AuxInt = int32ToAuxInt(-2)
		v.AddArg(x)
		return true
	}
	// match: (SHLQconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SHLQconst [d] (MOVQconst [c]))
	// result: (MOVQconst [c << uint64(d)])
	for {
		d := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(c << uint64(d))
		return true
	}
	// match: (SHLQconst [d] (MOVLconst [c]))
	// result: (MOVQconst [int64(c) << uint64(d)])
	for {
		d := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(c) << uint64(d))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLXLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SHLXLload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SHLLconst [int8(c&31)] (MOVLload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHLLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLXQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SHLXQload [off] {sym} ptr (MOVQconst [c]) mem)
	// result: (SHLQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	// match: (SHLXQload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SHLQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SHRB x (MOVQconst [c]))
	// cond: c&31 < 8
	// result: (SHRBconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&31 < 8) {
			break
		}
		v.reset(OpAMD64SHRBconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRB x (MOVLconst [c]))
	// cond: c&31 < 8
	// result: (SHRBconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 < 8) {
			break
		}
		v.reset(OpAMD64SHRBconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRB _ (MOVQconst [c]))
	// cond: c&31 >= 8
	// result: (MOVLconst [0])
	for {
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&31 >= 8) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SHRB _ (MOVLconst [c]))
	// cond: c&31 >= 8
	// result: (MOVLconst [0])
	for {
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 >= 8) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRBconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SHRL x (MOVQconst [c]))
	// result: (SHRLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SHRLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRL x (MOVLconst [c]))
	// result: (SHRLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SHRLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRL x (ADDQconst [c] y))
	// cond: c & 31 == 0
	// result: (SHRL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHRL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRL x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 31 == 0
	// result: (SHRL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHRL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRL x (ANDQconst [c] y))
	// cond: c & 31 == 31
	// result: (SHRL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHRL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRL x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 31 == 31
	// result: (SHRL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHRL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRL x (ADDLconst [c] y))
	// cond: c & 31 == 0
	// result: (SHRL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHRL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRL x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 31 == 0
	// result: (SHRL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHRL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRL x (ANDLconst [c] y))
	// cond: c & 31 == 31
	// result: (SHRL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHRL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRL x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 31 == 31
	// result: (SHRL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHRL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRL l:(MOVLload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SHRXLload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SHRXLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRLconst [1] (SHLLconst [1] x))
	// result: (ANDLconst [0x7fffffff] x)
	for {
		if auxIntToInt8(v.AuxInt) != 1 || v_0.Op != OpAMD64SHLLconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(0x7fffffff)
		v.AddArg(x)
		return true
	}
	// match: (SHRLconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SHRQ x (MOVQconst [c]))
	// result: (SHRQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SHRQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SHRQ x (MOVLconst [c]))
	// result: (SHRQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SHRQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SHRQ x (ADDQconst [c] y))
	// cond: c & 63 == 0
	// result: (SHRQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRQ x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 63 == 0
	// result: (SHRQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRQ x (ANDQconst [c] y))
	// cond: c & 63 == 63
	// result: (SHRQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRQ x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 63 == 63
	// result: (SHRQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRQ x (ADDLconst [c] y))
	// cond: c & 63 == 0
	// result: (SHRQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRQ x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 63 == 0
	// result: (SHRQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRQ x (ANDLconst [c] y))
	// cond: c & 63 == 63
	// result: (SHRQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRQ x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 63 == 63
	// result: (SHRQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRQ l:(MOVQload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SHRXQload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SHRXQload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRQconst [1] (SHLQconst [1] x))
	// result: (BTRQconst [63] x)
	for {
		if auxIntToInt8(v.AuxInt) != 1 || v_0.Op != OpAMD64SHLQconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64BTRQconst)
		v.AuxInt = int8ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	// match: (SHRQconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SHRW x (MOVQconst [c]))
	// cond: c&31 < 16
	// result: (SHRWconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&31 < 16) {
			break
		}
		v.reset(OpAMD64SHRWconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRW x (MOVLconst [c]))
	// cond: c&31 < 16
	// result: (SHRWconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 < 16) {
			break
		}
		v.reset(OpAMD64SHRWconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRW _ (MOVQconst [c]))
	// cond: c&31 >= 16
	// result: (MOVLconst [0])
	for {
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&31 >= 16) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SHRW _ (MOVLconst [c]))
	// cond: c&31 >= 16
	// result: (MOVLconst [0])
	for {
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 >= 16) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRWconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRXLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SHRXLload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SHRLconst [int8(c&31)] (MOVLload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHRLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRXQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SHRXQload [off] {sym} ptr (MOVQconst [c]) mem)
	// result: (SHRQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHRQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	// match: (SHRXQload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SHRQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHRQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBL x (MOVLconst [c]))
	// result: (SUBLconst x [c])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SUBLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUBL (MOVLconst [c]) x)
	// result: (NEGL (SUBLconst <v.Type> x [c]))
	for {
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpAMD64NEGL)
		v0 := b.NewValue0(v.Pos, OpAMD64SUBLconst, v.Type)
		v0.AuxInt = int32ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBL x x)
	// result: (MOVLconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SUBL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBLload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SUBLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBLconst [c] x)
	// cond: c==0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SUBLconst [c] x)
	// result: (ADDLconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		v.reset(OpAMD64ADDLconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
}
func rewriteValueAMD64_OpAMD64SUBLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBLload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBLload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBLload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBLload x [off] {sym} ptr (MOVSSstore [off] {sym} ptr y _))
	// result: (SUBL x (MOVLf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSSstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64SUBL)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLf2i, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBLmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBLmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SUBLmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
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
		v.reset(OpAMD64SUBLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBQ x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (SUBQconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpAMD64SUBQconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (SUBQ (MOVQconst [c]) x)
	// cond: is32Bit(c)
	// result: (NEGQ (SUBQconst <v.Type> x [int32(c)]))
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64SUBQconst, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBQ x x)
	// result: (MOVQconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUBQ x l:(MOVQload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBQload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SUBQload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQborrow(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBQborrow x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (SUBQconstborrow x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpAMD64SUBQconstborrow)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBQconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBQconst [c] x)
	// cond: c != -(1<<31)
	// result: (ADDQconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c != -(1 << 31)) {
			break
		}
		v.reset(OpAMD64ADDQconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (SUBQconst (MOVQconst [d]) [c])
	// result: (MOVQconst [d-int64(c)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(d - int64(c))
		return true
	}
	// match: (SUBQconst (SUBQconst x [d]) [c])
	// cond: is32Bit(int64(-c)-int64(d))
	// result: (ADDQconst [-c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64SUBQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(int64(-c) - int64(d))) {
			break
		}
		v.reset(OpAMD64ADDQconst)
		v.AuxInt = int32ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBQload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBQload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBQload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBQload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBQload x [off] {sym} ptr (MOVSDstore [off] {sym} ptr y _))
	// result: (SUBQ x (MOVQf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64SUBQ)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQf2i, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBQmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBQmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SUBQmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBQmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
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
		v.reset(OpAMD64SUBQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBSD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBSD x l:(MOVSDload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBSDload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVSDload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SUBSDload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBSDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBSDload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBSDload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSDload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBSDload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSDload x [off] {sym} ptr (MOVQstore [off] {sym} ptr y _))
	// result: (SUBSD x (MOVQi2f y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVQstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64SUBSD)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQi2f, typ.Float64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBSS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBSS x l:(MOVSSload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBSSload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVSSload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SUBSSload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBSSload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBSSload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBSSload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSSload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBSSload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSSload x [off] {sym} ptr (MOVLstore [off] {sym} ptr y _))
	// result: (SUBSS x (MOVLi2f y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVLstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64SUBSS)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLi2f, typ.Float32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TESTB (MOVLconst [c]) x)
	// result: (TESTBconst [int8(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_1
			v.reset(OpAMD64TESTBconst)
			v.AuxInt = int8ToAuxInt(int8(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TESTB l:(MOVBload {sym} [off] ptr mem) l2)
	// cond: l == l2 && l.Uses == 2 && clobber(l)
	// result: @l.Block (CMPBconstload {sym} [makeValAndOff(0, off)] ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			l := v_0
			if l.Op != OpAMD64MOVBload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			l2 := v_1
			if !(l == l2 && l.Uses == 2 && clobber(l)) {
				continue
			}
			b = l.Block
			v0 := b.NewValue0(l.Pos, OpAMD64CMPBconstload, types.TypeFlags)
			v.copyOf(v0)
			v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, off))
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TESTBconst [-1] x)
	// cond: x.Op != OpAMD64MOVLconst
	// result: (TESTB x x)
	for {
		if auxIntToInt8(v.AuxInt) != -1 {
			break
		}
		x := v_0
		if !(x.Op != OpAMD64MOVLconst) {
			break
		}
		v.reset(OpAMD64TESTB)
		v.AddArg2(x, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TESTL (MOVLconst [c]) x)
	// result: (TESTLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_1
			v.reset(OpAMD64TESTLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TESTL l:(MOVLload {sym} [off] ptr mem) l2)
	// cond: l == l2 && l.Uses == 2 && clobber(l)
	// result: @l.Block (CMPLconstload {sym} [makeValAndOff(0, off)] ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			l := v_0
			if l.Op != OpAMD64MOVLload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			l2 := v_1
			if !(l == l2 && l.Uses == 2 && clobber(l)) {
				continue
			}
			b = l.Block
			v0 := b.NewValue0(l.Pos, OpAMD64CMPLconstload, types.TypeFlags)
			v.copyOf(v0)
			v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, off))
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			return true
		}
		break
	}
	// match: (TESTL a:(ANDLload [off] {sym} x ptr mem) a)
	// cond: a.Uses == 2 && a.Block == v.Block && clobber(a)
	// result: (TESTL (MOVLload <a.Type> [off] {sym} ptr mem) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if a.Op != OpAMD64ANDLload {
				continue
			}
			off := auxIntToInt32(a.AuxInt)
			sym := auxToSym(a.Aux)
			mem := a.Args[2]
			x := a.Args[0]
			ptr := a.Args[1]
			if a != v_1 || !(a.Uses == 2 && a.Block == v.Block && clobber(a)) {
				continue
			}
			v.reset(OpAMD64TESTL)
			v0 := b.NewValue0(a.Pos, OpAMD64MOVLload, a.Type)
			v0.AuxInt = int32ToAuxInt(off)
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TESTLconst [c] (MOVLconst [c]))
	// cond: c == 0
	// result: (FlagEQ)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0.AuxInt) != c || !(c == 0) {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (TESTLconst [c] (MOVLconst [c]))
	// cond: c < 0
	// result: (FlagLT_UGT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0.AuxInt) != c || !(c < 0) {
			break
		}
		v.reset(OpAMD64FlagLT_UGT)
		return true
	}
	// match: (TESTLconst [c] (MOVLconst [c]))
	// cond: c > 0
	// result: (FlagGT_UGT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0.AuxInt) != c || !(c > 0) {
			break
		}
		v.reset(OpAMD64FlagGT_UGT)
		return true
	}
	// match: (TESTLconst [-1] x)
	// cond: x.Op != OpAMD64MOVLconst
	// result: (TESTL x x)
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		x := v_0
		if !(x.Op != OpAMD64MOVLconst) {
			break
		}
		v.reset(OpAMD64TESTL)
		v.AddArg2(x, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TESTQ (MOVQconst [c]) x)
	// cond: is32Bit(c)
	// result: (TESTQconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			x := v_1
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpAMD64TESTQconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TESTQ l:(MOVQload {sym} [off] ptr mem) l2)
	// cond: l == l2 && l.Uses == 2 && clobber(l)
	// result: @l.Block (CMPQconstload {sym} [makeValAndOff(0, off)] ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			l := v_0
			if l.Op != OpAMD64MOVQload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			l2 := v_1
			if !(l == l2 && l.Uses == 2 && clobber(l)) {
				continue
			}
			b = l.Block
			v0 := b.NewValue0(l.Pos, OpAMD64CMPQconstload, types.TypeFlags)
			v.copyOf(v0)
			v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, off))
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			return true
		}
		break
	}
	// match: (TESTQ a:(ANDQload [off] {sym} x ptr mem) a)
	// cond: a.Uses == 2 && a.Block == v.Block && clobber(a)
	// result: (TESTQ (MOVQload <a.Type> [off] {sym} ptr mem) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if a.Op != OpAMD64ANDQload {
				continue
			}
			off := auxIntToInt32(a.AuxInt)
			sym := auxToSym(a.Aux)
			mem := a.Args[2]
			x := a.Args[0]
			ptr := a.Args[1]
			if a != v_1 || !(a.Uses == 2 && a.Block == v.Block && clobber(a)) {
				continue
			}
			v.reset(OpAMD64TESTQ)
			v0 := b.NewValue0(a.Pos, OpAMD64MOVQload, a.Type)
			v0.AuxInt = int32ToAuxInt(off)
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TESTQconst [c] (MOVQconst [d]))
	// cond: int64(c) == d && c == 0
	// result: (FlagEQ)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(int64(c) == d && c == 0) {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (TESTQconst [c] (MOVQconst [d]))
	// cond: int64(c) == d && c < 0
	// result: (FlagLT_UGT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(int64(c) == d && c < 0) {
			break
		}
		v.reset(OpAMD64FlagLT_UGT)
		return true
	}
	// match: (TESTQconst [c] (MOVQconst [d]))
	// cond: int64(c) == d && c > 0
	// result: (FlagGT_UGT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(int64(c) == d && c > 0) {
			break
		}
		v.reset(OpAMD64FlagGT_UGT)
		return true
	}
	// match: (TESTQconst [-1] x)
	// cond: x.Op != OpAMD64MOVQconst
	// result: (TESTQ x x)
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		x := v_0
		if !(x.Op != OpAMD64MOVQconst) {
			break
		}
		v.reset(OpAMD64TESTQ)
		v.AddArg2(x, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TESTW (MOVLconst [c]) x)
	// result: (TESTWconst [int16(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_1
			v.reset(OpAMD64TESTWconst)
			v.AuxInt = int16ToAuxInt(int16(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TESTW l:(MOVWload {sym} [off] ptr mem) l2)
	// cond: l == l2 && l.Uses == 2 && clobber(l)
	// result: @l.Block (CMPWconstload {sym} [makeValAndOff(0, off)] ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			l := v_0
			if l.Op != OpAMD64MOVWload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			l2 := v_1
			if !(l == l2 && l.Uses == 2 && clobber(l)) {
				continue
			}
			b = l.Block
			v0 := b.NewValue0(l.Pos, OpAMD64CMPWconstload, types.TypeFlags)
			v.copyOf(v0)
			v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, off))
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			return true
		}
		break
```