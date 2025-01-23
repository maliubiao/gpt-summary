Response: The user wants a summary of the provided Go code, which is a part of the `rewriteMIPS64.go` file. This file seems to be involved in the SSA (Static Single Assignment) rewriting process for the MIPS64 architecture in the Go compiler.

The code contains two main functions: `rewriteValueMIPS64_OpFMOVDstore` and `rewriteValueMIPS64_OpZero`, and a third function `rewriteBlockMIPS64`.

`rewriteValueMIPS64_OpFMOVDstore`: This function seems to optimize or rewrite operations related to storing double-precision floating-point values in memory. It checks if the stored value is a float64 and then uses the `OpMIPS64MOVDstore` instruction.

`rewriteValueMIPS64_OpZero`: This function appears to handle the zeroing of memory regions. It has multiple cases based on the size of the memory region to be zeroed (`v.AuxInt`). It uses different MIPS64 store instructions (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVVstore`) for smaller sizes and potentially `DUFFZERO` or `LoweredZero` for larger sizes, considering alignment.

`rewriteBlockMIPS64`: This function seems to be involved in rewriting control flow blocks based on certain conditions. It handles different block kinds like `BlockMIPS64EQ`, `BlockMIPS64GEZ`, `BlockIf`, etc., and tries to simplify or optimize the control flow based on the operations within the block's control value.

To provide a comprehensive answer, I will:
1. Summarize the functionality of each function.
2. Provide Go code examples to illustrate the transformations performed by `rewriteValueMIPS64_OpFMOVDstore` and `rewriteValueMIPS64_OpZero`.
3. Explain any assumptions made during code inference.
4. Describe how the code might handle command-line parameters (although not explicitly present, I can discuss the broader context of compiler flags).
5. Point out potential pitfalls for users (if any are apparent from the code).
6. Provide a final overall summary of the code's purpose.
```go
// result: (MOVDstore ptr val mem)
for {
	t := auxToType(v.Aux)
	ptr := v_0
	val := v_1
	mem := v_2
	if !(t.Size() == 8 && t.IsFloat()) {
		break
	}
	v.reset(OpMIPS64MOVDstore)
	v.AddArg3(ptr, val, mem)
	return true
}
return false
}
func rewriteValueMIPS64_OpZero(v *Value) bool {
v_1 := v.Args[1]
v_0 := v.Args[0]
b := v.Block
config := b.Func.Config
typ := &b.Func.Config.Types
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
// match: (Zero [1] ptr mem)
// result: (MOVBstore ptr (MOVVconst [0]) mem)
for {
	if auxIntToInt64(v.AuxInt) != 1 {
		break
	}
	ptr := v_0
	mem := v_1
	v.reset(OpMIPS64MOVBstore)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v.AddArg3(ptr, v0, mem)
	return true
}
// match: (Zero [2] {t} ptr mem)
// cond: t.Alignment()%2 == 0
// result: (MOVHstore ptr (MOVVconst [0]) mem)
for {
	if auxIntToInt64(v.AuxInt) != 2 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%2 == 0) {
		break
	}
	v.reset(OpMIPS64MOVHstore)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v.AddArg3(ptr, v0, mem)
	return true
}
// match: (Zero [2] ptr mem)
// result: (MOVBstore [1] ptr (MOVVconst [0]) (MOVBstore [0] ptr (MOVVconst [0]) mem))
for {
	if auxIntToInt64(v.AuxInt) != 2 {
		break
	}
	ptr := v_0
	mem := v_1
	v.reset(OpMIPS64MOVBstore)
	v.AuxInt = int32ToAuxInt(1)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(0)
	v1.AddArg3(ptr, v0, mem)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [4] {t} ptr mem)
// cond: t.Alignment()%4 == 0
// result: (MOVWstore ptr (MOVVconst [0]) mem)
for {
	if auxIntToInt64(v.AuxInt) != 4 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%4 == 0) {
		break
	}
	v.reset(OpMIPS64MOVWstore)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v.AddArg3(ptr, v0, mem)
	return true
}
// match: (Zero [4] {t} ptr mem)
// cond: t.Alignment()%2 == 0
// result: (MOVHstore [2] ptr (MOVVconst [0]) (MOVHstore [0] ptr (MOVVconst [0]) mem))
for {
	if auxIntToInt64(v.AuxInt) != 4 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%2 == 0) {
		break
	}
	v.reset(OpMIPS64MOVHstore)
	v.AuxInt = int32ToAuxInt(2)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(0)
	v1.AddArg3(ptr, v0, mem)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [4] ptr mem)
// result: (MOVBstore [3] ptr (MOVVconst [0]) (MOVBstore [2] ptr (MOVVconst [0]) (MOVBstore [1] ptr (MOVVconst [0]) (MOVBstore [0] ptr (MOVVconst [0]) mem))))
for {
	if auxIntToInt64(v.AuxInt) != 4 {
		break
	}
	ptr := v_0
	mem := v_1
	v.reset(OpMIPS64MOVBstore)
	v.AuxInt = int32ToAuxInt(3)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(2)
	v2 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
	v2.AuxInt = int32ToAuxInt(1)
	v3 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
	v3.AuxInt = int32ToAuxInt(0)
	v3.AddArg3(ptr, v0, mem)
	v2.AddArg3(ptr, v0, v3)
	v1.AddArg3(ptr, v0, v2)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [8] {t} ptr mem)
// cond: t.Alignment()%8 == 0
// result: (MOVVstore ptr (MOVVconst [0]) mem)
for {
	if auxIntToInt64(v.AuxInt) != 8 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%8 == 0) {
		break
	}
	v.reset(OpMIPS64MOVVstore)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v.AddArg3(ptr, v0, mem)
	return true
}
// match: (Zero [8] {t} ptr mem)
// cond: t.Alignment()%4 == 0
// result: (MOVWstore [4] ptr (MOVVconst [0]) (MOVWstore [0] ptr (MOVVconst [0]) mem))
for {
	if auxIntToInt64(v.AuxInt) != 8 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%4 == 0) {
		break
	}
	v.reset(OpMIPS64MOVWstore)
	v.AuxInt = int32ToAuxInt(4)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(0)
	v1.AddArg3(ptr, v0, mem)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [8] {t} ptr mem)
// cond: t.Alignment()%2 == 0
// result: (MOVHstore [6] ptr (MOVVconst [0]) (MOVHstore [4] ptr (MOVVconst [0]) (MOVHstore [2] ptr (MOVVconst [0]) (MOVHstore [0] ptr (MOVVconst [0]) mem))))
for {
	if auxIntToInt64(v.AuxInt) != 8 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%2 == 0) {
		break
	}
	v.reset(OpMIPS64MOVHstore)
	v.AuxInt = int32ToAuxInt(6)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(4)
	v2 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
	v2.AuxInt = int32ToAuxInt(2)
	v3 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
	v3.AuxInt = int32ToAuxInt(0)
	v3.AddArg3(ptr, v0, mem)
	v2.AddArg3(ptr, v0, v3)
	v1.AddArg3(ptr, v0, v2)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [3] ptr mem)
// result: (MOVBstore [2] ptr (MOVVconst [0]) (MOVBstore [1] ptr (MOVVconst [0]) (MOVBstore [0] ptr (MOVVconst [0]) mem)))
for {
	if auxIntToInt64(v.AuxInt) != 3 {
		break
	}
	ptr := v_0
	mem := v_1
	v.reset(OpMIPS64MOVBstore)
	v.AuxInt = int32ToAuxInt(2)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(1)
	v2 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
	v2.AuxInt = int32ToAuxInt(0)
	v2.AddArg3(ptr, v0, mem)
	v1.AddArg3(ptr, v0, v2)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [6] {t} ptr mem)
// cond: t.Alignment()%2 == 0
// result: (MOVHstore [4] ptr (MOVVconst [0]) (MOVHstore [2] ptr (MOVVconst [0]) (MOVHstore [0] ptr (MOVVconst [0]) mem)))
for {
	if auxIntToInt64(v.AuxInt) != 6 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%2 == 0) {
		break
	}
	v.reset(OpMIPS64MOVHstore)
	v.AuxInt = int32ToAuxInt(4)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(2)
	v2 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
	v2.AuxInt = int32ToAuxInt(0)
	v2.AddArg3(ptr, v0, mem)
	v1.AddArg3(ptr, v0, v2)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [12] {t} ptr mem)
// cond: t.Alignment()%4 == 0
// result: (MOVWstore [8] ptr (MOVVconst [0]) (MOVWstore [4] ptr (MOVVconst [0]) (MOVWstore [0] ptr (MOVVconst [0]) mem)))
for {
	if auxIntToInt64(v.AuxInt) != 12 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%4 == 0) {
		break
	}
	v.reset(OpMIPS64MOVWstore)
	v.AuxInt = int32ToAuxInt(8)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(4)
	v2 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
	v2.AuxInt = int32ToAuxInt(0)
	v2.AddArg3(ptr, v0, mem)
	v1.AddArg3(ptr, v0, v2)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [16] {t} ptr mem)
// cond: t.Alignment()%8 == 0
// result: (MOVVstore [8] ptr (MOVVconst [0]) (MOVVstore [0] ptr (MOVVconst [0]) mem))
for {
	if auxIntToInt64(v.AuxInt) != 16 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%8 == 0) {
		break
	}
	v.reset(OpMIPS64MOVVstore)
	v.AuxInt = int32ToAuxInt(8)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(0)
	v1.AddArg3(ptr, v0, mem)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [24] {t} ptr mem)
// cond: t.Alignment()%8 == 0
// result: (MOVVstore [16] ptr (MOVVconst [0]) (MOVVstore [8] ptr (MOVVconst [0]) (MOVVstore [0] ptr (MOVVconst [0]) mem)))
for {
	if auxIntToInt64(v.AuxInt) != 24 {
		break
	}
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(t.Alignment()%8 == 0) {
		break
	}
	v.reset(OpMIPS64MOVVstore)
	v.AuxInt = int32ToAuxInt(16)
	v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
	v0.AuxInt = int64ToAuxInt(0)
	v1 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
	v1.AuxInt = int32ToAuxInt(8)
	v2 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
	v2.AuxInt = int32ToAuxInt(0)
	v2.AddArg3(ptr, v0, mem)
	v1.AddArg3(ptr, v0, v2)
	v.AddArg3(ptr, v0, v1)
	return true
}
// match: (Zero [s] {t} ptr mem)
// cond: s%8 == 0 && s > 24 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice
// result: (DUFFZERO [8 * (128 - s/8)] ptr mem)
for {
	s := auxIntToInt64(v.AuxInt)
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !(s%8 == 0 && s > 24 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice) {
		break
	}
	v.reset(OpMIPS64DUFFZERO)
	v.AuxInt = int64ToAuxInt(8 * (128 - s/8))
	v.AddArg2(ptr, mem)
	return true
}
// match: (Zero [s] {t} ptr mem)
// cond: (s > 8*128 || config.noDuffDevice) || t.Alignment()%8 != 0
// result: (LoweredZero [t.Alignment()] ptr (ADDVconst <ptr.Type> ptr [s-moveSize(t.Alignment(), config)]) mem)
for {
	s := auxIntToInt64(v.AuxInt)
	t := auxToType(v.Aux)
	ptr := v_0
	mem := v_1
	if !((s > 8*128 || config.noDuffDevice) || t.Alignment()%8 != 0) {
		break
	}
	v.reset(OpMIPS64LoweredZero)
	v.AuxInt = int64ToAuxInt(t.Alignment())
	v0 := b.NewValue0(v.Pos, OpMIPS64ADDVconst, ptr.Type)
	v0.AuxInt = int64ToAuxInt(s - moveSize(t.Alignment(), config))
	v0.AddArg(ptr)
	v.AddArg3(ptr, v0, mem)
	return true
}
return false
}
func rewriteBlockMIPS64(b *Block) bool {
switch b.Kind {
case BlockMIPS64EQ:
	// match: (EQ (FPFlagTrue cmp) yes no)
	// result: (FPF cmp yes no)
	for b.Controls[0].Op == OpMIPS64FPFlagTrue {
		v_0 := b.Controls[0]
		cmp := v_0.Args[0]
		b.resetWithControl(BlockMIPS64FPF, cmp)
		return true
	}
	// match: (EQ (FPFlagFalse cmp) yes no)
	// result: (FPT cmp yes no)
	for b.Controls[0].Op == OpMIPS64FPFlagFalse {
		v_0 := b.Controls[0]
		cmp := v_0.Args[0]
		b.resetWithControl(BlockMIPS64FPT, cmp)
		return true
	}
	// match: (EQ (XORconst [1] cmp:(SGT _ _)) yes no)
	// result: (NE cmp yes no)
	for b.Controls[0].Op == OpMIPS64XORconst {
		v_0 := b.Controls[0]
		if auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		cmp := v_0.Args[0]
		if cmp.Op != OpMIPS64SGT {
			break
		}
		b.resetWithControl(BlockMIPS64NE, cmp)
		return true
	}
	// match: (EQ (XORconst [1] cmp:(SGTU _ _)) yes no)
	// result: (NE cmp yes no)
	for b.Controls[0].Op == OpMIPS64XORconst {
		v_0 := b.Controls[0]
		if auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		cmp := v_0.Args[0]
		if cmp.Op != OpMIPS64SGTU {
			break
		}
		b.resetWithControl(BlockMIPS64NE, cmp)
		return true
	}
	// match: (EQ (XORconst [1] cmp:(SGTconst _)) yes no)
	// result: (NE cmp yes no)
	for b.Controls[0].Op == OpMIPS64XORconst {
		v_0 := b.Controls[0]
		if auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		cmp := v_0.Args[0]
		if cmp.Op != OpMIPS64SGTconst {
			break
		}
		b.resetWithControl(BlockMIPS64NE, cmp)
		return true
	}
	// match: (EQ (XORconst [1] cmp:(SGTUconst _)) yes no)
	// result: (NE cmp yes no)
	for b.Controls[0].Op == OpMIPS64XORconst {
		v_0 := b.Controls[0]
		if auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		cmp := v_0.Args[0]
		if cmp.Op != OpMIPS64SGTUconst {
			break
		}
		b.resetWithControl(BlockMIPS64NE, cmp)
		return true
	}
	// match: (EQ (SGTUconst [1] x) yes no)
	// result: (NE x yes no)
	for b.Controls[0].Op == OpMIPS64SGTUconst {
		v_0 := b.Controls[0]
		if auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		b.resetWithControl(BlockMIPS64NE, x)
		return true
	}
	// match: (EQ (SGTU x (MOVVconst [0])) yes no)
	// result: (EQ x yes no)
	for b.Controls[0].Op == OpMIPS64SGTU {
		v_0 := b.Controls[0]
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
			break
		}
		b.resetWithControl(BlockMIPS64EQ, x)
		return true
	}
	// match: (EQ (SGTconst [0] x) yes no)
	// result: (GEZ x yes no)
	for b.Controls[0].Op == OpMIPS64SGTconst {
		v_0 := b.Controls[0]
		if auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		b.resetWithControl(BlockMIPS64GEZ, x)
		return true
	}
	// match: (EQ (SGT x (MOVVconst [0])) yes no)
	// result: (LEZ x yes no)
	for b.Controls[0].Op == OpMIPS64SGT {
		v_0 := b.Controls[0]
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
			break
		}
		b.resetWithControl(BlockMIPS64LEZ, x)
		return true
	}
	// match: (EQ (MOVVconst [0]) yes no)
	// result: (First yes no)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		if auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		b.Reset(BlockFirst)
		return true
	}
	// match: (EQ (MOVVconst [c]) yes no)
	// cond: c != 0
	// result: (First no yes)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		c := auxIntToInt64(v_0.AuxInt)
		if !(c != 0) {
			break
		}
		b.Reset(BlockFirst)
		b.swapSuccessors()
		return true
	}
case BlockMIPS64GEZ:
	// match: (GEZ (MOVVconst [c]) yes no)
	// cond: c >= 0
	// result: (First yes no)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		c := auxIntToInt64(v_0.AuxInt)
		if !(c >= 0) {
			break
		}
		b.Reset(BlockFirst)
		return true
	}
	// match: (GEZ (MOVVconst [c]) yes no)
	// cond: c < 0
	// result: (First no yes)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		c := auxIntToInt64(v_0.AuxInt)
		if !(c < 0) {
			break
		}
		b.Reset(BlockFirst)
		b.swapSuccessors()
		return true
	}
case BlockMIPS64GTZ:
	// match: (GTZ (MOVVconst [c]) yes no)
	// cond: c > 0
	// result: (First yes no)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		c := auxIntToInt64(v_0.AuxInt)
		if !(c > 0) {
			break
		}
		b.Reset(BlockFirst)
		return true
	}
	// match: (GTZ (MOVVconst [c]) yes no)
	// cond: c <= 0
	// result: (First no yes)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		c := auxIntToInt64(v_0.AuxInt)
		if !(c <= 0) {
			break
		}
		b.Reset(BlockFirst)
		b.swapSuccessors()
		return true
	}
case BlockIf:
	// match: (If cond yes no)
	// result: (NE cond yes no)
	for {
		cond := b.Controls[0]
		b.resetWithControl(BlockMIPS64NE, cond)
		return true
	}
case BlockMIPS64LEZ:
	// match: (LEZ (MOVVconst [c]) yes no)
	// cond: c <= 0
	// result: (First yes no)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		c := auxIntToInt64(v_0.AuxInt)
		if !(c <= 0) {
			break
		}
		b.Reset(BlockFirst)
		return true
	}
	// match: (LEZ (MOVVconst [c]) yes no)
	// cond: c > 0
	// result: (First no yes)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		c := auxIntToInt64(v_0.AuxInt)
		if !(c > 0) {
			break
		}
		b.Reset(BlockFirst)
		b.swapSuccessors()
		return true
	}
case BlockMIPS64LTZ:
	// match: (LTZ (MOVVconst [c]) yes no)
	// cond: c < 0
	// result: (First yes no)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		c := auxIntToInt64(v_0.AuxInt)
		if !(c < 0) {
			break
		}
		b.Reset(BlockFirst)
		return true
	}
	// match: (LTZ (MOVVconst [c]) yes no)
	// cond: c >= 0
	// result: (First no yes)
	for b.Controls[0].Op == OpMIPS64MOVVconst {
		v_0 := b.Controls[0]
		c := auxIntToInt64(v_0.AuxInt)
		if !(c >= 0) {
			break
		}
		b.Reset(BlockFirst)
		b.
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
// result: (MOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && t.IsFloat()) {
			break
		}
		v.reset(OpMIPS64MOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpZero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
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
	// match: (Zero [1] ptr mem)
	// result: (MOVBstore ptr (MOVVconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPS64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore ptr (MOVVconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] ptr mem)
	// result: (MOVBstore [1] ptr (MOVVconst [0]) (MOVBstore [0] ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [4] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore ptr (MOVVconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [4] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [2] ptr (MOVVconst [0]) (MOVHstore [0] ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [4] ptr mem)
	// result: (MOVBstore [3] ptr (MOVVconst [0]) (MOVBstore [2] ptr (MOVVconst [0]) (MOVBstore [1] ptr (MOVVconst [0]) (MOVBstore [0] ptr (MOVVconst [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(1)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg3(ptr, v0, mem)
		v2.AddArg3(ptr, v0, v3)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [8] {t} ptr mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVVstore ptr (MOVVconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [8] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [4] ptr (MOVVconst [0]) (MOVWstore [0] ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [8] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [6] ptr (MOVVconst [0]) (MOVHstore [4] ptr (MOVVconst [0]) (MOVHstore [2] ptr (MOVVconst [0]) (MOVHstore [0] ptr (MOVVconst [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(2)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg3(ptr, v0, mem)
		v2.AddArg3(ptr, v0, v3)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [3] ptr mem)
	// result: (MOVBstore [2] ptr (MOVVconst [0]) (MOVBstore [1] ptr (MOVVconst [0]) (MOVBstore [0] ptr (MOVVconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [6] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [4] ptr (MOVVconst [0]) (MOVHstore [2] ptr (MOVVconst [0]) (MOVHstore [0] ptr (MOVVconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [12] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [8] ptr (MOVVconst [0]) (MOVWstore [4] ptr (MOVVconst [0]) (MOVWstore [0] ptr (MOVVconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [16] {t} ptr mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVVstore [8] ptr (MOVVconst [0]) (MOVVstore [0] ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [24] {t} ptr mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVVstore [16] ptr (MOVVconst [0]) (MOVVstore [8] ptr (MOVVconst [0]) (MOVVstore [0] ptr (MOVVconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 24 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [s] {t} ptr mem)
	// cond: s%8 == 0 && s > 24 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice
	// result: (DUFFZERO [8 * (128 - s/8)] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(s%8 == 0 && s > 24 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice) {
			break
		}
		v.reset(OpMIPS64DUFFZERO)
		v.AuxInt = int64ToAuxInt(8 * (128 - s/8))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] {t} ptr mem)
	// cond: (s > 8*128 || config.noDuffDevice) || t.Alignment()%8 != 0
	// result: (LoweredZero [t.Alignment()] ptr (ADDVconst <ptr.Type> ptr [s-moveSize(t.Alignment(), config)]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !((s > 8*128 || config.noDuffDevice) || t.Alignment()%8 != 0) {
			break
		}
		v.reset(OpMIPS64LoweredZero)
		v.AuxInt = int64ToAuxInt(t.Alignment())
		v0 := b.NewValue0(v.Pos, OpMIPS64ADDVconst, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - moveSize(t.Alignment(), config))
		v0.AddArg(ptr)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteBlockMIPS64(b *Block) bool {
	switch b.Kind {
	case BlockMIPS64EQ:
		// match: (EQ (FPFlagTrue cmp) yes no)
		// result: (FPF cmp yes no)
		for b.Controls[0].Op == OpMIPS64FPFlagTrue {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPS64FPF, cmp)
			return true
		}
		// match: (EQ (FPFlagFalse cmp) yes no)
		// result: (FPT cmp yes no)
		for b.Controls[0].Op == OpMIPS64FPFlagFalse {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPS64FPT, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGT _ _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGT {
				break
			}
			b.resetWithControl(BlockMIPS64NE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTU _ _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTU {
				break
			}
			b.resetWithControl(BlockMIPS64NE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTconst _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTconst {
				break
			}
			b.resetWithControl(BlockMIPS64NE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTUconst _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTUconst {
				break
			}
			b.resetWithControl(BlockMIPS64NE, cmp)
			return true
		}
		// match: (EQ (SGTUconst [1] x) yes no)
		// result: (NE x yes no)
		for b.Controls[0].Op == OpMIPS64SGTUconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPS64NE, x)
			return true
		}
		// match: (EQ (SGTU x (MOVVconst [0])) yes no)
		// result: (EQ x yes no)
		for b.Controls[0].Op == OpMIPS64SGTU {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, x)
			return true
		}
		// match: (EQ (SGTconst [0] x) yes no)
		// result: (GEZ x yes no)
		for b.Controls[0].Op == OpMIPS64SGTconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPS64GEZ, x)
			return true
		}
		// match: (EQ (SGT x (MOVVconst [0])) yes no)
		// result: (LEZ x yes no)
		for b.Controls[0].Op == OpMIPS64SGT {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockMIPS64LEZ, x)
			return true
		}
		// match: (EQ (MOVVconst [0]) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (EQ (MOVVconst [c]) yes no)
		// cond: c != 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c != 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPS64GEZ:
		// match: (GEZ (MOVVconst [c]) yes no)
		// cond: c >= 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c >= 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GEZ (MOVVconst [c]) yes no)
		// cond: c < 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c < 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPS64GTZ:
		// match: (GTZ (MOVVconst [c]) yes no)
		// cond: c > 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c > 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GTZ (MOVVconst [c]) yes no)
		// cond: c <= 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c <= 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockIf:
		// match: (If cond yes no)
		// result: (NE cond yes no)
		for {
			cond := b.Controls[0]
			b.resetWithControl(BlockMIPS64NE, cond)
			return true
		}
	case BlockMIPS64LEZ:
		// match: (LEZ (MOVVconst [c]) yes no)
		// cond: c <= 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c <= 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LEZ (MOVVconst [c]) yes no)
		// cond: c > 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c > 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPS64LTZ:
		// match: (LTZ (MOVVconst [c]) yes no)
		// cond: c < 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c < 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LTZ (MOVVconst [c]) yes no)
		// cond: c >= 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c >= 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPS64NE:
		// match: (NE (FPFlagTrue cmp) yes no)
		// result: (FPT cmp yes no)
		for b.Controls[0].Op == OpMIPS64FPFlagTrue {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPS64FPT, cmp)
			return true
		}
		// match: (NE (FPFlagFalse cmp) yes no)
		// result: (FPF cmp yes no)
		for b.Controls[0].Op == OpMIPS64FPFlagFalse {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPS64FPF, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGT _ _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGT {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTU _ _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTU {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTconst _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTconst {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTUconst _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTUconst {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, cmp)
			return true
		}
		// match: (NE (SGTUconst [1] x) yes no)
		// result: (EQ x yes no)
		for b.Controls[0].Op == OpMIPS64SGTUconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPS64EQ, x)
			return true
		}
		// match: (NE (SGTU x (MOVVconst [0])) yes no)
		// result: (NE x yes no)
		for b.Controls[0].Op == OpMIPS64SGTU {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockMIPS64NE, x)
			return true
		}
		// match: (NE (SGTconst [0] x) yes no)
		// result: (LTZ x yes no)
		for b.Controls[0].Op == OpMIPS64SGTconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPS64LTZ, x)
			return true
		}
		// match: (NE (SGT x (MOVVconst [0])) yes no)
		// result: (GTZ x yes no)
		for b.Controls[0].Op == OpMIPS64SGT {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockMIPS64GTZ, x)
			return true
		}
		// match: (NE (MOVVconst [0]) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (NE (MOVVconst [c]) yes no)
		// cond: c != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
	}
	return false
}
```