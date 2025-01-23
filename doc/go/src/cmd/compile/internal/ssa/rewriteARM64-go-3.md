Response: The user wants to understand the functionality of a Go source code snippet. This snippet is part of the SSA (Static Single Assignment) rewrite rules for the ARM64 architecture in the Go compiler.

The code defines several functions named `rewriteValueARM64_OpARM64...`. These functions are responsible for optimizing or transforming specific ARM64 operations within the SSA representation. Each function examines the operands of a particular operation and, based on certain conditions, rewrites the operation into a more efficient equivalent.

The overall goal of these rewrite rules is to simplify the generated assembly code and improve performance.

Let's break down the functionality of the provided functions:

1. **`rewriteValueARM64_OpARM64MOVBUload`**: Deals with loading an unsigned byte from memory. It tries to optimize cases like loading from a constant address or when the load is paired with a preceding zero store to the same location.

2. **`rewriteValueARM64_OpARM64MOVBUloadidx`**: Handles loading an unsigned byte from memory using an indexed address. Similar optimizations as `MOVBUload` are applied.

3. **`rewriteValueARM64_OpARM64MOVBUreg`**: Focuses on moving an unsigned byte value to a register. It optimizes cases like moving a constant or masking an existing value. It also handles bitfield extraction.

4. **`rewriteValueARM64_OpARM64MOVBload`**: Handles loading a signed byte from memory, similar to `MOVBUload` but for signed bytes.

5. **`rewriteValueARM64_OpARM64MOVBloadidx`**: Handles loading a signed byte from memory using an indexed address, similar to `MOVBUloadidx`.

6. **`rewriteValueARM64_OpARM64MOVBreg`**: Focuses on moving a signed byte value to a register, similar to `MOVBUreg`.

7. **`rewriteValueARM64_OpARM64MOVBstore`**: Deals with storing a byte to memory. It optimizes cases like storing a constant zero or when the store is preceded by setting the memory to zero.

8. **`rewriteValueARM64_OpARM64MOVBstoreidx`**: Handles storing a byte to memory using an indexed address.

9. **`rewriteValueARM64_OpARM64MOVBstorezero`**: Specifically handles storing a zero byte to memory.

10. **`rewriteValueARM64_OpARM64MOVBstorezeroidx`**: Handles storing a zero byte to memory using an indexed address.

11. **`rewriteValueARM64_OpARM64MOVDload`**: Handles loading a 64-bit word from memory. It includes optimizations for loading from constant addresses, merging loads with preceding stores, and loading read-only data.

12. **`rewriteValueARM64_OpARM64MOVDloadidx`**: Handles loading a 64-bit word from memory using an indexed address.

13. **`rewriteValueARM64_OpARM64MOVDloadidx8`**: A specialized version of `MOVDloadidx` where the index is multiplied by 8.

14. **`rewriteValueARM64_OpARM64MOVDnop`**: Handles a no-operation for 64-bit values, often used for register moves that can be eliminated.

15. **`rewriteValueARM64_OpARM64MOVDreg`**: Deals with moving a 64-bit value between registers, potentially eliminating redundant moves.

16. **`rewriteValueARM64_OpARM64MOVDstore`**: Handles storing a 64-bit word to memory, with optimizations similar to byte stores.

17. **`rewriteValueARM64_OpARM64MOVDstoreidx`**: Handles storing a 64-bit word to memory using an indexed address.

18. **`rewriteValueARM64_OpARM64MOVDstoreidx8`**: A specialized version of `MOVDstoreidx` where the index is multiplied by 8.

19. **`rewriteValueARM64_OpARM64MOVDstorezero`**: Specifically handles storing a zero 64-bit word to memory, potentially merging consecutive zero stores.

20. **`rewriteValueARM64_OpARM64MOVDstorezeroidx`**: Handles storing a zero 64-bit word to memory using an indexed address.

21. **`rewriteValueARM64_OpARM64MOVDstorezeroidx8`**: A specialized version of `MOVDstorezeroidx` where the index is multiplied by 8.

22. **`rewriteValueARM64_OpARM64MOVHUload`**: Deals with loading an unsigned half-word (16 bits) from memory.

23. **`rewriteValueARM64_OpARM64MOVHUloadidx`**: Handles loading an unsigned half-word from memory using an indexed address.

24. **`rewriteValueARM64_OpARM64MOVHUloadidx2`**: A specialized version of `MOVHUloadidx` where the index is multiplied by 2.

25. **`rewriteValueARM64_OpARM64MOVHUreg`**: Focuses on moving an unsigned half-word value to a register.

26. **`rewriteValueARM64_OpARM64MOVHload`**: Handles loading a signed half-word from memory.

27. **`rewriteValueARM64_OpARM64MOVHloadidx`**: Handles loading a signed half-word from memory using an indexed address.

28. **`rewriteValueARM64_OpARM64MOVHloadidx2`**: A specialized version of `MOVHloadidx` where the index is multiplied by 2.

29. **`rewriteValueARM64_OpARM64MOVHreg`**: Focuses on moving a signed half-word value to a register.

30. **`rewriteValueARM64_OpARM64MOVHstore`**: Deals with storing a half-word to memory.

31. **`rewriteValueARM64_OpARM64MOVHstoreidx`**: Handles storing a half-word to memory using an indexed address.

32. **`rewriteValueARM64_OpARM64MOVHstoreidx2`**: A specialized version of `MOVHstoreidx` where the index is multiplied by 2.

33. **`rewriteValue`**: This function name seems incomplete. It's likely that the provided snippet ends abruptly.

Now, let's provide examples for some of these functions.
```go
package ssa

import (
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/obj/arm64"
	"internal/goarch"
)

// 第4部分，共10部分

func rewriteValueARM64_OpARM64MOVBUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBUload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBUload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBUloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVBUloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVBUload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBUload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off] {sym} ptr (MOVBstorezero [off2] {sym2} ptr2 _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVDconst [0])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVBstorezero {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVBUload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVDconst [int64(read8(sym, int64(off)))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(read8(sym, int64(off))))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBUloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBUloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVBUload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVBUload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUloadidx ptr idx (MOVBstorezeroidx ptr2 idx2 _))
	// cond: (isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2))
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVBstorezeroidx {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBUreg (ANDconst [c] x))
	// result: (ANDconst [c&(1<<8-1)] x)
	for {
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(c & (1<<8 - 1))
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint8(c))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		return true
	}
	// match: (MOVBUreg x)
	// cond: v.Type.Size() <= 1
	// result: x
	for {
		x := v_0
		if !(v.Type.Size() <= 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg (SLLconst [lc] x))
	// cond: lc >= 8
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		if !(lc >= 8) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVBUreg (SLLconst [lc] x))
	// cond: lc < 8
	// result: (UBFIZ [armBFAuxInt(lc, 8-lc)] x)
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < 8) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, 8-lc))
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (SRLconst [rc] x))
	// cond: rc < 8
	// result: (UBFX [armBFAuxInt(rc, 8)] x)
	for {
		if v_0.Op != OpARM64SRLconst {
			break
		}
		rc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(rc < 8) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 8))
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (UBFX [bfc] x))
	// cond: bfc.width() <= 8
	// result: (UBFX [bfc] x)
	for {
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(bfc.width() <= 8) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVBloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVBload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off] {sym} ptr (MOVBstorezero [off2] {sym2} ptr2 _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVDconst [0])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVBstorezero {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVBload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVBload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBloadidx ptr idx (MOVBstorezeroidx ptr2 idx2 _))
	// cond: (isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2))
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVBstorezeroidx {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int8(c))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int8(c)))
		return true
	}
	// match: (MOVBreg x)
	// cond: v.Type.Size() <= 1
	// result: x
	for {
		x := v_0
		if !(v.Type.Size() <= 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBreg <t> (ANDconst x [c]))
	// cond: uint64(c) & uint64(0xffffffffffffff80) == 0
	// result: (ANDconst <t> x [c])
	for {
		t := v.Type
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(uint64(c)&uint64(0xffffffffffffff80) == 0) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SLLconst [lc] x))
	// cond: lc < 8
	// result: (SBFIZ [armBFAuxInt(lc, 8-lc)] x)
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < 8) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, 8-lc))
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SBFX [bfc] x))
	// cond: bfc.width() <= 8
	// result: (SBFX [bfc] x)
	for {
		if v_0.Op != OpARM64SBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(bfc.width() <= 8) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} (ADD ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVBstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVBstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共10部分，请归纳一下它的功能
```

### 源代码
```go
x)
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVBUload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVDconst [int64(read8(sym, int64(off)))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(read8(sym, int64(off))))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBUloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBUloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVBUload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVBUload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUloadidx ptr idx (MOVBstorezeroidx ptr2 idx2 _))
	// cond: (isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2))
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVBstorezeroidx {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBUreg (ANDconst [c] x))
	// result: (ANDconst [c&(1<<8-1)] x)
	for {
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(c & (1<<8 - 1))
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint8(c))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		return true
	}
	// match: (MOVBUreg x)
	// cond: v.Type.Size() <= 1
	// result: x
	for {
		x := v_0
		if !(v.Type.Size() <= 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg (SLLconst [lc] x))
	// cond: lc >= 8
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		if !(lc >= 8) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVBUreg (SLLconst [lc] x))
	// cond: lc < 8
	// result: (UBFIZ [armBFAuxInt(lc, 8-lc)] x)
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < 8) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, 8-lc))
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (SRLconst [rc] x))
	// cond: rc < 8
	// result: (UBFX [armBFAuxInt(rc, 8)] x)
	for {
		if v_0.Op != OpARM64SRLconst {
			break
		}
		rc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(rc < 8) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 8))
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (UBFX [bfc] x))
	// cond: bfc.width() <= 8
	// result: (UBFX [bfc] x)
	for {
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(bfc.width() <= 8) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVBloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVBload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off] {sym} ptr (MOVBstorezero [off2] {sym2} ptr2 _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVDconst [0])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVBstorezero {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVBload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVBload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBloadidx ptr idx (MOVBstorezeroidx ptr2 idx2 _))
	// cond: (isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2))
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVBstorezeroidx {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int8(c))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int8(c)))
		return true
	}
	// match: (MOVBreg x)
	// cond: v.Type.Size() <= 1
	// result: x
	for {
		x := v_0
		if !(v.Type.Size() <= 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBreg <t> (ANDconst x [c]))
	// cond: uint64(c) & uint64(0xffffffffffffff80) == 0
	// result: (ANDconst <t> x [c])
	for {
		t := v.Type
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(uint64(c)&uint64(0xffffffffffffff80) == 0) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SLLconst [lc] x))
	// cond: lc < 8
	// result: (SBFIZ [armBFAuxInt(lc, 8-lc)] x)
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < 8) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, 8-lc))
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (SBFX [bfc] x))
	// cond: bfc.width() <= 8
	// result: (SBFX [bfc] x)
	for {
		if v_0.Op != OpARM64SBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(bfc.width() <= 8) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} (ADD ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVBstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVBstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpARM64MOVBstorezero)
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
		if v_1.Op != OpARM64MOVBreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVBstore)
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
		if v_1.Op != OpARM64MOVBUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVBstore)
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
		if v_1.Op != OpARM64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVBstore)
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
		if v_1.Op != OpARM64MOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVBstore)
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
		if v_1.Op != OpARM64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVBstore)
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
		if v_1.Op != OpARM64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstoreidx ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVBstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstoreidx (MOVDconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVBstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVDconst [0]) mem)
	// result: (MOVBstorezeroidx ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpARM64MOVBstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVBreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVBreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVBUreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVBUreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVHreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVHUreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHUreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVWreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVWUreg x) mem)
	// result: (MOVBstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWUreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVBstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBstorezero [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstorezero [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstorezero [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstorezero [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBstorezeroidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVBstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVBstorezeroidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstorezeroidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVBstorezero [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstorezeroidx (MOVDconst [c]) idx mem)
	// cond: is32Bit(c)
	// result: (MOVBstorezero [int32(c)] idx mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVDload [off] {sym} ptr (FMOVDstore [off] {sym} ptr val _))
	// result: (FMOVDfpgp val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64FMOVDstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpARM64FMOVDfpgp)
		v.AddArg(val)
		return true
	}
	// match: (MOVDload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVDloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVDloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVDload [off] {sym} (ADDshiftLL [3] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVDloadidx8 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVDloadidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVDload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off] {sym} ptr (MOVDstorezero [off2] {sym2} ptr2 _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVDconst [0])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVDstorezero {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVDload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVDconst [int64(read64(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(read64(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVDload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVDload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVDload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVDload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDloadidx ptr (SLLconst [3] idx) mem)
	// result: (MOVDloadidx8 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 3 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVDloadidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVDloadidx (SLLconst [3] idx) ptr mem)
	// result: (MOVDloadidx8 ptr idx mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARM64MOVDloadidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVDloadidx ptr idx (MOVDstorezeroidx ptr2 idx2 _))
	// cond: (isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2))
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVDstorezeroidx {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDloadidx8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDloadidx8 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<3)
	// result: (MOVDload [int32(c)<<3] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 3)) {
			break
		}
		v.reset(OpARM64MOVDload)
		v.AuxInt = int32ToAuxInt(int32(c) << 3)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDloadidx8 ptr idx (MOVDstorezeroidx8 ptr2 idx2 _))
	// cond: isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVDstorezeroidx8 {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDnop(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVDnop (MOVDconst [c]))
	// result: (MOVDconst [c])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVDreg x)
	// cond: x.Uses == 1
	// result: (MOVDnop x)
	for {
		x := v_0
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64MOVDnop)
		v.AddArg(x)
		return true
	}
	// match: (MOVDreg (MOVDconst [c]))
	// result: (MOVDconst [c])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVDstore [off] {sym} ptr (FMOVDfpgp val) mem)
	// result: (FMOVDstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64FMOVDfpgp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64FMOVDstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} (ADD ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVDstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVDstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} (ADDshiftLL [3] ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVDstoreidx8 ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVDstoreidx8)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVDstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpARM64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstoreidx ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVDstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstoreidx (MOVDconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVDstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (MOVDstoreidx ptr (SLLconst [3] idx) val mem)
	// result: (MOVDstoreidx8 ptr idx val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 3 {
			break
		}
		idx := v_1.Args[0]
		val := v_2
		mem := v_3
		v.reset(OpARM64MOVDstoreidx8)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVDstoreidx (SLLconst [3] idx) ptr val mem)
	// result: (MOVDstoreidx8 ptr idx val mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARM64MOVDstoreidx8)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVDstoreidx ptr idx (MOVDconst [0]) mem)
	// result: (MOVDstorezeroidx ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpARM64MOVDstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDstoreidx8(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstoreidx8 ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c<<3)
	// result: (MOVDstore [int32(c)<<3] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c << 3)) {
			break
		}
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c) << 3)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstoreidx8 ptr idx (MOVDconst [0]) mem)
	// result: (MOVDstorezeroidx8 ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpARM64MOVDstorezeroidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVDstorezero {s} [i] ptr x:(MOVDstorezero {s} [i+8] ptr mem))
	// cond: x.Uses == 1 && setPos(v, x.Pos) && clobber(x)
	// result: (MOVQstorezero {s} [i] ptr mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		ptr := v_0
		x := v_1
		if x.Op != OpARM64MOVDstorezero || auxIntToInt32(x.AuxInt) != i+8 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[1]
		if ptr != x.Args[0] || !(x.Uses == 1 && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpARM64MOVQstorezero)
		v.AuxInt = int32ToAuxInt(i)
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDstorezero {s} [i] ptr x:(MOVDstorezero {s} [i-8] ptr mem))
	// cond: x.Uses == 1 && setPos(v, x.Pos) && clobber(x)
	// result: (MOVQstorezero {s} [i-8] ptr mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		ptr := v_0
		x := v_1
		if x.Op != OpARM64MOVDstorezero || auxIntToInt32(x.AuxInt) != i-8 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[1]
		if ptr != x.Args[0] || !(x.Uses == 1 && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpARM64MOVQstorezero)
		v.AuxInt = int32ToAuxInt(i - 8)
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDstorezero [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDstorezero [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDstorezero [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDstorezero [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVDstorezeroidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVDstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVDstorezero [off] {sym} (ADDshiftLL [3] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVDstorezeroidx8 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVDstorezeroidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDstorezeroidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstorezeroidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVDstorezero [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDstorezeroidx (MOVDconst [c]) idx mem)
	// cond: is32Bit(c)
	// result: (MOVDstorezero [int32(c)] idx mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(idx, mem)
		return true
	}
	// match: (MOVDstorezeroidx ptr (SLLconst [3] idx) mem)
	// result: (MOVDstorezeroidx8 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 3 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVDstorezeroidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVDstorezeroidx (SLLconst [3] idx) ptr mem)
	// result: (MOVDstorezeroidx8 ptr idx mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARM64MOVDstorezeroidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVDstorezeroidx8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstorezeroidx8 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<3)
	// result: (MOVDstorezero [int32(c<<3)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 3)) {
			break
		}
		v.reset(OpARM64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(int32(c << 3))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHUload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHUload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHUloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVHUloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHUload [off] {sym} (ADDshiftLL [1] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHUloadidx2 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVHUloadidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHUload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHUload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUload [off] {sym} ptr (MOVHstorezero [off2] {sym2} ptr2 _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVDconst [0])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVHstorezero {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVHUload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVDconst [int64(read16(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(read16(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHUloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHUloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVHUload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVHUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVHUload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVHUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUloadidx ptr (SLLconst [1] idx) mem)
	// result: (MOVHUloadidx2 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVHUloadidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHUloadidx ptr (ADD idx idx) mem)
	// result: (MOVHUloadidx2 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64ADD {
			break
		}
		idx := v_1.Args[1]
		if idx != v_1.Args[0] {
			break
		}
		mem := v_2
		v.reset(OpARM64MOVHUloadidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHUloadidx (ADD idx idx) ptr mem)
	// result: (MOVHUloadidx2 ptr idx mem)
	for {
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		if idx != v_0.Args[0] {
			break
		}
		ptr := v_1
		mem := v_2
		v.reset(OpARM64MOVHUloadidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHUloadidx ptr idx (MOVHstorezeroidx ptr2 idx2 _))
	// cond: (isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2))
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHstorezeroidx {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHUloadidx2(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHUloadidx2 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<1)
	// result: (MOVHUload [int32(c)<<1] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 1)) {
			break
		}
		v.reset(OpARM64MOVHUload)
		v.AuxInt = int32ToAuxInt(int32(c) << 1)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUloadidx2 ptr idx (MOVHstorezeroidx2 ptr2 idx2 _))
	// cond: isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHstorezeroidx2 {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHUreg (ANDconst [c] x))
	// result: (ANDconst [c&(1<<16-1)] x)
	for {
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(c & (1<<16 - 1))
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint16(c))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		return true
	}
	// match: (MOVHUreg x)
	// cond: v.Type.Size() <= 2
	// result: x
	for {
		x := v_0
		if !(v.Type.Size() <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHUreg (SLLconst [lc] x))
	// cond: lc >= 16
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		if !(lc >= 16) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVHUreg (SLLconst [lc] x))
	// cond: lc < 16
	// result: (UBFIZ [armBFAuxInt(lc, 16-lc)] x)
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < 16) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, 16-lc))
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg (SRLconst [rc] x))
	// cond: rc < 16
	// result: (UBFX [armBFAuxInt(rc, 16)] x)
	for {
		if v_0.Op != OpARM64SRLconst {
			break
		}
		rc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(rc < 16) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 16))
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg (UBFX [bfc] x))
	// cond: bfc.width() <= 16
	// result: (UBFX [bfc] x)
	for {
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(bfc.width() <= 16) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVHloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHload [off] {sym} (ADDshiftLL [1] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHloadidx2 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVHloadidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off] {sym} ptr (MOVHstorezero [off2] {sym2} ptr2 _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVDconst [0])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVHstorezero {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVHload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVHload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVHload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVHload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHloadidx ptr (SLLconst [1] idx) mem)
	// result: (MOVHloadidx2 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVHloadidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHloadidx ptr (ADD idx idx) mem)
	// result: (MOVHloadidx2 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64ADD {
			break
		}
		idx := v_1.Args[1]
		if idx != v_1.Args[0] {
			break
		}
		mem := v_2
		v.reset(OpARM64MOVHloadidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHloadidx (ADD idx idx) ptr mem)
	// result: (MOVHloadidx2 ptr idx mem)
	for {
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		if idx != v_0.Args[0] {
			break
		}
		ptr := v_1
		mem := v_2
		v.reset(OpARM64MOVHloadidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHloadidx ptr idx (MOVHstorezeroidx ptr2 idx2 _))
	// cond: (isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2))
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHstorezeroidx {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2) || isSamePtr(ptr, idx2) && isSamePtr(idx, ptr2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHloadidx2(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHloadidx2 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<1)
	// result: (MOVHload [int32(c)<<1] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 1)) {
			break
		}
		v.reset(OpARM64MOVHload)
		v.AuxInt = int32ToAuxInt(int32(c) << 1)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHloadidx2 ptr idx (MOVHstorezeroidx2 ptr2 idx2 _))
	// cond: isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)
	// result: (MOVDconst [0])
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHstorezeroidx2 {
			break
		}
		idx2 := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr, ptr2) && isSamePtr(idx, idx2)) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int16(c))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int16(c)))
		return true
	}
	// match: (MOVHreg x)
	// cond: v.Type.Size() <= 2
	// result: x
	for {
		x := v_0
		if !(v.Type.Size() <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg <t> (ANDconst x [c]))
	// cond: uint64(c) & uint64(0xffffffffffff8000) == 0
	// result: (ANDconst <t> x [c])
	for {
		t := v.Type
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(uint64(c)&uint64(0xffffffffffff8000) == 0) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SLLconst [lc] x))
	// cond: lc < 16
	// result: (SBFIZ [armBFAuxInt(lc, 16-lc)] x)
	for {
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < 16) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, 16-lc))
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SBFX [bfc] x))
	// cond: bfc.width() <= 16
	// result: (SBFX [bfc] x)
	for {
		if v_0.Op != OpARM64SBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(bfc.width() <= 16) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} (ADD ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVHstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} (ADDshiftLL [1] ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHstoreidx2 ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64MOVHstoreidx2)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVHstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpARM64MOVHstorezero)
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
		if v_1.Op != OpARM64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVHstore)
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
		if v_1.Op != OpARM64MOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVHstore)
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
		if v_1.Op != OpARM64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVHstore)
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
		if v_1.Op != OpARM64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreidx ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVHstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstoreidx (MOVDconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVHstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (MOVHstoreidx ptr (SLLconst [1] idx) val mem)
	// result: (MOVHstoreidx2 ptr idx val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		idx := v_1.Args[0]
		val := v_2
		mem := v_3
		v.reset(OpARM64MOVHstoreidx2)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstoreidx ptr (ADD idx idx) val mem)
	// result: (MOVHstoreidx2 ptr idx val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64ADD {
			break
		}
		idx := v_1.Args[1]
		if idx != v_1.Args[0] {
			break
		}
		val := v_2
		mem := v_3
		v.reset(OpARM64MOVHstoreidx2)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstoreidx (SLLconst [1] idx) ptr val mem)
	// result: (MOVHstoreidx2 ptr idx val mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARM64MOVHstoreidx2)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstoreidx (ADD idx idx) ptr val mem)
	// result: (MOVHstoreidx2 ptr idx val mem)
	for {
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		if idx != v_0.Args[0] {
			break
		}
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARM64MOVHstoreidx2)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVDconst [0]) mem)
	// result: (MOVHstorezeroidx ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpARM64MOVHstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVHreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVHUreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHUreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVWreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVWUreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWUreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MOVHstoreidx2(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreidx2 ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c<<1)
	// result: (MOVHstore [int32(c)<<1] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c << 1)) {
			break
		}
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(int32(c) << 1)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstoreidx2 ptr idx (MOVDconst [0]) mem)
	// result: (MOVHstorezeroidx2 ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpARM64MOVHstorezeroidx2)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHstoreidx2 ptr idx (MOVHreg x) mem)
	// result: (MOVHstoreidx2 ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVHstoreidx2)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx2 ptr idx (MOVHUreg x) mem)
	// result: (MOVHstoreidx2 ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVHUreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVHstoreidx2)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx2 ptr idx (MOVWreg x) mem)
	// result: (MOVHstoreidx2 ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVHstoreidx2)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx2 ptr idx (MOVWUreg x) mem)
	// result: (MOVHstoreidx2 ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARM64MOVWUreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpARM64MOVHstoreidx2)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	return false
}
func rewriteValue
```