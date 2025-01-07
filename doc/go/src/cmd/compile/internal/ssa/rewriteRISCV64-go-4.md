Response:
The user wants a summary of the functionality of the provided Go code snippet. This code is part of the SSA (Static Single Assignment) rewrite rules for the RISCV64 architecture in the Go compiler.

The code defines several functions named `rewriteValueRISCV64_Op...`, each responsible for optimizing a specific RISCV64 opcode. These functions try to match certain patterns of operations and replace them with more efficient equivalents.

Based on the function names and the operations within them, the main functionalities are:

1. **Load/Store Optimization:**  Combining address calculations with load/store operations, handling zero stores, and using register-to-register moves where applicable.
2. **Arithmetic Optimization:** Simplifying arithmetic operations like negation, addition, subtraction, bitwise OR, AND, XOR, and shifts. This includes handling constants and specific patterns.
3. **Rotate Optimization:** Implementing rotate left/right operations using shift and OR operations, and optimizing rotations with constant amounts.
4. **Comparison Optimization:** Simplifying comparison operations like SLT (Set Less Than) and SEQZ/SNEZ (Set Equal/Not Equal to Zero).
5. **Shift Optimization:** Optimizing shift operations (SLL, SRL, SRA) with constant values and register moves.
6. **Handling of Extended Loads:** Optimizing loads of smaller data types (like `MOVWUload`) into larger registers.
7. **Shift Bounds Checking (Implicit):**  The `shiftIsBounded` condition in some functions related to shifts implies logic to handle cases where the shift amount might exceed the register size.

To provide a concise summary, I will focus on the main categories of optimizations performed by these functions.
这段Go语言代码是Go编译器中用于RISCV64架构的SSA（静态单赋值）重写规则的一部分。它的主要功能是**对RISCV64指令进行优化**。

具体来说，这段代码定义了一系列名为 `rewriteValueRISCV64_Op<OperationName>` 的函数，每个函数都负责针对特定的RISCV64操作码(`OpRISCV64<OperationName>`)进行模式匹配和优化。

**归纳一下它的功能：**

这段代码的主要功能是**通过模式匹配和替换，将一些RISCV64指令序列优化为更高效的等价形式**。 优化的手段包括：

1. **合并指令:** 例如，将地址计算指令 (`MOVaddr`) 与内存访问指令 (`MOVWload`, `MOVWstore`) 合并成一条带有偏移量的内存访问指令。
2. **利用指令特性:** 例如，将存储零值的操作替换为专门的零值存储指令 (`MOVWstorezero`)。
3. **简化运算:** 例如，将与零异或替换为自身，将与-1或操作替换为加载-1常量。
4. **优化常量操作:** 将涉及常量的运算直接计算出结果，生成常量指令 (`MOVDconst`)。
5. **处理寄存器移动:** 例如，当存储一个寄存器的值时，如果源操作已经是寄存器移动指令，则直接使用源寄存器的值。
6. **处理移位和旋转:** 将移位操作与常量进行结合，使用立即数移位指令。将循环移位操作转换为使用右移指令。
7. **处理符号扩展和零扩展:**  优化涉及符号扩展和零扩展的移位操作。

总而言之，这段代码的目标是**降低RISCV64架构上执行Go代码的指令数量，提高代码执行效率。** 它属于编译器后端优化的一个重要环节。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteRISCV64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共7部分，请归纳一下它的功能

"""
x)
		return true
	}
	// match: (MOVWreg <t> x:(MOVWUload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWload <t> [off] {sym} ptr mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpRISCV64MOVWUload {
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
		v0 := b.NewValue0(x.Pos, OpRISCV64MOVWload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstore [off1] {sym1} (MOVaddr [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVWstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpRISCV64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym} (ADDI [off2] base) val mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVWstore [off1+int32(off2)] {sym} base val mem)
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
		v.reset(OpRISCV64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVWstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpRISCV64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWUreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpRISCV64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpRISCV64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64MOVWstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstorezero [off1] {sym1} (MOVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2))
	// result: (MOVWstorezero [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
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
		v.reset(OpRISCV64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstorezero [off1] {sym} (ADDI [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2)
	// result: (MOVWstorezero [off1+int32(off2)] {sym} ptr mem)
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
		v.reset(OpRISCV64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64NEG(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (NEG (SUB x y))
	// result: (SUB y x)
	for {
		if v_0.Op != OpRISCV64SUB {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpRISCV64SUB)
		v.AddArg2(y, x)
		return true
	}
	// match: (NEG <t> s:(ADDI [val] (SUB x y)))
	// cond: s.Uses == 1 && is32Bit(-val)
	// result: (ADDI [-val] (SUB <t> y x))
	for {
		t := v.Type
		s := v_0
		if s.Op != OpRISCV64ADDI {
			break
		}
		val := auxIntToInt64(s.AuxInt)
		s_0 := s.Args[0]
		if s_0.Op != OpRISCV64SUB {
			break
		}
		y := s_0.Args[1]
		x := s_0.Args[0]
		if !(s.Uses == 1 && is32Bit(-val)) {
			break
		}
		v.reset(OpRISCV64ADDI)
		v.AuxInt = int64ToAuxInt(-val)
		v0 := b.NewValue0(v.Pos, OpRISCV64SUB, t)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (NEG (NEG x))
	// result: x
	for {
		if v_0.Op != OpRISCV64NEG {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (NEG (MOVDconst [x]))
	// result: (MOVDconst [-x])
	for {
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(-x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64NEGW(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGW (MOVDconst [x]))
	// result: (MOVDconst [int64(int32(-x))])
	for {
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(-x)))
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64OR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (OR (MOVDconst [val]) x)
	// cond: is32Bit(val)
	// result: (ORI [val] x)
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
			v.reset(OpRISCV64ORI)
			v.AuxInt = int64ToAuxInt(val)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64ORI(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORI [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ORI [-1] x)
	// result: (MOVDconst [-1])
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORI [x] (MOVDconst [y]))
	// result: (MOVDconst [x | y])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(x | y)
		return true
	}
	// match: (ORI [x] (ORI [y] z))
	// result: (ORI [x | y] z)
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64ORI {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		z := v_0.Args[0]
		v.reset(OpRISCV64ORI)
		v.AuxInt = int64ToAuxInt(x | y)
		v.AddArg(z)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64ROL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROL x (MOVDconst [val]))
	// result: (RORI [int64(int8(-val)&63)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64RORI)
		v.AuxInt = int64ToAuxInt(int64(int8(-val) & 63))
		v.AddArg(x)
		return true
	}
	// match: (ROL x (NEG y))
	// result: (ROR x y)
	for {
		x := v_0
		if v_1.Op != OpRISCV64NEG {
			break
		}
		y := v_1.Args[0]
		v.reset(OpRISCV64ROR)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64ROLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROLW x (MOVDconst [val]))
	// result: (RORIW [int64(int8(-val)&31)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64RORIW)
		v.AuxInt = int64ToAuxInt(int64(int8(-val) & 31))
		v.AddArg(x)
		return true
	}
	// match: (ROLW x (NEG y))
	// result: (RORW x y)
	for {
		x := v_0
		if v_1.Op != OpRISCV64NEG {
			break
		}
		y := v_1.Args[0]
		v.reset(OpRISCV64RORW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64ROR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROR x (MOVDconst [val]))
	// result: (RORI [int64(val&63)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64RORI)
		v.AuxInt = int64ToAuxInt(int64(val & 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64RORW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RORW x (MOVDconst [val]))
	// result: (RORIW [int64(val&31)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64RORIW)
		v.AuxInt = int64ToAuxInt(int64(val & 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SEQZ(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SEQZ (NEG x))
	// result: (SEQZ x)
	for {
		if v_0.Op != OpRISCV64NEG {
			break
		}
		x := v_0.Args[0]
		v.reset(OpRISCV64SEQZ)
		v.AddArg(x)
		return true
	}
	// match: (SEQZ (SEQZ x))
	// result: (SNEZ x)
	for {
		if v_0.Op != OpRISCV64SEQZ {
			break
		}
		x := v_0.Args[0]
		v.reset(OpRISCV64SNEZ)
		v.AddArg(x)
		return true
	}
	// match: (SEQZ (SNEZ x))
	// result: (SEQZ x)
	for {
		if v_0.Op != OpRISCV64SNEZ {
			break
		}
		x := v_0.Args[0]
		v.reset(OpRISCV64SEQZ)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLL x (MOVDconst [val]))
	// result: (SLLI [int64(val&63)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64SLLI)
		v.AuxInt = int64ToAuxInt(int64(val & 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SLLI(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLLI [x] (MOVDconst [y]))
	// cond: is32Bit(y << uint32(x))
	// result: (MOVDconst [y << uint32(x)])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		if !(is32Bit(y << uint32(x))) {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(y << uint32(x))
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SLLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLLW x (MOVDconst [val]))
	// result: (SLLIW [int64(val&31)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64SLLIW)
		v.AuxInt = int64ToAuxInt(int64(val & 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SLT(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLT x (MOVDconst [val]))
	// cond: val >= -2048 && val <= 2047
	// result: (SLTI [val] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		if !(val >= -2048 && val <= 2047) {
			break
		}
		v.reset(OpRISCV64SLTI)
		v.AuxInt = int64ToAuxInt(val)
		v.AddArg(x)
		return true
	}
	// match: (SLT x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SLTI(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLTI [x] (MOVDconst [y]))
	// result: (MOVDconst [b2i(int64(y) < int64(x))])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(int64(y) < int64(x)))
		return true
	}
	// match: (SLTI [x] (ANDI [y] _))
	// cond: y >= 0 && int64(y) < int64(x)
	// result: (MOVDconst [1])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64ANDI {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		if !(y >= 0 && int64(y) < int64(x)) {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SLTI [x] (ORI [y] _))
	// cond: y >= 0 && int64(y) >= int64(x)
	// result: (MOVDconst [0])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64ORI {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		if !(y >= 0 && int64(y) >= int64(x)) {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SLTIU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLTIU [x] (MOVDconst [y]))
	// result: (MOVDconst [b2i(uint64(y) < uint64(x))])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(uint64(y) < uint64(x)))
		return true
	}
	// match: (SLTIU [x] (ANDI [y] _))
	// cond: y >= 0 && uint64(y) < uint64(x)
	// result: (MOVDconst [1])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64ANDI {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		if !(y >= 0 && uint64(y) < uint64(x)) {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SLTIU [x] (ORI [y] _))
	// cond: y >= 0 && uint64(y) >= uint64(x)
	// result: (MOVDconst [0])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64ORI {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		if !(y >= 0 && uint64(y) >= uint64(x)) {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SLTU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLTU x (MOVDconst [val]))
	// cond: val >= -2048 && val <= 2047
	// result: (SLTIU [val] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		if !(val >= -2048 && val <= 2047) {
			break
		}
		v.reset(OpRISCV64SLTIU)
		v.AuxInt = int64ToAuxInt(val)
		v.AddArg(x)
		return true
	}
	// match: (SLTU x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SNEZ(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SNEZ (NEG x))
	// result: (SNEZ x)
	for {
		if v_0.Op != OpRISCV64NEG {
			break
		}
		x := v_0.Args[0]
		v.reset(OpRISCV64SNEZ)
		v.AddArg(x)
		return true
	}
	// match: (SNEZ (SEQZ x))
	// result: (SEQZ x)
	for {
		if v_0.Op != OpRISCV64SEQZ {
			break
		}
		x := v_0.Args[0]
		v.reset(OpRISCV64SEQZ)
		v.AddArg(x)
		return true
	}
	// match: (SNEZ (SNEZ x))
	// result: (SNEZ x)
	for {
		if v_0.Op != OpRISCV64SNEZ {
			break
		}
		x := v_0.Args[0]
		v.reset(OpRISCV64SNEZ)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRA x (MOVDconst [val]))
	// result: (SRAI [int64(val&63)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64SRAI)
		v.AuxInt = int64ToAuxInt(int64(val & 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SRAI(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (SRAI <t> [x] (MOVWreg y))
	// cond: x >= 0 && x <= 31
	// result: (SRAIW <t> [int64(x)] y)
	for {
		t := v.Type
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVWreg {
			break
		}
		y := v_0.Args[0]
		if !(x >= 0 && x <= 31) {
			break
		}
		v.reset(OpRISCV64SRAIW)
		v.Type = t
		v.AuxInt = int64ToAuxInt(int64(x))
		v.AddArg(y)
		return true
	}
	// match: (SRAI <t> [x] (MOVBreg y))
	// cond: x >= 8
	// result: (SRAI [63] (SLLI <t> [56] y))
	for {
		t := v.Type
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVBreg {
			break
		}
		y := v_0.Args[0]
		if !(x >= 8) {
			break
		}
		v.reset(OpRISCV64SRAI)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLLI, t)
		v0.AuxInt = int64ToAuxInt(56)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (SRAI <t> [x] (MOVHreg y))
	// cond: x >= 16
	// result: (SRAI [63] (SLLI <t> [48] y))
	for {
		t := v.Type
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVHreg {
			break
		}
		y := v_0.Args[0]
		if !(x >= 16) {
			break
		}
		v.reset(OpRISCV64SRAI)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLLI, t)
		v0.AuxInt = int64ToAuxInt(48)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (SRAI <t> [x] (MOVWreg y))
	// cond: x >= 32
	// result: (SRAIW [31] y)
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVWreg {
			break
		}
		y := v_0.Args[0]
		if !(x >= 32) {
			break
		}
		v.reset(OpRISCV64SRAIW)
		v.AuxInt = int64ToAuxInt(31)
		v.AddArg(y)
		return true
	}
	// match: (SRAI [x] (MOVDconst [y]))
	// result: (MOVDconst [int64(y) >> uint32(x)])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(y) >> uint32(x))
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SRAW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRAW x (MOVDconst [val]))
	// result: (SRAIW [int64(val&31)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64SRAIW)
		v.AuxInt = int64ToAuxInt(int64(val & 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRL x (MOVDconst [val]))
	// result: (SRLI [int64(val&63)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64SRLI)
		v.AuxInt = int64ToAuxInt(int64(val & 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SRLI(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRLI <t> [x] (MOVWUreg y))
	// cond: x >= 0 && x <= 31
	// result: (SRLIW <t> [int64(x)] y)
	for {
		t := v.Type
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVWUreg {
			break
		}
		y := v_0.Args[0]
		if !(x >= 0 && x <= 31) {
			break
		}
		v.reset(OpRISCV64SRLIW)
		v.Type = t
		v.AuxInt = int64ToAuxInt(int64(x))
		v.AddArg(y)
		return true
	}
	// match: (SRLI <t> [x] (MOVBUreg y))
	// cond: x >= 8
	// result: (MOVDconst <t> [0])
	for {
		t := v.Type
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVBUreg {
			break
		}
		if !(x >= 8) {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.Type = t
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLI <t> [x] (MOVHUreg y))
	// cond: x >= 16
	// result: (MOVDconst <t> [0])
	for {
		t := v.Type
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVHUreg {
			break
		}
		if !(x >= 16) {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.Type = t
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLI <t> [x] (MOVWUreg y))
	// cond: x >= 32
	// result: (MOVDconst <t> [0])
	for {
		t := v.Type
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVWUreg {
			break
		}
		if !(x >= 32) {
			break
		}
		v.reset(OpRISCV64MOVDconst)
		v.Type = t
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLI [x] (MOVDconst [y]))
	// result: (MOVDconst [int64(uint64(y) >> uint32(x))])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(y) >> uint32(x)))
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SRLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRLW x (MOVDconst [val]))
	// result: (SRLIW [int64(val&31)] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		v.reset(OpRISCV64SRLIW)
		v.AuxInt = int64ToAuxInt(int64(val & 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUB x (MOVDconst [val]))
	// cond: is32Bit(-val)
	// result: (ADDI [-val] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(-val)) {
			break
		}
		v.reset(OpRISCV64ADDI)
		v.AuxInt = int64ToAuxInt(-val)
		v.AddArg(x)
		return true
	}
	// match: (SUB <t> (MOVDconst [val]) y)
	// cond: is32Bit(-val)
	// result: (NEG (ADDI <t> [-val] y))
	for {
		t := v.Type
		if v_0.Op != OpRISCV64MOVDconst {
			break
		}
		val := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(is32Bit(-val)) {
			break
		}
		v.reset(OpRISCV64NEG)
		v0 := b.NewValue0(v.Pos, OpRISCV64ADDI, t)
		v0.AuxInt = int64ToAuxInt(-val)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (SUB x (MOVDconst [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SUB (MOVDconst [0]) x)
	// result: (NEG x)
	for {
		if v_0.Op != OpRISCV64MOVDconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpRISCV64NEG)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64SUBW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBW x (MOVDconst [0]))
	// result: (ADDIW [0] x)
	for {
		x := v_0
		if v_1.Op != OpRISCV64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpRISCV64ADDIW)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg(x)
		return true
	}
	// match: (SUBW (MOVDconst [0]) x)
	// result: (NEGW x)
	for {
		if v_0.Op != OpRISCV64MOVDconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpRISCV64NEGW)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRISCV64XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR (MOVDconst [val]) x)
	// cond: is32Bit(val)
	// result: (XORI [val] x)
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
			v.reset(OpRISCV64XORI)
			v.AuxInt = int64ToAuxInt(val)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueRISCV64_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x y)
	// result: (OR (SLL <t> x (ANDI [15] <y.Type> y)) (SRL <t> (ZeroExt16to64 x) (ANDI [15] <y.Type> (NEG <y.Type> y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpRISCV64OR)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v1 := b.NewValue0(v.Pos, OpRISCV64ANDI, y.Type)
		v1.AuxInt = int64ToAuxInt(15)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRISCV64SRL, t)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpRISCV64ANDI, y.Type)
		v4.AuxInt = int64ToAuxInt(15)
		v5 := b.NewValue0(v.Pos, OpRISCV64NEG, y.Type)
		v5.AddArg(y)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueRISCV64_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x y)
	// result: (OR (SLL <t> x (ANDI [7] <y.Type> y)) (SRL <t> (ZeroExt8to64 x) (ANDI [7] <y.Type> (NEG <y.Type> y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpRISCV64OR)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v1 := b.NewValue0(v.Pos, OpRISCV64ANDI, y.Type)
		v1.AuxInt = int64ToAuxInt(7)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRISCV64SRL, t)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpRISCV64ANDI, y.Type)
		v4.AuxInt = int64ToAuxInt(7)
		v5 := b.NewValue0(v.Pos, OpRISCV64NEG, y.Type)
		v5.AddArg(y)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueRISCV64_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SRL <t> (ZeroExt16to64 x) y) (Neg16 <t> (SLTIU <t> [64] (ZeroExt16to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpNeg16, t)
		v3 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v2.AddArg(v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Rsh16Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRL (ZeroExt16to64 x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRL)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SRL <t> (ZeroExt16to64 x) y) (Neg16 <t> (SLTIU <t> [64] (ZeroExt32to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpNeg16, t)
		v3 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v2.AddArg(v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Rsh16Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRL (ZeroExt16to64 x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRL)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SRL <t> (ZeroExt16to64 x) y) (Neg16 <t> (SLTIU <t> [64] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpNeg16, t)
		v3 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Rsh16Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRL (ZeroExt16to64 x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRL)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SRL <t> (ZeroExt16to64 x) y) (Neg16 <t> (SLTIU <t> [64] (ZeroExt8to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpNeg16, t)
		v3 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v2.AddArg(v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Rsh16Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRL (ZeroExt16to64 x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRL)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) (OR <y.Type> y (ADDI <y.Type> [-1] (SLTIU <y.Type> [64] (ZeroExt16to64 y)))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpRISCV64OR, y.Type)
		v2 := b.NewValue0(v.Pos, OpRISCV64ADDI, y.Type)
		v2.AuxInt = int64ToAuxInt(-1)
		v3 := b.NewValue0(v.Pos, OpRISCV64SLTIU, y.Type)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v2.AddArg(v3)
		v1.AddArg2(y, v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh16x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) (OR <y.Type> y (ADDI <y.Type> [-1] (SLTIU <y.Type> [64] (ZeroExt32to64 y)))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpRISCV64OR, y.Type)
		v2 := b.NewValue0(v.Pos, OpRISCV64ADDI, y.Type)
		v2.AuxInt = int64ToAuxInt(-1)
		v3 := b.NewValue0(v.Pos, OpRISCV64SLTIU, y.Type)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v2.AddArg(v3)
		v1.AddArg2(y, v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh16x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) (OR <y.Type> y (ADDI <y.Type> [-1] (SLTIU <y.Type> [64] y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpRISCV64OR, y.Type)
		v2 := b.NewValue0(v.Pos, OpRISCV64ADDI, y.Type)
		v2.AuxInt = int64ToAuxInt(-1)
		v3 := b.NewValue0(v.Pos, OpRISCV64SLTIU, y.Type)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg2(y, v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh16x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) (OR <y.Type> y (ADDI <y.Type> [-1] (SLTIU <y.Type> [64] (ZeroExt8to64 y)))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddA
"""




```