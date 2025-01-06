Response: The user wants a summary of the functionality of the provided Go code snippet. This code is part of the Go compiler for the MIPS64 architecture, specifically dealing with rewriting SSA (Static Single Assignment) values.

The code defines several functions named `rewriteValueMIPS64_Op...`. Each function handles a specific SSA operation (`Op`) for the MIPS64 architecture. These functions aim to simplify or optimize the SSA representation by applying rewrite rules.

Here's a breakdown of the common patterns and purposes:

1. **Constant Folding:** Many rules check for operations involving constants and perform the computation directly, replacing the operation with a new constant.
2. **Identity and Simplification:** Some rules identify cases where an operation is redundant or can be simplified (e.g., `AND x x` becomes `x`).
3. **Lowering of Generic Operations:** Certain operations might be "lowered" into more specific or efficient MIPS64 instructions.
4. **Address Calculation Optimization:** Rules exist to combine or simplify address calculations involving constants and base pointers.
5. **Memory Load/Store Optimizations:** Some rules optimize memory access patterns, like combining offsets or recognizing zero stores.
6. **Register Usage Hints:**  Rules might provide hints about register usage (e.g., `MOVVreg` with a single use becomes `MOVVnop`).
7. **Type Conversions/Extensions:** Operations like `MOVBUreg` are handled, sometimes optimizing them away or converting them to `MOVVreg`.

To provide a good summary, I need to group these individual rewrite rules by the type of optimization or simplification they achieve.
这是 `go/src/cmd/compile/internal/ssa/rewriteMIPS64.go` 文件的第二部分，主要功能是定义了一系列针对 MIPS64 架构的 SSA (Static Single Assignment) 值的重写规则。这些规则旨在优化和简化 SSA 图，使其更接近底层的机器指令，从而提高编译后代码的效率。

具体来说，这部分代码涵盖了以下操作的重写规则：

**1. 逻辑运算优化:**

*   **`OpMIPS64AND`**:  优化 `AND` 操作，例如 `AND x x` 简化为 `x`，或者将与常量进行的 `AND` 操作转换为 `ANDconst` 操作。
*   **`OpMIPS64ANDconst`**:  优化与常量进行的 `AND` 操作，例如 `ANDconst [0] _` 简化为 `MOVVconst [0]`，或者将连续的 `ANDconst` 操作合并。
*   **`OpMIPS64NOR`**: 将 `NOR x (MOVVconst [c])` 转换为 `NORconst [c] x` 以便后续优化。
*   **`OpMIPS64NORconst`**: 优化与常量进行的 `NOR` 操作。
*   **`OpMIPS64OR`**: 优化 `OR` 操作，例如 `OR x x` 简化为 `x`，或者将与常量进行的 `OR` 操作转换为 `ORconst` 操作。
*   **`OpMIPS64ORconst`**: 优化与常量进行的 `OR` 操作，例如 `ORconst [0] x` 简化为 `x`，或者将连续的 `ORconst` 操作合并。

**2. 原子操作优化:**

*   **`OpMIPS64LoweredAtomicAdd32` 和 `OpMIPS64LoweredAtomicAdd64`**:  当原子加操作的第二个参数是常量时，将其转换为 `LoweredAtomicAddconst32` 或 `LoweredAtomicAddconst64`。
*   **`OpMIPS64LoweredAtomicStore32` 和 `OpMIPS64LoweredAtomicStore64`**:  当原子存储的值是常量 0 时，将其转换为 `LoweredAtomicStorezero32` 或 `LoweredAtomicStorezero64`。

**3. 加载/存储操作优化:**

*   **`OpMIPS64MOVBUload`， `OpMIPS64MOVBload`， `OpMIPS64MOVHload`， `OpMIPS64MOVWload`， `OpMIPS64MOVVload`**:  对不同大小的加载操作进行优化，例如将带有常量偏移的加载转换为单一的加载指令，或者在已知的情况下直接加载常量值。
*   **`OpMIPS64MOVBUreg`， `OpMIPS64MOVBreg`， `OpMIPS64MOVHUreg`， `OpMIPS64MOVHreg`， `OpMIPS64MOVWUreg`， `OpMIPS64MOVWreg`**:  优化寄存器扩展操作，例如将加载结果直接用作寄存器。
*   **`OpMIPS64MOVBstore`， `OpMIPS64MOVHstore`， `OpMIPS64MOVWstore`， `OpMIPS64MOVVstore`**:  对不同大小的存储操作进行优化，例如将带有常量偏移的存储转换为单一的存储指令，或者在存储常量 0 时使用特殊的 `storezero` 指令。
*   **`OpMIPS64MOVBstorezero`， `OpMIPS64MOVHstorezero`， `OpMIPS64MOVWstorezero`， `OpMIPS64MOVVstorezero`**: 优化存储零值的操作，可能合并偏移。
*   **`OpMIPS64MOVDload` 和 `OpMIPS64MOVDstore`**:  优化浮点数的双精度加载和存储，可能会利用 `MOVVgpfp` 和 `MOVVfpgp` 进行寄存器之间的移动。
*   **`OpMIPS64MOVFload` 和 `OpMIPS64MOVFstore`**:  优化浮点数的单精度加载和存储，可能会利用 `MOVWgpfp` 和 `MOVWfpgp` 进行寄存器之间的移动。

**4. 常量操作和寄存器移动优化:**

*   **`OpMIPS64MOVVconst`**:  虽然没有直接的重写规则，但它是许多其他规则的目标，用于创建或替换为常量值。
*   **`OpMIPS64MOVVnop`**:  移除冗余的寄存器移动操作。
*   **`OpMIPS64MOVVreg`**:  优化寄存器移动操作，如果一个移动操作的结果只使用一次，则可以将其替换为 `MOVVnop`。

**5. 算术运算优化:**

*   **`OpMIPS64NEGV`**:  优化取反操作，直接计算常量的相反数。

**6. 比较运算优化:**

*   **`OpMIPS64SGT`**:  优化大于比较操作，将与常量的比较转换为 `SGTconst`。
*   **`OpMIPS64SGTU`**: 优化无符号大于比较操作，将与常量的比较转换为 `SGTUconst`。
*   **`OpMIPS64SGTUconst`**: 优化与常量进行的无符号大于比较操作，直接计算比较结果。
*   **`OpMIPS64SGTconst`**: 优化与常量进行的大于比较操作，直接计算比较结果。

**7. 移位运算优化:**

*   **`OpMIPS64SLLV`**:  优化左移操作，当移位量为常量时转换为 `SLLVconst`。
*   **`OpMIPS64SLLVconst`**:  优化常量左移操作，直接计算结果。
*   **`OpMIPS64SRAV`**:  优化算术右移操作，当移位量为常量时转换为 `SRAVconst`。
*   **`OpMIPS64SRAVconst`**:  优化常量算术右移操作，直接计算结果。
*   **`OpMIPS64SRLV`**:  优化逻辑右移操作，当移位量为常量时转换为 `SRLVconst`。
*   **`OpMIPS64SRLVconst`**:  优化常量逻辑右移操作，直接计算结果。

**代码示例 (假设的 `AND` 操作优化):**

假设有以下 Go 代码：

```go
package main

func main() {
	a := 10
	b := a & a
	println(b)
}
```

在编译过程中，SSA 生成器可能会为 `a & a` 生成一个 `OpMIPS64AND` 的 SSA 值。 `rewriteValueMIPS64_OpMIPS64AND` 函数会识别出这是一个 `AND x x` 的模式，并将其重写为直接使用 `x`，避免了实际的 `AND` 运算。

**假设的 SSA 输入 (简化表示):**

```
v1 = LocalInt a
v2 = MIPS64AND v1, v1
v3 = Println v2
```

**`rewriteValueMIPS64_OpMIPS64AND` 函数处理后假设的 SSA 输出:**

```
v1 = LocalInt a
v2 = v1 // OpMIPS64AND 被优化掉，直接使用 v1
v3 = Println v2
```

**使用者易犯错的点:**

由于这些是编译器内部的重写规则，普通 Go 语言使用者不会直接与这些代码交互，因此不存在使用者易犯错的点。这些规则是编译器开发者为了提高代码效率而设计的。

**总结一下它的功能:**

这部分 `rewriteMIPS64.go` 文件的主要功能是定义了大量的针对 MIPS64 架构的 SSA 值重写规则。这些规则通过模式匹配和替换，实现了对 SSA 图的各种优化和简化，包括常量折叠、身份变换、指令选择优化以及地址计算优化等，最终目的是生成更高效的机器码。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共4部分，请归纳一下它的功能

"""
is32Bit(c)
	// result: (ANDconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPS64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpMIPS64ANDconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64ANDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDconst [0] _)
	// result: (MOVVconst [0])
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (ANDconst [-1] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ANDconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c&d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(c & d)
		return true
	}
	// match: (ANDconst [c] (ANDconst [d] x))
	// result: (ANDconst [c&d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64ANDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpMIPS64ANDconst)
		v.AuxInt = int64ToAuxInt(c & d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64LoweredAtomicAdd32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LoweredAtomicAdd32 ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (LoweredAtomicAddconst32 [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpMIPS64LoweredAtomicAddconst32)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64LoweredAtomicAdd64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LoweredAtomicAdd64 ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (LoweredAtomicAddconst64 [c] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpMIPS64LoweredAtomicAddconst64)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64LoweredAtomicStore32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LoweredAtomicStore32 ptr (MOVVconst [0]) mem)
	// result: (LoweredAtomicStorezero32 ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpMIPS64LoweredAtomicStorezero32)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64LoweredAtomicStore64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LoweredAtomicStore64 ptr (MOVVconst [0]) mem)
	// result: (LoweredAtomicStorezero64 ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpMIPS64LoweredAtomicStorezero64)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVBUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBUload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVBUload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVBUload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVBUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBUreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (MOVVconst [c]))
	// result: (MOVVconst [int64(uint8(c))])
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVBload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVBload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVBload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVVconst [int64(read8(sym, int64(off)))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(read8(sym, int64(off))))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBreg x:(MOVBload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg x:(MOVBreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (MOVVconst [c]))
	// result: (MOVVconst [int64(int8(c))])
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(int8(c)))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVBstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVBstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVVconst [0]) mem)
	// result: (MOVBstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpMIPS64MOVBstorezero)
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
		if v_1.Op != OpMIPS64MOVBreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
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
		if v_1.Op != OpMIPS64MOVBUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
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
		if v_1.Op != OpMIPS64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
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
		if v_1.Op != OpMIPS64MOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
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
		if v_1.Op != OpMIPS64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
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
		if v_1.Op != OpMIPS64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVBstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBstorezero [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVBstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstorezero [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVBstorezero [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVDload [off] {sym} ptr (MOVVstore [off] {sym} ptr val _))
	// result: (MOVVgpfp val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpMIPS64MOVVgpfp)
		v.AddArg(val)
		return true
	}
	// match: (MOVDload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVDload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVDload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVDstore [off] {sym} ptr (MOVVgpfp val) mem)
	// result: (MOVVstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVgpfp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVVstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVDstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVDstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVFload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVFload [off] {sym} ptr (MOVWstore [off] {sym} ptr val _))
	// result: (MOVWgpfp val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVWstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpMIPS64MOVWgpfp)
		v.AddArg(val)
		return true
	}
	// match: (MOVFload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVFload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVFload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVFload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVFload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVFload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVFstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVFstore [off] {sym} ptr (MOVWgpfp val) mem)
	// result: (MOVWstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVWgpfp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVFstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVFstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVFstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVFstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVFstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVFstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVHUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHUload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVHUload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVHUload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVHUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHUreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVHUload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVHUreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg (MOVVconst [c]))
	// result: (MOVVconst [int64(uint16(c))])
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVHload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVHload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVHload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVVconst [int64(read16(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(read16(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHreg x:(MOVBload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVHload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVHreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (MOVVconst [c]))
	// result: (MOVVconst [int64(int16(c))])
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(int16(c)))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVHstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVHstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVHstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVVconst [0]) mem)
	// result: (MOVHstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpMIPS64MOVHstorezero)
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
		if v_1.Op != OpMIPS64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVHstore)
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
		if v_1.Op != OpMIPS64MOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVHstore)
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
		if v_1.Op != OpMIPS64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVHstore)
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
		if v_1.Op != OpMIPS64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVHstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHstorezero [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVHstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstorezero [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVHstorezero [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVVload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVVload [off] {sym} ptr (MOVDstore [off] {sym} ptr val _))
	// result: (MOVVfpgp val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVDstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpMIPS64MOVVfpgp)
		v.AddArg(val)
		return true
	}
	// match: (MOVVload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVVload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVVload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVVload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVVload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVVconst [int64(read64(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(read64(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVVnop(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVVnop (MOVVconst [c]))
	// result: (MOVVconst [c])
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVVreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVVreg x)
	// cond: x.Uses == 1
	// result: (MOVVnop x)
	for {
		x := v_0
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpMIPS64MOVVnop)
		v.AddArg(x)
		return true
	}
	// match: (MOVVreg (MOVVconst [c]))
	// result: (MOVVconst [c])
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVVstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVVstore [off] {sym} ptr (MOVVfpgp val) mem)
	// result: (MOVDstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVfpgp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVDstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVVstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVVstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVVstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVVstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVVstore [off] {sym} ptr (MOVVconst [0]) mem)
	// result: (MOVVstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpMIPS64MOVVstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVVstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVVstorezero [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVVstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVVstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVstorezero [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVVstorezero [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVVstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVWUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (MOVWUload [off] {sym} ptr (MOVFstore [off] {sym} ptr val _))
	// result: (ZeroExt32to64 (MOVWfpgp <typ.Float32> val))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVFstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpZeroExt32to64)
		v0 := b.NewValue0(v_1.Pos, OpMIPS64MOVWfpgp, typ.Float32)
		v0.AddArg(val)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWUload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVWUload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVWUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWUload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVWUload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVWUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVWUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWUreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVHUload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVWUload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVHUreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVWUreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg (MOVVconst [c]))
	// result: (MOVVconst [int64(uint32(c))])
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVWload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVWload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVVconst [int64(read32(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(read32(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWreg x:(MOVBload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVHload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVHUload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVWload {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVBUreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVHreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpMIPS64MOVWreg {
			break
		}
		v.reset(OpMIPS64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (MOVVconst [c]))
	// result: (MOVVconst [int64(int32(c))])
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(int32(c)))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWstore [off] {sym} ptr (MOVWfpgp val) mem)
	// result: (MOVFstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVWfpgp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVFstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVWstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVWstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVVconst [0]) mem)
	// result: (MOVWstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpMIPS64MOVWstorezero)
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
		if v_1.Op != OpMIPS64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVWstore)
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
		if v_1.Op != OpMIPS64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64MOVWstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWstorezero [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVWstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstorezero [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (MOVWstorezero [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(OpMIPS64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64NEGV(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGV (MOVVconst [c]))
	// result: (MOVVconst [-c])
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(-c)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64NOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NOR x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (NORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPS64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpMIPS64NORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64NORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NORconst [c] (MOVVconst [d]))
	// result: (MOVVconst [^(c|d)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(^(c | d))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64OR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (OR x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (ORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPS64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpMIPS64ORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (OR x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64ORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ORconst [-1] _)
	// result: (MOVVconst [-1])
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c|d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(c | d)
		return true
	}
	// match: (ORconst [c] (ORconst [d] x))
	// cond: is32Bit(c|d)
	// result: (ORconst [c|d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64ORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c | d)) {
			break
		}
		v.reset(OpMIPS64ORconst)
		v.AuxInt = int64ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SGT(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SGT (MOVVconst [c]) x)
	// cond: is32Bit(c)
	// result: (SGTconst [c] x)
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpMIPS64SGTconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SGT x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SGTU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SGTU (MOVVconst [c]) x)
	// cond: is32Bit(c)
	// result: (SGTUconst [c] x)
	for {
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpMIPS64SGTUconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SGTU x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SGTUconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SGTUconst [c] (MOVVconst [d]))
	// cond: uint64(c)>uint64(d)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(uint64(c) > uint64(d)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (MOVVconst [d]))
	// cond: uint64(c)<=uint64(d)
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(uint64(c) <= uint64(d)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTUconst [c] (MOVBUreg _))
	// cond: 0xff < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVBUreg || !(0xff < uint64(c)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (MOVHUreg _))
	// cond: 0xffff < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVHUreg || !(0xffff < uint64(c)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (ANDconst [m] _))
	// cond: uint64(m) < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		if !(uint64(m) < uint64(c)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (SRLVconst _ [d]))
	// cond: 0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64SRLVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SGTconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SGTconst [c] (MOVVconst [d]))
	// cond: c>d
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(c > d) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVVconst [d]))
	// cond: c<=d
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(c <= d) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVBreg _))
	// cond: 0x7f < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVBreg || !(0x7f < c) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVBreg _))
	// cond: c <= -0x80
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVBreg || !(c <= -0x80) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVBUreg _))
	// cond: 0xff < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVBUreg || !(0xff < c) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVBUreg _))
	// cond: c < 0
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVBUreg || !(c < 0) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVHreg _))
	// cond: 0x7fff < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVHreg || !(0x7fff < c) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVHreg _))
	// cond: c <= -0x8000
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVHreg || !(c <= -0x8000) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVHUreg _))
	// cond: 0xffff < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVHUreg || !(0xffff < c) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVHUreg _))
	// cond: c < 0
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVHUreg || !(c < 0) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVWUreg _))
	// cond: c < 0
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVWUreg || !(c < 0) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (ANDconst [m] _))
	// cond: 0 <= m && m < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		if !(0 <= m && m < c) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (SRLVconst _ [d]))
	// cond: 0 <= c && 0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64SRLVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(0 <= c && 0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SLLV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLLV _ (MOVVconst [c]))
	// cond: uint64(c)>=64
	// result: (MOVVconst [0])
	for {
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SLLV x (MOVVconst [c]))
	// result: (SLLVconst x [c])
	for {
		x := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpMIPS64SLLVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SLLVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLLVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [d<<uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(d << uint64(c))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SRAV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRAV x (MOVVconst [c]))
	// cond: uint64(c)>=64
	// result: (SRAVconst x [63])
	for {
		x := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpMIPS64SRAVconst)
		v.AuxInt = int64ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	// match: (SRAV x (MOVVconst [c]))
	// result: (SRAVconst x [c])
	for {
		x := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpMIPS64SRAVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SRAVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRAVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [d>>uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(d >> uint64(c))
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SRLV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRLV _ (MOVVconst [c]))
	// cond: uint64(c)>=64
	// result: (MOVVconst [0])
	for {
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLV x (MOVVconst [c]))
	// result: (SRLVconst x [c])
	for {
		x := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpMIPS64SRLVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SRLVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRLVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [int64(uint64(d)>>uint64(c))])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(d) >> uint64(c)))
		return true
	}
	return false
}
f
"""




```