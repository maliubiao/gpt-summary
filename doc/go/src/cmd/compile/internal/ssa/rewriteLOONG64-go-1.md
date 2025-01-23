Response: The user wants a summary of the functionality of the provided Go code snippet. This code seems to be part of the compiler's intermediate representation (SSA) rewriting rules for the LOONG64 architecture.

The code consists of multiple functions named `rewriteValueLOONG64_Op...`. Each function handles the optimization of a specific LOONG64 assembly instruction (`OpLOONG64...`). These optimizations involve pattern matching on the operands of the instruction and replacing it with a more efficient equivalent sequence of operations or a simpler instruction.

To summarize, I need to iterate through each function and identify the kind of optimizations it performs. The optimizations generally fall into categories like:

1. **Constant folding:** Performing arithmetic or logical operations on constants at compile time.
2. **Algebraic simplification:** Applying algebraic identities to simplify expressions.
3. **Instruction selection:** Replacing a sequence of operations with a single, more efficient instruction.
4. **Address mode optimization:** Combining address calculations to reduce the number of instructions.
5. **Redundancy elimination:** Removing unnecessary moves or operations.

Let's go through the functions one by one:

- `rewriteValueLOONG64_OpLOONG64MOVBstorezero`: Optimizes storing a zero byte. It handles cases where the address is calculated with an offset, a symbol, or an indexed addressing mode.
- `rewriteValueLOONG64_OpLOONG64MOVBstorezeroidx`:  Optimizes storing a zero byte with indexed addressing, particularly when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVDload`: Optimizes loading a double word, including cases with offsets, symbols, and indexed addressing. It also has a case to recognize loading a value that was just stored.
- `rewriteValueLOONG64_OpLOONG64MOVDloadidx`: Optimizes double word loads with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVDstore`: Optimizes storing a double word, including cases with offsets, symbols, and indexed addressing. It also handles storing a value that was converted from a floating-point register.
- `rewriteValueLOONG64_OpLOONG64MOVDstoreidx`: Optimizes double word stores with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVFload`: Optimizes loading a single-precision floating-point value, including cases with offsets, symbols, and indexed addressing. It also has a case to recognize loading a value that was just stored.
- `rewriteValueLOONG64_OpLOONG64MOVFloadidx`: Optimizes single-precision float loads with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVFstore`: Optimizes storing a single-precision floating-point value, including cases with offsets, symbols, and indexed addressing. It also handles storing a value that was converted from a general-purpose register.
- `rewriteValueLOONG64_OpLOONG64MOVFstoreidx`: Optimizes single-precision float stores with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVHUload`: Optimizes loading an unsigned half-word, including cases with offsets, symbols, and indexed addressing.
- `rewriteValueLOONG64_OpLOONG64MOVHUloadidx`: Optimizes unsigned half-word loads with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVHUreg`: Optimizes moving an unsigned half-word between registers. It handles cases where the source is a bitfield extract, a smaller load, or a constant.
- `rewriteValueLOONG64_OpLOONG64MOVHload`: Optimizes loading a signed half-word, including cases with offsets, symbols, and indexed addressing.
- `rewriteValueLOONG64_OpLOONG64MOVHloadidx`: Optimizes signed half-word loads with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVHreg`: Optimizes moving a signed half-word between registers. It handles cases where the source is a smaller load or a constant.
- `rewriteValueLOONG64_OpLOONG64MOVHstore`: Optimizes storing a half-word, including cases with offsets, symbols, and indexed addressing. It also handles storing zero or a value that was extended from a smaller size.
- `rewriteValueLOONG64_OpLOONG64MOVHstoreidx`: Optimizes half-word stores with indexed addressing, especially when the index is a constant or the value being stored is zero.
- `rewriteValueLOONG64_OpLOONG64MOVHstorezero`: Optimizes storing a zero half-word, including cases with offsets, symbols, and indexed addressing.
- `rewriteValueLOONG64_OpLOONG64MOVHstorezeroidx`: Optimizes storing a zero half-word with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVVload`: Optimizes loading a general-purpose register value, including cases with offsets, symbols, and indexed addressing. It also has a case to recognize loading a value that was just stored.
- `rewriteValueLOONG64_OpLOONG64MOVVloadidx`: Optimizes general-purpose register loads with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVVnop`: Optimizes a no-operation move by simplifying it if the source is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVVreg`: Optimizes moving a general-purpose register value, particularly removing redundant moves or simplifying moves from constants.
- `rewriteValueLOONG64_OpLOONG64MOVVstore`: Optimizes storing a general-purpose register value, including cases with offsets, symbols, and indexed addressing. It also handles storing zero or a value that was moved from a floating-point register.
- `rewriteValueLOONG64_OpLOONG64MOVVstoreidx`: Optimizes general-purpose register stores with indexed addressing, especially when the index is a constant or the value being stored is zero.
- `rewriteValueLOONG64_OpLOONG64MOVVstorezero`: Optimizes storing a zero value to memory, including cases with offsets, symbols, and indexed addressing.
- `rewriteValueLOONG64_OpLOONG64MOVVstorezeroidx`: Optimizes storing a zero value with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVWUload`: Optimizes loading an unsigned word, including cases with offsets, symbols, and indexed addressing. It also handles loading a value that was just stored as a float.
- `rewriteValueLOONG64_OpLOONG64MOVWUloadidx`: Optimizes unsigned word loads with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVWUreg`: Optimizes moving an unsigned word between registers. It handles cases where the source is a bitfield extract, a smaller load, or a constant.
- `rewriteValueLOONG64_OpLOONG64MOVWload`: Optimizes loading a signed word, including cases with offsets, symbols, and indexed addressing.
- `rewriteValueLOONG64_OpLOONG64MOVWloadidx`: Optimizes signed word loads with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MOVWreg`: Optimizes moving a signed word between registers. It handles cases where the source is a smaller load or a constant.
- `rewriteValueLOONG64_OpLOONG64MOVWstore`: Optimizes storing a word, including cases with offsets, symbols, and indexed addressing. It also handles storing a float or zero or a value that was extended from a smaller size.
- `rewriteValueLOONG64_OpLOONG64MOVWstoreidx`: Optimizes word stores with indexed addressing, especially when the index is a constant or the value being stored is zero.
- `rewriteValueLOONG64_OpLOONG64MOVWstorezero`: Optimizes storing a zero word, including cases with offsets, symbols, and indexed addressing.
- `rewriteValueLOONG64_OpLOONG64MOVWstorezeroidx`: Optimizes storing a zero word with indexed addressing, especially when the index is a constant.
- `rewriteValueLOONG64_OpLOONG64MULV`: Optimizes multiplication operations, particularly when one operand is a constant (like -1, 0, 1, or a power of two).
- `rewriteValueLOONG64_OpLOONG64NEGV`: Optimizes negation operations, especially when negating a constant.
- `rewriteValueLOONG64_OpLOONG64NOR`: Optimizes NOR operations by converting them to constant operations when one operand is a constant.
- `rewriteValueLOONG64_OpLOONG64NORconst`: Optimizes NOR operations with a constant by performing the operation at compile time if the other operand is also a constant.
- `rewriteValueLOONG64_OpLOONG64OR`: Optimizes OR operations by converting them to constant operations when one operand is a constant, and also handles the case where both operands are the same.
- `rewriteValueLOONG64_OpLOONG64ORconst`: Optimizes OR operations with a constant, especially for identity and annihilation cases.
这段代码是Go语言编译器针对LOONG64架构进行优化的一个环节，主要功能是对中间表示（SSA）中的特定操作进行重写，以生成更高效的机器码。

**具体来说，这段代码实现了以下几类优化：**

1. **存储零值的优化:**  针对 `MOVBstorezero`, `MOVHstorezero`, `MOVVstorezero`, `MOVWstorezero` 这类将零值存储到内存的操作，尝试将地址计算中的常量偏移、符号信息合并，并将其转换为更简洁的 `...storezero` 或 `...storezeroidx` 指令。

2. **加载和存储指令的优化:**  针对各种加载 (`MOVBload`, `MOVHload`, `MOVWload`, `MOVDload`, `MOVFload`, `MOVHUload`, `MOVWUload`, `MOVVload`) 和存储 (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVDstore`, `MOVFstore`, `MOVVstore`) 指令，进行以下优化：
    * **地址计算合并:** 将地址计算中的常量偏移(`ADDVconst`) 或地址加载 (`MOVVaddr`) 与存储/加载指令本身的偏移合并，减少指令数量。例如，将 `MOVBstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem`  优化为 `MOVBstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem`。
    * **索引寻址优化:**  将带有常量偏移为 0 的加法地址计算 `(ADDV ptr idx)` 转换为使用索引寻址模式的指令，例如 `MOVBstoreidx ptr idx val mem`。
    * **冗余存储后立即加载的消除:**  如果一个加载指令紧跟着对相同地址的存储指令，并且存储的值可以直接使用，则用存储的值替换加载指令，例如 `MOVDload [off] {sym} ptr (MOVVstore [off] {sym} ptr val _)` 被替换为 `MOVVgpfp val`。
    * **类型转换优化:** 针对浮点数和整数寄存器之间的移动，以及不同大小整数之间的移动进行优化，例如 `MOVDstore` 指令在源操作数为 `MOVVgpfp` 时，可以直接转换为 `MOVVstore`。

3. **寄存器移动的优化:** 针对寄存器移动指令 (`MOVHreg`, `MOVHUreg`, `MOVWreg`, `MOVWUreg`, `MOVVreg`)，主要进行以下优化：
    * **零扩展或符号扩展优化:** 当源操作是较小的加载指令 (`MOVBload`, `MOVBUload`, `MOVHload`, `MOVHUload`, `MOVWUload`) 或扩展指令 (`MOVBUreg`, `MOVHUreg`, `MOVWUreg`) 时，直接使用源操作的结果，避免额外的移动。
    * **位域提取优化:** 将部分移位操作 (`SRLVconst`) 转换为位域提取指令 (`BSTRPICKV`)。
    * **常量优化:**  如果源操作是常量，则直接生成目标类型的常量。
    * **冗余移动消除:** 如果 `MOVVreg` 的结果只被使用一次，则直接用源操作替换，相当于做了一个别名。

4. **算术和逻辑运算的优化:**
    * **乘法优化:** 针对乘以 -1 (转换为取反 `NEGV`)，0 (结果为 0)，1 (结果为原值)，以及 2 的幂次方 (转换为左移 `SLLVconst`) 的乘法进行优化。
    * **取反优化:**  对常量进行取反时，直接计算结果常量。
    * **逻辑运算优化:**  针对 `NOR` 和 `OR` 运算，当其中一个操作数为常量时，将其转换为对应的常量操作指令 (`NORconst`, `ORconst`)，并在两个操作数都是常量时，直接计算结果。
    * **OR 运算的恒等律:**  当 `OR` 运算的两个操作数相同时，结果为操作数本身。

**可以推理出它是什么go语言功能的实现:**

这段代码是 **Go 语言编译器的后端代码生成部分**，负责将与体系结构无关的中间表示（SSA）转换为特定于 LOONG64 架构的高效机器码。 具体来说，它属于 **SSA 重写规则** 的一部分，这些规则在编译过程中被应用，用于优化生成的代码。

**Go代码举例说明 (假设的输入与输出):**

```go
package main

func main() {
	var x int64 = 10
	var y int64 = 0
	// ... 某些操作后 ...
	y = x * 8 // 乘法，可以被优化为左移
}
```

**假设的 SSA 输入 (针对 `y = x * 8`):**

```
v1 = LOONG64MOVVreg x
v2 = LOONG64MOVVconst [8]
v3 = LOONG64MULV v1 v2
// ... 后续存储 v3 到 y 的操作
```

**这段代码中 `rewriteValueLOONG64_OpLOONG64MULV` 函数会匹配到 `LOONG64MULV v1 v2` 并且 `v2` 是 2 的幂次方，然后将其重写为:**

**假设的 SSA 输出:**

```
v1 = LOONG64MOVVreg x
v3 = LOONG64SLLVconst [3] v1 // 8 的对数是 3
// ... 后续存储 v3 到 y 的操作
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。 命令行参数的处理通常发生在编译器的前端或驱动程序中。 然而，代码中的一些条件判断，例如 `config.ctxt.Flag_dynlink`，可能会受到编译时命令行参数的影响。 例如，如果编译时指定了动态链接，则 `Flag_dynlink` 会被设置，从而影响某些重写规则是否生效 (例如，避免在动态链接的代码中使用某些地址模式优化)。

**使用者易犯错的点:**

普通 Go 语言开发者不会直接接触到这部分代码，因此不存在使用者易犯错的点。这是编译器内部的实现细节。

**归纳一下它的功能 (作为第2部分):**

这段代码的主要功能是 **针对 LOONG64 架构的 SSA 指令进行基于模式匹配的优化和转换**。 它通过识别特定的指令序列和操作数特征，并将其替换为更有效的指令或指令序列，从而提升最终生成机器码的性能。 涵盖了存储零值、加载和存储操作的地址计算优化、寄存器移动的简化、以及基本算术和逻辑运算的常量折叠等多种优化策略。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteLOONG64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
2(ptr, mem)
		return true
	}
	// match: (MOVBstorezero [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstorezero [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstorezero [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBstorezeroidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVBstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBstorezeroidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstorezeroidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVBstorezero [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstorezeroidx (MOVVconst [c]) idx mem)
	// cond: is32Bit(c)
	// result: (MOVBstorezero [int32(c)] idx mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVDload(v *Value) bool {
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
		if v_1.Op != OpLOONG64MOVVstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpLOONG64MOVVgpfp)
		v.AddArg(val)
		return true
	}
	// match: (MOVDload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVDload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVDloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVDloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVDloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDloadidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVDload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVDload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDloadidx (MOVVconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVDload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVDload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVDstore(v *Value) bool {
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
		if v_1.Op != OpLOONG64MOVVgpfp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVDstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
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
		v.reset(OpLOONG64MOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off] {sym} (ADDV ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVDstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVDstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVDstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstoreidx ptr (MOVVconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVDstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstoreidx (MOVVconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVDstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVFload(v *Value) bool {
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
		if v_1.Op != OpLOONG64MOVWstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpLOONG64MOVWgpfp)
		v.AddArg(val)
		return true
	}
	// match: (MOVFload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVFload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVFload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVFload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVFload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVFload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVFload [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVFloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVFloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVFloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVFloadidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVFload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVFload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVFloadidx (MOVVconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVFload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVFload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVFstore(v *Value) bool {
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
		if v_1.Op != OpLOONG64MOVWgpfp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVFstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVFstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVFstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVFstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVFstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
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
		v.reset(OpLOONG64MOVFstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVFstore [off] {sym} (ADDV ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVFstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVFstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVFstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVFstoreidx ptr (MOVVconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVFstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVFstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVFstoreidx (MOVVconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVFstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVFstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHUload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHUload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHUload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUload [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHUloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVHUloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHUloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHUloadidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVHUload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVHUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUloadidx (MOVVconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVHUload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVHUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHUreg (SRLVconst [rc] x))
	// cond: rc < 16
	// result: (BSTRPICKV [rc + (15+rc)<<6] x)
	for {
		if v_0.Op != OpLOONG64SRLVconst {
			break
		}
		rc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(rc < 16) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc + (15+rc)<<6)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVHUload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVHUreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg (SLLVconst [lc] x))
	// cond: lc >= 16
	// result: (MOVVconst [0])
	for {
		if v_0.Op != OpLOONG64SLLVconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		if !(lc >= 16) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVHUreg (MOVVconst [c]))
	// result: (MOVVconst [int64(uint16(c))])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVHloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHloadidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVHload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVHload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHloadidx (MOVVconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVHload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVHload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHreg x:(MOVBload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVHload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVHreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (MOVVconst [c]))
	// result: (MOVVconst [int64(int16(c))])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(int16(c)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
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
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVHstore)
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
		if v_1.Op != OpLOONG64MOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVHstore)
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
		if v_1.Op != OpLOONG64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVHstore)
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
		if v_1.Op != OpLOONG64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVVconst [0]) mem)
	// result: (MOVHstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpLOONG64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} (ADDV ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVHstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreidx ptr (MOVVconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVHstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstoreidx (MOVVconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVHstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVVconst [0]) mem)
	// result: (MOVHstorezeroidx ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpLOONG64MOVVconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpLOONG64MOVHstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHstorezero [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstorezero [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVHstorezero [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstorezero [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVHstorezeroidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVHstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVHstorezeroidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstorezeroidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVHstorezero [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstorezeroidx (MOVVconst [c]) idx mem)
	// cond: is32Bit(c)
	// result: (MOVHstorezero [int32(c)] idx mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVVload(v *Value) bool {
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
		if v_1.Op != OpLOONG64MOVDstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpLOONG64MOVVfpgp)
		v.AddArg(val)
		return true
	}
	// match: (MOVVload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVVload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVVload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVVload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVVload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVload [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVVloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVVloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVVloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVVloadidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVVload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVVload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVloadidx (MOVVconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVVload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVVload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVVnop(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVVnop (MOVVconst [c]))
	// result: (MOVVconst [c])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVVreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVVreg x)
	// cond: x.Uses == 1
	// result: (MOVVnop x)
	for {
		x := v_0
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpLOONG64MOVVnop)
		v.AddArg(x)
		return true
	}
	// match: (MOVVreg (MOVVconst [c]))
	// result: (MOVVconst [c])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVVstore(v *Value) bool {
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
		if v_1.Op != OpLOONG64MOVVfpgp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVDstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVVstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVVstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVVstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVVstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
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
		v.reset(OpLOONG64MOVVstore)
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
		if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpLOONG64MOVVstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVstore [off] {sym} (ADDV ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVVstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVVstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVVstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVVstoreidx ptr (MOVVconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVVstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVVstoreidx (MOVVconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVVstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (MOVVstoreidx ptr idx (MOVVconst [0]) mem)
	// result: (MOVVstorezeroidx ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpLOONG64MOVVconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpLOONG64MOVVstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVVstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVVstorezero [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVVstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVVstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVstorezero [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVVstorezero [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVVstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVstorezero [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVVstorezeroidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVVstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVVstorezeroidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVVstorezeroidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVVstorezero [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVVstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVVstorezeroidx (MOVVconst [c]) idx mem)
	// cond: is32Bit(c)
	// result: (MOVVstorezero [int32(c)] idx mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVVstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWUload(v *Value) bool {
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
		if v_1.Op != OpLOONG64MOVFstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpZeroExt32to64)
		v0 := b.NewValue0(v_1.Pos, OpLOONG64MOVWfpgp, typ.Float32)
		v0.AddArg(val)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWUload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWUload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVWUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWUload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWUload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVWUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWUload [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWUloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVWUloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWUloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWUloadidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVWUload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVWUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWUloadidx (MOVVconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVWUload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVWUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWUreg (SRLVconst [rc] x))
	// cond: rc < 32
	// result: (BSTRPICKV [rc + (31+rc)<<6] x)
	for {
		if v_0.Op != OpLOONG64SRLVconst {
			break
		}
		rc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(rc < 32) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc + (31+rc)<<6)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVHUload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVWUload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVHUreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVWUreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg (SLLVconst [lc] x))
	// cond: lc >= 32
	// result: (MOVVconst [0])
	for {
		if v_0.Op != OpLOONG64SLLVconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		if !(lc >= 32) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVWUreg (MOVVconst [c]))
	// result: (MOVVconst [int64(uint32(c))])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVWloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWloadidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVWload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVWload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWloadidx (MOVVconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVWload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVWload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWreg x:(MOVBload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVHload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVHUload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVWload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVHreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVWreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (MOVVconst [c]))
	// result: (MOVVconst [int64(int32(c))])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(int32(c)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWstore(v *Value) bool {
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
		if v_1.Op != OpLOONG64MOVWfpgp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVFstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
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
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVWstore)
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
		if v_1.Op != OpLOONG64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVVconst [0]) mem)
	// result: (MOVWstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpLOONG64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} (ADDV ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVWstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreidx ptr (MOVVconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVWstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstoreidx (MOVVconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVWstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (MOVVconst [0]) mem)
	// result: (MOVWstorezeroidx ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpLOONG64MOVVconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpLOONG64MOVWstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVWstorezero [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstorezero [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVWstorezero [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstorezero [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVWstorezeroidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVWstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVWstorezeroidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstorezeroidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVWstorezero [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstorezeroidx (MOVVconst [c]) idx mem)
	// cond: is32Bit(c)
	// result: (MOVWstorezero [int32(c)] idx mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MULV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULV x (MOVVconst [-1]))
	// result: (NEGV x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != -1 {
				continue
			}
			v.reset(OpLOONG64NEGV)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MULV _ (MOVVconst [0]))
	// result: (MOVVconst [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
				continue
			}
			v.reset(OpLOONG64MOVVconst)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (MULV x (MOVVconst [1]))
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != 1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (MULV x (MOVVconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (SLLVconst [log64(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpLOONG64SLLVconst)
			v.AuxInt = int64ToAuxInt(log64(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MULV (MOVVconst [c]) (MOVVconst [d]))
	// result: (MOVVconst [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLOONG64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpLOONG64MOVVconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpLOONG64MOVVconst)
			v.AuxInt = int64ToAuxInt(c * d)
			return true
		}
		break
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64NEGV(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGV (MOVVconst [c]))
	// result: (MOVVconst [-c])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(-c)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64NOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NOR x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (NORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpLOONG64NORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64NORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NORconst [c] (MOVVconst [d]))
	// result: (MOVVconst [^(c|d)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(^(c | d))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64OR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (OR x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (ORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpLOONG64ORconst)
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
func rewriteValueLOONG64_OpLOONG64ORconst(v *Value) bool {
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
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
```