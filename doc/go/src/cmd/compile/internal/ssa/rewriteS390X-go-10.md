Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `rewriteS390X.go` file. This file seems to contain rewrite rules for the SSA (Static Single Assignment) intermediate representation for the s390x architecture in the Go compiler.

Here's a breakdown of how to approach this:

1. **Identify the main purpose:** The code consists of functions named `rewriteValueS390X_Op...` and `rewriteBlockS390X`. These functions are clearly involved in rewriting SSA values and blocks for the s390x architecture.

2. **Analyze `rewriteValueS390X_Op...` functions:** Each of these functions handles a specific SSA operation (e.g., `OpS390XXORconst`, `OpS390XLoad`, `OpSelect0`). They attempt to match specific patterns in the SSA and replace them with more efficient or canonical forms.

3. **Analyze `rewriteBlockS390X` function:** This function handles rewriting control flow blocks. It seems to focus on optimizing conditional branches (`BlockS390XBRC`).

4. **Infer the goal of these rewrites:** The rewrites likely aim to:
    * **Optimize common patterns:**  Replace sequences of operations with single, more efficient instructions (e.g., using FMA instructions).
    * **Simplify expressions:**  Perform constant folding and other algebraic simplifications.
    * **Combine operations:** Fuse load/store operations with arithmetic operations.
    * **Canonicalize representations:** Ensure a consistent and predictable form for certain operations.
    * **Handle specific instruction properties:** Account for instruction limitations like immediate value ranges.

5. **Provide concrete examples:** For some of the simpler rewrites, it's possible to illustrate with Go code how the compiler might transform the code at the SSA level. This requires making assumptions about how Go code would be represented in SSA.

6. **Address potential pitfalls:**  Consider common mistakes that developers might make that could be affected by these rewrite rules (although this might be less directly evident from the provided snippet).

7. **Summarize the overall functionality:**  Combine the observations to provide a concise description of the code's role in the Go compilation process for the s390x architecture.

**Thinking about specific rewrites:**

* **`XORconst` and `XORWconst`:** These handle XORing with constants, potentially simplifying to `MOVDconst` if the operand is already a constant, or removing the operation if the constant is 0.
* **`XORload` and `XORWload`:** These appear to optimize XOR operations where one operand is loaded from memory, potentially folding address calculations.
* **`Select0` and `Select1`:** These handle extracting the first and second results from multi-value operations (like arithmetic with carry/borrow). They also seem to identify opportunities to use FMA (fused multiply-add) instructions.
* **`Store`:** This function selects the appropriate store instruction based on the data type and size.
* **`Zero`:** This optimizes zeroing out memory regions, using specialized instructions for different sizes and potentially breaking down large zeroing operations into smaller chunks.
* **`BRC`:** This block rewrite focuses on simplifying conditional branches based on comparison results. It tries to combine the comparison and branch into a single instruction where possible and handles different comparison operators and constant operands.

By analyzing these individual rewrite functions, we can build a comprehensive picture of the code's overall purpose.
这段Go语言代码是Go编译器中用于S390X架构的SSA（Static Single Assignment）重写规则的一部分，文件名是 `rewriteS390X.go`。  它定义了一系列的函数，这些函数负责在编译过程中，针对S390X架构的特性，对SSA中间表示进行优化和转换。

**主要功能归纳:**

这段代码的核心功能是**定义了一系列用于优化S390X架构的SSA重写规则**。这些规则针对特定的SSA操作符（OpCode）和操作数模式，将其转换为更高效或更符合S390X指令集的指令序列。

更具体地说，这些重写规则旨在：

1. **简化算术和逻辑运算:** 例如，将异或常量与常量加载合并为一个常量加载，消除与零异或的操作。
2. **优化内存访问:** 例如，合并地址计算到加载/存储指令中，利用S390X架构的寻址模式。
3. **利用S390X特定的指令:** 例如，使用`FMADD` (浮点乘加) 指令替换单独的乘法和加法操作。
4. **处理带进位/借位的算术运算:**  将高级的带进位/借位操作转换为S390X架构的底层指令序列。
5. **优化条件分支:**  将比较操作和条件分支合并为更紧凑的S390X条件跳转指令。
6. **优化内存清零操作:**  使用S390X的`CLEAR`指令或分解为更小的存储操作来高效地清零内存。

**具体功能举例说明 (带假设的输入与输出):**

**示例 1: 简化异或常量操作**

```go
// 假设 SSA 中的一个异或常量操作
// 输入: v 是一个 *Value，代表 XORconst 操作
//      v.AuxInt = 10 (十进制)
//      v.Args[0] 是一个 *Value，代表 MOVDconst 操作，其 v.Args[0].AuxInt = 5 (十进制)

// 匹配: (XORconst [c] (MOVDconst [d]))
// 结果: (MOVDconst [c^d])

func rewriteValueS390X_OpS390XXORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c^d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		return true
	}
	return false
}

// 假设输入的 SSA 操作如下:
// b1: v1 = MOVDconst [5]
// b1: v2 = XORconst [10] v1

// 重写后，v2 会被替换为:
// b1: v2 = MOVDconst [15]  // 5 ^ 10 = 15
```

**示例 2:  合并加载和异或操作**

```go
// 假设 SSA 中的一个异或加载操作
// 输入: v 是一个 *Value，代表 XORload 操作
//      v.AuxInt = 8 (偏移量)
//      v.Aux 是一个符号
//      v.Args[0] 是一个寄存器值
//      v.Args[1] 是一个 ADDconst 操作，代表指针加上一个常量偏移
//      v.Args[2] 是内存状态

// 匹配: (XORload [off1] {sym} x (ADDconst [off2] ptr) mem)
// 条件: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
// 结果: (XORload [off1+off2] {sym} x ptr mem)

func rewriteValueS390X_OpS390XXORload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (XORWload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XXORWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// ... 更多匹配模式 ...
	return false
}

// 假设输入的 SSA 操作如下:
// b1: v1 = ADDconst [4]  ptr  // ptr 是一个地址
// b1: v2 = XORload [8] {main.data} reg v1 mem

// 重写后，v2 可能会被替换为:
// b1: v2 = XORload [12] {main.data} reg ptr mem
```

**命令行参数处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 Go 编译器的前端和主流程中。这个文件定义的是在 SSA 生成之后，特定于 S390X 架构的优化规则。  不过，编译器的命令行参数可能会影响到 SSA 的生成方式，进而间接地影响到这里定义的重写规则是否会被触发和如何被触发。 例如，优化级别可能会影响某些优化的应用。

**使用者易犯错的点 (开发者角度):**

这段代码是 Go 编译器内部的一部分，通常不是 Go 语言开发者直接操作或修改的。  对于 Go 语言的使用者来说，**不容易犯错**，因为这些优化是编译器自动完成的。

然而，对于 **Go 编译器开发者** 来说，编写或修改这类重写规则时容易犯错的点包括：

* **条件判断错误:**  `cond` 中的逻辑必须精确，确保只在正确的条件下应用重写。
* **SSA 操作符理解偏差:** 需要准确理解每个 SSA 操作符的语义和输入输出。
* **S390X 指令集理解不足:** 需要熟悉 S390X 的指令特性、寻址模式和限制。
* **引入死循环:** 如果重写规则没有正确地收敛，可能会导致无限的重写循环。
* **破坏 SSA 形式:** 重写必须保证结果仍然是有效的 SSA 代码。
* **性能影响评估不准确:**  需要仔细评估重写规则对最终生成代码的性能影响，避免引入性能下降。

**作为第 11 部分，共 13 部分，它的功能归纳:**

考虑到这是整个 S390X 架构 SSA 重写过程的第 11 部分， 我们可以推断：

* **前序部分 (1-10):**  可能处理了更基础的 SSA 转换、通用的优化、或者与其他类型的 S390X 指令相关的重写规则。
* **后续部分 (12-13):** 可能会处理更高级的优化、代码生成相关的转换、或者特定边缘情况的处理。

因此，这第 11 部分可能专注于**中级的SSA优化和转换**， 涵盖了常见的算术、逻辑、内存访问操作的优化，并开始引入一些更具 S390X 架构特性的指令替换。 它在整个编译流程中扮演着将较为通用的 SSA 表示逐步转化为更贴近目标机器指令的关键角色。

总的来说， `rewriteS390X.go` 的这一部分是 Go 编译器为 S390X 架构生成高效机器码的关键组成部分，它通过一系列精细的重写规则，在 SSA 层面进行了深入的优化。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第11部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
xInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c) ^ d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XXORWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (XORWload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XXORWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (XORWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (XORWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XXORWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XXORconst(v *Value) bool {
	v_0 := v.Args[0]
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
	// match: (XORconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c^d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XXORload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (XOR x (LGDR <t> y))
	for {
		t := v.Type
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr1 := v_1
		if v_2.Op != OpS390XFMOVDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XXOR)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (XORload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (XORload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XXORload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (XORload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (XORload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XXORload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADDE x y (Select1 <types.TypeFlags> (ADDCconst c [-1]))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpS390XADDE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpS390XADDCconst, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2.AuxInt = int16ToAuxInt(-1)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Sub64borrow x y c))
	// result: (Select0 <typ.UInt64> (SUBE x y (Select1 <types.TypeFlags> (SUBC (MOVDconst [0]) c))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpS390XSUBE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpS390XSUBC, types.NewTuple(typ.UInt64, types.TypeFlags))
		v3 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v2.AddArg2(v3, c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 <t> (AddTupleFirst32 val tuple))
	// result: (ADDW val (Select0 <t> tuple))
	for {
		t := v.Type
		if v_0.Op != OpS390XAddTupleFirst32 {
			break
		}
		tuple := v_0.Args[1]
		val := v_0.Args[0]
		v.reset(OpS390XADDW)
		v0 := b.NewValue0(v.Pos, OpSelect0, t)
		v0.AddArg(tuple)
		v.AddArg2(val, v0)
		return true
	}
	// match: (Select0 <t> (AddTupleFirst64 val tuple))
	// result: (ADD val (Select0 <t> tuple))
	for {
		t := v.Type
		if v_0.Op != OpS390XAddTupleFirst64 {
			break
		}
		tuple := v_0.Args[1]
		val := v_0.Args[0]
		v.reset(OpS390XADD)
		v0 := b.NewValue0(v.Pos, OpSelect0, t)
		v0.AddArg(tuple)
		v.AddArg2(val, v0)
		return true
	}
	// match: (Select0 (ADDCconst (MOVDconst [c]) [d]))
	// result: (MOVDconst [c+int64(d)])
	for {
		if v_0.Op != OpS390XADDCconst {
			break
		}
		d := auxIntToInt16(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c + int64(d))
		return true
	}
	// match: (Select0 (SUBC (MOVDconst [c]) (MOVDconst [d])))
	// result: (MOVDconst [c-d])
	for {
		if v_0.Op != OpS390XSUBC {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0_1.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c - d)
		return true
	}
	// match: (Select0 (FADD (FMUL y z) x))
	// cond: x.Block.Func.useFMA(v)
	// result: (FMADD x y z)
	for {
		if v_0.Op != OpS390XFADD {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpS390XFMUL {
				continue
			}
			z := v_0_0.Args[1]
			y := v_0_0.Args[0]
			x := v_0_1
			if !(x.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpS390XFMADD)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (Select0 (FSUB (FMUL y z) x))
	// cond: x.Block.Func.useFMA(v)
	// result: (FMSUB x y z)
	for {
		if v_0.Op != OpS390XFSUB {
			break
		}
		x := v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XFMUL {
			break
		}
		z := v_0_0.Args[1]
		y := v_0_0.Args[0]
		if !(x.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpS390XFMSUB)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (Select0 (FADDS (FMULS y z) x))
	// cond: x.Block.Func.useFMA(v)
	// result: (FMADDS x y z)
	for {
		if v_0.Op != OpS390XFADDS {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpS390XFMULS {
				continue
			}
			z := v_0_0.Args[1]
			y := v_0_0.Args[0]
			x := v_0_1
			if !(x.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpS390XFMADDS)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (Select0 (FSUBS (FMULS y z) x))
	// cond: x.Block.Func.useFMA(v)
	// result: (FMSUBS x y z)
	for {
		if v_0.Op != OpS390XFSUBS {
			break
		}
		x := v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XFMULS {
			break
		}
		z := v_0_0.Args[1]
		y := v_0_0.Args[0]
		if !(x.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpS390XFMSUBS)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueS390X_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADDE (MOVDconst [0]) (MOVDconst [0]) (Select1 <types.TypeFlags> (ADDE x y (Select1 <types.TypeFlags> (ADDCconst c [-1]))))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpS390XADDE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XADDE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v4 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v5 := b.NewValue0(v.Pos, OpS390XADDCconst, types.NewTuple(typ.UInt64, types.TypeFlags))
		v5.AuxInt = int16ToAuxInt(-1)
		v5.AddArg(c)
		v4.AddArg(v5)
		v3.AddArg3(x, y, v4)
		v2.AddArg(v3)
		v0.AddArg3(v1, v1, v2)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Sub64borrow x y c))
	// result: (NEG (Select0 <typ.UInt64> (SUBE (MOVDconst [0]) (MOVDconst [0]) (Select1 <types.TypeFlags> (SUBE x y (Select1 <types.TypeFlags> (SUBC (MOVDconst [0]) c)))))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpS390XNEG)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpS390XSUBE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v4 := b.NewValue0(v.Pos, OpS390XSUBE, types.NewTuple(typ.UInt64, types.TypeFlags))
		v5 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v6 := b.NewValue0(v.Pos, OpS390XSUBC, types.NewTuple(typ.UInt64, types.TypeFlags))
		v6.AddArg2(v2, c)
		v5.AddArg(v6)
		v4.AddArg3(x, y, v5)
		v3.AddArg(v4)
		v1.AddArg3(v2, v2, v3)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (AddTupleFirst32 _ tuple))
	// result: (Select1 tuple)
	for {
		if v_0.Op != OpS390XAddTupleFirst32 {
			break
		}
		tuple := v_0.Args[1]
		v.reset(OpSelect1)
		v.AddArg(tuple)
		return true
	}
	// match: (Select1 (AddTupleFirst64 _ tuple))
	// result: (Select1 tuple)
	for {
		if v_0.Op != OpS390XAddTupleFirst64 {
			break
		}
		tuple := v_0.Args[1]
		v.reset(OpSelect1)
		v.AddArg(tuple)
		return true
	}
	// match: (Select1 (ADDCconst (MOVDconst [c]) [d]))
	// cond: uint64(c+int64(d)) >= uint64(c) && c+int64(d) == 0
	// result: (FlagEQ)
	for {
		if v_0.Op != OpS390XADDCconst {
			break
		}
		d := auxIntToInt16(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		if !(uint64(c+int64(d)) >= uint64(c) && c+int64(d) == 0) {
			break
		}
		v.reset(OpS390XFlagEQ)
		return true
	}
	// match: (Select1 (ADDCconst (MOVDconst [c]) [d]))
	// cond: uint64(c+int64(d)) >= uint64(c) && c+int64(d) != 0
	// result: (FlagLT)
	for {
		if v_0.Op != OpS390XADDCconst {
			break
		}
		d := auxIntToInt16(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		if !(uint64(c+int64(d)) >= uint64(c) && c+int64(d) != 0) {
			break
		}
		v.reset(OpS390XFlagLT)
		return true
	}
	// match: (Select1 (SUBC (MOVDconst [c]) (MOVDconst [d])))
	// cond: uint64(d) <= uint64(c) && c-d == 0
	// result: (FlagGT)
	for {
		if v_0.Op != OpS390XSUBC {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0_1.AuxInt)
		if !(uint64(d) <= uint64(c) && c-d == 0) {
			break
		}
		v.reset(OpS390XFlagGT)
		return true
	}
	// match: (Select1 (SUBC (MOVDconst [c]) (MOVDconst [d])))
	// cond: uint64(d) <= uint64(c) && c-d != 0
	// result: (FlagOV)
	for {
		if v_0.Op != OpS390XSUBC {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0_1.AuxInt)
		if !(uint64(d) <= uint64(c) && c-d != 0) {
			break
		}
		v.reset(OpS390XFlagOV)
		return true
	}
	return false
}
func rewriteValueS390X_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRADconst (NEG <t> x) [63])
	for {
		t := v.Type
		x := v_0
		v.reset(OpS390XSRADconst)
		v.AuxInt = uint8ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpS390XNEG, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpStore(v *Value) bool {
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
		v.reset(OpS390XFMOVDstore)
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
		v.reset(OpS390XFMOVSstore)
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
		v.reset(OpS390XMOVDstore)
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
		v.reset(OpS390XMOVWstore)
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
		v.reset(OpS390XMOVHstore)
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
		v.reset(OpS390XMOVBstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpSub32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Sub32F x y)
	// result: (Select0 (FSUBS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpS390XFSUBS, types.NewTuple(typ.Float32, types.TypeFlags))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpSub64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Sub64F x y)
	// result: (Select0 (FSUB x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpS390XFSUB, types.NewTuple(typ.Float64, types.TypeFlags))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpTrunc(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc x)
	// result: (FIDBR [5] x)
	for {
		x := v_0
		v.reset(OpS390XFIDBR)
		v.AuxInt = int8ToAuxInt(5)
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpZero(v *Value) bool {
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
	// result: (MOVBstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [2] destptr mem)
	// result: (MOVHstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [4] destptr mem)
	// result: (MOVWstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [8] destptr mem)
	// result: (MOVDstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVDstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [3] destptr mem)
	// result: (MOVBstoreconst [makeValAndOff(0,2)] destptr (MOVHstoreconst [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 2))
		v0 := b.NewValue0(v.Pos, OpS390XMOVHstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [5] destptr mem)
	// result: (MOVBstoreconst [makeValAndOff(0,4)] destptr (MOVWstoreconst [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v0 := b.NewValue0(v.Pos, OpS390XMOVWstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [6] destptr mem)
	// result: (MOVHstoreconst [makeValAndOff(0,4)] destptr (MOVWstoreconst [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v0 := b.NewValue0(v.Pos, OpS390XMOVWstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [7] destptr mem)
	// result: (MOVWstoreconst [makeValAndOff(0,3)] destptr (MOVWstoreconst [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 3))
		v0 := b.NewValue0(v.Pos, OpS390XMOVWstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s > 0 && s <= 1024
	// result: (CLEAR [makeValAndOff(int32(s), 0)] destptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s > 0 && s <= 1024) {
			break
		}
		v.reset(OpS390XCLEAR)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(s), 0))
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s > 1024
	// result: (LoweredZero [s%256] destptr (ADDconst <destptr.Type> destptr [(int32(s)/256)*256]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s > 1024) {
			break
		}
		v.reset(OpS390XLoweredZero)
		v.AuxInt = int64ToAuxInt(s % 256)
		v0 := b.NewValue0(v.Pos, OpS390XADDconst, destptr.Type)
		v0.AuxInt = int32ToAuxInt((int32(s) / 256) * 256)
		v0.AddArg(destptr)
		v.AddArg3(destptr, v0, mem)
		return true
	}
	return false
}
func rewriteBlockS390X(b *Block) bool {
	typ := &b.Func.Config.Types
	switch b.Kind {
	case BlockS390XBRC:
		// match: (BRC {c} x:(CMP _ _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMP {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPW _ _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPW {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPU _ _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPU {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPWU _ _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPWU {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPconst _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPWconst _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPUconst _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} x:(CMPWUconst _) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (BRC {c&^s390x.Unordered} x yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			x := b.Controls[0]
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, x)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMP x y) yes no)
		// result: (CGRJ {c&^s390x.Unordered} x y yes no)
		for b.Controls[0].Op == OpS390XCMP {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl2(BlockS390XCGRJ, x, y)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPW x y) yes no)
		// result: (CRJ {c&^s390x.Unordered} x y yes no)
		for b.Controls[0].Op == OpS390XCMPW {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl2(BlockS390XCRJ, x, y)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPU x y) yes no)
		// result: (CLGRJ {c&^s390x.Unordered} x y yes no)
		for b.Controls[0].Op == OpS390XCMPU {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl2(BlockS390XCLGRJ, x, y)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPWU x y) yes no)
		// result: (CLRJ {c&^s390x.Unordered} x y yes no)
		for b.Controls[0].Op == OpS390XCMPWU {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl2(BlockS390XCLRJ, x, y)
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPconst x [y]) yes no)
		// cond: y == int32( int8(y))
		// result: (CGIJ {c&^s390x.Unordered} x [ int8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(int8(y))) {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPWconst x [y]) yes no)
		// cond: y == int32( int8(y))
		// result: (CIJ {c&^s390x.Unordered} x [ int8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(int8(y))) {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPUconst x [y]) yes no)
		// cond: y == int32(uint8(y))
		// result: (CLGIJ {c&^s390x.Unordered} x [uint8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(uint8(y))) {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {c} (CMPWUconst x [y]) yes no)
		// cond: y == int32(uint8(y))
		// result: (CLIJ {c&^s390x.Unordered} x [uint8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(uint8(y))) {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c &^ s390x.Unordered)
			return true
		}
		// match: (BRC {s390x.Less} (CMPconst x [ 128]) yes no)
		// result: (CGIJ {s390x.LessOrEqual} x [ 127] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 128 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(127)
			b.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
			return true
		}
		// match: (BRC {s390x.Less} (CMPWconst x [ 128]) yes no)
		// result: (CIJ {s390x.LessOrEqual} x [ 127] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 128 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(127)
			b.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
			return true
		}
		// match: (BRC {s390x.LessOrEqual} (CMPconst x [-129]) yes no)
		// result: (CGIJ {s390x.Less} x [-128] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != -129 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.LessOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(-128)
			b.Aux = s390xCCMaskToAux(s390x.Less)
			return true
		}
		// match: (BRC {s390x.LessOrEqual} (CMPWconst x [-129]) yes no)
		// result: (CIJ {s390x.Less} x [-128] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != -129 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.LessOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(-128)
			b.Aux = s390xCCMaskToAux(s390x.Less)
			return true
		}
		// match: (BRC {s390x.Greater} (CMPconst x [-129]) yes no)
		// result: (CGIJ {s390x.GreaterOrEqual} x [-128] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != -129 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(-128)
			b.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
			return true
		}
		// match: (BRC {s390x.Greater} (CMPWconst x [-129]) yes no)
		// result: (CIJ {s390x.GreaterOrEqual} x [-128] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != -129 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(-128)
			b.Aux = s390xCCMaskToAux(s390x.GreaterOrEqual)
			return true
		}
		// match: (BRC {s390x.GreaterOrEqual} (CMPconst x [ 128]) yes no)
		// result: (CGIJ {s390x.Greater} x [ 127] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 128 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(127)
			b.Aux = s390xCCMaskToAux(s390x.Greater)
			return true
		}
		// match: (BRC {s390x.GreaterOrEqual} (CMPWconst x [ 128]) yes no)
		// result: (CIJ {s390x.Greater} x [ 127] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 128 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(127)
			b.Aux = s390xCCMaskToAux(s390x.Greater)
			return true
		}
		// match: (BRC {s390x.Less} (CMPWUconst x [256]) yes no)
		// result: (CLIJ {s390x.LessOrEqual} x [255] yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 256 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(255)
			b.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
			return true
		}
		// match: (BRC {s390x.Less} (CMPUconst x [256]) yes no)
		// result: (CLGIJ {s390x.LessOrEqual} x [255] yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 256 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(255)
			b.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
			return true
		}
		// match: (BRC {s390x.GreaterOrEqual} (CMPWUconst x [256]) yes no)
		// result: (CLIJ {s390x.Greater} x [255] yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 256 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(255)
			b.Aux = s390xCCMaskToAux(s390x.Greater)
			return true
		}
		// match: (BRC {s390x.GreaterOrEqual} (CMPUconst x [256]) yes no)
		// result: (CLGIJ {s390x.Greater} x [255] yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 256 {
				break
			}
			x := v_0.Args[0]
			if auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(255)
			b.Aux = s390xCCMaskToAux(s390x.Greater)
			return true
		}
		// match: (BRC {c} (CMPconst x [y]) yes no)
		// cond: y == int32(uint8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)
		// result: (CLGIJ {c} x [uint8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(uint8(y)) && (c == s390x.
```