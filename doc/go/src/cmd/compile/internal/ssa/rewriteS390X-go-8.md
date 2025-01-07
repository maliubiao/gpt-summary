Response:
My thinking process to answer the question about the provided Go code snippet goes like this:

1. **Understand the Context:** The prompt clearly states this is part of `go/src/cmd/compile/internal/ssa/rewriteS390X.go`. This immediately tells me it's related to the Go compiler's intermediate representation (SSA) and specifically targets the S390X architecture. The "rewrite" part suggests this code aims to optimize or transform SSA instructions. The "Part 9 of 13" indicates this is a section within a larger file.

2. **Analyze the Code Structure:** The code consists of several Go functions, all named `rewriteValueS390X_Op...`. The `Op` part strongly suggests these functions handle specific SSA operations for the S390X architecture. Each function takes a `*Value` as input, which represents an SSA value/instruction. They all return a `bool`, likely indicating whether a rewrite rule was applied.

3. **Examine Individual Rewrite Functions:** I'll go through each function to understand its purpose:

    * **`rewriteValueS390X_OpS390XMULLDload(v *Value) bool`:** This function seems to optimize `MULLDload` (Multiply Double Load) operations. It looks for specific patterns:
        * Multiplying with a value loaded from memory where the load is immediately preceded by a floating-point store to the *same* memory location. It replaces this with a `MULLD` (Multiply Double) operation with a direct load of the stored value.
        * Multiplying with a value loaded from a memory address calculated by adding a constant offset. It folds the constant offsets.
        * Multiplying with a value loaded from a memory address with a symbol and offset. It merges the symbols and offsets if possible.

    * **`rewriteValueS390X_OpS390XMULLW(v *Value) bool`:** This handles `MULLW` (Multiply Word) operations.
        * It optimizes multiplication by a constant by transforming it into `MULLWconst`.
        * It looks for `MULLW` where one operand is a direct `MOVWload` or `MOVWZload` and tries to combine them into a `MULLWload` if certain conditions are met (memory access constraints, clobbering).

    * **`rewriteValueS390X_OpS390XMULLWconst(v *Value) bool`:** This deals with `MULLWconst` (Multiply Word by Constant).
        * It optimizes multiplication by constants that are "near" powers of two by rewriting them using shifts and adds/subs. This leverages the S390X instruction set's efficiency with shifts.
        * It optimizes multiplying a constant by another constant by performing the multiplication directly.

    * **`rewriteValueS390X_OpS390XMULLWload(v *Value) bool`:**  Similar to `MULLDload`, this optimizes `MULLWload` by folding constant offsets and merging symbols.

    * **`rewriteValueS390X_OpS390XNEG(v *Value) bool`:** This handles the `NEG` (Negate) operation.
        * It negates constant values directly.
        * It simplifies negation of `ADDconst` with a negated operand.

    * **`rewriteValueS390X_OpS390XNEGW(v *Value) bool`:**  Handles `NEGW` (Negate Word), negating constants.

    * **`rewriteValueS390X_OpS390XNOT(v *Value) bool`:**  Handles the bitwise `NOT` operation, implementing it using `XOR` with a constant -1.

    * **`rewriteValueS390X_OpS390XNOTW(v *Value) bool`:** Handles bitwise `NOTW` (NOT Word), using `XORWconst` with -1.

    * **`rewriteValueS390X_OpS390XOR(v *Value) bool`:** Handles bitwise `OR` operations.
        * Optimizes `OR` with a constant.
        * Looks for specific floating-point manipulation patterns involving `LGDR` and `LPDFR`.
        * Optimizes `OR` of two constants.
        * Simplifies `OR` of a value with itself.
        * Combines `OR` with a subsequent `MOVDload` into an `ORload`.

    * **`rewriteValueS390X_OpS390XORW(v *Value) bool`:**  Handles bitwise `ORW` (OR Word). Similar optimizations as `OR`, but for word-sized operations.

    * **`rewriteValueS390X_OpS390XORWconst(v *Value) bool`:** Optimizes `ORWconst` (OR Word with Constant) operations.

    * **`rewriteValueS390X_OpS390XORWload(v *Value) bool`:** Optimizes `ORWload` by folding offsets and merging symbols.

    * **`rewriteValueS390X_OpS390XORconst(v *Value) bool`:** Optimizes `ORconst` (OR with Constant).

    * **`rewriteValueS390X_OpS390XORload(v *Value) bool`:** Optimizes `ORload` operations, similar to `MULLDload` by looking for store-load pairs and folding address calculations.

    * **`rewriteValueS390X_OpS390XRISBGZ(v *Value) bool`:** This function appears to optimize the `RISBGZ` (Rotate and Insert Selected Bits General, then Zero) instruction, which is a powerful bit manipulation instruction on S390X. It looks for patterns involving other bitwise operations (`MOVWZreg`, `MOVHZreg`, `MOVBZreg`, shifts, other `RISBGZ` instructions) to simplify or combine them.

    * **`rewriteValueS390X_OpS390XRLL(v *Value) bool`:** Handles `RLL` (Rotate Left Logical) by converting rotations by constant amounts to `RLLconst`.

    * **`rewriteValueS390X_OpS390XRLLG(v *Value) bool`:** Handles `RLLG` (Rotate Left Logical General) by converting rotations by constants to `RISBGZ`.

    * **`rewriteValueS390X_OpS390XSLD(v *Value) bool`:** Handles `SLD` (Shift Left Double). It optimizes shifts by constants, simplifies shifts after masking operations, and removes redundant moves.

    * **`rewriteValueS390X_OpS390XSLDconst(v *Value) bool`:** Optimizes `SLDconst` (Shift Left Double by Constant) by combining it with `SRDconst` and other `RISBGZ` operations.

    * **`rewriteValueS390X_OpS390XSLW(v *Value) bool`:** Handles `SLW` (Shift Left Word). Similar optimizations to `SLD` but for word size.

4. **Infer Overall Functionality:** Based on the individual function analysis, the primary function of this code is to **optimize SSA code for the S390X architecture**. This involves recognizing common patterns of operations and replacing them with more efficient equivalent sequences of instructions. This includes:

    * **Constant folding:** Performing arithmetic or logical operations on constants at compile time.
    * **Instruction selection:** Choosing more specific or efficient S390X instructions for certain operations.
    * **Memory access optimization:** Combining load and store operations, folding address calculations.
    * **Bit manipulation optimization:** Simplifying and combining bitwise operations, leveraging the `RISBGZ` instruction.
    * **Redundancy elimination:** Removing unnecessary move or conversion operations.

5. **Provide Examples (Mental Simulation):**  While the prompt asks for Go code examples, constructing a full runnable program that demonstrates these specific SSA rewrites is complex as it requires interacting with the Go compiler's internals. However, I can mentally simulate some basic scenarios:

    * **`MULLDload` example:** Imagine Go code like `x * (*float64)(p)`. If the compiler sees a store to `p` right before this load, this rewrite might turn it into a direct `MULLD` with the stored value.
    * **`MULLWconst` example:**  `x * 8` could be rewritten using shift instructions (`x << 3`).
    * **`OR` example:** `x | 0xFF` could become an `ORconst` instruction.

6. **Address Other Points in the Prompt:**

    * **Go Language Feature:** This code directly implements optimizations for the S390X backend of the Go compiler. It doesn't implement a specific high-level Go language feature.
    * **Command-line Arguments:** This code doesn't directly handle command-line arguments. The Go compiler itself handles those, and this code operates within the compilation pipeline.
    * **User Mistakes:** Users don't directly interact with this code. Potential mistakes happen at the Go language level, which this code *helps* optimize away.

7. **Summarize the Functionality (as requested for Part 9):**  Given it's part 9, and the focus has been on arithmetic and logical operations, I'd summarize that this section focuses on **optimizing arithmetic (multiplication, negation) and bitwise logical operations (NOT, OR) for the S390X architecture within the Go compiler's SSA framework.** It aims to improve performance by simplifying expressions, using more efficient instructions, and optimizing memory access patterns related to these operations. The significant focus on `RISBGZ` highlights its importance for bit manipulation on S390X.

By following these steps, I can arrive at a comprehensive and accurate answer that addresses all aspects of the prompt, even without directly running the code. The key is to understand the context, analyze the structure, deduce the purpose of individual functions, and then generalize to the overall functionality.
这个Go语言代码文件 `go/src/cmd/compile/internal/ssa/rewriteS390X.go` 的一部分，主要负责 **S390X 架构下 Go 语言代码的 SSA (Static Single Assignment) 中间表示的重写规则**。

简单来说，它的功能是 **针对 S390X 架构，对 Go 编译器生成的中间代码进行优化**。它通过模式匹配的方式，找到一些可以被更高效的指令或指令序列替代的 SSA 操作，从而提升最终生成的可执行程序的性能。

**具体功能归纳 (针对提供的第 9 部分):**

这部分代码主要定义了针对以下 S390X SSA 操作的重写规则：

* **`OpS390XMULLDload` (双字乘法加载):**  尝试优化双字乘法后跟加载操作的场景。
* **`OpS390XMULLW` (字乘法):**  优化字乘法操作，包括与常数的乘法和与内存加载值的乘法。
* **`OpS390XMULLWconst` (字乘法常量):** 优化字乘法常量的操作，利用移位和加减法来替换乘法。
* **`OpS390XMULLWload` (字乘法加载):** 尝试优化字乘法后跟加载操作的场景。
* **`OpS390XNEG` (取反):** 优化取反操作，特别是针对常数和特定模式的取反。
* **`OpS390XNEGW` (字取反):** 优化字取反操作，特别是针对常数。
* **`OpS390XNOT` (按位取反):** 将按位取反操作替换为与 -1 进行异或操作。
* **`OpS390XNOTW` (字按位取反):** 将字按位取反操作替换为与 -1 进行异或常量操作。
* **`OpS390XOR` (按位或):** 优化按位或操作，包括与常数的或、特定浮点数操作的组合、以及与自身或。
* **`OpS390XORW` (字按位或):** 优化字按位或操作，包括与常数的或以及与自身或。
* **`OpS390XORWconst` (字按位或常量):** 优化字按位或常量操作。
* **`OpS390XORWload` (字按位或加载):** 尝试优化字按位或后跟加载操作的场景。
* **`OpS390XORconst` (按位或常量):** 优化按位或常量操作。
* **`OpS390XORload` (按位或加载):** 尝试优化按位或后跟加载操作的场景。
* **`OpS390XRISBGZ` (旋转并插入选定位然后置零):**  这是一个强大的 S390X 指令，这里尝试对它进行各种优化，包括与其他位操作的结合。
* **`OpS390XRLL` (逻辑左移):** 将逻辑左移操作替换为逻辑左移常量操作。
* **`OpS390XRLLG` (广义逻辑左移):** 将广义逻辑左移操作替换为 `RISBGZ` 指令。
* **`OpS390XSLD` (双字左移):** 优化双字左移操作，包括与常数的左移和特定模式的左移。
* **`OpS390XSLDconst` (双字左移常量):** 优化双字左移常量操作，尝试与其他位操作结合。
* **`OpS390XSLW` (字左移):** 优化字左移操作，包括与常数的左移和特定模式的左移。

**Go 代码举例说明 (推理解释):**

以下是一些基于代码片段的推理解释和 Go 代码示例，展示了这些重写规则可能优化的场景：

**假设输入 SSA 代码包含以下模式：**

```
// 假设 v 是一个 OpS390XMULLDload 操作
v.Args[0] // x: 一个寄存器值
v.Args[1] // ptr1: 一个指向内存的指针
v.Args[2] // 另一个 SSA 操作，假设是 FMOVDstore
```

**`rewriteValueS390X_OpS390XMULLDload` 中的第一个匹配规则：**

该规则匹配这样的场景：一个双字乘法加载操作 (`MULLDload`)，其加载的内存地址正是之前被一个浮点数存储操作 (`FMOVDstore`) 写入的地址，并且两个指针相同。

**假设的输入 SSA (简化表示):**

```
t = <some type>
off = 16
sym = <some symbol>
x = R1 // 假设 x 在寄存器 R1 中
ptr1 = R2 // 假设 ptr1 在寄存器 R2 中
ptr2 = R2 // 假设 ptr2 也在寄存器 R2 中
y = R3 // 假设 y 在寄存器 R3 中

v1 = FMOVDstore [off] {sym} ptr2 y _  // 将 y 存储到 ptr2 指向的内存
v = MULLDload <t> [off] {sym} x ptr1 v1 // 从 ptr1 加载值并与 x 相乘
```

**优化后的 SSA (简化表示):**

```
t = <some type>
x = R1
y = R3

v0 = LGDR <t> y // 直接从 y 寄存器加载 (假设 y 之前被加载或计算)
v = MULLD x v0    // 将 x 与加载的 y 相乘
```

**Go 代码示例 (可能会生成上述 SSA 的 Go 代码):**

```go
package main

func main() {
	var a float64 = 3.14
	var p *float64 = &a
	var x int64 = 5

	*p = a // 对应 FMOVDstore
	result := x * (*p) // 对应 MULLDload
	println(result)
}
```

**`rewriteValueS390X_OpS390XMULLWconst` 中的规则：**

该规则尝试将乘以常数的操作，如果常数接近 2 的幂，就用移位和加减法来替换。

**假设的输入 SSA (简化表示):**

```
t = <some type>
c = 12 // 假设常数为 12
x = R1

v = MULLWconst <t> x [c]
```

**优化后的 SSA (简化表示):**

因为 12 可以表示为 8 + 4，也就是 (1 << 3) + (1 << 2)

```
t = <some type>
x = R1

v0 = SLWconst <t> x [3] // 左移 3 位 (乘以 8)
v1 = SLWconst <t> x [2] // 左移 2 位 (乘以 4)
v = ADDW v0 v1        // 将两个移位结果相加
```

**Go 代码示例 (可能会生成上述 SSA 的 Go 代码):**

```go
package main

func main() {
	var x int32 = 5
	result := x * 12
	println(result)
}
```

**命令行参数的具体处理:**

这个代码文件本身不直接处理命令行参数。它是 Go 编译器内部的一部分，当使用 `go build` 或 `go run` 等命令时，编译器会读取源文件，生成 SSA 中间表示，然后应用这些重写规则进行优化。命令行参数会影响编译器的整体行为，但这些 `.go` 文件定义的是具体的 SSA 转换逻辑。

**使用者易犯错的点:**

由于这是编译器内部的优化规则，Go 语言的使用者通常不会直接与这些代码交互，因此不存在使用者容易犯错的点。这些是编译器开发者需要关注的细节，以确保生成的代码在 S390X 架构上尽可能高效。

**总结第 9 部分的功能:**

第 9 部分的 `rewriteS390X.go` 文件主要定义了针对 S390X 架构的 **乘法 (包括与内存加载的乘法)、取反和基本的按位逻辑运算 (NOT, OR) 的 SSA 重写规则**。这些规则旨在识别可以被更高效的 S390X 指令或指令序列替代的模式，从而提高生成代码的性能。特别地，它还深入优化了 S390X 架构特有的 `RISBGZ` 指令，以及左移操作。 这部分是编译器后端优化的关键组成部分，对于生成高性能的 S390X Go 程序至关重要。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第9部分，共13部分，请归纳一下它的功能

"""
 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULLDload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MULLD x (LGDR <t> y))
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
		v.reset(OpS390XMULLD)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (MULLDload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (MULLDload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XMULLDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (MULLDload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (MULLDload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XMULLDload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMULLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLW x (MOVDconst [c]))
	// result: (MULLWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XMULLWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MULLW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (MULLWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XMULLWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (MULLW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (MULLWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWZload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XMULLWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XMULLWconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULLWconst <t> x [c])
	// cond: isPowerOfTwo(c&(c-1))
	// result: (ADDW (SLWconst <t> x [uint8(log32(c&(c-1)))]) (SLWconst <t> x [uint8(log32(c&^(c-1)))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c & (c - 1))) {
			break
		}
		v.reset(OpS390XADDW)
		v0 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(c & (c - 1))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(c &^ (c - 1))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLWconst <t> x [c])
	// cond: isPowerOfTwo(c+(c&^(c-1)))
	// result: (SUBW (SLWconst <t> x [uint8(log32(c+(c&^(c-1))))]) (SLWconst <t> x [uint8(log32(c&^(c-1)))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c + (c &^ (c - 1)))) {
			break
		}
		v.reset(OpS390XSUBW)
		v0 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(c + (c &^ (c - 1)))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(c &^ (c - 1))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLWconst <t> x [c])
	// cond: isPowerOfTwo(-c+(-c&^(-c-1)))
	// result: (SUBW (SLWconst <t> x [uint8(log32(-c&^(-c-1)))]) (SLWconst <t> x [uint8(log32(-c+(-c&^(-c-1))))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(-c + (-c &^ (-c - 1)))) {
			break
		}
		v.reset(OpS390XSUBW)
		v0 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(-c &^ (-c - 1))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLWconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(-c + (-c &^ (-c - 1)))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c*int32(d))])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c * int32(d)))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMULLWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (MULLWload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XMULLWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (MULLWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (MULLWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XMULLWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XNEG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEG (MOVDconst [c]))
	// result: (MOVDconst [-c])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(-c)
		return true
	}
	// match: (NEG (ADDconst [c] (NEG x)))
	// cond: c != -(1<<31)
	// result: (ADDconst [-c] x)
	for {
		if v_0.Op != OpS390XADDconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpS390XNEG {
			break
		}
		x := v_0_0.Args[0]
		if !(c != -(1 << 31)) {
			break
		}
		v.reset(OpS390XADDconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XNEGW(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGW (MOVDconst [c]))
	// result: (MOVDconst [int64(int32(-c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(-c)))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XNOT(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NOT x)
	// result: (XOR (MOVDconst [-1]) x)
	for {
		x := v_0
		v.reset(OpS390XXOR)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(-1)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueS390X_OpS390XNOTW(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NOTW x)
	// result: (XORWconst [-1] x)
	for {
		x := v_0
		v.reset(OpS390XXORWconst)
		v.AuxInt = int32ToAuxInt(-1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpS390XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (OR x (MOVDconst [c]))
	// cond: isU32Bit(c)
	// result: (ORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isU32Bit(c)) {
				continue
			}
			v.reset(OpS390XORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (OR (MOVDconst [-1<<63]) (LGDR <t> x))
	// result: (LGDR <t> (LNDFR <x.Type> x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0.AuxInt) != -1<<63 || v_1.Op != OpS390XLGDR {
				continue
			}
			t := v_1.Type
			x := v_1.Args[0]
			v.reset(OpS390XLGDR)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpS390XLNDFR, x.Type)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (OR (RISBGZ (LGDR x) {r}) (LGDR (LPDFR <t> y)))
	// cond: r == s390x.NewRotateParams(0, 0, 0)
	// result: (LGDR (CPSDR <t> y x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XRISBGZ {
				continue
			}
			r := auxToS390xRotateParams(v_0.Aux)
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XLGDR {
				continue
			}
			x := v_0_0.Args[0]
			if v_1.Op != OpS390XLGDR {
				continue
			}
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpS390XLPDFR {
				continue
			}
			t := v_1_0.Type
			y := v_1_0.Args[0]
			if !(r == s390x.NewRotateParams(0, 0, 0)) {
				continue
			}
			v.reset(OpS390XLGDR)
			v0 := b.NewValue0(v.Pos, OpS390XCPSDR, t)
			v0.AddArg2(y, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (OR (RISBGZ (LGDR x) {r}) (MOVDconst [c]))
	// cond: c >= 0 && r == s390x.NewRotateParams(0, 0, 0)
	// result: (LGDR (CPSDR <x.Type> (FMOVDconst <x.Type> [math.Float64frombits(uint64(c))]) x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XRISBGZ {
				continue
			}
			r := auxToS390xRotateParams(v_0.Aux)
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XLGDR {
				continue
			}
			x := v_0_0.Args[0]
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c >= 0 && r == s390x.NewRotateParams(0, 0, 0)) {
				continue
			}
			v.reset(OpS390XLGDR)
			v0 := b.NewValue0(v.Pos, OpS390XCPSDR, x.Type)
			v1 := b.NewValue0(v.Pos, OpS390XFMOVDconst, x.Type)
			v1.AuxInt = float64ToAuxInt(math.Float64frombits(uint64(c)))
			v0.AddArg2(v1, x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (OR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c|d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XMOVDconst)
			v.AuxInt = int64ToAuxInt(c | d)
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
	// match: (OR <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ORload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVDload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XORload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XORW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORW x (MOVDconst [c]))
	// result: (ORWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XORWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ORW x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ORW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ORWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XORWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (ORW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (ORWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWZload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XORWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XORWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORWconst [c] x)
	// cond: int32(c)==0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(int32(c) == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ORWconst [c] _)
	// cond: int32(c)==-1
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if !(int32(c) == -1) {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c)|d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c) | d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XORWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (ORWload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XORWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (ORWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (ORWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XORWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XORconst(v *Value) bool {
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
	// result: (MOVDconst [-1])
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c|d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(c | d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XORload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (OR x (LGDR <t> y))
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
		v.reset(OpS390XOR)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (ORload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (ORload [off1+off2] {sym} x ptr mem)
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
		v.reset(OpS390XORload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (ORload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (ORload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
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
		v.reset(OpS390XORload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XRISBGZ(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (RISBGZ (MOVWZreg x) {r})
	// cond: r.InMerge(0xffffffff) != nil
	// result: (RISBGZ x {*r.InMerge(0xffffffff)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XMOVWZreg {
			break
		}
		x := v_0.Args[0]
		if !(r.InMerge(0xffffffff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.InMerge(0xffffffff))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (MOVHZreg x) {r})
	// cond: r.InMerge(0x0000ffff) != nil
	// result: (RISBGZ x {*r.InMerge(0x0000ffff)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XMOVHZreg {
			break
		}
		x := v_0.Args[0]
		if !(r.InMerge(0x0000ffff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.InMerge(0x0000ffff))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (MOVBZreg x) {r})
	// cond: r.InMerge(0x000000ff) != nil
	// result: (RISBGZ x {*r.InMerge(0x000000ff)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XMOVBZreg {
			break
		}
		x := v_0.Args[0]
		if !(r.InMerge(0x000000ff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.InMerge(0x000000ff))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (SLDconst x [c]) {r})
	// cond: r.InMerge(^uint64(0)<<c) != nil
	// result: (RISBGZ x {(*r.InMerge(^uint64(0)<<c)).RotateLeft(c)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XSLDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		if !(r.InMerge(^uint64(0)<<c) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*r.InMerge(^uint64(0) << c)).RotateLeft(c))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (SRDconst x [c]) {r})
	// cond: r.InMerge(^uint64(0)>>c) != nil
	// result: (RISBGZ x {(*r.InMerge(^uint64(0)>>c)).RotateLeft(-c)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XSRDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		if !(r.InMerge(^uint64(0)>>c) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*r.InMerge(^uint64(0) >> c)).RotateLeft(-c))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (RISBGZ x {y}) {z})
	// cond: z.InMerge(y.OutMask()) != nil
	// result: (RISBGZ x {(*z.InMerge(y.OutMask())).RotateLeft(y.Amount)})
	for {
		z := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		y := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(z.InMerge(y.OutMask()) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*z.InMerge(y.OutMask())).RotateLeft(y.Amount))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r.End == 63 && r.Start == -r.Amount&63
	// result: (SRDconst x [-r.Amount&63])
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r.End == 63 && r.Start == -r.Amount&63) {
			break
		}
		v.reset(OpS390XSRDconst)
		v.AuxInt = uint8ToAuxInt(-r.Amount & 63)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r.Start == 0 && r.End == 63-r.Amount
	// result: (SLDconst x [r.Amount])
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r.Start == 0 && r.End == 63-r.Amount) {
			break
		}
		v.reset(OpS390XSLDconst)
		v.AuxInt = uint8ToAuxInt(r.Amount)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (SRADconst x [c]) {r})
	// cond: r.Start == r.End && (r.Start+r.Amount)&63 <= c
	// result: (RISBGZ x {s390x.NewRotateParams(r.Start, r.Start, -r.Start&63)})
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XSRADconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		if !(r.Start == r.End && (r.Start+r.Amount)&63 <= c) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(r.Start, r.Start, -r.Start&63))
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r == s390x.NewRotateParams(56, 63, 0)
	// result: (MOVBZreg x)
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r == s390x.NewRotateParams(56, 63, 0)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r == s390x.NewRotateParams(48, 63, 0)
	// result: (MOVHZreg x)
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r == s390x.NewRotateParams(48, 63, 0)) {
			break
		}
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ x {r})
	// cond: r == s390x.NewRotateParams(32, 63, 0)
	// result: (MOVWZreg x)
	for {
		r := auxToS390xRotateParams(v.Aux)
		x := v_0
		if !(r == s390x.NewRotateParams(32, 63, 0)) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (RISBGZ (LGDR <t> x) {r})
	// cond: r == s390x.NewRotateParams(1, 63, 0)
	// result: (LGDR <t> (LPDFR <x.Type> x))
	for {
		r := auxToS390xRotateParams(v.Aux)
		if v_0.Op != OpS390XLGDR {
			break
		}
		t := v_0.Type
		x := v_0.Args[0]
		if !(r == s390x.NewRotateParams(1, 63, 0)) {
			break
		}
		v.reset(OpS390XLGDR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpS390XLPDFR, x.Type)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XRLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RLL x (MOVDconst [c]))
	// result: (RLLconst x [uint8(c&31)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XRLLconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XRLLG(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RLLG x (MOVDconst [c]))
	// result: (RISBGZ x {s390x.NewRotateParams(0, 63, uint8(c&63))})
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(0, 63, uint8(c&63)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSLD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SLD x (MOVDconst [c]))
	// result: (SLDconst x [uint8(c&63)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XSLDconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SLD x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (AND (MOVDconst [c]) y))
	// result: (SLD x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSLD)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SLD x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVWreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVHreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVBreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVWZreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVHZreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLD x (MOVBZreg y))
	// result: (SLD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLD)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSLDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLDconst (SRDconst x [c]) [d])
	// result: (RISBGZ x {s390x.NewRotateParams(uint8(max(0, int8(c-d))), 63-d, uint8(int8(d-c)&63))})
	for {
		d := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XSRDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(uint8(max(0, int8(c-d))), 63-d, uint8(int8(d-c)&63)))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst (RISBGZ x {r}) [c])
	// cond: s390x.NewRotateParams(0, 63-c, c).InMerge(r.OutMask()) != nil
	// result: (RISBGZ x {(*s390x.NewRotateParams(0, 63-c, c).InMerge(r.OutMask())).RotateLeft(r.Amount)})
	for {
		c := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(s390x.NewRotateParams(0, 63-c, c).InMerge(r.OutMask()) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*s390x.NewRotateParams(0, 63-c, c).InMerge(r.OutMask())).RotateLeft(r.Amount))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SLW x (MOVDconst [c]))
	// cond: c&32 == 0
	// result: (SLWconst x [uint8(c&31)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 == 0) {
			break
		}
		v.reset(OpS390XSLWconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SLW _ (MOVDconst [c]))
	// cond: c&32 != 0
	// result: (MOVDconst [0])
	for {
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 != 0) {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SLW x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (AND (MOVDconst [c]) y))
	// result: (SLW x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSLW)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SLW x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVWreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVHreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVBreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVWZreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVHZreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SLW x (MOVBZreg y))
	// result: (SLW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSLW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
fun
"""




```