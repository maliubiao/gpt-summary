Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for a functional summary of a Go code snippet (`rewritePPC64.go`), specifically focusing on the transformations it performs. It also wants examples and explanations related to Go features, code reasoning, command-line parameters (if applicable), and common mistakes (if any). Crucially, it emphasizes this is *part 8 of 12*.

2. **Analyze the Code:**  I scan the provided code, noting the following key characteristics:
    * **Function `rewriteValuePPC64_*`:** The code consists of many functions named `rewriteValuePPC64_OpPPC64*`. This naming convention strongly suggests that these functions are part of a larger system for rewriting or optimizing Go intermediate representation (SSA - Static Single Assignment) specifically for the PPC64 architecture.
    * **Pattern Matching and Replacement:** Each function seems to implement pattern matching on the structure of SSA values (`v *Value`). When a specific pattern is found, the code modifies the `v` (the current SSA value) to a more optimized or canonical form. The `match:` comments are explicit indicators of this.
    * **Architecture-Specific Operations:** The code heavily uses `OpPPC64*` opcodes. This confirms it's targeted at the PPC64 architecture.
    * **Optimization Focus:** The transformations often involve simplifying expressions, eliminating redundant operations (like double `MOVWZreg`), and using more efficient instructions (like merging loads with address calculations).
    * **Auxiliary Information:**  The code utilizes `AuxInt` and `Aux` fields of SSA values, which carry architecture-specific constants, symbols, or other metadata.
    * **Conditional Rewrites:** Many rewrites are conditional (`cond:` comments). These conditions often relate to the size of constants, the type of operands, or the number of uses of a value.

3. **Infer the Purpose:** Based on the analysis, I conclude that this code is a part of the Go compiler's backend. Specifically, it's the SSA rewriting phase for the PPC64 architecture. Its main purpose is to optimize the generated assembly code by transforming high-level SSA operations into more efficient, low-level PPC64 instructions.

4. **Categorize Functionality:** I group the functions based on the SSA operation they handle. This helps in summarizing the overall functionality:
    * **Load/Store Optimizations:**  Functions like `rewriteValuePPC64_OpPPC64MOVWload`, `rewriteValuePPC64_OpPPC64MOVWstore`, etc., focus on optimizing memory access operations. They try to combine address calculations, use indexed addressing, and handle zero stores efficiently.
    * **Register Move Optimizations:**  Functions like `rewriteValuePPC64_OpPPC64MOVWreg` and `rewriteValuePPC64_OpPPC64MOVWZreg` aim to simplify register moves, eliminate redundant moves, and canonicalize representations (e.g., ensuring the correct zero-extension).
    * **Arithmetic/Logical Operation Optimizations:** Functions like `rewriteValuePPC64_OpPPC64ADD`, `rewriteValuePPC64_OpPPC64OR`, `rewriteValuePPC64_OpPPC64NEG`, etc., focus on simplifying arithmetic and logical expressions, often by folding constants or using more specific instructions.
    * **Bit Manipulation Optimizations:** Functions like `rewriteValuePPC64_OpPPC64ROTLWconst` and `rewriteValuePPC64_OpPPC64RLWINM` target the efficient implementation of bitwise rotations and masks on PPC64.
    * **Comparison Optimizations:** Functions like `rewriteValuePPC64_OpPPC64NotEqual` optimize comparison operations by directly generating the appropriate PPC64 instructions.

5. **Provide Examples:** I select some representative functions and craft Go code examples that illustrate the transformations. The examples should be simple and clearly show the before-and-after state of the SSA. I also include hypothetical input and output SSA representations to make the transformations more concrete.

6. **Address Other Points:**
    * **Go Language Feature:** I identify that the code is implementing low-level optimizations that are transparent to most Go programmers. The examples touch upon basic arithmetic and memory access, which are fundamental Go features.
    * **Command-line Parameters:** I recognize that this code operates within the Go compiler and doesn't directly process command-line parameters in the usual sense. Compiler flags like `-gcflags` could indirectly influence the optimization level, but there are no specific parameters handled *within* this code.
    * **Common Mistakes:** Since this is compiler code, end-users generally don't interact with it directly. Therefore, I state that there are no easily made mistakes by users in this context.
    * **Part of a Larger System:** I emphasize that this is just one part of the overall SSA rewriting process for PPC64.

7. **Summarize the Functionality (Part 8):** I condense the findings into a concise summary, highlighting the key types of optimizations performed within this specific part of the file. I mention load/store, register moves, and logical operations as the main areas covered in the provided snippet.

8. **Review and Refine:** I reread the entire answer to ensure it's clear, accurate, and addresses all aspects of the request. I check for consistency in terminology and ensure the examples are easy to understand.

This systematic approach allows me to break down the complex code into manageable parts, understand its purpose, and generate a comprehensive and informative answer. The key is to recognize the patterns in the code and connect them to the broader context of compiler optimization.
这是 Go 语言编译器中用于将中间表示（SSA，Static Single Assignment）转换为 PPC64 汇编指令的一部分。具体来说，它负责 `rewriteValuePPC64.go` 文件的第 8 部分的功能实现。

**功能归纳:**

这部分代码主要针对 PPC64 架构，定义了一系列针对特定 SSA 操作码的重写规则（rewrite rules）。这些规则旨在优化代码，将一些通用的 SSA 操作转换为更高效或更符合 PPC64 架构特性的操作。 涉及到的主要优化类型包括：

* **`MOVWZreg` (带零扩展的 32 位移动到 64 位寄存器):**  旨在消除冗余的 `MOVWZreg` 操作，并将其与之前的某些操作合并或简化。
* **`MOVWload` (加载 32 位字):** 优化加载操作，例如合并地址计算、使用索引寻址等。
* **`MOVWloadidx` (带索引的加载 32 位字):** 优化带索引的加载操作。
* **`MOVWreg` (32 位移动到 64 位寄存器):** 旨在简化 32 位到 64 位寄存器的移动，并消除冗余操作。
* **`MOVWstore` (存储 32 位字):** 优化存储操作，例如合并地址计算、使用零值存储指令等。
* **`MOVWstoreidx` (带索引的存储 32 位字):** 优化带索引的存储操作。
* **`MOVWstorezero` (存储零值 32 位字):** 优化存储零值操作。
* **`MTVSRD` (将通用寄存器值移动到浮点状态寄存器):** 优化将通用寄存器值移动到浮点状态寄存器的操作。
* **`MULLD` (64 位乘法):** 优化 64 位乘法操作，特别是与常数的乘法。
* **`MULLW` (32 位乘法):** 优化 32 位乘法操作，特别是与常数的乘法。
* **`NEG` (取反):** 优化取反操作，特别是针对常数加减的情况。
* **`NOR` (按位或非):** 优化按位或非操作，特别是针对常数的情况。
* **`NotEqual` (不等于比较):** 将不等于比较操作转换为设置条件寄存器的指令。
* **`OR` (按位或):** 优化按位或操作，特别是针对常数的情况。
* **`ORN` (按位或非):** 优化按位或非操作，特别是针对常数的情况。
* **`ORconst` (按位或常量):** 优化按位或常量操作，合并连续的常量或操作。
* **`RLWINM` (带掩码的循环左移):** 优化带掩码的循环左移操作，与前面的操作合并。
* **`ROTL` (循环左移):** 将循环左移操作转换为带常量的循环左移指令。
* **`ROTLW` (32 位循环左移):** 将 32 位循环左移操作转换为带常量的循环左移指令。
* **`ROTLWconst` (带常量的 32 位循环左移):** 优化带常量的 32 位循环左移操作，特别是与掩码操作结合时。
* **`SETBC` (根据条件位设置):** 将根据条件位设置的操作转换为直接加载常量。

**Go 语言功能实现推理与代码示例:**

这部分代码是 Go 编译器内部的优化步骤，并非直接对应某个特定的 Go 语言功能。它作用于编译过程中的中间表示，目的是生成更高效的机器码。

我们可以通过一些例子来理解其优化思路。

**例子 1: 优化 `MOVWZreg`**

```go
// 假设有如下 SSA 代码：
// v1 = LOAD(ptr)  // 加载一个 32 位整数到 v1
// v2 = MOVWZreg v1 // 将 v1 零扩展到 64 位寄存器 v2
// v3 = ADD v2, x   // 将 v2 与 x 相加

// rewritePPC64.go 中的规则可能会将上述代码优化为：
// v1 = LOAD(ptr)
// v3 = ADD v1, x   // 直接将 32 位的值与 x 相加 (假设 ADD 指令支持 32 位操作数)
```

在这种情况下，如果后续操作只需要低 32 位，并且 PPC64 的 `ADD` 指令可以直接处理 32 位操作数，那么 `MOVWZreg` 操作就是冗余的，可以被消除。

**例子 2: 优化 `MOVWload`**

```go
// 假设有如下 SSA 代码：
// p = MOVDaddr {sym:main.variable, offset:8} base // 计算地址
// v = MOVWload p                                  // 从计算出的地址加载 32 位值

// rewritePPC64.go 中的规则可能会将上述代码优化为：
// v = MOVWload {sym:main.variable, offset:8} base // 直接将偏移合并到加载指令中
```

这里，如果地址计算 `MOVDaddr` 的结果只被 `MOVWload` 使用一次，编译器会尝试将偏移量合并到 `MOVWload` 指令中，减少指令数量。

**假设的输入与输出 (针对 `MOVWZreg` 的一个规则):**

```
// 假设输入 SSA 值 v 代表一个 MOVWZreg 操作
// v.Op = OpPPC64MOVWZreg
// v.Args[0].Op = OpPPC64MOVWreg
// v.Args[0].Args[0] 是某个寄存器 x

// 那么 rewriteValuePPC64_OpPPC64MOVWZreg 函数中可能存在这样的规则：
// match: (MOVWZreg y:(MOVWreg x))
// result: (MOVWZreg x)

// 输出的 SSA 值 v 将被修改为：
// v.Op = OpPPC64MOVWZreg
// v.Args[0] = x  // 直接使用 MOVWreg 的输入
```

**命令行参数处理:**

这段代码本身不直接处理命令行参数。它是 Go 编译器内部的一部分，受到编译器整体的命令行参数控制，例如 `-gcflags` 可以传递一些编译器的 flag，这些 flag 可能会影响到 SSA 的优化级别，从而间接影响到这些 rewrite 规则的执行。

**使用者易犯错的点:**

由于这是编译器内部的代码，Go 语言使用者一般不会直接与这些代码交互，因此不存在使用者容易犯错的点。这些优化规则是在编译过程中自动应用的。

**总结 (针对第 8 部分):**

`rewritePPC64.go` 的第 8 部分主要负责针对 PPC64 架构下多种与 32 位整数操作相关的 SSA 指令进行优化。其核心功能在于通过模式匹配和替换，将这些指令转换为更高效的 PPC64 机器码，例如消除冗余的类型转换、合并地址计算、利用特定的机器指令等，从而提升最终生成的可执行程序的性能。这部分包含了对加载、存储、寄存器移动、算术运算、逻辑运算以及位操作等多种指令的优化规则。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第8部分，共12部分，请归纳一下它的功能

"""
C64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg (RLWINM [r] y))
	// cond: mergePPC64MovwzregRlwinm(r) != 0
	// result: (RLWINM [mergePPC64MovwzregRlwinm(r)] y)
	for {
		if v_0.Op != OpPPC64RLWINM {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if !(mergePPC64MovwzregRlwinm(r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64MovwzregRlwinm(r))
		v.AddArg(y)
		return true
	}
	// match: (MOVWZreg w:(SLWconst u))
	// result: w
	for {
		w := v_0
		if w.Op != OpPPC64SLWconst {
			break
		}
		v.copyOf(w)
		return true
	}
	// match: (MOVWZreg y:(MOVWZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVWZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVHZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVBZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVHBRload _ _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHBRload {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVWBRload _ _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVWBRload {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(MOVWreg x))
	// result: (MOVWZreg x)
	for {
		y := v_0
		if y.Op != OpPPC64MOVWreg {
			break
		}
		x := y.Args[0]
		v.reset(OpPPC64MOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg (OR <t> x (MOVWZreg y)))
	// result: (MOVWZreg (OR <t> x y))
	for {
		if v_0.Op != OpPPC64OR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVWZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVWZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64OR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVWZreg (XOR <t> x (MOVWZreg y)))
	// result: (MOVWZreg (XOR <t> x y))
	for {
		if v_0.Op != OpPPC64XOR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVWZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVWZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64XOR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVWZreg (AND <t> x (MOVWZreg y)))
	// result: (MOVWZreg (AND <t> x y))
	for {
		if v_0.Op != OpPPC64AND {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVWZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVWZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64AND, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVWZreg z:(ANDconst [c] (MOVBZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		z_0 := z.Args[0]
		if z_0.Op != OpPPC64MOVBZload {
			break
		}
		v.copyOf(z)
		return true
	}
	// match: (MOVWZreg z:(AND y (MOVWZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64AND {
			break
		}
		_ = z.Args[1]
		z_0 := z.Args[0]
		z_1 := z.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
			if z_1.Op != OpPPC64MOVWZload {
				continue
			}
			v.copyOf(z)
			return true
		}
		break
	}
	// match: (MOVWZreg z:(ANDconst [c] (MOVHZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		z_0 := z.Args[0]
		if z_0.Op != OpPPC64MOVHZload {
			break
		}
		v.copyOf(z)
		return true
	}
	// match: (MOVWZreg z:(ANDconst [c] (MOVWZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		z_0 := z.Args[0]
		if z_0.Op != OpPPC64MOVWZload {
			break
		}
		v.copyOf(z)
		return true
	}
	// match: (MOVWZreg x:(MOVBZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVBZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVHZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVHZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVWZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVWZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVWZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVWZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(Select0 (LoweredAtomicLoad32 _ _)))
	// result: x
	for {
		x := v_0
		if x.Op != OpSelect0 {
			break
		}
		x_0 := x.Args[0]
		if x_0.Op != OpPPC64LoweredAtomicLoad32 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(Arg <t>))
	// cond: (is8BitInt(t) || is16BitInt(t) || is32BitInt(t)) && !t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !((is8BitInt(t) || is16BitInt(t) || is32BitInt(t)) && !t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint32(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVWload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off1] {sym} (ADDconst [off2] x) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVWload [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVWload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVWload [0] {sym} p:(ADD ptr idx) mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVWloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		mem := v_1
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVWloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWloadidx ptr (MOVDconst [c]) mem)
	// cond: ((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVWload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWloadidx (MOVDconst [c]) ptr mem)
	// cond: ((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !((is16Bit(c) && c%4 == 0) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVWload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVWreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0xFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0xFFFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWreg y:(AND (MOVDconst [c]) _))
	// cond: uint64(c) <= 0x7FFFFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64AND {
			break
		}
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			if y_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(y_0.AuxInt)
			if !(uint64(c) <= 0x7FFFFFFF) {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (MOVWreg (SRAWconst [c] (MOVBreg x)))
	// result: (SRAWconst [c] (MOVBreg x))
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVBreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWreg (SRAWconst [c] (MOVHreg x)))
	// result: (SRAWconst [c] (MOVHreg x))
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVHreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWreg (SRAWconst [c] (MOVWreg x)))
	// result: (SRAWconst [c] (MOVWreg x))
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVWreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWreg (SRAWconst [c] x))
	// cond: x.Type.Size() <= 32
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() <= 32) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (SRDconst [c] x))
	// cond: c>32
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > 32) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (SRADconst [c] x))
	// cond: c>=32
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRADconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 32) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg (SRDconst [c] x))
	// cond: c==32
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c == 32) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg y:(MOVWreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVWreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWreg y:(MOVHreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWreg y:(MOVBreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWreg y:(MOVWZreg x))
	// result: (MOVWreg x)
	for {
		y := v_0
		if y.Op != OpPPC64MOVWZreg {
			break
		}
		x := y.Args[0]
		v.reset(OpPPC64MOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVHloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVWload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVWload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVWloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVWloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(Arg <t>))
	// cond: (is8BitInt(t) || is16BitInt(t) || is32BitInt(t)) && t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !((is8BitInt(t) || is16BitInt(t) || is32BitInt(t)) && t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int32(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVWstore [off1] {sym} (ADDconst [off2] x) val mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVWstore [off1+int32(off2)] {sym} x val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(x, val, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVWstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVWstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpPPC64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstore [0] {sym} p:(ADD ptr idx) val mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVWstoreidx ptr idx val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVWstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWZreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr r:(BRW val) mem)
	// cond: r.Uses == 1
	// result: (MOVWBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		r := v_1
		if r.Op != OpPPC64BRW {
			break
		}
		val := r.Args[0]
		mem := v_2
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVWBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (Bswap32 val) mem)
	// result: (MOVWBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpBswap32 {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreidx ptr (MOVDconst [c]) val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstoreidx (MOVDconst [c]) ptr val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWstore [int32(c)] ptr val mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		val := v_2
		mem := v_3
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVWstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (MOVWreg x) mem)
	// result: (MOVWstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVWstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (MOVWZreg x) mem)
	// result: (MOVWstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVWstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx r:(BRW val) mem)
	// cond: r.Uses == 1
	// result: (MOVWBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		r := v_2
		if r.Op != OpPPC64BRW {
			break
		}
		val := r.Args[0]
		mem := v_3
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVWBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVWstoreidx ptr idx (Bswap32 val) mem)
	// result: (MOVWBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpBswap32 {
			break
		}
		val := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVWBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstorezero [off1] {sym} (ADDconst [off2] x) mem)
	// cond: ((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1)+off2)))
	// result: (MOVWstorezero [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1) + off2))) {
			break
		}
		v.reset(OpPPC64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVWstorezero [off1] {sym1} p:(MOVDaddr [off2] {sym2} x) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVWstorezero [off1+off2] {mergeSym(sym1,sym2)} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		x := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MTVSRD(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MTVSRD (MOVDconst [c]))
	// cond: !math.IsNaN(math.Float64frombits(uint64(c)))
	// result: (FMOVDconst [math.Float64frombits(uint64(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if !(!math.IsNaN(math.Float64frombits(uint64(c)))) {
			break
		}
		v.reset(OpPPC64FMOVDconst)
		v.AuxInt = float64ToAuxInt(math.Float64frombits(uint64(c)))
		return true
	}
	// match: (MTVSRD x:(MOVDload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (FMOVDload [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVDload {
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
		v0 := b.NewValue0(x.Pos, OpPPC64FMOVDload, typ.Float64)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MULLD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLD x (MOVDconst [c]))
	// cond: is16Bit(c)
	// result: (MULLDconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is16Bit(c)) {
				continue
			}
			v.reset(OpPPC64MULLDconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64MULLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLW x (MOVDconst [c]))
	// cond: is16Bit(c)
	// result: (MULLWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is16Bit(c)) {
				continue
			}
			v.reset(OpPPC64MULLWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64NEG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEG (ADDconst [c] x))
	// cond: is32Bit(-c)
	// result: (SUBFCconst [-c] x)
	for {
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c)) {
			break
		}
		v.reset(OpPPC64SUBFCconst)
		v.AuxInt = int64ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (NEG (SUBFCconst [c] x))
	// cond: is32Bit(-c)
	// result: (ADDconst [-c] x)
	for {
		if v_0.Op != OpPPC64SUBFCconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c)) {
			break
		}
		v.reset(OpPPC64ADDconst)
		v.AuxInt = int64ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (NEG (SUB x y))
	// result: (SUB y x)
	for {
		if v_0.Op != OpPPC64SUB {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64SUB)
		v.AddArg2(y, x)
		return true
	}
	// match: (NEG (NEG x))
	// result: x
	for {
		if v_0.Op != OpPPC64NEG {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64NOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NOR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [^(c|d)])
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
			v.AuxInt = int64ToAuxInt(^(c | d))
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64NotEqual(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NotEqual (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (NotEqual (FlagLT))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (NotEqual (FlagGT))
	// result: (MOVDconst [1])
	for {
		if v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (NotEqual (InvertFlags x))
	// result: (NotEqual x)
	for {
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64NotEqual)
		v.AddArg(x)
		return true
	}
	// match: (NotEqual cmp)
	// result: (SETBCR [2] cmp)
	for {
		cmp := v_0
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v.AddArg(cmp)
		return true
	}
}
func rewriteValuePPC64_OpPPC64OR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (OR x (NOR y y))
	// result: (ORN x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64NOR {
				continue
			}
			y := v_1.Args[1]
			if y != v_1.Args[0] {
				continue
			}
			v.reset(OpPPC64ORN)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (OR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c|d])
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
			v.AuxInt = int64ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (OR x (MOVDconst [c]))
	// cond: isU32Bit(c)
	// result: (ORconst [c] x)
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
			v.reset(OpPPC64ORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64ORN(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORN x (MOVDconst [-1]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst || auxIntToInt64(v_1.AuxInt) != -1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ORN (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c|^d])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(c | ^d)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64ORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORconst [c] (ORconst [d] x))
	// result: (ORconst [c|d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpPPC64ORconst)
		v.AuxInt = int64ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	// match: (ORconst [-1] _)
	// result: (MOVDconst [-1])
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
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
	return false
}
func rewriteValuePPC64_OpPPC64RLWINM(v *Value) bool {
	v_0 := v.Args[0]
	// match: (RLWINM [r] (MOVHZreg u))
	// cond: mergePPC64RlwinmAnd(r,0xFFFF) != 0
	// result: (RLWINM [mergePPC64RlwinmAnd(r,0xFFFF)] u)
	for {
		r := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVHZreg {
			break
		}
		u := v_0.Args[0]
		if !(mergePPC64RlwinmAnd(r, 0xFFFF) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64RlwinmAnd(r, 0xFFFF))
		v.AddArg(u)
		return true
	}
	// match: (RLWINM [r] (ANDconst [a] u))
	// cond: mergePPC64RlwinmAnd(r,uint32(a)) != 0
	// result: (RLWINM [mergePPC64RlwinmAnd(r,uint32(a))] u)
	for {
		r := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		a := auxIntToInt64(v_0.AuxInt)
		u := v_0.Args[0]
		if !(mergePPC64RlwinmAnd(r, uint32(a)) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64RlwinmAnd(r, uint32(a)))
		v.AddArg(u)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64ROTL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROTL x (MOVDconst [c]))
	// result: (ROTLconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64ROTLconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64ROTLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROTLW x (MOVDconst [c]))
	// result: (ROTLWconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64ROTLWconst)
		v.AuxInt = int64ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64ROTLWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ROTLWconst [r] (AND (MOVDconst [m]) x))
	// cond: isPPC64WordRotateMask(m)
	// result: (RLWINM [encodePPC64RotateMask(r,rotateLeft32(m,r),32)] x)
	for {
		r := auxIntToInt64(v.AuxInt)
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
			if !(isPPC64WordRotateMask(m)) {
				continue
			}
			v.reset(OpPPC64RLWINM)
			v.AuxInt = int64ToAuxInt(encodePPC64RotateMask(r, rotateLeft32(m, r), 32))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ROTLWconst [r] (ANDconst [m] x))
	// cond: isPPC64WordRotateMask(m)
	// result: (RLWINM [encodePPC64RotateMask(r,rotateLeft32(m,r),32)] x)
	for {
		r := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isPPC64WordRotateMask(m)) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(encodePPC64RotateMask(r, rotateLeft32(m, r), 32))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SETBC(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETBC [0] (FlagLT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBC [0] (FlagGT))
	// result: (MOVDconst
"""




```