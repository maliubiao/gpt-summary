Response:
My thought process to analyze the provided Go code snippet goes like this:

1. **Understand the Context:** The prompt mentions the file path `go/src/cmd/compile/internal/ssa/rewrite386.go`. This immediately tells me we're dealing with compiler optimizations, specifically for the 386 architecture, within the Go compiler's static single assignment (SSA) intermediate representation. The "rewrite" part suggests that this code aims to transform the SSA graph into a more efficient equivalent. The prompt also says it's part 6 of 9, implying a larger set of architecture-specific optimizations.

2. **Identify the Core Functionality:** The code consists of a series of Go functions named `rewriteValue386_Op...`. Each function takes a `*Value` as input and returns a `bool`. The `*Value` likely represents a node in the SSA graph. The function name pattern `rewriteValue386_Op<Operation>` strongly suggests that each function handles specific SSA operations (`Op`). The return value likely indicates whether a rewrite rule was applied.

3. **Analyze Individual Rewrite Rules:** I start examining the logic within each function. They generally follow a pattern:
    * **Pattern Matching:** They look for specific patterns in the input `*Value`'s arguments and auxiliary information (`AuxInt`, `Aux`). This pattern matching uses `if` statements and checks on `v.Op`, `v.Args`, `v.AuxInt`, and `v.Aux`.
    * **Conditions:**  Sometimes, there are additional conditions (`cond: ...`) that must be true for the rewrite to be applied. These conditions often involve checks on the values of constants or properties of the operands.
    * **Transformation:** If the pattern matches and the conditions are met, the code performs a transformation. This typically involves:
        * `v.reset(Op...)`: Changing the operation of the current node.
        * `v.AuxInt = ...`, `v.Aux = ...`: Modifying the auxiliary information.
        * `v.AddArg(...)`, `v.AddArg2(...)`, `v.AddArg3(...)`:  Adjusting the arguments of the current node, potentially creating new nodes (`b.NewValue0`).
        * `v.copyOf(x)`:  Replacing the current node with one of its arguments.
    * **Return Value:** The function returns `true` if a rewrite was performed, and `false` otherwise.

4. **Categorize the Rewrites:**  As I go through the functions, I notice recurring themes:
    * **Constant Folding/Propagation:** Rewriting operations involving constants into simpler forms (e.g., `SHRBconst x [0]` becomes `x`, `SUBL x (MOVLconst [c])` becomes `SUBLconst x [c]`).
    * **Strength Reduction:** Replacing an operation with a cheaper equivalent (e.g., `Bswap16 x` becomes `ROLWconst [8] x`).
    * **Combining Operations:** Merging operations, especially loads, to potentially reduce memory accesses (e.g., `SUBL x l:(MOVLload ...)` becomes `SUBLload ...`).
    * **Handling Shift Operations:**  Specific optimizations for shift operations, taking into account the shift amount (e.g., masking the shift amount).
    * **Comparison and Conditional Setting:**  Transforming comparison operations into set instructions (`SETEQ`, `SETL`, etc.).
    * **Address Calculation:** Using `LEAL` for address calculations.

5. **Infer Go Language Features (Where Possible):** By observing the transformations, I can sometimes infer the Go language features being optimized. For example:
    * Shift operations (`<<`, `>>`).
    * Integer arithmetic (`+`, `-`, `*`, `/`, `%`, `&`, `|`, `^`).
    * Comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`).
    * Boolean logic.
    * Pointer operations.
    * Function calls (indirectly, through memory loads/stores).

6. **Consider Edge Cases and Potential Errors:** The prompt asks about common mistakes. While this code doesn't directly involve user interaction, potential "mistakes" in the *compiler implementation* could arise from:
    * **Incorrect Pattern Matching:**  Missing a valid pattern or misidentifying an invalid one.
    * **Incorrect Conditions:**  Having conditions that are too restrictive or too lenient.
    * **Incorrect Transformations:**  Generating semantically incorrect code.
    * **Performance Regressions:** Applying rewrites that unexpectedly make the code slower in certain scenarios.

7. **Synthesize the Summary:**  Based on the analysis, I can summarize the functionality of this code snippet. It's a set of architecture-specific rewrite rules for the 386 architecture within the Go compiler's SSA phase. These rules aim to optimize the generated machine code by simplifying expressions, reducing instruction counts, and improving efficiency.

8. **Address Specific Instructions in the Prompt:**  Finally, I review the prompt to ensure I've addressed all the requirements, such as providing code examples, explaining command-line parameters (if any), and discussing potential errors. In this specific snippet, there are no direct command-line parameter interactions, but the compiler flags mentioned in the conditions (`config.ctxt.Flag_shared`) are relevant.

This methodical approach, starting with understanding the context and gradually drilling down into the details of the code, allows me to effectively analyze and summarize the functionality of such a code snippet.
这段代码是Go编译器中用于 **x86 (specifically 386架构)** 的 **SSA（Static Single Assignment）中间表示** 的一个 **重写规则（rewrite rules）** 文件的一部分。它的主要功能是：

**核心功能：优化 386 架构下的指令序列**

这段代码定义了一系列的函数，每个函数都尝试匹配特定的 SSA 操作符（例如 `Op386SHRBconst`, `Op386SUBL`, `Op386XORL` 等）及其操作数，并在满足特定条件时，将其替换为更高效或等价的指令序列。

**具体功能归纳：**

1. **常量折叠与传播:**
   - 将涉及常量的操作直接计算出结果，例如 `SHRBconst x [0]` 直接返回 `x`，因为右移 0 位等于没有移动。
   - 将常量加载合并到运算指令中，例如 `SUBL x (MOVLconst [c])` 转换为 `SUBLconst x [c]`。

2. **强度削减:**
   - 将一些开销较大的操作替换为开销较小的等价操作。例如 `Bswap16 x` （字节交换）替换为 `ROLWconst [8] x` (循环左移 8 位)。

3. **指令选择优化:**
   - 选择更适合 386 架构的指令。例如，`Addr {sym} base` (取地址) 替换为 `LEAL {sym} base` (加载有效地址)，因为 `LEAL` 指令更灵活且常常更高效。

4. **内存操作优化:**
   - 尝试将内存加载操作融入到其他操作中，减少独立的加载指令。 例如， `SUBL x l:(MOVLload [off] {sym} ptr mem)` 在满足条件时转换为 `SUBLload x [off] {sym} ptr mem`，这意味着减法操作可以直接从内存加载数据。
   - 优化带有偏移的内存访问，例如将 `SUBLload [off1] {sym} val (ADDLconst [off2] base) mem` 优化为 `SUBLload [off1+off2] {sym} val base mem`，合并偏移量。

5. **位运算优化:**
   - 优化移位操作，例如 `SHRL x (MOVLconst [c])` 转换为 `SHRLconst [c&31] x`，确保移位量在有效范围内 (0-31 for 32-bit integers)。
   - 优化异或操作，例如 `XORL x x` 直接替换为 `MOVLconst [0]`，因为任何数与自身异或结果为 0。

6. **条件码设置优化:**
   - 将高级语言的比较操作 (`Eq`, `Leq`, `Less` 等) 转换为 386 架构下设置条件码的指令 (`SETEQ`, `SETL`, `SETBE` 等) 和比较指令 (`CMPW`, `CMPL`, `CMPB`, `UCOMISS`, `UCOMISD`) 的组合。

**可以推理出的 Go 语言功能实现：**

这段代码优化的都是底层的指令序列，它对应于 Go 语言中各种基本的运算操作和控制流，例如：

* **算术运算:** 加法 (`+`), 减法 (`-`), 乘法 (`*`), 除法 (`/`), 取模 (`%`)
* **位运算:** 与 (`&`), 或 (`|`), 异或 (`^`), 左移 (`<<`), 右移 (`>>`)
* **比较运算:** 等于 (`==`), 不等于 (`!=`), 小于 (`<`), 小于等于 (`<=`), 大于 (`>`), 大于等于 (`>=`)
* **类型转换:** 例如 `SignExt8to16`, `ZeroExt8to16` 等隐含的类型转换操作。
* **指针操作:**  取地址 (`&`)
* **常量:**  各种类型的常量表示。

**Go 代码举例说明 (假设的输入与输出):**

假设有以下 Go 代码片段：

```go
package main

func main() {
	var a int32 = 10
	var b int32 = 5
	c := a - 5 // 这里的 5 是常量
	println(c)
}
```

**SSA 生成 (简化表示):**

```
// ... 一些初始的 SSA 代码 ...
v1 = Const32 [10]  // a
v2 = Const32 [5]   // 常量 5
v3 = Subl v1 v2     // a - 5  (对应 Op386SUBL)
// ... 后续使用 v3 的代码 ...
```

**`rewriteValue386_Op386SUBL` 的优化:**

`rewriteValue386_Op386SUBL` 函数中，有如下匹配规则：

```go
// match: (SUBL x (MOVLconst [c]))
// result: (SUBLconst x [c])
for {
	x := v_0
	if v_1.Op != Op386MOVLconst {
		break
	}
	c := auxIntToInt32(v_1.AuxInt)
	v.reset(Op386SUBLconst)
	v.AuxInt = int32ToAuxInt(c)
	v.AddArg(x)
	return true
}
```

**假设输入:**  `v` 是表示 `v3 = Subl v1 v2` 的 SSA Value，其中 `v1` 是某个值，`v2` 是 `MOVLconst [5]`。

**输出:**  `rewriteValue386_Op386SUBL` 函数会匹配到这个模式，并将 `v3` 的操作符 `Op` 从 `Op386SUBL` 重写为 `Op386SUBLconst`，同时将常量值 `5` 作为 `AuxInt` 存储起来。

**优化后的 SSA (简化表示):**

```
// ... 一些初始的 SSA 代码 ...
v1 = Const32 [10]
v3 = SUBLconst [5] v1  //  优化后的减法，直接包含常量
// ... 后续使用 v3 的代码 ...
```

**涉及命令行参数的具体处理:**

在这段代码中，没有直接处理命令行参数。这些重写规则是 Go 编译器内部的优化步骤，通常在编译过程中自动执行。 但是，编译器的一些 flag 可能会影响这些重写规则的执行。例如，某些优化 flag 可能会禁用或启用某些特定的重写规则。

在代码中可以看到一些条件判断会检查编译器的配置，例如 `config.ctxt.Flag_shared`。这表明某些优化可能只在特定的编译模式下生效。

**使用者易犯错的点:**

作为编译器开发者，容易犯错的点可能包括：

1. **模式匹配错误:**  定义的匹配模式不够精确，导致错误的重写或遗漏了可以优化的场景。
2. **条件判断错误:**  `cond` 中的条件判断逻辑错误，导致不应该被重写的指令被重写，或者应该被重写的指令没有被重写。
3. **重写逻辑错误:**  重写后的指令序列在语义上与原始指令序列不一致，导致程序行为错误。
4. **性能回退:**  某些看似优化的重写规则，在某些特定的场景下，反而可能导致性能下降。例如，过度激进的内联。

**这段代码的功能归纳 (作为第 6 部分):**

作为 `rewrite386.go` 的一部分，并且是第 6 部分，这段代码的功能是针对 **x86 (386)** 架构的 SSA 中间表示，实现 **第二批次的、专注于特定操作符的优化重写规则**。  它涵盖了算术运算、位运算、比较运算以及内存访问等方面的优化，旨在将抽象的 SSA 指令转化为更接近目标机器、更高效的指令序列，为后续的指令调度和代码生成阶段打下基础。  可以推测，之前的几部分可能处理了更基础的优化或通用的重写规则，而后续的部分可能会处理更复杂的优化或与特定指令相关的重写。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewrite386.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共9部分，请归纳一下它的功能
```

### 源代码
```go
nt)
		if !(c&31 >= 8) {
			break
		}
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValue386_Op386SHRBconst(v *Value) bool {
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
func rewriteValue386_Op386SHRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SHRL x (MOVLconst [c]))
	// result: (SHRLconst [c&31] x)
	for {
		x := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(Op386SHRLconst)
		v.AuxInt = int32ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	// match: (SHRL x (ANDLconst [31] y))
	// result: (SHRL x y)
	for {
		x := v_0
		if v_1.Op != Op386ANDLconst || auxIntToInt32(v_1.AuxInt) != 31 {
			break
		}
		y := v_1.Args[0]
		v.reset(Op386SHRL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_Op386SHRLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRLconst x [0])
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValue386_Op386SHRW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SHRW x (MOVLconst [c]))
	// cond: c&31 < 16
	// result: (SHRWconst [int16(c&31)] x)
	for {
		x := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 < 16) {
			break
		}
		v.reset(Op386SHRWconst)
		v.AuxInt = int16ToAuxInt(int16(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRW _ (MOVLconst [c]))
	// cond: c&31 >= 16
	// result: (MOVLconst [0])
	for {
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 >= 16) {
			break
		}
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValue386_Op386SHRWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRWconst x [0])
	// result: x
	for {
		if auxIntToInt16(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValue386_Op386SUBL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBL x (MOVLconst [c]))
	// result: (SUBLconst x [c])
	for {
		x := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(Op386SUBLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUBL (MOVLconst [c]) x)
	// result: (NEGL (SUBLconst <v.Type> x [c]))
	for {
		if v_0.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(Op386NEGL)
		v0 := b.NewValue0(v.Pos, Op386SUBLconst, v.Type)
		v0.AuxInt = int32ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBLload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != Op386MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(Op386SUBLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (SUBL x x)
	// result: (MOVLconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValue386_Op386SUBLcarry(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBLcarry x (MOVLconst [c]))
	// result: (SUBLconstcarry [c] x)
	for {
		x := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(Op386SUBLconstcarry)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValue386_Op386SUBLconst(v *Value) bool {
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
		v.reset(Op386ADDLconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
}
func rewriteValue386_Op386SUBLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SUBLload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBLload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386SUBLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBLload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (SUBLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386SUBLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386SUBLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SUBLmodify [off1] {sym} (ADDLconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBLmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386SUBLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SUBLmodify [off1] {sym1} (LEAL [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (SUBLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386SUBLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386SUBSD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBSD x l:(MOVSDload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBSDload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != Op386MOVSDload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(Op386SUBSDload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386SUBSDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SUBSDload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBSDload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386SUBSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSDload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (SUBSDload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386SUBSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386SUBSS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBSS x l:(MOVSSload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBSSload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != Op386MOVSSload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(Op386SUBSSload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386SUBSSload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SUBSSload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBSSload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386SUBSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSSload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (SUBSSload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386SUBSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386XORL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORL x (MOVLconst [c]))
	// result: (XORLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != Op386MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(Op386XORLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XORL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (XORLload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != Op386MOVLload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(Op386XORLload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (XORL x x)
	// result: (MOVLconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValue386_Op386XORLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORLconst [c] (XORLconst [d] x))
	// result: (XORLconst [c ^ d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386XORLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(Op386XORLconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [c] x)
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
	// match: (XORLconst [c] (MOVLconst [d]))
	// result: (MOVLconst [c^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		return true
	}
	return false
}
func rewriteValue386_Op386XORLconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (XORLconstmodify [valoff1] {sym} (ADDLconst [off2] base) mem)
	// cond: valoff1.canAdd32(off2)
	// result: (XORLconstmodify [valoff1.addOffset32(off2)] {sym} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(valoff1.canAdd32(off2)) {
			break
		}
		v.reset(Op386XORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(valoff1.addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (XORLconstmodify [valoff1] {sym1} (LEAL [off2] {sym2} base) mem)
	// cond: valoff1.canAdd32(off2) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (XORLconstmodify [valoff1.addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(valoff1.canAdd32(off2) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386XORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(valoff1.addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386XORLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (XORLload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORLload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386XORLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (XORLload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (XORLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386XORLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386XORLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (XORLmodify [off1] {sym} (ADDLconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORLmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386XORLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (XORLmodify [off1] {sym1} (LEAL [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (XORLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386XORLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValue386_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (LEAL {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(Op386LEAL)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValue386_OpBswap16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Bswap16 x)
	// result: (ROLWconst [8] x)
	for {
		x := v_0
		v.reset(Op386ROLWconst)
		v.AuxInt = int16ToAuxInt(8)
		v.AddArg(x)
		return true
	}
}
func rewriteValue386_OpConst16(v *Value) bool {
	// match: (Const16 [c])
	// result: (MOVLconst [int32(c)])
	for {
		c := auxIntToInt16(v.AuxInt)
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
}
func rewriteValue386_OpConst8(v *Value) bool {
	// match: (Const8 [c])
	// result: (MOVLconst [int32(c)])
	for {
		c := auxIntToInt8(v.AuxInt)
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
}
func rewriteValue386_OpConstBool(v *Value) bool {
	// match: (ConstBool [c])
	// result: (MOVLconst [b2i32(c)])
	for {
		c := auxIntToBool(v.AuxInt)
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(b2i32(c))
		return true
	}
}
func rewriteValue386_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVLconst [0])
	for {
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
}
func rewriteValue386_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz16 x)
	// result: (BSFL (ORLconst <typ.UInt32> [0x10000] x))
	for {
		x := v_0
		v.reset(Op386BSFL)
		v0 := b.NewValue0(v.Pos, Op386ORLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0x10000)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz8 x)
	// result: (BSFL (ORLconst <typ.UInt32> [0x100] x))
	for {
		x := v_0
		v.reset(Op386BSFL)
		v0 := b.NewValue0(v.Pos, Op386ORLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0x100)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (DIVW (SignExt8to16 x) (SignExt8to16 y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386DIVW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to16, typ.Int16)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to16, typ.Int16)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValue386_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (DIVWU (ZeroExt8to16 x) (ZeroExt8to16 y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386DIVWU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to16, typ.UInt16)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to16, typ.UInt16)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValue386_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq16 x y)
	// result: (SETEQ (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETEQ)
		v0 := b.NewValue0(v.Pos, Op386CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32 x y)
	// result: (SETEQ (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETEQ)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (SETEQF (UCOMISS x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETEQF)
		v0 := b.NewValue0(v.Pos, Op386UCOMISS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (SETEQF (UCOMISD x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETEQF)
		v0 := b.NewValue0(v.Pos, Op386UCOMISD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq8 x y)
	// result: (SETEQ (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETEQ)
		v0 := b.NewValue0(v.Pos, Op386CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqB x y)
	// result: (SETEQ (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETEQ)
		v0 := b.NewValue0(v.Pos, Op386CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqPtr x y)
	// result: (SETEQ (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETEQ)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsInBounds idx len)
	// result: (SETB (CMPL idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(Op386SETB)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsNonNil p)
	// result: (SETNE (TESTL p p))
	for {
		p := v_0
		v.reset(Op386SETNE)
		v0 := b.NewValue0(v.Pos, Op386TESTL, types.TypeFlags)
		v0.AddArg2(p, p)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsSliceInBounds idx len)
	// result: (SETBE (CMPL idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(Op386SETBE)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq16 x y)
	// result: (SETLE (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETLE)
		v0 := b.NewValue0(v.Pos, Op386CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq16U x y)
	// result: (SETBE (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETBE)
		v0 := b.NewValue0(v.Pos, Op386CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32 x y)
	// result: (SETLE (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETLE)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (SETGEF (UCOMISS y x))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETGEF)
		v0 := b.NewValue0(v.Pos, Op386UCOMISS, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32U x y)
	// result: (SETBE (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETBE)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (SETGEF (UCOMISD y x))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETGEF)
		v0 := b.NewValue0(v.Pos, Op386UCOMISD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq8 x y)
	// result: (SETLE (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETLE)
		v0 := b.NewValue0(v.Pos, Op386CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq8U x y)
	// result: (SETBE (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETBE)
		v0 := b.NewValue0(v.Pos, Op386CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less16 x y)
	// result: (SETL (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETL)
		v0 := b.NewValue0(v.Pos, Op386CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less16U x y)
	// result: (SETB (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETB)
		v0 := b.NewValue0(v.Pos, Op386CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32 x y)
	// result: (SETL (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETL)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (SETGF (UCOMISS y x))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETGF)
		v0 := b.NewValue0(v.Pos, Op386UCOMISS, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32U x y)
	// result: (SETB (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETB)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (SETGF (UCOMISD y x))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETGF)
		v0 := b.NewValue0(v.Pos, Op386UCOMISD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less8 x y)
	// result: (SETL (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETL)
		v0 := b.NewValue0(v.Pos, Op386CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less8U x y)
	// result: (SETB (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETB)
		v0 := b.NewValue0(v.Pos, Op386CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) || isPtr(t))
	// result: (MOVLload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(Op386MOVLload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is16BitInt(t)
	// result: (MOVWload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t)) {
			break
		}
		v.reset(Op386MOVWload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (t.IsBoolean() || is8BitInt(t))
	// result: (MOVBload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsBoolean() || is8BitInt(t)) {
			break
		}
		v.reset(Op386MOVBload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (MOVSSload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(Op386MOVSSload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (MOVSDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(Op386MOVSDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (LEAL {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(Op386LEAL)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (LEAL {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(Op386LEAL)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValue386_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHLL <t> x y) (SBBLcarrymask <t> (CMPWconst y [32])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPWconst, types.TypeFlags)
		v2.AuxInt = int16ToAuxInt(32)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh16x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHLL <t> x y) (SBBLcarrymask <t> (CMPLconst y [32])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPLconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh16x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHLL
```