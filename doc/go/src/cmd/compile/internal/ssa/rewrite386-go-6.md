Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Context:**

The initial prompt clearly states this is part of `go/src/cmd/compile/internal/ssa/rewrite386.go`. This immediately tells us:

* **`cmd/compile`:** It's related to the Go compiler.
* **`internal/ssa`:** It operates on the Static Single Assignment (SSA) intermediate representation of Go code. This means it's performing optimizations or transformations at a lower level than the source code.
* **`rewrite386.go`:**  It's specific to the 386 architecture (x86 32-bit). The name "rewrite" suggests it's involved in transforming or simplifying the SSA representation.

**2. Analyzing the Code Structure:**

The code consists of a series of Go functions, all named `rewriteValue386_Op...`. This naming convention is a strong indicator of its purpose:

* **`rewriteValue386_`:**  Confirms it's part of the 386 rewriting process.
* **`Op...`:**  Suggests that these functions handle different Go *operations* as represented in the SSA. The specific operation is indicated by the part following "Op".

**3. Deconstructing Individual Functions (Example: `rewriteValue386_OpLsh16x64`)**

Let's take a single function and analyze its components:

* **Function Signature:** `func rewriteValue386_OpLsh16x64(v *Value) bool`
    * `v *Value`:  The input is a pointer to an SSA `Value`. This `Value` represents an operation in the SSA graph.
    * `bool`: The function returns a boolean, indicating whether a rewrite rule was applied.

* **Accessing Arguments:** `v_1 := v.Args[1]` and `v_0 := v.Args[0]`
    * This retrieves the arguments of the SSA operation represented by `v`. The order of arguments is important.

* **Matching Patterns:** The code uses `if` statements to check the structure of the SSA `Value`. For example:
    * `if v_1.Op != OpConst64 { break }` checks if the second argument is a constant 64-bit value.
    * `c := auxIntToInt64(v_1.AuxInt)` extracts the actual integer value of the constant.

* **Applying Rewrite Rules (the `v.reset(...)` part):** If a pattern matches, the code *rewrites* the SSA `Value`.
    * `v.reset(Op386SHLLconst)` changes the operation of the `Value` to `Op386SHLLconst` (a 386-specific left shift with a constant).
    * `v.AuxInt = int32ToAuxInt(int32(c))` sets an auxiliary integer value associated with the operation (the shift amount).
    * `v.AddArg(x)` adds the original first argument as an argument to the new operation.

* **Conditional Logic (`cond:`):** The `// cond:` comments specify additional conditions that must be met for the rewrite to occur.

**4. Identifying Common Themes and Operations:**

By examining multiple functions, we can see recurring patterns:

* **Handling Specific Data Types:**  The function names often include data types like `Int16`, `Int32`, `Float32`, etc., indicating they deal with operations on those types.
* **Optimization for Constants:** Many rewrites involve constant values, suggesting optimizations that can be done at compile time.
* **Lowering to 386 Instructions:**  The `v.reset()` calls often use `Op386...` opcodes, indicating a lowering from more generic SSA operations to specific 386 machine instructions.
* **Shift Operations:** A significant portion of the code deals with left and right shift operations (`Lsh`, `Rsh`).
* **Conditional Moves/Compares:** Operations like `CMP`, `SETNE`, etc., are used for implementing conditional logic.
* **Memory Operations:** `Move`, `Load`, `Store` operations are present, showing how memory access is handled.

**5. Inferring Go Language Features:**

Based on the operations being rewritten, we can infer the corresponding Go language features:

* **Arithmetic Operations:** `Add`, `Sub`, `Mul`, `Div`, `Mod`
* **Bitwise Operations:** `And`, `Or`, `Xor`, `Shl`, `Shr`
* **Comparison Operations:** `Eq`, `Neq`, `Lt`, `Leq`, `Gt`, `Geq`
* **Type Conversions:**  The `SignExt` and `ZeroExt` operations suggest implicit or explicit type conversions.
* **Memory Access:**  The `Move`, `Load`, and `Store` operations are fundamental to how Go interacts with memory (including assignments, function calls, etc.).
* **Constants:** The handling of `Const` operations highlights how the compiler deals with literal values.

**6. Reasoning About Specific Examples (with Assumptions):**

For `rewriteValue386_OpLsh16x64`:

* **Assumption:** The Go code contains a left shift operation where a 16-bit integer is shifted by a 64-bit integer.
* **Input SSA:**  An `OpLsh16x64` `Value` with two arguments:
    * `v.Args[0]`: An `OpLoad` representing loading a `int16` from memory.
    * `v.Args[1]`: An `OpConst64` with `AuxInt` representing the constant shift amount (e.g., 3).
* **Output SSA (if condition met):** The `OpLsh16x64` `Value` is rewritten to an `Op386SHLLconst` with:
    * `AuxInt` set to 3 (the shift amount).
    * The original `OpLoad` as its argument.
* **Output SSA (if condition not met - shift >= 16):** The `OpLsh16x64` is rewritten to `OpConst16` with a value of 0.

**7. Considering Potential Mistakes:**

Looking at how shifts are handled, a common mistake might be assuming that shifting by a value greater than or equal to the bit size of the operand will always result in zero. While this is often the case, the code explicitly handles these cases, suggesting that the Go language specification might not guarantee this behavior for all integer types in all situations.

**8. Synthesizing the Functionality (for the Part):**

After analyzing the functions in the provided snippet, the core functionality is clear:

* **Architecture-Specific Optimization:** This part of the code optimizes Go operations specifically for the 386 architecture.
* **SSA Rewriting:** It transforms the SSA representation of Go code to use more efficient 386 instructions.
* **Handling Shift Operations:** A significant focus is on optimizing left and right shift operations, especially when the shift amount is a constant.
* **Lowering Generic Operations:**  It lowers generic operations like `Lsh16x64` to their 386-specific counterparts like `SHLLconst`.
* **Constant Folding:** It performs constant folding for shift operations where the shift amount is a constant.
* **Boundary Checks (Implicit):** The more complex shift rewrites involving `ANDL` and `SBBLcarrymask` suggest handling cases where the shift amount might be out of bounds.

By following this systematic approach, we can thoroughly understand the purpose and functionality of the provided Go code snippet. The key is to recognize the context, analyze the structure and individual functions, identify common themes, and then reason about the implications for the Go language and potential optimizations.
这是 `go/src/cmd/compile/internal/ssa/rewrite386.go` 文件的一部分，它主要负责 **将 Go 语言的通用中间表示 (SSA) 中的操作，针对 386 架构进行特定的重写和优化**。  简单来说，它将一些通用的操作转化为 386 架构上更有效率的指令序列。

**具体功能归纳 (针对提供的代码片段):**

这个代码片段主要集中在 **386 架构下的位移操作 (左移和右移)** 和一些相关的优化：

1. **左移操作 (`OpLsh...`) 的重写:**
   - 针对不同大小的整数 (8, 16, 32 位) 和不同大小的位移量 (8, 16, 32, 64 位) 的左移操作进行处理。
   - 当位移量是常量时，会尝试使用 `SHLLconst` (左移常量) 指令，这是一个更高效的 386 指令。
   - 当位移量超出数据类型的大小时，会将结果直接置为 0，例如 `Lsh16x64` 如果位移量大于等于 16，结果直接是常量 0。
   - 对于位移量不是常量的情况，会根据 `shiftIsBounded(v)` 的结果选择不同的指令序列。如果位移量有可能是越界的，会使用 `ANDL` 和 `SBBLcarrymask` 指令来确保结果的正确性 (即使位移量很大)。

2. **右移操作 (`OpRsh...`, `OpRsh...Ux...`) 的重写:**
   - 类似于左移，针对不同大小的整数和位移量进行处理。
   - 对于无符号右移 (`OpRsh...Ux...`)，当位移量是常量时，使用 `SHRWconst` 或 `SHRLconst`。如果位移量超出大小，结果置为 0。
   - 对于有符号右移 (`OpRsh...`)，当位移量是常量时，使用 `SARWconst` 或 `SARLconst`。如果位移量超出大小，结果会根据符号位进行填充 (算术右移)。
   - 对于非常量位移，同样会根据 `shiftIsBounded(v)` 选择不同的指令序列，可能使用 `SARW` 或 `SARL` 配合 `ORL`, `NOTL`, `SBBLcarrymask` 来处理潜在的越界情况。

3. **取模运算 (`OpMod8`, `OpMod8u`):**
   - 将 8 位有符号和无符号的取模运算分别转换为 16 位的取模运算 (`MODW`, `MODWU`)，并在操作数上进行符号扩展或零扩展。这是因为 386 硬件直接支持 16 位的取模指令。

4. **内存移动 (`OpMove`):**
   - 针对不同大小的内存移动 (由 `AuxInt` 指定移动的字节数) 进行优化。
   - 对于小块内存移动 (1, 2, 4 字节)，直接使用 `MOVBstore`, `MOVWstore`, `MOVLstore` 指令。
   - 对于稍大的内存移动 (3, 5, 6, 7, 8 字节)，会拆分成多个小的内存移动指令。
   - 对于更大的内存移动，会考虑使用 `DUFFCOPY` (Duff's Device 的变种，一种循环展开的优化技巧) 或者 `REPMOVSL` (repeat move string long，x86 的硬件加速指令)。

5. **浮点数取负 (`OpNeg32F`, `OpNeg64F`):**
   - 使用 `PXOR` 指令与一个表示负零的常量进行异或操作来实现浮点数取负。

6. **比较操作 (`OpNeq16`, `OpNeq32`, `OpNeq8`, `OpNeqB`, `OpNeqPtr`, `OpNeq32F`, `OpNeq64F`):**
   - 将不等比较操作转换为比较指令 (`CMPW`, `CMPL`, `CMPB`, `UCOMISS`, `UCOMISD`) 之后设置条件码，然后使用 `SETNE` 或 `SETNEF` 指令来获取比较结果 (0 或 1)。

7. **逻辑非 (`OpNot`):**
   - 使用与 1 进行异或 (`XORLconst`) 来实现逻辑非操作。

8. **指针偏移 (`OpOffPtr`):**
   - 将指针偏移操作转换为 `ADDLconst` (加常量) 指令。

9. **panic 边界检查相关 (`OpPanicBounds`, `OpPanicExtend`):**
   - 根据 `boundsABI` 的设置，选择不同的 `LoweredPanicBounds...` 和 `LoweredPanicExtend...` 操作。这可能涉及到不同的函数调用约定或参数传递方式来处理数组越界等 panic 情况。

**推断 Go 语言功能及代码示例:**

**假设输入:** Go 源代码中进行了以下操作：

```go
package main

func main() {
	var i int16 = 10
	var shift uint64 = 3
	j := i << shift // 左移
	println(j)

	var k int32 = 100
	var mask int32 = 7
	l := k % mask // 取模
	println(l)

	var arr1 [10]byte
	var arr2 [10]byte
	copy(arr1[:], arr2[:]) // 内存拷贝
}
```

**对应的 SSA (简化表示，可能与实际略有不同):**

* **`i << shift`:**  可能会对应一个 `OpLsh16x64` 的 SSA Value，其中一个参数是 `i` 的加载结果，另一个参数是常量 `3`。
* **`k % mask`:** 可能会对应一个 `OpMod32` 的 SSA Value。由于目标架构是 386，并且代码片段中没有直接的 `OpMod32` 的重写规则，编译器可能会将 32 位的取模分解成更底层的操作序列，或者在之前的 pass 中已经处理。但是，对于 8 位取模，我们看到了 `OpMod8` 的重写。
* **`copy(arr1[:], arr2[:])`:** 可能会对应一个 `OpMove` 的 SSA Value，其 `AuxInt` 表示要拷贝的字节数 (10)。

**基于代码片段的推理 (针对 `OpLsh16x64`):**

**输入 SSA (假设):**

```
OpLsh16x64 <int16>  %1  %2
  %1 = Load <int16> ... // 加载变量 i
  %2 = Const64 <uint64> [3] // 常量 3
```

**输出 SSA (根据 `rewriteValue386_OpLsh16x64`):**

```
Op386SHLLconst <int16>  %1 [3]
  %1 = Load <int16> ...
```

**解释:** 由于位移量是常量 3，且小于 16，`OpLsh16x64` 被重写为 `Op386SHLLconst`，这是一个 386 架构下专门用于常量位移的左移指令。

**使用者易犯错的点:**

虽然这个代码是编译器内部的实现，普通 Go 开发者不会直接接触，但理解这些重写规则可以帮助理解一些性能特性：

* **位移操作的性能:**  了解常量位移通常比变量位移更高效。
* **小块内存拷贝的效率:**  知道编译器会针对小块内存拷贝进行优化，使用更快的指令。
* **整数取模的开销:**  可以看到 8 位取模被提升到 16 位，可能暗示了更小位宽的取模操作在某些架构上可能需要额外的处理。

**命令行参数的具体处理:**

这个代码片段本身不直接处理命令行参数。`rewrite386.go` 是编译过程中的一个步骤，它作用于已经生成的 SSA 中间表示。 命令行参数 (例如 `-gcflags`) 会在编译的更早阶段影响代码的生成和优化策略。

**总结 (第 7 部分的功能):**

这部分 `rewrite386.go` 的主要功能是 **针对 386 架构，对 Go 语言的位移操作、小整数取模、内存移动、浮点数取负和基本比较操作进行特定的指令级优化**。它通过模式匹配和条件判断，将通用的 SSA 操作替换为更高效的 386 汇编指令序列，从而提升最终生成的可执行程序的性能。 这也体现了 Go 编译器在不同目标架构上进行针对性优化的策略。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewrite386.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```go
)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh16x64 x (Const64 [c]))
	// cond: uint64(c) < 16
	// result: (SHLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(Op386SHLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Lsh16x64 _ (Const64 [c]))
	// cond: uint64(c) >= 16
	// result: (Const16 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 16) {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValue386_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHLL <t> x y) (SBBLcarrymask <t> (CMPBconst y [32])))
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
		v2 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v2.AuxInt = int8ToAuxInt(32)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh16x8 <t> x y)
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
func rewriteValue386_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x16 <t> x y)
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
	// match: (Lsh32x16 <t> x y)
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
func rewriteValue386_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x32 <t> x y)
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
	// match: (Lsh32x32 <t> x y)
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
func rewriteValue386_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh32x64 x (Const64 [c]))
	// cond: uint64(c) < 32
	// result: (SHLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(Op386SHLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Lsh32x64 _ (Const64 [c]))
	// cond: uint64(c) >= 32
	// result: (Const32 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 32) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValue386_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHLL <t> x y) (SBBLcarrymask <t> (CMPBconst y [32])))
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
		v2 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v2.AuxInt = int8ToAuxInt(32)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh32x8 <t> x y)
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
func rewriteValue386_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x16 <t> x y)
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
	// match: (Lsh8x16 <t> x y)
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
func rewriteValue386_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x32 <t> x y)
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
	// match: (Lsh8x32 <t> x y)
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
func rewriteValue386_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh8x64 x (Const64 [c]))
	// cond: uint64(c) < 8
	// result: (SHLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(Op386SHLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Lsh8x64 _ (Const64 [c]))
	// cond: uint64(c) >= 8
	// result: (Const8 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 8) {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValue386_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHLL <t> x y) (SBBLcarrymask <t> (CMPBconst y [32])))
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
		v2 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v2.AuxInt = int8ToAuxInt(32)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh8x8 <t> x y)
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
func rewriteValue386_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (MODW (SignExt8to16 x) (SignExt8to16 y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386MODW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to16, typ.Int16)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to16, typ.Int16)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValue386_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (MODWU (ZeroExt8to16 x) (ZeroExt8to16 y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386MODWU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to16, typ.UInt16)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to16, typ.UInt16)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValue386_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Move [0] _ _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.copyOf(mem)
		return true
	}
	// match: (Move [1] dst src mem)
	// result: (MOVBstore dst (MOVBload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(Op386MOVBstore)
		v0 := b.NewValue0(v.Pos, Op386MOVBload, typ.UInt8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVWstore dst (MOVWload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(Op386MOVWstore)
		v0 := b.NewValue0(v.Pos, Op386MOVWload, typ.UInt16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVLstore dst (MOVLload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(Op386MOVLstore)
		v0 := b.NewValue0(v.Pos, Op386MOVLload, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBload [2] src mem) (MOVWstore dst (MOVWload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(Op386MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, Op386MOVBload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, Op386MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, Op386MOVWload, typ.UInt16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [5] dst src mem)
	// result: (MOVBstore [4] dst (MOVBload [4] src mem) (MOVLstore dst (MOVLload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(Op386MOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, Op386MOVBload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, Op386MOVLstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, Op386MOVLload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [6] dst src mem)
	// result: (MOVWstore [4] dst (MOVWload [4] src mem) (MOVLstore dst (MOVLload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(Op386MOVWstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, Op386MOVWload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, Op386MOVLstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, Op386MOVLload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [7] dst src mem)
	// result: (MOVLstore [3] dst (MOVLload [3] src mem) (MOVLstore dst (MOVLload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(Op386MOVLstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, Op386MOVLload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, Op386MOVLstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, Op386MOVLload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] dst src mem)
	// result: (MOVLstore [4] dst (MOVLload [4] src mem) (MOVLstore dst (MOVLload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(Op386MOVLstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, Op386MOVLload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, Op386MOVLstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, Op386MOVLload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 8 && s%4 != 0
	// result: (Move [s-s%4] (ADDLconst <dst.Type> dst [int32(s%4)]) (ADDLconst <src.Type> src [int32(s%4)]) (MOVLstore dst (MOVLload src mem) mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 8 && s%4 != 0) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(s - s%4)
		v0 := b.NewValue0(v.Pos, Op386ADDLconst, dst.Type)
		v0.AuxInt = int32ToAuxInt(int32(s % 4))
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, Op386ADDLconst, src.Type)
		v1.AuxInt = int32ToAuxInt(int32(s % 4))
		v1.AddArg(src)
		v2 := b.NewValue0(v.Pos, Op386MOVLstore, types.TypeMem)
		v3 := b.NewValue0(v.Pos, Op386MOVLload, typ.UInt32)
		v3.AddArg2(src, mem)
		v2.AddArg3(dst, v3, mem)
		v.AddArg3(v0, v1, v2)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 8 && s <= 4*128 && s%4 == 0 && !config.noDuffDevice && logLargeCopy(v, s)
	// result: (DUFFCOPY [10*(128-s/4)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 8 && s <= 4*128 && s%4 == 0 && !config.noDuffDevice && logLargeCopy(v, s)) {
			break
		}
		v.reset(Op386DUFFCOPY)
		v.AuxInt = int64ToAuxInt(10 * (128 - s/4))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: (s > 4*128 || config.noDuffDevice) && s%4 == 0 && logLargeCopy(v, s)
	// result: (REPMOVSL dst src (MOVLconst [int32(s/4)]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !((s > 4*128 || config.noDuffDevice) && s%4 == 0 && logLargeCopy(v, s)) {
			break
		}
		v.reset(Op386REPMOVSL)
		v0 := b.NewValue0(v.Pos, Op386MOVLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(int32(s / 4))
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValue386_OpNeg32F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neg32F x)
	// result: (PXOR x (MOVSSconst <typ.Float32> [float32(math.Copysign(0, -1))]))
	for {
		x := v_0
		v.reset(Op386PXOR)
		v0 := b.NewValue0(v.Pos, Op386MOVSSconst, typ.Float32)
		v0.AuxInt = float32ToAuxInt(float32(math.Copysign(0, -1)))
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValue386_OpNeg64F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neg64F x)
	// result: (PXOR x (MOVSDconst <typ.Float64> [math.Copysign(0, -1)]))
	for {
		x := v_0
		v.reset(Op386PXOR)
		v0 := b.NewValue0(v.Pos, Op386MOVSDconst, typ.Float64)
		v0.AuxInt = float64ToAuxInt(math.Copysign(0, -1))
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValue386_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq16 x y)
	// result: (SETNE (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETNE)
		v0 := b.NewValue0(v.Pos, Op386CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32 x y)
	// result: (SETNE (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETNE)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32F x y)
	// result: (SETNEF (UCOMISS x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETNEF)
		v0 := b.NewValue0(v.Pos, Op386UCOMISS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64F x y)
	// result: (SETNEF (UCOMISD x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETNEF)
		v0 := b.NewValue0(v.Pos, Op386UCOMISD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq8 x y)
	// result: (SETNE (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETNE)
		v0 := b.NewValue0(v.Pos, Op386CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpNeqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (NeqB x y)
	// result: (SETNE (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETNE)
		v0 := b.NewValue0(v.Pos, Op386CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (NeqPtr x y)
	// result: (SETNE (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(Op386SETNE)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not x)
	// result: (XORLconst [1] x)
	for {
		x := v_0
		v.reset(Op386XORLconst)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValue386_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr [off] ptr)
	// result: (ADDLconst [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(Op386ADDLconst)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
}
func rewriteValue386_OpPanicBounds(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 0
	// result: (LoweredPanicBoundsA [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 0) {
			break
		}
		v.reset(Op386LoweredPanicBoundsA)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 1
	// result: (LoweredPanicBoundsB [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 1) {
			break
		}
		v.reset(Op386LoweredPanicBoundsB)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 2
	// result: (LoweredPanicBoundsC [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 2) {
			break
		}
		v.reset(Op386LoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValue386_OpPanicExtend(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PanicExtend [kind] hi lo y mem)
	// cond: boundsABI(kind) == 0
	// result: (LoweredPanicExtendA [kind] hi lo y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		hi := v_0
		lo := v_1
		y := v_2
		mem := v_3
		if !(boundsABI(kind) == 0) {
			break
		}
		v.reset(Op386LoweredPanicExtendA)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg4(hi, lo, y, mem)
		return true
	}
	// match: (PanicExtend [kind] hi lo y mem)
	// cond: boundsABI(kind) == 1
	// result: (LoweredPanicExtendB [kind] hi lo y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		hi := v_0
		lo := v_1
		y := v_2
		mem := v_3
		if !(boundsABI(kind) == 1) {
			break
		}
		v.reset(Op386LoweredPanicExtendB)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg4(hi, lo, y, mem)
		return true
	}
	// match: (PanicExtend [kind] hi lo y mem)
	// cond: boundsABI(kind) == 2
	// result: (LoweredPanicExtendC [kind] hi lo y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		hi := v_0
		lo := v_1
		y := v_2
		mem := v_3
		if !(boundsABI(kind) == 2) {
			break
		}
		v.reset(Op386LoweredPanicExtendC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg4(hi, lo, y, mem)
		return true
	}
	return false
}
func rewriteValue386_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRW <t> x y) (SBBLcarrymask <t> (CMPWconst y [16])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPWconst, types.TypeFlags)
		v2.AuxInt = int16ToAuxInt(16)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh16Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHRW <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHRW)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRW <t> x y) (SBBLcarrymask <t> (CMPLconst y [16])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPLconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(16)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh16Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHRW <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHRW)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh16Ux64 x (Const64 [c]))
	// cond: uint64(c) < 16
	// result: (SHRWconst x [int16(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(Op386SHRWconst)
		v.AuxInt = int16ToAuxInt(int16(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh16Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 16
	// result: (Const16 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 16) {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValue386_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRW <t> x y) (SBBLcarrymask <t> (CMPBconst y [16])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v2.AuxInt = int8ToAuxInt(16)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh16Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHRW <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHRW)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARW <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPWconst y [16])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARW)
		v.Type = t
		v0 := b.NewValue0(v.Pos, Op386ORL, y.Type)
		v1 := b.NewValue0(v.Pos, Op386NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, Op386SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, Op386CMPWconst, types.TypeFlags)
		v3.AuxInt = int16ToAuxInt(16)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SARW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARW <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPLconst y [16])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARW)
		v.Type = t
		v0 := b.NewValue0(v.Pos, Op386ORL, y.Type)
		v1 := b.NewValue0(v.Pos, Op386NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, Op386SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, Op386CMPLconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(16)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SARW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh16x64 x (Const64 [c]))
	// cond: uint64(c) < 16
	// result: (SARWconst x [int16(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(Op386SARWconst)
		v.AuxInt = int16ToAuxInt(int16(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh16x64 x (Const64 [c]))
	// cond: uint64(c) >= 16
	// result: (SARWconst x [15])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 16) {
			break
		}
		v.reset(Op386SARWconst)
		v.AuxInt = int16ToAuxInt(15)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValue386_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARW <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPBconst y [16])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARW)
		v.Type = t
		v0 := b.NewValue0(v.Pos, Op386ORL, y.Type)
		v1 := b.NewValue0(v.Pos, Op386NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, Op386SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v3.AuxInt = int8ToAuxInt(16)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SARW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRL <t> x y) (SBBLcarrymask <t> (CMPWconst y [32])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHRL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPWconst, types.TypeFlags)
		v2.AuxInt = int16ToAuxInt(32)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh32Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRL <t> x y) (SBBLcarrymask <t> (CMPLconst y [32])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHRL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPLconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh32Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh32Ux64 x (Const64 [c]))
	// cond: uint64(c) < 32
	// result: (SHRLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(Op386SHRLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh32Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 32
	// result: (Const32 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 32) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValue386_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRL <t> x y) (SBBLcarrymask <t> (CMPBconst y [32])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHRL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v2.AuxInt = int8ToAuxInt(32)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh32Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARL <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPWconst y [32])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, Op386ORL, y.Type)
		v1 := b.NewValue0(v.Pos, Op386NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, Op386SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, Op386CMPWconst, types.TypeFlags)
		v3.AuxInt = int16ToAuxInt(32)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SARL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARL <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPLconst y [32])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, Op386ORL, y.Type)
		v1 := b.NewValue0(v.Pos, Op386NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, Op386SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, Op386CMPLconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x,
```