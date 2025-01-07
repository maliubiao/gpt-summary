Response:
Let's break down the thought process for analyzing this Go code snippet and generating the desired comprehensive answer.

1. **Understanding the Request:** The core request is to analyze a specific Go file (`rewrite386.go`) and explain its functionality, relate it to general Go concepts, provide code examples, discuss potential pitfalls, and summarize its purpose (as part 8 of 9).

2. **Initial Code Scan and Keyword Recognition:**  The first step is to quickly read through the code, looking for patterns and familiar keywords. Notice the function names like `rewriteValue386_Op...` and `rewriteBlock386`. The `Op...` strongly suggests this code is related to *operations* within a compiler or code transformation framework. The `386` hints at the target architecture. Terms like `Rsh`, `Store`, `Zero`, and comparison flags (`EQ`, `LT`, `GT`) stand out.

3. **Identifying the Core Functionality:** The `rewriteValue386_Op...` functions take a `*Value` as input and return a boolean. This pattern suggests a system for rewriting or optimizing individual operations. The `rewriteBlock386` function operates on `*Block` and likely handles control flow optimizations.

4. **Focusing on `rewriteValue386` Examples:**  Let's pick a few `rewriteValue386` functions and analyze them in detail.

   * **`rewriteValue386_OpRsh32x32`:**  This function deals with right shifts of 32-bit integers by a 32-bit amount. The "match" and "cond" comments are crucial. It checks if the shift amount is bounded (`shiftIsBounded(v)`). If not, it generates more complex code involving `ORL`, `NOTL`, `SBBLcarrymask`, and `CMPBconst` to handle shifts greater than or equal to 32 correctly (by essentially shifting by 31 and preserving the sign). If bounded, it simplifies to a `SARL` (Shift Arithmetic Right Logical). This starts to suggest this code is about ensuring correctness and potentially optimizing shift operations on the 386 architecture.

   * **`rewriteValue386_OpRsh32x64`:** This handles right shifts of a 32-bit value by a 64-bit constant. It checks if the constant is less than 32. If so, it uses `SARLconst` with the constant value. If the constant is 32 or greater, it uses `SARLconst` with 31. This again reinforces the idea of handling edge cases and ensuring correct behavior for shifts exceeding the bit width.

   * **`rewriteValue386_OpStore`:** This function handles memory stores. It differentiates based on the size and type (float or not) of the value being stored and selects the appropriate 386 instruction (`MOVSDstore`, `MOVSSstore`, `MOVLstore`, etc.). This clearly links the code to the generation of specific machine instructions for memory operations.

   * **`rewriteValue386_OpZero`:** This function optimizes setting blocks of memory to zero. It handles small sizes with individual `MOV` instructions and larger sizes using `DUFFZERO` (Duff's device optimization) or `REPSTOSL` (repeat string operation). This highlights the code's role in performance optimization.

5. **Inferring the Overall Context:** Based on the observed patterns, the file appears to be part of the Go compiler's backend, specifically the stage responsible for:

   * **Lowering:** Transforming high-level Go operations into architecture-specific instructions.
   * **Optimization:** Identifying opportunities to replace sequences of instructions with more efficient ones.
   * **Correctness:** Ensuring that operations, especially those with potential edge cases (like shifts), are handled correctly on the target architecture.

6. **Connecting to Go Language Features:**  The operations being rewritten (shifts, stores, zeroing) are fundamental Go operations. The code demonstrates how the compiler translates these high-level concepts to low-level instructions for the 386 architecture. The example code snippets provided in the answer illustrate the Go syntax that would eventually be processed by this rewriting logic.

7. **Analyzing `rewriteBlock386`:** This function deals with conditional branching. It looks for opportunities to simplify or directly map Go's `if` statements and comparison results to 386 conditional jump instructions. For example, it directly maps `SETL` (Set Less) to a `Block386LT`.

8. **Identifying Potential Pitfalls (Though None Explicitly in This Snippet):**  While the provided code doesn't show obvious user-facing errors, the process of generating optimized assembly is complex. Errors in these rewrite rules could lead to incorrect code generation. A broader understanding of compiler development would reveal potential issues like incorrect flag handling or missed optimization opportunities. Since the prompt asked for *user* errors and none were directly apparent in *this code*,  it's correct to state that.

9. **Structuring the Answer:**  Organize the findings logically:
    * Start with a general overview of the file's function.
    * Provide specific examples from `rewriteValue386` with input/output assumptions (even if implicit in the code's logic).
    * Explain `rewriteBlock386`.
    * Connect everything back to Go language features.
    * Discuss command-line parameters (though none are present in this snippet).
    * Address potential user errors (or the lack thereof).
    * Finally, summarize the functionality as requested.

10. **Refining and Reviewing:** Read through the generated answer to ensure clarity, accuracy, and completeness, addressing all parts of the original request. For instance, ensuring the Go code examples are syntactically correct and illustrate the intended behavior.

This systematic approach, moving from a high-level understanding to detailed code analysis and then back to a summarized view, is crucial for effectively analyzing and explaining complex code like this. The keywords and structural patterns within the code provide valuable clues about its purpose within the larger Go compilation process.
这是 `go/src/cmd/compile/internal/ssa/rewrite386.go` 文件的一部分，它负责在 Go 编译器的 SSA (Static Single Assignment) 中间表示阶段，针对 **386 架构** 进行特定的代码重写和优化。

**功能归纳 (针对提供的代码片段):**

这段代码主要定义了一系列的重写规则，用于优化和转换 **右移 (Right Shift)** 和 **内存操作 (Store 和 Zero)** 等操作在 386 架构上的实现方式。具体来说，它针对不同的右移操作数类型和常量情况，以及不同大小的内存清零操作，尝试将其转换为更高效的 386 指令序列。

**更详细的功能分解：**

1. **优化右移操作 (`OpRsh*`)：**
   - 针对不同大小的无符号和有符号整数的右移操作 (`OpRsh8Ux*`, `OpRsh16Ux*`, `OpRsh32Ux*`, `OpRsh8x*`, `OpRsh16x*`, `OpRsh32x*`)，以及不同的移位位数类型 (`int8`, `int16`, `int32`, `int64`)。
   - **常量移位：** 如果移位位数是常量，并且在有效范围内，则会将其转换为 386 的常量移位指令 (`SARLconst`, `SHRBconst`, `SHRLconst`)，例如将 `Rsh32x64 x (Const64 [c])` 转换为 `SARLconst x [int32(c)]`。
   - **非常量移位：** 如果移位位数不是常量，代码会根据 `shiftIsBounded(v)` 的结果进行不同的处理。
     - **`shiftIsBounded(v)` 为 `true` (移位位数在有效范围内)：** 则直接使用 386 的移位指令 (`SARL`, `SHRB`, `SHRL`)。
     - **`shiftIsBounded(v)` 为 `false` (移位位数可能超出范围)：**  为了保证移位操作的正确性，会生成更复杂的指令序列，例如使用 `ORL`, `NOTL`, `SBBLcarrymask`, `CMP*const` 等指令来确保移位结果的正确性，特别是处理移位位数大于等于操作数位数的情况。

2. **优化 `Select0` 和 `Select1` 操作：**
   - 针对 `Mul32uover` (32位无符号乘法并返回溢出标志) 操作，将其转换为 `MULLU` (386 的无符号乘法指令)，并分别使用 `Select0` 获取乘法结果，使用 `Select1` 和 `SETO` 获取溢出标志。

3. **优化 `Signmask` 操作：**
   - 将 `Signmask x` 操作转换为 `SARLconst x [31]`，利用算术右移的特性来提取符号位。

4. **优化 `Slicemask` 操作：**
   - 将 `Slicemask <t> x` 操作转换为 `SARLconst (NEGL <t> x) [31]`， 用于获取切片的掩码。

5. **优化 `Store` 操作：**
   - 根据要存储的数据类型大小和是否为浮点数，选择合适的 386 存储指令 (`MOVSDstore`, `MOVSSstore`, `MOVLstore`, `MOVWstore`, `MOVBstore`)。

6. **优化 `Zero` 操作 (内存清零)：**
   - 针对不同大小的内存清零操作，选择不同的 386 指令序列以提高效率。
     - 小于等于 4 字节：使用 `MOVBstoreconst`, `MOVWstoreconst`, `MOVLstoreconst` 等指令。
     - 较大尺寸：可能会使用循环展开 (`DUFFZERO`) 或 `REPSTOSL` 指令进行批量清零。

7. **优化控制流块 (`rewriteBlock386`)：**
   - 针对不同的控制流块类型 (`Block386EQ`, `Block386GE`, `Block386GT`, `BlockIf`, `Block386LE`, `Block386LT`, `Block386NE`)，根据其控制条件 (通常是比较指令的结果，如 `SETL`, `SETEQ` 等)，将其转换为更底层的 386 条件跳转指令。例如，将 `If (SETL cmp) yes no` 转换为 `LT cmp yes no`。

**Go 语言功能实现推理和代码示例：**

这段代码主要涉及到 Go 语言中的以下功能：

* **整数运算：** 特别是右移操作。
* **内存操作：** 包括变量的存储和内存的清零。
* **控制流：** `if` 语句和其他条件分支结构。

**示例 1：右移操作的优化**

假设有以下 Go 代码：

```go
package main

func rightShift(x int32, y uint32) int32 {
	return x >> y
}

func main() {
	a := int32(-10)
	b := uint32(2)
	result := rightShift(a, b)
	println(result) // 输出 -3
}
```

当编译器编译 `rightShift` 函数时，如果目标架构是 386，并且 `y` 在编译时未知 (非常量)，`rewrite386.go` 中的 `rewriteValue386_OpRsh32x32` 函数可能会被应用。

**假设的 SSA 输入 (简化表示):**

```
v1 = Param: x (int32)
v2 = Param: y (uint32)
v3 = Rsh32x32 <int32> v1 v2
Return v3
```

**可能的 SSA 输出 (如果 `shiftIsBounded(v)` 为 `false`):**

```
v1 = Param: x (int32)
v2 = Param: y (uint32)
b1:
  v4 = ORL <uint32> v2 (NOTL <uint32> (SBBLcarrymask <uint32> (CMPBconst v2 [32])))
  v3 = SARL <int32> v1 v4
Return v3
```

这里 `SARL` 是 386 的算术右移指令。复杂的 `ORL`, `NOTL` 等指令是为了处理移位位数超出 32 的情况，确保行为的正确性。

**示例 2：内存清零的优化**

假设有以下 Go 代码：

```go
package main

func clearMemory(arr []int) {
	for i := range arr {
		arr[i] = 0
	}
}

func main() {
	myArray := make([]int, 10)
	clearMemory(myArray)
	println(myArray[0]) // 输出 0
}
```

在 `clearMemory` 函数中，对切片 `arr` 进行清零操作。编译器可能会将循环内的赋值操作转换为 `Zero` 操作。

**假设的 SSA 输入 (简化表示，假设对连续内存块清零):**

```
v1 = Param: arr ([]int)
v2 = Len <int> v1
v3 = Convert <uintptr> v2
v4 = ConstInt 0
v5 = PtrOfIndex <*int> v1 v4
v6 = Zero [40] v5 mem // 假设 int 大小为 4 字节，10 个元素共 40 字节
Return mem
```

**可能的 SSA 输出 (如果大小合适，且允许使用 `DUFFZERO`):**

```
v1 = Param: arr ([]int)
v2 = Len <int> v1
v3 = Convert <uintptr> v2
v4 = ConstInt 0
v5 = PtrOfIndex <*int> v1 v4
v6 = DUFFZERO [1*(128-40/4)] v5 (MOVLconst [0]) mem
Return v6
```

这里 `DUFFZERO` 是一个使用了 Duff's device 优化的指令序列，用于高效地将内存块设置为零。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它是在 Go 编译器的内部 SSA 优化阶段执行的，而命令行参数的解析和处理通常发生在编译过程的早期阶段。这段代码依赖于编译器已经分析过的程序结构和类型信息。

**使用者易犯错的点：**

这段代码是编译器内部的实现细节，普通 Go 语言开发者不会直接接触到它，因此不会有使用者易犯错的点。这里的“使用者”是 Go 编译器本身，或者更精确地说，是 SSA 生成和优化的过程。

**作为第 8 部分的功能归纳：**

作为 9 个部分中的第 8 部分，可以推断 `rewrite386.go` 文件定义了一系列针对 386 架构的 **最终代码生成前的优化和转换规则**。在这个阶段，高层次的 SSA 操作会被转换为更接近目标机器指令的操作序列。第 8 部分很可能专注于 **基本运算 (如移位) 和内存操作的底层实现和优化**，为最终的汇编代码生成做好准备。接下来的第 9 部分可能涉及更细节的指令选择、寄存器分配或其他架构特定的优化。

总而言之，这段 `rewrite386.go` 代码是 Go 编译器针对 386 架构进行代码优化的重要组成部分，它通过模式匹配和规则替换，将通用的 SSA 中间表示转换为更高效的 386 指令序列。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewrite386.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第8部分，共9部分，请归纳一下它的功能

"""
 v0)
		return true
	}
	// match: (Rsh32x32 <t> x y)
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
func rewriteValue386_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh32x64 x (Const64 [c]))
	// cond: uint64(c) < 32
	// result: (SARLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(Op386SARLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh32x64 x (Const64 [c]))
	// cond: uint64(c) >= 32
	// result: (SARLconst x [31])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 32) {
			break
		}
		v.reset(Op386SARLconst)
		v.AuxInt = int32ToAuxInt(31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValue386_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARL <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPBconst y [32])))))
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
		v3 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v3.AuxInt = int8ToAuxInt(32)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x8 <t> x y)
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
func rewriteValue386_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRB <t> x y) (SBBLcarrymask <t> (CMPWconst y [8])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHRB, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPWconst, types.TypeFlags)
		v2.AuxInt = int16ToAuxInt(8)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh8Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHRB <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHRB)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRB <t> x y) (SBBLcarrymask <t> (CMPLconst y [8])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHRB, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPLconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(8)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh8Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHRB <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHRB)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh8Ux64 x (Const64 [c]))
	// cond: uint64(c) < 8
	// result: (SHRBconst x [int8(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(Op386SHRBconst)
		v.AuxInt = int8ToAuxInt(int8(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh8Ux64 _ (Const64 [c]))
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
func rewriteValue386_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRB <t> x y) (SBBLcarrymask <t> (CMPBconst y [8])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386ANDL)
		v0 := b.NewValue0(v.Pos, Op386SHRB, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v2.AuxInt = int8ToAuxInt(8)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh8Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SHRB <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SHRB)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARB <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPWconst y [8])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARB)
		v.Type = t
		v0 := b.NewValue0(v.Pos, Op386ORL, y.Type)
		v1 := b.NewValue0(v.Pos, Op386NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, Op386SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, Op386CMPWconst, types.TypeFlags)
		v3.AuxInt = int16ToAuxInt(8)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SARB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARB <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPLconst y [8])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARB)
		v.Type = t
		v0 := b.NewValue0(v.Pos, Op386ORL, y.Type)
		v1 := b.NewValue0(v.Pos, Op386NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, Op386SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, Op386CMPLconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(8)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SARB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh8x64 x (Const64 [c]))
	// cond: uint64(c) < 8
	// result: (SARBconst x [int8(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(Op386SARBconst)
		v.AuxInt = int8ToAuxInt(int8(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh8x64 x (Const64 [c]))
	// cond: uint64(c) >= 8
	// result: (SARBconst x [7])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 8) {
			break
		}
		v.reset(Op386SARBconst)
		v.AuxInt = int8ToAuxInt(7)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValue386_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARB <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPBconst y [8])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARB)
		v.Type = t
		v0 := b.NewValue0(v.Pos, Op386ORL, y.Type)
		v1 := b.NewValue0(v.Pos, Op386NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, Op386SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v3.AuxInt = int8ToAuxInt(8)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SARB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(Op386SARB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValue386_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Mul32uover x y))
	// result: (Select0 <typ.UInt32> (MULLU x y))
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSelect0)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, Op386MULLU, types.NewTuple(typ.UInt32, types.TypeFlags))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValue386_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Mul32uover x y))
	// result: (SETO (Select1 <types.TypeFlags> (MULLU x y)))
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(Op386SETO)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, Op386MULLU, types.NewTuple(typ.UInt32, types.TypeFlags))
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValue386_OpSignmask(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Signmask x)
	// result: (SARLconst x [31])
	for {
		x := v_0
		v.reset(Op386SARLconst)
		v.AuxInt = int32ToAuxInt(31)
		v.AddArg(x)
		return true
	}
}
func rewriteValue386_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SARLconst (NEGL <t> x) [31])
	for {
		t := v.Type
		x := v_0
		v.reset(Op386SARLconst)
		v.AuxInt = int32ToAuxInt(31)
		v0 := b.NewValue0(v.Pos, Op386NEGL, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValue386_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && t.IsFloat()
	// result: (MOVSDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && t.IsFloat()) {
			break
		}
		v.reset(Op386MOVSDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && t.IsFloat()
	// result: (MOVSSstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && t.IsFloat()) {
			break
		}
		v.reset(Op386MOVSSstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && !t.IsFloat()
	// result: (MOVLstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && !t.IsFloat()) {
			break
		}
		v.reset(Op386MOVLstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 2
	// result: (MOVWstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 2) {
			break
		}
		v.reset(Op386MOVWstore)
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
		v.reset(Op386MOVBstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValue386_OpZero(v *Value) bool {
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
	// match: (Zero [1] destptr mem)
	// result: (MOVBstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [2] destptr mem)
	// result: (MOVWstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [4] destptr mem)
	// result: (MOVLstoreconst [0] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(0)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [3] destptr mem)
	// result: (MOVBstoreconst [makeValAndOff(0,2)] destptr (MOVWstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 2))
		v0 := b.NewValue0(v.Pos, Op386MOVWstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [5] destptr mem)
	// result: (MOVBstoreconst [makeValAndOff(0,4)] destptr (MOVLstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v0 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [6] destptr mem)
	// result: (MOVWstoreconst [makeValAndOff(0,4)] destptr (MOVLstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v0 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [7] destptr mem)
	// result: (MOVLstoreconst [makeValAndOff(0,3)] destptr (MOVLstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 3))
		v0 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s%4 != 0 && s > 4
	// result: (Zero [s-s%4] (ADDLconst destptr [int32(s%4)]) (MOVLstoreconst [0] destptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s%4 != 0 && s > 4) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(s - s%4)
		v0 := b.NewValue0(v.Pos, Op386ADDLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(int32(s % 4))
		v0.AddArg(destptr)
		v1 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(0)
		v1.AddArg2(destptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [8] destptr mem)
	// result: (MOVLstoreconst [makeValAndOff(0,4)] destptr (MOVLstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v0 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [12] destptr mem)
	// result: (MOVLstoreconst [makeValAndOff(0,8)] destptr (MOVLstoreconst [makeValAndOff(0,4)] destptr (MOVLstoreconst [makeValAndOff(0,0)] destptr mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 8))
		v0 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v1 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v1.AddArg2(destptr, mem)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [16] destptr mem)
	// result: (MOVLstoreconst [makeValAndOff(0,12)] destptr (MOVLstoreconst [makeValAndOff(0,8)] destptr (MOVLstoreconst [makeValAndOff(0,4)] destptr (MOVLstoreconst [makeValAndOff(0,0)] destptr mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(Op386MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 12))
		v0 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 8))
		v1 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v2 := b.NewValue0(v.Pos, Op386MOVLstoreconst, types.TypeMem)
		v2.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v2.AddArg2(destptr, mem)
		v1.AddArg2(destptr, v2)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s > 16 && s <= 4*128 && s%4 == 0 && !config.noDuffDevice
	// result: (DUFFZERO [1*(128-s/4)] destptr (MOVLconst [0]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s > 16 && s <= 4*128 && s%4 == 0 && !config.noDuffDevice) {
			break
		}
		v.reset(Op386DUFFZERO)
		v.AuxInt = int64ToAuxInt(1 * (128 - s/4))
		v0 := b.NewValue0(v.Pos, Op386MOVLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(destptr, v0, mem)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: (s > 4*128 || (config.noDuffDevice && s > 16)) && s%4 == 0
	// result: (REPSTOSL destptr (MOVLconst [int32(s/4)]) (MOVLconst [0]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !((s > 4*128 || (config.noDuffDevice && s > 16)) && s%4 == 0) {
			break
		}
		v.reset(Op386REPSTOSL)
		v0 := b.NewValue0(v.Pos, Op386MOVLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(int32(s / 4))
		v1 := b.NewValue0(v.Pos, Op386MOVLconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0)
		v.AddArg4(destptr, v0, v1, mem)
		return true
	}
	return false
}
func rewriteValue386_OpZeromask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Zeromask <t> x)
	// result: (XORLconst [-1] (SBBLcarrymask <t> (CMPLconst x [1])))
	for {
		t := v.Type
		x := v_0
		v.reset(Op386XORLconst)
		v.AuxInt = int32ToAuxInt(-1)
		v0 := b.NewValue0(v.Pos, Op386SBBLcarrymask, t)
		v1 := b.NewValue0(v.Pos, Op386CMPLconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(1)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteBlock386(b *Block) bool {
	switch b.Kind {
	case Block386EQ:
		// match: (EQ (InvertFlags cmp) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == Op386InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386EQ, cmp)
			return true
		}
		// match: (EQ (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (EQ (FlagLT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagLT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagLT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagLT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagGT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagGT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagGT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagGT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case Block386GE:
		// match: (GE (InvertFlags cmp) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == Op386InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386LE, cmp)
			return true
		}
		// match: (GE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (FlagLT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagLT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GE (FlagLT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagLT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GE (FlagGT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagGT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (FlagGT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagGT_UGT {
			b.Reset(BlockFirst)
			return true
		}
	case Block386GT:
		// match: (GT (InvertFlags cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == Op386InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386LT, cmp)
			return true
		}
		// match: (GT (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagLT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagLT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagLT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagLT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagGT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagGT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GT (FlagGT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagGT_UGT {
			b.Reset(BlockFirst)
			return true
		}
	case BlockIf:
		// match: (If (SETL cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == Op386SETL {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386LT, cmp)
			return true
		}
		// match: (If (SETLE cmp) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == Op386SETLE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386LE, cmp)
			return true
		}
		// match: (If (SETG cmp) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == Op386SETG {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386GT, cmp)
			return true
		}
		// match: (If (SETGE cmp) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == Op386SETGE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386GE, cmp)
			return true
		}
		// match: (If (SETEQ cmp) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == Op386SETEQ {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386EQ, cmp)
			return true
		}
		// match: (If (SETNE cmp) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == Op386SETNE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386NE, cmp)
			return true
		}
		// match: (If (SETB cmp) yes no)
		// result: (ULT cmp yes no)
		for b.Controls[0].Op == Op386SETB {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386ULT, cmp)
			return true
		}
		// match: (If (SETBE cmp) yes no)
		// result: (ULE cmp yes no)
		for b.Controls[0].Op == Op386SETBE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386ULE, cmp)
			return true
		}
		// match: (If (SETA cmp) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == Op386SETA {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386UGT, cmp)
			return true
		}
		// match: (If (SETAE cmp) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == Op386SETAE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386UGE, cmp)
			return true
		}
		// match: (If (SETO cmp) yes no)
		// result: (OS cmp yes no)
		for b.Controls[0].Op == Op386SETO {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386OS, cmp)
			return true
		}
		// match: (If (SETGF cmp) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == Op386SETGF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386UGT, cmp)
			return true
		}
		// match: (If (SETGEF cmp) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == Op386SETGEF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386UGE, cmp)
			return true
		}
		// match: (If (SETEQF cmp) yes no)
		// result: (EQF cmp yes no)
		for b.Controls[0].Op == Op386SETEQF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386EQF, cmp)
			return true
		}
		// match: (If (SETNEF cmp) yes no)
		// result: (NEF cmp yes no)
		for b.Controls[0].Op == Op386SETNEF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386NEF, cmp)
			return true
		}
		// match: (If cond yes no)
		// result: (NE (TESTB cond cond) yes no)
		for {
			cond := b.Controls[0]
			v0 := b.NewValue0(cond.Pos, Op386TESTB, types.TypeFlags)
			v0.AddArg2(cond, cond)
			b.resetWithControl(Block386NE, v0)
			return true
		}
	case Block386LE:
		// match: (LE (InvertFlags cmp) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == Op386InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386GE, cmp)
			return true
		}
		// match: (LE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagLT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagLT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagLT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagLT_UGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagGT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagGT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LE (FlagGT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagGT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case Block386LT:
		// match: (LT (InvertFlags cmp) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == Op386InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(Block386GT, cmp)
			return true
		}
		// match: (LT (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LT (FlagLT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagLT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LT (FlagLT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == Op386FlagLT_UGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LT (FlagGT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagGT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LT (FlagGT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == Op386FlagGT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case Block386NE:
		// match: (NE (TESTB (SETL cmp) (SETL cmp)) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETL {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETL || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386LT, cmp)
			return true
		}
		// match: (NE (TESTB (SETLE cmp) (SETLE cmp)) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETLE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETLE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386LE, cmp)
			return true
		}
		// match: (NE (TESTB (SETG cmp) (SETG cmp)) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETG {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETG || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386GT, cmp)
			return true
		}
		// match: (NE (TESTB (SETGE cmp) (SETGE cmp)) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETGE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETGE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386GE, cmp)
			return true
		}
		// match: (NE (TESTB (SETEQ cmp) (SETEQ cmp)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETEQ {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETEQ || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386EQ, cmp)
			return true
		}
		// match: (NE (TESTB (SETNE cmp) (SETNE cmp)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETNE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETNE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386NE, cmp)
			return true
		}
		// match: (NE (TESTB (SETB cmp) (SETB cmp)) yes no)
		// result: (ULT cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETB {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETB || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386ULT, cmp)
			return true
		}
		// match: (NE (TESTB (SETBE cmp) (SETBE cmp)) yes no)
		// result: (ULE cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETBE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETBE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386ULE, cmp)
			return true
		}
		// match: (NE (TESTB (SETA cmp) (SETA cmp)) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETA {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETA || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386UGT, cmp)
			return true
		}
		// match: (NE (TESTB (SETAE cmp) (SETAE cmp)) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETAE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETAE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386UGE, cmp)
			return true
		}
		// match: (NE (TESTB (SETO cmp) (SETO cmp)) yes no)
		// result: (OS cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETO {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETO || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(Block386OS, cmp)
			return true
		}
		// match: (NE (TESTB (SETGF cmp) (SETGF cmp)) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == Op386TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != Op386SETGF {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != Op386SETGF || cmp != 
"""




```