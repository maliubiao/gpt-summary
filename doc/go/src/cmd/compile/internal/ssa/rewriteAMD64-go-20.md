Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understanding the Context:** The initial information is crucial: "path is go/src/cmd/compile/internal/ssa/rewriteAMD64.go", "part of a Go language implementation", and "part 21 of 23". This immediately tells us we're dealing with low-level compiler optimizations for the AMD64 architecture. The "rewrite" part suggests this code transforms intermediate representations (SSA - Static Single Assignment) of Go code into more efficient AMD64 instructions.

2. **Scanning for Patterns:**  A quick scan of the code reveals repeating structures. We see many functions named `rewriteValueAMD64_Op...`. This suggests each function handles the rewriting of a specific Go operation (`Op`).

3. **Focusing on a Single Function:** To understand the details, let's pick a relatively simple function, like `rewriteValueAMD64_OpRsh64x16`.

4. **Analyzing the Function's Structure:**  Each `rewriteValueAMD64_Op...` function follows a pattern:
    * It takes a `*Value` as input. This `Value` represents an SSA value, which holds information about an operation and its arguments.
    * It extracts the arguments of the operation (`v.Args`).
    * It often has multiple "match" blocks. Each match block checks if the current `Value` matches a specific pattern.
    * Inside a match block, there's a "cond" (condition). If the condition is true, the code inside the "result" block executes.
    * The "result" block rewrites the `Value` by changing its operation (`v.reset`) and its arguments. It often creates new `Value`s using `b.NewValue0`.

5. **Deconstructing a "Match" Block (Example: `rewriteValueAMD64_OpRsh64x16`):**
    * **`// match: (Rsh64x16 <t> x y)`:** This tells us the function is handling the right shift operation (`Rsh64x16`) where a 64-bit integer `x` is shifted by a 16-bit integer `y`. `<t>` represents the type.
    * **`// cond: !shiftIsBounded(v)`:** This condition checks if the shift amount `y` is potentially greater than or equal to the size of `x` (64 bits). If it's *not* bounded, special handling is needed.
    * **`// result: (SARQ <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPWconst y [64])))))`:** This is the core of the rewrite. Instead of a direct shift, it's creating a more complex sequence of AMD64 instructions. Let's break this down further:
        * `SARQ <t> x ...`:  This is the AMD64 instruction for an arithmetic right shift of a quad word (64 bits).
        * The complex expression inside the parentheses calculates a mask. If `y` is greater than or equal to 64, this mask will effectively become all ones, ensuring the result of the shift is either 0 or -1 (preserving the sign bit for signed shifts). This is the standard way to handle unbounded shifts in many architectures.
    * The second "match" block for `Rsh64x16` handles the case where `shiftIsBounded(v)` is true, meaning the shift amount is within the valid range. In this case, it can directly use the `SARQ` instruction.

6. **Inferring Functionality (Based on Operation Names):** By looking at the `Op` names in the function names (e.g., `OpRsh64x16`, `OpRsh8Ux32`, `OpSelect0`, `OpStore`, `OpZero`), we can infer the high-level Go operations being optimized. These include:
    * Right shifts (signed and unsigned, with different operand sizes).
    * `Select0` and `Select1`: Accessing the first or second element of a tuple (often results of multi-value operations).
    * `Store`: Writing a value to memory.
    * `Zero`: Setting a block of memory to zero.

7. **Recognizing Optimization Techniques:** The code demonstrates several optimization techniques:
    * **Lowering High-Level Operations to Specific Instructions:**  Go's generic right shift is being translated into the AMD64 `SARQ` instruction.
    * **Handling Edge Cases:** The code explicitly handles unbounded shift amounts.
    * **Using Carry Flags:**  Operations like `Add64carry` and `Sub64borrow` are being translated to AMD64 instructions that utilize the carry flag for multi-word arithmetic.
    * **Optimizing Memory Operations:** The `SelectN` function attempts to optimize `runtime.memmove` calls into a direct `Move` operation. The `Zero` function optimizes zeroing memory blocks using efficient `MOV` instructions.
    * **Atomic Operations:** The `Select1` function has specific optimizations for atomic `AND` and `OR` operations.
    * **Conditional Moves:** `SpectreIndex` and `SpectreSliceIndex` use conditional move instructions (`CMOVQCC`, `CMOVQHI`), which can avoid branch mispredictions on modern CPUs.

8. **Inferring Go Language Feature Implementations:** Based on the optimized operations, we can infer the corresponding Go language features:
    * **Shift Operators:** `>>` for signed right shift, `>>>` for unsigned right shift (though the code doesn't explicitly show unsigned shifts here, other parts of the file likely do).
    * **Multi-Value Returns:** The `Select0` and `Select1` operations are crucial for handling functions that return multiple values.
    * **Assignments and Memory Writes:** The `Store` operation is fundamental for any assignment operation.
    * **Zero Initialization:**  The `Zero` operation is used when variables are declared without explicit initialization or when memory is allocated using `make`.
    * **Atomic Operations:** The optimizations for `LoweredAtomicAnd` and `LoweredAtomicOr` relate to the `sync/atomic` package.
    * **Slices and Arrays:** The `SpectreIndex` and `SpectreSliceIndex` optimizations relate to accessing elements of slices and arrays, specifically to mitigate Spectre vulnerabilities.

9. **Command-Line Arguments (Inference):**  This specific code snippet doesn't directly handle command-line arguments. However, given its context in the Go compiler, we know that the compiler as a whole takes various command-line flags (e.g., `-gcflags` to pass flags to the compiler backend). These flags could influence the code generation process and potentially enable or disable certain optimizations. For example, flags related to security might affect whether Spectre mitigations are applied. Flags related to target architecture would definitely influence the choice of instructions.

10. **User Mistakes (Potential):** While this code is internal to the compiler, understanding it can help avoid performance pitfalls. For example, performing very large shifts might not be as efficient as expected if the compiler doesn't optimize them well. However, the provided code *is* the optimization, so user mistakes are less direct here. A more relevant example from a *different* part of the compiler would be how inlining decisions impact performance.

11. **Summarizing Functionality (as requested in the prompt):** The provided code snippet from `rewriteAMD64.go` focuses on optimizing various Go language operations for the AMD64 architecture. It specifically rewrites SSA instructions for right shifts (signed and unsigned, with different operand sizes), accessing elements from multi-value results, storing values to memory, zeroing memory blocks, and performing atomic operations. It also includes mitigations for Spectre vulnerabilities when accessing array and slice elements. The overall goal is to translate high-level Go operations into efficient sequences of low-level AMD64 instructions.

This detailed thought process combines code analysis, pattern recognition, and knowledge of compiler internals and computer architecture to understand the functionality of the provided Go code.
这是 `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` 文件的一部分，它负责在 Go 编译器的 SSA（Static Single Assignment）中间表示阶段，将一些通用的操作符（Op）针对 AMD64 架构进行特定的重写和优化。

**功能归纳:**

这段代码主要负责 **将 Go 语言中的右移操作 (`>>`) 和一些特定的复合操作 (如乘法溢出, 带进位/借位的加减法, 原子操作) 转换为更高效的 AMD64 汇编指令序列。** 它还包含了一些针对 Spectre 漏洞的缓解措施，以及对 `select` 语句和内存操作的优化。

**具体功能列表:**

1. **优化右移操作 (`OpRsh`)：**
   - 针对不同大小和类型的操作数（例如 `Rsh64x16`、`Rsh8Ux32` 等），它会根据移位量是否可能超出范围 (`shiftIsBounded`) 来选择不同的 AMD64 指令。
   - 如果移位量可能超出范围，它会生成更复杂的指令序列，确保结果的正确性，例如使用 `ORL`, `NOTL`, `SBBLcarrymask`, `CMP` 等指令来创建一个掩码。
   - 如果移位量在范围内，则直接使用 AMD64 的移位指令（例如 `SARQ`、`SHRB`）。

2. **优化带符号乘法溢出 (`OpMul64uover`, `OpMul32uover`)：**
   - 将 Go 的带符号乘法溢出检查操作转换为 AMD64 的 `MULQU` 和 `MULLU` 指令，这些指令会产生一个双字的结果，并配合 `Select0` 和 `Select1` 来分别获取低位和溢出标志。

3. **优化带进位/借位的加减法 (`OpAdd64carry`, `OpSub64borrow`)：**
   - 将 Go 的带进位/借位加减法操作转换为 AMD64 的 `ADCQ` 和 `SBBQ` 指令，并使用 `Select1` 和 `NEGLflags` 来处理进位/借位标志。

4. **优化 `Select0` 和 `Select1` 操作：**
   - `Select0` 用于获取一个多返回值函数的第一个返回值，`Select1` 用于获取第二个返回值。
   - 此代码针对一些特定的 `Select0` 和 `Select1` 的输入进行了优化，例如将 `Select0(Mul64uover)` 转换为 `Select0(MULQU)`，将 `Select1(Add64carry)` 转换为更底层的指令序列。
   - 还优化了访问由 `AddTupleFirst32` 和 `AddTupleFirst64` 创建的元组的情况。

5. **优化原子操作 (`LoweredAtomicAnd64`, `LoweredAtomicOr64` 等)：**
   - 将 SSA 的原子操作转换为 AMD64 的锁指令 (`ANDQlock`, `ORQlock` 等)，前提是该原子操作只被使用一次。

6. **优化 `SelectN` 操作（通常用于多返回值函数）：**
   - 尝试识别 `runtime.memmove` 的调用模式，并将其转换为更高效的 `Move` 指令。 这涉及到检查特定的指令序列和参数。

7. **优化 `Slicemask` 操作：**
   - 将获取切片掩码的操作转换为 AMD64 的 `SARQconst` 和 `NEGQ` 指令。

8. **实现 Spectre 漏洞缓解措施 (`SpectreIndex`, `SpectreSliceIndex`)：**
   - 当访问数组或切片时，为了防止 Spectre 漏洞，会插入 `CMOVQCC` 或 `CMOVQHI` 指令，基于比较结果条件移动，避免分支预测带来的安全风险。

9. **优化 `Store` 操作：**
   - 根据存储的数据类型大小和是否为浮点数，选择合适的 AMD64 存储指令 (`MOVSDstore`, `MOVSSstore`, `MOVQstore`, `MOVLstore`, `MOVWstore`, `MOVBstore`)。

10. **优化 `Trunc` 操作：**
    - 将浮点数截断操作转换为 AMD64 的 `ROUNDSD` 指令。

11. **优化 `Zero` 操作 (内存清零)：**
    - 针对不同大小的内存清零操作，使用不同的 `MOV` 指令组合，以实现高效的内存清零。 特别是针对小块内存和使用 SSE 指令的情况进行了优化。

**代码推理与示例:**

以 `rewriteValueAMD64_OpRsh64x16` 为例：

```go
func rewriteValueAMD64_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARQ <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPWconst y [64])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64ORL, y.Type)
		v1 := b.NewValue0(v.Pos, OpAMD64NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, OpAMD64CMPWconst, types.TypeFlags)
		v3.AuxInt = int16ToAuxInt(64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SARQ x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.AddArg2(x, y)
		return true
	}
	return false
}
```

**假设的输入和输出：**

**假设输入 Go 代码:**

```go
package main

func main() {
	var a int64 = 100
	var b uint16 = 70
	c := a >> b
	_ = c
}
```

**SSA 表示中 `a >> b` 的部分 (简化):**

```
v1 = Const64 <int64> [100]
v2 = ConvU16to64 <uint64> v_b  // 假设 v_b 是 b 的 SSA 值
v3 = Rsh64x64 <int64> v1 v2
```

**`rewriteValueAMD64_OpRsh64x64` 函数的处理 (因为 `b` 被转换为 `uint64`):**

如果 `shiftIsBounded(v3)` 返回 `false`（例如，编译器无法确定 `b` 的值是否小于 64），则会匹配第一个 `match`，并生成如下 AMD64 指令对应的 SSA：

```
v4 = SARQ <int64> v1 v5
v5 = ORQ <uint64> v2 v6
v6 = NOTQ <uint64> v7
v7 = SBBQcarrymask <uint64> v8
v8 = CMPQconst <types.TypeFlags> v2 [64]
```

这段 SSA 对应于以下 AMD64 汇编（大致）：

```assembly
CMPQ $64, b  // 比较 b 和 64
SBBQ $-1, $-1 // 设置为全 0 或全 1 基于比较结果
NOTQ  %rax      // 取反
ORQ   b, %rax      // 或操作
SARQ  %cl, a      // 算术右移
```

如果 `shiftIsBounded(v3)` 返回 `true`，则会匹配第二个 `match`，直接生成 `SARQ` 指令：

```
v4 = SARQ <int64> v1 v2
```

对应 AMD64 汇编：

```assembly
SARQ  %cl, a
```

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。它是在 Go 编译器的编译过程中被调用的。Go 编译器的命令行参数会影响整个编译过程，包括是否启用某些优化。例如，`-gcflags "-N"` 可以禁用优化，这将阻止此类重写规则生效。

**使用者易犯错的点：**

由于这段代码是编译器内部的实现，普通 Go 开发者不会直接与其交互，因此不易犯错。然而，理解这些优化有助于理解 Go 代码在特定架构上的执行效率。

**总结这段代码的功能：**

这段 `rewriteAMD64.go` 代码（的第 21 部分）的核心功能是针对 AMD64 架构优化 Go 语言的右移操作以及一些特定的复合操作和内存操作。它根据操作数的类型、大小以及特定的条件，将通用的 SSA 操作符转换为更高效的 AMD64 汇编指令序列，并包含针对 Spectre 漏洞的缓解措施。 它是 Go 编译器后端优化的重要组成部分。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第21部分，共23部分，请归纳一下它的功能

"""
Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARQ <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPWconst y [64])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64ORL, y.Type)
		v1 := b.NewValue0(v.Pos, OpAMD64NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, OpAMD64CMPWconst, types.TypeFlags)
		v3.AuxInt = int16ToAuxInt(64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SARQ x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARQ <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPLconst y [64])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64ORL, y.Type)
		v1 := b.NewValue0(v.Pos, OpAMD64NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SARQ x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARQ <t> x (ORQ <y.Type> y (NOTQ <y.Type> (SBBQcarrymask <y.Type> (CMPQconst y [64])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64ORQ, y.Type)
		v1 := b.NewValue0(v.Pos, OpAMD64NOTQ, y.Type)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBQcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SARQ x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARQ <t> x (ORL <y.Type> y (NOTL <y.Type> (SBBLcarrymask <y.Type> (CMPBconst y [64])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64ORL, y.Type)
		v1 := b.NewValue0(v.Pos, OpAMD64NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, OpAMD64CMPBconst, types.TypeFlags)
		v3.AuxInt = int8ToAuxInt(64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SARQ x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARQ)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh8Ux16(v *Value) bool {
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
		v.reset(OpAMD64ANDL)
		v0 := b.NewValue0(v.Pos, OpAMD64SHRB, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, OpAMD64CMPWconst, types.TypeFlags)
		v2.AuxInt = int16ToAuxInt(8)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh8Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SHRB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SHRB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh8Ux32(v *Value) bool {
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
		v.reset(OpAMD64ANDL)
		v0 := b.NewValue0(v.Pos, OpAMD64SHRB, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(8)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh8Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SHRB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SHRB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (ANDL (SHRB <t> x y) (SBBLcarrymask <t> (CMPQconst y [8])))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64ANDL)
		v0 := b.NewValue0(v.Pos, OpAMD64SHRB, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(8)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh8Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SHRB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SHRB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh8Ux8(v *Value) bool {
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
		v.reset(OpAMD64ANDL)
		v0 := b.NewValue0(v.Pos, OpAMD64SHRB, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, t)
		v2 := b.NewValue0(v.Pos, OpAMD64CMPBconst, types.TypeFlags)
		v2.AuxInt = int8ToAuxInt(8)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Rsh8Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SHRB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SHRB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh8x16(v *Value) bool {
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
		v.reset(OpAMD64SARB)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64ORL, y.Type)
		v1 := b.NewValue0(v.Pos, OpAMD64NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, OpAMD64CMPWconst, types.TypeFlags)
		v3.AuxInt = int16ToAuxInt(8)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SARB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh8x32(v *Value) bool {
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
		v.reset(OpAMD64SARB)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64ORL, y.Type)
		v1 := b.NewValue0(v.Pos, OpAMD64NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(8)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SARB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (SARB <t> x (ORQ <y.Type> y (NOTQ <y.Type> (SBBQcarrymask <y.Type> (CMPQconst y [8])))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARB)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64ORQ, y.Type)
		v1 := b.NewValue0(v.Pos, OpAMD64NOTQ, y.Type)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBQcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(8)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SARB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpRsh8x8(v *Value) bool {
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
		v.reset(OpAMD64SARB)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64ORL, y.Type)
		v1 := b.NewValue0(v.Pos, OpAMD64NOTL, y.Type)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBLcarrymask, y.Type)
		v3 := b.NewValue0(v.Pos, OpAMD64CMPBconst, types.TypeFlags)
		v3.AuxInt = int8ToAuxInt(8)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg2(y, v1)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SARB x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpAMD64SARB)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Mul64uover x y))
	// result: (Select0 <typ.UInt64> (MULQU x y))
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpAMD64MULQU, types.NewTuple(typ.UInt64, types.TypeFlags))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
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
		v0 := b.NewValue0(v.Pos, OpAMD64MULLU, types.NewTuple(typ.UInt32, types.TypeFlags))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADCQ x y (Select1 <types.TypeFlags> (NEGLflags c))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpAMD64ADCQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpAMD64NEGLflags, types.NewTuple(typ.UInt32, types.TypeFlags))
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Sub64borrow x y c))
	// result: (Select0 <typ.UInt64> (SBBQ x y (Select1 <types.TypeFlags> (NEGLflags c))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpAMD64SBBQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpAMD64NEGLflags, types.NewTuple(typ.UInt32, types.TypeFlags))
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 <t> (AddTupleFirst32 val tuple))
	// result: (ADDL val (Select0 <t> tuple))
	for {
		t := v.Type
		if v_0.Op != OpAMD64AddTupleFirst32 {
			break
		}
		tuple := v_0.Args[1]
		val := v_0.Args[0]
		v.reset(OpAMD64ADDL)
		v0 := b.NewValue0(v.Pos, OpSelect0, t)
		v0.AddArg(tuple)
		v.AddArg2(val, v0)
		return true
	}
	// match: (Select0 <t> (AddTupleFirst64 val tuple))
	// result: (ADDQ val (Select0 <t> tuple))
	for {
		t := v.Type
		if v_0.Op != OpAMD64AddTupleFirst64 {
			break
		}
		tuple := v_0.Args[1]
		val := v_0.Args[0]
		v.reset(OpAMD64ADDQ)
		v0 := b.NewValue0(v.Pos, OpSelect0, t)
		v0.AddArg(tuple)
		v.AddArg2(val, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Mul64uover x y))
	// result: (SETO (Select1 <types.TypeFlags> (MULQU x y)))
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpAMD64SETO)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpAMD64MULQU, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Mul32uover x y))
	// result: (SETO (Select1 <types.TypeFlags> (MULLU x y)))
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpAMD64SETO)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpAMD64MULLU, types.NewTuple(typ.UInt32, types.TypeFlags))
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Add64carry x y c))
	// result: (NEGQ <typ.UInt64> (SBBQcarrymask <typ.UInt64> (Select1 <types.TypeFlags> (ADCQ x y (Select1 <types.TypeFlags> (NEGLflags c))))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpAMD64NEGQ)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpAMD64SBBQcarrymask, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpAMD64ADCQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v3 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v4 := b.NewValue0(v.Pos, OpAMD64NEGLflags, types.NewTuple(typ.UInt32, types.TypeFlags))
		v4.AddArg(c)
		v3.AddArg(v4)
		v2.AddArg3(x, y, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Sub64borrow x y c))
	// result: (NEGQ <typ.UInt64> (SBBQcarrymask <typ.UInt64> (Select1 <types.TypeFlags> (SBBQ x y (Select1 <types.TypeFlags> (NEGLflags c))))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpAMD64NEGQ)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpAMD64SBBQcarrymask, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpAMD64SBBQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v3 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v4 := b.NewValue0(v.Pos, OpAMD64NEGLflags, types.NewTuple(typ.UInt32, types.TypeFlags))
		v4.AddArg(c)
		v3.AddArg(v4)
		v2.AddArg3(x, y, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (NEGLflags (MOVQconst [0])))
	// result: (FlagEQ)
	for {
		if v_0.Op != OpAMD64NEGLflags {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_0_0.AuxInt) != 0 {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (Select1 (NEGLflags (NEGQ (SBBQcarrymask x))))
	// result: x
	for {
		if v_0.Op != OpAMD64NEGLflags {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAMD64NEGQ {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		if v_0_0_0.Op != OpAMD64SBBQcarrymask {
			break
		}
		x := v_0_0_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Select1 (AddTupleFirst32 _ tuple))
	// result: (Select1 tuple)
	for {
		if v_0.Op != OpAMD64AddTupleFirst32 {
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
		if v_0.Op != OpAMD64AddTupleFirst64 {
			break
		}
		tuple := v_0.Args[1]
		v.reset(OpSelect1)
		v.AddArg(tuple)
		return true
	}
	// match: (Select1 a:(LoweredAtomicAnd64 ptr val mem))
	// cond: a.Uses == 1 && clobber(a)
	// result: (ANDQlock ptr val mem)
	for {
		a := v_0
		if a.Op != OpAMD64LoweredAtomicAnd64 {
			break
		}
		mem := a.Args[2]
		ptr := a.Args[0]
		val := a.Args[1]
		if !(a.Uses == 1 && clobber(a)) {
			break
		}
		v.reset(OpAMD64ANDQlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Select1 a:(LoweredAtomicAnd32 ptr val mem))
	// cond: a.Uses == 1 && clobber(a)
	// result: (ANDLlock ptr val mem)
	for {
		a := v_0
		if a.Op != OpAMD64LoweredAtomicAnd32 {
			break
		}
		mem := a.Args[2]
		ptr := a.Args[0]
		val := a.Args[1]
		if !(a.Uses == 1 && clobber(a)) {
			break
		}
		v.reset(OpAMD64ANDLlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Select1 a:(LoweredAtomicOr64 ptr val mem))
	// cond: a.Uses == 1 && clobber(a)
	// result: (ORQlock ptr val mem)
	for {
		a := v_0
		if a.Op != OpAMD64LoweredAtomicOr64 {
			break
		}
		mem := a.Args[2]
		ptr := a.Args[0]
		val := a.Args[1]
		if !(a.Uses == 1 && clobber(a)) {
			break
		}
		v.reset(OpAMD64ORQlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Select1 a:(LoweredAtomicOr32 ptr val mem))
	// cond: a.Uses == 1 && clobber(a)
	// result: (ORLlock ptr val mem)
	for {
		a := v_0
		if a.Op != OpAMD64LoweredAtomicOr32 {
			break
		}
		mem := a.Args[2]
		ptr := a.Args[0]
		val := a.Args[1]
		if !(a.Uses == 1 && clobber(a)) {
			break
		}
		v.reset(OpAMD64ORLlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SelectN [0] call:(CALLstatic {sym} s1:(MOVQstoreconst _ [sc] s2:(MOVQstore _ src s3:(MOVQstore _ dst mem)))))
	// cond: sc.Val64() >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sc.Val64(), config) && clobber(s1, s2, s3, call)
	// result: (Move [sc.Val64()] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpAMD64CALLstatic || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpAMD64MOVQstoreconst {
			break
		}
		sc := auxIntToValAndOff(s1.AuxInt)
		_ = s1.Args[1]
		s2 := s1.Args[1]
		if s2.Op != OpAMD64MOVQstore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpAMD64MOVQstore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sc.Val64() >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sc.Val64(), config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sc.Val64())
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(CALLstatic {sym} dst src (MOVQconst [sz]) mem))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpAMD64CALLstatic || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpAMD64MOVQconst {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SARQconst (NEGQ <t> x) [63])
	for {
		t := v.Type
		x := v_0
		v.reset(OpAMD64SARQconst)
		v.AuxInt = int8ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpSpectreIndex(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SpectreIndex <t> x y)
	// result: (CMOVQCC x (MOVQconst [0]) (CMPQ x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64CMOVQCC)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpAMD64CMPQ, types.TypeFlags)
		v1.AddArg2(x, y)
		v.AddArg3(x, v0, v1)
		return true
	}
}
func rewriteValueAMD64_OpSpectreSliceIndex(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SpectreSliceIndex <t> x y)
	// result: (CMOVQHI x (MOVQconst [0]) (CMPQ x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64CMOVQHI)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpAMD64CMPQ, types.TypeFlags)
		v1.AddArg2(x, y)
		v.AddArg3(x, v0, v1)
		return true
	}
}
func rewriteValueAMD64_OpStore(v *Value) bool {
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
		v.reset(OpAMD64MOVSDstore)
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
		v.reset(OpAMD64MOVSSstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && !t.IsFloat()
	// result: (MOVQstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && !t.IsFloat()) {
			break
		}
		v.reset(OpAMD64MOVQstore)
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
		v.reset(OpAMD64MOVLstore)
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
		v.reset(OpAMD64MOVWstore)
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
		v.reset(OpAMD64MOVBstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpTrunc(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc x)
	// result: (ROUNDSD [3] x)
	for {
		x := v_0
		v.reset(OpAMD64ROUNDSD)
		v.AuxInt = int8ToAuxInt(3)
		v.AddArg(x)
		return true
	}
}
func rewriteValueAMD64_OpZero(v *Value) bool {
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
	// result: (MOVBstoreconst [makeValAndOff(0,0)] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [2] destptr mem)
	// result: (MOVWstoreconst [makeValAndOff(0,0)] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [4] destptr mem)
	// result: (MOVLstoreconst [makeValAndOff(0,0)] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [8] destptr mem)
	// result: (MOVQstoreconst [makeValAndOff(0,0)] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVQstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
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
		v.reset(OpAMD64MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 2))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVWstoreconst, types.TypeMem)
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
		v.reset(OpAMD64MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLstoreconst, types.TypeMem)
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
		v.reset(OpAMD64MOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 4))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLstoreconst, types.TypeMem)
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
		v.reset(OpAMD64MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 3))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s%8 != 0 && s > 8 && !config.useSSE
	// result: (Zero [s-s%8] (OffPtr <destptr.Type> destptr [s%8]) (MOVQstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s%8 != 0 && s > 8 && !config.useSSE) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(s - s%8)
		v0 := b.NewValue0(v.Pos, OpOffPtr, destptr.Type)
		v0.AuxInt = int64ToAuxInt(s % 8)
		v0.AddArg(destptr)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v1.AddArg2(destptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [16] destptr mem)
	// cond: !config.useSSE
	// result: (MOVQstoreconst [makeValAndOff(0,8)] destptr (MOVQstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(!config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVQstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 8))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [24] destptr mem)
	// cond: !config.useSSE
	// result: (MOVQstoreconst [makeValAndOff(0,16)] destptr (MOVQstoreconst [makeValAndOff(0,8)] destptr (MOVQstoreconst [makeValAndOff(0,0)] destptr mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 24 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(!config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVQstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 16))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 8))
		v1 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v1.AddArg2(destptr, mem)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [32] destptr mem)
	// cond: !config.useSSE
	// result: (MOVQstoreconst [makeValAndOff(0,24)] destptr (MOVQstoreconst [makeValAndOff(0,16)] destptr (MOVQstoreconst [makeValAndOff(0,8)] destptr (MOVQstoreconst [makeValAndOff(0,0)] destptr mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(!config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVQstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 24))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 16))
		v1 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 8))
		v2 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v2.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v2.AddArg2(destptr, mem)
		v1.AddArg2(destptr, v2)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [9] destptr mem)
	// cond: config.useSSE
	// result: (MOVBstoreconst [makeValAndOff(0,8)] destptr (MOVQstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 9 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 8))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [10] destptr mem)
	// cond: config.useSSE
	// result: (MOVWstoreconst [makeValAndOff(0,8)] destptr (MOVQstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 10 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 8))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [11] destptr mem)
	// cond: config.useSSE
	// result: (MOVLstoreconst [makeValAndOff(0,7)] destptr (MOVQstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 11 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 7))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [12] destptr mem)
	// cond: config.useSSE
	// result: (MOVLstoreconst [makeValAndOff(0,8)] destptr (MOVQstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 8))
		v0 :
"""




```