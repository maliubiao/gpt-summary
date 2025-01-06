Response: My goal is to analyze the given Go code snippet and fulfill the user's request. Here's a breakdown of the thinking process:

1. **Understand the Context:** The user states that this is part of the `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` file and specifically mentions it's part 11 of 12. This tells me the code is related to compiler optimizations for the AMD64 architecture, specifically within the Static Single Assignment (SSA) intermediate representation. The "rewrite" part suggests these functions transform the SSA graph.

2. **Analyze the Functions:**  I'll iterate through each function in the provided code:

   * **`rewriteValueAMD64_OpRsh64x16`, `rewriteValueAMD64_OpRsh64x32`, `rewriteValueAMD64_OpRsh64x64`, `rewriteValueAMD64_OpRsh64x8`:** These functions seem to handle right shifts on 64-bit integers where the shift amount is an integer of size 16, 32, 64, and 8 bits respectively. They have a pattern:
      * Check `!shiftIsBounded(v)`. If true, generate more complex assembly using `SARQ`, `ORL`/`ORQ`, `NOTL`/`NOTQ`, `SBBLcarrymask`/`SBBQcarrymask`, and `CMPWconst`/`CMPLconst`/`CMPQconst`. This likely handles shifts where the shift amount could be larger than the register size (64 bits).
      * If `shiftIsBounded(v)` is true, simply use `SARQ`. This is the standard arithmetic right shift.

   * **`rewriteValueAMD64_OpRsh8Ux16`, `rewriteValueAMD64_OpRsh8Ux32`, `rewriteValueAMD64_OpRsh8Ux64`, `rewriteValueAMD64_OpRsh8Ux8`:** Similar to the above, but for *unsigned* right shifts on 8-bit integers with different shift amount sizes. The pattern is:
      * If `!shiftIsBounded(v)`, use `ANDL`, `SHRB`, `SBBLcarrymask`, and `CMPWconst`/`CMPLconst`/`CMPQconst`. This likely masks the result to handle out-of-bounds shifts for unsigned values.
      * If `shiftIsBounded(v)`, simply use `SHRB` (shift right byte).

   * **`rewriteValueAMD64_OpRsh8x16`, `rewriteValueAMD64_OpRsh8x32`, `rewriteValueAMD64_OpRsh8x64`, `rewriteValueAMD64_OpRsh8x8`:**  Signed right shifts on 8-bit integers. The pattern is again:
      * If `!shiftIsBounded(v)`, use `SARB`, `ORL`/`ORQ`, `NOTL`/`NOTQ`, `SBBLcarrymask`/`SBBQcarrymask`, and `CMPWconst`/`CMPLconst`/`CMPQconst`. Similar logic to the 64-bit signed shifts but using byte operations.
      * If `shiftIsBounded(v)`, use `SARB` (shift arithmetic right byte).

   * **`rewriteValueAMD64_OpSelect0`:** This function deals with `Select0` operations. It looks for specific paired operations (like `Mul64uover` and `MULQU`) and transforms them. It also handles `Add64carry`, `Sub64borrow`, and operations involving `AddTupleFirst32/64`. It seems to be optimizing the selection of the first result from multi-value operations.

   * **`rewriteValueAMD64_OpSelect1`:** This handles `Select1` operations, selecting the second result. It has similar optimization patterns for multi-value operations like `Mul64uover`, `Add64carry`, `Sub64borrow`, and `NEGLflags`. It also has cases for atomic operations (`LoweredAtomicAnd/Or`) where it simplifies them to locked versions if the result is used only once.

   * **`rewriteValueAMD64_OpSelectN`:** This seems to handle selecting the Nth result from a function call, focusing on optimizing `runtime.memmove` calls into a `Move` operation.

   * **`rewriteValueAMD64_OpSlicemask`:** This function seems to implement the logic for generating a slice mask, using a combination of `NEGQ` and `SARQconst`.

   * **`rewriteValueAMD64_OpSpectreIndex` and `rewriteValueAMD64_OpSpectreSliceIndex`:** These likely relate to mitigations for Spectre vulnerabilities. They use `CMOVQCC` and `CMOVQHI` to conditionally move a value based on a comparison.

   * **`rewriteValueAMD64_OpStore`:** This function optimizes `Store` operations based on the data type's size and whether it's a float, using specific `MOV` instructions for different sizes and types.

   * **`rewriteValueAMD64_OpTrunc`:** This function seems to optimize floating-point truncation using the `ROUNDSD` instruction.

   * **`rewriteValueAMD64_OpZero`:** This function optimizes zeroing out memory regions of different sizes. It uses various `MOV` instructions with constant zero values and has special cases for larger blocks, potentially using `DUFFZERO` or `REPSTOSQ`.

3. **Infer Go Language Features:** Based on the operations being optimized, I can infer the corresponding Go features:

   * **Shift Operations (>>, <<):** The `OpRsh` family of functions clearly relates to Go's right shift operations. The different variants (e.g., `Rsh64x16`) handle shifts where the shift amount has a specific type.
   * **Multi-Value Returns:** `OpSelect0` and `OpSelect1` are directly related to functions that return multiple values.
   * **Multiplication with Overflow Detection:** `OpMul64uover` and `OpMul32uover` suggest Go's support for checking for overflow during multiplication.
   * **Addition and Subtraction with Carry/Borrow:** `OpAdd64carry` and `OpSub64borrow` map to Go's low-level mechanisms for handling carry and borrow bits in arithmetic operations, potentially used in implementing large number arithmetic.
   * **Atomic Operations:** `LoweredAtomicAnd64/32` and `LoweredAtomicOr64/32` directly relate to Go's `sync/atomic` package.
   * **Memory Copying (`runtime.memmove`):** `OpSelectN`'s optimization of `runtime.memmove` is a core part of Go's memory management.
   * **Slices:** `OpSlicemask` is used in the implementation of Go slices.
   * **Memory Zeroing:** The `OpZero` function is used to implement setting memory regions to zero, which happens in various scenarios (e.g., initializing variables).
   * **Floating-point Conversions:** `OpTrunc` relates to converting floating-point numbers to integers.

4. **Provide Go Code Examples:**  For the most prominent features (shifts and multi-value returns), I will construct simple Go examples demonstrating their usage and how the compiler might optimize them.

5. **Code Reasoning (with Assumptions):**  For the shift operations, I'll explain the logic behind the "bounded" and "unbounded" shift optimizations, making assumptions about the intent (handling shifts exceeding register size). I'll show hypothetical inputs and outputs of the SSA transformations.

6. **Command-line Arguments:** Since this code is about compiler internals and SSA rewriting, it doesn't directly handle command-line arguments in the typical sense. However, compiler flags (like those controlling SSE usage) *influence* these rewrites. I'll explain this indirect relationship.

7. **Common Mistakes:** I'll focus on mistakes users might make that could *prevent* these optimizations, such as not understanding the implications of different shift operand types or potential performance issues with very large shifts if the compiler doesn't optimize well.

8. **Summarize Functionality:**  I will synthesize the analysis into a concise summary, highlighting the main purpose of this code section.

**(Self-Correction/Refinement during the process):**

* **Initial thought:** Focus only on direct Go syntax.
* **Correction:** Realize that compiler optimizations often deal with lower-level representations. Emphasize the connection between Go features and the SSA operations.
* **Initial thought:** Provide very complex Go examples.
* **Correction:** Keep the Go examples simple and focused on illustrating the specific feature being optimized.
* **Initial thought:** Explain every single line of generated assembly.
* **Correction:** Focus on the *intent* of the assembly transformations rather than a detailed instruction-by-instruction breakdown. Highlight the core optimization being performed.
这是 `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` 文件的第 11 部分，主要负责定义针对 AMD64 架构的 SSA 中间表示的重写规则，用于优化代码。

**其核心功能是：**

* **将高级的 Go 语言操作转换为更底层的、更适合 AMD64 架构的指令序列。** 这些转换旨在提高代码的执行效率。
* **针对特定的 Go 语言操作（例如位运算、类型转换、内存操作等）进行模式匹配和替换。** 它会寻找符合特定模式的 SSA 值，并将其替换为更优化的指令组合。

**以下是针对代码中出现的一些 `Op` 的功能推断和示例：**

**1. 位移操作的优化 (`OpRsh64x*`, `OpRsh8Ux*`, `OpRsh8x*`)**

这些函数处理右移操作，其中被移位的值和移位量的类型不同。主要的优化策略是区分移位量是否在有效范围内 (`shiftIsBounded`)：

* **如果移位量可能超出范围 (>= 寄存器位数)，则生成更复杂的指令序列，以确保行为的正确性。**  这通常涉及使用 `OR`, `NOT`, `SBBcarrymask` 和比较指令来处理移位溢出的情况，防止移位超过位数导致未定义行为。
* **如果移位量保证在范围内，则直接使用 `SARQ` (算术右移 64 位) 或 `SHRB` (逻辑右移 8 位) 等指令。**

**Go 代码示例 (假设 `shiftIsBounded` 的实现能够识别常量移位量)：**

```go
package main

func main() {
	var x int64 = 0xFFFFFFFFFFFFFFFF
	var y uint16 = 10
	var z int8 = 3

	// 假设编译器能识别出 10 和 3 在各自类型下不会超过 int64 的位数
	_ = x >> y // 可能被优化为 SARQ
	_ = x >> z // 可能被优化为 SARQ

	var largeShift uint16 = 100 // 假设编译器认为 100 可能超出范围
	_ = x >> largeShift // 可能被优化为更复杂的指令序列
}
```

**假设的 SSA 输入与输出 (`OpRsh64x16`)：**

**输入 (移位量 `y` 是一个 `uint16`，且编译器认为可能超出范围):**

```
v1 = Arg <int64> {}
v2 = Arg <uint16> {}
v3 = Rsh64x16 <int64> v1 v2
```

**输出 (对应的 AMD64 指令序列):**

```assembly
  SARQ v1, y_masked  // y_masked 是通过 ORL, NOTL, SBBLcarrymask, CMPWconst 计算出的屏蔽值
```

**输入 (移位量 `y` 是一个 `uint16`，且编译器认为在范围内):**

```
v1 = Arg <int64> {}
v2 = Arg <uint16> {}
v3 = Rsh64x16 <int64> v1 v2
```

**输出 (对应的 AMD64 指令):**

```assembly
  SARQ v1, v2
```

**2. `OpSelect0` 和 `OpSelect1` 的优化**

这两个函数处理从返回多个值的操作中选择特定结果的情况。

* **`OpSelect0`**: 选择操作的第一个返回值。
* **`OpSelect1`**: 选择操作的第二个返回值。

这些优化通常会将多值操作和选择操作合并成更高效的单指令操作，或者进行一些代数简化。

**Go 代码示例：**

```go
package main

func mulAndOverflow(a, b uint64) (uint64, bool) {
	res := a * b
	overflow := res < a
	return res, overflow
}

func main() {
	x := uint64(10)
	y := uint64(20)
	result, _ := mulAndOverflow(x, y) // OpSelect0
	_, overflow := mulAndOverflow(x, y) // OpSelect1
	println(result, overflow)
}
```

**假设的 SSA 输入与输出 (`OpSelect0`):**

**输入:**

```
v1 = Arg <uint64> {}
v2 = Arg <uint64> {}
v3 = Call <(uint64, bool)> {mulAndOverflow} v1 v2
v4 = Select0 <uint64> v3
```

**输出 (可能被优化为 AMD64 的 `MULQU` 指令，该指令同时产生结果和溢出标志):**

```assembly
  MULQU v1, v2 // 结果存储在 AX:DX (高位:低位)
  MOVQ AX, v4
```

**3. `OpSelectN` 的优化**

这个函数处理选择第 N 个返回值的操作，当前代码片段中主要关注 `runtime.memmove` 的优化。它尝试将对 `runtime.memmove` 的调用模式识别出来，并替换为更底层的 `Move` 指令。

**Go 代码示例：**

```go
package main

import "runtime"
import "unsafe"

func main() {
	src := []byte("hello")
	dst := make([]byte, len(src))
	runtime.memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)))
	println(string(dst))
}
```

**假设的 SSA 输入与输出 (`OpSelectN`):**

**输入 (对 `runtime.memmove` 的调用模式):**

```
v1 = ... // dst 指针
v2 = ... // src 指针
v3 = Const64 <uintptr> {5} // 长度
v4 = MemArg <mem> {}
v5 = CALLstatic <mem> {runtime.memmove} v1 v2 v3 v4
v6 = SelectN [0] v5
```

**输出 (被优化为 `Move` 指令):**

```
v6 = Move [5] v1 v2 v4
```

**4. `OpSlicemask` 的优化**

这个函数用于生成 slice 的掩码，它使用位运算来实现。

**Go 代码示例：**

```go
package main

func main() {
	var x int = 5
	mask := -1 << uint(x) // 相当于生成一个低 x 位为 0，高位为 1 的掩码
	println(mask)
}
```

**5. `OpSpectreIndex` 和 `OpSpectreSliceIndex` 的优化**

这两个函数与 Spectre 漏洞缓解有关。它们使用条件移动指令 (`CMOVQCC`, `CMOVQHI`) 来防止推测执行攻击。

**Go 代码示例 (这部分优化通常在编译器内部，用户代码不直接控制):**

```go
package main

func main() {
	index := 5
	length := 10
	// ... 访问数组，编译器可能会插入 Spectre 缓解措施
	if index < length {
		// ...
	}
}
```

**6. `OpStore` 的优化**

这个函数根据要存储的值的类型和大小，选择最合适的 `MOV` 指令。

**Go 代码示例：**

```go
package main

func main() {
	var i int64 = 10
	var f float64 = 3.14
	var b byte = 'a'

	var p *int64 = &i
	var pf *float64 = &f
	var pb *byte = &b

	*p = 20     // 可能被优化为 MOVQstore
	*pf = 6.28  // 可能被优化为 MOVSDstore
	*pb = 'b'   // 可能被优化为 MOVBstore
}
```

**7. `OpTrunc` 的优化**

这个函数用于将浮点数截断为整数。

**Go 代码示例：**

```go
package main

func main() {
	var f float64 = 3.14
	i := int(f) // 截断，小数部分被丢弃
	println(i)
}
```

**8. `OpZero` 的优化**

这个函数用于将内存区域置零，它会根据要置零的字节数选择不同的指令序列，以实现高效的内存清零。对于小块内存，可能会使用多个 `MOV` 指令；对于大块内存，可能会使用 `REP STOSQ` 或 `DUFFZERO` 等指令。

**Go 代码示例：**

```go
package main

func main() {
	arr := make([]int, 10)
	// ...
	for i := range arr {
		arr[i] = 0 // 编译器可能会优化为 OpZero 操作
	}
}
```

**命令行参数的具体处理:**

这个代码片段本身不直接处理命令行参数。但是，Go 编译器的命令行参数会影响 SSA 的生成和优化过程。例如，`-gcflags` 可以传递给编译器标志，这些标志可能启用或禁用某些优化，从而影响到这里的重写规则是否被应用。

**使用者易犯错的点:**

由于这是编译器内部的优化代码，普通 Go 开发者不会直接与之交互，因此不容易犯错。但是，理解这些优化有助于编写出更高效的代码。例如，了解到位移操作的优化策略可以帮助开发者选择合适的移位量类型，避免不必要的性能损失。

**这是第11部分的功能归纳:**

第 11 部分的 `rewriteAMD64.go` 文件主要负责实现针对 AMD64 架构的特定 Go 语言操作的 SSA 重写规则，特别是针对位移操作（包括有符号和无符号的各种类型组合）、多值返回值的选择、`runtime.memmove` 的调用、内存置零、浮点数截断以及 Spectre 漏洞缓解措施的优化。它的目标是将这些高级操作转换为更高效的底层 AMD64 指令序列，从而提升最终生成的可执行文件的性能。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第11部分，共12部分，请归纳一下它的功能

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
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s > 12 && s < 16 && config.useSSE
	// result: (MOVQstoreconst [makeValAndOff(0,int32(s-8))] destptr (MOVQstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s > 12 && s < 16 && config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVQstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, int32(s-8)))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s%16 != 0 && s > 16 && s%16 > 8 && config.useSSE
	// result: (Zero [s-s%16] (OffPtr <destptr.Type> destptr [s%16]) (MOVOstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s%16 != 0 && s > 16 && s%16 > 8 && config.useSSE) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(s - s%16)
		v0 := b.NewValue0(v.Pos, OpOffPtr, destptr.Type)
		v0.AuxInt = int64ToAuxInt(s % 16)
		v0.AddArg(destptr)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v1.AddArg2(destptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s%16 != 0 && s > 16 && s%16 <= 8 && config.useSSE
	// result: (Zero [s-s%16] (OffPtr <destptr.Type> destptr [s%16]) (MOVOstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s%16 != 0 && s > 16 && s%16 <= 8 && config.useSSE) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(s - s%16)
		v0 := b.NewValue0(v.Pos, OpOffPtr, destptr.Type)
		v0.AuxInt = int64ToAuxInt(s % 16)
		v0.AddArg(destptr)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v1.AddArg2(destptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [16] destptr mem)
	// cond: config.useSSE
	// result: (MOVOstoreconst [makeValAndOff(0,0)] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [32] destptr mem)
	// cond: config.useSSE
	// result: (MOVOstoreconst [makeValAndOff(0,16)] destptr (MOVOstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 16))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [48] destptr mem)
	// cond: config.useSSE
	// result: (MOVOstoreconst [makeValAndOff(0,32)] destptr (MOVOstoreconst [makeValAndOff(0,16)] destptr (MOVOstoreconst [makeValAndOff(0,0)] destptr mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 48 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 32))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 16))
		v1 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v1.AddArg2(destptr, mem)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [64] destptr mem)
	// cond: config.useSSE
	// result: (MOVOstoreconst [makeValAndOff(0,48)] destptr (MOVOstoreconst [makeValAndOff(0,32)] destptr (MOVOstoreconst [makeValAndOff(0,16)] destptr (MOVOstoreconst [makeValAndOff(0,0)] destptr mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 64 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 48))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 32))
		v1 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 16))
		v2 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v2.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v2.AddArg2(destptr, mem)
		v1.AddArg2(destptr, v2)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s > 64 && s <= 1024 && s%16 == 0 && !config.noDuffDevice
	// result: (DUFFZERO [s] destptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s > 64 && s <= 1024 && s%16 == 0 && !config.noDuffDevice) {
			break
		}
		v.reset(OpAMD64DUFFZERO)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: (s > 1024 || (config.noDuffDevice && s > 64 || !config.useSSE && s > 32)) && s%8 == 0
	// result: (REPSTOSQ destptr (MOVQconst [s/8]) (MOVQconst [0]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !((s > 1024 || (config.noDuffDevice && s > 64 || !config.useSSE && s > 32)) && s%8 == 0) {
			break
		}
		v.reset(OpAMD64REPSTOSQ)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(s / 8)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVQconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg4(destptr, v0, v1, mem)
		return true
	}
	return false
}
func rewriteBlockAMD64(b *Block) bool {
	typ := &b.Func.Config.Types
	switch b.Kind {
	case BlockAMD64EQ:
		// match: (EQ (TESTL (SHLL (MOVLconst [1]) x) y))
		// result: (UGE (BTL x y))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64SHLL {
					continue
				}
				x := v_0_0.Args[1]
				v_0_0_0 := v_0_0.Args[0]
				if v_0_0_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0_0_0.AuxInt) != 1 {
					continue
				}
				y := v_0_1
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTL, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTQ (SHLQ (MOVQconst [1]) x) y))
		// result: (UGE (BTQ x y))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64SHLQ {
					continue
				}
				x := v_0_0.Args[1]
				v_0_0_0 := v_0_0.Args[0]
				if v_0_0_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_0_0_0.AuxInt) != 1 {
					continue
				}
				y := v_0_1
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQ, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTLconst [c] x))
		// cond: isUint32PowerOfTwo(int64(c))
		// result: (UGE (BTLconst [int8(log32(c))] x))
		for b.Controls[0].Op == OpAMD64TESTLconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(isUint32PowerOfTwo(int64(c))) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log32(c)))
			v0.AddArg(x)
			b.resetWithControl(BlockAMD64UGE, v0)
			return true
		}
		// match: (EQ (TESTQconst [c] x))
		// cond: isUint64PowerOfTwo(int64(c))
		// result: (UGE (BTQconst [int8(log32(c))] x))
		for b.Controls[0].Op == OpAMD64TESTQconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(isUint64PowerOfTwo(int64(c))) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log32(c)))
			v0.AddArg(x)
			b.resetWithControl(BlockAMD64UGE, v0)
			return true
		}
		// match: (EQ (TESTQ (MOVQconst [c]) x))
		// cond: isUint64PowerOfTwo(c)
		// result: (UGE (BTQconst [int8(log64(c))] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64MOVQconst {
					continue
				}
				c := auxIntToInt64(v_0_0.AuxInt)
				x := v_0_1
				if !(isUint64PowerOfTwo(c)) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(int8(log64(c)))
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2))
		// cond: z1==z2
		// result: (UGE (BTQconst [63] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHLQconst || auxIntToInt8(z1.AuxInt) != 63 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHRQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(63)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTL z1:(SHLLconst [31] (SHRQconst [31] x)) z2))
		// cond: z1==z2
		// result: (UGE (BTQconst [31] x))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHLLconst || auxIntToInt8(z1.AuxInt) != 31 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHRQconst || auxIntToInt8(z1_0.AuxInt) != 31 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(31)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTQ z1:(SHRQconst [63] (SHLQconst [63] x)) z2))
		// cond: z1==z2
		// result: (UGE (BTQconst [0] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHLQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(0)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTL z1:(SHRLconst [31] (SHLLconst [31] x)) z2))
		// cond: z1==z2
		// result: (UGE (BTLconst [0] x))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHLLconst || auxIntToInt8(z1_0.AuxInt) != 31 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTLconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(0)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTQ z1:(SHRQconst [63] x) z2))
		// cond: z1==z2
		// result: (UGE (BTQconst [63] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
					continue
				}
				x := z1.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(63)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTL z1:(SHRLconst [31] x) z2))
		// cond: z1==z2
		// result: (UGE (BTLconst [31] x))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
					continue
				}
				x := z1.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTLconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(31)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (InvertFlags cmp) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64EQ, cmp)
			return true
		}
		// match: (EQ (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (EQ (FlagLT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagLT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagGT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagGT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (TESTQ s:(Select0 blsr:(BLSRQ _)) s) yes no)
		// result: (EQ (Select1 <types.TypeFlags> blsr) yes no)
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				s := v_0_0
				if s.Op != OpSelect0 {
					continue
				}
				blsr := s.Args[0]
				if blsr.Op != OpAMD64BLSRQ || s != v_0_1 {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v0.AddArg(blsr)
				b.resetWithControl(BlockAMD64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTL s:(Select0 blsr:(BLSRL _)) s) yes no)
		// result: (EQ (Select1 <types.TypeFlags> blsr) yes no)
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				s := v_0_0
				if s.Op != OpSelect0 {
					continue
				}
				blsr := s.Args[0]
				if blsr.Op != OpAMD64BLSRL || s != v_0_1 {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v0.AddArg(blsr)
				b.resetWithControl(BlockAMD64EQ, v0)
				return true
			}
			break
		}
	case BlockAMD64GE:
		// match: (GE (InvertFlags cmp) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64LE, cmp)
			return true
		}
		// match: (GE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (FlagLT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GE (FlagLT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GE (FlagGT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (FlagGT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			return true
		}
	case BlockAMD64GT:
		// match: (GT (InvertFlags cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64LT, cmp)
			return true
		}
		// match: (GT (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagLT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagLT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagGT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GT (FlagGT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			return true
		}
	case BlockIf:
		// match: (If (SETL cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETL {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64LT, cmp)
			return true
		}
		// match: (If (SETLE cmp) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETLE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64LE, cmp)
			return true
		}
		// match: (If (SETG cmp) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETG {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64GT, cmp)
			return true
		}
		// match: (If (SETGE cmp) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETGE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64GE, cmp)
			return true
		}
		// match: (If (SETEQ cmp) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpAMD64SETEQ {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64EQ, cmp)
			return true
		}
		// match: (If (SETNE cmp) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETNE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64NE, cmp)
			return true
		}
		// match: (If (SETB cmp) yes no)
		// result: (ULT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETB {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64ULT, cmp)
			return true
		}
		// match: (If (SETBE cmp) yes no)
		// result: (ULE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETBE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64ULE, cmp)
			return true
		}
		// match: (If (SETA cmp) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETA {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64UGT, cmp)
			return true
		}
		// match: (If (SETAE cmp) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETAE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64UGE, cmp)
			return true
		}
		// match: (If (SETO cmp) yes no)
		// result: (OS cmp yes no)
		for b.Controls[0].Op == OpAMD64SETO {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64OS, cmp)
			return true
		}
		// match: (If (SETGF cmp) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETGF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64UGT, cmp)
			return true
		}
		// match: (If (SETGEF cmp) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETGEF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64UGE, cmp)
			return true
		}
		// match: (If (SETEQF cmp) yes no)
		// result: (EQF cmp yes no)
		for b.Controls[0].Op == OpAMD64SETEQF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64EQF, cmp)
			return true
		}
		// match: (If (SETNEF cmp) yes no)
		// result: (NEF cmp yes no)
		for b.Controls[0].Op == OpAMD64SETNEF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64NEF, cmp)
			return true
		}
		// match: (If cond yes no)
		// result: (NE (TESTB cond cond) yes no)
		for {
			cond := b.Controls[0]
			v0 := b.NewValue0(cond.Pos, OpAMD64TESTB, types.TypeFlags)
			v0.AddArg2(cond, cond)
			b.resetWithControl(BlockAMD64NE, v0)
			return true
		}
	case BlockJumpTable:
		// match: (JumpTable idx)
		// result: (JUMPTABLE {makeJumpTableSym(b)} idx (LEAQ <typ.Uintptr> {makeJumpTableSym(b)} (SB)))
		for {
			idx := b.Controls[0]
			v0 := b.NewValue0(b.Pos, OpAMD64LEAQ, typ.Uintptr)
			v0.Aux = symToAux(makeJumpTableSym(b))
			v1 := b.NewValue0(b.Pos, OpSB, typ.Uintptr)
			v0.AddArg(v1)
			b.resetWithControl2(BlockAMD64JUMPTABLE, idx, v0)
			b.Aux = symToAux(makeJumpTableSym(b))
			return true
		}
	case BlockAMD64LE:
		// match: (LE (InvertFlags cmp) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64GE, cmp)
			return true
		}
		// match: (LE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagLT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagLT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagGT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LE (FlagGT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockAMD64LT:
		// match: (LT (InvertFlags cmp) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64GT, cmp)
			return true
		}
		// match: (LT (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LT (FlagLT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LT (FlagLT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LT (FlagGT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LT (FlagGT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockAMD64NE:
		// match: (NE (TESTB (SETL cmp) (SETL cmp)) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETL {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETL || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64LT, cmp)
			return true
		}
		// match: (NE (TESTB (SETLE cmp) (SETLE cmp)) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETLE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETLE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64LE, cmp)
			return true
		}
		// match: (NE (TESTB (SETG cmp) (SETG cmp)) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETG {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETG || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64GT, cmp)
			return true
		}
		// match: (NE (TESTB (SETGE cmp) (SETGE cmp)) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETGE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETGE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64GE, cmp)
			return true
		}
		// match: (NE (TESTB (SETEQ cmp) (SETEQ cmp)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETEQ {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETEQ || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64EQ, cmp)
			return true
		}
		// match: (NE (TESTB (SETNE cmp) (SETNE cmp)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETNE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETNE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64NE, cmp)
			return true
		}
		// match: (NE (TESTB (SETB cmp) (SETB cmp)) yes no)
		// result: (ULT cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETB {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETB || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64ULT, cmp)
			return true
		}
		// match: (NE (TESTB (SETBE cmp) (SETBE cmp)) yes no)
		// result: (ULE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETBE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETBE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64ULE, cmp)
			return true
		}
		// match: (NE (TESTB (SETA cmp) (SETA cmp)) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETA {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETA || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64UGT, cmp)
			return true
		}
		// match: (NE (TESTB (SETAE cmp) (SETAE cmp)) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETAE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETAE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64UGE, cmp)
			return true
		}
		// match: (NE (TESTB (SETO cmp) (SETO cmp)) yes no)
		// result: (OS cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETO {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETO || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64OS, cmp)
			return true
		}
		// match: (NE (TESTL (SHLL (MOVLconst [1]) x) y))
		// result: (ULT (BTL x y))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64SHLL {
					continue
				}
				x := v_0_0.Args[1]
				v_0_0_0 := v_0_0.Args[0]
				if v_0_0_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0_0_0.AuxInt) != 1 {
					continue
				}
				y := v_0_1
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTL, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockAMD64ULT, v0)
				return true
			}
			break
		}
		// match: (NE (TESTQ (SHLQ (MOVQconst [1]) x) y))
		// result: (ULT (BTQ x y))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64SHLQ {
					continue
				}
				x := v_0_0.Args[1]
				v_0_0_0 := v_0_0.Args[0]
				if v_0_0_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_0_0_0.AuxInt) != 1 {
					continue
				}
				y := v_0_1
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQ, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockAMD64ULT, v0)
				return true
			}
			break
		}
		// match: (NE (TESTLconst [c] x))
		// cond: isUint32PowerOfTwo(int64(c))
		// result: (ULT (BTLconst [int8(log32(c))] x))
		for b.Controls[0].Op == OpAMD64TESTLconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(isUint32PowerOfTwo(int64(c))) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log32(c)))
			v0.AddArg(x)
			b.resetWithControl(BlockAMD64ULT, v0)
			return true
		}
		// match: (NE (TESTQconst [c] x))
		// cond: isUint64PowerOfTwo(int64(c))
		// result: (ULT (BTQconst [int8(log32(c))] x))
		for b.Controls[0].Op == OpAMD64TESTQconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(isUint64PowerOfTwo(int64(c))) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log32(c)))
			v0.AddArg(x)
			b.resetWithControl(BlockAMD64ULT, v0)
			return true
		}
		// match: (NE (TESTQ (MOVQconst [c]) x))
		// cond: isUint64PowerOfTwo(c)
		// result: (ULT (BTQconst [int8(log64(c))] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64MOVQconst {
					continue
				}
				c := auxIntToInt64(v_0_0.AuxInt)
				x := v_0_1
				if !(isUint64PowerOfTwo(c)) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(int8(log64(c)))
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64ULT, v0)
				return true
			}
			break
		}
		// match: (NE (TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2))
		// cond: z1==z2
		// result: (ULT (BTQconst [63] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHLQconst || auxIntToInt8(z1.AuxInt) != 63 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHRQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(63)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64ULT, v0)
				return true
			}
			break
		}
		// match: (NE (TESTL z1:(SHLLconst [31] (SHRQconst [31] x)) z2))
		// cond: z1==z2
		// result: (ULT (BTQconst [31] x))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := 
"""




```