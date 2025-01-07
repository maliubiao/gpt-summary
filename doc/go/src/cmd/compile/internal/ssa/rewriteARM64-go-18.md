Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Context:**

The first crucial step is to recognize the file path: `go/src/cmd/compile/internal/ssa/rewriteARM64.go`. This immediately tells us we're dealing with the Go compiler, specifically the part that optimizes code for the ARM64 architecture. The `ssa` in the path stands for Static Single Assignment, an intermediate representation used during compilation. The `rewrite` part signifies that this code performs transformations or optimizations on the SSA form.

**2. Deconstructing the Code Structure:**

The code is a `switch` statement on `b.Type`, where `b` is likely a `Block` in the SSA graph. Each `case` handles a specific block type (e.g., `BlockARM64JEQ`, `BlockARM64LE`, `BlockARM64LT`, `BlockARM64NE`, `BlockARM64NZ`). Inside each `case`, there are further patterns (using `match:`) that look for specific combinations of operations (`Op`) and arguments within the block's control value (`b.Controls[0]`).

**3. Identifying the Core Functionality:**

The primary function of this code is to apply peephole optimizations on the SSA representation of ARM64 code. It identifies common patterns and replaces them with more efficient or equivalent sequences of operations. This is done by:

* **Pattern Matching:**  The `match:` comments describe the specific patterns of operations and operands being looked for.
* **Condition Checking:** The `cond:` comments specify additional conditions that must be met for the rewrite to be applied. These often involve checking the number of uses of a value (`z.Uses == 1`) or the value of a constant (`auxIntToInt64(v_0.AuxInt) != 0`).
* **Transformation:** The `result:` comments describe how the block is modified if the pattern and conditions match. This usually involves:
    * Resetting the block type (`b.resetWithControl`, `b.Reset`).
    * Changing the control value's operation (`Op`).
    * Modifying the arguments of the control value (`AddArg`, `AddArg2`).
    * Potentially swapping the successors of the block (`b.swapSuccessors()`).

**4. Inferring Go Language Feature Implementations (and Why it's Difficult Here):**

While the code optimizes ARM64 instructions, it doesn't directly implement a high-level Go language feature. It operates at a lower level, transforming the compiler's intermediate representation. It's difficult to point to a specific `if`, `for`, or function call in Go and say "this code optimizes that." Instead, it optimizes the *assembly instructions* that those Go constructs eventually become.

However, we can make educated guesses based on the *types* of optimizations being performed:

* **Conditional Statements (if/else):**  The various `BlockARM64` types (like `JEQ`, `JNE`, `JLT`, `JGE`, `LE`, `LT`, `NE`) directly correspond to different kinds of conditional branches and comparisons. The code optimizes how these branches are implemented at the assembly level.
* **Boolean Logic (AND, OR, NOT):** Optimizations like changing `CMPconst [0] z:(AND x y)` to `TST x y` are related to how boolean AND operations are evaluated and tested for truthiness.
* **Arithmetic Operations (+, -, *, etc.):** Optimizations involving `ADDconst`, `MADD`, `MSUB`, and `NEG` suggest that the code is looking for ways to perform arithmetic operations more efficiently.

**5. Crafting Example Go Code (Based on Inferences):**

Since the optimizations are low-level, the Go code examples need to be simple enough to illustrate the *potential* high-level constructs that might lead to the optimized assembly. For instance:

*  The `TST` optimization relates to checking if a number is non-zero after applying a bitmask (AND). This is often done in Go with boolean checks or bitwise operations.
* The optimizations involving `CMN` (compare negative) and `ADD` relate to checking for conditions after addition.

**6. Considering Command-Line Arguments and Common Mistakes:**

Because this code is part of the compiler's internal workings, there aren't direct command-line arguments that users can manipulate to affect these specific optimizations. The compiler handles these transformations automatically.

Common mistakes by *Go developers* aren't directly related to *this specific code*. However, the *existence* of such optimization code highlights the importance of writing clear and idiomatic Go code. The compiler can often optimize well-structured code more effectively than convoluted code.

**7. Synthesizing the Summary (for Part 19 of 20):**

Since this is part 19 of 20, the focus should be on summarizing the *accumulated* functionality. This specific snippet continues the theme of peephole optimizations for conditional branches and comparisons on ARM64, building upon the transformations seen in earlier parts. The summary should emphasize the pattern-matching and replacement nature of the code, aiming for improved efficiency and potentially smaller code size.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This code implements `if` statements."  **Correction:** While related, it's more accurate to say it optimizes the *assembly code* generated for `if` statements and other conditional constructs.
* **Initial thought:** "Let's find specific Go code that triggers *this exact* optimization." **Correction:**  It's difficult to guarantee a direct mapping. Focus on illustrating the *kinds* of Go code that might lead to the patterns being optimized.
* **Realization:**  The `z.Uses == 1` condition is recurring. This indicates the optimizer is looking for opportunities where intermediate results are used only once, allowing for simplification.

By following these steps, including the iterative refinement, we can arrive at a comprehensive and accurate understanding of the provided Go code snippet.
这是 `go/src/cmd/compile/internal/ssa/rewriteARM64.go` 文件的一部分，它主要负责 **ARM64 架构下的 SSA（Static Single Assignment）形式的 Go 代码重写规则**。更具体地说，它定义了一系列模式匹配和替换规则，用于将一些常见的、低效的 SSA 指令序列转换为更优化的指令序列。

由于这是第 19 部分，共 20 部分，我们可以推断这部分代码主要集中在 **条件跳转指令的优化** 上。通过匹配特定的比较指令（例如 `CMPconst`, `CMPWconst`）以及一些逻辑和算术运算指令（例如 `AND`, `ADD`, `MADD`, `MSUB`, `NEG`），将其转换为更直接、更高效的跳转指令或比较指令。

**功能归纳：**

这部分代码的主要功能是 **优化 ARM64 架构下条件分支指令的生成**。它通过识别特定的 SSA 指令模式，并将其替换为更简洁、更高效的指令组合，从而提高生成的机器码的执行效率。 重点集中在对 `BlockARM64LE`, `BlockARM64LEnoov`, `BlockARM64LT`, `BlockARM64LTnoov`, `BlockARM64NE`, `BlockARM64NZ` 这些表示不同条件跳转块类型的优化。

**Go 语言功能推断和代码示例：**

虽然这段代码本身不直接实现特定的 Go 语言功能，但它优化了 Go 语言中 **条件语句（`if`, `else if`, `else`）和逻辑运算** 的底层实现。

**示例 1：优化 `if` 语句中的 `&` 运算**

代码片段中多次出现将 `(LE (CMPconst [0] z:(AND x y)) yes no)` 优化为 `(LE (TST x y) yes no)` 的模式。这对应于 Go 语言中 `if` 语句中使用 `&` 运算进行条件判断的情况。

```go
package main

func main() {
	a := 5
	b := 3
	if a & b <= 0 { // 这里的 a & b 对应 SSA 中的 AND 运算
		println("条件成立")
	} else {
		println("条件不成立")
	}
}
```

**假设的 SSA 输入 (简化版)：**

假设 `a` 和 `b` 对应的 SSA 值分别为 `v1` 和 `v2`。

```
b1:
  v3 = AND v1 v2
  v4 = CMPconst [0] v3
  If v4 -> b2, b3
b2:
  // 条件成立分支
  ...
b3:
  // 条件不成立分支
  ...
```

**优化后的 SSA 输出 (简化版)：**

经过 `rewriteARM64.go` 的优化，会将 `CMPconst [0] (AND ...)` 替换为 `TST` 指令。

```
b1:
  v3 = TST v1 v2
  If v3 -> b2, b3
b2:
  // 条件成立分支
  ...
b3:
  // 条件不成立分支
  ...
```

**解释：** `TST` 指令（Test）在 ARM64 中执行按位与操作，并根据结果设置标志位，但不会保存结果。对于判断与运算结果是否为零的情况，`TST` 比先进行 `AND` 运算再与 0 比较更高效。

**示例 2：优化 `if` 语句中的加法运算后与 0 比较**

代码片段中有将 `(LE (CMPconst [0] z:(ADD x y)) yes no)` 优化为 `(LEnoov (CMN x y) yes no)` 的模式。这对应于 Go 语言中 `if` 语句中使用加法运算后与 0 比较的情况。

```go
package main

func main() {
	a := 5
	b := -5
	if a + b <= 0 { // 这里的 a + b 对应 SSA 中的 ADD 运算
		println("条件成立")
	} else {
		println("条件不成立")
	}
}
```

**假设的 SSA 输入 (简化版)：**

```
b1:
  v3 = ADD v1 v2
  v4 = CMPconst [0] v3
  If v4 -> b2, b3
b2:
  // 条件成立分支
  ...
b3:
  // 条件不成立分支
  ...
```

**优化后的 SSA 输出 (简化版)：**

```
b1:
  v3 = CMN v1 v2 // CMN 是 Compare Negative，相当于比较 x 和 -y
  If.noov v3 -> b2, b3 // .noov 表示不考虑溢出标志
b2:
  // 条件成立分支
  ...
b3:
  // 条件不成立分支
  ...
```

**解释：** `CMN` 指令（Compare Negative）将一个寄存器的值与另一个寄存器的值的相反数相加，并设置相应的标志位。对于判断 `a + b <= 0`，等价于判断 `a <= -b`，使用 `CMN` 可以更直接地表达这个比较。`LEnoov` 表示小于等于且不考虑溢出。

**命令行参数的具体处理：**

该代码是 Go 编译器内部的一部分，不直接涉及用户可配置的命令行参数。这些重写规则在编译过程中自动应用。

**使用者易犯错的点：**

作为编译器开发者，可能犯错的点在于：

* **模式匹配错误：**  定义的匹配模式不够精确，导致错误的优化。
* **条件判断错误：**  `cond:` 中的条件判断不正确，导致不应该应用的优化被应用。
* **替换逻辑错误：**  `result:` 中的替换逻辑有误，导致生成的代码不正确或效率更低。
* **忽略边界情况：**  某些特殊情况下，优化规则可能不适用，需要仔细考虑各种情况。

**总结（针对第 19 部分）：**

作为 `rewriteARM64.go` 的第 19 部分，这段代码专注于 **优化各种条件跳转指令**。它通过模式匹配，将涉及到 `CMPconst` 或 `CMPWconst` 指令，并且比较对象是特定逻辑或算术运算结果的跳转块，转换为更直接的 `TST`, `CMN` 或基于标志位直接跳转的指令。这种优化能够减少指令数量，提高代码执行效率。代码中针对 `BlockARM64LE`, `BlockARM64LEnoov`, `BlockARM64LT`, `BlockARM64LTnoov`, `BlockARM64NE`, `BlockARM64NZ` 等不同类型的条件跳转块进行了细致的优化。这部分是整个 ARM64 代码生成优化的重要组成部分，旨在生成更精简、更快速的机器码。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第19部分，共20部分，请归纳一下它的功能

"""
 = symToAux(makeJumpTableSym(b))
			v1 := b.NewValue0(b.Pos, OpSB, typ.Uintptr)
			v0.AddArg(v1)
			b.resetWithControl2(BlockARM64JUMPTABLE, idx, v0)
			b.Aux = symToAux(makeJumpTableSym(b))
			return true
		}
	case BlockARM64LE:
		// match: (LE (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (LE (TST x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TST, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64LE, v0)
				return true
			}
			break
		}
		// match: (LE (CMPconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (LE (TSTconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64LE, v0)
			return true
		}
		// match: (LE (CMPWconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (LE (TSTW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TSTW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64LE, v0)
				return true
			}
			break
		}
		// match: (LE (CMPWconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (LE (TSTWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64LE, v0)
			return true
		}
		// match: (LE (CMPconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (LEnoov (CMNconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64LEnoov, v0)
			return true
		}
		// match: (LE (CMPWconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (LEnoov (CMNWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64LEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (LEnoov (CMN x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64LEnoov, v0)
				return true
			}
			break
		}
		// match: (LE (CMPWconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (LEnoov (CMNW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64LEnoov, v0)
				return true
			}
			break
		}
		// match: (LE (CMPconst [0] z:(MADD a x y)) yes no)
		// cond: z.Uses==1
		// result: (LEnoov (CMN a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADD {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64LEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] z:(MSUB a x y)) yes no)
		// cond: z.Uses==1
		// result: (LEnoov (CMP a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUB {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMP, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64LEnoov, v0)
			return true
		}
		// match: (LE (CMPWconst [0] z:(MADDW a x y)) yes no)
		// cond: z.Uses==1
		// result: (LEnoov (CMNW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADDW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64LEnoov, v0)
			return true
		}
		// match: (LE (CMPWconst [0] z:(MSUBW a x y)) yes no)
		// cond: z.Uses==1
		// result: (LEnoov (CMPW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUBW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64LEnoov, v0)
			return true
		}
		// match: (LE (FlagConstant [fc]) yes no)
		// cond: fc.le()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.le()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagConstant [fc]) yes no)
		// cond: !fc.le()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.le()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LE (InvertFlags cmp) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64GE, cmp)
			return true
		}
	case BlockARM64LEnoov:
		// match: (LEnoov (FlagConstant [fc]) yes no)
		// cond: fc.leNoov()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.leNoov()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LEnoov (FlagConstant [fc]) yes no)
		// cond: !fc.leNoov()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.leNoov()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LEnoov (InvertFlags cmp) yes no)
		// result: (GEnoov cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64GEnoov, cmp)
			return true
		}
	case BlockARM64LT:
		// match: (LT (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (LT (TST x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TST, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64LT, v0)
				return true
			}
			break
		}
		// match: (LT (CMPconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (LT (TSTconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64LT, v0)
			return true
		}
		// match: (LT (CMPWconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (LT (TSTW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TSTW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64LT, v0)
				return true
			}
			break
		}
		// match: (LT (CMPWconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (LT (TSTWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64LT, v0)
			return true
		}
		// match: (LT (CMPconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (LTnoov (CMNconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64LTnoov, v0)
			return true
		}
		// match: (LT (CMPWconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (LTnoov (CMNWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64LTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (LTnoov (CMN x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64LTnoov, v0)
				return true
			}
			break
		}
		// match: (LT (CMPWconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (LTnoov (CMNW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64LTnoov, v0)
				return true
			}
			break
		}
		// match: (LT (CMPconst [0] z:(MADD a x y)) yes no)
		// cond: z.Uses==1
		// result: (LTnoov (CMN a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADD {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64LTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] z:(MSUB a x y)) yes no)
		// cond: z.Uses==1
		// result: (LTnoov (CMP a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUB {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMP, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64LTnoov, v0)
			return true
		}
		// match: (LT (CMPWconst [0] z:(MADDW a x y)) yes no)
		// cond: z.Uses==1
		// result: (LTnoov (CMNW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADDW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64LTnoov, v0)
			return true
		}
		// match: (LT (CMPWconst [0] z:(MSUBW a x y)) yes no)
		// cond: z.Uses==1
		// result: (LTnoov (CMPW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUBW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64LTnoov, v0)
			return true
		}
		// match: (LT (CMPWconst [0] x) yes no)
		// result: (TBNZ [31] x yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockARM64TBNZ, x)
			b.AuxInt = int64ToAuxInt(31)
			return true
		}
		// match: (LT (CMPconst [0] x) yes no)
		// result: (TBNZ [63] x yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockARM64TBNZ, x)
			b.AuxInt = int64ToAuxInt(63)
			return true
		}
		// match: (LT (FlagConstant [fc]) yes no)
		// cond: fc.lt()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.lt()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LT (FlagConstant [fc]) yes no)
		// cond: !fc.lt()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.lt()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LT (InvertFlags cmp) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64GT, cmp)
			return true
		}
	case BlockARM64LTnoov:
		// match: (LTnoov (FlagConstant [fc]) yes no)
		// cond: fc.ltNoov()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.ltNoov()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LTnoov (FlagConstant [fc]) yes no)
		// cond: !fc.ltNoov()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.ltNoov()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LTnoov (InvertFlags cmp) yes no)
		// result: (GTnoov cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64GTnoov, cmp)
			return true
		}
	case BlockARM64NE:
		// match: (NE (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (NE (TST x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TST, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64NE, v0)
				return true
			}
			break
		}
		// match: (NE (CMPconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (NE (TSTconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (CMPWconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (NE (TSTW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TSTW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64NE, v0)
				return true
			}
			break
		}
		// match: (NE (CMPWconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (NE (TSTWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (CMPconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (NE (CMNconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (CMPWconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (NE (CMNWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (CMPconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (NE (CMN x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64NE, v0)
				return true
			}
			break
		}
		// match: (NE (CMPWconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (NE (CMNW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64NE, v0)
				return true
			}
			break
		}
		// match: (NE (CMP x z:(NEG y)) yes no)
		// cond: z.Uses == 1
		// result: (NE (CMN x y) yes no)
		for b.Controls[0].Op == OpARM64CMP {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpARM64NEG {
				break
			}
			y := z.Args[0]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (CMPW x z:(NEG y)) yes no)
		// cond: z.Uses == 1
		// result: (NE (CMNW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPW {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpARM64NEG {
				break
			}
			y := z.Args[0]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (CMPconst [0] x) yes no)
		// result: (NZ x yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockARM64NZ, x)
			return true
		}
		// match: (NE (CMPWconst [0] x) yes no)
		// result: (NZW x yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockARM64NZW, x)
			return true
		}
		// match: (NE (CMPconst [0] z:(MADD a x y)) yes no)
		// cond: z.Uses==1
		// result: (NE (CMN a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADD {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (CMPconst [0] z:(MSUB a x y)) yes no)
		// cond: z.Uses==1
		// result: (NE (CMP a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUB {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMP, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (CMPWconst [0] z:(MADDW a x y)) yes no)
		// cond: z.Uses==1
		// result: (NE (CMNW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADDW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (CMPWconst [0] z:(MSUBW a x y)) yes no)
		// cond: z.Uses==1
		// result: (NE (CMPW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUBW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64NE, v0)
			return true
		}
		// match: (NE (TSTconst [c] x) yes no)
		// cond: oneBit(c)
		// result: (TBNZ [int64(ntz64(c))] x yes no)
		for b.Controls[0].Op == OpARM64TSTconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			x := v_0.Args[0]
			if !(oneBit(c)) {
				break
			}
			b.resetWithControl(BlockARM64TBNZ, x)
			b.AuxInt = int64ToAuxInt(int64(ntz64(c)))
			return true
		}
		// match: (NE (TSTWconst [c] x) yes no)
		// cond: oneBit(int64(uint32(c)))
		// result: (TBNZ [int64(ntz64(int64(uint32(c))))] x yes no)
		for b.Controls[0].Op == OpARM64TSTWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(oneBit(int64(uint32(c)))) {
				break
			}
			b.resetWithControl(BlockARM64TBNZ, x)
			b.AuxInt = int64ToAuxInt(int64(ntz64(int64(uint32(c)))))
			return true
		}
		// match: (NE (FlagConstant [fc]) yes no)
		// cond: fc.ne()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.ne()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (NE (FlagConstant [fc]) yes no)
		// cond: !fc.ne()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.ne()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (NE (InvertFlags cmp) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64NE, cmp)
			return true
		}
	case BlockARM64NZ:
		// match: (NZ (Equal cc) yes no)
		// result: (EQ cc yes no)
		for b.Controls[0].Op == OpARM64Equal {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64EQ, cc)
			return true
		}
		// match: (NZ (NotEqual cc) yes no)
		// result: (NE cc yes no)
		for b.Controls[0].Op == OpARM64NotEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64NE, cc)
			return true
		}
		// match: (NZ (LessThan cc) yes no)
		// result: (LT cc yes no)
		for b.Controls[0].Op == OpARM64LessThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64LT, cc)
			return true
		}
		// match: (NZ (LessThanU cc) yes no)
		// result: (ULT cc yes no)
		for b.Controls[0].Op == OpARM64LessThanU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64ULT, cc)
			return true
		}
		// match: (NZ (LessEqual cc) yes no)
		// result: (LE cc yes no)
		for b.Controls[0].Op == OpARM64LessEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64LE, cc)
			return true
		}
		// match: (NZ (LessEqualU cc) yes no)
		// result: (ULE cc yes no)
		for b.Controls[0].Op == OpARM64LessEqualU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64ULE, cc)
			return true
		}
		// match: (NZ (GreaterThan cc) yes no)
		// result: (GT cc yes no)
		for b.Controls[0].Op == OpARM64GreaterThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64GT, cc)
			return true
		}
		// match: (NZ (GreaterThanU cc) yes no)
		// result: (UGT cc yes no)
		for b.Controls[0].Op == OpARM64GreaterThanU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64UGT, cc)
			return true
		}
		// match: (NZ (GreaterEqual cc) yes no)
		// result: (GE cc yes no)
		for b.Controls[0].Op == OpARM64GreaterEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64GE, cc)
			return true
		}
		// match: (NZ (GreaterEqualU cc) yes no)
		// result: (UGE cc yes no)
		for b.Controls[0].Op == OpARM64GreaterEqualU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64UGE, cc)
			return true
		}
		// match: (NZ (LessThanF cc) yes no)
		// result: (FLT cc yes no)
		for b.Controls[0].Op == OpARM64LessThanF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64FLT, cc)
			return true
		}
		// match: (NZ (LessEqualF cc) yes no)
		// result: (FLE cc yes no)
		for b.Controls[0].Op == OpARM64LessEqualF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64FLE, cc)
			return true
		}
		// match: (NZ (GreaterThanF cc) yes no)
		// result: (FGT cc yes no)
		for b.Controls[0].Op == OpARM64GreaterThanF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64FGT, cc)
			return true
		}
		// match: (NZ (GreaterEqualF cc) yes no)
		// result: (FGE cc yes no)
		for b.Controls[0].Op == OpARM64GreaterEqualF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64FGE, cc)
			return true
		}
		// match: (NZ (ANDconst [c] x) yes no)
		// cond: oneBit(c)
		// result: (TBNZ [int64(ntz64(c))] x yes no)
		for b.Controls[0].Op == OpARM64ANDconst {
			v_0 := b.Controls[0]
			c := auxIntT
"""




```