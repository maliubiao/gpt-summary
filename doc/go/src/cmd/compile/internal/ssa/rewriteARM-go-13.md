Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code snippet, which is a part of the `rewriteARM.go` file. It also asks for explanations, examples, and identification of potential pitfalls. Crucially, it's the 14th part of a 16-part series, so I need to keep that context in mind for the summary.

2. **Analyze the Code Structure:**  The code primarily consists of a `switch` statement operating on the `b.Block.Kind`. Inside each `case`, there are further `for` loops that check the operation (`Op`) of the control value (`b.Controls[0]`). Based on these checks, the code performs transformations on the current block (`b`). These transformations often involve:
    * Resetting the block's kind (`b.Reset`).
    * Resetting the block's control value (`b.resetWithControl`).
    * Swapping successors (`b.swapSuccessors`).
    * Creating new values (`b.NewValue0`).

3. **Identify the Core Functionality:** The code's main purpose is to optimize the control flow of the program at the SSA level for the ARM architecture. It does this by recognizing specific patterns of operations and replacing them with more efficient equivalents. The `rewriteARM.go` file suggests this is part of the compilation process, specifically targeting ARM.

4. **Categorize the Transformations:**  Within each `case`, I observe patterns in the transformations. For instance, the `BlockARMLE` case has many transformations related to comparisons with zero (`CMPconst [0]`) followed by arithmetic or logical operations. These are often converted into equivalent operations that directly set the flags without an explicit compare, like `TST`, `CMN`, or by using flag constants.

5. **Focus on `BlockARMLE` (and others):**  The bulk of the provided code deals with the `BlockARMLE` case. This indicates a significant focus on optimizing blocks where the condition is "less than or equal to". I also see similar patterns in other cases like `BlockARMLT`.

6. **Infer Go Language Features:**  The transformations suggest optimizations related to:
    * **Conditional statements (if/else):**  The `BlockARM...` constants clearly represent different conditional jump scenarios.
    * **Arithmetic and logical operations:** The code manipulates expressions involving `ADD`, `SUB`, `MUL`, `AND`, `XOR`, and their shifted variants.
    * **Comparisons:** The `CMP` and related instructions are central to the transformations.

7. **Construct Example (Focusing on a representative transformation):**  I'll choose a simple and common pattern from the `BlockARMLE` case:

   ```go
   // match: (LE (CMPconst [0] l:(SUB x y)) yes no)
   // cond: l.Uses==1
   // result: (LEnoov (CMP x y) yes no)
   ```

   This translates to: if we have a "less than or equal to" block controlled by comparing the result of a subtraction (`x - y`) with zero, and that subtraction is only used once, we can directly use the result of `CMP x y` to control a `LEnoov` block. This avoids the explicit comparison with zero. I can then create a corresponding Go code example:

   ```go
   package main

   func example(a, b int32) bool {
       if a - b <= 0 { // This will eventually be represented by a CMPconst and SUB
           return true
       }
       return false
   }
   ```
   I would then provide a hypothetical SSA representation and the optimized version, illustrating the transformation.

8. **Address Command Line Arguments:** Since the code is part of the compiler's internal logic, it doesn't directly handle command-line arguments in the way a typical application does. The compilation process itself is driven by `go build`, `go run`, etc., but these flags don't directly control *this specific* rewrite pass in a granular fashion. I need to explain this distinction.

9. **Identify Potential Pitfalls (Based on the Code):** The `l.Uses==1` condition appears frequently. This suggests a potential pitfall: if the intermediate result of an operation (like the subtraction in the example above) is used multiple times, this specific optimization might not be applicable. This is a common theme in compiler optimizations – ensuring the transformation is valid and doesn't change the program's behavior.

10. **Synthesize the Summary:**  Based on the analysis of the different `case` blocks, the transformations they perform, and the overall purpose of the code, I can summarize the functionality of this part: it focuses on optimizing conditional control flow blocks (`If` statements in Go) for the ARM architecture. It achieves this by recognizing patterns involving comparisons and arithmetic/logical operations and rewriting them into more efficient sequences of ARM instructions, often leveraging the processor's flag register.

11. **Structure the Answer:**  Finally, I organize my findings into the requested format, using clear headings and explanations. I make sure to explicitly state the assumptions and context (being part 14 of 16). I use the provided code comments as hints for the explanations.

By following these steps, I can systematically analyze the code, infer its purpose, provide relevant examples, and address the specific points raised in the request. The iterative refinement and pattern recognition are key to understanding this kind of compiler optimization code.
## 功能列举与代码推理：`rewriteARM.go` 第14部分

这部分代码主要负责对SSA（Static Single Assignment）形式的Go语言代码进行**基于ARM架构的重写规则**优化。 具体来说，它针对不同类型的控制流块（`Block`）进行模式匹配和转换，旨在生成更高效的ARM汇编指令。

**核心功能概括：**

这部分代码定义了一系列针对特定控制流块类型的重写规则，其主要目的是：

* **简化基于标志寄存器的条件跳转:**  识别并优化基于ARM标志寄存器 (`FlagConstant`, `InvertFlags`) 的条件跳转，例如直接根据标志位的值决定跳转方向，避免额外的比较操作。
* **优化比较指令与算术/逻辑运算的组合:**  针对比较指令 (`CMPconst`) 紧跟着算术或逻辑运算的情况进行优化，例如将 `CMPconst [0] (SUB x y)` 优化为直接使用 `CMP x y` 的结果，并选择合适的无溢出标志的条件跳转块 (`LEnoov`, `LTnoov` 等)。
* **转换成更底层的ARM条件跳转块:** 将高级的条件判断操作（如 `If (GreaterEqual cc)`) 转换为更底层的、直接对应ARM条件码的块类型 (`BlockARMGE`, `BlockARMUGE` 等)。
* **处理通用的 `If` 语句:** 将不满足特定模式的通用 `If` 语句转换为基于 `CMPconst [0]` 的比较和 `NE` (Not Equal) 跳转。

**Go语言功能实现推断与代码示例：**

这部分代码主要处理的是Go语言中的**条件控制语句**，例如 `if` 和 `else`。

**假设输入SSA代码：**

假设我们有以下Go代码片段：

```go
package main

func compare(a int32) bool {
	if a <= 0 {
		return true
	}
	return false
}
```

在SSA中间表示中，`if a <= 0` 可能会被表示为一个 `BlockARMLE` 类型的块，其控制值 (`b.Controls[0]`) 是一个比较操作，例如 `OpARMCMPconst` 将 `a` 与常量 `0` 进行比较。

**对应的SSA块的可能形式（简化）：**

```
b1 (ARMLE):
  v1 = CMPconst [0] a
  goto b2, b3 (v1)
b2: // true branch
  ...
b3: // false branch
  ...
```

**代码推理与转换示例 (基于 `BlockARMLE` 的部分规则)：**

1. **匹配 FlagConstant:** 如果控制值直接是一个 `FlagConstant` (表示编译时就能确定的条件)，例如：

   ```
   b1 (ARMLE):
     v1 = FlagConstant [FlagConstantLT] // 假设表示小于
     goto b2, b3 (v1)
   ```

   代码中的：

   ```go
   // match: (LE (FlagConstant [fc]) yes no)
   // cond: fc.le()
   // result: (First yes no)
   for b.Controls[0].Op == OpARMFlagConstant {
       v_0 := b.Controls[0]
       fc := auxIntToFlagConstant(v_0.AuxInt)
       if !(fc.le()) {
           break
       }
       b.Reset(BlockFirst)
       return true
   }
   ```

   这段代码会检查 `FlagConstant` 的值是否满足 `le()` (less than or equal)。如果满足，则将当前块 `b` 重置为 `BlockFirst`，意味着总是执行 `yes` 分支。

   **假设输入:** `v1` 代表的 `FlagConstant` 实际上是 `FlagConstantLE` (小于等于)。
   **输出:** 块 `b1` 被重置为 `BlockFirst`，后续只会跳转到 `b2`。

2. **匹配 CMPconst 后的 SUB 操作:**  如果控制值是一个将减法结果与 0 比较的操作，且该减法操作仅被使用一次：

   ```
   b1 (ARMLE):
     v1 = CMPconst [0] v2
     v2 = SUB a b
     goto b2, b3 (v1)
   ```

   代码中的：

   ```go
   // match: (LE (CMPconst [0] l:(SUB x y)) yes no)
   // cond: l.Uses==1
   // result: (LEnoov (CMP x y) yes no)
   for b.Controls[0].Op == OpARMCMPconst {
       v_0 := b.Controls[0]
       if auxIntToInt32(v_0.AuxInt) != 0 {
           break
       }
       l := v_0.Args[0]
       if l.Op != OpARMSUB {
           break
       }
       y := l.Args[1]
       x := l.Args[0]
       if !(l.Uses == 1) {
           break
       }
       v0 := b.NewValue0(v_0.Pos, OpARMCMP, types.TypeFlags)
       v0.AddArg2(x, y)
       b.resetWithControl(BlockARMLEnoov, v0)
       return true
   }
   ```

   这段代码会将 `CMPconst [0] (SUB a b)` 优化为直接使用 `CMP a b` 的结果，并将块类型更改为 `BlockARMLEnoov` (小于等于，无溢出)。

   **假设输入:**  `v2` (代表 `SUB a b`) 只被 `v1` 使用 (`l.Uses == 1`)。
   **输出:** 块 `b1` 的控制值变为 `CMP a b`，块类型变为 `BlockARMLEnoov`。

3. **通用 If 语句处理:** 如果控制值是一个普通的条件表达式：

   ```
   b1 (If):
     v1 = GreaterEqual a b
     goto b2, b3 (v1)
   ```

   代码中的：

   ```go
   // match: (If cond yes no)
   // result: (NE (CMPconst [0] cond) yes no)
   for {
       cond := b.Controls[0]
       v0 := b.NewValue0(cond.Pos, OpARMCMPconst, types.TypeFlags)
       v0.AuxInt = int32ToAuxInt(0)
       v0.AddArg(cond)
       b.resetWithControl(BlockARMNE, v0)
       return true
   }
   ```

   这段代码会将 `If` 块转换为 `BlockARMNE` (Not Equal) 块，其控制值是通过 `CMPconst [0]` 比较原始条件表达式的结果。

   **假设输入:** `v1` 代表 `a >= b` 的布尔结果。
   **输出:** 块 `b1` 的控制值变为 `CMPconst [0] v1`，块类型变为 `BlockARMNE`。

**命令行参数的具体处理：**

这段代码是Go编译器内部的一部分，并不直接处理用户在命令行输入的参数。编译器的行为受到 `go build`, `go run` 等命令的选项控制，例如 `-gcflags` 可以传递给Go编译器底层的参数，但这些参数通常不会直接控制到 `rewriteARM.go` 这样的特定重写规则的开启或关闭。

**使用者易犯错的点：**

由于这是编译器内部的优化代码，普通Go语言开发者不会直接接触或配置这些规则。因此，不存在使用者易犯错的点。这些优化是编译器自动进行的。

**第14部分功能归纳：**

作为 `rewriteARM.go` 的第14部分，这段代码专注于**优化SSA中间表示中特定类型的控制流块**，特别是 `BlockARMLE`、`BlockARMLT` 等基于比较结果的条件跳转块。它通过模式匹配，将这些高级的条件跳转操作转换为更底层的、更接近ARM硬件指令的形式，或者进行简化以减少不必要的计算和比较。这有助于生成更高效的ARM机器码，提升Go程序在ARM架构上的执行效率。这部分延续了之前部分对ARM架构特性进行优化的工作，并为后续的代码生成阶段做好准备。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第14部分，共16部分，请归纳一下它的功能
```

### 源代码
```go
b.Controls[0].Op == OpARMGreaterEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMGE, cc)
			return true
		}
		// match: (If (GreaterEqualU cc) yes no)
		// result: (UGE cc yes no)
		for b.Controls[0].Op == OpARMGreaterEqualU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMUGE, cc)
			return true
		}
		// match: (If cond yes no)
		// result: (NE (CMPconst [0] cond) yes no)
		for {
			cond := b.Controls[0]
			v0 := b.NewValue0(cond.Pos, OpARMCMPconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(0)
			v0.AddArg(cond)
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
	case BlockARMLE:
		// match: (LE (FlagConstant [fc]) yes no)
		// cond: fc.le()
		// result: (First yes no)
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARMGE, cmp)
			return true
		}
		// match: (LE (CMPconst [0] l:(SUB x y)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMP x y) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUB {
				break
			}
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMP, types.TypeFlags)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(MULS x y a)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMP a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMMULS {
				break
			}
			a := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMP, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARMMUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(SUBconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMPconst [c] x) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBconst {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg(x)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(SUBshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMPshiftLL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftLL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftLL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(SUBshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMPshiftRL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftRL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftRL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(SUBshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMPshiftRA x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftRA {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftRA, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(SUBshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMPshiftLLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftLLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftLLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(SUBshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMPshiftRLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftRLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftRLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(SUBshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMPshiftRAreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftRAreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftRAreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ADD x y)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMN x y) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADD {
				break
			}
			_ = l.Args[1]
			l_0 := l.Args[0]
			l_1 := l.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, l_0, l_1 = _i0+1, l_1, l_0 {
				x := l_0
				y := l_1
				if !(l.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARMCMN, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARMLEnoov, v0)
				return true
			}
			break
		}
		// match: (LE (CMPconst [0] l:(MULA x y a)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMN a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMMULA {
				break
			}
			a := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMN, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARMMUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ADDconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMNconst [c] x) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDconst {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg(x)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ADDshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMNshiftLL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftLL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftLL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ADDshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMNshiftRL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftRL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftRL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ADDshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMNshiftRA x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftRA {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftRA, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ADDshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMNshiftLLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftLLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftLLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ADDshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMNshiftRLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftRLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftRLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ADDshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (CMNshiftRAreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftRAreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftRAreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(AND x y)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TST x y) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMAND {
				break
			}
			_ = l.Args[1]
			l_0 := l.Args[0]
			l_1 := l.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, l_0, l_1 = _i0+1, l_1, l_0 {
				x := l_0
				y := l_1
				if !(l.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARMTST, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARMLEnoov, v0)
				return true
			}
			break
		}
		// match: (LE (CMPconst [0] l:(ANDconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TSTconst [c] x) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMANDconst {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTSTconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg(x)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ANDshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TSTshiftLL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMANDshiftLL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTSTshiftLL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ANDshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TSTshiftRL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMANDshiftRL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTSTshiftRL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ANDshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TSTshiftRA x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMANDshiftRA {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTSTshiftRA, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ANDshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TSTshiftLLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMANDshiftLLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTSTshiftLLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ANDshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TSTshiftRLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMANDshiftRLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTSTshiftRLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(ANDshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TSTshiftRAreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMANDshiftRAreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTSTshiftRAreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(XOR x y)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TEQ x y) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMXOR {
				break
			}
			_ = l.Args[1]
			l_0 := l.Args[0]
			l_1 := l.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, l_0, l_1 = _i0+1, l_1, l_0 {
				x := l_0
				y := l_1
				if !(l.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARMTEQ, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARMLEnoov, v0)
				return true
			}
			break
		}
		// match: (LE (CMPconst [0] l:(XORconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TEQconst [c] x) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMXORconst {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTEQconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg(x)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(XORshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TEQshiftLL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMXORshiftLL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTEQshiftLL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(XORshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TEQshiftRL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMXORshiftRL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTEQshiftRL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(XORshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TEQshiftRA x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMXORshiftRA {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTEQshiftRA, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(XORshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TEQshiftLLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMXORshiftLLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTEQshiftLLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(XORshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TEQshiftRLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMXORshiftRLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTEQshiftRLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
		// match: (LE (CMPconst [0] l:(XORshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LEnoov (TEQshiftRAreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMXORshiftRAreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTEQshiftRAreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLEnoov, v0)
			return true
		}
	case BlockARMLEnoov:
		// match: (LEnoov (FlagConstant [fc]) yes no)
		// cond: fc.leNoov()
		// result: (First yes no)
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARMGEnoov, cmp)
			return true
		}
	case BlockARMLT:
		// match: (LT (FlagConstant [fc]) yes no)
		// cond: fc.lt()
		// result: (First yes no)
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARMGT, cmp)
			return true
		}
		// match: (LT (CMPconst [0] l:(SUB x y)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMP x y) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUB {
				break
			}
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMP, types.TypeFlags)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(MULS x y a)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMP a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMMULS {
				break
			}
			a := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMP, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARMMUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(SUBconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMPconst [c] x) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBconst {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg(x)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(SUBshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMPshiftLL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftLL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftLL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(SUBshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMPshiftRL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftRL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftRL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(SUBshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMPshiftRA x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftRA {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftRA, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(SUBshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMPshiftLLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftLLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftLLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(SUBshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMPshiftRLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftRLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftRLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(SUBshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMPshiftRAreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMSUBshiftRAreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMPshiftRAreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ADD x y)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMN x y) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADD {
				break
			}
			_ = l.Args[1]
			l_0 := l.Args[0]
			l_1 := l.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, l_0, l_1 = _i0+1, l_1, l_0 {
				x := l_0
				y := l_1
				if !(l.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARMCMN, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARMLTnoov, v0)
				return true
			}
			break
		}
		// match: (LT (CMPconst [0] l:(MULA x y a)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMN a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMMULA {
				break
			}
			a := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMN, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARMMUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ADDconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMNconst [c] x) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDconst {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg(x)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ADDshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMNshiftLL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftLL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftLL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ADDshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMNshiftRL x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftRL {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftRL, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ADDshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMNshiftRA x y [c]) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftRA {
				break
			}
			c := auxIntToInt32(l.AuxInt)
			y := l.Args[1]
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftRA, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ADDshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMNshiftLLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			if l.Op != OpARMADDshiftLLreg {
				break
			}
			z := l.Args[2]
			x := l.Args[0]
			y := l.Args[1]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMCMNshiftLLreg, types.TypeFlags)
			v0.AddArg3(x, y, z)
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ADDshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMNshiftRLreg x y z) yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			l := v_0.Args[0]
			i
```