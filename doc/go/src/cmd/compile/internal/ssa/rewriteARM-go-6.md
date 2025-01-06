Response: My thought process to answer the request goes through these stages:

1. **Understanding the Goal:** The primary goal is to analyze a snippet of Go code from `rewriteARM.go` and explain its functionality, infer the broader Go feature it relates to, provide examples, and summarize its purpose within the larger context of the file. It's also important to note the "part 7 of 8" constraint, suggesting a larger sequence of code transformations.

2. **Initial Code Scan (Pattern Recognition):** I quickly scan the code, looking for recurring patterns. I notice:
    * **Block Matching:** The code heavily uses `switch b.Kind()` and within each case, it iterates through `b.Controls[0].Op`. This suggests the code is operating on control flow blocks (`b`) and examining the operations (`Op`) that determine their branching behavior.
    * **Conditionals (GE, GT, LE, LT):**  The `case` statements deal with block kinds like `BlockARMGE`, `BlockARMGT`, `BlockARMLE`, `BlockARMLT`. These clearly relate to conditional branching based on comparison results (Greater or Equal, Greater Than, Less or Equal, Less Than).
    * **CMPconst:** A common pattern is checking if `b.Controls[0].Op == OpARMCMPconst`. This indicates that the code is specifically looking at comparisons with a constant value.
    * **Logical and Arithmetic Operations (AND, SUB, ADD, XOR):** The code frequently examines the operands of `CMPconst`, looking for specific arithmetic and logical operations like `OpARMAND`, `OpARMSUB`, `OpARMADD`, `OpARMXOR`, often with variations like `const`, `shiftLL`, `shiftRL`, `shiftRA`, and their register counterparts.
    * **"Uses == 1" Condition:**  A recurring condition is `l.Uses == 1`, where `l` is a value derived from `b.Controls[0].Args[0]`. This suggests an optimization that's only applied if the result of the operation (`l`) is used exactly once.
    * **Transformation to TST/TEQ:**  A key transformation is replacing `CMPconst [0]` followed by operations like `AND` or `XOR` with `TST` or `TEQ` instructions.
    * **`b.resetWithControl`:** This function is used to change the type of the control flow block, often to a "no overflow" variant (e.g., `BlockARMGEnoov`).

3. **Inferring the Purpose (Hypothesis Formation):** Based on the patterns, I hypothesize that this section of the code performs optimizations on conditional branch instructions in the ARM architecture. Specifically, it seems to be:
    * **Simplifying comparisons with zero:** It detects comparisons with zero (`CMPconst [0]`) following certain arithmetic or logical operations.
    * **Using Test Instructions (TST/TEQ):** It replaces these comparison-plus-operation sequences with more efficient ARM "test" instructions (`TST` for AND-like operations, `TEQ` for XOR-like operations). Test instructions implicitly set flags without needing a separate comparison.
    * **Handling shifted operands:** The code explicitly deals with shifted operands in the arithmetic and logical operations.
    * **Considering single-use values:** The `l.Uses == 1` condition points to a peephole optimization where the intermediate result is only used for the comparison.

4. **Constructing Examples:**  To illustrate the inferred functionality, I create Go code examples. I focus on scenarios where the code snippet would apply:
    * **Comparison after AND:**  I show an `if` condition using `x & y == 0`. This is a prime candidate for the `TST` optimization.
    * **Comparison after XOR:** I show an `if` condition using `x ^ y == 0`. This is a prime candidate for the `TEQ` optimization.
    * **Importance of `l.Uses == 1`:** I create an example where the result of the AND operation is used multiple times, demonstrating why the optimization wouldn't apply in that case.

5. **Explaining the Underlying Go Feature:**  I recognize that this code is part of the Go compiler's intermediate representation (SSA - Static Single Assignment) rewriting phase. This phase optimizes the generated code before final assembly. The specific feature being implemented is the optimization of conditional expressions on the ARM architecture.

6. **Addressing Specific Instructions:**
    * **`auxIntToInt32` and `int32ToAuxInt`:** I explain that these are likely helper functions to convert between the generic `AuxInt` type used in the SSA representation and specific integer types.
    * **`b.resetWithControl`:**  I elaborate on its role in changing the block type, which affects how the conditional branch is implemented.

7. **Summarizing the Functionality:** I synthesize the observations and inferences into a concise summary, highlighting the core optimization being performed. I emphasize the transformation of comparisons after certain operations into more efficient test instructions.

8. **Considering "Part 7 of 8":**  I recognize that this is likely part of a larger sequence of rewriting rules for the ARM architecture. The other parts likely handle different kinds of optimizations or transformations.

9. **Review and Refinement:** I reread my explanation to ensure clarity, accuracy, and completeness. I check that the examples are relevant and easy to understand. I make sure to connect the code snippet to the broader concepts of compiler optimization and SSA.

This iterative process of code analysis, hypothesis formation, example creation, and contextualization allows me to arrive at a comprehensive and accurate answer to the request. The pattern recognition is crucial for quickly grasping the overall logic, and the examples solidify the understanding and make it more concrete.

这个go语言文件 `go/src/cmd/compile/internal/ssa/rewriteARM.go` 的一部分， 主要功能是对Go语言编译过程中生成的 **静态单赋值形式 (SSA)** 的中间代码进行 **重写 (rewriting)** 和 **优化**， 目标架构是 **ARM**。

更具体来说， 这部分代码专注于 **优化控制流块 (control flow blocks)**， 特别是那些表示条件分支的块 (例如 `BlockARMGE`, `BlockARMGT`, `BlockARMLE`, `BlockARMLT`)。 它尝试识别特定的 **模式 (patterns)**， 这些模式涉及到比较指令 (`CMPconst`) 和一些常见的算术或逻辑运算 (例如 `AND`, `SUB`, `ADD`, `XOR`)， 并且在满足特定条件时， 将这些模式 **替换 (replace)** 为更高效的 ARM 指令。

**功能归纳:**

这段代码的主要功能是 **优化 ARM 架构下的条件分支指令**。 它通过模式匹配的方式，将一些常见的比较操作和其前的算术/逻辑运算组合，替换为更简洁或更高效的 ARM 指令。 这种优化通常能减少指令数量，提高执行效率。

**推理 Go 语言功能的实现:**

这段代码优化的 Go 语言功能主要是 **条件语句 (if statements)** 和 **比较操作**。 当 Go 编译器将 `if` 语句编译成 SSA 中间代码时， 可能会生成类似的比较和算术/逻辑运算的组合， 而这段代码就是针对这些组合进行优化的。

**Go 代码举例说明:**

假设我们有以下 Go 代码:

```go
package main

func main() {
	x := 10
	y := 5
	if x & y == 0 {
		println("Bitwise AND is zero")
	}
	if x ^ y == 0 {
		println("Bitwise XOR is zero")
	}
}
```

**假设的输入 (SSA 中间代码片段):**

对于 `x & y == 0` 这个条件， 可能会生成类似的 SSA 代码块 (简化表示):

```
b1:
  v1 = AND x y
  v2 = ConstInt 0
  v3 = CMPconst v2 v1
  If v3 goto b2 else b3
b2:
  // then 分支
  ...
b3:
  // else 分支
  ...
```

**这段代码的功能将会识别出 `CMPconst [0] l:(AND x y)` 这样的模式， 并将其转化为更高效的 `TST` 指令:**

**优化后的 SSA 中间代码 (模拟):**

```
b1:
  v1 = TST x y
  If v1 goto b2 else b3 // BlockARMGEnoov, BlockARMGTnoov 等
b2:
  // then 分支
  ...
b3:
  // else 分支
  ...
```

对于 `x ^ y == 0` 这个条件， 类似地， 代码会将 `CMPconst [0] l:(XOR x y)` 优化为 `TEQ` 指令。

**假设的输入与输出 (针对代码片段):**

以 `// match: (GE (CMPconst [0] l:(AND x y)) yes no)` 这个规则为例:

**假设输入 (SSA 块 `b` 的状态):**

```
b.Kind = BlockARMGE
b.Controls[0].Op = OpARMCMPconst
b.Controls[0].AuxInt = 0 // 代表比较 0
b.Controls[0].Args[0].Op = OpARMAND
b.Controls[0].Args[0].Args[0] = x // 某个 SSA 值
b.Controls[0].Args[0].Args[1] = y // 某个 SSA 值
b.Controls[0].Args[0].Uses = 1
```

**输出 (SSA 块 `b` 的状态):**

```
b.Kind = BlockARMGEnoov
b.Controls[0].Op = OpARMTST
b.Controls[0].Args[0] = x
b.Controls[0].Args[1] = y
```

**涉及命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。 它是 Go 编译器内部的优化步骤。 Go 编译器的命令行参数 (例如 `-gcflags`) 可以影响编译过程和优化级别， 间接地影响这段代码是否会被执行以及执行的效果。 例如， 如果编译时禁用了某些优化， 那么这段代码可能就不会起作用。

**使用者易犯错的点:**

普通 Go 开发者通常不需要直接关注或修改这些底层的编译器代码。  这里的 "使用者" 可以理解为 Go 编译器的开发者或者需要深入理解 Go 编译过程的人员。

一个潜在的易错点是 **错误地理解或修改模式匹配的条件**。 例如， 代码中 `l.Uses == 1` 这个条件非常重要， 它确保了只有当 `AND` 或 `XOR` 的结果只被使用一次 (即用于比较) 时， 才能进行优化。 如果错误地移除了这个条件， 可能会导致在某些情况下错误地进行优化， 破坏程序的正确性。

**第7部分，共8部分，请归纳一下它的功能:**

作为第7部分， 考虑到之前和之后的部分可能涵盖了 SSA 重写的其他方面 (例如， 操作码的替换， 常量折叠等)， 这部分的功能可以归纳为：

**专注于 ARM 架构下条件分支指令的优化， 特别是针对比较指令 (`CMPconst`) 紧跟着特定算术或逻辑运算 (`AND`, `SUB`, `ADD`, `XOR`) 且运算结果仅被使用一次的场景， 将其转化为更高效的 ARM 测试指令 (`TST`, `TEQ`) 或带有 "no overflow" 标记的控制流块。**

总而言之， 这段代码是 Go 编译器针对 ARM 架构进行性能优化的一个重要组成部分， 通过细致的模式匹配和指令替换， 提高了生成代码的效率。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第7部分，共8部分，请归纳一下它的功能

"""
IntToInt32(l.AuxInt)
			x := l.Args[0]
			if !(l.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARMTSTconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(c)
			v0.AddArg(x)
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(ANDshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TSTshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(ANDshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TSTshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(ANDshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TSTshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(ANDshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TSTshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(ANDshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TSTshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(ANDshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TSTshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(XOR x y)) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TEQ x y) yes no)
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
				b.resetWithControl(BlockARMGEnoov, v0)
				return true
			}
			break
		}
		// match: (GE (CMPconst [0] l:(XORconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TEQconst [c] x) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(XORshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TEQshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(XORshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TEQshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(XORshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TEQshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(XORshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TEQshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(XORshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TEQshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] l:(XORshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GEnoov (TEQshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMGEnoov, v0)
			return true
		}
	case BlockARMGEnoov:
		// match: (GEnoov (FlagConstant [fc]) yes no)
		// cond: fc.geNoov()
		// result: (First yes no)
		for b.Controls[0].Op == OpARMFlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.geNoov()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GEnoov (FlagConstant [fc]) yes no)
		// cond: !fc.geNoov()
		// result: (First no yes)
		for b.Controls[0].Op == OpARMFlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.geNoov()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GEnoov (InvertFlags cmp) yes no)
		// result: (LEnoov cmp yes no)
		for b.Controls[0].Op == OpARMInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARMLEnoov, cmp)
			return true
		}
	case BlockARMGT:
		// match: (GT (FlagConstant [fc]) yes no)
		// cond: fc.gt()
		// result: (First yes no)
		for b.Controls[0].Op == OpARMFlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.gt()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GT (FlagConstant [fc]) yes no)
		// cond: !fc.gt()
		// result: (First no yes)
		for b.Controls[0].Op == OpARMFlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.gt()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (InvertFlags cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpARMInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARMLT, cmp)
			return true
		}
		// match: (GT (CMPconst [0] l:(SUB x y)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMP x y) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(MULS x y a)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMP a (MUL <x.Type> x y)) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(SUBconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMPconst [c] x) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(SUBshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMPshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(SUBshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMPshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(SUBshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMPshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(SUBshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMPshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(SUBshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMPshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(SUBshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMPshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ADD x y)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMN x y) yes no)
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
				b.resetWithControl(BlockARMGTnoov, v0)
				return true
			}
			break
		}
		// match: (GT (CMPconst [0] l:(ADDconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMNconst [c] x) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ADDshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMNshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ADDshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMNshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ADDshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMNshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ADDshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMNshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ADDshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMNshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ADDshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMNshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(MULA x y a)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMN a (MUL <x.Type> x y)) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(AND x y)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TST x y) yes no)
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
				b.resetWithControl(BlockARMGTnoov, v0)
				return true
			}
			break
		}
		// match: (GT (CMPconst [0] l:(ANDconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TSTconst [c] x) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ANDshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TSTshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ANDshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TSTshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ANDshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TSTshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ANDshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TSTshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ANDshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TSTshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(ANDshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TSTshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(XOR x y)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TEQ x y) yes no)
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
				b.resetWithControl(BlockARMGTnoov, v0)
				return true
			}
			break
		}
		// match: (GT (CMPconst [0] l:(XORconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TEQconst [c] x) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(XORshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TEQshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(XORshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TEQshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(XORshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TEQshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(XORshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TEQshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(XORshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TEQshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] l:(XORshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (TEQshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMGTnoov, v0)
			return true
		}
	case BlockARMGTnoov:
		// match: (GTnoov (FlagConstant [fc]) yes no)
		// cond: fc.gtNoov()
		// result: (First yes no)
		for b.Controls[0].Op == OpARMFlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.gtNoov()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GTnoov (FlagConstant [fc]) yes no)
		// cond: !fc.gtNoov()
		// result: (First no yes)
		for b.Controls[0].Op == OpARMFlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.gtNoov()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GTnoov (InvertFlags cmp) yes no)
		// result: (LTnoov cmp yes no)
		for b.Controls[0].Op == OpARMInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARMLTnoov, cmp)
			return true
		}
	case BlockIf:
		// match: (If (Equal cc) yes no)
		// result: (EQ cc yes no)
		for b.Controls[0].Op == OpARMEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMEQ, cc)
			return true
		}
		// match: (If (NotEqual cc) yes no)
		// result: (NE cc yes no)
		for b.Controls[0].Op == OpARMNotEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMNE, cc)
			return true
		}
		// match: (If (LessThan cc) yes no)
		// result: (LT cc yes no)
		for b.Controls[0].Op == OpARMLessThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMLT, cc)
			return true
		}
		// match: (If (LessThanU cc) yes no)
		// result: (ULT cc yes no)
		for b.Controls[0].Op == OpARMLessThanU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMULT, cc)
			return true
		}
		// match: (If (LessEqual cc) yes no)
		// result: (LE cc yes no)
		for b.Controls[0].Op == OpARMLessEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMLE, cc)
			return true
		}
		// match: (If (LessEqualU cc) yes no)
		// result: (ULE cc yes no)
		for b.Controls[0].Op == OpARMLessEqualU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMULE, cc)
			return true
		}
		// match: (If (GreaterThan cc) yes no)
		// result: (GT cc yes no)
		for b.Controls[0].Op == OpARMGreaterThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMGT, cc)
			return true
		}
		// match: (If (GreaterThanU cc) yes no)
		// result: (UGT cc yes no)
		for b.Controls[0].Op == OpARMGreaterThanU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARMUGT, cc)
			return true
		}
		// match: (If (GreaterEqual cc) yes no)
		// result: (GE cc yes no)
		for b.Controls[0].Op == OpARMGreaterEqual {
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
"""




```