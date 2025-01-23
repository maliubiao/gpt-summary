Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze the provided Go code snippet from `rewriteARM.go` and explain its functionality, especially within the context of the Go compiler's SSA (Static Single Assignment) optimization phase. The request specifically asks about the purpose, potential Go language feature implemented, code examples, command-line arguments (if any), common mistakes, and a summary of the functionality of this specific part (part 13 of 16).

2. **Initial Code Examination:** I first scan the code for keywords and patterns. I see `switch b.Kind`, `case BlockARM...`, `match: (...)`, `cond: (...)`, `result: (...)`. This strongly suggests that the code is performing pattern matching and applying rewrites to SSA blocks based on their kind and the operations within them. The `// match: ... // cond: ... // result: ...` comments are crucial; they explicitly state the transformations being performed.

3. **Focus on Block Types:**  The `switch b.Kind` statement indicates the code is operating on different kinds of control flow blocks in the SSA graph. The `case` statements list specific ARM-related block types like `BlockARMLT`, `BlockARMLE`, `BlockARMGE`, `BlockARMGT`, `BlockARMGEnoov`, `BlockARMGTnoov`, and `BlockIf`. This tells me the code is about optimizing conditional branches and comparisons on the ARM architecture. The "noov" suffix likely refers to "no overflow" or similar conditions related to arithmetic operations.

4. **Analyze Individual Cases (Pattern Matching):**  I then go through each `case` and its internal `for` loops. The structure within the `for` loops is consistently looking for specific patterns in the control flow graph:

   - **`b.Controls[0].Op == OpARM...`**:  This checks the operation of the control instruction of the current block. It's often a comparison operation like `OpARMCMPconst` (compare with constant).
   - **`v_0 := b.Controls[0]`**: Assigns the control instruction to `v_0` for easier access.
   - **`auxIntToInt32(v_0.AuxInt) != 0`**: Checks the immediate value associated with the operation.
   - **`l := v_0.Args[0]`**:  Accesses the first argument of the control instruction, which is often the value being compared.
   - **`l.Op == OpARM...`**: Checks the operation of this argument (e.g., `OpARMAND`, `OpARMSUB`, `OpARMXOR`).
   - **`l.Uses == 1`**:  A crucial condition indicating that the result of the operation `l` is used only once. This is important for safe inlining and rewriting.
   - **`b.NewValue0(...)`**: Creates new SSA values (instructions).
   - **`b.resetWithControl(BlockARM..., ...)`**:  This is the core of the rewrite. It changes the block's type and its control instruction to a potentially more efficient equivalent.

5. **Infer Functionality (Based on Rewrites):** By examining the "match" and "result" comments, I can infer the optimizations being performed. For example:

   - `// match: (LE (CMPconst [0] l:(SUB x y)) yes no)`
   - `// result: (LEnoov (CMP x y) yes no)`
   This suggests that if a "Less Equal" block (`LE`) is controlled by a comparison with zero of a subtraction (`SUB`), and the result of the subtraction is used only once, it can be rewritten as a "Less Equal no overflow" block (`LEnoov`) directly comparing `x` and `y`. This eliminates the explicit subtraction instruction.

   -  Many patterns transform comparisons against zero of bitwise AND, OR, and XOR operations into corresponding test instructions (`TST`, `TEQ`). This is a common optimization on architectures with dedicated test instructions.

6. **Connect to Go Language Features:** I consider what Go language constructs these optimizations might relate to. The comparisons and bitwise operations naturally map to:

   - **Relational Operators:** `<`, `<=`, `>`, `>=`, `==`, `!=`
   - **Bitwise Operators:** `&`, `|`, `^`
   - **Arithmetic Operators:** `+`, `-`

   The optimizations specifically target cases where these operations are compared against zero. This is a very common pattern in conditional statements.

7. **Construct Go Code Examples:** Based on the inferred functionality, I create simple Go code examples that would likely trigger these rewrites. The key is to create conditional statements involving comparisons with zero after the specific operations identified in the patterns.

8. **Consider Command-Line Arguments and Common Mistakes:** Since the code is part of the compiler's internal optimization phase, there are unlikely to be direct command-line arguments controlling *these specific* rewrites. The Go compiler has flags for overall optimization levels, but not fine-grained control over individual SSA rewrites. Regarding mistakes, the "l.Uses == 1" condition highlights a potential pitfall:  if the result of the intermediate operation is used multiple times, the rewrite might not be safe or beneficial.

9. **Summarize Functionality:** Finally, I synthesize my understanding into a concise summary, focusing on the pattern matching and optimization of conditional branches based on comparisons against zero involving arithmetic and bitwise operations.

10. **Address Part Number:** I note that this is part 13 of 16, which suggests this is a section dealing with specific kinds of optimizations related to conditional control flow on the ARM architecture. The other parts likely handle different sets of rewrites or other compiler phases.

By following these steps, I can break down the complex code snippet and provide a comprehensive explanation of its purpose and functionality within the Go compiler.
## 功能分析：go/src/cmd/compile/internal/ssa/rewriteARM.go 第13部分

这段代码是 Go 语言编译器中，针对 ARM 架构进行**静态单赋值 (SSA) 中间表示**优化的一个部分。 具体来说，它主要关注**控制流块 (Block)** 的转换和优化，特别是针对各种**比较操作 (Comparison)** 后的条件分支。

**核心功能：简化和优化基于比较结果的条件分支。**

这段代码遍历 SSA 图中的不同类型的控制流块 (`BlockARMLT`, `BlockARMLE`, `BlockARMGE`, `BlockARMGT`, `BlockARMGEnoov`, `BlockARMGTnoov`, `BlockIf`)，并尝试将一些复杂的比较操作模式替换为更简洁、更高效的操作。 它通过模式匹配的方式，寻找特定的指令序列，并在满足特定条件时，将其替换为更底层的 ARM 指令。

**具体功能分解 (基于代码中的 `match` 和 `result` 注释)：**

1. **优化带 `CMPconst [0]` 的比较操作:**
   - 当比较一个算术运算 (如 `SUB`, `ADD`, `MULS`, `MULA`) 或位运算 (`AND`, `XOR`) 的结果是否等于 0 时，可以将 `CMPconst [0]` 和运算操作合并为一个更底层的比较指令，例如：
     - `SUB x y` + `CMPconst [0]`  -> `CMP x y` (结果用 `GTnoov`, `LTnoov` 等块处理)
     - `ADD x y` + `CMPconst [0]`  -> `CMN x y` (结果用 `GTnoov`, `LTnoov` 等块处理)
     - `AND x y` + `CMPconst [0]`  -> `TST x y` (结果用 `GTnoov`, `LTnoov` 等块处理)
     - `XOR x y` + `CMPconst [0]`  -> `TEQ x y` (结果用 `GTnoov`, `LTnoov` 等块处理)
   - 类似的优化也适用于带常量的算术和位运算，以及带移位的运算。
   - 这些优化通常会产生 `GTnoov`, `LTnoov`, `GEnoov`, `LEnoov` 等新的块类型，这些块类型表明比较操作不会产生溢出。

2. **优化基于 `FlagConstant` 的条件分支:**
   - 当条件分支的控制依赖于一个已知的标志位常量 (`FlagConstant`) 时，可以直接根据该常量的值决定跳转方向，从而消除比较操作。例如，如果标志位常量表明 "大于等于无溢出" (`geNoov`) 为真，那么 `GEnoov` 块可以直接跳转到 `yes` 分支。

3. **优化 `InvertFlags` 操作:**
   - 当条件分支的控制依赖于 `InvertFlags` 操作时，可以将该操作直接转换为相反的条件分支。例如，`GE (InvertFlags cmp)` 可以直接转换为 `LEnoov cmp`。

4. **简化 `If` 块:**
   - 将 `If` 块的控制条件从高级的比较操作符 (`Equal`, `NotEqual`, `LessThan`, etc.) 直接转换为对应的 ARM 条件码块 (`EQ`, `NE`, `LT`, `ULT`, `LE`, `ULE`, `GT`, `UGT`, `GE`).

**推理解释与 Go 代码示例:**

假设我们有以下 Go 代码：

```go
package main

func compare(a, b int32) bool {
	return a - b > 0
}
```

在编译器的 SSA 阶段，`return a - b > 0` 可能会被表示为类似以下的 SSA 图结构 (简化)：

```
b1:
    v1 = Param: a (int32)
    v2 = Param: b (int32)
    v3 = SubInt32 v1, v2
    v4 = ConstInt32 [0]
    v5 = GreaterThan v3, v4
    If v5 goto b2 else b3

b2: // true分支
    ...
b3: // false分支
    ...
```

这段 `rewriteARM.go` 代码的目的是将 `b1` 块中涉及 `SubInt32` 和 `GreaterThan` 的部分进行优化。 根据代码片段中的匹配规则：

```
		// match: (GT (CMPconst [0] l:(SUB x y)) yes no)
		// cond: l.Uses==1
		// result: (GTnoov (CMP x y) yes no)
```

当 SSA 图中存在一个 `GT` 块 (对应 `GreaterThan`)，其控制条件是一个将 `SUB` 指令的结果与常量 `0` 进行比较的 `CMPconst [0]` 指令，并且 `SUB` 指令的结果只被使用一次 (`l.Uses==1`) 时，就可以进行优化。

**优化过程：**

1. **识别模式:** 代码会识别出 `b1` 块的 `If` 指令的控制条件 `v5` 是一个 `GreaterThan` 操作。
2. **检查控制指令:** `v5` 的参数是一个比较操作 `v3 > v4`，其中 `v4` 是常量 `0`，而 `v3` 是 `SubInt32 v1, v2` 的结果。 这符合 `(GT (CMPconst [0] l:(SUB x y)) yes no)` 的模式。
3. **检查使用次数:** 代码会检查 `v3` (即 `SubInt32` 的结果) 是否只被 `v5` 使用了一次。
4. **应用重写规则:** 如果条件满足，代码会将 `b1` 块的类型重置为 `BlockARMGTnoov`，并将控制指令替换为一个直接比较 `v1` 和 `v2` 的 `CMP` 指令。

**优化后的 SSA 图 (推测)：**

```
b1:
    v1 = Param: a (int32)
    v2 = Param: b (int32)
    v6 = CMP v1, v2
    GotoIfGTnoov v6 goto b2 else b3  // BlockARMGTnoov

b2: // true分支
    ...
b3: // false分支
    ...
```

**假设的输入与输出:**

**输入 (SSA 块 `b` 的初始状态):**

```
b.Kind = BlockIf
b.Controls = [
  {Op: OpARMGreaterThan, Args: [{Op: OpARMCMPconst, AuxInt: 0, Args: [{Op: OpARMSUB, Args: [x, y]}]}]}
]
```

**输出 (SSA 块 `b` 的最终状态):**

```
b.Kind = BlockARMGTnoov
b.Controls = [
  {Op: OpARMCMP, Args: [x, y]}
]
```

**命令行参数:**

这段代码本身不涉及命令行参数的处理。 它是在 Go 编译器内部的 SSA 优化阶段执行的。 用户可以通过 Go 编译器的 `-gcflags` 参数来控制编译器的优化级别，但这不会直接影响到这段代码的执行逻辑，而是会影响到 SSA 图的生成和优化过程的整体行为。

**易犯错的点:**

使用者通常不会直接与这段代码交互，因为它属于编译器内部实现。 但是，理解这些优化规则可以帮助开发者更好地理解 Go 代码在底层是如何被编译和优化的。

**归纳一下它的功能 (第13部分):**

作为 `rewriteARM.go` 的第 13 部分，这段代码专注于对 ARM 架构的 SSA 图中的条件分支进行细粒度的优化。 它通过模式匹配和条件判断，将一些常见的比较操作模式转换为更底层的、更高效的 ARM 指令序列。 重点在于简化比较零的操作，以及利用标志位常量直接进行跳转判断，从而提升最终生成代码的执行效率。 这一部分主要处理 `LT`, `LE`, `GE`, `GT` 等比较操作相关的控制流块，并尝试将它们转换为 `LTnoov`, `LEnoov`, `GEnoov`, `GTnoov` 等无溢出版本的块，或者直接使用底层的比较指令。同时，它也负责简化通用的 `If` 块，将其转换为特定 ARM 条件码的控制流块。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第13部分，共16部分，请归纳一下它的功能
```

### 源代码
```go
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
		for
```