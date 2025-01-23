Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for an explanation of the provided Go code snippet, specifically focusing on its functionality within the context of `rewriteARM.go`. The key is to identify the patterns it's trying to match and the transformations it applies. Since it's part 15 of 16, a summary of the overall file's purpose will also be important.

2. **Analyze the Code Structure:**  I immediately recognize the structure as a series of `switch` statements on block types (`BlockARMLT`, `BlockARMLTnoov`, `BlockARMNE`). Within each case, there are multiple `for` loops checking the `Op` code of control values. This suggests a pattern-matching and replacement mechanism.

3. **Focus on Individual Matches:**  I pick a representative "match" block within the `BlockARMLT` case:

   ```go
   // match: (LT (CMPconst [0] l:(ADD x y)) yes no)
   // cond: l.Uses==1
   // result: (LTnoov (CMN x y) yes no)
   for b.Controls[0].Op == OpARMCMPconst {
       // ... (code to extract arguments) ...
       v0 := b.NewValue0(v_0.Pos, OpARMCMN, types.TypeFlags)
       v0.AddArg2(x, y)
       b.resetWithControl(BlockARMLTnoov, v0)
       return true
   }
   ```

4. **Deconstruct the Match and Result:** I break down the comment:
    * `// match: (LT (CMPconst [0] l:(ADD x y)) yes no)`: This means the code is looking for a block of type `LT` whose control is a `CMPconst` instruction comparing against 0, and the first argument of the `CMPconst` is an `ADD` instruction with arguments `x` and `y`.
    * `// cond: l.Uses==1`:  This is a condition that must be true for the match to proceed. It checks if the `ADD` instruction is used only once.
    * `// result: (LTnoov (CMN x y) yes no)`: If the conditions are met, the block's type is changed to `LTnoov`, and its control is replaced with a `CMN` instruction with arguments `x` and `y`.

5. **Infer the Functionality:** Based on this, I deduce that the code is performing optimizations. It's identifying specific patterns of ARM instructions and replacing them with more efficient or semantically equivalent instructions. The `l.Uses==1` condition suggests it's trying to avoid introducing side effects or breaking other parts of the code. The transformation from `CMPconst [0]` combined with `ADD` to `CMN` (compare negative) is a common ARM optimization.

6. **Generalize the Findings:** I look at other "match" blocks within `BlockARMLT` and see similar patterns involving other arithmetic and logical operations (`SUB`, `AND`, `XOR`) and their shifted variants. The transformations often involve replacing a `CMPconst [0]` with a dedicated test instruction (`TST`, `TEQ`) or a compare negative (`CMN`).

7. **Analyze Other Block Types:** I examine the `BlockARMLTnoov` and `BlockARMNE` cases.
    * `BlockARMLTnoov`:  Deals with the "less than, no overflow" condition. It simplifies based on flag constants and can invert the flags to change the block type to `GTnoov`.
    * `BlockARMNE`:  Handles the "not equal" condition. It optimizes based on the comparison being done (e.g., replacing `NE (CMPconst [0] (Equal cc))` with `EQ cc`). It also contains optimizations similar to `BlockARMLT` for arithmetic and logical operations.

8. **Connect to Go Functionality (Inference):** I consider where these optimizations might be useful in Go. Comparisons, especially against zero, are very common in `if` statements, loops, and other control flow constructs. The patterns suggest the code is optimizing these low-level comparisons. I come up with a simple `if` statement example to illustrate how the `LT` case might be triggered.

9. **Address Other Parts of the Request:**
    * **Code Example:**  I create a Go function with a simple `if` condition that I believe would trigger one of the optimization patterns. I include the assumed input and output, focusing on the intermediate representation (SSA).
    * **Command-line Arguments:** I realize this snippet doesn't directly handle command-line arguments. The `rewrite` pass is typically part of the compilation process, not directly controlled by user flags.
    * **Common Mistakes:**  I consider potential pitfalls. Since the transformations depend on instruction usage counts (`l.Uses == 1`), manually trying to apply these optimizations without understanding the SSA representation could lead to incorrect code.
    * **Summarize the Function:** Given it's part 15 of 16, I infer that the entire `rewriteARM.go` file is responsible for architecture-specific optimizations for ARM. This specific part focuses on optimizing conditional branches based on comparisons.

10. **Structure the Answer:** I organize the findings into clear sections as requested: functionality, inferred Go functionality, code example, command-line arguments, common mistakes, and summary. I use clear and concise language.

By following these steps, I can systematically analyze the code snippet and provide a comprehensive and accurate answer to the user's request. The key is to break down the code into smaller, understandable units and then build up a general understanding of its purpose.
这是 `go/src/cmd/compile/internal/ssa/rewriteARM.go` 文件的一部分，主要功能是 **在 SSA 中间表示阶段，针对 ARM 架构进行特定的代码重写和优化**。

由于这是第 15 部分，共 16 部分，我们可以推断出，这个文件很可能包含了大量的针对 ARM 指令的优化规则。前面的部分可能处理了更基础的指令和模式，而这部分则专注于更具体的条件分支优化。

**这部分代码的功能归纳:**

这部分代码主要关注 **优化基于比较结果的条件跳转指令**。它针对 `BlockARMLT` (小于), `BlockARMLTnoov` (小于且无溢出), 和 `BlockARMNE` (不等于) 这三种基本块类型，尝试将复杂的比较操作简化为更高效的 ARM 指令。

具体来说，它做了以下几件事：

1. **将复杂的条件比较转换为更直接的比较指令:**
   - 例如，将 `LT (CMPconst [0] l:(ADD x y))` 且 `l` 只被使用一次的情况，转换为 `LTnoov (CMN x y)`。这里 `CMPconst [0]` 后跟一个 `ADD`，可以被替换为 `CMN` (Compare Negative)，它直接比较 `x + y` 是否为负数。
   - 类似的优化也适用于 `SUB`、`AND`、`XOR` 等运算，以及它们的带移位操作的版本。

2. **利用 ARM 的条件码特性:**
   - 例如，在 `BlockARMLTnoov` 中，如果控制流依赖于一个 `FlagConstant`，它可以直接根据常量的值来决定跳转方向，避免实际的比较操作。
   - 它也能识别 `InvertFlags` 操作，并根据其结果调整跳转块的类型 (例如，将 `LTnoov (InvertFlags cmp)` 转换为 `GTnoov cmp`)。

3. **针对特定的比较模式进行优化:**
   - 例如，将 `NE (CMP x (RSBconst [0] y))` 转换为 `NE (CMN x y)`。`RSBconst [0] y` 相当于 `-y`，所以 `CMP x -y` 等价于比较 `x + y` 是否为 0，可以用 `CMN` 指令实现。

**可以推理出它是什么 go 语言功能的实现：**

这部分代码主要针对的是 **Go 语言中各种比较运算符 (`<`, `<=`, `>`, `>=`, `==`, `!=`) 在 ARM 架构上的底层实现优化**。当 Go 代码中使用这些比较运算符时，编译器会将其转换为 SSA 中间表示，而 `rewriteARM.go` 中的规则会尝试将这些通用的比较操作转换为更高效的 ARM 指令序列。

**Go 代码举例说明 (假设的输入与输出):**

```go
package main

func compare(a, b int32) bool {
	return a < b
}

func compareAndAdd(a, b int32) bool {
	if a + b < 0 {
		return true
	}
	return false
}
```

**假设的 SSA 输入 (对于 `compareAndAdd` 函数中的 `a + b < 0`):**

```
b1:
    v1 = LocalSlot(SB) // ...
    v2 = Param:a
    v3 = Param:b
    v4 = Add32 v2 v3
    v5 = Const32 <int32 0>
    v6 = LessThan v4 v5
    If v6 -> b2 b3

b2:
    // ... true branch
b3:
    // ... false branch
```

**经过这部分 `rewriteARM.go` 代码处理后，假设的 SSA 输出:**

```
b1:
    v1 = LocalSlot(SB) // ...
    v2 = Param:a
    v3 = Param:b
    v4 = Add32 v2 v3
    // 关键变化：LessThan 结合 Add 被优化为 CMN 指令
    v5 = CMN v2 v3  //  隐含比较 v2 + v3 是否为负数
    IfLTnoov v5 -> b2 b3 // 使用 LTnoov 块，基于 CMN 的结果跳转

b2:
    // ... true branch
b3:
    // ... false branch
```

**解释:**

- 原始的 SSA 中，`a + b < 0` 被分解为 `Add32` 和 `LessThan` 两个操作。
- `rewriteARM.go` 的这部分代码识别出 `LessThan` 的比较对象是常量 0，并且其比较的输入是一个 `Add32` 操作，于是将其优化为一个 `CMN` 指令。
- `CMN` 指令会设置 ARM 的条件码，后续的 `IfLTnoov` 指令可以直接根据这些条件码进行跳转，而不需要显式的比较操作。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。`rewriteARM.go` 是 `go` 编译器内部的一个模块，它的执行是由编译器驱动的，而不是通过用户直接传递命令行参数来控制。

`go` 编译器本身有很多命令行参数，例如 `-gcflags` 可以用来传递底层的编译器标志，但这通常用于更细粒度的控制，不会直接影响到 `rewrite` 阶段的特定规则。

**使用者易犯错的点:**

作为 Go 语言使用者，通常不会直接接触到 `rewriteARM.go` 这样的底层代码。这个文件是 Go 编译器开发者的工作内容。

不过，理解这种优化机制可以帮助开发者更好地理解 Go 代码在底层是如何执行的，以及为什么某些代码模式可能更高效。

**总结 (针对第 15 部分):**

`rewriteARM.go` 的第 15 部分专注于 **优化 ARM 架构下基于比较结果的条件分支指令**。它通过模式匹配和替换，将通用的比较操作和运算组合转换为更高效的 ARM 指令，例如使用 `CMN`、`TST`、`TEQ` 等指令来替代 `CMPconst [0]` 加运算的组合，以及利用 ARM 的条件码特性来简化跳转逻辑。这有助于提升 Go 程序在 ARM 架构上的执行效率。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第15部分，共16部分，请归纳一下它的功能
```

### 源代码
```go
f l.Op != OpARMADDshiftRLreg {
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ADDshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (CMNshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(AND x y)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TST x y) yes no)
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
				b.resetWithControl(BlockARMLTnoov, v0)
				return true
			}
			break
		}
		// match: (LT (CMPconst [0] l:(ANDconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TSTconst [c] x) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ANDshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TSTshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ANDshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TSTshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ANDshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TSTshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ANDshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TSTshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ANDshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TSTshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(ANDshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TSTshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(XOR x y)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TEQ x y) yes no)
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
				b.resetWithControl(BlockARMLTnoov, v0)
				return true
			}
			break
		}
		// match: (LT (CMPconst [0] l:(XORconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TEQconst [c] x) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(XORshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TEQshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(XORshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TEQshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(XORshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TEQshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(XORshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TEQshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(XORshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TEQshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
		// match: (LT (CMPconst [0] l:(XORshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (LTnoov (TEQshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMLTnoov, v0)
			return true
		}
	case BlockARMLTnoov:
		// match: (LTnoov (FlagConstant [fc]) yes no)
		// cond: fc.ltNoov()
		// result: (First yes no)
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARMGTnoov, cmp)
			return true
		}
	case BlockARMNE:
		// match: (NE (CMPconst [0] (Equal cc)) yes no)
		// result: (EQ cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMEqual {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMEQ, cc)
			return true
		}
		// match: (NE (CMPconst [0] (NotEqual cc)) yes no)
		// result: (NE cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMNotEqual {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMNE, cc)
			return true
		}
		// match: (NE (CMPconst [0] (LessThan cc)) yes no)
		// result: (LT cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMLessThan {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMLT, cc)
			return true
		}
		// match: (NE (CMPconst [0] (LessThanU cc)) yes no)
		// result: (ULT cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMLessThanU {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMULT, cc)
			return true
		}
		// match: (NE (CMPconst [0] (LessEqual cc)) yes no)
		// result: (LE cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMLessEqual {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMLE, cc)
			return true
		}
		// match: (NE (CMPconst [0] (LessEqualU cc)) yes no)
		// result: (ULE cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMLessEqualU {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMULE, cc)
			return true
		}
		// match: (NE (CMPconst [0] (GreaterThan cc)) yes no)
		// result: (GT cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMGreaterThan {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMGT, cc)
			return true
		}
		// match: (NE (CMPconst [0] (GreaterThanU cc)) yes no)
		// result: (UGT cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMGreaterThanU {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMUGT, cc)
			return true
		}
		// match: (NE (CMPconst [0] (GreaterEqual cc)) yes no)
		// result: (GE cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMGreaterEqual {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMGE, cc)
			return true
		}
		// match: (NE (CMPconst [0] (GreaterEqualU cc)) yes no)
		// result: (UGE cc yes no)
		for b.Controls[0].Op == OpARMCMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpARMGreaterEqualU {
				break
			}
			cc := v_0_0.Args[0]
			b.resetWithControl(BlockARMUGE, cc)
			return true
		}
		// match: (NE (FlagConstant [fc]) yes no)
		// cond: fc.ne()
		// result: (First yes no)
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARMNE, cmp)
			return true
		}
		// match: (NE (CMP x (RSBconst [0] y)))
		// result: (NE (CMN x y))
		for b.Controls[0].Op == OpARMCMP {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpARMRSBconst || auxIntToInt32(v_0_1.AuxInt) != 0 {
				break
			}
			y := v_0_1.Args[0]
			v0 := b.NewValue0(v_0.Pos, OpARMCMN, types.TypeFlags)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMN x (RSBconst [0] y)))
		// result: (NE (CMP x y))
		for b.Controls[0].Op == OpARMCMN {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpARMRSBconst || auxIntToInt32(v_0_1.AuxInt) != 0 {
					continue
				}
				y := v_0_1.Args[0]
				v0 := b.NewValue0(v_0.Pos, OpARMCMP, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARMNE, v0)
				return true
			}
			break
		}
		// match: (NE (CMPconst [0] l:(SUB x y)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMP x y) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(MULS x y a)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMP a (MUL <x.Type> x y)) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(SUBconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMPconst [c] x) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(SUBshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (NE (CMPshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(SUBshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (NE (CMPshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(SUBshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (NE (CMPshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(SUBshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMPshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(SUBshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMPshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(SUBshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMPshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ADD x y)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMN x y) yes no)
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
				b.resetWithControl(BlockARMNE, v0)
				return true
			}
			break
		}
		// match: (NE (CMPconst [0] l:(MULA x y a)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMN a (MUL <x.Type> x y)) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ADDconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMNconst [c] x) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ADDshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (NE (CMNshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ADDshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (NE (CMNshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ADDshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (NE (CMNshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ADDshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMNshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ADDshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMNshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ADDshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (NE (CMNshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(AND x y)) yes no)
		// cond: l.Uses==1
		// result: (NE (TST x y) yes no)
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
				b.resetWithControl(BlockARMNE, v0)
				return true
			}
			break
		}
		// match: (NE (CMPconst [0] l:(ANDconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (NE (TSTconst [c] x) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ANDshiftLL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (NE (TSTshiftLL x y [c]) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ANDshiftRL x y [c])) yes no)
		// cond: l.Uses==1
		// result: (NE (TSTshiftRL x y [c]) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ANDshiftRA x y [c])) yes no)
		// cond: l.Uses==1
		// result: (NE (TSTshiftRA x y [c]) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ANDshiftLLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (NE (TSTshiftLLreg x y z) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ANDshiftRLreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (NE (TSTshiftRLreg x y z) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(ANDshiftRAreg x y z)) yes no)
		// cond: l.Uses==1
		// result: (NE (TSTshiftRAreg x y z) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match: (NE (CMPconst [0] l:(XOR x y)) yes no)
		// cond: l.Uses==1
		// result: (NE (TEQ x y) yes no)
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
				b.resetWithControl(BlockARMNE, v0)
				return true
			}
			break
		}
		// match: (NE (CMPconst [0] l:(XORconst [c] x)) yes no)
		// cond: l.Uses==1
		// result: (NE (TEQconst [c] x) yes no)
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
			b.resetWithControl(BlockARMNE, v0)
			return true
		}
		// match:
```