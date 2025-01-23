Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first crucial step is recognizing the file path: `go/src/cmd/compile/internal/ssa/rewriteS390X.go`. This immediately tells us we're dealing with the Go compiler, specifically the SSA (Static Single Assignment) intermediate representation, and architecture-specific optimizations for S390X. The "rewrite" part suggests this code modifies the SSA graph.

2. **Identify the Core Function:** The provided code is a single Go function, likely named something like `rewriteBlockS390X` (though the name isn't explicitly given in the snippet). The `b *Block` argument confirms it operates on SSA basic blocks.

3. **Analyze the Structure:**  The function uses a `switch b.Kind` statement. This indicates it's handling different types of control flow blocks in the SSA graph. The cases are specific to the S390X architecture: `BlockS390XBRC`, `BlockS390XCGRJ`, `BlockS390XCLGRJ`, `BlockS390XCLIJ`, `BlockS390XCLRJ`, `BlockS390XCRJ`, and `BlockIf`.

4. **Deconstruct Each Case:**  For each `case`, examine the "match" and "cond" comments. These describe patterns in the SSA graph that the code is looking for. The "result" comment shows how the block is transformed if the match and condition are met.

   * **Example (BlockS390XBRC):**
      * `match: (BRC {c} (CMPconst x [y]) yes no)`  - Looks for a `BRC` block with a `CMPconst` instruction as its control.
      * `cond: is8Bit(y)` - Checks if the constant value `y` fits within an 8-bit range.
      * `result: (CIJ {c} x [int8(y)] yes no)` - Transforms it into a `CIJ` block, using an immediate 8-bit comparison.

5. **Identify the Transformation Goal:**  Across the various cases, a common theme emerges: **optimization**. The code is trying to replace more general comparison and branching instructions with more efficient, architecture-specific instructions, often involving immediate values. It also handles simplifications where the comparison result is known.

6. **Infer Go Feature Implementation:** Based on the optimizations, we can infer that this code is involved in the **lowering and optimization of control flow structures** in Go for the S390X architecture. This includes `if` statements, comparisons, and potentially `for` loops (which often compile down to conditional branches).

7. **Construct Go Code Examples:**  For each identified optimization pattern, create a simple Go code example that *could* lead to the SSA pattern being matched. This requires understanding how basic Go constructs translate into lower-level operations.

   * **Example (BRC case with CMPconst):** An `if` statement comparing a variable to a small constant (`if x == 5`).

8. **Infer Input and Output (for Code Reasoning):** For each transformation, consider the *input* SSA block structure (as described by "match") and the *output* SSA block structure (as described by "result"). This clarifies the transformation being applied.

9. **Analyze Command Line Arguments (if applicable):** In this specific snippet, there's no explicit handling of command-line arguments. The transformations are based on the structure of the SSA graph itself.

10. **Identify Potential Pitfalls:** Think about situations where a programmer might write Go code that could *seem* straightforward but might lead to less optimal S390X assembly if this optimization didn't exist. For instance, comparing against a constant that could be an immediate value.

11. **Synthesize the Overall Function:**  Combine the analysis of individual cases to describe the overarching purpose of the `rewriteS390X.go` file and this specific function within it. Emphasize the optimization aspect and the target architecture.

12. **Address the "Part 13 of 13" Aspect:** The fact that this is the last part suggests summarizing the *entire* file's likely purpose based on the observed transformations. Since these transformations are about optimizing branches and comparisons, it's reasonable to infer that the entire file focuses on low-level code generation and optimization for S390X.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This looks complicated."  **Correction:** Break it down case by case.
* **Initial thought:** "What are `OpS390XMOVDconst` and `BlockS390XBRC`?" **Correction:** Recognize these are architecture-specific SSA opcodes and block types, indicating low-level optimization.
* **Initial thought:** "How do I know what Go code generates these SSA patterns?" **Correction:** Use general knowledge of how compilers translate high-level code, and focus on control flow and comparisons.
* **Initial thought:** "Are there command-line flags related to this?" **Correction:**  The code itself doesn't show any direct interaction with command-line flags, so focus on the SSA graph transformations.

By following these steps, we can systematically analyze the code snippet and arrive at a comprehensive understanding of its functionality and purpose within the Go compiler.
这是 `go/src/cmd/compile/internal/ssa/rewriteS390X.go` 文件的一部分，它负责 **S390X 架构下的 SSA（Static Single Assignment）中间表示的重写规则**。简单来说，它的功能是 **优化针对 S390X 架构的代码生成**。

这个特定部分（第 13 部分，共 13 部分）主要关注 **基本块 (Block) 的重写规则**，特别是针对不同类型的 S390X 条件跳转指令 (`BlockS390XBRC`, `BlockS390XCGRJ`, `BlockS390XCLGRJ`, `BlockS390XCLIJ`, `BlockS390XCLRJ`, `BlockS390XCRJ`) 和通用的 `BlockIf`。

**具体功能归纳:**

这个代码片段的核心目标是通过模式匹配和条件判断，将 SSA 图中的某些基本块结构替换为更优化的 S390X 指令序列。  它针对以下场景进行了优化：

1. **简化比较操作:**  将通用的比较和跳转操作替换为更具体的、更高效的 S390X 指令，例如将与常数的比较转换为使用立即数的比较指令 (例如 `CMPconst` 到 `CIJ`, `CMPUconst` 到 `CLIJ`, `CMPWconst` 到 `BRC`)。
2. **利用 S390X 的特性:**  利用 S390X 架构提供的特定指令和寻址模式，例如使用 `LOCGR` 进行比较并直接跳转。
3. **常量折叠和已知结果的优化:**  当比较的对象是常量，并且比较结果在编译时可以确定时，直接将条件跳转块替换为直接跳转到 `yes` 或 `no` 分支的块 (`BlockFirst`)。
4. **处理不同大小的立即数:**  针对不同大小的立即数（8位、32位），选择合适的比较指令。
5. **处理布尔类型的 `if` 语句:** 将通用的 `if` 语句转换为使用 S390X 的比较和条件跳转指令。

**Go 语言功能实现推理和代码示例:**

这段代码实现的底层功能是为了优化 Go 语言中的以下常见场景：

* **比较操作符 (==, !=, <, >, <=, >=):**  例如 `if x == 10`, `if y < 100`.
* **与常量比较的 `if` 语句:** 这是优化的重点，因为可以直接生成更高效的立即数比较指令。
* **布尔类型的条件判断:** 例如 `if flag`.

**代码示例：**

假设有以下 Go 代码：

```go
package main

func main() {
	x := 10
	if x == 5 {
		println("x is 5")
	} else {
		println("x is not 5")
	}
}
```

**假设的 SSA 输入 (简化表示，可能不完全一致):**

在编译过程中，`if x == 5` 可能会被转换为类似以下的 SSA 结构：

```
b1:
  v1 = ConstInt 10
  v2 = ConstInt 5
  v3 = EqInt v1 v2  // 比较 x 和 5
  If v3 -> b2, b3  // 如果 v3 为真，跳转到 b2，否则到 b3
b2:
  // ... "x is 5" 的代码 ...
  Goto b4
b3:
  // ... "x is not 5" 的代码 ...
  Goto b4
b4:
  // ... 后续代码 ...
```

**`rewriteS390X.go` 中对应的优化 (以 `BlockS390XBRC` 为例):**

在 `rewriteS390X.go` 中，对于 `BlockIf`，代码会将其转换为 `BlockS390XCLIJ`。  而对于像 `x == 5` 这样的比较，如果 `x` 是一个寄存器中的值，且常量是 8 位能表示的，则可能会匹配到 `BlockS390XBRC` 的某个 case：

```go
	case BlockS390XBRC:
		// match: (BRC {c} (CMPconst x [y]) yes no)
		// cond: is8Bit(y)
		// result: (CIJ {c} x [ int8(y)] yes no)
		for b.Controls[1].Op == OpS390XCMPconst {
			v_1 := b.Controls[1]
			x := b.Controls[0]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(is8Bit(y)) {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
```

**假设的 SSA 输出 (优化后):**

这个规则会将 `If v3 -> b2, b3` 这样的结构，如果 `v3` 是一个比较操作，并且常量 `5` 可以用 8 位表示，转换为使用 S390X 的 `CIJ` (Compare Immediate and Jump) 指令：

```
b1:
  v1 = <寄存器中 x 的值>
  CIJ {s390x.Equal} v1 [5] -> b2, b3  // 使用 CIJ 指令直接比较并跳转
b2:
  // ...
b3:
  // ...
```

**代码推理中的假设输入与输出:**

**假设输入 (对于 `BlockS390XBRC` 的第一个 case):**

* `b.Kind = BlockS390XBRC`
* `b.Controls[0]` 代表比较结果，假设是一个寄存器中的值。
* `b.Controls[1].Op = OpS390XCMPconst`，表示与常量比较。
* `auxIntToInt64(b.Controls[1].AuxInt) = 5` (比较的常量是 5)。
* `is8Bit(5)` 为真。
* `b.Aux` 包含比较的条件 (例如 `s390x.Equal`)。

**假设输出:**

* `b.Kind` 变为 `BlockS390XCIJ`。
* `b.Control` 变为寄存器中 `x` 的值。
* `b.AuxInt` 变为 `5`。
* `b.Aux` 保持比较条件。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是在 Go 编译器的内部执行的，作为 SSA 优化的一部分。Go 编译器的命令行参数会影响整个编译过程，间接地可能导致不同的 SSA 图，从而影响这里的重写规则是否被应用。例如，优化级别 `-O0`, `-O1`, `-O2` 可能会影响 SSA 的生成和优化过程。

**使用者易犯错的点:**

普通 Go 语言开发者通常不会直接接触到这些底层的 SSA 重写规则。这些是编译器开发者需要关注的。因此，对于 Go 语言使用者来说，没有直接易犯错的点。

**总结 `rewriteS390X.go` 的功能:**

`go/src/cmd/compile/internal/ssa/rewriteS390X.go` 文件的主要功能是 **定义了一系列规则，用于在 S390X 架构下优化 Go 程序的中间表示 (SSA)。** 它通过模式匹配和条件判断，将 SSA 图中的特定结构替换为更高效的 S390X 机器指令序列。  这个文件的最终目标是 **生成更快速、更精简的 S390X 汇编代码**。

这个特定的第 13 部分专注于 **优化控制流基本块**，特别是针对各种条件跳转指令和 `if` 语句的实现，通过利用 S390X 架构的特性，例如立即数比较指令，来提升性能。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第13部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
) y yes no)
		// cond: !isU8Bit(x) && isU32Bit(x)
		// result: (BRC {c.ReverseComparison()} (CMPUconst y [int32(x)]) yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(!isU8Bit(x) && isU32Bit(x)) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpS390XCMPUconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(x))
			v0.AddArg(y)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CLGRJ {c} x y yes no)
		// cond: x == y && c&s390x.Equal != 0
		// result: (First yes no)
		for {
			x := b.Controls[0]
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(x == y && c&s390x.Equal != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLGRJ {c} x y yes no)
		// cond: x == y && c&s390x.Equal == 0
		// result: (First no yes)
		for {
			x := b.Controls[0]
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(x == y && c&s390x.Equal == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockS390XCLIJ:
		// match: (CLIJ {s390x.LessOrGreater} (LOCGR {d} (MOVDconst [0]) (MOVDconst [x]) cmp) [0] yes no)
		// cond: int32(x) != 0
		// result: (BRC {d} cmp yes no)
		for b.Controls[0].Op == OpS390XLOCGR {
			v_0 := b.Controls[0]
			d := auxToS390xCCMask(v_0.Aux)
			cmp := v_0.Args[2]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0.AuxInt) != 0 {
				break
			}
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpS390XMOVDconst {
				break
			}
			x := auxIntToInt64(v_0_1.AuxInt)
			if auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater || !(int32(x) != 0) {
				break
			}
			b.resetWithControl(BlockS390XBRC, cmp)
			b.Aux = s390xCCMaskToAux(d)
			return true
		}
		// match: (CLIJ {c} (MOVWreg x) [y] yes no)
		// result: (CLIJ {c} x [y] yes no)
		for b.Controls[0].Op == OpS390XMOVWreg {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(y)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CLIJ {c} (MOVWZreg x) [y] yes no)
		// result: (CLIJ {c} x [y] yes no)
		for b.Controls[0].Op == OpS390XMOVWZreg {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(y)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CLIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal != 0 && uint32(x) == uint32(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal != 0 && uint32(x) == uint32(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less != 0 && uint32(x) < uint32(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less != 0 && uint32(x) < uint32(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater != 0 && uint32(x) > uint32(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater != 0 && uint32(x) > uint32(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal == 0 && uint32(x) == uint32(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal == 0 && uint32(x) == uint32(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less == 0 && uint32(x) < uint32(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less == 0 && uint32(x) < uint32(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater == 0 && uint32(x) > uint32(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater == 0 && uint32(x) > uint32(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLIJ {s390x.GreaterOrEqual} _ [0] yes no)
		// result: (First yes no)
		for {
			if auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLIJ {s390x.Less} _ [0] yes no)
		// result: (First no yes)
		for {
			if auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockS390XCLRJ:
		// match: (CLRJ {c} x (MOVDconst [y]) yes no)
		// cond: isU8Bit(y)
		// result: (CLIJ {c} x [uint8(y)] yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(isU8Bit(y)) {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CLRJ {c} (MOVDconst [x]) y yes no)
		// cond: isU8Bit(x)
		// result: (CLIJ {c.ReverseComparison()} y [uint8(x)] yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(isU8Bit(x)) {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, y)
			b.AuxInt = uint8ToAuxInt(uint8(x))
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CLRJ {c} x (MOVDconst [y]) yes no)
		// cond: !isU8Bit(y) && isU32Bit(y)
		// result: (BRC {c} (CMPWUconst x [int32(y)]) yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(!isU8Bit(y) && isU32Bit(y)) {
				break
			}
			v0 := b.NewValue0(x.Pos, OpS390XCMPWUconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(y))
			v0.AddArg(x)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CLRJ {c} (MOVDconst [x]) y yes no)
		// cond: !isU8Bit(x) && isU32Bit(x)
		// result: (BRC {c.ReverseComparison()} (CMPWUconst y [int32(x)]) yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(!isU8Bit(x) && isU32Bit(x)) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpS390XCMPWUconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(x))
			v0.AddArg(y)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CLRJ {c} x y yes no)
		// cond: x == y && c&s390x.Equal != 0
		// result: (First yes no)
		for {
			x := b.Controls[0]
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(x == y && c&s390x.Equal != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLRJ {c} x y yes no)
		// cond: x == y && c&s390x.Equal == 0
		// result: (First no yes)
		for {
			x := b.Controls[0]
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(x == y && c&s390x.Equal == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockS390XCRJ:
		// match: (CRJ {c} x (MOVDconst [y]) yes no)
		// cond: is8Bit(y)
		// result: (CIJ {c} x [ int8(y)] yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(is8Bit(y)) {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CRJ {c} (MOVDconst [x]) y yes no)
		// cond: is8Bit(x)
		// result: (CIJ {c.ReverseComparison()} y [ int8(x)] yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(is8Bit(x)) {
				break
			}
			b.resetWithControl(BlockS390XCIJ, y)
			b.AuxInt = int8ToAuxInt(int8(x))
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CRJ {c} x (MOVDconst [y]) yes no)
		// cond: !is8Bit(y) && is32Bit(y)
		// result: (BRC {c} (CMPWconst x [int32(y)]) yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(!is8Bit(y) && is32Bit(y)) {
				break
			}
			v0 := b.NewValue0(x.Pos, OpS390XCMPWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(y))
			v0.AddArg(x)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CRJ {c} (MOVDconst [x]) y yes no)
		// cond: !is8Bit(x) && is32Bit(x)
		// result: (BRC {c.ReverseComparison()} (CMPWconst y [int32(x)]) yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(!is8Bit(x) && is32Bit(x)) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpS390XCMPWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(x))
			v0.AddArg(y)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CRJ {c} x y yes no)
		// cond: x == y && c&s390x.Equal != 0
		// result: (First yes no)
		for {
			x := b.Controls[0]
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(x == y && c&s390x.Equal != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CRJ {c} x y yes no)
		// cond: x == y && c&s390x.Equal == 0
		// result: (First no yes)
		for {
			x := b.Controls[0]
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(x == y && c&s390x.Equal == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockIf:
		// match: (If cond yes no)
		// result: (CLIJ {s390x.LessOrGreater} (MOVBZreg <typ.Bool> cond) [0] yes no)
		for {
			cond := b.Controls[0]
			v0 := b.NewValue0(cond.Pos, OpS390XMOVBZreg, typ.Bool)
			v0.AddArg(cond)
			b.resetWithControl(BlockS390XCLIJ, v0)
			b.AuxInt = uint8ToAuxInt(0)
			b.Aux = s390xCCMaskToAux(s390x.LessOrGreater)
			return true
		}
	}
	return false
}
```