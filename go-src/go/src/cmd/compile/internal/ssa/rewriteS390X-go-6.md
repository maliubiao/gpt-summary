Response: The user wants to understand the functionality of the provided Go code snippet, which is part of the `rewriteS390X.go` file in the Go compiler.

The code consists of a function that takes a `*ssa.Block` as input and attempts to rewrite it based on certain patterns. The code uses pattern matching and conditional logic to transform the control flow graph represented by the `ssa.Block`.

Here's a breakdown of the thought process:

1. **Identify the core function:** The code defines a function that operates on `ssa.Block`. This strongly suggests that the code is involved in optimizing or transforming the intermediate representation of Go code during compilation. The filename `rewriteS390X.go` indicates that these rewrites are specific to the S390X architecture.

2. **Analyze the `switch` statement:** The function uses a `switch` statement on `b.Kind`. This means it handles different types of control flow blocks. The cases are specific to the S390X architecture (e.g., `BlockS390XBRC`, `BlockS390XCGRJ`, `BlockS390XCLIJ`, etc.).

3. **Examine individual cases:**  Each `case` within the `switch` represents a specific type of block that the function attempts to rewrite. Inside each case, there are `for` loops that implement pattern matching on the block's control values (`b.Controls`) and auxiliary information (`b.Aux`, `b.AuxInt`).

4. **Understand the rewrites:** The code performs rewrites by:
    - Changing the block's kind using `b.resetWithControl()` or `b.Reset()`.
    - Modifying the block's auxiliary information (`b.Aux`, `b.AuxInt`).
    - Swapping the successors of the block using `b.swapSuccessors()`.
    - Creating new values using `b.NewValue0()`.

5. **Infer the purpose of rewrites:** The rewrites appear to be aimed at simplifying or optimizing the control flow by:
    - Combining conditional checks.
    - Specializing comparisons based on constant values.
    - Eliminating redundant operations.
    - Converting higher-level control flow constructs into lower-level machine instructions.

6. **Focus on specific examples:** To illustrate the functionality, it's helpful to pick a few representative cases and explain them in more detail. For instance, the cases involving `MOVDconst` suggest optimizations where comparisons with constants can be directly translated into branch instructions.

7. **Consider the overall context:** The filename and the nature of the rewrites strongly suggest that this code is part of the compiler's backend, responsible for generating efficient machine code for the S390X architecture.

8. **Address the specific requests:**
    - **List the functions:** Summarize the observed functionalities from the code.
    - **Infer Go language features:**  Relate the rewrites to higher-level Go constructs. For example, the `BlockIf` case clearly deals with Go's `if` statements.
    - **Provide Go code examples:** Create illustrative Go code snippets that would result in the identified rewrites.
    - **Explain code reasoning:** Describe the input and output of the rewrites in the chosen examples.
    - **Address command-line arguments:**  Since the code doesn't directly process command-line arguments, state that.
    - **Identify common mistakes:**  Think about potential pitfalls for compiler developers or those working on similar code, focusing on the complexity of the rewrites and the need for correctness.
    - **Summarize the overall function:** Provide a concise summary of the code's role.

9. **Structure the response:** Organize the information logically, starting with a general overview and then diving into specific examples and addressing the user's specific questions.
这个Go语言代码片段是Go编译器中用于S390X架构的SSA（Static Single Assignment）中间表示的重写规则的一部分。它的主要功能是**对控制流图中的基本块进行模式匹配和转换，以实现代码优化和指令选择**。

具体来说，这段代码针对不同类型的控制流块（`BlockS390XBRC`, `BlockS390XCGRJ`, `BlockS390XCLIJ`, `BlockS390XCLRJ`, `BlockS390XCRJ`, `BlockIf`）定义了一系列的重写规则。这些规则试图将一些常见的操作模式转换为更有效率的S390X指令序列。

**以下是根据代码片段推断出的部分功能，并用Go代码举例说明：**

**1. 优化比较操作和条件分支：**

代码中大量的模式匹配针对各种比较指令（例如 `CMPUconst`, `CMPWUconst`, `CMPWconst`）以及条件分支指令 (`BRC`, `CGRJ`, `CLIJ`, `CLRJ`, `CRJ`)。  它尝试将比较操作与常量进行合并或优化。

**例子 1: 将比较常量并根据结果分支转换为 `BRC` 指令**

```go
// match: (CLGRJ {c} x (MOVDconst [y]) yes no)
// cond: isU32Bit(y)
// result: (BRC {c} (CMPUconst x [int32(y)]) yes no)
```

**假设输入 SSA 代码 (伪代码):**

```
b1: // BlockS390XCGRJ
  v1 = <some value>
  v2 = MOVDconst [100]
  CLGRJ {Less} v1 v2 goto b2, b3
```

**对应的 Go 代码片段可能如下：**

```go
package main

func compare(a int64) bool {
	if a < 100 {
		return true
	} else {
		return false
	}
}
```

**输出 SSA 代码 (伪代码):**

```
b1: // BlockS390XBRC
  v1 = <some value>
  v3 = CMPUconst v1 [100]
  BRC {Less} v3 goto b2, b3
```

**推理:**  当比较一个值 `x` 和一个32位无符号常量 `y` 时，可以将其转换为使用 `CMPUconst` 指令和 `BRC` 指令，这通常是更底层的和可能更高效的表示方式。

**2. 优化与小常量的比较：**

代码中多次出现针对8位和32位常量的优化，尤其是和 `MOVDconst` 指令结合使用的情况。

**例子 2:  将与8位常量比较的 `CLRJ` 转换为 `CLIJ`**

```go
// match: (CLRJ {c} x (MOVDconst [y]) yes no)
// cond: isU8Bit(y)
// result: (CLIJ {c} x [uint8(y)] yes no)
```

**假设输入 SSA 代码 (伪代码):**

```
b1: // BlockS390XCLRJ
  v1 = <some value>
  v2 = MOVDconst [25]
  CLRJ {Equal} v1 v2 goto b2, b3
```

**对应的 Go 代码片段可能如下：**

```go
package main

func compareByte(a int64) bool {
	if a == 25 {
		return true
	} else {
		return false
	}
}
```

**输出 SSA 代码 (伪代码):**

```
b1: // BlockS390XCLIJ
  v1 = <some value>
  CLIJ {Equal} v1 [25] goto b2, b3
```

**推理:**  当比较一个值 `x` 和一个8位常量 `y` 时，可以使用更精细的 `CLIJ` 指令，该指令直接支持与立即数的比较。

**3. 处理 `If` 语句：**

```go
case BlockIf:
	// match: (If cond yes no)
	// result: (CLIJ {s390x.LessOrGreater} (MOVBZreg <typ.Bool> cond) [0] yes no)
```

**假设输入 SSA 代码 (伪代码):**

```
b1: // BlockIf
  v1 = <boolean value>
  If v1 goto b2, b3
```

**对应的 Go 代码片段可能如下：**

```go
package main

func check(ok bool) {
	if ok {
		println("true")
	} else {
		println("false")
	}
}
```

**输出 SSA 代码 (伪代码):**

```
b1: // BlockS390XCLIJ
  v2 = MOVBZreg <bool> v1
  CLIJ {LessOrGreater} v2 [0] goto b2, b3
```

**推理:**  Go 的 `if` 语句在SSA层会被转换为特定的条件分支块。这个重写规则将 `If` 块转换为 `CLIJ` 块，它首先将布尔值零扩展到一个寄存器 (`MOVBZreg`)，然后与 0 进行比较，以决定跳转方向。 `s390x.LessOrGreater` 实际上表示“不等于”，因为布尔值要么是0（false）要么是1（true）。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是在Go编译器的内部执行的，作为SSA优化过程的一部分。命令行参数会影响编译器的行为，例如选择目标架构（这里是S390X），但这些参数是在更早的编译阶段处理的。

**使用者易犯错的点:**

作为编译器开发者，或者进行底层代码生成和优化的工程师，容易犯错的点包括：

* **模式匹配的正确性:**  确保匹配的模式覆盖了所有需要优化的场景，并且不会错误地匹配不应该被转换的代码。
* **条件判断的严谨性:**  `cond` 中的条件必须完全捕捉到适用该优化的场景，避免引入逻辑错误。例如，对于常量范围的判断 (`isU8Bit`, `is32Bit` 等) 需要准确。
* **生成指令的正确性:**  转换后生成的指令序列必须在S390X架构上语义等价于原始代码。
* **Auxiliary 信息的处理:**  正确设置和使用 `Aux` 和 `AuxInt` 等辅助信息对于生成正确的机器码至关重要。例如，条件码的设置 (`c`, `c.ReverseComparison()`)。

**归纳一下它的功能 (作为第7部分):**

作为整个 `rewriteS390X.go` 文件的一部分，这段代码是**S390X架构特定SSA重写规则的最后一部分** (第7部分)。它的主要职责是**进一步优化和转换控制流图中的基本块**，着重于：

* **细化比较操作:** 将更通用的比较操作转换为更具体的、针对常量的比较指令。
* **优化小常量比较:** 特别处理与8位和32位常量的比较，利用S390X架构的特性。
* **降低控制流复杂度:** 将高级控制流结构（如 `If` 语句）转换为更底层的条件分支指令。

总体而言，`rewriteS390X.go` 文件通过一系列的重写规则，将SSA中间表示逐步转换为更接近目标机器代码的形式，提高生成代码的效率和性能。这段代码片段作为最后一部分，可能处理的是一些更细致的优化或指令选择的收尾工作。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第7部分，共7部分，请归纳一下它的功能

"""
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

"""




```