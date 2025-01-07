Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first and most important step is recognizing the file path: `go/src/cmd/compile/internal/ssa/rewriteS390X.go`. This immediately tells us we're dealing with compiler internals, specifically the SSA (Static Single Assignment) form and target architecture S390X. The "rewrite" part suggests that this code is involved in optimizing or transforming the SSA representation. The fact that this is part 12 of 13 reinforces the idea of a sequential process.

2. **Identify the Core Functionality:**  The code is structured as a large `switch b.Kind` statement. Each `case` corresponds to a specific block type (`BlockS390XBRC`, `BlockS390XCGIJ`, etc.). Within each case, there are multiple "match" and "result" comments. This pattern strongly indicates a rule-based rewriting system. The code is trying to match specific patterns of operations within a basic block and transform them into more efficient equivalents.

3. **Analyze the "match" and "result" Structure:**  Each "match" line describes a pattern to look for within the current basic block (`b`). This pattern usually involves the control operation of the block (`b.Controls[0]` or `b.Controls[1]`) and potentially its arguments and auxiliary information (`Aux`, `AuxInt`). The "result" line shows how the block is transformed when a match is found. This often involves changing the block's kind (`b.resetWithControl`), updating its auxiliary information, or even simplifying the block entirely (`b.Reset(BlockFirst)`).

4. **Focus on the Transformations:**  The core of the functionality lies in understanding *what* transformations are being performed. Here are some common themes observed:

    * **Simplifying Comparisons with Constants:**  Many transformations involve comparing a register with a constant. For example, converting `BRC {c} (CMPconst x [y])` to `CLIJ {c} x [uint8(y)]` when the constant `y` fits within an 8-bit unsigned integer. This suggests an optimization where smaller immediate values can be used for efficiency.
    * **Handling Conditional Branches:** The code extensively manipulates conditional branch instructions (`BRC`, `CGIJ`, `CLGIJ`, etc.). It aims to optimize these branches based on the preceding comparison results. The `Aux` field plays a crucial role here, storing the condition code.
    * **Exploiting Flag Registers:**  The code checks for specific flag states (`FlagEQ`, `FlagLT`, `FlagGT`, `FlagOV`) and simplifies the control flow accordingly. If a branch condition is always true (e.g., branching if equal when the equal flag is set), the block can be directly transitioned to the target.
    * **Using Carry/Borrow Flags:** The transformations related to `ADDE` and `SUBE` show how the carry and borrow flags are used in multi-precision arithmetic or in specific conditional scenarios.
    * **Reversing Comparisons:** The `ReverseComparison()` function suggests that the code can sometimes optimize by inverting the comparison and swapping the target blocks.

5. **Infer Go Language Features:** Based on the transformations, we can infer some underlying Go language features or compiler optimizations being addressed:

    * **Integer Comparisons:** The transformations dealing with `CMPconst`, `CMPUconst`, and comparisons with `MOVDconst` directly relate to how Go handles integer comparisons (signed and unsigned).
    * **Boolean Logic and Control Flow:** The simplification of `BRC` blocks based on flag states is fundamental to implementing Go's `if` statements, `for` loops, and other control flow constructs.
    * **Multi-Word Arithmetic:** The `ADDE` and `SUBE` operations, along with the handling of carry and borrow flags, point to the compiler's ability to handle arithmetic operations on integers larger than the native word size.

6. **Construct Illustrative Examples:** To solidify understanding, creating simple Go code examples that would trigger these transformations is crucial. The key is to write code that results in the specific SSA patterns being matched. For instance, a simple comparison with a small constant would trigger the `CLIJ` optimization.

7. **Consider Command-Line Arguments (if applicable):**  In this specific snippet, there's no direct handling of command-line arguments. However, it's important to remember that compiler optimizations are often influenced by flags passed to the Go compiler (e.g., optimization level, target architecture).

8. **Identify Potential Pitfalls:**  While not explicitly present in this snippet, general compiler optimization pitfalls include:
    * **Over-optimization:** Aggressive optimizations can sometimes introduce subtle bugs if not handled carefully.
    * **Platform-specific issues:** Optimizations for one architecture might not be valid for another.
    * **Debugging complexity:** Heavily optimized code can be harder to debug.

9. **Synthesize the Summary:** Finally, combine the observations into a concise summary that captures the main purpose of the code. Highlight the rule-based nature of the transformations and the goal of generating more efficient S390X assembly code. Emphasize that this section specifically deals with block-level rewrites, focusing on conditional branches and comparisons.

By following these steps, we can effectively analyze and understand the functionality of this Go compiler code snippet. The key is to move from the concrete code to the abstract concepts of compiler optimization and target architecture specifics.
这段代码是Go编译器中用于S390X架构的SSA（静态单赋值）重写规则的一部分。它主要关注**控制流块**的优化，特别是针对条件分支指令 (`BRC`, `CGIJ`, `CLGIJ`, `CGRJ`, `CLGRJ`, `CIJ`) 的优化。

**核心功能归纳:**

这个代码片段定义了一系列的重写规则，这些规则旨在简化和优化S390X架构下的条件分支块。它通过匹配特定的操作码序列和条件，将复杂的条件分支操作替换为更简单、更高效的指令序列。

**具体功能拆解:**

1. **简化基于比较结果的条件分支:**
   - 当条件分支 (`BRC`) 的条件是由比较指令 (`CMP`, `CMPW`, `CMPU`, `CMPWU`) 产生时，并且比较的是一个能用小立即数表示的常量，那么可以将 `BRC` 替换为更精细的条件跳转指令，如 `CLIJ` (比较逻辑立即数跳转), `CGIJ` (比较生成立即数跳转) 等。这样做可以减少指令的执行周期和代码大小。
   - **例子:** 将 `BRC {c} (CMPconst x [y]) yes no` 替换为 `CLIJ {c} x [uint8(y)] yes no`，前提是 `y` 可以用 `uint8` 表示。这意味着如果需要根据一个变量和一个小的无符号常量进行比较跳转，编译器会尝试使用更直接的 `CLIJ` 指令。

2. **利用标志寄存器进行优化:**
   - 当条件分支 (`BRC`) 的条件是直接基于标志寄存器 (`FlagEQ`, `FlagLT`, `FlagGT`, `FlagOV`) 的状态时，如果分支条件与 `BRC` 的掩码匹配，则可以直接跳转到目标块，无需进行额外的比较。
   - **例子:** 如果 `BRC` 的条件是 "相等" (`c&s390x.Equal != 0`) 并且控制指令是 `FlagEQ`，那么可以无条件跳转到 `yes` 块。

3. **常量比较的优化:**
   - 对于 `CGIJ`, `CLGIJ`, `CIJ` 这些已经针对立即数比较的跳转指令，如果控制指令是加载常量 (`MOVDconst`)，可以直接根据常量的值和跳转条件，决定跳转到 `yes` 块还是 `no` 块，甚至可以直接变成无条件跳转到其中一个块。
   - **例子:** 如果 `CGIJ {c} (MOVDconst [x]) [y] yes no` 并且条件是相等 (`c&s390x.Equal != 0`) 并且常量 `x` 和 `y` 相等，那么可以直接跳转到 `yes` 块。

4. **处理进位和借位标志:**
   - 对于涉及到加法 (`ADDE`) 和减法 (`SUBE`) 并产生进位/借位的操作，可以通过 `CGIJ` 和 `CLGIJ` 结合 `Select0` 操作来判断进位/借位标志，并将其转化为直接基于进位/借位的条件分支 (`BRC`)。

5. **比较指令的转换:**
   - 将通用的比较跳转指令 (`CGRJ`, `CLGRJ`) 在某些情况下转换为更具体的立即数比较跳转指令 (`CGIJ`, `CLGIJ`)，前提是比较的其中一个操作数是立即数，且该立即数可以用较小的位数表示。

6. **反转比较条件:**
   - 在某些比较跳转指令中 (`CGRJ`, `CLGRJ`)，如果交换比较的两个操作数，可以同时反转比较条件，以便进行进一步的优化。

**推断 Go 语言功能的实现 (结合假设输入与输出):**

这段代码主要优化的是 Go 语言中的比较操作和条件语句的底层实现。例如，`if` 语句的编译结果就可能涉及到这些条件分支指令。

**假设的 Go 代码:**

```go
package main

func compare(a int, b uint8) bool {
	if a > int(b) {
		return true
	}
	return false
}

func compareUint(a uint64, b uint8) bool {
	if a < uint64(b) {
		return true
	}
	return false
}
```

**假设的 SSA 输入 (针对 `compare` 函数中的 `if a > int(b)`):**

```
b1:
  v1 = ArgInt a
  v2 = ArgUint8 b
  v3 = ConvI8toI  v2
  v4 = CMP  v1 v3
  If v4 goto b2 else b3

b2: // yes branch
  ...
b3: // no branch
  ...
```

**应用代码片段中的规则后可能的 SSA 输出 (简化版):**

如果 `b` 的值在编译时已知或者可以推断出来是一个小的常量，那么 `CMP v1 v3` 可能会被优化掉，直接使用更高效的比较和跳转指令。例如，如果 `b` 是常量 `10`，并且 `>` 对应 `s390x.Greater`，那么可能会应用类似以下的转换：

```
b1:
  v1 = ArgInt a
  // v2 = ArgUint8 b  // 假设 b 的值是常量 10
  // v3 = ConvI8toI  v2
  // v4 = CMPconst v1 [10] // 优化后的比较
  CLGIJ {Greater} v1 [10] goto b2 else b3 // 使用 CLGIJ 进行比较和跳转

b2: // yes branch
  ...
b3: // no branch
  ...
```

**假设的 SSA 输入 (针对 `compareUint` 函数中的 `if a < uint64(b)`):**

```
b4:
  v5 = ArgUint64 a
  v6 = ArgUint8 b
  v7 = ConvU8toU64 v6
  v8 = CMPU v5 v7
  If v8 goto b5 else b6

b5: // yes branch
  ...
b6: // no branch
  ...
```

**应用代码片段中的规则后可能的 SSA 输出 (简化版):**

类似地，如果 `b` 是一个小常量，`CMPU` 可能会被优化为 `CLGIJ`：

```
b4:
  v5 = ArgUint64 a
  // v6 = ArgUint8 b // 假设 b 的值是常量 5
  // v7 = ConvU8toU64 v6
  // v8 = CMPUconst v5 [5] // 优化后的比较
  CLGIJ {Less} v5 [5] goto b5 else b6 // 使用 CLGIJ 进行比较和跳转

b5: // yes branch
  ...
b6: // no branch
  ...
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。但是，Go 编译器的命令行参数，如 `-gcflags` 等，会影响到 SSA 的生成和优化过程。例如，优化级别越高，这些重写规则被应用的程度可能就越高。

**使用者易犯错的点:**

作为编译器开发者，理解这些规则以及它们适用的场景至关重要。对于普通的 Go 语言使用者来说，他们通常不需要直接关心这些底层的优化细节。编译器会自动应用这些规则来生成高效的代码。

**第12部分的功能归纳:**

这是 `rewriteS390X.go` 文件的第 12 部分，专注于**优化 S390X 架构下控制流块中的条件分支指令**。它定义了一系列匹配和替换规则，可以将复杂的条件分支操作转化为更简单、更高效的指令序列，从而提高生成代码的性能。这部分主要处理了各种基于比较结果和标志寄存器的条件跳转，以及针对常量比较的特殊优化。它是整个 SSA 重写过程中的一个重要环节，旨在生成更优化的机器码。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第12部分，共13部分，请归纳一下它的功能

"""
Equal || c == s390x.LessOrGreater)) {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (BRC {c} (CMPWconst x [y]) yes no)
		// cond: y == int32(uint8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)
		// result: (CLIJ {c} x [uint8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPWconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(uint8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)) {
				break
			}
			b.resetWithControl(BlockS390XCLIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (BRC {c} (CMPUconst x [y]) yes no)
		// cond: y == int32( int8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)
		// result: (CGIJ {c} x [ int8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPUconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(int8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)) {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (BRC {c} (CMPWUconst x [y]) yes no)
		// cond: y == int32( int8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)
		// result: (CIJ {c} x [ int8(y)] yes no)
		for b.Controls[0].Op == OpS390XCMPWUconst {
			v_0 := b.Controls[0]
			y := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			if !(y == int32(int8(y)) && (c == s390x.Equal || c == s390x.LessOrGreater)) {
				break
			}
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (BRC {c} (InvertFlags cmp) yes no)
		// result: (BRC {c.ReverseComparison()} cmp yes no)
		for b.Controls[0].Op == OpS390XInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl(BlockS390XBRC, cmp)
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (BRC {c} (FlagEQ) yes no)
		// cond: c&s390x.Equal != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XFlagEQ {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (BRC {c} (FlagLT) yes no)
		// cond: c&s390x.Less != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XFlagLT {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (BRC {c} (FlagGT) yes no)
		// cond: c&s390x.Greater != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XFlagGT {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (BRC {c} (FlagOV) yes no)
		// cond: c&s390x.Unordered != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XFlagOV {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (BRC {c} (FlagEQ) yes no)
		// cond: c&s390x.Equal == 0
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XFlagEQ {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (BRC {c} (FlagLT) yes no)
		// cond: c&s390x.Less == 0
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XFlagLT {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (BRC {c} (FlagGT) yes no)
		// cond: c&s390x.Greater == 0
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XFlagGT {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (BRC {c} (FlagOV) yes no)
		// cond: c&s390x.Unordered == 0
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XFlagOV {
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Unordered == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockS390XCGIJ:
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal != 0 && int64(x) == int64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal != 0 && int64(x) == int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less != 0 && int64(x) < int64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less != 0 && int64(x) < int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater != 0 && int64(x) > int64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater != 0 && int64(x) > int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal == 0 && int64(x) == int64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal == 0 && int64(x) == int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less == 0 && int64(x) < int64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less == 0 && int64(x) < int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater == 0 && int64(x) > int64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater == 0 && int64(x) > int64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CGIJ {s390x.Equal} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.NoCarry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.NoCarry)
			return true
		}
		// match: (CGIJ {s390x.Equal} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [1])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CGIJ {s390x.LessOrGreater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CGIJ {s390x.LessOrGreater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [1])
		// result: (BRC {s390x.NoCarry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.NoCarry)
			return true
		}
		// match: (CGIJ {s390x.Greater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CGIJ {s390x.Equal} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.NoBorrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.NoBorrow)
			return true
		}
		// match: (CGIJ {s390x.Equal} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [1])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
		// match: (CGIJ {s390x.LessOrGreater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
		// match: (CGIJ {s390x.LessOrGreater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [1])
		// result: (BRC {s390x.NoBorrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.NoBorrow)
			return true
		}
		// match: (CGIJ {s390x.Greater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToInt8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
	case BlockS390XCGRJ:
		// match: (CGRJ {c} x (MOVDconst [y]) yes no)
		// cond: is8Bit(y)
		// result: (CGIJ {c} x [ int8(y)] yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(is8Bit(y)) {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, x)
			b.AuxInt = int8ToAuxInt(int8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CGRJ {c} (MOVDconst [x]) y yes no)
		// cond: is8Bit(x)
		// result: (CGIJ {c.ReverseComparison()} y [ int8(x)] yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(is8Bit(x)) {
				break
			}
			b.resetWithControl(BlockS390XCGIJ, y)
			b.AuxInt = int8ToAuxInt(int8(x))
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CGRJ {c} x (MOVDconst [y]) yes no)
		// cond: !is8Bit(y) && is32Bit(y)
		// result: (BRC {c} (CMPconst x [int32(y)]) yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(!is8Bit(y) && is32Bit(y)) {
				break
			}
			v0 := b.NewValue0(x.Pos, OpS390XCMPconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(y))
			v0.AddArg(x)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CGRJ {c} (MOVDconst [x]) y yes no)
		// cond: !is8Bit(x) && is32Bit(x)
		// result: (BRC {c.ReverseComparison()} (CMPconst y [int32(x)]) yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(!is8Bit(x) && is32Bit(x)) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpS390XCMPconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(x))
			v0.AddArg(y)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CGRJ {c} x y yes no)
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
		// match: (CGRJ {c} x y yes no)
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
	case BlockS390XCIJ:
		// match: (CIJ {c} (MOVWreg x) [y] yes no)
		// result: (CIJ {c} x [y] yes no)
		for b.Controls[0].Op == OpS390XMOVWreg {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(y)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CIJ {c} (MOVWZreg x) [y] yes no)
		// result: (CIJ {c} x [y] yes no)
		for b.Controls[0].Op == OpS390XMOVWZreg {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			b.resetWithControl(BlockS390XCIJ, x)
			b.AuxInt = int8ToAuxInt(y)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal != 0 && int32(x) == int32(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal != 0 && int32(x) == int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less != 0 && int32(x) < int32(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less != 0 && int32(x) < int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater != 0 && int32(x) > int32(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater != 0 && int32(x) > int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal == 0 && int32(x) == int32(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal == 0 && int32(x) == int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less == 0 && int32(x) < int32(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less == 0 && int32(x) < int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater == 0 && int32(x) > int32(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToInt8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater == 0 && int32(x) > int32(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockS390XCLGIJ:
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal != 0 && uint64(x) == uint64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal != 0 && uint64(x) == uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less != 0 && uint64(x) < uint64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less != 0 && uint64(x) < uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater != 0 && uint64(x) > uint64(y)
		// result: (First yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater != 0 && uint64(x) > uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Equal == 0 && uint64(x) == uint64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Equal == 0 && uint64(x) == uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Less == 0 && uint64(x) < uint64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Less == 0 && uint64(x) < uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLGIJ {c} (MOVDconst [x]) [y] yes no)
		// cond: c&s390x.Greater == 0 && uint64(x) > uint64(y)
		// result: (First no yes)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := auxIntToUint8(b.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(c&s390x.Greater == 0 && uint64(x) > uint64(y)) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLGIJ {s390x.GreaterOrEqual} _ [0] yes no)
		// result: (First yes no)
		for {
			if auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.GreaterOrEqual {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (CLGIJ {s390x.Less} _ [0] yes no)
		// result: (First no yes)
		for {
			if auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Less {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (CLGIJ {s390x.Equal} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.NoCarry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.NoCarry)
			return true
		}
		// match: (CLGIJ {s390x.Equal} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [1])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CLGIJ {s390x.LessOrGreater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CLGIJ {s390x.LessOrGreater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [1])
		// result: (BRC {s390x.NoCarry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.NoCarry)
			return true
		}
		// match: (CLGIJ {s390x.Greater} (Select0 (ADDE (MOVDconst [0]) (MOVDconst [0]) carry)) [0])
		// result: (BRC {s390x.Carry} carry)
		for b.Controls[0].Op == OpSelect0 {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpS390XADDE {
				break
			}
			carry := v_0_0.Args[2]
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XBRC, carry)
			b.Aux = s390xCCMaskToAux(s390x.Carry)
			return true
		}
		// match: (CLGIJ {s390x.Equal} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.NoBorrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.NoBorrow)
			return true
		}
		// match: (CLGIJ {s390x.Equal} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [1])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.Equal {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
		// match: (CLGIJ {s390x.LessOrGreater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
		// match: (CLGIJ {s390x.LessOrGreater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [1])
		// result: (BRC {s390x.NoBorrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 1 || auxToS390xCCMask(b.Aux) != s390x.LessOrGreater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.NoBorrow)
			return true
		}
		// match: (CLGIJ {s390x.Greater} (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) borrow))) [0])
		// result: (BRC {s390x.Borrow} borrow)
		for b.Controls[0].Op == OpS390XNEG {
			v_0 := b.Controls[0]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpSelect0 {
				break
			}
			v_0_0_0 := v_0_0.Args[0]
			if v_0_0_0.Op != OpS390XSUBE {
				break
			}
			borrow := v_0_0_0.Args[2]
			v_0_0_0_0 := v_0_0_0.Args[0]
			if v_0_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_0.AuxInt) != 0 {
				break
			}
			v_0_0_0_1 := v_0_0_0.Args[1]
			if v_0_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_0_0_0_1.AuxInt) != 0 || auxIntToUint8(b.AuxInt) != 0 || auxToS390xCCMask(b.Aux) != s390x.Greater {
				break
			}
			b.resetWithControl(BlockS390XBRC, borrow)
			b.Aux = s390xCCMaskToAux(s390x.Borrow)
			return true
		}
	case BlockS390XCLGRJ:
		// match: (CLGRJ {c} x (MOVDconst [y]) yes no)
		// cond: isU8Bit(y)
		// result: (CLGIJ {c} x [uint8(y)] yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(isU8Bit(y)) {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, x)
			b.AuxInt = uint8ToAuxInt(uint8(y))
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CLGRJ {c} (MOVDconst [x]) y yes no)
		// cond: isU8Bit(x)
		// result: (CLGIJ {c.ReverseComparison()} y [uint8(x)] yes no)
		for b.Controls[0].Op == OpS390XMOVDconst {
			v_0 := b.Controls[0]
			x := auxIntToInt64(v_0.AuxInt)
			y := b.Controls[1]
			c := auxToS390xCCMask(b.Aux)
			if !(isU8Bit(x)) {
				break
			}
			b.resetWithControl(BlockS390XCLGIJ, y)
			b.AuxInt = uint8ToAuxInt(uint8(x))
			b.Aux = s390xCCMaskToAux(c.ReverseComparison())
			return true
		}
		// match: (CLGRJ {c} x (MOVDconst [y]) yes no)
		// cond: !isU8Bit(y) && isU32Bit(y)
		// result: (BRC {c} (CMPUconst x [int32(y)]) yes no)
		for b.Controls[1].Op == OpS390XMOVDconst {
			x := b.Controls[0]
			v_1 := b.Controls[1]
			y := auxIntToInt64(v_1.AuxInt)
			c := auxToS390xCCMask(b.Aux)
			if !(!isU8Bit(y) && isU32Bit(y)) {
				break
			}
			v0 := b.NewValue0(x.Pos, OpS390XCMPUconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(y))
			v0.AddArg(x)
			b.resetWithControl(BlockS390XBRC, v0)
			b.Aux = s390xCCMaskToAux(c)
			return true
		}
		// match: (CLGRJ {c} (MOVDconst [x]
"""




```