Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code, which is a part of the `rewriteLOONG64.go` file. This strongly suggests we're looking at compiler optimizations or instruction selection rules specific to the LOONG64 architecture.

2. **Identify the Core Structure:** The code consists of multiple Go functions, all named in the pattern `rewriteValueLOONG64_Op<Operation>`. This naming convention is a huge clue. It indicates these functions are likely part of a larger system that rewrites or transforms intermediate representation (IR) nodes (represented by the `*Value` type) based on the specific operation (`Op`).

3. **Analyze Individual Functions:**  The best approach is to examine each function individually. For each function:
    * **Identify the Input:**  Each function takes a `*Value` as input. The comments within each function often reveal the expected `Op` of this input `*Value` (e.g., `OpLOONG64OR`, `OpLOONG64REMV`).
    * **Identify the Arguments:** The first few lines within each function usually extract the arguments of the input `*Value` (e.g., `v.Args[0]`, `v.Args[1]`).
    * **Look for `match` and `result` Comments:** These comments are crucial. They describe a pattern matching on the input and the corresponding transformation (the "result").
    * **Understand the `cond` Comment (if present):**  Conditions specify when a rewrite rule is applicable. These often involve checking properties of constants or other operands (e.g., `is32Bit`, `isPowerOfTwo`).
    * **Trace the Logic:**  Follow the `if` conditions and the `break` statements within the `for` loops. This helps understand the conditions under which a rewrite happens.
    * **Identify the Rewrite:** When a match is found and the condition is met, the code typically calls `v.reset()` with a new `Op` and sets `v.AuxInt` and adds arguments using `v.AddArg()`. This is the core of the rewrite process.

4. **Look for Patterns and Common Themes:**  After analyzing a few functions, patterns emerge:
    * **Constant Folding:** Many rewrites involve cases where one or both operands are constants (`OpLOONG64MOVVconst`). The rewrite often performs the operation at compile time and replaces the original operation with a constant.
    * **Strength Reduction:** Some rewrites replace a more expensive operation with a cheaper one (e.g., division by a power of two replaced with an AND).
    * **Instruction Selection:** The rewrites often map high-level IR operations to specific LOONG64 instructions (e.g., `OpLOONG64ROTR` to `OpLOONG64ROTRconst`).
    * **Commutativity:** Some rewrites handle commutative operations (like `OR` and `XOR`) by ensuring a consistent operand order.
    * **Bit Manipulation Optimizations:** Several rewrites focus on optimizing bitwise operations (shifts, AND, OR, XOR).

5. **Infer Higher-Level Functionality:** Based on the observed patterns, we can infer that this code implements optimization passes within the Go compiler for the LOONG64 architecture. Specifically, it's likely part of the SSA (Static Single Assignment) rewriting phase, where the compiler tries to simplify and optimize the IR before generating machine code.

6. **Construct Examples (as requested):** To illustrate the rewrites, create simple Go code snippets that would generate the IR patterns being matched. Then, show what the optimized code would look like after the rewrite. This requires understanding the semantics of the Go operations and the corresponding LOONG64 instructions. *Initially, I might struggle with the exact Go code that produces a specific IR node, but by focusing on the `Op` and the operands, I can get close. Trial and error with a Go compiler's `-gcflags=-S` output can help refine these examples.*

7. **Address Specific Request Points:**
    * **List Functionalities:** Summarize the types of optimizations being performed (constant folding, strength reduction, etc.).
    * **Infer Go Language Feature:**  Recognize that this is related to compiler optimizations and instruction selection.
    * **Provide Go Code Examples:**  Create illustrative examples as described above.
    * **Handle Code Reasoning:** Explain the input, the matching condition, and the resulting output for specific rewrites.
    * **Command-Line Arguments:** Since the code doesn't explicitly handle command-line arguments, mention that it's part of the compiler's internal workings and not directly influenced by user-provided flags *in this specific file*.
    * **Common Mistakes:** Think about situations where the compiler might *not* apply a rewrite, even if it seems possible. This often relates to the conditions (e.g., `is32Bit`).
    * **Summarize Functionality (for Part 5):**  Focus on the specific operations covered in this particular code segment (OR, REM, ROTR, SGT, SLLV, SRAV, SRLV, SUB, XOR, and comparisons).

8. **Refine and Organize:**  Structure the answer clearly with headings and bullet points. Use precise language and avoid jargon where possible. Ensure the Go code examples are correct and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "These functions look like they're just doing simple replacements."  **Correction:** Realize that the conditions and the structure suggest a more systematic optimization process within the compiler.
* **Stuck on a particular rewrite rule:**  Go back to the definition of the involved LOONG64 instructions or consult the Go compiler source code for related passes.
* **Go example too complex:** Simplify the Go example to clearly demonstrate the targeted rewrite rule.
* **Overlooking a pattern:**  Review the functions again to see if there are any recurring optimization strategies being used.

By following this structured approach of individual analysis, pattern recognition, and inference, we can effectively understand and summarize the functionality of this Go code snippet.
这是 `go/src/cmd/compile/internal/ssa/rewriteLOONG64.go` 文件的一部分，主要负责在 Go 编译器的 SSA (Static Single Assignment) 中间表示阶段，针对 LOONG64 架构进行特定的代码重写和优化。这些重写规则旨在将一些通用的操作转换为更高效的 LOONG64 指令序列，或者对特定模式的代码进行简化。

**第 5 部分的功能归纳：**

这部分代码主要定义了一系列针对特定 LOONG64 操作码 (`OpLOONG64...`) 的重写规则，涵盖了以下几个方面的功能：

* **逻辑运算优化 (`OpLOONG64OR`)**: 针对 `OR` 操作，特别是与常量的 `OR` 运算进行优化，尝试合并连续的常量 `OR` 操作，并将其转换为更简洁的 `MOVVconst` 或 `ORconst` 指令。
* **取余运算优化 (`OpLOONG64REMV`, `OpLOONG64REMVU`)**:  对有符号和无符号的取余运算进行优化，特别是当除数为常量时，可以将其替换为更高效的指令，例如当除数为 2 的幂时，可以转换为 `AND` 操作。
* **循环右移运算优化 (`OpLOONG64ROTR`, `OpLOONG64ROTRV`)**: 针对循环右移操作，当移位量为常量时，转换为 `ROTRconst` 和 `ROTRVconst` 指令，并屏蔽掉移位量的高位。
* **比较运算优化 (`OpLOONG64SGT`, `OpLOONG64SGTU`, `OpLOONG64SGTconst`, `OpLOONG64SGTUconst`)**:  对大于比较操作进行优化，特别是与常量的比较，尝试将其转换为 `SGTconst` 或 `SGTUconst` 指令，或者在某些特定情况下直接生成常量结果。
* **移位运算优化 (`OpLOONG64SLLV`, `OpLOONG64SLLVconst`, `OpLOONG64SRAV`, `OpLOONG64SRAVconst`, `OpLOONG64SRLV`, `OpLOONG64SRLVconst`)**:  对左移、算术右移和逻辑右移运算进行优化，当移位量为常量时，转换为相应的常量移位指令 (`SLLVconst`, `SRAVconst`, `SRLVconst`)。 对于逻辑右移常量，还尝试匹配特定的模式，例如从较小的位域提取数据 (`BSTRPICKV`)。
* **浮点数减法优化 (`OpLOONG64SUBD`, `OpLOONG64SUBF`)**: 尝试将浮点数的减法操作与乘法操作结合，利用 FMA (Fused Multiply-Add) 指令进行优化，提升性能。
* **减法运算优化 (`OpLOONG64SUBV`, `OpLOONG64SUBVconst`)**: 对减法运算进行优化，特别是与常量的减法，可以转换为 `SUBVconst` 指令，或者在特定情况下转换为 `NEGV` (取反) 或 `ADDVconst` 指令。
* **异或运算优化 (`OpLOONG64XOR`, `OpLOONG64XORconst`)**:  针对异或运算，特别是与常量的异或运算进行优化，尝试将其转换为 `XORconst` 指令，并合并连续的常量异或操作。
* **比较操作的转换 (`OpLeq16`, `OpLeq16U`, `OpLeq32`, `OpLeq32F`, `OpLeq32U`, `OpLeq64`, `OpLeq64F`, `OpLeq64U`, `OpLeq8`, `OpLeq8U`, `OpLess16`, `OpLess16U`, `OpLess32`, `OpLess32F`, `OpLess32U`, `OpLess64`, `OpLess64F`, `OpLess64U`, `OpLess8`, `OpLess8U`)**: 将高级语言中的比较操作符 (例如 `<=`，`<`) 转换为 LOONG64 架构下更底层的比较和逻辑运算组合，例如使用 `SGT` 或 `SGTU` 并结合 `XOR` 来实现 `<=`。
* **Load 操作优化 (`OpLoad`)**: 针对 `Load` 操作，当加载的是布尔类型时，将其转换为更具体的 `MOVBUload` (加载一个字节) 操作。

**可以推理出它是什么 go 语言功能的实现：**

这部分代码是 Go 编译器后端的一部分，负责将 Go 语言的抽象语法树 (AST) 转换为 LOONG64 汇编代码的过程中，对中间表示 (SSA) 进行优化的一个步骤。它体现了编译器在目标架构上的指令选择和优化策略。

**Go 代码举例说明 (带假设的输入与输出):**

假设有以下 Go 代码片段：

```go
package main

func main() {
	a := 10
	b := 5
	c := a | b
	println(c)
}
```

在编译器的 SSA 阶段，可能会生成类似以下的中间表示 (简化)：

```
v1 = MOVVconst [10]
v2 = MOVVconst [5]
v3 = OR v1 v2
```

`rewriteLOONG64.go` 中的 `rewriteValueLOONG64_OpLOONG64OR` 函数可能会匹配到这个模式，并根据其规则进行优化。

例如，如果输入是 `OR` 操作，并且其中一个操作数是常量，它可能会将其转换为 `ORconst` 操作。 如果两个操作数都是常量，则会直接计算结果并用 `MOVVconst` 替换。

**假设的输入 (SSA Value):**
`v` 代表 `OR` 操作的 SSA Value， `v.Op = OpLOONG64OR`, `v.Args = [v1, v2]`，其中 `v1.Op = OpLOONG64MOVVconst`, `v1.AuxInt = 10`, `v2.Op = OpLOONG64MOVVconst`, `v2.AuxInt = 5`。

**输出 (优化后的 SSA Value):**
`v` 的操作码被重置为 `OpLOONG64MOVVconst`，`v.AuxInt` 被设置为 `10 | 5 = 15`。

**另一个例子 (取余优化):**

```go
package main

func main() {
	a := 23
	b := a % 4
	println(b)
}
```

在 SSA 阶段可能生成：

```
v1 = <some operation producing 23>
v2 = MOVVconst [4]
v3 = REMV v1 v2
```

`rewriteValueLOONG64_OpLOONG64REMVU` 函数会匹配除数为 2 的幂的情况，将其转换为 `ANDconst` 操作。

**假设的输入 (SSA Value):**
`v` 代表 `REMV` 操作的 SSA Value， `v.Op = OpLOONG64REMVU`, `v.Args = [v1, v2]`，其中 `v2.Op = OpLOONG64MOVVconst`, `v2.AuxInt = 4`。

**输出 (优化后的 SSA Value):**
`v` 的操作码被重置为 `OpLOONG64ANDconst`，`v.AuxInt` 被设置为 `4 - 1 = 3`，`v` 的参数变为 `[v1]`。

**命令行参数的具体处理：**

这个代码片段本身不直接处理命令行参数。它是 Go 编译器内部工作的一部分。Go 编译器的命令行参数（例如 `-O` 控制优化级别）会影响到整体的编译流程，从而间接地影响到这些重写规则是否被启用以及以何种程度应用。

例如，使用 `-gcflags="-N"` 可以禁用优化，那么这些重写规则就不会被执行。

**使用者易犯错的点：**

作为 Go 语言的使用者，通常不需要直接关心这些底层的编译器优化细节。开发者编写 Go 代码时，编译器会在后台进行这些优化。

**总结这部分的功能：**

这部分 `rewriteLOONG64.go` 代码是 Go 编译器针对 LOONG64 架构进行 SSA 优化的核心组成部分。它定义了一系列模式匹配和重写规则，旨在将通用的中间表示转换为更高效的 LOONG64 特定指令，从而提升生成代码的性能。这些优化涵盖了逻辑运算、算术运算、位运算和比较操作等多个方面。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteLOONG64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共8部分，请归纳一下它的功能

"""
// match: (ORconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c|d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c | d)
		return true
	}
	// match: (ORconst [c] (ORconst [d] x))
	// cond: is32Bit(c|d)
	// result: (ORconst [c|d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c | d)) {
			break
		}
		v.reset(OpLOONG64ORconst)
		v.AuxInt = int64ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64REMV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (REMV (MOVVconst [c]) (MOVVconst [d]))
	// cond: d != 0
	// result: (MOVVconst [c%d])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c % d)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64REMVU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (REMVU _ (MOVVconst [1]))
	// result: (MOVVconst [0])
	for {
		if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (REMVU x (MOVVconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (ANDconst [c-1] x)
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpLOONG64ANDconst)
		v.AuxInt = int64ToAuxInt(c - 1)
		v.AddArg(x)
		return true
	}
	// match: (REMVU (MOVVconst [c]) (MOVVconst [d]))
	// cond: d != 0
	// result: (MOVVconst [int64(uint64(c)%uint64(d))])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) % uint64(d)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64ROTR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROTR x (MOVVconst [c]))
	// result: (ROTRconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64ROTRconst)
		v.AuxInt = int64ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64ROTRV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROTRV x (MOVVconst [c]))
	// result: (ROTRVconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64ROTRVconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SGT(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SGT (MOVVconst [c]) (NEGV (SUBVconst [d] x)))
	// cond: is32Bit(d-c)
	// result: (SGT x (MOVVconst [d-c]))
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64NEGV {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpLOONG64SUBVconst {
			break
		}
		d := auxIntToInt64(v_1_0.AuxInt)
		x := v_1_0.Args[0]
		if !(is32Bit(d - c)) {
			break
		}
		v.reset(OpLOONG64SGT)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(d - c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SGT (MOVVconst [c]) x)
	// cond: is32Bit(c)
	// result: (SGTconst [c] x)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64SGTconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SGT x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SGTU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SGTU (MOVVconst [c]) x)
	// cond: is32Bit(c)
	// result: (SGTUconst [c] x)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64SGTUconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SGTU x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SGTUconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SGTUconst [c] (MOVVconst [d]))
	// cond: uint64(c)>uint64(d)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(uint64(c) > uint64(d)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (MOVVconst [d]))
	// cond: uint64(c)<=uint64(d)
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(uint64(c) <= uint64(d)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTUconst [c] (MOVBUreg _))
	// cond: 0xff < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg || !(0xff < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (MOVHUreg _))
	// cond: 0xffff < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg || !(0xffff < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (ANDconst [m] _))
	// cond: uint64(m) < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		if !(uint64(m) < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (SRLVconst _ [d]))
	// cond: 0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64SRLVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SGTconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SGTconst [c] (MOVVconst [d]))
	// cond: c>d
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(c > d) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVVconst [d]))
	// cond: c<=d
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(c <= d) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVBreg _))
	// cond: 0x7f < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBreg || !(0x7f < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVBreg _))
	// cond: c <= -0x80
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBreg || !(c <= -0x80) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVBUreg _))
	// cond: 0xff < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg || !(0xff < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVBUreg _))
	// cond: c < 0
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg || !(c < 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVHreg _))
	// cond: 0x7fff < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHreg || !(0x7fff < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVHreg _))
	// cond: c <= -0x8000
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHreg || !(c <= -0x8000) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVHUreg _))
	// cond: 0xffff < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg || !(0xffff < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVHUreg _))
	// cond: c < 0
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg || !(c < 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVWUreg _))
	// cond: c < 0
	// result: (MOVVconst [0])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVWUreg || !(c < 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (ANDconst [m] _))
	// cond: 0 <= m && m < c
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		if !(0 <= m && m < c) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (SRLVconst _ [d]))
	// cond: 0 <= c && 0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)
	// result: (MOVVconst [1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64SRLVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(0 <= c && 0 < d && d <= 63 && 0xffffffffffffffff>>uint64(d) < uint64(c)) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SLLV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLLV _ (MOVVconst [c]))
	// cond: uint64(c)>=64
	// result: (MOVVconst [0])
	for {
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SLLV x (MOVVconst [c]))
	// result: (SLLVconst x [c])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64SLLVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SLLVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLLVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [d<<uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(d << uint64(c))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SRAV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRAV x (MOVVconst [c]))
	// cond: uint64(c)>=64
	// result: (SRAVconst x [63])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpLOONG64SRAVconst)
		v.AuxInt = int64ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	// match: (SRAV x (MOVVconst [c]))
	// result: (SRAVconst x [c])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64SRAVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SRAVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRAVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [d>>uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(d >> uint64(c))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SRLV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRLV _ (MOVVconst [c]))
	// cond: uint64(c)>=64
	// result: (MOVVconst [0])
	for {
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLV x (MOVVconst [c]))
	// result: (SRLVconst x [c])
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpLOONG64SRLVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SRLVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRLVconst [rc] (SLLVconst [lc] x))
	// cond: lc <= rc
	// result: (BSTRPICKV [rc-lc + ((64-lc)-1)<<6] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64SLLVconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc <= rc) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc - lc + ((64-lc)-1)<<6)
		v.AddArg(x)
		return true
	}
	// match: (SRLVconst [rc] (MOVWUreg x))
	// cond: rc < 32
	// result: (BSTRPICKV [rc + 31<<6] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVWUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 32) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc + 31<<6)
		v.AddArg(x)
		return true
	}
	// match: (SRLVconst [rc] (MOVHUreg x))
	// cond: rc < 16
	// result: (BSTRPICKV [rc + 15<<6] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 16) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc + 15<<6)
		v.AddArg(x)
		return true
	}
	// match: (SRLVconst [rc] (MOVBUreg x))
	// cond: rc < 8
	// result: (BSTRPICKV [rc + 7<<6] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 8) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc + 7<<6)
		v.AddArg(x)
		return true
	}
	// match: (SRLVconst [rc] (MOVWUreg x))
	// cond: rc >= 32
	// result: (MOVVconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVWUreg {
			break
		}
		if !(rc >= 32) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLVconst [rc] (MOVHUreg x))
	// cond: rc >= 16
	// result: (MOVVconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVHUreg {
			break
		}
		if !(rc >= 16) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLVconst [rc] (MOVBUreg x))
	// cond: rc >= 8
	// result: (MOVVconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVBUreg {
			break
		}
		if !(rc >= 8) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [int64(uint64(d)>>uint64(c))])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(d) >> uint64(c)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SUBD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBD (MULD x y) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FMSUBD x y z)
	for {
		if v_0.Op != OpLOONG64MULD {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		z := v_1
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FMSUBD)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBD z (MULD x y))
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMSUBD x y z)
	for {
		z := v_0
		if v_1.Op != OpLOONG64MULD {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FNMSUBD)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBD z (NEGD (MULD x y)))
	// cond: z.Block.Func.useFMA(v)
	// result: (FMADDD x y z)
	for {
		z := v_0
		if v_1.Op != OpLOONG64NEGD {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpLOONG64MULD {
			break
		}
		y := v_1_0.Args[1]
		x := v_1_0.Args[0]
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FMADDD)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBD (NEGD (MULD x y)) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMADDD x y z)
	for {
		if v_0.Op != OpLOONG64NEGD {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpLOONG64MULD {
			break
		}
		y := v_0_0.Args[1]
		x := v_0_0.Args[0]
		z := v_1
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FNMADDD)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SUBF(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBF (MULF x y) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FMSUBF x y z)
	for {
		if v_0.Op != OpLOONG64MULF {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		z := v_1
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FMSUBF)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBF z (MULF x y))
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMSUBF x y z)
	for {
		z := v_0
		if v_1.Op != OpLOONG64MULF {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FNMSUBF)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBF z (NEGF (MULF x y)))
	// cond: z.Block.Func.useFMA(v)
	// result: (FMADDF x y z)
	for {
		z := v_0
		if v_1.Op != OpLOONG64NEGF {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpLOONG64MULF {
			break
		}
		y := v_1_0.Args[1]
		x := v_1_0.Args[0]
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FMADDF)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBF (NEGF (MULF x y)) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMADDF x y z)
	for {
		if v_0.Op != OpLOONG64NEGF {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpLOONG64MULF {
			break
		}
		y := v_0_0.Args[1]
		x := v_0_0.Args[0]
		z := v_1
		if !(z.Block.Func.useFMA(v)) {
			break
		}
		v.reset(OpLOONG64FNMADDF)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SUBV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBV x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (SUBVconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64SUBVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUBV x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUBV (MOVVconst [0]) x)
	// result: (NEGV x)
	for {
		if v_0.Op != OpLOONG64MOVVconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpLOONG64NEGV)
		v.AddArg(x)
		return true
	}
	// match: (SUBV (MOVVconst [c]) (NEGV (SUBVconst [d] x)))
	// result: (ADDVconst [c-d] x)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64NEGV {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpLOONG64SUBVconst {
			break
		}
		d := auxIntToInt64(v_1_0.AuxInt)
		x := v_1_0.Args[0]
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64SUBVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBVconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [d-c])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(d - c)
		return true
	}
	// match: (SUBVconst [c] (SUBVconst [d] x))
	// cond: is32Bit(-c-d)
	// result: (ADDVconst [-c-d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64SUBVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c - d)) {
			break
		}
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	// match: (SUBVconst [c] (ADDVconst [d] x))
	// cond: is32Bit(-c+d)
	// result: (ADDVconst [-c+d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c + d)) {
			break
		}
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(-c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpLOONG64XORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64XORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (XORconst [-1] x)
	// result: (NORconst [0] x)
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.reset(OpLOONG64NORconst)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg(x)
		return true
	}
	// match: (XORconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c^d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		return true
	}
	// match: (XORconst [c] (XORconst [d] x))
	// cond: is32Bit(c^d)
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64XORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c ^ d)) {
			break
		}
		v.reset(OpLOONG64XORconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (XOR (MOVVconst [1]) (SGT (SignExt16to64 x) (SignExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGT, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (XOR (MOVVconst [1]) (SGTU (ZeroExt16to64 x) (ZeroExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32 x y)
	// result: (XOR (MOVVconst [1]) (SGT (SignExt32to64 x) (SignExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGT, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (FPFlagTrue (CMPGEF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPGEF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32U x y)
	// result: (XOR (MOVVconst [1]) (SGTU (ZeroExt32to64 x) (ZeroExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64 x y)
	// result: (XOR (MOVVconst [1]) (SGT x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGT, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (FPFlagTrue (CMPGED y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPGED, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpLeq64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64U x y)
	// result: (XOR (MOVVconst [1]) (SGTU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (XOR (MOVVconst [1]) (SGT (SignExt8to64 x) (SignExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGT, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (XOR (MOVVconst [1]) (SGTU (ZeroExt8to64 x) (ZeroExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (SGT (SignExt16to64 y) (SignExt16to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGT)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (SGTU (ZeroExt16to64 y) (ZeroExt16to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32 x y)
	// result: (SGT (SignExt32to64 y) (SignExt32to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGT)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (FPFlagTrue (CMPGTF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPGTF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32U x y)
	// result: (SGTU (ZeroExt32to64 y) (ZeroExt32to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less64 x y)
	// result: (SGT y x)
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGT)
		v.AddArg2(y, x)
		return true
	}
}
func rewriteValueLOONG64_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (FPFlagTrue (CMPGTD y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPGTD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpLess64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less64U x y)
	// result: (SGTU y x)
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v.AddArg2(y, x)
		return true
	}
}
func rewriteValueLOONG64_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (SGT (SignExt8to64 y) (SignExt8to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGT)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (SGTU (ZeroExt8to64 y) (ZeroExt8to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Load <t> ptr mem)
	// cond: t.IsBoolean()
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		
"""




```