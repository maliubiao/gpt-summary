Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Functionality:** The filename `rewriteMIPS.go` and the package `ssa` strongly suggest this code is part of the compiler's intermediate representation (SSA - Static Single Assignment) rewriting phase, specifically for the MIPS architecture. Rewriting rules transform the SSA graph into a more efficient or target-architecture-specific form.

2. **Recognize the Pattern:** The code consists of numerous functions named `rewriteValueMIPS_OpSomething`. This naming convention is a strong indicator of a pattern-matching and replacement mechanism. Each function likely handles the rewriting of a specific SSA operation (`OpSomething`).

3. **Focus on Individual Functions:**  Since the overall structure is repetitive, analyze a few representative functions in detail. Let's pick `rewriteValueMIPS_OpMIPSSGTUconst`.

4. **Dissect a Single Function (`rewriteValueMIPS_OpMIPSSGTUconst`):**

   * **Input:** The function takes a `*Value` named `v`. Within the function, `v.Args[0]` (aliased as `v_0`) is accessed. This suggests the operation being rewritten is a binary operation. The name `SGTUconst` hints that it's a "Set Greater Than Unsigned Constant".
   * **Pattern Matching:** The code uses a `for {}` loop with `break` conditions to implement pattern matching. It checks the `Op` field of `v_0` against specific MIPS opcodes like `OpMIPSMOVWconst`, `OpMIPSMOVBUreg`, etc. It also examines the `AuxInt` field of `v` and `v_0`, representing immediate values or constants.
   * **Conditions:**  Each pattern match is followed by a conditional check (`if !(condition) { break }`). These conditions determine if the rewrite rule applies. For instance, `uint32(c) > uint32(d)` in the first match.
   * **Rewriting:** If a pattern matches and the condition is met, `v.reset(OpMIPSMOVWconst)` changes the operation of the current value `v`. `v.AuxInt = int32ToAuxInt(1)` sets a new constant value for `v`. The function returns `true`, indicating a rewrite occurred.
   * **Purpose:** This specific function seems to be optimizing comparisons with constants. If the result of an unsigned greater-than comparison with a constant can be determined statically based on the type and value of the other operand, it's replaced with a direct move of the constant `0` or `1`.

5. **Generalize the Findings:**  Based on the analysis of `rewriteValueMIPS_OpMIPSSGTUconst`, we can generalize:

   * The code rewrites SSA values for the MIPS architecture.
   * Each `rewriteValueMIPS_Op...` function handles a specific SSA operation.
   * The functions use pattern matching on the operands and their properties (`Op`, `AuxInt`, `Type`).
   * Conditions determine if a rewrite is valid.
   * Rewrites often involve replacing complex operations with simpler ones, often involving loading constants (`MOVWconst`).

6. **Infer Overall Function:**  The primary goal is to optimize MIPS code generation by simplifying certain operations at the SSA level. This involves recognizing specific patterns of operations and replacing them with more efficient equivalents. This is a crucial step in the compilation process.

7. **Provide Examples:** To illustrate the functionality, create simple Go code snippets that would lead to the specific SSA operations being rewritten. Then, mentally trace how the rewrite rules would apply. For instance, `if uint32(x) > 10` would likely involve a `SGTUconst` operation.

8. **Address Potential Issues:** Think about common mistakes users might make or edge cases. In this context, understanding the bitwise operations and type conversions (`uint32`, `int32`) within the conditions is crucial. The implicit assumptions about the operand types also matter.

9. **Focus on Part 4:** The prompt specifically asks for the function of *this part*. This section mainly deals with comparisons (`SGTUconst`, `SGTUzero`, `SGTconst`, `SGTzero`, `Neq...`), shifts (`SLL`, `SRA`, `SRL`), arithmetic (`SUB`), bitwise operations (`XOR`), and some conversions/extensions. Therefore, summarize the functionality based on the operations covered in this specific snippet.

10. **Structure the Answer:** Organize the findings into clear categories like "Functionality," "Go Language Feature Implementation," "Code Examples," etc., as requested in the prompt. Use clear and concise language. Provide specific examples from the code where possible (e.g., referencing `OpMIPSMOVWconst`).

This structured approach allows for a systematic analysis of even large and complex code snippets by breaking them down into smaller, manageable parts and looking for recurring patterns and functionalities.这是 `go/src/cmd/compile/internal/ssa/rewriteMIPS.go` 文件的一部分，专门针对 MIPS 架构的 SSA (Static Single Assignment) 中间表示进行优化的重写规则定义。

**它的主要功能是:**

对 MIPS 架构特定的 SSA 指令进行模式匹配和替换，以简化和优化生成的汇编代码。 这部分代码主要关注以下类型的优化：

* **比较指令的优化:**  针对各种比较操作 (如大于无符号数、大于有符号数等) 与常量或零的比较，尝试将其简化为直接加载常量 0 或 1。
* **位移指令的优化:** 将位移指令 (左移、右移) 的位移量如果是常量，则转换为特定的常量位移指令。
* **算术指令的优化:**  针对减法指令，特别是与常量的减法，以及特殊情况下的减法 (如减数为 0 或两数相等)。
* **位运算指令的优化:** 针对异或指令，特别是与常量的异或，以及特殊情况下的异或 (如两数相等)。
* **取模运算的展开:** 将高级语言的取模运算 (`Mod16`, `Mod32` 等) 展开为基于除法指令 (`DIV`, `DIVU`) 的实现。
* **内存拷贝 (`Move`) 的优化:** 针对不同大小和对齐方式的内存拷贝，生成更高效的 MIPS 汇编指令序列，例如直接使用 `MOVBstore`, `MOVHstore`, `MOVWstore` 等指令。
* **不等比较的优化:** 将不等比较 (`Neq`) 转换为基于异或和无符号大于比较的实现。
* **逻辑非运算的优化:** 将逻辑非运算 (`Not`) 转换为与 1 进行异或的运算。
* **指针运算的优化:** 将基于偏移的指针运算 (`OffPtr`) 转换为 `MOVWaddr` (如果基址是栈指针 SP) 或 `ADDconst` 指令。
* **边界检查的优化:**  针对不同的边界检查 ABI (Application Binary Interface)，选择不同的 LoweredPanicBounds 实现。
* **带溢出检查的运算优化:** 针对带溢出检查的加减法，选择不同的 LoweredPanicExtend 实现。
* **循环移位操作的展开:** 将循环移位操作 (`RotateLeft16`, `RotateLeft32`) 展开为左移和右移的组合。

**可以推理出它是什么 go 语言功能的实现：**

这部分代码主要服务于 Go 语言的 **编译器后端**，特别是 **代码生成** 阶段。它作用于 **SSA 中间表示**，这意味着它是在将 Go 源代码转换为机器码的早期阶段进行优化的。

**Go 代码举例说明 (涉及代码推理):**

假设有以下 Go 代码：

```go
package main

func main() {
	var x uint32 = 10
	if x > 5 {
		println("x is greater than 5")
	}
}
```

**假设的 SSA 输入 (OpSGTUconst 部分):**

在编译过程中，`x > 5` 可能会被转换为类似于以下的 SSA 指令：

```
v1 = ConstU32 <uint32> [5]
v2 = SGTU <bool> v_x v1
```

其中 `v_x` 是表示变量 `x` 的 SSA 值。

**`rewriteValueMIPS_OpMIPSSGTUconst` 的处理:**

`rewriteValueMIPS_OpMIPSSGTUconst` 函数会尝试匹配类似于以下的模式：

```
// match: (SGTUconst [c] (MOVWconst [d]))
// cond: uint32(c) <= uint32(d)
// result: (MOVWconst [0])
```

或者

```
// match: (SGTUconst [c] (MOVWconst [d]))
// cond: uint32(c) > uint32(d)
// result: (MOVWconst [1])
```

如果 SSA 输入是：

```
v1 = ConstU32 <uint32> [5]
v2 = SGTUconst <bool> [5] v_x
```

并且 `v_x` 在之前的阶段被确定为一个 `MOVWconst` 类型的 SSA 值，例如 `v_x = MOVWconst <uint32> [10]`，那么第一个匹配就会生效，因为 `uint32(5) <= uint32(10)` 不成立，第二个匹配会生效，因为 `uint32(5) < uint32(10)` 成立。 `v2` 将会被重写为 `MOVWconst <int32> [1]`。

**假设的 SSA 输入 (OpMove 部分):**

假设有以下 Go 代码：

```go
package main

func main() {
	a := [4]byte{1, 2, 3, 4}
	b := [4]byte{}
	copy(b[:], a[:])
}
```

**假设的 SSA 输入:**

`copy(b[:], a[:])` 可能会被转换为一个 `Move` 操作，类似于：

```
v_move = Move <mem> [4] v_b_ptr v_a_ptr v_mem
```

其中 `v_b_ptr` 和 `v_a_ptr` 分别是指向数组 `b` 和 `a` 的指针， `v_mem` 是内存状态。

**`rewriteValueMIPS_OpMove` 的处理:**

`rewriteValueMIPS_OpMove` 函数会根据拷贝的大小 (AuxInt) 和目标类型的对齐方式尝试匹配更高效的指令序列。 在这个例子中，大小为 4，如果 `b` 的类型对齐是 4 字节，则可能会匹配到：

```
// match: (Move [4] {t} dst src mem)
// cond: t.Alignment()%4 == 0
// result: (MOVWstore dst (MOVWload src mem) mem)
```

`v_move` 将会被重写为一系列 `MOVWload` 和 `MOVWstore` 指令。

**命令行参数的具体处理:**

这部分代码本身不直接处理命令行参数。 命令行参数的处理发生在编译器的前端和更上层的代码中。 这部分代码是编译器内部 SSA 优化的一部分，它接收已经解析和转换后的 SSA 中间表示作为输入。

**使用者易犯错的点:**

作为编译器开发者，理解这些重写规则至关重要。  常见的错误可能包括：

* **条件判断错误:**  在编写重写规则时，条件判断的逻辑错误可能导致错误的优化或程序行为异常。例如，比较操作符使用错误，或者忽略了某些边界条件。
* **模式匹配不完整:**  未能覆盖所有可能的 SSA 指令组合，导致某些可以优化的场景没有被优化到。
* **引入新的 SSA 指令时未添加相应的重写规则:**  当引入新的 SSA 指令时，需要考虑是否需要添加针对该指令的优化规则。
* **对 `AuxInt` 和 `Aux` 的理解偏差:** `AuxInt` 和 `Aux` 存储了与 SSA 指令相关的附加信息，理解其含义对于编写正确的重写规则至关重要。 例如，`Move` 指令的 `AuxInt` 表示拷贝的字节数，`Aux` 表示拷贝的类型信息。

**总结一下它的功能 (第4部分):**

这是 `rewriteMIPS.go` 文件的第四部分，其核心功能是定义了一系列针对 MIPS 架构的 SSA 重写规则，用于优化比较操作、位移操作、算术运算、位运算、内存拷贝、不等比较、逻辑非运算、指针运算以及边界检查和带溢出检查的运算。  通过模式匹配和条件判断，将一些通用的 SSA 指令转换为更高效的 MIPS 特定指令序列或常量，从而提升最终生成代码的性能。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共6部分，请归纳一下它的功能

"""
Int(1)
		return true
	}
	// match: (SGTUconst [c] (MOVWconst [d]))
	// cond: uint32(c) <= uint32(d)
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		if !(uint32(c) <= uint32(d)) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SGTUconst [c] (MOVBUreg _))
	// cond: 0xff < uint32(c)
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVBUreg || !(0xff < uint32(c)) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (MOVHUreg _))
	// cond: 0xffff < uint32(c)
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVHUreg || !(0xffff < uint32(c)) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (ANDconst [m] _))
	// cond: uint32(m) < uint32(c)
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSANDconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(uint32(m) < uint32(c)) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTUconst [c] (SRLconst _ [d]))
	// cond: uint32(d) <= 31 && 0xffffffff>>uint32(d) < uint32(c)
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSSRLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		if !(uint32(d) <= 31 && 0xffffffff>>uint32(d) < uint32(c)) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSGTUzero(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SGTUzero (MOVWconst [d]))
	// cond: d != 0
	// result: (MOVWconst [1])
	for {
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTUzero (MOVWconst [d]))
	// cond: d == 0
	// result: (MOVWconst [0])
	for {
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		if !(d == 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSGTconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SGTconst [c] (MOVWconst [d]))
	// cond: c > d
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		if !(c > d) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVWconst [d]))
	// cond: c <= d
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		if !(c <= d) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVBreg _))
	// cond: 0x7f < c
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVBreg || !(0x7f < c) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVBreg _))
	// cond: c <= -0x80
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVBreg || !(c <= -0x80) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVBUreg _))
	// cond: 0xff < c
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVBUreg || !(0xff < c) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVBUreg _))
	// cond: c < 0
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVBUreg || !(c < 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVHreg _))
	// cond: 0x7fff < c
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVHreg || !(0x7fff < c) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVHreg _))
	// cond: c <= -0x8000
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVHreg || !(c <= -0x8000) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (MOVHUreg _))
	// cond: 0xffff < c
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVHUreg || !(0xffff < c) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (MOVHUreg _))
	// cond: c < 0
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVHUreg || !(c < 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SGTconst [c] (ANDconst [m] _))
	// cond: 0 <= m && m < c
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSANDconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= m && m < c) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTconst [c] (SRLconst _ [d]))
	// cond: 0 <= c && uint32(d) <= 31 && 0xffffffff>>uint32(d) < uint32(c)
	// result: (MOVWconst [1])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSSRLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		if !(0 <= c && uint32(d) <= 31 && 0xffffffff>>uint32(d) < uint32(c)) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSGTzero(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SGTzero (MOVWconst [d]))
	// cond: d > 0
	// result: (MOVWconst [1])
	for {
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		if !(d > 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SGTzero (MOVWconst [d]))
	// cond: d <= 0
	// result: (MOVWconst [0])
	for {
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		if !(d <= 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLL x (MOVWconst [c]))
	// result: (SLLconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpMIPSSLLconst)
		v.AuxInt = int32ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSLLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLLconst [c] (MOVWconst [d]))
	// result: (MOVWconst [d<<uint32(c)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(d << uint32(c))
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRA x (MOVWconst [c]))
	// result: (SRAconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpMIPSSRAconst)
		v.AuxInt = int32ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSRAconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRAconst [c] (MOVWconst [d]))
	// result: (MOVWconst [d>>uint32(c)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(d >> uint32(c))
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRL x (MOVWconst [c]))
	// result: (SRLconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpMIPSSRLconst)
		v.AuxInt = int32ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSRLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRLconst [c] (MOVWconst [d]))
	// result: (MOVWconst [int32(uint32(d)>>uint32(c))])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(d) >> uint32(c)))
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUB x (MOVWconst [c]))
	// result: (SUBconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpMIPSSUBconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUB x x)
	// result: (MOVWconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SUB (MOVWconst [0]) x)
	// result: (NEG x)
	for {
		if v_0.Op != OpMIPSMOVWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpMIPSNEG)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSSUBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBconst [c] (MOVWconst [d]))
	// result: (MOVWconst [d-c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(d - c)
		return true
	}
	// match: (SUBconst [c] (SUBconst [d] x))
	// result: (ADDconst [-c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpMIPSADDconst)
		v.AuxInt = int32ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	// match: (SUBconst [c] (ADDconst [d] x))
	// result: (ADDconst [-c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpMIPSADDconst)
		v.AuxInt = int32ToAuxInt(-c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSXOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVWconst [c]))
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPSMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpMIPSXORconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR x x)
	// result: (MOVWconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSXORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (XORconst [-1] x)
	// result: (NORconst [0] x)
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.reset(OpMIPSNORconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
	// match: (XORconst [c] (MOVWconst [d]))
	// result: (MOVWconst [c^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		return true
	}
	// match: (XORconst [c] (XORconst [d] x))
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSXORconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (Select0 (DIV (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPSDIV, types.NewTuple(typ.Int32, typ.Int32))
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (Select0 (DIVU (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPSDIVU, types.NewTuple(typ.UInt32, typ.UInt32))
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32 x y)
	// result: (Select0 (DIV x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPSDIV, types.NewTuple(typ.Int32, typ.Int32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32u x y)
	// result: (Select0 (DIVU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPSDIVU, types.NewTuple(typ.UInt32, typ.UInt32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (Select0 (DIV (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPSDIV, types.NewTuple(typ.Int32, typ.Int32))
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (Select0 (DIVU (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPSDIVU, types.NewTuple(typ.UInt32, typ.UInt32))
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Move [0] _ _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.copyOf(mem)
		return true
	}
	// match: (Move [1] dst src mem)
	// result: (MOVBstore dst (MOVBUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpMIPSMOVBstore)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore dst (MOVHUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPSMOVHstore)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVHUload, typ.UInt16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVBstore [1] dst (MOVBUload [1] src mem) (MOVBstore dst (MOVBUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpMIPSMOVBstore)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore dst (MOVWload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPSMOVWstore)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [2] dst (MOVHUload [2] src mem) (MOVHstore dst (MOVHUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPSMOVHstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVHUload, typ.UInt16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVBstore [3] dst (MOVBUload [3] src mem) (MOVBstore [2] dst (MOVBUload [2] src mem) (MOVBstore [1] dst (MOVBUload [1] src mem) (MOVBstore dst (MOVBUload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpMIPSMOVBstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v2.AuxInt = int32ToAuxInt(2)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(1)
		v4 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v4.AuxInt = int32ToAuxInt(1)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBUload [2] src mem) (MOVBstore [1] dst (MOVBUload [1] src mem) (MOVBstore dst (MOVBUload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpMIPSMOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v2.AuxInt = int32ToAuxInt(1)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpMIPSMOVBUload, typ.UInt8)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [4] dst (MOVWload [4] src mem) (MOVWstore dst (MOVWload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPSMOVWstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [6] dst (MOVHload [6] src mem) (MOVHstore [4] dst (MOVHload [4] src mem) (MOVHstore [2] dst (MOVHload [2] src mem) (MOVHstore dst (MOVHload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPSMOVHstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVHload, typ.Int16)
		v0.AuxInt = int32ToAuxInt(6)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVHload, typ.Int16)
		v2.AuxInt = int32ToAuxInt(4)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVHstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(2)
		v4 := b.NewValue0(v.Pos, OpMIPSMOVHload, typ.Int16)
		v4.AuxInt = int32ToAuxInt(2)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpMIPSMOVHstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpMIPSMOVHload, typ.Int16)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [6] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [4] dst (MOVHload [4] src mem) (MOVHstore [2] dst (MOVHload [2] src mem) (MOVHstore dst (MOVHload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPSMOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVHload, typ.Int16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVHload, typ.Int16)
		v2.AuxInt = int32ToAuxInt(2)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVHstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpMIPSMOVHload, typ.Int16)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [12] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [8] dst (MOVWload [8] src mem) (MOVWstore [4] dst (MOVWload [4] src mem) (MOVWstore dst (MOVWload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPSMOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(4)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [16] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [12] dst (MOVWload [12] src mem) (MOVWstore [8] dst (MOVWload [8] src mem) (MOVWstore [4] dst (MOVWload [4] src mem) (MOVWstore dst (MOVWload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPSMOVWstore)
		v.AuxInt = int32ToAuxInt(12)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(12)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(8)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(4)
		v4 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v4.AuxInt = int32ToAuxInt(4)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpMIPSMOVWload, typ.UInt32)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] {t} dst src mem)
	// cond: (s > 16 && logLargeCopy(v, s) || t.Alignment()%4 != 0)
	// result: (LoweredMove [int32(t.Alignment())] dst src (ADDconst <src.Type> src [int32(s-moveSize(t.Alignment(), config))]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 16 && logLargeCopy(v, s) || t.Alignment()%4 != 0) {
			break
		}
		v.reset(OpMIPSLoweredMove)
		v.AuxInt = int32ToAuxInt(int32(t.Alignment()))
		v0 := b.NewValue0(v.Pos, OpMIPSADDconst, src.Type)
		v0.AuxInt = int32ToAuxInt(int32(s - moveSize(t.Alignment(), config)))
		v0.AddArg(src)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (SGTU (XOR (ZeroExt16to32 x) (ZeroExt16to32 y)) (MOVWconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTU)
		v0 := b.NewValue0(v.Pos, OpMIPSXOR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32 x y)
	// result: (SGTU (XOR x y) (MOVWconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTU)
		v0 := b.NewValue0(v.Pos, OpMIPSXOR, typ.UInt32)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32F x y)
	// result: (FPFlagFalse (CMPEQF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSFPFlagFalse)
		v0 := b.NewValue0(v.Pos, OpMIPSCMPEQF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64F x y)
	// result: (FPFlagFalse (CMPEQD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSFPFlagFalse)
		v0 := b.NewValue0(v.Pos, OpMIPSCMPEQD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (SGTU (XOR (ZeroExt8to32 x) (ZeroExt8to32 y)) (MOVWconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTU)
		v0 := b.NewValue0(v.Pos, OpMIPSXOR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqPtr x y)
	// result: (SGTU (XOR x y) (MOVWconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTU)
		v0 := b.NewValue0(v.Pos, OpMIPSXOR, typ.UInt32)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not x)
	// result: (XORconst [1] x)
	for {
		x := v_0
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueMIPS_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr [off] ptr:(SP))
	// result: (MOVWaddr [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if ptr.Op != OpSP {
			break
		}
		v.reset(OpMIPSMOVWaddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// result: (ADDconst [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpMIPSADDconst)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
}
func rewriteValueMIPS_OpPanicBounds(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 0
	// result: (LoweredPanicBoundsA [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 0) {
			break
		}
		v.reset(OpMIPSLoweredPanicBoundsA)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 1
	// result: (LoweredPanicBoundsB [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 1) {
			break
		}
		v.reset(OpMIPSLoweredPanicBoundsB)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 2
	// result: (LoweredPanicBoundsC [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 2) {
			break
		}
		v.reset(OpMIPSLoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpPanicExtend(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PanicExtend [kind] hi lo y mem)
	// cond: boundsABI(kind) == 0
	// result: (LoweredPanicExtendA [kind] hi lo y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		hi := v_0
		lo := v_1
		y := v_2
		mem := v_3
		if !(boundsABI(kind) == 0) {
			break
		}
		v.reset(OpMIPSLoweredPanicExtendA)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg4(hi, lo, y, mem)
		return true
	}
	// match: (PanicExtend [kind] hi lo y mem)
	// cond: boundsABI(kind) == 1
	// result: (LoweredPanicExtendB [kind] hi lo y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		hi := v_0
		lo := v_1
		y := v_2
		mem := v_3
		if !(boundsABI(kind) == 1) {
			break
		}
		v.reset(OpMIPSLoweredPanicExtendB)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg4(hi, lo, y, mem)
		return true
	}
	// match: (PanicExtend [kind] hi lo y mem)
	// cond: boundsABI(kind) == 2
	// result: (LoweredPanicExtendC [kind] hi lo y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		hi := v_0
		lo := v_1
		y := v_2
		mem := v_3
		if !(boundsABI(kind) == 2) {
			break
		}
		v.reset(OpMIPSLoweredPanicExtendC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg4(hi, lo, y, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVWconst [c]))
	// result: (Or16 (Lsh16x32 <t> x (MOVWconst [c&15])) (Rsh16Ux32 <t> x (MOVWconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x32, t)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux32, t)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRotateLeft32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft32 <t> x (MOVWconst [c]))
	// result: (Or32 (Lsh32x32 <t> x (MOVWconst [c&31])) (Rsh32Ux32 <t> x (MOVWconst [-c&31])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpOr32)
		v0 := b.NewValue0(v.Pos, OpLsh32x32, t)
		v1 :=
"""




```