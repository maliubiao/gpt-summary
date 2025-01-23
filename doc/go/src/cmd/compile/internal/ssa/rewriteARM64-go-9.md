Response: The user wants to understand the functionality of the provided Go code snippet, which is part of the `rewriteARM64.go` file in the Go compiler. This file seems to be responsible for applying rewrite rules to the intermediate representation (SSA) of Go code, specifically for the ARM64 architecture.

The code consists of a large `switch` statement on the block kind (`b.Kind`). Each case within the `switch` handles a specific type of control flow block in the SSA graph. Inside each case, there are a series of "match and rewrite" rules. These rules look for specific patterns of operations within the control flow block and, if a match is found and the associated conditions are met, rewrite the block with a more efficient or canonical form.

Here's a breakdown of the steps to answer the user's request:

1. **Identify the overall purpose of the file:** The file `rewriteARM64.go` is part of the Go compiler's SSA optimization pipeline for the ARM64 architecture. It applies architecture-specific rewrite rules to the SSA representation.

2. **Analyze the structure of the code:** The code is primarily a large `switch` statement on the block kind. Each `case` handles rewrites for a specific block type like `BlockARM64EQ`, `BlockARM64NE`, `BlockARM64LT`, etc.

3. **Understand the rewrite rules:** Each `case` contains multiple "match" and "result" blocks.
    - **Match:** Defines a pattern of operations (e.g., `(LE (CMPconst [0] z:(AND x y)) yes no)`) to look for in the current block (`b`). It can also have "cond" (condition) clauses that must be true for the rule to apply.
    - **Result:** Specifies how the block should be rewritten if a match is found (e.g., `(LE (TST x y) yes no)`). This often involves creating new values and resetting the block's control flow.

4. **Infer the Go language features being optimized:** By examining the patterns being matched and the rewrites being performed, we can infer the underlying Go language features being optimized. For instance, optimizations involving `CMPconst [0]` and `AND` suggest optimizations related to boolean logic or bitwise operations. The presence of different block types like `LE`, `LT`, `NE` indicates optimizations around comparison operations and conditional branching.

5. **Provide Go code examples:** Based on the inferred Go language features, construct simple Go code snippets that would likely lead to the SSA patterns being optimized by these rewrite rules.

6. **Explain code reasoning with input and output (SSA terms):** Demonstrate how a specific rewrite rule transforms a portion of the SSA graph. This involves showing the initial SSA structure (input) and the resulting SSA structure after the rewrite (output).

7. **Identify potential missteps for users:**  Since this is compiler-internal code, end-users typically don't interact with it directly. However, if we consider the *intent* of these optimizations, we can point out coding patterns that might hinder these optimizations. For example, unnecessary complexity in conditional expressions might prevent certain rewrites from being applied.

8. **Summarize the functionality (for part 10):** Concisely describe the overall purpose of this specific code snippet within the larger context of the Go compiler.

**Detailed Breakdown of Specific Rules (Example):**

Consider this rule:

```go
// match: (LE (CMPconst [0] z:(AND x y)) yes no)
// cond: z.Uses == 1
// result: (LE (TST x y) yes no)
```

- **Match:** It looks for a `BlockARM64LE` whose control is a `OpARM64CMPconst` comparing against 0, and the argument to `CMPconst` is an `OpARM64AND`.
- **Cond:** It checks if the `OpARM64AND` result is used only once.
- **Result:** If the condition is met, it rewrites the block to use `OpARM64TST` instead of `CMPconst` and `AND`.

This rule optimizes the case where you're checking if the bitwise AND of two values is less than or equal to zero. Since we're only interested in whether the result is zero or not for the LE comparison, we can use the `TST` instruction which performs a bitwise AND and sets flags based on whether the result is zero without needing an explicit comparison.
这是 `go/src/cmd/compile/internal/ssa/rewriteARM64.go` 文件的一部分，它专注于对 Go 语言编译过程中生成的 **静态单赋值 (SSA) 中间表示** 进行 **针对 ARM64 架构的重写优化**。

**功能归纳:**

这部分代码的主要功能是 **优化控制流块 (Blocks) 的结构**，特别是针对 ARM64 架构的特性进行改进，以生成更高效的机器码。它通过模式匹配的方式，寻找特定的 SSA 结构，并在满足特定条件时，将其替换为更优化的结构。

**具体功能列举:**

这段代码主要处理各种控制流块类型的重写规则，例如 `BlockARM64EQ` (等于跳转), `BlockARM64NE` (不等于跳转), `BlockARM64LT` (小于跳转) 等。对于每种控制流块类型，它会尝试匹配特定的指令模式，并进行如下类型的优化：

1. **将复杂的比较操作简化为更高效的指令:**
   - 例如，将 `(LE (CMPconst [0] z:(AND x y)) yes no)` 优化为 `(LE (TST x y) yes no)`。这意味着如果判断 `(x & y) <= 0`，并且 `(x & y)` 的结果只使用了一次，可以直接使用 `TST` 指令来设置标志位，而无需显式比较。
   - 类似地，针对加法、减法、乘法等操作，也存在类似的优化规则，例如将 `CMPconst [0]` 与 `ADD` 组合优化为 `CMN` (compare negative)。

2. **利用 ARM64 特有的指令:**
   - 例如，将对常量进行位测试的场景，如 `(NE (TSTconst [c] x) yes no)`，在特定条件下（`c` 只有一个位为 1），转换为使用 `TBNZ` (Test bit and Branch if Non-Zero) 指令。

3. **简化基于标志位的跳转:**
   - 例如，如果一个跳转条件直接基于标志位常量 ( `FlagConstant` )，例如 `(LE (FlagConstant [fc]) yes no)`，并且该标志位常量满足条件 (`fc.le()`)，则可以直接跳转到 `yes` 分支。

4. **处理标志位反转:**
   - 例如，将基于反转标志位的跳转 `(LE (InvertFlags cmp) yes no)` 转换为等价的非反转标志位跳转 `(GE cmp yes no)`。

5. **优化特定常量值的比较:**
   - 例如，将与零比较的场景 `(NE (CMPconst [0] x) yes no)` 简化为直接判断 `x` 是否非零的指令 `(NZ x yes no)`。

6. **处理跳转表:**
   - 代码中也包含了对跳转表 (`BlockARM64JUMPTABLE`) 的处理逻辑，这通常用于实现 `switch` 语句。

**推断 Go 语言功能的实现并举例说明:**

这段代码优化的主要是 **条件语句和位运算** 在 ARM64 架构上的实现。

**Go 代码示例 (条件语句优化):**

```go
package main

func test(a, b int64) bool {
	return (a & b) <= 0 // 对应 LE (CMPconst [0] z:(AND x y)) 优化
}

func main() {
	println(test(5, 2)) // Output: false
	println(test(0, 3)) // Output: true
	println(test(-1, 1)) // Output: true
}
```

**SSA 转换 (假设输入与输出):**

**假设输入 (针对 `test(a, b int64)` 函数中的 `(a & b) <= 0` 表达式的 SSA 部分):**

```
b1:
    v1 = Param: a int64
    v2 = Param: b int64
    v3 = AND <int64> v1 v2
    v4 = ConstInt64 <int64> [0]
    v5 = CMPconst <flags> v3 [0]
    IfLe v5 -> b2 b3

b2: // yes branch
    v6 = ConstBool <bool> [true]
    Ret v6

b3: // no branch
    v7 = ConstBool <bool> [false]
    Ret v7
```

**优化后的输出 (使用 `TST` 指令):**

```
b1:
    v1 = Param: a int64
    v2 = Param: b int64
    v3 = TST <flags> v1 v2
    IfLe v3 -> b2 b3

b2: // yes branch
    v6 = ConstBool <bool> [true]
    Ret v6

b3: // no branch
    v7 = ConstBool <bool> [false]
    Ret v7
```

**解释:** 原始的 SSA 需要进行 `AND` 运算后再与常量 0 进行比较 (`CMPconst`)。优化后，直接使用 `TST` 指令，它会进行按位与操作并设置标志位，但不需要存储结果，更高效。

**Go 代码示例 (位运算优化):**

```go
package main

func testBit(x int32) bool {
	return x & 4 != 0 // 对应 NE (TSTconst [c] x) 优化，假设 c=4，二进制 0100
}

func main() {
	println(testBit(5)) // Output: true (0101 & 0100 != 0)
	println(testBit(2)) // Output: false (0010 & 0100 == 0)
}
```

**SSA 转换 (假设输入与输出，针对 `x & 4 != 0`):**

**假设输入:**

```
b1:
    v1 = Param: x int32
    v2 = ConstInt32 <int32> [4]
    v3 = AND <int32> v1 v2
    v4 = ConstInt32 <int32> [0]
    v5 = CMPconst <flags> v3 [0]
    IfNe v5 -> b2 b3
```

**优化后的输出 (使用 `TBNZ` 指令，假设优化器识别出常量 4 只有一个位为 1，即第 2 位):**

```
b1:
    v1 = Param: x int32
    v2 = ConstInt64 <int64> [2] // 表示测试第 2 位 (从 0 开始)
    v3 = TBNZ <flags> v2 v1
    If v3 -> b2 b3
```

**解释:** 原始的 SSA 需要进行 `AND` 运算后再与常量 0 进行比较。优化后，可以直接使用 `TBNZ` 指令测试 `x` 的特定位是否为 1。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。`rewriteARM64.go` 文件是 Go 编译器内部的一部分，它在编译过程的 SSA 优化阶段被调用。编译器的命令行参数会影响整个编译流程，可能会间接地影响到 SSA 的生成和优化，但这段代码专注于 SSA 图的转换规则。

**使用者易犯错的点:**

由于这是编译器内部的代码，普通 Go 开发者不会直接编写或修改它。因此，不存在使用者易犯错的点。然而，理解这些优化规则可以帮助开发者编写出更符合编译器优化习惯的代码。例如，避免不必要的复杂条件判断，或者在位运算中尽量使用清晰直接的方式，可能会更容易被编译器优化。

**总结其功能 (第 10 部分):**

作为 `rewriteARM64.go` 文件的第 10 部分，这段代码延续了该文件的核心功能：**对 SSA 图中的控制流块进行基于 ARM64 架构的特定优化**。它通过一系列的模式匹配和重写规则，旨在将常见的、但可能效率较低的 SSA 结构，转换为更直接、更符合 ARM64 硬件特性的指令序列，从而提高最终生成的可执行文件的性能。这段代码特别关注于 **条件跳转** 相关的优化，包括简化比较操作、利用 ARM64 的条件码和位测试指令等。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第10部分，共10部分，请归纳一下它的功能
```

### 源代码
```go
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
			c := auxIntToInt64(v_0.AuxInt)
			x := v_0.Args[0]
			if !(oneBit(c)) {
				break
			}
			b.resetWithControl(BlockARM64TBNZ, x)
			b.AuxInt = int64ToAuxInt(int64(ntz64(c)))
			return true
		}
		// match: (NZ (MOVDconst [0]) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64MOVDconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (NZ (MOVDconst [c]) yes no)
		// cond: c != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64MOVDconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
	case BlockARM64NZW:
		// match: (NZW (ANDconst [c] x) yes no)
		// cond: oneBit(int64(uint32(c)))
		// result: (TBNZ [int64(ntz64(int64(uint32(c))))] x yes no)
		for b.Controls[0].Op == OpARM64ANDconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			x := v_0.Args[0]
			if !(oneBit(int64(uint32(c)))) {
				break
			}
			b.resetWithControl(BlockARM64TBNZ, x)
			b.AuxInt = int64ToAuxInt(int64(ntz64(int64(uint32(c)))))
			return true
		}
		// match: (NZW (MOVDconst [c]) yes no)
		// cond: int32(c) == 0
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64MOVDconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(int32(c) == 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (NZW (MOVDconst [c]) yes no)
		// cond: int32(c) != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64MOVDconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(int32(c) != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
	case BlockARM64TBNZ:
		// match: (TBNZ [0] (Equal cc) yes no)
		// result: (EQ cc yes no)
		for b.Controls[0].Op == OpARM64Equal {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64EQ, cc)
			return true
		}
		// match: (TBNZ [0] (NotEqual cc) yes no)
		// result: (NE cc yes no)
		for b.Controls[0].Op == OpARM64NotEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64NE, cc)
			return true
		}
		// match: (TBNZ [0] (LessThan cc) yes no)
		// result: (LT cc yes no)
		for b.Controls[0].Op == OpARM64LessThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64LT, cc)
			return true
		}
		// match: (TBNZ [0] (LessThanU cc) yes no)
		// result: (ULT cc yes no)
		for b.Controls[0].Op == OpARM64LessThanU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64ULT, cc)
			return true
		}
		// match: (TBNZ [0] (LessEqual cc) yes no)
		// result: (LE cc yes no)
		for b.Controls[0].Op == OpARM64LessEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64LE, cc)
			return true
		}
		// match: (TBNZ [0] (LessEqualU cc) yes no)
		// result: (ULE cc yes no)
		for b.Controls[0].Op == OpARM64LessEqualU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64ULE, cc)
			return true
		}
		// match: (TBNZ [0] (GreaterThan cc) yes no)
		// result: (GT cc yes no)
		for b.Controls[0].Op == OpARM64GreaterThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64GT, cc)
			return true
		}
		// match: (TBNZ [0] (GreaterThanU cc) yes no)
		// result: (UGT cc yes no)
		for b.Controls[0].Op == OpARM64GreaterThanU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64UGT, cc)
			return true
		}
		// match: (TBNZ [0] (GreaterEqual cc) yes no)
		// result: (GE cc yes no)
		for b.Controls[0].Op == OpARM64GreaterEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64GE, cc)
			return true
		}
		// match: (TBNZ [0] (GreaterEqualU cc) yes no)
		// result: (UGE cc yes no)
		for b.Controls[0].Op == OpARM64GreaterEqualU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64UGE, cc)
			return true
		}
		// match: (TBNZ [0] (LessThanF cc) yes no)
		// result: (FLT cc yes no)
		for b.Controls[0].Op == OpARM64LessThanF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64FLT, cc)
			return true
		}
		// match: (TBNZ [0] (LessEqualF cc) yes no)
		// result: (FLE cc yes no)
		for b.Controls[0].Op == OpARM64LessEqualF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64FLE, cc)
			return true
		}
		// match: (TBNZ [0] (GreaterThanF cc) yes no)
		// result: (FGT cc yes no)
		for b.Controls[0].Op == OpARM64GreaterThanF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64FGT, cc)
			return true
		}
		// match: (TBNZ [0] (GreaterEqualF cc) yes no)
		// result: (FGE cc yes no)
		for b.Controls[0].Op == OpARM64GreaterEqualF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			if auxIntToInt64(b.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockARM64FGE, cc)
			return true
		}
	case BlockARM64UGE:
		// match: (UGE (FlagConstant [fc]) yes no)
		// cond: fc.uge()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.uge()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (UGE (FlagConstant [fc]) yes no)
		// cond: !fc.uge()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.uge()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (UGE (InvertFlags cmp) yes no)
		// result: (ULE cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64ULE, cmp)
			return true
		}
	case BlockARM64UGT:
		// match: (UGT (FlagConstant [fc]) yes no)
		// cond: fc.ugt()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.ugt()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (UGT (FlagConstant [fc]) yes no)
		// cond: !fc.ugt()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.ugt()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (UGT (InvertFlags cmp) yes no)
		// result: (ULT cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64ULT, cmp)
			return true
		}
	case BlockARM64ULE:
		// match: (ULE (FlagConstant [fc]) yes no)
		// cond: fc.ule()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.ule()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (ULE (FlagConstant [fc]) yes no)
		// cond: !fc.ule()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.ule()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (ULE (InvertFlags cmp) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64UGE, cmp)
			return true
		}
	case BlockARM64ULT:
		// match: (ULT (FlagConstant [fc]) yes no)
		// cond: fc.ult()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.ult()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (ULT (FlagConstant [fc]) yes no)
		// cond: !fc.ult()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.ult()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (ULT (InvertFlags cmp) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64UGT, cmp)
			return true
		}
	case BlockARM64Z:
		// match: (Z (ANDconst [c] x) yes no)
		// cond: oneBit(c)
		// result: (TBZ [int64(ntz64(c))] x yes no)
		for b.Controls[0].Op == OpARM64ANDconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			x := v_0.Args[0]
			if !(oneBit(c)) {
				break
			}
			b.resetWithControl(BlockARM64TBZ, x)
			b.AuxInt = int64ToAuxInt(int64(ntz64(c)))
			return true
		}
		// match: (Z (MOVDconst [0]) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64MOVDconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (Z (MOVDconst [c]) yes no)
		// cond: c != 0
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64MOVDconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c != 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockARM64ZW:
		// match: (ZW (ANDconst [c] x) yes no)
		// cond: oneBit(int64(uint32(c)))
		// result: (TBZ [int64(ntz64(int64(uint32(c))))] x yes no)
		for b.Controls[0].Op == OpARM64ANDconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			x := v_0.Args[0]
			if !(oneBit(int64(uint32(c)))) {
				break
			}
			b.resetWithControl(BlockARM64TBZ, x)
			b.AuxInt = int64ToAuxInt(int64(ntz64(int64(uint32(c)))))
			return true
		}
		// match: (ZW (MOVDconst [c]) yes no)
		// cond: int32(c) == 0
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64MOVDconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(int32(c) == 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (ZW (MOVDconst [c]) yes no)
		// cond: int32(c) != 0
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64MOVDconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(int32(c) != 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	}
	return false
}
```