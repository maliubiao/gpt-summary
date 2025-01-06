Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understanding the Context:** The initial prompt tells us this is part of the `rewriteARM64.go` file within the Go compiler's SSA (Static Single Assignment) package. This immediately suggests that the code is involved in optimizing Go code for ARM64 architectures. The "rewrite" part implies that it's transforming the SSA representation of the code. The "part 11 of 20" is also crucial – it indicates this is a section of a larger set of transformations.

2. **Identifying the Core Functionality:**  The code primarily consists of several functions named `rewriteValueARM64_OpARM64...`. The suffix `OpARM64...` strongly suggests that each function handles optimizations or rewrites for specific ARM64 assembly instructions (or pseudo-instructions represented in the SSA).

3. **Analyzing Individual Functions:**  The core work happens inside each `rewriteValueARM64_OpARM64...` function. Let's take `rewriteValueARM64_OpARM64MULW` as an example:

    * **Input:** Each function takes a `*Value` as input. This `Value` likely represents a node in the SSA graph, corresponding to an operation.
    * **Matching Patterns:** The code uses `if` statements to check the `Op` field of the input `Value` and its arguments. This is pattern matching. The `// match:` comments clearly describe the pattern being looked for. For example, `// match: (MULW x (MOVDconst [c]))`. This means it's looking for a `MULW` operation where the second argument is a constant.
    * **Conditions:** After matching a pattern, there might be additional `// cond:` comments with boolean expressions. These specify further conditions that must be true for the rewrite to apply. For example, `// cond: c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)`.
    * **Rewriting:** If a match is found and the conditions are met, the code performs a rewrite. This usually involves:
        * `v.reset(...)`: Changing the operation of the current `Value` (`v`).
        * `b.NewValue0(...)`: Creating new `Value` nodes (representing new instructions).
        * `v.AddArg(...)` or `v.AddArg2(...)`:  Adding arguments to the current or newly created `Value` nodes.
        * `v.AuxInt = ...`: Setting auxiliary integer data associated with the `Value`.
        * `return true`:  Signaling that a rewrite occurred.
    * **Looping and Argument Order:** Some functions use nested loops (`for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0`) to handle commutative operations where the order of arguments doesn't matter.

4. **Inferring Functionality from Examples:**  Let's look at a specific rewrite within `rewriteValueARM64_OpARM64MULW`:

    ```go
    // match: (MULW x (MOVDconst [c]))
    // cond: c%3 == 0 && isPowerOfTwo(c/3) && is32Bit(c)
    // result: (SLLconst <x.Type> (ADDshiftLL <x.Type> x x [1]) [log64(c/3)])
    ```
    * **Input:** A 32-bit multiplication (`MULW`) where the second operand is a constant `c`.
    * **Condition:** The constant `c` must be divisible by 3, `c/3` must be a power of two, and `c` must fit in 32 bits.
    * **Output:**  The multiplication is rewritten as a left shift (`SLLconst`) of an addition with a left shift (`ADDshiftLL`). The `ADDshiftLL <x.Type> x x [1]` is equivalent to `x + (x << 1)`, which is `3 * x`. The outer `SLLconst` then multiplies by the remaining factor (`c/3`).

    This kind of analysis helps us understand that these rewrites are often about replacing a potentially expensive operation (like multiplication by an arbitrary constant) with a sequence of cheaper operations (shifts and additions) when the constant has a specific form.

5. **Identifying Common Optimization Themes:**  Across the different functions, we see recurring themes:

    * **Constant Folding:** Operations involving constants are often simplified (e.g., `MULW (MOVDconst [c]) (MOVDconst [d])` becomes `MOVDconst [int64(uint32(c*d))]`).
    * **Strength Reduction:** Replacing more expensive operations with cheaper ones (like multiplication with shifts and additions).
    * **Algebraic Simplification:** Applying algebraic identities (e.g., `MVN (XOR x y)` becomes `EON x y`).
    * **Bit Manipulation Optimizations:** Using specialized bit manipulation instructions like `BFI`, `BFXIL`, `EXTR`, etc., to perform operations more efficiently.
    * **Handling Commutativity:** The loops for commutative operations ensure that the rewrite rules apply regardless of the order of operands.

6. **Considering Command-line Arguments (If Applicable):**  While this specific snippet doesn't show direct command-line argument processing, it's good to know that the Go compiler has flags that control optimization levels. These flags would indirectly influence *whether* and *how* these rewrite rules are applied. For instance, a higher optimization level might enable more aggressive rewrites.

7. **Identifying Potential Pitfalls (If Applicable):**  In this low-level code, common pitfalls for *developers of the compiler* would be:

    * **Incorrect Conditions:**  A condition that's too broad could lead to incorrect transformations.
    * **Incorrect Rewrites:** A rewrite that doesn't produce the semantically equivalent result.
    * **Performance Regressions:**  A rewrite that, in some cases, might actually make the code slower.
    * **Introducing Bugs:** Incorrectly handling edge cases or types.

    For *users of Go*, they don't directly interact with this code. However, misunderstandings of how Go optimizations work *in general* could lead to unexpected performance characteristics in their code. This isn't a direct "easy mistake" with this specific snippet, but a broader concept.

8. **Synthesizing the Summary:**  Finally, based on the analysis, we can summarize the functionality. The key is to focus on the purpose of the code within the larger context of the Go compiler.

By following these steps, we can systematically analyze the provided Go code snippet and understand its role in the Go compiler's optimization process for ARM64 architectures. The key is to recognize the patterns, conditions, and rewrites, and then infer the underlying optimization strategies.
这段代码是 Go 语言编译器的一部分，具体来说，它位于 `go/src/cmd/compile/internal/ssa/rewriteARM64.go` 文件中，负责对 ARM64 架构的 SSA（Static Single Assignment）中间代码进行优化和转换。

**功能归纳 (针对提供的代码片段):**

这个代码片段主要定义了一系列针对 ARM64 架构特定指令的操作的重写规则（rewrite rules）。这些规则旨在将一些操作模式转换为更有效率或更符合 ARM64 硬件特性的指令序列。  这些重写规则涵盖了 `MULW` (32位乘法), `MVN` (按位取反), `NEG` (取负) 以及 `NotEqual` 和 `OR`, `ORN` 等逻辑运算。

**具体功能列举:**

1. **优化 32 位乘法 (`MULW`) 操作:**
   - 将乘以某些特定常数（例如 3, 5, 7, 9 的倍数且除以这些数后是 2 的幂）的乘法操作，转换为使用移位和加法指令的组合来实现，以提高效率。
   - 将两个常量相乘的 `MULW` 操作，直接计算结果并用 `MOVDconst` 指令加载常量结果。

2. **优化按位取反 (`MVN`) 操作:**
   - 将 `MVN (XOR x y)` 转换为 `EON x y` (按位异或非)。
   - 将 `MVN` 常量转换为直接加载取反后的常量。
   - 将 `MVN` 与移位操作结合的情况，转换为对应的 `MVNshiftLL`, `MVNshiftRL`, `MVNshiftRA`, `MVNshiftRO` 指令，这通常是 ARM64 架构提供的融合指令，更高效。

3. **优化取负 (`NEG`) 操作:**
   - 将对乘法结果取负的操作 (`NEG (MUL x y)`) 转换为 `MNEG x y` 指令。
   - 将对 32 位乘法结果取负的操作 (`NEG (MULW x y)`) 转换为 `MNEGW x y` 指令。
   - 将对取负操作再取负 (`NEG (NEG x)`) 简化为原值 `x`。
   - 将对常量取负的操作转换为直接加载负常量。
   - 将 `NEG` 与移位操作结合的情况，转换为对应的 `NEGshiftLL`, `NEGshiftRL`, `NEGshiftRA` 指令。

4. **优化不等于 (`NotEqual`) 比较操作:**
   - 将 `NotEqual` 与某些特定的比较模式结合，转换为更底层的 ARM64 比较指令，例如：
     - `NotEqual (CMPconst [0] z:(AND x y))`  转换为 `NotEqual (TST x y)` (位测试)。
     - `NotEqual (CMPWconst [0] x:(ANDconst [c] y))` 转换为 `NotEqual (TSTWconst [int32(c)] y)`。
     - `NotEqual (CMP x z:(NEG y))` 转换为 `NotEqual (CMN x y)` (加法比较)。
     - `NotEqual (CMPconst [0] x:(ADDconst [c] y))` 转换为 `NotEqual (CMNconst [c] y)`。
     - 涉及 `MADD` 和 `MSUB` 的比较也会进行相应的转换。
   - 将 `NotEqual` 一个 `FlagConstant` 转换为对应的布尔值（0 或 1）。
   - 将 `NotEqual (InvertFlags x)` 简化为 `NotEqual x`。

5. **优化按位或 (`OR`) 和按位或非 (`ORN`) 操作:**
   - 将 `OR` 操作与常量结合的情况，转换为 `ORconst` 指令。
   - 将 `OR x x` 简化为 `x`。
   - 将 `OR x (MVN y)` 转换为 `ORN x y`。
   - 将 `OR` 与移位操作结合的情况，转换为 `ORshiftLL`, `ORshiftRL`, `ORshiftRA`, `ORshiftRO` 指令。
   - 针对特定的位域操作模式，将 `OR` 与 `UBFIZ` 或 `UBFX` 以及 `ANDconst` 结合的情况，转换为 `BFI` 和 `BFXIL` 等更高效的位操作指令。
   - `ORN` 操作也有类似的针对常量和移位操作的优化。

**Go 语言功能推断与代码示例:**

这些重写规则的目标是优化底层的运算，对于上层 Go 语言代码来说是透明的。它们作用于编译器内部的 SSA 表示，最终生成更优的汇编代码。

**假设的输入与输出示例 (针对 `MULW` 优化):**

**输入 (SSA 代码片段):**

```
v1 = Const64 <int64> [15]
v2 = Local <int32>
v3 = Load <int32> v2
v4 = MULW <int32> v3 v1
```

**输出 (SSA 代码片段，经过 `rewriteARM64_OpARM64MULW` 优化后):**

```
v2 = Local <int32>
v3 = Load <int32> v2
v5 = ADDshiftLL <int32> v3 v3 [2]  // v3 + (v3 << 2)  相当于 v3 * 5
v4 = SLLconst <int32> v5 [1]      // v5 << 1  相当于 v5 * 2
```

**解释:**  假设乘数是 15 (3 * 5)，编译器会将 `MULW v3 v1` 转换为先计算 `v3 * 5` (使用 `ADDshiftLL` 实现)，然后再将结果左移 1 位 (乘以 2)，从而得到 `v3 * 10`，这里可能是一个简化的例子，实际的转换会更精确地匹配规则。

**假设的输入与输出示例 (针对 `MVN` 优化):**

**输入 (SSA 代码片段):**

```
v1 = Local <int64>
v2 = Load <int64> v1
v3 = XOR <int64> v2 c
v4 = MVN <int64> v3
```

**输出 (SSA 代码片段，经过 `rewriteValueARM64_OpARM64MVN` 优化后):**

```
v1 = Local <int64>
v2 = Load <int64> v1
v4 = EON <int64> v2 c
```

**解释:**  `MVN (XOR x y)` 被直接替换为 `EON x y`。

**命令行参数:**

这个代码片段本身不直接处理命令行参数。这些重写规则是 Go 编译器内部优化流程的一部分，当使用 `go build` 或 `go run` 等命令编译代码时，编译器会根据其内部的优化策略应用这些规则。  Go 编译器提供了一些命令行参数来控制优化级别，例如：

- `-gcflags="-N"`: 禁用所有优化。
- `-gcflags="-l"`: 禁用内联。
- `-o <output file>`: 指定输出文件。

更高的优化级别可能会触发更多的重写规则。

**使用者易犯错的点:**

作为 Go 语言的使用者，一般不会直接接触到这些底层的编译器重写规则。  易犯错的点更多是关于对编译器优化的理解和预期：

- **过度依赖或不信任编译器优化:**  有些开发者可能会尝试手动编写非常底层的代码来“帮助”编译器优化，但现代编译器通常比人工更擅长进行这些优化。  有时候手动优化的代码反而可能更难被编译器优化。
- **不理解编译器的优化策略:** 编译器的优化是基于一系列的启发式规则和分析，了解一些基本的优化原理（例如常量折叠、死代码消除、指令选择）有助于写出更易于编译器优化的代码。

**总结第 11 部分的功能:**

这段 `rewriteARM64.go` 的第 11 部分专注于针对 ARM64 架构的 `MULW`, `MVN`, `NEG`, `NotEqual`, `OR`, 和 `ORN` 等操作进行精细化的代码重写和优化。它通过模式匹配和条件判断，将这些操作的特定使用场景转换为更高效的 ARM64 指令序列，从而提升最终生成代码的性能。 这部分是整个 ARM64 代码生成和优化流程中的一个重要环节。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第11部分，共20部分，请归纳一下它的功能

"""
 int64ToAuxInt(2)
			v1.AddArg2(x, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)
	// result: (MOVWUreg (SLLconst <x.Type> [log64(c/7)] (ADDshiftLL <x.Type> (NEG <x.Type> x) x [3])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%7 == 0 && isPowerOfTwo(c/7) && is32Bit(c)) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c / 7))
			v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(3)
			v2 := b.NewValue0(v.Pos, OpARM64NEG, x.Type)
			v2.AddArg(x)
			v1.AddArg2(v2, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW x (MOVDconst [c]))
	// cond: c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)
	// result: (MOVWUreg (SLLconst <x.Type> [log64(c/9)] (ADDshiftLL <x.Type> x x [3])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(c%9 == 0 && isPowerOfTwo(c/9) && is32Bit(c)) {
				continue
			}
			v.reset(OpARM64MOVWUreg)
			v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
			v0.AuxInt = int64ToAuxInt(log64(c / 9))
			v1 := b.NewValue0(v.Pos, OpARM64ADDshiftLL, x.Type)
			v1.AuxInt = int64ToAuxInt(3)
			v1.AddArg2(x, x)
			v0.AddArg(v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MULW (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [int64(uint32(c*d))])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64MOVDconst)
			v.AuxInt = int64ToAuxInt(int64(uint32(c * d)))
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64MVN(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVN (XOR x y))
	// result: (EON x y)
	for {
		if v_0.Op != OpARM64XOR {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64EON)
		v.AddArg2(x, y)
		return true
	}
	// match: (MVN (MOVDconst [c]))
	// result: (MOVDconst [^c])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^c)
		return true
	}
	// match: (MVN x:(SLLconst [c] y))
	// cond: clobberIfDead(x)
	// result: (MVNshiftLL [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64MVNshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (MVN x:(SRLconst [c] y))
	// cond: clobberIfDead(x)
	// result: (MVNshiftRL [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64MVNshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (MVN x:(SRAconst [c] y))
	// cond: clobberIfDead(x)
	// result: (MVNshiftRA [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64MVNshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (MVN x:(RORconst [c] y))
	// cond: clobberIfDead(x)
	// result: (MVNshiftRO [c] y)
	for {
		x := v_0
		if x.Op != OpARM64RORconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64MVNshiftRO)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MVNshiftLL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftLL (MOVDconst [c]) [d])
	// result: (MOVDconst [^int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) << uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MVNshiftRA(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftRA (MOVDconst [c]) [d])
	// result: (MOVDconst [^(c>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^(c >> uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MVNshiftRL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftRL (MOVDconst [c]) [d])
	// result: (MOVDconst [^int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) >> uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64MVNshiftRO(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MVNshiftRO (MOVDconst [c]) [d])
	// result: (MOVDconst [^rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(^rotateRight64(c, d))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NEG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEG (MUL x y))
	// result: (MNEG x y)
	for {
		if v_0.Op != OpARM64MUL {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64MNEG)
		v.AddArg2(x, y)
		return true
	}
	// match: (NEG (MULW x y))
	// cond: v.Type.Size() <= 4
	// result: (MNEGW x y)
	for {
		if v_0.Op != OpARM64MULW {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(v.Type.Size() <= 4) {
			break
		}
		v.reset(OpARM64MNEGW)
		v.AddArg2(x, y)
		return true
	}
	// match: (NEG (NEG x))
	// result: x
	for {
		if v_0.Op != OpARM64NEG {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (NEG (MOVDconst [c]))
	// result: (MOVDconst [-c])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-c)
		return true
	}
	// match: (NEG x:(SLLconst [c] y))
	// cond: clobberIfDead(x)
	// result: (NEGshiftLL [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64NEGshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (NEG x:(SRLconst [c] y))
	// cond: clobberIfDead(x)
	// result: (NEGshiftRL [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64NEGshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	// match: (NEG x:(SRAconst [c] y))
	// cond: clobberIfDead(x)
	// result: (NEGshiftRA [c] y)
	for {
		x := v_0
		if x.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(clobberIfDead(x)) {
			break
		}
		v.reset(OpARM64NEGshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NEGshiftLL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGshiftLL (MOVDconst [c]) [d])
	// result: (MOVDconst [-int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-int64(uint64(c) << uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NEGshiftRA(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGshiftRA (MOVDconst [c]) [d])
	// result: (MOVDconst [-(c>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-(c >> uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NEGshiftRL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (NEGshiftRL (MOVDconst [c]) [d])
	// result: (MOVDconst [-int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-int64(uint64(c) >> uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64NotEqual(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (NotEqual (CMPconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (TST x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TST, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (NotEqual (TSTWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (TSTW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (NotEqual (TSTconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMP x z:(NEG y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMN x y))
	for {
		if v_0.Op != OpARM64CMP {
			break
		}
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPW x z:(NEG y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMNW x y))
	for {
		if v_0.Op != OpARM64CMPW {
			break
		}
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (NotEqual (CMNconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (NotEqual (CMNWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMN x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64ADD {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMNW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64ADD {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] z:(MADD a x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMN a (MUL <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPconst [0] z:(MSUB a x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMP a (MUL <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] z:(MADDW a x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMNW a (MULW <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (CMPWconst [0] z:(MSUBW a x y)))
	// cond: z.Uses == 1
	// result: (NotEqual (CMPW a (MULW <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
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
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (NotEqual (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.ne())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.ne()))
		return true
	}
	// match: (NotEqual (InvertFlags x))
	// result: (NotEqual x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64NotEqual)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64OR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (OR x (MOVDconst [c]))
	// result: (ORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64ORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (OR x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (OR x (MVN y))
	// result: (ORN x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MVN {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpARM64ORN)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (OR x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORshiftLL x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SLLconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64ORshiftLL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (OR x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORshiftRL x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SRLconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64ORshiftRL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (OR x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORshiftRA x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SRAconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64ORshiftRA)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (OR x0 x1:(RORconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORshiftRO x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64RORconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64ORshiftRO)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (OR (UBFIZ [bfc] x) (ANDconst [ac] y))
	// cond: ac == ^((1<<uint(bfc.width())-1) << uint(bfc.lsb()))
	// result: (BFI [bfc] y x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64UBFIZ {
				continue
			}
			bfc := auxIntToArm64BitField(v_0.AuxInt)
			x := v_0.Args[0]
			if v_1.Op != OpARM64ANDconst {
				continue
			}
			ac := auxIntToInt64(v_1.AuxInt)
			y := v_1.Args[0]
			if !(ac == ^((1<<uint(bfc.width()) - 1) << uint(bfc.lsb()))) {
				continue
			}
			v.reset(OpARM64BFI)
			v.AuxInt = arm64BitFieldToAuxInt(bfc)
			v.AddArg2(y, x)
			return true
		}
		break
	}
	// match: (OR (UBFX [bfc] x) (ANDconst [ac] y))
	// cond: ac == ^(1<<uint(bfc.width())-1)
	// result: (BFXIL [bfc] y x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64UBFX {
				continue
			}
			bfc := auxIntToArm64BitField(v_0.AuxInt)
			x := v_0.Args[0]
			if v_1.Op != OpARM64ANDconst {
				continue
			}
			ac := auxIntToInt64(v_1.AuxInt)
			y := v_1.Args[0]
			if !(ac == ^(1<<uint(bfc.width()) - 1)) {
				continue
			}
			v.reset(OpARM64BFXIL)
			v.AuxInt = arm64BitFieldToAuxInt(bfc)
			v.AddArg2(y, x)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64ORN(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORN x (MOVDconst [c]))
	// result: (ORconst [^c] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^c)
		v.AddArg(x)
		return true
	}
	// match: (ORN x x)
	// result: (MOVDconst [-1])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORN x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORNshiftLL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64ORNshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (ORN x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORNshiftRL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64ORNshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (ORN x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORNshiftRA x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64ORNshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (ORN x0 x1:(RORconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (ORNshiftRO x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64RORconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64ORNshiftRO)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORNshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORNshiftLL x (MOVDconst [c]) [d])
	// result: (ORconst x [^int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORNshiftLL (SLLconst x [c]) x [c])
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORNshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORNshiftRA x (MOVDconst [c]) [d])
	// result: (ORconst x [^(c>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^(c >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORNshiftRA (SRAconst x [c]) x [c])
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRAconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORNshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORNshiftRL x (MOVDconst [c]) [d])
	// result: (ORconst x [^int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORNshiftRL (SRLconst x [c]) x [c])
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORNshiftRO(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ORNshiftRO x (MOVDconst [c]) [d])
	// result: (ORconst x [^rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(^rotateRight64(c, d))
		v.AddArg(x)
		return true
	}
	// match: (ORNshiftRO (RORconst x [c]) x [c])
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64RORconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ORconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ORconst [-1] _)
	// result: (MOVDconst [-1])
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (ORconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c|d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(c | d)
		return true
	}
	// match: (ORconst [c] (ORconst [d] x))
	// result: (ORconst [c|d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	// match: (ORconst [c1] (ANDconst [c2] x))
	// cond: c2|c1 == ^0
	// result: (ORconst [c1] x)
	for {
		c1 := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c2|c1 == ^0) {
			break
		}
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c1)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ORshiftLL (MOVDconst [c]) x [d])
	// result: (ORconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftLL x (MOVDconst [c]) [d])
	// result: (ORconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftLL y:(SLLconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpARM64SLLconst || auxIntToInt64(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ORshiftLL <typ.UInt16> [8] (UBFX <typ.UInt16> [armBFAuxInt(8, 8)] x) x)
	// result: (REV16W x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt64(v.AuxInt) != 8 || v_0.Op != OpARM64UBFX || v_0.Type != typ.UInt16 || auxIntToArm64BitField(v_0.AuxInt) != armBFAuxInt(8, 8) {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64REV16W)
		v.AddArg(x)
		return true
	}
	// match: (ORshiftLL [8] (UBFX [armBFAuxInt(8, 24)] (ANDconst [c1] x)) (ANDconst [c2] x))
	// cond: uint32(c1) == 0xff00ff00 && uint32(c2) == 0x00ff00ff
	// result: (REV16W x)
	for {
		if auxIntToInt64(v.AuxInt) != 8 || v_0.Op != OpARM64UBFX || auxIntToArm64BitField(v_0.AuxInt) != armBFAuxInt(8, 24) {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARM64ANDconst {
			break
		}
		c1 := auxIntToInt64(v_0_0.AuxInt)
		x := v_0_0.Args[0]
		if v_1.Op != OpARM64ANDconst {
			break
		}
		c2 := auxIntToInt64(v_1.AuxInt)
		if x != v_1.Args[0] || !(uint32(c1) == 0xff00ff00 && uint32(c2) == 0x00ff00ff) {
			break
		}
		v.reset(OpARM64REV16W)
		v.AddArg(x)
		return true
	}
	// match: (ORshiftLL [8] (SRLconst [8] (ANDconst [c1] x)) (ANDconst [c2] x))
	// cond: (uint64(c1) == 0xff00ff00ff00ff00 && uint64(c2) == 0x00ff00ff00ff00ff)
	// result: (REV16 x)
	for {
		if auxIntToInt64(v.AuxInt) != 8 || v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != 8 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARM64ANDconst {
			break
		}
		c1 := auxIntToInt64(v_0_0.AuxInt)
		x := v_0_0.Args[0]
		if v_1.Op != OpARM64ANDconst {
			break
		}
		c2 := auxIntToInt64(v_1.AuxInt)
		if x != v_1.Args[0] || !(uint64(c1) == 0xff00ff00ff00ff00 && uint64(c2) == 0x00ff00ff00ff00ff) {
			break
		}
		v.reset(OpARM64REV16)
		v.AddArg(x)
		return true
	}
	// match: (ORshiftLL [8] (SRLconst [8] (ANDconst [c1] x)) (ANDconst [c2] x))
	// cond: (uint64(c1) == 0xff00ff00 && uint64(c2) == 0x00ff00ff)
	// result: (REV16 (ANDconst <x.Type> [0xffffffff] x))
	for {
		if auxIntToInt64(v.AuxInt) != 8 || v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != 8 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARM64ANDconst {
			break
		}
		c1 := auxIntToInt64(v_0_0.AuxInt)
		x := v_0_0.Args[0]
		if v_1.Op != OpARM64ANDconst {
			break
		}
		c2 := auxIntToInt64(v_1.AuxInt)
		if x != v_1.Args[0] || !(uint64(c1) == 0xff00ff00 && uint64(c2) == 0x00ff00ff) {
			break
		}
		v.reset(OpARM64REV16)
		v0 := b.NewValue0(v.Pos, OpARM64ANDconst, x.Type)
		v0.AuxInt = int64ToAuxInt(0xffffffff)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: ( ORshiftLL [c] (SRLconst x [64-c]) x2)
	// result: (EXTRconst [64-c] x2 x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != 64-c {
			break
		}
		x := v_0.Args[0]
		x2 := v_1
		v.reset(OpARM64EXTRconst)
		v.AuxInt = int64ToAuxInt(64 - c)
		v.AddArg2(x2, x)
		return true
	}
	// match: ( ORshiftLL <t> [c] (UBFX [bfc] x) x2)
	// cond: c < 32 && t.Size() == 4 && bfc == armBFAuxInt(32-c, c)
	// result: (EXTRWconst [32-c] x2 x)
	for {
		t := v.Type
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		x2 := v_1
		if !(c < 32 && t.Size() == 4 && bfc == armBFAuxInt(32-c, c)) {
			break
		}
		v.reset(OpARM64EXTRWconst)
		v.AuxInt = int64ToAuxInt(32 - c)
		v.AddArg2(x2, x)
		return true
	}
	// match: (ORshiftLL [s] (ANDconst [xc] x) (ANDconst [yc] y))
	// cond: xc == ^(yc << s) && yc & (yc+1) == 0 && yc > 0 && s+log64(yc+1) <= 64
	// result: (BFI [armBFAuxInt(s, log64(yc+1))] x y)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		xc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if v_1.Op != OpARM64ANDconst {
			break
		}
		yc := auxIntToInt64(v_1.AuxInt)
		y := v_1.Args[0]
		if !(xc == ^(yc<<s) && yc&(yc+1) == 0 && yc > 0 && s+log64(yc+1) <= 64) {
			break
		}
		v.reset(OpARM64BFI)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(s, log64(yc+1)))
		v.AddArg2(x, y)
		return true
	}
	// match: (ORshiftLL [sc] (UBFX [bfc] x) (SRLconst [sc] y))
	// cond: sc == bfc.width()
	// result: (BFXIL [bfc] y x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if v_1.Op != OpARM64SRLconst || auxIntToInt64(v_1.AuxInt) != sc {
			break
		}
		y := v_1.Args[0]
		if !(sc == bfc.width()) {
			break
		}
		v.reset(OpARM64BFXIL)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRA (MOVDconst [c]) x [d])
	// result: (ORconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRAconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRA x (MOVDconst [c]) [d])
	// result: (ORconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op 
"""




```