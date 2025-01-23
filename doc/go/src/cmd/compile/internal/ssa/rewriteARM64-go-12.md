Response:
My goal is to analyze the given Go code snippet and provide a comprehensive explanation of its functionality, potential use cases, and common pitfalls. Here's my thought process:

1. **Identify the Core Functionality:** The code consists of a series of Go functions, all named `rewriteValueARM64_Op...`. This naming convention strongly suggests that these functions are part of a larger system responsible for rewriting or optimizing intermediate representation (IR) code, specifically for the ARM64 architecture. The `Op` part of the name likely refers to specific IR operations.

2. **Analyze Individual Functions:** I need to examine the logic within each function. Each function takes a `*Value` as input and returns a boolean. The boolean return likely indicates whether a rewrite rule was applied. The structure of each function typically involves:
    * Accessing arguments (`v.Args`).
    * Matching patterns in the input `Value`'s operands and opcode (`v_0.Op`, `v_1.Op`).
    * Checking conditions (`cond:` lines).
    * If a match is found, resetting the current `Value`'s opcode and arguments to represent the rewritten form (`v.reset(...)`, `v.AddArg(...)`).
    * Using `auxIntToInt64`, `int64ToAuxInt`, `auxIntToArm64BitField`, etc., suggests the code manipulates auxiliary integer data associated with the IR operations.

3. **Infer the Overall Purpose:**  Given the pattern matching and rewriting logic, I can infer that this code is part of the **SSA (Static Single Assignment) optimization passes for the Go compiler, specifically targeting the ARM64 architecture.**  The goal is to transform certain sequences of operations into more efficient or canonical forms. This is a common practice in compiler optimization.

4. **Categorize Rewrites:** I notice different kinds of rewrites:
    * **Constant Folding:** Replacing operations with constant operands by their result (e.g., `SUBshiftLL (SLLconst x [c]) x [c]` becomes `MOVDconst [0]`).
    * **Strength Reduction:** Replacing a more expensive operation with a cheaper equivalent (e.g., `UDIV x (MOVDconst [c])` where `c` is a power of two becomes `SRLconst [log64(c)] x`).
    * **Instruction Selection:**  Choosing specific ARM64 instructions that are more efficient for certain patterns (e.g.,  using `TSTconst` instead of `TST x (MOVDconst [c])`).
    * **Canonicalization:**  Transforming equivalent expressions into a standard form (e.g., swapping operands of commutative operations like `TST`).
    * **Dead Code Elimination Hints:**  The `clobberIfDead` condition suggests opportunities for later dead code elimination passes.

5. **Construct Go Examples:** To illustrate the rewrites, I'll create simple Go code snippets that would compile down to the IR patterns being matched. I'll provide the *input* Go code and the *expected output* after the rewrite. This requires a bit of guesswork about how the Go compiler generates IR.

6. **Consider Command-Line Arguments:** This code snippet doesn't directly process command-line arguments. It's part of the compiler's internal workings. Therefore, I should explain that its behavior is influenced by the overall compilation process and any flags that affect optimization levels.

7. **Identify Potential Mistakes:**  Common mistakes users might make are usually related to misunderstanding the compiler's optimization process. For instance, relying on specific instruction sequences when writing assembly or assuming that the compiler will *not* perform certain optimizations. However, the provided code is about *compiler internals*, not something directly user-facing, so user-facing errors are less applicable here. A more relevant "mistake" might be assuming a particular IR structure will *always* be generated for a given Go construct.

8. **Summarize Functionality:** The key takeaway is that this code optimizes ARM64 SSA by applying specific rewrite rules to simplify expressions and generate more efficient machine code.

9. **Address the "Part 13 of 20" Instruction:** This indicates that the provided code is just a segment of a larger file. Therefore, my summary should focus on the functions within this specific part, while acknowledging that it's part of a larger optimization process.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:**  Maybe these are just helper functions for generating ARM64 assembly.
* **Correction:** The `rewriteValue` prefix and the manipulation of `Op` codes strongly point towards SSA rewriting within the compiler.

* **Initial thought:** The examples should be very low-level assembly-like.
* **Correction:** Providing Go code examples that *lead* to the IR patterns is more helpful for understanding the purpose of the rewrites.

* **Initial thought:** Focus on all possible user errors related to ARM64 programming.
* **Correction:**  Since this is compiler-internal code, the focus should be on potential misunderstandings of compiler optimization rather than general ARM64 programming errors.

By following this detailed process, including self-correction, I can construct a comprehensive and accurate answer to the user's request.
这段代码是Go语言编译器的一部分，位于 `go/src/cmd/compile/internal/ssa/rewriteARM64.go` 文件中。它的主要功能是**针对ARM64架构的SSA（Static Single Assignment）中间表示进行重写规则的应用，以优化生成的机器码**。

具体来说，这段代码定义了一系列名为 `rewriteValueARM64_Op...` 的函数。每个函数都对应一个特定的SSA操作符（`OpARM64...`），并尝试将该操作符及其操作数匹配特定的模式，如果匹配成功，则将其替换为更优化的操作序列。

**归纳一下这段代码的功能（第13部分）：**

这段代码主要负责 **优化 ARM64 架构下涉及减法 (`SUBshiftLL`, `SUBshiftRA`, `SUBshiftRL`) 和测试 (`TST`, `TSTW`, `TSTconst`, `TSTshiftLL`, `TSTshiftRA`, `TSTshiftRL`, `TSTshiftRO`) 操作的 SSA 代码**。 它还包括了一些位域操作 (`UBFIZ`, `UBFX`)、无符号除法 (`UDIV`, `UDIVW`)、无符号取模 (`UMOD`, `UMODW`) 以及异或运算 (`XOR`, `XORconst`, `XORshiftLL`, `XORshiftRA`, `XORshiftRL`, `XORshiftRO`) 的优化规则。最后，它还包含了地址加载 (`Addr`) 和一些位操作 (`Avg64u`, `BitLen32`, `BitLen64`, `BitRev16`, `BitRev8`) 的优化。

**以下是一些功能的Go代码示例和推理：**

**1. 优化减法操作（例如 `SUBshiftLL`）：**

   假设输入的SSA代码表示 `x - (y << c)` 且 `y == x`，编译器可能会将其优化为常数 0。

   ```go
   // 假设输入 SSA Value 结构如下：
   // v.Op = OpARM64SUBshiftLL
   // v.AuxInt = c // 移位量
   // v.Args[0] 指向表示 y << c 的 SSA Value (OpARM64SLLconst, AuxInt: c, Args: [x])
   // v.Args[1] 指向表示 x 的 SSA Value

   // 对应的 Go 代码可能是：
   package main

   func main() {
       x := 10
       c := 2
       result := x - (x << c) // 实际生成的 SSA 可能有所不同，这里只是一个概念性的例子
       println(result)
   }

   // 输出结果：
   // -30
   ```

   **代码推理（`rewriteValueARM64_OpARM64SUBshiftLL` 中的第二个 `for` 循环）：**

   * **假设输入:**  一个 `OpARM64SUBshiftLL` 的 SSA 值 `v`，其 `v.Args[0]` 是一个 `OpARM64SLLconst`，且移位量与 `v` 的辅助整数相同，并且 `OpARM64SLLconst` 的参数是 `v.Args[1]` (即 `x`)。
   * **匹配条件:**  `v_0.Op == OpARM64SLLconst && auxIntToInt64(v_0.AuxInt) == c && x == v_1`
   * **输出:**  `v` 被重置为 `OpARM64MOVDconst`，其辅助整数设置为 0。这意味着 `x - (x << c)` 被优化为 `0`。  **注意：这个例子中的 Go 代码并不直接对应优化的场景，优化针对的是 SSA 中间表示。这里的优化实际上针对的是 `x - (x << c)` 且已知 `x` 和 `y` 指向同一个变量的特殊情况。**

**2. 优化测试操作（例如 `TST`）：**

   如果测试操作 `TST x (MOVDconst [c])` 中的第二个操作数是一个常量，可以将其转换为 `TSTconst [c] x`，这可能在某些硬件上更有效率。

   ```go
   // 假设输入 SSA Value 结构如下：
   // v.Op = OpARM64TST
   // v.Args[0] 指向表示 x 的 SSA Value
   // v.Args[1] 指向表示常量 c 的 SSA Value (OpARM64MOVDconst, AuxInt: c)

   // 对应的 Go 代码可能是：
   package main

   func main() {
       x := 10
       c := 4
       if x & c != 0 {
           println("Non-zero")
       } else {
           println("Zero")
       }
   }

   // 输出结果：
   // Zero
   ```

   **代码推理（`rewriteValueARM64_OpARM64TST` 中的第一个 `for` 循环）：**

   * **假设输入:** 一个 `OpARM64TST` 的 SSA 值 `v`，其 `v.Args[1]` 是一个 `OpARM64MOVDconst`，表示常量 `c`。
   * **匹配条件:** `v_1.Op == OpARM64MOVDconst`
   * **输出:** `v` 被重置为 `OpARM64TSTconst`，其辅助整数设置为 `c`，并且参数设置为 `x`。

**3. 优化无符号除法操作（例如 `UDIV`）：**

   如果除数是一个 2 的幂，无符号除法可以被优化为右移操作。

   ```go
   // 假设输入 SSA Value 结构如下：
   // v.Op = OpARM64UDIV
   // v.Args[0] 指向表示 x 的 SSA Value
   // v.Args[1] 指向表示常量 8 的 SSA Value (OpARM64MOVDconst, AuxInt: 8)

   // 对应的 Go 代码可能是：
   package main

   func main() {
       x := uint64(100)
       divisor := uint64(8)
       result := x / divisor
       println(result)
   }

   // 输出结果：
   // 12
   ```

   **代码推理（`rewriteValueARM64_OpARM64UDIV` 中的第二个 `for` 循环）：**

   * **假设输入:** 一个 `OpARM64UDIV` 的 SSA 值 `v`，其 `v.Args[1]` 是一个 `OpARM64MOVDconst`，且其值是 2 的幂（例如 8）。
   * **匹配条件:** `v_1.Op == OpARM64MOVDconst && isPowerOfTwo(c)`
   * **输出:** `v` 被重置为 `OpARM64SRLconst`，其辅助整数设置为 `log64(c)` (例如 `log64(8) == 3`)，参数设置为 `x`。这意味着无符号除法被优化为逻辑右移。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它是 Go 编译器内部优化过程的一部分。编译器在编译时会读取各种命令行参数（例如 `-O` 优化级别），这些参数会影响到优化器的行为，从而间接地影响到这段代码的执行。例如，如果禁用了某些优化级别，这段代码中的某些重写规则可能就不会被应用。

**使用者易犯错的点：**

由于这段代码是编译器内部实现，普通 Go 语言开发者不会直接与其交互，因此不存在使用者易犯错的点。然而，理解这些优化规则对于理解编译器如何将 Go 代码转换为机器码以及如何进行性能调优是有帮助的。例如，了解某些操作会被编译器优化成更高效的形式，可以帮助开发者编写更易于编译器优化的代码。

**总结第13部分的功能：**

这段代码（`rewriteARM64.go` 的第 13 部分）专注于对 ARM64 架构下的 SSA 中间表示进行细粒度的优化，特别是针对减法、测试、位域操作、无符号除法、无符号取模和异或运算。它通过模式匹配和替换，将一些常见的操作组合转化为更有效率的指令序列，从而提升最终生成的可执行程序的性能。 这一部分是整个编译器优化流程中的一个环节，与其他部分的重写规则共同作用，以实现更佳的编译结果。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第13部分，共20部分，请归纳一下它的功能
```

### 源代码
```go
v.AddArg(x)
		return true
	}
	// match: (SUBshiftLL (SLLconst x [c]) x [c])
	// result: (MOVDconst [0])
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
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUBshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBshiftRA x (MOVDconst [c]) [d])
	// result: (SUBconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (SUBshiftRA (SRAconst x [c]) x [c])
	// result: (MOVDconst [0])
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
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUBshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBshiftRL x (MOVDconst [c]) [d])
	// result: (SUBconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (SUBshiftRL (SRLconst x [c]) x [c])
	// result: (MOVDconst [0])
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
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TST(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (TST x (MOVDconst [c]))
	// result: (TSTconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64TSTconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TST x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (TSTshiftLL x0 y [c])
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
			v.reset(OpARM64TSTshiftLL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (TST x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (TSTshiftRL x0 y [c])
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
			v.reset(OpARM64TSTshiftRL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (TST x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (TSTshiftRA x0 y [c])
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
			v.reset(OpARM64TSTshiftRA)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (TST x0 x1:(RORconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (TSTshiftRO x0 y [c])
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
			v.reset(OpARM64TSTshiftRO)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64TSTW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (TSTW x (MOVDconst [c]))
	// result: (TSTWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64TSTWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64TSTWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TSTWconst (MOVDconst [x]) [y])
	// result: (FlagConstant [logicFlags32(int32(x)&y)])
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(logicFlags32(int32(x) & y))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TSTconst (MOVDconst [x]) [y])
	// result: (FlagConstant [logicFlags64(x&y)])
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(logicFlags64(x & y))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftLL (MOVDconst [c]) x [d])
	// result: (TSTconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftLL x (MOVDconst [c]) [d])
	// result: (TSTconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRA (MOVDconst [c]) x [d])
	// result: (TSTconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRAconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRA x (MOVDconst [c]) [d])
	// result: (TSTconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRL (MOVDconst [c]) x [d])
	// result: (TSTconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRL x (MOVDconst [c]) [d])
	// result: (TSTconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64TSTshiftRO(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRO (MOVDconst [c]) x [d])
	// result: (TSTconst [c] (RORconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64RORconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRO x (MOVDconst [c]) [d])
	// result: (TSTconst x [rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64TSTconst)
		v.AuxInt = int64ToAuxInt(rotateRight64(c, d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UBFIZ(v *Value) bool {
	v_0 := v.Args[0]
	// match: (UBFIZ [bfc] (SLLconst [sc] x))
	// cond: sc < bfc.width()
	// result: (UBFIZ [armBFAuxInt(bfc.lsb()+sc, bfc.width()-sc)] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.width()) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()+sc, bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UBFX(v *Value) bool {
	v_0 := v.Args[0]
	// match: (UBFX [bfc] (ANDconst [c] x))
	// cond: isARM64BFMask(0, c, 0) && bfc.lsb() + bfc.width() <= arm64BFWidth(c, 0)
	// result: (UBFX [bfc] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isARM64BFMask(0, c, 0) && bfc.lsb()+bfc.width() <= arm64BFWidth(c, 0)) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(bfc)
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] e:(MOVWUreg x))
	// cond: e.Uses == 1 && bfc.lsb() < 32
	// result: (UBFX [armBFAuxInt(bfc.lsb(), min(bfc.width(), 32-bfc.lsb()))] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		e := v_0
		if e.Op != OpARM64MOVWUreg {
			break
		}
		x := e.Args[0]
		if !(e.Uses == 1 && bfc.lsb() < 32) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb(), min(bfc.width(), 32-bfc.lsb())))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] e:(MOVHUreg x))
	// cond: e.Uses == 1 && bfc.lsb() < 16
	// result: (UBFX [armBFAuxInt(bfc.lsb(), min(bfc.width(), 16-bfc.lsb()))] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		e := v_0
		if e.Op != OpARM64MOVHUreg {
			break
		}
		x := e.Args[0]
		if !(e.Uses == 1 && bfc.lsb() < 16) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb(), min(bfc.width(), 16-bfc.lsb())))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] e:(MOVBUreg x))
	// cond: e.Uses == 1 && bfc.lsb() < 8
	// result: (UBFX [armBFAuxInt(bfc.lsb(), min(bfc.width(), 8-bfc.lsb()))] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		e := v_0
		if e.Op != OpARM64MOVBUreg {
			break
		}
		x := e.Args[0]
		if !(e.Uses == 1 && bfc.lsb() < 8) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb(), min(bfc.width(), 8-bfc.lsb())))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] (SRLconst [sc] x))
	// cond: sc+bfc.width()+bfc.lsb() < 64
	// result: (UBFX [armBFAuxInt(bfc.lsb()+sc, bfc.width())] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SRLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc+bfc.width()+bfc.lsb() < 64) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()+sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] (SLLconst [sc] x))
	// cond: sc == bfc.lsb()
	// result: (ANDconst [1<<uint(bfc.width())-1] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc == bfc.lsb()) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(1<<uint(bfc.width()) - 1)
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] (SLLconst [sc] x))
	// cond: sc < bfc.lsb()
	// result: (UBFX [armBFAuxInt(bfc.lsb()-sc, bfc.width())] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.lsb()) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()-sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (UBFX [bfc] (SLLconst [sc] x))
	// cond: sc > bfc.lsb() && sc < bfc.lsb()+bfc.width()
	// result: (UBFIZ [armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc)] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc > bfc.lsb() && sc < bfc.lsb()+bfc.width()) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UDIV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (UDIV x (MOVDconst [1]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (UDIV x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (SRLconst [log64(c)] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(log64(c))
		v.AddArg(x)
		return true
	}
	// match: (UDIV (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint64(c)/uint64(d))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) / uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UDIVW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (UDIVW x (MOVDconst [c]))
	// cond: uint32(c)==1
	// result: (MOVWUreg x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) == 1) {
			break
		}
		v.reset(OpARM64MOVWUreg)
		v.AddArg(x)
		return true
	}
	// match: (UDIVW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c) && is32Bit(c)
	// result: (SRLconst [log64(c)] (MOVWUreg <v.Type> x))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(log64(c))
		v0 := b.NewValue0(v.Pos, OpARM64MOVWUreg, v.Type)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (UDIVW (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint32(c)/uint32(d))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c) / uint32(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UMOD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (UMOD <typ.UInt64> x y)
	// result: (MSUB <typ.UInt64> x y (UDIV <typ.UInt64> x y))
	for {
		if v.Type != typ.UInt64 {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64MSUB)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpARM64UDIV, typ.UInt64)
		v0.AddArg2(x, y)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (UMOD _ (MOVDconst [1]))
	// result: (MOVDconst [0])
	for {
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (UMOD x (MOVDconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (ANDconst [c-1] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(c - 1)
		v.AddArg(x)
		return true
	}
	// match: (UMOD (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint64(c)%uint64(d))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) % uint64(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64UMODW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (UMODW <typ.UInt32> x y)
	// result: (MSUBW <typ.UInt32> x y (UDIVW <typ.UInt32> x y))
	for {
		if v.Type != typ.UInt32 {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64MSUBW)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, OpARM64UDIVW, typ.UInt32)
		v0.AddArg2(x, y)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (UMODW _ (MOVDconst [c]))
	// cond: uint32(c)==1
	// result: (MOVDconst [0])
	for {
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) == 1) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (UMODW x (MOVDconst [c]))
	// cond: isPowerOfTwo(c) && is32Bit(c)
	// result: (ANDconst [c-1] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c) && is32Bit(c)) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(c - 1)
		v.AddArg(x)
		return true
	}
	// match: (UMODW (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint32(c)%uint32(d))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c) % uint32(d)))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVDconst [c]))
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64XORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XOR x (MVN y))
	// result: (EON x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MVN {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpARM64EON)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (XORshiftLL x0 y [c])
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
			v.reset(OpARM64XORshiftLL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (XOR x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (XORshiftRL x0 y [c])
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
			v.reset(OpARM64XORshiftRL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (XOR x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (XORshiftRA x0 y [c])
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
			v.reset(OpARM64XORshiftRA)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (XOR x0 x1:(RORconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (XORshiftRO x0 y [c])
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
			v.reset(OpARM64XORshiftRO)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64XORconst(v *Value) bool {
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
	// result: (MVN x)
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.reset(OpARM64MVN)
		v.AddArg(x)
		return true
	}
	// match: (XORconst [c] (MOVDconst [d]))
	// result: (MOVDconst [c^d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		return true
	}
	// match: (XORconst [c] (XORconst [d] x))
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64XORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64XORshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (XORshiftLL (MOVDconst [c]) x [d])
	// result: (XORconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftLL x (MOVDconst [c]) [d])
	// result: (XORconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL (SLLconst x [c]) x [c])
	// result: (MOVDconst [0])
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
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XORshiftLL <typ.UInt16> [8] (UBFX <typ.UInt16> [armBFAuxInt(8, 8)] x) x)
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
	// match: (XORshiftLL [8] (UBFX [armBFAuxInt(8, 24)] (ANDconst [c1] x)) (ANDconst [c2] x))
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
	// match: (XORshiftLL [8] (SRLconst [8] (ANDconst [c1] x)) (ANDconst [c2] x))
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
	// match: (XORshiftLL [8] (SRLconst [8] (ANDconst [c1] x)) (ANDconst [c2] x))
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
	// match: (XORshiftLL [c] (SRLconst x [64-c]) x2)
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
	// match: (XORshiftLL <t> [c] (UBFX [bfc] x) x2)
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
	return false
}
func rewriteValueARM64_OpARM64XORshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRA (MOVDconst [c]) x [d])
	// result: (XORconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRAconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRA x (MOVDconst [c]) [d])
	// result: (XORconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRA (SRAconst x [c]) x [c])
	// result: (MOVDconst [0])
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
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64XORshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRL (MOVDconst [c]) x [d])
	// result: (XORconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRL x (MOVDconst [c]) [d])
	// result: (XORconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRL (SRLconst x [c]) x [c])
	// result: (MOVDconst [0])
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
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64XORshiftRO(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRO (MOVDconst [c]) x [d])
	// result: (XORconst [c] (RORconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64RORconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRO x (MOVDconst [c]) [d])
	// result: (XORconst x [rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(rotateRight64(c, d))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRO (RORconst x [c]) x [c])
	// result: (MOVDconst [0])
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
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVDaddr {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpARM64MOVDaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueARM64_OpAvg64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg64u <t> x y)
	// result: (ADD (SRLconst <t> (SUB <t> x y) [1]) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpARM64ADD)
		v0 := b.NewValue0(v.Pos, OpARM64SRLconst, t)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpARM64SUB, t)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueARM64_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen32 x)
	// result: (SUB (MOVDconst [32]) (CLZW <typ.Int> x))
	for {
		x := v_0
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(32)
		v1 := b.NewValue0(v.Pos, OpARM64CLZW, typ.Int)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpBitLen64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen64 x)
	// result: (SUB (MOVDconst [64]) (CLZ <typ.Int> x))
	for {
		x := v_0
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(64)
		v1 := b.NewValue0(v.Pos, OpARM64CLZ, typ.Int)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpBitRev16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitRev16 x)
	// result: (SRLconst [48] (RBIT <typ.UInt64> x))
	for {
		x := v_0
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(48)
		v0 := b.NewValue0(v.Pos, OpARM64RBIT, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpBitRev8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitRev8 x)
	// result: (SRLconst [56] (RBIT <typ.UInt64> x))
	for {
		x := v_0
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(56)
		v0 := b.NewValue0(v.Pos, OpARM64RBIT, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpCondSelect(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b :=
```