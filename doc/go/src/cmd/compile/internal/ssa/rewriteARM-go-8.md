Response:
My thought process for answering the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze the provided Go code snippet, which is a part of the `rewriteARM.go` file in the Go compiler, and explain its functionality. The request specifically asks for identifying Go language features implemented, providing code examples, handling of command-line arguments (if applicable), common mistakes, and a summary of the function.

2. **Identify the Context:** The path `go/src/cmd/compile/internal/ssa/rewriteARM.go` immediately tells me this code is part of the Go compiler's intermediate representation (SSA - Static Single Assignment) manipulation for the ARM architecture. The "rewrite" part strongly suggests this code performs optimization or transformation on the SSA form.

3. **Analyze the Code Structure:** The code consists of multiple Go functions, each named `rewriteValueARM_Op...`. This naming convention is a strong clue. The `Op` prefix likely refers to SSA opcodes. Each function takes a `*Value` as input, which represents a node in the SSA graph. The functions return a boolean, suggesting whether a rewriting rule was applied.

4. **Examine Individual Functions (Pattern Matching):**  I look at the structure within each `rewriteValueARM_Op...` function. The consistent pattern is:
    * Accessing arguments of the input `Value` (`v.Args`).
    * Checking the `Op` field of these arguments.
    * Sometimes checking `AuxInt` (auxiliary integer data associated with the operation).
    * Performing a "match" condition based on the `Op` codes and `AuxInt` values.
    * If a match is found, the function "resets" the input `Value` (`v.reset`) to a new `Op` and potentially adds new arguments or modifies `AuxInt`. This is the *rewrite* happening.

5. **Infer Functionality (Opcode Transformations):** Based on the pattern matching and the renaming of opcodes, I can infer the functionality. For example:
    * `rewriteValueARM_OpARMTEQshiftLLreg`: It looks for a `TEQshiftLLreg` operation where one of the operands is a constant (`MOVWconst`). If found, it can rewrite it to either `TEQconst` with a shifted value or `TEQshiftLL` with the constant as the shift amount. This suggests simplifying expressions involving bitwise operations with constants.
    * `rewriteValueARM_OpARMTST`: This function tries to simplify `TST` (Test bits) operations by rearranging operands or introducing specialized shift versions (`TSTshiftLL`, `TSTshiftRL`, etc.) when constants or shift operations are involved.
    * `rewriteValueARM_OpARMXOR`: This function handles `XOR` (Exclusive OR) operations, similarly simplifying them when constants or shifts are involved. It also has a special case for `XOR x x` which simplifies to a constant zero.

6. **Connect to Go Language Features:** The operations being rewritten (TEQ, TST, XOR, shifts) are fundamental bitwise operations available in Go. The transformations aim to optimize these operations, often by taking advantage of hardware-specific instructions or by simplifying expressions involving constants.

7. **Provide Code Examples (Illustrative):** To demonstrate the rewrites, I create simple Go code snippets that would result in the SSA opcodes being matched by the rewrite rules. I provide the *input* Go code and the *output* SSA-like representation after the rewrite. I make sure the examples use the relevant operators (`==` for TEQ, `&` for TST-like comparisons, `^` for XOR, and bit shifts).

8. **Address Command-Line Arguments:** Since this code is part of the compiler's internal workings and doesn't directly interact with command-line arguments during the SSA rewrite phase, I explain that it doesn't directly handle them. However, I mention that the *compiler* as a whole takes command-line arguments for optimization levels, target architecture, etc., and these indirectly influence the SSA generation and rewriting process.

9. **Identify Common Mistakes:** The code itself doesn't have "user" mistakes in the traditional sense, as it's compiler code. The "mistakes" here are more about missed optimization opportunities or incorrect rewrite rules. I focus on a common pattern: failing to consider all possible operand orders or constant positions, which the code explicitly handles with loops and checks.

10. **Summarize the Functionality:** I synthesize the observations into a concise summary, highlighting that this part of `rewriteARM.go` focuses on optimizing bitwise logical and comparison operations on 32-bit integers for the ARM architecture by applying pattern matching and rewriting rules.

11. **Address the "Part 9 of 16" Instruction:** I acknowledge that this is part of a larger process and that its specific role is within the broader SSA rewriting phase for ARM.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this is directly related to parsing Go code. **Correction:** The file path and "ssa" clearly indicate it's working on the intermediate representation *after* parsing.
* **Initial thought:**  The `AuxInt` might be arbitrary. **Correction:**  The code uses functions like `auxIntToInt32` and `int32ToAuxInt`, indicating it's a way to store integer data within the SSA representation.
* **Initial thought:**  The examples should be very low-level assembly. **Correction:**  Showing the transformations at the SSA level is more appropriate and directly reflects what the code is doing. Mentioning the potential connection to assembly generation is good context.
* **Considering edge cases:** I review the conditions in the code (e.g., `0 <= c && c < 32` for shift amounts) and make sure my examples and explanations account for these limitations.

By following these steps, I can systematically analyze the code and provide a comprehensive and accurate explanation of its functionality within the context of the Go compiler.
这是 `go/src/cmd/compile/internal/ssa/rewriteARM.go` 文件的一部分，主要负责对 ARM 架构的 SSA（Static Single Assignment）中间表示进行优化的重写规则定义。

**功能归纳:**

这段代码定义了一系列针对 ARM 架构的特定 SSA 操作的重写规则。这些规则的目标是：

* **简化表达式:** 将复杂的 SSA 操作替换为更简单、更高效的操作。
* **利用 ARM 指令特性:** 将通用的 SSA 操作映射到特定的高效 ARM 汇编指令。
* **常量折叠:** 在编译时计算出常量表达式的值。
* **操作符交换律和结合律的应用:** 调整操作数的顺序或组合方式以利于后续优化。

**具体功能分解:**

这段代码主要处理了 `TEQ` (Test Equivalence) 和 `TST` (Test bits) 以及 `XOR` (异或) 操作的重写规则。

1. **`rewriteValueARM_OpARMTEQshiftLLreg(v *Value) bool`**:
   - 功能：优化 `TEQshiftLLreg` 操作（测试两个操作数左移后的等价性）。
   - 规则：
     - 如果左操作数是常量，则将其转换为 `TEQconst` 操作，并对右操作数进行相应的左移。
     - 如果右操作数是常量且在 0-31 范围内，则将其转换为 `TEQshiftLL` 操作，并将常量作为移位量。

2. **`rewriteValueARM_OpARMTEQshiftRAreg(v *Value) bool`**:
   - 功能：优化 `TEQshiftRAreg` 操作（测试两个操作数算术右移后的等价性）。
   - 规则：
     - 如果左操作数是常量，则将其转换为 `TEQconst` 操作，并对右操作数进行相应的算术右移。
     - 如果右操作数是常量且在 0-31 范围内，则将其转换为 `TEQshiftRA` 操作，并将常量作为移位量。

3. **`rewriteValueARM_OpARMTEQshiftRLreg(v *Value) bool`**:
   - 功能：优化 `TEQshiftRLreg` 操作（测试两个操作数逻辑右移后的等价性）。
   - 规则：
     - 如果左操作数是常量，则将其转换为 `TEQconst` 操作，并对右操作数进行相应的逻辑右移。
     - 如果右操作数是常量且在 0-31 范围内，则将其转换为 `TEQshiftRL` 操作，并将常量作为移位量。

4. **`rewriteValueARM_OpARMTST(v *Value) bool`**:
   - 功能：优化 `TST` 操作（按位与测试）。
   - 规则：
     - 如果其中一个操作数是常量，则将其转换为 `TSTconst` 操作。
     - 如果其中一个操作数是移位操作，则将其转换为相应的 `TSTshift...` 操作，例如 `TSTshiftLL`，`TSTshiftRL`，`TSTshiftRA`，`TSTshiftLLreg`， `TSTshiftRLreg`，`TSTshiftRAreg`。

5. **`rewriteValueARM_OpARMTSTconst(v *Value) bool`**:
   - 功能：优化 `TSTconst` 操作（按位与测试常量）。
   - 规则：如果操作数是常量，则直接计算按位与的结果，并将其转换为 `FlagConstant`，表示条件码寄存器的状态。

6. **`rewriteValueARM_OpARMTSTshiftLL(v *Value) bool`**:
   - 功能：优化 `TSTshiftLL` 操作（按位与测试左移）。
   - 规则：
     - 如果左操作数是常量，则转换为 `TSTconst` 操作，并对右操作数进行相应的左移。
     - 如果右操作数是常量，则转换为 `TSTconst` 操作，并对常量进行相应的左移。

7. **`rewriteValueARM_OpARMTSTshiftRA`**, **`rewriteValueARM_OpARMTSTshiftRL`**, **`rewriteValueARM_OpARMTSTshiftLLreg`**, **`rewriteValueARM_OpARMTSTshiftRAreg`**, **`rewriteValueARM_OpARMTSTshiftRLreg`**:
   - 这些函数分别处理 `TST` 与不同类型的移位操作结合的情况，其优化规则类似于 `rewriteValueARM_OpARMTSTshiftLL`，旨在将常量操作数提取出来，或者将移位量为常量的移位操作转换为特定的 SSA 操作。

8. **`rewriteValueARM_OpARMXOR(v *Value) bool`**:
   - 功能：优化 `XOR` 操作（按位异或）。
   - 规则：
     - 如果其中一个操作数是常量，则将其转换为 `XORconst` 操作。
     - 如果其中一个操作数是移位操作，则将其转换为相应的 `XORshift...` 操作，例如 `XORshiftLL`，`XORshiftRL`，`XORshiftRA`，`XORshiftRR`，`XORshiftLLreg`， `XORshiftRLreg`，`XORshiftRAreg`。
     - 如果两个操作数相同，则结果为 0，转换为 `MOVWconst [0]`。

9. **`rewriteValueARM_OpARMXORconst(v *Value) bool`**:
   - 功能：优化 `XORconst` 操作（按位异或常量）。
   - 规则：
     - 如果异或的常量是 0，则结果为另一个操作数本身。
     - 如果另一个操作数也是常量，则直接计算异或的结果，并将其转换为 `MOVWconst`。
     - 如果另一个操作数也是 `XORconst` 操作，则将两个常量合并。

10. **`rewriteValueARM_OpARMXORshiftLL`**, **`rewriteValueARM_OpARMXORshiftRA`**, **`rewriteValueARM_OpARMXORshiftRL`**, **`rewriteValueARM_OpARMXORshiftRR`**, **`rewriteValueARM_OpARMXORshiftLLreg`**, **`rewriteValueARM_OpARMXORshiftRAreg`**, **`rewriteValueARM_OpARMXORshiftRLreg`**:
    - 这些函数分别处理 `XOR` 与不同类型的移位操作结合的情况，其优化规则类似于 `rewriteValueARM_OpARMTSTshiftLL` 和 `rewriteValueARM_OpARMXOR`，旨在提取常量操作数或将常量移位量转换为特定的 SSA 操作，并可能进行一些特定于架构的优化，例如针对 `XORshiftLL` 识别出 `REV16` (字节序反转) 指令的模式。

**可以推理出它是什么go语言功能的实现：**

这段代码是 Go 编译器中 **SSA 中间表示的优化阶段** 的一部分，专门针对 ARM 架构。它通过模式匹配和规则替换来改进生成的机器码的效率。涉及的 Go 语言功能主要是 **位运算** 和 **条件判断**。

**Go 代码举例说明:**

以下是一些可能触发这些重写规则的 Go 代码示例以及经过优化后可能对应的 SSA 操作变化：

**示例 1: `TEQ` 优化**

```go
package main

func main() {
	x := 10
	y := 2
	if x == (5 << y) { // 触发 TEQshiftLLreg 或类似优化
		println("equal")
	}
}
```

**假设的输入 SSA (部分):**
```
v1 = LocalInt "x"
v2 = LocalInt "y"
v3 = Const32 [5]
v4 = Lsh32 v3 v2
v5 = Eq32 v1 v4
If v5 goto label1 else label2
```

**可能的输出 SSA (部分):**
```
v1 = LocalInt "x"
v2 = LocalInt "y"
v3 = Const32 [5]
v4 = Lsh32 v3 v2
v5 = TEQshiftLLreg v1 v3 v2 // 如果匹配到 TEQshiftLLreg 的规则
If v5 goto label1 else label2
```
**或者，如果 `v2` 是常量:**
```
v1 = LocalInt "x"
v2 = Const32 [2]
v3 = Const32 [5]
v4 = Const32 [20] // 5 << 2
v5 = TEQconst [20] v1 // 如果匹配到 TEQconst 的规则
If v5 goto label1 else label2
```

**示例 2: `TST` 优化**

```go
package main

func main() {
	x := 10
	if x & 4 == 4 { // 触发 TST 或 TSTconst 优化
		println("bit set")
	}
}
```

**假设的输入 SSA (部分):**
```
v1 = LocalInt "x"
v2 = Const32 [4]
v3 = And32 v1 v2
v4 = Eq32 v3 v2
If v4 goto label1 else label2
```

**可能的输出 SSA (部分):**
```
v1 = LocalInt "x"
v2 = Const32 [4]
v3 = TSTconst [4] v1 // 如果匹配到 TSTconst 的规则
If v3 goto label1 else label2
```

**示例 3: `XOR` 优化**

```go
package main

func main() {
	x := 10
	y := 5
	z := x ^ (y << 2) // 触发 XORshiftLL 或类似优化
	println(z)
}
```

**假设的输入 SSA (部分):**
```
v1 = LocalInt "x"
v2 = LocalInt "y"
v3 = Const32 [2]
v4 = Lsh32 v2 v3
v5 = Xor32 v1 v4
Store z v5
```

**可能的输出 SSA (部分):**
```
v1 = LocalInt "x"
v2 = LocalInt "y"
v3 = Const32 [2]
v4 = Lsh32 v2 v3
v5 = XORshiftLLreg v1 v2 v3 // 如果匹配到 XORshiftLLreg 的规则
Store z v5
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是 Go 编译器内部 SSA 优化的一部分。Go 编译器的命令行参数（例如 `-gcflags` 用于传递编译器标志）会影响整个编译流程，包括 SSA 的生成和优化。不同的优化级别可能会启用或禁用某些重写规则。

**使用者易犯错的点:**

由于这段代码是编译器内部实现，普通 Go 开发者不会直接编写或修改它。易犯错的点更多是编译器开发者需要注意的：

* **错误的匹配条件:** 重写规则的条件写错，导致不应该被替换的操作被错误地替换。
* **错误的替换逻辑:** 重写后的操作语义不正确，导致程序行为改变。
* **性能回退:** 某些“优化”在特定情况下反而可能导致性能下降。
* **未考虑所有情况:**  只考虑了部分操作数类型或常量值，导致某些可以优化的场景没有被覆盖。

**总结第9部分的功能:**

作为 `rewriteARM.go` 的一部分，这段代码（第 9 部分）专门负责 **优化 ARM 架构下 SSA 中间表示中的 `TEQ`、`TST` 和 `XOR` 操作**。它通过模式匹配识别出可以简化的表达式，并将它们转换为更高效的等价形式，例如利用常量进行计算或使用特定的 ARM 移位指令。这些优化有助于生成更精简、更快速的 ARM 机器码。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第9部分，共16部分，请归纳一下它的功能
```

### 源代码
```go
v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftLLreg (MOVWconst [c]) x y)
	// result: (TEQconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TEQshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMTEQshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftRA (MOVWconst [c]) x [d])
	// result: (TEQconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftRA x (MOVWconst [c]) [d])
	// result: (TEQconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftRAreg (MOVWconst [c]) x y)
	// result: (TEQconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TEQshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMTEQshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftRL (MOVWconst [c]) x [d])
	// result: (TEQconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftRL x (MOVWconst [c]) [d])
	// result: (TEQconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftRLreg (MOVWconst [c]) x y)
	// result: (TEQconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TEQshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMTEQshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTST(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (TST x (MOVWconst [c]))
	// result: (TSTconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMTSTconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TST x (SLLconst [c] y))
	// result: (TSTshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (TST x (SRLconst [c] y))
	// result: (TSTshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (TST x (SRAconst [c] y))
	// result: (TSTshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (TST x (SLL y z))
	// result: (TSTshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (TST x (SRL y z))
	// result: (TSTshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (TST x (SRA y z))
	// result: (TSTshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftRAreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMTSTconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TSTconst (MOVWconst [x]) [y])
	// result: (FlagConstant [logicFlags32(x&y)])
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMFlagConstant)
		v.AuxInt = flagConstantToAuxInt(logicFlags32(x & y))
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftLL (MOVWconst [c]) x [d])
	// result: (TSTconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftLL x (MOVWconst [c]) [d])
	// result: (TSTconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftLLreg (MOVWconst [c]) x y)
	// result: (TSTconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TSTshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMTSTshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRA (MOVWconst [c]) x [d])
	// result: (TSTconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRA x (MOVWconst [c]) [d])
	// result: (TSTconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRAreg (MOVWconst [c]) x y)
	// result: (TSTconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TSTshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMTSTshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRL (MOVWconst [c]) x [d])
	// result: (TSTconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRL x (MOVWconst [c]) [d])
	// result: (TSTconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRLreg (MOVWconst [c]) x y)
	// result: (TSTconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TSTshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMTSTshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVWconst [c]))
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMXORconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR x (SLLconst [c] y))
	// result: (XORshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMXORshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x (SRLconst [c] y))
	// result: (XORshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x (SRAconst [c] y))
	// result: (XORshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x (SRRconst [c] y))
	// result: (XORshiftRR x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRRconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRR)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x (SLL y z))
	// result: (XORshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMXORshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (XOR x (SRL y z))
	// result: (XORshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (XOR x (SRA y z))
	// result: (XORshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRAreg)
			v.AddArg3(x, y, z)
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
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORconst(v *Value) bool {
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
	// match: (XORconst [c] (MOVWconst [d]))
	// result: (MOVWconst [c^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		return true
	}
	// match: (XORconst [c] (XORconst [d] x))
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMXORconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (XORshiftLL (MOVWconst [c]) x [d])
	// result: (XORconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftLL x (MOVWconst [c]) [d])
	// result: (XORconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL <typ.UInt16> [8] (BFXU <typ.UInt16> [int32(armBFAuxInt(8, 8))] x) x)
	// result: (REV16 x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt32(v.AuxInt) != 8 || v_0.Op != OpARMBFXU || v_0.Type != typ.UInt16 || auxIntToInt32(v_0.AuxInt) != int32(armBFAuxInt(8, 8)) {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMREV16)
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL <typ.UInt16> [8] (SRLconst <typ.UInt16> [24] (SLLconst [16] x)) x)
	// cond: buildcfg.GOARM.Version>=6
	// result: (REV16 x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt32(v.AuxInt) != 8 || v_0.Op != OpARMSRLconst || v_0.Type != typ.UInt16 || auxIntToInt32(v_0.AuxInt) != 24 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARMSLLconst || auxIntToInt32(v_0_0.AuxInt) != 16 {
			break
		}
		x := v_0_0.Args[0]
		if x != v_1 || !(buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMREV16)
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL (SLLconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSLLconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftLLreg (MOVWconst [c]) x y)
	// result: (XORconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (XORshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMXORshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRA (MOVWconst [c]) x [d])
	// result: (XORconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRA x (MOVWconst [c]) [d])
	// result: (XORconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRA (SRAconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSRAconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRAreg (MOVWconst [c]) x y)
	// result: (XORconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (XORshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMXORshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRL (MOVWconst [c]) x [d])
	// result: (XORconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRL x (MOVWconst [c]) [d])
	// result: (XORconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRL (SRLconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSRLconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRLreg (MOVWconst [c]) x y)
	// result: (XORconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (XORshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMXORshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftRR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRR (MOVWconst [c]) x [d])
	// result: (XORconst [c] (SRRconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRRconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRR x (MOVWconst [c]) [d])
	// result: (XORconst x [int32(uint32(c)>>uint64(d)|uint32(c)<<uint64(32-d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c)>>uint64(d) | uint32(c)<<uint64(32-d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVWaddr {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpARMMOVWaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueARM_OpAvg32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg32u <t> x y)
	// result: (ADD (SRLconst <t> (SUB <t> x y) [1]) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, t)
		v0.AuxInt = int32ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpARMSUB, t)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueARM_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (BitLen32 <t> x)
	// result: (RSBconst [32] (CLZ <t> x))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARMCLZ, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpBswap32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Bswap32 <t> x)
	// cond: buildcfg.GOARM.Version==5
	// result: (XOR <t> (SRLconst <t> (BICconst <t> (XOR <t> x (SRRconst <t> [16] x)) [0xff0000]) [8]) (SRRconst <t> x [8]))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version == 5) {
			break
		}
		v.reset(OpARMXOR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, t)
		v0.AuxInt = int32ToAuxInt(8)
		v1 := b.NewValue0(v.Pos, OpARMBICconst, t)
		v1.AuxInt = int32ToAuxInt(0xff0000)
		v2 := b.NewValue0(v.Pos, OpARMXOR, t)
		v3 := b.NewValue0(v.Pos, OpARMSRRconst, t)
		v3.AuxInt = int32ToAuxInt(16)
		v3.AddArg(x)
		v2.AddArg2(x, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpARMSRRconst, t)
		v4.AuxInt = int32ToAuxInt(8)
		v4.AddArg(x)
		v.AddArg2(v0, v4)
		return true
	}
	// match: (Bswap32 x)
	// cond: buildcfg.GOARM.Version>=6
	// result: (REV x)
	for {
		x := v_0
		if !(buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMREV)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVWconst [int32(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(val))
		return true
	}
}
func rewriteValueARM_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVWconst [int32(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(val))
		return true
	}
}
func rewriteValueARM_OpConst32F(v *Value) bool {
	// match: (Const32F [val])
	// result: (MOVFconst [float64(val)])
	for {
		val := auxIntToFloat32(v.AuxInt)
		v.reset(OpARMMOVFconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueARM_OpConst64F(v *Value) bool {
	// match: (Const64F [val])
	// result: (MOVDconst [float64(val)])
	for {
		val := auxIntToFloat64(v.AuxInt)
		v.reset(OpARMMOVDconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueARM_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVWconst [int32(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(val))
		return true
	}
}
func rewriteValueARM_OpConstBool(v *Value) bool {
	// match: (ConstBool [t])
	// result: (MOVWconst [b2i32(t)])
	for {
		t := auxIntToBool(v.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(t))
		return true
	}
}
func rewriteValueARM_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVWconst [0])
	for {
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
}
func rewriteValueARM_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz16 <t> x)
	// cond: buildcfg.GOARM.Version<=6
	// result: (RSBconst [32] (CLZ <t> (SUBconst <typ.UInt32> (AND <typ.UInt32> (ORconst <typ.UInt32> [0x10000] x) (RSBconst <typ.UInt32> [0] (ORconst <typ.UInt32> [0x10000] x))) [1])))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version <= 6) {
			break
		}
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARMCLZ, t)
		v1 := b.NewValue0(v.Pos, OpARMSUBconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpARMAND, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpARMORconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0x10000)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpARMRSBconst, typ.UInt32)
		v4.AuxInt = int32ToAuxInt(0)
		v4.AddArg(v3)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Ctz16 <t> x)
	// cond: buildcfg.GOARM.Version==7
	// result: (CLZ <t> (RBIT <typ.UInt32> (ORconst <typ.UInt32> [0x10000] x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version == 7) {
			break
		}
		v.reset(OpARMCLZ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARMRBIT, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpARMORconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0x10000)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Ctz32 <t> x)
	// cond: buildcfg.GOARM.Version<=6
	// result: (RSBconst [32] (CLZ <t> (SUBconst <t> (AND <t> x (RSBconst <t> [0] x)) [1])))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version <= 6) {
			break
		}
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARMCLZ, t)
		v1 := b.NewValue0(v.Pos, OpARMSUBconst, t)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpARMAND, t)
		v3 := b.NewValue0(v.Pos, OpARMRSBconst, t)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg(x)
		v2.AddArg2(x, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Ctz32 <t> x)
	// cond: buildcfg.GOARM.Version==7
	// result: (CLZ <t> (RBIT <t> x))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version == 7) {
			break
		}
		v.reset(OpARMCLZ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARMRBIT, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz8 <t> x)
	// cond: buildcfg.GOARM.Version<=6
	// result: (RSBconst [32] (CLZ <t> (SUBconst <typ.UInt32> (AND <typ.UInt32> (ORconst <typ.UInt32> [0x100] x) (RSBconst <typ.UInt32> [0] (ORconst <typ.UInt32> [0x100] x))) [1])))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version <= 6) {
			break
		}
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARMCLZ, t)
		v1 := b.NewValue0(v.Pos, OpARMSUBconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpARMAND, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpARMORconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0x100)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpARMRSBconst, typ.UInt32)
		v4.AuxInt = int32ToAuxInt(0)
		v4.AddArg(v3)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Ctz8 <t> x)
	// cond: buildcfg.GOARM.Version==7
	// result: (CLZ <t> (RBIT <typ.UInt32> (ORconst <typ.UInt32> [0x100] x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version == 7) {
			break
		}
		v.reset(OpARMCLZ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARMRBIT, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpARMORconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0x100)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 x y)
	// result: (Div32 (SignExt16to32 x) (SignExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpDiv32)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (Div32u (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpDiv32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32 x y)
	// result: (SUB (XOR <typ.UInt32> (Select0 <typ.UInt32> (CALLudiv (SUB <typ.UInt32> (XOR x <typ.UInt32> (Signmask x)) (Signmask x)) (SUB <typ.UInt32> (XOR y <typ.UInt32> (Signmask y)) (Signmask y)))) (Signmask (XOR <typ.UInt32> x y))) (Signmask (XOR <typ.UInt32> x y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSUB)
		v0 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpSelect0, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpARMCALLudiv, types.NewTuple(typ.UInt32,
```