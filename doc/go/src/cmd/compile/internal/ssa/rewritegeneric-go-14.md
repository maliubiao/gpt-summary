Response:
My thought process for analyzing the given Go code snippet and generating the response went through these stages:

1. **Understanding the Context:** The prompt clearly states this is part of the `rewritegeneric.go` file within the Go compiler (`cmd/compile/internal/ssa`). The filename itself suggests this code is related to rewriting generic SSA (Static Single Assignment) form. The "part 15 of 26" information is helpful for understanding the scope but doesn't directly affect the analysis of this particular snippet.

2. **Initial Code Scan - Identifying Key Operations:** I quickly scanned the code, looking for repeated patterns and the types of operations being performed. The recurring `for` loops with `_i0`, `_i1` variables, the `v.reset(Op...)`, `v.AddArg...`, and conditional checks like `v_0.Op == OpConst...` immediately stood out. The operations like `OpMul16`, `OpMul32`, `OpNeg16`, `OpNeq16` etc., are clearly SSA opcodes representing arithmetic, negation, and comparison operations.

3. **Focusing on Individual Rewrite Functions:**  The code is organized into functions like `rewriteValuegeneric_OpMul16`, `rewriteValuegeneric_OpMul32`, etc. Each of these functions seems dedicated to rewriting a specific SSA operation. This made the analysis manageable by breaking it down per function.

4. **Analyzing the Rewrite Rules (Match and Result):**  Within each function, the code follows a pattern:
    * **`match:` comment:** Describes the input pattern of SSA operations.
    * **`cond:` comment (optional):** Specifies conditions that must be met for the rewrite to apply.
    * **`result:` comment:**  Shows the rewritten SSA operation.
    * **Go code implementing the match and rewrite:**  The `for` loops and `if` conditions implement the pattern matching, and the `v.reset(...)` and `v.AddArg(...)` calls perform the rewrite.

5. **Inferring Functionality Based on Rewrite Rules:**  By examining the `match` and `result` comments, I could infer the purpose of each rewrite rule. For example:
    * `// match: (Mul16 (Const16 [c]) (Const16 [d]))`
    * `// result: (Const16 [c*d])`
    This clearly shows a rule for constant folding of multiplication.

6. **Identifying Common Themes and Optimizations:**  As I analyzed more rules, I noticed common themes:
    * **Constant Folding:** Replacing operations with constant inputs with their result (e.g., multiplying two constants).
    * **Identity Elimination:** Removing unnecessary identity operations (e.g., multiplying by 1).
    * **Algebraic Simplifications:** Applying algebraic identities to simplify expressions (e.g., `Neg(Sub(x, y))` becomes `Sub(y, x)`).
    * **Strength Reduction:** Replacing expensive operations with cheaper ones (e.g., multiplying by a power of two with a left shift).
    * **Canonicalization:**  Putting expressions into a standard form (e.g., rearranging operands in multiplication).

7. **Inferring the Overall Purpose:** Based on the individual rewrite rules, the overall functionality of this code is to perform various optimizations and simplifications on the generic SSA representation of Go code. This helps the compiler generate more efficient machine code.

8. **Generating the Response - Structuring and Explaining:**  I structured the response as requested:
    * **Functionality Listing:** I listed the core functionalities identified (constant folding, identity elimination, etc.).
    * **Go Language Feature Inference:** I correctly inferred that the code implements compiler optimizations.
    * **Code Examples:** I selected representative examples (constant folding, power of two multiplication) and provided corresponding Go code snippets to illustrate when these optimizations might occur.
    * **Input/Output Assumptions:** For the code examples, I specified the assumed input Go code and the corresponding optimized output SSA, highlighting the changes made by the rewrite rules.
    * **No Command-line Arguments:** I correctly noted the absence of command-line argument handling in this snippet.
    * **No Common Mistakes:**  Since this is compiler code, user mistakes are not directly applicable here.
    * **Summary of Functionality:** I summarized the main purpose as optimizing generic SSA.

9. **Review and Refinement:** I reviewed my response to ensure accuracy, clarity, and completeness, making sure it addressed all aspects of the prompt. I made sure the language used was appropriate for explaining compiler internals. For example, using terms like "SSA operations," "constant folding," and "strength reduction."

This iterative process of scanning, analyzing individual rules, identifying patterns, and then synthesizing the overall functionality allowed me to generate a comprehensive and accurate answer to the prompt.
这是一个Go语言编译器中，对中间表示（SSA）进行优化的代码片段。具体来说，它位于 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 文件中，负责实现 **与类型无关的通用重写规则**。

这个代码片段主要针对一些算术和逻辑运算进行优化，特别是涉及到常量的情况。我们可以将它的功能归纳为以下几点：

**1. 常量折叠 (Constant Folding):**

   - 将操作数都是常量的运算直接计算出结果，替换为常量。
   - 例如，对于 `OpMul16`（16位乘法），如果两个操作数都是常量，则直接计算乘积，生成一个新的常量节点。

   ```go
   // match: (Mul16 (Const16 [c]) (Const16 [d]))
   // result: (Const16 [c*d])
   ```

   **Go代码示例:**

   ```go
   package main

   func main() {
       x := 5 * 10 // 编译器会在编译时将 5 * 10 折叠为 50
       println(x)
   }
   ```

   **假设输入 (SSA):**

   ```
   v1 = Const16 <int16> [5]
   v2 = Const16 <int16> [10]
   v3 = Mul16 v1 v2
   ```

   **优化后输出 (SSA):**

   ```
   v1 = Const16 <int16> [50]
   ```

**2. 零值优化 (Zero Value Optimization):**

   - 将与零相关的运算简化。
   - 例如，任何数乘以零都等于零。

   ```go
   // match: (Mul16 (Const16 [0]) _)
   // result: (Const16 [0])
   ```

   **Go代码示例:**

   ```go
   package main

   func main() {
       y := 0 * someVariable
       println(y)
   }
   ```

   **假设输入 (SSA):**

   ```
   v1 = Const16 <int16> [0]
   v2 = ... // someVariable 的 SSA 值
   v3 = Mul16 v1 v2
   ```

   **优化后输出 (SSA):**

   ```
   v1 = Const16 <int16> [0]
   ```

**3. 单位元优化 (Identity Element Optimization):**

   - 将与单位元相关的运算简化。
   - 例如，任何数乘以 1 都等于它本身。

   ```go
   // match: (Mul16 (Const16 [1]) x)
   // result: x
   ```

   **Go代码示例:**

   ```go
   package main

   func main() {
       z := 1 * anotherVariable
       println(z)
   }
   ```

   **假设输入 (SSA):**

   ```
   v1 = Const16 <int16> [1]
   v2 = ... // anotherVariable 的 SSA 值
   v3 = Mul16 v1 v2
   ```

   **优化后输出 (SSA):**

   ```
   v3 = ... // 直接使用 anotherVariable 的 SSA 值
   ```

**4. 负一优化 (Negative One Optimization):**

   - 将乘以 -1 的操作转换为取反操作。

   ```go
   // match: (Mul16 (Const16 [-1]) x)
   // result: (Neg16 x)
   ```

   **Go代码示例:**

   ```go
   package main

   func main() {
       w := -1 * yetAnotherVariable
       println(w)
   }
   ```

   **假设输入 (SSA):**

   ```
   v1 = Const16 <int16> [-1]
   v2 = ... // yetAnotherVariable 的 SSA 值
   v3 = Mul16 v1 v2
   ```

   **优化后输出 (SSA):**

   ```
   v3 = Neg16 v2
   ```

**5. 乘法结合律重排 (Multiplication Associativity Rearrangement):**

   - 当乘法运算中存在常量时，尝试将常量聚集在一起，方便常量折叠。

   ```go
   // match: (Mul16 (Mul16 i:(Const16 <t>) z) x)
   // cond: (z.Op != OpConst16 && x.Op != OpConst16)
   // result: (Mul16 i (Mul16 <t> x z))
   ```

   **Go代码示例 (虽然不太常见，但可以构造出类似情况):**

   ```go
   package main

   func main() {
       const a = 5
       b := someValue
       c := anotherValue
       result := (a * b) * c
       println(result)
   }
   ```

   **假设输入 (SSA):**

   ```
   v1 = Const16 <int16> [5]
   v2 = ... // someValue 的 SSA 值
   v3 = Mul16 v1 v2
   v4 = ... // anotherValue 的 SSA 值
   v5 = Mul16 v3 v4
   ```

   **优化后输出 (SSA):**

   ```
   v1 = Const16 <int16> [5]
   v2 = ... // someValue 的 SSA 值
   v4 = ... // anotherValue 的 SSA 值
   v6 = Mul16 v4 v2
   v5 = Mul16 v1 v6
   ```

**6. 乘法常量合并 (Multiplication Constant Merging):**

   - 如果乘法运算中有多个常量相乘，则将它们合并成一个常量。

   ```go
   // match: (Mul16 (Const16 <t> [c]) (Mul16 (Const16 <t> [d]) x))
   // result: (Mul16 (Const16 <t> [c*d]) x)
   ```

   **Go代码示例:**

   ```go
   package main

   func main() {
       const a = 5
       const b = 10
       val := someValue
       result := a * (b * val)
       println(result)
   }
   ```

   **假设输入 (SSA):**

   ```
   v1 = Const16 <int16> [5]
   v2 = Const16 <int16> [10]
   v3 = ... // someValue 的 SSA 值
   v4 = Mul16 v2 v3
   v5 = Mul16 v1 v4
   ```

   **优化后输出 (SSA):**

   ```
   v6 = Const16 <int16> [50]
   v3 = ... // someValue 的 SSA 值
   v5 = Mul16 v6 v3
   ```

**7. 幂运算优化为移位 (Power of Two Optimization to Shift):**

   - 将乘以 2 的幂的操作转换为左移操作。
   - 例如，乘以 8 (2的3次方) 可以转换为左移 3 位。

   ```go
   // match: (Mul16 <t> n (Const16 [c]))
   // cond: isPowerOfTwo(c)
   // result: (Lsh16x64 <t> n (Const64 <typ.UInt64> [log16(c)]))
   ```

   **Go代码示例:**

   ```go
   package main

   func main() {
       num := someValue
       multiplied := num * 8
       println(multiplied)
   }
   ```

   **假设输入 (SSA):**

   ```
   v1 = ... // someValue 的 SSA 值
   v2 = Const16 <int16> [8]
   v3 = Mul16 v1 v2
   ```

   **优化后输出 (SSA):**

   ```
   v1 = ... // someValue 的 SSA 值
   v4 = Const64 <uint64> [3]
   v3 = Lsh16x64 v1 v4
   ```

**8. 负数幂运算优化为取反和移位:**

   - 将乘以负的 2 的幂的操作转换为取反和左移操作。

   ```go
   // match: (Mul16 <t> n (Const16 [c]))
   // cond: t.IsSigned() && isPowerOfTwo(-c)
   // result: (Neg16 (Lsh16x64 <t> n (Const64 <typ.UInt64> [log16(-c)])))
   ```

   **Go代码示例:**

   ```go
   package main

   func main() {
       num := someValue
       multiplied := num * -8
       println(multiplied)
   }
   ```

   **假设输入 (SSA):**

   ```
   v1 = ... // someValue 的 SSA 值
   v2 = Const16 <int16> [-8]
   v3 = Mul16 v1 v2
   ```

   **优化后输出 (SSA):**

   ```
   v1 = ... // someValue 的 SSA 值
   v4 = Const64 <uint64> [3]
   v5 = Lsh16x64 v1 v4
   v3 = Neg16 v5
   ```

**9. 分配律的应用 (Distribution Law Application):**

   - 将乘法分配到加法上，有助于常量折叠。

   ```go
   // match: (Mul16 (Const16 <t> [c]) (Add16 <t> (Const16 <t> [d]) x))
   // result: (Add16 (Const16 <t> [c*d]) (Mul16 <t> (Const16 <t> [c]) x))
   ```

   **Go代码示例:**

   ```go
   package main

   func main() {
       const a = 5
       const b = 10
       val := someValue
       result := a * (b + val)
       println(result)
   }
   ```

   **假设输入 (SSA):**

   ```
   v1 = Const16 <int16> [5]
   v2 = Const16 <int16> [10]
   v3 = ... // someValue 的 SSA 值
   v4 = Add16 v2 v3
   v5 = Mul16 v1 v4
   ```

   **优化后输出 (SSA):**

   ```
   v1 = Const16 <int16> [5]
   v2 = Const16 <int16> [10]
   v3 = ... // someValue 的 SSA 值
   v6 = Const16 <int16> [50]
   v7 = Mul16 v1 v3
   v5 = Add16 v6 v7
   ```

**关于 `rewriteValuegeneric_OpNeg...` 和 `rewriteValuegeneric_OpNeq...` 等函数的功能:**

- `rewriteValuegeneric_OpNeg...`: 针对取反操作 (`OpNeg16`, `OpNeg32` 等) 进行优化，例如将对常量的取反直接计算出结果，或者简化双重取反。
- `rewriteValuegeneric_OpNeq...`: 针对不等比较操作 (`OpNeq16`, `OpNeq32` 等) 进行优化，例如将与自身比较简化为 `false`，或者对常量比较直接得出布尔结果。

**这个代码片段是 Go 语言编译器进行 SSA 优化的重要组成部分，它通过模式匹配和替换，将一些常见的、可以简化的运算转换成更高效的形式，从而提升最终生成代码的性能。**

**命令行参数的具体处理:**

这个代码片段本身并不直接处理命令行参数。它是 Go 编译器的内部实现，在编译过程中被调用。Go 编译器的命令行参数由 `go build` 或 `go run` 等命令处理，这些参数会影响编译过程的各个阶段，包括 SSA 的生成和优化。

**使用者易犯错的点:**

作为编译器内部的代码，普通 Go 语言使用者不会直接与这段代码交互，因此不存在使用者易犯错的点。

**总结一下它的功能 (针对提供的第15部分代码):**

这第15部分代码主要负责对 **16位、32位和64位整数以及单精度浮点数的乘法 (`OpMul16`, `OpMul32`, `OpMul64`, `OpMul32F`)** 进行各种通用优化，包括常量折叠、零值优化、单位元优化、负一优化、乘法结合律重排、乘法常量合并以及将乘以 2 的幂转换为移位操作。此外，它还包含了对 **8位整数乘法 (`OpMul8`)** 和 **取反操作 (`OpNeg16`, `OpNeg32`, `OpNeg32F`, `OpNeg64`, `OpNeg64F`, `OpNeg8`)** 以及 **不等比较操作 (`OpNeq16`, `OpNeq32`, `OpNeq32F`)** 的优化规则。

总而言之，这段代码的核心目标是在编译期间尽可能地简化和优化表达式，特别是那些涉及到常量的表达式，以提高生成代码的效率。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第15部分，共26部分，请归纳一下它的功能
```

### 源代码
```go
sh16x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v1.AuxInt = int64ToAuxInt(log16(-c))
			v0.AddArg2(n, v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Mul16 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Mul16 (Mul16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Mul16 i (Mul16 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul16 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst16 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst16 && x.Op != OpConst16) {
					continue
				}
				v.reset(OpMul16)
				v0 := b.NewValue0(v.Pos, OpMul16, t)
				v0.AddArg2(x, z)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Mul16 (Const16 <t> [c]) (Mul16 (Const16 <t> [d]) x))
	// result: (Mul16 (Const16 <t> [c*d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpMul16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst16 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt16(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpMul16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c * d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul32 (Const32 [c]) (Const32 [d]))
	// result: (Const32 [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul32 (Const32 [1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul32 (Const32 [-1]) x)
	// result: (Neg32 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpNeg32)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul32 <t> n (Const32 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Lsh32x64 <t> n (Const64 <typ.UInt64> [log32(c)]))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpLsh32x64)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v0.AuxInt = int64ToAuxInt(log32(c))
			v.AddArg2(n, v0)
			return true
		}
		break
	}
	// match: (Mul32 <t> n (Const32 [c]))
	// cond: t.IsSigned() && isPowerOfTwo(-c)
	// result: (Neg32 (Lsh32x64 <t> n (Const64 <typ.UInt64> [log32(-c)])))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			if !(t.IsSigned() && isPowerOfTwo(-c)) {
				continue
			}
			v.reset(OpNeg32)
			v0 := b.NewValue0(v.Pos, OpLsh32x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v1.AuxInt = int64ToAuxInt(log32(-c))
			v0.AddArg2(n, v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Mul32 (Const32 <t> [c]) (Add32 <t> (Const32 <t> [d]) x))
	// result: (Add32 (Const32 <t> [c*d]) (Mul32 <t> (Const32 <t> [c]) x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpAdd32 || v_1.Type != t {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt32(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpAdd32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c * d)
				v1 := b.NewValue0(v.Pos, OpMul32, t)
				v2 := b.NewValue0(v.Pos, OpConst32, t)
				v2.AuxInt = int32ToAuxInt(c)
				v1.AddArg2(v2, x)
				v.AddArg2(v0, v1)
				return true
			}
		}
		break
	}
	// match: (Mul32 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Mul32 (Mul32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Mul32 i (Mul32 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul32 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst32 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst32 && x.Op != OpConst32) {
					continue
				}
				v.reset(OpMul32)
				v0 := b.NewValue0(v.Pos, OpMul32, t)
				v0.AddArg2(x, z)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Mul32 (Const32 <t> [c]) (Mul32 (Const32 <t> [d]) x))
	// result: (Mul32 (Const32 <t> [c*d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt32(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpMul32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c * d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mul32F (Const32F [c]) (Const32F [d]))
	// cond: c*d == c*d
	// result: (Const32F [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32F {
				continue
			}
			c := auxIntToFloat32(v_0.AuxInt)
			if v_1.Op != OpConst32F {
				continue
			}
			d := auxIntToFloat32(v_1.AuxInt)
			if !(c*d == c*d) {
				continue
			}
			v.reset(OpConst32F)
			v.AuxInt = float32ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul32F x (Const32F [1]))
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst32F || auxIntToFloat32(v_1.AuxInt) != 1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul32F x (Const32F [-1]))
	// result: (Neg32F x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst32F || auxIntToFloat32(v_1.AuxInt) != -1 {
				continue
			}
			v.reset(OpNeg32F)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul32F x (Const32F [2]))
	// result: (Add32F x x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst32F || auxIntToFloat32(v_1.AuxInt) != 2 {
				continue
			}
			v.reset(OpAdd32F)
			v.AddArg2(x, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul64 (Const64 [1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul64 (Const64 [-1]) x)
	// result: (Neg64 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpNeg64)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul64 <t> n (Const64 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Lsh64x64 <t> n (Const64 <typ.UInt64> [log64(c)]))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpLsh64x64)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v0.AuxInt = int64ToAuxInt(log64(c))
			v.AddArg2(n, v0)
			return true
		}
		break
	}
	// match: (Mul64 <t> n (Const64 [c]))
	// cond: t.IsSigned() && isPowerOfTwo(-c)
	// result: (Neg64 (Lsh64x64 <t> n (Const64 <typ.UInt64> [log64(-c)])))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(t.IsSigned() && isPowerOfTwo(-c)) {
				continue
			}
			v.reset(OpNeg64)
			v0 := b.NewValue0(v.Pos, OpLsh64x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v1.AuxInt = int64ToAuxInt(log64(-c))
			v0.AddArg2(n, v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Mul64 (Const64 <t> [c]) (Add64 <t> (Const64 <t> [d]) x))
	// result: (Add64 (Const64 <t> [c*d]) (Mul64 <t> (Const64 <t> [c]) x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpAdd64 || v_1.Type != t {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt64(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpAdd64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c * d)
				v1 := b.NewValue0(v.Pos, OpMul64, t)
				v2 := b.NewValue0(v.Pos, OpConst64, t)
				v2.AuxInt = int64ToAuxInt(c)
				v1.AddArg2(v2, x)
				v.AddArg2(v0, v1)
				return true
			}
		}
		break
	}
	// match: (Mul64 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Mul64 (Mul64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Mul64 i (Mul64 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul64 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst64 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst64 && x.Op != OpConst64) {
					continue
				}
				v.reset(OpMul64)
				v0 := b.NewValue0(v.Pos, OpMul64, t)
				v0.AddArg2(x, z)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Mul64 (Const64 <t> [c]) (Mul64 (Const64 <t> [d]) x))
	// result: (Mul64 (Const64 <t> [c*d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpMul64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt64(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpMul64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c * d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mul64F (Const64F [c]) (Const64F [d]))
	// cond: c*d == c*d
	// result: (Const64F [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64F {
				continue
			}
			c := auxIntToFloat64(v_0.AuxInt)
			if v_1.Op != OpConst64F {
				continue
			}
			d := auxIntToFloat64(v_1.AuxInt)
			if !(c*d == c*d) {
				continue
			}
			v.reset(OpConst64F)
			v.AuxInt = float64ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul64F x (Const64F [1]))
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst64F || auxIntToFloat64(v_1.AuxInt) != 1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul64F x (Const64F [-1]))
	// result: (Neg64F x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst64F || auxIntToFloat64(v_1.AuxInt) != -1 {
				continue
			}
			v.reset(OpNeg64F)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul64F x (Const64F [2]))
	// result: (Add64F x x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpConst64F || auxIntToFloat64(v_1.AuxInt) != 2 {
				continue
			}
			v.reset(OpAdd64F)
			v.AddArg2(x, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpMul8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c*d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1.AuxInt)
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul8 (Const8 [1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul8 (Const8 [-1]) x)
	// result: (Neg8 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpNeg8)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul8 <t> n (Const8 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Lsh8x64 <t> n (Const64 <typ.UInt64> [log8(c)]))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpLsh8x64)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v0.AuxInt = int64ToAuxInt(log8(c))
			v.AddArg2(n, v0)
			return true
		}
		break
	}
	// match: (Mul8 <t> n (Const8 [c]))
	// cond: t.IsSigned() && isPowerOfTwo(-c)
	// result: (Neg8 (Lsh8x64 <t> n (Const64 <typ.UInt64> [log8(-c)])))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1.AuxInt)
			if !(t.IsSigned() && isPowerOfTwo(-c)) {
				continue
			}
			v.reset(OpNeg8)
			v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v1.AuxInt = int64ToAuxInt(log8(-c))
			v0.AddArg2(n, v1)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Mul8 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Mul8 (Mul8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Mul8 i (Mul8 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul8 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst8 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst8 && x.Op != OpConst8) {
					continue
				}
				v.reset(OpMul8)
				v0 := b.NewValue0(v.Pos, OpMul8, t)
				v0.AddArg2(x, z)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Mul8 (Const8 <t> [c]) (Mul8 (Const8 <t> [d]) x))
	// result: (Mul8 (Const8 <t> [c*d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpMul8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst8 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt8(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpMul8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c * d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeg16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neg16 (Const16 [c]))
	// result: (Const16 [-c])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(-c)
		return true
	}
	// match: (Neg16 (Sub16 x y))
	// result: (Sub16 y x)
	for {
		if v_0.Op != OpSub16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSub16)
		v.AddArg2(y, x)
		return true
	}
	// match: (Neg16 (Neg16 x))
	// result: x
	for {
		if v_0.Op != OpNeg16 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Neg16 <t> (Com16 x))
	// result: (Add16 (Const16 <t> [1]) x)
	for {
		t := v.Type
		if v_0.Op != OpCom16 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAdd16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neg32 (Const32 [c]))
	// result: (Const32 [-c])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(-c)
		return true
	}
	// match: (Neg32 (Sub32 x y))
	// result: (Sub32 y x)
	for {
		if v_0.Op != OpSub32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSub32)
		v.AddArg2(y, x)
		return true
	}
	// match: (Neg32 (Neg32 x))
	// result: x
	for {
		if v_0.Op != OpNeg32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Neg32 <t> (Com32 x))
	// result: (Add32 (Const32 <t> [1]) x)
	for {
		t := v.Type
		if v_0.Op != OpCom32 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAdd32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg32F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg32F (Const32F [c]))
	// cond: c != 0
	// result: (Const32F [-c])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		if !(c != 0) {
			break
		}
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(-c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neg64 (Const64 [c]))
	// result: (Const64 [-c])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(-c)
		return true
	}
	// match: (Neg64 (Sub64 x y))
	// result: (Sub64 y x)
	for {
		if v_0.Op != OpSub64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSub64)
		v.AddArg2(y, x)
		return true
	}
	// match: (Neg64 (Neg64 x))
	// result: x
	for {
		if v_0.Op != OpNeg64 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Neg64 <t> (Com64 x))
	// result: (Add64 (Const64 <t> [1]) x)
	for {
		t := v.Type
		if v_0.Op != OpCom64 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAdd64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg64F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg64F (Const64F [c]))
	// cond: c != 0
	// result: (Const64F [-c])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		if !(c != 0) {
			break
		}
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(-c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeg8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neg8 (Const8 [c]))
	// result: (Const8 [-c])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(-c)
		return true
	}
	// match: (Neg8 (Sub8 x y))
	// result: (Sub8 y x)
	for {
		if v_0.Op != OpSub8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpSub8)
		v.AddArg2(y, x)
		return true
	}
	// match: (Neg8 (Neg8 x))
	// result: x
	for {
		if v_0.Op != OpNeg8 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Neg8 <t> (Com8 x))
	// result: (Add8 (Const8 <t> [1]) x)
	for {
		t := v.Type
		if v_0.Op != OpCom8 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAdd8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Neq16 (Const16 <t> [c]) (Add16 (Const16 <t> [d]) x))
	// result: (Neq16 (Const16 <t> [c-d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpAdd16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst16 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt16(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpNeq16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Neq16 (Const16 [c]) (Const16 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (Neq16 n (Lsh16x64 (Rsh16x64 (Add16 <t> n (Rsh16Ux64 <t> (Rsh16x64 <t> n (Const64 <typ.UInt64> [15])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 15 && kbar == 16 - k
	// result: (Neq16 (And16 <t> n (Const16 <t> [1<<uint(k)-1])) (Const16 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpLsh16x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpRsh16x64 {
				continue
			}
			_ = v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAdd16 {
				continue
			}
			t := v_1_0_0.Type
			_ = v_1_0_0.Args[1]
			v_1_0_0_0 := v_1_0_0.Args[0]
			v_1_0_0_1 := v_1_0_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0_0_0, v_1_0_0_1 = _i1+1, v_1_0_0_1, v_1_0_0_0 {
				if n != v_1_0_0_0 || v_1_0_0_1.Op != OpRsh16Ux64 || v_1_0_0_1.Type != t {
					continue
				}
				_ = v_1_0_0_1.Args[1]
				v_1_0_0_1_0 := v_1_0_0_1.Args[0]
				if v_1_0_0_1_0.Op != OpRsh16x64 || v_1_0_0_1_0.Type != t {
					continue
				}
				_ = v_1_0_0_1_0.Args[1]
				if n != v_1_0_0_1_0.Args[0] {
					continue
				}
				v_1_0_0_1_0_1 := v_1_0_0_1_0.Args[1]
				if v_1_0_0_1_0_1.Op != OpConst64 || v_1_0_0_1_0_1.Type != typ.UInt64 || auxIntToInt64(v_1_0_0_1_0_1.AuxInt) != 15 {
					continue
				}
				v_1_0_0_1_1 := v_1_0_0_1.Args[1]
				if v_1_0_0_1_1.Op != OpConst64 || v_1_0_0_1_1.Type != typ.UInt64 {
					continue
				}
				kbar := auxIntToInt64(v_1_0_0_1_1.AuxInt)
				v_1_0_1 := v_1_0.Args[1]
				if v_1_0_1.Op != OpConst64 || v_1_0_1.Type != typ.UInt64 {
					continue
				}
				k := auxIntToInt64(v_1_0_1.AuxInt)
				v_1_1 := v_1.Args[1]
				if v_1_1.Op != OpConst64 || v_1_1.Type != typ.UInt64 || auxIntToInt64(v_1_1.AuxInt) != k || !(k > 0 && k < 15 && kbar == 16-k) {
					continue
				}
				v.reset(OpNeq16)
				v0 := b.NewValue0(v.Pos, OpAnd16, t)
				v1 := b.NewValue0(v.Pos, OpConst16, t)
				v1.AuxInt = int16ToAuxInt(1<<uint(k) - 1)
				v0.AddArg2(n, v1)
				v2 := b.NewValue0(v.Pos, OpConst16, t)
				v2.AuxInt = int16ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	// match: (Neq16 s:(Sub16 x y) (Const16 [0]))
	// cond: s.Uses == 1
	// result: (Neq16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			s := v_0
			if s.Op != OpSub16 {
				continue
			}
			y := s.Args[1]
			x := s.Args[0]
			if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != 0 || !(s.Uses == 1) {
				continue
			}
			v.reset(OpNeq16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Neq16 (And16 <t> x (Const16 <t> [y])) (Const16 <t> [y]))
	// cond: oneBit16(y)
	// result: (Eq16 (And16 <t> x (Const16 <t> [y])) (Const16 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd16 {
				continue
			}
			t := v_0.Type
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst16 || v_0_1.Type != t {
					continue
				}
				y := auxIntToInt16(v_0_1.AuxInt)
				if v_1.Op != OpConst16 || v_1.Type != t || auxIntToInt16(v_1.AuxInt) != y || !(oneBit16(y)) {
					continue
				}
				v.reset(OpEq16)
				v0 := b.NewValue0(v.Pos, OpAnd16, t)
				v1 := b.NewValue0(v.Pos, OpConst16, t)
				v1.AuxInt = int16ToAuxInt(y)
				v0.AddArg2(x, v1)
				v2 := b.NewValue0(v.Pos, OpConst16, t)
				v2.AuxInt = int16ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32 x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Neq32 (Const32 <t> [c]) (Add32 (Const32 <t> [d]) x))
	// result: (Neq32 (Const32 <t> [c-d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpAdd32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt32(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpNeq32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Neq32 (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (Neq32 n (Lsh32x64 (Rsh32x64 (Add32 <t> n (Rsh32Ux64 <t> (Rsh32x64 <t> n (Const64 <typ.UInt64> [31])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 31 && kbar == 32 - k
	// result: (Neq32 (And32 <t> n (Const32 <t> [1<<uint(k)-1])) (Const32 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpLsh32x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpRsh32x64 {
				continue
			}
			_ = v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAdd32 {
				continue
			}
			t := v_1_0_0.Type
			_ = v_1_0_0.Args[1]
			v_1_0_0_0 := v_1_0_0.Args[0]
			v_1_0_0_1 := v_1_0_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0_0_0, v_1_0_0_1 = _i1+1, v_1_0_0_1, v_1_0_0_0 {
				if n != v_1_0_0_0 || v_1_0_0_1.Op != OpRsh32Ux64 || v_1_0_0_1.Type != t {
					continue
				}
				_ = v_1_0_0_1.Args[1]
				v_1_0_0_1_0 := v_1_0_0_1.Args[0]
				if v_1_0_0_1_0.Op != OpRsh32x64 || v_1_0_0_1_0.Type != t {
					continue
				}
				_ = v_1_0_0_1_0.Args[1]
				if n != v_1_0_0_1_0.Args[0] {
					continue
				}
				v_1_0_0_1_0_1 := v_1_0_0_1_0.Args[1]
				if v_1_0_0_1_0_1.Op != OpConst64 || v_1_0_0_1_0_1.Type != typ.UInt64 || auxIntToInt64(v_1_0_0_1_0_1.AuxInt) != 31 {
					continue
				}
				v_1_0_0_1_1 := v_1_0_0_1.Args[1]
				if v_1_0_0_1_1.Op != OpConst64 || v_1_0_0_1_1.Type != typ.UInt64 {
					continue
				}
				kbar := auxIntToInt64(v_1_0_0_1_1.AuxInt)
				v_1_0_1 := v_1_0.Args[1]
				if v_1_0_1.Op != OpConst64 || v_1_0_1.Type != typ.UInt64 {
					continue
				}
				k := auxIntToInt64(v_1_0_1.AuxInt)
				v_1_1 := v_1.Args[1]
				if v_1_1.Op != OpConst64 || v_1_1.Type != typ.UInt64 || auxIntToInt64(v_1_1.AuxInt) != k || !(k > 0 && k < 31 && kbar == 32-k) {
					continue
				}
				v.reset(OpNeq32)
				v0 := b.NewValue0(v.Pos, OpAnd32, t)
				v1 := b.NewValue0(v.Pos, OpConst32, t)
				v1.AuxInt = int32ToAuxInt(1<<uint(k) - 1)
				v0.AddArg2(n, v1)
				v2 := b.NewValue0(v.Pos, OpConst32, t)
				v2.AuxInt = int32ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	// match: (Neq32 s:(Sub32 x y) (Const32 [0]))
	// cond: s.Uses == 1
	// result: (Neq32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			s := v_0
			if s.Op != OpSub32 {
				continue
			}
			y := s.Args[1]
			x := s.Args[0]
			if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != 0 || !(s.Uses == 1) {
				continue
			}
			v.reset(OpNeq32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Neq32 (And32 <t> x (Const32 <t> [y])) (Const32 <t> [y]))
	// cond: oneBit32(y)
	// result: (Eq32 (And32 <t> x (Const32 <t> [y])) (Const32 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd32 {
				continue
			}
			t := v_0.Type
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst32 || v_0_1.Type != t {
					continue
				}
				y := auxIntToInt32(v_0_1.AuxInt)
				if v_1.Op != OpConst32 || v_1.Type != t || auxIntToInt32(v_1.AuxInt) != y || !(oneBit32(y)) {
					continue
				}
				v.reset(OpEq32)
				v0 := b.NewValue0(v.Pos, OpAnd32, t)
				v1 := b.NewValue0(v.Pos, OpConst32, t)
				v1.AuxInt = int32ToAuxInt(y)
				v0.AddArg2(x, v1)
				v2 := b.NewValue0(v.Pos, OpConst32, t)
				v2.AuxInt = int32ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Neq32F (Const32F [c]) (Const32F [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v
```