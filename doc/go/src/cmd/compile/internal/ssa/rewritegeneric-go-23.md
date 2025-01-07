Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding and Context:**

* **File Path:** `go/src/cmd/compile/internal/ssa/rewritegeneric.go` immediately tells us this is part of the Go compiler, specifically within the SSA (Static Single Assignment) optimization phase. The "rewritegeneric" suggests this file contains generic rewriting rules applicable to various data types.
* **Function Signatures:** The functions like `rewriteValuegeneric_OpSub16`, `rewriteValuegeneric_OpSub32`, etc., clearly indicate these are functions that attempt to rewrite expressions involving subtraction (`Sub`) for different integer sizes (16-bit, 32-bit, etc.). The `rewriteValuegeneric_` prefix strongly implies a pattern related to SSA value rewriting.
* **SSA Concepts:**  Knowing SSA is crucial. Each `v` is an SSA value (think of it as a variable with a unique definition). `v.Op` is the operation of the value (e.g., `OpSub16`, `OpConst16`, `OpAdd16`). `v.Args` are the input values to the operation. `v.reset()` changes the operation of the current value. `b.NewValue0()` creates a new SSA value in the current block. `v.AddArg()` adds an argument to a value. `v.copyOf()` copies the value and its arguments.
* **Goal:** The primary goal of these functions is to simplify or optimize SSA code by replacing certain patterns of operations with more efficient equivalents.

**2. Analyzing Individual Code Blocks (Example: `rewriteValuegeneric_OpSub16`):**

* **Pattern Matching:** The code heavily uses nested `for` loops with `break` and `continue` to match specific patterns of SSA operations. The comments like `// match: (Sub16 (Const16 [c]) (Const16 [d]))` clearly describe the pattern being looked for.
* **Operation Codes:**  Understanding the `Op...` constants is key. `OpConst16` represents a 16-bit constant, `OpAdd16` is 16-bit addition, `OpMul16` is 16-bit multiplication, and so on.
* **Auxiliary Information:**  `v.AuxInt` often stores the value of a constant. Helper functions like `auxIntToInt16` and `int16ToAuxInt` are used to convert between the raw `AuxInt` representation and the actual integer value. `v.Type` holds the data type of the SSA value.
* **Rewriting Rules:** Once a pattern is matched, the code uses `v.reset()` to change the operation and `v.AddArg()` or `v.AddArg2()` to set the new arguments, effectively rewriting the SSA expression.
* **Conditions (`cond:`):**  Some rewrite rules have conditional checks (`if !(...) { break }` or `if !(condition) { continue }`). These conditions ensure the rewrite is only applied when it's safe and beneficial.
* **Symmetry:** Notice patterns like the multiplication rewrite where the order of `x` and `y` in `Mul16 x y` doesn't matter. The inner loop with `_i0` and swapping of `v_0_0` and `v_0_1` handles this symmetry.

**3. Inferring Go Language Features:**

* **Arithmetic Operations:** The presence of `OpAdd`, `OpSub`, `OpMul`, `OpNeg`, `OpCom` for various integer sizes directly relates to Go's integer arithmetic operators (`+`, `-`, `*`, unary `-`, `^`).
* **Constants:**  `OpConst` represents Go's integer and floating-point constants.
* **Type Conversions/Truncation:** Functions like `rewriteValuegeneric_OpTrunc16to8` and the corresponding `OpTrunc...` operations relate to Go's type conversion rules, especially when narrowing integer types (e.g., `int8(myInt16)`).
* **Bitwise Operations:** Although not as prevalent in this snippet, the presence of `OpCom` suggests bitwise complement (`^`). Other bitwise operations (AND, OR, XOR, shifts) would likely have similar rewrite functions elsewhere.

**4. Code Examples and Reasoning:**

* The provided examples are excellent. They take a snippet of Go code and show how it might be transformed into SSA, and then how the rewrite rules optimize it. For instance, the `a - 10` example with `OpAdd16(OpConst16(-10), a)` clearly illustrates the rewrite of subtraction with a constant into addition of a negative constant.

**5. Command-Line Parameters and User Mistakes:**

* The code itself doesn't directly handle command-line parameters. These rewrite rules are applied internally by the Go compiler.
* User mistakes aren't directly related to *using* this code (as it's internal). However, the optimizations themselves highlight potential areas where the compiler helps:
    *  Writing `a - a` which the compiler simplifies to `0`.
    *  Redundant operations like `x - (-y)` becoming `x + y`.

**6. Summarizing the Function (For the 24th part):**

* At this point (part 24), the code has primarily focused on rewriting subtraction operations (`OpSub`) for various integer sizes (8, 16, 32, 64 bits) and floating-point types (32F, 64F). It includes optimizations for:
    * Subtracting constants.
    * Simplifying expressions involving multiplication, addition, negation, and complement.
    * Handling specific patterns with constants to further simplify expressions.
    * Basic algebraic identities.
* The code also starts to include rewrites for truncation operations (`OpTrunc...`), which are related to type conversions.

**7. Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This looks like a lot of repetitive code."
* **Refinement:** "Yes, but the repetition is structured around the different integer sizes. The underlying optimization logic is similar, just applied to different types." This understanding is crucial for summarizing the functionality efficiently.
* **Initial thought:** "How does this connect to the actual compilation process?"
* **Refinement:** "These are *rewriting rules* applied during the SSA optimization phase. The compiler will generate the initial SSA, and then these functions will be called to simplify it before code generation."

By following these steps, we can effectively analyze the given Go code snippet, understand its purpose within the Go compiler, and infer the related Go language features and optimizations. The key is to combine knowledge of Go, compiler principles (especially SSA), and careful examination of the code patterns.这是 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 文件的一部分，主要定义了一系列用于简化和优化 Go 语言代码的 **SSA (Static Single Assignment) 中间表示** 的重写规则。这些规则针对的是 **泛型操作**，意味着它们不依赖于特定的硬件架构，可以在不同的平台上应用。

具体到你提供的第 24 部分代码，它主要集中在 **`OpSub` (减法) 操作** 的重写规则，涵盖了 `int8`、`int16`、`int32` 和 `int64` 这几种整数类型，以及 `float32` 和 `float64` 浮点数类型。 此外，还包括了 `OpTrunc` (截断) 和 `OpTruncXtoY` (类型截断) 操作的重写规则。

**功能归纳：**

这部分代码的功能是定义了针对不同数据类型的减法和截断操作的优化规则。这些规则的目标是将复杂的或冗余的减法和截断运算替换为更简单、更高效的形式，例如：

* **常量折叠：** 将两个常量相减直接计算出结果常量。
* **代数简化：**  例如 `x - x` 简化为 `0`， `x - (-y)` 简化为 `x + y`。
* **模式匹配和替换：**  识别特定的操作模式，并将其替换为等价但更优化的形式。例如，将 `a - constant` 替换为 `a + (-constant)`，这可能为后续的优化创造条件。
* **消除冗余转换：** 例如，将先扩展再截断的操作简化为原始值。

**推断 Go 语言功能及代码示例：**

这部分代码主要处理的是 Go 语言中的 **算术运算 (减法)** 和 **类型转换 (截断)**。

**1. 减法运算的优化 (`OpSub`)**

```go
package main

import "fmt"

func main() {
	a := 10
	b := 5
	c := a - b
	fmt.Println(c) // Output: 5

	d := a - a
	fmt.Println(d) // Output: 0

	e := a - (-b)
	fmt.Println(e) // Output: 15
}
```

**假设的 SSA 输入和输出 (针对 `a - b`)：**

**输入 SSA (简化表示):**

```
v1 = Const32 [10]  // a
v2 = Const32 [5]   // b
v3 = Sub32 v1 v2     // a - b
```

**应用 `rewriteValuegeneric_OpSub32` 中常量折叠规则后的输出 SSA：**

```
v1 = Const32 [10]
v2 = Const32 [5]
v3 = Const32 [5]   // 直接计算出 10 - 5 的结果
```

**假设的 SSA 输入和输出 (针对 `a - a`)：**

**输入 SSA:**

```
v1 = ... // 代表变量 a 的 SSA 值
v2 = ... // 同样代表变量 a 的 SSA 值 (在 SSA 中，即使是同一个变量，每次使用也可能有不同的版本)
v3 = Sub32 v1 v2
```

**应用 `rewriteValuegeneric_OpSub32` 中 `x - x` 规则后的输出 SSA：**

```
v1 = ...
v2 = ...
v3 = Const32 [0]
```

**假设的 SSA 输入和输出 (针对 `a - (-b)`)：**

**输入 SSA:**

```
v1 = Const32 [10]  // a
v2 = Const32 [5]   // b
v3 = Neg32 v2      // -b
v4 = Sub32 v1 v3     // a - (-b)
```

**应用 `rewriteValuegeneric_OpSub32` 中 `x - (-y)` 模式匹配规则后的输出 SSA：**

```
v1 = Const32 [10]
v2 = Const32 [5]
v3 = Neg32 v2
v4 = Add32 v1 v2    // 替换为 a + b
```

**2. 类型截断的优化 (`OpTruncXtoY`)**

```go
package main

import "fmt"

func main() {
	var a int16 = 258
	b := int8(a)
	fmt.Println(b) // Output: 2
}
```

**假设的 SSA 输入和输出：**

**输入 SSA (简化表示):**

```
v1 = Const16 [258] // a
v2 = Trunc16to8 v1  // int8(a)
```

**应用 `rewriteValuegeneric_OpTrunc16to8` 中常量折叠规则后的输出 SSA：**

```
v1 = Const16 [258]
v2 = Const8 [2]    // 直接计算出截断后的结果
```

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。`rewritegeneric.go` 是 Go 编译器内部的一部分，它的功能是在编译过程中自动执行的。命令行参数的处理发生在编译器的其他阶段，例如语法分析和语义分析。

**使用者易犯错的点：**

作为编译器开发者，在编写或修改这些重写规则时，容易犯错的点包括：

* **模式匹配不准确：**  编写的匹配规则可能过于宽泛或过于狭窄，导致错误的替换或遗漏优化机会。
* **条件判断错误：**  `cond:` 中的条件判断逻辑错误可能导致不安全的优化。
* **类型不匹配：**  在重写过程中，操作数的类型必须保持一致，否则会导致编译错误。
* **引入无限循环：** 如果重写规则没有正确地终止条件，可能会导致 SSA 图的无限重写。

**第 24 部分的功能归纳：**

第 24 部分的 `rewritegeneric.go` 主要定义了针对 Go 语言中不同大小的整数和浮点数的减法运算 (`OpSub`) 以及类型截断运算 (`OpTrunc` 和 `OpTruncXtoY`) 的一系列优化规则。这些规则旨在简化 SSA 中间表示，提高代码执行效率。它通过常量折叠、代数简化和模式匹配等技术，将复杂的运算转化为更简单的等价形式。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第24部分，共26部分，请归纳一下它的功能

"""
	if v_1.Op != OpConst16 {
			break
		}
		t := v_1.Type
		c := auxIntToInt16(v_1.AuxInt)
		if !(x.Op != OpConst16) {
			break
		}
		v.reset(OpAdd16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(-c)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub16 <t> (Mul16 x y) (Mul16 x z))
	// result: (Mul16 x (Sub16 <t> y z))
	for {
		t := v.Type
		if v_0.Op != OpMul16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if v_1.Op != OpMul16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				z := v_1_1
				v.reset(OpMul16)
				v0 := b.NewValue0(v.Pos, OpSub16, t)
				v0.AddArg2(y, z)
				v.AddArg2(x, v0)
				return true
			}
		}
		break
	}
	// match: (Sub16 x x)
	// result: (Const16 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Sub16 (Neg16 x) (Com16 x))
	// result: (Const16 [1])
	for {
		if v_0.Op != OpNeg16 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpCom16 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(1)
		return true
	}
	// match: (Sub16 (Com16 x) (Neg16 x))
	// result: (Const16 [-1])
	for {
		if v_0.Op != OpCom16 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpNeg16 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(-1)
		return true
	}
	// match: (Sub16 (Add16 t x) (Add16 t y))
	// result: (Sub16 x y)
	for {
		if v_0.Op != OpAdd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			t := v_0_0
			x := v_0_1
			if v_1.Op != OpAdd16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpSub16)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Sub16 (Add16 x y) x)
	// result: y
	for {
		if v_0.Op != OpAdd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if x != v_1 {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Sub16 (Add16 x y) y)
	// result: x
	for {
		if v_0.Op != OpAdd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if y != v_1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Sub16 (Sub16 x y) x)
	// result: (Neg16 y)
	for {
		if v_0.Op != OpSub16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpNeg16)
		v.AddArg(y)
		return true
	}
	// match: (Sub16 x (Add16 x y))
	// result: (Neg16 y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if x != v_1_0 {
				continue
			}
			y := v_1_1
			v.reset(OpNeg16)
			v.AddArg(y)
			return true
		}
		break
	}
	// match: (Sub16 x (Sub16 i:(Const16 <t>) z))
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Sub16 (Add16 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		z := v_1.Args[1]
		i := v_1.Args[0]
		if i.Op != OpConst16 {
			break
		}
		t := i.Type
		if !(z.Op != OpConst16 && x.Op != OpConst16) {
			break
		}
		v.reset(OpSub16)
		v0 := b.NewValue0(v.Pos, OpAdd16, t)
		v0.AddArg2(x, z)
		v.AddArg2(v0, i)
		return true
	}
	// match: (Sub16 x (Add16 z i:(Const16 <t>)))
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Sub16 (Sub16 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z := v_1_0
			i := v_1_1
			if i.Op != OpConst16 {
				continue
			}
			t := i.Type
			if !(z.Op != OpConst16 && x.Op != OpConst16) {
				continue
			}
			v.reset(OpSub16)
			v0 := b.NewValue0(v.Pos, OpSub16, t)
			v0.AddArg2(x, z)
			v.AddArg2(v0, i)
			return true
		}
		break
	}
	// match: (Sub16 (Sub16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Sub16 i (Add16 <t> z x))
	for {
		if v_0.Op != OpSub16 {
			break
		}
		z := v_0.Args[1]
		i := v_0.Args[0]
		if i.Op != OpConst16 {
			break
		}
		t := i.Type
		x := v_1
		if !(z.Op != OpConst16 && x.Op != OpConst16) {
			break
		}
		v.reset(OpSub16)
		v0 := b.NewValue0(v.Pos, OpAdd16, t)
		v0.AddArg2(z, x)
		v.AddArg2(i, v0)
		return true
	}
	// match: (Sub16 (Add16 z i:(Const16 <t>)) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Add16 i (Sub16 <t> z x))
	for {
		if v_0.Op != OpAdd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			z := v_0_0
			i := v_0_1
			if i.Op != OpConst16 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst16 && x.Op != OpConst16) {
				continue
			}
			v.reset(OpAdd16)
			v0 := b.NewValue0(v.Pos, OpSub16, t)
			v0.AddArg2(z, x)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Sub16 (Const16 <t> [c]) (Sub16 (Const16 <t> [d]) x))
	// result: (Add16 (Const16 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpSub16 {
			break
		}
		x := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 || v_1_0.Type != t {
			break
		}
		d := auxIntToInt16(v_1_0.AuxInt)
		v.reset(OpAdd16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(c - d)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub16 (Const16 <t> [c]) (Add16 (Const16 <t> [d]) x))
	// result: (Sub16 (Const16 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpConst16 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt16(v_1_0.AuxInt)
			x := v_1_1
			v.reset(OpSub16)
			v0 := b.NewValue0(v.Pos, OpConst16, t)
			v0.AuxInt = int16ToAuxInt(c - d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSub32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Sub32 (Const32 [c]) (Const32 [d]))
	// result: (Const32 [c-d])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(c - d)
		return true
	}
	// match: (Sub32 x (Const32 <t> [c]))
	// cond: x.Op != OpConst32
	// result: (Add32 (Const32 <t> [-c]) x)
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		t := v_1.Type
		c := auxIntToInt32(v_1.AuxInt)
		if !(x.Op != OpConst32) {
			break
		}
		v.reset(OpAdd32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(-c)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub32 <t> (Mul32 x y) (Mul32 x z))
	// result: (Mul32 x (Sub32 <t> y z))
	for {
		t := v.Type
		if v_0.Op != OpMul32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				z := v_1_1
				v.reset(OpMul32)
				v0 := b.NewValue0(v.Pos, OpSub32, t)
				v0.AddArg2(y, z)
				v.AddArg2(x, v0)
				return true
			}
		}
		break
	}
	// match: (Sub32 x x)
	// result: (Const32 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Sub32 (Neg32 x) (Com32 x))
	// result: (Const32 [1])
	for {
		if v_0.Op != OpNeg32 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpCom32 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (Sub32 (Com32 x) (Neg32 x))
	// result: (Const32 [-1])
	for {
		if v_0.Op != OpCom32 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpNeg32 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(-1)
		return true
	}
	// match: (Sub32 (Add32 t x) (Add32 t y))
	// result: (Sub32 x y)
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			t := v_0_0
			x := v_0_1
			if v_1.Op != OpAdd32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpSub32)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Sub32 (Add32 x y) x)
	// result: y
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if x != v_1 {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Sub32 (Add32 x y) y)
	// result: x
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if y != v_1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Sub32 (Sub32 x y) x)
	// result: (Neg32 y)
	for {
		if v_0.Op != OpSub32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpNeg32)
		v.AddArg(y)
		return true
	}
	// match: (Sub32 x (Add32 x y))
	// result: (Neg32 y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if x != v_1_0 {
				continue
			}
			y := v_1_1
			v.reset(OpNeg32)
			v.AddArg(y)
			return true
		}
		break
	}
	// match: (Sub32 x (Sub32 i:(Const32 <t>) z))
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Sub32 (Add32 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		z := v_1.Args[1]
		i := v_1.Args[0]
		if i.Op != OpConst32 {
			break
		}
		t := i.Type
		if !(z.Op != OpConst32 && x.Op != OpConst32) {
			break
		}
		v.reset(OpSub32)
		v0 := b.NewValue0(v.Pos, OpAdd32, t)
		v0.AddArg2(x, z)
		v.AddArg2(v0, i)
		return true
	}
	// match: (Sub32 x (Add32 z i:(Const32 <t>)))
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Sub32 (Sub32 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z := v_1_0
			i := v_1_1
			if i.Op != OpConst32 {
				continue
			}
			t := i.Type
			if !(z.Op != OpConst32 && x.Op != OpConst32) {
				continue
			}
			v.reset(OpSub32)
			v0 := b.NewValue0(v.Pos, OpSub32, t)
			v0.AddArg2(x, z)
			v.AddArg2(v0, i)
			return true
		}
		break
	}
	// match: (Sub32 (Sub32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Sub32 i (Add32 <t> z x))
	for {
		if v_0.Op != OpSub32 {
			break
		}
		z := v_0.Args[1]
		i := v_0.Args[0]
		if i.Op != OpConst32 {
			break
		}
		t := i.Type
		x := v_1
		if !(z.Op != OpConst32 && x.Op != OpConst32) {
			break
		}
		v.reset(OpSub32)
		v0 := b.NewValue0(v.Pos, OpAdd32, t)
		v0.AddArg2(z, x)
		v.AddArg2(i, v0)
		return true
	}
	// match: (Sub32 (Add32 z i:(Const32 <t>)) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Add32 i (Sub32 <t> z x))
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			z := v_0_0
			i := v_0_1
			if i.Op != OpConst32 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst32 && x.Op != OpConst32) {
				continue
			}
			v.reset(OpAdd32)
			v0 := b.NewValue0(v.Pos, OpSub32, t)
			v0.AddArg2(z, x)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Sub32 (Const32 <t> [c]) (Sub32 (Const32 <t> [d]) x))
	// result: (Add32 (Const32 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpSub32 {
			break
		}
		x := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 || v_1_0.Type != t {
			break
		}
		d := auxIntToInt32(v_1_0.AuxInt)
		v.reset(OpAdd32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(c - d)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub32 (Const32 <t> [c]) (Add32 (Const32 <t> [d]) x))
	// result: (Sub32 (Const32 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpConst32 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt32(v_1_0.AuxInt)
			x := v_1_1
			v.reset(OpSub32)
			v0 := b.NewValue0(v.Pos, OpConst32, t)
			v0.AuxInt = int32ToAuxInt(c - d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSub32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Sub32F (Const32F [c]) (Const32F [d]))
	// cond: c-d == c-d
	// result: (Const32F [c-d])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		if v_1.Op != OpConst32F {
			break
		}
		d := auxIntToFloat32(v_1.AuxInt)
		if !(c-d == c-d) {
			break
		}
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(c - d)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSub64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Sub64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c-d])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(c - d)
		return true
	}
	// match: (Sub64 x (Const64 <t> [c]))
	// cond: x.Op != OpConst64
	// result: (Add64 (Const64 <t> [-c]) x)
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(x.Op != OpConst64) {
			break
		}
		v.reset(OpAdd64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(-c)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub64 <t> (Mul64 x y) (Mul64 x z))
	// result: (Mul64 x (Sub64 <t> y z))
	for {
		t := v.Type
		if v_0.Op != OpMul64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if v_1.Op != OpMul64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				z := v_1_1
				v.reset(OpMul64)
				v0 := b.NewValue0(v.Pos, OpSub64, t)
				v0.AddArg2(y, z)
				v.AddArg2(x, v0)
				return true
			}
		}
		break
	}
	// match: (Sub64 x x)
	// result: (Const64 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Sub64 (Neg64 x) (Com64 x))
	// result: (Const64 [1])
	for {
		if v_0.Op != OpNeg64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpCom64 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (Sub64 (Com64 x) (Neg64 x))
	// result: (Const64 [-1])
	for {
		if v_0.Op != OpCom64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpNeg64 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (Sub64 (Add64 t x) (Add64 t y))
	// result: (Sub64 x y)
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			t := v_0_0
			x := v_0_1
			if v_1.Op != OpAdd64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpSub64)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Sub64 (Add64 x y) x)
	// result: y
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if x != v_1 {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Sub64 (Add64 x y) y)
	// result: x
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if y != v_1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Sub64 (Sub64 x y) x)
	// result: (Neg64 y)
	for {
		if v_0.Op != OpSub64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpNeg64)
		v.AddArg(y)
		return true
	}
	// match: (Sub64 x (Add64 x y))
	// result: (Neg64 y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if x != v_1_0 {
				continue
			}
			y := v_1_1
			v.reset(OpNeg64)
			v.AddArg(y)
			return true
		}
		break
	}
	// match: (Sub64 x (Sub64 i:(Const64 <t>) z))
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Sub64 (Add64 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		z := v_1.Args[1]
		i := v_1.Args[0]
		if i.Op != OpConst64 {
			break
		}
		t := i.Type
		if !(z.Op != OpConst64 && x.Op != OpConst64) {
			break
		}
		v.reset(OpSub64)
		v0 := b.NewValue0(v.Pos, OpAdd64, t)
		v0.AddArg2(x, z)
		v.AddArg2(v0, i)
		return true
	}
	// match: (Sub64 x (Add64 z i:(Const64 <t>)))
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Sub64 (Sub64 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z := v_1_0
			i := v_1_1
			if i.Op != OpConst64 {
				continue
			}
			t := i.Type
			if !(z.Op != OpConst64 && x.Op != OpConst64) {
				continue
			}
			v.reset(OpSub64)
			v0 := b.NewValue0(v.Pos, OpSub64, t)
			v0.AddArg2(x, z)
			v.AddArg2(v0, i)
			return true
		}
		break
	}
	// match: (Sub64 (Sub64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Sub64 i (Add64 <t> z x))
	for {
		if v_0.Op != OpSub64 {
			break
		}
		z := v_0.Args[1]
		i := v_0.Args[0]
		if i.Op != OpConst64 {
			break
		}
		t := i.Type
		x := v_1
		if !(z.Op != OpConst64 && x.Op != OpConst64) {
			break
		}
		v.reset(OpSub64)
		v0 := b.NewValue0(v.Pos, OpAdd64, t)
		v0.AddArg2(z, x)
		v.AddArg2(i, v0)
		return true
	}
	// match: (Sub64 (Add64 z i:(Const64 <t>)) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Add64 i (Sub64 <t> z x))
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			z := v_0_0
			i := v_0_1
			if i.Op != OpConst64 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst64 && x.Op != OpConst64) {
				continue
			}
			v.reset(OpAdd64)
			v0 := b.NewValue0(v.Pos, OpSub64, t)
			v0.AddArg2(z, x)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Sub64 (Const64 <t> [c]) (Sub64 (Const64 <t> [d]) x))
	// result: (Add64 (Const64 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst64 {
			break
		}
		t := v_0.Type
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpSub64 {
			break
		}
		x := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 || v_1_0.Type != t {
			break
		}
		d := auxIntToInt64(v_1_0.AuxInt)
		v.reset(OpAdd64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c - d)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub64 (Const64 <t> [c]) (Add64 (Const64 <t> [d]) x))
	// result: (Sub64 (Const64 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst64 {
			break
		}
		t := v_0.Type
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpConst64 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt64(v_1_0.AuxInt)
			x := v_1_1
			v.reset(OpSub64)
			v0 := b.NewValue0(v.Pos, OpConst64, t)
			v0.AuxInt = int64ToAuxInt(c - d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSub64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Sub64F (Const64F [c]) (Const64F [d]))
	// cond: c-d == c-d
	// result: (Const64F [c-d])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		if v_1.Op != OpConst64F {
			break
		}
		d := auxIntToFloat64(v_1.AuxInt)
		if !(c-d == c-d) {
			break
		}
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(c - d)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSub8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Sub8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c-d])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst8 {
			break
		}
		d := auxIntToInt8(v_1.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(c - d)
		return true
	}
	// match: (Sub8 x (Const8 <t> [c]))
	// cond: x.Op != OpConst8
	// result: (Add8 (Const8 <t> [-c]) x)
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		t := v_1.Type
		c := auxIntToInt8(v_1.AuxInt)
		if !(x.Op != OpConst8) {
			break
		}
		v.reset(OpAdd8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(-c)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub8 <t> (Mul8 x y) (Mul8 x z))
	// result: (Mul8 x (Sub8 <t> y z))
	for {
		t := v.Type
		if v_0.Op != OpMul8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if v_1.Op != OpMul8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				z := v_1_1
				v.reset(OpMul8)
				v0 := b.NewValue0(v.Pos, OpSub8, t)
				v0.AddArg2(y, z)
				v.AddArg2(x, v0)
				return true
			}
		}
		break
	}
	// match: (Sub8 x x)
	// result: (Const8 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Sub8 (Neg8 x) (Com8 x))
	// result: (Const8 [1])
	for {
		if v_0.Op != OpNeg8 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpCom8 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(1)
		return true
	}
	// match: (Sub8 (Com8 x) (Neg8 x))
	// result: (Const8 [-1])
	for {
		if v_0.Op != OpCom8 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpNeg8 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(-1)
		return true
	}
	// match: (Sub8 (Add8 t x) (Add8 t y))
	// result: (Sub8 x y)
	for {
		if v_0.Op != OpAdd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			t := v_0_0
			x := v_0_1
			if v_1.Op != OpAdd8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpSub8)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Sub8 (Add8 x y) x)
	// result: y
	for {
		if v_0.Op != OpAdd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if x != v_1 {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Sub8 (Add8 x y) y)
	// result: x
	for {
		if v_0.Op != OpAdd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if y != v_1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Sub8 (Sub8 x y) x)
	// result: (Neg8 y)
	for {
		if v_0.Op != OpSub8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpNeg8)
		v.AddArg(y)
		return true
	}
	// match: (Sub8 x (Add8 x y))
	// result: (Neg8 y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if x != v_1_0 {
				continue
			}
			y := v_1_1
			v.reset(OpNeg8)
			v.AddArg(y)
			return true
		}
		break
	}
	// match: (Sub8 x (Sub8 i:(Const8 <t>) z))
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Sub8 (Add8 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		z := v_1.Args[1]
		i := v_1.Args[0]
		if i.Op != OpConst8 {
			break
		}
		t := i.Type
		if !(z.Op != OpConst8 && x.Op != OpConst8) {
			break
		}
		v.reset(OpSub8)
		v0 := b.NewValue0(v.Pos, OpAdd8, t)
		v0.AddArg2(x, z)
		v.AddArg2(v0, i)
		return true
	}
	// match: (Sub8 x (Add8 z i:(Const8 <t>)))
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Sub8 (Sub8 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z := v_1_0
			i := v_1_1
			if i.Op != OpConst8 {
				continue
			}
			t := i.Type
			if !(z.Op != OpConst8 && x.Op != OpConst8) {
				continue
			}
			v.reset(OpSub8)
			v0 := b.NewValue0(v.Pos, OpSub8, t)
			v0.AddArg2(x, z)
			v.AddArg2(v0, i)
			return true
		}
		break
	}
	// match: (Sub8 (Sub8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Sub8 i (Add8 <t> z x))
	for {
		if v_0.Op != OpSub8 {
			break
		}
		z := v_0.Args[1]
		i := v_0.Args[0]
		if i.Op != OpConst8 {
			break
		}
		t := i.Type
		x := v_1
		if !(z.Op != OpConst8 && x.Op != OpConst8) {
			break
		}
		v.reset(OpSub8)
		v0 := b.NewValue0(v.Pos, OpAdd8, t)
		v0.AddArg2(z, x)
		v.AddArg2(i, v0)
		return true
	}
	// match: (Sub8 (Add8 z i:(Const8 <t>)) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Add8 i (Sub8 <t> z x))
	for {
		if v_0.Op != OpAdd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			z := v_0_0
			i := v_0_1
			if i.Op != OpConst8 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst8 && x.Op != OpConst8) {
				continue
			}
			v.reset(OpAdd8)
			v0 := b.NewValue0(v.Pos, OpSub8, t)
			v0.AddArg2(z, x)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Sub8 (Const8 <t> [c]) (Sub8 (Const8 <t> [d]) x))
	// result: (Add8 (Const8 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpSub8 {
			break
		}
		x := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 || v_1_0.Type != t {
			break
		}
		d := auxIntToInt8(v_1_0.AuxInt)
		v.reset(OpAdd8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(c - d)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub8 (Const8 <t> [c]) (Add8 (Const8 <t> [d]) x))
	// result: (Sub8 (Const8 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpConst8 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt8(v_1_0.AuxInt)
			x := v_1_1
			v.reset(OpSub8)
			v0 := b.NewValue0(v.Pos, OpConst8, t)
			v0.AuxInt = int8ToAuxInt(c - d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpTrunc(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc (Const64F [c]))
	// result: (Const64F [math.Trunc(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(math.Trunc(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpTrunc16to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc16to8 (Const16 [c]))
	// result: (Const8 [int8(c)])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(int8(c))
		return true
	}
	// match: (Trunc16to8 (ZeroExt8to16 x))
	// result: x
	for {
		if v_0.Op != OpZeroExt8to16 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc16to8 (SignExt8to16 x))
	// result: x
	for {
		if v_0.Op != OpSignExt8to16 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc16to8 (And16 (Const16 [y]) x))
	// cond: y&0xFF == 0xFF
	// result: (Trunc16to8 x)
	for {
		if v_0.Op != OpAnd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst16 {
				continue
			}
			y := auxIntToInt16(v_0_0.AuxInt)
			x := v_0_1
			if !(y&0xFF == 0xFF) {
				continue
			}
			v.reset(OpTrunc16to8)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpTrunc32to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc32to16 (Const32 [c]))
	// result: (Const16 [int16(c)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(c))
		return true
	}
	// match: (Trunc32to16 (ZeroExt8to32 x))
	// result: (ZeroExt8to16 x)
	for {
		if v_0.Op != OpZeroExt8to32 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpZeroExt8to16)
		v.AddArg(x)
		return true
	}
	// match: (Trunc32to16 (ZeroExt16to32 x))
	// result: x
	for {
		if v_0.Op != OpZeroExt16to32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc32to16 (SignExt8to32 x))
	// result: (SignExt8to16 x)
	for {
		if v_0.Op != OpSignExt8to32 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpSignExt8to16)
		v.AddArg(x)
		return true
	}
	// match: (Trunc32to16 (SignExt16to32 x))
	// result: x
	for {
		if v_0.Op != OpSignExt16to32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc32to16 (And32 (Const32 [y]) x))
	// cond: y&0xFFFF == 0xFFFF
	// result: (Trunc32to16 x)
	for {
		if v_0.Op != OpAnd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 {
				continue
			}
			y := auxIntToInt32(v_0_0.AuxInt)
			x := v_0_1
			if !(y&0xFFFF == 0xFFFF) {
				continue
			}
			v.reset(OpTrunc32to16)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpTrunc32to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc32to8 (Const32 [c]))
	// result: (Const8 [int8(c)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(int8(c))
		return true
	}
	// match: (Trunc32to8 (ZeroExt8to32 x))
	// result: x
	for {
		if v_0.Op != OpZeroExt8to32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc32to8 (SignExt8to32 x))
	// 
"""




```