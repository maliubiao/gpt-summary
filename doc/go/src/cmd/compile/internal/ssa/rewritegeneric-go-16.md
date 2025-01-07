Response:
Let's break down the thought process for analyzing this Go code snippet and generating the desired response.

**1. Understanding the Goal:**

The primary goal is to understand the *functionality* of the provided Go code, which is a part of the `rewritegeneric.go` file in the Go compiler. The request also asks for specific information like examples, command-line arguments (if applicable), common mistakes, and a summary.

**2. Initial Code Examination:**

The code consists of a series of Go functions named `rewriteValuegeneric_OpOr16`, `rewriteValuegeneric_OpOr32`, and `rewriteValuegeneric_OpOr64`. These function names immediately suggest they are related to the bitwise OR operation (`OpOr`) on different integer sizes (16, 32, and 64 bits).

**3. Deeper Dive into a Single Function (e.g., `rewriteValuegeneric_OpOr16`):**

* **Structure:** Each function has a similar structure:
    * It takes a pointer to a `Value` as input. This `Value` is likely an intermediate representation of an operation in the Go compiler's SSA (Static Single Assignment) form.
    * It initializes some variables (`v_0`, `v_1`, `b`, `config`). `b` likely refers to the current block in the control flow graph, and `config` holds compiler configuration details.
    * It contains multiple `for` loops (sometimes nested). The outer loops often iterate through permutations of the arguments of the `Or` operation.
    * Inside the loops, there are `if` conditions that check the `Op` field of the `Value` arguments. This suggests the code is trying to match specific patterns of operations.
    * If a pattern matches, the code might:
        * Call `v.reset(OpSomething)` to change the operation of the current `Value`.
        * Create new `Value`s using `b.NewValue0`.
        * Add arguments to the `Value` using `v.AddArg` or `v.AddArg2`.
        * Return `true`, indicating a rewrite occurred.
    * If no pattern matches, the function eventually returns `false`.

* **Pattern Matching Logic:** The `if` conditions are the core of the pattern matching. They check for specific sequences of operations (like `OpAnd16`, `OpConst16`, `OpLsh16x64`, `OpRsh16Ux64`, `OpSub64`, etc.). The code often extracts arguments from these operations and checks their properties (e.g., the `AuxInt` field of `OpConst` nodes, which represents the constant value).

* **Rewriting Logic:** When a pattern matches, the code rewrites the expression. For example, it might simplify an expression involving constants, rearrange operands, or recognize specific bit manipulation idioms (like the rotate left pattern).

**4. Generalizing the Observations:**

After analyzing one function, it becomes clear that the other functions (`rewriteValuegeneric_OpOr32` and `rewriteValuegeneric_OpOr64`) follow a very similar pattern but operate on 32-bit and 64-bit integers, respectively. The logic and the types of operations being matched are analogous.

**5. Inferring the Overall Functionality:**

The filename (`rewritegeneric.go`), the function names, and the code structure strongly suggest that this code performs *peephole optimizations* or *rewrites* on the SSA representation of Go code. It looks for specific patterns of operations involving bitwise OR and simplifies or transforms them into more efficient equivalents.

**6. Constructing Examples:**

Based on the identified patterns, we can construct Go code examples that trigger these rewrites. For instance, the code recognizes patterns for simplifying OR operations with constants, combining ORs with common operands, and converting left and right shifts into rotate operations.

**7. Identifying the Go Feature:**

The code directly manipulates bitwise OR operations, left shifts, right shifts, and complements. Therefore, it's directly related to Go's *bitwise operators*.

**8. Command-Line Arguments and Common Mistakes:**

Since this code is part of the Go compiler's internal workings, it doesn't directly involve user-facing command-line arguments. Common mistakes are also less relevant from a user perspective, as these optimizations happen automatically during compilation. However, a developer working on the compiler might make mistakes in defining or implementing these rewrite rules.

**9. Summarizing the Functionality:**

The summary should concisely describe the core purpose: optimizing bitwise OR operations by recognizing and rewriting specific patterns in the SSA representation.

**10. Iterative Refinement (Self-Correction):**

During the process, I might initially focus too narrowly on one specific optimization. Realizing the broader context (SSA rewrites, the `rewritegeneric.go` file) helps to refine the understanding and provide a more accurate and comprehensive answer. For example, I might initially think it's just about constant folding, but then the rotate left pattern shows it handles more complex bit manipulations. Similarly, understanding that this is part of the *compiler* helps clarify why there are no direct command-line arguments.
这是一个Go语言编译器的代码，路径为 `go/src/cmd/compile/internal/ssa/rewritegeneric.go`，它是SSA（Static Single Assignment）中间表示的一个重写规则文件。这个文件的第17部分主要定义了针对 **16位、32位和64位无符号整数的按位或（OR）操作** 的一系列优化和重写规则。

**功能归纳：**

该代码片段的功能是**对SSA中的按位或（OR）操作进行模式匹配和优化**。它尝试识别特定的操作模式，并将其转换为更简单或更高效的等价形式。这些优化包括但不限于：

* **常量折叠:**  如果OR运算的两个操作数都是常量，则直接计算结果。
* **代数化简:**  例如 `x | x` 简化为 `x`，`0 | x` 简化为 `x`，`-1 | x` 简化为 `-1`。
* **按位取反的优化:**  识别 `(^x) | (^y)` 并将其转换为 `^(x & y)`。
* **结合律和交换律的应用:**  例如将 `(c | z) | x` 且 `c` 是常量转换为 `c | (z | x)`，前提是 `z` 和 `x` 不是常量，以方便后续的常量折叠。
* **与运算和常量的结合优化:**  识别 `(x & c2) | c1` 且 `^(c1 | c2) == 0` 的情况，将其转化为 `c1 | x`。
* **识别位旋转操作:**  当OR运算由左移和右移构成时，如果满足特定条件，则将其识别为位旋转操作 (`RotateLeft`)。

**Go语言功能实现推断：**

这段代码是Go语言编译器的一部分，负责实现对Go语言中**位运算符 `|` (按位或)** 的优化。

**Go代码举例说明：**

假设我们有以下Go代码：

```go
package main

func orExample(a uint16, b uint16) uint16 {
	c := 0x00FF
	d := 0xFF00
	return (a << 8) | (b >> 8) // 可能被识别为 RotateLeft16
}

func orConstExample() uint16 {
	return 0x0F | 0xF0 //  会被常量折叠
}

func orIdentityExample(a uint16) uint16 {
	return 0 | a // 会被简化为 a
}

func orComplementExample(a uint16) uint16 {
	return ^a | 0xFFFF // 会被简化为 0xFFFF
}
```

**代码推理 (假设的输入与输出):**

当编译器处理 `orExample` 函数时，`rewritegeneric.go` 中的 `rewriteValuegeneric_OpOr16` 函数可能会识别出 `(a << 8) | (b >> 8)` 这种模式，并尝试将其转换为 `RotateLeft16` 操作，如果满足移位量互补的条件。

* **假设输入 (针对 `orExample` 中的 OR 操作):**
    * `v.Op` 是 `OpOr16`
    * `v.Args[0].Op` 是 `OpLsh16x??` (例如 `OpLsh16x64`)
    * `v.Args[1].Op` 是 `OpRsh16Ux??` (例如 `OpRsh16Ux64`)
    * 并且移位量满足旋转的条件 (例如，左移8位，右移8位)。

* **假设输出:**
    * `v.reset(OpRotateLeft16)`
    * `v.AddArg2(x, z)`  // 其中 x 是被旋转的值，z 是旋转的位数。

当编译器处理 `orConstExample` 函数时，`rewriteValuegeneric_OpOr16` 函数会识别出两个操作数都是常量的情况。

* **假设输入 (针对 `orConstExample` 中的 OR 操作):**
    * `v.Op` 是 `OpOr16`
    * `v.Args[0].Op` 是 `OpConst16`，`v.Args[0].AuxInt` 表示 `0x0F`
    * `v.Args[1].Op` 是 `OpConst16`，`v.Args[1].AuxInt` 表示 `0xF0`

* **假设输出:**
    * `v.reset(OpConst16)`
    * `v.AuxInt` 被设置为 `0x0F | 0xF0` 的结果，即 `0xFF`。

**命令行参数：**

此代码是编译器内部实现，不直接涉及用户在命令行中指定的参数。编译器的优化级别（例如 `-O1`, `-O2`）可能会影响这些重写规则的启用程度，但这部分代码本身不处理命令行参数。

**使用者易犯错的点：**

由于这是编译器内部的优化，普通Go语言使用者不会直接与这段代码交互，因此不存在使用者易犯错的点。 错误可能存在于编译器开发者的实现中，例如模式匹配的条件不正确，或者重写后的代码语义不等价。

**第17部分功能总结：**

`rewritegeneric.go` 文件的第17部分专门负责优化SSA中间表示中的 **16位、32位和64位无符号整数的按位或（OR）操作**。它通过模式匹配识别可以简化的 OR 运算，例如常量折叠、代数化简、按位取反的优化以及位旋转操作的识别，从而提升最终生成代码的效率。这部分是Go编译器进行后端优化的重要组成部分。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第17部分，共26部分，请归纳一下它的功能

"""
 {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd16 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst16 {
					continue
				}
				c2 := auxIntToInt16(v_0_1.AuxInt)
				if v_1.Op != OpConst16 {
					continue
				}
				t := v_1.Type
				c1 := auxIntToInt16(v_1.AuxInt)
				if !(^(c1 | c2) == 0) {
					continue
				}
				v.reset(OpOr16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c1)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or16 (Or16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Or16 i (Or16 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOr16 {
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
				v.reset(OpOr16)
				v0 := b.NewValue0(v.Pos, OpOr16, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Or16 (Const16 <t> [c]) (Or16 (Const16 <t> [d]) x))
	// result: (Or16 (Const16 <t> [c|d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpOr16 {
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
				v.reset(OpOr16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c | d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or16 (Lsh16x64 x z:(Const64 <t> [c])) (Rsh16Ux64 x (Const64 [d])))
	// cond: c < 16 && d == 16-c && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh16x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh16Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 16 && d == 16-c && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or16 left:(Lsh16x64 x y) right:(Rsh16Ux64 x (Sub64 (Const64 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or16 left:(Lsh16x32 x y) right:(Rsh16Ux32 x (Sub32 (Const32 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or16 left:(Lsh16x16 x y) right:(Rsh16Ux16 x (Sub16 (Const16 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or16 left:(Lsh16x8 x y) right:(Rsh16Ux8 x (Sub8 (Const8 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or16 right:(Rsh16Ux64 x y) left:(Lsh16x64 x z:(Sub64 (Const64 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or16 right:(Rsh16Ux32 x y) left:(Lsh16x32 x z:(Sub32 (Const32 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or16 right:(Rsh16Ux16 x y) left:(Lsh16x16 x z:(Sub16 (Const16 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or16 right:(Rsh16Ux8 x y) left:(Lsh16x8 x z:(Sub8 (Const8 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpOr32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Or32 (Const32 [c]) (Const32 [d]))
	// result: (Const32 [c|d])
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
			v.AuxInt = int32ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (Or32 <t> (Com32 x) (Com32 y))
	// result: (Com32 (And32 <t> x y))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom32 {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpCom32 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpCom32)
			v0 := b.NewValue0(v.Pos, OpAnd32, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Or32 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Or32 (Const32 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Or32 (Const32 [-1]) _)
	// result: (Const32 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != -1 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or32 (Com32 x) x)
	// result: (Const32 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom32 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or32 x (Or32 x y))
	// result: (Or32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpOr32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpOr32)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Or32 (And32 x (Const32 [c2])) (Const32 <t> [c1]))
	// cond: ^(c1 | c2) == 0
	// result: (Or32 (Const32 <t> [c1]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd32 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst32 {
					continue
				}
				c2 := auxIntToInt32(v_0_1.AuxInt)
				if v_1.Op != OpConst32 {
					continue
				}
				t := v_1.Type
				c1 := auxIntToInt32(v_1.AuxInt)
				if !(^(c1 | c2) == 0) {
					continue
				}
				v.reset(OpOr32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c1)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or32 (Or32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Or32 i (Or32 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOr32 {
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
				v.reset(OpOr32)
				v0 := b.NewValue0(v.Pos, OpOr32, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Or32 (Const32 <t> [c]) (Or32 (Const32 <t> [d]) x))
	// result: (Or32 (Const32 <t> [c|d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpOr32 {
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
				v.reset(OpOr32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c | d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or32 (Lsh32x64 x z:(Const64 <t> [c])) (Rsh32Ux64 x (Const64 [d])))
	// cond: c < 32 && d == 32-c && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh32x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh32Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 32 && d == 32-c && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or32 left:(Lsh32x64 x y) right:(Rsh32Ux64 x (Sub64 (Const64 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or32 left:(Lsh32x32 x y) right:(Rsh32Ux32 x (Sub32 (Const32 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or32 left:(Lsh32x16 x y) right:(Rsh32Ux16 x (Sub16 (Const16 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or32 left:(Lsh32x8 x y) right:(Rsh32Ux8 x (Sub8 (Const8 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or32 right:(Rsh32Ux64 x y) left:(Lsh32x64 x z:(Sub64 (Const64 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or32 right:(Rsh32Ux32 x y) left:(Lsh32x32 x z:(Sub32 (Const32 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or32 right:(Rsh32Ux16 x y) left:(Lsh32x16 x z:(Sub16 (Const16 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or32 right:(Rsh32Ux8 x y) left:(Lsh32x8 x z:(Sub8 (Const8 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpOr64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Or64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c|d])
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
			v.AuxInt = int64ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (Or64 <t> (Com64 x) (Com64 y))
	// result: (Com64 (And64 <t> x y))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom64 {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpCom64 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpCom64)
			v0 := b.NewValue0(v.Pos, OpAnd64, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Or64 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Or64 (Const64 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Or64 (Const64 [-1]) _)
	// result: (Const64 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != -1 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or64 (Com64 x) x)
	// result: (Const64 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom64 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or64 x (Or64 x y))
	// result: (Or64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpOr64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpOr64)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Or64 (And64 x (Const64 [c2])) (Const64 <t> [c1]))
	// cond: ^(c1 | c2) == 0
	// result: (Or64 (Const64 <t> [c1]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd64 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst64 {
					continue
				}
				c2 := auxIntToInt64(v_0_1.AuxInt)
				if v_1.Op != OpConst64 {
					continue
				}
				t := v_1.Type
				c1 := auxIntToInt64(v_1.AuxInt)
				if !(^(c1 | c2) == 0) {
					continue
				}
				v.reset(OpOr64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c1)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or64 (Or64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Or64 i (Or64 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOr64 {
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
				v.reset(OpOr64)
				v0 := b.NewValue0(v.Pos, OpOr64, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Or64 (Const64 <t> [c]) (Or64 (Const64 <t> [d]) x))
	// result: (Or64 (Const64 <t> [c|d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpOr64 {
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
				v.reset(OpOr64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c | d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or64 (Lsh64x64 x z:(Const64 <t> [c])) (Rsh64Ux64 x (Const64 [d])))
	// cond: c < 64 && d == 64-c && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh64x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh64Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 64 && d == 64-c && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or64 left:(Lsh64x64 x y) right:(Rsh64Ux64 x (Sub64 (Const64 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or64 left:(Lsh64x32 x y) right:(Rsh64Ux32 x (Sub32 (Const32 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or64 left:(Lsh64x16 x y) right:(Rsh64Ux16 x (Sub16 (Const16 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or64 left:(Lsh64x8 x y) right:(Rsh64Ux8 x (Sub8 (Const8 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Or64 right:(Rsh64Ux64 x y) left:(Lsh64x64 x z:(Sub64 (Const64 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or64 right:(Rsh64Ux32 x y) left:(Lsh64x32 x z:(Sub32 (Const32 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(
"""




```