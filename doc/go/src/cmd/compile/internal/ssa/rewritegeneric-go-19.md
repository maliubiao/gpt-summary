Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional description of the provided Go code snippet, which is a part of the `rewritegeneric.go` file within the Go compiler. It specifically asks for the implemented Go language feature, code examples, reasoning with assumptions, command-line argument handling (if any), common mistakes, and a summary of the functionality given it's part 20 of 26.

2. **Analyze the Code:** The code consists of multiple Go functions, all named `rewriteValuegeneric_OpSomething`. Each function takes a `*Value` as input and returns a boolean. The core logic within each function is a series of `match:` and `cond:` blocks followed by `result:`. This structure strongly suggests a pattern-matching and replacement system. The `Op` fields within the `match:` blocks refer to specific operation codes (like `OpRotateLeft32`, `OpAdd64`, `OpConst64`). The `cond:` blocks contain boolean expressions that further restrict the matches. The `result:` blocks describe how to rewrite the input `Value` if a match occurs.

3. **Identify the Core Functionality:** The repeated pattern of matching specific operations and their arguments, along with the renaming of variables and restructuring of the expression, points towards **compiler optimizations**. Specifically, these functions seem to be implementing rewrite rules for the SSA (Static Single Assignment) intermediate representation used by the Go compiler.

4. **Infer the Targeted Go Language Feature:** The specific operations like `RotateLeft32`, `RotateLeft64`, and `RotateLeft8` clearly relate to **bitwise rotation operations** in Go. The code is optimizing these operations under various conditions involving constants and other arithmetic operations.

5. **Construct Code Examples:** To illustrate the optimizations, I need to provide Go code snippets that would trigger these rewrite rules. I will focus on the most common and easily understandable rules. For instance, the rule `// match: (RotateLeft32 x (Const32 [c])) // cond: c%32 == 0 // result: x` shows an optimization where rotating by a multiple of 32 bits does nothing. A simple example would be `y := x << 32 | x >> (32 - 32)`. Similarly, optimizations involving additions with constants that are multiples of the bit size (e.g., `c & 31 == 0`) are good candidates for examples.

6. **Reason About Input and Output:**  For each code example, I need to specify the *assumed* input SSA representation and the *expected* output SSA representation after the rewrite rule is applied. This involves understanding how the Go compiler represents these operations internally. For example, `x << c` where `c` is a constant will likely be represented as `OpLsh32 x (OpConst32 [c])`.

7. **Address Command-Line Arguments:** I need to consider if this code is directly influenced by any command-line flags passed to the Go compiler. While these rewrite rules are generally applied during compilation, certain flags might affect the overall optimization level. I'll mention the possibility of flags like `-gcflags` but acknowledge that this specific file likely doesn't parse them directly.

8. **Identify Potential User Errors:**  Users don't directly interact with this SSA rewrite code. However, understanding the *optimizations* can indirectly help avoid writing inefficient code. For example, knowing that the compiler optimizes rotations by multiples of the word size means a programmer doesn't need to manually handle such cases. A potential "error" could be writing verbose code that relies on manual manipulations which the compiler already handles.

9. **Summarize the Functionality:** Given that this is part 20 of 26, the overall goal of the `rewritegeneric.go` file is to perform a wide range of generic SSA optimizations. This particular snippet focuses on optimizing bitwise rotation operations for different integer sizes.

10. **Structure the Answer:**  I'll organize the answer using the headings provided in the request, ensuring clarity and completeness. I will use code blocks for Go examples and SSA representations. I will use clear and concise language.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level details of the SSA representation. I need to balance that with explaining the high-level Go language features being optimized.
* I should avoid getting bogged down in explaining every single rewrite rule. Focusing on representative examples is more effective.
* When explaining the reasoning, I need to make sure the connection between the Go code example and the SSA rewrite rule is clear. Specifying the assumed SSA input is crucial.
* I need to be careful not to overstate the impact of command-line arguments. This particular file is more about the core optimization logic.

By following these steps and iteratively refining my understanding, I can generate a comprehensive and accurate answer to the request.
这个go语言实现文件 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 的一部分，主要负责定义和实现 **SSA（Static Single Assignment）中间表示的通用重写规则**。 这些规则用于在编译器的优化阶段，对程序的中间表示进行转换和简化，以提高代码的执行效率。

**具体功能归纳（针对提供的代码片段）：**

这部分代码主要针对 **32位和64位以及8位整数的循环左移（RotateLeft）操作** 进行优化。 它定义了一系列的匹配模式和对应的重写规则，旨在识别出可以被简化或替换为更高效形式的循环左移操作。

**更详细的功能分解：**

1. **恒等变换优化:**
   - 针对 `RotateLeft32 x (Const32 [c])`，如果 `c` 是 32 的倍数，则循环移位相当于没有移位，可以直接将表达式替换为 `x`。
   - 针对 `RotateLeft64 x (Const64 [c])`，如果 `c` 是 64 的倍数，则循环移位相当于没有移位，可以直接将表达式替换为 `x`。
   - 针对 `RotateLeft8 x (Const8 [c])`，如果 `c` 是 8 的倍数，则循环移位相当于没有移位，可以直接将表达式替换为 `x`。

2. **与运算掩码优化:**
   - 针对循环左移的移位量是与上一个掩码的情况（例如 `And64 y (Const64 [c])`），如果掩码覆盖了所有可能的移位位数（例如 32位是 `c&31 == 31`，64位是 `c&63 == 63`，8位是 `c&7 == 7`），则可以直接使用未进行掩码的移位量 `y`。
   - 这可以避免不必要的掩码操作。

3. **取反操作优化:**
   - 针对循环左移的移位量是取反后再与上掩码的情况，如果掩码覆盖了所有可能的移位位数，则可以将移位量替换为对原始变量的取反操作。

4. **加法操作优化:**
   - 针对循环左移的移位量是加上一个常数的情况，如果常数是移位位数的倍数（例如 32位是 `c&31 == 0`，64位是 `c&63 == 0`，8位是 `c&7 == 0`），则这个加法操作实际上不影响最终的循环移位结果，可以省略。

5. **减法操作优化:**
   - 针对循环左移的移位量是用一个常数减去另一个值的情况，如果常数是移位位数的倍数，则可以将移位量替换为对被减数的取反操作。

6. **类型转换优化:**
   - 在32位架构下，如果 `RotateLeft32/64/8` 的移位量是一个 `Const64` 类型，可以将其转换为 `Const32` 类型，因为移位量最终只会取低位。

7. **连续循环左移合并优化:**
   - 如果存在连续的循环左移操作 `(RotateLeft32 x c) d`，且 `c` 和 `d` 的类型大小相同，则可以将移位量合并为一个加法操作 `(RotateLeft32 x (Add... c d))`。这避免了多次循环移位操作。

**推断的 Go 语言功能实现：**

这部分代码是 Go 语言中 **位运算** 功能的优化实现。 具体来说，是针对循环左移运算符 `<<` 的优化。Go 语言的循环移位在标准库中没有直接的运算符，通常需要通过位运算和位或运算来实现，例如 `x << n | x >> (bitsizeof(x) - n)`。 编译器能够识别并优化这种模式，以及一些更复杂的变体。

**Go 代码示例说明：**

```go
package main

import "fmt"

func main() {
	var x uint32 = 0b1010_0000_0000_0000_0000_0000_0000_0000
	var c uint32 = 32

	// 示例 1: 恒等变换优化
	y1 := x << c | x >> (32 - c) // 相当于 RotateLeft32 x 32
	fmt.Printf("y1: %b\n", y1) // 编译器优化后，y1 的计算可能直接等同于 x

	// 示例 2: 加法操作优化
	c2 := 64 // 相当于 32 + 32
	y2 := x << c2 | x >> (32 - c2) // 相当于 RotateLeft32 x 64
	fmt.Printf("y2: %b\n", y2) // 编译器优化后，可能直接按照 RotateLeft32 x (64 % 32) 处理

	// 假设输入 SSA 表示（简化）：
	// v1 = OpConst32 {val: 64}
	// v2 = OpLsh32 {arg0: x, arg1: v1}
	// v3 = OpSub32 {arg0: OpConst32 {val: 32}, arg1: v1}
	// v4 = OpRsh32 {arg0: x, arg1: v3}
	// y2 = OpOr32 {arg0: v2, arg1: v4}

	// 优化后的 SSA 表示：
	// v1 = OpConst32 {val: 0} // 64 % 32 = 0
	// y2 = x // 循环移位 0 位，结果不变
}
```

**假设的输入与输出（SSA 表示）：**

**示例 1 (恒等变换优化):**

* **假设输入 SSA:**
  ```
  v1 = OpConst32 {val: 32}
  v2 = OpLsh32 {arg0: x, arg1: v1}
  v3 = OpSub32 {arg0: OpConst32 {val: 32}, arg1: v1}
  v4 = OpRsh32 {arg0: x, arg1: v3}
  y1 = OpOr32 {arg0: v2, arg1: v4}
  ```
* **优化后输出 SSA:**
  ```
  y1 = x
  ```

**示例 2 (加法操作优化):**

* **假设输入 SSA:** (见上面的代码注释)
* **优化后输出 SSA:** (见上面的代码注释)

**命令行参数的具体处理：**

此代码片段本身不直接处理命令行参数。 `rewritegeneric.go` 文件是 Go 编译器内部的一部分，它读取和操作的是程序的 SSA 中间表示。  但是，Go 编译器的命令行参数（例如 `-gcflags`）可能会影响到整体的优化级别，从而间接地影响到这些重写规则是否会被应用。 例如，在开发模式下，某些优化可能会被禁用以加快编译速度。

**使用者易犯错的点：**

开发者通常不需要直接与这些底层的 SSA 重写规则打交道。 这些是编译器内部的优化。 然而，理解这些优化有助于编写出更高效的代码，虽然编译器已经做了很多工作。

**本部分功能总结 (作为第 20 部分)：**

作为 `rewritegeneric.go` 文件的一部分，这第 20 部分专注于 **优化 32位、64位和8位整数的循环左移操作**。 它通过定义一系列的匹配模式和重写规则，识别并简化常见的循环左移表达式，例如移位量是常数倍数、与运算掩码、加法或减法常数等情况。  这些优化有助于提升生成代码的效率，是 Go 编译器进行代码优化的重要组成部分。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第20部分，共26部分，请归纳一下它的功能

"""
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Add64 y (Const64 [c])))
	// cond: c&31 == 0
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&31 == 0) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Add32 y (Const32 [c])))
	// cond: c&31 == 0
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&31 == 0) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Add16 y (Const16 [c])))
	// cond: c&31 == 0
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&31 == 0) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Add8 y (Const8 [c])))
	// cond: c&31 == 0
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&31 == 0) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Sub64 (Const64 [c]) y))
	// cond: c&31 == 0
	// result: (RotateLeft32 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_0.AuxInt)
		if !(c&31 == 0) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 x (Sub32 (Const32 [c]) y))
	// cond: c&31 == 0
	// result: (RotateLeft32 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		if !(c&31 == 0) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 x (Sub16 (Const16 [c]) y))
	// cond: c&31 == 0
	// result: (RotateLeft32 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1_0.AuxInt)
		if !(c&31 == 0) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 x (Sub8 (Const8 [c]) y))
	// cond: c&31 == 0
	// result: (RotateLeft32 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1_0.AuxInt)
		if !(c&31 == 0) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 x (Const64 <t> [c]))
	// cond: config.PtrSize == 4
	// result: (RotateLeft32 x (Const32 <t> [int32(c)]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 (RotateLeft32 x c) d)
	// cond: c.Type.Size() == 8 && d.Type.Size() == 8
	// result: (RotateLeft32 x (Add64 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft32 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 8 && d.Type.Size() == 8) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpAdd64, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 (RotateLeft32 x c) d)
	// cond: c.Type.Size() == 4 && d.Type.Size() == 4
	// result: (RotateLeft32 x (Add32 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft32 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 4 && d.Type.Size() == 4) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpAdd32, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 (RotateLeft32 x c) d)
	// cond: c.Type.Size() == 2 && d.Type.Size() == 2
	// result: (RotateLeft32 x (Add16 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft32 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 2 && d.Type.Size() == 2) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpAdd16, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft32 (RotateLeft32 x c) d)
	// cond: c.Type.Size() == 1 && d.Type.Size() == 1
	// result: (RotateLeft32 x (Add8 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft32 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 1 && d.Type.Size() == 1) {
			break
		}
		v.reset(OpRotateLeft32)
		v0 := b.NewValue0(v.Pos, OpAdd8, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRotateLeft64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (RotateLeft64 x (Const64 [c]))
	// cond: c%64 == 0
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c%64 == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (RotateLeft64 x (And64 y (Const64 [c])))
	// cond: c&63 == 63
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (And32 y (Const32 [c])))
	// cond: c&63 == 63
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (And16 y (Const16 [c])))
	// cond: c&63 == 63
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (And8 y (Const8 [c])))
	// cond: c&63 == 63
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Neg64 (And64 y (Const64 [c]))))
	// cond: c&63 == 63
	// result: (RotateLeft64 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg64 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd64 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_0_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Neg32 (And32 y (Const32 [c]))))
	// cond: c&63 == 63
	// result: (RotateLeft64 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg32 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd32 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_0_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Neg16 (And16 y (Const16 [c]))))
	// cond: c&63 == 63
	// result: (RotateLeft64 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg16 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd16 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_0_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Neg8 (And8 y (Const8 [c]))))
	// cond: c&63 == 63
	// result: (RotateLeft64 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg8 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd8 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_0_1.AuxInt)
			if !(c&63 == 63) {
				continue
			}
			v.reset(OpRotateLeft64)
			v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Add64 y (Const64 [c])))
	// cond: c&63 == 0
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&63 == 0) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Add32 y (Const32 [c])))
	// cond: c&63 == 0
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&63 == 0) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Add16 y (Const16 [c])))
	// cond: c&63 == 0
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&63 == 0) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Add8 y (Const8 [c])))
	// cond: c&63 == 0
	// result: (RotateLeft64 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&63 == 0) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft64 x (Sub64 (Const64 [c]) y))
	// cond: c&63 == 0
	// result: (RotateLeft64 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_0.AuxInt)
		if !(c&63 == 0) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 x (Sub32 (Const32 [c]) y))
	// cond: c&63 == 0
	// result: (RotateLeft64 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		if !(c&63 == 0) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 x (Sub16 (Const16 [c]) y))
	// cond: c&63 == 0
	// result: (RotateLeft64 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1_0.AuxInt)
		if !(c&63 == 0) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 x (Sub8 (Const8 [c]) y))
	// cond: c&63 == 0
	// result: (RotateLeft64 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1_0.AuxInt)
		if !(c&63 == 0) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 x (Const64 <t> [c]))
	// cond: config.PtrSize == 4
	// result: (RotateLeft64 x (Const32 <t> [int32(c)]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 (RotateLeft64 x c) d)
	// cond: c.Type.Size() == 8 && d.Type.Size() == 8
	// result: (RotateLeft64 x (Add64 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft64 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 8 && d.Type.Size() == 8) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpAdd64, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 (RotateLeft64 x c) d)
	// cond: c.Type.Size() == 4 && d.Type.Size() == 4
	// result: (RotateLeft64 x (Add32 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft64 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 4 && d.Type.Size() == 4) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpAdd32, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 (RotateLeft64 x c) d)
	// cond: c.Type.Size() == 2 && d.Type.Size() == 2
	// result: (RotateLeft64 x (Add16 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft64 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 2 && d.Type.Size() == 2) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpAdd16, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft64 (RotateLeft64 x c) d)
	// cond: c.Type.Size() == 1 && d.Type.Size() == 1
	// result: (RotateLeft64 x (Add8 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft64 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 1 && d.Type.Size() == 1) {
			break
		}
		v.reset(OpRotateLeft64)
		v0 := b.NewValue0(v.Pos, OpAdd8, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (RotateLeft8 x (Const8 [c]))
	// cond: c%8 == 0
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		if !(c%8 == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (RotateLeft8 x (And64 y (Const64 [c])))
	// cond: c&7 == 7
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (And32 y (Const32 [c])))
	// cond: c&7 == 7
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (And16 y (Const16 [c])))
	// cond: c&7 == 7
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (And8 y (Const8 [c])))
	// cond: c&7 == 7
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Neg64 (And64 y (Const64 [c]))))
	// cond: c&7 == 7
	// result: (RotateLeft8 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg64 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd64 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_0_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Neg32 (And32 y (Const32 [c]))))
	// cond: c&7 == 7
	// result: (RotateLeft8 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg32 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd32 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_0_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Neg16 (And16 y (Const16 [c]))))
	// cond: c&7 == 7
	// result: (RotateLeft8 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg16 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd16 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_0_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Neg8 (And8 y (Const8 [c]))))
	// cond: c&7 == 7
	// result: (RotateLeft8 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg8 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd8 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_0_1.AuxInt)
			if !(c&7 == 7) {
				continue
			}
			v.reset(OpRotateLeft8)
			v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Add64 y (Const64 [c])))
	// cond: c&7 == 0
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&7 == 0) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Add32 y (Const32 [c])))
	// cond: c&7 == 0
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&7 == 0) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Add16 y (Const16 [c])))
	// cond: c&7 == 0
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&7 == 0) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Add8 y (Const8 [c])))
	// cond: c&7 == 0
	// result: (RotateLeft8 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&7 == 0) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft8 x (Sub64 (Const64 [c]) y))
	// cond: c&7 == 0
	// result: (RotateLeft8 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_0.AuxInt)
		if !(c&7 == 0) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 x (Sub32 (Const32 [c]) y))
	// cond: c&7 == 0
	// result: (RotateLeft8 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		if !(c&7 == 0) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 x (Sub16 (Const16 [c]) y))
	// cond: c&7 == 0
	// result: (RotateLeft8 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1_0.AuxInt)
		if !(c&7 == 0) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 x (Sub8 (Const8 [c]) y))
	// cond: c&7 == 0
	// result: (RotateLeft8 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1_0.AuxInt)
		if !(c&7 == 0) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 x (Const64 <t> [c]))
	// cond: config.PtrSize == 4
	// result: (RotateLeft8 x (Const32 <t> [int32(c)]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 (RotateLeft8 x c) d)
	// cond: c.Type.Size() == 8 && d.Type.Size() == 8
	// result: (RotateLeft8 x (Add64 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft8 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 8 && d.Type.Size() == 8) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpAdd64, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 (RotateLeft8 x c) d)
	// cond: c.Type.Size() == 4 && d.Type.Size() == 4
	// result: (RotateLeft8 x (Add32 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft8 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 4 && d.Type.Size() == 4) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpAdd32, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 (RotateLeft8 x c) d)
	// cond: c.Type.Size() == 2 && d.Type.Size() == 2
	// result: (RotateLeft8 x (Add16 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft8 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 2 && d.Type.Size() == 2) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpAdd16, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft8 (RotateLeft8 x c) d)
	// cond: c.Type.Size() == 1 && d.Type.Size() == 1
	// result: (RotateLeft8 x (Add8 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft8 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 1 && d.Type.Size() == 1) {
			break
		}
		v.reset(OpRotateLeft8)
		v0 := b.NewValue0(v.Pos, OpAdd8, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRound32F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Round32F x:(Const32F))
	// result: x
	for {
		x := v_0
		if x.Op != OpConst32F {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRound64F(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Round64F x:(Const64F))
	// result: x
	for {
		x := v_0
		if x.Op != OpConst64F {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRoundToEven(v *Value) bool {
	v_0 := v.Args[0]
	// match: (RoundToEven (Const64F [c]))
	// result: (Const64F [math.RoundToEven(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(math.RoundToEven(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16Ux16 <t> x (Const16 [c]))
	// result: (Rsh16Ux64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux16 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16Ux32 <t> x (Const32 [c]))
	// result: (Rsh16Ux64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux32 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 (Const16 [c]) (Const64 [d]))
	// result: (Const16 [int16(uint16(c) >> uint64(d))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(uint16(c) >> uint64(d)))
		return true
	}
	// match: (Rsh16Ux64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh16Ux64 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Rsh16Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 16
	// result: (Const16 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 16) {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Rsh16Ux64 <t> (Rsh16Ux64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh16Ux64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh16Ux64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(!uaddOvf(c, d)) {
			break
		}
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux64 (Rsh16x64 x _) (Const64 <t> [15]))
	// result: (Rsh16Ux64 x (Const64 <t> [15]))
	for {
		if v_0.Op != OpRsh16x64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 15 {
			break
		}
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(15)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux64 i:(Lsh16x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 16 && i.Uses == 1
	// result: (And16 x (Const16 <v.Type> [int16(^uint16(0)>>c)]))
	for {
		i := v_0
		if i.Op != OpLsh16x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.
"""




```