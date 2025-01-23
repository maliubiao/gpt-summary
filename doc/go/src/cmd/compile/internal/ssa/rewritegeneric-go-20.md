Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of a specific Go code snippet within the compiler, and if possible, to infer the broader Go feature it supports. It also asks for examples and identification of potential pitfalls. Crucially, it specifies that this is part 21 of 26, suggesting a larger context related to code rewriting and optimization.

2. **Analyze the Code Structure:** The code consists of multiple functions named `rewriteValuegeneric_Op...`. Each function takes a `*Value` as input and returns a `bool`. The core logic within each function is a series of `for {}` loops with `if` conditions and `break` statements, indicative of pattern matching. The actions within the successful matches involve `v.reset(...)`, `b.NewValue0(...)`, and `v.AddArg(...)`, suggesting manipulation of the intermediate representation (SSA) of the code.

3. **Identify the Pattern:** The function names follow a consistent pattern: `rewriteValuegeneric_Op[Operation][Type1][Type2]`. For example, `rewriteValuegeneric_OpRsh16Ux64` deals with the right shift operation (`Rsh`) of a 16-bit unsigned integer (`16U`) by a 64-bit integer (`64`).

4. **Infer High-Level Functionality:** Given the function names and the internal operations, I can infer that this code is part of the **SSA rewriting phase** of the Go compiler. It aims to optimize code by replacing certain patterns of operations with more efficient equivalents. The `generic` in the function names likely indicates that these rewrites are applicable across different architectures.

5. **Focus on Specific Examples:** To provide concrete explanations, I need to pick out representative rewrite rules. I look for rules that are relatively easy to understand and illustrate. For instance:
    * `// match: (Rsh16Ux64 x (Const64 [0])) // result: x` is a simple case of right-shifting by zero.
    * `// match: (Rsh16Ux64 (Const16 [c]) (Const64 [d])) // result: (Const16 [c >> uint64(d)])` shows constant folding.
    * The more complex examples with `Lsh` and `Rsh` combined illustrate how sequences of operations can be simplified.

6. **Formulate Explanations for the Examples:**  For each selected example, I:
    * **Describe the Pattern:** Explain what the "match" part represents in terms of Go operations.
    * **Explain the Condition (if any):**  Clarify the conditions under which the rewrite applies.
    * **Describe the Result:** Explain the optimized equivalent.
    * **Provide a Go Code Example:** Create a simple Go snippet that would trigger the original pattern.
    * **Show the Expected Output (SSA):**  Demonstrate how the Go compiler (specifically this rewrite rule) would transform the code at the SSA level. *Initially, I considered showing the actual Go assembly, but SSA is more directly relevant to this code snippet.*

7. **Infer the Broader Go Feature:**  The presence of bitwise shift operations (`Rsh`, `Lsh`) strongly suggests this code is related to the implementation and optimization of **bitwise shift operators** in Go (`>>`, `<<`).

8. **Address Command Line Arguments:**  Based on my knowledge of the Go compiler, the SSA rewriting phase is typically not directly controlled by user-level command-line flags in a granular way. It's an internal optimization process. Therefore, I conclude that there are likely no specific command-line arguments directly related to this particular code.

9. **Identify Potential Pitfalls:** The code focuses on specific optimizations. A common mistake for users might be writing overly complex expressions involving shifts, thinking they are being clever, when the compiler already handles these optimizations. Another pitfall could be assuming a specific optimization *will* always happen, leading to code that relies on implementation details rather than clear logic.

10. **Summarize the Functionality (Part 21 of 26):** Given that this is part 21 of 26 related to SSA rewriting, it's likely focused on a specific set of optimization rules. Based on the operations seen (mostly right shifts and related transformations), I summarize it as optimizing right-shift operations, potentially in conjunction with left-shift operations, for 16-bit and 32-bit unsigned integers. The previous parts likely covered other operations, and the subsequent parts will cover the remaining ones.

11. **Review and Refine:** I reread my answer to ensure clarity, accuracy, and completeness, addressing all parts of the prompt. I make sure the Go code examples are correct and that the explanation of the SSA transformation is understandable.
这是 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 文件的一部分，主要负责在 Go 编译器的 **SSA（Static Single Assignment）中间表示** 阶段，对代码进行 **泛型类型的重写和优化**。

**功能归纳 (针对提供的代码片段):**

这段代码专注于 **无符号 16 位和 32 位整数的右移 (Rsh)** 操作的特定模式匹配和优化。它尝试识别可以简化或替换为更高效操作的右移模式。

**具体功能列举:**

这段代码定义了一系列名为 `rewriteValuegeneric_OpRsh...` 的函数，每个函数都针对特定的右移操作符（例如 `OpRsh16Ux64` 表示将一个 16 位无符号整数右移 64 位）。每个函数内部包含多个针对不同操作数模式的匹配规则，如果匹配成功，则会将当前的 SSA 值节点 `v` 重置为更优化的操作。

以下是代码片段中几个主要功能的具体描述：

1. **常量右移优化:**
   - 当右移的位数是一个常量时，直接计算结果并替换为常量节点。
   - 例如，`(Rsh16Ux64 (Const16 [c]) (Const64 [d]))` 会被优化为 `(Const16 [uint16(c) >> uint64(d)])`。
   - 针对不同大小的常量进行了处理 (Const8, Const16, Const32, Const64)。

2. **右移 0 位优化:**
   - 将任何数右移 0 位，结果就是它本身。
   - 例如，`(Rsh16Ux64 x (Const64 [0]))` 会被优化为 `x`。

3. **常量 0 右移优化:**
   - 将常量 0 右移任何位数，结果都是 0。
   - 例如，`(Rsh16Ux64 (Const16 [0]) _)` 会被优化为 `(Const16 [0])`。

4. **连续右移优化:**
   - 将连续的右移操作合并成一个右移操作，将位移量相加。
   - 例如，`(Rsh16Ux64 <t> (Rsh16Ux64 x (Const64 [c])) (Const64 [d]))` 在 `c` 和 `d` 相加不溢出的情况下，会被优化为 `(Rsh16Ux64 x (Const64 <t> [c+d]))`。

5. **左移后再右移的特定模式优化:**
   - 识别 `(Rsh16Ux64 (Lsh16x64 x (Const64 [8])) (Const64 [8]))` 这样的模式，它可以被优化为零扩展操作。
   - 类似的模式针对不同的位移量进行了优化，例如 8 位移位可以转换为 `ZeroExt8to16`。

6. **位掩码优化:**
   - 识别左移后再用相同位数右移的模式，可以转换为位与操作。
   - 例如，`(Rsh32Ux64 i:(Lsh32x64 x (Const64 [c])) (Const64 [c]))` 在满足条件的情况下，会被优化为 `(And32 x (Const32 <v.Type> [int32(^uint32(0)>>c)]))`。这实际上创建了一个掩码来提取低 `32-c` 位。

7. **复杂的移位组合优化:**
   - 识别更复杂的 `Rsh` 和 `Lsh` 组合，例如 `(Rsh16Ux64 (Lsh16x64 (Rsh16Ux64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))`，并将其简化为单个右移操作。

**推理出的 Go 语言功能实现：**

这段代码是 Go 语言中 **位移运算符 (`>>`)** 的一部分优化实现。它旨在提高位移操作的效率，尤其是在涉及常量位移量或连续位移操作时。

**Go 代码举例说明:**

```go
package main

func main() {
	var a uint16 = 10
	var b uint32 = 20

	// 对应常量右移优化
	_ = a >> 2
	_ = b >> 4

	// 对应右移 0 位优化
	_ = a >> 0
	_ = b >> 0

	// 对应常量 0 右移优化
	_ = uint16(0) >> 5
	_ = uint32(0) >> 10

	// 对应连续右移优化
	var c uint32 = 0xFFFFFFFF
	shift1 := 4
	shift2 := 8
	_ = (c >> shift1) >> shift2

	// 对应左移后再右移的特定模式优化
	var d uint16 = 0xABCD
	_ = (d << 8) >> 8

	// 对应位掩码优化
	var e uint32 = 0xFF00FF00
	shift3 := 8
	_ = (e << shift3) >> shift3
}
```

**假设的输入与输出 (针对位掩码优化的例子):**

**输入 (SSA 形式):**

假设在 SSA 阶段，对于 `_ = (e << shift3) >> shift3`，`e` 的类型是 `uint32`，`shift3` 的值为 8，可能会有如下 SSA 代码：

```
v1 = Arg {e 的值}
v2 = Const64 <int64(8)>
v3 = Lsh32x64 v1 v2
v4 = Const64 <int64(8)>
v5 = Rsh32Ux64 v3 v4
```

**输出 (SSA 形式，经过优化):**

经过 `rewriteValuegeneric_OpRsh32Ux64` 函数中对应的位掩码优化规则匹配后，SSA 代码可能被重写为：

```
v1 = Arg {e 的值}
v2 = Const32 <uint32(0xFFFFFF00)>  // ^uint32(0) >> 8
v5 = And32 v1 v2
```

**解释:**  原来的左移和右移操作被替换为一个按位与操作，直接使用一个常量掩码 `0xFFFFFF00` 来提取 `e` 的高 24 位（因为右移了 8 位）。

**命令行参数的具体处理:**

`rewritegeneric.go` 文件中的代码主要在编译器的内部优化阶段运行，**通常不直接受用户通过命令行参数控制**。Go 编译器的命令行参数主要控制编译流程的更高级别设置，例如目标平台、是否启用优化、是否进行内联等。

虽然没有直接控制这些特定重写规则的参数，但 `-gcflags` 可以传递参数给 Go 编译器后端，这可能会间接影响 SSA 的生成和优化。然而，精确控制 `rewritegeneric.go` 中的特定规则是不太可能的。

**使用者易犯错的点:**

通常使用者不需要直接关注或编写 `rewritegeneric.go` 这样的编译器内部代码。然而，理解其背后的优化原理可以帮助编写更高效的 Go 代码。

一个潜在的“易犯错点” (更像是误解) 是 **过度依赖编译器优化来弥补低效的代码**。虽然编译器会进行很多优化，但编写清晰、直接的代码仍然很重要。例如，虽然连续的位移操作会被优化，但在代码可读性方面，有时将其写成一个操作可能更清晰。

**归纳其功能 (作为第 21 部分，共 26 部分):**

考虑到这是整个 SSA 重写过程的第 21 部分，并且文件名包含 "generic"，可以推断出：

**这个代码片段 (第 21 部分) 专注于实现针对特定类型的无符号整数 (16 位和 32 位) 的右移操作的泛型重写规则。**  在整个 SSA 重写过程中，不同的部分会负责不同操作符和数据类型的优化。 第 21 部分特别关注无符号右移，并尝试识别和应用各种优化模式，以生成更高效的目标代码。 之前的部分可能处理了其他算术或逻辑运算，而后续的部分可能会继续处理其他类型的操作或更高级的优化。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第21部分，共26部分，请归纳一下它的功能
```

### 源代码
```go
Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 16 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd16)
		v0 := b.NewValue0(v.Pos, OpConst16, v.Type)
		v0.AuxInt = int16ToAuxInt(int16(^uint16(0) >> c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux64 (Lsh16x64 (Rsh16Ux64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Rsh16Ux64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpLsh16x64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh16Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		x := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c1 := auxIntToInt64(v_0_0_1.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c2 := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		c3 := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)) {
			break
		}
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux64 (Lsh16x64 x (Const64 [8])) (Const64 [8]))
	// result: (ZeroExt8to16 (Trunc16to8 <typ.UInt8> x))
	for {
		if v_0.Op != OpLsh16x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 8 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 8 {
			break
		}
		v.reset(OpZeroExt8to16)
		v0 := b.NewValue0(v.Pos, OpTrunc16to8, typ.UInt8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16Ux8 <t> x (Const8 [c]))
	// result: (Rsh16Ux64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh16Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16Ux8 (Const16 [0]) _)
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
func rewriteValuegeneric_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16x16 <t> x (Const16 [c]))
	// result: (Rsh16x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x16 (Const16 [0]) _)
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
func rewriteValuegeneric_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16x32 <t> x (Const32 [c]))
	// result: (Rsh16x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x32 (Const16 [0]) _)
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
func rewriteValuegeneric_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 (Const16 [c]) (Const64 [d]))
	// result: (Const16 [c >> uint64(d)])
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
		v.AuxInt = int16ToAuxInt(c >> uint64(d))
		return true
	}
	// match: (Rsh16x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh16x64 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Rsh16x64 <t> (Rsh16x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh16x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh16x64 {
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
		v.reset(OpRsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x64 (Lsh16x64 x (Const64 [8])) (Const64 [8]))
	// result: (SignExt8to16 (Trunc16to8 <typ.Int8> x))
	for {
		if v_0.Op != OpLsh16x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 8 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 8 {
			break
		}
		v.reset(OpSignExt8to16)
		v0 := b.NewValue0(v.Pos, OpTrunc16to8, typ.Int8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh16x8 <t> x (Const8 [c]))
	// result: (Rsh16x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh16x8 (Const16 [0]) _)
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
func rewriteValuegeneric_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux16 <t> x (Const16 [c]))
	// result: (Rsh32Ux64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux16 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux32 <t> x (Const32 [c]))
	// result: (Rsh32Ux64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux32 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 (Const32 [c]) (Const64 [d]))
	// result: (Const32 [int32(uint32(c) >> uint64(d))])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		return true
	}
	// match: (Rsh32Ux64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh32Ux64 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Rsh32Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 32
	// result: (Const32 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 32) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Rsh32Ux64 <t> (Rsh32Ux64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh32Ux64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh32Ux64 {
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
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux64 (Rsh32x64 x _) (Const64 <t> [31]))
	// result: (Rsh32Ux64 x (Const64 <t> [31]))
	for {
		if v_0.Op != OpRsh32x64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 31 {
			break
		}
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(31)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux64 i:(Lsh32x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 32 && i.Uses == 1
	// result: (And32 x (Const32 <v.Type> [int32(^uint32(0)>>c)]))
	for {
		i := v_0
		if i.Op != OpLsh32x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 32 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd32)
		v0 := b.NewValue0(v.Pos, OpConst32, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(^uint32(0) >> c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux64 (Lsh32x64 (Rsh32Ux64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Rsh32Ux64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh32Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		x := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c1 := auxIntToInt64(v_0_0_1.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c2 := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		c3 := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)) {
			break
		}
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux64 (Lsh32x64 x (Const64 [24])) (Const64 [24]))
	// result: (ZeroExt8to32 (Trunc32to8 <typ.UInt8> x))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 24 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 24 {
			break
		}
		v.reset(OpZeroExt8to32)
		v0 := b.NewValue0(v.Pos, OpTrunc32to8, typ.UInt8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh32Ux64 (Lsh32x64 x (Const64 [16])) (Const64 [16]))
	// result: (ZeroExt16to32 (Trunc32to16 <typ.UInt16> x))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 16 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 16 {
			break
		}
		v.reset(OpZeroExt16to32)
		v0 := b.NewValue0(v.Pos, OpTrunc32to16, typ.UInt16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux8 <t> x (Const8 [c]))
	// result: (Rsh32Ux64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh32Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32Ux8 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x16 <t> x (Const16 [c]))
	// result: (Rsh32x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x16 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x32 <t> x (Const32 [c]))
	// result: (Rsh32x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x32 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x64 (Const32 [c]) (Const64 [d]))
	// result: (Const32 [c >> uint64(d)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		return true
	}
	// match: (Rsh32x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh32x64 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Rsh32x64 <t> (Rsh32x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh32x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh32x64 {
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
		v.reset(OpRsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x64 (Lsh32x64 x (Const64 [24])) (Const64 [24]))
	// result: (SignExt8to32 (Trunc32to8 <typ.Int8> x))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 24 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 24 {
			break
		}
		v.reset(OpSignExt8to32)
		v0 := b.NewValue0(v.Pos, OpTrunc32to8, typ.Int8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh32x64 (Lsh32x64 x (Const64 [16])) (Const64 [16]))
	// result: (SignExt16to32 (Trunc32to16 <typ.Int16> x))
	for {
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 16 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 16 {
			break
		}
		v.reset(OpSignExt16to32)
		v0 := b.NewValue0(v.Pos, OpTrunc32to16, typ.Int16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x8 <t> x (Const8 [c]))
	// result: (Rsh32x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh32x8 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64Ux16 <t> x (Const16 [c]))
	// result: (Rsh64Ux64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux16 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64Ux32 <t> x (Const32 [c]))
	// result: (Rsh64Ux64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux32 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [int64(uint64(c) >> uint64(d))])
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
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		return true
	}
	// match: (Rsh64Ux64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh64Ux64 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Rsh64Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 64
	// result: (Const64 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Rsh64Ux64 <t> (Rsh64Ux64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh64Ux64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh64Ux64 {
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
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux64 (Rsh64x64 x _) (Const64 <t> [63]))
	// result: (Rsh64Ux64 x (Const64 <t> [63]))
	for {
		if v_0.Op != OpRsh64x64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 63 {
			break
		}
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(63)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux64 i:(Lsh64x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 64 && i.Uses == 1
	// result: (And64 x (Const64 <v.Type> [int64(^uint64(0)>>c)]))
	for {
		i := v_0
		if i.Op != OpLsh64x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 64 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd64)
		v0 := b.NewValue0(v.Pos, OpConst64, v.Type)
		v0.AuxInt = int64ToAuxInt(int64(^uint64(0) >> c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux64 (Lsh64x64 (Rsh64Ux64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Rsh64Ux64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh64Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		x := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c1 := auxIntToInt64(v_0_0_1.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c2 := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		c3 := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)) {
			break
		}
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux64 (Lsh64x64 x (Const64 [56])) (Const64 [56]))
	// result: (ZeroExt8to64 (Trunc64to8 <typ.UInt8> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 56 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 56 {
			break
		}
		v.reset(OpZeroExt8to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to8, typ.UInt8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh64Ux64 (Lsh64x64 x (Const64 [48])) (Const64 [48]))
	// result: (ZeroExt16to64 (Trunc64to16 <typ.UInt16> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 48 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 48 {
			break
		}
		v.reset(OpZeroExt16to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to16, typ.UInt16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh64Ux64 (Lsh64x64 x (Const64 [32])) (Const64 [32]))
	// result: (ZeroExt32to64 (Trunc64to32 <typ.UInt32> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 32 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 32 {
			break
		}
		v.reset(OpZeroExt32to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to32, typ.UInt32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64Ux8 <t> x (Const8 [c]))
	// result: (Rsh64Ux64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh64Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux8 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x16 <t> x (Const16 [c]))
	// result: (Rsh64x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x16 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x32 <t> x (Const32 [c]))
	// result: (Rsh64x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x32 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c >> uint64(d)])
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
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		return true
	}
	// match: (Rsh64x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh64x64 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Rsh64x64 <t> (Rsh64x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh64x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh64x64 {
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
		v.reset(OpRsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x64 (Lsh64x64 x (Const64 [56])) (Const64 [56]))
	// result: (SignExt8to64 (Trunc64to8 <typ.Int8> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 56 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 56 {
			break
		}
		v.reset(OpSignExt8to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to8, typ.Int8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh64x64 (Lsh64x64 x (Const64 [48])) (Const64 [48]))
	// result: (SignExt16to64 (Trunc64to16 <typ.Int16> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 48 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 48 {
			break
		}
		v.reset(OpSignExt16to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to16, typ.Int16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh64x64 (Lsh64x64 x (Const64 [32])) (Const64 [32]))
	// result: (SignExt32to64 (Trunc64to32 <typ.Int32> x))
	for {
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 || auxIntToInt64(v_0_1.AuxInt) != 32 || v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 32 {
			break
		}
		v.reset(OpSignExt32to64)
		v0 := b.NewValue0(v.Pos, OpTrunc64to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x8 <t> x (Const8 [c]))
	// result: (Rsh64x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x8 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux16 <t> x (Const16 [c]))
	// result: (Rsh8Ux64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux16 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux32 <t> x (Const32 [c]))
	// result: (Rsh8Ux64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux32 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 (Const8 [c]) (Const64 [d]))
	// result: (Const8 [int8(uint8(c) >> uint64(d))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(int8(uint8(c) >> uint64(d)))
		return true
	}
	// match: (Rsh8Ux64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh8Ux64 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Rsh8Ux64 _ (Const64 [c]))
	// cond: uint64(c) >= 8
	// result: (Const8 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 8) {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Rsh8Ux64 <t> (Rsh8Ux64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh8Ux64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh8Ux64 {
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
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpCon
```