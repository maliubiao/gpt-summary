Response:
My thought process for analyzing the provided Go code snippet and answering the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of a specific part of a Go source file (`rewriteMIPS.go`), which deals with instruction rewriting for the MIPS architecture within the SSA (Static Single Assignment) intermediate representation. The fact that it's part 5 of 6 suggests a larger process of optimizing or transforming the SSA form for MIPS.

2. **Identify the Scope:** The snippet primarily contains a series of Go functions named `rewriteValueMIPS_Op...`. This naming convention is a strong clue. The `rewriteValue` prefix suggests these functions are responsible for transforming specific SSA `Value` operations (`Op`). The `MIPS` part clearly indicates the target architecture.

3. **Analyze Individual Functions:** I'll examine each function individually, focusing on its purpose.

    * **Look for Patterns:**  The structure within each function is remarkably consistent:
        * Get the input `Value` and its arguments.
        * Extract the block (`b`) and type information (`typ`).
        * Use a `for {}` loop (often with a `break`) to represent a single attempt at rewriting.
        * `match:` comments describe the pattern being matched in the SSA graph (e.g., `RotateLeft32 <t> x (MOVWconst [c])`).
        * `result:` comments describe the rewritten SSA graph structure (e.g., `Or32 (Lsh32x32 <t> x (MOVWconst [c&31])) (Rsh32Ux32 <t> x (MOVWconst [-c&31])))`).
        * The core of the function is often a `v.reset(Op...)` call, which changes the operation of the current `Value`.
        * New `Value`s (`b.NewValue0(...)`) are created and their arguments are set.
        * The function returns `true` if a rewrite occurred, `false` otherwise.

    * **Infer Functionality from `Op` Names:** The `Op` names are crucial. They represent specific SSA operations. For example:
        * `OpRotateLeft32`, `OpRotateLeft64`, `OpRotateLeft8`: Implement left bitwise rotation for different integer sizes.
        * `OpRsh16Ux16`, `OpRsh16x16`, etc.: Implement right bitwise shift operations (unsigned and signed) for various operand types. The `Ux` suffix denotes unsigned shift.
        * `OpSelect0`, `OpSelect1`:  Extract the first or second result of a multi-value operation (like `Add32carry` or `MULTU`).
        * `OpSignmask`: Generates a mask with all bits set if the input is negative, and all bits clear otherwise.
        * `OpSlicemask`: Generates a mask used for slicing operations.
        * `OpStore`: Writes a value to memory.
        * `OpSub32withcarry`: Implements subtraction with a carry-in.
        * `OpZero`:  Initializes a memory region with zeros.

    * **Analyze Rewriting Logic:** The code transforms high-level operations into lower-level MIPS instructions or combinations of instructions. For example, rotation is implemented using left and right shifts combined with an OR operation. Right shifts often involve conditional moves (`CMOVZ`) to handle cases where the shift amount is greater than or equal to the bit width. Multiplication results (`MULTU`) are split into high and low parts using `Select0` and `Select1`.

4. **Identify the Overall Purpose:**  Given the individual function analyses, the overarching goal is clearly to *optimize or lower* the SSA representation for the MIPS architecture. This involves:

    * **Implementing complex operations using simpler MIPS instructions:**  Rotation, for example.
    * **Handling different data types and sizes correctly:**  The functions are specific to operand types (e.g., `Rsh16Ux64`).
    * **Optimizing for constants:** Many rewrites have conditions that check for constant arguments (`MOVWconst`, `Const64`) and perform simpler operations in those cases.
    * **Translating generic SSA ops into MIPS-specific ops:**  `OpStore` becomes `OpMIPSMOVBstore`, `OpMIPSMOVHstore`, etc.

5. **Infer Go Language Features:** The code demonstrates the following Go features:

    * **Packages and Imports:** The `package ssa` declaration and the implied imports (though not fully shown) are standard Go.
    * **Functions and Methods:** The `rewriteValueMIPS_Op...` functions are regular Go functions.
    * **Structs and Pointers:** The `*Value` type indicates the use of pointers to `Value` structs, which likely represent nodes in the SSA graph.
    * **Type System:**  The code manipulates types (`v.Type`, `typ.UInt32`, `t.FieldType(0)`) and uses type assertions or checks implicitly.
    * **Control Flow:** `for` loops, `if` statements, `break`, and `return` are standard control flow constructs.
    * **Constants:** Integer literals are used extensively.
    * **Bitwise Operations:** `&`, `|`, `<<`, `>>`, `^` are used for bit manipulation.
    * **Auxiliary Information:** The `v.AuxInt` and `v.Aux` fields are used to store additional information associated with SSA values, like constant values or types.

6. **Construct Example (Code Reasoning):** The rotation operations are good examples for code reasoning. Let's take `rewriteValueMIPS_OpRotateLeft32`:

   * **Assumption:**  The input is an `OpRotateLeft32` value where the second argument is a constant (`MOVWconst`).
   * **Input:**  A SSA `Value` representing `x << c | x >> (32 - c)`, where `c` is a constant.
   * **Output:** The code rewrites this into `(x << (c & 31)) | (x >> (-c & 31))`. The `& 31` handles cases where `c` is larger than 31, effectively taking the rotation amount modulo 32. The `-c & 31` cleverly calculates `32 - c` (modulo 32) because of how two's complement works.

   ```go
   // Assuming 'b' is a *ssa.Block and 'x' is a *ssa.Value representing some 32-bit integer
   c := int32(5) // Example constant rotation amount
   rotateLeft := b.NewValue0(pos, OpRotateLeft32, types.UInt32)
   constVal := b.NewValue0(pos, OpMIPSMOVWconst, types.UInt32)
   constVal.AuxInt = int32ToAuxInt(c)
   rotateLeft.AddArg2(x, constVal)

   // After the rewrite, 'rotateLeft' will be transformed into an 'OpOr32'
   // with two 'OpLsh32x32' and 'OpRsh32Ux32' arguments.
   ```

7. **Handle Command-Line Arguments:** The provided code snippet *doesn't* directly deal with command-line arguments. This file is about SSA rewriting, which happens *during* the compilation process, not when the `go` command is invoked. Command-line arguments are handled earlier in the compilation pipeline.

8. **Identify Common Mistakes:** Without knowing the broader context and the intended users, it's hard to pinpoint specific mistakes. However, some general potential issues in compiler development include:

    * **Incorrectly implementing the semantics of an operation:** A flaw in the rewrite logic could produce incorrect results.
    * **Missing cases:** Not handling all possible forms of an input `Op`.
    * **Performance regressions:** A rewrite that's logically correct but slower than the original.
    * **Introducing new dependencies or complexity:** A rewrite that makes later stages of compilation more difficult.

9. **Final Summary (Part 5):** Based on the analysis of the functions in this specific snippet, the primary function of this part of `rewriteMIPS.go` is to **perform architecture-specific rewrites for a range of bitwise shift, rotate, select, store, zeroing, and carry-related operations in the SSA intermediate representation for the MIPS architecture.** It transforms these higher-level operations into combinations of simpler, more direct MIPS instructions, often optimizing for cases involving constant operands. This contributes to the overall goal of generating efficient machine code for MIPS.

This structured approach allows me to break down the code, understand its purpose, and address all aspects of the request.
这是 `go/src/cmd/compile/internal/ssa/rewriteMIPS.go` 文件的一部分，主要负责 **针对 MIPS 架构的 SSA (Static Single Assignment) 中间表示进行优化的重写规则定义**。

具体来说，这部分代码定义了一系列的 `rewriteValueMIPS_Op...` 函数，每个函数都对应着一个特定的 SSA 操作符 (`Op`)，并尝试将该操作符及其操作数转换为更有效率或更符合 MIPS 架构特性的指令序列。

**归纳一下这部分的功能 (作为第 5 部分):**

这部分代码继续定义了针对 MIPS 架构的 SSA 重写规则，主要集中在以下几个方面：

* **位操作的优化:**  包括左移、右移（逻辑和算术）、循环移位等操作的优化。它会将一些通用的 SSA 位操作转换为 MIPS 架构特有的指令组合，例如使用 `OR` 和移位指令来实现循环移位。
* **选择操作的优化:**  针对 `Select0` 和 `Select1` 操作符（通常用于获取多返回值函数的特定返回值），定义了在 MIPS 架构下的优化规则，特别是在操作数是常量的情况下。
* **符号扩展和零扩展:**  虽然这部分代码没有直接展示符号扩展和零扩展的优化，但之前的代码已经涵盖了，这部分的代码产生的中间结果可能会被后续的重写规则进一步优化。
* **存储操作的优化:**  根据存储数据的大小和类型，选择合适的 MIPS 存储指令，例如 `MOVBstore` (存储字节), `MOVHstore` (存储半字), `MOVWstore` (存储字), `MOVFstore` (存储浮点数), `MOVDstore` (存储双精度浮点数)。
* **零值初始化的优化:**  针对将内存区域设置为零值的 `Zero` 操作，定义了使用 MIPS 存储指令进行优化的规则，例如使用 `MOVBstore` 或 `MOVHstore` 等。
* **带进位减法的优化:**  针对 `Sub32withcarry` 操作，将其转换为两个 `SUB` 指令的组合。

**可以推理出它是什么 go 语言功能的实现：**

这部分代码是 Go 语言编译器中 **SSA 中间表示到 MIPS 汇编指令转换** 过程中的一个重要环节。它属于 **codegen (代码生成)** 阶段的一部分，负责将与架构无关的 SSA 表示转换成特定架构的高效指令。

**Go 代码举例说明 (循环左移的优化):**

假设我们有以下 Go 代码：

```go
package main

func rotateLeft32(x uint32, k uint32) uint32 {
	return (x << k) | (x >> (32 - k))
}

func main() {
	var a uint32 = 0x12345678
	var b uint32 = 5
	result := rotateLeft32(a, b)
	println(result) // Output: 1083037816
}
```

在编译器的 SSA 中间表示阶段，`rotateLeft32` 函数的实现可能会包含一个 `OpRotateLeft32` 操作符。  `rewriteValueMIPS_OpRotateLeft32` 函数的功能就是将这个 `OpRotateLeft32` 操作符转换为 MIPS 架构下的移位和或运算指令。

**代码推理 (基于 `rewriteValueMIPS_OpRotateLeft32`):**

**假设输入:**

* `v` 是一个 `*Value`，其 `Op` 是 `OpRotateLeft32`。
* `v.Args[0]` 是一个表示被循环移位的值 `x` 的 `*Value`。
* `v.Args[1]` 是一个 `*Value`，其 `Op` 是 `OpMIPSMOVWconst`，表示循环移位的位数 `c`（例如，值为 5）。

**输出:**

`rewriteValueMIPS_OpRotateLeft32` 函数会将 `v` 的操作符重置为 `OpOr32`，并添加两个参数：

1. 一个 `OpLsh32x32` 类型的 `*Value`，表示左移操作 `x << (c & 31)`。 其中 `c & 31` 用于确保移位位数在 0-31 之间。
2. 一个 `OpRsh32Ux32` 类型的 `*Value`，表示无符号右移操作 `x >> (-c & 31)`。 这里 `-c & 31` 的巧妙用法是为了计算 `32 - c`，因为在二进制补码表示中，对负数进行位运算会得到预期的结果。

**示例转换后的 SSA 表示 (简化):**

```
v (OpOr32)
  v0 (OpLsh32x32)
    x
    v1 (OpMIPSMOVWconst, AuxInt: 5) // 实际 AuxInt 是 5 & 31 = 5
  v2 (OpRsh32Ux32)
    x
    v3 (OpMIPSMOVWconst, AuxInt: -5) // 实际 AuxInt 是 -5 & 31 = 27 (32 - 5)
```

**命令行参数的具体处理:**

这个代码片段本身不处理命令行参数。命令行参数的处理发生在编译器的前端和配置阶段。`rewriteMIPS.go` 中的代码是编译器后端 SSA 优化的一部分，它基于已经解析和处理过的程序信息进行操作。

**使用者易犯错的点:**

由于这是编译器内部的代码，直接的使用者是 Go 编译器的开发者。 普通 Go 语言开发者不会直接接触或修改这些代码。 编译器开发者在编写或修改这类重写规则时，容易犯的错误包括：

* **逻辑错误:**  重写规则的逻辑不正确，导致生成的代码行为与原始代码不符。
* **性能问题:**  新的重写规则虽然功能正确，但生成的代码效率低下。
* **破坏 SSA 形式:**  引入的新的 SSA 值或操作不符合 SSA 的规范。
* **未考虑所有情况:**  重写规则只覆盖了部分输入模式，对于其他模式没有处理或处理错误。

**总结 (针对提供的代码片段):**

这部分 `rewriteMIPS.go` 代码专注于优化 MIPS 架构下的位操作、选择操作、存储操作以及零值初始化等。它通过模式匹配和替换，将通用的 SSA 操作转换为更符合 MIPS 架构特性的指令序列，从而提升生成代码的效率。 例如，它使用移位和或运算的组合来实现循环移位，并根据数据大小选择合适的存储指令。 这部分是 Go 编译器后端代码生成阶段的关键组成部分，负责将架构无关的中间表示转化为目标架构的高效机器码。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共6部分，请归纳一下它的功能

"""
 b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(c & 31)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh32Ux32, t)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(-c & 31)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRotateLeft64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft64 <t> x (MOVWconst [c]))
	// result: (Or64 (Lsh64x32 <t> x (MOVWconst [c&63])) (Rsh64Ux32 <t> x (MOVWconst [-c&63])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpOr64)
		v0 := b.NewValue0(v.Pos, OpLsh64x32, t)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(c & 63)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh64Ux32, t)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(-c & 63)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVWconst [c]))
	// result: (Or8 (Lsh8x32 <t> x (MOVWconst [c&7])) (Rsh8Ux32 <t> x (MOVWconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x32, t)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux32, t)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 <t> x y)
	// result: (CMOVZ (SRL <t> (ZeroExt16to32 x) (ZeroExt16to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt16to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v4.AuxInt = int32ToAuxInt(32)
		v4.AddArg(v2)
		v.AddArg3(v0, v3, v4)
		return true
	}
}
func rewriteValueMIPS_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 <t> x y)
	// result: (CMOVZ (SRL <t> (ZeroExt16to32 x) y) (MOVWconst [0]) (SGTUconst [32] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 x (Const64 [c]))
	// cond: uint32(c) < 16
	// result: (SRLconst (SLLconst <typ.UInt32> x [16]) [int32(c+16)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) < 16) {
			break
		}
		v.reset(OpMIPSSRLconst)
		v.AuxInt = int32ToAuxInt(int32(c + 16))
		v0 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16Ux64 _ (Const64 [c]))
	// cond: uint32(c) >= 16
	// result: (MOVWconst [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) >= 16) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 <t> x y)
	// result: (CMOVZ (SRL <t> (ZeroExt16to32 x) (ZeroExt8to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt8to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v4.AuxInt = int32ToAuxInt(32)
		v4.AddArg(v2)
		v.AddArg3(v0, v3, v4)
		return true
	}
}
func rewriteValueMIPS_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 x y)
	// result: (SRA (SignExt16to32 x) ( CMOVZ <typ.UInt32> (ZeroExt16to32 y) (MOVWconst [31]) (SGTUconst [32] (ZeroExt16to32 y))))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpMIPSCMOVZ, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(31)
		v4 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v4.AuxInt = int32ToAuxInt(32)
		v4.AddArg(v2)
		v1.AddArg3(v2, v3, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 x y)
	// result: (SRA (SignExt16to32 x) ( CMOVZ <typ.UInt32> y (MOVWconst [31]) (SGTUconst [32] y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpMIPSCMOVZ, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(31)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 x (Const64 [c]))
	// cond: uint32(c) < 16
	// result: (SRAconst (SLLconst <typ.UInt32> x [16]) [int32(c+16)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) < 16) {
			break
		}
		v.reset(OpMIPSSRAconst)
		v.AuxInt = int32ToAuxInt(int32(c + 16))
		v0 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16x64 x (Const64 [c]))
	// cond: uint32(c) >= 16
	// result: (SRAconst (SLLconst <typ.UInt32> x [16]) [31])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) >= 16) {
			break
		}
		v.reset(OpMIPSSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v0 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 x y)
	// result: (SRA (SignExt16to32 x) ( CMOVZ <typ.UInt32> (ZeroExt8to32 y) (MOVWconst [31]) (SGTUconst [32] (ZeroExt8to32 y))))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpMIPSCMOVZ, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(31)
		v4 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v4.AuxInt = int32ToAuxInt(32)
		v4.AddArg(v2)
		v1.AddArg3(v2, v3, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 <t> x y)
	// result: (CMOVZ (SRL <t> x (ZeroExt16to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt16to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux32 <t> x y)
	// result: (CMOVZ (SRL <t> x y) (MOVWconst [0]) (SGTUconst [32] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSRL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueMIPS_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh32Ux64 x (Const64 [c]))
	// cond: uint32(c) < 32
	// result: (SRLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) < 32) {
			break
		}
		v.reset(OpMIPSSRLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh32Ux64 _ (Const64 [c]))
	// cond: uint32(c) >= 32
	// result: (MOVWconst [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) >= 32) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 <t> x y)
	// result: (CMOVZ (SRL <t> x (ZeroExt8to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt8to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 x y)
	// result: (SRA x ( CMOVZ <typ.UInt32> (ZeroExt16to32 y) (MOVWconst [31]) (SGTUconst [32] (ZeroExt16to32 y))))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSRA)
		v0 := b.NewValue0(v.Pos, OpMIPSCMOVZ, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(31)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v0.AddArg3(v1, v2, v3)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueMIPS_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x32 x y)
	// result: (SRA x ( CMOVZ <typ.UInt32> y (MOVWconst [31]) (SGTUconst [32] y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSRA)
		v0 := b.NewValue0(v.Pos, OpMIPSCMOVZ, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(31)
		v2 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueMIPS_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh32x64 x (Const64 [c]))
	// cond: uint32(c) < 32
	// result: (SRAconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) < 32) {
			break
		}
		v.reset(OpMIPSSRAconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh32x64 x (Const64 [c]))
	// cond: uint32(c) >= 32
	// result: (SRAconst x [31])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) >= 32) {
			break
		}
		v.reset(OpMIPSSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 x y)
	// result: (SRA x ( CMOVZ <typ.UInt32> (ZeroExt8to32 y) (MOVWconst [31]) (SGTUconst [32] (ZeroExt8to32 y))))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSRA)
		v0 := b.NewValue0(v.Pos, OpMIPSCMOVZ, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(31)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v0.AddArg3(v1, v2, v3)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueMIPS_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 <t> x y)
	// result: (CMOVZ (SRL <t> (ZeroExt8to32 x) (ZeroExt16to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt16to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v4.AuxInt = int32ToAuxInt(32)
		v4.AddArg(v2)
		v.AddArg3(v0, v3, v4)
		return true
	}
}
func rewriteValueMIPS_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 <t> x y)
	// result: (CMOVZ (SRL <t> (ZeroExt8to32 x) y) (MOVWconst [0]) (SGTUconst [32] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 x (Const64 [c]))
	// cond: uint32(c) < 8
	// result: (SRLconst (SLLconst <typ.UInt32> x [24]) [int32(c+24)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) < 8) {
			break
		}
		v.reset(OpMIPSSRLconst)
		v.AuxInt = int32ToAuxInt(int32(c + 24))
		v0 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(24)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8Ux64 _ (Const64 [c]))
	// cond: uint32(c) >= 8
	// result: (MOVWconst [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) >= 8) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 <t> x y)
	// result: (CMOVZ (SRL <t> (ZeroExt8to32 x) (ZeroExt8to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt8to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v4.AuxInt = int32ToAuxInt(32)
		v4.AddArg(v2)
		v.AddArg3(v0, v3, v4)
		return true
	}
}
func rewriteValueMIPS_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 x y)
	// result: (SRA (SignExt16to32 x) ( CMOVZ <typ.UInt32> (ZeroExt16to32 y) (MOVWconst [31]) (SGTUconst [32] (ZeroExt16to32 y))))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpMIPSCMOVZ, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(31)
		v4 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v4.AuxInt = int32ToAuxInt(32)
		v4.AddArg(v2)
		v1.AddArg3(v2, v3, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 x y)
	// result: (SRA (SignExt16to32 x) ( CMOVZ <typ.UInt32> y (MOVWconst [31]) (SGTUconst [32] y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpMIPSCMOVZ, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(31)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 x (Const64 [c]))
	// cond: uint32(c) < 8
	// result: (SRAconst (SLLconst <typ.UInt32> x [24]) [int32(c+24)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) < 8) {
			break
		}
		v.reset(OpMIPSSRAconst)
		v.AuxInt = int32ToAuxInt(int32(c + 24))
		v0 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(24)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8x64 x (Const64 [c]))
	// cond: uint32(c) >= 8
	// result: (SRAconst (SLLconst <typ.UInt32> x [24]) [31])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) >= 8) {
			break
		}
		v.reset(OpMIPSSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v0 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(24)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 x y)
	// result: (SRA (SignExt16to32 x) ( CMOVZ <typ.UInt32> (ZeroExt8to32 y) (MOVWconst [31]) (SGTUconst [32] (ZeroExt8to32 y))))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpMIPSCMOVZ, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(31)
		v4 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v4.AuxInt = int32ToAuxInt(32)
		v4.AddArg(v2)
		v1.AddArg3(v2, v3, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Add32carry <t> x y))
	// result: (ADD <t.FieldType(0)> x y)
	for {
		if v_0.Op != OpAdd32carry {
			break
		}
		t := v_0.Type
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpMIPSADD)
		v.Type = t.FieldType(0)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Sub32carry <t> x y))
	// result: (SUB <t.FieldType(0)> x y)
	for {
		if v_0.Op != OpSub32carry {
			break
		}
		t := v_0.Type
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpMIPSSUB)
		v.Type = t.FieldType(0)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (MULTU (MOVWconst [0]) _ ))
	// result: (MOVWconst [0])
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst || auxIntToInt32(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpMIPSMOVWconst)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Select0 (MULTU (MOVWconst [1]) _ ))
	// result: (MOVWconst [0])
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst || auxIntToInt32(v_0_0.AuxInt) != 1 {
				continue
			}
			v.reset(OpMIPSMOVWconst)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Select0 (MULTU (MOVWconst [-1]) x ))
	// result: (CMOVZ (ADDconst <x.Type> [-1] x) (MOVWconst [0]) x)
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst || auxIntToInt32(v_0_0.AuxInt) != -1 {
				continue
			}
			x := v_0_1
			v.reset(OpMIPSCMOVZ)
			v0 := b.NewValue0(v.Pos, OpMIPSADDconst, x.Type)
			v0.AuxInt = int32ToAuxInt(-1)
			v0.AddArg(x)
			v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
			v1.AuxInt = int32ToAuxInt(0)
			v.AddArg3(v0, v1, x)
			return true
		}
		break
	}
	// match: (Select0 (MULTU (MOVWconst [c]) x ))
	// cond: isPowerOfTwo(int64(uint32(c)))
	// result: (SRLconst [int32(32-log2uint32(int64(c)))] x)
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			x := v_0_1
			if !(isPowerOfTwo(int64(uint32(c)))) {
				continue
			}
			v.reset(OpMIPSSRLconst)
			v.AuxInt = int32ToAuxInt(int32(32 - log2uint32(int64(c))))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Select0 (MULTU (MOVWconst [c]) (MOVWconst [d])))
	// result: (MOVWconst [int32((int64(uint32(c))*int64(uint32(d)))>>32)])
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_0_1.Op != OpMIPSMOVWconst {
				continue
			}
			d := auxIntToInt32(v_0_1.AuxInt)
			v.reset(OpMIPSMOVWconst)
			v.AuxInt = int32ToAuxInt(int32((int64(uint32(c)) * int64(uint32(d))) >> 32))
			return true
		}
		break
	}
	// match: (Select0 (DIV (MOVWconst [c]) (MOVWconst [d])))
	// cond: d != 0
	// result: (MOVWconst [c%d])
	for {
		if v_0.Op != OpMIPSDIV {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(c % d)
		return true
	}
	// match: (Select0 (DIVU (MOVWconst [c]) (MOVWconst [d])))
	// cond: d != 0
	// result: (MOVWconst [int32(uint32(c)%uint32(d))])
	for {
		if v_0.Op != OpMIPSDIVU {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) % uint32(d)))
		return true
	}
	return false
}
func rewriteValueMIPS_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Add32carry <t> x y))
	// result: (SGTU <typ.Bool> x (ADD <t.FieldType(0)> x y))
	for {
		if v_0.Op != OpAdd32carry {
			break
		}
		t := v_0.Type
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpMIPSSGTU)
		v.Type = typ.Bool
		v0 := b.NewValue0(v.Pos, OpMIPSADD, t.FieldType(0))
		v0.AddArg2(x, y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Select1 (Sub32carry <t> x y))
	// result: (SGTU <typ.Bool> (SUB <t.FieldType(0)> x y) x)
	for {
		if v_0.Op != OpSub32carry {
			break
		}
		t := v_0.Type
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpMIPSSGTU)
		v.Type = typ.Bool
		v0 := b.NewValue0(v.Pos, OpMIPSSUB, t.FieldType(0))
		v0.AddArg2(x, y)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Select1 (MULTU (MOVWconst [0]) _ ))
	// result: (MOVWconst [0])
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst || auxIntToInt32(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpMIPSMOVWconst)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Select1 (MULTU (MOVWconst [1]) x ))
	// result: x
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst || auxIntToInt32(v_0_0.AuxInt) != 1 {
				continue
			}
			x := v_0_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Select1 (MULTU (MOVWconst [-1]) x ))
	// result: (NEG <x.Type> x)
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst || auxIntToInt32(v_0_0.AuxInt) != -1 {
				continue
			}
			x := v_0_1
			v.reset(OpMIPSNEG)
			v.Type = x.Type
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Select1 (MULTU (MOVWconst [c]) x ))
	// cond: isPowerOfTwo(int64(uint32(c)))
	// result: (SLLconst [int32(log2uint32(int64(c)))] x)
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			x := v_0_1
			if !(isPowerOfTwo(int64(uint32(c)))) {
				continue
			}
			v.reset(OpMIPSSLLconst)
			v.AuxInt = int32ToAuxInt(int32(log2uint32(int64(c))))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Select1 (MULTU (MOVWconst [c]) (MOVWconst [d])))
	// result: (MOVWconst [int32(uint32(c)*uint32(d))])
	for {
		if v_0.Op != OpMIPSMULTU {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpMIPSMOVWconst {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_0_1.Op != OpMIPSMOVWconst {
				continue
			}
			d := auxIntToInt32(v_0_1.AuxInt)
			v.reset(OpMIPSMOVWconst)
			v.AuxInt = int32ToAuxInt(int32(uint32(c) * uint32(d)))
			return true
		}
		break
	}
	// match: (Select1 (DIV (MOVWconst [c]) (MOVWconst [d])))
	// cond: d != 0
	// result: (MOVWconst [c/d])
	for {
		if v_0.Op != OpMIPSDIV {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(c / d)
		return true
	}
	// match: (Select1 (DIVU (MOVWconst [c]) (MOVWconst [d])))
	// cond: d != 0
	// result: (MOVWconst [int32(uint32(c)/uint32(d))])
	for {
		if v_0.Op != OpMIPSDIVU {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) / uint32(d)))
		return true
	}
	return false
}
func rewriteValueMIPS_OpSignmask(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Signmask x)
	// result: (SRAconst x [31])
	for {
		x := v_0
		v.reset(OpMIPSSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v.AddArg(x)
		return true
	}
}
func rewriteValueMIPS_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRAconst (NEG <t> x) [31])
	for {
		t := v.Type
		x := v_0
		v.reset(OpMIPSSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v0 := b.NewValue0(v.Pos, OpMIPSNEG, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 1
	// result: (MOVBstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 1) {
			break
		}
		v.reset(OpMIPSMOVBstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 2
	// result: (MOVHstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 2) {
			break
		}
		v.reset(OpMIPSMOVHstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && !t.IsFloat()
	// result: (MOVWstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && !t.IsFloat()) {
			break
		}
		v.reset(OpMIPSMOVWstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && t.IsFloat()
	// result: (MOVFstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && t.IsFloat()) {
			break
		}
		v.reset(OpMIPSMOVFstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && t.IsFloat()
	// result: (MOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && t.IsFloat()) {
			break
		}
		v.reset(OpMIPSMOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpSub32withcarry(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Sub32withcarry <t> x y c)
	// result: (SUB (SUB <t> x y) c)
	for {
		t := v.Type
		x := v_0
		y := v_1
		c := v_2
		v.reset(OpMIPSSUB)
		v0 := b.NewValue0(v.Pos, OpMIPSSUB, t)
		v0.AddArg2(x, y)
		v.AddArg2(v0, c)
		return true
	}
}
func rewriteValueMIPS_OpZero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Zero [0] _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_1
		v.copyOf(mem)
		return true
	}
	// match: (Zero [1] ptr mem)
	// result: (MOVBstore ptr (MOVWconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPSMOVBstore)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore ptr (MOVWconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPSMOVHstore)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] ptr mem)
	// result: (MOVBstore [1] ptr (MOVWconst [0]) (MOVBstore [0] ptr (MOVWconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPSMOVBstore)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1
"""




```