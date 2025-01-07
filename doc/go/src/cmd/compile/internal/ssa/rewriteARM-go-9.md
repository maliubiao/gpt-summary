Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Goal:** The request asks for the functionality of a specific Go file, `rewriteARM.go`, within the Go compiler. The snippet provided is a *part* of this file. The core task of `rewriteARM.go` is likely to perform architecture-specific optimizations or transformations on the intermediate representation (SSA) of Go code, targeting the ARM architecture.

2. **Initial Code Scan - Identifying Patterns:** The first thing to do is quickly scan the code for recurring patterns. Notice:
    * Function names like `rewriteValueARM_Op...`. This strongly suggests that the functions are responsible for rewriting specific SSA operations (`Op`). The `ARM` part confirms the target architecture.
    * Each function takes a `*Value` as input, which is an SSA value.
    * Inside each function, there are usually `match:` and `result:` comments. This clearly indicates a pattern-matching and rewriting approach.
    * The code frequently uses `b.NewValue0` to create new SSA values, suggesting the manipulation of the SSA graph.
    * There are references to `typ` and constants like `types.TypeFlags`, indicating interaction with Go's type system.
    *  Operations like `OpARMSUB`, `OpARMXOR`, `OpARMCMP`, etc., are present. These are ARM-specific assembly instructions or compiler intrinsics represented as SSA ops.
    *  There are checks for specific types using functions like `is8BitInt`, `is32BitFloat`, and extensions like `SignExt8to32`, `ZeroExt16to32`.

3. **Inferring the Overall Process:** Based on the patterns, the file likely works by iterating through the SSA representation of the code. For each SSA operation, it tries to find a "match" according to the defined patterns. If a match is found, it replaces the original operation with the "result," which is a sequence of new, potentially more efficient, SSA operations tailored for ARM.

4. **Analyzing Individual Functions (Examples):** Now, let's examine a few functions in more detail to solidify the understanding:

    * **`rewriteValueARM_OpAdd32`:**  The `match:` is `(Add32 x y)`, a standard 32-bit addition. The `result:` is `(ADD x y)`. This is a straightforward mapping of the generic `Add32` operation to the ARM-specific `ADD` instruction.

    * **`rewriteValueARM_OpAddPtr`:** The `match:` is `(AddPtr ptr inc)`, pointer arithmetic. The `result:` is `(ADD ptr inc)`. Similar to `OpAdd32`, this maps directly to the ARM `ADD`.

    * **`rewriteValueARM_OpAvg32u`:** The `match:` is `(Avg32u x y)`, unsigned 32-bit average. The `result:` is more complex, involving `SUB`, `XOR`, `Signmask`, and `CALLudiv`. This indicates a more involved optimization where the average is computed using bitwise operations and unsigned division. The code implements the formula `(x ^ y) >> 1 + min(x, y)` or similar logic using bit manipulation to avoid potential overflow.

    * **`rewriteValueARM_OpDiv32u`:** The `match:` is `(Div32u x y)`, unsigned 32-bit division. The `result:` uses `OpARMCALLudiv`, which is likely a call to a runtime function for unsigned division, and then selects the quotient (`Select0`).

    * **`rewriteValueARM_OpEq16`:** The `match:` is `(Eq16 x y)`, 16-bit equality comparison. The `result:` uses `OpARMCMP` (compare) after zero-extending the 16-bit values to 32 bits. The result of the comparison is then fed into `OpARMEqual` to produce the boolean equality value.

5. **Identifying Go Feature Implementation (Example - Integer Division/Modulo):**  Looking at `rewriteValueARM_OpDiv32`, `rewriteValueARM_OpDiv32u`, `rewriteValueARM_OpMod32`, and `rewriteValueARM_OpMod32u`, we can infer that this section handles the implementation of Go's integer division and modulo operations for 32-bit integers on the ARM architecture. The unsigned versions likely map to specific ARM division instructions or runtime calls, while the signed versions might involve more complex logic to handle negative numbers correctly.

6. **Inferring Command-Line Parameters (Less Likely Here):**  Based on the code structure, it's unlikely this specific file directly handles command-line parameters. Files involved in parsing command-line arguments and setting up the compilation environment would be located elsewhere in the Go compiler's source code (e.g., in the `cmd/compile` directory). The focus of this file is on SSA rewriting, which happens *after* the initial parsing and command-line processing.

7. **Identifying Potential Pitfalls (Example - Integer Division by Zero):** While this code doesn't explicitly show error handling, a common pitfall with integer division is division by zero. The compiler and/or runtime likely have mechanisms to handle this, but this rewriting logic itself focuses on *how* to perform the division assuming the divisor is not zero.

8. **Synthesizing the Summary:**  Finally, based on the analysis of the function names, the operations being rewritten, and the target architecture, we can summarize the functionality: This part of `rewriteARM.go` defines rewrite rules for various Go language operators (like addition, subtraction, comparison, division, etc.) when targeting the ARM architecture. It translates these generic operations into sequences of more specific ARM assembly instructions or intrinsic operations, aiming for better performance or to match the capabilities of the ARM instruction set.

This systematic approach of pattern recognition, detailed analysis of individual functions, and inference based on the context within the Go compiler source code allows us to understand the purpose and function of the provided code snippet.
这是 `go/src/cmd/compile/internal/ssa/rewriteARM.go` 文件的一部分，专门针对 ARM 架构的 SSA（Static Single Assignment）进行优化的重写规则。

**功能归纳:**

这部分代码定义了一系列用于将 Go 语言的通用操作（例如加法、减法、比较、位运算、加载、存储等）转换为更具体的、针对 ARM 架构优化的指令序列的重写规则。  它旨在利用 ARM 架构的特性来提升 Go 代码在 ARM 平台上的执行效率。

**具体功能列举和 Go 代码示例说明:**

这部分代码针对多种 Go 语言的操作进行了重写，以下列举一些例子并进行解释：

1. **算术运算优化:**

   - **`OpAdd32` 和 `OpAddPtr`:**  将 32 位整数加法和指针加法直接映射到 ARM 的 `ADD` 指令。

     ```go
     // 假设 SSA 中的操作是 OpAdd32，参数为 x 和 y
     // 输入: x = 10, y = 5
     // 输出: ARM 的 ADD 指令，结果为 15

     a := int32(10)
     b := int32(5)
     c := a + b // 在 SSA 层面会表示为 OpAdd32(a, b)
     ```

   - **`OpAvg32u`:**  将无符号 32 位整数的平均值计算转换为一系列位运算和减法，这可能比直接除法更高效。

     ```go
     // 假设 SSA 中的操作是 OpAvg32u，参数为 x 和 y
     // 输入: x = 10, y = 20
     // 输出: 通过一系列 SUB, XOR, Signmask 等操作计算出的平均值 15

     a := uint32(10)
     b := uint32(20)
     avg := (a + b) / 2 // 在 SSA 层面会表示为 OpAvg32u(a, b)
     ```

   - **`OpDiv32u` 和 `OpMod32u`:** 将无符号 32 位整数的除法和取模操作转换为调用 ARM 架构特定的 `CALLudiv` 函数，并使用 `Select0` 和 `Select1` 来提取商和余数。

     ```go
     // 假设 SSA 中的操作是 OpDiv32u 和 OpMod32u
     // 输入: x = 25, y = 5
     // 输出: OpDiv32u 对应 ARM 的 CALLudiv，然后 Select0 提取商 5
     //       OpMod32u 对应 ARM 的 CALLudiv，然后 Select1 提取余数 0

     a := uint32(25)
     b := uint32(5)
     quotient := a / b // 在 SSA 层面会表示为 OpDiv32u(a, b)
     remainder := a % b // 在 SSA 层面会表示为 OpMod32u(a, b)
     ```

2. **比较运算优化:**

   - **`OpEq16`, `OpEq32`, `OpEq8` 等:** 将相等比较操作转换为 ARM 的 `CMP` 指令，并使用 `Equal` 操作符来表示比较结果。对于小于 32 位的类型，通常会先进行零扩展或符号扩展。

     ```go
     // 假设 SSA 中的操作是 OpEq32，参数为 x 和 y
     // 输入: x = 10, y = 10
     // 输出: ARM 的 CMP 指令，然后 Equal 操作符根据 CMP 的结果生成 true

     a := int32(10)
     b := int32(10)
     equal := a == b // 在 SSA 层面会表示为 OpEq32(a, b)
     ```

   - **`OpLeq16`, `OpLess32`, `OpGreaterEqual` 等:**  类似地，将小于等于、小于、大于等于等比较操作转换为 ARM 的 `CMP` 指令，并使用相应的条件码操作符 (`LessEqual`, `LessThan`, `GreaterThanEqual` 等)。

3. **位运算优化:**

   - **`OpLsh16x16`, `OpRsh32x64`, `OpOr32` 等:**  将左移、右移、或运算等位运算直接映射到 ARM 相应的指令 (`SLL`, `SRL`, `ORR` 等)。对于不同大小的移位量，可能会有特殊的处理，例如当移位量是常量时，可以使用 `SLLconst` 这样的指令。

4. **加载和存储优化:**

   - **`OpLoad`:** 根据加载的数据类型，选择合适的 ARM 加载指令 (`MOVBUload`, `MOVBload`, `MOVHload`, `MOVWload`, `MOVFload`, `MOVDload`)。例如，加载布尔值会使用 `MOVBUload`（加载无符号字节）。

   - **`OpStore`:** 类似地，根据存储的数据类型选择合适的 ARM 存储指令 (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVFstore`, `MOVDstore`)。

5. **其他操作:**

   - **`OpMove`:**  优化内存拷贝操作，对于小的拷贝可能直接使用一系列的字节、半字或字的存储，对于大的拷贝可能会使用 `DUFFCOPY` 这样的优化的拷贝机制。
   - **`OpSignExt8to32`, `OpZeroExt16to32`:**  进行符号扩展和零扩展，这是在不同大小的整数类型之间进行转换时常见的操作。

**推理 Go 语言功能实现:**

这部分代码是 Go 编译器中后端编译的一部分，负责将 Go 语言的高级抽象操作转换为目标机器（这里是 ARM）的指令。它涉及到以下 Go 语言功能的实现：

- **基本数据类型操作:**  例如 `int`, `uint`, `bool`, `float32`, `float64` 等类型的算术运算、比较运算和位运算。
- **指针操作:**  例如指针的加法（地址偏移）、比较等。
- **类型转换:**  例如小整数类型到大整数类型的扩展。
- **内存操作:**  例如变量的加载和存储、内存拷贝。
- **控制流:** (虽然这段代码没有直接体现，但 `rewriteARM.go` 的其他部分会处理例如 `if`, `for`, `switch` 等语句的转换)

**假设的输入与输出 (代码推理示例):**

考虑 `rewriteValueARM_OpAdd32` 函数：

```go
func rewriteValueARM_OpAdd32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Add32 x y)
	// result: (ADD x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpARMADD)
		v.AddArg2(x, y)
		return true
	}
}
```

**假设输入:**

一个 SSA `Value` 类型的 `v`，其操作码 `v.Op` 是 `OpAdd32`，并且 `v.Args` 包含两个参数 `v_0` 和 `v_1`，它们分别代表要相加的两个 32 位整数。

**输出:**

函数返回 `true`，表示进行了重写。`v` 的状态被修改为：
- `v.Op` 变为 `OpARMADD` (ARM 的加法指令)。
- `v.Args` 仍然包含两个参数，即原来的 `v_0` 和 `v_1`，它们将作为 ARM `ADD` 指令的操作数。

**命令行参数的具体处理:**

`rewriteARM.go` 文件本身不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的前端和中间部分。例如，用户指定的架构 (`GOARCH=arm`) 会影响到编译器选择哪个架构的后端代码（包括 `rewriteARM.go`）来执行。

**使用者易犯错的点:**

对于直接使用 `go tool compile` 的开发者来说，理解这些底层的重写规则不是必须的。但是，对于想要深入了解 Go 编译器行为或者进行性能优化的开发者，可能会遇到以下容易犯错的点：

- **错误理解指令的语义:** ARM 指令集非常丰富，不同的指令有不同的行为和限制。错误理解 ARM 指令的语义可能导致重写规则的错误实现。
- **忽略了特定架构的限制:** 例如，某些 ARM 指令只能操作特定的寄存器或内存地址。重写规则必须考虑到这些限制。
- **过度优化导致代码复杂性增加:** 有时候为了追求极致的性能，可能会引入非常复杂的重写规则，这会增加代码的维护难度。
- **没有充分测试:**  对编译器后端代码的修改需要进行充分的测试，以确保生成的代码的正确性和性能。

**总结这部分的功能:**

这部分 `rewriteARM.go` 代码的核心功能是将 Go 语言中通用的、架构无关的操作转换为针对 ARM 架构优化的具体指令序列。 这是 Go 编译器后端针对特定架构进行代码优化的关键步骤，旨在提升 Go 程序在 ARM 平台上的性能。 它通过模式匹配和替换的方式，将 SSA 中间表示转换为更底层的、更贴近硬件的指令。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第10部分，共16部分，请归纳一下它的功能

"""
 typ.UInt32))
		v3 := b.NewValue0(v.Pos, OpARMSUB, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v5 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v5.AddArg(x)
		v4.AddArg2(x, v5)
		v3.AddArg2(v4, v5)
		v6 := b.NewValue0(v.Pos, OpARMSUB, typ.UInt32)
		v7 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v8 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v8.AddArg(y)
		v7.AddArg2(y, v8)
		v6.AddArg2(v7, v8)
		v2.AddArg2(v3, v6)
		v1.AddArg(v2)
		v9 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v10 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v10.AddArg2(x, y)
		v9.AddArg(v10)
		v0.AddArg2(v1, v9)
		v.AddArg2(v0, v9)
		return true
	}
}
func rewriteValueARM_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32u x y)
	// result: (Select0 <typ.UInt32> (CALLudiv x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, OpARMCALLudiv, types.NewTuple(typ.UInt32, typ.UInt32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (Div32 (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpDiv32)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (Div32u (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpDiv32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (Equal (CMP (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32 x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (Equal (CMPF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (Equal (CMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (Equal (CMP (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (XORconst [1] (XOR <typ.Bool> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpARMXOR, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqPtr x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpFMA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMA x y z)
	// result: (FMULAD z x y)
	for {
		x := v_0
		y := v_1
		z := v_2
		v.reset(OpARMFMULAD)
		v.AddArg3(z, x, y)
		return true
	}
}
func rewriteValueARM_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsInBounds idx len)
	// result: (LessThanU (CMP idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpARMLessThanU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsNonNil ptr)
	// result: (NotEqual (CMPconst [0] ptr))
	for {
		ptr := v_0
		v.reset(OpARMNotEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(ptr)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsSliceInBounds idx len)
	// result: (LessEqualU (CMP idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpARMLessEqualU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (LessEqual (CMP (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (LessEqualU (CMP (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqualU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32 x y)
	// result: (LessEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (GreaterEqual (CMPF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMGreaterEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32U x y)
	// result: (LessEqualU (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqualU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (GreaterEqual (CMPD y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMGreaterEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (LessEqual (CMP (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (LessEqualU (CMP (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqualU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (LessThan (CMP (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThan)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (LessThanU (CMP (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThanU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32 x y)
	// result: (LessThan (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThan)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (GreaterThan (CMPF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMGreaterThan)
		v0 := b.NewValue0(v.Pos, OpARMCMPF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32U x y)
	// result: (LessThanU (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThanU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (GreaterThan (CMPD y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMGreaterThan)
		v0 := b.NewValue0(v.Pos, OpARMCMPD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (LessThan (CMP (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThan)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (LessThanU (CMP (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThanU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Load <t> ptr mem)
	// cond: t.IsBoolean()
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsBoolean()) {
			break
		}
		v.reset(OpARMMOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && t.IsSigned())
	// result: (MOVBload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpARMMOVBload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && !t.IsSigned())
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpARMMOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && t.IsSigned())
	// result: (MOVHload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpARMMOVHload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && !t.IsSigned())
	// result: (MOVHUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpARMMOVHUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) || isPtr(t))
	// result: (MOVWload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpARMMOVWload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (MOVFload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpARMMOVFload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (MOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpARMMOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVWaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpARMMOVWaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVWaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpARMMOVWaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueARM_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x (ZeroExt16to32 y)) (CMPconst [256] (ZeroExt16to32 y)) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x32 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x y) (CMPconst [256] y) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh16x64 x (Const64 [c]))
	// cond: uint64(c) < 16
	// result: (SLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpARMSLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Lsh16x64 _ (Const64 [c]))
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
	return false
}
func rewriteValueARM_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 x y)
	// result: (SLL x (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSLL)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x (ZeroExt16to32 y)) (CMPconst [256] (ZeroExt16to32 y)) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x32 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x y) (CMPconst [256] y) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh32x64 x (Const64 [c]))
	// cond: uint64(c) < 32
	// result: (SLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(OpARMSLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Lsh32x64 _ (Const64 [c]))
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
	return false
}
func rewriteValueARM_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 x y)
	// result: (SLL x (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSLL)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x (ZeroExt16to32 y)) (CMPconst [256] (ZeroExt16to32 y)) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x32 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x y) (CMPconst [256] y) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh8x64 x (Const64 [c]))
	// cond: uint64(c) < 8
	// result: (SLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(OpARMSLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Lsh8x64 _ (Const64 [c]))
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
	return false
}
func rewriteValueARM_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 x y)
	// result: (SLL x (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSLL)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (Mod32 (SignExt16to32 x) (SignExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (Mod32u (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32 x y)
	// result: (SUB (XOR <typ.UInt32> (Select1 <typ.UInt32> (CALLudiv (SUB <typ.UInt32> (XOR <typ.UInt32> x (Signmask x)) (Signmask x)) (SUB <typ.UInt32> (XOR <typ.UInt32> y (Signmask y)) (Signmask y)))) (Signmask x)) (Signmask x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSUB)
		v0 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpARMCALLudiv, types.NewTuple(typ.UInt32, typ.UInt32))
		v3 := b.NewValue0(v.Pos, OpARMSUB, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v5 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v5.AddArg(x)
		v4.AddArg2(x, v5)
		v3.AddArg2(v4, v5)
		v6 := b.NewValue0(v.Pos, OpARMSUB, typ.UInt32)
		v7 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v8 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v8.AddArg(y)
		v7.AddArg2(y, v8)
		v6.AddArg2(v7, v8)
		v2.AddArg2(v3, v6)
		v1.AddArg(v2)
		v0.AddArg2(v1, v5)
		v.AddArg2(v0, v5)
		return true
	}
}
func rewriteValueARM_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32u x y)
	// result: (Select1 <typ.UInt32> (CALLudiv x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, OpARMCALLudiv, types.NewTuple(typ.UInt32, typ.UInt32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (Mod32 (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (Mod32u (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Move [0] _ _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.copyOf(mem)
		return true
	}
	// match: (Move [1] dst src mem)
	// result: (MOVBstore dst (MOVBUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v0 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore dst (MOVHUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpARMMOVHstore)
		v0 := b.NewValue0(v.Pos, OpARMMOVHUload, typ.UInt16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVBstore [1] dst (MOVBUload [1] src mem) (MOVBstore dst (MOVBUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore dst (MOVWload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpARMMOVWstore)
		v0 := b.NewValue0(v.Pos, OpARMMOVWload, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [2] dst (MOVHUload [2] src mem) (MOVHstore dst (MOVHUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARMMOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARMMOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARMMOVHUload, typ.UInt16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVBstore [3] dst (MOVBUload [3] src mem) (MOVBstore [2] dst (MOVBUload [2] src mem) (MOVBstore [1] dst (MOVBUload [1] src mem) (MOVBstore dst (MOVBUload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v2.AuxInt = int32ToAuxInt(2)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(1)
		v4 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v4.AuxInt = int32ToAuxInt(1)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBUload [2] src mem) (MOVBstore [1] dst (MOVBUload [1] src mem) (MOVBstore dst (MOVBUload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v2.AuxInt = int32ToAuxInt(1)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] {t} dst src mem)
	// cond: s%4 == 0 && s > 4 && s <= 512 && t.Alignment()%4 == 0 && !config.noDuffDevice && logLargeCopy(v, s)
	// result: (DUFFCOPY [8 * (128 - s/4)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%4 == 0 && s > 4 && s <= 512 && t.Alignment()%4 == 0 && !config.noDuffDevice && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpARMDUFFCOPY)
		v.AuxInt = int64ToAuxInt(8 * (128 - s/4))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] {t} dst src mem)
	// cond: ((s > 512 || config.noDuffDevice) || t.Alignment()%4 != 0) && logLargeCopy(v, s)
	// result: (LoweredMove [t.Alignment()] dst src (ADDconst <src.Type> src [int32(s-moveSize(t.Alignment(), config))]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(((s > 512 || config.noDuffDevice) || t.Alignment()%4 != 0) && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpARMLoweredMove)
		v.AuxInt = int64ToAuxInt(t.Alignment())
		v0 := b.NewValue0(v.Pos, OpARMADDconst, src.Type)
		v0.AuxInt = int32ToAuxInt(int32(s - moveSize(t.Alignment(), config)))
		v0.AddArg(src)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpNeg16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg16 x)
	// result: (RSBconst [0] x)
	for {
		x := v_0
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
}
func rewriteValueARM_OpNeg32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg32 x)
	// result: (RSBconst [0] x)
	for {
		x := v_0
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
}
func rewriteValueARM_OpNeg8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg8 x)
	// result: (RSBconst [0] x)
	for {
		x := v_0
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
}
func rewriteValueARM_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (NotEqual (CMP (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMNotEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32 x y)
	// result: (NotEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMNotEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}

"""




```