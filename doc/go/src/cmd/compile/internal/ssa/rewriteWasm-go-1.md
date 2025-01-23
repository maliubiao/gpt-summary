Response: The user wants to understand the functionality of the provided Go code snippet. This code is part of the Go compiler, specifically targeting the WebAssembly (Wasm) architecture. It seems to be involved in rewriting intermediate representation (SSA) of Go code into Wasm-specific operations.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core task:** The file name `rewriteWasm.go` and the function names like `rewriteValueWasm_OpRsh64x16` strongly suggest this code is responsible for transforming generic SSA operations into their Wasm equivalents. The `rewriteValueWasm_Op...` pattern indicates that each function handles a specific SSA operation.

2. **Analyze individual functions:**  Each function follows a similar structure:
   - It takes a `*Value` as input, representing an SSA value.
   - It extracts arguments from the `Value`.
   - It performs pattern matching on the operation and arguments of the `Value`.
   - If a match is found, it rewrites the `Value` to a Wasm-specific operation, potentially creating new `Value`s.

3. **Focus on specific examples:** Let's take `rewriteValueWasm_OpRsh64x16` as an example.
   - It handles the `OpRsh64x16` operation, which is a right shift of a 64-bit value by a 16-bit value.
   - The "match" comment indicates the pattern it looks for: `(Rsh64x16 [c] x y)`. `c` is an auxiliary integer, `x` is the 64-bit value, and `y` is the 16-bit shift amount.
   - The "result" comment shows the transformation: `(Rsh64x64 [c] x (ZeroExt16to64 y))`. This means it converts the 16-bit shift amount to 64-bit by zero-extension and then performs a 64-bit right shift.

4. **Infer the broader purpose:**  By examining multiple functions, a pattern emerges: the code translates Go's generic right-shift operations (with varying shift operand sizes) into a canonical 64-bit right shift in Wasm, possibly involving zero-extension or sign-extension of the operands.

5. **Identify key Wasm operations:**  The code uses operations prefixed with `OpWasm`, such as `OpWasmI64ShrS` (64-bit signed right shift), `OpWasmI64Const` (64-bit constant), `OpWasmZeroExt16to64` (zero-extend 16-bit to 64-bit), etc. This confirms the Wasm target.

6. **Consider the role of `auxInt`:** The code uses `auxInt` to store additional information, like constant values or flags. The functions `auxIntToBool`, `boolToAuxInt`, `auxIntToInt64`, etc., are used to convert between `auxInt` and Go's native types.

7. **Look for conditional logic:** Some rewrites have "cond" comments, indicating conditions that must be met for the transformation to occur. For example, `rewriteValueWasm_OpRsh64x64` has conditions based on whether the shift amount is bounded or if it's a constant. This shows optimization and handling of specific cases.

8. **Infer Go language features:**  The operations being rewritten (like `Rsh64x16`, `Rsh64x32`, `SignExt`, `ZeroExt`) correspond directly to Go's bitwise shift and type conversion operations.

9. **Construct Go examples:** Based on the transformations observed, create Go code examples that would trigger these rewrites. For instance, a right shift of an `int64` by an `int16` would likely be handled by `rewriteValueWasm_OpRsh64x16`.

10. **Address specific request points:**
    - **Functionality:** Summarize the purpose of each function and the overall goal of the file.
    - **Go language feature:**  Connect the rewrites to Go's shift and type conversion operations. Provide concrete Go code examples.
    - **Code reasoning:** Explain the input, the matching process, and the output transformation, including the assumptions about the SSA representation.
    - **Command-line arguments:** Scan the code for any explicit handling of command-line flags. In this snippet, there aren't any. Mention this explicitly.
    - **Common mistakes:** Think about potential errors a user might make when writing Go code that would be processed by this compiler stage. For example, relying on specific behavior for large shift amounts, which the compiler might optimize away.
    - **Overall function (for part 2):** Provide a concise summary of the code's role in the compilation process.

By following these steps, we can arrive at a comprehensive understanding of the code and generate the detailed answer requested by the user.
这是 `go/src/cmd/compile/internal/ssa/rewriteWasm.go` 文件的一部分，主要负责在 Go 编译器的 SSA（Static Single Assignment）中间表示阶段，针对 WebAssembly (Wasm) 平台进行特定的代码重写和优化。

**功能归纳：**

这部分代码定义了一系列以 `rewriteValueWasm_Op...` 为前缀的函数。每个函数都针对一个特定的 Go 语言操作符（例如 `OpRsh64x16` 表示 64 位整数右移 16 位）进行模式匹配和代码转换。

**具体功能：**

1. **将 Go 语言的通用操作转换为 WebAssembly 特定的操作:**  由于 WebAssembly 有其特定的指令集和类型系统，这部分代码负责将 Go 语言的通用操作（在 SSA 中表示）转换为最适合 WebAssembly 执行的指令序列。例如，`OpRsh64x16` 被转换为 `OpWasmRsh64x64`，并显式地将 16 位的移位量零扩展为 64 位。

2. **实现特定操作的优化:**  部分函数还实现了针对 WebAssembly 的特定优化。例如，`rewriteValueWasm_OpRsh64x64` 函数针对不同的移位量（常量或变量）以及是否超出边界进行了优化，以利用 WebAssembly 的 `I64ShrS` 指令。

3. **处理类型转换:** 像 `rewriteValueWasm_OpSignExt16to32` 和 `rewriteValueWasm_OpZeroExt8to64` 这样的函数负责处理 Go 语言中的符号扩展和零扩展操作，并将其转换为相应的 WebAssembly 操作或指令序列。

4. **处理内存操作:**  `rewriteValueWasm_OpStore` 和 `rewriteValueWasm_OpLoad` 系列的函数根据存储或加载的数据类型大小，将其转换为 WebAssembly 中对应的内存访问指令 (`I64Store8`, `I64Store16`, `I64Load32U` 等)。

5. **常量折叠:**  对于某些操作（如加法、乘法、位运算），如果操作数是常量，代码会尝试在编译时进行计算，生成新的常量节点，这是一种常见的编译器优化技术。例如 `rewriteValueWasm_OpWasmI64Add` 中处理两个常量相加的情况。

**推断的 Go 语言功能实现及代码示例：**

这部分代码主要处理 Go 语言的以下功能：

* **位运算:**  右移 (`>>`) 操作，包括不同大小的移位量。
* **类型转换:** 显式的类型转换，如将 `int16` 转换为 `int32` (符号扩展) 或将 `uint8` 转换为 `uint64` (零扩展)。
* **内存操作:**  通过指针进行值的存储和加载。

**Go 代码示例：**

```go
package main

func main() {
	var x int64 = 0xFFFFFFFFFFFFFFFF
	var y int16 = 10
	var z uint8 = 5

	// 对应 rewriteValueWasm_OpRsh64x16
	result1 := x >> y
	println(result1)

	// 对应 rewriteValueWasm_OpSignExt8to64 (假设 buildcfg.GOWASM.SignExt 为 false)
	var a int8 = -1
	var b int64 = int64(a)
	println(b)

	// 对应 rewriteValueWasm_OpZeroExt8to64
	var c uint8 = 255
	var d uint64 = uint64(c)
	println(d)

	// 对应 rewriteValueWasm_OpStore 和 rewriteValueWasm_OpLoad
	var val int32 = 12345
	ptr := &val
	*ptr = 67890
	loadedVal := *ptr
	println(loadedVal)
}
```

**假设的输入与输出 (针对 `rewriteValueWasm_OpRsh64x16`)：**

**假设输入 (SSA Value `v`)：**

```
Op: OpRsh64x16
AuxInt: (一些表示 bool 值的 int)
Args: [Value{Op: ..., Type: int64}, Value{Op: ..., Type: int16}]
```

例如，`v.Args[0]` 可能是一个代表变量 `x` 的 SSA 值，`v.Args[1]` 可能是一个代表变量 `y` 的 SSA 值。

**输出 (修改后的 SSA Value `v`)：**

```
Op: OpWasmRsh64x64
AuxInt: (与输入相同)
Args: [Value{Op: ... (与输入相同)}, Value{Op: OpZeroExt16to64, Args: [Value{Op: ... (输入 v.Args[1])}]}]
```

输出中，`OpRsh64x16` 被替换为 `OpWasmRsh64x64`，并且第二个参数 `y` 被包裹在一个 `OpZeroExt16to64` 操作中，确保移位量是 64 位的。

**命令行参数的具体处理：**

在这部分代码中，没有直接处理命令行参数的逻辑。这些 `rewriteValueWasm_Op...` 函数是在编译器的后端执行的，它们依赖于之前阶段的分析和决策。命令行参数（如 `-gcflags` 等）会影响编译过程的早期阶段，例如词法分析、语法分析、类型检查等，以及中间表示的生成。

**使用者易犯错的点：**

对于直接使用这部分代码的开发者来说，理解 SSA 的结构和 Go 编译器的内部工作机制是至关重要的。普通 Go 开发者不会直接接触到这些代码。

**归纳一下它的功能 (第2部分):**

作为 `rewriteWasm.go` 文件的一部分，这部分代码的核心功能是在 Go 编译器的 SSA 阶段，将 Go 语言的中间表示转换为更贴近 WebAssembly 平台的表示。它针对特定的 Go 语言操作符，通过模式匹配和转换规则，生成等效的 WebAssembly 操作序列，并进行一些平台相关的优化。这确保了最终生成的 WebAssembly 代码能够高效地执行 Go 程序。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteWasm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
writeValueWasm_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x16 [c] x y)
	// result: (Rsh64x64 [c] x (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x32 [c] x y)
	// result: (Rsh64x64 [c] x (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x64 x y)
	// cond: shiftIsBounded(v)
	// result: (I64ShrS x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpWasmI64ShrS)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x64 x (I64Const [c]))
	// cond: uint64(c) < 64
	// result: (I64ShrS x (I64Const [c]))
	for {
		x := v_0
		if v_1.Op != OpWasmI64Const {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 64) {
			break
		}
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x64 x (I64Const [c]))
	// cond: uint64(c) >= 64
	// result: (I64ShrS x (I64Const [63]))
	for {
		x := v_0
		if v_1.Op != OpWasmI64Const {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(63)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64x64 x y)
	// result: (I64ShrS x (Select <typ.Int64> y (I64Const [63]) (I64LtU y (I64Const [64]))))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmSelect, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpWasmI64LtU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(y, v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x8 [c] x y)
	// result: (Rsh64x64 [c] x (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt8to64 x) (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt8to64 x) (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt8to64 x) y)
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueWasm_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 [c] x y)
	// result: (Rsh64x64 [c] (SignExt8to64 x) (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 [c] x y)
	// result: (Rsh64x64 [c] (SignExt8to64 x) (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 [c] x y)
	// result: (Rsh64x64 [c] (SignExt8to64 x) y)
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueWasm_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 [c] x y)
	// result: (Rsh64x64 [c] (SignExt8to64 x) (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpSignExt16to32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SignExt16to32 x:(I64Load16S _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load16S {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SignExt16to32 x)
	// cond: buildcfg.GOWASM.SignExt
	// result: (I64Extend16S x)
	for {
		x := v_0
		if !(buildcfg.GOWASM.SignExt) {
			break
		}
		v.reset(OpWasmI64Extend16S)
		v.AddArg(x)
		return true
	}
	// match: (SignExt16to32 x)
	// result: (I64ShrS (I64Shl x (I64Const [48])) (I64Const [48]))
	for {
		x := v_0
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmI64Shl, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(48)
		v0.AddArg2(x, v1)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpSignExt16to64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SignExt16to64 x:(I64Load16S _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load16S {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SignExt16to64 x)
	// cond: buildcfg.GOWASM.SignExt
	// result: (I64Extend16S x)
	for {
		x := v_0
		if !(buildcfg.GOWASM.SignExt) {
			break
		}
		v.reset(OpWasmI64Extend16S)
		v.AddArg(x)
		return true
	}
	// match: (SignExt16to64 x)
	// result: (I64ShrS (I64Shl x (I64Const [48])) (I64Const [48]))
	for {
		x := v_0
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmI64Shl, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(48)
		v0.AddArg2(x, v1)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpSignExt32to64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SignExt32to64 x:(I64Load32S _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load32S {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SignExt32to64 x)
	// cond: buildcfg.GOWASM.SignExt
	// result: (I64Extend32S x)
	for {
		x := v_0
		if !(buildcfg.GOWASM.SignExt) {
			break
		}
		v.reset(OpWasmI64Extend32S)
		v.AddArg(x)
		return true
	}
	// match: (SignExt32to64 x)
	// result: (I64ShrS (I64Shl x (I64Const [32])) (I64Const [32]))
	for {
		x := v_0
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmI64Shl, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(32)
		v0.AddArg2(x, v1)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpSignExt8to16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SignExt8to16 x:(I64Load8S _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load8S {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SignExt8to16 x)
	// cond: buildcfg.GOWASM.SignExt
	// result: (I64Extend8S x)
	for {
		x := v_0
		if !(buildcfg.GOWASM.SignExt) {
			break
		}
		v.reset(OpWasmI64Extend8S)
		v.AddArg(x)
		return true
	}
	// match: (SignExt8to16 x)
	// result: (I64ShrS (I64Shl x (I64Const [56])) (I64Const [56]))
	for {
		x := v_0
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmI64Shl, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(56)
		v0.AddArg2(x, v1)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpSignExt8to32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SignExt8to32 x:(I64Load8S _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load8S {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SignExt8to32 x)
	// cond: buildcfg.GOWASM.SignExt
	// result: (I64Extend8S x)
	for {
		x := v_0
		if !(buildcfg.GOWASM.SignExt) {
			break
		}
		v.reset(OpWasmI64Extend8S)
		v.AddArg(x)
		return true
	}
	// match: (SignExt8to32 x)
	// result: (I64ShrS (I64Shl x (I64Const [56])) (I64Const [56]))
	for {
		x := v_0
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmI64Shl, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(56)
		v0.AddArg2(x, v1)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpSignExt8to64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SignExt8to64 x:(I64Load8S _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load8S {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SignExt8to64 x)
	// cond: buildcfg.GOWASM.SignExt
	// result: (I64Extend8S x)
	for {
		x := v_0
		if !(buildcfg.GOWASM.SignExt) {
			break
		}
		v.reset(OpWasmI64Extend8S)
		v.AddArg(x)
		return true
	}
	// match: (SignExt8to64 x)
	// result: (I64ShrS (I64Shl x (I64Const [56])) (I64Const [56]))
	for {
		x := v_0
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmI64Shl, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(56)
		v0.AddArg2(x, v1)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Slicemask x)
	// result: (I64ShrS (I64Sub (I64Const [0]) x) (I64Const [63]))
	for {
		x := v_0
		v.reset(OpWasmI64ShrS)
		v0 := b.NewValue0(v.Pos, OpWasmI64Sub, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v0.AddArg2(v1, x)
		v2 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v2.AuxInt = int64ToAuxInt(63)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueWasm_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Store {t} ptr val mem)
	// cond: is64BitFloat(t)
	// result: (F64Store ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpWasmF64Store)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: is32BitFloat(t)
	// result: (F32Store ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpWasmF32Store)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8
	// result: (I64Store ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8) {
			break
		}
		v.reset(OpWasmI64Store)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4
	// result: (I64Store32 ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4) {
			break
		}
		v.reset(OpWasmI64Store32)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 2
	// result: (I64Store16 ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 2) {
			break
		}
		v.reset(OpWasmI64Store16)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 1
	// result: (I64Store8 ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 1) {
			break
		}
		v.reset(OpWasmI64Store8)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmF64Add(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (F64Add (F64Const [x]) (F64Const [y]))
	// result: (F64Const [x + y])
	for {
		if v_0.Op != OpWasmF64Const {
			break
		}
		x := auxIntToFloat64(v_0.AuxInt)
		if v_1.Op != OpWasmF64Const {
			break
		}
		y := auxIntToFloat64(v_1.AuxInt)
		v.reset(OpWasmF64Const)
		v.AuxInt = float64ToAuxInt(x + y)
		return true
	}
	// match: (F64Add (F64Const [x]) y)
	// cond: y.Op != OpWasmF64Const
	// result: (F64Add y (F64Const [x]))
	for {
		if v_0.Op != OpWasmF64Const {
			break
		}
		x := auxIntToFloat64(v_0.AuxInt)
		y := v_1
		if !(y.Op != OpWasmF64Const) {
			break
		}
		v.reset(OpWasmF64Add)
		v0 := b.NewValue0(v.Pos, OpWasmF64Const, typ.Float64)
		v0.AuxInt = float64ToAuxInt(x)
		v.AddArg2(y, v0)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmF64Mul(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (F64Mul (F64Const [x]) (F64Const [y]))
	// cond: !math.IsNaN(x * y)
	// result: (F64Const [x * y])
	for {
		if v_0.Op != OpWasmF64Const {
			break
		}
		x := auxIntToFloat64(v_0.AuxInt)
		if v_1.Op != OpWasmF64Const {
			break
		}
		y := auxIntToFloat64(v_1.AuxInt)
		if !(!math.IsNaN(x * y)) {
			break
		}
		v.reset(OpWasmF64Const)
		v.AuxInt = float64ToAuxInt(x * y)
		return true
	}
	// match: (F64Mul (F64Const [x]) y)
	// cond: y.Op != OpWasmF64Const
	// result: (F64Mul y (F64Const [x]))
	for {
		if v_0.Op != OpWasmF64Const {
			break
		}
		x := auxIntToFloat64(v_0.AuxInt)
		y := v_1
		if !(y.Op != OpWasmF64Const) {
			break
		}
		v.reset(OpWasmF64Mul)
		v0 := b.NewValue0(v.Pos, OpWasmF64Const, typ.Float64)
		v0.AuxInt = float64ToAuxInt(x)
		v.AddArg2(y, v0)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Add(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (I64Add (I64Const [x]) (I64Const [y]))
	// result: (I64Const [x + y])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(x + y)
		return true
	}
	// match: (I64Add (I64Const [x]) y)
	// cond: y.Op != OpWasmI64Const
	// result: (I64Add y (I64Const [x]))
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(y.Op != OpWasmI64Const) {
			break
		}
		v.reset(OpWasmI64Add)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(x)
		v.AddArg2(y, v0)
		return true
	}
	// match: (I64Add x (I64Const <t> [y]))
	// cond: !t.IsPtr()
	// result: (I64AddConst [y] x)
	for {
		x := v_0
		if v_1.Op != OpWasmI64Const {
			break
		}
		t := v_1.Type
		y := auxIntToInt64(v_1.AuxInt)
		if !(!t.IsPtr()) {
			break
		}
		v.reset(OpWasmI64AddConst)
		v.AuxInt = int64ToAuxInt(y)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64AddConst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (I64AddConst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (I64AddConst [off] (LoweredAddr {sym} [off2] base))
	// cond: isU32Bit(off+int64(off2))
	// result: (LoweredAddr {sym} [int32(off)+off2] base)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmLoweredAddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		if !(isU32Bit(off + int64(off2))) {
			break
		}
		v.reset(OpWasmLoweredAddr)
		v.AuxInt = int32ToAuxInt(int32(off) + off2)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	// match: (I64AddConst [off] x:(SP))
	// cond: isU32Bit(off)
	// result: (LoweredAddr [int32(off)] x)
	for {
		off := auxIntToInt64(v.AuxInt)
		x := v_0
		if x.Op != OpSP || !(isU32Bit(off)) {
			break
		}
		v.reset(OpWasmLoweredAddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64And(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (I64And (I64Const [x]) (I64Const [y]))
	// result: (I64Const [x & y])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(x & y)
		return true
	}
	// match: (I64And (I64Const [x]) y)
	// cond: y.Op != OpWasmI64Const
	// result: (I64And y (I64Const [x]))
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(y.Op != OpWasmI64Const) {
			break
		}
		v.reset(OpWasmI64And)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(x)
		v.AddArg2(y, v0)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Eq(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (I64Eq (I64Const [x]) (I64Const [y]))
	// cond: x == y
	// result: (I64Const [1])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		if !(x == y) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (I64Eq (I64Const [x]) (I64Const [y]))
	// cond: x != y
	// result: (I64Const [0])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		if !(x != y) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (I64Eq (I64Const [x]) y)
	// cond: y.Op != OpWasmI64Const
	// result: (I64Eq y (I64Const [x]))
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(y.Op != OpWasmI64Const) {
			break
		}
		v.reset(OpWasmI64Eq)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(x)
		v.AddArg2(y, v0)
		return true
	}
	// match: (I64Eq x (I64Const [0]))
	// result: (I64Eqz x)
	for {
		x := v_0
		if v_1.Op != OpWasmI64Const || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpWasmI64Eqz)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Eqz(v *Value) bool {
	v_0 := v.Args[0]
	// match: (I64Eqz (I64Eqz (I64Eqz x)))
	// result: (I64Eqz x)
	for {
		if v_0.Op != OpWasmI64Eqz {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpWasmI64Eqz {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpWasmI64Eqz)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64LeU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (I64LeU x (I64Const [0]))
	// result: (I64Eqz x)
	for {
		x := v_0
		if v_1.Op != OpWasmI64Const || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpWasmI64Eqz)
		v.AddArg(x)
		return true
	}
	// match: (I64LeU (I64Const [1]) x)
	// result: (I64Eqz (I64Eqz x))
	for {
		if v_0.Op != OpWasmI64Const || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpWasmI64Eqz)
		v0 := b.NewValue0(v.Pos, OpWasmI64Eqz, typ.Bool)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Load(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (I64Load [off] (I64AddConst [off2] ptr) mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Load [off+off2] ptr mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Load)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (I64Load [off] (LoweredAddr {sym} [off2] (SB)) _)
	// cond: symIsRO(sym) && isU32Bit(off+int64(off2))
	// result: (I64Const [int64(read64(sym, off+int64(off2), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmLoweredAddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB || !(symIsRO(sym) && isU32Bit(off+int64(off2))) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(int64(read64(sym, off+int64(off2), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Load16S(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64Load16S [off] (I64AddConst [off2] ptr) mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Load16S [off+off2] ptr mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Load16S)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Load16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (I64Load16U [off] (I64AddConst [off2] ptr) mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Load16U [off+off2] ptr mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Load16U)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (I64Load16U [off] (LoweredAddr {sym} [off2] (SB)) _)
	// cond: symIsRO(sym) && isU32Bit(off+int64(off2))
	// result: (I64Const [int64(read16(sym, off+int64(off2), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmLoweredAddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB || !(symIsRO(sym) && isU32Bit(off+int64(off2))) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(int64(read16(sym, off+int64(off2), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Load32S(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64Load32S [off] (I64AddConst [off2] ptr) mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Load32S [off+off2] ptr mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Load32S)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Load32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (I64Load32U [off] (I64AddConst [off2] ptr) mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Load32U [off+off2] ptr mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Load32U)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (I64Load32U [off] (LoweredAddr {sym} [off2] (SB)) _)
	// cond: symIsRO(sym) && isU32Bit(off+int64(off2))
	// result: (I64Const [int64(read32(sym, off+int64(off2), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmLoweredAddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB || !(symIsRO(sym) && isU32Bit(off+int64(off2))) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(int64(read32(sym, off+int64(off2), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Load8S(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64Load8S [off] (I64AddConst [off2] ptr) mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Load8S [off+off2] ptr mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Load8S)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Load8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64Load8U [off] (I64AddConst [off2] ptr) mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Load8U [off+off2] ptr mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Load8U)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (I64Load8U [off] (LoweredAddr {sym} [off2] (SB)) _)
	// cond: symIsRO(sym) && isU32Bit(off+int64(off2))
	// result: (I64Const [int64(read8(sym, off+int64(off2)))])
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmLoweredAddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB || !(symIsRO(sym) && isU32Bit(off+int64(off2))) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(int64(read8(sym, off+int64(off2))))
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64LtU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (I64LtU (I64Const [0]) x)
	// result: (I64Eqz (I64Eqz x))
	for {
		if v_0.Op != OpWasmI64Const || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpWasmI64Eqz)
		v0 := b.NewValue0(v.Pos, OpWasmI64Eqz, typ.Bool)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (I64LtU x (I64Const [1]))
	// result: (I64Eqz x)
	for {
		x := v_0
		if v_1.Op != OpWasmI64Const || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpWasmI64Eqz)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Mul(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (I64Mul (I64Const [x]) (I64Const [y]))
	// result: (I64Const [x * y])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(x * y)
		return true
	}
	// match: (I64Mul (I64Const [x]) y)
	// cond: y.Op != OpWasmI64Const
	// result: (I64Mul y (I64Const [x]))
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(y.Op != OpWasmI64Const) {
			break
		}
		v.reset(OpWasmI64Mul)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(x)
		v.AddArg2(y, v0)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Ne(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (I64Ne (I64Const [x]) (I64Const [y]))
	// cond: x == y
	// result: (I64Const [0])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		if !(x == y) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (I64Ne (I64Const [x]) (I64Const [y]))
	// cond: x != y
	// result: (I64Const [1])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		if !(x != y) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (I64Ne (I64Const [x]) y)
	// cond: y.Op != OpWasmI64Const
	// result: (I64Ne y (I64Const [x]))
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(y.Op != OpWasmI64Const) {
			break
		}
		v.reset(OpWasmI64Ne)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(x)
		v.AddArg2(y, v0)
		return true
	}
	// match: (I64Ne x (I64Const [0]))
	// result: (I64Eqz (I64Eqz x))
	for {
		x := v_0
		if v_1.Op != OpWasmI64Const || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpWasmI64Eqz)
		v0 := b.NewValue0(v.Pos, OpWasmI64Eqz, typ.Bool)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Or(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (I64Or (I64Const [x]) (I64Const [y]))
	// result: (I64Const [x | y])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(x | y)
		return true
	}
	// match: (I64Or (I64Const [x]) y)
	// cond: y.Op != OpWasmI64Const
	// result: (I64Or y (I64Const [x]))
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(y.Op != OpWasmI64Const) {
			break
		}
		v.reset(OpWasmI64Or)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(x)
		v.AddArg2(y, v0)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Shl(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64Shl (I64Const [x]) (I64Const [y]))
	// result: (I64Const [x << uint64(y)])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(x << uint64(y))
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64ShrS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64ShrS (I64Const [x]) (I64Const [y]))
	// result: (I64Const [x >> uint64(y)])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(x >> uint64(y))
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64ShrU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64ShrU (I64Const [x]) (I64Const [y]))
	// result: (I64Const [int64(uint64(x) >> uint64(y))])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(int64(uint64(x) >> uint64(y)))
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Store(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64Store [off] (I64AddConst [off2] ptr) val mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Store [off+off2] ptr val mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Store)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Store16(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64Store16 [off] (I64AddConst [off2] ptr) val mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Store16 [off+off2] ptr val mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Store16)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Store32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64Store32 [off] (I64AddConst [off2] ptr) val mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Store32 [off+off2] ptr val mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Store32)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Store8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (I64Store8 [off] (I64AddConst [off2] ptr) val mem)
	// cond: isU32Bit(off+off2)
	// result: (I64Store8 [off+off2] ptr val mem)
	for {
		off := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpWasmI64AddConst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(isU32Bit(off + off2)) {
			break
		}
		v.reset(OpWasmI64Store8)
		v.AuxInt = int64ToAuxInt(off + off2)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpWasmI64Xor(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (I64Xor (I64Const [x]) (I64Const [y]))
	// result: (I64Const [x ^ y])
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpWasmI64Const {
			break
		}
		y := auxIntToInt64(v_1.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(x ^ y)
		return true
	}
	// match: (I64Xor (I64Const [x]) y)
	// cond: y.Op != OpWasmI64Const
	// result: (I64Xor y (I64Const [x]))
	for {
		if v_0.Op != OpWasmI64Const {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		y := v_1
		if !(y.Op != OpWasmI64Const) {
			break
		}
		v.reset(OpWasmI64Xor)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(x)
		v.AddArg2(y, v0)
		return true
	}
	return false
}
func rewriteValueWasm_OpZero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
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
	// match: (Zero [1] destptr mem)
	// result: (I64Store8 destptr (I64Const [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store8)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(destptr, v0, mem)
		return true
	}
	// match: (Zero [2] destptr mem)
	// result: (I64Store16 destptr (I64Const [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store16)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(destptr, v0, mem)
		return true
	}
	// match: (Zero [4] destptr mem)
	// result: (I64Store32 destptr (I64Const [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store32)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(destptr, v0, mem)
		return true
	}
	// match: (Zero [8] destptr mem)
	// result: (I64Store destptr (I64Const [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(destptr, v0, mem)
		return true
	}
	// match: (Zero [3] destptr mem)
	// result: (I64Store8 [2] destptr (I64Const [0]) (I64Store16 destptr (I64Const [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store8)
		v.AuxInt = int64ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store16, types.TypeMem)
		v1.AddArg3(destptr, v0, mem)
		v.AddArg3(destptr, v0, v1)
		return true
	}
	// match: (Zero [5] destptr mem)
	// result: (I64Store8 [4] destptr (I64Const [0]) (I64Store32 destptr (I64Const [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store8)
		v.AuxInt = int64ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store32, types.TypeMem)
		v1.AddArg3(destptr, v0, mem)
		v.AddArg3(destptr, v0, v1)
		return true
	}
	// match: (Zero [6] destptr mem)
	// result: (I64Store16 [4] destptr (I64Const [0]) (I64Store32 destptr (I64Const [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store16)
		v.AuxInt = int64ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store32, types.TypeMem)
		v1.AddArg3(destptr, v0, mem)
		v.AddArg3(destptr, v0, v1)
		return true
	}
	// match: (Zero [7] destptr mem)
	// result: (I64Store32 [3] destptr (I64Const [0]) (I64Store32 destptr (I64Const [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store32)
		v.AuxInt = int64ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store32, types.TypeMem)
		v1.AddArg3(destptr, v0, mem)
		v.AddArg3(destptr, v0, v1)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s%8 != 0 && s > 8 && s < 32
	// result: (Zero [s-s%8] (OffPtr <destptr.Type> destptr [s%8]) (I64Store destptr (I64Const [0]) mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s%8 != 0 && s > 8 && s < 32) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(s - s%8)
		v0 := b.NewValue0(v.Pos, OpOffPtr, destptr.Type)
		v0.AuxInt = int64ToAuxInt(s % 8)
		v0.AddArg(destptr)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v1.AddArg3(destptr, v2, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [16] destptr mem)
	// result: (I64Store [8] destptr (I64Const [0]) (I64Store destptr (I64Const [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store)
		v.AuxInt = int64ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store, types.TypeMem)
		v1.AddArg3(destptr, v0, mem)
		v.AddArg3(destptr, v0, v1)
		return true
	}
	// match: (Zero [24] destptr mem)
	// result: (I64Store [16] destptr (I64Const [0]) (I64Store [8] destptr (I64Const [0]) (I64Store destptr (I64Const [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 24 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store)
		v.AuxInt = int64ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpWasmI64Store, types.TypeMem)
		v2.AddArg3(destptr, v0, mem)
		v1.AddArg3(destptr, v0, v2)
		v.AddArg3(destptr, v0, v1)
		return true
	}
	// match: (Zero [32] destptr mem)
	// result: (I64Store [24] destptr (I64Const [0]) (I64Store [16] destptr (I64Const [0]) (I64Store [8] destptr (I64Const [0]) (I64Store destptr (I64Const [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpWasmI64Store)
		v.AuxInt = int64ToAuxInt(24)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(16)
		v2 := b.NewValue0(v.Pos, OpWasmI64Store, types.TypeMem)
		v2.AuxInt = int64ToAuxInt(8)
		v3 := b.NewValue0(v.Pos, OpWasmI64Store, types.TypeMem)
		v3.AddArg3(destptr, v0, mem)
		v2.AddArg3(destptr, v0, v3)
		v1.AddArg3(destptr, v0, v2)
		v.AddArg3(destptr, v0, v1)
		return true
	}
	// match: (Zero [s] destptr mem)
	// result: (LoweredZero [s] destptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		v.reset(OpWasmLoweredZero)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(destptr, mem)
		return true
	}
}
func rewriteValueWasm_OpZeroExt16to32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ZeroExt16to32 x:(I64Load16U _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load16U {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ZeroExt16to32 x)
	// result: (I64And x (I64Const [0xffff]))
	for {
		x := v_0
		v.reset(OpWasmI64And)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0xffff)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpZeroExt16to64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ZeroExt16to64 x:(I64Load16U _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load16U {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ZeroExt16to64 x)
	// result: (I64And x (I64Const [0xffff]))
	for {
		x := v_0
		v.reset(OpWasmI64And)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0xffff)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpZeroExt32to64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ZeroExt32to64 x:(I64Load32U _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load32U {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ZeroExt32to64 x)
	// result: (I64And x (I64Const [0xffffffff]))
	for {
		x := v_0
		v.reset(OpWasmI64And)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0xffffffff)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpZeroExt8to16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ZeroExt8to16 x:(I64Load8U _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load8U {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ZeroExt8to16 x)
	// result: (I64And x (I64Const [0xff]))
	for {
		x := v_0
		v.reset(OpWasmI64And)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0xff)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpZeroExt8to32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ZeroExt8to32 x:(I64Load8U _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load8U {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ZeroExt8to32 x)
	// result: (I64And x (I64Const [0xff]))
	for {
		x := v_0
		v.reset(OpWasmI64And)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0xff)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpZeroExt8to64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ZeroExt8to64 x:(I64Load8U _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpWasmI64Load8U {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ZeroExt8to64 x)
	// result: (I64And x (I64Const [0xff]))
	for {
		x := v_0
		v.reset(OpWasmI64And)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0xff)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteBlockWasm(b *Block) bool {
	return false
}
```