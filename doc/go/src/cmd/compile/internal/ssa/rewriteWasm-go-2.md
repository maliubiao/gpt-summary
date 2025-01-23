Response:
The user wants a summary of the functionality of the provided Go code snippet. This code is part of the Go compiler for the WASM architecture, specifically focusing on rewriting operations at the SSA level.

The code defines several functions named `rewriteValueWasm_Op...`. Each function takes a `*Value` as input, which represents an operation in the SSA form. These functions attempt to match specific patterns of SSA operations and replace them with potentially more efficient or WASM-native equivalents.

The operations covered in this snippet seem to be related to:
- **Right shift operations** (`Rsh`, `RshU`) with different operand sizes.
- **Sign extension operations** (`SignExt`) with different input and output sizes.
- **Slicemask operation**.
- **Store operation**.
- **WASM-specific arithmetic and logical operations** (`F64Add`, `F64Mul`, `I64Add`, `I64And`, `I64Eq`, `I64Eqz`, `I64LeU`, `I64Load`, `I64Mul`, `I64Ne`, `I64Or`, `I64Shl`, `I64ShrS`, `I64ShrU`).

The core functionality is to perform peephole optimizations and transformations specific to the WASM target during the SSA rewriting phase of the Go compilation process. It looks for opportunities to directly use WASM instructions or simplify Go's generic operations into more specific WASM idioms.
这段代码是Go语言编译器针对WASM架构进行优化的一个部分，专注于将Go语言的通用操作（在SSA中间表示形式下）转换为更底层的、更适合WASM执行的操作。它定义了一系列以 `rewriteValueWasm_Op` 开头的函数，每个函数负责处理一种特定的Go语言操作符。

**归纳其功能如下:**

这段代码的主要功能是在Go语言编译到WASM目标平台的过程中，对程序进行中间表示（SSA）级别的重写和优化。它针对特定的Go语言操作符，尝试将其转化为更符合WASM特性的操作，从而提高WASM代码的执行效率。

具体来说，这段代码涵盖了以下几类操作的转换：

1. **右移操作 (`OpRsh...`)**:  将Go语言的右移操作，包括有符号和无符号的，以及不同数据类型之间的右移，转换为WASM的右移操作。这其中涉及到类型转换，例如将较小的类型零扩展或符号扩展到64位后再进行右移。

2. **符号扩展操作 (`OpSignExt...`)**:  将Go语言的符号扩展操作，例如将 `int8` 扩展到 `int16` 或 `int64`，尝试直接映射到WASM的符号扩展指令 (`I64Extend...`)。如果编译配置不允许直接使用WASM的符号扩展指令，则会使用移位和算术右移的组合来实现。

3. **Slicemask 操作 (`OpSlicemask`)**:  将Go语言的 `slicemask` 操作转换为一系列WASM的算术和移位操作。

4. **存储操作 (`OpStore`)**: 根据存储的数据类型大小，将Go语言的通用存储操作转换为WASM特定的存储指令，例如 `F64Store`, `F32Store`, `I64Store`, `I64Store32`, `I64Store16`, `I64Store8`。

5. **WASM特定操作的优化 (`OpWasmF64Add`, `OpWasmI64Add`, 等)**:  针对已经是WASM操作的节点，进行进一步的常量折叠和模式匹配优化。例如，将两个常量相加直接替换为它们的和的常量。

**代码功能举例说明 (以 `OpRsh64x16` 为例):**

假设有以下Go代码：

```go
package main

func main() {
	var x int64 = 100
	var y int16 = 2
	z := x >> y
	println(z)
}
```

在编译到WASM时，SSA阶段可能会产生一个 `OpRsh64x16` 的节点来表示 `x >> y` 这个操作。 `rewriteValueWasm_OpRsh64x16` 函数的功能就是将这个操作转换为更适合WASM执行的形式。

**假设的输入 SSA：**

一个 `OpRsh64x16` 类型的 `Value`，其 `Args` 包含两个 `Value`：
- `v_0`: 表示 `x` 的值的 `Value` (类型为 `int64`)
- `v_1`: 表示 `y` 的值的 `Value` (类型为 `int16`)

**`rewriteValueWasm_OpRsh64x16` 函数的处理：**

```go
func rewriteValueWasm_OpRsh64x16(v *Value) bool {
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
```

这个函数会匹配到 `OpRsh64x16` 操作，然后将其重写为 `OpRsh64x64` 操作，并将第二个参数（`int16` 类型的 `y`）通过 `OpZeroExt16to64` 零扩展到 `uint64` 类型。

**假设的输出 SSA：**

原来的 `OpRsh64x16` 的 `Value` 被修改为 `OpRsh64x64` 类型，其 `Args` 变为：
- `v_0`: 表示 `x` 的值的 `Value`
- 一个新的 `OpZeroExt16to64` 类型的 `Value`，其 `Arg` 指向表示 `y` 的值的 `Value`。

**涉及代码推理的例子 (以 `OpRsh64x64` 为例):**

假设有以下Go代码：

```go
package main

func main() {
	var x int64 = 100
	var y int64 = 2
	z := x >> y
	println(z)
}
```

**假设的输入 SSA：**

一个 `OpRsh64x64` 类型的 `Value`，其 `Args` 包含两个 `Value`：
- `v_0`: 表示 `x` 的值的 `Value`
- `v_1`: 表示 `y` 的值的 `Value`

**`rewriteValueWasm_OpRsh64x64` 函数的处理 (部分):**

```go
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
    // ... 其他匹配 ...
}
```

如果 `shiftIsBounded(v)` 返回 `true` (意味着编译器可以确定移位量在有效范围内)，则 `OpRsh64x64` 会被直接替换为 WASM 的带符号右移指令 `OpWasmI64ShrS`。

**假设的输出 SSA (如果 `shiftIsBounded` 为 true):**

原来的 `OpRsh64x64` 的 `Value` 被修改为 `OpWasmI64ShrS` 类型，其 `Args` 不变。

**命令行参数处理：**

这段代码本身不直接处理命令行参数。它是在Go编译器内部的SSA重写阶段运行的。编译器的命令行参数会影响整个编译流程，可能会间接地影响到这里代码的执行，例如 `-gcflags` 可以传递参数来控制编译器的行为，但这段代码并不直接解析这些参数。

**使用者易犯错的点：**

由于这是编译器内部的代码，普通Go语言开发者不会直接与这段代码交互，因此不存在使用者易犯错的点。这段代码的编写者（编译器开发者）需要非常熟悉Go语言的SSA表示和WASM的指令集，以确保转换的正确性和优化效果。

总而言之，这段代码是Go语言编译器为了更好地支持WASM目标平台而进行底层优化的关键部分，它通过模式匹配和转换，将Go语言的高级概念映射到WASM的低级指令，从而提升最终WASM代码的性能。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteWasm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能
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
```