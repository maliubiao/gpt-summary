Response:
The user wants a summary of the functionality of the provided Go code snippet. This is the last part of a four-part code listing. The code is located in `go/src/cmd/compile/internal/ssa/rewriteWasm.go`.

Based on the function names and operations, this code seems to be part of the SSA (Static Single Assignment) rewrite rules specifically for the WASM (WebAssembly) architecture in the Go compiler. It defines a set of functions, each responsible for rewriting a specific SSA operation (`Op`). The goal of these rewrites is likely to optimize or transform the intermediate representation of the Go code into a form that is more suitable for WASM.

Here's a breakdown of the functionality by inspecting the code:

1. **`rewriteValueWasm_OpWasmI64Shr`**: This function seems to optimize right bit shifts (`>>`) for 64-bit integers when the shift amount is a constant. It directly calculates the shifted value and replaces the original operation with a constant.

2. **`rewriteValueWasm_OpWasmI64Store`**, **`rewriteValueWasm_OpWasmI64Store16`**, **`rewriteValueWasm_OpWasmI64Store32`**, **`rewriteValueWasm_OpWasmI64Store8`**: These functions deal with memory store operations for different sizes (8, 16, 32, and 64 bits). They appear to optimize store operations when the memory address is calculated by adding a constant offset to a base pointer. If the combined offset fits within a 32-bit unsigned integer, it merges the two offsets into a single offset in the store instruction.

3. **`rewriteValueWasm_OpWasmI64Xor`**: This function optimizes bitwise XOR operations (`^`) for 64-bit integers. It handles cases where both operands are constants by directly calculating the result. It also reorders the operands so that if one is a constant, it becomes the second operand.

4. **`rewriteValueWasm_OpZero`**: This function seems to handle the initialization of memory to zero. It provides specialized implementations for setting small blocks of memory to zero using store instructions of different sizes. For larger blocks, it might fall back to a more general `LoweredZero` operation.

5. **`rewriteValueWasm_OpZeroExt16to32`**, **`rewriteValueWasm_OpZeroExt16to64`**, **`rewriteValueWasm_OpZeroExt32to64`**, **`rewriteValueWasm_OpZeroExt8to16`**, **`rewriteValueWasm_OpZeroExt8to32`**, **`rewriteValueWasm_OpZeroExt8to64`**: These functions handle zero extension operations. They optimize cases where the zero extension is immediately followed by a load of the same size (e.g., zero-extending a 16-bit value loaded with `I64Load16U`). In other cases, they use a bitwise AND operation with a mask to achieve the zero extension.

6. **`rewriteBlockWasm`**: This function currently returns `false`, suggesting it might be a placeholder or that there are no block-level rewrite rules defined in this specific part of the code.

**Overall Functionality:** This part of `rewriteWasm.go` focuses on value-level rewrites for 64-bit integer operations and memory operations within the WASM backend of the Go compiler. It aims to optimize common patterns like constant arithmetic, address calculations for memory access, and zero initialization.
这是 `go/src/cmd/compile/internal/ssa/rewriteWasm.go` 文件的一部分，它专门针对 WASM (WebAssembly) 架构进行 SSA (Static Single Assignment) 重写规则的定义。

**归纳其功能:**

这部分代码定义了一系列针对 WASM 平台上 64 位整数运算和内存操作的 SSA 重写规则。其主要目的是在编译过程中，对中间代码表示（SSA）进行优化和转换，使其更符合 WASM 的特性，从而提高生成代码的效率。

具体来说，这部分代码涵盖了以下功能：

*   **常量优化:**  针对 64 位整数的右移 (`OpWasmI64Shr`) 和异或 (`OpWasmI64Xor`) 操作，如果操作数是常量，则直接计算结果，将操作替换为常量。
*   **内存访问优化:** 针对不同大小 (8/16/32/64 位) 的内存存储操作 (`OpWasmI64Store`, `OpWasmI64Store8`, `OpWasmI64Store16`, `OpWasmI64Store32`)，如果存储地址是通过一个基址指针加上一个常量偏移量计算得到的，并且合并后的偏移量在 32 位无符号整数范围内，则将偏移量合并到存储指令中。
*   **零值初始化优化:** 针对将内存区域置零的操作 (`OpZero`)，提供了针对不同大小内存块的优化策略，包括使用不同大小的存储指令组合来高效地完成零值初始化。对于较大的内存块，可能会使用一个 `LoweredZero` 的操作，这可能在其他地方有更底层的实现。
*   **零扩展优化:** 针对将较小的整数类型零扩展到 64 位整数的操作 (`OpZeroExt8to64`, `OpZeroExt16to64`, `OpZeroExt32to64` 以及它们到 32 位和 16 位的变体)，如果零扩展的操作数本身就是一个对应大小的无符号加载操作 (`OpWasmI64Load8U`, `OpWasmI64Load16U`, `OpWasmI64Load32U`)，则可以直接使用加载操作的结果，避免额外的零扩展操作。否则，会使用与操作 (`OpWasmI64And`) 和一个合适的掩码来实现零扩展。
*   **块级重写（当前为空）:** `rewriteBlockWasm` 函数目前返回 `false`，表示这部分代码没有定义针对 WASM 的块级 SSA 重写规则。

**Go 代码示例说明:**

**假设输入:** 一段 Go 代码中包含一个 64 位整数的右移操作，且移动的位数是常量。

```go
package main

func main() {
	var x int64 = 128
	y := x >> 3
	println(y)
}
```

**SSA 转换（简化）：**  在编译过程中，上述 Go 代码可能会被转换为类似的 SSA 表示：

```
v1 = ConstInt64 <int64> 128
v2 = ConstInt <int> 3
v3 = Rsh64 <int64> v1 v2
```

**`rewriteValueWasm_OpWasmI64Shr` 的推理和输出：**

*   **匹配:** `rewriteValueWasm_OpWasmI64Shr` 函数会匹配到 `OpWasmI64Shr` 类型的操作，并且检查其第二个参数是否为常量。
*   **假设输入:**  `v` 代表 `v3`，`v_0` 代表 `v1`，`v_1` 代表 `v2`。 `v_0.Op` 是 `OpWasmI64Const`，`v_0.AuxInt` 是 128。 `v_1.Op` 是 `OpWasmI64Const`，`v_1.AuxInt` 是 3。
*   **计算:** 函数会计算 `uint64(128) >> uint64(3)` 的结果，即 16。
*   **重写:**  原始的右移操作 `v3` 会被重写为一个常量操作。

**重写后的 SSA (简化):**

```
v1 = ConstInt64 <int64> 128
v2 = ConstInt <int> 3
v3 = ConstInt64 <int64> 16
```

**WASM 代码生成：** 最终，这个常量值 `16` 会直接被用于生成 WASM 代码，避免了运行时的移位计算。

**`rewriteValueWasm_OpZero` 的推理和输出：**

**假设输入:** 一段 Go 代码中初始化一个小的数组。

```go
package main

func main() {
	var arr [3]int64
	println(arr[0])
}
```

**SSA 转换（简化）：** 初始化数组可能会涉及到 `OpZero` 操作。

```
v1 = ... // 指向数组起始地址的指针
v2 = Mem // 当前的内存状态
v3 = Zero <mem> [24] v1 v2 // 假设 int64 占 8 字节，3 个元素共 24 字节
```

**`rewriteValueWasm_OpZero` 的推理和输出：**

*   **匹配:** `rewriteValueWasm_OpZero` 函数会匹配到 `OpZero` 类型的操作，并根据其 `AuxInt` (要置零的字节数) 的值进行不同的优化。
*   **假设输入:** `v` 代表 `v3`， `v.AuxInt` 是 24， `v_0` 代表 `v1`， `v_1` 代表 `v2`。
*   **匹配规则:** 由于 `v.AuxInt` 是 24，会匹配到 `// match: (Zero [24] destptr mem)` 对应的规则。
*   **重写:**  `OpZero` 操作会被展开为多个 `OpWasmI64Store` 操作，分别存储 0 值到数组的不同位置。

**重写后的 SSA (简化):**

```
v1 = ...
v2 = Mem
v3 = I64Store <mem> [16] v1 (ConstInt64 <int64> 0) v2
v4 = I64Store <mem> [8] v1 (ConstInt64 <int64> 0) v3
v5 = I64Store <mem> [0] v1 (ConstInt64 <int64> 0) v4
```

**WASM 代码生成：** 最终会生成多个 WASM 的内存存储指令来完成数组的零值初始化。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是 Go 编译器内部 SSA 优化的一部分。Go 编译器的命令行参数会影响整个编译流程，间接地影响到 SSA 的生成和优化过程。例如，`-gcflags` 参数可以传递给 Go 编译器底层的 GC 编译器，可能会影响到 WASM 目标的编译。

**使用者易犯错的点:**

作为编译器内部的实现，普通 Go 开发者不会直接接触到这部分代码。开发者在使用 Go 编写针对 WASM 的代码时，需要注意 WASM 的一些特性和限制，例如：

*   **内存模型:** WASM 的内存是线性内存，需要注意内存访问的边界和安全性。
*   **类型系统:** WASM 有自己的类型系统，Go 的类型需要在编译时映射到 WASM 的类型。
*   **性能考量:** 了解 WASM 的执行特性，避免编写在 WASM 上性能较差的代码。

**总结:**

这是 `rewriteWasm.go` 文件中处理 64 位整数和内存操作优化的一个重要部分，通过定义针对特定 WASM 指令的重写规则，提升了 Go 代码编译到 WASM 后的性能和效率。它利用了 SSA 的特性，在中间代码层面进行优化，对最终生成的 WASM 代码质量有显著影响。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteWasm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
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