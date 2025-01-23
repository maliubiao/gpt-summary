Response:
The user wants a summary of the functionality of the provided Go code snippet. This code is part of the Go compiler for the LOONG64 architecture and deals with rewriting SSA (Static Single Assignment) values. Each function `rewriteValueLOONG64_Op...` seems to be responsible for transforming a specific Go operation (`Op`) into a sequence of LOONG64 assembly instructions.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Task:** The code is within the `rewriteLOONG64.go` file, indicating architecture-specific SSA rewriting. The functions are named `rewriteValueLOONG64_Op...`, clearly showing they handle rewriting specific `Op` (operations) in the SSA representation for the LOONG64 architecture.

2. **Analyze Individual Functions:**
   - **`rewriteValueLOONG64_OpLoad`:** This function has several `match:` and `result:` blocks. Each block transforms a generic `Load` operation into a specific LOONG64 load instruction based on the data type being loaded (boolean, 8-bit int, 16-bit int, 32-bit int, 64-bit int, pointer, 32-bit float, 64-bit float). This suggests it's optimizing memory loads based on the type.

   - **`rewriteValueLOONG64_OpLocalAddr`:**  This function handles the `LocalAddr` operation, which gets the address of a local variable. It seems to differentiate between local variables that might contain pointers and those that don't, using different LOONG64 instructions accordingly (`MOVVaddr` with or without `SPanchored`).

   - **`rewriteValueLOONG64_OpLsh...` (Left Shift):**  There are multiple functions for left shift operations (`Lsh`) with different operand sizes (8, 16, 32, 64) and shift amounts (8, 16, 32, 64). The `result:` parts consistently use `MASKEQZ` and `SLLV`, suggesting a pattern for handling left shifts, possibly masking out bits based on the shift amount to avoid undefined behavior for large shifts.

   - **`rewriteValueLOONG64_OpMod...` (Modulo):**  These functions handle the modulo operation (`Mod`) for different integer sizes (8, 16, 32, 64), both signed and unsigned. The `result:` parts use `REMV` (remainder) and type conversions (`SignExt`, `ZeroExt`) to ensure correct behavior.

   - **`rewriteValueLOONG64_OpMove`:** This is more complex. It handles copying memory. It has specific optimized cases for small sizes (1 to 16 bytes) using individual store/load instructions. For larger sizes, it uses `DUFFCOPY` (likely an optimized Duff's device implementation for copying) or `LoweredMove` for very large copies, potentially using a loop.

   - **`rewriteValueLOONG64_OpNeq...` (Not Equal):** These functions handle the "not equal" comparison (`Neq`) for different data types (8, 16, 32, 64, 32F, 64F, pointer). They generally use `SGTU` (Set Greater Than Unsigned) after an `XOR`, which is a common way to check for inequality. For floats, they use `CMPEQF`/`CMPEQD` and `FPFlagFalse`.

   - **`rewriteValueLOONG64_OpNot`:** This handles the logical NOT operation, simply flipping the bits using `XORconst [1]`.

   - **`rewriteValueLOONG64_OpOffPtr`:** This function calculates an offset from a pointer. If the pointer is the stack pointer (`SP`), it uses `MOVVaddr` with an immediate offset. Otherwise, it uses `ADDVconst`.

   - **`rewriteValueLOONG64_OpPanicBounds`:** This function seems related to handling out-of-bounds access panics. It uses `LoweredPanicBoundsA`, `LoweredPanicBoundsB`, and `LoweredPanicBoundsC`, suggesting different ways to trigger the panic based on some ABI (Application Binary Interface) convention.

3. **Identify Common Themes:**
   - **Type-Specific Optimization:**  The code heavily relies on the data types of the operands to choose the most efficient LOONG64 instruction.
   - **SSA Rewriting:** The core function is to transform high-level SSA operations into low-level, architecture-specific instructions.
   - **Performance:** The optimizations aim to improve the performance of the generated LOONG64 code.
   - **Handling Edge Cases:**  The left shift operations' masking and the `Move` operation's handling of different sizes suggest attention to detail and correctness.

4. **Synthesize the Summary:** Combine the observations into a concise summary, focusing on the main purpose and the common patterns observed. Mentioning the architecture (LOONG64), the stage (SSA rewriting), and the goal (code generation and optimization) is important.

5. **Review and Refine:** Ensure the summary is accurate, comprehensive, and easy to understand. Make sure it addresses the user's request for a functional overview.
这是路径为go/src/cmd/compile/internal/ssa/rewriteLOONG64.go的go语言实现的一部分，它的功能是针对LOONG64架构，对SSA（Static Single Assignment）中间表示中的特定操作（Op）进行重写，将其转化为更底层的、更接近LOONG64硬件指令的操作序列。

具体来说，这部分代码主要负责将一些通用的操作，例如内存加载（Load）、获取本地变量地址（LocalAddr）、位移操作（Lsh）、取模运算（Mod）、内存拷贝（Move）、比较操作（Neq）、逻辑非（Not）、指针偏移（OffPtr）以及边界检查Panic（PanicBounds）等，根据其操作数的类型和一些特定条件，转换为相应的LOONG64指令。

**以下是对代码中涉及的一些功能的具体说明和代码示例：**

**1. 内存加载 (Load):**

这段代码将通用的 `Load` 操作根据加载的数据类型（如布尔、不同大小的整数、浮点数）转换为特定的 LOONG64 加载指令，例如 `MOVBUload` (加载无符号字节)、`MOVBload` (加载有符号字节)、`MOVHUload`、`MOVHload`、`MOVWUload`、`MOVWload`、`MOVVload` (加载字)、`MOVFload` (加载单精度浮点)、`MOVDload` (加载双精度浮点)。

```go
// 假设 SSA 中有以下 Load 操作：
// v = Load <int32> ptr mem

// 该代码会将其重写为：
// v = OpLOONG64MOVWload ptr mem
```

**2. 获取本地变量地址 (LocalAddr):**

`LocalAddr` 操作用于获取局部变量的地址。代码会根据局部变量的类型是否包含指针来选择不同的 LOONG64 指令。如果包含指针，则使用 `MOVVaddr` 配合 `SPanchored`，否则直接使用 `MOVVaddr`。

```go
// 假设 SSA 中有以下 LocalAddr 操作：
// v = LocalAddr <*int> {sym:"local_var"} base mem

// 如果 *int 类型包含指针，则会被重写为：
// v = OpLOONG64MOVVaddr {sym:"local_var"} (SPanchored base mem)

// 如果 *int 类型不包含指针，则会被重写为：
// v = OpLOONG64MOVVaddr {sym:"local_var"} base
```

**3. 位移操作 (Lsh):**

代码针对不同大小的整数进行左移操作 (`Lsh`) 的重写。它使用 `MASKEQZ` 和 `SLLV` 指令，并且会根据位移量的大小进行处理，避免移位量过大导致的未定义行为。

```go
// 假设 SSA 中有以下 Lsh16x8 操作：
// v = Lsh16x8 <int32> x y

// 会被重写为：
// v = OpLOONG64MASKEQZ (SLLV <int32> x (ZeroExt8to64 y)) (SGTU (MOVVconst <uint64> [64]) (ZeroExt8to64 y))
```

这里 `MASKEQZ` 用于根据条件掩码结果，`SLLV` 是逻辑左移指令，`ZeroExt8to64` 是零扩展操作，`SGTU` 是无符号大于比较。这段代码确保了只有当移位量小于 64 时才进行移位操作。

**4. 取模运算 (Mod):**

代码将通用的取模运算 (`Mod`) 根据操作数的类型转换为 LOONG64 的 `REMV` (有符号取余) 或 `REMVU` (无符号取余) 指令，并进行必要的符号扩展或零扩展。

```go
// 假设 SSA 中有以下 Mod16 操作：
// v = Mod16 x y

// 会被重写为：
// v = OpLOONG64REMV (SignExt16to64 x) (SignExt16to64 y)
```

**5. 内存拷贝 (Move):**

`Move` 操作用于拷贝内存。代码针对不同大小的拷贝进行了优化。对于小尺寸的拷贝（小于等于 16 字节），会展开为一系列的 `MOVBstore`、`MOVHstore`、`MOVWstore` 和 `MOVVstore` 指令。对于较大的拷贝，会使用 `DUFFCOPY` (Duff's Device 的实现) 或 `LoweredMove`。

```go
// 假设 SSA 中有以下 Move 操作，拷贝 4 字节：
// v = Move [4] dst src mem

// 会被重写为：
// v = OpLOONG64MOVWstore dst (MOVWUload src mem) mem
```

**6. 不等于比较 (Neq):**

代码将不等于比较操作 (`Neq`) 转换为 LOONG64 的比较指令。对于整数和指针类型，通常使用 `XOR` 和 `SGTU` 来实现。对于浮点数，则使用浮点比较指令 `CMPEQF` 或 `CMPEQD`，并结合 `FPFlagFalse` 来判断结果。

```go
// 假设 SSA 中有以下 Neq32 操作：
// v = Neq32 x y

// 会被重写为：
// v = OpLOONG64SGTU (XOR (ZeroExt32to64 x) (ZeroExt32to64 y)) (MOVVconst [0])
```

**7. 逻辑非 (Not):**

逻辑非操作 `Not` 被简单地转换为与常量 1 进行异或操作 (`XORconst [1]`)。

```go
// 假设 SSA 中有以下 Not 操作：
// v = Not x

// 会被重写为：
// v = OpLOONG64XORconst [1] x
```

**8. 指针偏移 (OffPtr):**

`OffPtr` 操作计算指针的偏移地址。如果基址是指针寄存器 SP (栈指针)，则使用带有立即数的地址加载指令 `MOVVaddr`，否则使用加法指令 `ADDVconst`。

```go
// 假设 SSA 中有以下 OffPtr 操作：
// v = OffPtr [8] ptr

// 如果 ptr 是 SP，则会被重写为：
// v = OpLOONG64MOVVaddr [8] ptr

// 否则会被重写为：
// v = OpLOONG64ADDVconst [8] ptr
```

**9. 边界检查 Panic (PanicBounds):**

`PanicBounds` 操作用于在发生数组越界等错误时触发 panic。代码根据 `boundsABI` 的返回值选择不同的底层 panic 实现 (`LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC`)，这可能与不同的调用约定或 panic 处理机制有关。

**归纳一下它的功能 (第 6 部分):**

这部分代码主要负责 **将 SSA 中的内存加载、本地地址获取、位移、取模运算以及内存拷贝操作，针对 LOONG64 架构进行指令级别的细化和优化**。它根据操作数的类型和大小，选择最合适的 LOONG64 指令序列来实现这些通用操作，旨在生成更高效的机器码。 此外，它还处理了不等于比较、逻辑非、指针偏移和边界检查 panic 等操作的底层转换。

作为第 6 部分，它可以被认为是整个 SSA 重写流程中的一个关键阶段，专注于将一些基础但重要的操作转换成目标架构的指令，为后续更复杂的优化和代码生成奠定基础。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteLOONG64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```go
if !(t.IsBoolean()) {
			break
		}
		v.reset(OpLOONG64MOVBUload)
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
		v.reset(OpLOONG64MOVBload)
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
		v.reset(OpLOONG64MOVBUload)
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
		v.reset(OpLOONG64MOVHload)
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
		v.reset(OpLOONG64MOVHUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) && t.IsSigned())
	// result: (MOVWload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpLOONG64MOVWload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) && !t.IsSigned())
	// result: (MOVWUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpLOONG64MOVWUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (MOVVload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpLOONG64MOVVload)
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
		v.reset(OpLOONG64MOVFload)
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
		v.reset(OpLOONG64MOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVVaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpLOONG64MOVVaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVVaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpLOONG64MOVVaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x64 <t> x y)
	// result: (MASKEQZ (SLLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x32 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x64 <t> x y)
	// result: (MASKEQZ (SLLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x16 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x32 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x64 <t> x y)
	// result: (MASKEQZ (SLLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x8 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x64 <t> x y)
	// result: (MASKEQZ (SLLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 <t> x y)
	// result: (MASKEQZ (SLLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (REMV (SignExt16to64 x) (SignExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (REMVU (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMVU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32 x y)
	// result: (REMV (SignExt32to64 x) (SignExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32u x y)
	// result: (REMVU (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMVU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod64 x y)
	// result: (REMV x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMV)
		v.AddArg2(x, y)
		return true
	}
}
func rewriteValueLOONG64_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (REMV (SignExt8to64 x) (SignExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (REMVU (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64REMVU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpMove(v *Value) bool {
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
		v.reset(OpLOONG64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVBUload, typ.UInt8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVHstore dst (MOVHUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVHUload, typ.UInt16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBUload [2] src mem) (MOVHstore dst (MOVHUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVHUload, typ.UInt16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVWstore dst (MOVWUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [5] dst src mem)
	// result: (MOVBstore [4] dst (MOVBUload [4] src mem) (MOVWstore dst (MOVWUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [6] dst src mem)
	// result: (MOVHstore [4] dst (MOVHUload [4] src mem) (MOVWstore dst (MOVWUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [7] dst src mem)
	// result: (MOVWstore [3] dst (MOVWUload [3] src mem) (MOVWstore dst (MOVWUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] dst src mem)
	// result: (MOVVstore dst (MOVVload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [9] dst src mem)
	// result: (MOVBstore [8] dst (MOVBUload [8] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 9 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [10] dst src mem)
	// result: (MOVHstore [8] dst (MOVHUload [8] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 10 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [11] dst src mem)
	// result: (MOVWstore [7] dst (MOVWload [7] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 11 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVWload, typ.Int32)
		v0.AuxInt = int32ToAuxInt(7)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [12] dst src mem)
	// result: (MOVWstore [8] dst (MOVWUload [8] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVWUload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [13] dst src mem)
	// result: (MOVVstore [5] dst (MOVVload [5] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 13 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(5)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(5)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [14] dst src mem)
	// result: (MOVVstore [6] dst (MOVVload [6] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 14 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(6)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [15] dst src mem)
	// result: (MOVVstore [7] dst (MOVVload [7] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 15 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(7)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [16] dst src mem)
	// result: (MOVVstore [8] dst (MOVVload [8] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%8 != 0 && s > 16
	// result: (Move [s%8] (OffPtr <dst.Type> dst [s-s%8]) (OffPtr <src.Type> src [s-s%8]) (Move [s-s%8] dst src mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%8 != 0 && s > 16) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(s % 8)
		v0 := b.NewValue0(v.Pos, OpOffPtr, dst.Type)
		v0.AuxInt = int64ToAuxInt(s - s%8)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpOffPtr, src.Type)
		v1.AuxInt = int64ToAuxInt(s - s%8)
		v1.AddArg(src)
		v2 := b.NewValue0(v.Pos, OpMove, types.TypeMem)
		v2.AuxInt = int64ToAuxInt(s - s%8)
		v2.AddArg3(dst, src, mem)
		v.AddArg3(v0, v1, v2)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%8 == 0 && s > 16 && s <= 8*128 && !config.noDuffDevice && logLargeCopy(v, s)
	// result: (DUFFCOPY [16 * (128 - s/8)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%8 == 0 && s > 16 && s <= 8*128 && !config.noDuffDevice && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpLOONG64DUFFCOPY)
		v.AuxInt = int64ToAuxInt(16 * (128 - s/8))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%8 == 0 && s > 1024 && logLargeCopy(v, s)
	// result: (LoweredMove dst src (ADDVconst <src.Type> src [s-8]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%8 == 0 && s > 1024 && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpLOONG64LoweredMove)
		v0 := b.NewValue0(v.Pos, OpLOONG64ADDVconst, src.Type)
		v0.AuxInt = int64ToAuxInt(s - 8)
		v0.AddArg(src)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (SGTU (XOR (ZeroExt16to32 x) (ZeroExt16to64 y)) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32 x y)
	// result: (SGTU (XOR (ZeroExt32to64 x) (ZeroExt32to64 y)) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32F x y)
	// result: (FPFlagFalse (CMPEQF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagFalse)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPEQF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq64 x y)
	// result: (SGTU (XOR x y) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64F x y)
	// result: (FPFlagFalse (CMPEQD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagFalse)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPEQD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (SGTU (XOR (ZeroExt8to64 x) (ZeroExt8to64 y)) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqPtr x y)
	// result: (SGTU (XOR x y) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not x)
	// result: (XORconst [1] x)
	for {
		x := v_0
		v.reset(OpLOONG64XORconst)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueLOONG64_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr [off] ptr:(SP))
	// result: (MOVVaddr [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if ptr.Op != OpSP {
			break
		}
		v.reset(OpLOONG64MOVVaddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// result: (ADDVconst [off] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(off)
		v.AddArg(ptr)
		return true
	}
}
func rewriteValueLOONG64_OpPanicBounds(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 0
	// result: (LoweredPanicBoundsA [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 0) {
			break
		}
		v.reset(OpLOONG64LoweredPanicBoundsA)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 1
	// result: (LoweredPanicBoundsB [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 1) {
			break
		}
		v.reset(OpLOONG64LoweredPanicBoundsB)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 2
	// result: (LoweredPanicBoundsC [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 2) {
			break
		}
		v.reset(OpLOONG64LoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_Op
```