Response: The user wants a summary of the functionality of the provided Go code snippet. This code seems to be part of the compiler's intermediate representation (SSA) rewriting rules for the LOONG64 architecture. It defines functions that try to simplify or transform certain SSA operations into more efficient or architecture-specific instructions.

Here's a breakdown of the thinking process:

1. **Identify the file and its purpose:** The file path `go/src/cmd/compile/internal/ssa/rewriteLOONG64.go` strongly suggests this file contains SSA rewriting rules specific to the LOONG64 architecture within the Go compiler.

2. **Analyze the function signatures:**  The functions have names like `rewriteValueLOONG64_OpPopCount16`, `rewriteValueLOONG64_OpRotateLeft32`, and `rewriteBlockLOONG64`. This naming convention is a strong indicator that these functions are responsible for rewriting specific SSA value operations (`Op...`) or block types for the LOONG64 architecture.

3. **Examine individual rewrite functions:**
    * **`rewriteValueLOONG64_OpPopCount*`:** These functions seem to be implementing the "population count" (number of set bits) operation for different integer sizes (16, 32, 64 bits). They achieve this by converting the integer to a floating-point representation, using a vector population count instruction (`VPCNT*`), and then converting it back. This looks like a specific optimization for LOONG64.
    * **`rewriteValueLOONG64_OpRotateLeft*`:** These functions implement left bit rotation. They have special cases for constant rotation amounts, using shifts and ORs. For variable rotation amounts, they use the `ROTR` (rotate right) instruction with a negated shift amount.
    * **`rewriteValueLOONG64_OpRsh*Ux*` and `rewriteValueLOONG64_OpRsh*x*`:** These handle right shift operations (unsigned and signed) for various operand sizes. They introduce `MASKEQZ` operations to handle cases where the shift amount is greater than or equal to the bit size, ensuring a zero result for unsigned shifts and sign extension for signed shifts.
    * **`rewriteValueLOONG64_OpSelect0` and `rewriteValueLOONG64_OpSelect1`:** These functions likely deal with selecting the first or second result from operations that produce multiple results (like division with quotient and remainder, or arithmetic operations with carry/borrow). They map Go's generic multi-value returns to specific LOONG64 instructions.
    * **`rewriteValueLOONG64_OpSelectN`:** This function has a specific case for optimizing `runtime.memmove` calls into `OpMove` when certain conditions are met.
    * **`rewriteValueLOONG64_OpSlicemask`:** This appears to be implementing a way to get a mask based on a slice length, often used in bounds checking.
    * **`rewriteValueLOONG64_OpStore`:** This function translates Go's generic `Store` operation into specific LOONG64 store instructions based on the size and type of the value being stored (e.g., `MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVVstore`, `MOVFstore`, `MOVDstore`).
    * **`rewriteValueLOONG64_OpZero`:** This function optimizes zeroing out memory. It has specific patterns for small sizes and uses `DUFFZERO` or `LoweredZero` for larger blocks, which are likely optimized library functions or compiler intrinsics for efficient memory zeroing.
    * **`rewriteBlockLOONG64`:** This function rewrites control flow blocks. It looks for opportunities to replace generic `EQ` and `NE` blocks with more specific LOONG64 conditional branch instructions (like `BEQ`, `BNE`, `BGE`, `BGEU`, `BLT`, `BLTU`, `FPF`, `FPT`, `GEZ`, `GTZ`, `LEZ`, `LTZ`). It also optimizes conditional branches based on constant values.

4. **Identify the overall goal:** The overarching purpose of these functions is to lower the Go SSA representation to the specific instruction set and idioms of the LOONG64 architecture, aiming for better performance. This involves recognizing common Go operations and replacing them with their most efficient LOONG64 equivalents.

5. **Consider the "part 4 of 4" aspect:** This signifies that this is the final part of a larger set of rewriting rules. Therefore, it should cover the remaining aspects not handled in the previous parts.

6. **Synthesize the functionality and provide examples:** Based on the analysis, describe the core functions of the code and provide illustrative Go examples that would trigger these rewrites. For code inference, make reasonable assumptions about the input and expected output. Address the prompt's request for command-line parameters (though none are apparent in this code snippet) and common mistakes.

7. **Final Summary:** Condense the findings into a concise summary of the file's role.
这是 `go/src/cmd/compile/internal/ssa/rewriteLOONG64.go` 文件的一部分，专注于将 Go 语言的通用 SSA（静态单赋值）中间表示转换为更具体的、针对 LOONG64 架构优化的 SSA 指令。

**它的主要功能可以归纳为：**

* **指令选择和优化：**  针对 LOONG64 架构，将通用的 Go 语言操作（例如 PopCount, RotateLeft, Right Shift, Select, Store, Zero 等）替换为更底层的、LOONG64 硬件支持的指令序列，以提高性能。
* **模式匹配和替换：**  通过一系列的 `rewriteValueLOONG64_Op...` 和 `rewriteBlockLOONG64` 函数，定义了各种模式匹配规则。当 SSA 图中的节点或块与这些模式匹配时，就会被替换为更优化的 LOONG64 指令序列。
* **利用 LOONG64 特性：** 代码中使用了像 `VPCNT16`, `VPCNT32`, `VPCNT64` (向量人口计数), `ROTR` (循环右移), `MASKEQZ` (条件置零) 等 LOONG64 特有的指令。

**以下是一些具体功能的代码示例和推理：**

**1. `PopCount` 系列函数 (人口计数)**

这些函数实现了计算一个整数中置位 (1) 的数量。LOONG64 提供了向量人口计数指令，这里利用了浮点寄存器和浮点转换指令来使用这些指令。

```go
// 假设输入是一个 uint16 类型的变量 x
x := uint16(10) // 二进制表示为 0000000000001010

// 经过 rewriteValueLOONG64_OpPopCount16 处理后，
// 会生成类似以下的 LOONG64 指令序列（伪代码）：

// 将 x 零扩展到 32 位
temp32 = zero_extend_16_to_32(x)

// 将 32 位整数转换为单精度浮点数
float32_x = int_to_float32(temp32)

// 将单精度浮点数移动到通用浮点寄存器
fpreg = mov_gp_to_fp(float32_x)

// 使用向量人口计数指令计算 16 位的人口计数
popcount_fpreg = vpcnt16(fpreg)

// 将浮点寄存器中的结果移动到通用寄存器
result = mov_fp_to_gp(popcount_fpreg)
```

**假设输入:**  一个 `*Value` 类型的 `v`，代表 `PopCount16` 操作，其第一个参数 `v.Args[0]` 是一个 `uint16` 类型的 SSA 值，例如代表变量 `x`。

**推理输出:**  `v` 的操作码会被重置为 `OpLOONG64MOVWfpgp`，并且它的参数会被设置为一个新的 SSA 值，该值表示执行了 LOONG64 的向量人口计数指令序列。最终 `v` 代表了人口计数的结果。

**2. `RotateLeft` 系列函数 (循环左移)**

这些函数实现了循环左移操作。对于常量移位量，它使用了移位和 OR 操作；对于变量移位量，它利用了 LOONG64 的循环右移指令 (`ROTR`)。

```go
// 假设输入是一个 uint16 类型的变量 x 和一个移位量 c
x := uint16(0b0000000011110000)
c := uint64(2)

// 对于常量移位量，rewriteValueLOONG64_OpRotateLeft16 可能会生成：
// result = (x << (c & 15)) | (x >> (16 - (c & 15)))

// 对于变量移位量，rewriteValueLOONG64_OpRotateLeft16 可能会生成：
// result = rotr(x | (x << 16), -y)
```

**假设输入 (常量移位):** 一个 `*Value` 类型的 `v`，代表 `RotateLeft16` 操作，第一个参数 `v.Args[0]` 是要旋转的值，第二个参数 `v.Args[1]` 是一个 `MOVVconst` 操作，表示常量移位量 `c`。

**推理输出 (常量移位):** `v` 的操作码会被重置为 `OpOr16`，并且它的参数会被设置为两个移位操作的结果，然后进行 OR 运算。

**假设输入 (变量移位):** 一个 `*Value` 类型的 `v`，代表 `RotateLeft16` 操作，第一个参数 `v.Args[0]` 是要旋转的值，第二个参数 `v.Args[1]` 是变量移位量 `y`。

**推理输出 (变量移位):** `v` 的操作码会被重置为 `OpLOONG64ROTR`，并且其参数会被设置为一个经过扩展和左移的值，以及移位量 `y` 的负数。

**3. `Rsh` 系列函数 (右移)**

这些函数实现了右移操作，包括有符号右移和无符号右移。它们处理了移位量大于等于数据位宽的情况，以确保结果的正确性。`MASKEQZ` 指令用于实现条件置零。

```go
// 假设输入是一个 int16 类型的变量 x 和一个移位量 y
x := int16(-10) // 二进制补码表示
y := uint64(10)

// rewriteValueLOONG64_OpRsh16x16 可能会生成：
// shift_amount = y & 63 // 确保移位量在有效范围内
// mask = -(y >= 64)      // 如果 y >= 64，mask 为 -1，否则为 0
// result = (x >> shift_amount) | mask
// 或者使用 SRAV 和条件 OR 指令来实现。
```

**假设输入:** 一个 `*Value` 类型的 `v`，代表 `Rsh16Ux16` 操作，第一个参数 `v.Args[0]` 是要右移的无符号 16 位值 `x`，第二个参数 `v.Args[1]` 是移位量 `y`。

**推理输出:** `v` 的操作码会被重置为 `OpLOONG64MASKEQZ`，并且其参数会包括一个逻辑右移操作 (`SRLV`) 和一个用于生成掩码的比较操作 (`SGTU`)。

**4. `Select0` 和 `Select1` 函数 (选择多返回值)**

这些函数处理从具有多个返回值的操作中选择特定返回值的情况。例如，从 `Mul64uhilo` (64 位无符号乘法，返回高 64 位和低 64 位) 中选择高位或低位。

```go
// 假设一个 Go 函数返回一个 128 位乘法的结果 (高 64 位, 低 64 位)
func multiply128(x, y uint64) (uint64, uint64) {
	// ...
}

// 在 SSA 中，调用 multiply128 可能会生成一个 Mul64uhilo 操作

// Select0 会选择低 64 位，rewriteValueLOONG64_OpSelect0 会将其转换为 MULV 指令
// Select1 会选择高 64 位，rewriteValueLOONG64_OpSelect1 会将其转换为 MULHVU 指令
```

**假设输入:** 一个 `*Value` 类型的 `v`，代表 `Select0` 操作，其参数 `v.Args[0]` 是一个 `Mul64uhilo` 操作。

**推理输出:** `v` 的操作码会被重置为 `OpLOONG64MULHVU`（对于高位选择）或 `OpLOONG64MULV`（对于低位选择），并设置相应的参数。

**5. `Store` 函数 (存储)**

这个函数根据要存储的数据类型大小，选择合适的 LOONG64 存储指令 (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVVstore`, `MOVFstore`, `MOVDstore`)。

```go
// 假设要存储一个 int32 类型的变量 val 到地址 ptr
var val int32 = 10
var ptr *int32

// 在 SSA 中，这会表示为一个 Store 操作

// rewriteValueLOONG64_OpStore 会将其转换为 MOVWstore 指令
```

**假设输入:** 一个 `*Value` 类型的 `v`，代表 `Store` 操作，`v.Aux` 存储了要存储的数据类型信息，`v.Args[0]` 是目标地址，`v.Args[1]` 是要存储的值。

**推理输出:** `v` 的操作码会被重置为相应的 LOONG64 存储指令，例如 `OpLOONG64MOVWstore`，并设置相应的参数。

**6. `Zero` 函数 (零值初始化)**

这个函数优化了将内存区域设置为零的操作。对于小块内存，它使用一系列的存储零值指令；对于大块内存，它可能会使用 `DUFFZERO` 或 `LoweredZero` 等更高效的方法。

```go
// 假设要将一块大小为 16 字节的内存设置为零

// rewriteValueLOONG64_OpZero 可能会将其转换为两个 MOVVstore 指令
```

**假设输入:** 一个 `*Value` 类型的 `v`，代表 `Zero` 操作，`v.AuxInt` 存储了要清零的内存大小，`v.Args[0]` 是起始地址。

**推理输出:** `v` 的操作码会被重置为一系列的存储零值指令或更高效的清零操作指令。

**7. `rewriteBlockLOONG64` 函数 (重写控制流块)**

这个函数负责优化控制流块，例如 `If` 语句的条件判断。它会将通用的条件判断操作转换为 LOONG64 特有的分支指令，例如 `BEQ` (相等分支), `BNE` (不相等分支), `BGE` (大于等于分支) 等。

```go
// 假设一个 if 语句的条件是 a == b

// 在 SSA 中，可能会表示为一个 EQ 块，其控制参数是 SUBV a b

// rewriteBlockLOONG64 会将这个 EQ 块转换为 BEQ 块
```

**假设输入:** 一个 `*Block` 类型的 `b`，其类型为 `BlockLOONG64EQ`，并且其控制参数是一个 `OpLOONG64SUBV` 操作。

**推理输出:** `b` 的类型会被重置为 `BlockLOONG64BEQ`，并且其控制参数会被设置为 `SUBV` 操作的两个操作数。

**涉及代码推理，需要带上假设的输入与输出：** (见上述各功能点的假设输入和推理输出)

**如果涉及命令行参数的具体处理，请详细介绍一下：**

在这个代码片段中，并没有直接处理命令行参数。这些是编译器内部的 SSA 重写规则，它们在编译过程中自动应用。命令行参数可能会影响到更上层的编译流程，例如是否启用某些优化，但这部分代码本身不直接处理命令行参数。

**如果有哪些使用者易犯错的点，请举例说明，没有则不必说明：**

对于直接使用 `go/src/cmd/compile/internal/ssa` 包进行底层编译操作的开发者来说，容易犯错的点可能在于：

* **不理解 SSA 的结构和语义：**  错误地创建或修改 SSA 图会导致编译错误或生成不正确的代码。
* **不熟悉 LOONG64 指令集：**  可能无法编写出有效的或最优的重写规则。
* **重写规则的顺序和冲突：**  不合理的重写规则顺序可能导致某些优化无法应用，或者出现规则之间的冲突。
* **对 `aux` 和 `auxInt` 的误用：**  `aux` 存储类型信息或符号等，`auxInt` 存储整数常量等，错误使用会导致类型错误或逻辑错误。

**这是第4部分，共4部分，请归纳一下它的功能：**

作为第 4 部分，也是最后一部分，这个代码片段主要集中在 **LOONG64 架构特有的、较为底层的指令选择和控制流优化**。它涵盖了：

* **利用 LOONG64 向量指令进行人口计数。**
* **使用 LOONG64 循环移位指令。**
* **处理右移操作的边界情况和使用条件置零指令。**
* **将 Go 的多返回值操作映射到 LOONG64 的指令。**
* **根据数据类型选择合适的存储指令。**
* **优化内存零值初始化，包括使用高效的库函数或指令。**
* **将通用的控制流块转换为 LOONG64 特有的条件分支指令。**

总而言之，`rewriteLOONG64.go` 的这部分代码是 Go 语言编译器针对 LOONG64 架构进行 **后端代码生成和优化的关键组成部分**，它确保了生成的机器码能够充分利用 LOONG64 硬件的特性，从而提高程序的执行效率。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteLOONG64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
PopCount16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount16 <t> x)
	// result: (MOVWfpgp <t> (VPCNT16 <typ.Float32> (MOVWgpfp <typ.Float32> (ZeroExt16to32 x))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64MOVWfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64VPCNT16, typ.Float32)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWgpfp, typ.Float32)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(x)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpPopCount32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount32 <t> x)
	// result: (MOVWfpgp <t> (VPCNT32 <typ.Float32> (MOVWgpfp <typ.Float32> x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64MOVWfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64VPCNT32, typ.Float32)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWgpfp, typ.Float32)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpPopCount64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount64 <t> x)
	// result: (MOVVfpgp <t> (VPCNT64 <typ.Float64> (MOVVgpfp <typ.Float64> x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64MOVVfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64VPCNT64, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVgpfp, typ.Float64)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVVconst [c]))
	// result: (Or16 (Lsh16x64 <t> x (MOVVconst [c&15])) (Rsh16Ux64 <t> x (MOVVconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (RotateLeft16 <t> x y)
	// result: (ROTR <t> (OR <typ.UInt32> (ZeroExt16to32 x) (SLLVconst <t> (ZeroExt16to32 x) [16])) (NEGV <typ.Int64> y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64ROTR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpLOONG64SLLVconst, t)
		v2.AuxInt = int64ToAuxInt(16)
		v2.AddArg(v1)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64NEGV, typ.Int64)
		v3.AddArg(y)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRotateLeft32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RotateLeft32 x y)
	// result: (ROTR x (NEGV <y.Type> y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64ROTR)
		v0 := b.NewValue0(v.Pos, OpLOONG64NEGV, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRotateLeft64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RotateLeft64 x y)
	// result: (ROTRV x (NEGV <y.Type> y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64ROTRV)
		v0 := b.NewValue0(v.Pos, OpLOONG64NEGV, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVVconst [c]))
	// result: (Or8 (Lsh8x64 <t> x (MOVVconst [c&7])) (Rsh8Ux64 <t> x (MOVVconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (RotateLeft8 <t> x y)
	// result: (OR <t> (SLLV <t> x (ANDconst <typ.Int64> [7] y)) (SRLV <t> (ZeroExt8to64 x) (ANDconst <typ.Int64> [7] (NEGV <typ.Int64> y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64OR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64ANDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(7)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpLOONG64ANDconst, typ.Int64)
		v4.AuxInt = int64ToAuxInt(7)
		v5 := b.NewValue0(v.Pos, OpLOONG64NEGV, typ.Int64)
		v5.AddArg(y)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt16to64 x) (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt16to64 x) (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt16to64 x) y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt16to64 x) (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 <t> x y)
	// result: (SRAV (SignExt16to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt16to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 <t> x y)
	// result: (SRAV (SignExt16to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt32to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 <t> x y)
	// result: (SRAV (SignExt16to64 x) (OR <t> (NEGV <t> (SGTU y (MOVVconst <typ.UInt64> [63]))) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(y, v4)
		v2.AddArg(v3)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 <t> x y)
	// result: (SRAV (SignExt16to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt8to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt32to64 x) (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux32 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt32to64 x) (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt32to64 x) y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt32to64 x) (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 <t> x y)
	// result: (SRAV (SignExt32to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt16to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x32 <t> x y)
	// result: (SRAV (SignExt32to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt32to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x64 <t> x y)
	// result: (SRAV (SignExt32to64 x) (OR <t> (NEGV <t> (SGTU y (MOVVconst <typ.UInt64> [63]))) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(y, v4)
		v2.AddArg(v3)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 <t> x y)
	// result: (SRAV (SignExt32to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt8to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux16 <t> x y)
	// result: (MASKEQZ (SRLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
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
func rewriteValueLOONG64_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux32 <t> x y)
	// result: (MASKEQZ (SRLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
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
func rewriteValueLOONG64_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux64 <t> x y)
	// result: (MASKEQZ (SRLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux8 <t> x y)
	// result: (MASKEQZ (SRLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
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
func rewriteValueLOONG64_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x16 <t> x y)
	// result: (SRAV x (OR <t> (NEGV <t> (SGTU (ZeroExt16to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg2(v1, v3)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x32 <t> x y)
	// result: (SRAV x (OR <t> (NEGV <t> (SGTU (ZeroExt32to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg2(v1, v3)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x64 <t> x y)
	// result: (SRAV x (OR <t> (NEGV <t> (SGTU y (MOVVconst <typ.UInt64> [63]))) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(63)
		v2.AddArg2(y, v3)
		v1.AddArg(v2)
		v0.AddArg2(v1, y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x8 <t> x y)
	// result: (SRAV x (OR <t> (NEGV <t> (SGTU (ZeroExt8to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg2(v1, v3)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt8to64 x) (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt8to64 x) (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt8to64 x) y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt8to64 x) (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 <t> x y)
	// result: (SRAV (SignExt8to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt16to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 <t> x y)
	// result: (SRAV (SignExt8to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt32to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 <t> x y)
	// result: (SRAV (SignExt8to64 x) (OR <t> (NEGV <t> (SGTU y (MOVVconst <typ.UInt64> [63]))) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(y, v4)
		v2.AddArg(v3)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 <t> x y)
	// result: (SRAV (SignExt8to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt8to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Select0 (Mul64uhilo x y))
	// result: (MULHVU x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLOONG64MULHVU)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Mul64uover x y))
	// result: (MULV x y)
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLOONG64MULV)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 <t> (Add64carry x y c))
	// result: (ADDV (ADDV <t> x y) c)
	for {
		t := v.Type
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpLOONG64ADDV)
		v0 := b.NewValue0(v.Pos, OpLOONG64ADDV, t)
		v0.AddArg2(x, y)
		v.AddArg2(v0, c)
		return true
	}
	// match: (Select0 <t> (Sub64borrow x y c))
	// result: (SUBV (SUBV <t> x y) c)
	for {
		t := v.Type
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpLOONG64SUBV)
		v0 := b.NewValue0(v.Pos, OpLOONG64SUBV, t)
		v0.AddArg2(x, y)
		v.AddArg2(v0, c)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Mul64uhilo x y))
	// result: (MULV x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLOONG64MULV)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select1 (Mul64uover x y))
	// result: (SGTU <typ.Bool> (MULHVU x y) (MOVVconst <typ.UInt64> [0]))
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLOONG64SGTU)
		v.Type = typ.Bool
		v0 := b.NewValue0(v.Pos, OpLOONG64MULHVU, typ.UInt64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Select1 <t> (Add64carry x y c))
	// result: (OR (SGTU <t> x s:(ADDV <t> x y)) (SGTU <t> s (ADDV <t> s c)))
	for {
		t := v.Type
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpLOONG64OR)
		v0 := b.NewValue0(v.Pos, OpLOONG64SGTU, t)
		s := b.NewValue0(v.Pos, OpLOONG64ADDV, t)
		s.AddArg2(x, y)
		v0.AddArg2(x, s)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64ADDV, t)
		v3.AddArg2(s, c)
		v2.AddArg2(s, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Select1 <t> (Sub64borrow x y c))
	// result: (OR (SGTU <t> s:(SUBV <t> x y) x) (SGTU <t> (SUBV <t> s c) s))
	for {
		t := v.Type
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpLOONG64OR)
		v0 := b.NewValue0(v.Pos, OpLOONG64SGTU, t)
		s := b.NewValue0(v.Pos, OpLOONG64SUBV, t)
		s.AddArg2(x, y)
		v0.AddArg2(s, x)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SUBV, t)
		v3.AddArg2(s, c)
		v2.AddArg2(v3, s)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SelectN [0] call:(CALLstatic {sym} dst src (MOVVconst [sz]) mem))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpLOONG64CALLstatic || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpLOONG64MOVVconst {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRAVconst (NEGV <t> x) [63])
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64SRAVconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpStore(v *Value) bool {
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
		v.reset(OpLOONG64MOVBstore)
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
		v.reset(OpLOONG64MOVHstore)
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
		v.reset(OpLOONG64MOVWstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && !t.IsFloat()
	// result: (MOVVstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && !t.IsFloat()) {
			break
		}
		v.reset(OpLOONG64MOVVstore)
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
		v.reset(OpLOONG64MOVFstore)
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
		v.reset(OpLOONG64MOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpZero(v *Value) bool {
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
	// result: (MOVBstore ptr (MOVVconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] ptr mem)
	// result: (MOVHstore ptr (MOVVconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [3] ptr mem)
	// result: (MOVBstore [2] ptr (MOVVconst [0]) (MOVHstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVHstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [4] {t} ptr mem)
	// result: (MOVWstore ptr (MOVVconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [5] ptr mem)
	// result: (MOVBstore [4] ptr (MOVVconst [0]) (MOVWstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [6] ptr mem)
	// result: (MOVHstore [4] ptr (MOVVconst [0]) (MOVWstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [7] ptr mem)
	// result: (MOVWstore [3] ptr (MOVVconst [0]) (MOVWstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [8] {t} ptr mem)
	// result: (MOVVstore ptr (MOVVconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVVstore)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [9] ptr mem)
	// result: (MOVBstore [8] ptr (MOVVconst [0]) (MOVVstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 9 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [10] ptr mem)
	// result: (MOVHstore [8] ptr (MOVVconst [0]) (MOVVstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 10 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVHstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [11] ptr mem)
	// result: (MOVWstore [7] ptr (MOVVconst [0]) (MOVVstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 11 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [12] ptr mem)
	// result: (MOVWstore [8] ptr (MOVVconst [0]) (MOVVstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [13] ptr mem)
	// result: (MOVVstore [5] ptr (MOVVconst [0]) (MOVVstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 13 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(5)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [14] ptr mem)
	// result: (MOVVstore [6] ptr (MOVVconst [0]) (MOVVstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 14 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [15] ptr mem)
	// result: (MOVVstore [7] ptr (MOVVconst [0]) (MOVVstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 15 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [16] ptr mem)
	// result: (MOVVstore [8] ptr (MOVVconst [0]) (MOVVstore ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpLOONG64MOVVstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%8 != 0 && s > 16
	// result: (Zero [s%8] (OffPtr <ptr.Type> ptr [s-s%8]) (Zero [s-s%8] ptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%8 != 0 && s > 16) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(s % 8)
		v0 := b.NewValue0(v.Pos, OpOffPtr, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - s%8)
		v0.AddArg(ptr)
		v1 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(s - s%8)
		v1.AddArg2(ptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%8 == 0 && s > 16 && s <= 8*128 && !config.noDuffDevice
	// result: (DUFFZERO [8 * (128 - s/8)] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%8 == 0 && s > 16 && s <= 8*128 && !config.noDuffDevice) {
			break
		}
		v.reset(OpLOONG64DUFFZERO)
		v.AuxInt = int64ToAuxInt(8 * (128 - s/8))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%8 == 0 && s > 8*128
	// result: (LoweredZero ptr (ADDVconst <ptr.Type> ptr [s-8]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%8 == 0 && s > 8*128) {
			break
		}
		v.reset(OpLOONG64LoweredZero)
		v0 := b.NewValue0(v.Pos, OpLOONG64ADDVconst, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - 8)
		v0.AddArg(ptr)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteBlockLOONG64(b *Block) bool {
	typ := &b.Func.Config.Types
	switch b.Kind {
	case BlockLOONG64EQ:
		// match: (EQ (FPFlagTrue cmp) yes no)
		// result: (FPF cmp yes no)
		for b.Controls[0].Op == OpLOONG64FPFlagTrue {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockLOONG64FPF, cmp)
			return true
		}
		// match: (EQ (FPFlagFalse cmp) yes no)
		// result: (FPT cmp yes no)
		for b.Controls[0].Op == OpLOONG64FPFlagFalse {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockLOONG64FPT, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGT _ _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpLOONG64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpLOONG64SGT {
				break
			}
			b.resetWithControl(BlockLOONG64NE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTU _ _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpLOONG64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpLOONG64SGTU {
				break
			}
			b.resetWithControl(BlockLOONG64NE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTconst _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpLOONG64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpLOONG64SGTconst {
				break
			}
			b.resetWithControl(BlockLOONG64NE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTUconst _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpLOONG64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpLOONG64SGTUconst {
				break
			}
			b.resetWithControl(BlockLOONG64NE, cmp)
			return true
		}
		// match: (EQ (SGTUconst [1] x) yes no)
		// result: (NE x yes no)
		for b.Controls[0].Op == OpLOONG64SGTUconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockLOONG64NE, x)
			return true
		}
		// match: (EQ (SGTU x (MOVVconst [0])) yes no)
		// result: (EQ x yes no)
		for b.Controls[0].Op == OpLOONG64SGTU {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockLOONG64EQ, x)
			return true
		}
		// match: (EQ (SGTconst [0] x) yes no)
		// result: (GEZ x yes no)
		for b.Controls[0].Op == OpLOONG64SGTconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockLOONG64GEZ, x)
			return true
		}
		// match: (EQ (SGT x (MOVVconst [0])) yes no)
		// result: (LEZ x yes no)
		for b.Controls[0].Op == OpLOONG64SGT {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockLOONG64LEZ, x)
			return true
		}
		// match: (EQ (SGTU (MOVVconst [c]) y) yes no)
		// cond: c >= -2048 && c <= 2047
		// result: (EQ (SGTUconst [c] y) yes no)
		for b.Controls[0].Op == OpLOONG64SGTU {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpLOONG64MOVVconst {
				break
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if !(c >= -2048 && c <= 2047) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpLOONG64SGTUconst, typ.Bool)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockLOONG64EQ, v0)
			return true
		}
		// match: (EQ (SUBV x y) yes no)
		// result: (BEQ x y yes no)
		for b.Controls[0].Op == OpLOONG64SUBV {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			b.resetWithControl2(BlockLOONG64BEQ, x, y)
			return true
		}
		// match: (EQ (SGT x y) yes no)
		// result: (BGE y x yes no)
		for b.Controls[0].Op == OpLOONG64SGT {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			b.resetWithControl2(BlockLOONG64BGE, y, x)
			return true
		}
		// match: (EQ (SGTU x y) yes no)
		// result: (BGEU y x yes no)
		for b.Controls[0].Op == OpLOONG64SGTU {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			b.resetWithControl2(BlockLOONG64BGEU, y, x)
			return true
		}
		// match: (EQ (MOVVconst [0]) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (EQ (MOVVconst [c]) yes no)
		// cond: c != 0
		// result: (First no yes)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c != 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockLOONG64GEZ:
		// match: (GEZ (MOVVconst [c]) yes no)
		// cond: c >= 0
		// result: (First yes no)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c >= 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GEZ (MOVVconst [c]) yes no)
		// cond: c < 0
		// result: (First no yes)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c < 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockLOONG64GTZ:
		// match: (GTZ (MOVVconst [c]) yes no)
		// cond: c > 0
		// result: (First yes no)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c > 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GTZ (MOVVconst [c]) yes no)
		// cond: c <= 0
		// result: (First no yes)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c <= 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockIf:
		// match: (If cond yes no)
		// result: (NE (MOVBUreg <typ.UInt64> cond) yes no)
		for {
			cond := b.Controls[0]
			v0 := b.NewValue0(cond.Pos, OpLOONG64MOVBUreg, typ.UInt64)
			v0.AddArg(cond)
			b.resetWithControl(BlockLOONG64NE, v0)
			return true
		}
	case BlockLOONG64LEZ:
		// match: (LEZ (MOVVconst [c]) yes no)
		// cond: c <= 0
		// result: (First yes no)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c <= 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LEZ (MOVVconst [c]) yes no)
		// cond: c > 0
		// result: (First no yes)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c > 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockLOONG64LTZ:
		// match: (LTZ (MOVVconst [c]) yes no)
		// cond: c < 0
		// result: (First yes no)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c < 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LTZ (MOVVconst [c]) yes no)
		// cond: c >= 0
		// result: (First no yes)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c >= 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockLOONG64NE:
		// match: (NE (FPFlagTrue cmp) yes no)
		// result: (FPT cmp yes no)
		for b.Controls[0].Op == OpLOONG64FPFlagTrue {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockLOONG64FPT, cmp)
			return true
		}
		// match: (NE (FPFlagFalse cmp) yes no)
		// result: (FPF cmp yes no)
		for b.Controls[0].Op == OpLOONG64FPFlagFalse {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockLOONG64FPF, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGT _ _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpLOONG64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpLOONG64SGT {
				break
			}
			b.resetWithControl(BlockLOONG64EQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTU _ _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpLOONG64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpLOONG64SGTU {
				break
			}
			b.resetWithControl(BlockLOONG64EQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTconst _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpLOONG64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpLOONG64SGTconst {
				break
			}
			b.resetWithControl(BlockLOONG64EQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTUconst _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpLOONG64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpLOONG64SGTUconst {
				break
			}
			b.resetWithControl(BlockLOONG64EQ, cmp)
			return true
		}
		// match: (NE (SGTUconst [1] x) yes no)
		// result: (EQ x yes no)
		for b.Controls[0].Op == OpLOONG64SGTUconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockLOONG64EQ, x)
			return true
		}
		// match: (NE (SGTU x (MOVVconst [0])) yes no)
		// result: (NE x yes no)
		for b.Controls[0].Op == OpLOONG64SGTU {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockLOONG64NE, x)
			return true
		}
		// match: (NE (SGTconst [0] x) yes no)
		// result: (LTZ x yes no)
		for b.Controls[0].Op == OpLOONG64SGTconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockLOONG64LTZ, x)
			return true
		}
		// match: (NE (SGT x (MOVVconst [0])) yes no)
		// result: (GTZ x yes no)
		for b.Controls[0].Op == OpLOONG64SGT {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockLOONG64GTZ, x)
			return true
		}
		// match: (NE (SGTU (MOVVconst [c]) y) yes no)
		// cond: c >= -2048 && c <= 2047
		// result: (NE (SGTUconst [c] y) yes no)
		for b.Controls[0].Op == OpLOONG64SGTU {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpLOONG64MOVVconst {
				break
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if !(c >= -2048 && c <= 2047) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpLOONG64SGTUconst, typ.Bool)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockLOONG64NE, v0)
			return true
		}
		// match: (NE (SUBV x y) yes no)
		// result: (BNE x y yes no)
		for b.Controls[0].Op == OpLOONG64SUBV {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			b.resetWithControl2(BlockLOONG64BNE, x, y)
			return true
		}
		// match: (NE (SGT x y) yes no)
		// result: (BLT y x yes no)
		for b.Controls[0].Op == OpLOONG64SGT {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			b.resetWithControl2(BlockLOONG64BLT, y, x)
			return true
		}
		// match: (NE (SGTU x y) yes no)
		// result: (BLTU y x yes no)
		for b.Controls[0].Op == OpLOONG64SGTU {
			v_0 := b.Controls[0]
			y := v_0.Args[1]
			x := v_0.Args[0]
			b.resetWithControl2(BlockLOONG64BLTU, y, x)
			return true
		}
		// match: (NE (MOVVconst [0]) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (NE (MOVVconst [c]) yes no)
		// cond: c != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpLOONG64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
	}
	return false
}
```