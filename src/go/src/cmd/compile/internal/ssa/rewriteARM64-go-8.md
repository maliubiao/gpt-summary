Response: The user wants a summary of the functionality of the provided Go code snippet. This code is part of the SSA (Static Single Assignment) rewriting rules for the ARM64 architecture within the Go compiler.

My plan is to:
1. **Identify the primary function**: The code consists of several functions named `rewriteValueARM64_Op...` and `rewriteBlockARM64`. These functions are responsible for transforming SSA values and blocks, respectively, based on specific patterns.
2. **Categorize the transformations**:  Group the transformations by the SSA operation they handle (e.g., `OpRsh64x64`, `OpStore`, `OpZero`) and by the type of block (e.g., `BlockARM64EQ`, `BlockIf`).
3. **Summarize the purpose of each category**: Explain what kind of optimization or lowering each group of rewrites achieves. This will likely involve recognizing common patterns like handling bounded vs. unbounded shifts, converting high-level operations into sequences of ARM64 instructions, and optimizing control flow.
4. **Infer the broader Go feature**: Based on the operations being rewritten (shift operations, stores, zeroing memory, control flow), deduce the related Go language features.
5. **Provide Go code examples**: Illustrate the Go features being implemented with simple code snippets.
6. **Infer input/output for code reasoning**: For code rewrites that involve specific transformations, describe the likely input SSA operation and the resulting output SSA operation.
7. **Identify the overall purpose**: Since this is part 9 of 10, consider what general phase of compilation this code relates to. It's likely a late-stage optimization and lowering pass specific to the ARM64 architecture.
```go
func rewriteValueARM64_OpRsh64Ux16(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh64Ux32(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh64Ux64(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh64Ux8(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh64x16(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh64x32(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh64x64(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh64x8(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh8Ux16(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh8Ux32(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh8Ux64(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh8Ux8(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh8x16(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh8x32(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh8x64(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpRsh8x8(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpSelect0(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpSelect1(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpSelectN(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpSlicemask(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpStore(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteValueARM64_OpZero(v *Value) bool {
	// ... (rest of the function code)
}
func rewriteBlockARM64(b *Block) bool {
	// ... (rest of the function code)
}
```

### 功能归纳

这段代码是Go语言编译器中用于将**通用 SSA (Static Single Assignment) 中间表示** 转换为 **ARM64 特定 SSA 表示** 的一部分，专注于 **第9部分** 的转换规则。  它主要定义了一系列的 **rewrite rules (重写规则)**，这些规则描述了如何将一种 SSA 操作或代码块模式转换为更低级的、更接近 ARM64 硬件指令的等价形式。

具体来说，这部分代码涵盖了以下功能：

1. **实现位移操作 (`OpRsh`, `OpLsh`)**:
   - 针对不同大小和类型的操作数（例如 `int64` 右移 `int64`, `uint8` 右移 `uint16` 等），以及有符号和无符号的位移。
   - 区分了 **有界位移 (bounded shift)** 和 **无界位移 (unbounded shift)**。对于无界位移，它会生成额外的代码来确保位移量在有效范围内（0 到 63）。
   - 将 Go 的位移操作符 (`>>`, `>>>`) 转换为 ARM64 的算术右移 (`SRA`) 和逻辑右移 (`SRL`) 指令。

2. **实现元组选择操作 (`OpSelect0`, `OpSelect1`, `OpSelectN`)**:
   - `OpSelect0` 和 `OpSelect1` 用于从返回多个值的操作中提取第一个或第二个值。
   - 针对特定的多返回值操作（如 `Mul64uhilo`，`Add64carry`，`Sub64borrow`，`Mul64uover`），将其转换为对应的 ARM64 指令 (`UMULH`, `ADCSflags`, `SBCSflags`, `MUL`) 或者使用 `Select1` 来进一步提取标志位。
   - `OpSelectN` 用于选择具有多个返回值的函数调用结果，并针对 `runtime.memmove` 这样的特定函数调用进行了优化，直接转换为 `OpMove` 操作。

3. **实现 Slicemask 操作 (`OpSlicemask`)**:
   - 用于计算切片的掩码，该掩码用于判断索引是否在切片的有效范围内。
   - 将其转换为 ARM64 的 `SRAconst` 和 `NEG` 指令组合。

4. **实现存储操作 (`OpStore`)**:
   - 根据要存储的数据类型的大小和是否为浮点数，选择合适的 ARM64 存储指令 (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVDstore`, `FMOVSstore`, `FMOVDstore`)。

5. **实现零值填充操作 (`OpZero`)**:
   - 用于将内存区域填充为零值。
   - 针对不同大小的内存区域，生成优化的 ARM64 存储指令序列，包括使用 `MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVDstore`, `STP` (store pair) 指令。
   - 对于较大的内存区域，会考虑使用 `DUFFZERO` (Duff's device for zeroing) 或者 `LoweredZero` 来实现更高效的清零。

6. **优化控制流块 (`rewriteBlockARM64`)**:
   - 针对不同的控制流块类型 (`BlockARM64EQ`, `BlockARM64FGE`, `BlockIf` 等)，根据其控制条件（通常是比较指令的结果），进行进一步的优化。
   - 例如，将比较指令后跟随的条件跳转块 (`BlockARM64EQ`) 与特定的指令模式（如 `AND`, `ADD`, `MADD`, `MSUB` 的比较）结合起来，生成更简洁的 ARM64 指令（如 `TST`, `CMN`）。
   - 将通用的 `If` 块转换为特定于 ARM64 的条件分支块 (`TBNZ`, `TBZ`, `EQ`, `NE`, `LT`, `GT` 等)。
   - 针对标志位常量 (`FlagConstant`) 进行优化，直接跳转到 `yes` 或 `no` 分支。
   - 处理 `InvertFlags`，将其应用于后续的条件块。

### Go 语言功能实现推断及代码示例

基于以上功能，可以推断这段代码主要实现了以下 Go 语言功能在 ARM64 架构上的底层转换和优化：

1. **基本数据类型的运算**:  特别是位运算（移位）。
2. **复合数据类型的操作**: 例如，从函数的多返回值中获取特定值。
3. **切片操作**:  计算切片的边界。
4. **内存操作**:  包括变量的赋值（存储）和内存的初始化（零值填充）。
5. **控制流**:  `if` 语句等条件分支结构。

**Go 代码示例：**

```go
package main

func shiftRight(x int64, y uint64) int64 {
	return x >> y
}

func multiReturn() (int, bool) {
	return 1, true
}

func main() {
	a := int64(10)
	b := uint64(3)
	result := shiftRight(a, b)
	println(result)

	val, ok := multiReturn()
	println(val, ok)

	s := make([]int, 10)
	s[5] = 100

	var z int
	println(z) // z will be zero-initialized

	if val > 0 {
		println("Value is positive")
	}
}
```

**代码推理示例 (针对 `OpRsh64x64`)：**

**假设输入 SSA (有界位移):**

```
v1 = ParamInt64 { ... } // x
v2 = ParamUInt64 { ... } // y
v3 = Rsh64x64 v1 v2
```

**输出 SSA (使用 SRA 指令):**

```
v1 = ParamInt64 { ... } // x
v2 = ParamUInt64 { ... } // y
v3 = ARM64SRA v1 v2
```

**假设输入 SSA (无界位移):**

```
v1 = ParamInt64 { ... } // x
v2 = ParamUInt64 { ... } // y
v3 = Rsh64x64 v1 v2
```

**输出 SSA (使用 CSEL 保证位移量):**

```
v1 = ParamInt64 { ... } // x
v2 = ParamUInt64 { ... } // y
b1:
  v4 = Const64 <y.Type> [63]
  v5 = ARM64CMPconst <types.TypeFlags> [64] v2
  v6 = ARM64CSEL <y.Type> [OpARM64LessThanU] v2 v4 v5
  v3 = ARM64SRA v1 v6
```

### 命令行参数处理

这段代码本身不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的更上层。但是，编译器会根据目标架构 (这里是 ARM64) 和编译选项 (例如是否开启某些优化) 来选择和配置这些 rewrite 规则。

### 使用者易犯错的点

作为编译器开发者，编写这些 rewrite 规则时容易犯错的点包括：

- **条件判断错误**: `cond` 条件不正确可能导致错误的转换。
- **类型匹配错误**:  确保操作数的类型与 rewrite 规则匹配。
- **指令选择错误**:  选择了不合适的 ARM64 指令。
- **Auxiliary 信息处理不当**: `AuxInt` 和 `Aux` 字段包含重要的信息，处理错误会导致转换失败。
- **遗漏边界情况**:  例如，没有正确处理有界和无界位移的区别。
- **引入性能回退**:  虽然目标是优化，但错误的 rewrite 规则可能导致性能下降。

### 第9部分功能归纳

作为共 10 部分的第 9 部分，可以推断这部分代码处于 **SSA lowering 和架构特定优化的后期阶段**。 在这个阶段，通用的 SSA 表示已经被转换成更接近目标架构的形式，并且正在进行针对 ARM64 架构的特定优化，例如指令选择、寻址模式优化、以及利用 ARM64 特有的指令和特性（如条件选择指令 `CSEL`）。  第 9 部分可能专注于处理一些更复杂的操作和控制流优化，为最终的代码生成阶段做准备。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第9部分，共10部分，请归纳一下它的功能

"""
ssThanU)
		v1 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x64 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA x (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] y)))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v0.AuxInt = opToAuxInt(OpARM64LessThanU)
		v1 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x8 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA x (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt8to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v0.AuxInt = opToAuxInt(OpARM64LessThanU)
		v1 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt8to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt8to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt8to64 x) y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt8to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x16 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt8to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt16to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x32 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt8to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt32to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x64 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt8to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] y)))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x8 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt8to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt8to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Mul64uhilo x y))
	// result: (UMULH x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64UMULH)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADCSflags x y (Select1 <types.TypeFlags> (ADDSconstflags [-1] c))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpARM64ADCSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpARM64ADDSconstflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2.AuxInt = int64ToAuxInt(-1)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Sub64borrow x y bo))
	// result: (Select0 <typ.UInt64> (SBCSflags x y (Select1 <types.TypeFlags> (NEGSflags bo))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		bo := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpARM64SBCSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpARM64NEGSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2.AddArg(bo)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Mul64uover x y))
	// result: (MUL x y)
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64MUL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Mul64uhilo x y))
	// result: (MUL x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64MUL)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select1 (Add64carry x y c))
	// result: (ADCzerocarry <typ.UInt64> (Select1 <types.TypeFlags> (ADCSflags x y (Select1 <types.TypeFlags> (ADDSconstflags [-1] c)))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpARM64ADCzerocarry)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64ADCSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpARM64ADDSconstflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v3.AuxInt = int64ToAuxInt(-1)
		v3.AddArg(c)
		v2.AddArg(v3)
		v1.AddArg3(x, y, v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Sub64borrow x y bo))
	// result: (NEG <typ.UInt64> (NGCzerocarry <typ.UInt64> (Select1 <types.TypeFlags> (SBCSflags x y (Select1 <types.TypeFlags> (NEGSflags bo))))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		bo := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpARM64NEG)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpARM64NGCzerocarry, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpARM64SBCSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v3 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v4 := b.NewValue0(v.Pos, OpARM64NEGSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v4.AddArg(bo)
		v3.AddArg(v4)
		v2.AddArg3(x, y, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Mul64uover x y))
	// result: (NotEqual (CMPconst (UMULH <typ.UInt64> x y) [0]))
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64UMULH, typ.UInt64)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SelectN [0] call:(CALLstatic {sym} s1:(MOVDstore _ (MOVDconst [sz]) s2:(MOVDstore _ src s3:(MOVDstore {t} _ dst mem)))))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpARM64CALLstatic || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpARM64MOVDstore {
			break
		}
		_ = s1.Args[2]
		s1_1 := s1.Args[1]
		if s1_1.Op != OpARM64MOVDconst {
			break
		}
		sz := auxIntToInt64(s1_1.AuxInt)
		s2 := s1.Args[2]
		if s2.Op != OpARM64MOVDstore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpARM64MOVDstore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(CALLstatic {sym} dst src (MOVDconst [sz]) mem))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpARM64CALLstatic || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpARM64MOVDconst {
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
func rewriteValueARM64_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRAconst (NEG <t> x) [63])
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64SRAconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpARM64NEG, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpStore(v *Value) bool {
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
		v.reset(OpARM64MOVBstore)
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
		v.reset(OpARM64MOVHstore)
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
		v.reset(OpARM64MOVWstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && !t.IsFloat()
	// result: (MOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && !t.IsFloat()) {
			break
		}
		v.reset(OpARM64MOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && t.IsFloat()
	// result: (FMOVSstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && t.IsFloat()) {
			break
		}
		v.reset(OpARM64FMOVSstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && t.IsFloat()
	// result: (FMOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && t.IsFloat()) {
			break
		}
		v.reset(OpARM64FMOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpZero(v *Value) bool {
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
	// result: (MOVBstore ptr (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] ptr mem)
	// result: (MOVHstore ptr (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [4] ptr mem)
	// result: (MOVWstore ptr (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [3] ptr mem)
	// result: (MOVBstore [2] ptr (MOVDconst [0]) (MOVHstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVHstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [5] ptr mem)
	// result: (MOVBstore [4] ptr (MOVDconst [0]) (MOVWstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [6] ptr mem)
	// result: (MOVHstore [4] ptr (MOVDconst [0]) (MOVWstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [7] ptr mem)
	// result: (MOVWstore [3] ptr (MOVDconst [0]) (MOVWstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [8] ptr mem)
	// result: (MOVDstore ptr (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [9] ptr mem)
	// result: (MOVBstore [8] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 9 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [10] ptr mem)
	// result: (MOVHstore [8] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 10 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [11] ptr mem)
	// result: (MOVDstore [3] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 11 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [12] ptr mem)
	// result: (MOVWstore [8] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [13] ptr mem)
	// result: (MOVDstore [5] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 13 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(5)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [14] ptr mem)
	// result: (MOVDstore [6] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 14 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [15] ptr mem)
	// result: (MOVDstore [7] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 15 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [16] ptr mem)
	// result: (STP [0] ptr (MOVDconst [0]) (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg4(ptr, v0, v0, mem)
		return true
	}
	// match: (Zero [32] ptr mem)
	// result: (STP [16] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [0] ptr (MOVDconst [0]) (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg4(ptr, v0, v0, mem)
		v.AddArg4(ptr, v0, v0, v1)
		return true
	}
	// match: (Zero [48] ptr mem)
	// result: (STP [32] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [16] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [0] ptr (MOVDconst [0]) (MOVDconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 48 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(16)
		v2 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg4(ptr, v0, v0, mem)
		v1.AddArg4(ptr, v0, v0, v2)
		v.AddArg4(ptr, v0, v0, v1)
		return true
	}
	// match: (Zero [64] ptr mem)
	// result: (STP [48] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [32] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [16] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [0] ptr (MOVDconst [0]) (MOVDconst [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 64 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(48)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(32)
		v2 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(16)
		v3 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg4(ptr, v0, v0, mem)
		v2.AddArg4(ptr, v0, v0, v3)
		v1.AddArg4(ptr, v0, v0, v2)
		v.AddArg4(ptr, v0, v0, v1)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%16 != 0 && s%16 <= 8 && s > 16
	// result: (Zero [8] (OffPtr <ptr.Type> ptr [s-8]) (Zero [s-s%16] ptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%16 != 0 && s%16 <= 8 && s > 16) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpOffPtr, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - 8)
		v0.AddArg(ptr)
		v1 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(s - s%16)
		v1.AddArg2(ptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%16 != 0 && s%16 > 8 && s > 16
	// result: (Zero [16] (OffPtr <ptr.Type> ptr [s-16]) (Zero [s-s%16] ptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%16 != 0 && s%16 > 8 && s > 16) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpOffPtr, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - 16)
		v0.AddArg(ptr)
		v1 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(s - s%16)
		v1.AddArg2(ptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%16 == 0 && s > 64 && s <= 16*64 && !config.noDuffDevice
	// result: (DUFFZERO [4 * (64 - s/16)] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%16 == 0 && s > 64 && s <= 16*64 && !config.noDuffDevice) {
			break
		}
		v.reset(OpARM64DUFFZERO)
		v.AuxInt = int64ToAuxInt(4 * (64 - s/16))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%16 == 0 && (s > 16*64 || config.noDuffDevice)
	// result: (LoweredZero ptr (ADDconst <ptr.Type> [s-16] ptr) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%16 == 0 && (s > 16*64 || config.noDuffDevice)) {
			break
		}
		v.reset(OpARM64LoweredZero)
		v0 := b.NewValue0(v.Pos, OpARM64ADDconst, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - 16)
		v0.AddArg(ptr)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteBlockARM64(b *Block) bool {
	typ := &b.Func.Config.Types
	switch b.Kind {
	case BlockARM64EQ:
		// match: (EQ (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (TST x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TST, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (CMPconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (EQ (TSTconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (CMPWconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (TSTW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TSTW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (CMPWconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (EQ (TSTWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (CMPconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (EQ (CMNconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (CMPWconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (EQ (CMNWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (CMPconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (CMN x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (CMPWconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (CMNW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (CMP x z:(NEG y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (CMN x y) yes no)
		for b.Controls[0].Op == OpARM64CMP {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpARM64NEG {
				break
			}
			y := z.Args[0]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (CMPW x z:(NEG y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (CMNW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPW {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpARM64NEG {
				break
			}
			y := z.Args[0]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
			v0.AddArg2(x, y)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (CMPconst [0] x) yes no)
		// result: (Z x yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockARM64Z, x)
			return true
		}
		// match: (EQ (CMPWconst [0] x) yes no)
		// result: (ZW x yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockARM64ZW, x)
			return true
		}
		// match: (EQ (CMPconst [0] z:(MADD a x y)) yes no)
		// cond: z.Uses==1
		// result: (EQ (CMN a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADD {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (CMPconst [0] z:(MSUB a x y)) yes no)
		// cond: z.Uses==1
		// result: (EQ (CMP a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUB {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMP, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (CMPWconst [0] z:(MADDW a x y)) yes no)
		// cond: z.Uses==1
		// result: (EQ (CMNW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADDW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (CMPWconst [0] z:(MSUBW a x y)) yes no)
		// cond: z.Uses==1
		// result: (EQ (CMPW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUBW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64EQ, v0)
			return true
		}
		// match: (EQ (TSTconst [c] x) yes no)
		// cond: oneBit(c)
		// result: (TBZ [int64(ntz64(c))] x yes no)
		for b.Controls[0].Op == OpARM64TSTconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			x := v_0.Args[0]
			if !(oneBit(c)) {
				break
			}
			b.resetWithControl(BlockARM64TBZ, x)
			b.AuxInt = int64ToAuxInt(int64(ntz64(c)))
			return true
		}
		// match: (EQ (TSTWconst [c] x) yes no)
		// cond: oneBit(int64(uint32(c)))
		// result: (TBZ [int64(ntz64(int64(uint32(c))))] x yes no)
		for b.Controls[0].Op == OpARM64TSTWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(oneBit(int64(uint32(c)))) {
				break
			}
			b.resetWithControl(BlockARM64TBZ, x)
			b.AuxInt = int64ToAuxInt(int64(ntz64(int64(uint32(c)))))
			return true
		}
		// match: (EQ (FlagConstant [fc]) yes no)
		// cond: fc.eq()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.eq()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (EQ (FlagConstant [fc]) yes no)
		// cond: !fc.eq()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.eq()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (InvertFlags cmp) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64EQ, cmp)
			return true
		}
	case BlockARM64FGE:
		// match: (FGE (InvertFlags cmp) yes no)
		// result: (FLE cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64FLE, cmp)
			return true
		}
	case BlockARM64FGT:
		// match: (FGT (InvertFlags cmp) yes no)
		// result: (FLT cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64FLT, cmp)
			return true
		}
	case BlockARM64FLE:
		// match: (FLE (InvertFlags cmp) yes no)
		// result: (FGE cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64FGE, cmp)
			return true
		}
	case BlockARM64FLT:
		// match: (FLT (InvertFlags cmp) yes no)
		// result: (FGT cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64FGT, cmp)
			return true
		}
	case BlockARM64GE:
		// match: (GE (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (GE (TST x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TST, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64GE, v0)
				return true
			}
			break
		}
		// match: (GE (CMPconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (GE (TSTconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64GE, v0)
			return true
		}
		// match: (GE (CMPWconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (GE (TSTW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TSTW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64GE, v0)
				return true
			}
			break
		}
		// match: (GE (CMPWconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (GE (TSTWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64GE, v0)
			return true
		}
		// match: (GE (CMPconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (GEnoov (CMNconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64GEnoov, v0)
			return true
		}
		// match: (GE (CMPWconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (GEnoov (CMNWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64GEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (GEnoov (CMN x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64GEnoov, v0)
				return true
			}
			break
		}
		// match: (GE (CMPWconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (GEnoov (CMNW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64GEnoov, v0)
				return true
			}
			break
		}
		// match: (GE (CMPconst [0] z:(MADD a x y)) yes no)
		// cond: z.Uses==1
		// result: (GEnoov (CMN a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADD {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64GEnoov, v0)
			return true
		}
		// match: (GE (CMPconst [0] z:(MSUB a x y)) yes no)
		// cond: z.Uses==1
		// result: (GEnoov (CMP a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUB {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMP, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64GEnoov, v0)
			return true
		}
		// match: (GE (CMPWconst [0] z:(MADDW a x y)) yes no)
		// cond: z.Uses==1
		// result: (GEnoov (CMNW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADDW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64GEnoov, v0)
			return true
		}
		// match: (GE (CMPWconst [0] z:(MSUBW a x y)) yes no)
		// cond: z.Uses==1
		// result: (GEnoov (CMPW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUBW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64GEnoov, v0)
			return true
		}
		// match: (GE (CMPWconst [0] x) yes no)
		// result: (TBZ [31] x yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockARM64TBZ, x)
			b.AuxInt = int64ToAuxInt(31)
			return true
		}
		// match: (GE (CMPconst [0] x) yes no)
		// result: (TBZ [63] x yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockARM64TBZ, x)
			b.AuxInt = int64ToAuxInt(63)
			return true
		}
		// match: (GE (FlagConstant [fc]) yes no)
		// cond: fc.ge()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.ge()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (FlagConstant [fc]) yes no)
		// cond: !fc.ge()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.ge()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GE (InvertFlags cmp) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64LE, cmp)
			return true
		}
	case BlockARM64GEnoov:
		// match: (GEnoov (FlagConstant [fc]) yes no)
		// cond: fc.geNoov()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.geNoov()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GEnoov (FlagConstant [fc]) yes no)
		// cond: !fc.geNoov()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.geNoov()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GEnoov (InvertFlags cmp) yes no)
		// result: (LEnoov cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64LEnoov, cmp)
			return true
		}
	case BlockARM64GT:
		// match: (GT (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (GT (TST x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TST, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64GT, v0)
				return true
			}
			break
		}
		// match: (GT (CMPconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (GT (TSTconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64GT, v0)
			return true
		}
		// match: (GT (CMPWconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (GT (TSTW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TSTW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64GT, v0)
				return true
			}
			break
		}
		// match: (GT (CMPWconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (GT (TSTWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64TSTWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64GT, v0)
			return true
		}
		// match: (GT (CMPconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (GTnoov (CMNconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(c)
			v0.AddArg(y)
			b.resetWithControl(BlockARM64GTnoov, v0)
			return true
		}
		// match: (GT (CMPWconst [0] x:(ADDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (GTnoov (CMNWconst [int32(c)] y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ADDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0]
			if !(x.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNWconst, types.TypeFlags)
			v0.AuxInt = int32ToAuxInt(int32(c))
			v0.AddArg(y)
			b.resetWithControl(BlockARM64GTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (GTnoov (CMN x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64GTnoov, v0)
				return true
			}
			break
		}
		// match: (GT (CMPWconst [0] z:(ADD x y)) yes no)
		// cond: z.Uses == 1
		// result: (GTnoov (CMNW x y) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64ADD {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64GTnoov, v0)
				return true
			}
			break
		}
		// match: (GT (CMPconst [0] z:(MADD a x y)) yes no)
		// cond: z.Uses==1
		// result: (GTnoov (CMN a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADD {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMN, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64GTnoov, v0)
			return true
		}
		// match: (GT (CMPconst [0] z:(MSUB a x y)) yes no)
		// cond: z.Uses==1
		// result: (GTnoov (CMP a (MUL <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUB {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMP, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MUL, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64GTnoov, v0)
			return true
		}
		// match: (GT (CMPWconst [0] z:(MADDW a x y)) yes no)
		// cond: z.Uses==1
		// result: (GTnoov (CMNW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MADDW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMNW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64GTnoov, v0)
			return true
		}
		// match: (GT (CMPWconst [0] z:(MSUBW a x y)) yes no)
		// cond: z.Uses==1
		// result: (GTnoov (CMPW a (MULW <x.Type> x y)) yes no)
		for b.Controls[0].Op == OpARM64CMPWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64MSUBW {
				break
			}
			y := z.Args[2]
			a := z.Args[0]
			x := z.Args[1]
			if !(z.Uses == 1) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpARM64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v_0.Pos, OpARM64MULW, x.Type)
			v1.AddArg2(x, y)
			v0.AddArg2(a, v1)
			b.resetWithControl(BlockARM64GTnoov, v0)
			return true
		}
		// match: (GT (FlagConstant [fc]) yes no)
		// cond: fc.gt()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.gt()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GT (FlagConstant [fc]) yes no)
		// cond: !fc.gt()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.gt()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (InvertFlags cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64LT, cmp)
			return true
		}
	case BlockARM64GTnoov:
		// match: (GTnoov (FlagConstant [fc]) yes no)
		// cond: fc.gtNoov()
		// result: (First yes no)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(fc.gtNoov()) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GTnoov (FlagConstant [fc]) yes no)
		// cond: !fc.gtNoov()
		// result: (First no yes)
		for b.Controls[0].Op == OpARM64FlagConstant {
			v_0 := b.Controls[0]
			fc := auxIntToFlagConstant(v_0.AuxInt)
			if !(!fc.gtNoov()) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GTnoov (InvertFlags cmp) yes no)
		// result: (LTnoov cmp yes no)
		for b.Controls[0].Op == OpARM64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARM64LTnoov, cmp)
			return true
		}
	case BlockIf:
		// match: (If (Equal cc) yes no)
		// result: (EQ cc yes no)
		for b.Controls[0].Op == OpARM64Equal {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64EQ, cc)
			return true
		}
		// match: (If (NotEqual cc) yes no)
		// result: (NE cc yes no)
		for b.Controls[0].Op == OpARM64NotEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64NE, cc)
			return true
		}
		// match: (If (LessThan cc) yes no)
		// result: (LT cc yes no)
		for b.Controls[0].Op == OpARM64LessThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64LT, cc)
			return true
		}
		// match: (If (LessThanU cc) yes no)
		// result: (ULT cc yes no)
		for b.Controls[0].Op == OpARM64LessThanU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64ULT, cc)
			return true
		}
		// match: (If (LessEqual cc) yes no)
		// result: (LE cc yes no)
		for b.Controls[0].Op == OpARM64LessEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64LE, cc)
			return true
		}
		// match: (If (LessEqualU cc) yes no)
		// result: (ULE cc yes no)
		for b.Controls[0].Op == OpARM64LessEqualU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64ULE, cc)
			return true
		}
		// match: (If (GreaterThan cc) yes no)
		// result: (GT cc yes no)
		for b.Controls[0].Op == OpARM64GreaterThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64GT, cc)
			return true
		}
		// match: (If (GreaterThanU cc) yes no)
		// result: (UGT cc yes no)
		for b.Controls[0].Op == OpARM64GreaterThanU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64UGT, cc)
			return true
		}
		// match: (If (GreaterEqual cc) yes no)
		// result: (GE cc yes no)
		for b.Controls[0].Op == OpARM64GreaterEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64GE, cc)
			return true
		}
		// match: (If (GreaterEqualU cc) yes no)
		// result: (UGE cc yes no)
		for b.Controls[0].Op == OpARM64GreaterEqualU {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64UGE, cc)
			return true
		}
		// match: (If (LessThanF cc) yes no)
		// result: (FLT cc yes no)
		for b.Controls[0].Op == OpARM64LessThanF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64FLT, cc)
			return true
		}
		// match: (If (LessEqualF cc) yes no)
		// result: (FLE cc yes no)
		for b.Controls[0].Op == OpARM64LessEqualF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64FLE, cc)
			return true
		}
		// match: (If (GreaterThanF cc) yes no)
		// result: (FGT cc yes no)
		for b.Controls[0].Op == OpARM64GreaterThanF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64FGT, cc)
			return true
		}
		// match: (If (GreaterEqualF cc) yes no)
		// result: (FGE cc yes no)
		for b.Controls[0].Op == OpARM64GreaterEqualF {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockARM64FGE, cc)
			return true
		}
		// match: (If cond yes no)
		// result: (TBNZ [0] cond yes no)
		for {
			cond := b.Controls[0]
			b.resetWithControl(BlockARM64TBNZ, cond)
			b.AuxInt = int64ToAuxInt(0)
			return true
		}
	case BlockJumpTable:
		// match: (JumpTable idx)
		// result: (JUMPTABLE {makeJumpTableSym(b)} idx (MOVDaddr <typ.Uintptr> {makeJumpTableSym(b)} (SB)))
		for {
			idx := b.Controls[0]
			v0 := b.NewValue0(b.Pos, OpARM64MOVDaddr, typ.Uintptr)
			v0.Aux
"""




```