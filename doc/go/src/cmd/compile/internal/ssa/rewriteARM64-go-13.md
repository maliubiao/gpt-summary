Response:
The user wants to understand the functionality of a specific part of the Go compiler's code, specifically the `rewriteARM64.go` file. This file seems to contain rewrite rules for the SSA (Static Single Assignment) intermediate representation, targeting the ARM64 architecture.

The request asks for:
1. **Functionality listing:**  Describe what each function in the provided code snippet does.
2. **Go language feature implementation (if applicable):** If a function seems to implement a specific Go feature, provide a Go code example.
3. **Code reasoning (if applicable):** For functions involving code manipulation, explain the logic, including assumed inputs and outputs.
4. **Command-line argument handling (if applicable):** Describe how command-line arguments are processed if relevant.
5. **Common mistakes (if applicable):** Point out potential pitfalls for users.
6. **Summary:**  Provide a concise summary of the code's purpose within the larger context.

Let's go through each function in the provided snippet:

- **`rewriteBlockARM64_OpCondSelect`:** This function seems to handle the `CondSelect` SSA operation, which is likely related to conditional expressions or ternary operators in Go. It rewrites this operation into an ARM64 `CSEL` (Conditional Select) instruction. The two cases suggest different ways of handling the boolean condition based on whether the boolean value is directly available as a flag.
- **`rewriteValueARM64_OpConst16` to `rewriteValueARM64_OpConstNil`:** These functions handle different constant value operations (`Const16`, `Const32`, etc.). They seem to be lowering these high-level constant representations into the ARM64 `MOVDconst` instruction.
- **`rewriteValueARM64_OpCtz16` to `rewriteValueARM64_OpCtz8`:** These functions implement the "count trailing zeros" operation for different integer sizes. They use a combination of ARM64 instructions like `CLZ` (Count Leading Zeros), `RBIT` (Reverse Bits), and `ORconst`.
- **`rewriteValueARM64_OpDiv16` to `rewriteValueARM64_OpDiv8u`:** These functions handle division operations for different integer sizes and signedness. They are lowered to ARM64 `DIVW` (Divide Word) and `UDIVW` (Unsigned Divide Word) instructions, potentially with sign or zero extension.
- **`rewriteValueARM64_OpEq16` to `rewriteValueARM64_OpEqPtr`:** These functions implement equality comparisons for various types. They use ARM64's `CMP` (Compare) or `FCMPS`/`FCMPD` (Floating-point Compare) instructions and then use the `Equal` condition code.
- **`rewriteValueARM64_OpFMA`:** This function handles the fused multiply-add operation, mapping it to the ARM64 `FMADDD` instruction.
- **`rewriteValueARM64_OpHmul32` and `rewriteValueARM64_OpHmul32u`:** These functions implement high multiplication (returning the upper half of the multiplication result). They use `MULL` (Multiply Long) or `UMULL` (Unsigned Multiply Long) followed by a right shift.
- **`rewriteValueARM64_OpIsInBounds` and `rewriteValueARM64_OpIsSliceInBounds`:** These functions check if an index is within the bounds of an array or slice. They are lowered to comparisons using `CMP` and then using `LessThanU` or `LessEqualU` condition codes.
- **`rewriteValueARM64_OpIsNonNil`:** This function checks if a pointer is not nil. It's implemented by comparing the pointer to zero.
- **`rewriteValueARM64_OpLeq16` to `rewriteValueARM64_OpLeq8U`:** These functions implement less than or equal to comparisons for various types. They involve comparisons and the `LessEqual` or `LessEqualU` condition codes.
- **`rewriteValueARM64_OpLess16` to `rewriteValueARM64_OpLess8U`:** These functions implement less than comparisons for various types. They involve comparisons and the `LessThan` or `LessThanU` condition codes.
- **`rewriteValueARM64_OpLoad`:** This function handles memory load operations. It selects the appropriate ARM64 load instruction (`MOVBload`, `MOVHload`, `MOVWload`, `MOVDload`, `FMOVSload`, `FMOVDload`) based on the data type being loaded.
- **`rewriteValueARM64_OpLocalAddr`:** This function retrieves the address of a local variable. It uses the `MOVDaddr` instruction, potentially with `SPanchored` for stack-allocated variables.
- **`rewriteValueARM64_OpLsh16x16` to `rewriteValueARM64_OpLsh32x16`:** These functions handle left shift operations for different operand sizes. They use the `SLL` (Shift Left Logical) instruction and handle cases where the shift amount might exceed the operand size using conditional selects (`CSEL`).
这是 `go/src/cmd/compile/internal/ssa/rewriteARM64.go` 文件的一部分，主要负责将 Go 语言的中间表示（SSA，Static Single Assignment）中与操作相关的节点，针对 ARM64 架构进行重写，以便更高效地映射到 ARM64 的指令集。

下面列举一下这段代码的功能：

1. **条件选择 (`OpCondSelect`) 的优化：**
    *   它试图将 `CondSelect` 操作（类似于三元运算符 `condition ? value1 : value2`）转换为 ARM64 的 `CSEL`（Conditional Select）指令。
    *   `CSEL` 指令可以根据条件标志的值，有条件地选择两个源寄存器中的一个作为结果。
    *   它区分了两种情况：
        *   如果条件值（`boolval`）可以直接作为标志（例如，来自比较指令的结果），则直接使用该标志。
        *   如果条件值不是直接的标志，则会使用 `TSTWconst [1]` 指令来测试该值是否为非零（即 true），并将结果作为条件标志。

2. **常量 (`OpConst...`) 的处理：**
    *   它将各种类型的常量（`Const16`, `Const32`, `Const32F`, `Const64`, `Const64F`, `Const8`, `ConstBool`, `ConstNil`) 转换为 ARM64 的 `MOVDconst` (Move Doubleword Constant) 或 `FMOVSconst`/`FMOVDconst` (Move Single/Double-precision Floating-point Constant) 指令。
    *   这是一种将 Go 语言中的常量值表示转换为 ARM64 架构下表示的方式。

3. **计算尾部零个数 (`OpCtz...`) 的实现：**
    *   它实现了计算整数尾部零个数的操作 (`Ctz16`, `Ctz32`, `Ctz64`, `Ctz8`)。
    *   它使用 ARM64 的 `CLZ` (Count Leading Zeros) 和 `RBIT` (Reverse Bits) 指令来实现。
    *   对于 16 位和 8 位的情况，它还会使用 `ORconst` 来确保最高位被置位，以便 `RBIT` 和 `CLZ` 能正确工作。

4. **除法运算 (`OpDiv...`) 的实现：**
    *   它实现了有符号和无符号的除法运算 (`Div16`, `Div16u`, `Div32`, `Div64`, `Div8`, `Div8u`)。
    *   它将 Go 语言的除法操作转换为 ARM64 的 `DIVW` (Divide Word) 或 `UDIVW` (Unsigned Divide Word) 指令。
    *   对于小于 32 位的除法，需要进行符号扩展或零扩展以匹配 `DIVW`/`UDIVW` 的操作数大小。

5. **相等比较 (`OpEq...`) 的实现：**
    *   它实现了各种类型值的相等比较 (`Eq16`, `Eq32`, `Eq32F`, `Eq64`, `Eq64F`, `Eq8`, `EqB`, `EqPtr`)。
    *   它使用 ARM64 的 `CMPW` (Compare Word), `CMP` (Compare), `FCMPS` (Float Compare Single-precision), `FCMPD` (Float Compare Double-precision) 指令进行比较，并通过 `Equal` 条件码来表示比较结果。
    *   对于布尔类型的相等比较 (`EqB`), 它使用了异或操作 (`XOR`) 和常量 `1` 来实现。

6. **融合乘法加法 (`OpFMA`) 的实现：**
    *   它将 Go 语言的融合乘法加法操作 (`FMA`) 转换为 ARM64 的 `FMADDD` (Floating-point Multiply-Add Double-precision) 指令。

7. **高位乘法 (`OpHmul32`, `OpHmul32u`) 的实现：**
    *   它实现了返回乘法结果高 32 位的操作。
    *   它使用 ARM64 的 `MULL` (Multiply Long) 或 `UMULL` (Unsigned Multiply Long) 指令进行 64 位乘法，然后使用 `SRAconst` (Shift Right Arithmetic Constant) 指令将结果右移 32 位。

8. **边界检查 (`OpIsInBounds`, `OpIsSliceInBounds`) 的实现：**
    *   它实现了检查索引是否在数组或切片边界内的操作。
    *   它使用 ARM64 的 `CMP` 指令进行比较，并使用 `LessThanU` (Less Than Unsigned) 或 `LessEqualU` (Less Than or Equal Unsigned) 条件码来表示结果。

9. **非空指针检查 (`OpIsNonNil`) 的实现：**
    *   它实现了检查指针是否为非空的操作。
    *   它使用 `CMPconst [0]` 指令将指针与常量 0 进行比较，并使用 `NotEqual` 条件码来表示结果。

10. **小于等于比较 (`OpLeq...`) 的实现：**
    *   它实现了各种类型的小于等于比较 (`Leq16`, `Leq16U`, `Leq32`, `Leq32F`, `Leq32U`, `Leq64`, `Leq64F`, `Leq64U`, `Leq8`, `Leq8U`)。
    *   它使用 ARM64 的 `CMPW`, `CMP`, `FCMPS`, `FCMPD` 指令进行比较，并通过 `LessEqual` 或 `LessEqualU` 条件码来表示比较结果。
    *   对于一些特殊情况（例如与 0 或 1 比较），会进行优化。

11. **小于比较 (`OpLess...`) 的实现：**
    *   它实现了各种类型的小于比较 (`Less16`, `Less16U`, `Less32`, `Less32F`, `Less32U`, `Less64`, `Less64F`, `Less64U`, `Less8`, `Less8U`)。
    *   它使用 ARM64 的 `CMPW`, `CMP`, `FCMPS`, `FCMPD` 指令进行比较，并通过 `LessThan` 或 `LessThanU` 条件码来表示比较结果。
    *   对于一些特殊情况（例如与 0 或 1 比较），会进行优化。

12. **加载 (`OpLoad`) 操作的实现：**
    *   它实现了从内存加载值的操作。
    *   它根据加载的数据类型 (`t`) 选择合适的 ARM64 加载指令，例如 `MOVBUload` (Move Byte Unsigned Load), `MOVBload` (Move Byte Load), `MOVHUload` (Move Halfword Unsigned Load), `MOVHload` (Move Halfword Load), `MOVWUload` (Move Word Unsigned Load), `MOVWload` (Move Word Load), `MOVDload` (Move Doubleword Load), `FMOVSload` (Float Move Single-precision Load), `FMOVDload` (Float Move Double-precision Load)。

13. **获取局部变量地址 (`OpLocalAddr`) 的实现：**
    *   它实现了获取局部变量地址的操作。
    *   它使用 `MOVDaddr` (Move Doubleword Address) 指令，并根据局部变量是否包含指针选择是否使用 `SPanchored` 操作。`SPanchored` 通常用于基于栈指针的寻址。

14. **左移 (`OpLsh...`) 操作的实现：**
    *   它实现了左移操作 (`Lsh16x16`, `Lsh16x32`, `Lsh16x64`, `Lsh16x8`, `Lsh32x16`)。
    *   它将 Go 语言的左移操作转换为 ARM64 的 `SLL` (Shift Left Logical) 指令。
    *   它会检查移位量是否超出范围 (`shiftIsBounded`)。如果超出范围，为了保证行为与 Go 语言规范一致（超出移位量的移位结果为 0），会使用 `CSEL` 指令进行条件选择。如果移位量小于 64，则执行 `SLL`，否则结果为 0。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码是 Go 编译器的一部分，负责将 Go 语言的各种操作符（算术、比较、逻辑等）和语言结构（例如常量、条件表达式）转换为 ARM64 汇编指令。 它涉及到：

*   **基本数据类型和操作：**  `int`, `int8`, `int16`, `int32`, `int64`, `uint`, `uint8`, `uint16`, `uint32`, `uint64`, `bool`, `float32`, `float64`, 指针等类型的常量表示和基本运算（加、减、乘、除、比较、位运算等）。
*   **控制流：** `CondSelect` 对应于 Go 语言中的条件表达式或某些 `if-else` 语句的优化。
*   **内存访问：** `Load` 和 `LocalAddr` 对应于 Go 语言中读取变量值和获取变量地址的操作。
*   **位运算：** `Ctz` 和 `Lsh` 对应于 Go 语言中的位操作符。

**Go 代码举例说明：**

```go
package main

func main() {
	// 条件选择
	a := 10
	b := 20
	max := 0
	if a > b {
		max = a
	} else {
		max = b
	}
	println(max)

	// 常量
	const pi float32 = 3.14
	println(pi)

	// 计算尾部零个数
	x := 8 // 二进制 1000
	count := ctz(uint(x))
	println(count) // 输出 3

	// 除法
	y := 15
	z := 3
	result := y / z
	println(result)

	// 相等比较
	p := 5
	q := 5
	isEqual := p == q
	println(isEqual)

	// 融合乘法加法
	var f1, f2, f3 float64 = 2.0, 3.0, 4.0
	fmaResult := f1*f2 + f3
	println(fmaResult)

	// 高位乘法 (Go 标准库没有直接提供，这里仅为示例概念)
	n1 := uint32(0xFFFFFFFF)
	n2 := uint32(0xFFFFFFFF)
	highBits := hmul32(n1, n2)
	println(highBits)

	// 边界检查
	arr := [5]int{1, 2, 3, 4, 5}
	index := 3
	if index >= 0 && index < len(arr) {
		println(arr[index])
	}

	// 非空指针检查
	var ptr *int
	if ptr != nil {
		println("ptr is not nil")
	} else {
		println("ptr is nil")
	}

	// 小于等于比较
	m := 10
	n := 10
	isLeq := m <= n
	println(isLeq)

	// 小于比较
	r := 5
	s := 7
	isLess := r < s
	println(isLess)

	// 加载 (通过访问变量)
	value := arr[0]
	println(value)

	// 获取局部变量地址
	addr := &value
	println(addr)

	// 左移
	val := 2 // 二进制 10
	shifted := val << 2
	println(shifted) // 输出 8，二进制 1000
}

// 模拟 ctz
func ctz(x uint) int {
	count := 0
	for x > 0 && x&1 == 0 {
		count++
		x >>= 1
	}
	return count
}

// 模拟高位乘法 (仅为示例)
func hmul32(x, y uint32) uint32 {
	result := uint64(x) * uint64(y)
	return uint32(result >> 32)
}
```

**假设的输入与输出（以 `rewriteBlockARM64_OpCondSelect` 为例）：**

**假设输入 SSA 代码片段:**

```
v1 = LessThan a b  // 假设 a 和 b 是整数
v2 = Val bool      // 某个布尔值
v3 = CondSelect x y v1
v4 = CondSelect p q v2
```

**对应 `rewriteBlockARM64_OpCondSelect` 处理 `v3` 的情况：**

*   **输入：** `v` 指向表示 `v3` 的 SSA Value，其操作为 `OpCondSelect`，参数为 `x`, `y`, `v1`。
*   **条件：** `flagArg(v1)` 返回一个非空的值，因为 `v1` 是一个比较操作的结果，可以直接作为条件标志。
*   **输出 SSA 代码修改：** `v3` 的操作被重置为 `OpARM64CSEL`，`AuxInt` 设置为 `OpARM64LessThan` (假设 `LessThan` 映射到这个 ARM64 操作码)，并添加参数 `x`, `y`, `v1`。

**对应 `rewriteBlockARM64_OpCondSelect` 处理 `v4` 的情况：**

*   **输入：** `v` 指向表示 `v4` 的 SSA Value，其操作为 `OpCondSelect`，参数为 `p`, `q`, `v2`。
*   **条件：** `flagArg(v2)` 返回 `nil`，因为 `v2` 可能不是一个直接产生标志的操作。
*   **输出 SSA 代码修改：** `v4` 的操作被重置为 `OpARM64CSEL`，`AuxInt` 设置为 `OpARM64NotEqual`，添加参数 `p`, `q` 和一个新的 `OpARM64TSTWconst` 节点，用于测试 `v2` 是否非零。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。它是 Go 编译器内部 SSA 优化的一部分。命令行参数的处理发生在编译器的其他阶段，例如词法分析、语法分析和类型检查等。

**使用者易犯错的点：**

作为编译器开发者，理解这些重写规则至关重要，以确保生成的 ARM64 代码的正确性和性能。 普通 Go 语言使用者不会直接与这些代码交互。

**总结一下它的功能：**

这段代码是 Go 编译器中针对 ARM64 架构的关键组成部分。它的主要功能是：

*   **将 Go 语言的通用中间表示 (SSA) 中的操作，转换为更接近 ARM64 硬件的指令序列。** 这包括条件选择、常量加载、算术运算、比较运算、位运算和内存访问等。
*   **进行特定于 ARM64 架构的优化。** 例如，利用 `CSEL` 指令进行条件选择，使用高效的指令序列实现位操作等。
*   **确保 Go 语言的语义在 ARM64 架构上得到正确实现。** 例如，处理移位操作的边界情况，进行正确的类型转换和扩展等。

总而言之，这段代码负责 Go 语言代码到 ARM64 机器码转换过程中的核心的、架构相关的优化和转换工作。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第14部分，共20部分，请归纳一下它的功能
```

### 源代码
```go
v.Block
	// match: (CondSelect x y boolval)
	// cond: flagArg(boolval) != nil
	// result: (CSEL [boolval.Op] x y flagArg(boolval))
	for {
		x := v_0
		y := v_1
		boolval := v_2
		if !(flagArg(boolval) != nil) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(boolval.Op)
		v.AddArg3(x, y, flagArg(boolval))
		return true
	}
	// match: (CondSelect x y boolval)
	// cond: flagArg(boolval) == nil
	// result: (CSEL [OpARM64NotEqual] x y (TSTWconst [1] boolval))
	for {
		x := v_0
		y := v_1
		boolval := v_2
		if !(flagArg(boolval) == nil) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64TSTWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(1)
		v0.AddArg(boolval)
		v.AddArg3(x, y, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueARM64_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueARM64_OpConst32F(v *Value) bool {
	// match: (Const32F [val])
	// result: (FMOVSconst [float64(val)])
	for {
		val := auxIntToFloat32(v.AuxInt)
		v.reset(OpARM64FMOVSconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueARM64_OpConst64(v *Value) bool {
	// match: (Const64 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt64(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueARM64_OpConst64F(v *Value) bool {
	// match: (Const64F [val])
	// result: (FMOVDconst [float64(val)])
	for {
		val := auxIntToFloat64(v.AuxInt)
		v.reset(OpARM64FMOVDconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueARM64_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueARM64_OpConstBool(v *Value) bool {
	// match: (ConstBool [t])
	// result: (MOVDconst [b2i(t)])
	for {
		t := auxIntToBool(v.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(t))
		return true
	}
}
func rewriteValueARM64_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVDconst [0])
	for {
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValueARM64_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz16 <t> x)
	// result: (CLZW <t> (RBITW <typ.UInt32> (ORconst <typ.UInt32> [0x10000] x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64CLZW)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64RBITW, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpARM64ORconst, typ.UInt32)
		v1.AuxInt = int64ToAuxInt(0x10000)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Ctz32 <t> x)
	// result: (CLZW (RBITW <t> x))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64CLZW)
		v0 := b.NewValue0(v.Pos, OpARM64RBITW, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpCtz64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Ctz64 <t> x)
	// result: (CLZ (RBIT <t> x))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64CLZ)
		v0 := b.NewValue0(v.Pos, OpARM64RBIT, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz8 <t> x)
	// result: (CLZW <t> (RBITW <typ.UInt32> (ORconst <typ.UInt32> [0x100] x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64CLZW)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64RBITW, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpARM64ORconst, typ.UInt32)
		v1.AuxInt = int64ToAuxInt(0x100)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 [false] x y)
	// result: (DIVW (SignExt16to32 x) (SignExt16to32 y))
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64DIVW)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (UDIVW (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64UDIVW)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div32 [false] x y)
	// result: (DIVW x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64DIVW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div64 [false] x y)
	// result: (DIV x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpARM64DIV)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (DIVW (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64DIVW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (UDIVW (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64UDIVW)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (Equal (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32 x y)
	// result: (Equal (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (Equal (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64 x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (Equal (FCMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (Equal (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (XOR (MOVDconst [1]) (XOR <typ.Bool> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64XOR)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpARM64XOR, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqPtr x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpFMA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMA x y z)
	// result: (FMADDD z x y)
	for {
		x := v_0
		y := v_1
		z := v_2
		v.reset(OpARM64FMADDD)
		v.AddArg3(z, x, y)
		return true
	}
}
func rewriteValueARM64_OpHmul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32 x y)
	// result: (SRAconst (MULL <typ.Int64> x y) [32])
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64SRAconst)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARM64MULL, typ.Int64)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpHmul32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32u x y)
	// result: (SRAconst (UMULL <typ.UInt64> x y) [32])
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64SRAconst)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARM64UMULL, typ.UInt64)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsInBounds idx len)
	// result: (LessThanU (CMP idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsNonNil ptr)
	// result: (NotEqual (CMPconst [0] ptr))
	for {
		ptr := v_0
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(0)
		v0.AddArg(ptr)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsSliceInBounds idx len)
	// result: (LessEqualU (CMP idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (LessEqual (CMPW (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x zero:(MOVDconst [0]))
	// result: (Eq16 x zero)
	for {
		x := v_0
		zero := v_1
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		v.reset(OpEq16)
		v.AddArg2(x, zero)
		return true
	}
	// match: (Leq16U (MOVDconst [1]) x)
	// result: (Neq16 (MOVDconst [0]) x)
	for {
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq16)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq16U x y)
	// result: (LessEqualU (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32 x y)
	// result: (LessEqual (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (LessEqualF (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualF)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32U x zero:(MOVDconst [0]))
	// result: (Eq32 x zero)
	for {
		x := v_0
		zero := v_1
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		v.reset(OpEq32)
		v.AddArg2(x, zero)
		return true
	}
	// match: (Leq32U (MOVDconst [1]) x)
	// result: (Neq32 (MOVDconst [0]) x)
	for {
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq32)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq32U x y)
	// result: (LessEqualU (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64 x y)
	// result: (LessEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (LessEqualF (FCMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualF)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64U x zero:(MOVDconst [0]))
	// result: (Eq64 x zero)
	for {
		x := v_0
		zero := v_1
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		v.reset(OpEq64)
		v.AddArg2(x, zero)
		return true
	}
	// match: (Leq64U (MOVDconst [1]) x)
	// result: (Neq64 (MOVDconst [0]) x)
	for {
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq64)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq64U x y)
	// result: (LessEqualU (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (LessEqual (CMPW (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x zero:(MOVDconst [0]))
	// result: (Eq8 x zero)
	for {
		x := v_0
		zero := v_1
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		v.reset(OpEq8)
		v.AddArg2(x, zero)
		return true
	}
	// match: (Leq8U (MOVDconst [1]) x)
	// result: (Neq8 (MOVDconst [0]) x)
	for {
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		x := v_1
		v.reset(OpNeq8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Leq8U x y)
	// result: (LessEqualU (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessEqualU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (LessThan (CMPW (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U zero:(MOVDconst [0]) x)
	// result: (Neq16 zero x)
	for {
		zero := v_0
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpNeq16)
		v.AddArg2(zero, x)
		return true
	}
	// match: (Less16U x (MOVDconst [1]))
	// result: (Eq16 x (MOVDconst [0]))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq16)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less16U x y)
	// result: (LessThanU (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32 x y)
	// result: (LessThan (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (LessThanF (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanF)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32U zero:(MOVDconst [0]) x)
	// result: (Neq32 zero x)
	for {
		zero := v_0
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpNeq32)
		v.AddArg2(zero, x)
		return true
	}
	// match: (Less32U x (MOVDconst [1]))
	// result: (Eq32 x (MOVDconst [0]))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq32)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less32U x y)
	// result: (LessThanU (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64 x y)
	// result: (LessThan (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (LessThanF (FCMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanF)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less64U zero:(MOVDconst [0]) x)
	// result: (Neq64 zero x)
	for {
		zero := v_0
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpNeq64)
		v.AddArg2(zero, x)
		return true
	}
	// match: (Less64U x (MOVDconst [1]))
	// result: (Eq64 x (MOVDconst [0]))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq64)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less64U x y)
	// result: (LessThanU (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (LessThan (CMPW (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThan)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U zero:(MOVDconst [0]) x)
	// result: (Neq8 zero x)
	for {
		zero := v_0
		if zero.Op != OpARM64MOVDconst || auxIntToInt64(zero.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpNeq8)
		v.AddArg2(zero, x)
		return true
	}
	// match: (Less8U x (MOVDconst [1]))
	// result: (Eq8 x (MOVDconst [0]))
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less8U x y)
	// result: (LessThanU (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpLoad(v *Value) bool {
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
		v.reset(OpARM64MOVBUload)
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
		v.reset(OpARM64MOVBload)
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
		v.reset(OpARM64MOVBUload)
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
		v.reset(OpARM64MOVHload)
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
		v.reset(OpARM64MOVHUload)
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
		v.reset(OpARM64MOVWload)
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
		v.reset(OpARM64MOVWUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (MOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpARM64MOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (FMOVSload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpARM64FMOVSload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (FMOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpARM64FMOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVDaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpARM64MOVDaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVDaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpARM64MOVDaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessT
```