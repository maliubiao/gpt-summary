Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Context:**

The prompt clearly states this is part of `go/src/cmd/compile/internal/ssa/rewritePPC64.go`. This immediately tells us several crucial things:

* **Compiler Internals:** This code is part of the Go compiler, specifically dealing with the Static Single Assignment (SSA) intermediate representation.
* **Architecture Specific:** The `PPC64` in the filename indicates this code is for the 64-bit PowerPC architecture.
* **Rewriting Rules:** The structure of the code, with `rewriteValuePPC64_Op...` functions, strongly suggests these are rewrite rules. These rules are used during the compilation process to transform SSA operations into more efficient or architecture-specific sequences of operations.

**2. Analyzing the Function Signatures:**

Each function has the signature `func rewriteValuePPC64_Op<Operation>(v *Value) bool`. This tells us:

* **Input:** The function takes a pointer to a `Value` as input. In SSA, a `Value` represents the result of an operation.
* **Output:** The function returns a boolean. This likely indicates whether a rewrite rule was successfully applied (`true`) or not (`false`).
* **Operation Specificity:** The `Op<Operation>` part denotes the specific SSA operation this function handles (e.g., `OpRsh16Ux64` for a right shift of a 16-bit unsigned integer by a 64-bit integer).

**3. Deconstructing a Single Rewrite Rule (Example: `rewriteValuePPC64_OpRsh16Ux64`):**

Let's take the first function as an example and dissect its structure:

```go
func rewriteValuePPC64_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 16
	// result: (SRWconst (ZeroExt16to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// ... other match clauses ...
}
```

* **Argument Extraction:** `v_1 := v.Args[1]` and `v_0 := v.Args[0]` extract the arguments of the `Rsh16Ux64` operation. We assume that the first argument (`v_0`) is the value being shifted, and the second (`v_1`) is the shift amount.
* **Block and Types:** `b := v.Block` and `typ := &b.Func.Config.Types` get the current basic block and the type information, which are often needed for creating new SSA values.
* **`// match:` Comment:** This is a pattern matching the input SSA structure. `(Rsh16Ux64 x (MOVDconst [c]))` means it's looking for an `Rsh16Ux64` operation where the right operand is a constant (`MOVDconst`).
* **`// cond:` Comment:** This specifies a condition that must be true for the rewrite to apply. `uint64(c) < 16` means the constant shift amount must be less than 16.
* **`// result:` Comment:** This describes the new SSA operation(s) to replace the original one. `(SRWconst (ZeroExt16to32 x) [c])` indicates it will be replaced by a `SRWconst` (Shift Right Word Constant) operation. It also shows a `ZeroExt16to32` operation being applied to the left operand.
* **`for {}` Loop:** This suggests the function tries multiple rewrite rules within it. If a match and condition are met, the rewrite is performed, and the function returns `true`.
* **`v.reset(...)`:** This changes the opcode of the original `Value` (`v`).
* **`v.AuxInt = ...`:** This sets auxiliary integer data associated with the operation (often used for constants).
* **`b.NewValue0(...)`:** This creates a new SSA `Value`.
* **`v.AddArg(...)` and `v.AddArg2(...)`:** These add arguments to the SSA operation.

**4. Generalizing the Observations:**

By examining multiple `rewriteValuePPC64_Op...` functions, we can see a consistent pattern:

* **Optimization Focus:**  Many rules aim to optimize shift operations based on the shift amount (constant or variable) and the data type.
* **Architecture-Specific Instructions:** The target of the rewrites is often specific PPC64 instructions like `SRW`, `SRD`, `SRAD`, `SRWconst`, `SRADconst`, `ISEL`, and register moves like `MOVHZreg`, `MOVHreg`, `MOVBZreg`, `MOVBreg`.
* **Conditional Rewrites:**  The `cond` comments highlight the conditions under which a particular rewrite is beneficial. This is key to ensuring correctness and efficiency.
* **Handling of Constants:** Special cases are often implemented for shifts by constant amounts, allowing the use of more efficient "constant shift" instructions.
* **Type Conversions:**  Operations like `ZeroExt16to32` and `SignExt16to32` are used to adjust the size or signedness of values as needed by the target instructions.
* **`ISEL` Instruction:** The `ISEL` instruction appears frequently. This is a conditional select instruction on PowerPC, allowing the compiler to implement certain operations without explicit branching.

**5. Inferring Go Language Features (Rsh Example):**

The `OpRsh...` functions clearly relate to right-shift operations in Go. The different suffixes (e.g., `16Ux64`, `32x32`) indicate the data types involved.

* **Unsigned Right Shift (`>>` with unsigned types):**  Functions like `rewriteValuePPC64_OpRsh16Ux64` handle unsigned right shifts.
* **Signed Right Shift (`>>` with signed types):** Functions like `rewriteValuePPC64_OpRsh16x64` handle signed right shifts (arithmetic shift).

**6. Inferring Go Language Features (Other Operations):**

While the provided snippet mainly focuses on right shifts, the presence of comments like `// match: (ANDconst [0x00F0] y)` and the use of `OpPPC64ANDconst` suggest this file also deals with bitwise AND operations and potentially other bitwise operations.

**7. Considering the Larger Picture:**

Knowing this is part of the compiler, these rewrite rules play a vital role in:

* **Performance:** Selecting the most efficient machine instructions for common Go operations on PPC64.
* **Correctness:** Ensuring that Go semantics are preserved when translating to machine code.
* **Code Generation:**  Providing a structured way to map higher-level operations to lower-level instructions.

By following this detailed thought process, we can systematically understand the purpose and functionality of the provided Go code snippet within the context of the Go compiler. The key is to combine the specific details of the code with general knowledge about compilers, intermediate representations, and target architectures.
这是 `go/src/cmd/compile/internal/ssa/rewritePPC64.go` 文件的一部分，主要负责 **PPC64 架构下的 SSA (Static Single Assignment) 中间表示的重写规则**。

**功能归纳:**

这个代码片段定义了一系列的 `rewriteValuePPC64_Op...` 函数，这些函数实现了针对特定 SSA 操作码 (`Op`) 的重写规则。其核心功能是将通用的 SSA 操作转换为更具体、更高效的 PPC64 汇编指令序列。  这部分主要关注 **右移操作 (Right Shift)** 的优化和转换。

**具体功能分解:**

这段代码针对 Go 语言的右移操作 (`>>`) 提供了多种重写规则，涵盖了不同大小和有无符号的整数类型，以及不同的移位量来源 (常量或变量)。  主要目标是通过模式匹配和条件判断，将通用的右移操作转换为更优的 PPC64 指令，例如：

* **常量移位优化:** 当移位量是常量时，会尝试使用 PPC64 的常量移位指令 (例如 `SRWconst`, `SRDconst`, `SRAWconst`)，这通常比使用变量移位指令更高效。
* **小立即数优化:** 对于一些小范围的常量移位，可以直接嵌入到指令中。
* **有符号/无符号移位:** 区分有符号数和无符号数的右移，使用不同的 PPC64 指令 (`SRW`, `SRD` 用于无符号，`SRAW`, `SRAD` 用于有符号)。
* **类型转换与扩展:**  在进行移位操作前，可能需要对操作数进行类型扩展 (例如 `ZeroExt`, `SignExt`)，以匹配 PPC64 指令的要求。
* **使用条件选择指令 (`ISEL`):**  对于一些边界情况，会使用 PPC64 的条件选择指令 `ISEL` 来避免分支，提高效率。例如，当移位量可能超出有效范围时，可以使用 `ISEL` 来选择移位结果或直接返回 0。
* **寄存器操作:**  根据操作数的大小，选择合适的寄存器操作指令，例如 `MOVHreg`, `MOVBreg`, `MOVHZreg`, `MOVBZreg` 等，用于将数据加载到寄存器中。

**Go 语言功能实现推断与代码示例:**

这段代码主要实现了 Go 语言的 **位运算中的右移操作 (`>>`)**。

```go
package main

import "fmt"

func main() {
	var unsigned16 uint16 = 256  // 二进制: 00000001 00000000
	var signed16 int16 = -256    // 二进制补码 (假设): 11111110 00000000
	var shiftAmount uint64 = 4

	// 无符号右移
	resultUnsigned := unsigned16 >> shiftAmount
	fmt.Printf("无符号右移: %d >> %d = %d\n", unsigned16, shiftAmount, resultUnsigned) // Output: 无符号右移: 256 >> 4 = 16

	// 有符号右移
	resultSigned := signed16 >> shiftAmount
	fmt.Printf("有符号右移: %d >> %d = %d\n", signed16, shiftAmount, resultSigned)   // Output: 有符号右移: -256 >> 4 = -16 (算术右移，高位补符号位)

	var unsigned8 uint8 = 100
	resultUnsigned8 := unsigned8 >> 2
	fmt.Printf("无符号右移 uint8: %d >> %d = %d\n", unsigned8, 2, resultUnsigned8) // Output: 无符号右移 uint8: 100 >> 2 = 25
}
```

**代码推理与假设的输入输出:**

以 `rewriteValuePPC64_OpRsh16Ux64` 中的一个 match 为例：

```go
	// match: (Rsh16Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 16
	// result: (SRWconst (ZeroExt16to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
```

**假设输入:**

* `v` 是一个代表 `uint16` 类型的值右移 `uint64` 类型常量值的 SSA `Value`。
* `v_0` (即 `x`) 代表要进行右移的 `uint16` 类型的 SSA `Value`。假设其值为 `256`。
* `v_1` 代表移位量的 SSA `Value`，其 `Op` 是 `OpPPC64MOVDconst`，表示一个 64 位常量。
* `v_1.AuxInt` 代表常量值，假设为 `4`。

**推理过程:**

1. 代码首先检查 `v_1` 是否是 64 位常量 (`OpPPC64MOVDconst`)。
2. 然后获取常量值 `c`，这里 `c` 为 `4`。
3. 接着判断常量值 `c` 是否小于 16 (`uint64(4) < 16`)，条件成立。
4. 如果条件成立，则将当前的右移操作 `v` 重置为 `OpPPC64SRWconst` (PPC64 的 32 位常量右移指令)。
5. 将常量移位量 `c` 设置到 `v` 的 `AuxInt` 中。
6. 创建一个新的 SSA `Value` (`v0`)，表示将 `x` (即 `v_0`) 进行零扩展，将其从 16 位扩展到 32 位 (`OpZeroExt16to32`)。 这是因为 `SRWconst` 通常操作 32 位寄存器。
7. 将零扩展后的值 `v0` 添加为 `OpPPC64SRWconst` 操作的参数。
8. 函数返回 `true`，表示重写规则已应用。

**假设输出 (SSA 表示):**

原始的 SSA 指令可能是类似：

```
v10 = Rsh16Ux64 v8, v9
```
其中 `v8` 代表 `unsigned16` 的值， `v9` 代表常量 `4`。

经过重写后，SSA 指令会变成类似：

```
v10 = SRWconst (ZeroExt16to32 v8), [4]
```

**命令行参数处理:**

这段代码本身不直接处理命令行参数。`rewritePPC64.go` 文件是 Go 编译器的内部实现，它在编译过程中被调用。 编译器的命令行参数（例如 `-gcflags` 等）可能会影响到编译过程和最终生成的代码，但这段代码本身并不解析这些参数。

**易犯错的点 (使用者角度):**

从使用 Go 语言的角度来看，开发者在使用右移操作时需要注意以下几点，这些也是这段代码尝试正确处理的地方：

* **有符号 vs. 无符号:**  对有符号数进行右移是算术右移（高位补符号位），对无符号数进行右移是逻辑右移（高位补 0）。Go 语言会根据变量的类型自动处理，但理解其背后的机制很重要。
* **移位量超出范围:**  如果移位量大于或等于被移位值的位数，其行为在不同语言和架构上可能有所不同。Go 语言规范定义了其行为，编译器会尝试生成正确的代码。例如，对于 `uint16 >> 16`，结果将为 `0`。  代码中的 `ISEL` 指令就是用来处理这类情况的。
* **类型转换:**  在进行位运算前，可能需要显式或隐式地进行类型转换，以避免意外的结果。例如，将一个 `int8` 的值右移一个 `uint64` 的值。

**总结本部分功能 (第 10 部分，共 12 部分):**

作为 `rewritePPC64.go` 的一部分，这段代码专注于 **优化 PPC64 架构下的右移操作**。它通过模式匹配和条件判断，将通用的 Go 语言右移操作转换为更高效的 PPC64 汇编指令，包括常量移位、有符号/无符号移位的区分、以及对移位量边界情况的处理。  这部分是编译器后端代码生成和优化的重要组成部分，旨在提升在 PPC64 架构上运行的 Go 程序的性能。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第10部分，共12部分，请归纳一下它的功能

"""
Func.Config.Types
	// match: (Rsh16Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 16
	// result: (SRWconst (ZeroExt16to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux64 <t> x y)
	// result: (ISEL [0] (SRD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux8 <t> x y)
	// result: (ISEL [2] (SRD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00F0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0x00F0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x16 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVHreg x) y) (SRADconst <t> (MOVHreg x) [15]) (CMPconst [0] (ANDconst [0xFFF0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(15)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x32 <t> x y)
	// result: (ISEL [0] (SRAD <t> (MOVHreg x) y) (SRADconst <t> (MOVHreg x) [15]) (CMPWUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(15)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 x (MOVDconst [c]))
	// cond: uint64(c) >= 16
	// result: (SRAWconst (SignExt16to32 x) [63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16x64 x (MOVDconst [c]))
	// cond: uint64(c) < 16
	// result: (SRAWconst (SignExt16to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x64 <t> x y)
	// result: (ISEL [0] (SRAD <t> (MOVHreg x) y) (SRADconst <t> (MOVHreg x) [15]) (CMPUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(15)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVHreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVHreg x) y) (SRADconst <t> (MOVHreg x) [15]) (CMPconst [0] (ANDconst [0x00F0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(15)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0x00F0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux16 <t> x y)
	// result: (ISEL [2] (SRW <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFE0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFE0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux32 <t> x y)
	// result: (ISEL [0] (SRW <t> x y) (MOVDconst [0]) (CMPWUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 32
	// result: (SRWconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Rsh32Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux64 <t> x y)
	// result: (ISEL [0] (SRW <t> x y) (MOVDconst [0]) (CMPUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32Ux8 <t> x y)
	// result: (ISEL [2] (SRW <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00E0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00E0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x16 <t> x y)
	// result: (ISEL [2] (SRAW <t> x y) (SRAWconst <t> x [31]) (CMPconst [0] (ANDconst [0xFFE0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRAWconst, t)
		v1.AuxInt = int64ToAuxInt(31)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFE0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x32 <t> x y)
	// result: (ISEL [0] (SRAW <t> x y) (SRAWconst <t> x [31]) (CMPWUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRAWconst, t)
		v1.AuxInt = int64ToAuxInt(31)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x64 x (MOVDconst [c]))
	// cond: uint64(c) >= 32
	// result: (SRAWconst x [63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 32) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	// match: (Rsh32x64 x (MOVDconst [c]))
	// cond: uint64(c) < 32
	// result: (SRAWconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Rsh32x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x64 <t> x y)
	// result: (ISEL [0] (SRAW <t> x y) (SRAWconst <t> x [31]) (CMPUconst y [32]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRAWconst, t)
		v1.AuxInt = int64ToAuxInt(31)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAW x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh32x8 <t> x y)
	// result: (ISEL [2] (SRAW <t> x y) (SRAWconst <t> x [31]) (CMPconst [0] (ANDconst [0x00E0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAW, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRAWconst, t)
		v1.AuxInt = int64ToAuxInt(31)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00E0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux16 <t> x y)
	// result: (ISEL [2] (SRD <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFC0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFC0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux32 <t> x y)
	// result: (ISEL [0] (SRD <t> x y) (MOVDconst [0]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 64
	// result: (SRDconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 64) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Rsh64Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux64 <t> x y)
	// result: (ISEL [0] (SRD <t> x y) (MOVDconst [0]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux8 <t> x y)
	// result: (ISEL [2] (SRD <t> x y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00C0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00C0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x16 <t> x y)
	// result: (ISEL [2] (SRAD <t> x y) (SRADconst <t> x [63]) (CMPconst [0] (ANDconst [0xFFC0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v1.AuxInt = int64ToAuxInt(63)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0xFFC0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x32 <t> x y)
	// result: (ISEL [0] (SRAD <t> x y) (SRADconst <t> x [63]) (CMPWUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v1.AuxInt = int64ToAuxInt(63)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x64 x (MOVDconst [c]))
	// cond: uint64(c) >= 64
	// result: (SRADconst x [63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	// match: (Rsh64x64 x (MOVDconst [c]))
	// cond: uint64(c) < 64
	// result: (SRADconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 64) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Rsh64x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x64 <t> x y)
	// result: (ISEL [0] (SRAD <t> x y) (SRADconst <t> x [63]) (CMPUconst y [64]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v1.AuxInt = int64ToAuxInt(63)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> x y) (SRADconst <t> x [63]) (CMPconst [0] (ANDconst [0x00C0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v1.AuxInt = int64ToAuxInt(63)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v3.AuxInt = int64ToAuxInt(0x00C0)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValuePPC64_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux16 <t> x y)
	// result: (ISEL [2] (SRD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFF8] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux32 <t> x y)
	// result: (ISEL [0] (SRD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPWUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 x (MOVDconst [c]))
	// cond: uint64(c) < 8
	// result: (SRWconst (ZeroExt8to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux64 <t> x y)
	// result: (ISEL [0] (SRD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVBZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux8 <t> x y)
	// result: (ISEL [2] (SRD <t> (MOVBZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00F8] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0x00F8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x16 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPconst [0] (ANDconst [0xFFF8] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(7)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x32 <t> x y)
	// result: (ISEL [0] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPWUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(7)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 x (MOVDconst [c]))
	// cond: uint64(c) >= 8
	// result: (SRAWconst (SignExt8to32 x) [63])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 8) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8x64 x (MOVDconst [c]))
	// cond: uint64(c) < 8
	// result: (SRAWconst (SignExt8to32 x) [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x64 <t> x y)
	// result: (ISEL [0] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPUconst y [8]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(7)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(8)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SRAD (MOVBreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRAD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		
"""




```