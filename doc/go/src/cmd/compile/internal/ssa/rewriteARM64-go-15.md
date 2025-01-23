Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Task:** The request asks for a summary of the functionality of the provided Go code snippet, which is part of the ARM64 backend for the Go compiler. It also asks for examples, potential errors, and a broader overview of the file's purpose within the larger compiler context.

2. **Analyze the Code Structure:** I notice the code consists of several Go functions named `rewriteValueARM64_Op...`. This naming convention strongly suggests that these functions are part of a rewriting pass in the compiler. The input to each function is a `*Value`, which represents an intermediate representation (IR) node in the compiler's SSA form. The return value is a boolean, indicating whether a rewrite was performed.

3. **Deconstruct Individual Functions:** I go through each function and identify its specific purpose:
    * **`rewriteValueARM64_OpOffPtr`:**  This function handles the `OpOffPtr` operation. It checks if the offset fits within a 32-bit immediate and uses `MOVDaddr` if it does, otherwise, it uses `ADDconst`. This strongly suggests optimization of address calculations.
    * **`rewriteValueARM64_OpPanicBounds`:** This function rewrites `OpPanicBounds` based on the `boundsABI` value. This points to different strategies for handling array bounds checks, potentially for performance reasons or compatibility.
    * **`rewriteValueARM64_OpPopCount*`:** These functions implement population count (counting set bits) for different integer sizes using floating-point instructions. This is a common optimization technique on architectures with efficient floating-point units.
    * **`rewriteValueARM64_OpPrefetchCache` and `rewriteValueARM64_OpPrefetchCacheStreamed`:**  These functions translate Go's prefetch operations to the corresponding ARM64 `PRFM` instruction, indicating support for memory prefetching.
    * **`rewriteValueARM64_OpPubBarrier`:** This translates Go's public memory barrier to the ARM64 `DMB` instruction, demonstrating support for memory synchronization primitives.
    * **`rewriteValueARM64_OpRotateLeft*`:** These functions implement left bit rotation using a combination of shifts and OR operations or the dedicated `ROR` instruction, optimizing rotation operations. The constant rotation case is handled specially.
    * **`rewriteValueARM64_OpRsh*x*`:** This large set of functions handles right bit shifts (both signed and unsigned) for various operand sizes. They implement bounded shifts using direct `SRL` or `SRA` instructions and unbounded shifts using conditional selects (`CSEL`) to handle cases where the shift amount is greater than or equal to the operand size. This is crucial for correct and efficient shift operations.

4. **Identify Common Patterns:** I observe recurring patterns:
    * **Pattern Matching:**  Each function starts with a `match:` comment describing the IR pattern being targeted.
    * **Conditional Rewriting:**  Rewrites are often performed based on conditions (e.g., the size of an immediate, whether a shift is bounded).
    * **Introduction of ARM64-Specific Instructions:**  The rewrites generally involve replacing generic Go IR operations with more specific ARM64 instructions.
    * **Use of `AuxInt` and `Aux`:** These fields of the `Value` struct are used to store additional information, such as immediate values or types.

5. **Infer the Overall Functionality of the File:** Based on the individual function analyses, I conclude that `rewriteARM64.go` is responsible for a crucial stage in the Go compilation process for the ARM64 architecture: **converting the architecture-independent intermediate representation (SSA) of Go code into a form that directly maps to ARM64 instructions.** This involves instruction selection, optimization, and handling architecture-specific details.

6. **Construct Examples and Explanations:**  I choose a few representative functions to illustrate the rewriting process with Go code examples, hypothetical inputs, and outputs. I focus on examples that clearly show the transformation happening. For instance, the `OpOffPtr` example demonstrates how address calculations are optimized. The `OpPanicBounds` example showcases the handling of different bounds check strategies. The `OpRotateLeft` examples illustrate both constant and variable rotation implementations. The `OpRsh` examples highlight the bounded vs. unbounded shift handling.

7. **Address Potential Pitfalls:** I consider common mistakes users might make when dealing with shifts, especially the behavior of shifts when the shift amount is out of bounds. This leads to the explanation of bounded and unbounded shifts and how the code handles these cases.

8. **Synthesize a Summary:** Finally, I combine all the observations and analyses into a concise summary of the file's functionality, emphasizing its role in the code generation pipeline for ARM64. I highlight the key aspects like instruction selection, optimization, and architecture-specific handling. I also emphasize that this file contributes to the efficiency and correctness of Go code on ARM64.

9. **Review and Refine:** I reread my answer to ensure clarity, accuracy, and completeness, making sure all parts of the original request are addressed. I pay attention to the constraints like using Chinese and explicitly mentioning it's part 16 of 20.
这是一个Go语言源文件 `go/src/cmd/compile/internal/ssa/rewriteARM64.go` 的第16部分，它主要的功能是**定义了一系列的重写规则 (rewrite rules)，用于将 Go 语言的通用中间表示 (SSA - Static Single Assignment) 转换为更具体的 ARM64 架构的 SSA 指令。**

换句话说，这个文件是 Go 编译器中针对 ARM64 架构的后端代码生成部分，负责将高级的、平台无关的操作转换为 ARM64 处理器能够直接执行的指令序列。  这些重写规则通常是为了：

* **指令选择 (Instruction Selection):**  将通用的操作映射到最合适的 ARM64 指令。
* **性能优化 (Performance Optimization):**  利用 ARM64 架构的特性进行优化，例如使用特定的指令组合或寻址模式。
* **处理架构差异 (Handling Architecture Differences):**  解决 Go 语言抽象操作和底层硬件指令之间的差异。

**功能归纳 (针对提供的代码片段):**

从提供的代码片段来看，这个文件的第16部分主要关注以下几种操作的重写：

1. **`OpOffPtr` (偏移指针):**  将计算指针偏移的操作转换为 ARM64 的 `MOVDaddr` (如果偏移量是小的立即数) 或 `ADDconst` 指令。这是对指针算术的优化。
2. **`OpPanicBounds` (边界检查失败时的 panic):**  根据不同的 `boundsABI` (边界检查的 ABI 约定)，将其转换为不同的 ARM64 的 `LoweredPanicBoundsA/B/C` 指令。这表明 Go 编译器可能支持多种边界检查策略。
3. **`OpPopCount16/32/64` (统计二进制表示中 1 的个数):**  使用一系列 ARM64 的浮点和向量指令 (`FMOVDfpgp`, `VUADDLV`, `VCNT`, `FMOVDgpfp`, `ZeroExt...to64`) 来高效地实现位计数。这是一种利用硬件加速的优化技巧。
4. **`OpPrefetchCache` 和 `OpPrefetchCacheStreamed` (预取数据到缓存):**  将 Go 的预取操作转换为 ARM64 的 `PRFM` (Prefetch Memory) 指令。
5. **`OpPubBarrier` (公共内存屏障):**  将 Go 的公共内存屏障操作转换为 ARM64 的 `DMB` (Data Memory Barrier) 指令，用于确保内存操作的顺序性。
6. **`OpRotateLeft16/32/64/8` (循环左移):**  将循环左移操作转换为 ARM64 的 `Or16/8` (配合 `Lsh` 和 `Rsh`) 或 `RORW/ROR` (Rotate Right) 指令，以及可能的 `NEG` (取反) 操作。对常量移位和变量移位使用了不同的策略。
7. **`OpRsh...` (右移，包括逻辑右移和算术右移):**  针对不同大小的无符号和有符号整数的右移操作，根据移位量是否超出范围 (`shiftIsBounded`)，选择使用 `SRL` (Shift Right Logical), `SRA` (Shift Right Arithmetic) 或 `CSEL` (Conditional Select) 指令结合 `SRL/SRA` 或常量 0/最大值来实现。  这部分代码非常详细地处理了移位操作的各种情况，包括边界处理。

**Go 语言功能实现示例 (代码推理):**

我们可以推断出这些代码正在实现 Go 语言中的以下功能：

* **指针运算:**  `OpOffPtr` 对应于 Go 中的指针加法操作，例如 `ptr + offset`。
* **数组/切片边界检查:** `OpPanicBounds` 与 Go 运行时中发生的数组或切片越界访问时的 panic 机制相关。
* **位操作:** `OpPopCount` 对应于 Go 标准库 `math/bits` 包中的位计数函数，例如 `bits.OnesCount16(x)`。
* **内存预取:** `OpPrefetchCache` 和 `OpPrefetchCacheStreamed` 可能对应于一些底层的、不常用的 Go 语言特性，或者编译器自动插入的优化。
* **并发/同步原语:** `OpPubBarrier` 与 Go 的并发机制中的内存同步操作有关，例如在某些情况下确保共享变量的可见性。
* **位运算:** `OpRotateLeft` 和 `OpRsh` 对应于 Go 语言中的左移 `<<` 和右移 `>>` 操作。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"math/bits"
	"unsafe"
)

func main() {
	// 指针运算
	arr := [5]int{1, 2, 3, 4, 5}
	ptr := &arr[0]
	offset := 2
	newPtr := unsafe.Pointer(uintptr(ptr) + uintptr(offset)*unsafe.Sizeof(arr[0]))
	fmt.Println(*(*int)(newPtr)) // 输出: 3

	// 数组边界检查 (会导致 panic)
	// _ = arr[10]

	// 位计数
	x := uint16(0b1011010011110001)
	count := bits.OnesCount16(x)
	fmt.Println("Number of set bits:", count) // 输出: Number of set bits: 11

	// 位运算 (循环左移)
	y := uint8(0b00010000)
	rotatedY := y<<2 | y>>(8-2) // 模拟循环左移 2 位
	fmt.Printf("Original: %b, Rotated: %b\n", y, rotatedY) // 输出: Original: 10000, Rotated: 1000000

	// 位运算 (右移)
	z := int16(-16)
	unsignedRightShift := uint16(z) >> 2
	signedRightShift := z >> 2
	fmt.Printf("Original: %b, Unsigned Right Shift: %b, Signed Right Shift: %b\n", z, unsignedRightShift, signedRightShift)

	// 内存预取 (实际使用中可能需要更底层的库)
	// var val int
	// runtime.prefetch(&val, 0) // 假设有这样的接口
}
```

**假设的输入与输出 (针对 `OpOffPtr`):**

假设 SSA 中有以下表示指针偏移的操作：

**输入 (SSA Value `v`):**
* `v.Op` = `OpOffPtr`
* `v.AuxInt` = 8 (偏移量)
* `v.Args[0]` 指向一个基地址 (例如，一个局部变量的地址)

**输出 (如果偏移量适合 `MOVDaddr`):**
* `v.Op` 会被重置为 `OpARM64MOVDaddr`
* `v.AuxInt` 会被设置为 8
* `v.Args[0]` 仍然是基地址

**输出 (如果偏移量不适合 `MOVDaddr`):**
* `v.Op` 会被重置为 `OpARM64ADDconst`
* `v.AuxInt` 会被设置为 8
* `v.Args[0]` 仍然是基地址

**命令行参数的具体处理:**

这个代码片段本身不直接处理命令行参数。 命令行参数的处理通常发生在编译器的前端和主控流程中。 `rewriteARM64.go` 文件中的代码是在 SSA 生成之后、机器码生成之前执行的，它专注于代码转换和优化。  与 ARM64 架构相关的命令行参数可能会影响到编译器的目标架构选择和一些优化选项，但这些参数的处理逻辑不会在这个文件中。

**使用者易犯错的点 (以右移操作为例):**

* **有符号数和无符号数的右移:**  在 Go 语言中，有符号数的右移是算术右移 (高位补符号位)，而无符号数的右移是逻辑右移 (高位补 0)。  初学者可能会混淆这两种行为，尤其是在进行位操作时。 `rewriteARM64.go` 中的代码通过 `SRA` 和 `SRL` 指令区分了这两种右移，确保了 Go 语言语义的正确实现。
* **移位量超出范围:**  在很多编程语言中，如果移位量大于或等于操作数的位数，其行为是未定义的或会得到意想不到的结果。 Go 语言规范定义了移位操作的行为，`rewriteARM64.go` 中针对 `!shiftIsBounded(v)` 的处理就是为了确保即使移位量超出范围，也能得到符合 Go 规范的结果 (例如，无符号右移结果为 0，有符号右移结果为全 0 或全 1)。

**总结 `rewriteARM64.go` 的功能 (基于提供的部分和推断):**

总而言之，`go/src/cmd/compile/internal/ssa/rewriteARM64.go` 文件的主要功能是**将 Go 语言的 SSA 中间表示转换为 ARM64 架构特定的 SSA 指令，以便后续的代码生成阶段可以生成高效的 ARM64 机器码**。  它通过定义一系列的重写规则，针对不同的 Go 语言操作，选择合适的 ARM64 指令，并进行架构相关的优化和边界处理，确保 Go 程序在 ARM64 架构上的正确性和性能。 提供的第16部分主要关注指针运算、边界检查、位计数、内存预取、内存屏障和移位操作的转换和优化。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第16部分，共20部分，请归纳一下它的功能
```

### 源代码
```go
eak
		}
		v.reset(OpARM64MOVDaddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// result: (ADDconst [off] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(off)
		v.AddArg(ptr)
		return true
	}
}
func rewriteValueARM64_OpPanicBounds(v *Value) bool {
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
		v.reset(OpARM64LoweredPanicBoundsA)
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
		v.reset(OpARM64LoweredPanicBoundsB)
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
		v.reset(OpARM64LoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpPopCount16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount16 <t> x)
	// result: (FMOVDfpgp <t> (VUADDLV <typ.Float64> (VCNT <typ.Float64> (FMOVDgpfp <typ.Float64> (ZeroExt16to64 x)))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64FMOVDfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64VUADDLV, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpARM64VCNT, typ.Float64)
		v2 := b.NewValue0(v.Pos, OpARM64FMOVDgpfp, typ.Float64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(x)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpPopCount32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount32 <t> x)
	// result: (FMOVDfpgp <t> (VUADDLV <typ.Float64> (VCNT <typ.Float64> (FMOVDgpfp <typ.Float64> (ZeroExt32to64 x)))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64FMOVDfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64VUADDLV, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpARM64VCNT, typ.Float64)
		v2 := b.NewValue0(v.Pos, OpARM64FMOVDgpfp, typ.Float64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(x)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpPopCount64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount64 <t> x)
	// result: (FMOVDfpgp <t> (VUADDLV <typ.Float64> (VCNT <typ.Float64> (FMOVDgpfp <typ.Float64> x))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64FMOVDfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64VUADDLV, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpARM64VCNT, typ.Float64)
		v2 := b.NewValue0(v.Pos, OpARM64FMOVDgpfp, typ.Float64)
		v2.AddArg(x)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpPrefetchCache(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PrefetchCache addr mem)
	// result: (PRFM [0] addr mem)
	for {
		addr := v_0
		mem := v_1
		v.reset(OpARM64PRFM)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg2(addr, mem)
		return true
	}
}
func rewriteValueARM64_OpPrefetchCacheStreamed(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PrefetchCacheStreamed addr mem)
	// result: (PRFM [1] addr mem)
	for {
		addr := v_0
		mem := v_1
		v.reset(OpARM64PRFM)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg2(addr, mem)
		return true
	}
}
func rewriteValueARM64_OpPubBarrier(v *Value) bool {
	v_0 := v.Args[0]
	// match: (PubBarrier mem)
	// result: (DMB [0xe] mem)
	for {
		mem := v_0
		v.reset(OpARM64DMB)
		v.AuxInt = int64ToAuxInt(0xe)
		v.AddArg(mem)
		return true
	}
}
func rewriteValueARM64_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVDconst [c]))
	// result: (Or16 (Lsh16x64 <t> x (MOVDconst [c&15])) (Rsh16Ux64 <t> x (MOVDconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v3 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (RotateLeft16 <t> x y)
	// result: (RORW <t> (ORshiftLL <typ.UInt32> (ZeroExt16to32 x) (ZeroExt16to32 x) [16]) (NEG <typ.Int64> y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpARM64RORW)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64ORshiftLL, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(16)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, v1)
		v2 := b.NewValue0(v.Pos, OpARM64NEG, typ.Int64)
		v2.AddArg(y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM64_OpRotateLeft32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RotateLeft32 x y)
	// result: (RORW x (NEG <y.Type> y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64RORW)
		v0 := b.NewValue0(v.Pos, OpARM64NEG, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM64_OpRotateLeft64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RotateLeft64 x y)
	// result: (ROR x (NEG <y.Type> y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64ROR)
		v0 := b.NewValue0(v.Pos, OpARM64NEG, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM64_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVDconst [c]))
	// result: (Or8 (Lsh8x64 <t> x (MOVDconst [c&7])) (Rsh8Ux64 <t> x (MOVDconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v3 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (RotateLeft8 <t> x y)
	// result: (OR <t> (SLL <t> x (ANDconst <typ.Int64> [7] y)) (SRL <t> (ZeroExt8to64 x) (ANDconst <typ.Int64> [7] (NEG <typ.Int64> y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpARM64OR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v1 := b.NewValue0(v.Pos, OpARM64ANDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(7)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpARM64ANDconst, typ.Int64)
		v4.AuxInt = int64ToAuxInt(7)
		v5 := b.NewValue0(v.Pos, OpARM64NEG, typ.Int64)
		v5.AddArg(y)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM64_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt16to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
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
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
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
func rewriteValueARM64_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt16to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
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
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
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
func rewriteValueARM64_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt16to64 x) y) (Const64 <t> [0]) (CMPconst [64] y))
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
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
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
func rewriteValueARM64_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt16to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
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
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
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
func rewriteValueARM64_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x16 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt16to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
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
func rewriteValueARM64_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x32 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt32to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
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
func rewriteValueARM64_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x64 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] y)))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
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
func rewriteValueARM64_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt16to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16x8 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt16to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt8to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
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
func rewriteValueARM64_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt32to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
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
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
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
func rewriteValueARM64_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt32to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
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
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
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
func rewriteValueARM64_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt32to64 x) y) (Const64 <t> [0]) (CMPconst [64] y))
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
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
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
func rewriteValueARM64_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt32to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
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
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
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
func rewriteValueARM64_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32x16 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt32to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt16to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
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
func rewriteValueARM64_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32x32 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt32to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt32to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
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
func rewriteValueARM64_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32x64 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt32to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] y)))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
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
func rewriteValueARM64_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt32to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh32x8 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt32to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt8to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
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
func rewriteValueARM64_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
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
func rewriteValueARM64_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
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
func rewriteValueARM64_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64Ux64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> x y) (Const64 <t> [0]) (CMPconst [64] y))
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
func rewriteValueARM64_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
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
func rewriteValueARM64_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x16 <t> x y)
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
	// match: (Rsh64x16 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA x (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt16to64 y))))
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
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x32 <t> x y)
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
	// match: (Rsh64x32 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA x (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt32to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v0.AuxInt = opToAuxInt(OpARM64Le
```