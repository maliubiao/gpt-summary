Response:
My goal is to analyze the given Go code snippet and provide a comprehensive explanation of its functionality. Here's a breakdown of my thought process:

1. **Identify the Context:** The code is part of `go/src/cmd/compile/internal/ssa/rewriteARM.go`. This immediately tells me it's related to the Go compiler, specifically the SSA (Static Single Assignment) intermediate representation, and the ARM architecture. The filename suggests it's responsible for rewriting SSA values for ARM. The "part 11 of 16" information indicates this is a portion of a larger file dedicated to ARM-specific rewrites.

2. **Understand the Core Functionality:**  The functions in the snippet have names like `rewriteValueARM_OpNeq32F`, `rewriteValueARM_OpOffPtr`, etc. The naming convention `rewriteValueARM_Op<OpName>` strongly suggests these functions are responsible for transforming SSA `Value`s of a specific operation (`OpName`) into equivalent or more efficient ARM instructions. Each function takes a `*Value` as input and returns a boolean, presumably indicating whether a rewrite was performed.

3. **Analyze Individual Functions (Pattern Matching and Rewriting):**
    * **`rewriteValueARM_OpNeq...` functions:** These handle "not equal" comparisons for different data types (32-bit float, 64-bit float, 8-bit integer, pointer). The pattern `// match: (Neq... x y)` and `// result: (...)` clearly shows the intended transformation. For example, `Neq32F x y` is rewritten as `NotEqual(CMPF x y)`. This means a high-level "not equal" operation is being translated into a comparison followed by a "not equal" flag check, which is typical for assembly-level implementations of comparisons.
    * **`rewriteValueARM_OpNot`:** This function rewrites a logical "NOT" operation. The comment `// result: (XORconst [1] x)` indicates it's being implemented using an XOR operation with the constant 1. This is a standard bitwise trick for inverting a single bit (effectively a boolean).
    * **`rewriteValueARM_OpOffPtr`:** This function deals with pointer offsets. It has two match/result patterns. The first handles the case where the base pointer is the stack pointer (`SP`), rewriting it to a `MOVWaddr` instruction with the offset embedded. The second handles general pointer offsets, rewriting it to an `ADDconst` instruction. This shows optimization for common stack-based offsets.
    * **`rewriteValueARM_OpPanicBounds` and `rewriteValueARM_OpPanicExtend`:** These functions relate to bounds checking during array/slice access, which can trigger a panic. The `boundsABI` condition and the different `LoweredPanicBounds...` and `LoweredPanicExtend...` results suggest different calling conventions or mechanisms for handling bounds panics. The `kind` auxInt likely specifies the type of bounds check.
    * **`rewriteValueARM_OpRotateLeft...` functions:** These implement left rotation for different bit sizes. The transformations involve bitwise shifts and OR operations, which is the standard way to implement rotation in architectures that don't have a dedicated rotate instruction. The constant rotation cases are optimized.
    * **`rewriteValueARM_OpRsh...` functions:** These functions handle right shifts (both unsigned and signed) for various data types and shift amounts. They often involve conditional moves (`CMOVWHSconst`) and comparisons to handle shifts greater than or equal to the bit width of the operand. Constant shift amounts are often optimized to dedicated shift-by-constant instructions.
    * **`rewriteValueARM_OpSelect0` and `rewriteValueARM_OpSelect1`:** These likely extract the quotient and remainder, respectively, from a division operation. The patterns involving `CALLudiv` suggest they are dealing with the result of an unsigned division call. Optimizations for division by 1 and powers of 2 are present.
    * **`rewriteValueARM_OpSignmask`:**  This extracts the sign bit of an integer. It uses a right shift by 31 bits, which effectively moves the sign bit to the least significant position.
    * **`rewriteValueARM_OpSlicemask`:** This appears to create a mask based on a value, likely for implementing slicing operations.
    * **`rewriteValueARM_OpStore`:** This function handles memory store operations for different data types. It maps the high-level `Store` operation to specific ARM store instructions (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVFstore`, `MOVDstore`) based on the size and type of the data being stored.
    * **`rewriteValueARM_OpZero`:** This function handles zeroing out memory regions. It includes optimizations for small sizes (using individual store instructions) and larger sizes (potentially using a Duff's device implementation or a loop). The `config.noDuffDevice` check is relevant here.
    * **`rewriteValueARM_OpZeromask`:** Similar to `OpSlicemask`, this likely creates a mask related to zeroing out bits.
    * **`rewriteBlockARM`:** This function rewrites entire control flow blocks. It handles conditional branches (`EQ`) and optimizes based on constant flags and comparisons.

4. **Infer Go Language Features:** Based on the operations being rewritten, I can infer the Go language features being implemented:
    * **Comparison Operators:** `==`, `!=` (handled by `OpNeq...` and `EQ` blocks)
    * **Logical NOT Operator:** `!` (handled by `OpNot`)
    * **Pointer Arithmetic:**  Accessing memory at offsets (handled by `OpOffPtr`)
    * **Array/Slice Access with Bounds Checking:** (handled by `OpPanicBounds` and `OpPanicExtend`)
    * **Bitwise Rotation:** `<<`, `>>` (handled by `OpRotateLeft...`)
    * **Bitwise Right Shift:** `>>` (handled by `OpRsh...`)
    * **Integer Division and Remainder:** `/`, `%` (handled by `OpSelect0` and `OpSelect1`)
    * **Sign Extraction:**  Not a direct Go operator, but used internally for implementation.
    * **Memory Store Operations:** Assignment to variables, array/slice elements, struct fields (handled by `OpStore`)
    * **Zero Initialization:**  `var x T`, `make([]T, n)` (handled by `OpZero`)
    * **Masking Operations:** Used internally for bit manipulation.

5. **Construct Go Code Examples:** For each inferred Go feature, I create simple illustrative code snippets. This demonstrates how the SSA operations being rewritten correspond to actual Go code.

6. **Address Specific Questions:**
    * **Functionality Listing:**  I create a bulleted list summarizing the purpose of the code.
    * **Go Feature Inference and Examples:** As described above.
    * **Code Reasoning (Input/Output):** I choose a few representative functions (like `rewriteValueARM_OpNeq32F` and `rewriteValueARM_OpOffPtr`) and provide a hypothetical SSA input and the resulting rewritten SSA output. This helps illustrate the transformation process.
    * **Command-line Arguments:**  I realize this code snippet doesn't directly process command-line arguments. This is part of the compiler's internal workings, not something controlled by direct command-line flags in this specific file.
    * **Common Mistakes:** I consider potential pitfalls for users *of the Go language* that relate to the optimizations happening here. For example, relying on the bit-level representation of floating-point numbers or assuming a specific implementation of bounds checking might lead to unexpected behavior if optimizations change.
    * **Summarize Functionality:** I provide a concise summary of the code's role within the Go compiler.

7. **Structure and Language:**  I ensure the answer is in Chinese, uses clear and concise language, and is well-organized with headings and bullet points.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on the low-level ARM instructions without clearly connecting them back to Go language features. **Correction:** Emphasize the mapping between Go concepts and the SSA rewrites.
* **Overcomplication:** Get bogged down in the details of every single rewrite function. **Correction:** Focus on providing representative examples and a general understanding of the patterns.
* **Clarity of Examples:**  Provide overly complex Go examples. **Correction:** Keep the Go examples simple and directly related to the specific SSA operation.
* **Handling "No Mistakes" Case:** Initially think about listing potential mistakes even if none are obvious from this snippet. **Correction:**  Stick to the instruction and only list mistakes if they are genuinely apparent from the code's behavior. In this case, it's more about potential misunderstandings of compiler optimizations rather than direct errors in using the language.
这是一个Go语言实现的片段，位于Go语言编译器源码的 `go/src/cmd/compile/internal/ssa/rewriteARM.go` 文件中。这个文件的主要作用是定义了针对ARM架构的SSA（Static Single Assignment）中间表示的重写规则。这些规则用于将通用的SSA操作转换为更具体、更适合ARM架构的指令序列，从而提高代码的执行效率。

**具体来说，这段代码的功能是定义了一系列针对特定SSA操作码（OpCode）的重写规则函数，这些函数的名字都以 `rewriteValueARM_Op` 开头。每个函数都对应一个特定的SSA操作，并尝试将其转换为更底层的ARM指令序列。**

以下是这段代码中各个函数的功能归纳：

* **`rewriteValueARM_OpNeq32F(v *Value) bool`**: 将 32 位浮点数的不等于（`Neq32F`）操作重写为 ARM 的浮点数比较（`CMPF`）后跟一个不等于判断（`NotEqual`）。
* **`rewriteValueARM_OpNeq64F(v *Value) bool`**: 将 64 位浮点数的不等于（`Neq64F`）操作重写为 ARM 的双精度浮点数比较（`CMPD`）后跟一个不等于判断（`NotEqual`）。
* **`rewriteValueARM_OpNeq8(v *Value) bool`**: 将 8 位整数的不等于（`Neq8`）操作重写为将两个 8 位整数零扩展到 32 位后进行比较（`CMP`），然后判断不等于（`NotEqual`）。
* **`rewriteValueARM_OpNeqPtr(v *Value) bool`**: 将指针类型的不等于（`NeqPtr`）操作重写为直接使用 ARM 的比较指令（`CMP`）后跟一个不等于判断（`NotEqual`）。
* **`rewriteValueARM_OpNot(v *Value) bool`**: 将逻辑非（`Not`）操作重写为与常量 1 进行异或操作（`XORconst`），这是一种常见的按位取反的实现方式。
* **`rewriteValueARM_OpOffPtr(v *Value) bool`**: 将计算指针偏移（`OffPtr`）的操作进行重写。如果基址是指针寄存器 `SP`，则使用带偏移的地址加载指令 `MOVWaddr`；否则，使用加立即数指令 `ADDconst`。
* **`rewriteValueARM_OpPanicBounds(v *Value) bool`**:  处理数组或切片访问时的越界 panic。根据不同的 `boundsABI` 配置，将其重写为不同的底层 panic 函数 (`LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC`)。这可能涉及到不同的调用约定或错误处理机制。
* **`rewriteValueARM_OpPanicExtend(v *Value) bool`**: 类似于 `OpPanicBounds`，处理更复杂的越界 panic 情况，并根据 `boundsABI` 重写为不同的底层 panic 函数 (`LoweredPanicExtendA`, `LoweredPanicExtendB`, `LoweredPanicExtendC`)。
* **`rewriteValueARM_OpRotateLeft16(v *Value) bool`**: 将 16 位整数的循环左移（`RotateLeft16`）操作，如果移动量是常量，则重写为使用左移和右移指令的组合来实现。
* **`rewriteValueARM_OpRotateLeft32(v *Value) bool`**: 将 32 位整数的循环左移（`RotateLeft32`）操作重写为使用 ARM 的 `SRR` 指令，并通过 `RSBconst` 指令计算出循环右移的量。
* **`rewriteValueARM_OpRotateLeft8(v *Value) bool`**: 将 8 位整数的循环左移（`RotateLeft8`）操作，如果移动量是常量，则重写为使用左移和右移指令的组合来实现。
* **`rewriteValueARM_OpRsh16Ux16` - `rewriteValueARM_OpRsh8x8`**:  处理各种不同类型和位宽的无符号和有符号右移操作（`Rsh`）。这些函数通常会根据操作数的类型和移动量，将其转换为相应的ARM移位指令（如 `SRL`, `SRA`）或条件移动指令 (`CMOVWHSconst`, `SRAcond`)，并处理一些特殊情况，例如移动量超出范围。
* **`rewriteValueARM_OpSelect0(v *Value) bool`**:  处理从一个返回多个值的操作中选择第一个值的操作。这里专门处理了 `CALLudiv` (无符号除法) 的情况，如果除数是常量 1 或 2 的幂，则可以优化为移位操作。
* **`rewriteValueARM_OpSelect1(v *Value) bool`**: 处理从一个返回多个值的操作中选择第二个值的操作。 同样针对 `CALLudiv` 进行了优化，如果除数是常量 1 或 2 的幂，则可以使用位运算（`ANDconst`）来获取余数。
* **`rewriteValueARM_OpSignmask(v *Value) bool`**: 将获取符号位的操作（`Signmask`）重写为算术右移 31 位 (`SRAconst`)，将符号位移到最低位。
* **`rewriteValueARM_OpSlicemask(v *Value) bool`**:  生成用于切片操作的掩码。
* **`rewriteValueARM_OpStore(v *Value) bool`**:  将通用的存储操作（`Store`）重写为特定大小和类型的 ARM 存储指令，如 `MOVBstore` (字节存储), `MOVHstore` (半字存储), `MOVWstore` (字存储), `MOVFstore` (单精度浮点存储), `MOVDstore` (双精度浮点存储)。
* **`rewriteValueARM_OpZero(v *Value) bool`**: 处理将内存区域置零的操作（`Zero`）。对于小块内存，使用一系列的存储零值指令；对于较大的内存块，可能会使用 Duff's device 或调用底层的零值填充函数 (`LoweredZero`)。
* **`rewriteValueARM_OpZeromask(v *Value) bool`**: 生成用于清零特定位的掩码。
* **`rewriteBlockARM(b *Block) bool`**:  重写控制流块。例如，针对 `BlockARMEQ` (ARM 的等于条件跳转块)，会尝试根据标志位常量的值来简化控制流，或者处理标志位的反转情况。

**推理其实现的Go语言功能：**

这段代码是Go编译器后端的一部分，负责将Go语言的高级特性转换为底层的ARM机器指令。它涵盖了以下Go语言功能在ARM架构上的实现细节：

* **基本数据类型的操作**:  整数和浮点数的算术运算、比较运算、位运算等。
* **指针操作**:  指针的比较、偏移计算等。
* **控制流**:  条件判断（`if` 语句）、循环等。
* **函数调用**:  `PanicBounds` 和 `PanicExtend` 与运行时错误处理相关。
* **内存操作**:  变量赋值、结构体和数组/切片元素的读写和初始化。

**Go代码举例说明：**

```go
package main

import "fmt"

func main() {
	var a float32 = 1.0
	var b float32 = 2.0
	fmt.Println(a != b) // 这会触发 OpNeq32F 的重写

	var ptr *int
	var ptr2 *int
	fmt.Println(ptr != ptr2) // 这会触发 OpNeqPtr 的重写

	var x int = 5
	fmt.Println(^x) // 这会触发 OpNot 的重写

	arr := [10]int{}
	// 访问超出数组边界会触发 OpPanicBounds 或 OpPanicExtend 的重写
	// _ = arr[10]

	var y uint16 = 0xA5A5
	fmt.Printf("%#x\n", y<<2) // 循环左移，可能会触发 OpRotateLeft16 的重写

	var z uint32 = 0xFF00FF00
	fmt.Printf("%#x\n", z>>4) // 无符号右移，会触发 OpRsh32Ux32 的重写

	quotient := 10 / 3
	remainder := 10 % 3 // 这会触发 OpSelect0 和 OpSelect1 的重写 (针对 CALLudiv)

	var num int32 = -10
	mask := num >> 31 // 获取符号位，会触发 OpSignmask 的重写

	var buffer [10]byte
	// 将 buffer 置零，会触发 OpZero 的重写
	for i := range buffer {
		buffer[i] = 0
	}
}
```

**假设的输入与输出（以 `rewriteValueARM_OpNeq32F` 为例）：**

**假设输入 (SSA Value `v`):**

```
Op: OpNeq32F
Args: [val1, val2]  // val1 和 val2 是表示两个 float32 值的 SSA Value
```

**输出 (修改后的 SSA Value `v`):**

```
Op: OpARMNotEqual
Args: [cmp_result]  // cmp_result 是一个新的 SSA Value，表示比较的结果
```

**其中 `cmp_result` 的 SSA Value 可能如下:**

```
Op: OpARMCMPF
Args: [val1, val2]
Type: TypeFlags  // 表示比较的结果，用于后续的条件判断
```

**这段代码不直接处理命令行参数。** 命令行参数的处理通常发生在编译器的前端和驱动程序部分，而 SSA 的重写是编译器后端的一部分，它处理的是已经构建好的中间表示。

**这段代码片段本身不容易让使用者犯错，因为它属于编译器内部实现。**  但是，理解编译器如何优化代码可以帮助开发者避免一些性能陷阱：

* **依赖浮点数的位表示进行比较**: Go 语言中的浮点数比较应该使用 `==` 或 `!=`，编译器会将其转换为合适的浮点数比较指令。直接进行位比较可能会得到意想不到的结果，因为浮点数的表示方式比较复杂。
* **过度依赖位运算的技巧**: 虽然编译器会进行一些位运算的优化，但编写过于复杂的、依赖特定位运算技巧的代码可能难以理解和维护，并且在不同的架构上可能效果不一致。

**总结一下这段代码的功能：**

这段代码是Go语言编译器中针对ARM架构的SSA重写规则的一部分。它定义了将Go语言中的各种操作（例如比较、算术运算、内存操作等）转换为高效的ARM机器指令的具体步骤。通过这些重写规则，Go编译器能够生成针对ARM架构优化过的、性能更好的代码。 它是Go语言编译过程中的一个关键环节，负责将高级的Go语言概念映射到具体的硬件指令。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第11部分，共16部分，请归纳一下它的功能

"""
}
func rewriteValueARM_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32F x y)
	// result: (NotEqual (CMPF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMNotEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64F x y)
	// result: (NotEqual (CMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMNotEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (NotEqual (CMP (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMNotEqual)
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
func rewriteValueARM_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (NeqPtr x y)
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
}
func rewriteValueARM_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not x)
	// result: (XORconst [1] x)
	for {
		x := v_0
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueARM_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr [off] ptr:(SP))
	// result: (MOVWaddr [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if ptr.Op != OpSP {
			break
		}
		v.reset(OpARMMOVWaddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// result: (ADDconst [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
}
func rewriteValueARM_OpPanicBounds(v *Value) bool {
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
		v.reset(OpARMLoweredPanicBoundsA)
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
		v.reset(OpARMLoweredPanicBoundsB)
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
		v.reset(OpARMLoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpPanicExtend(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PanicExtend [kind] hi lo y mem)
	// cond: boundsABI(kind) == 0
	// result: (LoweredPanicExtendA [kind] hi lo y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		hi := v_0
		lo := v_1
		y := v_2
		mem := v_3
		if !(boundsABI(kind) == 0) {
			break
		}
		v.reset(OpARMLoweredPanicExtendA)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg4(hi, lo, y, mem)
		return true
	}
	// match: (PanicExtend [kind] hi lo y mem)
	// cond: boundsABI(kind) == 1
	// result: (LoweredPanicExtendB [kind] hi lo y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		hi := v_0
		lo := v_1
		y := v_2
		mem := v_3
		if !(boundsABI(kind) == 1) {
			break
		}
		v.reset(OpARMLoweredPanicExtendB)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg4(hi, lo, y, mem)
		return true
	}
	// match: (PanicExtend [kind] hi lo y mem)
	// cond: boundsABI(kind) == 2
	// result: (LoweredPanicExtendC [kind] hi lo y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		hi := v_0
		lo := v_1
		y := v_2
		mem := v_3
		if !(boundsABI(kind) == 2) {
			break
		}
		v.reset(OpARMLoweredPanicExtendC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg4(hi, lo, y, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVWconst [c]))
	// result: (Or16 (Lsh16x32 <t> x (MOVWconst [c&15])) (Rsh16Ux32 <t> x (MOVWconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x32, t)
		v1 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux32, t)
		v3 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueARM_OpRotateLeft32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RotateLeft32 x y)
	// result: (SRR x (RSBconst [0] <y.Type> y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRR)
		v0 := b.NewValue0(v.Pos, OpARMRSBconst, y.Type)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVWconst [c]))
	// result: (Or8 (Lsh8x32 <t> x (MOVWconst [c&7])) (Rsh8Ux32 <t> x (MOVWconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x32, t)
		v1 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux32, t)
		v3 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueARM_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 x y)
	// result: (CMOVWHSconst (SRL <x.Type> (ZeroExt16to32 x) (ZeroExt16to32 y)) (CMPconst [256] (ZeroExt16to32 y)) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(256)
		v3.AddArg(v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueARM_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 x y)
	// result: (CMOVWHSconst (SRL <x.Type> (ZeroExt16to32 x) y) (CMPconst [256] y) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 x (Const64 [c]))
	// cond: uint64(c) < 16
	// result: (SRLconst (SLLconst <typ.UInt32> x [16]) [int32(c+16)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpARMSRLconst)
		v.AuxInt = int32ToAuxInt(int32(c + 16))
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16Ux64 _ (Const64 [c]))
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
func rewriteValueARM_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 x y)
	// result: (SRL (ZeroExt16to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRL)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 x y)
	// result: (SRAcond (SignExt16to32 x) (ZeroExt16to32 y) (CMPconst [256] (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRAcond)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(v1)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueARM_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 x y)
	// result: (SRAcond (SignExt16to32 x) y (CMPconst [256] y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRAcond)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(y)
		v.AddArg3(v0, y, v1)
		return true
	}
}
func rewriteValueARM_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 x (Const64 [c]))
	// cond: uint64(c) < 16
	// result: (SRAconst (SLLconst <typ.UInt32> x [16]) [int32(c+16)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(int32(c + 16))
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh16x64 x (Const64 [c]))
	// cond: uint64(c) >= 16
	// result: (SRAconst (SLLconst <typ.UInt32> x [16]) [31])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 16) {
			break
		}
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 x y)
	// result: (SRA (SignExt16to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRA)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 x y)
	// result: (CMOVWHSconst (SRL <x.Type> x (ZeroExt16to32 y)) (CMPconst [256] (ZeroExt16to32 y)) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
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
func rewriteValueARM_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32Ux32 x y)
	// result: (CMOVWHSconst (SRL <x.Type> x y) (CMPconst [256] y) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh32Ux64 x (Const64 [c]))
	// cond: uint64(c) < 32
	// result: (SRLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(OpARMSRLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh32Ux64 _ (Const64 [c]))
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
func rewriteValueARM_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 x y)
	// result: (SRL x (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRL)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 x y)
	// result: (SRAcond x (ZeroExt16to32 y) (CMPconst [256] (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRAcond)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(v0)
		v.AddArg3(x, v0, v1)
		return true
	}
}
func rewriteValueARM_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh32x32 x y)
	// result: (SRAcond x y (CMPconst [256] y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRAcond)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(256)
		v0.AddArg(y)
		v.AddArg3(x, y, v0)
		return true
	}
}
func rewriteValueARM_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Rsh32x64 x (Const64 [c]))
	// cond: uint64(c) < 32
	// result: (SRAconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Rsh32x64 x (Const64 [c]))
	// cond: uint64(c) >= 32
	// result: (SRAconst x [31])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 32) {
			break
		}
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 x y)
	// result: (SRA x (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRA)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 x y)
	// result: (CMOVWHSconst (SRL <x.Type> (ZeroExt8to32 x) (ZeroExt16to32 y)) (CMPconst [256] (ZeroExt16to32 y)) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(256)
		v3.AddArg(v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueARM_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 x y)
	// result: (CMOVWHSconst (SRL <x.Type> (ZeroExt8to32 x) y) (CMPconst [256] y) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 x (Const64 [c]))
	// cond: uint64(c) < 8
	// result: (SRLconst (SLLconst <typ.UInt32> x [24]) [int32(c+24)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(OpARMSRLconst)
		v.AuxInt = int32ToAuxInt(int32(c + 24))
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(24)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8Ux64 _ (Const64 [c]))
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
func rewriteValueARM_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 x y)
	// result: (SRL (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRL)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 x y)
	// result: (SRAcond (SignExt8to32 x) (ZeroExt16to32 y) (CMPconst [256] (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRAcond)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(v1)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueARM_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 x y)
	// result: (SRAcond (SignExt8to32 x) y (CMPconst [256] y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRAcond)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(y)
		v.AddArg3(v0, y, v1)
		return true
	}
}
func rewriteValueARM_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 x (Const64 [c]))
	// cond: uint64(c) < 8
	// result: (SRAconst (SLLconst <typ.UInt32> x [24]) [int32(c+24)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(int32(c + 24))
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(24)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (Rsh8x64 x (Const64 [c]))
	// cond: uint64(c) >= 8
	// result: (SRAconst (SLLconst <typ.UInt32> x [24]) [31])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 8) {
			break
		}
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(24)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 x y)
	// result: (SRA (SignExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSRA)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Select0 (CALLudiv x (MOVWconst [1])))
	// result: x
	for {
		if v_0.Op != OpARMCALLudiv {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpARMMOVWconst || auxIntToInt32(v_0_1.AuxInt) != 1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Select0 (CALLudiv x (MOVWconst [c])))
	// cond: isPowerOfTwo(c)
	// result: (SRLconst [int32(log32(c))] x)
	for {
		if v_0.Op != OpARMCALLudiv {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARMSRLconst)
		v.AuxInt = int32ToAuxInt(int32(log32(c)))
		v.AddArg(x)
		return true
	}
	// match: (Select0 (CALLudiv (MOVWconst [c]) (MOVWconst [d])))
	// cond: d != 0
	// result: (MOVWconst [int32(uint32(c)/uint32(d))])
	for {
		if v_0.Op != OpARMCALLudiv {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) / uint32(d)))
		return true
	}
	return false
}
func rewriteValueARM_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Select1 (CALLudiv _ (MOVWconst [1])))
	// result: (MOVWconst [0])
	for {
		if v_0.Op != OpARMCALLudiv {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpARMMOVWconst || auxIntToInt32(v_0_1.AuxInt) != 1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Select1 (CALLudiv x (MOVWconst [c])))
	// cond: isPowerOfTwo(c)
	// result: (ANDconst [c-1] x)
	for {
		if v_0.Op != OpARMCALLudiv {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c - 1)
		v.AddArg(x)
		return true
	}
	// match: (Select1 (CALLudiv (MOVWconst [c]) (MOVWconst [d])))
	// cond: d != 0
	// result: (MOVWconst [int32(uint32(c)%uint32(d))])
	for {
		if v_0.Op != OpARMCALLudiv {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0_0.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) % uint32(d)))
		return true
	}
	return false
}
func rewriteValueARM_OpSignmask(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Signmask x)
	// result: (SRAconst x [31])
	for {
		x := v_0
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v.AddArg(x)
		return true
	}
}
func rewriteValueARM_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRAconst (RSBconst <t> [0] x) [31])
	for {
		t := v.Type
		x := v_0
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v0 := b.NewValue0(v.Pos, OpARMRSBconst, t)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpStore(v *Value) bool {
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
		v.reset(OpARMMOVBstore)
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
		v.reset(OpARMMOVHstore)
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
		v.reset(OpARMMOVWstore)
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
		v.reset(OpARMMOVFstore)
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
		v.reset(OpARMMOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpZero(v *Value) bool {
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
	// result: (MOVBstore ptr (MOVWconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARMMOVBstore)
		v0 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore ptr (MOVWconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpARMMOVHstore)
		v0 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] ptr mem)
	// result: (MOVBstore [1] ptr (MOVWconst [0]) (MOVBstore [0] ptr (MOVWconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [4] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore ptr (MOVWconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpARMMOVWstore)
		v0 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [4] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [2] ptr (MOVWconst [0]) (MOVHstore [0] ptr (MOVWconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARMMOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [4] ptr mem)
	// result: (MOVBstore [3] ptr (MOVWconst [0]) (MOVBstore [2] ptr (MOVWconst [0]) (MOVBstore [1] ptr (MOVWconst [0]) (MOVBstore [0] ptr (MOVWconst [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(1)
		v3 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg3(ptr, v0, mem)
		v2.AddArg3(ptr, v0, v3)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [3] ptr mem)
	// result: (MOVBstore [2] ptr (MOVWconst [0]) (MOVBstore [1] ptr (MOVWconst [0]) (MOVBstore [0] ptr (MOVWconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [s] {t} ptr mem)
	// cond: s%4 == 0 && s > 4 && s <= 512 && t.Alignment()%4 == 0 && !config.noDuffDevice
	// result: (DUFFZERO [4 * (128 - s/4)] ptr (MOVWconst [0]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(s%4 == 0 && s > 4 && s <= 512 && t.Alignment()%4 == 0 && !config.noDuffDevice) {
			break
		}
		v.reset(OpARMDUFFZERO)
		v.AuxInt = int64ToAuxInt(4 * (128 - s/4))
		v0 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [s] {t} ptr mem)
	// cond: (s > 512 || config.noDuffDevice) || t.Alignment()%4 != 0
	// result: (LoweredZero [t.Alignment()] ptr (ADDconst <ptr.Type> ptr [int32(s-moveSize(t.Alignment(), config))]) (MOVWconst [0]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !((s > 512 || config.noDuffDevice) || t.Alignment()%4 != 0) {
			break
		}
		v.reset(OpARMLoweredZero)
		v.AuxInt = int64ToAuxInt(t.Alignment())
		v0 := b.NewValue0(v.Pos, OpARMADDconst, ptr.Type)
		v0.AuxInt = int32ToAuxInt(int32(s - moveSize(t.Alignment(), config)))
		v0.AddArg(ptr)
		v1 := b.NewValue0(v.Pos, OpARMMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0)
		v.AddArg4(ptr, v0, v1, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpZeromask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Zeromask x)
	// result: (SRAconst (RSBshiftRL <typ.Int32> x x [1]) [31])
	for {
		x := v_0
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v0 := b.NewValue0(v.Pos, OpARMRSBshiftRL, typ.Int32)
		v0.AuxInt = int32ToAuxInt(1)
		v0.AddArg2(x, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteBlockARM(b *Block) bool {
	switch b.Kind {
	case BlockARMEQ:
		// match: (EQ (FlagConstant [fc]) yes no)
		// cond: fc.eq()
		// result: (First yes no)
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMFlagConstant {
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
		for b.Controls[0].Op == OpARMInvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockARMEQ, cmp)
			return true
		}
		// match: (EQ (CMP x (RSBconst [0] y)))
		// result: (EQ (CMN x y))
		for b.Controls[0].Op == OpARMCMP {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v
"""




```