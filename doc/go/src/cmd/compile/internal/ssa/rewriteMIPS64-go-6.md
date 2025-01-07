Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Purpose:** The filename `rewriteMIPS64.go` and the package `ssa` immediately suggest this code is part of the Go compiler's intermediate representation (SSA - Static Single Assignment) and is specifically targeting the MIPS64 architecture. The "rewrite" part indicates that this code is involved in optimizing or transforming the SSA representation.

2. **Examine the Function Signatures:**  The code defines two primary functions: `rewriteValueMIPS64` and `rewriteBlockMIPS64`. This suggests two distinct levels of operation:
    * `rewriteValueMIPS64`:  Likely operates on individual SSA *values* (representing computations).
    * `rewriteBlockMIPS64`:  Likely operates on control flow *blocks* within the SSA graph.

3. **Analyze `rewriteValueMIPS64`:**

    * **Structure:**  The function uses a `switch` statement based on the `v.Op` (the operation code of the SSA value). This is a common pattern for handling different types of SSA operations.
    * **Case Analysis (Example: `OpMIPS64MOVSDstore`):**
        * The code checks the type of the value being stored (`auxToType(v.Aux)`).
        * It verifies the size is 8 bytes and the type is floating-point.
        * If the conditions are met, it *resets* the operation of the value (`v.reset(OpMIPS64MOVDstore)`) and adjusts the arguments. This implies a transformation or optimization. The change from `MOVSDstore` to `MOVDstore` suggests a potential type-specific optimization. It appears to be handling the case where a single-precision float store can be represented as a double-precision store on MIPS64 (likely due to register size or instruction set details).
    * **Case Analysis (Example: `OpZero`):**
        * This case handles the `Zero` operation, which represents setting a block of memory to zero.
        * It has multiple `match:` clauses, suggesting different optimization strategies based on the size (`v.AuxInt`) and alignment (`t.Alignment()`) of the memory being zeroed.
        * The code directly manipulates memory store operations (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVVstore`) for small sizes, effectively unrolling the zeroing operation.
        * It introduces `OpMIPS64DUFFZERO` for larger aligned blocks, indicating the use of a Duff's device or a similar optimized zeroing technique.
        * It falls back to `OpMIPS64LoweredZero` for very large or unaligned blocks, suggesting a more general zeroing mechanism.
    * **General Observations for `rewriteValueMIPS64`:**
        * The function aims to replace potentially less efficient operations with more efficient MIPS64-specific instructions.
        * It uses auxiliary information (`v.Aux`, `v.AuxInt`) to guide the rewriting process.
        * Alignment is a key factor in choosing optimization strategies.

4. **Analyze `rewriteBlockMIPS64`:**

    * **Structure:** Similar to `rewriteValueMIPS64`, it uses a `switch` statement based on the `b.Kind` (the type of the control flow block).
    * **Case Analysis (Example: `BlockMIPS64EQ`):**
        * This case deals with blocks that branch based on equality (`EQ`).
        * It looks for specific patterns involving comparison operations (`SGT`, `SGTU`, `SGTconst`, `SGTUconst`) and logical operations (`XORconst`).
        * It transforms these patterns into more direct MIPS64 branch instructions (`FPF`, `FPT`, `NE`, `GEZ`, `LEZ`). It also handles simple constant conditions.
    * **Case Analysis (Example: `BlockIf`):**
        * This case directly maps a generic `If` block to a MIPS64 "not equal" branch (`NE`). This indicates how high-level control flow is translated to the target architecture's branching mechanisms.
    * **General Observations for `rewriteBlockMIPS64`:**
        * The function optimizes control flow by replacing generic block types with MIPS64-specific conditional branch blocks.
        * It simplifies conditional expressions to match the available branching instructions on the target architecture.

5. **Infer Go Language Feature Implementation (Based on `OpZero`):** The `OpZero` case strongly suggests this code is involved in implementing the zeroing of memory, which is fundamental to many Go operations, including:
    * **Initialization of variables:** When a variable is declared without an explicit initial value, it's zero-initialized.
    * **Allocation of slices and maps:** The underlying memory for these data structures needs to be zeroed.
    * **`unsafe.Slice` creation:** When creating a slice from raw memory, the memory needs to be in a known state.

6. **Construct Go Code Example:**  Based on the `OpZero` analysis, a simple example demonstrating zero initialization is appropriate.

7. **Consider Command-Line Arguments (and their absence):** The code itself doesn't directly process command-line arguments. However, the `config.noDuffDevice` flag hints at a compiler configuration option that *could* be controlled by a command-line flag. This is an indirect connection.

8. **Identify Potential Pitfalls:**  The code highlights the importance of alignment. A common mistake in low-level programming is to assume data is aligned when it's not, leading to crashes or incorrect behavior. The different code paths for aligned and unaligned memory in the `OpZero` case illustrate this point.

9. **Synthesize the Summary:** Combine the observations from the individual function analyses to provide a high-level overview of the file's purpose within the Go compiler.

10. **Self-Correction/Refinement:**  During the process, you might go back and forth. For example, initially, I might have focused too much on the specific MIPS64 instructions. Realizing the broader context of SSA rewriting helps to understand *why* these transformations are happening. The "rewrite" aspect is crucial – it's about transforming the code into a more efficient form for the target architecture. Also, connecting the `OpZero` case to concrete Go language features like variable initialization makes the explanation more grounded.
## 功能列表：go/src/cmd/compile/internal/ssa/rewriteMIPS64.go (第7部分，共7部分)

这个文件 `rewriteMIPS64.go` 的主要功能是：**针对 MIPS64 架构，对 Go 语言编译器的静态单赋值形式 (SSA) 中间表示进行特定的重写和优化。**

具体来说，它包含两个主要的函数：

1. **`rewriteValueMIPS64(v *Value) bool`**:
    * **功能**:  这个函数遍历 SSA 中的 `Value` 节点，并根据 `Value` 的操作类型 (`v.Op`) 和其他属性 (例如辅助信息 `v.Aux`, 辅助整数 `v.AuxInt`)，尝试将其重写为更优化的 MIPS64 指令序列。
    * **优化目标**:  通常是将一些通用的操作转化为 MIPS64 架构下更高效的指令，或者消除冗余操作。
    * **匹配模式**:  通过一系列 `match:` 和 `cond:` 注释，定义了各种需要被重写的 `Value` 节点的模式。
    * **重写规则**:  如果一个 `Value` 节点匹配了某个模式，函数会修改该节点的属性，例如改变其操作类型 (`v.reset`)，添加或修改其参数 (`v.AddArg`)。

2. **`rewriteBlockMIPS64(b *Block) bool`**:
    * **功能**: 这个函数遍历 SSA 中的 `Block` 节点，这些节点代表了代码的控制流块。它根据 `Block` 的类型 (`b.Kind`) 和控制流条件 (`b.Controls`)，尝试重写控制流结构，使其更符合 MIPS64 的特性或者进行优化。
    * **优化目标**:  通常是将通用的控制流块转化为 MIPS64 特有的条件分支指令，或者简化控制流。
    * **匹配模式**:  通过一系列 `match:` 注释，定义了各种需要被重写的 `Block` 节点的模式。
    * **重写规则**: 如果一个 `Block` 节点匹配了某个模式，函数会修改该节点的类型 (`b.resetWithControl`) 或交换其后继节点 (`b.swapSuccessors`)。

**归纳一下第7部分的功能：**

这部分代码主要集中在 `rewriteValueMIPS64` 函数中对 **内存操作 (`OpZero`, `OpStore`, `OpAddPtr`)** 以及 **浮点数存储 (`OpMOVSDstore`)** 的优化重写，以及 `rewriteBlockMIPS64` 函数中对 **各种条件分支块 (`BlockMIPS64EQ`, `BlockMIPS64GEZ`, `BlockIf` 等)** 的优化重写。  它完成了针对 MIPS64 架构 SSA 重写规则的最后一部分。

## 推理 Go 语言功能实现并举例

基于代码内容，可以推断出以下 Go 语言功能的实现涉及到这些重写规则：

1. **零值初始化 (`OpZero`)**:  `OpZero` 节点用于将一块内存区域设置为零值。  `rewriteValueMIPS64` 中的 `OpZero` 的多个 `match:` 子句展示了如何根据内存大小和对齐方式，将 `OpZero` 操作转化为一系列更细粒度的 MIPS64 存储指令 (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVVstore`)，或者使用优化的 `DUFFZERO` 指令（如果可用）。

   **Go 代码示例:**

   ```go
   package main

   func main() {
       var arr [10]int // 数组会被零值初始化
       println(arr[0])    // 输出 0
   }
   ```

   **假设的 SSA 输入 (简化):**

   ```
   v1 = OpZero [80] ptr mem // 假设 ptr 指向 arr 的起始地址，需要 zero 80 字节
   ```

   **可能的 SSA 输出 (根据对齐和大小):**

   如果对齐且大小合适，可能会被重写为 `OpMIPS64DUFFZERO`:

   ```
   v2 = OpMIPS64DUFFZERO [优化后的偏移量] ptr mem
   ```

   如果大小较小，可能会被重写为多个 `OpMIPS64MOVVstore`:

   ```
   v2 = OpMIPS64MOVVstore ptr (OpMIPS64MOVVconst [0]) mem
   v3 = OpMIPS64MOVVstore (OpMIPS64ADDVconst ptr [8]) (OpMIPS64MOVVconst [0]) v2
   // ... 更多 MOVVstore 指令
   ```

2. **变量赋值和结构体/数组元素赋值 (`OpStore`, `OpMOVSDstore`)**: `OpStore` 用于将一个值存储到内存中。 `OpMOVSDstore` 专门用于存储单精度浮点数。`rewriteValueMIPS64` 中的相关规则尝试将其转化为更高效的 MIPS64 存储指令 (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVVstore`, `MOVDstore`)。特别是 `OpMOVSDstore` 被优化为 `OpMIPS64MOVDstore`，这可能与 MIPS64 的浮点寄存器和指令集有关。

   **Go 代码示例:**

   ```go
   package main

   func main() {
       var x int64
       x = 10

       type Point struct {
           X float32
           Y float32
       }
       p := Point{X: 1.0, Y: 2.0}
       println(p.X)
   }
   ```

   **假设的 SSA 输入 (简化):**

   ```
   v1 = OpStore ptr_x (OpConst64 [10]) mem // ptr_x 指向变量 x 的地址
   v2 = OpMOVSDstore ptr_p_x (OpConstFloat32 [1.0]) mem // ptr_p_x 指向 p.X 的地址
   ```

   **可能的 SSA 输出:**

   ```
   v1' = OpMIPS64MOVVstore ptr_x (OpMIPS64MOVVconst [10]) mem
   v2' = OpMIPS64MOVDstore ptr_p_x (OpMIPS64MOVVFconst [1.0]) mem // 单精度浮点存储优化为双精度存储
   ```

3. **指针运算 (`OpAddPtr`)**: `OpAddPtr` 用于进行指针的加法运算。虽然这段代码中没有直接展示 `OpAddPtr` 的重写，但在 `OpZero` 的重写规则中，可以看到使用了 `OpMIPS64ADDVconst` 来计算偏移后的地址，这暗示了对指针运算的优化。

   **Go 代码示例:**

   ```go
   package main

   func main() {
       arr := [5]int{1, 2, 3, 4, 5}
       ptr := &arr[0]
       nextPtr := ptr + 1
       println(*nextPtr) // 输出 2
   }
   ```

   **假设的 SSA 输入 (简化):**

   ```
   v1 = OpAddr arr
   v2 = OpAddPtr v1 (OpConst64 [8]) // 假设 int 是 8 字节
   ```

   **可能的 SSA 输出:**

   ```
   v1' = OpAddr arr
   v2' = OpMIPS64ADDVconst v1' [8]
   ```

4. **条件分支 (`BlockMIPS64EQ`, `BlockMIPS64NE`, 等)**: `rewriteBlockMIPS64` 函数针对不同的条件分支块进行优化，将其转化为 MIPS64 架构下更直接的条件分支指令，例如 `FPF` (浮点假时跳转), `FPT` (浮点真时跳转),  `BEQ` (等于时跳转), `BNE` (不等于时跳转) 等。

   **Go 代码示例:**

   ```go
   package main

   func main() {
       x := 10
       if x == 0 {
           println("x is zero")
       } else {
           println("x is not zero")
       }
   }
   ```

   **假设的 SSA 输入 (简化):**

   ```
   b1:
       v1 = OpConst64 [10]
       // ...
       If v2 goto b2 else b3  // v2 代表 x == 0 的比较结果
   b2:
       // ...
   b3:
       // ...
   ```

   **可能的 SSA 输出:**

   ```
   b1:
       v1 = OpConst64 [10]
       v2 = OpMIPS64SGTconst [0] v1 // 生成 MIPS64 的比较指令
       // ...
       NE v2 goto b3 else b2  // 将通用的 If 转化为 MIPS64 的 NE (不等于跳转)
   b2:
       // ...
   b3:
       // ...
   ```

## 命令行参数的具体处理

这段代码本身并不直接处理命令行参数。它的作用是在编译器的内部，对 SSA 中间表示进行转换。  然而，编译器本身会接收命令行参数，例如 `-gcflags` 可以用来传递一些编译选项。

**`config.noDuffDevice`** 字段暗示可能存在一个编译选项，用于禁用 Duff's device 优化。 这可能通过编译器接收的某个命令行参数来控制，但具体的参数名称和处理逻辑不在这个代码片段中。

## 使用者易犯错的点

作为编译器开发者，在编写或修改这类重写规则时，容易犯以下错误：

1. **模式匹配错误**: 定义的 `match:` 条件过于宽泛或过于狭窄，导致不应该被重写的 `Value` 或 `Block` 被错误地修改，或者应该被重写的却没有被识别出来。
2. **重写逻辑错误**:  在 `v.reset` 和 `v.AddArg` 时，目标指令的操作类型或参数设置不正确，导致生成的 MIPS64 代码错误。
3. **忽略边界条件**:  例如在 `OpZero` 的重写中，没有考虑到内存大小不是 2 的幂次，或者地址不对齐的情况，导致优化只在特定情况下生效。
4. **对 MIPS64 指令集理解不足**:  不熟悉 MIPS64 的指令特性和限制，可能导致选择了次优的指令或者使用了不存在的指令。
5. **影响其他平台的正确性**:  在编写 MIPS64 特定的优化时，需要确保不会对其他架构的编译过程产生负面影响。

**举例说明 (假设的错误):**

如果在 `rewriteValueMIPS64` 的 `OpZero` 中，某个 `match:` 条件错误地匹配了所有大小大于 0 的内存清零操作，并全部替换为了 `DUFFZERO`，但 `DUFFZERO`  只对特定大小和对齐的内存有效，那么对于不满足条件的 `OpZero` 操作，就会生成错误的 MIPS64 代码。

## 总结其功能

总而言之，`go/src/cmd/compile/internal/ssa/rewriteMIPS64.go` 这个文件的主要功能是**实现 Go 语言编译器针对 MIPS64 架构的特定代码优化**。它通过模式匹配和重写规则，将 SSA 中间表示中的通用操作和控制流结构转化为更高效的 MIPS64 指令序列，从而提升在 MIPS64 架构上运行的 Go 程序的性能。 这段代码是 Go 编译器后端针对特定架构进行优化的关键组成部分。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共7部分，请归纳一下它的功能

"""

	// result: (MOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && t.IsFloat()) {
			break
		}
		v.reset(OpMIPS64MOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpZero(v *Value) bool {
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
		v.reset(OpMIPS64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore ptr (MOVVconst [0]) mem)
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
		v.reset(OpMIPS64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] ptr mem)
	// result: (MOVBstore [1] ptr (MOVVconst [0]) (MOVBstore [0] ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [4] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore ptr (MOVVconst [0]) mem)
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
		v.reset(OpMIPS64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [4] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [2] ptr (MOVVconst [0]) (MOVHstore [0] ptr (MOVVconst [0]) mem))
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
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [4] ptr mem)
	// result: (MOVBstore [3] ptr (MOVVconst [0]) (MOVBstore [2] ptr (MOVVconst [0]) (MOVBstore [1] ptr (MOVVconst [0]) (MOVBstore [0] ptr (MOVVconst [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(1)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg3(ptr, v0, mem)
		v2.AddArg3(ptr, v0, v3)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [8] {t} ptr mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVVstore ptr (MOVVconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [8] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [4] ptr (MOVVconst [0]) (MOVWstore [0] ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [8] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [6] ptr (MOVVconst [0]) (MOVHstore [4] ptr (MOVVconst [0]) (MOVHstore [2] ptr (MOVVconst [0]) (MOVHstore [0] ptr (MOVVconst [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(2)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg3(ptr, v0, mem)
		v2.AddArg3(ptr, v0, v3)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [3] ptr mem)
	// result: (MOVBstore [2] ptr (MOVVconst [0]) (MOVBstore [1] ptr (MOVVconst [0]) (MOVBstore [0] ptr (MOVVconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [6] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [4] ptr (MOVVconst [0]) (MOVHstore [2] ptr (MOVVconst [0]) (MOVHstore [0] ptr (MOVVconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [12] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [8] ptr (MOVVconst [0]) (MOVWstore [4] ptr (MOVVconst [0]) (MOVWstore [0] ptr (MOVVconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [16] {t} ptr mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVVstore [8] ptr (MOVVconst [0]) (MOVVstore [0] ptr (MOVVconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [24] {t} ptr mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVVstore [16] ptr (MOVVconst [0]) (MOVVstore [8] ptr (MOVVconst [0]) (MOVVstore [0] ptr (MOVVconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 24 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [s] {t} ptr mem)
	// cond: s%8 == 0 && s > 24 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice
	// result: (DUFFZERO [8 * (128 - s/8)] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(s%8 == 0 && s > 24 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice) {
			break
		}
		v.reset(OpMIPS64DUFFZERO)
		v.AuxInt = int64ToAuxInt(8 * (128 - s/8))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] {t} ptr mem)
	// cond: (s > 8*128 || config.noDuffDevice) || t.Alignment()%8 != 0
	// result: (LoweredZero [t.Alignment()] ptr (ADDVconst <ptr.Type> ptr [s-moveSize(t.Alignment(), config)]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !((s > 8*128 || config.noDuffDevice) || t.Alignment()%8 != 0) {
			break
		}
		v.reset(OpMIPS64LoweredZero)
		v.AuxInt = int64ToAuxInt(t.Alignment())
		v0 := b.NewValue0(v.Pos, OpMIPS64ADDVconst, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - moveSize(t.Alignment(), config))
		v0.AddArg(ptr)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteBlockMIPS64(b *Block) bool {
	switch b.Kind {
	case BlockMIPS64EQ:
		// match: (EQ (FPFlagTrue cmp) yes no)
		// result: (FPF cmp yes no)
		for b.Controls[0].Op == OpMIPS64FPFlagTrue {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPS64FPF, cmp)
			return true
		}
		// match: (EQ (FPFlagFalse cmp) yes no)
		// result: (FPT cmp yes no)
		for b.Controls[0].Op == OpMIPS64FPFlagFalse {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPS64FPT, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGT _ _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGT {
				break
			}
			b.resetWithControl(BlockMIPS64NE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTU _ _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTU {
				break
			}
			b.resetWithControl(BlockMIPS64NE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTconst _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTconst {
				break
			}
			b.resetWithControl(BlockMIPS64NE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTUconst _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTUconst {
				break
			}
			b.resetWithControl(BlockMIPS64NE, cmp)
			return true
		}
		// match: (EQ (SGTUconst [1] x) yes no)
		// result: (NE x yes no)
		for b.Controls[0].Op == OpMIPS64SGTUconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPS64NE, x)
			return true
		}
		// match: (EQ (SGTU x (MOVVconst [0])) yes no)
		// result: (EQ x yes no)
		for b.Controls[0].Op == OpMIPS64SGTU {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, x)
			return true
		}
		// match: (EQ (SGTconst [0] x) yes no)
		// result: (GEZ x yes no)
		for b.Controls[0].Op == OpMIPS64SGTconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPS64GEZ, x)
			return true
		}
		// match: (EQ (SGT x (MOVVconst [0])) yes no)
		// result: (LEZ x yes no)
		for b.Controls[0].Op == OpMIPS64SGT {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockMIPS64LEZ, x)
			return true
		}
		// match: (EQ (MOVVconst [0]) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
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
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c != 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPS64GEZ:
		// match: (GEZ (MOVVconst [c]) yes no)
		// cond: c >= 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
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
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c < 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPS64GTZ:
		// match: (GTZ (MOVVconst [c]) yes no)
		// cond: c > 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
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
		for b.Controls[0].Op == OpMIPS64MOVVconst {
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
		// result: (NE cond yes no)
		for {
			cond := b.Controls[0]
			b.resetWithControl(BlockMIPS64NE, cond)
			return true
		}
	case BlockMIPS64LEZ:
		// match: (LEZ (MOVVconst [c]) yes no)
		// cond: c <= 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
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
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c > 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPS64LTZ:
		// match: (LTZ (MOVVconst [c]) yes no)
		// cond: c < 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
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
		for b.Controls[0].Op == OpMIPS64MOVVconst {
			v_0 := b.Controls[0]
			c := auxIntToInt64(v_0.AuxInt)
			if !(c >= 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPS64NE:
		// match: (NE (FPFlagTrue cmp) yes no)
		// result: (FPT cmp yes no)
		for b.Controls[0].Op == OpMIPS64FPFlagTrue {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPS64FPT, cmp)
			return true
		}
		// match: (NE (FPFlagFalse cmp) yes no)
		// result: (FPF cmp yes no)
		for b.Controls[0].Op == OpMIPS64FPFlagFalse {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPS64FPF, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGT _ _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGT {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTU _ _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTU {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTconst _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTconst {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTUconst _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPS64XORconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPS64SGTUconst {
				break
			}
			b.resetWithControl(BlockMIPS64EQ, cmp)
			return true
		}
		// match: (NE (SGTUconst [1] x) yes no)
		// result: (EQ x yes no)
		for b.Controls[0].Op == OpMIPS64SGTUconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 1 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPS64EQ, x)
			return true
		}
		// match: (NE (SGTU x (MOVVconst [0])) yes no)
		// result: (NE x yes no)
		for b.Controls[0].Op == OpMIPS64SGTU {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockMIPS64NE, x)
			return true
		}
		// match: (NE (SGTconst [0] x) yes no)
		// result: (LTZ x yes no)
		for b.Controls[0].Op == OpMIPS64SGTconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPS64LTZ, x)
			return true
		}
		// match: (NE (SGT x (MOVVconst [0])) yes no)
		// result: (GTZ x yes no)
		for b.Controls[0].Op == OpMIPS64SGT {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			x := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0_1.AuxInt) != 0 {
				break
			}
			b.resetWithControl(BlockMIPS64GTZ, x)
			return true
		}
		// match: (NE (MOVVconst [0]) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPS64MOVVconst {
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
		for b.Controls[0].Op == OpMIPS64MOVVconst {
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

"""




```