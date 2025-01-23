Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first thing is to recognize the file path: `go/src/cmd/compile/internal/ssa/rewriteLOONG64.go`. This immediately tells us we're in the Go compiler's internals, specifically dealing with the Static Single Assignment (SSA) intermediate representation for the LOONG64 architecture. The "rewrite" part suggests this code is responsible for optimizing or transforming the SSA form.

2. **Identify Key Functions:** The code defines several functions starting with `rewriteValueLOONG64_` and `rewriteBlockLOONG64_`. This naming convention is a strong indicator of their purpose: they rewrite `Value` and `Block` nodes in the SSA graph, targeting the LOONG64 architecture.

3. **Analyze `rewriteValueLOONG64_Op...` Functions:** Each of these functions handles a specific SSA operation (`Op`). The general pattern is:
    * **Input:** Takes a pointer to a `Value` (`*Value`).
    * **Matching:** Uses pattern matching on the `Value`'s arguments and auxiliary information (`Aux`, `AuxInt`).
    * **Conditionals:**  Applies conditions to ensure the rewrite is valid and beneficial.
    * **Transformation:** If a match is found and conditions are met, the function modifies the `Value`'s opcode (`reset`), auxiliary information, and arguments to a more efficient or target-specific instruction.
    * **Return Value:** Returns `true` if a rewrite occurred, `false` otherwise.

4. **Focus on Specific Examples:**  Let's take a few examples to understand the rewrites:

    * **`rewriteValueLOONG64_OpCall`:** This looks for calls to `runtime.memmove` with specific conditions (size, single use, inlinability). If these conditions are met, it replaces the call with a direct `OpMove`, likely an optimized instruction for memory movement on LOONG64.

    * **`rewriteValueLOONG64_OpSlicemask`:** This converts a `Slicemask` operation into a sequence of LOONG64 specific instructions (`SRAVconst`, `NEGV`). This demonstrates architecture-specific optimization.

    * **`rewriteValueLOONG64_OpStore`:** This function handles memory stores. It examines the size and type of the data being stored and selects the appropriate LOONG64 store instruction (`MOVBstore`, `MOVHstore`, etc.). This is crucial for correctness and efficiency on the target architecture.

    * **`rewriteValueLOONG64_OpZero`:**  This function deals with zeroing out memory. It has various cases for small sizes, using specific store instructions. For larger sizes, it uses Duff's device or a lowered zeroing loop, again demonstrating optimization strategies.

5. **Analyze `rewriteBlockLOONG64`:** This function works similarly to the `rewriteValue` functions but operates on `Block` nodes in the SSA graph. Blocks represent control flow. The rewrites here transform conditional branches and control flow based on LOONG64-specific instructions and optimizations. Examples include:
    * Simplifying comparisons (`EQ`, `NE`) based on `FPFlag` values or XOR patterns.
    * Replacing generic `If` blocks with LOONG64-specific conditional branches (`BEQ`, `BNE`, `BGE`, etc.).
    * Optimizing branches based on constant values.

6. **Infer Overall Functionality:** By examining the individual rewrites, we can infer the overall purpose of this code: **architecture-specific optimization of the SSA representation for the LOONG64 architecture.**  It aims to translate generic SSA operations into efficient LOONG64 instructions, taking advantage of the architecture's features.

7. **Consider Go Functionality and Examples:**  Relating these rewrites back to Go code, we can see how they impact various Go features:

    * **`memmove` optimization:** This directly relates to operations like copying slices or structs.
    * **`Slicemask`:** This is used internally when working with slices to determine the mask for the slice's capacity.
    * **`Store` and `Zero`:** These are fundamental to memory operations in Go, such as variable assignment, array/slice initialization, and zeroing out memory for security or correctness.
    * **Block rewrites:** These affect how `if`, `else`, `for`, and `switch` statements are compiled into machine code on LOONG64.

8. **Address Specific Questions (as in the prompt):**

    * **Functionality Listing:**  Summarize the purpose of each function based on the analysis above.
    * **Go Feature and Example:**  Choose relevant Go features and construct simple examples that would trigger the rewrites. This involves thinking about the kinds of Go code that would result in the specific SSA operations being rewritten.
    * **Assumptions, Inputs, Outputs:** For code inference, explicitly state the assumptions about the SSA representation and show how an input SSA `Value` is transformed into an output `Value`.
    * **Command-line Arguments:** Since this code is part of the compiler's internals, it doesn't directly handle command-line arguments. The compiler itself takes arguments, but these rewrite functions operate within the compilation process.
    * **Common Mistakes:**  Think about what might go wrong if these rewrites were implemented incorrectly. For example, incorrect size checks in `OpStore` could lead to memory corruption. However, the prompt asks for *user* mistakes, and since this is compiler code, there aren't direct user errors related to this specific file.
    * **Overall Function:**  Provide a concise summary of the code's primary role.

9. **Structure the Answer:** Organize the findings logically, addressing each point in the prompt. Use clear and concise language, and provide code examples where requested.

This structured approach allows for a thorough understanding of the code's functionality and its role within the Go compiler. The key is to connect the low-level SSA rewrites to higher-level Go language concepts.
这是 `go/src/cmd/compile/internal/ssa/rewriteLOONG64.go` 文件的第 8 部分，也是最后一部分。它主要包含针对 LOONG64 架构的 SSA (Static Single Assignment) 中间表示的重写规则，用于优化代码生成。

**归纳一下它的功能:**

总的来说，这个文件的功能是定义了一系列模式匹配和替换规则，用于将 SSA 图中的某些操作（`Op`）和控制流块（`Block`）转换成更适合 LOONG64 架构的等价操作或块。这些转换旨在提高生成代码的效率，例如减少指令数量、利用特定的 LOONG64 指令、优化内存操作等。

**具体功能列举:**

* **`rewriteValueLOONG64_OpCall(v *Value) bool`:**  优化函数调用，特别是针对 `runtime.memmove`。如果满足特定条件（例如，大小非负，调用的是 `runtime.memmove`，只被使用一次，可以内联，并且可以安全地覆盖），则将对 `runtime.memmove` 的调用替换为更底层的 `OpMove` 操作。

* **`rewriteValueLOONG64_OpSlicemask(v *Value) bool`:**  将计算切片掩码的操作 `OpSlicemask` 转换为 LOONG64 特定的指令序列，使用 `SRAVconst` 和 `NEGV`。

* **`rewriteValueLOONG64_OpStore(v *Value) bool`:**  根据存储值的大小和类型，将通用的 `OpStore` 操作替换为 LOONG64 架构特定的存储指令，例如 `MOVBstore` (存储字节)、`MOVHstore` (存储半字)、`MOVWstore` (存储字)、`MOVVstore` (存储双字)、`MOVFstore` (存储单精度浮点数)、`MOVDstore` (存储双精度浮点数)。

* **`rewriteValueLOONG64_OpZero(v *Value) bool`:**  优化将内存区域置零的操作 `OpZero`。针对不同大小的内存区域，使用不同的 LOONG64 指令序列进行优化。对于小尺寸，使用一系列的 `MOVBstore`、`MOVHstore`、`MOVWstore`、`MOVVstore` 指令。对于较大的尺寸，会尝试使用 `DUFFZERO` (Duff's device 的变体) 或者降低为循环的零操作 (`LoweredZero`)。

* **`rewriteBlockLOONG64(b *Block) bool`:**  重写控制流块，例如 `BlockLOONG64EQ` (相等跳转)、`BlockLOONG64GEZ` (大于等于零跳转) 等。它会根据 LOONG64 架构的特性，将某些条件判断或控制流结构转换为更有效的形式。例如，将比较操作和常量值的组合转换为直接的跳转指令。

**Go 语言功能实现推理及代码示例:**

1. **`rewriteValueLOONG64_OpCall` (优化 `runtime.memmove`)**

   这个函数优化了内存复制操作。在 Go 语言中，当你使用 `copy()` 函数或者进行结构体赋值时，如果涉及到内存重叠且无法简单地按字节复制，Go 的运行时会调用 `runtime.memmove` 来安全地执行内存移动。

   ```go
   package main

   import "fmt"

   func main() {
       src := []int{1, 2, 3, 4, 5}
       dst := make([]int, 5)

       // 使用 copy 函数，可能会触发 runtime.memmove
       n := copy(dst, src)
       fmt.Println(dst, n) // Output: [1 2 3 4 5] 5

       // 结构体赋值也可能触发
       type Data struct {
           a int
           b string
       }
       d1 := Data{a: 10, b: "hello"}
       d2 := d1
       fmt.Println(d2) // Output: {10 hello}
   }
   ```

   **假设的 SSA 输入 (针对 `copy` 函数内部的 `runtime.memmove` 调用):**

   ```
   // 假设 call_2 是对 runtime.memmove 的调用
   v1 = ... // dst 的地址
   v2 = ... // src 的地址
   v3 = ... // 要复制的字节数 (sz)
   call_2 = Call {runtime.memmove, v1, v2, v3, mem} // mem 是当前的内存状态
   ```

   **假设的 SSA 输出 (如果满足优化条件):**

   ```
   v_new = Move <mem> v1, v2, v3 // 使用 OpMove 指令
   ```

2. **`rewriteValueLOONG64_OpSlicemask` (计算切片掩码)**

   切片掩码用于确定切片的容量的最大值。例如，一个容量为 8 的切片，其掩码为 7 (二进制 `0111`)。

   ```go
   package main

   import "fmt"

   func main() {
       s := make([]int, 3, 8)
       // 编译器内部会使用 Slicemask 来计算容量的掩码
       _ = cap(s) // 实际上，cap() 函数的实现会用到类似的操作
       fmt.Println("Capacity:", cap(s))
   }
   ```

   **假设的 SSA 输入:**

   ```
   v1 = ... // 代表切片容量的值 (例如 8)
   slicemask_op = Slicemask <TypeInt> v1
   ```

   **假设的 SSA 输出:**

   ```
   neg_v1 = NEGV <TypeInt> v1
   srav_op = SRAVconst <TypeInt> neg_v1 [63]
   ```

3. **`rewriteValueLOONG64_OpStore` (内存存储)**

   当我们给变量赋值时，就会涉及到内存存储操作。

   ```go
   package main

   func main() {
       var i int8 = 10
       var j int32 = 1000
       var f float32 = 3.14
       _ = i
       _ = j
       _ = f
   }
   ```

   **假设的 SSA 输入 (对于 `var i int8 = 10`):**

   ```
   ptr_i = ... // 变量 i 的地址
   value_10 = ConstInt8 [10]
   store_op = Store {int8} ptr_i value_10 mem
   ```

   **假设的 SSA 输出:**

   ```
   movbstore_op = MOVBstore ptr_i value_10 mem
   ```

4. **`rewriteValueLOONG64_OpZero` (内存置零)**

   当声明变量但未初始化，或者使用 `make()` 创建切片、map 等时，可能需要将内存置零。

   ```go
   package main

   import "fmt"

   func main() {
       var arr [10]int // 数组未初始化，内存可能需要置零
       s := make([]int, 5) // 新创建的切片，底层数组需要置零
       fmt.Println(arr, s)
   }
   ```

   **假设的 SSA 输入 (对于 `var arr [10]int` 的部分置零操作):**

   ```
   ptr_arr = ... // 数组 arr 的起始地址
   zero_op = Zero [80] ptr_arr mem // 假设 int 是 8 字节，10 个 int 是 80 字节
   ```

   **假设的 SSA 输出 (对于小尺寸，例如 8 字节):**

   ```
   const_0 = MOVVconst [0]
   movvstore_op = MOVVstore ptr_arr const_0 mem
   ```

**命令行参数处理:**

这个文件中的代码是 Go 编译器内部的 SSA 重写规则，它不直接处理命令行参数。Go 编译器的命令行参数由 `go build` 等命令处理，这些参数会影响编译过程，但不会直接传递到这个文件中定义的重写函数中。这个文件在编译过程的 SSA 生成和优化阶段起作用。

**使用者易犯错的点:**

由于这个文件是编译器内部实现，普通 Go 语言使用者不会直接与之交互，因此不存在使用者易犯错的点。开发者可能会在编写新的 SSA 重写规则时犯错，例如：

* **模式匹配不准确:**  导致不应该被重写的代码被错误地修改。
* **条件判断错误:**  使得重写在不应该发生的场景下发生，或者应该发生的场景下没有发生。
* **生成的指令序列不正确:**  导致代码逻辑错误或性能下降。

**总结 `rewriteLOONG64.go` 的功能:**

这个文件是 Go 编译器针对 LOONG64 架构进行代码优化的核心组成部分。它定义了一系列的规则，用于在 SSA 中间表示层面上将通用的操作转换成更高效、更贴合 LOONG64 硬件特性的指令序列。这些优化涵盖了函数调用、内存操作、位运算、控制流等多个方面，最终目的是提升 Go 程序在 LOONG64 架构上的执行效率。作为最后一部分，它与其他部分的 `rewriteLOONG64.go` 文件共同完成了针对 LOONG64 架构的 SSA 重写工作。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteLOONG64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第8部分，共8部分，请归纳一下它的功能
```

### 源代码
```go
(call_2.AuxInt)
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