Response:
My thinking process to answer the prompt goes like this:

1. **Understand the Goal:** The prompt asks for the functionality of a specific Go code snippet within the `rewriteAMD64.go` file, which is part of the Go compiler's SSA (Static Single Assignment) optimization phase for the AMD64 architecture. The goal is to explain *what* this code does and *why* it does it.

2. **Analyze the Code Structure:** I see a series of `for` loops within a function. Each loop has a `match:` comment indicating a pattern it's trying to find in the SSA representation, a `cond:` comment with a condition that must be true, and a `result:` comment showing how the matched pattern should be rewritten. This strongly suggests that this section of the code implements *peephole optimizations* or *rewrite rules*. The `v.reset(...)` and `b.NewValue0(...)` calls confirm this, as they are used to modify the SSA graph.

3. **Focus on the `Zero` Op:**  The outer loop iterates through nodes where `v.Op == OpZero`. This immediately tells me that the code is specifically concerned with optimizing operations that zero out memory. The `AuxInt` field of the `Zero` op likely stores the size of the memory region to be zeroed. The arguments `destptr` and `mem` are likely the destination pointer and the memory operand (representing the side effect of the zeroing operation).

4. **Examine Individual Rewrite Rules:** Now, I go through each `match`, `cond`, and `result` block.

   * **Small Sizes (<= 12 bytes):** The initial rules handle small zeroing operations (up to 12 bytes) by replacing the `Zero` op with a sequence of `MOVQstoreconst` (move quadword constant to memory) operations. This is an optimization because direct `MOVQstoreconst` is often more efficient for small sizes than a generic zeroing loop or function call.

   * **Sizes near 16 bytes (13-15 bytes):** The next rule handles sizes slightly smaller than 16 bytes. It cleverly uses two `MOVQstoreconst` operations to zero out the memory.

   * **Sizes greater than 16 bytes with remainders:** The rules for `s % 16 != 0` handle cases where the size isn't a multiple of 16. They break the zeroing down into a `Zero` operation for the largest multiple of 16 less than the target size and a `MOVOstoreconst` (move octoword constant to memory) for the remaining bytes. The `OffPtr` op is used to adjust the starting address for the initial `Zero` operation.

   * **Specific Powers of 2 (16, 32, 48, 64):**  There are explicit rules for zeroing 16, 32, 48, and 64 bytes using sequences of `MOVOstoreconst`. This shows an optimization strategy that favors these SIMD-friendly 16-byte moves.

   * **Larger Multiples of 16 (up to 1024 bytes):** The rule for `s > 64 && s <= 1024 && s%16 == 0 && !config.noDuffDevice` introduces `OpAMD64DUFFZERO`. This suggests the use of a Duff's device optimization, a technique for unrolling loops to improve performance. The `config.noDuffDevice` check indicates a way to disable this optimization.

   * **Even Larger Sizes:** Finally, the rule for `s > 1024` (or other conditions) utilizes `OpAMD64REPSTOSQ`. This signifies using the `rep stosq` instruction, which is an efficient way to fill a large memory region with a constant value (in this case, zero).

5. **Identify Go Language Features:** The code optimizes memory zeroing, which is a fundamental operation in many Go programs. I can think of scenarios where Go implicitly or explicitly performs zeroing:

   * **`make()` for slices and maps:** When you create a slice or map using `make()`, the underlying memory is zeroed.
   * **Variable declaration without initialization:** Declaring a variable without an initial value (e.g., `var x int`) initializes it to its zero value. For structs and arrays, this means all fields/elements are zeroed.

6. **Construct Go Examples:** Based on the identified features, I create simple Go code examples that would trigger the zeroing optimizations.

7. **Infer Command-Line Arguments (if applicable):**  The `config.useSSE` and `config.noDuffDevice` checks suggest that there might be compiler flags or build configurations that influence these optimizations. I make an educated guess about what these flags might be called (e.g., `-gcflags="-N"` to disable optimizations, though this is a general optimization flag, not specific to these rules).

8. **Identify Potential Pitfalls:**  While this specific code section doesn't directly expose user-level pitfalls, understanding its behavior helps in debugging performance issues related to memory operations. If someone is seeing unexpected performance for memory zeroing, understanding these optimization rules could be helpful.

9. **Synthesize the Functionality Summary:** I combine my understanding of the individual rewrite rules into a concise summary of the code's overall function, highlighting its focus on optimizing memory zeroing for different sizes and hardware capabilities.

10. **Address the "Part 22 of 23" aspect:** This implies the code is part of a larger sequence of rewrite passes. I conclude that this specific part focuses on `OpZero` and that the overall file handles architecture-specific rewrites for AMD64.

By following this breakdown, I can systematically analyze the code and generate a comprehensive answer that addresses all parts of the prompt. The key is to recognize the pattern-matching nature of the code and connect it to the underlying Go language features and potential compiler behaviors.
这是第22部分，共23部分，`go/src/cmd/compile/internal/ssa/rewriteAMD64.go` 文件主要负责定义 AMD64 架构下 SSA（Static Single Assignment）形式的中间代码的重写规则。这些规则旨在将通用的 SSA 操作转换为更具体、更高效的 AMD64 汇编指令序列。

**这个特定部分（第22部分）的功能是优化 `OpZero` 操作。** `OpZero` 表示将一块内存区域填充为零。这部分代码根据要清零的内存大小和编译器的配置（例如是否使用 SSE 指令集，是否禁用 Duff's device 优化）应用不同的优化策略。

**具体功能分解：**

1. **小尺寸优化 (<= 12 字节):**  对于非常小的内存块（不超过 12 字节），它会将 `OpZero` 替换为一系列 `MOVQstoreconst` 指令，每次移动 8 字节的 0。这比调用通用的清零函数更高效。

2. **接近 16 字节的优化 (13-15 字节):** 对于 13 到 15 字节的内存块，它使用两个 `MOVQstoreconst` 指令来清零。

3. **非 16 字节对齐的大尺寸优化 (> 16 字节):**
   - 如果大小不是 16 的倍数，并且剩余部分大于 8 字节或小于等于 8 字节，它会将 `OpZero` 分解为两部分：
     - 一个 `Zero` 操作，用于清零大小减去剩余部分的大小。
     - 一个 `MOVOstoreconst` 操作，用于清零剩余部分（16 字节）。`OffPtr` 用于调整目标地址。

4. **16, 32, 48, 64 字节的优化:** 对于 16、32、48 和 64 字节的特定大小，它使用 `MOVOstoreconst` 指令的组合来高效地清零内存。`MOVOstoreconst` 每次移动 16 字节。

5. **较大尺寸且为 16 字节倍数的优化 (64 < size <= 1024):** 如果内存大小在 64 到 1024 字节之间，并且是 16 的倍数，且编译器配置允许使用 Duff's device 优化，它会将 `OpZero` 替换为 `OpAMD64DUFFZERO` 指令。Duff's device 是一种循环展开的优化技术，可以提高大块内存清零的性能。

6. **更大尺寸或不满足 Duff's device 条件的优化:** 对于更大的内存块，或者在禁用 Duff's device 或不支持 SSE 的情况下，且大小是 8 的倍数，它会将 `OpZero` 替换为 `OpAMD64REPSTOSQ` 指令。`REPSTOSQ` 是 AMD64 架构提供的字符串存储指令，可以高效地将一个值（这里是 0）重复写入内存。

**Go 语言功能实现示例：**

这部分代码优化的主要是 Go 语言中将内存初始化为零值的场景，例如：

```go
package main

import "fmt"

func main() {
	// 声明一个未初始化的数组，其元素会被零值初始化
	var arr [10]int
	fmt.Println(arr) // 输出: [0 0 0 0 0 0 0 0 0 0]

	// 使用 make 创建切片，底层数组会被零值初始化
	slice := make([]int, 5)
	fmt.Println(slice) // 输出: [0 0 0 0 0]

	// 声明一个结构体变量，其字段会被零值初始化
	var s struct {
		A int
		B string
	}
	fmt.Println(s) // 输出: {0 }
}
```

在编译上述代码时，编译器会将数组、切片底层数组和结构体的内存初始化为零。`rewriteAMD64.go` 的这部分代码就是在优化这些零值初始化的操作。

**代码推理示例：**

假设有以下 Go 代码：

```go
package main

func main() {
	var arr [13]byte
	_ = arr
}
```

**假设的输入 SSA (`OpZero` 节点):**

```
v1 = OpZero [13] destptr mem
```

其中 `destptr` 指向 `arr` 的起始地址，`mem` 是内存状态。

**输出 SSA (根据代码中的一个匹配规则):**

```
v2 = OpAMD64MOVQstoreconst [valAndOffToAuxInt(makeValAndOff(0, 0))] destptr mem
v3 = OpAMD64MOVQstoreconst [valAndOffToAuxInt(makeValAndOff(0, 5))] destptr v2
```

这里将 13 字节的 `OpZero` 拆分成两个 `MOVQstoreconst` 指令。第一个 `MOVQstoreconst` 将 8 字节的 0 写入 `destptr`。第二个 `MOVQstoreconst` 将 8 字节的 0 写入 `destptr + 5`，但实际上只会覆盖剩余的 5 字节。

**命令行参数的具体处理：**

这段代码中涉及的命令行参数主要是通过 `config` 对象来体现的，这个 `config` 对象在编译过程中会被填充。相关的配置可能包括：

- **`-gcflags "-sse4.1"` 或类似的标志:**  这些标志会影响 `config.useSSE` 的值，指示编译器是否可以生成使用 SSE 指令集的代码。如果设置了相应的 SSE 版本，则 `config.useSSE` 为 true，反之为 false。

- **`-gcflags "-N"`:** 这个标志通常会禁用所有的优化，包括这里的 `OpZero` 优化。如果禁用优化，这段代码的规则可能不会被应用。

- **可能还存在一些更细粒度的控制标志**，用于控制是否启用 Duff's device 优化等，但这在给定的代码片段中没有直接体现，可能在 `config` 对象的其他部分或编译器的其他阶段处理。

**使用者易犯错的点：**

通常开发者不需要直接关心这些底层的 SSA 重写规则。这些是编译器内部的优化，对于最终生成的代码性能有影响，但不会改变代码的语义。

**总结一下它的功能：**

这是 `rewriteAMD64.go` 文件的一部分，专门负责优化 `OpZero` 操作。它根据要清零的内存大小和编译器的配置，选择最合适的 AMD64 汇编指令序列来高效地将内存填充为零。优化的策略包括使用 `MOVQstoreconst` 处理小尺寸，使用 `MOVOstoreconst` 处理 16 字节的倍数，使用 Duff's device 优化中等大小的内存块，以及使用 `REPSTOSQ` 处理大尺寸的内存块。这些优化旨在提高 Go 程序在 AMD64 架构上的性能，特别是在涉及大量内存初始化的场景中。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第22部分，共23部分，请归纳一下它的功能

"""
= b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s > 12 && s < 16 && config.useSSE
	// result: (MOVQstoreconst [makeValAndOff(0,int32(s-8))] destptr (MOVQstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s > 12 && s < 16 && config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVQstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, int32(s-8)))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s%16 != 0 && s > 16 && s%16 > 8 && config.useSSE
	// result: (Zero [s-s%16] (OffPtr <destptr.Type> destptr [s%16]) (MOVOstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s%16 != 0 && s > 16 && s%16 > 8 && config.useSSE) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(s - s%16)
		v0 := b.NewValue0(v.Pos, OpOffPtr, destptr.Type)
		v0.AuxInt = int64ToAuxInt(s % 16)
		v0.AddArg(destptr)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v1.AddArg2(destptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s%16 != 0 && s > 16 && s%16 <= 8 && config.useSSE
	// result: (Zero [s-s%16] (OffPtr <destptr.Type> destptr [s%16]) (MOVOstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s%16 != 0 && s > 16 && s%16 <= 8 && config.useSSE) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(s - s%16)
		v0 := b.NewValue0(v.Pos, OpOffPtr, destptr.Type)
		v0.AuxInt = int64ToAuxInt(s % 16)
		v0.AddArg(destptr)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v1.AddArg2(destptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [16] destptr mem)
	// cond: config.useSSE
	// result: (MOVOstoreconst [makeValAndOff(0,0)] destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [32] destptr mem)
	// cond: config.useSSE
	// result: (MOVOstoreconst [makeValAndOff(0,16)] destptr (MOVOstoreconst [makeValAndOff(0,0)] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 16))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [48] destptr mem)
	// cond: config.useSSE
	// result: (MOVOstoreconst [makeValAndOff(0,32)] destptr (MOVOstoreconst [makeValAndOff(0,16)] destptr (MOVOstoreconst [makeValAndOff(0,0)] destptr mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 48 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 32))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 16))
		v1 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v1.AddArg2(destptr, mem)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [64] destptr mem)
	// cond: config.useSSE
	// result: (MOVOstoreconst [makeValAndOff(0,48)] destptr (MOVOstoreconst [makeValAndOff(0,32)] destptr (MOVOstoreconst [makeValAndOff(0,16)] destptr (MOVOstoreconst [makeValAndOff(0,0)] destptr mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 64 {
			break
		}
		destptr := v_0
		mem := v_1
		if !(config.useSSE) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 48))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 32))
		v1 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v1.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 16))
		v2 := b.NewValue0(v.Pos, OpAMD64MOVOstoreconst, types.TypeMem)
		v2.AuxInt = valAndOffToAuxInt(makeValAndOff(0, 0))
		v2.AddArg2(destptr, mem)
		v1.AddArg2(destptr, v2)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: s > 64 && s <= 1024 && s%16 == 0 && !config.noDuffDevice
	// result: (DUFFZERO [s] destptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !(s > 64 && s <= 1024 && s%16 == 0 && !config.noDuffDevice) {
			break
		}
		v.reset(OpAMD64DUFFZERO)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [s] destptr mem)
	// cond: (s > 1024 || (config.noDuffDevice && s > 64 || !config.useSSE && s > 32)) && s%8 == 0
	// result: (REPSTOSQ destptr (MOVQconst [s/8]) (MOVQconst [0]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		destptr := v_0
		mem := v_1
		if !((s > 1024 || (config.noDuffDevice && s > 64 || !config.useSSE && s > 32)) && s%8 == 0) {
			break
		}
		v.reset(OpAMD64REPSTOSQ)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(s / 8)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVQconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg4(destptr, v0, v1, mem)
		return true
	}
	return false
}
func rewriteBlockAMD64(b *Block) bool {
	typ := &b.Func.Config.Types
	switch b.Kind {
	case BlockAMD64EQ:
		// match: (EQ (TESTL (SHLL (MOVLconst [1]) x) y))
		// result: (UGE (BTL x y))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64SHLL {
					continue
				}
				x := v_0_0.Args[1]
				v_0_0_0 := v_0_0.Args[0]
				if v_0_0_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0_0_0.AuxInt) != 1 {
					continue
				}
				y := v_0_1
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTL, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTQ (SHLQ (MOVQconst [1]) x) y))
		// result: (UGE (BTQ x y))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64SHLQ {
					continue
				}
				x := v_0_0.Args[1]
				v_0_0_0 := v_0_0.Args[0]
				if v_0_0_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_0_0_0.AuxInt) != 1 {
					continue
				}
				y := v_0_1
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQ, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTLconst [c] x))
		// cond: isUint32PowerOfTwo(int64(c))
		// result: (UGE (BTLconst [int8(log32(c))] x))
		for b.Controls[0].Op == OpAMD64TESTLconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(isUint32PowerOfTwo(int64(c))) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log32(c)))
			v0.AddArg(x)
			b.resetWithControl(BlockAMD64UGE, v0)
			return true
		}
		// match: (EQ (TESTQconst [c] x))
		// cond: isUint64PowerOfTwo(int64(c))
		// result: (UGE (BTQconst [int8(log32(c))] x))
		for b.Controls[0].Op == OpAMD64TESTQconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(isUint64PowerOfTwo(int64(c))) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log32(c)))
			v0.AddArg(x)
			b.resetWithControl(BlockAMD64UGE, v0)
			return true
		}
		// match: (EQ (TESTQ (MOVQconst [c]) x))
		// cond: isUint64PowerOfTwo(c)
		// result: (UGE (BTQconst [int8(log64(c))] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64MOVQconst {
					continue
				}
				c := auxIntToInt64(v_0_0.AuxInt)
				x := v_0_1
				if !(isUint64PowerOfTwo(c)) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(int8(log64(c)))
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2))
		// cond: z1==z2
		// result: (UGE (BTQconst [63] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHLQconst || auxIntToInt8(z1.AuxInt) != 63 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHRQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(63)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTL z1:(SHLLconst [31] (SHRQconst [31] x)) z2))
		// cond: z1==z2
		// result: (UGE (BTQconst [31] x))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHLLconst || auxIntToInt8(z1.AuxInt) != 31 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHRQconst || auxIntToInt8(z1_0.AuxInt) != 31 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(31)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTQ z1:(SHRQconst [63] (SHLQconst [63] x)) z2))
		// cond: z1==z2
		// result: (UGE (BTQconst [0] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHLQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(0)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTL z1:(SHRLconst [31] (SHLLconst [31] x)) z2))
		// cond: z1==z2
		// result: (UGE (BTLconst [0] x))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHLLconst || auxIntToInt8(z1_0.AuxInt) != 31 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTLconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(0)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTQ z1:(SHRQconst [63] x) z2))
		// cond: z1==z2
		// result: (UGE (BTQconst [63] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
					continue
				}
				x := z1.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(63)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTL z1:(SHRLconst [31] x) z2))
		// cond: z1==z2
		// result: (UGE (BTLconst [31] x))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
					continue
				}
				x := z1.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTLconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(31)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64UGE, v0)
				return true
			}
			break
		}
		// match: (EQ (InvertFlags cmp) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64EQ, cmp)
			return true
		}
		// match: (EQ (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (EQ (FlagLT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagLT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagGT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagGT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (TESTQ s:(Select0 blsr:(BLSRQ _)) s) yes no)
		// result: (EQ (Select1 <types.TypeFlags> blsr) yes no)
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				s := v_0_0
				if s.Op != OpSelect0 {
					continue
				}
				blsr := s.Args[0]
				if blsr.Op != OpAMD64BLSRQ || s != v_0_1 {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v0.AddArg(blsr)
				b.resetWithControl(BlockAMD64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (TESTL s:(Select0 blsr:(BLSRL _)) s) yes no)
		// result: (EQ (Select1 <types.TypeFlags> blsr) yes no)
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				s := v_0_0
				if s.Op != OpSelect0 {
					continue
				}
				blsr := s.Args[0]
				if blsr.Op != OpAMD64BLSRL || s != v_0_1 {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v0.AddArg(blsr)
				b.resetWithControl(BlockAMD64EQ, v0)
				return true
			}
			break
		}
	case BlockAMD64GE:
		// match: (GE (InvertFlags cmp) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64LE, cmp)
			return true
		}
		// match: (GE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (FlagLT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GE (FlagLT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GE (FlagGT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (FlagGT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			return true
		}
	case BlockAMD64GT:
		// match: (GT (InvertFlags cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64LT, cmp)
			return true
		}
		// match: (GT (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagLT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagLT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagGT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GT (FlagGT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			return true
		}
	case BlockIf:
		// match: (If (SETL cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETL {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64LT, cmp)
			return true
		}
		// match: (If (SETLE cmp) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETLE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64LE, cmp)
			return true
		}
		// match: (If (SETG cmp) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETG {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64GT, cmp)
			return true
		}
		// match: (If (SETGE cmp) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETGE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64GE, cmp)
			return true
		}
		// match: (If (SETEQ cmp) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpAMD64SETEQ {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64EQ, cmp)
			return true
		}
		// match: (If (SETNE cmp) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETNE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64NE, cmp)
			return true
		}
		// match: (If (SETB cmp) yes no)
		// result: (ULT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETB {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64ULT, cmp)
			return true
		}
		// match: (If (SETBE cmp) yes no)
		// result: (ULE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETBE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64ULE, cmp)
			return true
		}
		// match: (If (SETA cmp) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETA {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64UGT, cmp)
			return true
		}
		// match: (If (SETAE cmp) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETAE {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64UGE, cmp)
			return true
		}
		// match: (If (SETO cmp) yes no)
		// result: (OS cmp yes no)
		for b.Controls[0].Op == OpAMD64SETO {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64OS, cmp)
			return true
		}
		// match: (If (SETGF cmp) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == OpAMD64SETGF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64UGT, cmp)
			return true
		}
		// match: (If (SETGEF cmp) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == OpAMD64SETGEF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64UGE, cmp)
			return true
		}
		// match: (If (SETEQF cmp) yes no)
		// result: (EQF cmp yes no)
		for b.Controls[0].Op == OpAMD64SETEQF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64EQF, cmp)
			return true
		}
		// match: (If (SETNEF cmp) yes no)
		// result: (NEF cmp yes no)
		for b.Controls[0].Op == OpAMD64SETNEF {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64NEF, cmp)
			return true
		}
		// match: (If cond yes no)
		// result: (NE (TESTB cond cond) yes no)
		for {
			cond := b.Controls[0]
			v0 := b.NewValue0(cond.Pos, OpAMD64TESTB, types.TypeFlags)
			v0.AddArg2(cond, cond)
			b.resetWithControl(BlockAMD64NE, v0)
			return true
		}
	case BlockJumpTable:
		// match: (JumpTable idx)
		// result: (JUMPTABLE {makeJumpTableSym(b)} idx (LEAQ <typ.Uintptr> {makeJumpTableSym(b)} (SB)))
		for {
			idx := b.Controls[0]
			v0 := b.NewValue0(b.Pos, OpAMD64LEAQ, typ.Uintptr)
			v0.Aux = symToAux(makeJumpTableSym(b))
			v1 := b.NewValue0(b.Pos, OpSB, typ.Uintptr)
			v0.AddArg(v1)
			b.resetWithControl2(BlockAMD64JUMPTABLE, idx, v0)
			b.Aux = symToAux(makeJumpTableSym(b))
			return true
		}
	case BlockAMD64LE:
		// match: (LE (InvertFlags cmp) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64GE, cmp)
			return true
		}
		// match: (LE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagLT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagLT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagGT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LE (FlagGT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockAMD64LT:
		// match: (LT (InvertFlags cmp) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == OpAMD64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockAMD64GT, cmp)
			return true
		}
		// match: (LT (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LT (FlagLT_ULT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagLT_ULT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LT (FlagLT_UGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpAMD64FlagLT_UGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LT (FlagGT_ULT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_ULT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LT (FlagGT_UGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpAMD64FlagGT_UGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockAMD64NE:
		// match: (NE (TESTB (SETL cmp) (SETL cmp)) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETL {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETL || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64LT, cmp)
			return true
		}
		// match: (NE (TESTB (SETLE cmp) (SETLE cmp)) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETLE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETLE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64LE, cmp)
			return true
		}
		// match: (NE (TESTB (SETG cmp) (SETG cmp)) yes no)
		// result: (GT cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETG {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETG || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64GT, cmp)
			return true
		}
		// match: (NE (TESTB (SETGE cmp) (SETGE cmp)) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETGE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETGE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64GE, cmp)
			return true
		}
		// match: (NE (TESTB (SETEQ cmp) (SETEQ cmp)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETEQ {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETEQ || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64EQ, cmp)
			return true
		}
		// match: (NE (TESTB (SETNE cmp) (SETNE cmp)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETNE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETNE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64NE, cmp)
			return true
		}
		// match: (NE (TESTB (SETB cmp) (SETB cmp)) yes no)
		// result: (ULT cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETB {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETB || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64ULT, cmp)
			return true
		}
		// match: (NE (TESTB (SETBE cmp) (SETBE cmp)) yes no)
		// result: (ULE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETBE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETBE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64ULE, cmp)
			return true
		}
		// match: (NE (TESTB (SETA cmp) (SETA cmp)) yes no)
		// result: (UGT cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETA {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETA || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64UGT, cmp)
			return true
		}
		// match: (NE (TESTB (SETAE cmp) (SETAE cmp)) yes no)
		// result: (UGE cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETAE {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETAE || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64UGE, cmp)
			return true
		}
		// match: (NE (TESTB (SETO cmp) (SETO cmp)) yes no)
		// result: (OS cmp yes no)
		for b.Controls[0].Op == OpAMD64TESTB {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64SETO {
				break
			}
			cmp := v_0_0.Args[0]
			v_0_1 := v_0.Args[1]
			if v_0_1.Op != OpAMD64SETO || cmp != v_0_1.Args[0] {
				break
			}
			b.resetWithControl(BlockAMD64OS, cmp)
			return true
		}
		// match: (NE (TESTL (SHLL (MOVLconst [1]) x) y))
		// result: (ULT (BTL x y))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64SHLL {
					continue
				}
				x := v_0_0.Args[1]
				v_0_0_0 := v_0_0.Args[0]
				if v_0_0_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0_0_0.AuxInt) != 1 {
					continue
				}
				y := v_0_1
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTL, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockAMD64ULT, v0)
				return true
			}
			break
		}
		// match: (NE (TESTQ (SHLQ (MOVQconst [1]) x) y))
		// result: (ULT (BTQ x y))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64SHLQ {
					continue
				}
				x := v_0_0.Args[1]
				v_0_0_0 := v_0_0.Args[0]
				if v_0_0_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_0_0_0.AuxInt) != 1 {
					continue
				}
				y := v_0_1
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQ, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockAMD64ULT, v0)
				return true
			}
			break
		}
		// match: (NE (TESTLconst [c] x))
		// cond: isUint32PowerOfTwo(int64(c))
		// result: (ULT (BTLconst [int8(log32(c))] x))
		for b.Controls[0].Op == OpAMD64TESTLconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(isUint32PowerOfTwo(int64(c))) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log32(c)))
			v0.AddArg(x)
			b.resetWithControl(BlockAMD64ULT, v0)
			return true
		}
		// match: (NE (TESTQconst [c] x))
		// cond: isUint64PowerOfTwo(int64(c))
		// result: (ULT (BTQconst [int8(log32(c))] x))
		for b.Controls[0].Op == OpAMD64TESTQconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if !(isUint64PowerOfTwo(int64(c))) {
				break
			}
			v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log32(c)))
			v0.AddArg(x)
			b.resetWithControl(BlockAMD64ULT, v0)
			return true
		}
		// match: (NE (TESTQ (MOVQconst [c]) x))
		// cond: isUint64PowerOfTwo(c)
		// result: (ULT (BTQconst [int8(log64(c))] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				if v_0_0.Op != OpAMD64MOVQconst {
					continue
				}
				c := auxIntToInt64(v_0_0.AuxInt)
				x := v_0_1
				if !(isUint64PowerOfTwo(c)) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(int8(log64(c)))
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64ULT, v0)
				return true
			}
			break
		}
		// match: (NE (TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2))
		// cond: z1==z2
		// result: (ULT (BTQconst [63] x))
		for b.Controls[0].Op == OpAMD64TESTQ {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := v_0_0
				if z1.Op != OpAMD64SHLQconst || auxIntToInt8(z1.AuxInt) != 63 {
					continue
				}
				z1_0 := z1.Args[0]
				if z1_0.Op != OpAMD64SHRQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
					continue
				}
				x := z1_0.Args[0]
				z2 := v_0_1
				if !(z1 == z2) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpAMD64BTQconst, types.TypeFlags)
				v0.AuxInt = int8ToAuxInt(63)
				v0.AddArg(x)
				b.resetWithControl(BlockAMD64ULT, v0)
				return true
			}
			break
		}
		// match: (NE (TESTL z1:(SHLLconst [31] (SHRQconst [31] x)) z2))
		// cond: z1==z2
		// result: (ULT (BTQconst [31] x))
		for b.Controls[0].Op == OpAMD64TESTL {
			v_0 := b.Controls[0]
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
				z1 := 
"""




```