Response:
Let's break down the thought process for analyzing this Go code snippet and generating the comprehensive answer.

**1. Understanding the Goal:**

The core request is to analyze a specific Go file (`rewritegeneric.go`) within the Go compiler, focusing on a particular segment (part 23 of 26). The key is to understand *what* this code does, *how* it achieves it, and illustrate it with examples. The decomposed instructions highlight specific areas to cover: functionality, underlying Go feature, code examples, input/output assumptions, command-line arguments (if applicable), and common mistakes. Finally, a summary of the current section's functionality is required.

**2. Initial Code Scan & Pattern Recognition:**

The first step is to quickly read through the code, looking for repeating patterns and keywords. Immediately noticeable are:

* **`rewriteValuegeneric_Op...` functions:** This naming convention strongly suggests that these functions are part of a rewrite system, likely operating on the SSA (Static Single Assignment) intermediate representation of Go code. Each function seems to handle a specific SSA operation (`Op`).
* **`v *Value`:** The input to these functions is a `*Value`, a key component of the SSA representation.
* **`v.Args`, `v.Aux`, `v.AuxInt`, `v.reset(...)`, `b.NewValue0(...)`:** These are standard methods and fields used to inspect and manipulate SSA values and blocks.
* **`match: (...)`, `cond: (...)`, `result: (...)`:** These comments are crucial. They clearly delineate the matching patterns in the SSA graph, the conditions under which a rewrite occurs, and the resulting transformation. This is the heart of the rewrite rules.
* **Specific `Op` codes like `OpStaticLECall`, `OpAddr`, `OpSB`, `OpConst64`, `OpLoad`, `OpEq8`, `OpMakeResult`, `OpStore`, `OpStringLen`, `OpStringPtr`, `OpStructSelect`, `OpSub16`, etc.:** These indicate the types of operations being analyzed and optimized.
* **References to `runtime.memequal` and `runtime.makeslice`:** This hints at the code's involvement in optimizing common runtime functions.
* **Checks like `isSameCall`, `symIsRO`, `canLoadUnaligned`, `isSamePtr`, `isConstZero`, `disjoint`, `clobber`, `CanSSA`:** These are helper functions/conditions used to refine the rewrite rules.

**3. Deeper Dive into Specific Code Blocks:**

Now, focus on individual `rewriteValuegeneric_Op...` functions.

* **`rewriteValuegeneric_OpStaticLECall`:**  The multiple `match`/`cond`/`result` blocks strongly suggest a series of optimizations for `StaticLECall` operations. The conditions often involve checking the called function (`runtime.memequal`, `runtime.makeslice`), the types and values of arguments, and properties of memory locations (read-only, alignment). The results often transform these calls into more efficient operations like direct comparisons (`OpEq8`, `OpEq16`, etc.) or constant values.

* **`rewriteValuegeneric_OpStore`:** This function deals with optimizations related to storing values in memory. It looks for patterns involving loading values before storing them, zeroing memory, and potentially combining multiple store operations into more efficient ones (`OpMove`). The conditions often involve checking for pointer equality, disjoint memory regions, and the size of data being moved.

* **`rewriteValuegeneric_OpStringLen` and `rewriteValuegeneric_OpStringPtr`:** These are simpler, focusing on optimizing the retrieval of the length and pointer of a string, particularly when the string is constructed using `StringMake`.

* **`rewriteValuegeneric_OpStructSelect`:** This function optimizes accessing fields within a struct. It handles cases where the struct is being created directly (`StructMake`) or loaded from memory.

* **`rewriteValuegeneric_OpSub16`:** This shows a simple optimization for subtracting constant 16-bit integers.

**4. Inferring the Underlying Go Feature:**

Based on the patterns observed, the strong connection to `runtime.memequal` and `runtime.makeslice`, along with the focus on memory operations and comparisons, suggests that this code is involved in optimizing:

* **String and Slice Operations:**  `runtime.memequal` is used for comparing memory regions, which is fundamental to string and slice equality checks. `runtime.makeslice` is used for creating slices.
* **Memory Access Efficiency:** The optimizations in `OpStore` aim to reduce redundant loads and stores, and potentially combine multiple stores.
* **Struct Field Access:** `OpStructSelect` directly targets the efficiency of accessing struct fields.

**5. Constructing Examples and Assumptions:**

For each key optimization, create a simple Go code example that would trigger the rewrite rule. Then, based on the `match` pattern, describe the input SSA and the resulting output SSA after the transformation. This requires understanding the basic structure of SSA.

**6. Command-Line Arguments:**

A quick search or knowledge of the Go compiler reveals that there aren't specific command-line arguments to directly control *these specific* SSA rewrites. However, general optimization flags like `-gcflags "-N"` (disable optimizations) or `-gcflags "-l"` (disable inlining) would affect the overall compilation process and potentially prevent these rewrites from occurring.

**7. Identifying Common Mistakes:**

Think about scenarios where a programmer might write code that looks like the "before" state of a rewrite rule. For example, manually comparing byte-by-byte when `==` would suffice for strings. Or, repeatedly accessing the same struct field when a local variable could be used.

**8. Synthesizing the Summary:**

Finally, condense the observations into a concise summary of the section's functionality. Focus on the common thread linking the different `rewriteValuegeneric_Op...` functions.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is about generic programming. **Correction:** While the filename is `rewritegeneric.go`, the content heavily focuses on low-level memory and runtime optimizations, not the type parameter features of Go generics. The "generic" likely refers to the fact that these rewrites apply across different types in some cases.
* **Misinterpreting `StaticLECall`:**  Initially, might think it's just about static function calls. **Correction:** Realize it's specifically about calls to the "runtime library external," hence the "LE".
* **Overlooking conditions:**  It's easy to focus on the `match` and `result`. **Correction:** Emphasize the importance of the `cond`itions, as they determine when the rewrite is valid.

By following this structured approach, combining code analysis with knowledge of the Go compiler and runtime, a comprehensive and accurate answer can be generated. The comments in the code are invaluable for understanding the intent behind the rewrite rules.

这是 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 文件的一部分，它属于 Go 编译器的 SSA（Static Single Assignment）中间表示的优化阶段。这个文件的主要功能是定义了一系列的重写规则，用于将 SSA 图中的某些模式替换为更优化的模式。

**功能概览 (第 23 部分):**

这部分代码主要关注以下几个方面的优化：

1. **优化对 `runtime.memequal` 的调用:**  当比较小的、固定大小的内存区域时，将对 `runtime.memequal` 的调用替换为更直接的比较操作（例如 `OpEq8`, `OpEq16`, `OpEq32`, `OpEq64`）。这避免了函数调用的开销，并允许后续的优化。
2. **优化对 `runtime.makeslice` 的调用:** 当创建零长度的切片时，将其替换为直接获取 `zerobase` 的地址，避免了函数调用。
3. **优化 `OpStore` 操作:**  寻找可以被简化的 `OpStore` 操作，例如当存储的值是刚刚加载的值时，或者当存储的是零值并覆盖了之前的零值区域时。此外，它还尝试合并相邻的 `OpStore` 和 `OpMove` 操作，以提高效率。
4. **优化 `OpStringLen` 和 `OpStringPtr`:** 当字符串是由 `OpStringMake` 创建时，直接提取长度和指针信息，避免重复计算。
5. **优化 `OpStructSelect`:**  当选择结构体字段时，如果结构体是由 `OpStructMake` 创建的，则直接返回对应的参数。对于从内存加载的结构体，如果类型不允许 SSA，则会计算字段的偏移量并执行加载。
6. **优化 `OpSub16`:**  对于两个常量 `int16` 的减法，直接计算结果并替换为常量。

**推理解释与代码示例:**

**1. 优化 `runtime.memequal` 调用:**

这段代码尝试识别对 `runtime.memequal` 的调用，尤其是当比较的内存大小是 1, 2, 4 或 8 字节，并且其中一个操作数是位于只读数据段的常量时。

**假设输入 SSA (匹配第一个模式):**

```
v1 = (Addr {<symbol>} (SB))
v2 = (Const64 <type> [1])
v3 = (Load <type> {ptr} mem)
v4 = (StaticLECall {runtime.memequal} v3 v1 v2 mem)
```

**假设输出 SSA:**

```
v5 = (Eq8 v3 <常量值>)
v4 = (MakeResult v5 mem)
```

**Go 代码示例 (触发此优化):**

```go
package main

import "unsafe"

var globalByte byte = 10

func main() {
	var localByte byte = 10
	if localByte == globalByte { // 这里会触发 memequal 优化
		println("Equal")
	}
}
```

**推理:**  编译器会识别出 `localByte == globalByte` 的比较实际上是对两个单字节内存区域的比较。由于 `globalByte` 是全局变量，其地址在编译时是已知的，并且可以被视为只读数据段的一部分。因此，编译器会将对 `runtime.memequal` 的调用替换为直接加载 `globalByte` 的值并与 `localByte` 进行比较。

**2. 优化 `runtime.makeslice` 调用:**

当使用 `make([]T, 0, 0)` 创建零长度的切片时，编译器可以直接使用预定义的 `zerobase` 符号的地址。

**假设输入 SSA:**

```
v1 = (Const64 <type> [0])
v2 = (StaticLECall {runtime.makeslice} <类型信息> v1 v1 mem)
```

**假设输出 SSA:**

```
v3 = (Addr {zerobase} (SB))
v2 = (MakeResult v3 mem)
```

**Go 代码示例 (触发此优化):**

```go
package main

func main() {
	s := make([]int, 0) // 这里会触发 makeslice 优化
	_ = s
}
```

**推理:** 创建一个零长度的切片不需要实际分配内存，编译器可以直接使用 `zerobase` 的地址来表示空切片的底层数组。

**3. 优化 `OpStore` 操作:**

例如，当存储的值是刚刚从相同地址加载的值时，这个存储操作是冗余的。

**假设输入 SSA:**

```
v1 = (Load <type> ptr mem)
v2 = (Store <type> ptr v1 mem)
```

**假设输出 SSA:**

```
v2 = mem
```

**Go 代码示例 (触发此优化):**

```go
package main

func main() {
	var x int
	y := x
	x = y // 这里的存储操作会被优化掉
	println(x)
}
```

**推理:**  `x = y` 操作中，`y` 的值就是刚刚从 `x` 的地址加载的，所以这个存储操作不会改变内存状态，可以被安全地移除。

**命令行参数:**

这个代码片段本身并不直接处理命令行参数。这些重写规则是 Go 编译器内部优化的一部分，通常由编译器自动应用。 用户可以通过一些 `go build` 的标志间接地影响这些优化，例如：

* `-gcflags="-N"`: 禁用所有优化，包括这里的 SSA 重写。
* `-gcflags="-l"`: 禁用内联，这可能会影响某些依赖于内联的优化。
* `-gcflags="-m"`:  打印编译器的优化决策，可以用来观察某些重写是否发生。

**使用者易犯错的点 (不在此部分代码中体现，但与 SSA 优化相关):**

虽然这段代码是编译器内部的优化，开发者通常不需要直接关注，但了解 SSA 优化可以帮助理解某些性能特性。 一些可能导致性能问题的代码模式，而 SSA 优化可能会尝试缓解：

* **不必要的内存拷贝:**  例如，在函数调用中传递大型结构体的值而不是指针。SSA 优化可能会消除一些拷贝，但最好还是避免。
* **重复计算:**  例如，在一个循环中多次计算相同的表达式。SSA 优化可以识别并重用计算结果，但手动优化通常更有效。

**归纳第 23 部分的功能:**

第 23 部分的 `rewritegeneric.go` 代码主要负责针对特定的 SSA 操作 (`OpStaticLECall`, `OpStore`, `OpStringLen`, `OpStringPtr`, `OpStructSelect`, `OpSub16`) 定义重写规则，以达到以下目标：

* **减少函数调用开销:** 特别是对于像 `runtime.memequal` 和 `runtime.makeslice` 这样的运行时函数。
* **简化内存操作:** 移除冗余的加载和存储操作，并尝试合并相邻的操作。
* **利用已知信息:** 例如，当操作数是常量或者字符串是由 `OpStringMake` 创建时，可以直接获取结果。
* **提高代码执行效率:** 通过将一些复杂的操作替换为更底层的、更快速的操作。

总而言之，这部分代码是 Go 编译器优化管道中的重要组成部分，旨在提升生成代码的性能。它通过模式匹配和替换的方式，将 SSA 图转换为更高效的形式，从而减少运行时的开销。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第23部分，共26部分，请归纳一下它的功能
```

### 源代码
```go
on := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 1 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq8, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int8)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst8, typ.Int8)
		v2.AuxInt = int8ToAuxInt(int8(read8(scon, 0)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} (Addr {scon} (SB)) sptr (Const64 [1]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon)
	// result: (MakeResult (Eq8 (Load <typ.Int8> sptr mem) (Const8 <typ.Int8> [int8(read8(scon,0))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_0 := v.Args[0]
		if v_0.Op != OpAddr {
			break
		}
		scon := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB {
			break
		}
		sptr := v.Args[1]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 1 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq8, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int8)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst8, typ.Int8)
		v2.AuxInt = int8ToAuxInt(int8(read8(scon, 0)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} sptr (Addr {scon} (SB)) (Const64 [2]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)
	// result: (MakeResult (Eq16 (Load <typ.Int16> sptr mem) (Const16 <typ.Int16> [int16(read16(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		sptr := v.Args[0]
		v_1 := v.Args[1]
		if v_1.Op != OpAddr {
			break
		}
		scon := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 2 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq16, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int16)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst16, typ.Int16)
		v2.AuxInt = int16ToAuxInt(int16(read16(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} (Addr {scon} (SB)) sptr (Const64 [2]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)
	// result: (MakeResult (Eq16 (Load <typ.Int16> sptr mem) (Const16 <typ.Int16> [int16(read16(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_0 := v.Args[0]
		if v_0.Op != OpAddr {
			break
		}
		scon := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB {
			break
		}
		sptr := v.Args[1]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 2 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq16, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int16)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst16, typ.Int16)
		v2.AuxInt = int16ToAuxInt(int16(read16(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} sptr (Addr {scon} (SB)) (Const64 [4]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)
	// result: (MakeResult (Eq32 (Load <typ.Int32> sptr mem) (Const32 <typ.Int32> [int32(read32(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		sptr := v.Args[0]
		v_1 := v.Args[1]
		if v_1.Op != OpAddr {
			break
		}
		scon := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 4 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq32, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int32)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.Int32)
		v2.AuxInt = int32ToAuxInt(int32(read32(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} (Addr {scon} (SB)) sptr (Const64 [4]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)
	// result: (MakeResult (Eq32 (Load <typ.Int32> sptr mem) (Const32 <typ.Int32> [int32(read32(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_0 := v.Args[0]
		if v_0.Op != OpAddr {
			break
		}
		scon := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB {
			break
		}
		sptr := v.Args[1]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 4 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq32, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int32)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.Int32)
		v2.AuxInt = int32ToAuxInt(int32(read32(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} sptr (Addr {scon} (SB)) (Const64 [8]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config) && config.PtrSize == 8
	// result: (MakeResult (Eq64 (Load <typ.Int64> sptr mem) (Const64 <typ.Int64> [int64(read64(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		sptr := v.Args[0]
		v_1 := v.Args[1]
		if v_1.Op != OpAddr {
			break
		}
		scon := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 8 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config) && config.PtrSize == 8) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq64, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int64)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.Int64)
		v2.AuxInt = int64ToAuxInt(int64(read64(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} (Addr {scon} (SB)) sptr (Const64 [8]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config) && config.PtrSize == 8
	// result: (MakeResult (Eq64 (Load <typ.Int64> sptr mem) (Const64 <typ.Int64> [int64(read64(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_0 := v.Args[0]
		if v_0.Op != OpAddr {
			break
		}
		scon := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB {
			break
		}
		sptr := v.Args[1]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 8 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config) && config.PtrSize == 8) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq64, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int64)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.Int64)
		v2.AuxInt = int64ToAuxInt(int64(read64(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} _ _ (Const64 [0]) mem)
	// cond: isSameCall(callAux, "runtime.memequal")
	// result: (MakeResult (ConstBool <typ.Bool> [true]) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 0 || !(isSameCall(callAux, "runtime.memequal")) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpConstBool, typ.Bool)
		v0.AuxInt = boolToAuxInt(true)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} p q _ mem)
	// cond: isSameCall(callAux, "runtime.memequal") && isSamePtr(p, q)
	// result: (MakeResult (ConstBool <typ.Bool> [true]) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		p := v.Args[0]
		q := v.Args[1]
		if !(isSameCall(callAux, "runtime.memequal") && isSamePtr(p, q)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpConstBool, typ.Bool)
		v0.AuxInt = boolToAuxInt(true)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} _ (Const64 [0]) (Const64 [0]) mem)
	// cond: isSameCall(callAux, "runtime.makeslice")
	// result: (MakeResult (Addr <v.Type.FieldType(0)> {ir.Syms.Zerobase} (SB)) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_1 := v.Args[1]
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 0 || !(isSameCall(callAux, "runtime.makeslice")) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpAddr, v.Type.FieldType(0))
		v0.Aux = symToAux(ir.Syms.Zerobase)
		v1 := b.NewValue0(v.Pos, OpSB, typ.Uintptr)
		v0.AddArg(v1)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} _ (Const32 [0]) (Const32 [0]) mem)
	// cond: isSameCall(callAux, "runtime.makeslice")
	// result: (MakeResult (Addr <v.Type.FieldType(0)> {ir.Syms.Zerobase} (SB)) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_1 := v.Args[1]
		if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst32 || auxIntToInt32(v_2.AuxInt) != 0 || !(isSameCall(callAux, "runtime.makeslice")) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpAddr, v.Type.FieldType(0))
		v0.Aux = symToAux(ir.Syms.Zerobase)
		v1 := b.NewValue0(v.Pos, OpSB, typ.Uintptr)
		v0.AddArg(v1)
		v.AddArg2(v0, mem)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Store {t1} p1 (Load <t2> p2 mem) mem)
	// cond: isSamePtr(p1, p2) && t2.Size() == t1.Size()
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		p1 := v_0
		if v_1.Op != OpLoad {
			break
		}
		t2 := v_1.Type
		mem := v_1.Args[1]
		p2 := v_1.Args[0]
		if mem != v_2 || !(isSamePtr(p1, p2) && t2.Size() == t1.Size()) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} p1 (Load <t2> p2 oldmem) mem:(Store {t3} p3 _ oldmem))
	// cond: isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		p1 := v_0
		if v_1.Op != OpLoad {
			break
		}
		t2 := v_1.Type
		oldmem := v_1.Args[1]
		p2 := v_1.Args[0]
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t3 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p3 := mem.Args[0]
		if oldmem != mem.Args[2] || !(isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} p1 (Load <t2> p2 oldmem) mem:(Store {t3} p3 _ (Store {t4} p4 _ oldmem)))
	// cond: isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size()) && disjoint(p1, t1.Size(), p4, t4.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		p1 := v_0
		if v_1.Op != OpLoad {
			break
		}
		t2 := v_1.Type
		oldmem := v_1.Args[1]
		p2 := v_1.Args[0]
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t3 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p3 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		p4 := mem_2.Args[0]
		if oldmem != mem_2.Args[2] || !(isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size()) && disjoint(p1, t1.Size(), p4, t4.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} p1 (Load <t2> p2 oldmem) mem:(Store {t3} p3 _ (Store {t4} p4 _ (Store {t5} p5 _ oldmem))))
	// cond: isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size()) && disjoint(p1, t1.Size(), p4, t4.Size()) && disjoint(p1, t1.Size(), p5, t5.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		p1 := v_0
		if v_1.Op != OpLoad {
			break
		}
		t2 := v_1.Type
		oldmem := v_1.Args[1]
		p2 := v_1.Args[0]
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t3 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p3 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		p4 := mem_2.Args[0]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(mem_2_2.Aux)
		_ = mem_2_2.Args[2]
		p5 := mem_2_2.Args[0]
		if oldmem != mem_2_2.Args[2] || !(isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size()) && disjoint(p1, t1.Size(), p4, t4.Size()) && disjoint(p1, t1.Size(), p5, t5.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t} (OffPtr [o] p1) x mem:(Zero [n] p2 _))
	// cond: isConstZero(x) && o >= 0 && t.Size() + o <= n && isSamePtr(p1, p2)
	// result: mem
	for {
		t := auxToType(v.Aux)
		if v_0.Op != OpOffPtr {
			break
		}
		o := auxIntToInt64(v_0.AuxInt)
		p1 := v_0.Args[0]
		x := v_1
		mem := v_2
		if mem.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem.AuxInt)
		p2 := mem.Args[0]
		if !(isConstZero(x) && o >= 0 && t.Size()+o <= n && isSamePtr(p1, p2)) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} op:(OffPtr [o1] p1) x mem:(Store {t2} p2 _ (Zero [n] p3 _)))
	// cond: isConstZero(x) && o1 >= 0 && t1.Size() + o1 <= n && isSamePtr(p1, p3) && disjoint(op, t1.Size(), p2, t2.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		x := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p2 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem_2.AuxInt)
		p3 := mem_2.Args[0]
		if !(isConstZero(x) && o1 >= 0 && t1.Size()+o1 <= n && isSamePtr(p1, p3) && disjoint(op, t1.Size(), p2, t2.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} op:(OffPtr [o1] p1) x mem:(Store {t2} p2 _ (Store {t3} p3 _ (Zero [n] p4 _))))
	// cond: isConstZero(x) && o1 >= 0 && t1.Size() + o1 <= n && isSamePtr(p1, p4) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		x := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p2 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		p3 := mem_2.Args[0]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem_2_2.AuxInt)
		p4 := mem_2_2.Args[0]
		if !(isConstZero(x) && o1 >= 0 && t1.Size()+o1 <= n && isSamePtr(p1, p4) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} op:(OffPtr [o1] p1) x mem:(Store {t2} p2 _ (Store {t3} p3 _ (Store {t4} p4 _ (Zero [n] p5 _)))))
	// cond: isConstZero(x) && o1 >= 0 && t1.Size() + o1 <= n && isSamePtr(p1, p5) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size()) && disjoint(op, t1.Size(), p4, t4.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		x := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p2 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		p3 := mem_2.Args[0]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		_ = mem_2_2.Args[2]
		p4 := mem_2_2.Args[0]
		mem_2_2_2 := mem_2_2.Args[2]
		if mem_2_2_2.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem_2_2_2.AuxInt)
		p5 := mem_2_2_2.Args[0]
		if !(isConstZero(x) && o1 >= 0 && t1.Size()+o1 <= n && isSamePtr(p1, p5) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size()) && disjoint(op, t1.Size(), p4, t4.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store _ (StructMake ___) _)
	// result: rewriteStructStore(v)
	for {
		if v_1.Op != OpStructMake {
			break
		}
		v.copyOf(rewriteStructStore(v))
		return true
	}
	// match: (Store {t} dst (Load src mem) mem)
	// cond: !CanSSA(t)
	// result: (Move {t} [t.Size()] dst src mem)
	for {
		t := auxToType(v.Aux)
		dst := v_0
		if v_1.Op != OpLoad {
			break
		}
		mem := v_1.Args[1]
		src := v_1.Args[0]
		if mem != v_2 || !(!CanSSA(t)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(t.Size())
		v.Aux = typeToAux(t)
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Store {t} dst (Load src mem) (VarDef {x} mem))
	// cond: !CanSSA(t)
	// result: (Move {t} [t.Size()] dst src (VarDef {x} mem))
	for {
		t := auxToType(v.Aux)
		dst := v_0
		if v_1.Op != OpLoad {
			break
		}
		mem := v_1.Args[1]
		src := v_1.Args[0]
		if v_2.Op != OpVarDef {
			break
		}
		x := auxToSym(v_2.Aux)
		if mem != v_2.Args[0] || !(!CanSSA(t)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(t.Size())
		v.Aux = typeToAux(t)
		v0 := b.NewValue0(v.Pos, OpVarDef, types.TypeMem)
		v0.Aux = symToAux(x)
		v0.AddArg(mem)
		v.AddArg3(dst, src, v0)
		return true
	}
	// match: (Store _ (ArrayMake0) mem)
	// result: mem
	for {
		if v_1.Op != OpArrayMake0 {
			break
		}
		mem := v_2
		v.copyOf(mem)
		return true
	}
	// match: (Store dst (ArrayMake1 e) mem)
	// result: (Store {e.Type} dst e mem)
	for {
		dst := v_0
		if v_1.Op != OpArrayMake1 {
			break
		}
		e := v_1.Args[0]
		mem := v_2
		v.reset(OpStore)
		v.Aux = typeToAux(e.Type)
		v.AddArg3(dst, e, mem)
		return true
	}
	// match: (Store (SelectN [0] call:(StaticLECall _ _)) x mem:(SelectN [1] call))
	// cond: isConstZero(x) && isSameCall(call.Aux, "runtime.newobject")
	// result: mem
	for {
		if v_0.Op != OpSelectN || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		call := v_0.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 {
			break
		}
		x := v_1
		mem := v_2
		if mem.Op != OpSelectN || auxIntToInt64(mem.AuxInt) != 1 || call != mem.Args[0] || !(isConstZero(x) && isSameCall(call.Aux, "runtime.newobject")) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store (OffPtr (SelectN [0] call:(StaticLECall _ _))) x mem:(SelectN [1] call))
	// cond: isConstZero(x) && isSameCall(call.Aux, "runtime.newobject")
	// result: mem
	for {
		if v_0.Op != OpOffPtr {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSelectN || auxIntToInt64(v_0_0.AuxInt) != 0 {
			break
		}
		call := v_0_0.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 {
			break
		}
		x := v_1
		mem := v_2
		if mem.Op != OpSelectN || auxIntToInt64(mem.AuxInt) != 1 || call != mem.Args[0] || !(isConstZero(x) && isSameCall(call.Aux, "runtime.newobject")) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [0] p2) d2 m3:(Move [n] p3 _ mem)))
	// cond: m2.Uses == 1 && m3.Uses == 1 && o1 == t2.Size() && n == t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && clobber(m2, m3)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 mem))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr || auxIntToInt64(op2.AuxInt) != 0 {
			break
		}
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpMove {
			break
		}
		n := auxIntToInt64(m3.AuxInt)
		mem := m3.Args[2]
		p3 := m3.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && o1 == t2.Size() && n == t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && clobber(m2, m3)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v0.AddArg3(op2, d2, mem)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [o2] p2) d2 m3:(Store {t3} op3:(OffPtr [0] p3) d3 m4:(Move [n] p4 _ mem))))
	// cond: m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && o2 == t3.Size() && o1-o2 == t2.Size() && n == t3.Size() + t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && clobber(m2, m3, m4)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 (Store {t3} op3 d3 mem)))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpStore {
			break
		}
		t3 := auxToType(m3.Aux)
		_ = m3.Args[2]
		op3 := m3.Args[0]
		if op3.Op != OpOffPtr || auxIntToInt64(op3.AuxInt) != 0 {
			break
		}
		p3 := op3.Args[0]
		d3 := m3.Args[1]
		m4 := m3.Args[2]
		if m4.Op != OpMove {
			break
		}
		n := auxIntToInt64(m4.AuxInt)
		mem := m4.Args[2]
		p4 := m4.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && o2 == t3.Size() && o1-o2 == t2.Size() && n == t3.Size()+t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && clobber(m2, m3, m4)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v1.AddArg3(op3, d3, mem)
		v0.AddArg3(op2, d2, v1)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [o2] p2) d2 m3:(Store {t3} op3:(OffPtr [o3] p3) d3 m4:(Store {t4} op4:(OffPtr [0] p4) d4 m5:(Move [n] p5 _ mem)))))
	// cond: m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && m5.Uses == 1 && o3 == t4.Size() && o2-o3 == t3.Size() && o1-o2 == t2.Size() && n == t4.Size() + t3.Size() + t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && clobber(m2, m3, m4, m5)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 (Store {t3} op3 d3 (Store {t4} op4 d4 mem))))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpStore {
			break
		}
		t3 := auxToType(m3.Aux)
		_ = m3.Args[2]
		op3 := m3.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d3 := m3.Args[1]
		m4 := m3.Args[2]
		if m4.Op != OpStore {
			break
		}
		t4 := auxToType(m4.Aux)
		_ = m4.Args[2]
		op4 := m4.Args[0]
		if op4.Op != OpOffPtr || auxIntToInt64(op4.AuxInt) != 0 {
			break
		}
		p4 := op4.Args[0]
		d4 := m4.Args[1]
		m5 := m4.Args[2]
		if m5.Op != OpMove {
			break
		}
		n := auxIntToInt64(m5.AuxInt)
		mem := m5.Args[2]
		p5 := m5.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && m5.Uses == 1 && o3 == t4.Size() && o2-o3 == t3.Size() && o1-o2 == t2.Size() && n == t4.Size()+t3.Size()+t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && clobber(m2, m3, m4, m5)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v2.Aux = typeToAux(t4)
		v2.AddArg3(op4, d4, mem)
		v1.AddArg3(op3, d3, v2)
		v0.AddArg3(op2, d2, v1)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [0] p2) d2 m3:(Zero [n] p3 mem)))
	// cond: m2.Uses == 1 && m3.Uses == 1 && o1 == t2.Size() && n == t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && clobber(m2, m3)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 mem))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr || auxIntToInt64(op2.AuxInt) != 0 {
			break
		}
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpZero {
			break
		}
		n := auxIntToInt64(m3.AuxInt)
		mem := m3.Args[1]
		p3 := m3.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && o1 == t2.Size() && n == t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && clobber(m2, m3)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v0.AddArg3(op2, d2, mem)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [o2] p2) d2 m3:(Store {t3} op3:(OffPtr [0] p3) d3 m4:(Zero [n] p4 mem))))
	// cond: m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && o2 == t3.Size() && o1-o2 == t2.Size() && n == t3.Size() + t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && clobber(m2, m3, m4)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 (Store {t3} op3 d3 mem)))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpStore {
			break
		}
		t3 := auxToType(m3.Aux)
		_ = m3.Args[2]
		op3 := m3.Args[0]
		if op3.Op != OpOffPtr || auxIntToInt64(op3.AuxInt) != 0 {
			break
		}
		p3 := op3.Args[0]
		d3 := m3.Args[1]
		m4 := m3.Args[2]
		if m4.Op != OpZero {
			break
		}
		n := auxIntToInt64(m4.AuxInt)
		mem := m4.Args[1]
		p4 := m4.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && o2 == t3.Size() && o1-o2 == t2.Size() && n == t3.Size()+t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && clobber(m2, m3, m4)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v1.AddArg3(op3, d3, mem)
		v0.AddArg3(op2, d2, v1)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [o2] p2) d2 m3:(Store {t3} op3:(OffPtr [o3] p3) d3 m4:(Store {t4} op4:(OffPtr [0] p4) d4 m5:(Zero [n] p5 mem)))))
	// cond: m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && m5.Uses == 1 && o3 == t4.Size() && o2-o3 == t3.Size() && o1-o2 == t2.Size() && n == t4.Size() + t3.Size() + t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && clobber(m2, m3, m4, m5)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 (Store {t3} op3 d3 (Store {t4} op4 d4 mem))))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpStore {
			break
		}
		t3 := auxToType(m3.Aux)
		_ = m3.Args[2]
		op3 := m3.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d3 := m3.Args[1]
		m4 := m3.Args[2]
		if m4.Op != OpStore {
			break
		}
		t4 := auxToType(m4.Aux)
		_ = m4.Args[2]
		op4 := m4.Args[0]
		if op4.Op != OpOffPtr || auxIntToInt64(op4.AuxInt) != 0 {
			break
		}
		p4 := op4.Args[0]
		d4 := m4.Args[1]
		m5 := m4.Args[2]
		if m5.Op != OpZero {
			break
		}
		n := auxIntToInt64(m5.AuxInt)
		mem := m5.Args[1]
		p5 := m5.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && m5.Uses == 1 && o3 == t4.Size() && o2-o3 == t3.Size() && o1-o2 == t2.Size() && n == t4.Size()+t3.Size()+t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && clobber(m2, m3, m4, m5)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v2.Aux = typeToAux(t4)
		v2.AddArg3(op4, d4, mem)
		v1.AddArg3(op3, d3, v2)
		v0.AddArg3(op2, d2, v1)
		v.AddArg3(op1, d1, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStringLen(v *Value) bool {
	v_0 := v.Args[0]
	// match: (StringLen (StringMake _ (Const64 <t> [c])))
	// result: (Const64 <t> [c])
	for {
		if v_0.Op != OpStringMake {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		t := v_0_1.Type
		c := auxIntToInt64(v_0_1.AuxInt)
		v.reset(OpConst64)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStringPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (StringPtr (StringMake (Addr <t> {s} base) _))
	// result: (Addr <t> {s} base)
	for {
		if v_0.Op != OpStringMake {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAddr {
			break
		}
		t := v_0_0.Type
		s := auxToSym(v_0_0.Aux)
		base := v_0_0.Args[0]
		v.reset(OpAddr)
		v.Type = t
		v.Aux = symToAux(s)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStructSelect(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (StructSelect [i] x:(StructMake ___))
	// result: x.Args[i]
	for {
		i := auxIntToInt64(v.AuxInt)
		x := v_0
		if x.Op != OpStructMake {
			break
		}
		v.copyOf(x.Args[i])
		return true
	}
	// match: (StructSelect [i] x:(Load <t> ptr mem))
	// cond: !CanSSA(t)
	// result: @x.Block (Load <v.Type> (OffPtr <v.Type.PtrTo()> [t.FieldOff(int(i))] ptr) mem)
	for {
		i := auxIntToInt64(v.AuxInt)
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(!CanSSA(t)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, v.Type)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, v.Type.PtrTo())
		v1.AuxInt = int64ToAuxInt(t.FieldOff(int(i)))
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (StructSelect [0] (IData x))
	// result: (IData x)
	for {
		if auxIntToInt64(v.AuxInt) != 0 || v_0.Op != OpIData {
			break
		}
		x := v_0.Args[0]
		v.reset(OpIData)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSub16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Sub16 (Const16 [c]) (Const16 [d]))
	// result: (Const16 [c-d])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst16 {
			break
		}
		d := auxIntToInt16(v_1.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(c - d)
		return true
	}
	// match: (Sub16 x (Const16 <t> [c]))
	// cond: x.Op != OpConst16
	// result: (Add16 (Const16 <t> [-c]) x)
	for {
		x := v_0
```