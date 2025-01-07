Response:
The user is asking for a summary of the functionality of a Go code snippet from `go/src/cmd/compile/internal/ssa/rewriteAMD64.go`. This file is part of the Go compiler and is responsible for applying architecture-specific optimizations to the intermediate representation (SSA) of Go programs targeting the AMD64 architecture.

The provided code snippet consists of several functions named `rewriteValueAMD64_Op...`. Each of these functions takes a `*Value` as input and returns a boolean. The `*Value` represents an operation in the SSA form. These functions seem to implement rewrite rules, meaning they look for specific patterns of operations and replace them with more efficient equivalents.

The naming convention `OpAMD64...` suggests that these rewrites are specific to the AMD64 architecture. The functions check the `Op` field of the input `*Value` to determine the type of operation.

Let's break down the functionality of each function:

*   `rewriteValueAMD64_OpAMD64SETBEstore`: This function seems to handle rewrite rules for the `SETBEstore` operation, which likely sets a byte in memory based on the "below or equal" flag. The rewrites optimize cases where the flag is derived from comparison operations (like `FlagLT_UGT`, `FlagGT_ULT`, etc.) by directly storing a 0 or 1 value. It also handles cases with `InvertFlags`.
*   `rewriteValueAMD64_OpAMD64SETBstore`: Similar to the previous function, but likely handles the `SETBstore` operation, which sets a byte based on the "below" flag. It also optimizes based on flag operations and address calculations.
*   `rewriteValueAMD64_OpAMD64SETEQ`: This function handles rewrites for the `SETEQ` operation, which sets a value based on the "equal" flag. It looks for patterns involving `TESTL`, `TESTQ`, `CMPLconst`, `CMPQconst`, bit shifts, and flag operations, replacing them with more direct flag checks or constant values.
*   `rewriteValueAMD64_OpAMD64SETEQstore`:  This function deals with the `SETEQstore` operation, which stores a byte based on the "equal" flag. It mirrors the optimizations done in `rewriteValueAMD64_OpAMD64SETEQ` but applies them in the context of a memory store operation.
*   `rewriteValueAMD64_OpAMD64SETG`: This function handles rewrites for the `SETG` operation (set if greater). It optimizes based on inverted flags and direct flag values.
*   `rewriteValueAMD64_OpAMD64SETGE`: This function handles rewrites for the `SETGE` operation (set if greater or equal), optimizing for inverted flags and direct flag values.

**Overall Function of the Snippet:**

This part of `rewriteAMD64.go` focuses on optimizing conditional byte setting and flag manipulation operations in the SSA representation for AMD64. It identifies common patterns where a byte is set in memory or a value is set based on the result of a comparison or flag operation. It then replaces these patterns with more efficient low-level instructions or constant values. This process helps the compiler generate optimized machine code for AMD64 architectures.

**Illustrative Go Code Example (Hypothetical):**

Let's consider the `SETBEstore` example. Suppose the Go code contains a comparison and then sets a boolean value in memory based on the result. The compiler might generate SSA like this (simplified):

**Hypothetical Input SSA:**

```
v1 = CMPL(x, y)  // Compare x and y
v2 = FlagLT_UGT(v1) // Check if x < y (unsigned)
v3 = SETBEstore [0] {some_var} ptr v2 mem // Store 1 if v2 is true, 0 otherwise (hypothetical SETBEstore)
```

The `rewriteValueAMD64_OpAMD64SETBEstore` function with the matching pattern would transform this to:

**Hypothetical Output SSA:**

```
v1 = CMPL(x, y)
v2 = FlagLT_UGT(v1)
v4 = MOVLconst <uint8> [0] // Directly create a constant 0
v3 = MOVBstore [0] {some_var} ptr v4 mem // Store the constant 0 directly
```

**Go Code that might lead to this (Hypothetical):**

```go
package main

var some_var bool

func main() {
	x := 10
	y := 20
	if x <= y {
		some_var = true
	} else {
		some_var = false
	}
}
```

**Reasoning:** The `SETBEstore` operation is being optimized by recognizing that when the condition is derived from `FlagLT_UGT` (which implies unsigned less than),  setting the byte to 0 achieves the desired outcome when the condition is *not* met (i.e., when it's greater than). A similar logic applies to other flag combinations.

**Command Line Arguments:** This code is part of the Go compiler's internal workings and doesn't directly interact with command-line arguments in the way a user-facing program does. The compiler itself takes Go source files as input, and this code operates on the intermediate representation generated during the compilation process.

**User Mistakes:** Users don't directly interact with this level of the compiler. The transformations happen automatically during compilation. However, understanding these optimizations can help in understanding how certain code patterns might be compiled more efficiently. There aren't really "mistakes" users can make that directly affect this specific part of the compiler, but writing inefficient Go code might lead to the compiler having more opportunities for these kinds of rewrites.

**Summary of Functionality (Part 13/23):**

This specific section of `rewriteAMD64.go` focuses on **optimizing conditional byte store operations and flag-based value setting for the AMD64 architecture**. It achieves this by recognizing common patterns involving comparison flags and replacing them with more direct memory store instructions or constant value assignments. This optimization contributes to generating more efficient machine code by avoiding unnecessary flag evaluations and conditional branches in certain scenarios.

这是 `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` 文件的一部分，主要负责对 AMD64 架构下的 SSA（Static Single Assignment）中间表示进行优化的重写规则。

**功能归纳（第 13 部分）：**

这部分代码主要定义了针对以下 AMD64 SSA 操作的重写规则：

*   **`OpAMD64SETBEstore`**:  优化基于“低于或等于”标志位的字节存储操作。它将一些基于比较结果的 `SETBEstore` 操作替换为直接存储常量 0 或 1 的 `MOVBstore` 操作。
*   **`OpAMD64SETBstore`**: 优化基于“低于”标志位的字节存储操作。类似于 `SETBEstore`，它也将基于比较结果的 `SETBstore` 操作替换为直接存储常量 0 或 1 的 `MOVBstore` 操作，并处理了一些地址计算的优化。
*   **`OpAMD64SETEQ`**: 优化基于“等于”标志位设置值的操作。它识别出多种基于 `TEST` 指令、比较指令 (`CMPLconst`, `CMPQconst`) 和位移操作的结果来设置等于标志的情况，并将其转换为更直接的标志位检查操作 (如 `SETAE` 基于 `BTL` 或 `BTQ`) 或者直接生成常量 0 或 1。
*   **`OpAMD64SETEQstore`**: 优化基于“等于”标志位的字节存储操作。与 `SETEQ` 类似，但作用于内存存储，将基于复杂条件判断的 `SETEQstore` 转换为更简单的基于位测试指令的 `SETAEstore` 或直接存储常量。
*   **`OpAMD64SETG`**: 优化基于“大于”标志位设置值的操作。将基于反转标志的操作转换为基于相反条件的操作，并将基于特定标志的 `SETG` 操作直接替换为常量 0 或 1。
*   **`OpAMD64SETGE`**: 优化基于“大于或等于”标志位设置值的操作。 类似于 `SETG`，处理反转标志的情况，并根据具体的标志位直接生成常量 0 或 1。

**Go 语言功能实现推断与代码示例：**

这部分代码主要实现了对布尔表达式求值并存储结果的优化。例如，在 Go 代码中进行比较操作并将结果赋值给布尔变量时，编译器会生成相应的 SSA 代码，而这些重写规则可以简化这些 SSA 代码。

**示例 (针对 `OpAMD64SETBEstore`):**

**假设的输入 SSA (用于说明 `SETBEstore` 的优化):**

```
v1 = CMPL x y       // 比较 x 和 y (有符号比较)
v2 = FlagLT_UGT v1  // 获取无符号小于或有符号大于标志 (模拟 <= 的逻辑，但使用了 FlagLT_UGT)
v3 = SETBEstore [0] {someBool} ptr v2 mem // 如果 v2 为真，存储 1，否则存储 0 到 ptr 指向的地址
```

**优化后的 SSA:**

```
v1 = CMPL x y
v4 = MOVLconst <uint8> [0] // 直接生成常量 0
v3 = MOVBstore [0] {someBool} ptr v4 mem // 直接存储常量 0 (因为 FlagLT_UGT 在这种上下文中为假)
```

**对应的 Go 代码 (可能导致以上 SSA):**

```go
package main

var someBool bool

func main() {
	x := 10
	y := 20
	if x <= y {
		someBool = true
	} else {
		someBool = false
	}
}
```

**推理:**  `FlagLT_UGT` 通常与无符号比较相关。在这个 `SETBEstore` 的上下文中，如果直接使用 `FlagLT_UGT`，且我们知道 `SETBEstore` 的目的是存储一个布尔值（0 或 1），那么当 `FlagLT_UGT` 为真时，会存储 1，否则存储 0。代码中的一个优化是将基于 `FlagLT_UGT` 的 `SETBEstore` 转换为直接存储 0 的 `MOVBstore`。这可能是因为在特定的比较场景下，`FlagLT_UGT` 的结果为假，或者存在其他优化路径。

**示例 (针对 `OpAMD64SETEQ`):**

**假设的输入 SSA:**

```
v1 = SHLLconst [1] (MOVLconst [1])  // 左移常量 1 位 (结果是 2)
v2 = TESTL v1 z                // 将 v1 与 z 进行 TEST 操作
v3 = SETEQ v2                  // 如果 TEST 的结果为零标志位被设置，则 v3 为 1，否则为 0
```

**优化后的 SSA:**

```
v4 = BTLconst [1] z         // 测试 z 的第 1 位是否为 0
v3 = SETAE v4              // 如果 BTL 结果表示位未设置 (即为 0)，则 v3 为 1
```

**对应的 Go 代码 (可能导致以上 SSA):**

```go
package main

import "fmt"

func main() {
	z := 4
	result := (2 & z) == 0
	fmt.Println(result) // Output: false
}
```

**推理:**  `SETEQ` 观察到 `TESTL` 操作的结果，并根据零标志位来设置值。优化后的代码使用 `BTLconst` (位测试) 指令，并使用 `SETAE` (如果低于则设置) 来达到相同的效果，这在某些情况下可能更高效。

**命令行参数的具体处理：**

这个代码片段是 Go 编译器内部的优化规则，不直接处理用户提供的命令行参数。Go 编译器的命令行参数用于控制编译过程的各个方面，例如指定目标架构、优化级别等，但这些参数不会直接影响到这些特定的 SSA 重写规则的逻辑。

**使用者易犯错的点：**

由于这是编译器内部的优化，Go 语言使用者通常不会直接与这些代码交互，因此不存在使用者易犯错的点。这些优化是编译器自动进行的。理解这些优化规则可以帮助开发者更好地理解 Go 代码是如何被编译成机器码的，从而编写出更高效的代码。然而，过度关注这些底层的优化细节通常不是编写高效 Go 代码的关键。

**总结：**

总而言之，这部分 `rewriteAMD64.go` 代码的功能是定义了一系列针对 AMD64 架构的 SSA 重写规则，旨在优化条件字节存储操作和基于标志位设置值的操作，通过识别特定的指令模式并将其替换为更高效的指令序列或常量值，提升最终生成机器码的性能。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第13部分，共23部分，请归纳一下它的功能

"""
tr, v0, mem)
		return true
	}
	// match: (SETBEstore [off] {sym} ptr (FlagLT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETBEstore [off] {sym} ptr (FlagGT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETBEstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETBstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETAstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETAstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETBstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETBstore [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SETBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETBstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETBstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SETBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETBstore [off] {sym} ptr (FlagEQ) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagEQ {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETBstore [off] {sym} ptr (FlagLT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETBstore [off] {sym} ptr (FlagLT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETBstore [off] {sym} ptr (FlagGT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETBstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETEQ(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (SETEQ (TESTL (SHLL (MOVLconst [1]) x) y))
	// result: (SETAE (BTL x y))
	for {
		if v_0.Op != OpAMD64TESTL {
			break
		}
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
			v.reset(OpAMD64SETAE)
			v0 := b.NewValue0(v.Pos, OpAMD64BTL, types.TypeFlags)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (TESTQ (SHLQ (MOVQconst [1]) x) y))
	// result: (SETAE (BTQ x y))
	for {
		if v_0.Op != OpAMD64TESTQ {
			break
		}
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
			v.reset(OpAMD64SETAE)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQ, types.TypeFlags)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (TESTLconst [c] x))
	// cond: isUint32PowerOfTwo(int64(c))
	// result: (SETAE (BTLconst [int8(log32(c))] x))
	for {
		if v_0.Op != OpAMD64TESTLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isUint32PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETAE)
		v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SETEQ (TESTQconst [c] x))
	// cond: isUint64PowerOfTwo(int64(c))
	// result: (SETAE (BTQconst [int8(log32(c))] x))
	for {
		if v_0.Op != OpAMD64TESTQconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isUint64PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETAE)
		v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SETEQ (TESTQ (MOVQconst [c]) x))
	// cond: isUint64PowerOfTwo(c)
	// result: (SETAE (BTQconst [int8(log64(c))] x))
	for {
		if v_0.Op != OpAMD64TESTQ {
			break
		}
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
			v.reset(OpAMD64SETAE)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log64(c)))
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (CMPLconst [1] s:(ANDLconst [1] _)))
	// result: (SETNE (CMPLconst [0] s))
	for {
		if v_0.Op != OpAMD64CMPLconst || auxIntToInt32(v_0.AuxInt) != 1 {
			break
		}
		s := v_0.Args[0]
		if s.Op != OpAMD64ANDLconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		v.reset(OpAMD64SETNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg(v0)
		return true
	}
	// match: (SETEQ (CMPQconst [1] s:(ANDQconst [1] _)))
	// result: (SETNE (CMPQconst [0] s))
	for {
		if v_0.Op != OpAMD64CMPQconst || auxIntToInt32(v_0.AuxInt) != 1 {
			break
		}
		s := v_0.Args[0]
		if s.Op != OpAMD64ANDQconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		v.reset(OpAMD64SETNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg(v0)
		return true
	}
	// match: (SETEQ (TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2))
	// cond: z1==z2
	// result: (SETAE (BTQconst [63] x))
	for {
		if v_0.Op != OpAMD64TESTQ {
			break
		}
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
			v.reset(OpAMD64SETAE)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (TESTL z1:(SHLLconst [31] (SHRQconst [31] x)) z2))
	// cond: z1==z2
	// result: (SETAE (BTQconst [31] x))
	for {
		if v_0.Op != OpAMD64TESTL {
			break
		}
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
			v.reset(OpAMD64SETAE)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (TESTQ z1:(SHRQconst [63] (SHLQconst [63] x)) z2))
	// cond: z1==z2
	// result: (SETAE (BTQconst [0] x))
	for {
		if v_0.Op != OpAMD64TESTQ {
			break
		}
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
			v.reset(OpAMD64SETAE)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (TESTL z1:(SHRLconst [31] (SHLLconst [31] x)) z2))
	// cond: z1==z2
	// result: (SETAE (BTLconst [0] x))
	for {
		if v_0.Op != OpAMD64TESTL {
			break
		}
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
			v.reset(OpAMD64SETAE)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (TESTQ z1:(SHRQconst [63] x) z2))
	// cond: z1==z2
	// result: (SETAE (BTQconst [63] x))
	for {
		if v_0.Op != OpAMD64TESTQ {
			break
		}
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
			v.reset(OpAMD64SETAE)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (TESTL z1:(SHRLconst [31] x) z2))
	// cond: z1==z2
	// result: (SETAE (BTLconst [31] x))
	for {
		if v_0.Op != OpAMD64TESTL {
			break
		}
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
			v.reset(OpAMD64SETAE)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (InvertFlags x))
	// result: (SETEQ x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETEQ)
		v.AddArg(x)
		return true
	}
	// match: (SETEQ (FlagEQ))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETEQ (FlagLT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETEQ (FlagLT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETEQ (FlagGT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETEQ (FlagGT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETEQ (TESTQ s:(Select0 blsr:(BLSRQ _)) s))
	// result: (SETEQ (Select1 <types.TypeFlags> blsr))
	for {
		if v_0.Op != OpAMD64TESTQ {
			break
		}
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
			v.reset(OpAMD64SETEQ)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETEQ (TESTL s:(Select0 blsr:(BLSRL _)) s))
	// result: (SETEQ (Select1 <types.TypeFlags> blsr))
	for {
		if v_0.Op != OpAMD64TESTL {
			break
		}
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
			v.reset(OpAMD64SETEQ)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg(v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETEQstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETEQstore [off] {sym} ptr (TESTL (SHLL (MOVLconst [1]) x) y) mem)
	// result: (SETAEstore [off] {sym} ptr (BTL x y) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpAMD64SHLL {
				continue
			}
			x := v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_1_0_0.AuxInt) != 1 {
				continue
			}
			y := v_1_1
			mem := v_2
			v.reset(OpAMD64SETAEstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTL, types.TypeFlags)
			v0.AddArg2(x, y)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETEQstore [off] {sym} ptr (TESTQ (SHLQ (MOVQconst [1]) x) y) mem)
	// result: (SETAEstore [off] {sym} ptr (BTQ x y) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpAMD64SHLQ {
				continue
			}
			x := v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_1_0_0.AuxInt) != 1 {
				continue
			}
			y := v_1_1
			mem := v_2
			v.reset(OpAMD64SETAEstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQ, types.TypeFlags)
			v0.AddArg2(x, y)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETEQstore [off] {sym} ptr (TESTLconst [c] x) mem)
	// cond: isUint32PowerOfTwo(int64(c))
	// result: (SETAEstore [off] {sym} ptr (BTLconst [int8(log32(c))] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		x := v_1.Args[0]
		mem := v_2
		if !(isUint32PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETAEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETEQstore [off] {sym} ptr (TESTQconst [c] x) mem)
	// cond: isUint64PowerOfTwo(int64(c))
	// result: (SETAEstore [off] {sym} ptr (BTQconst [int8(log32(c))] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		x := v_1.Args[0]
		mem := v_2
		if !(isUint64PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETAEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETEQstore [off] {sym} ptr (TESTQ (MOVQconst [c]) x) mem)
	// cond: isUint64PowerOfTwo(c)
	// result: (SETAEstore [off] {sym} ptr (BTQconst [int8(log64(c))] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			x := v_1_1
			mem := v_2
			if !(isUint64PowerOfTwo(c)) {
				continue
			}
			v.reset(OpAMD64SETAEstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log64(c)))
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETEQstore [off] {sym} ptr (CMPLconst [1] s:(ANDLconst [1] _)) mem)
	// result: (SETNEstore [off] {sym} ptr (CMPLconst [0] s) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64CMPLconst || auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		s := v_1.Args[0]
		if s.Op != OpAMD64ANDLconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		mem := v_2
		v.reset(OpAMD64SETNEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETEQstore [off] {sym} ptr (CMPQconst [1] s:(ANDQconst [1] _)) mem)
	// result: (SETNEstore [off] {sym} ptr (CMPQconst [0] s) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64CMPQconst || auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		s := v_1.Args[0]
		if s.Op != OpAMD64ANDQconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		mem := v_2
		v.reset(OpAMD64SETNEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETEQstore [off] {sym} ptr (TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2) mem)
	// cond: z1==z2
	// result: (SETAEstore [off] {sym} ptr (BTQconst [63] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHLQconst || auxIntToInt8(z1.AuxInt) != 63 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHRQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETAEstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETEQstore [off] {sym} ptr (TESTL z1:(SHLLconst [31] (SHRLconst [31] x)) z2) mem)
	// cond: z1==z2
	// result: (SETAEstore [off] {sym} ptr (BTLconst [31] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHLLconst || auxIntToInt8(z1.AuxInt) != 31 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHRLconst || auxIntToInt8(z1_0.AuxInt) != 31 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETAEstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETEQstore [off] {sym} ptr (TESTQ z1:(SHRQconst [63] (SHLQconst [63] x)) z2) mem)
	// cond: z1==z2
	// result: (SETAEstore [off] {sym} ptr (BTQconst [0] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHLQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETAEstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETEQstore [off] {sym} ptr (TESTL z1:(SHRLconst [31] (SHLLconst [31] x)) z2) mem)
	// cond: z1==z2
	// result: (SETAEstore [off] {sym} ptr (BTLconst [0] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHLLconst || auxIntToInt8(z1_0.AuxInt) != 31 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETAEstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETEQstore [off] {sym} ptr (TESTQ z1:(SHRQconst [63] x) z2) mem)
	// cond: z1==z2
	// result: (SETAEstore [off] {sym} ptr (BTQconst [63] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
				continue
			}
			x := z1.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETAEstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETEQstore [off] {sym} ptr (TESTL z1:(SHRLconst [31] x) z2) mem)
	// cond: z1==z2
	// result: (SETAEstore [off] {sym} ptr (BTLconst [31] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
				continue
			}
			x := z1.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETAEstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETEQstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETEQstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETEQstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETEQstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETEQstore [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SETEQstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETEQstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETEQstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SETEQstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETEQstore [off] {sym} ptr (FlagEQ) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagEQ {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETEQstore [off] {sym} ptr (FlagLT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETEQstore [off] {sym} ptr (FlagLT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETEQstore [off] {sym} ptr (FlagGT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETEQstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SETG (InvertFlags x))
	// result: (SETL x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETL)
		v.AddArg(x)
		return true
	}
	// match: (SETG (FlagEQ))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETG (FlagLT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETG (FlagLT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETG (FlagGT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETG (FlagGT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETGE(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SETGE (InvertFlags x))
	// result: (SETLE x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETLE)
		v.AddArg(x)
		return true
	}
	// match: (SETGE (FlagEQ))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true

"""




```