Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/cmd/compile/internal/ssa/rewriteAMD64.go`. This file seems to be part of the Go compiler's SSA (Static Single Assignment) optimization phase, specifically targeting the AMD64 architecture.

The code consists of a series of Go functions named `rewriteValueAMD64_Op...`. These functions appear to implement rewrite rules for specific SSA operations (`Op...`). Each function takes a `*Value` as input, which represents an SSA value, and returns a boolean indicating whether a rewrite occurred.

The general structure of each function is:
1. Extract arguments of the SSA operation.
2. Define a "match" pattern for the operation, potentially with conditions on the arguments' properties (e.g., their type, value, or opcode).
3. If the pattern matches and the conditions are met, perform a rewrite by resetting the current `Value` to a new operation with potentially modified arguments.

Let's analyze the individual functions in the provided snippet:

- **`rewriteValueAMD64_OpAMD64TESTWconst(v *Value) bool`**: This function rewrites a `TESTWconst` operation (bitwise AND of a word with a constant) when the constant is -1. It replaces it with `TESTW x x`, which tests if `x` is zero. The condition `x.Op != OpAMD64MOVLconst` likely aims to avoid rewriting if `x` is already a constant, preventing potential infinite loops or unnecessary rewrites.

- **`rewriteValueAMD64_OpAMD64XADDLlock(v *Value) bool`** and **`rewriteValueAMD64_OpAMD64XADDQlock(v *Value) bool`**: These functions handle `XADDLlock` (atomic add of a 32-bit value) and `XADDQlock` (atomic add of a 64-bit value) operations, respectively. They aim to combine constant offsets in the address calculation. If the address is calculated as `ADDQconst [off2] ptr` and the `XADDLlock/XADDQlock` instruction already has an offset `off1`, and the combined offset `off1 + off2` fits within a 32-bit integer, the code rewrites the operation to directly use the combined offset. This optimization reduces the number of instructions.

- **`rewriteValueAMD64_OpAMD64XCHGL(v *Value) bool`** and **`rewriteValueAMD64_OpAMD64XCHGQ(v *Value) bool`**: These functions handle `XCHGL` (atomic exchange of a 32-bit value) and `XCHGQ` (atomic exchange of a 64-bit value) operations. Similar to the `XADDLlock/XADDQlock` functions, they optimize address calculations by combining constant offsets, whether the address is calculated using `ADDQconst` or `LEAQ`. The `canMergeSym` condition suggests that it's also attempting to merge symbolic offsets when using `LEAQ`. The condition `ptr.Op != OpSB` probably avoids rewriting when the base pointer is a static base pointer.

- **`rewriteValueAMD64_OpAMD64XORL(v *Value) bool`**: This function optimizes `XORL` (bitwise XOR of 32-bit values) operations. It has several rewrite rules:
    - If one operand is `SHLL (MOVLconst [1]) y`, it rewrites to `BTCL x y` (bitwise complement and store of a bit).
    - If one operand is a constant, it rewrites to `XORLconst`.
    - If both operands are the same, it rewrites to `MOVLconst [0]`.
    - It attempts to merge an `XORL` with a preceding `MOVLload` into an `XORLload`.
    - For Go 1.18 and later (indicated by `buildcfg.GOAMD64 >= 3`), it optimizes `XORL x (ADDLconst [-1] x)` to `BLSMSKL x`.

- **`rewriteValueAMD64_OpAMD64XORLconst(v *Value) bool`**: This function optimizes `XORLconst` (bitwise XOR of a 32-bit value with a constant) operations. It focuses on simplifying expressions involving boolean flags (SETxx instructions) and constant folding of XOR operations.

- **`rewriteValueAMD64_OpAMD64XORLconstmodify(v *Value) bool`**: This function optimizes `XORLconstmodify` (bitwise XOR of a memory location with a constant) operations by combining constant offsets in the address calculation, similar to the atomic operations.

- **`rewriteValueAMD64_OpAMD64XORLload(v *Value) bool`**: This function optimizes `XORLload` (bitwise XOR of a 32-bit value with a value loaded from memory) operations, including combining constant offsets and potentially fusing with a preceding `MOVSSstore`.

- **`rewriteValueAMD64_OpAMD64XORLmodify(v *Value) bool`**: This function optimizes `XORLmodify` (bitwise XOR of a memory location with a register value) operations by combining constant offsets in the address calculation.

- **`rewriteValueAMD64_OpAMD64XORQ(v *Value) bool`**: This function is similar to `rewriteValueAMD64_OpAMD64XORL` but handles 64-bit XOR operations (`XORQ`). It includes rules for bitwise complement and store (`BTCQ`, `BTCQconst`) and constant folding.

- **`rewriteValueAMD64_OpAMD64XORQconst(v *Value) bool`**: This function is similar to `rewriteValueAMD64_OpAMD64XORLconst` but handles 64-bit constants.

- **`rewriteValueAMD64_OpAMD64XORQconstmodify(v *Value) bool`**: Similar to `rewriteValueAMD64_OpAMD64XORLconstmodify`, but for 64-bit operations.

- **`rewriteValueAMD64_OpAMD64XORQload(v *Value) bool`**: Similar to `rewriteValueAMD64_OpAMD64XORLload`, but for 64-bit operations and potentially fusing with `MOVSDstore`.

- **`rewriteValueAMD64_OpAMD64XORQmodify(v *Value) bool`**: Similar to `rewriteValueAMD64_OpAMD64XORLmodify`, but for 64-bit operations.

- **`rewriteValueAMD64_OpAddr(v *Value) bool`**: This function rewrites the generic `Addr` operation to the AMD64-specific `LEAQ` (load effective address) instruction.

- **`rewriteValueAMD64_OpAtomicAdd32(v *Value) bool`** and **`rewriteValueAMD64_OpAtomicAdd64(v *Value) bool`**: These functions rewrite the generic atomic addition operations to the AMD64-specific `XADDLlock` and `XADDQlock` instructions, respectively, and wrap the result in `AddTupleFirst32/64` to extract the original value.

- **`rewriteValueAMD64_OpAtomicAnd32(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicAnd32value(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicAnd64value(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicAnd8(v *Value) bool`**: These functions rewrite the generic atomic AND operations to their AMD64 counterparts (`ANDLlock`, `LoweredAtomicAnd32/64`, `ANDBlock`).

- **`rewriteValueAMD64_OpAtomicCompareAndSwap32(v *Value) bool`** and **`rewriteValueAMD64_OpAtomicCompareAndSwap64(v *Value) bool`**: These functions rewrite the generic atomic compare-and-swap operations to the AMD64-specific `CMPXCHGLlock` and `CMPXCHGQlock` instructions.

- **`rewriteValueAMD64_OpAtomicExchange32(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicExchange64(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicExchange8(v *Value) bool`**: These functions rewrite the generic atomic exchange operations to the AMD64-specific `XCHGL`, `XCHGQ`, and `XCHGB` instructions.

- **`rewriteValueAMD64_OpAtomicLoad32(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicLoad64(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicLoad8(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicLoadPtr(v *Value) bool`**: These functions rewrite generic atomic load operations to their AMD64 counterparts (`MOVLatomicload`, `MOVQatomicload`, `MOVBatomicload`).

- **`rewriteValueAMD64_OpAtomicOr32(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicOr32value(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicOr64value(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicOr8(v *Value) bool`**: These functions rewrite the generic atomic OR operations to their AMD64 counterparts (`ORLlock`, `LoweredAtomicOr32/64`, `ORBlock`).

- **`rewriteValueAMD64_OpAtomicStore32(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicStore64(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicStore8(v *Value) bool`**, **`rewriteValueAMD64_OpAtomicStorePtrNoWB(v *Value) bool`**: These functions rewrite generic atomic store operations to their AMD64 counterparts (`XCHGL`, `XCHGQ`, `XCHGB`) and use `Select1` to extract the memory state after the exchange.

- **`rewriteValueAMD64_OpBitLen16(v *Value) bool`** and **`rewriteValueAMD64_OpBitLen32(v *Value) bool`**: These functions implement the `BitLen` operation (finding the index of the most significant set bit) for 16-bit and 32-bit integers, using different AMD64 instructions based on the Go compiler version.

**Overall Function of this Part:**

This section of `rewriteAMD64.go` focuses on **optimizing and lowering generic SSA operations to specific AMD64 instructions**. It covers various arithmetic, logical, and atomic operations, applying rewrite rules to improve efficiency by:

- **Combining constant offsets in memory addressing.**
- **Utilizing more specialized AMD64 instructions for specific patterns.**
- **Performing constant folding.**
- **Lowering generic atomic operations to their lock-based AMD64 equivalents.**

**Example Go Code and its Potential Rewrite:**

Consider the following Go code snippet that might lead to an `OpAMD64XORL` operation:

```go
package main

func main() {
	a := 10
	b := 5
	c := a ^ b
	println(c)
}
```

During the compilation process, the `a ^ b` operation would be represented as an SSA `XORL` operation. The `rewriteValueAMD64_OpAMD64XORL` function might not directly rewrite this simple register-to-register XOR.

However, consider a case where one operand is a shifted constant:

```go
package main

func main() {
	a := 10
	mask := 1 << 2 // Equivalent to 4
	c := a ^ mask
	println(c)
}
```

If the SSA representation of `mask` is `SHLL (MOVLconst [1]) 2`, then the `rewriteValueAMD64_OpAMD64XORL` function would rewrite the `XORL` operation to `BTCL a 2`.

**Hypothetical Input and Output for `rewriteValueAMD64_OpAMD64XORL`:**

**Input (SSA representation before rewrite):**

```
b1: v1 = ConstInt32 <int> [10]
    v2 = ConstInt32 <int> [1]
    v3 = ConstInt32 <int> [2]
    v4 = SHLL <int> v2 v3
    v5 = XORL <int> v1 v4
```

**Output (SSA representation after rewrite):**

```
b1: v1 = ConstInt32 <int> [10]
    v3 = ConstInt32 <int> [2]
    v5 = BTCL <int> v1 v3
```

**Hypothetical Input and Output for `rewriteValueAMD64_OpAMD64XADDLlock`:**

**Input (SSA representation before rewrite):**

```
b1: v1 = ... // some value
    v2 = ADDQconst <*int32> [8] ptr
    v3 = Mem(...)
    v4 = XADDLlock <(UInt32,Mem)> [4] {obj} v1 v2 v3
```

**Output (SSA representation after rewrite):**

```
b1: v1 = ... // some value
    v3 = Mem(...)
    v4 = XADDLlock <(UInt32,Mem)> [12] {obj} v1 ptr v3
```

**No Specific Command-line Arguments Handled:**

This code operates within the Go compiler's intermediate representation and does not directly handle command-line arguments. The compiler's overall command-line flags (like `-gcflags`) might influence the compilation process, but this specific code snippet is about instruction-level optimization.

**Potential User Errors:**

Users generally don't directly interact with this level of compiler optimization. These rewrite rules are internal to the Go compiler. However, understanding these optimizations can help in writing code that the compiler can optimize effectively. For instance, being aware that constant offsets in memory access can be combined might subtly influence how one structures data and performs operations on it, although the compiler usually handles this well. There aren't typical "user errors" related to these rewrite rules.

**Summary of Functionality (Part 17/23):**

This 17th part of `rewriteAMD64.go` focuses on **optimizing arithmetic, logical (specifically XOR), and atomic operations for the AMD64 architecture**. It implements a series of rewrite rules that transform specific patterns of SSA operations into more efficient AMD64 instructions, including combining constant offsets in memory addressing and leveraging specialized atomic instructions. The optimizations are applied to both 32-bit and 64-bit operations.

这是 `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` 文件的第 17 部分，其主要功能是 **定义了一系列针对 AMD64 架构的 SSA 中间代码的重写规则，以优化代码生成**。

具体来说，这部分代码涵盖了以下几个方面的优化：

1. **`TESTWconst` 指令优化:**
   - 当 `TESTWconst` 指令的常量操作数为 -1 时，将其重写为 `TESTW x x`。这可以简化代码，因为与 -1 进行按位与操作等价于测试操作数是否为零。
   - **原理:**  `TESTW const, x` 会设置标志位，效果类似 `ANDW const, x`，但不修改 `x` 的值。当 `const` 为 -1 (所有位都是 1) 时，`x & -1` 的结果与 `x` 相同，因此 `TESTW -1, x` 的效果等价于测试 `x` 是否为零，这可以通过 `TESTW x, x` 实现。

2. **原子操作地址计算优化 (`XADDLlock`, `XADDQlock`, `XCHGL`, `XCHGQ`):**
   - 对于原子加锁和原子交换指令，如果其内存操作数的地址是通过 `ADDQconst` 指令加上一个常量偏移得到的，并且该原子操作本身也有一个偏移量，并且这两个偏移量之和可以用 32 位表示，则将这两个偏移量合并，减少指令数。
   - 对于原子交换指令，如果内存操作数的地址是通过 `LEAQ` 指令加上一个常量偏移和符号得到的，并且该原子操作本身也有一个偏移量，并且这两个偏移量之和可以用 32 位表示，且符号可以合并，则将偏移量合并，减少指令数。
   - **原理:**  AMD64 的内存寻址支持偏移量，合并偏移量可以减少地址计算的指令，提高效率。

3. **`XORL` 指令优化:**
   - 将 `XORL (SHLL (MOVLconst [1]) y) x` 重写为 `BTCL x y`。这利用了 AMD64 的位测试和清除指令。
   - 将 `XORL x (MOVLconst [c])` 重写为 `XORLconst [c] x`，将常量操作数移到指令本身，可能便于后续的常量折叠优化。
   - 将 `XORL x x` 重写为 `MOVLconst [0]`，因为任何值与自身异或的结果都为 0。
   - 尝试将 `XORL` 操作与之前的 `MOVLload` 操作合并为 `XORLload` 操作，这可以减少内存访问次数。
   - 对于支持 `BLSMSK` 指令的 CPU (GOAMD64 >= 3)，将 `XORL x (ADDLconst [-1] x)` 重写为 `BLSMSKL x`，这是一个更高效的指令。
   - **原理:**  针对 `XORL` 指令的特定模式进行优化，利用更高效的指令或减少冗余操作。

4. **`XORLconst` 指令优化:**
   - 针对 `XORLconst` 指令与条件设置指令 (`SETNE`, `SETEQ` 等) 组合的情况进行优化，将异或 1 操作转换为相反的条件设置指令。例如，`XORLconst [1] (SETNE x)` 被重写为 `SETEQ x`。
   - 将连续的 `XORLconst` 操作合并为一个 `XORLconst` 操作。
   - 将 `XORLconst [c] x` 当 `c` 为 0 时重写为 `x`，因为与 0 异或不改变值。
   - 将 `XORLconst` 与 `MOVLconst` 组合进行常量折叠。
   - **原理:** 利用异或操作的特性和常量折叠进行优化。

5. **`XORLconstmodify`, `XORLload`, `XORLmodify` 指令的地址计算优化:**
   -  与原子操作类似，对这些涉及内存操作的 XOR 指令，如果其内存地址是通过 `ADDQconst` 或 `LEAQ` 加上常量偏移得到的，则合并偏移量。

6. **`XORQ` 和 `XORQconst` 等 64 位指令的类似优化:**
   -  与 `XORL` 和 `XORLconst` 类似的优化规则，但应用于 64 位的 `XORQ` 指令。包括利用 `BTCQ` 指令进行位操作优化，以及常量折叠等。

7. **通用地址操作优化 (`OpAddr`):**
   - 将通用的 `OpAddr` 操作符重写为 AMD64 特有的 `LEAQ` 指令，用于获取地址。

8. **原子操作的降低 (`OpAtomicAdd32`, `OpAtomicAdd64` 等):**
   - 将通用的原子操作（例如 `AtomicAdd32`）降低为 AMD64 特有的带锁指令（例如 `XADDLlock`）。
   - 对于某些原子操作，例如 `AtomicStore`，会使用 `XCHG` 指令，并通过 `Select1` 提取内存状态。
   - 对于 `AtomicAnd`, `AtomicOr` 等操作，会降低为相应的带锁指令，或者针对特定情况降低为 "LoweredAtomic" 版本。

9. **`BitLen` 操作的实现 (`OpBitLen16`, `OpBitLen32`):**
   -  实现了计算一个数的二进制表示中最高位 1 的索引的操作。根据 Go 版本和 CPU 特性，使用了不同的 AMD64 指令 (`BSRL`, `BSRQ`, `LZCNTL`) 来实现。

**总结来说，这部分代码的核心功能是针对 AMD64 架构，通过模式匹配和条件判断，将 SSA 中间代码中的某些操作替换为更高效、更底层的 AMD64 指令序列，从而提升最终生成代码的性能。** 它是 Go 编译器后端优化的重要组成部分。

**Go 代码示例 (基于推断):**

假设有以下 Go 代码：

```go
package main

import "sync/atomic"

func main() {
	var count int32 = 10
	atomic.AddInt32(&count, 5)
	println(count)
}
```

在 SSA 阶段，`atomic.AddInt32(&count, 5)` 可能会被表示为类似 `OpAtomicAdd32` 的操作。`rewriteValueAMD64_OpAtomicAdd32` 函数会将这个操作重写为使用 `XADDLlock` 指令：

**假设的 SSA 输入:**

```
b1: v1 = Addr <*int32> {main.count}
    v2 = ConstInt32 <int32> [5]
    v3 = Mem(...)
    v4 = AtomicAdd32 <int32> v1 v2 v3
```

**重写后的 SSA 输出:**

```
b1: v1 = Addr <*int32> {main.count}
    v2 = ConstInt32 <int32> [5]
    v3 = Mem(...)
    v5 = XADDLlock <(UInt32,Mem)> v2 v1 v3
    v4 = AddTupleFirst32 <int32> v2 v5
```

这里 `XADDLlock` 是 AMD64 的原子加并返回原值的指令，`AddTupleFirst32` 用于提取 `XADDLlock` 返回的元组的第一个元素（即原值），但实际 `AtomicAddInt32` 并不需要原值，这个重写是为了符合 SSA 的规范。

**使用者易犯错的点:**

由于这些是编译器内部的优化规则，普通 Go 开发者不会直接与之交互，因此不存在典型的“使用者易犯错的点”。 但是，理解这些优化有助于开发者编写出更易于编译器优化的代码。例如，了解编译器会合并常量偏移，可能在编写涉及内存操作的代码时会有更清晰的认识。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第17部分，共23部分，请归纳一下它的功能

"""
}
	return false
}
func rewriteValueAMD64_OpAMD64TESTWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TESTWconst [-1] x)
	// cond: x.Op != OpAMD64MOVLconst
	// result: (TESTW x x)
	for {
		if auxIntToInt16(v.AuxInt) != -1 {
			break
		}
		x := v_0
		if !(x.Op != OpAMD64MOVLconst) {
			break
		}
		v.reset(OpAMD64TESTW)
		v.AddArg2(x, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XADDLlock(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XADDLlock [off1] {sym} val (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XADDLlock [off1+off2] {sym} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XADDLlock)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XADDQlock(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XADDQlock [off1] {sym} val (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XADDQlock [off1+off2] {sym} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XADDQlock)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XCHGL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XCHGL [off1] {sym} val (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XCHGL [off1+off2] {sym} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XCHGL)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, ptr, mem)
		return true
	}
	// match: (XCHGL [off1] {sym1} val (LEAQ [off2] {sym2} ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && ptr.Op != OpSB
	// result: (XCHGL [off1+off2] {mergeSym(sym1,sym2)} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpAMD64XCHGL)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XCHGQ(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XCHGQ [off1] {sym} val (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XCHGQ [off1+off2] {sym} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XCHGQ)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, ptr, mem)
		return true
	}
	// match: (XCHGQ [off1] {sym1} val (LEAQ [off2] {sym2} ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && ptr.Op != OpSB
	// result: (XCHGQ [off1+off2] {mergeSym(sym1,sym2)} val ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpAMD64XCHGQ)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORL (SHLL (MOVLconst [1]) y) x)
	// result: (BTCL x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64SHLL {
				continue
			}
			y := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.reset(OpAMD64BTCL)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XORL x (MOVLconst [c]))
	// result: (XORLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpAMD64XORLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XORL x x)
	// result: (MOVLconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (XORL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (XORLload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVLload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64XORLload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (XORL x (ADDLconst [-1] x))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (BLSMSKL x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDLconst || auxIntToInt32(v_1.AuxInt) != -1 || x != v_1.Args[0] || !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpAMD64BLSMSKL)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORLconst [1] (SETNE x))
	// result: (SETEQ x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETNE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETEQ)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETEQ x))
	// result: (SETNE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETEQ {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETNE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETL x))
	// result: (SETGE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETL {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETGE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETGE x))
	// result: (SETL x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETGE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETL)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETLE x))
	// result: (SETG x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETLE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETG)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETG x))
	// result: (SETLE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETG {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETLE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETB x))
	// result: (SETAE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETB {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETAE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETAE x))
	// result: (SETB x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETAE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETB)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETBE x))
	// result: (SETA x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETBE {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETA)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [1] (SETA x))
	// result: (SETBE x)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpAMD64SETA {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETBE)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [c] (XORLconst [d] x))
	// result: (XORLconst [c ^ d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64XORLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64XORLconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	// match: (XORLconst [c] x)
	// cond: c==0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (XORLconst [c] (MOVLconst [d]))
	// result: (MOVLconst [c^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORLconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORLconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (XORLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2)) {
			break
		}
		v.reset(OpAMD64XORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (XORLconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (XORLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64XORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (XORLload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORLload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XORLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (XORLload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (XORLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64XORLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (XORLload x [off] {sym} ptr (MOVSSstore [off] {sym} ptr y _))
	// result: (XORL x (MOVLf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSSstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64XORL)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLf2i, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORLmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORLmodify [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64XORLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (XORLmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (XORLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64XORLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORQ (SHLQ (MOVQconst [1]) y) x)
	// result: (BTCQ x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64SHLQ {
				continue
			}
			y := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAMD64MOVQconst || auxIntToInt64(v_0_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.reset(OpAMD64BTCQ)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XORQ (MOVQconst [c]) x)
	// cond: isUint64PowerOfTwo(c) && uint64(c) >= 1<<31
	// result: (BTCQconst [int8(log64(c))] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			x := v_1
			if !(isUint64PowerOfTwo(c) && uint64(c) >= 1<<31) {
				continue
			}
			v.reset(OpAMD64BTCQconst)
			v.AuxInt = int8ToAuxInt(int8(log64(c)))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XORQ x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (XORQconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpAMD64XORQconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XORQ x x)
	// result: (MOVQconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XORQ x l:(MOVQload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (XORQload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVQload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64XORQload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (XORQ x (ADDQconst [-1] x))
	// cond: buildcfg.GOAMD64 >= 3
	// result: (BLSMSKQ x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDQconst || auxIntToInt32(v_1.AuxInt) != -1 || x != v_1.Args[0] || !(buildcfg.GOAMD64 >= 3) {
				continue
			}
			v.reset(OpAMD64BLSMSKQ)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORQconst [c] (XORQconst [d] x))
	// result: (XORQconst [c ^ d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64XORQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64XORQconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	// match: (XORQconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (XORQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [int64(c)^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(c) ^ d)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORQconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (XORQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2)) {
			break
		}
		v.reset(OpAMD64XORQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (XORQconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (XORQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64XORQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (XORQload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORQload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64XORQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (XORQload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (XORQload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64XORQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (XORQload x [off] {sym} ptr (MOVSDstore [off] {sym} ptr y _))
	// result: (XORQ x (MOVQf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64XORQ)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQf2i, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64XORQmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORQmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (XORQmodify [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64XORQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (XORQmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (XORQmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64XORQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (LEAQ {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpAMD64LEAQ)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAdd32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicAdd32 ptr val mem)
	// result: (AddTupleFirst32 val (XADDLlock val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64AddTupleFirst32)
		v0 := b.NewValue0(v.Pos, OpAMD64XADDLlock, types.NewTuple(typ.UInt32, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg2(val, v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAdd64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicAdd64 ptr val mem)
	// result: (AddTupleFirst64 val (XADDQlock val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64AddTupleFirst64)
		v0 := b.NewValue0(v.Pos, OpAMD64XADDQlock, types.NewTuple(typ.UInt64, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg2(val, v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAnd32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicAnd32 ptr val mem)
	// result: (ANDLlock ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64ANDLlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAnd32value(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicAnd32value ptr val mem)
	// result: (LoweredAtomicAnd32 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64LoweredAtomicAnd32)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAnd64value(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicAnd64value ptr val mem)
	// result: (LoweredAtomicAnd64 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64LoweredAtomicAnd64)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicAnd8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicAnd8 ptr val mem)
	// result: (ANDBlock ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64ANDBlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicCompareAndSwap32(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicCompareAndSwap32 ptr old new_ mem)
	// result: (CMPXCHGLlock ptr old new_ mem)
	for {
		ptr := v_0
		old := v_1
		new_ := v_2
		mem := v_3
		v.reset(OpAMD64CMPXCHGLlock)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicCompareAndSwap64(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicCompareAndSwap64 ptr old new_ mem)
	// result: (CMPXCHGQlock ptr old new_ mem)
	for {
		ptr := v_0
		old := v_1
		new_ := v_2
		mem := v_3
		v.reset(OpAMD64CMPXCHGQlock)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicExchange32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicExchange32 ptr val mem)
	// result: (XCHGL val ptr mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64XCHGL)
		v.AddArg3(val, ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicExchange64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicExchange64 ptr val mem)
	// result: (XCHGQ val ptr mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64XCHGQ)
		v.AddArg3(val, ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicExchange8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicExchange8 ptr val mem)
	// result: (XCHGB val ptr mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64XCHGB)
		v.AddArg3(val, ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicLoad32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad32 ptr mem)
	// result: (MOVLatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVLatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicLoad64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad64 ptr mem)
	// result: (MOVQatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVQatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicLoad8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad8 ptr mem)
	// result: (MOVBatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVBatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicLoadPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoadPtr ptr mem)
	// result: (MOVQatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpAMD64MOVQatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicOr32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicOr32 ptr val mem)
	// result: (ORLlock ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64ORLlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicOr32value(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicOr32value ptr val mem)
	// result: (LoweredAtomicOr32 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64LoweredAtomicOr32)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicOr64value(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicOr64value ptr val mem)
	// result: (LoweredAtomicOr64 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64LoweredAtomicOr64)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicOr8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicOr8 ptr val mem)
	// result: (ORBlock ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpAMD64ORBlock)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueAMD64_OpAtomicStore32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicStore32 ptr val mem)
	// result: (Select1 (XCHGL <types.NewTuple(typ.UInt32,types.TypeMem)> val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpAMD64XCHGL, types.NewTuple(typ.UInt32, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicStore64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicStore64 ptr val mem)
	// result: (Select1 (XCHGQ <types.NewTuple(typ.UInt64,types.TypeMem)> val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpAMD64XCHGQ, types.NewTuple(typ.UInt64, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicStore8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicStore8 ptr val mem)
	// result: (Select1 (XCHGB <types.NewTuple(typ.UInt8,types.TypeMem)> val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpAMD64XCHGB, types.NewTuple(typ.UInt8, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpAtomicStorePtrNoWB(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicStorePtrNoWB ptr val mem)
	// result: (Select1 (XCHGQ <types.NewTuple(typ.BytePtr,types.TypeMem)> val ptr mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpAMD64XCHGQ, types.NewTuple(typ.BytePtr, types.TypeMem))
		v0.AddArg3(val, ptr, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpBitLen16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen16 x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSRL (LEAL1 <typ.UInt32> [1] (MOVWQZX <typ.UInt32> x) (MOVWQZX <typ.UInt32> x)))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSRL)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL1, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVWQZX, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, v1)
		v.AddArg(v0)
		return true
	}
	// match: (BitLen16 <t> x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (NEGQ (ADDQconst <t> [-32] (LZCNTL (MOVWQZX <x.Type> x))))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64ADDQconst, t)
		v0.AuxInt = int32ToAuxInt(-32)
		v1 := b.NewValue0(v.Pos, OpAMD64LZCNTL, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpAMD64MOVWQZX, x.Type)
		v2.AddArg(x)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen32 x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (Select0 (BSRQ (LEAQ1 <typ.UInt64> [1] (MOVLQZX <typ.UInt64> x) (MOVLQZX <typ.UInt64> x))))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64BSRQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpAMD64LEAQ1, typ.UInt64)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpAMD64MOVLQZX, typ.UInt64)
		v2.AddArg(x)
		v1.AddArg2(v2, v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (BitLen32 <t> x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (NEGQ (ADDQconst <t> [-32] (LZCNTL x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64ADDQconst, t)
		v0.AuxInt = int32ToAuxInt(-32)
		v1 := b.NewValue0(v.Pos, OpAMD64LZCNTL, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0
"""




```