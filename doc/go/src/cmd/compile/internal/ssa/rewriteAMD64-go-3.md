Response: The user wants a summary of the functionality of the provided Go code snippet. The code is part of the `rewriteAMD64.go` file, which suggests it's related to rewriting SSA (Static Single Assignment) instructions for the AMD64 architecture in the Go compiler.

The code consists of multiple functions, each named `rewriteValueAMD64_Op...`. This naming convention strongly suggests that each function handles the rewriting of a specific AMD64 opcode.

Let's analyze the functions one by one and group them by the opcode they handle:

- **`rewriteValueAMD64_OpAMD64ADDQ`**: Rewrites expressions involving the `ADDQ` (add quadword) opcode. It seems to look for specific patterns like `ADDQconst` and potentially simplify them.
- **`rewriteValueAMD64_OpAMD64LEAQ2`**, **`rewriteValueAMD64_OpAMD64LEAQ4`**, **`rewriteValueAMD64_OpAMD64LEAQ8`**: These handle the `LEAQ2`, `LEAQ4`, and `LEAQ8` opcodes, which are likely load effective address with scaling by 2, 4, and 8 respectively. They appear to optimize address calculations by combining constants and merging symbols.
- **`rewriteValueAMD64_OpAMD64MOVBELstore`**, **`rewriteValueAMD64_OpAMD64MOVBEQstore`**, **`rewriteValueAMD64_OpAMD64MOVBEWstore`**: These functions deal with byte-swapping store operations (`MOVBELstore`, `MOVBEQstore`, `MOVBEWstore`). They seem to identify byte-swapping patterns and replace them with native store instructions where applicable.
- **`rewriteValueAMD64_OpAMD64MOVBQSX`**, **`rewriteValueAMD64_OpAMD64MOVBQSXload`**: These handle move byte quadword sign-extended (`MOVBQSX`) operations. They seem to optimize loading and sign-extending byte values.
- **`rewriteValueAMD64_OpAMD64MOVBQZX`**: Handles move byte quadword zero-extended (`MOVBQZX`). Similar to `MOVBQSX`, it optimizes loading and zero-extending byte values.
- **`rewriteValueAMD64_OpAMD64MOVBatomicload`**, **`rewriteValueAMD64_OpAMD64MOVBload`**: These functions deal with loading byte values (`MOVBatomicload` for atomic loads and `MOVBload` for regular loads). They optimize memory access by combining offsets and merging symbols.
- **`rewriteValueAMD64_OpAMD64MOVBstore`**, **`rewriteValueAMD64_OpAMD64MOVBstoreconst`**: These handle storing byte values (`MOVBstore`) and storing constant byte values (`MOVBstoreconst`). They optimize store operations by recognizing patterns with set flags, constant values, and address calculations.
- **`rewriteValueAMD64_OpAMD64MOVLQSX`**, **`rewriteValueAMD64_OpAMD64MOVLQSXload`**: Handle move longword quadword sign-extended (`MOVLQSX`). They optimize loading and sign-extending longword values.
- **`rewriteValueAMD64_OpAMD64MOVLQZX`**: Handles move longword quadword zero-extended (`MOVLQZX`). Similar to `MOVLQSX`, it optimizes loading and zero-extending longword values.
- **`rewriteValueAMD64_OpAMD64MOVLatomicload`**, **`rewriteValueAMD64_OpAMD64MOVLf2i`**, **`rewriteValueAMD64_OpAMD64MOVLi2f`**, **`rewriteValueAMD64_OpAMD64MOVLload`**, **`rewriteValueAMD64_OpAMD64MOVLstore`**, **`rewriteValueAMD64_OpAMD64MOVLstoreconst`**: These functions handle operations related to longwords (32-bit integers), including atomic loads, conversions between float and integer (`MOVLf2i`, `MOVLi2f`), regular loads, stores, and storing constant values. They apply various optimizations like combining offsets, merging symbols, and recognizing specific patterns for simplification.
- **`rewriteValueAMD64_OpAMD64MOVOload`**, **`rewriteValueAMD64_OpAMD64MOVOstore`**, **`rewriteValueAMD64_OpAMD64MOVOstoreconst`**: These handle operations on octowords (128-bit values). They focus on optimizing load and store operations, similar to the byte and longword operations.
- **`rewriteValueAMD64_OpAMD64MOVQatomicload`**, **`rewriteValueAMD64_OpAMD64MOVQf2i`**, **`rewriteValueAMD64_OpAMD64MOVQi2f`**, **`rewriteValueAMD64_OpAMD64MOVQload`**: These functions deal with quadwords (64-bit integers), including atomic loads, conversions between float and integer (`MOVQf2i`, `MOVQi2f`), and regular loads.

**Overall Function:**

The primary function of this code snippet is to optimize SSA instructions for the AMD64 architecture. It achieves this by identifying common patterns in the intermediate representation and replacing them with more efficient equivalents. These rewrites often involve:

- **Combining constant offsets**: Simplifying memory access calculations.
- **Merging symbols**:  Optimizing access to global variables or function addresses.
- **Recognizing and utilizing specific AMD64 instructions**:  Leveraging instructions like `LEA` with scaling.
- **Eliminating redundant operations**: Removing unnecessary conversions or loads.
- **Handling byte-swapping efficiently**: Utilizing specific instructions when available.

This part of the code focuses on loads, stores, additions, and address calculations. It doesn't seem to involve complex control flow changes or high-level language features directly.

Let's draft the response based on this analysis.
代码片段 `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` 的这一部分（第 4/12 部分）的主要功能是 **定义了一系列针对 AMD64 架构的 SSA (Static Single Assignment) 值重写规则**。 这些规则旨在优化生成的机器码，提高程序的执行效率。

具体来说，每个以 `rewriteValueAMD64_Op...` 开头的函数都对应于一个特定的 AMD64 操作码 (OpCode)，并尝试将该操作码的某些特定模式的用法转换为更优化的形式。

以下是对代码片段中各个函数功能的归纳：

* **`rewriteValueAMD64_OpAMD64ADDQ(v *Value) bool`**:  处理 `ADDQ` (加法，操作数为 64 位) 操作。目前只包含一个简单的规则，如果加法的其中一个操作数是常量 0，则可以直接用另一个操作数替换整个加法操作。这是一种基本的加法恒等律优化。

* **`rewriteValueAMD64_OpAMD64LEAQ2(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64LEAQ4(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64LEAQ8(v *Value) bool`**: 这三个函数分别处理 `LEAQ2` (加载有效地址，第二个操作数乘以 2), `LEAQ4` (乘以 4), 和 `LEAQ8` (乘以 8) 操作。 这些函数旨在优化地址计算，例如：
    * 合并相邻的常量偏移量。
    * 合并来自 `ADDQconst` 操作的常量。
    * 将 `LEAQ2` 与 `SHLQconst [1]` 或 `SHLQconst [2]` 组合转换为 `LEAQ4` 或 `LEAQ8`，利用移位操作实现乘法。
    * 合并嵌套的 `LEAQ` 操作。
    * 将与 `MOVQconst` 或 `MOVLconst` 相乘的模式转换为单个 `LEAQ` 操作。

* **`rewriteValueAMD64_OpAMD64MOVBELstore(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVBEQstore(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVBEWstore(v *Value) bool`**:  这三个函数处理大端存储操作 (`MOVBELstore` - 字节, `MOVBEQstore` - 64位, `MOVBEWstore` - 16位)。它们尝试识别在存储之前进行字节序转换的模式，并将其替换为更直接的存储操作。例如，如果存储的值是通过 `BSWAPL` (字节交换 32 位) 得到的，则可以将其优化为直接的 `MOVLstore`。

* **`rewriteValueAMD64_OpAMD64MOVBQSX(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVBQSXload(v *Value) bool`**: 这两个函数处理带符号扩展的字节移动到 64 位 (`MOVBQSX`) 操作。它们旨在优化从内存加载字节并进行符号扩展的场景，例如将 `MOVBload` 或其他加载操作直接替换为 `MOVBQSXload`。  此外，还包含对常量与操作的优化。

* **`rewriteValueAMD64_OpAMD64MOVBQZX(v *Value) bool`**:  处理零扩展的字节移动到 64 位 (`MOVBQZX`) 操作。 类似于 `MOVBQSX`，它优化了从内存加载字节并进行零扩展的场景。

* **`rewriteValueAMD64_OpAMD64MOVBatomicload(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVBload(v *Value) bool`**: 这两个函数处理字节加载操作 (`MOVBatomicload` 是原子加载)。它们尝试合并地址计算中的常量偏移量和符号。对于 `MOVBload`，还会尝试识别从只读内存加载常量的情况，并将其替换为 `MOVLconst`。

* **`rewriteValueAMD64_OpAMD64MOVBstore(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVBstoreconst(v *Value) bool`**:  处理字节存储操作 (`MOVBstore`) 和常量字节存储操作 (`MOVBstoreconst`)。 `MOVBstore` 尝试识别存储布尔类型 (通过 `SET` 指令实现) 的模式，并将其转换为特定的 `SETxxxstore` 操作。 还会优化存储带符号或零扩展的字节的情况，以及合并地址计算中的常量偏移量。 `MOVBstoreconst` 优化了常量存储的地址计算。

* **`rewriteValueAMD64_OpAMD64MOVLQSX(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVLQSXload(v *Value) bool`**: 处理带符号扩展的 32 位移动到 64 位 (`MOVLQSX`) 操作。 类似于 `MOVBQSX`，它优化了从内存加载 32 位值并进行符号扩展的场景。

* **`rewriteValueAMD64_OpAMD64MOVLQZX(v *Value) bool`**: 处理零扩展的 32 位移动到 64 位 (`MOVLQZX`) 操作。 类似于 `MOVBQZX`，它优化了从内存加载 32 位值并进行零扩展的场景。

* **`rewriteValueAMD64_OpAMD64MOVLatomicload(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVLf2i(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVLi2f(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVLload(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVLstore(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVLstoreconst(v *Value) bool`**:  这些函数处理 32 位整数 (`MOVL`) 的原子加载、浮点数到整数的转换 (`MOVLf2i`)、整数到浮点数的转换 (`MOVLi2f`)、加载、存储和常量存储操作。 它们进行了类似的地址计算优化、识别内存中的常量以及对特定模式的存储操作进行优化，例如将 `MOVLload` 后跟 `MOVLstore` 的模式替换为直接的赋值。

* **`rewriteValueAMD64_OpAMD64MOVOload(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVOstore(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVOstoreconst(v *Value) bool`**: 这些函数处理 128 位操作 (`MOVO`) 的加载、存储和常量存储。 它们主要关注优化地址计算。

* **`rewriteValueAMD64_OpAMD64MOVQatomicload(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVQf2i(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVQi2f(v *Value) bool`**, **`rewriteValueAMD64_OpAMD64MOVQload(v *Value) bool`**: 这些函数处理 64 位整数 (`MOVQ`) 的原子加载、浮点数到整数的转换、整数到浮点数的转换和加载操作。 `MOVQload` 尝试识别加载后立即存储的情况，并直接使用存储的值。

**代码示例 (推断)**

以下是一些基于代码推断出的 Go 语言功能实现示例。请注意，这只是基于代码模式的猜测，并非实际运行的代码：

**假设输入/输出 (针对 `rewriteValueAMD64_OpAMD64ADDQ`)**

```go
// 假设 SSA 代码中存在以下加法操作
// v 是代表 ADDQ 操作的 *Value

// 输入：v.Args[0] = x (某个 *Value), v.Args[1] = 常量 0
// 输出：v 会被重置为 x，即 v.reset(x.Op, x.Args...)  (实际上代码是直接返回 true，表示发生了重写)

// 可以推断出对应的 Go 代码可能是：
a := someValue
b := 0
c := a + b  // 在 SSA 阶段，这可能会被表示为 ADDQ a, 0

// 经过 rewriteValueAMD64_OpAMD64ADDQ 处理后，SSA 表示可能简化为直接使用 a
```

**假设输入/输出 (针对 `rewriteValueAMD64_OpAMD64LEAQ2`)**

```go
// 假设 SSA 代码中存在以下 LEAQ2 操作
// v 是代表 LEAQ2 操作的 *Value

// 输入：v.Args[0] 是一个 ADDQconst 操作，例如 (ADDQconst [10] ptr)， v.Args[1] 是 y
// 输出：v 会被重写为 LEAQ2 [c+d] {s} x y，其中 c 是 LEAQ2 的原有偏移量，d 是 ADDQconst 的常量

// 可以推断出对应的 Go 代码可能是：
ptr := &someVariable
offset1 := 5
offset2 := 10
y := someOtherValue
address := uintptr(ptr) + uintptr(offset1) + uintptr(offset2) + uintptr(y) * 2 // 在 SSA 阶段，这可能涉及 LEAQ2 和 ADDQconst

// 经过 rewriteValueAMD64_OpAMD64LEAQ2 处理后，地址计算可能会被优化
```

**使用者易犯错的点**

这段代码是 Go 编译器内部的代码，直接的使用者是 Go 语言的开发者和编译器维护者。 普通 Go 语言使用者不会直接接触到这些重写规则。 因此，不存在普通使用者易犯错的点。

**总结**

`go/src/cmd/compile/internal/ssa/rewriteAMD64.go` 的第 4 部分主要定义了针对 AMD64 架构中各种基本操作 (如加法、加载有效地址、存储、带符号/零扩展的移动等) 的 SSA 值重写规则。 这些规则通过模式匹配和转换，旨在将低效的 SSA 表示转换为更优化的形式，从而提高最终生成机器码的性能。 这一部分的代码集中在内存访问、地址计算和基本算术运算的优化上。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共12部分，请归纳一下它的功能

"""
	v.reset(OpAMD64ADDQ)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAQ2(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LEAQ2 [c] {s} (ADDQconst [d] x) y)
	// cond: is32Bit(int64(c)+int64(d)) && x.Op != OpSB
	// result: (LEAQ2 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(c)+int64(d)) && x.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAQ2)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ2 [c] {s} x (ADDQconst [d] y))
	// cond: is32Bit(int64(c)+2*int64(d)) && y.Op != OpSB
	// result: (LEAQ2 [c+2*d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(is32Bit(int64(c)+2*int64(d)) && y.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAQ2)
		v.AuxInt = int32ToAuxInt(c + 2*d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ2 [c] {s} x (SHLQconst [1] y))
	// result: (LEAQ4 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64SHLQconst || auxIntToInt8(v_1.AuxInt) != 1 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64LEAQ4)
		v.AuxInt = int32ToAuxInt(c)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ2 [c] {s} x (SHLQconst [2] y))
	// result: (LEAQ8 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64SHLQconst || auxIntToInt8(v_1.AuxInt) != 2 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64LEAQ8)
		v.AuxInt = int32ToAuxInt(c)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ2 [off1] {sym1} (LEAQ [off2] {sym2} x) y)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB
	// result: (LEAQ2 [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAQ2)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ2 [off1] {sym1} x (LEAQ1 [off2] {sym2} y y))
	// cond: is32Bit(int64(off1)+2*int64(off2)) && sym2 == nil
	// result: (LEAQ4 [off1+2*off2] {sym1} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64LEAQ1 {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		y := v_1.Args[1]
		if y != v_1.Args[0] || !(is32Bit(int64(off1)+2*int64(off2)) && sym2 == nil) {
			break
		}
		v.reset(OpAMD64LEAQ4)
		v.AuxInt = int32ToAuxInt(off1 + 2*off2)
		v.Aux = symToAux(sym1)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ2 [off] {sym} x (MOVQconst [scale]))
	// cond: is32Bit(int64(off)+int64(scale)*2)
	// result: (LEAQ [off+int32(scale)*2] {sym} x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		scale := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(int64(off) + int64(scale)*2)) {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(off + int32(scale)*2)
		v.Aux = symToAux(sym)
		v.AddArg(x)
		return true
	}
	// match: (LEAQ2 [off] {sym} x (MOVLconst [scale]))
	// cond: is32Bit(int64(off)+int64(scale)*2)
	// result: (LEAQ [off+int32(scale)*2] {sym} x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		scale := auxIntToInt32(v_1.AuxInt)
		if !(is32Bit(int64(off) + int64(scale)*2)) {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(off + int32(scale)*2)
		v.Aux = symToAux(sym)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAQ4(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LEAQ4 [c] {s} (ADDQconst [d] x) y)
	// cond: is32Bit(int64(c)+int64(d)) && x.Op != OpSB
	// result: (LEAQ4 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(c)+int64(d)) && x.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAQ4)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ4 [c] {s} x (ADDQconst [d] y))
	// cond: is32Bit(int64(c)+4*int64(d)) && y.Op != OpSB
	// result: (LEAQ4 [c+4*d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(is32Bit(int64(c)+4*int64(d)) && y.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAQ4)
		v.AuxInt = int32ToAuxInt(c + 4*d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ4 [c] {s} x (SHLQconst [1] y))
	// result: (LEAQ8 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64SHLQconst || auxIntToInt8(v_1.AuxInt) != 1 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpAMD64LEAQ8)
		v.AuxInt = int32ToAuxInt(c)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ4 [off1] {sym1} (LEAQ [off2] {sym2} x) y)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB
	// result: (LEAQ4 [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAQ4)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ4 [off1] {sym1} x (LEAQ1 [off2] {sym2} y y))
	// cond: is32Bit(int64(off1)+4*int64(off2)) && sym2 == nil
	// result: (LEAQ8 [off1+4*off2] {sym1} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64LEAQ1 {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		y := v_1.Args[1]
		if y != v_1.Args[0] || !(is32Bit(int64(off1)+4*int64(off2)) && sym2 == nil) {
			break
		}
		v.reset(OpAMD64LEAQ8)
		v.AuxInt = int32ToAuxInt(off1 + 4*off2)
		v.Aux = symToAux(sym1)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ4 [off] {sym} x (MOVQconst [scale]))
	// cond: is32Bit(int64(off)+int64(scale)*4)
	// result: (LEAQ [off+int32(scale)*4] {sym} x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		scale := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(int64(off) + int64(scale)*4)) {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(off + int32(scale)*4)
		v.Aux = symToAux(sym)
		v.AddArg(x)
		return true
	}
	// match: (LEAQ4 [off] {sym} x (MOVLconst [scale]))
	// cond: is32Bit(int64(off)+int64(scale)*4)
	// result: (LEAQ [off+int32(scale)*4] {sym} x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		scale := auxIntToInt32(v_1.AuxInt)
		if !(is32Bit(int64(off) + int64(scale)*4)) {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(off + int32(scale)*4)
		v.Aux = symToAux(sym)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64LEAQ8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LEAQ8 [c] {s} (ADDQconst [d] x) y)
	// cond: is32Bit(int64(c)+int64(d)) && x.Op != OpSB
	// result: (LEAQ8 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(c)+int64(d)) && x.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAQ8)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ8 [c] {s} x (ADDQconst [d] y))
	// cond: is32Bit(int64(c)+8*int64(d)) && y.Op != OpSB
	// result: (LEAQ8 [c+8*d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(is32Bit(int64(c)+8*int64(d)) && y.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAQ8)
		v.AuxInt = int32ToAuxInt(c + 8*d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ8 [off1] {sym1} (LEAQ [off2] {sym2} x) y)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB
	// result: (LEAQ8 [off1+off2] {mergeSym(sym1,sym2)} x y)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		y := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && x.Op != OpSB) {
			break
		}
		v.reset(OpAMD64LEAQ8)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, y)
		return true
	}
	// match: (LEAQ8 [off] {sym} x (MOVQconst [scale]))
	// cond: is32Bit(int64(off)+int64(scale)*8)
	// result: (LEAQ [off+int32(scale)*8] {sym} x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		scale := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(int64(off) + int64(scale)*8)) {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(off + int32(scale)*8)
		v.Aux = symToAux(sym)
		v.AddArg(x)
		return true
	}
	// match: (LEAQ8 [off] {sym} x (MOVLconst [scale]))
	// cond: is32Bit(int64(off)+int64(scale)*8)
	// result: (LEAQ [off+int32(scale)*8] {sym} x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		scale := auxIntToInt32(v_1.AuxInt)
		if !(is32Bit(int64(off) + int64(scale)*8)) {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(off + int32(scale)*8)
		v.Aux = symToAux(sym)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBELstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBELstore [i] {s} p x:(BSWAPL w) mem)
	// cond: x.Uses == 1
	// result: (MOVLstore [i] {s} p w mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		x := v_1
		if x.Op != OpAMD64BSWAPL {
			break
		}
		w := x.Args[0]
		mem := v_2
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpAMD64MOVLstore)
		v.AuxInt = int32ToAuxInt(i)
		v.Aux = symToAux(s)
		v.AddArg3(p, w, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBEQstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBEQstore [i] {s} p x:(BSWAPQ w) mem)
	// cond: x.Uses == 1
	// result: (MOVQstore [i] {s} p w mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		x := v_1
		if x.Op != OpAMD64BSWAPQ {
			break
		}
		w := x.Args[0]
		mem := v_2
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpAMD64MOVQstore)
		v.AuxInt = int32ToAuxInt(i)
		v.Aux = symToAux(s)
		v.AddArg3(p, w, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBEWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBEWstore [i] {s} p x:(ROLWconst [8] w) mem)
	// cond: x.Uses == 1
	// result: (MOVWstore [i] {s} p w mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		x := v_1
		if x.Op != OpAMD64ROLWconst || auxIntToInt8(x.AuxInt) != 8 {
			break
		}
		w := x.Args[0]
		mem := v_2
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpAMD64MOVWstore)
		v.AuxInt = int32ToAuxInt(i)
		v.Aux = symToAux(s)
		v.AddArg3(p, w, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBQSX(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVBQSX x:(MOVBload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBQSXload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVBload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBQSXload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBQSX x:(MOVWload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBQSXload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVWload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBQSXload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBQSX x:(MOVLload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBQSXload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBQSXload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBQSX x:(MOVQload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBQSXload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBQSXload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBQSX (ANDLconst [c] x))
	// cond: c & 0x80 == 0
	// result: (ANDLconst [c & 0x7f] x)
	for {
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c&0x80 == 0) {
			break
		}
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(c & 0x7f)
		v.AddArg(x)
		return true
	}
	// match: (MOVBQSX (MOVBQSX x))
	// result: (MOVBQSX x)
	for {
		if v_0.Op != OpAMD64MOVBQSX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVBQSX)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBQSXload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBQSXload [off] {sym} ptr (MOVBstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVBQSX x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVBstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpAMD64MOVBQSX)
		v.AddArg(x)
		return true
	}
	// match: (MOVBQSXload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBQSXload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVBQSXload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBQZX(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVBQZX x:(MOVBload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVBload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBQZX x:(MOVWload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVWload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBQZX x:(MOVLload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBQZX x:(MOVQload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVBload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBQZX (ANDLconst [c] x))
	// result: (ANDLconst [c & 0xff] x)
	for {
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(c & 0xff)
		v.AddArg(x)
		return true
	}
	// match: (MOVBQZX (MOVBQZX x))
	// result: (MOVBQZX x)
	for {
		if v_0.Op != OpAMD64MOVBQZX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVBQZX)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBatomicload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBatomicload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVBatomicload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVBatomicload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBatomicload [off1] {sym1} (LEAQ [off2] {sym2} ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBatomicload [off1+off2] {mergeSym(sym1, sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVBatomicload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBload [off] {sym} ptr (MOVBstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVBQZX x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVBstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpAMD64MOVBQZX)
		v.AddArg(x)
		return true
	}
	// match: (MOVBload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVBload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVBload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVLconst [int32(read8(sym, int64(off)))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(int32(read8(sym, int64(off))))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstore [off] {sym} ptr y:(SETL x) mem)
	// cond: y.Uses == 1
	// result: (SETLstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETL {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETLstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr y:(SETLE x) mem)
	// cond: y.Uses == 1
	// result: (SETLEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETLE {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETLEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr y:(SETG x) mem)
	// cond: y.Uses == 1
	// result: (SETGstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETG {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETGstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr y:(SETGE x) mem)
	// cond: y.Uses == 1
	// result: (SETGEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETGE {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETGEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr y:(SETEQ x) mem)
	// cond: y.Uses == 1
	// result: (SETEQstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETEQ {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETEQstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr y:(SETNE x) mem)
	// cond: y.Uses == 1
	// result: (SETNEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETNE {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETNEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr y:(SETB x) mem)
	// cond: y.Uses == 1
	// result: (SETBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETB {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr y:(SETBE x) mem)
	// cond: y.Uses == 1
	// result: (SETBEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETBE {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETBEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr y:(SETA x) mem)
	// cond: y.Uses == 1
	// result: (SETAstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETA {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETAstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr y:(SETAE x) mem)
	// cond: y.Uses == 1
	// result: (SETAEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SETAE {
			break
		}
		x := y.Args[0]
		mem := v_2
		if !(y.Uses == 1) {
			break
		}
		v.reset(OpAMD64SETAEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBQSX x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVBQSX {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBQZX x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVBQZX {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym} (ADDQconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVBstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (MOVBstoreconst [makeValAndOff(int32(int8(c)),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int8(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVQconst [c]) mem)
	// result: (MOVBstoreconst [makeValAndOff(int32(int8(c)),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int8(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVBstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVBstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstoreconst [sc] {s} (ADDQconst [off] ptr) mem)
	// cond: ValAndOff(sc).canAdd32(off)
	// result: (MOVBstoreconst [ValAndOff(sc).addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstoreconst [sc] {sym1} (LEAQ [off] {sym2} ptr) mem)
	// cond: canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)
	// result: (MOVBstoreconst [ValAndOff(sc).addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVBstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVLQSX(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVLQSX x:(MOVLload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVLQSXload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVLQSXload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLQSX x:(MOVQload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVLQSXload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVLQSXload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLQSX (ANDLconst [c] x))
	// cond: uint32(c) & 0x80000000 == 0
	// result: (ANDLconst [c & 0x7fffffff] x)
	for {
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(uint32(c)&0x80000000 == 0) {
			break
		}
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(c & 0x7fffffff)
		v.AddArg(x)
		return true
	}
	// match: (MOVLQSX (MOVLQSX x))
	// result: (MOVLQSX x)
	for {
		if v_0.Op != OpAMD64MOVLQSX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVLQSX)
		v.AddArg(x)
		return true
	}
	// match: (MOVLQSX (MOVWQSX x))
	// result: (MOVWQSX x)
	for {
		if v_0.Op != OpAMD64MOVWQSX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVWQSX)
		v.AddArg(x)
		return true
	}
	// match: (MOVLQSX (MOVBQSX x))
	// result: (MOVBQSX x)
	for {
		if v_0.Op != OpAMD64MOVBQSX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVBQSX)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVLQSXload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVLQSXload [off] {sym} ptr (MOVLstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVLQSX x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpAMD64MOVLQSX)
		v.AddArg(x)
		return true
	}
	// match: (MOVLQSXload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVLQSXload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVLQSXload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVLQZX(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVLQZX x:(MOVLload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVLload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVLload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLQZX x:(MOVQload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVLload <v.Type> [off] {sym} ptr mem)
	for {
		x := v_0
		if x.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpAMD64MOVLload, v.Type)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLQZX (ANDLconst [c] x))
	// result: (ANDLconst [c] x)
	for {
		if v_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVLQZX (MOVLQZX x))
	// result: (MOVLQZX x)
	for {
		if v_0.Op != OpAMD64MOVLQZX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVLQZX)
		v.AddArg(x)
		return true
	}
	// match: (MOVLQZX (MOVWQZX x))
	// result: (MOVWQZX x)
	for {
		if v_0.Op != OpAMD64MOVWQZX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVWQZX)
		v.AddArg(x)
		return true
	}
	// match: (MOVLQZX (MOVBQZX x))
	// result: (MOVBQZX x)
	for {
		if v_0.Op != OpAMD64MOVBQZX {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64MOVBQZX)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVLatomicload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVLatomicload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVLatomicload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVLatomicload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLatomicload [off1] {sym1} (LEAQ [off2] {sym2} ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVLatomicload [off1+off2] {mergeSym(sym1, sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVLatomicload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVLf2i(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVLf2i <t> (Arg <u> [off] {sym}))
	// cond: t.Size() == u.Size()
	// result: @b.Func.Entry (Arg <t> [off] {sym})
	for {
		t := v.Type
		if v_0.Op != OpArg {
			break
		}
		u := v_0.Type
		off := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		if !(t.Size() == u.Size()) {
			break
		}
		b = b.Func.Entry
		v0 := b.NewValue0(v.Pos, OpArg, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVLi2f(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVLi2f <t> (Arg <u> [off] {sym}))
	// cond: t.Size() == u.Size()
	// result: @b.Func.Entry (Arg <t> [off] {sym})
	for {
		t := v.Type
		if v_0.Op != OpArg {
			break
		}
		u := v_0.Type
		off := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		if !(t.Size() == u.Size()) {
			break
		}
		b = b.Func.Entry
		v0 := b.NewValue0(v.Pos, OpArg, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVLload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVLload [off] {sym} ptr (MOVLstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVLQZX x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpAMD64MOVLQZX)
		v.AddArg(x)
		return true
	}
	// match: (MOVLload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVLload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVLload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	// match: (MOVLload [off] {sym} ptr (MOVSSstore [off] {sym} ptr val _))
	// result: (MOVLf2i val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVSSstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpAMD64MOVLf2i)
		v.AddArg(val)
		return true
	}
	// match: (MOVLload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVQconst [int64(read32(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(read32(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVLstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVLstore [off] {sym} ptr (MOVLQSX x) mem)
	// result: (MOVLstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLQSX {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVLstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVLstore [off] {sym} ptr (MOVLQZX x) mem)
	// result: (MOVLstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLQZX {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVLstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVLstore [off1] {sym} (ADDQconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVLstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVLstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVLstore [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (MOVLstoreconst [makeValAndOff(int32(c),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLstore [off] {sym} ptr (MOVQconst [c]) mem)
	// result: (MOVLstoreconst [makeValAndOff(int32(c),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVLstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64MOVLstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVLstore {sym} [off] ptr y:(ADDLload x [off] {sym} ptr mem) mem)
	// cond: y.Uses==1 && clobber(y)
	// result: (ADDLmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ADDLload || auxIntToInt32(y.AuxInt) != off || auxToSym(y.Aux) != sym {
			break
		}
		mem := y.Args[2]
		x := y.Args[0]
		if ptr != y.Args[1] || mem != v_2 || !(y.Uses == 1 && clobber(y)) {
			break
		}
		v.reset(OpAMD64ADDLmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVLstore {sym} [off] ptr y:(ANDLload x [off] {sym} ptr mem) mem)
	// cond: y.Uses==1 && clobber(y)
	// result: (ANDLmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ANDLload || auxIntToInt32(y.AuxInt) != off || auxToSym(y.Aux) != sym {
			break
		}
		mem := y.Args[2]
		x := y.Args[0]
		if ptr != y.Args[1] || mem != v_2 || !(y.Uses == 1 && clobber(y)) {
			break
		}
		v.reset(OpAMD64ANDLmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVLstore {sym} [off] ptr y:(ORLload x [off] {sym} ptr mem) mem)
	// cond: y.Uses==1 && clobber(y)
	// result: (ORLmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ORLload || auxIntToInt32(y.AuxInt) != off || auxToSym(y.Aux) != sym {
			break
		}
		mem := y.Args[2]
		x := y.Args[0]
		if ptr != y.Args[1] || mem != v_2 || !(y.Uses == 1 && clobber(y)) {
			break
		}
		v.reset(OpAMD64ORLmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVLstore {sym} [off] ptr y:(XORLload x [off] {sym} ptr mem) mem)
	// cond: y.Uses==1 && clobber(y)
	// result: (XORLmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64XORLload || auxIntToInt32(y.AuxInt) != off || auxToSym(y.Aux) != sym {
			break
		}
		mem := y.Args[2]
		x := y.Args[0]
		if ptr != y.Args[1] || mem != v_2 || !(y.Uses == 1 && clobber(y)) {
			break
		}
		v.reset(OpAMD64XORLmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVLstore {sym} [off] ptr y:(ADDL l:(MOVLload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (ADDLmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ADDL {
			break
		}
		_ = y.Args[1]
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			l := y_0
			if l.Op != OpAMD64MOVLload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
				continue
			}
			mem := l.Args[1]
			if ptr != l.Args[0] {
				continue
			}
			x := y_1
			if mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
				continue
			}
			v.reset(OpAMD64ADDLmodify)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(ptr, x, mem)
			return true
		}
		break
	}
	// match: (MOVLstore {sym} [off] ptr y:(SUBL l:(MOVLload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (SUBLmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64SUBL {
			break
		}
		x := y.Args[1]
		l := y.Args[0]
		if l.Op != OpAMD64MOVLload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		if ptr != l.Args[0] || mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
			break
		}
		v.reset(OpAMD64SUBLmodify)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVLstore {sym} [off] ptr y:(ANDL l:(MOVLload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (ANDLmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ANDL {
			break
		}
		_ = y.Args[1]
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			l := y_0
			if l.Op != OpAMD64MOVLload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
				continue
			}
			mem := l.Args[1]
			if ptr != l.Args[0] {
				continue
			}
			x := y_1
			if mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
				continue
			}
			v.reset(OpAMD64ANDLmodify)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(ptr, x, mem)
			return true
		}
		break
	}
	// match: (MOVLstore {sym} [off] ptr y:(ORL l:(MOVLload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (ORLmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64ORL {
			break
		}
		_ = y.Args[1]
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			l := y_0
			if l.Op != OpAMD64MOVLload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
				continue
			}
			mem := l.Args[1]
			if ptr != l.Args[0] {
				continue
			}
			x := y_1
			if mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
				continue
			}
			v.reset(OpAMD64ORLmodify)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(ptr, x, mem)
			return true
		}
		break
	}
	// match: (MOVLstore {sym} [off] ptr y:(XORL l:(MOVLload [off] {sym} ptr mem) x) mem)
	// cond: y.Uses==1 && l.Uses==1 && clobber(y, l)
	// result: (XORLmodify [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		y := v_1
		if y.Op != OpAMD64XORL {
			break
		}
		_ = y.Args[1]
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			l := y_0
			if l.Op != OpAMD64MOVLload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
				continue
			}
			mem := l.Args[1]
			if ptr != l.Args[0] {
				continue
			}
			x := y_1
			if mem != v_2 || !(y.Uses == 1 && l.Uses == 1 && clobber(y, l)) {
				continue
			}
			v.reset(OpAMD64XORLmodify)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(ptr, x, mem)
			return true
		}
		break
	}
	// match: (MOVLstore [off] {sym} ptr a:(ADDLconst [c] l:(MOVLload [off] {sym} ptr2 mem)) mem)
	// cond: isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)
	// result: (ADDLconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		a := v_1
		if a.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		l := a.Args[0]
		if l.Op != OpAMD64MOVLload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		ptr2 := l.Args[0]
		if mem != v_2 || !(isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)) {
			break
		}
		v.reset(OpAMD64ADDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLstore [off] {sym} ptr a:(ANDLconst [c] l:(MOVLload [off] {sym} ptr2 mem)) mem)
	// cond: isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)
	// result: (ANDLconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		a := v_1
		if a.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		l := a.Args[0]
		if l.Op != OpAMD64MOVLload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		ptr2 := l.Args[0]
		if mem != v_2 || !(isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)) {
			break
		}
		v.reset(OpAMD64ANDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLstore [off] {sym} ptr a:(ORLconst [c] l:(MOVLload [off] {sym} ptr2 mem)) mem)
	// cond: isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)
	// result: (ORLconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		a := v_1
		if a.Op != OpAMD64ORLconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		l := a.Args[0]
		if l.Op != OpAMD64MOVLload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		ptr2 := l.Args[0]
		if mem != v_2 || !(isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)) {
			break
		}
		v.reset(OpAMD64ORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLstore [off] {sym} ptr a:(XORLconst [c] l:(MOVLload [off] {sym} ptr2 mem)) mem)
	// cond: isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)
	// result: (XORLconstmodify {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		a := v_1
		if a.Op != OpAMD64XORLconst {
			break
		}
		c := auxIntToInt32(a.AuxInt)
		l := a.Args[0]
		if l.Op != OpAMD64MOVLload || auxIntToInt32(l.AuxInt) != off || auxToSym(l.Aux) != sym {
			break
		}
		mem := l.Args[1]
		ptr2 := l.Args[0]
		if mem != v_2 || !(isSamePtr(ptr, ptr2) && a.Uses == 1 && l.Uses == 1 && clobber(l, a)) {
			break
		}
		v.reset(OpAMD64XORLconstmodify)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLstore [off] {sym} ptr (MOVLf2i val) mem)
	// result: (MOVSSstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLf2i {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64MOVSSstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVLstore [i] {s} p x:(BSWAPL w) mem)
	// cond: x.Uses == 1 && buildcfg.GOAMD64 >= 3
	// result: (MOVBELstore [i] {s} p w mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		x := v_1
		if x.Op != OpAMD64BSWAPL {
			break
		}
		w := x.Args[0]
		mem := v_2
		if !(x.Uses == 1 && buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64MOVBELstore)
		v.AuxInt = int32ToAuxInt(i)
		v.Aux = symToAux(s)
		v.AddArg3(p, w, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVLstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVLstoreconst [sc] {s} (ADDQconst [off] ptr) mem)
	// cond: ValAndOff(sc).canAdd32(off)
	// result: (MOVLstoreconst [ValAndOff(sc).addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVLstoreconst [sc] {sym1} (LEAQ [off] {sym2} ptr) mem)
	// cond: canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)
	// result: (MOVLstoreconst [ValAndOff(sc).addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVLstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVOload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVOload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVOload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVOload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVOload [off1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVOload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVOload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVOstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (MOVOstore [off1] {sym} (ADDQconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVOstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVOstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVOstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVOstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64MOVOstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVOstore [dstOff] {dstSym} ptr (MOVOload [srcOff] {srcSym} (SB) _) mem)
	// cond: symIsRO(srcSym)
	// result: (MOVQstore [dstOff+8] {dstSym} ptr (MOVQconst [int64(read64(srcSym, int64(srcOff)+8, config.ctxt.Arch.ByteOrder))]) (MOVQstore [dstOff] {dstSym} ptr (MOVQconst [int64(read64(srcSym, int64(srcOff), config.ctxt.Arch.ByteOrder))]) mem))
	for {
		dstOff := auxIntToInt32(v.AuxInt)
		dstSym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVOload {
			break
		}
		srcOff := auxIntToInt32(v_1.AuxInt)
		srcSym := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		mem := v_2
		if !(symIsRO(srcSym)) {
			break
		}
		v.reset(OpAMD64MOVQstore)
		v.AuxInt = int32ToAuxInt(dstOff + 8)
		v.Aux = symToAux(dstSym)
		v0 := b.NewValue0(v_1.Pos, OpAMD64MOVQconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(int64(read64(srcSym, int64(srcOff)+8, config.ctxt.Arch.ByteOrder)))
		v1 := b.NewValue0(v_1.Pos, OpAMD64MOVQstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(dstOff)
		v1.Aux = symToAux(dstSym)
		v2 := b.NewValue0(v_1.Pos, OpAMD64MOVQconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(int64(read64(srcSym, int64(srcOff), config.ctxt.Arch.ByteOrder)))
		v1.AddArg3(ptr, v2, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVOstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVOstoreconst [sc] {s} (ADDQconst [off] ptr) mem)
	// cond: ValAndOff(sc).canAdd32(off)
	// result: (MOVOstoreconst [ValAndOff(sc).addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVOstoreconst [sc] {sym1} (LEAQ [off] {sym2} ptr) mem)
	// cond: canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)
	// result: (MOVOstoreconst [ValAndOff(sc).addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ValAndOff(sc).canAdd32(off)) {
			break
		}
		v.reset(OpAMD64MOVOstoreconst)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(sc).addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVQatomicload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVQatomicload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVQatomicload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64MOVQatomicload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVQatomicload [off1] {sym1} (LEAQ [off2] {sym2} ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (MOVQatomicload [off1+off2] {mergeSym(sym1, sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64MOVQatomicload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVQf2i(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVQf2i <t> (Arg <u> [off] {sym}))
	// cond: t.Size() == u.Size()
	// result: @b.Func.Entry (Arg <t> [off] {sym})
	for {
		t := v.Type
		if v_0.Op != OpArg {
			break
		}
		u := v_0.Type
		off := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		if !(t.Size() == u.Size()) {
			break
		}
		b = b.Func.Entry
		v0 := b.NewValue0(v.Pos, OpArg, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVQi2f(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVQi2f <t> (Arg <u> [off] {sym}))
	// cond: t.Size() == u.Size()
	// result: @b.Func.Entry (Arg <t> [off] {sym})
	for {
		t := v.Type
		if v_0.Op != OpArg {
			break
		}
		u := v_0.Type
		off := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		if !(t.Size() == u.Size()) {
			break
		}
		b = b.Func.Entry
		v0 := b.NewValue0(v.Pos, OpArg, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64MOVQload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVQload [off] {sym} ptr (MOVQstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: x
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVQload [off1] {sym} (ADDQconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (MOVQload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.A
"""




```