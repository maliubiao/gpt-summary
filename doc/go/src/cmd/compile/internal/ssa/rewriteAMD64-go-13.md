Response:
My goal is to analyze the provided Go code snippet and fulfill the user's request. Here's a breakdown of the thought process:

1. **Understanding the Context:** The user explicitly mentions the file path `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` and that the snippet is part of a larger function or file. This indicates we're dealing with compiler optimizations for the AMD64 architecture within Go's SSA (Static Single Assignment) intermediate representation. The "part 14 of 23" further emphasizes that this is a segment of a larger process.

2. **Initial Code Scan and Keyword Identification:**  I'll quickly scan the code for prominent keywords and patterns. I see:
    * Function definitions like `rewriteValueAMD64_OpAMD64SETGE`, `rewriteValueAMD64_OpAMD64SETGEstore`, etc. The naming convention suggests these functions handle rewriting specific SSA operations (`OpAMD64SETGE`, `OpAMD64SETGEstore`).
    * Conditional logic (`if`, `for`, `break`).
    * Node manipulation (`v.reset`, `v.AuxInt = ...`, `v.Aux = ...`, `v.AddArg`). These are typical of SSA rewriting where nodes are transformed into equivalent, potentially more efficient, forms.
    * Specific AMD64 instructions (or SSA opcodes representing them) like `MOVLconst`, `SETLEstore`, `ADDQconst`, `LEAQ`, `MOVBstore`, `InvertFlags`, `FlagEQ`, `FlagLT_ULT`, etc.
    * Helper functions like `auxIntToInt32`, `auxToSym`, `symToAux`, `is32Bit`, `canMergeSym`, `mergeSym`, `int32ToAuxInt`, `int8ToAuxInt`, `log32`, `log64`, `isUint32PowerOfTwo`, `isUint64PowerOfTwo`. These likely facilitate working with the SSA node's auxiliary information.

3. **Identifying the Core Functionality:** Based on the function names (e.g., `rewriteValueAMD64_OpAMD64SETGE`), I can infer that this section focuses on rewriting SSA nodes related to setting flags based on comparisons (Greater than or Equal to, Greater than, Less than, Less than or Equal to, Not Equal). The `...store` variants likely deal with storing the result of these flag settings into memory.

4. **Analyzing Individual Rewrite Rules (Patterns):**  I'll examine the `match:` and `result:` comments within each `for` loop. These clearly define the rewrite rules. For example:
    * `// match: (SETGE (FlagLT_ULT))`  means if a `SETGE` operation's argument is a `FlagLT_ULT` operation...
    * `// result: (MOVLconst [0])` ...then rewrite the `SETGE` to a `MOVLconst` (move long constant) with a value of 0.

5. **Connecting Rewrite Rules to Go Semantics:** I need to understand what these SSA operations and rewrite rules mean in terms of actual Go code. The `SETGE`, `SETG`, `SETL`, `SETLE`, `SETNE` operations correspond directly to comparison operators (`>=`, `>`, `<`, `<=`, `!=`) in Go. The flag operations (`FlagEQ`, `FlagLT_ULT`, etc.) are internal representations of the results of underlying comparisons performed by the CPU. The rewrites are optimizations that try to directly generate the boolean (0 or 1) result of the comparison, sometimes avoiding the explicit setting of CPU flags.

6. **Formulating Explanations and Examples:** Now, I can formulate the explanation based on my understanding:
    * **Core Function:**  Optimize boolean result generation for comparison operations on AMD64.
    * **Specific Operations:** List the `SETGE`, `SETG`, `SETL`, `SETLE`, `SETNE` and their `store` variants.
    * **Rewrite Logic:** Explain that the code matches specific patterns of SSA operations and transforms them into more efficient equivalents. Mention the handling of `InvertFlags` which corresponds to negating the comparison.
    * **Example:** Create a simple Go code example demonstrating a comparison (`a >= b`). Then, *hypothesize* how this might be represented in SSA and how the rewrite rules would optimize it. I'll focus on one or two clear examples like `SETGE(FlagLT_ULT)` becoming `MOVLconst [0]`, illustrating the "greater than or equal to" of "less than" being false.
    * **Store Operations:** Explain that the `...store` versions handle assigning the boolean result to a memory location. Highlight optimizations like merging address calculations and directly storing constants.
    * **SETNE and Bitwise Operations:** Emphasize how `SETNE` interacts with bitwise operations like `TEST`, `SHL`, `SHR`, and bit manipulation instructions (`BTL`, `BTQ`).

7. **Addressing Potential Issues (User Mistakes):** While this specific code doesn't involve direct user input or command-line arguments, I can point out a general misconception:  Users might not realize the level of optimization the Go compiler performs under the hood. They might write code thinking it's being executed literally, unaware of these SSA rewrites. However, since the prompt explicitly asked for *user* errors, and this is compiler code,  I should state there are no direct user-facing errors within *this specific snippet*.

8. **Summarizing the Section's Function:** Finally, provide a concise summary of the functionality of this particular part of the `rewriteAMD64.go` file.

9. **Review and Refine:** I'll review my explanation for clarity, accuracy, and completeness, ensuring it addresses all parts of the user's prompt. I'll double-check the Go code example and the hypothesized SSA transformations. I'll make sure the language is clear and accessible.

This detailed thought process allows me to break down the complex code into understandable components and explain its purpose and functionality effectively. The focus on understanding the SSA representation and the mapping to Go semantics is crucial for a correct interpretation.
这段代码是Go语言编译器中AMD64架构特定代码重写规则的一部分，主要功能是针对比较操作的结果（大于等于）进行优化。

**具体功能归纳：**

这段代码定义了两个主要的函数：

1. **`rewriteValueAMD64_OpAMD64SETGE(v *Value) bool`**:  这个函数负责重写 `OpAMD64SETGE` 操作（表示设置大于等于标志）的值。它会检查 `SETGE` 操作的参数，如果参数是特定的比较标志（例如 `FlagLT_ULT`，表示小于），则会将 `SETGE` 操作直接替换为相应的常量值（例如，如果参数是 `FlagLT_ULT`，则 `a >= b` 且 `a < b` 同时成立是不可能的，所以结果为 `false`，用常量 `0` 表示）。

2. **`rewriteValueAMD64_OpAMD64SETGEstore(v *Value) bool`**: 这个函数负责重写 `OpAMD64SETGEstore` 操作（表示将大于等于比较的结果存储到内存中）。它会尝试优化存储操作，例如：
    * 将反转标志的比较存储转换为等价的相反比较存储 (`SETGEstore` with `InvertFlags` becomes `SETLEstore`).
    * 合并地址计算中的常量偏移 (`SETGEstore [off1] {sym} (ADDQconst [off2] base) ...` becomes `SETGEstore [off1+off2] {sym} base ...`).
    * 将基于比较标志的存储直接替换为存储常量 `0` 或 `1` 的操作 (`SETGEstore` with `FlagEQ`, `FlagLT_ULT`, `FlagGT_ULT` 等 becomes `MOVBstore` with `0` or `1`).

**它可以推理出这是Go语言布尔比较操作 `>=` 的实现优化。**

**Go代码举例说明：**

假设有以下Go代码：

```go
package main

func main() {
	a := 10
	b := 5
	result := a >= b
	println(result) // 输出 true
}
```

**SSA表示（简化的假设输入）：**

在编译过程中，`a >= b` 可能会被表示成类似以下的SSA结构（这只是一个概念性的例子，实际SSA更复杂）：

```
v1 = ConstInt 10
v2 = ConstInt 5
v3 = CMPL v1 v2  // 比较 v1 和 v2，设置标志位
v4 = SETGE v3     // 根据标志位设置 v4，如果 v1 >= v2，则 v4 为 1，否则为 0
```

**代码推理与假设输出：**

当编译器处理 `v4 = SETGE v3` 这一步时，`rewriteValueAMD64_OpAMD64SETGE` 函数会被调用，其中 `v` 代表 `v4`，`v_0` (即 `v.Args[0]`) 代表 `v3`。

假设 `CMPL` 操作（`v3`）设置的标志位最终被抽象成 `FlagGT_UGT` (大于，无符号)。

根据代码中的规则：

```go
	// match: (SETGE (FlagGT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
```

`rewriteValueAMD64_OpAMD64SETGE` 函数会识别出 `v_0.Op` 是 `OpAMD64FlagGT_UGT`，然后会将 `v4` 的操作重置为 `OpAMD64MOVLconst`，并将 `AuxInt` 设置为 `1`。

**假设输出的SSA（优化后）：**

```
v1 = ConstInt 10
v2 = ConstInt 5
v3 = CMPL v1 v2
v4 = MOVLconst 1  // SETGE 被直接替换为常量 1
```

这样，`SETGE` 操作就被优化掉了，直接得到了比较结果的常量值。

**存储操作的例子：**

对于 `result := a >= b`，如果 `result` 需要存储到内存中，可能会涉及 `SETGEstore` 操作。

**假设输入SSA：**

```
v1 = ConstInt 10
v2 = ConstInt 5
v3 = CMPL v1 v2
v4 = SETGE v3
v5 = Store result_addr v4 mem // 将 v4 的值存储到 result_addr
```

经过 `rewriteValueAMD64_OpAMD64SETGEstore` 的处理，可能会将 `SETGE` 和 `Store` 合并优化，例如直接存储常量值：

```go
	// match: (SETGEstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
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
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
```

如果 `v4` 是基于 `FlagGT_UGT` 的 `SETGE`，那么 `SETGEstore` 可以直接被替换为存储常量 `1` 的 `MOVBstore` 操作。

**命令行参数：**

这段代码本身不直接处理命令行参数。它是Go编译器内部的一部分，在编译过程中被调用。Go编译器的命令行参数会影响整个编译过程，但不会直接传递到这些重写函数中。

**使用者易犯错的点：**

因为这段代码是编译器内部的优化，普通Go语言开发者不会直接接触或编写这样的代码。因此，不存在使用者易犯错的点。  这段代码的编写者需要非常熟悉AMD64架构、SSA表示以及Go编译器的内部工作原理。

**这段代码（第14部分）的功能总结：**

这段代码是AMD64架构下，针对“大于等于”比较操作 (`>=`) 的SSA重写规则的一部分。它通过匹配特定的SSA操作模式，并将其转换为更高效的等价操作，例如直接生成常量值或优化存储操作。这有助于提高最终生成机器码的效率。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第14部分，共23部分，请归纳一下它的功能

"""
	}
	// match: (SETGE (FlagLT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETGE (FlagLT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETGE (FlagGT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETGE (FlagGT_UGT))
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
func rewriteValueAMD64_OpAMD64SETGEstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETGEstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETLEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETLEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETGEstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETGEstore [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64SETGEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETGEstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETGEstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64SETGEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETGEstore [off] {sym} ptr (FlagEQ) mem)
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
	// match: (SETGEstore [off] {sym} ptr (FlagLT_ULT) mem)
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
	// match: (SETGEstore [off] {sym} ptr (FlagLT_UGT) mem)
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
	// match: (SETGEstore [off] {sym} ptr (FlagGT_ULT) mem)
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
	// match: (SETGEstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
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
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETGstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETGstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETLstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETLstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETGstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETGstore [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64SETGstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETGstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETGstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64SETGstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETGstore [off] {sym} ptr (FlagEQ) mem)
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
	// match: (SETGstore [off] {sym} ptr (FlagLT_ULT) mem)
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
	// match: (SETGstore [off] {sym} ptr (FlagLT_UGT) mem)
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
	// match: (SETGstore [off] {sym} ptr (FlagGT_ULT) mem)
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
	// match: (SETGstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
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
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SETL (InvertFlags x))
	// result: (SETG x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETG)
		v.AddArg(x)
		return true
	}
	// match: (SETL (FlagEQ))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETL (FlagLT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETL (FlagLT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETL (FlagGT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETL (FlagGT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETLE(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SETLE (InvertFlags x))
	// result: (SETGE x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETGE)
		v.AddArg(x)
		return true
	}
	// match: (SETLE (FlagEQ))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETLE (FlagLT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETLE (FlagLT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETLE (FlagGT_ULT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETLE (FlagGT_UGT))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETLEstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETLEstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETGEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETGEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETLEstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETLEstore [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64SETLEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETLEstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETLEstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64SETLEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETLEstore [off] {sym} ptr (FlagEQ) mem)
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
	// match: (SETLEstore [off] {sym} ptr (FlagLT_ULT) mem)
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
	// match: (SETLEstore [off] {sym} ptr (FlagLT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
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
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETLEstore [off] {sym} ptr (FlagGT_ULT) mem)
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
	// match: (SETLEstore [off] {sym} ptr (FlagGT_UGT) mem)
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
func rewriteValueAMD64_OpAMD64SETLstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETLstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETGstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETGstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETLstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETLstore [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64SETLstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETLstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETLstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64SETLstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETLstore [off] {sym} ptr (FlagEQ) mem)
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
	// match: (SETLstore [off] {sym} ptr (FlagLT_ULT) mem)
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
	// match: (SETLstore [off] {sym} ptr (FlagLT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
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
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETLstore [off] {sym} ptr (FlagGT_ULT) mem)
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
	// match: (SETLstore [off] {sym} ptr (FlagGT_UGT) mem)
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
func rewriteValueAMD64_OpAMD64SETNE(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (SETNE (TESTBconst [1] x))
	// result: (ANDLconst [1] x)
	for {
		if v_0.Op != OpAMD64TESTBconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(x)
		return true
	}
	// match: (SETNE (TESTWconst [1] x))
	// result: (ANDLconst [1] x)
	for {
		if v_0.Op != OpAMD64TESTWconst || auxIntToInt16(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(x)
		return true
	}
	// match: (SETNE (TESTL (SHLL (MOVLconst [1]) x) y))
	// result: (SETB (BTL x y))
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
			v.reset(OpAMD64SETB)
			v0 := b.NewValue0(v.Pos, OpAMD64BTL, types.TypeFlags)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (TESTQ (SHLQ (MOVQconst [1]) x) y))
	// result: (SETB (BTQ x y))
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
			v.reset(OpAMD64SETB)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQ, types.TypeFlags)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (TESTLconst [c] x))
	// cond: isUint32PowerOfTwo(int64(c))
	// result: (SETB (BTLconst [int8(log32(c))] x))
	for {
		if v_0.Op != OpAMD64TESTLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isUint32PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETB)
		v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SETNE (TESTQconst [c] x))
	// cond: isUint64PowerOfTwo(int64(c))
	// result: (SETB (BTQconst [int8(log32(c))] x))
	for {
		if v_0.Op != OpAMD64TESTQconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isUint64PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETB)
		v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SETNE (TESTQ (MOVQconst [c]) x))
	// cond: isUint64PowerOfTwo(c)
	// result: (SETB (BTQconst [int8(log64(c))] x))
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
			v.reset(OpAMD64SETB)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log64(c)))
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (CMPLconst [1] s:(ANDLconst [1] _)))
	// result: (SETEQ (CMPLconst [0] s))
	for {
		if v_0.Op != OpAMD64CMPLconst || auxIntToInt32(v_0.AuxInt) != 1 {
			break
		}
		s := v_0.Args[0]
		if s.Op != OpAMD64ANDLconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg(v0)
		return true
	}
	// match: (SETNE (CMPQconst [1] s:(ANDQconst [1] _)))
	// result: (SETEQ (CMPQconst [0] s))
	for {
		if v_0.Op != OpAMD64CMPQconst || auxIntToInt32(v_0.AuxInt) != 1 {
			break
		}
		s := v_0.Args[0]
		if s.Op != OpAMD64ANDQconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg(v0)
		return true
	}
	// match: (SETNE (TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2))
	// cond: z1==z2
	// result: (SETB (BTQconst [63] x))
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
			v.reset(OpAMD64SETB)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (TESTL z1:(SHLLconst [31] (SHRQconst [31] x)) z2))
	// cond: z1==z2
	// result: (SETB (BTQconst [31] x))
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
			v.reset(OpAMD64SETB)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (TESTQ z1:(SHRQconst [63] (SHLQconst [63] x)) z2))
	// cond: z1==z2
	// result: (SETB (BTQconst [0] x))
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
			v.reset(OpAMD64SETB)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (TESTL z1:(SHRLconst [31] (SHLLconst [31] x)) z2))
	// cond: z1==z2
	// result: (SETB (BTLconst [0] x))
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
			v.reset(OpAMD64SETB)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (TESTQ z1:(SHRQconst [63] x) z2))
	// cond: z1==z2
	// result: (SETB (BTQconst [63] x))
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
			v.reset(OpAMD64SETB)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (TESTL z1:(SHRLconst [31] x) z2))
	// cond: z1==z2
	// result: (SETB (BTLconst [31] x))
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
			v.reset(OpAMD64SETB)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (InvertFlags x))
	// result: (SETNE x)
	for {
		if v_0.Op != OpAMD64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64SETNE)
		v.AddArg(x)
		return true
	}
	// match: (SETNE (FlagEQ))
	// result: (MOVLconst [0])
	for {
		if v_0.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SETNE (FlagLT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETNE (FlagLT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagLT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETNE (FlagGT_ULT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_ULT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETNE (FlagGT_UGT))
	// result: (MOVLconst [1])
	for {
		if v_0.Op != OpAMD64FlagGT_UGT {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (SETNE (TESTQ s:(Select0 blsr:(BLSRQ _)) s))
	// result: (SETNE (Select1 <types.TypeFlags> blsr))
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
			v.reset(OpAMD64SETNE)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (SETNE (TESTL s:(Select0 blsr:(BLSRL _)) s))
	// result: (SETNE (Select1 <types.TypeFlags> blsr))
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
			v.reset(OpAMD64SETNE)
			v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
			v0.AddArg(blsr)
			v.AddArg(v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64SETNEstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETNEstore [off] {sym} ptr (TESTL (SHLL (MOVLconst [1]) x) y) mem)
	// result: (SETBstore [off] {sym} ptr (BTL x y) mem)
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
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTL, types.TypeFlags)
			v0.AddArg2(x, y)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQ (SHLQ (MOVQconst [1]) x) y) mem)
	// result: (SETBstore [off] {sym} ptr (BTQ x y) mem)
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
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQ, types.TypeFlags)
			v0.AddArg2(x, y)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// matc
"""




```