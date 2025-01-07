Response:
My goal is to analyze the provided Go code snippet and describe its functionality, infer the Go features it implements, provide examples, explain command-line argument handling (if any), highlight potential pitfalls for users, and summarize its purpose within the larger context.

**Thinking Process:**

1. **Identify the File and Purpose:** The code is from `go/src/cmd/compile/internal/ssa/rewriteAMD64.go`. The `ssa` package is part of the Go compiler and deals with Static Single Assignment form, an intermediate representation of code used for optimization. The "rewriteAMD64.go" suggests this file contains architecture-specific (AMD64) rewrite rules for the SSA form. These rules transform certain SSA operations into more efficient or lower-level AMD64 instructions.

2. **Examine Function Signatures and Names:**  The functions are named `rewriteValueAMD64_Op*`. This naming convention strongly suggests that each function is responsible for rewriting a specific SSA operation (`Op`). The suffix "AMD64" reinforces the architecture-specific nature.

3. **Analyze Individual Functions:** I'll go through each function, trying to understand what SSA operation it handles and how it rewrites it.

    * **`rewriteValueAMD64_OpIsInBounds`:** Takes `idx` and `len` as input. The rewrite uses `SETB (CMPQ idx len)`. `CMPQ` compares two quad words (64-bit values). `SETB` sets the byte if the carry flag is set (unsigned less than). This strongly suggests this function implements a check for whether an index `idx` is within the bounds of a length `len` for unsigned integers.

    * **`rewriteValueAMD64_OpIsNonNil`:** Takes `p` as input. The rewrite uses `SETNE (TESTQ p p)`. `TESTQ` performs a bitwise AND and sets flags. `SETNE` sets the byte if the zero flag is not set. Testing a pointer against itself will set the zero flag if the pointer is nil. Therefore, this function checks if a pointer `p` is not nil.

    * **`rewriteValueAMD64_OpIsSliceInBounds`:** Takes `idx` and `len`. The rewrite uses `SETBE (CMPQ idx len)`. `SETBE` sets the byte if the carry flag or the zero flag is set (unsigned less than or equal to). This suggests it checks if an index `idx` is less than or equal to the length `len` which makes sense for checking if an index is within the bounds of a slice (including the upper bound conceptually).

4. **Infer Go Features:** Based on the analyzed functions:

    * **`OpIsInBounds`**: Likely related to array or slice indexing bounds checks.
    * **`OpIsNonNil`**:  Clearly related to checking for nil pointers.
    * **`OpIsSliceInBounds`**: Specifically related to slice bounds checks.

5. **Provide Go Code Examples:** Now I'll create simple Go code snippets that would generate the SSA operations being rewritten.

    * **`OpIsInBounds`**: Accessing an array element: `arr[i]` would implicitly involve a bounds check.
    * **`OpIsNonNil`**: Checking if a pointer is nil: `if ptr != nil { ... }`.
    * **`OpIsSliceInBounds`**:  Iterating up to the length of a slice is a common scenario where this check is relevant. Even though direct access like `slice[i]` might use `OpIsInBounds`,  comparison with slice length during loops could involve `OpIsSliceInBounds`.

6. **Hypothesize Inputs and Outputs (for code inference):**  For the `rewriteValueAMD64_Op` functions, the input is an SSA `Value`. The output is a boolean indicating if a rewrite occurred. Internally, the function manipulates the `Value` to represent the rewritten operation. I can show a simplified conceptual input and how it's transformed.

7. **Command-Line Arguments:**  This particular code snippet doesn't seem to directly handle command-line arguments. It's part of the compiler's internal logic. However, compiler flags (like `-gcflags`) can indirectly influence the code generation and thus the application of these rewrite rules.

8. **Potential Pitfalls:**  Users don't directly interact with these rewrite rules. The compiler uses them internally. However, understanding these low-level transformations can help in understanding compiler optimizations and potential performance implications of different Go code constructs. A potential conceptual pitfall is assuming that Go's bounds checks are always implemented the same way at the assembly level; these rewrite rules show there can be variations.

9. **Summarize Functionality:** The overall functionality of this part of `rewriteAMD64.go` is to optimize specific bounds checks and nil pointer checks by replacing the generic SSA operations with efficient AMD64 instructions.

10. **Context within Larger File:**  Knowing this is part 18/23 helps understand that the file is structured into sections, likely dealing with different categories of SSA operations.

By following these steps, I can systematically analyze the code, infer its purpose, and provide a comprehensive explanation. The key is to understand the role of SSA rewriting in the Go compilation process and how architecture-specific optimizations are applied.这是 `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` 文件的第 18 部分，主要负责针对 AMD64 架构的特定 SSA (Static Single Assignment) 操作进行优化的重写规则。

**功能归纳:**

这部分代码定义了一系列函数，每个函数都负责将特定的 Go 语言操作（在 SSA 中表示）转换为更高效的 AMD64 汇编指令序列。 这些转换通常基于 AMD64 架构的特性和指令集，旨在提升生成代码的性能。

**具体功能列举和 Go 语言功能实现推断:**

1. **`rewriteValueAMD64_OpIsInBounds(v *Value) bool`**:
   - **功能:**  将 `OpIsInBounds` 操作（检查索引是否在数组或切片的界限内）重写为 AMD64 的 `SETB` 指令。
   - **Go 语言功能:** 实现数组和切片的边界检查。
   - **代码示例:**
     ```go
     func main() {
         arr := [5]int{1, 2, 3, 4, 5}
         index := 3
         if index >= 0 && index < len(arr) { // 这部分逻辑会被编译成 OpIsInBounds
             println(arr[index])
         }
     }
     ```
   - **假设的输入与输出 (SSA):**
     - **输入 (SSA):** `v` 代表一个 `OpIsInBounds` 操作，带有 `index` 和 `length` 两个参数。
     - **输出 (SSA):** `v` 被重写为 `OpAMD64SETB` 操作，其输入是一个 `OpAMD64CMPQ` 操作，比较 `index` 和 `length`。

2. **`rewriteValueAMD64_OpIsNonNil(v *Value) bool`**:
   - **功能:** 将 `OpIsNonNil` 操作（检查指针是否为 nil）重写为 AMD64 的 `SETNE` 指令，配合 `TESTQ` 指令。
   - **Go 语言功能:** 实现指针的非空检查。
   - **代码示例:**
     ```go
     func main() {
         var ptr *int
         if ptr != nil { // 这部分逻辑会被编译成 OpIsNonNil
             println(*ptr)
         }
     }
     ```
   - **假设的输入与输出 (SSA):**
     - **输入 (SSA):** `v` 代表一个 `OpIsNonNil` 操作，带有指针参数 `p`。
     - **输出 (SSA):** `v` 被重写为 `OpAMD64SETNE` 操作，其输入是一个 `OpAMD64TESTQ` 操作，测试指针 `p` 本身。

3. **`rewriteValueAMD64_OpIsSliceInBounds(v *Value) bool`**:
   - **功能:** 将 `OpIsSliceInBounds` 操作（检查索引是否在切片的有效索引范围内，包括长度）重写为 AMD64 的 `SETBE` 指令。
   - **Go 语言功能:** 实现切片的边界检查，通常在切片操作中出现。
   - **代码示例:**
     ```go
     func main() {
         s := []int{1, 2, 3}
         index := 3
         if index <= len(s) { // 注意这里是 <= len(s)
             // ...
         }
     }
     ```
   - **假设的输入与输出 (SSA):**
     - **输入 (SSA):** `v` 代表一个 `OpIsSliceInBounds` 操作，带有 `index` 和 `length` 两个参数。
     - **输出 (SSA):** `v` 被重写为 `OpAMD64SETBE` 操作，其输入是一个 `OpAMD64CMPQ` 操作，比较 `index` 和 `length`。

**代码推理 (带假设的输入与输出):**

以 `rewriteValueAMD64_OpIsInBounds` 为例：

假设 SSA 中存在一个 `OpIsInBounds` 的操作 `v`，它的参数分别是代表索引的 SSA 值 `idx` 和代表长度的 SSA 值 `len`。

```
// 假设的 SSA 代码片段
v1 = <some operation producing index>
v2 = <some operation producing length>
v3 = IsInBounds v1 v2
```

`rewriteValueAMD64_OpIsInBounds(v3)` 函数会被调用。函数内部的匹配逻辑会识别出 `v3` 是一个 `OpIsInBounds` 操作，并将其重写为：

```
v4 = CMPQ v1 v2  // 执行比较操作，设置标志位
v5 = SETB v4      // 根据进位标志位设置结果 (无符号小于)
v3 (被重写) = v5
```

最终，`OpIsInBounds` 这个高级抽象操作被转换为底层的比较和标志位设置操作。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是在 Go 编译器内部工作的。但是，Go 编译器的命令行参数可能会影响到代码的生成和优化，从而间接影响到这些重写规则的应用。例如，使用 `-O` 标志开启优化可能会触发更多的重写规则。

**使用者易犯错的点:**

用户通常不需要直接关心这些底层的 SSA 重写规则。这些是编译器内部的优化步骤。因此，这里没有直接的使用者容易犯错的点。理解这些规则更多地是帮助理解编译器的工作原理。

**总结这部分的功能:**

这部分 `rewriteAMD64.go` 代码的核心功能是针对 AMD64 架构，优化 Go 语言中关于 **边界检查 (数组/切片索引) 和 nil 指针检查** 的操作。它通过将抽象的 SSA 操作替换为更底层的、高效的 AMD64 汇编指令来实现性能提升。  这种架构特定的优化是 Go 编译器能够生成高性能机器码的关键环节之一。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第18部分，共23部分，请归纳一下它的功能

"""
)
		return true
	}
	return false
}
func rewriteValueAMD64_OpBitLen64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen64 <t> x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (ADDQconst [1] (CMOVQEQ <t> (Select0 <t> (BSRQ x)) (MOVQconst <t> [-1]) (Select1 <types.TypeFlags> (BSRQ x))))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64ADDQconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpAMD64CMOVQEQ, t)
		v1 := b.NewValue0(v.Pos, OpSelect0, t)
		v2 := b.NewValue0(v.Pos, OpAMD64BSRQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2.AddArg(x)
		v1.AddArg(v2)
		v3 := b.NewValue0(v.Pos, OpAMD64MOVQconst, t)
		v3.AuxInt = int64ToAuxInt(-1)
		v4 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v4.AddArg(v2)
		v0.AddArg3(v1, v3, v4)
		v.AddArg(v0)
		return true
	}
	// match: (BitLen64 <t> x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (NEGQ (ADDQconst <t> [-64] (LZCNTQ x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64ADDQconst, t)
		v0.AuxInt = int32ToAuxInt(-64)
		v1 := b.NewValue0(v.Pos, OpAMD64LZCNTQ, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpBitLen8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen8 x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSRL (LEAL1 <typ.UInt32> [1] (MOVBQZX <typ.UInt32> x) (MOVBQZX <typ.UInt32> x)))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSRL)
		v0 := b.NewValue0(v.Pos, OpAMD64LEAL1, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpAMD64MOVBQZX, typ.UInt32)
		v1.AddArg(x)
		v0.AddArg2(v1, v1)
		v.AddArg(v0)
		return true
	}
	// match: (BitLen8 <t> x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (NEGQ (ADDQconst <t> [-32] (LZCNTL (MOVBQZX <x.Type> x))))
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
		v2 := b.NewValue0(v.Pos, OpAMD64MOVBQZX, x.Type)
		v2.AddArg(x)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpBswap16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Bswap16 x)
	// result: (ROLWconst [8] x)
	for {
		x := v_0
		v.reset(OpAMD64ROLWconst)
		v.AuxInt = int8ToAuxInt(8)
		v.AddArg(x)
		return true
	}
}
func rewriteValueAMD64_OpCeil(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ceil x)
	// result: (ROUNDSD [2] x)
	for {
		x := v_0
		v.reset(OpAMD64ROUNDSD)
		v.AuxInt = int8ToAuxInt(2)
		v.AddArg(x)
		return true
	}
}
func rewriteValueAMD64_OpCondSelect(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CondSelect <t> x y (SETEQ cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQEQ y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQ {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQEQ)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQNE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQNE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETL cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQLT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETL {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQLT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETG cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQGT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETG {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQGT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETLE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQLE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETLE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQLE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQGE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQGE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETA cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQHI y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETA {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQHI)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETB cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQCS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETB {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQCS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETAE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQCC y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETAE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQCC)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETBE cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQLS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETBE {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQLS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQF cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQEQF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQF {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQEQF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNEF cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQNEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNEF {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQNEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGF cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQGTF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGF {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQGTF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGEF cond))
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (CMOVQGEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGEF {
			break
		}
		cond := v_2.Args[0]
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpAMD64CMOVQGEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQ cond))
	// cond: is32BitInt(t)
	// result: (CMOVLEQ y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQ {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLEQ)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLNE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLNE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETL cond))
	// cond: is32BitInt(t)
	// result: (CMOVLLT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETL {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLLT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETG cond))
	// cond: is32BitInt(t)
	// result: (CMOVLGT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETG {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLGT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETLE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLLE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETLE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLLE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLGE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLGE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETA cond))
	// cond: is32BitInt(t)
	// result: (CMOVLHI y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETA {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLHI)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETB cond))
	// cond: is32BitInt(t)
	// result: (CMOVLCS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETB {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLCS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETAE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLCC y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETAE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLCC)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETBE cond))
	// cond: is32BitInt(t)
	// result: (CMOVLLS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETBE {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLLS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQF cond))
	// cond: is32BitInt(t)
	// result: (CMOVLEQF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQF {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLEQF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNEF cond))
	// cond: is32BitInt(t)
	// result: (CMOVLNEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNEF {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLNEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGF cond))
	// cond: is32BitInt(t)
	// result: (CMOVLGTF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGF {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLGTF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGEF cond))
	// cond: is32BitInt(t)
	// result: (CMOVLGEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGEF {
			break
		}
		cond := v_2.Args[0]
		if !(is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLGEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQ cond))
	// cond: is16BitInt(t)
	// result: (CMOVWEQ y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQ {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWEQ)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWNE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWNE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETL cond))
	// cond: is16BitInt(t)
	// result: (CMOVWLT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETL {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWLT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETG cond))
	// cond: is16BitInt(t)
	// result: (CMOVWGT y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETG {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWGT)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETLE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWLE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETLE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWLE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWGE y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWGE)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETA cond))
	// cond: is16BitInt(t)
	// result: (CMOVWHI y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETA {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWHI)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETB cond))
	// cond: is16BitInt(t)
	// result: (CMOVWCS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETB {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWCS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETAE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWCC y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETAE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWCC)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETBE cond))
	// cond: is16BitInt(t)
	// result: (CMOVWLS y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETBE {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWLS)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETEQF cond))
	// cond: is16BitInt(t)
	// result: (CMOVWEQF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETEQF {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWEQF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETNEF cond))
	// cond: is16BitInt(t)
	// result: (CMOVWNEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETNEF {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWNEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGF cond))
	// cond: is16BitInt(t)
	// result: (CMOVWGTF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGF {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWGTF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y (SETGEF cond))
	// cond: is16BitInt(t)
	// result: (CMOVWGEF y x cond)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64SETGEF {
			break
		}
		cond := v_2.Args[0]
		if !(is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWGEF)
		v.AddArg3(y, x, cond)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 1
	// result: (CondSelect <t> x y (MOVBQZX <typ.UInt64> check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 1) {
			break
		}
		v.reset(OpCondSelect)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64MOVBQZX, typ.UInt64)
		v0.AddArg(check)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 2
	// result: (CondSelect <t> x y (MOVWQZX <typ.UInt64> check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 2) {
			break
		}
		v.reset(OpCondSelect)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64MOVWQZX, typ.UInt64)
		v0.AddArg(check)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 4
	// result: (CondSelect <t> x y (MOVLQZX <typ.UInt64> check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 4) {
			break
		}
		v.reset(OpCondSelect)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLQZX, typ.UInt64)
		v0.AddArg(check)
		v.AddArg3(x, y, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 8 && (is64BitInt(t) || isPtr(t))
	// result: (CMOVQNE y x (CMPQconst [0] check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 8 && (is64BitInt(t) || isPtr(t))) {
			break
		}
		v.reset(OpAMD64CMOVQNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(check)
		v.AddArg3(y, x, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 8 && is32BitInt(t)
	// result: (CMOVLNE y x (CMPQconst [0] check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 8 && is32BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVLNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(check)
		v.AddArg3(y, x, v0)
		return true
	}
	// match: (CondSelect <t> x y check)
	// cond: !check.Type.IsFlags() && check.Type.Size() == 8 && is16BitInt(t)
	// result: (CMOVWNE y x (CMPQconst [0] check))
	for {
		t := v.Type
		x := v_0
		y := v_1
		check := v_2
		if !(!check.Type.IsFlags() && check.Type.Size() == 8 && is16BitInt(t)) {
			break
		}
		v.reset(OpAMD64CMOVWNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(check)
		v.AddArg3(y, x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpConst16(v *Value) bool {
	// match: (Const16 [c])
	// result: (MOVLconst [int32(c)])
	for {
		c := auxIntToInt16(v.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
}
func rewriteValueAMD64_OpConst8(v *Value) bool {
	// match: (Const8 [c])
	// result: (MOVLconst [int32(c)])
	for {
		c := auxIntToInt8(v.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
}
func rewriteValueAMD64_OpConstBool(v *Value) bool {
	// match: (ConstBool [c])
	// result: (MOVLconst [b2i32(c)])
	for {
		c := auxIntToBool(v.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(b2i32(c))
		return true
	}
}
func rewriteValueAMD64_OpConstNil(v *Value) bool {
	// match: (ConstNil )
	// result: (MOVQconst [0])
	for {
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValueAMD64_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz16 x)
	// result: (BSFL (ORLconst <typ.UInt32> [1<<16] x))
	for {
		x := v_0
		v.reset(OpAMD64BSFL)
		v0 := b.NewValue0(v.Pos, OpAMD64ORLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(1 << 16)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpCtz16NonZero(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ctz16NonZero x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTL)
		v.AddArg(x)
		return true
	}
	// match: (Ctz16NonZero x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSFL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSFL)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz32 x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTL)
		v.AddArg(x)
		return true
	}
	// match: (Ctz32 x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (Select0 (BSFQ (BTSQconst <typ.UInt64> [32] x)))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64BSFQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpAMD64BTSQconst, typ.UInt64)
		v1.AuxInt = int8ToAuxInt(32)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz32NonZero(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ctz32NonZero x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTL)
		v.AddArg(x)
		return true
	}
	// match: (Ctz32NonZero x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSFL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSFL)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz64 x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTQ x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTQ)
		v.AddArg(x)
		return true
	}
	// match: (Ctz64 <t> x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (CMOVQEQ (Select0 <t> (BSFQ x)) (MOVQconst <t> [64]) (Select1 <types.TypeFlags> (BSFQ x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64CMOVQEQ)
		v0 := b.NewValue0(v.Pos, OpSelect0, t)
		v1 := b.NewValue0(v.Pos, OpAMD64BSFQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1.AddArg(x)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpAMD64MOVQconst, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz64NonZero(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz64NonZero x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTQ x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTQ)
		v.AddArg(x)
		return true
	}
	// match: (Ctz64NonZero x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (Select0 (BSFQ x))
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64BSFQ, types.NewTuple(typ.UInt64, types.TypeFlags))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz8 x)
	// result: (BSFL (ORLconst <typ.UInt32> [1<<8 ] x))
	for {
		x := v_0
		v.reset(OpAMD64BSFL)
		v0 := b.NewValue0(v.Pos, OpAMD64ORLconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(1 << 8)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpCtz8NonZero(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ctz8NonZero x)
	// cond: buildcfg.GOAMD64 >= 3
	// result: (TZCNTL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 >= 3) {
			break
		}
		v.reset(OpAMD64TZCNTL)
		v.AddArg(x)
		return true
	}
	// match: (Ctz8NonZero x)
	// cond: buildcfg.GOAMD64 < 3
	// result: (BSFL x)
	for {
		x := v_0
		if !(buildcfg.GOAMD64 < 3) {
			break
		}
		v.reset(OpAMD64BSFL)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 [a] x y)
	// result: (Select0 (DIVW [a] x y))
	for {
		a := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVW, types.NewTuple(typ.Int16, typ.Int16))
		v0.AuxInt = boolToAuxInt(a)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (Select0 (DIVWU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVWU, types.NewTuple(typ.UInt16, typ.UInt16))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32 [a] x y)
	// result: (Select0 (DIVL [a] x y))
	for {
		a := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVL, types.NewTuple(typ.Int32, typ.Int32))
		v0.AuxInt = boolToAuxInt(a)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32u x y)
	// result: (Select0 (DIVLU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVLU, types.NewTuple(typ.UInt32, typ.UInt32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div64 [a] x y)
	// result: (Select0 (DIVQ [a] x y))
	for {
		a := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVQ, types.NewTuple(typ.Int64, typ.Int64))
		v0.AuxInt = boolToAuxInt(a)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div64u x y)
	// result: (Select0 (DIVQU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVQU, types.NewTuple(typ.UInt64, typ.UInt64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (Select0 (DIVW (SignExt8to16 x) (SignExt8to16 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVW, types.NewTuple(typ.Int16, typ.Int16))
		v1 := b.NewValue0(v.Pos, OpSignExt8to16, typ.Int16)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to16, typ.Int16)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (Select0 (DIVWU (ZeroExt8to16 x) (ZeroExt8to16 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpAMD64DIVWU, types.NewTuple(typ.UInt16, typ.UInt16))
		v1 := b.NewValue0(v.Pos, OpZeroExt8to16, typ.UInt16)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to16, typ.UInt16)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq16 x y)
	// result: (SETEQ (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32 x y)
	// result: (SETEQ (CMPL x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPL, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (SETEQF (UCOMISS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQF)
		v0 := b.NewValue0(v.Pos, OpAMD64UCOMISS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64 x y)
	// result: (SETEQ (CMPQ x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQ, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (SETEQF (UCOMISD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQF)
		v0 := b.NewValue0(v.Pos, OpAMD64UCOMISD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq8 x y)
	// result: (SETEQ (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqB x y)
	// result: (SETEQ (CMPB x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPB, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqPtr x y)
	// result: (SETEQ (CMPQ x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpAMD64SETEQ)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQ, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpFMA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMA x y z)
	// result: (VFMADD231SD z x y)
	for {
		x := v_0
		y := v_1
		z := v_2
		v.reset(OpAMD64VFMADD231SD)
		v.AddArg3(z, x, y)
		return true
	}
}
func rewriteValueAMD64_OpFloor(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Floor x)
	// result: (ROUNDSD [1] x)
	for {
		x := v_0
		v.reset(OpAMD64ROUNDSD)
		v.AuxInt = int8ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueAMD64_OpGetG(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GetG mem)
	// cond: v.Block.Func.OwnAux.Fn.ABI() != obj.ABIInternal
	// result: (LoweredGetG mem)
	for {
		mem := v_0
		if !(v.Block.Func.OwnAux.Fn.ABI() != obj.ABIInternal) {
			break
		}
		v.reset(OpAMD64LoweredGetG)
		v.AddArg(mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpHasCPUFeature(v *Value) bool {
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (HasCPUFeature {s})
	// result: (SETNE (CMPLconst [0] (LoweredHasCPUFeature {s})))
	for {
		s := auxToSym(v.Aux)
		v.reset(OpAMD64SETNE)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpAMD64LoweredHasCPUFeature, typ.UInt64)
		v1.Aux = symToAux(s)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsInBounds idx len)
	// result: (SETB (CMPQ idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpAMD64SETB)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQ, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsNonNil p)
	// result: (SETNE (TESTQ p p))
	for {
		p := v_0
		v.reset(OpAMD64SETNE)
		v0 := b.NewValue0(v.Pos, OpAMD64TESTQ, types.TypeFlags)
		v0.AddArg2(p, p)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueAMD64_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsSliceInBounds idx len)
	// result: (SETBE (CMPQ idx len))
	f
"""




```