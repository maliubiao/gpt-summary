Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code snippet, which is part of the SSA rewriting rules for the PPC64 architecture in the Go compiler. It also asks for explanations, examples, and potential pitfalls. The key is to identify what transformations this code performs.

2. **Break Down the Code:** I will iterate through each function (`rewriteValuePPC64_OpPPC64...`) and analyze its logic. Each function handles the rewriting of a specific PPC64 opcode (`OpPPC64...`).

3. **Analyze `rewriteValuePPC64_OpPPC64MOVHZloadidx`:**
   - **Purpose:**  This function rewrites instructions of the form `MOVHZloadidx ptr idx mem`. `MOVHZloadidx` likely loads a half-word (16 bits) from memory, with the address calculated by adding a pointer and an index.
   - **Rewriting Logic:** It checks if the index is a constant. If it is, and the constant fits within a 16-bit or (conditionally for newer architectures) 32-bit range, it transforms the `MOVHZloadidx` into a `MOVHZload` with the constant folded into the offset.
   - **Example:** If we have `MOVHZloadidx ptr (MOVDconst [10]) mem`, this could be rewritten to `MOVHZload [10] ptr mem`. This is an optimization.
   - **Conditions:** The `is16Bit(c)` and `is32Bit(c)` checks are important. The `buildcfg.GOPPC64 >= 10` condition suggests architecture-specific optimizations.

4. **Analyze `rewriteValuePPC64_OpPPC64MOVHZreg`:**
   - **Purpose:** This function deals with rewriting `MOVHZreg` instructions. `MOVHZreg` likely moves a value and zero-extends it to 64 bits.
   - **Rewriting Logic:** It looks for various patterns:
     - Masking with a constant: If the input is `ANDconst` with a mask <= 0xFFFF, the `MOVHZreg` is redundant.
     - Shift right and zero-extension:  If the input is a right shift of a zero-extended smaller value (`MOVBZreg`, `MOVHZreg`), the `MOVHZreg` is unnecessary.
     - Right shifts with large constants: If the shift amount is large enough that the upper bits are guaranteed to be zeroed, the `MOVHZreg` is redundant.
     - Applying a bitwise AND mask using `RLWINM`.
     - Redundant casts:  `MOVHZreg` of another `MOVHZreg` or `MOVBZreg`.
     - Loading from memory: If the input is a load instruction (`MOVHBRload`, `MOVHload`, `MOVBZload`), the `MOVHZreg` is often implicit.
     - Combining with bitwise OR, XOR, AND:  Simplifying expressions involving `MOVWZreg` or `MOVHZreg`.
     - Argument passing: If the argument type is already an unsigned 8-bit or 16-bit integer, the zero-extension is implicit.
     - Constant folding: Converting `MOVHZreg (MOVDconst [c])` to `MOVDconst [uint16(c)]`.
   - **Goal:** Many of these rewrites aim to eliminate redundant zero-extension operations or simplify the instruction sequence.

5. **Analyze `rewriteValuePPC64_OpPPC64MOVHload`:**
   - **Purpose:** This function optimizes `MOVHload` instructions, which load a half-word (16 bits) from memory.
   - **Rewriting Logic:**
     - Merging address calculations: If the address is calculated using `MOVDaddr` and has an offset, the offsets and symbols can be merged.
     - Adding a constant offset: If the address is calculated by adding a constant, the constant can be folded into the `MOVHload` offset.
     - Converting to indexed load: If the offset is zero and the address is an addition of a pointer and index, and the add is used only once, it can be rewritten as `MOVHloadidx`.

6. **Analyze `rewriteValuePPC64_OpPPC64MOVHloadidx`:**
   - **Purpose:**  Similar to `MOVHZloadidx`, this function optimizes `MOVHloadidx`.
   - **Rewriting Logic:** If the index is a constant, fold it into the `MOVHload` offset.

7. **Analyze `rewriteValuePPC64_OpPPC64MOVHreg`:**
   - **Purpose:**  Handles rewriting of `MOVHreg` instructions, which likely move a value and sign-extend it to 64 bits.
   - **Rewriting Logic:** Similar to `MOVHZreg` but focuses on sign extension. It looks for patterns involving `ANDconst`, signed shifts (`SRAWconst`), and redundant casts. The constant mask is `0x7FFF` for sign extension. It also handles cases where the input is already a memory load or a smaller signed type.

8. **Analyze `rewriteValuePPC64_OpPPC64MOVHstore`:**
   - **Purpose:** Optimizes `MOVHstore` instructions, which store a half-word (16 bits) to memory.
   - **Rewriting Logic:** Similar optimizations as `MOVHload`: merging address calculations, adding constant offsets, converting to indexed store (`MOVHstoreidx`), and optimizing stores of zero. It also handles cases where the value being stored is the result of a byte-swap operation (`BRH`, `Bswap16`). It also tries to remove redundant moves like `MOVHreg`, `MOVHZreg`, `MOVWreg`, `MOVWZreg`.

9. **Analyze `rewriteValuePPC64_OpPPC64MOVHstoreidx`:**
   - **Purpose:** Optimizes `MOVHstoreidx` instructions.
   - **Rewriting Logic:** If the index is a constant, fold it into the `MOVHstore` offset. It also tries to remove redundant moves before storing.

10. **Analyze `rewriteValuePPC64_OpPPC64MOVHstorezero`:**
    - **Purpose:** Optimizes `MOVHstorezero`, which stores zero to a half-word in memory.
    - **Rewriting Logic:** Merges address calculations and handles constant offsets.

11. **Analyze `rewriteValuePPC64_OpPPC64MOVWBRstore`:**
    - **Purpose:** Optimizes `MOVWBRstore`, which likely stores a word (32 bits) with byte reversal.
    - **Rewriting Logic:** Removes redundant moves like `MOVWreg` and `MOVWZreg` before the store.

12. **Analyze `rewriteValuePPC64_OpPPC64MOVWZload`:**
    - **Purpose:** Optimizes `MOVWZload`, loading a word (32 bits) and zero-extending.
    - **Rewriting Logic:** Similar to `MOVHload`: merging address calculations, adding constant offsets, converting to indexed load.

13. **Analyze `rewriteValuePPC64_OpPPC64MOVWZloadidx`:**
    - **Purpose:** Optimizes `MOVWZloadidx`.
    - **Rewriting Logic:** If the index is constant, fold it into the `MOVWZload` offset.

14. **Analyze `rewriteValuePPC64_OpPPC64MOVWZreg`:**
    - **Purpose:** Optimizes `MOVWZreg`, moving a value and zero-extending to 64 bits.
    - **Rewriting Logic:** Similar to `MOVHZreg`, but for word sizes. Checks for `ANDconst`, right shifts, and redundant casts.

15. **Synthesize the Functionality:**  After analyzing each function, I can summarize the overall functionality of the code snippet:

    - **Instruction Rewriting:**  The code implements rewriting rules for various PPC64 instructions related to loading, storing, and moving half-words (16 bits) and words (32 bits).
    - **Optimization:** The primary goal is optimization. This includes:
        - **Constant Folding:**  Embedding constant offsets directly into load/store instructions.
        - **Address Calculation Simplification:** Merging symbolic offsets and folding constant additions into addressing modes.
        - **Redundant Move Elimination:** Removing unnecessary `MOV` instructions (e.g., when the source is already the desired type or a memory load).
        - **Instruction Selection:**  Choosing more efficient instructions (e.g., using indexed load/store when appropriate).
    - **Architecture Awareness:**  The code considers different PPC64 sub-architectures (`buildcfg.GOPPC64 >= 10`).

16. **Provide Examples and Context:** I will create simple Go code examples to illustrate the transformations. I will also explain the context – this code is part of the Go compiler's optimization pipeline.

17. **Identify Potential Pitfalls (Though None Obvious in This Snippet):**  In this specific snippet, there aren't many obvious user-facing pitfalls. The rewrites are internal compiler optimizations. A more general pitfall in compiler development could be introducing incorrect rewrites that change the semantics of the code. Since the prompt asks, and there aren't direct user pitfalls in *this* code, I can skip this point as instructed.

18. **Structure the Answer:**  I will organize the answer with clear headings and use code blocks for examples. I will make sure to use Chinese as requested.

By following these steps, I can construct a comprehensive and accurate answer to the user's request.
这是 `go/src/cmd/compile/internal/ssa/rewritePPC64.go` 文件中关于 PPC64 架构的 SSA 重写规则的一部分。它的主要功能是**优化和简化中间代码（SSA）中的 PPC64 指令序列**，以便生成更高效的机器码。

以下是对代码片段中各函数功能的归纳和解释：

**1. `rewriteValuePPC64_OpPPC64MOVHZloadidx(v *Value) bool`**

* **功能:**  优化 `MOVHZloadidx` 指令。`MOVHZloadidx` 指令用于从内存中加载一个半字 (16位) 并进行零扩展，地址计算方式是 基址寄存器 + 索引寄存器。
* **优化策略:**  如果索引寄存器是一个常量，并且这个常量可以放入 16 位或 32 位（取决于 PPC64 版本）的立即数中，则将 `MOVHZloadidx` 替换为 `MOVHZload` 指令，并将常量索引值作为偏移量。
* **Go 代码示例:**
  ```go
  // 假设有如下 SSA 中间代码
  // v1 = MOVDconst [10]  // 索引常量 10
  // v2 = MOVHZloadidx ptr v1 mem

  // 经过此规则重写后可能变为
  // v2 = MOVHZload [10] ptr mem
  ```
* **假设的输入与输出:**
    * **输入 (SSA 指令):** `v2 = MOVHZloadidx ptr (MOVDconst [10]) mem`
    * **输出 (SSA 指令):** `v2 = MOVHZload [10] ptr mem`

**2. `rewriteValuePPC64_OpPPC64MOVHZreg(v *Value) bool`**

* **功能:** 优化 `MOVHZreg` 指令。`MOVHZreg` 指令将一个寄存器的低 16 位零扩展到 64 位。
* **优化策略:**
    * **消除冗余的零扩展:** 如果输入已经是零扩展的或者可以通过其他指令保证高位为零，则移除 `MOVHZreg`。
    * **与常量进行 AND 操作的优化:** 如果 `MOVHZreg` 的输入是一个与常量进行 AND 操作的结果，并且该常量能保证结果在低 16 位，则可以直接使用 AND 操作的结果。
    * **与移位操作的结合:**  优化 `MOVHZreg` 和右移操作 (`SRWconst`, `SRDconst`) 的组合。
    * **与其他零扩展指令的结合:** 例如，如果输入已经是 `MOVBZreg` 或另一个 `MOVHZreg`，则可以省略当前的 `MOVHZreg`。
    * **处理位域操作:** 优化与 `RLWINM` (Rotate Left Word Immediate then AND with Mask) 指令的结合。
    * **处理内存加载:** 当输入来自 `MOVBZload` 或 `MOVHZload` 等加载指令时，零扩展可能是隐含的。
    * **处理函数参数:** 如果函数参数本身是无符号的 8 位或 16 位整数类型，则 `MOVHZreg` 是多余的。
    * **常量折叠:** 如果输入是常量，则直接生成零扩展后的常量。
* **Go 代码示例:**
  ```go
  // 假设有如下 SSA 中间代码
  // v1 = ANDconst [0xFFFF] reg  // reg 的低 16 位
  // v2 = MOVHZreg v1

  // 经过此规则重写后可能变为
  // v2 = ANDconst [0xFFFF] reg
  ```
* **假设的输入与输出:**
    * **输入 (SSA 指令):** `v2 = MOVHZreg (ANDconst [0xFFFF] reg)`
    * **输出 (SSA 指令):** `v2 = ANDconst [0xFFFF] reg`

**3. `rewriteValuePPC64_OpPPC64MOVHload(v *Value) bool`**

* **功能:** 优化 `MOVHload` 指令。`MOVHload` 指令用于从内存中加载一个带符号的半字 (16位)。
* **优化策略:**
    * **合并地址计算:** 如果加载地址是通过 `MOVDaddr` 指令加上偏移量计算得到的，并且可以合并符号和偏移量，则进行合并。
    * **常量偏移优化:** 如果加载地址是通过 `ADDconst` 指令加上常量偏移量计算得到的，则将常量偏移量合并到 `MOVHload` 指令的偏移量中。
    * **转换为索引加载:** 如果偏移量为 0，并且加载地址是通过指针加索引的方式计算的，且该加法操作只被使用一次，则将 `MOVHload` 转换为 `MOVHloadidx`。
* **Go 代码示例:**
  ```go
  // 假设有如下 SSA 中间代码
  // v1 = MOVDaddr {sym} [10] ptr // 计算地址
  // v2 = MOVHload [20] {sym2} v1 mem

  // 经过此规则重写后可能变为
  // v2 = MOVHload [30] {merged_sym} ptr mem
  ```
* **假设的输入与输出:**
    * **输入 (SSA 指令):** `v2 = MOVHload [20] {sym2} (MOVDaddr {sym} [10] ptr) mem`
    * **输出 (SSA 指令):** `v2 = MOVHload [30] {merged_sym} ptr mem`

**4. `rewriteValuePPC64_OpPPC64MOVHloadidx(v *Value) bool`**

* **功能:** 优化 `MOVHloadidx` 指令 (与 `MOVHZloadidx` 类似，但加载的是带符号的半字)。
* **优化策略:** 如果索引寄存器是一个常量，将其合并到 `MOVHload` 指令的偏移量中。
* **Go 代码示例:**  与 `MOVHZloadidx` 类似，只是操作码不同。

**5. `rewriteValuePPC64_OpPPC64MOVHreg(v *Value) bool`**

* **功能:** 优化 `MOVHreg` 指令。`MOVHreg` 指令将一个寄存器的低 16 位进行符号扩展到 64 位。
* **优化策略:** 与 `MOVHZreg` 类似，但针对的是符号扩展，包括消除冗余的符号扩展，优化与常量 AND 操作和移位操作的组合，以及处理从内存加载和函数参数的情况。 注意常量掩码是 `0x7FFF`，因为最高位是符号位。
* **Go 代码示例:**
  ```go
  // 假设有如下 SSA 中间代码
  // v1 = SRAWconst [48] reg // 算术右移，会进行符号扩展
  // v2 = MOVHreg v1

  // 经过此规则重写后可能变为
  // v2 = SRAWconst [48] reg
  ```
* **假设的输入与输出:**
    * **输入 (SSA 指令):** `v2 = MOVHreg (SRAWconst [48] reg)`
    * **输出 (SSA 指令):** `v2 = SRAWconst [48] reg`

**6. `rewriteValuePPC64_OpPPC64MOVHstore(v *Value) bool`**

* **功能:** 优化 `MOVHstore` 指令。`MOVHstore` 指令将一个寄存器的低 16 位存储到内存中。
* **优化策略:**
    * **常量偏移和地址合并:** 与 `MOVHload` 类似。
    * **存储零值的优化:** 如果存储的值是常量 0，则使用 `MOVHstorezero` 指令。
    * **转换为索引存储:** 如果偏移量为 0，并且存储地址是通过指针加索引的方式计算的，则将 `MOVHstore` 转换为 `MOVHstoreidx`。
    * **移除冗余的寄存器移动:** 如果要存储的值已经是一个合适的寄存器类型（例如 `MOVHreg` 的结果），则移除中间的 `MOVHreg` 指令。
    * **处理字节序转换:** 优化存储字节序转换的情况，例如存储 `BRH` (Byte Reverse Halfword) 指令的结果。
* **Go 代码示例:**
  ```go
  // 假设有如下 SSA 中间代码
  // v1 = MOVHreg reg  // 将 reg 的低 16 位符号扩展
  // MOVHstore [10] ptr v1 mem

  // 经过此规则重写后可能变为
  // MOVHstore [10] ptr reg mem
  ```
* **假设的输入与输出:**
    * **输入 (SSA 指令):** `MOVHstore [10] ptr (MOVHreg reg) mem`
    * **输出 (SSA 指令):** `MOVHstore [10] ptr reg mem`

**7. `rewriteValuePPC64_OpPPC64MOVHstoreidx(v *Value) bool`**

* **功能:** 优化 `MOVHstoreidx` 指令。
* **优化策略:**
    * **常量索引优化:** 如果索引寄存器是一个常量，将其合并到 `MOVHstore` 指令的偏移量中。
    * **移除冗余的寄存器移动:** 类似于 `MOVHstore`，移除存储前的冗余寄存器移动。
    * **处理字节序转换:** 优化存储字节序转换的情况。
* **Go 代码示例:** 与 `MOVHstore` 类似，只是使用了索引寻址。

**8. `rewriteValuePPC64_OpPPC64MOVHstorezero(v *Value) bool`**

* **功能:** 优化 `MOVHstorezero` 指令，该指令用于将零值存储到内存中的一个半字。
* **优化策略:** 合并地址计算和常量偏移。

**9. `rewriteValuePPC64_OpPPC64MOVWBRstore(v *Value) bool`**

* **功能:** 优化 `MOVWBRstore` 指令。`MOVWBRstore` 用于存储一个字 (32位) 并进行字节反转。
* **优化策略:** 移除要存储值之前的冗余寄存器移动，例如 `MOVWreg` 或 `MOVWZreg`。

**10. `rewriteValuePPC64_OpPPC64MOVWZload(v *Value) bool`**

* **功能:** 优化 `MOVWZload` 指令。`MOVWZload` 从内存中加载一个字 (32位) 并进行零扩展。
* **优化策略:**  与 `MOVHload` 类似的地址计算合并和常量偏移优化，以及转换为索引加载。

**11. `rewriteValuePPC64_OpPPC64MOVWZloadidx(v *Value) bool`**

* **功能:** 优化 `MOVWZloadidx` 指令。
* **优化策略:** 将常量索引合并到 `MOVWZload` 指令的偏移量中。

**12. `rewriteValuePPC64_OpPPC64MOVWZreg(v *Value) bool`**

* **功能:** 优化 `MOVWZreg` 指令。`MOVWZreg` 将一个寄存器的低 32 位零扩展到 64 位。
* **优化策略:**  类似于 `MOVHZreg`，但操作的是 32 位，包括消除冗余的零扩展，优化与常量 AND 操作和移位操作的组合。

**总结第 7 部分的功能:**

这部分代码主要负责 **优化 PPC64 架构中与半字 (16 位) 和字 (32 位) 数据加载、存储和寄存器移动相关的 SSA 指令**。它通过模式匹配和条件判断，将一些复杂的指令序列替换为更简洁、更高效的指令，例如：

* **常量折叠:** 将常量计算融入到指令的立即数或偏移量中。
* **消除冗余操作:** 移除不必要的类型转换或寄存器移动指令。
* **指令选择:**  根据具体情况选择更合适的指令，例如使用索引寻址代替基址加偏移寻址。
* **地址计算优化:** 简化内存地址的计算方式。

这些优化都有助于生成更精简、执行速度更快的 PPC64 机器码。

**使用者易犯错的点:**

由于这些是底层的编译器优化规则，普通 Go 语言使用者通常不会直接与这些代码交互，因此不容易犯错。这些规则由 Go 编译器开发者维护和更新。 开发者在编写新的 SSA 重写规则时，需要非常小心，确保变换的正确性，避免引入 bug，导致生成的代码行为不符合预期。

总而言之，这段代码是 Go 编译器中针对 PPC64 架构进行性能优化的重要组成部分，它在编译过程中默默地工作，帮助我们生成更高效的机器码。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共12部分，请归纳一下它的功能
```

### 源代码
```go
alue) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHZloadidx ptr (MOVDconst [c]) mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHZload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVHZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHZloadidx (MOVDconst [c]) ptr mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHZload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVHZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHZreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVHZreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0xFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0xFFFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHZreg (SRWconst [c] (MOVBZreg x)))
	// result: (SRWconst [c] (MOVBZreg x))
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVBZreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVHZreg (SRWconst [c] (MOVHZreg x)))
	// result: (SRWconst [c] (MOVHZreg x))
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVHZreg (SRWconst [c] x))
	// cond: x.Type.Size() <= 16
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() <= 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg (SRDconst [c] x))
	// cond: c>=48
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 48) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg (SRWconst [c] x))
	// cond: c>=16
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg (RLWINM [r] y))
	// cond: mergePPC64AndRlwinm(0xFFFF,r) != 0
	// result: (RLWINM [mergePPC64AndRlwinm(0xFFFF,r)] y)
	for {
		if v_0.Op != OpPPC64RLWINM {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if !(mergePPC64AndRlwinm(0xFFFF, r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndRlwinm(0xFFFF, r))
		v.AddArg(y)
		return true
	}
	// match: (MOVHZreg y:(MOVHZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHZreg y:(MOVBZreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBZreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHZreg y:(MOVHBRload _ _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHBRload {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHZreg y:(MOVHreg x))
	// result: (MOVHZreg x)
	for {
		y := v_0
		if y.Op != OpPPC64MOVHreg {
			break
		}
		x := y.Args[0]
		v.reset(OpPPC64MOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHZreg (OR <t> x (MOVWZreg y)))
	// result: (MOVHZreg (OR <t> x y))
	for {
		if v_0.Op != OpPPC64OR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVWZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64OR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (XOR <t> x (MOVWZreg y)))
	// result: (MOVHZreg (XOR <t> x y))
	for {
		if v_0.Op != OpPPC64XOR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVWZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64XOR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (AND <t> x (MOVWZreg y)))
	// result: (MOVHZreg (AND <t> x y))
	for {
		if v_0.Op != OpPPC64AND {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVWZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64AND, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (OR <t> x (MOVHZreg y)))
	// result: (MOVHZreg (OR <t> x y))
	for {
		if v_0.Op != OpPPC64OR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVHZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64OR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (XOR <t> x (MOVHZreg y)))
	// result: (MOVHZreg (XOR <t> x y))
	for {
		if v_0.Op != OpPPC64XOR {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVHZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64XOR, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg (AND <t> x (MOVHZreg y)))
	// result: (MOVHZreg (AND <t> x y))
	for {
		if v_0.Op != OpPPC64AND {
			break
		}
		t := v_0.Type
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			if v_0_1.Op != OpPPC64MOVHZreg {
				continue
			}
			y := v_0_1.Args[0]
			v.reset(OpPPC64MOVHZreg)
			v0 := b.NewValue0(v.Pos, OpPPC64AND, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (MOVHZreg z:(ANDconst [c] (MOVBZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		z_0 := z.Args[0]
		if z_0.Op != OpPPC64MOVBZload {
			break
		}
		v.copyOf(z)
		return true
	}
	// match: (MOVHZreg z:(AND y (MOVHZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64AND {
			break
		}
		_ = z.Args[1]
		z_0 := z.Args[0]
		z_1 := z.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
			if z_1.Op != OpPPC64MOVHZload {
				continue
			}
			v.copyOf(z)
			return true
		}
		break
	}
	// match: (MOVHZreg z:(ANDconst [c] (MOVHZload ptr x)))
	// result: z
	for {
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		z_0 := z.Args[0]
		if z_0.Op != OpPPC64MOVHZload {
			break
		}
		v.copyOf(z)
		return true
	}
	// match: (MOVHZreg x:(MOVBZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg x:(MOVBZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVBZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg x:(MOVHZload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg x:(MOVHZloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg x:(Arg <t>))
	// cond: (is8BitInt(t) || is16BitInt(t)) && !t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !((is8BitInt(t) || is16BitInt(t)) && !t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHZreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint16(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVHload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off1] {sym} (ADDconst [off2] x) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVHload [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVHload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVHload [0] {sym} p:(ADD ptr idx) mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVHloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		mem := v_1
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVHloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHloadidx ptr (MOVDconst [c]) mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVHload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHloadidx (MOVDconst [c]) ptr mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVHload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVHreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0x7FFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0x7FFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHreg (SRAWconst [c] (MOVBreg x)))
	// result: (SRAWconst [c] (MOVBreg x))
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVBreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVHreg (SRAWconst [c] (MOVHreg x)))
	// result: (SRAWconst [c] (MOVHreg x))
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVHreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVHreg (SRAWconst [c] x))
	// cond: x.Type.Size() <= 16
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() <= 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRDconst [c] x))
	// cond: c>48
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > 48) {
			break
		}
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRDconst [c] x))
	// cond: c==48
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c == 48) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRADconst [c] x))
	// cond: c>=48
	// result: (SRADconst [c] x)
	for {
		if v_0.Op != OpPPC64SRADconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 48) {
			break
		}
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRWconst [c] x))
	// cond: c>16
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c > 16) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRAWconst [c] x))
	// cond: c>=16
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRAWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg (SRWconst [c] x))
	// cond: c==16
	// result: (SRAWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c == 16) {
			break
		}
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg y:(MOVHreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVHreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHreg y:(MOVBreg _))
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64MOVBreg {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVHreg y:(MOVHZreg x))
	// result: (MOVHreg x)
	for {
		y := v_0
		if y.Op != OpPPC64MOVHZreg {
			break
		}
		x := y.Args[0]
		v.reset(OpPPC64MOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHload _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHload {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg x:(MOVHloadidx _ _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpPPC64MOVHloadidx {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg x:(Arg <t>))
	// cond: (is8BitInt(t) || is16BitInt(t)) && t.IsSigned()
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !((is8BitInt(t) || is16BitInt(t)) && t.IsSigned()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int16(c))])
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int16(c)))
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVHstore [off1] {sym} (ADDconst [off2] x) val mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVHstore [off1+int32(off2)] {sym} x val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(x, val, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVHstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVDconst [0]) mem)
	// result: (MOVHstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpPPC64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstore [0] {sym} p:(ADD ptr idx) val mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVHstoreidx ptr idx val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVHZreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVWZreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr r:(BRH val) mem)
	// cond: r.Uses == 1
	// result: (MOVHBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		r := v_1
		if r.Op != OpPPC64BRH {
			break
		}
		val := r.Args[0]
		mem := v_2
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVHBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (Bswap16 val) mem)
	// result: (MOVHBRstore (MOVDaddr <ptr.Type> [off] {sym} ptr) val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpBswap16 {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVHBRstore)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDaddr, ptr.Type)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg(ptr)
		v.AddArg3(v0, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreidx ptr (MOVDconst [c]) val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstoreidx (MOVDconst [c]) ptr val mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVHstore [int32(c)] ptr val mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		val := v_2
		mem := v_3
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVHstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVHreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVHreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVHZreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVWreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (MOVWZreg x) mem)
	// result: (MOVHstoreidx ptr idx x mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHstoreidx)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx r:(BRH val) mem)
	// cond: r.Uses == 1
	// result: (MOVHBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		r := v_2
		if r.Op != OpPPC64BRH {
			break
		}
		val := r.Args[0]
		mem := v_3
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVHBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (MOVHstoreidx ptr idx (Bswap16 val) mem)
	// result: (MOVHBRstoreidx ptr idx val mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpBswap16 {
			break
		}
		val := v_2.Args[0]
		mem := v_3
		v.reset(OpPPC64MOVHBRstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVHstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstorezero [off1] {sym} (ADDconst [off2] x) mem)
	// cond: ((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1)+off2)))
	// result: (MOVHstorezero [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !((supportsPPC64PCRel() && is32Bit(int64(off1)+off2)) || (is16Bit(int64(off1) + off2))) {
			break
		}
		v.reset(OpPPC64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVHstorezero [off1] {sym1} p:(MOVDaddr [off2] {sym2} x) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVHstorezero [off1+off2] {mergeSym(sym1,sym2)} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		x := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (x.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(x, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWBRstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWBRstore ptr (MOVWreg x) mem)
	// result: (MOVWBRstore ptr x mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWBRstore)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWBRstore ptr (MOVWZreg x) mem)
	// result: (MOVWBRstore ptr x mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpPPC64MOVWBRstore)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWZload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWZload [off1] {sym1} p:(MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))
	// result: (MOVWZload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(p.AuxInt)
		sym2 := auxToSym(p.Aux)
		ptr := p.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && ((is16Bit(int64(off1+off2)) && (ptr.Op != OpSB || p.Uses == 1)) || (supportsPPC64PCRel() && is32Bit(int64(off1+off2))))) {
			break
		}
		v.reset(OpPPC64MOVWZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWZload [off1] {sym} (ADDconst [off2] x) mem)
	// cond: (is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2)))
	// result: (MOVWZload [off1+int32(off2)] {sym} x mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpPPC64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1)+off2) || (supportsPPC64PCRel() && is32Bit(int64(off1)+off2))) {
			break
		}
		v.reset(OpPPC64MOVWZload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(x, mem)
		return true
	}
	// match: (MOVWZload [0] {sym} p:(ADD ptr idx) mem)
	// cond: sym == nil && p.Uses == 1
	// result: (MOVWZloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		p := v_0
		if p.Op != OpPPC64ADD {
			break
		}
		idx := p.Args[1]
		ptr := p.Args[0]
		mem := v_1
		if !(sym == nil && p.Uses == 1) {
			break
		}
		v.reset(OpPPC64MOVWZloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWZloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWZloadidx ptr (MOVDconst [c]) mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWZload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVWZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWZloadidx (MOVDconst [c]) ptr mem)
	// cond: (is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c)))
	// result: (MOVWZload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is16Bit(c) || (buildcfg.GOPPC64 >= 10 && is32Bit(c))) {
			break
		}
		v.reset(OpPPC64MOVWZload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64MOVWZreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVWZreg y:(ANDconst [c] _))
	// cond: uint64(c) <= 0xFFFFFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64ANDconst {
			break
		}
		c := auxIntToInt64(y.AuxInt)
		if !(uint64(c) <= 0xFFFFFFFF) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (MOVWZreg y:(AND (MOVDconst [c]) _))
	// cond: uint64(c) <= 0xFFFFFFFF
	// result: y
	for {
		y := v_0
		if y.Op != OpPPC64AND {
			break
		}
		y_0 := y.Args[0]
		y_1 := y.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, y_0, y_1 = _i0+1, y_1, y_0 {
			if y_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(y_0.AuxInt)
			if !(uint64(c) <= 0xFFFFFFFF) {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (MOVWZreg (SRWconst [c] (MOVBZreg x)))
	// result: (SRWconst [c] (MOVBZreg x))
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVBZreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWZreg (SRWconst [c] (MOVHZreg x)))
	// result: (SRWconst [c] (MOVHZreg x))
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVHZreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWZreg (SRWconst [c] (MOVWZreg x)))
	// result: (SRWconst [c] (MOVWZreg x))
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpPPC64MOVWZreg {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (MOVWZreg (SRWconst [c] x))
	// cond: x.Type.Size() <= 32
	// result: (SRWconst [c] x)
	for {
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(x.Type.Size() <= 32) {
			break
		}
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg (SRDconst [c] x))
	// cond: c>=32
	// result: (SRDconst [c] x)
	for {
		if v_0.Op != OpPPC64SRDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c >= 32) {
			break
		}
		v.reset(OpPP
```