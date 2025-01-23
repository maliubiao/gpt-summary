Response:
My goal is to analyze the provided Go code snippet and explain its functionality in the context of the `rewriteS390X.go` file. Here's a breakdown of my thought process:

1. **Identify the File and Purpose:** The code is part of `go/src/cmd/compile/internal/ssa/rewriteS390X.go`. The `ssa` package suggests this is related to Static Single Assignment form, a compiler intermediate representation. The `rewrite` prefix and the `S390X` suffix strongly indicate that this file is responsible for applying architecture-specific optimizations or transformations to the SSA representation for the IBM z/Architecture (s390x).

2. **Examine Function Signatures:** The code consists of several functions named `rewriteValueS390X_OpS390X...`. This naming convention suggests that each function handles a specific SSA operation (`OpS390X...`). The input to each function is a `*Value`, which represents a node in the SSA graph. The return type is `bool`, likely indicating whether a rewrite rule was applied.

3. **Analyze Individual Functions:**  I'll go through each function and identify the patterns it tries to match and the transformations it performs. The core logic within each function is a series of `match:` and `cond:` followed by `result:`. This is a common pattern for rewrite rules:

    * **`match:`:** Defines the SSA instruction pattern to look for. It often involves checking the opcode (`Op`), auxiliary information (`AuxInt`, `Aux`), and arguments (`Args`).
    * **`cond:`:** Specifies the conditions under which the rewrite should be applied. These conditions might involve checks on constants, types, memory alignment, or other properties of the SSA values.
    * **`result:`:**  Describes the new SSA instruction or sequence of instructions that should replace the matched pattern.

4. **Focus on Specific Operations (Example: `OpS390XMOVHload`)**:
    * The function `rewriteValueS390X_OpS390XMOVHload` deals with the `MOVHload` operation, which likely represents loading a half-word (16 bits) from memory.
    * The rewrite rules aim to optimize common memory access patterns.
    * One rule combines a `MOVHload` with a preceding `MOVDaddr` (move doubleword address) if the offsets and symbols can be merged. This avoids redundant calculations of memory addresses.
    * Another rule looks for a `MOVHload` immediately following a `MOVHstore` to the same memory location and replaces it with a direct register move (`MOVHreg`). This is a store-load forwarding optimization.

5. **Infer Go Language Features:** Based on the operations being optimized, I can infer some of the Go language features that these rewrites might be related to:
    * **Memory Access:** Operations like `MOVHload`, `MOVHstore`, `MOVWload`, etc., are directly related to how Go accesses memory for different data types (int16, uint16, int32, etc.).
    * **Pointers and Addressing:**  `MOVDaddr` suggests the manipulation of memory addresses. The checks involving `OpSB` (stack base) indicate optimizations related to stack-allocated variables.
    * **Data Types and Sizes:** The operations are specific to the sizes of data (byte, half-word, word), reflecting Go's type system.
    * **Constants:** The use of `MOVDconst` and checks on constant values in the conditions indicate optimizations related to constant propagation and folding.
    * **Bitwise Operations:** `Bswap16` (byte swap) is present, suggesting optimizations related to endianness conversion or specific bit manipulations.

6. **Construct Go Code Examples:**  For each type of optimization, I'll construct a simple Go code snippet that could potentially trigger the rewrite rule. This will help illustrate the practical impact of the optimization.

7. **Identify Potential Pitfalls:** I'll consider scenarios where a programmer might write code that appears similar to the patterns being optimized but doesn't actually benefit from the rewrite. For example, performing a store and load with different offsets wouldn't be optimized by the store-load forwarding rule.

8. **Summarize Functionality:** Finally, I'll synthesize the information gathered from analyzing the individual functions and the overall purpose of the file to provide a concise summary of its functionality.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption:**  I might initially assume that all the rewrite rules are about performance. However, some rules might be related to correctness or code size reduction. For example, removing redundant moves.
* **Deeper Dive:** If a particular rewrite rule is complex, I might need to look up the definitions of the SSA operations involved or consult the Go compiler source code for more context.
* **Testing (Hypothetical):** If I were developing this code, I would write unit tests to ensure that each rewrite rule works correctly for various input SSA graphs. This would involve creating representative SSA structures and verifying that the transformations are applied as expected.

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive explanation of its functionality.
这是 `go/src/cmd/compile/internal/ssa/rewriteS390X.go` 文件的一部分，主要功能是定义了一系列的 SSA 重写规则，用于优化 S390X 架构下的 Go 代码。这些规则旨在将一些操作模式转换为更高效的指令序列。

**总的来说，这部分代码的功能是针对 S390X 架构的 `MOVHload` (加载半字)、`MOVHreg` (半字寄存器移动)、`MOVHstore` (存储半字)、`MOVHstoreconst` (存储半字常量)、`MOVHstoreidx` (带索引存储半字)、`MOVWBR` (字反转)、`MOVWZload` (零扩展加载字)、`MOVWZreg` (零扩展字寄存器移动)、`MOVWload` (加载字)、`MOVWreg` (字寄存器移动)、`MOVWstore` (存储字)、`MOVWstoreconst` (存储字常量)、`MOVWstoreidx` (带索引存储字) 以及 `MULLD` (乘法) 等操作进行优化的重写规则。**

由于这是第 8 部分，前面 7 部分可能已经定义了其他操作的重写规则。而这部分专注于对半字和字的操作进行优化，包括加载、存储、寄存器移动以及一些特定的转换，例如字反转。

**以下是对部分功能的更详细解释和代码示例：**

**1. 优化 `MOVHload` (加载半字):**

* **合并地址计算:** 当加载的地址是由 `MOVDaddr` 指令计算得到时，并且偏移和符号可以合并，就将两个偏移合并为一个，减少地址计算的步骤。
* **示例:**
  ```go
  // 假设的 SSA 输入
  // v1 = MOVDaddr [off2] {sym2} base
  // v = MOVHload [off1] {sym1} v1 mem

  // 重写后的 SSA 输出 (如果满足条件)
  // v = MOVHload [off1+off2] {mergeSym(sym1,sym2)} base mem
  ```
  **假设的输入与输出:**
  输入：一个 `MOVHload` 指令，其地址来自一个 `MOVDaddr` 指令。例如，加载地址 `base + off2 + off1` 的半字。
  输出：如果 `off1` 和 `off2` 可以合并，且符号也可以合并，则生成一个新的 `MOVHload` 指令，直接使用合并后的偏移 `off1 + off2`。

**2. 优化 `MOVHreg` (半字寄存器移动):**

* **消除冗余的符号扩展/零扩展:** 如果要移动的源寄存器已经是更小类型的符号扩展或零扩展结果，则可以直接使用源寄存器的值。
* **利用 `MOVHZload`:** 如果要移动的值来自一个只被使用一次的 `MOVHZload` 指令，则可以将 `MOVHreg` 直接替换为 `MOVHload`，避免额外的寄存器移动。
* **示例:**
  ```go
  // 假设的 SSA 输入
  // v1 = MOVHZreg x
  // v = MOVHreg v1

  // 重写后的 SSA 输出
  // v = MOVHreg x
  ```
  **假设的输入与输出:**
  输入：一个 `MOVHreg` 指令，其源操作数是一个 `MOVHZreg` 指令，表示将一个半字零扩展到更大的寄存器。
  输出：直接使用 `MOVHZreg` 的源操作数，因为 `MOVHreg` 也会进行符号扩展，而零扩展后的值再进行符号扩展不会改变其低 16 位的值。

**3. 优化 `MOVHstore` (存储半字):**

* **直接使用寄存器值:** 如果要存储的值来自 `MOVHreg` 或 `MOVHZreg`，则可以直接使用其源寄存器的值，避免额外的寄存器移动。
* **合并地址计算 (类似于 `MOVHload`):**  当存储的地址是由 `ADDconst` 或 `MOVDaddr` 指令计算得到时，并且偏移和符号可以合并，就将偏移合并为一个。
* **使用 `MOVHstoreconst`:** 如果要存储的是常量，并且偏移在一定范围内，可以使用更紧凑的 `MOVHstoreconst` 指令。
* **使用 `MOVHBRstore` (半字反转存储):** 如果要存储的值先进行了字节反转 (`Bswap16`)，可以直接使用 `MOVHBRstore` 指令。
* **示例:**
  ```go
  // 假设的 SSA 输入
  // v1 = MOVHreg x
  // v = MOVHstore [off] {sym} ptr v1 mem

  // 重写后的 SSA 输出
  // v = MOVHstore [off] {sym} ptr x mem
  ```
  **假设的输入与输出:**
  输入：一个 `MOVHstore` 指令，其要存储的值来自一个 `MOVHreg` 指令。
  输出：直接使用 `MOVHreg` 的源操作数 `x` 进行存储，避免中间的寄存器移动。

**4. 优化 `MOVWBR` (字反转):**

* **与加载指令结合:** 如果字反转操作紧跟着一个零扩展加载字的指令 (`MOVWZload` 或 `MOVWZloadidx`) 并且该加载指令只被使用一次，则可以将字反转操作融入到加载操作中，使用 `MOVWBRload` 或 `MOVWBRloadidx` 指令。
* **示例:**
  ```go
  // 假设的 SSA 输入
  // v1 = MOVWZload [off] {sym} ptr mem
  // v = MOVWBR v1

  // 重写后的 SSA 输出
  // v = MOVWZreg (MOVWBRload [off] {sym} ptr mem)
  ```
  **假设的输入与输出:**
  输入：先使用 `MOVWZload` 加载一个字并进行零扩展，然后对其结果进行字反转。
  输出：使用 `MOVWBRload` 指令，它会直接加载并反转字节序，并将结果零扩展到 64 位寄存器中。

**5. 优化 `MOVWZload` (零扩展加载字):**

* **消除冗余的存储-加载:** 如果加载操作紧跟着对相同地址的存储操作 (`MOVWstore`)，并且是相同的指针，则可以直接使用存储的值。
* **合并地址计算 (类似于 `MOVHload` 和 `MOVHstore`):** 当加载的地址是由 `ADDconst` 或 `MOVDaddr` 指令计算得到时，并且偏移和符号可以合并，就将偏移合并为一个。
* **示例:**
  ```go
  // 假设的 SSA 输入
  // v1 = MOVWstore [off] {sym} ptr x _
  // v = MOVWZload [off] {sym} ptr v1

  // 重写后的 SSA 输出
  // v = MOVWZreg x
  ```
  **假设的输入与输出:**
  输入：先使用 `MOVWstore` 存储一个字到某个内存地址，然后立即从相同的地址加载该字并进行零扩展。
  输出：直接使用 `MOVWstore` 存储的值 `x`，避免不必要的内存访问。

**6. 优化 `MOVWZreg` (零扩展字寄存器移动):**

* **消除冗余的零扩展:** 如果源寄存器已经是更小类型的零扩展结果，则可以直接使用源寄存器的值。
* **利用 `MOVWload`:** 如果要移动的值来自一个只被使用一次的 `MOVWload` 指令，则可以将 `MOVWZreg` 直接替换为 `MOVWZload`，避免额外的寄存器移动。
* **示例:**
  ```go
  // 假设的 SSA 输入
  // v1 = MOVHZreg x
  // v = MOVWZreg v1

  // 重写后的 SSA 输出
  // v = MOVHZreg x
  ```
  **假设的输入与输出:**
  输入：一个 `MOVWZreg` 指令，其源操作数是一个 `MOVHZreg` 指令，表示将一个半字零扩展到更大的寄存器。
  输出：直接使用 `MOVHZreg` 的结果，因为将其零扩展到 32 位再零扩展到 64 位是冗余的。

**7. 优化 `MOVWload` 和 `MOVWreg` (加载字和字寄存器移动):**

这些优化的思路与 `MOVHload` 和 `MOVHreg` 类似，只是操作的数据大小是字 (32 位)。包括合并地址计算、消除冗余的存储-加载、消除冗余的符号/零扩展等。

**8. 优化 `MOVWstore` (存储字):**

* **直接使用寄存器值:** 如果要存储的值来自 `MOVWreg` 或 `MOVWZreg`，则可以直接使用其源寄存器的值。
* **合并地址计算:**  类似于 `MOVHstore`。
* **使用 `MOVWstoreconst`:** 如果要存储的是常量，并且偏移和常量值在一定范围内，可以使用更紧凑的 `MOVWstoreconst` 指令。
* **指令融合 (`STM2`, `STM3`, `STM4`):**  将连续的多个 `MOVWstore` 指令存储到相邻的内存位置合并成 `STM2` (存储 2 个字), `STM3` (存储 3 个字), 或 `STM4` (存储 4 个字) 指令，提高存储效率。
* **使用 `MOVWBRstore` (字反转存储):** 如果要存储的值先进行了字反转 (`MOVWBR`)，可以直接使用 `MOVWBRstore` 指令。
* **示例 (指令融合):**
  ```go
  // 假设的 SSA 输入
  // v1 = MOVWstore [i-4] {s} p w0 mem
  // v = MOVWstore [i] {s} p w1 v1

  // 重写后的 SSA 输出
  // v = STM2 [i-4] {s} p w0 w1 mem
  ```
  **假设的输入与输出:**
  输入：两个连续的 `MOVWstore` 指令，存储到相邻的地址 `p + i - 4` 和 `p + i`。
  输出：使用 `STM2` 指令一次性存储两个字。

**9. 优化 `MULLD` (乘法):**

* **与常量相乘:** 如果乘法的一个操作数是常量，并且该常量可以表示为 32 位有符号整数，则可以使用 `MULLDconst` 指令，该指令接受一个立即数作为乘数。
* **与加载指令结合:** 如果乘法的一个操作数来自一个只被使用一次的 `MOVDload` 指令，则可以使用 `MULLDload` 指令，该指令可以直接从内存中加载并进行乘法运算。
* **示例:**
  ```go
  // 假设的 SSA 输入
  // v1 = MOVDload [off] {sym} ptr mem
  // v = MULLD x v1

  // 重写后的 SSA 输出
  // v = MULLDload [off] {sym} x ptr mem
  ```
  **假设的输入与输出:**
  输入：一个 `MULLD` 指令，其一个操作数是通过 `MOVDload` 从内存加载得到的。
  输出：使用 `MULLDload` 指令，它可以直接从内存加载数据并与另一个操作数 `x` 相乘。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它属于编译器的内部优化阶段。命令行参数通常在编译器的早期阶段被解析和处理，并可能影响到后续的 SSA 生成和优化过程。例如，`-gcflags` 可以传递一些控制优化的标志。

**使用者易犯错的点:**

由于这些是底层的编译器优化规则，Go 语言的使用者通常不需要直接关心这些细节。编译器会自动应用这些优化。因此，使用者不容易在这里犯错。

**总结这部分的功能:**

这部分 `rewriteS390X.go` 代码定义了针对 S390X 架构下半字和字操作的 SSA 重写规则，旨在通过合并地址计算、消除冗余操作、使用更高效的指令（如 `STMn` 和带内存操作数的指令）以及进行指令融合等方式来提高生成代码的性能。这些规则是 Go 编译器进行架构特定优化的重要组成部分。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第8部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
set(OpS390XMOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))
	// result: (MOVHload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))) {
			break
		}
		v.reset(OpS390XMOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVHreg e:(MOVBreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg e:(MOVHreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg e:(MOVWreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg e:(MOVHZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg e:(MOVWZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg x:(MOVHload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVHload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg x:(MOVBZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 1)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBZload || !(!x.Type.IsSigned() || x.Type.Size() > 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg <t> x:(MOVHZload [o] {s} p mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVHload <t> [o] {s} p mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XMOVHZload {
			break
		}
		o := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVHload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(o)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (MOVHreg x:(Arg <t>))
	// cond: t.IsSigned() && t.Size() <= 2
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(t.IsSigned() && t.Size() <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVHreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int16(c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int16(c)))
		return true
	}
	// match: (MOVHreg (ANDWconst [m] x))
	// cond: int16(m) >= 0
	// result: (MOVWZreg (ANDWconst <typ.UInt32> [int32(uint16(m))] x))
	for {
		if v_0.Op != OpS390XANDWconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(int16(m) >= 0) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(int32(uint16(m)))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVHstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVHstore)
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
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVHstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVHstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (MOVDconst [c]) mem)
	// cond: isU12Bit(int64(off)) && ptr.Op != OpSB
	// result: (MOVHstoreconst [makeValAndOff(int32(int16(c)),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(isU12Bit(int64(off)) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int16(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstore [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))
	// result: (MOVHstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%2 == 0 && (off1+off2)%2 == 0))) {
			break
		}
		v.reset(OpS390XMOVHstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVHstore [off] {sym} ptr (Bswap16 val) mem)
	// result: (MOVHBRstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpBswap16 {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVHBRstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreconst [sc] {s} (ADDconst [off] ptr) mem)
	// cond: isU12Bit(sc.Off64()+int64(off))
	// result: (MOVHstoreconst [sc.addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU12Bit(sc.Off64() + int64(off))) {
			break
		}
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHstoreconst [sc] {sym1} (MOVDaddr [off] {sym2} ptr) mem)
	// cond: ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)
	// result: (MOVHstoreconst [sc.addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)) {
			break
		}
		v.reset(OpS390XMOVHstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVHstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHstoreidx [off] {sym} ptr idx (Bswap16 val) mem)
	// result: (MOVHBRstoreidx [off] {sym} ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		if v_2.Op != OpBswap16 {
			break
		}
		val := v_2.Args[0]
		mem := v_3
		v.reset(OpS390XMOVHBRstoreidx)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWBR(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (MOVWBR x:(MOVWZload [off] {sym} ptr mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVWZreg (MOVWBRload [off] {sym} ptr mem))
	for {
		x := v_0
		if x.Op != OpS390XMOVWZload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVWZreg, typ.UInt64)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpS390XMOVWBRload, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg2(ptr, mem)
		v0.AddArg(v1)
		return true
	}
	// match: (MOVWBR x:(MOVWZloadidx [off] {sym} ptr idx mem))
	// cond: x.Uses == 1
	// result: @x.Block (MOVWZreg (MOVWBRloadidx [off] {sym} ptr idx mem))
	for {
		x := v_0
		if x.Op != OpS390XMOVWZloadidx {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		if !(x.Uses == 1) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpS390XMOVWZreg, typ.UInt64)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVWBRloadidx, typ.Int32)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg3(ptr, idx, mem)
		v0.AddArg(v1)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWZload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWZload [off] {sym} ptr1 (MOVWstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MOVWZreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XMOVWstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVWZload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVWZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWZload [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))
	// result: (MOVWZload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))) {
			break
		}
		v.reset(OpS390XMOVWZload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWZreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVWZreg e:(MOVBZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg e:(MOVHZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg e:(MOVWreg x))
	// cond: clobberIfDead(e)
	// result: (MOVWZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg e:(MOVWZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVWZreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVWZreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWZreg x:(MOVBZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 1)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBZload || !(!x.Type.IsSigned() || x.Type.Size() > 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVHZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 2)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVHZload || !(!x.Type.IsSigned() || x.Type.Size() > 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg x:(MOVWZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 4)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVWZload || !(!x.Type.IsSigned() || x.Type.Size() > 4) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg <t> x:(MOVWload [o] {s} p mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWZload <t> [o] {s} p mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XMOVWload {
			break
		}
		o := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVWZload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(o)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (MOVWZreg x:(Arg <t>))
	// cond: !t.IsSigned() && t.Size() <= 4
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(!t.IsSigned() && t.Size() <= 4) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWZreg (MOVDconst [c]))
	// result: (MOVDconst [int64(uint32(c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	// match: (MOVWZreg (RISBGZ x {r}))
	// cond: r.OutMerge(0xffffffff) != nil
	// result: (RISBGZ x {*r.OutMerge(0xffffffff)})
	for {
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(r.OutMerge(0xffffffff) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(*r.OutMerge(0xffffffff))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWload [off] {sym} ptr1 (MOVWstore [off] {sym} ptr2 x _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (MOVWreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr1 := v_0
		if v_1.Op != OpS390XMOVWstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVWload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWload [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))
	// result: (MOVWload [off1+off2] {mergeSym(sym1,sym2)} base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))) {
			break
		}
		v.reset(OpS390XMOVWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVWreg e:(MOVBreg x))
	// cond: clobberIfDead(e)
	// result: (MOVBreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVBreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg e:(MOVHreg x))
	// cond: clobberIfDead(e)
	// result: (MOVHreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVHreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg e:(MOVWreg x))
	// cond: clobberIfDead(e)
	// result: (MOVWreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg e:(MOVWZreg x))
	// cond: clobberIfDead(e)
	// result: (MOVWreg x)
	for {
		e := v_0
		if e.Op != OpS390XMOVWZreg {
			break
		}
		x := e.Args[0]
		if !(clobberIfDead(e)) {
			break
		}
		v.reset(OpS390XMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVHload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVHload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVWload _ _))
	// cond: (x.Type.IsSigned() || x.Type.Size() == 8)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVWload || !(x.Type.IsSigned() || x.Type.Size() == 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVBZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 1)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVBZload || !(!x.Type.IsSigned() || x.Type.Size() > 1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg x:(MOVHZload _ _))
	// cond: (!x.Type.IsSigned() || x.Type.Size() > 2)
	// result: x
	for {
		x := v_0
		if x.Op != OpS390XMOVHZload || !(!x.Type.IsSigned() || x.Type.Size() > 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg <t> x:(MOVWZload [o] {s} p mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVWload <t> [o] {s} p mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpS390XMOVWZload {
			break
		}
		o := auxIntToInt32(x.AuxInt)
		s := auxToSym(x.Aux)
		mem := x.Args[1]
		p := x.Args[0]
		if !(x.Uses == 1 && clobber(x)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVWload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(o)
		v0.Aux = symToAux(s)
		v0.AddArg2(p, mem)
		return true
	}
	// match: (MOVWreg x:(Arg <t>))
	// cond: t.IsSigned() && t.Size() <= 4
	// result: x
	for {
		x := v_0
		if x.Op != OpArg {
			break
		}
		t := x.Type
		if !(t.IsSigned() && t.Size() <= 4) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWreg (MOVDconst [c]))
	// result: (MOVDconst [int64(int32(c))])
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(c)))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVWZreg x) mem)
	// result: (MOVWstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpS390XMOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is20Bit(int64(off1)+int64(off2))
	// result: (MOVWstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is20Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpS390XMOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr (MOVDconst [c]) mem)
	// cond: is16Bit(c) && isU12Bit(int64(off)) && ptr.Op != OpSB
	// result: (MOVWstoreconst [makeValAndOff(int32(c),off)] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is16Bit(c) && isU12Bit(int64(off)) && ptr.Op != OpSB) {
			break
		}
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstore [off1] {sym1} (MOVDaddr <t> [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))
	// result: (MOVWstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		t := v_0.Type
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || (t.IsPtr() && t.Elem().Alignment()%4 == 0 && (off1+off2)%4 == 0))) {
			break
		}
		v.reset(OpS390XMOVWstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (MOVWstore [i] {s} p w1 x:(MOVWstore [i-4] {s} p w0 mem))
	// cond: p.Op != OpSB && x.Uses == 1 && is20Bit(int64(i)-4) && setPos(v, x.Pos) && clobber(x)
	// result: (STM2 [i-4] {s} p w0 w1 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w1 := v_1
		x := v_2
		if x.Op != OpS390XMOVWstore || auxIntToInt32(x.AuxInt) != i-4 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[2]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		if !(p.Op != OpSB && x.Uses == 1 && is20Bit(int64(i)-4) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTM2)
		v.AuxInt = int32ToAuxInt(i - 4)
		v.Aux = symToAux(s)
		v.AddArg4(p, w0, w1, mem)
		return true
	}
	// match: (MOVWstore [i] {s} p w2 x:(STM2 [i-8] {s} p w0 w1 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-8) && setPos(v, x.Pos) && clobber(x)
	// result: (STM3 [i-8] {s} p w0 w1 w2 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w2 := v_1
		x := v_2
		if x.Op != OpS390XSTM2 || auxIntToInt32(x.AuxInt) != i-8 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[3]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		w1 := x.Args[2]
		if !(x.Uses == 1 && is20Bit(int64(i)-8) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTM3)
		v.AuxInt = int32ToAuxInt(i - 8)
		v.Aux = symToAux(s)
		v.AddArg5(p, w0, w1, w2, mem)
		return true
	}
	// match: (MOVWstore [i] {s} p w3 x:(STM3 [i-12] {s} p w0 w1 w2 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-12) && setPos(v, x.Pos) && clobber(x)
	// result: (STM4 [i-12] {s} p w0 w1 w2 w3 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w3 := v_1
		x := v_2
		if x.Op != OpS390XSTM3 || auxIntToInt32(x.AuxInt) != i-12 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[4]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		w1 := x.Args[2]
		w2 := x.Args[3]
		if !(x.Uses == 1 && is20Bit(int64(i)-12) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTM4)
		v.AuxInt = int32ToAuxInt(i - 12)
		v.Aux = symToAux(s)
		v.AddArg6(p, w0, w1, w2, w3, mem)
		return true
	}
	// match: (MOVWstore [off] {sym} ptr r:(MOVWBR x) mem)
	// cond: r.Uses == 1
	// result: (MOVWBRstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		r := v_1
		if r.Op != OpS390XMOVWBR {
			break
		}
		x := r.Args[0]
		mem := v_2
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpS390XMOVWBRstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWstoreconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreconst [sc] {s} (ADDconst [off] ptr) mem)
	// cond: isU12Bit(sc.Off64()+int64(off))
	// result: (MOVWstoreconst [sc.addOffset32(off)] {s} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != OpS390XADDconst {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(isU12Bit(sc.Off64() + int64(off))) {
			break
		}
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVWstoreconst [sc] {sym1} (MOVDaddr [off] {sym2} ptr) mem)
	// cond: ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)
	// result: (MOVWstoreconst [sc.addOffset32(off)] {mergeSym(sym1, sym2)} ptr mem)
	for {
		sc := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpS390XMOVDaddr {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(ptr.Op != OpSB && canMergeSym(sym1, sym2) && sc.canAdd32(off)) {
			break
		}
		v.reset(OpS390XMOVWstoreconst)
		v.AuxInt = valAndOffToAuxInt(sc.addOffset32(off))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMOVWstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVWstoreidx [off] {sym} ptr idx r:(MOVWBR x) mem)
	// cond: r.Uses == 1
	// result: (MOVWBRstoreidx [off] {sym} ptr idx x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		r := v_2
		if r.Op != OpS390XMOVWBR {
			break
		}
		x := r.Args[0]
		mem := v_3
		if !(r.Uses == 1) {
			break
		}
		v.reset(OpS390XMOVWBRstoreidx)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg4(ptr, idx, x, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMULLD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MULLD x (MOVDconst [c]))
	// cond: is32Bit(c)
	// result: (MULLDconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpS390XMULLDconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (MULLD <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (MULLDload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVDload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XMULLDload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XMULLDconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MULLDconst <t> x [c])
	// cond: isPowerOfTwo(c&(c-1))
	// result: (ADD (SLDconst <t> x [uint8(log32(c&(c-1)))]) (SLDconst <t> x [uint8(log32(c&^(c-1)))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c & (c - 1))) {
			break
		}
		v.reset(OpS390XADD)
		v0 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(c & (c - 1))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(c &^ (c - 1))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLDconst <t> x [c])
	// cond: isPowerOfTwo(c+(c&^(c-1)))
	// result: (SUB (SLDconst <t> x [uint8(log32(c+(c&^(c-1))))]) (SLDconst <t> x [uint8(log32(c&^(c-1)))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(c + (c &^ (c - 1)))) {
			break
		}
		v.reset(OpS390XSUB)
		v0 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(c + (c &^ (c - 1)))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(c &^ (c - 1))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLDconst <t> x [c])
	// cond: isPowerOfTwo(-c+(-c&^(-c-1)))
	// result: (SUB (SLDconst <t> x [uint8(log32(-c&^(-c-1)))]) (SLDconst <t> x [uint8(log32(-c+(-c&^(-c-1))))]))
	for {
		t := v.Type
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(isPowerOfTwo(-c + (-c &^ (-c - 1)))) {
			break
		}
		v.reset(OpS390XSUB)
		v0 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v0.AuxInt = uint8ToAuxInt(uint8(log32(-c &^ (-c - 1))))
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XSLDconst, t)
		v1.AuxInt = uint8ToAuxInt(uint8(log32(-c + (-c &^ (-c - 1)))))
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (MULLDconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c)*d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(c) * d)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XMULLDload(v *Value) bool {
	v_2
```