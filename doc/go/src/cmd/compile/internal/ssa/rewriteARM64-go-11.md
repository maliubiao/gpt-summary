Response:
My goal is to analyze the provided Go code snippet and extract its functionality, identify the Go language features it implements, provide illustrative Go code examples, discuss potential command-line arguments, highlight common user errors (if any), and summarize its purpose within the larger context of the `rewriteARM64.go` file.

**Thinking Process:**

1. **Overall Structure:** The code consists of several functions, each named `rewriteValueARM64_OpARM64...`. This naming convention strongly suggests that these functions are part of a rewrite system for ARM64 assembly instructions (`OpARM64`). The "rewrite" aspect implies that these functions aim to simplify or optimize sequences of ARM64 instructions.

2. **Individual Function Analysis:**  I'll examine each function separately to understand its specific role. Each function takes a `*Value` as input, which likely represents a node in an intermediate representation (IR) of the Go code. The functions return a boolean, indicating whether a rewrite rule was applied.

3. **Pattern Matching and Rewriting:**  The core logic within each function involves pattern matching. They check if the input `Value` matches a specific structure of ARM64 operations. If a match is found, the code then rewrites the `Value` (and potentially creates new `Value` nodes) to a more efficient or canonical form.

4. **Key Operations:** I'll focus on identifying the ARM64 instructions being handled (e.g., `OR`, `SRA`, `SLL`, `ROR`, `REV`, `SUB`, `STP`). The code uses constants (`MOVDconst`), shifts (`shiftLL`, `shiftRL`, `shiftRO`), and bitfield manipulations (`BFI`, `BFXIL`, `SBFX`, `SBFIZ`, `UBFIZ`, `UBFX`).

5. **Go Language Feature Identification:**  The code appears to be implementing optimizations or lowering for various Go language constructs that eventually translate to these ARM64 instructions. I'll need to infer the higher-level Go features based on the transformations being performed. For instance, `ORshiftRL` might relate to bitwise OR operations combined with right shifts.

6. **Code Examples:**  For each identified Go feature, I'll create a simple Go code snippet that would likely result in the ARM64 instruction patterns being matched by the rewrite rules. I'll also provide the assumed input and output of the rewrite function.

7. **Command-Line Arguments:** Since this code is part of the Go compiler's backend, command-line arguments would primarily affect the overall compilation process (e.g., target architecture, optimization levels). I'll look for hints within the code about specific flags (like `config.ctxt.Flag_dynlink`).

8. **Common User Errors:**  Given the low-level nature of this code, direct user errors are less likely. However, I can think about scenarios where incorrect assumptions about bitwise operations or shifts might lead to unexpected behavior if these rewrites weren't in place.

9. **Summarization:** Finally, I'll synthesize the information gathered from analyzing the individual functions to provide a concise summary of the overall functionality of this part of `rewriteARM64.go`. I'll also note that this is part 12 of 20, suggesting that the entire file handles a comprehensive set of ARM64 instruction rewrites.

**Self-Correction/Refinement:**

* **Initial Thought:**  Maybe this is directly related to specific Go standard library functions.
* **Correction:** While that's possible, the focus on low-level ARM64 instructions points more towards the compiler's optimization and code generation phases.

* **Initial Thought:** The `auxIntToInt64` and `int64ToAuxInt` functions are likely for converting between different representations of immediate values in the IR.
* **Confirmation:**  This is a standard pattern in compiler IRs, where immediate values might need to be stored and manipulated in a specific format.

* **Initial Thought:**  The "match" comments indicate the pattern being searched for, and the "result" comment shows the transformation being applied.
* **Confirmation:**  This is a common way to document rewrite rules in compiler code.

By following these steps and constantly refining my understanding based on the code's structure and logic, I can arrive at a comprehensive and accurate answer.
这是 `go/src/cmd/compile/internal/ssa/rewriteARM64.go` 文件的一部分，主要负责针对 ARM64 架构的 SSA（Static Single Assignment）中间表示进行优化的重写规则。

**功能归纳（基于提供的代码片段）：**

这部分代码主要定义了针对 ARM64 指令的多种重写规则，旨在将一些特定的指令模式转换为更简洁或更高效的指令序列。这些规则主要针对位运算（OR、AND、位移等）和一些算术运算（SUB）。

**具体功能列举：**

1. **`rewriteValueARM64_OpARM64ORshiftRA`:**
   - 将 `ORshiftRA` 指令与常量进行匹配，并将其转换为 `ORconst` 和 `SRAconst` 的组合。
   - 识别 `ORshiftRA` 中操作数相同的情况，直接使用移位操作的结果。

2. **`rewriteValueARM64_OpARM64ORshiftRL`:**
   - 将 `ORshiftRL` 指令与常量进行匹配，并将其转换为 `ORconst` 和 `SRLconst` 的组合。
   - 识别 `ORshiftRL` 中操作数相同的情况，直接使用移位操作的结果。
   - 针对特定的 `ORshiftRL` 模式（与 `ANDconst` 和 `SLLconst` 结合），转换为更底层的位域操作指令 `BFI` 和 `BFXIL`。

3. **`rewriteValueARM64_OpARM64ORshiftRO`:**
   - 将 `ORshiftRO` 指令与常量进行匹配，并将其转换为 `ORconst` 和 `RORconst` 的组合。
   - 识别 `ORshiftRO` 中操作数相同的情况，直接使用移位操作的结果。

4. **`rewriteValueARM64_OpARM64REV` 和 `rewriteValueARM64_OpARM64REVW`:**
   - 识别连续的 `REV` 或 `REVW` 指令，并将其优化为无操作。

5. **`rewriteValueARM64_OpARM64ROR` 和 `rewriteValueARM64_OpARM64RORW`:**
   - 将 `ROR` 和 `RORW` 指令与常量移位量进行匹配，转换为 `RORconst` 和 `RORWconst` 指令。

6. **`rewriteValueARM64_OpARM64SBCSflags`:**
   - 针对 `SBCSflags` 指令的一些特定模式进行优化，例如当进位输入来自特定的 `NEG` 运算或常量 0 时，可以简化为 `SUBSflags` 或直接使用进位标志。

7. **`rewriteValueARM64_OpARM64SBFX`:**
   - 针对 `SBFX` (Signed Bitfield Extract) 指令，如果其输入是 `SLLconst`，且该 `SLLconst` 只被使用一次，则尝试合并这两个操作，直接提取需要的位域。

8. **`rewriteValueARM64_OpARM64SLL`:**
   - 将 `SLL` 指令与常量移位量进行匹配，转换为 `SLLconst` 指令。
   - 识别 `SLL` 指令的移位量是 `ANDconst [63]` 的结果，直接使用 `SLL` 指令。

9. **`rewriteValueARM64_OpARM64SLLconst`:**
   - 将 `SLLconst` 指令与常量进行匹配，直接计算结果。
   - 识别特定的 `SLLconst` 模式，例如与 `SRLconst` 互补的情况，转换为 `ANDconst`。
   - 针对将窄位寄存器移动到通用寄存器后进行左移的情况，转换为位域插入清零指令 (`SBFIZ` 或 `UBFIZ`)。
   - 识别 `SLLconst` 与 `ANDconst` 或 `UBFIZ` 结合的模式，合并为单个位域操作指令。

10. **`rewriteValueARM64_OpARM64SRA`:**
    - 将 `SRA` 指令与常量移位量进行匹配，转换为 `SRAconst` 指令。
    - 识别 `SRA` 指令的移位量是 `ANDconst [63]` 的结果，直接使用 `SRA` 指令。

11. **`rewriteValueARM64_OpARM64SRAconst`:**
    - 将 `SRAconst` 指令与常量进行匹配，直接计算结果。
    - 识别 `SRAconst` 与 `SLLconst` 结合的模式，转换为位域操作指令 (`SBFIZ` 或 `SBFX`)。
    - 针对窄位寄存器的算术右移，转换为位域提取指令 `SBFX`。
    - 识别 `SRAconst` 与 `SBFIZ` 结合的模式，合并为单个 `SBFIZ` 或 `SBFX` 指令。

12. **`rewriteValueARM64_OpARM64SRL`:**
    - 将 `SRL` 指令与常量移位量进行匹配，转换为 `SRLconst` 指令。
    - 识别 `SRL` 指令的移位量是 `ANDconst [63]` 的结果，直接使用 `SRL` 指令。

13. **`rewriteValueARM64_OpARM64SRLconst`:**
    - 将 `SRLconst` 指令与常量进行匹配，直接计算结果。
    - 识别特定的 `SRLconst` 模式，例如与 `SLLconst` 互补的情况，转换为 `ANDconst`。
    - 针对窄位无符号寄存器的逻辑右移，如果移位量超出窄位寄存器大小，则结果为 0。否则，转换为位域操作指令 (`UBFIZ` 或 `UBFX`)。
    - 识别 `SRLconst` 与 `ANDconst` 或 `UBFX`/`UBFIZ` 结合的模式，合并为单个位域操作指令。

14. **`rewriteValueARM64_OpARM64STP`:**
    - 优化 `STP` (Store Pair) 指令的地址计算，如果地址是基于常量偏移的加法或地址加载，并且偏移量可以合并，则进行合并。
    - 如果要存储的值是两个零常量，则将其转换为 `MOVQstorezero` 指令。

15. **`rewriteValueARM64_OpARM64SUB`:**
    - 将 `SUB` 指令与常量进行匹配，转换为 `SUBconst` 指令。
    - 识别 `SUB` 指令与乘法指令 (`MUL`, `MULW`, `MNEG`, `MNEGW`) 结合的模式，转换为融合乘加/减指令 (`MSUB`, `MADD`, `MSUBW`, `MADDW`)。
    - 识别 `SUB` 指令与带有常量偏移的乘法指令结合的模式，将常量偏移提取出来。
    - 识别 `SUB` 指令的两个操作数相同的情况，结果直接为零。
    - 针对嵌套的 `SUB` 指令进行重组，可能提高后续优化的机会。
    - 识别 `SUB` 指令的第二个操作数是移位常量的情况，转换为带移位的 `SUBshiftLL`、`SUBshiftRL` 或 `SUBshiftRA` 指令。

16. **`rewriteValueARM64_OpARM64SUBconst`:**
    - 将 `SUBconst` 指令与常量 0 进行匹配，优化为无操作。
    - 将 `SUBconst` 指令与常量进行匹配，直接计算结果。
    - 识别连续的 `SUBconst` 和 `ADDconst` 指令，进行常量合并。

17. **`rewriteValueARM64_OpARM64SUBshiftLL`:**
    - 将 `SUBshiftLL` 指令的移位量是常量的情况，如果移位操作数是常量，则直接计算结果。

**Go 语言功能实现推断与代码示例：**

这些重写规则主要针对底层的位运算和算术运算的优化。 很难直接对应到某个特定的高级 Go 语言功能，因为这些优化是在编译器的后端进行的。 但是，可以推断出它们会影响到所有涉及到这些基本操作的 Go 代码。

**示例 1: `ORshiftRL` 优化**

假设有以下 Go 代码：

```go
package main

func main() {
	x := uint64(0b1010)
	y := uint64(0b0101)
	shift := uint64(2)
	result := (x << shift) | (y >> shift)
	println(result)
}
```

在编译到 ARM64 架构时，`y >> shift` 可能会被表示为 `OpARM64SRL`，而 `(x << shift) | ...`  在某些情况下可能会与 `OpARM64ANDconst` 结合，形成 `OpARM64ORshiftRL` 规则匹配的模式。

**假设的 SSA 输入 (对于 `ORshiftRL` 的一个匹配)：**

```
v1 = Const64<uint64>(...) // 代表 x << shift 的结果
v2 = SRLconst <uint64> v_y [2] // 代表 y >> shift
v3 = ORshiftRL [2] v1 v_y
```

**假设的 SSA 输出 (应用 `ORshiftRL` 规则后)：**

如果匹配了 `ORshiftRL [rc] (ANDconst [ac] y) (SLLconst [lc] x)` 这样的规则，可能会被转换为 `BFXIL` 指令。

**示例 2: `STP` 优化**

假设有以下 Go 代码：

```go
package main

func main() {
	var arr [2]int64
	val1 := int64(10)
	val2 := int64(20)
	arr[0] = val1
	arr[1] = val2
	println(arr[0], arr[1])
}
```

在将 `val1` 和 `val2` 存储到数组 `arr` 中时，编译器可能会生成 `STP` 指令。

**假设的 SSA 输入 (对于 `STP` 优化)：**

```
v1 = LocalAddr arr
v2 = MOVD val1
v3 = MOVD val2
v4 = StorePair [0] v1 v2 v3 mem
```

**假设的 SSA 输出 (应用 `STP` 地址计算优化后)：**

如果地址计算可以合并，例如 `v1` 是一个 `ADDconst` 操作，则偏移量会被合并到 `STP` 指令中。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。 命令行参数会影响到编译器的整体行为，包括是否启用某些优化。 例如，`-gcflags="-N"` 可以禁用优化，从而避免这些重写规则的生效。  `config.ctxt.Flag_dynlink` 标志可能与动态链接有关，某些优化可能在动态链接的情况下被禁用。

**使用者易犯错的点：**

由于这是编译器后端的代码，普通 Go 语言使用者不会直接与之交互，因此不存在使用者易犯错的点。 这里的“使用者”指的是 Go 编译器的开发者或者需要深入理解 Go 编译器行为的人。

**总结:**

这段 `rewriteARM64.go` 代码是 Go 编译器中针对 ARM64 架构进行 SSA 优化的重要组成部分。 它定义了一系列模式匹配和重写规则，用于将一些常见的指令序列转换为更高效的指令，从而提升最终生成代码的性能。 这部分主要关注位运算、算术运算以及内存存储操作的优化。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第12部分，共20部分，请归纳一下它的功能

"""
!= OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftRA y:(SRAconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpARM64SRAconst || auxIntToInt64(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRL (MOVDconst [c]) x [d])
	// result: (ORconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRL x (MOVDconst [c]) [d])
	// result: (ORconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftRL y:(SRLconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpARM64SRLconst || auxIntToInt64(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (ORshiftRL [rc] (ANDconst [ac] x) (SLLconst [lc] y))
	// cond: lc > rc && ac == ^((1<<uint(64-lc)-1) << uint64(lc-rc))
	// result: (BFI [armBFAuxInt(lc-rc, 64-lc)] x y)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		ac := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if v_1.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_1.AuxInt)
		y := v_1.Args[0]
		if !(lc > rc && ac == ^((1<<uint(64-lc)-1)<<uint64(lc-rc))) {
			break
		}
		v.reset(OpARM64BFI)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc-rc, 64-lc))
		v.AddArg2(x, y)
		return true
	}
	// match: (ORshiftRL [rc] (ANDconst [ac] y) (SLLconst [lc] x))
	// cond: lc < rc && ac == ^((1<<uint(64-rc)-1))
	// result: (BFXIL [armBFAuxInt(rc-lc, 64-rc)] y x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		ac := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if v_1.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_1.AuxInt)
		x := v_1.Args[0]
		if !(lc < rc && ac == ^(1<<uint(64-rc)-1)) {
			break
		}
		v.reset(OpARM64BFXIL)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc-lc, 64-rc))
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ORshiftRO(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRO (MOVDconst [c]) x [d])
	// result: (ORconst [c] (RORconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64RORconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRO x (MOVDconst [c]) [d])
	// result: (ORconst x [rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64ORconst)
		v.AuxInt = int64ToAuxInt(rotateRight64(c, d))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftRO y:(RORconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if y.Op != OpARM64RORconst || auxIntToInt64(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64REV(v *Value) bool {
	v_0 := v.Args[0]
	// match: (REV (REV p))
	// result: p
	for {
		if v_0.Op != OpARM64REV {
			break
		}
		p := v_0.Args[0]
		v.copyOf(p)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64REVW(v *Value) bool {
	v_0 := v.Args[0]
	// match: (REVW (REVW p))
	// result: p
	for {
		if v_0.Op != OpARM64REVW {
			break
		}
		p := v_0.Args[0]
		v.copyOf(p)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64ROR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ROR x (MOVDconst [c]))
	// result: (RORconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64RORconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64RORW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RORW x (MOVDconst [c]))
	// result: (RORWconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64RORWconst)
		v.AuxInt = int64ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SBCSflags(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SBCSflags x y (Select1 <types.TypeFlags> (NEGSflags (NEG <typ.UInt64> (NGCzerocarry <typ.UInt64> bo)))))
	// result: (SBCSflags x y bo)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 || v_2.Type != types.TypeFlags {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpARM64NEGSflags {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpARM64NEG || v_2_0_0.Type != typ.UInt64 {
			break
		}
		v_2_0_0_0 := v_2_0_0.Args[0]
		if v_2_0_0_0.Op != OpARM64NGCzerocarry || v_2_0_0_0.Type != typ.UInt64 {
			break
		}
		bo := v_2_0_0_0.Args[0]
		v.reset(OpARM64SBCSflags)
		v.AddArg3(x, y, bo)
		return true
	}
	// match: (SBCSflags x y (Select1 <types.TypeFlags> (NEGSflags (MOVDconst [0]))))
	// result: (SUBSflags x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 || v_2.Type != types.TypeFlags {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpARM64NEGSflags {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpARM64MOVDconst || auxIntToInt64(v_2_0_0.AuxInt) != 0 {
			break
		}
		v.reset(OpARM64SUBSflags)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SBFX(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SBFX [bfc] s:(SLLconst [sc] x))
	// cond: s.Uses == 1 && sc <= bfc.lsb()
	// result: (SBFX [armBFAuxInt(bfc.lsb() - sc, bfc.width())] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		s := v_0
		if s.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(s.AuxInt)
		x := s.Args[0]
		if !(s.Uses == 1 && sc <= bfc.lsb()) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()-sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (SBFX [bfc] s:(SLLconst [sc] x))
	// cond: s.Uses == 1 && sc > bfc.lsb()
	// result: (SBFIZ [armBFAuxInt(sc - bfc.lsb(), bfc.width() - (sc-bfc.lsb()))] x)
	for {
		bfc := auxIntToArm64BitField(v.AuxInt)
		s := v_0
		if s.Op != OpARM64SLLconst {
			break
		}
		sc := auxIntToInt64(s.AuxInt)
		x := s.Args[0]
		if !(s.Uses == 1 && sc > bfc.lsb()) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc-bfc.lsb(), bfc.width()-(sc-bfc.lsb())))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLL x (MOVDconst [c]))
	// result: (SLLconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SLLconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	// match: (SLL x (ANDconst [63] y))
	// result: (SLL x y)
	for {
		x := v_0
		if v_1.Op != OpARM64ANDconst || auxIntToInt64(v_1.AuxInt) != 63 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpARM64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SLLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLLconst [c] (MOVDconst [d]))
	// result: (MOVDconst [d<<uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(d << uint64(c))
		return true
	}
	// match: (SLLconst [c] (SRLconst [c] x))
	// cond: 0 < c && c < 64
	// result: (ANDconst [^(1<<uint(c)-1)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if !(0 < c && c < 64) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(^(1<<uint(c) - 1))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVWreg x))
	// result: (SBFIZ [armBFAuxInt(lc, min(32, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(32, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVHreg x))
	// result: (SBFIZ [armBFAuxInt(lc, min(16, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(16, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVBreg x))
	// result: (SBFIZ [armBFAuxInt(lc, min(8, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(8, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVWUreg x))
	// result: (UBFIZ [armBFAuxInt(lc, min(32, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWUreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(32, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVHUreg x))
	// result: (UBFIZ [armBFAuxInt(lc, min(16, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHUreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(16, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [lc] (MOVBUreg x))
	// result: (UBFIZ [armBFAuxInt(lc, min(8, 64-lc))] x)
	for {
		lc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBUreg {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc, min(8, 64-lc)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [sc] (ANDconst [ac] x))
	// cond: isARM64BFMask(sc, ac, 0)
	// result: (UBFIZ [armBFAuxInt(sc, arm64BFWidth(ac, 0))] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		ac := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isARM64BFMask(sc, ac, 0)) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc, arm64BFWidth(ac, 0)))
		v.AddArg(x)
		return true
	}
	// match: (SLLconst [sc] (UBFIZ [bfc] x))
	// cond: sc+bfc.width()+bfc.lsb() < 64
	// result: (UBFIZ [armBFAuxInt(bfc.lsb()+sc, bfc.width())] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc+bfc.width()+bfc.lsb() < 64) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()+sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRA x (MOVDconst [c]))
	// result: (SRAconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SRAconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	// match: (SRA x (ANDconst [63] y))
	// result: (SRA x y)
	for {
		x := v_0
		if v_1.Op != OpARM64ANDconst || auxIntToInt64(v_1.AuxInt) != 63 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpARM64SRA)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SRAconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRAconst [c] (MOVDconst [d]))
	// result: (MOVDconst [d>>uint64(c)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(d >> uint64(c))
		return true
	}
	// match: (SRAconst [rc] (SLLconst [lc] x))
	// cond: lc > rc
	// result: (SBFIZ [armBFAuxInt(lc-rc, 64-lc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc > rc) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc-rc, 64-lc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [rc] (SLLconst [lc] x))
	// cond: lc <= rc
	// result: (SBFX [armBFAuxInt(rc-lc, 64-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc <= rc) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc-lc, 64-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [rc] (MOVWreg x))
	// cond: rc < 32
	// result: (SBFX [armBFAuxInt(rc, 32-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 32) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 32-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [rc] (MOVHreg x))
	// cond: rc < 16
	// result: (SBFX [armBFAuxInt(rc, 16-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 16) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 16-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [rc] (MOVBreg x))
	// cond: rc < 8
	// result: (SBFX [armBFAuxInt(rc, 8-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 8) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 8-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [sc] (SBFIZ [bfc] x))
	// cond: sc < bfc.lsb()
	// result: (SBFIZ [armBFAuxInt(bfc.lsb()-sc, bfc.width())] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.lsb()) {
			break
		}
		v.reset(OpARM64SBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()-sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (SRAconst [sc] (SBFIZ [bfc] x))
	// cond: sc >= bfc.lsb() && sc < bfc.lsb()+bfc.width()
	// result: (SBFX [armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc)] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc >= bfc.lsb() && sc < bfc.lsb()+bfc.width()) {
			break
		}
		v.reset(OpARM64SBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRL x (MOVDconst [c]))
	// result: (SRLconst x [c&63])
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SRLconst)
		v.AuxInt = int64ToAuxInt(c & 63)
		v.AddArg(x)
		return true
	}
	// match: (SRL x (ANDconst [63] y))
	// result: (SRL x y)
	for {
		x := v_0
		if v_1.Op != OpARM64ANDconst || auxIntToInt64(v_1.AuxInt) != 63 {
			break
		}
		y := v_1.Args[0]
		v.reset(OpARM64SRL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SRLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRLconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(uint64(d)>>uint64(c))])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(d) >> uint64(c)))
		return true
	}
	// match: (SRLconst [c] (SLLconst [c] x))
	// cond: 0 < c && c < 64
	// result: (ANDconst [1<<uint(64-c)-1] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if !(0 < c && c < 64) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(1<<uint(64-c) - 1)
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (MOVWUreg x))
	// cond: rc >= 32
	// result: (MOVDconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWUreg {
			break
		}
		if !(rc >= 32) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLconst [rc] (MOVHUreg x))
	// cond: rc >= 16
	// result: (MOVDconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHUreg {
			break
		}
		if !(rc >= 16) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLconst [rc] (MOVBUreg x))
	// cond: rc >= 8
	// result: (MOVDconst [0])
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBUreg {
			break
		}
		if !(rc >= 8) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRLconst [rc] (SLLconst [lc] x))
	// cond: lc > rc
	// result: (UBFIZ [armBFAuxInt(lc-rc, 64-lc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc > rc) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(lc-rc, 64-lc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (SLLconst [lc] x))
	// cond: lc < rc
	// result: (UBFX [armBFAuxInt(rc-lc, 64-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(lc < rc) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc-lc, 64-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (MOVWUreg x))
	// cond: rc < 32
	// result: (UBFX [armBFAuxInt(rc, 32-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 32) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 32-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (MOVHUreg x))
	// cond: rc < 16
	// result: (UBFX [armBFAuxInt(rc, 16-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 16) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 16-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [rc] (MOVBUreg x))
	// cond: rc < 8
	// result: (UBFX [armBFAuxInt(rc, 8-rc)] x)
	for {
		rc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBUreg {
			break
		}
		x := v_0.Args[0]
		if !(rc < 8) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(rc, 8-rc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (ANDconst [ac] x))
	// cond: isARM64BFMask(sc, ac, sc)
	// result: (UBFX [armBFAuxInt(sc, arm64BFWidth(ac, sc))] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		ac := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(isARM64BFMask(sc, ac, sc)) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc, arm64BFWidth(ac, sc)))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (UBFX [bfc] x))
	// cond: sc < bfc.width()
	// result: (UBFX [armBFAuxInt(bfc.lsb()+sc, bfc.width()-sc)] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFX {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.width()) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()+sc, bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (UBFIZ [bfc] x))
	// cond: sc == bfc.lsb()
	// result: (ANDconst [1<<uint(bfc.width())-1] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc == bfc.lsb()) {
			break
		}
		v.reset(OpARM64ANDconst)
		v.AuxInt = int64ToAuxInt(1<<uint(bfc.width()) - 1)
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (UBFIZ [bfc] x))
	// cond: sc < bfc.lsb()
	// result: (UBFIZ [armBFAuxInt(bfc.lsb()-sc, bfc.width())] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc < bfc.lsb()) {
			break
		}
		v.reset(OpARM64UBFIZ)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(bfc.lsb()-sc, bfc.width()))
		v.AddArg(x)
		return true
	}
	// match: (SRLconst [sc] (UBFIZ [bfc] x))
	// cond: sc > bfc.lsb() && sc < bfc.lsb()+bfc.width()
	// result: (UBFX [armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc)] x)
	for {
		sc := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64UBFIZ {
			break
		}
		bfc := auxIntToArm64BitField(v_0.AuxInt)
		x := v_0.Args[0]
		if !(sc > bfc.lsb() && sc < bfc.lsb()+bfc.width()) {
			break
		}
		v.reset(OpARM64UBFX)
		v.AuxInt = arm64BitFieldToAuxInt(armBFAuxInt(sc-bfc.lsb(), bfc.lsb()+bfc.width()-sc))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64STP(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (STP [off1] {sym} (ADDconst [off2] ptr) val1 val2 mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (STP [off1+int32(off2)] {sym} ptr val1 val2 mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val1 := v_1
		val2 := v_2
		mem := v_3
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg4(ptr, val1, val2, mem)
		return true
	}
	// match: (STP [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) val1 val2 mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (STP [off1+off2] {mergeSym(sym1,sym2)} ptr val1 val2 mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val1 := v_1
		val2 := v_2
		mem := v_3
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg4(ptr, val1, val2, mem)
		return true
	}
	// match: (STP [off] {sym} ptr (MOVDconst [0]) (MOVDconst [0]) mem)
	// result: (MOVQstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 || v_2.Op != OpARM64MOVDconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpARM64MOVQstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUB x (MOVDconst [c]))
	// result: (SUBconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUB a l:(MUL x y))
	// cond: l.Uses==1 && clobber(l)
	// result: (MSUB a x y)
	for {
		a := v_0
		l := v_1
		if l.Op != OpARM64MUL {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		v.reset(OpARM64MSUB)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUB a l:(MNEG x y))
	// cond: l.Uses==1 && clobber(l)
	// result: (MADD a x y)
	for {
		a := v_0
		l := v_1
		if l.Op != OpARM64MNEG {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		v.reset(OpARM64MADD)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUB a l:(MULW x y))
	// cond: v.Type.Size() <= 4 && l.Uses==1 && clobber(l)
	// result: (MSUBW a x y)
	for {
		a := v_0
		l := v_1
		if l.Op != OpARM64MULW {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(v.Type.Size() <= 4 && l.Uses == 1 && clobber(l)) {
			break
		}
		v.reset(OpARM64MSUBW)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUB a l:(MNEGW x y))
	// cond: v.Type.Size() <= 4 && l.Uses==1 && clobber(l)
	// result: (MADDW a x y)
	for {
		a := v_0
		l := v_1
		if l.Op != OpARM64MNEGW {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(v.Type.Size() <= 4 && l.Uses == 1 && clobber(l)) {
			break
		}
		v.reset(OpARM64MADDW)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUB a p:(ADDconst [c] m:(MUL _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (SUBconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MUL || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(ADDconst [c] m:(MULW _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (SUBconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MULW || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(ADDconst [c] m:(MNEG _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (SUBconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MNEG || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(ADDconst [c] m:(MNEGW _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (SUBconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MNEGW || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(SUBconst [c] m:(MUL _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (ADDconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64SUBconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MUL || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(SUBconst [c] m:(MULW _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (ADDconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64SUBconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MULW || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(SUBconst [c] m:(MNEG _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (ADDconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64SUBconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MNEG || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB a p:(SUBconst [c] m:(MNEGW _ _)))
	// cond: p.Uses==1 && m.Uses==1
	// result: (ADDconst [c] (SUB <v.Type> a m))
	for {
		a := v_0
		p := v_1
		if p.Op != OpARM64SUBconst {
			break
		}
		c := auxIntToInt64(p.AuxInt)
		m := p.Args[0]
		if m.Op != OpARM64MNEGW || !(p.Uses == 1 && m.Uses == 1) {
			break
		}
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SUB, v.Type)
		v0.AddArg2(a, m)
		v.AddArg(v0)
		return true
	}
	// match: (SUB x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUB x (SUB y z))
	// result: (SUB (ADD <v.Type> x z) y)
	for {
		x := v_0
		if v_1.Op != OpARM64SUB {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64ADD, v.Type)
		v0.AddArg2(x, z)
		v.AddArg2(v0, y)
		return true
	}
	// match: (SUB (SUB x y) z)
	// result: (SUB x (ADD <y.Type> y z))
	for {
		if v_0.Op != OpARM64SUB {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		z := v_1
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64ADD, y.Type)
		v0.AddArg2(y, z)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SUB x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (SUBshiftLL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64SUBshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (SUB x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (SUBshiftRL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64SUBshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (SUB x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (SUBshiftRA x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64SUBshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBconst [c] (MOVDconst [d]))
	// result: (MOVDconst [d-c])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(d - c)
		return true
	}
	// match: (SUBconst [c] (SUBconst [d] x))
	// result: (ADDconst [-c-d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SUBconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	// match: (SUBconst [c] (ADDconst [d] x))
	// result: (ADDconst [-c+d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(-c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64SUBshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBshiftLL x (MOVDconst [c]) [d])
	// result: (SUBconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64SUBconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
	
"""




```