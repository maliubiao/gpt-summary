Response:
My goal is to analyze the given Go code snippet and extract its functionality, potential Go language feature implementation, and other relevant details, as requested by the user.

**Plan:**

1. **Understand the Context:** The code is part of `go/src/cmd/compile/internal/ssa/rewritePPC64.go`. This indicates it's involved in the SSA (Static Single Assignment) optimization phase of the Go compiler, specifically for the PPC64 architecture. The "rewrite" part suggests it's about transforming or simplifying SSA operations.

2. **Analyze Each Function:**  The code consists of multiple functions, each starting with `rewriteValuePPC64_OpPPC64...`. These functions appear to be specific optimization rules for different PPC64 SSA operations. I need to examine the pattern matching and replacements within each function.

3. **Identify Functionality:**  Each function checks for specific patterns of SSA operations and transforms them into simpler or more efficient equivalents. The core functionality is **SSA rewriting** based on architectural specifics of PPC64.

4. **Infer Go Feature (if applicable):**  The transformations often relate to how Go operations are lowered to machine code on PPC64. I need to look for patterns that suggest a high-level Go construct being optimized. For example, comparisons, bitwise operations, and shifts are common.

5. **Provide Go Code Examples:** Based on the identified functionality, I'll create simple Go code snippets that would likely generate the SSA patterns being optimized. This will illustrate the purpose of the rewrite rules.

6. **Address Assumptions, Inputs, and Outputs:**  For code inference, I'll state the assumed input SSA operations and the resulting output SSA operations after the rewrite.

7. **Handle Command-line Arguments:** The provided snippet doesn't seem to directly involve command-line arguments. I'll explicitly state this.

8. **Identify Common Mistakes:** I'll consider if any of the rewrites might have subtle implications that users could misunderstand, although based on the nature of compiler optimization, user-level mistakes are less directly related to this level of code. I'll focus on potential misinterpretations of the optimization's impact.

9. **Summarize the Functionality (for Part 9):**  Since this is part 9 of 12, I need to summarize the specific transformations happening in this particular snippet. It mainly focuses on simplifying `SETBC` and `SETBCR` operations based on their arguments and flags, as well as optimizing shift operations.

**Detailed Breakdown of the Code:**

* **`rewriteValuePPC64_OpPPC64SETBC` and `rewriteValuePPC64_OpPPC64SETBCR`:** These functions handle the `SETBC` (Set Byte Conditional) and `SETBCR` (Set Byte Conditional Reversed) operations. They seem to be about converting these conditional byte-setting operations into simpler `MOVDconst` (Move Doubleword Constant) operations when the condition is trivially true or false. They also handle cases involving `InvertFlags` and combinations with `CMPconst`, `AND`, `OR`, and `XOR`. The rewrites involving `Select1` suggest these operations are part of a larger comparison or logical operation sequence that generates both a result and flags.

* **`rewriteValuePPC64_OpPPC64SLD`, `rewriteValuePPC64_OpPPC64SLDconst`, `rewriteValuePPC64_OpPPC64SLW`, `rewriteValuePPC64_OpPPC64SLWconst`:** These deal with left shift operations (`SLD` - Shift Left Doubleword, `SLW` - Shift Left Word) and their constant variants. They optimize shifts by constant amounts, potentially merging shifts with other operations like `SRWconst` and `RLWINM`. The rules involving `MOVBZreg`, `MOVHZreg`, `MOVWZreg`, and `ANDconst` suggest optimizations related to masking and zero-extension before shifting.

* **`rewriteValuePPC64_OpPPC64SRAD`, `rewriteValuePPC64_OpPPC64SRAW`, `rewriteValuePPC64_OpPPC64SRD`, `rewriteValuePPC64_OpPPC64SRW`, `rewriteValuePPC64_OpPPC64SRWconst`:** These handle right shift operations (arithmetic and logical) and their constant variants. Similar optimizations to the left shifts are likely happening here.

* **`rewriteValuePPC64_OpPPC64SUB`, `rewriteValuePPC64_OpPPC64SUBE`, `rewriteValuePPC64_OpPPC64SUBFCconst`:** These handle subtraction operations. Optimizations include converting subtraction by a constant to addition of a negative constant, and simplifying subtraction with constants.

* **`rewriteValuePPC64_OpPPC64XOR`, `rewriteValuePPC64_OpPPC64XORconst`:** These deal with XOR operations, optimizing XORing with constants and simplifying double XORs.

* **`rewriteValuePPC64_OpPanicBounds`:** This function seems related to handling bounds checking during array or slice access. It lowers the generic `PanicBounds` operation to architecture-specific variants (`LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC`) based on the `boundsABI` function, likely related to different calling conventions or ABI requirements for panic handling.

* **`rewriteValuePPC64_OpPopCount16`, `rewriteValuePPC64_OpPopCount32`, `rewriteValuePPC64_OpPopCount8`:** These functions optimize `PopCount` operations for different integer sizes by using specific PPC64 instructions (`POPCNTW`, `POPCNTB`) after appropriate zero-extension or move operations.

* **`rewriteValuePPC64_OpPrefetchCache`, `rewriteValuePPC64_OpPrefetchCacheStreamed`:** These functions lower the generic prefetch operations to the PPC64-specific `DCBT` (Data Cache Block Touch) instruction with different hints.

* **`rewriteValuePPC64_OpRotateLeft16`, `rewriteValuePPC64_OpRotateLeft8`:** These handle left rotation operations by breaking them down into left and right shifts followed by an OR.

* **`rewriteValuePPC64_OpRsh16Ux16`, `rewriteValuePPC64_OpRsh16Ux32`, `rewriteValuePPC64_OpRsh16Ux64`:** These handle unsigned right shift operations for 16-bit integers with different shift operand sizes. They optimize based on whether the shift amount is bounded and use `ISEL` (Select) instruction for conditional execution.

**Self-Correction/Refinement:** Initially, I focused on inferring a single, overarching Go feature. However, the code snippet shows optimizations for *many* low-level operations. It's more accurate to say it implements architecture-specific optimizations for various Go language constructs as they are lowered to PPC64 assembly. The key is the **transformation of SSA operations**, not the direct implementation of a single high-level feature. Also, while I considered potential user errors, it's more relevant in this context to highlight the *compiler's* role in ensuring correct and efficient execution, rather than user-level coding mistakes.

By following this thought process, I can generate a comprehensive and accurate answer to the user's request.
这是 `go/src/cmd/compile/internal/ssa/rewritePPC64.go` 文件中关于 PPC64 架构代码优化的第 9 部分。  这部分代码主要定义了一系列针对 PPC64 特定 SSA 操作的重写规则（rewrite rules）。这些规则的目标是通过模式匹配，将一些低效或者可以进一步简化的 SSA 操作转化为更高效的等价形式。

**功能归纳:**

这部分代码主要功能是针对 PPC64 架构的 SSA 中 `SETBC`、`SETBCR`、各种移位操作（`SLD`、`SLW`、`SRAD`、`SRAW`、`SRD`、`SRW`），以及算术和逻辑运算（`SUB`、`SUBE`、`XOR`）和一些特殊操作（`PanicBounds`，`PopCount`，`PrefetchCache`）进行优化。具体来说，它做了以下几件事：

1. **简化条件设置指令 (`SETBC`, `SETBCR`)**:  根据条件标志的状态和 `AuxInt` 的值，将条件设置指令替换为直接加载常量 (`MOVDconst`)，或者在 `InvertFlags` 的情况下进行转换。还包括一些与比较指令 (`CMPconst`) 结合的优化，以及与位运算 (`AND`, `OR`, `XOR`) 结合的优化，特别是当这些位运算的结果只被使用一次时，会尝试将其融合到条件设置指令中。

2. **优化移位指令 (`SLD`, `SLW`, `SRAD`, `SRAW`, `SRD`, `SRW`)**:
   - 将移位量为常量的移位指令替换为常量移位指令 (`SLDconst`, `SLWconst`, `SRADconst`, `SRAWconst`, `SRDconst`, `SRWconst`)。
   - 尝试合并连续的移位操作，例如 `SLDconst` 与 `SRWconst` 或 `RLWINM` 的合并。
   - 针对特定的移位和零扩展/符号扩展组合进行优化，例如将 `SLDconst` 与 `MOVBZreg` 等组合替换为 `CLRLSLDI`。
   - 对常量移位指令进行进一步优化，例如 `SRWconst` 与 `ANDconst` 结合时，如果掩码和移位量满足特定条件，可以直接替换为加载常量 0 或者 `RLWINM` 指令。

3. **优化算术和逻辑运算 (`SUB`, `SUBE`, `XOR`)**:
   - 将减去常量转换为加上负常量的加法 (`ADDconst`)。
   - 将常量减去一个值转换为带借位的减法指令 (`SUBFCconst`)。
   - 优化异或操作，例如常量与常量异或直接计算结果，与常量异或转换为 `XORconst` 指令，以及连续的 `XORconst` 指令合并。

4. **优化边界检查 (`PanicBounds`)**:  根据 `boundsABI` 的返回值，将通用的 `PanicBounds` 操作替换为特定的架构相关的边界检查指令 (`LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC`)。这可能与不同的 ABI 调用约定有关。

5. **优化位计数操作 (`PopCount16`, `PopCount32`, `PopCount8`)**:  使用 PPC64 特有的位计数指令 (`POPCNTW`, `POPCNTB`) 来实现位计数，并确保输入的参数类型正确。

6. **优化缓存预取 (`PrefetchCache`, `PrefetchCacheStreamed`)**: 将通用的缓存预取操作替换为 PPC64 的 `DCBT` 指令，并根据是否是流式预取设置不同的 `AuxInt` 值。

7. **优化循环移位 (`RotateLeft16`, `RotateLeft8`)**: 将循环左移操作拆分成左移和右移，然后进行或运算。

8. **优化无符号右移 (`Rsh16Ux16`, `Rsh16Ux32`, `Rsh16Ux64`)**:  在移位量确定有界的情况下，使用 `SRD` 指令进行优化。在一般情况下，使用 `ISEL` 指令结合条件比较来实现。

**Go 语言功能实现推断及代码示例:**

这部分代码主要关注的是底层指令的优化，它并不直接对应于某个单一的、高层次的 Go 语言功能。相反，它作用于 Go 代码编译过程的中间表示（SSA），目的是为了提升最终生成机器码的效率。  这些优化规则影响着各种 Go 语言结构在 PPC64 架构上的性能，例如：

* **条件语句 (if, else, switch):**  `SETBC` 和 `SETBCR` 的优化直接影响条件分支的效率。
* **位运算 (&, |, ^, <<, >>):**  各种移位和逻辑运算的优化提升了位操作的性能。
* **算术运算 (+, -, *):** `SUB` 和 `XOR` 的优化对算术运算有帮助。
* **数组和切片访问:** `PanicBounds` 的优化关系到边界检查的效率。
* **runtime 包中的某些函数:** `PopCount` 的优化可能被 `bits` 包中的函数使用。
* **sync/atomic 包中的某些操作:** 可能会用到一些位操作和算术操作。

**代码示例 (推断):**

例如，对于 `SETBC` 的一个优化规则：

```go
// match: (SETBC [0] (FlagGT))
// result: (MOVDconst [0])
for {
	if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagGT {
		break
	}
	v.reset(OpPPC64MOVDconst)
	v.AuxInt = int64ToAuxInt(0)
	return true
}
```

这表示如果 `SETBC` 指令的 `AuxInt` 是 0，并且其输入是一个 `FlagGT` 操作（表示前一个比较结果是大于），那么这个 `SETBC` 指令的结果必然是 0。  对应的 Go 代码可能类似于：

```go
package main

import "fmt"

func main() {
	a := 10
	b := 5
	var result int64
	if a > b {
		// 这里可能不会直接生成 SETBC [0]，但类似的比较和条件设置会触发相关优化
		result = 1
	} else {
		result = 0
	}
	fmt.Println(result) // Output: 1
}
```

在编译成 PPC64 汇编的过程中，如果 SSA 生成了符合 `SETBC [0] (FlagGT)` 模式的指令，就会被优化成 `MOVDconst [0]`。

再例如，对于 `SLDconst` 的一个优化规则：

```go
// match: (SLDconst [c] z:(MOVBZreg x))
// cond: c < 8 && z.Uses == 1
// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,56,63,64)] x)
for {
	c := auxIntToInt64(v.AuxInt)
	z := v_0
	if z.Op != OpPPC64MOVBZreg {
		break
	}
	x := z.Args[0]
	if !(c < 8 && z.Uses == 1) {
		break
	}
	v.reset(OpPPC64CLRLSLDI)
	v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 56, 63, 64))
	v.AddArg(x)
	return true
}
```

这表示如果将一个字节零扩展后左移小于 8 位的常量，可以优化为 `CLRLSLDI` 指令。对应的 Go 代码可能类似于：

```go
package main

import "fmt"

func main() {
	var a byte = 0x0F
	shift := 3
	result := int64(a) << shift
	fmt.Printf("%#x\n", result) // Output: 0x78
}
```

在编译过程中，`int64(a)` 可能会生成 `MOVBZreg`，然后进行左移操作，如果移位量是常量且小于 8，则会应用上述优化规则。

**假设的输入与输出 (以 `SETBC` 为例):**

**假设输入 SSA:**

```
v1 = OpPPC64FlagGT  // 假设 v1 表示一个比较操作的结果，标志为 GT (大于)
v2 = OpPPC64SETBC <type:int64> aux:0 arg0:v1
```

**优化后的输出 SSA:**

```
v2 = OpPPC64MOVDconst <type:int64> aux:0
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是在 Go 编译器的内部 SSA 优化阶段执行的，编译器会根据用户提供的 Go 代码和目标架构（这里是 PPC64）生成 SSA 中间表示，然后应用这些重写规则进行优化。命令行参数会影响编译器的整体行为，例如选择目标架构、优化级别等，但 `rewritePPC64.go` 中的代码是对已经生成的 SSA 进行转换。

**使用者易犯错的点:**

由于这是编译器内部的优化规则，普通 Go 语言使用者通常不会直接与这部分代码交互，因此不容易犯错。然而，理解这些优化有助于理解 Go 代码在特定架构上的性能特性。  一些可能需要注意的点是：

* **理解编译器优化:**  开发者不应该过度依赖编译器进行特定的优化。虽然编译器会尽力生成高效的代码，但编写清晰、符合语言习惯的代码仍然很重要。
* **性能测试:**  对于性能敏感的代码，应该进行实际的性能测试，而不是仅仅依赖对编译器优化规则的理解进行推断。

**总结一下它的功能:**

作为 `rewritePPC64.go` 的一部分，这段代码的核心功能是定义了一系列针对 PPC64 架构的 SSA 指令重写规则，旨在将低效或可以简化的指令模式转换为更高效的等价形式。  它涵盖了条件设置、移位操作、算术和逻辑运算、边界检查、位计数和缓存预取等多个方面，是 Go 编译器为 PPC64 架构生成高性能代码的关键组成部分。  这部分是优化流程中的一个环节，通过模式匹配和替换，逐步降低代码的抽象层次，使其更贴近目标机器的指令集。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第9部分，共12部分，请归纳一下它的功能

"""
 [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [0] (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [1] (FlagGT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBC [1] (FlagLT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [1] (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [2] (FlagEQ))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBC [2] (FlagLT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [2] (FlagGT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBC [0] (InvertFlags bool))
	// result: (SETBC [1] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(bool)
		return true
	}
	// match: (SETBC [1] (InvertFlags bool))
	// result: (SETBC [0] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(bool)
		return true
	}
	// match: (SETBC [2] (InvertFlags bool))
	// result: (SETBC [2] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(2)
		v.AddArg(bool)
		return true
	}
	// match: (SETBC [n] (InvertFlags bool))
	// result: (SETBCR [n] bool)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(bool)
		return true
	}
	// match: (SETBC [2] (CMPconst [0] a:(ANDconst [1] _)))
	// result: (XORconst [1] a)
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64ANDconst || auxIntToInt64(a.AuxInt) != 1 {
			break
		}
		v.reset(OpPPC64XORconst)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg(a)
		return true
	}
	// match: (SETBC [2] (CMPconst [0] a:(AND y z)))
	// cond: a.Uses == 1
	// result: (SETBC [2] (Select1 <types.TypeFlags> (ANDCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64AND {
			break
		}
		z := a.Args[1]
		y := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (SETBC [2] (CMPconst [0] o:(OR y z)))
	// cond: o.Uses == 1
	// result: (SETBC [2] (Select1 <types.TypeFlags> (ORCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		o := v_0.Args[0]
		if o.Op != OpPPC64OR {
			break
		}
		z := o.Args[1]
		y := o.Args[0]
		if !(o.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (SETBC [2] (CMPconst [0] a:(XOR y z)))
	// cond: a.Uses == 1
	// result: (SETBC [2] (Select1 <types.TypeFlags> (XORCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64XOR {
			break
		}
		z := a.Args[1]
		y := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SETBCR(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SETBCR [0] (FlagLT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBCR [0] (FlagGT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [0] (FlagEQ))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [1] (FlagGT))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBCR [1] (FlagLT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [1] (FlagEQ))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [2] (FlagEQ))
	// result: (MOVDconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagEQ {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SETBCR [2] (FlagLT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagLT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [2] (FlagGT))
	// result: (MOVDconst [1])
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64FlagGT {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (SETBCR [0] (InvertFlags bool))
	// result: (SETBCR [1] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 0 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(1)
		v.AddArg(bool)
		return true
	}
	// match: (SETBCR [1] (InvertFlags bool))
	// result: (SETBCR [0] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 1 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(bool)
		return true
	}
	// match: (SETBCR [2] (InvertFlags bool))
	// result: (SETBCR [2] bool)
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v.AddArg(bool)
		return true
	}
	// match: (SETBCR [n] (InvertFlags bool))
	// result: (SETBC [n] bool)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpPPC64InvertFlags {
			break
		}
		bool := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(bool)
		return true
	}
	// match: (SETBCR [2] (CMPconst [0] a:(ANDconst [1] _)))
	// result: a
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64ANDconst || auxIntToInt64(a.AuxInt) != 1 {
			break
		}
		v.copyOf(a)
		return true
	}
	// match: (SETBCR [2] (CMPconst [0] a:(AND y z)))
	// cond: a.Uses == 1
	// result: (SETBCR [2] (Select1 <types.TypeFlags> (ANDCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64AND {
			break
		}
		z := a.Args[1]
		y := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (SETBCR [2] (CMPconst [0] o:(OR y z)))
	// cond: o.Uses == 1
	// result: (SETBCR [2] (Select1 <types.TypeFlags> (ORCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		o := v_0.Args[0]
		if o.Op != OpPPC64OR {
			break
		}
		z := o.Args[1]
		y := o.Args[0]
		if !(o.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (SETBCR [2] (CMPconst [0] a:(XOR y z)))
	// cond: a.Uses == 1
	// result: (SETBCR [2] (Select1 <types.TypeFlags> (XORCC y z )))
	for {
		if auxIntToInt32(v.AuxInt) != 2 || v_0.Op != OpPPC64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		a := v_0.Args[0]
		if a.Op != OpPPC64XOR {
			break
		}
		z := a.Args[1]
		y := a.Args[0]
		if !(a.Uses == 1) {
			break
		}
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
		v1.AddArg2(y, z)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SLD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLD x (MOVDconst [c]))
	// result: (SLDconst [c&63 | (c>>6&1*63)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SLDconst)
		v.AuxInt = int64ToAuxInt(c&63 | (c >> 6 & 1 * 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SLDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLDconst [l] (SRWconst [r] x))
	// cond: mergePPC64SldiSrw(l,r) != 0
	// result: (RLWINM [mergePPC64SldiSrw(l,r)] x)
	for {
		l := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64SRWconst {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64SldiSrw(l, r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64SldiSrw(l, r))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [s] (RLWINM [r] y))
	// cond: mergePPC64SldiRlwinm(s,r) != 0
	// result: (RLWINM [mergePPC64SldiRlwinm(s,r)] y)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64RLWINM {
			break
		}
		r := auxIntToInt64(v_0.AuxInt)
		y := v_0.Args[0]
		if !(mergePPC64SldiRlwinm(s, r) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64SldiRlwinm(s, r))
		v.AddArg(y)
		return true
	}
	// match: (SLDconst [c] z:(MOVBZreg x))
	// cond: c < 8 && z.Uses == 1
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,56,63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVBZreg {
			break
		}
		x := z.Args[0]
		if !(c < 8 && z.Uses == 1) {
			break
		}
		v.reset(OpPPC64CLRLSLDI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 56, 63, 64))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [c] z:(MOVHZreg x))
	// cond: c < 16 && z.Uses == 1
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,48,63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVHZreg {
			break
		}
		x := z.Args[0]
		if !(c < 16 && z.Uses == 1) {
			break
		}
		v.reset(OpPPC64CLRLSLDI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 48, 63, 64))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [c] z:(MOVWZreg x))
	// cond: c < 32 && z.Uses == 1
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,32,63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVWZreg {
			break
		}
		x := z.Args[0]
		if !(c < 32 && z.Uses == 1) {
			break
		}
		v.reset(OpPPC64CLRLSLDI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 32, 63, 64))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [c] z:(ANDconst [d] x))
	// cond: z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (64-getPPC64ShiftMaskLength(d))
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,64-getPPC64ShiftMaskLength(d),63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		d := auxIntToInt64(z.AuxInt)
		x := z.Args[0]
		if !(z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (64-getPPC64ShiftMaskLength(d))) {
			break
		}
		v.reset(OpPPC64CLRLSLDI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 64-getPPC64ShiftMaskLength(d), 63, 64))
		v.AddArg(x)
		return true
	}
	// match: (SLDconst [c] z:(AND (MOVDconst [d]) x))
	// cond: z.Uses == 1 && isPPC64ValidShiftMask(d) && c<=(64-getPPC64ShiftMaskLength(d))
	// result: (CLRLSLDI [newPPC64ShiftAuxInt(c,64-getPPC64ShiftMaskLength(d),63,64)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64AND {
			break
		}
		_ = z.Args[1]
		z_0 := z.Args[0]
		z_1 := z.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
			if z_0.Op != OpPPC64MOVDconst {
				continue
			}
			d := auxIntToInt64(z_0.AuxInt)
			x := z_1
			if !(z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (64-getPPC64ShiftMaskLength(d))) {
				continue
			}
			v.reset(OpPPC64CLRLSLDI)
			v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 64-getPPC64ShiftMaskLength(d), 63, 64))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (SLDconst [c] z:(MOVWreg x))
	// cond: c < 32 && buildcfg.GOPPC64 >= 9
	// result: (EXTSWSLconst [c] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVWreg {
			break
		}
		x := z.Args[0]
		if !(c < 32 && buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64EXTSWSLconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SLW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLW x (MOVDconst [c]))
	// result: (SLWconst [c&31 | (c>>5&1*31)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SLWconst)
		v.AuxInt = int64ToAuxInt(c&31 | (c >> 5 & 1 * 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SLWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLWconst [s] (MOVWZreg w))
	// result: (SLWconst [s] w)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64MOVWZreg {
			break
		}
		w := v_0.Args[0]
		v.reset(OpPPC64SLWconst)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg(w)
		return true
	}
	// match: (SLWconst [c] z:(MOVBZreg x))
	// cond: z.Uses == 1 && c < 8
	// result: (CLRLSLWI [newPPC64ShiftAuxInt(c,24,31,32)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVBZreg {
			break
		}
		x := z.Args[0]
		if !(z.Uses == 1 && c < 8) {
			break
		}
		v.reset(OpPPC64CLRLSLWI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 24, 31, 32))
		v.AddArg(x)
		return true
	}
	// match: (SLWconst [c] z:(MOVHZreg x))
	// cond: z.Uses == 1 && c < 16
	// result: (CLRLSLWI [newPPC64ShiftAuxInt(c,16,31,32)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVHZreg {
			break
		}
		x := z.Args[0]
		if !(z.Uses == 1 && c < 16) {
			break
		}
		v.reset(OpPPC64CLRLSLWI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 16, 31, 32))
		v.AddArg(x)
		return true
	}
	// match: (SLWconst [c] z:(ANDconst [d] x))
	// cond: z.Uses == 1 && isPPC64ValidShiftMask(d) && c<=(32-getPPC64ShiftMaskLength(d))
	// result: (CLRLSLWI [newPPC64ShiftAuxInt(c,32-getPPC64ShiftMaskLength(d),31,32)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64ANDconst {
			break
		}
		d := auxIntToInt64(z.AuxInt)
		x := z.Args[0]
		if !(z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (32-getPPC64ShiftMaskLength(d))) {
			break
		}
		v.reset(OpPPC64CLRLSLWI)
		v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 32-getPPC64ShiftMaskLength(d), 31, 32))
		v.AddArg(x)
		return true
	}
	// match: (SLWconst [c] z:(AND (MOVDconst [d]) x))
	// cond: z.Uses == 1 && isPPC64ValidShiftMask(d) && c<=(32-getPPC64ShiftMaskLength(d))
	// result: (CLRLSLWI [newPPC64ShiftAuxInt(c,32-getPPC64ShiftMaskLength(d),31,32)] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64AND {
			break
		}
		_ = z.Args[1]
		z_0 := z.Args[0]
		z_1 := z.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
			if z_0.Op != OpPPC64MOVDconst {
				continue
			}
			d := auxIntToInt64(z_0.AuxInt)
			x := z_1
			if !(z.Uses == 1 && isPPC64ValidShiftMask(d) && c <= (32-getPPC64ShiftMaskLength(d))) {
				continue
			}
			v.reset(OpPPC64CLRLSLWI)
			v.AuxInt = int32ToAuxInt(newPPC64ShiftAuxInt(c, 32-getPPC64ShiftMaskLength(d), 31, 32))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (SLWconst [c] z:(MOVWreg x))
	// cond: c < 32 && buildcfg.GOPPC64 >= 9
	// result: (EXTSWSLconst [c] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		z := v_0
		if z.Op != OpPPC64MOVWreg {
			break
		}
		x := z.Args[0]
		if !(c < 32 && buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64EXTSWSLconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRAD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRAD x (MOVDconst [c]))
	// result: (SRADconst [c&63 | (c>>6&1*63)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(c&63 | (c >> 6 & 1 * 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRAW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRAW x (MOVDconst [c]))
	// result: (SRAWconst [c&31 | (c>>5&1*31)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SRAWconst)
		v.AuxInt = int64ToAuxInt(c&31 | (c >> 5 & 1 * 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRD x (MOVDconst [c]))
	// result: (SRDconst [c&63 | (c>>6&1*63)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SRDconst)
		v.AuxInt = int64ToAuxInt(c&63 | (c >> 6 & 1 * 63))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRW x (MOVDconst [c]))
	// result: (SRWconst [c&31 | (c>>5&1*31)] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpPPC64SRWconst)
		v.AuxInt = int64ToAuxInt(c&31 | (c >> 5 & 1 * 31))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SRWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRWconst (ANDconst [m] x) [s])
	// cond: mergePPC64RShiftMask(m>>uint(s),s,32) == 0
	// result: (MOVDconst [0])
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		if !(mergePPC64RShiftMask(m>>uint(s), s, 32) == 0) {
			break
		}
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRWconst (ANDconst [m] x) [s])
	// cond: mergePPC64AndSrwi(m>>uint(s),s) != 0
	// result: (RLWINM [mergePPC64AndSrwi(m>>uint(s),s)] x)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(mergePPC64AndSrwi(m>>uint(s), s) != 0) {
			break
		}
		v.reset(OpPPC64RLWINM)
		v.AuxInt = int64ToAuxInt(mergePPC64AndSrwi(m>>uint(s), s))
		v.AddArg(x)
		return true
	}
	// match: (SRWconst (AND (MOVDconst [m]) x) [s])
	// cond: mergePPC64RShiftMask(m>>uint(s),s,32) == 0
	// result: (MOVDconst [0])
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64AND {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0_0.AuxInt)
			if !(mergePPC64RShiftMask(m>>uint(s), s, 32) == 0) {
				continue
			}
			v.reset(OpPPC64MOVDconst)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (SRWconst (AND (MOVDconst [m]) x) [s])
	// cond: mergePPC64AndSrwi(m>>uint(s),s) != 0
	// result: (RLWINM [mergePPC64AndSrwi(m>>uint(s),s)] x)
	for {
		s := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64AND {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpPPC64MOVDconst {
				continue
			}
			m := auxIntToInt64(v_0_0.AuxInt)
			x := v_0_1
			if !(mergePPC64AndSrwi(m>>uint(s), s) != 0) {
				continue
			}
			v.reset(OpPPC64RLWINM)
			v.AuxInt = int64ToAuxInt(mergePPC64AndSrwi(m>>uint(s), s))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64SUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUB x (MOVDconst [c]))
	// cond: is32Bit(-c)
	// result: (ADDconst [-c] x)
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(-c)) {
			break
		}
		v.reset(OpPPC64ADDconst)
		v.AuxInt = int64ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (SUB (MOVDconst [c]) x)
	// cond: is32Bit(c)
	// result: (SUBFCconst [c] x)
	for {
		if v_0.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpPPC64SUBFCconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SUBE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBE x y (Select1 <typ.UInt64> (SUBCconst (MOVDconst [0]) [0])))
	// result: (SUBC x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 || v_2.Type != typ.UInt64 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpPPC64SUBCconst || auxIntToInt64(v_2_0.AuxInt) != 0 {
			break
		}
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpPPC64MOVDconst || auxIntToInt64(v_2_0_0.AuxInt) != 0 {
			break
		}
		v.reset(OpPPC64SUBC)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64SUBFCconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBFCconst [c] (NEG x))
	// result: (ADDconst [c] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64NEG {
			break
		}
		x := v_0.Args[0]
		v.reset(OpPPC64ADDconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUBFCconst [c] (SUBFCconst [d] x))
	// cond: is32Bit(c-d)
	// result: (ADDconst [c-d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64SUBFCconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c - d)) {
			break
		}
		v.reset(OpPPC64ADDconst)
		v.AuxInt = int64ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	// match: (SUBFCconst [0] x)
	// result: (NEG x)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.reset(OpPPC64NEG)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPPC64XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c^d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpPPC64MOVDconst)
			v.AuxInt = int64ToAuxInt(c ^ d)
			return true
		}
		break
	}
	// match: (XOR x (MOVDconst [c]))
	// cond: isU32Bit(c)
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpPPC64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isU32Bit(c)) {
				continue
			}
			v.reset(OpPPC64XORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuePPC64_OpPPC64XORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORconst [c] (XORconst [d] x))
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpPPC64XORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpPPC64XORconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	// match: (XORconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (XORconst [1] (SETBCR [n] cmp))
	// result: (SETBC [n] cmp)
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpPPC64SETBCR {
			break
		}
		n := auxIntToInt32(v_0.AuxInt)
		cmp := v_0.Args[0]
		v.reset(OpPPC64SETBC)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(cmp)
		return true
	}
	// match: (XORconst [1] (SETBC [n] cmp))
	// result: (SETBCR [n] cmp)
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpPPC64SETBC {
			break
		}
		n := auxIntToInt32(v_0.AuxInt)
		cmp := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(n)
		v.AddArg(cmp)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPanicBounds(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 0
	// result: (LoweredPanicBoundsA [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 0) {
			break
		}
		v.reset(OpPPC64LoweredPanicBoundsA)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 1
	// result: (LoweredPanicBoundsB [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 1) {
			break
		}
		v.reset(OpPPC64LoweredPanicBoundsB)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 2
	// result: (LoweredPanicBoundsC [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 2) {
			break
		}
		v.reset(OpPPC64LoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpPopCount16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount16 x)
	// result: (POPCNTW (MOVHZreg x))
	for {
		x := v_0
		v.reset(OpPPC64POPCNTW)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpPopCount32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount32 x)
	// result: (POPCNTW (MOVWZreg x))
	for {
		x := v_0
		v.reset(OpPPC64POPCNTW)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpPopCount8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount8 x)
	// result: (POPCNTB (MOVBZreg x))
	for {
		x := v_0
		v.reset(OpPPC64POPCNTB)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpPrefetchCache(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PrefetchCache ptr mem)
	// result: (DCBT ptr mem [0])
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64DCBT)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpPrefetchCacheStreamed(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PrefetchCacheStreamed ptr mem)
	// result: (DCBT ptr mem [16])
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64DCBT)
		v.AuxInt = int64ToAuxInt(16)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVDconst [c]))
	// result: (Or16 (Lsh16x64 <t> x (MOVDconst [c&15])) (Rsh16Ux64 <t> x (MOVDconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v3 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v3.AuxInt = int64ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValuePPC64_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVDconst [c]))
	// result: (Or8 (Lsh8x64 <t> x (MOVDconst [c&7])) (Rsh8Ux64 <t> x (MOVDconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v3 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v3.AuxInt = int64ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValuePPC64_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux16 <t> x y)
	// result: (ISEL [2] (SRD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFF0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 x y)
	// cond: shiftIsBounded(v)
	// result: (SRD (MOVHZreg x) y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SRD)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh16Ux32 <t> x y)
	// result: (ISEL [0] (SRD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPWUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SRD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.
"""




```