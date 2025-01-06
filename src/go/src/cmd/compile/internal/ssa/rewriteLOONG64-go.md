Response: My goal is to summarize the functionality of the provided Go code snippet. Here's my thought process:

1. **Identify the Core Function:** The code defines a function `rewriteValueLOONG64(v *Value) bool`. This function takes a `Value` pointer as input and returns a boolean. The name strongly suggests it's involved in rewriting or modifying the `Value`.

2. **Recognize the `switch` Statement:** The function body contains a large `switch` statement based on `v.Op`. This indicates the function handles different operations (`Op` codes) within the Go compiler's intermediate representation (SSA - Static Single Assignment).

3. **Understand the Rewriting Logic:** Inside each `case`, the code often changes `v.Op` to a different `Op` code (e.g., `v.Op = OpLOONG64ABSD`). This confirms the function's role in rewriting operations. The return value `true` likely signifies that a rewrite occurred.

4. **Focus on `Op` Codes:** The `Op` codes prefixed with "Op" seem to represent generic Go operations (e.g., `OpAdd32`, `OpMul64`). The `Op` codes prefixed with "OpLOONG64" likely represent specific instructions for the LOONG64 architecture. The function appears to be translating generic Go operations into their LOONG64 equivalents.

5. **Identify Helper Functions:**  The code calls other functions like `rewriteValueLOONG64_OpAddr(v)`, `rewriteValueLOONG64_OpAtomicAnd8(v)`, etc. This suggests a hierarchical rewriting structure, where `rewriteValueLOONG64` acts as a dispatcher, and more specific rewriting logic is handled in these helper functions.

6. **Look for Patterns and Themes:**
    * **Arithmetic Operations:**  Cases like `OpAdd16`, `OpSub64`, `OpMul32` are directly translated to their LOONG64 equivalents (`OpLOONG64ADDV`, `OpLOONG64SUBV`, `OpLOONG64MULV`).
    * **Floating-Point Operations:**  Cases like `OpAdd32F`, `OpDiv64F`, `OpSqrt` are translated to LOONG64 floating-point instructions (`OpLOONG64ADDF`, `OpLOONG64DIVD`, `OpLOONG64SQRTD`).
    * **Bitwise Operations:** Cases like `OpAnd32`, `OpOr64`, `OpXor8` are translated to LOONG64 bitwise instructions (`OpLOONG64AND`, `OpLOONG64OR`, `OpLOONG64XOR`).
    * **Atomic Operations:**  Cases like `OpAtomicAdd32`, `OpAtomicCompareAndSwap64` are translated to LOONG64 lowered atomic operations (`OpLOONG64LoweredAtomicAdd32`, `OpLOONG64LoweredAtomicCas64`). The "Lowered" prefix likely indicates a more complex implementation handled by the LOONG64 backend.
    * **Conversions:** Cases like `OpCvt32to64F`, `OpCvt64Fto32` are translated to LOONG64 conversion instructions (`OpLOONG64MOVWD`, `OpLOONG64TRUNCDW`).
    * **Constants:** Cases like `OpConst32`, `OpConst64F` are translated to LOONG64 constant loading instructions (`OpLOONG64MOVVconst`, `OpLOONG64MOVDconst`).
    * **Calls:** Cases like `OpStaticCall`, `OpInterCall`, `OpClosureCall` are translated to LOONG64 call instructions (`OpLOONG64CALLstatic`, `OpLOONG64CALLinter`, `OpLOONG64CALLclosure`).

7. **Infer the Purpose:** Based on these observations, the primary function of this code is to perform architecture-specific lowering or rewriting of SSA operations for the LOONG64 architecture. It takes the architecture-independent SSA representation and transforms it into a representation that uses LOONG64-specific instructions. This is a crucial step in the Go compilation process for this architecture.

8. **Formulate the Summary:**  Based on the above analysis, I would formulate the summary as follows: "This Go code snippet is part of the SSA rewriting phase for the LOONG64 architecture within the Go compiler. Its primary function is to translate generic, architecture-independent SSA operations into their corresponding LOONG64-specific machine instructions. The `rewriteValueLOONG64` function acts as a central dispatcher, using a switch statement to handle various SSA operations. For each operation, it rewrites the `Op` field of the `Value` to the appropriate LOONG64 instruction, often calling specialized helper functions for more complex rewriting logic. This process is essential for generating LOONG64-compatible machine code from Go source code."
代码的功能是 Go 语言编译器的一部分，专门针对 LOONG64 架构进行 SSA (Static Single Assignment) 形式的中间代码的转换和优化。

**更具体地说，`rewriteValueLOONG64` 函数遍历并检查 SSA 中的每个 `Value` (代表一个操作或数据)，并根据其 `Op` 字段（操作码）将其重写为更底层的、LOONG64 架构特定的操作。**

**功能归纳:**

这段代码的主要功能是 **将 Go 语言中通用的操作 (例如 `OpAdd32`, `OpMul64`) 转换为 LOONG64 架构特定的指令 (例如 `OpLOONG64ADDV`, `OpLOONG64MULV`)。**  这是一个将高级的、架构无关的中间表示转换为低级的、架构相关的指令的关键步骤。

**更详细的功能列举：**

* **算术运算转换:** 将通用的加法 (`OpAdd`), 减法 (`OpSub`), 乘法 (`OpMul`), 除法 (`OpDiv`) 等操作转换为 LOONG64 架构对应的指令，如 `OpLOONG64ADDV`, `OpLOONG64SUBV`, `OpLOONG64MULV`, `OpLOONG64DIVV` 等。
* **浮点运算转换:** 将浮点数的加法 (`OpAdd32F`, `OpAdd64F`), 减法 (`OpSub32F`, `OpSub64F`), 乘法 (`OpMul32F`, `OpMul64F`), 除法 (`OpDiv32F`, `OpDiv64F`), 平方根 (`OpSqrt`, `OpSqrt32`) 等操作转换为 LOONG64 架构的浮点指令，如 `OpLOONG64ADDF`, `OpLOONG64ADDD`, `OpLOONG64SUBF`, `OpLOONG64SUBD`, `OpLOONG64MULF`, `OpLOONG64MULD`, `OpLOONG64DIVF`, `OpLOONG64DIVD`, `OpLOONG64SQRTF`, `OpLOONG64SQRTD` 等。
* **位运算转换:** 将按位与 (`OpAnd`), 按位或 (`OpOr`), 按位异或 (`OpXor`), 按位取反 (`OpCom`), 位移 (`OpLsh`, `OpRsh`) 等操作转换为 LOONG64 架构的位操作指令，如 `OpLOONG64AND`, `OpLOONG64OR`, `OpLOONG64XOR`, `OpLOONG64NOR`, `OpLOONG64SLLV`, `OpLOONG64SRLV`, `OpLOONG64SRAV` 等。
* **比较运算转换:** 将比较操作 (`OpEq`, `OpNeq`, `OpLess`, `OpLeq`, `OpGreater`, `OpGeq`) 转换为 LOONG64 架构的比较指令，例如，`OpEq` 会根据数据类型调用不同的 helper 函数进行转换。
* **类型转换:** 将不同类型之间的转换操作 (`OpCvt`) 转换为 LOONG64 架构的类型转换指令，如 `OpLOONG64MOVWF`, `OpLOONG64MOVWD`, `OpLOONG64TRUNCFW`, `OpLOONG64TRUNCFV` 等。
* **常量加载:** 将常量 (`OpConst`) 加载操作转换为 LOONG64 架构的常量加载指令，如 `OpLOONG64MOVVconst`, `OpLOONG64MOVFconst`, `OpLOONG64MOVDconst`。
* **内存操作转换:** 将内存加载 (`OpLoad`) 和存储 (`OpStore`) 操作，以及地址计算 (`OpAddr`, `OpOffPtr`) 转换为 LOONG64 架构的内存访问指令，如 `OpLOONG64MOVBload`, `OpLOONG64MOVVstore`, `OpLOONG64MOVVaddr` 等。
* **原子操作转换:** 将原子操作 (`OpAtomicAdd`, `OpAtomicCompareAndSwap`, `OpAtomicLoad`, `OpAtomicStore`) 转换为 LOONG64 架构提供的原子操作指令，例如 `OpLOONG64LoweredAtomicAdd32`, `OpLOONG64LoweredAtomicCas64`, `OpLOONG64LoweredAtomicLoad32`, `OpLOONG64LoweredAtomicStore64` 等。  "Lowered" 前缀通常表示这些操作可能需要更复杂的指令序列来实现原子性。
* **函数调用转换:** 将函数调用 (`OpStaticCall`, `OpInterCall`, `OpClosureCall`, `OpTailCall`) 转换为 LOONG64 架构的调用指令，如 `OpLOONG64CALLstatic`, `OpLOONG64CALLinter`, `OpLOONG64CALLclosure`, `OpLOONG64CALLtail`。
* **其他操作转换:**  还包括一些其他操作的转换，例如获取调用者 PC (`OpGetCallerPC`), 获取调用者 SP (`OpGetCallerSP`), 空指针检查 (`OpNilCheck`) 等。

**代码推理示例 (假设):**

假设我们有如下 Go 代码片段，它执行一个 32 位整数的加法：

```go
package main

func main() {
	a := int32(10)
	b := int32(20)
	c := a + b
	println(c)
}
```

在编译过程中，SSA 生成阶段可能会产生一个 `OpAdd32` 的操作，其输入是 `a` 和 `b` 对应的 SSA 值。

**假设的输入 SSA `Value` (v):**

```
Op: OpAdd32
Args: [Value_for_a, Value_for_b]
```

**`rewriteValueLOONG64` 函数会匹配到 `case OpAdd32:`:**

```go
case OpAdd32:
	v.Op = OpLOONG64ADDV
	return true
```

**输出 SSA `Value` (v):**

```
Op: OpLOONG64ADDV
Args: [Value_for_a, Value_for_b]
```

**解释:**  通用的 `OpAdd32` 被重写为 LOONG64 架构特定的 32 位加法指令 `OpLOONG64ADDV`。在 LOONG64 架构中，整数运算通常使用 64 位寄存器，因此 `ADDV` 指令用于执行 64 位或 32 位整数的加法。

**命令行参数处理：**

这段代码本身并不直接处理命令行参数。它是 Go 编译器内部的一部分，由编译器主程序驱动。Go 编译器的命令行参数 (例如 `-gcflags`, `-ldflags`, `-o`) 会影响整个编译过程，但不会直接传递到这个特定的 `rewriteLOONG64.go` 文件中。

**使用者易犯错的点：**

作为编译器开发者，理解这些重写规则至关重要。  普通 Go 语言使用者不会直接与这段代码交互。

**总结:**

`rewriteValueLOONG64.go` 的这一部分是 Go 编译器中针对 LOONG64 架构进行代码生成优化的关键环节。它负责将通用的中间表示转换为可以直接在 LOONG64 处理器上执行的指令。 这涉及到大量的模式匹配和指令选择，确保生成的代码既正确又高效。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteLOONG64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共4部分，请归纳一下它的功能

"""
// Code generated from _gen/LOONG64.rules using 'go generate'; DO NOT EDIT.

package ssa

import "cmd/compile/internal/types"

func rewriteValueLOONG64(v *Value) bool {
	switch v.Op {
	case OpAbs:
		v.Op = OpLOONG64ABSD
		return true
	case OpAdd16:
		v.Op = OpLOONG64ADDV
		return true
	case OpAdd32:
		v.Op = OpLOONG64ADDV
		return true
	case OpAdd32F:
		v.Op = OpLOONG64ADDF
		return true
	case OpAdd64:
		v.Op = OpLOONG64ADDV
		return true
	case OpAdd64F:
		v.Op = OpLOONG64ADDD
		return true
	case OpAdd8:
		v.Op = OpLOONG64ADDV
		return true
	case OpAddPtr:
		v.Op = OpLOONG64ADDV
		return true
	case OpAddr:
		return rewriteValueLOONG64_OpAddr(v)
	case OpAnd16:
		v.Op = OpLOONG64AND
		return true
	case OpAnd32:
		v.Op = OpLOONG64AND
		return true
	case OpAnd64:
		v.Op = OpLOONG64AND
		return true
	case OpAnd8:
		v.Op = OpLOONG64AND
		return true
	case OpAndB:
		v.Op = OpLOONG64AND
		return true
	case OpAtomicAdd32:
		v.Op = OpLOONG64LoweredAtomicAdd32
		return true
	case OpAtomicAdd64:
		v.Op = OpLOONG64LoweredAtomicAdd64
		return true
	case OpAtomicAnd32:
		v.Op = OpLOONG64LoweredAtomicAnd32
		return true
	case OpAtomicAnd32value:
		v.Op = OpLOONG64LoweredAtomicAnd32value
		return true
	case OpAtomicAnd64value:
		v.Op = OpLOONG64LoweredAtomicAnd64value
		return true
	case OpAtomicAnd8:
		return rewriteValueLOONG64_OpAtomicAnd8(v)
	case OpAtomicCompareAndSwap32:
		return rewriteValueLOONG64_OpAtomicCompareAndSwap32(v)
	case OpAtomicCompareAndSwap32Variant:
		return rewriteValueLOONG64_OpAtomicCompareAndSwap32Variant(v)
	case OpAtomicCompareAndSwap64:
		v.Op = OpLOONG64LoweredAtomicCas64
		return true
	case OpAtomicCompareAndSwap64Variant:
		v.Op = OpLOONG64LoweredAtomicCas64Variant
		return true
	case OpAtomicExchange32:
		v.Op = OpLOONG64LoweredAtomicExchange32
		return true
	case OpAtomicExchange64:
		v.Op = OpLOONG64LoweredAtomicExchange64
		return true
	case OpAtomicExchange8Variant:
		v.Op = OpLOONG64LoweredAtomicExchange8Variant
		return true
	case OpAtomicLoad32:
		v.Op = OpLOONG64LoweredAtomicLoad32
		return true
	case OpAtomicLoad64:
		v.Op = OpLOONG64LoweredAtomicLoad64
		return true
	case OpAtomicLoad8:
		v.Op = OpLOONG64LoweredAtomicLoad8
		return true
	case OpAtomicLoadPtr:
		v.Op = OpLOONG64LoweredAtomicLoad64
		return true
	case OpAtomicOr32:
		v.Op = OpLOONG64LoweredAtomicOr32
		return true
	case OpAtomicOr32value:
		v.Op = OpLOONG64LoweredAtomicOr32value
		return true
	case OpAtomicOr64value:
		v.Op = OpLOONG64LoweredAtomicOr64value
		return true
	case OpAtomicOr8:
		return rewriteValueLOONG64_OpAtomicOr8(v)
	case OpAtomicStore32:
		v.Op = OpLOONG64LoweredAtomicStore32
		return true
	case OpAtomicStore32Variant:
		v.Op = OpLOONG64LoweredAtomicStore32Variant
		return true
	case OpAtomicStore64:
		v.Op = OpLOONG64LoweredAtomicStore64
		return true
	case OpAtomicStore64Variant:
		v.Op = OpLOONG64LoweredAtomicStore64Variant
		return true
	case OpAtomicStore8:
		v.Op = OpLOONG64LoweredAtomicStore8
		return true
	case OpAtomicStore8Variant:
		v.Op = OpLOONG64LoweredAtomicStore8Variant
		return true
	case OpAtomicStorePtrNoWB:
		v.Op = OpLOONG64LoweredAtomicStore64
		return true
	case OpAvg64u:
		return rewriteValueLOONG64_OpAvg64u(v)
	case OpBitLen32:
		return rewriteValueLOONG64_OpBitLen32(v)
	case OpBitLen64:
		return rewriteValueLOONG64_OpBitLen64(v)
	case OpBitRev16:
		return rewriteValueLOONG64_OpBitRev16(v)
	case OpBitRev32:
		v.Op = OpLOONG64BITREVW
		return true
	case OpBitRev64:
		v.Op = OpLOONG64BITREVV
		return true
	case OpBitRev8:
		v.Op = OpLOONG64BITREV4B
		return true
	case OpBswap16:
		v.Op = OpLOONG64REVB2H
		return true
	case OpBswap32:
		v.Op = OpLOONG64REVB2W
		return true
	case OpBswap64:
		v.Op = OpLOONG64REVBV
		return true
	case OpClosureCall:
		v.Op = OpLOONG64CALLclosure
		return true
	case OpCom16:
		return rewriteValueLOONG64_OpCom16(v)
	case OpCom32:
		return rewriteValueLOONG64_OpCom32(v)
	case OpCom64:
		return rewriteValueLOONG64_OpCom64(v)
	case OpCom8:
		return rewriteValueLOONG64_OpCom8(v)
	case OpCondSelect:
		return rewriteValueLOONG64_OpCondSelect(v)
	case OpConst16:
		return rewriteValueLOONG64_OpConst16(v)
	case OpConst32:
		return rewriteValueLOONG64_OpConst32(v)
	case OpConst32F:
		return rewriteValueLOONG64_OpConst32F(v)
	case OpConst64:
		return rewriteValueLOONG64_OpConst64(v)
	case OpConst64F:
		return rewriteValueLOONG64_OpConst64F(v)
	case OpConst8:
		return rewriteValueLOONG64_OpConst8(v)
	case OpConstBool:
		return rewriteValueLOONG64_OpConstBool(v)
	case OpConstNil:
		return rewriteValueLOONG64_OpConstNil(v)
	case OpCopysign:
		v.Op = OpLOONG64FCOPYSGD
		return true
	case OpCtz32:
		v.Op = OpLOONG64CTZW
		return true
	case OpCtz32NonZero:
		v.Op = OpCtz32
		return true
	case OpCtz64:
		v.Op = OpLOONG64CTZV
		return true
	case OpCtz64NonZero:
		v.Op = OpCtz64
		return true
	case OpCvt32Fto32:
		v.Op = OpLOONG64TRUNCFW
		return true
	case OpCvt32Fto64:
		v.Op = OpLOONG64TRUNCFV
		return true
	case OpCvt32Fto64F:
		v.Op = OpLOONG64MOVFD
		return true
	case OpCvt32to32F:
		v.Op = OpLOONG64MOVWF
		return true
	case OpCvt32to64F:
		v.Op = OpLOONG64MOVWD
		return true
	case OpCvt64Fto32:
		v.Op = OpLOONG64TRUNCDW
		return true
	case OpCvt64Fto32F:
		v.Op = OpLOONG64MOVDF
		return true
	case OpCvt64Fto64:
		v.Op = OpLOONG64TRUNCDV
		return true
	case OpCvt64to32F:
		v.Op = OpLOONG64MOVVF
		return true
	case OpCvt64to64F:
		v.Op = OpLOONG64MOVVD
		return true
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv16:
		return rewriteValueLOONG64_OpDiv16(v)
	case OpDiv16u:
		return rewriteValueLOONG64_OpDiv16u(v)
	case OpDiv32:
		return rewriteValueLOONG64_OpDiv32(v)
	case OpDiv32F:
		v.Op = OpLOONG64DIVF
		return true
	case OpDiv32u:
		return rewriteValueLOONG64_OpDiv32u(v)
	case OpDiv64:
		return rewriteValueLOONG64_OpDiv64(v)
	case OpDiv64F:
		v.Op = OpLOONG64DIVD
		return true
	case OpDiv64u:
		v.Op = OpLOONG64DIVVU
		return true
	case OpDiv8:
		return rewriteValueLOONG64_OpDiv8(v)
	case OpDiv8u:
		return rewriteValueLOONG64_OpDiv8u(v)
	case OpEq16:
		return rewriteValueLOONG64_OpEq16(v)
	case OpEq32:
		return rewriteValueLOONG64_OpEq32(v)
	case OpEq32F:
		return rewriteValueLOONG64_OpEq32F(v)
	case OpEq64:
		return rewriteValueLOONG64_OpEq64(v)
	case OpEq64F:
		return rewriteValueLOONG64_OpEq64F(v)
	case OpEq8:
		return rewriteValueLOONG64_OpEq8(v)
	case OpEqB:
		return rewriteValueLOONG64_OpEqB(v)
	case OpEqPtr:
		return rewriteValueLOONG64_OpEqPtr(v)
	case OpFMA:
		v.Op = OpLOONG64FMADDD
		return true
	case OpGetCallerPC:
		v.Op = OpLOONG64LoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = OpLOONG64LoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = OpLOONG64LoweredGetClosurePtr
		return true
	case OpHmul32:
		return rewriteValueLOONG64_OpHmul32(v)
	case OpHmul32u:
		return rewriteValueLOONG64_OpHmul32u(v)
	case OpHmul64:
		v.Op = OpLOONG64MULHV
		return true
	case OpHmul64u:
		v.Op = OpLOONG64MULHVU
		return true
	case OpInterCall:
		v.Op = OpLOONG64CALLinter
		return true
	case OpIsInBounds:
		return rewriteValueLOONG64_OpIsInBounds(v)
	case OpIsNonNil:
		return rewriteValueLOONG64_OpIsNonNil(v)
	case OpIsSliceInBounds:
		return rewriteValueLOONG64_OpIsSliceInBounds(v)
	case OpLOONG64ADDD:
		return rewriteValueLOONG64_OpLOONG64ADDD(v)
	case OpLOONG64ADDF:
		return rewriteValueLOONG64_OpLOONG64ADDF(v)
	case OpLOONG64ADDV:
		return rewriteValueLOONG64_OpLOONG64ADDV(v)
	case OpLOONG64ADDVconst:
		return rewriteValueLOONG64_OpLOONG64ADDVconst(v)
	case OpLOONG64AND:
		return rewriteValueLOONG64_OpLOONG64AND(v)
	case OpLOONG64ANDconst:
		return rewriteValueLOONG64_OpLOONG64ANDconst(v)
	case OpLOONG64DIVV:
		return rewriteValueLOONG64_OpLOONG64DIVV(v)
	case OpLOONG64DIVVU:
		return rewriteValueLOONG64_OpLOONG64DIVVU(v)
	case OpLOONG64MASKEQZ:
		return rewriteValueLOONG64_OpLOONG64MASKEQZ(v)
	case OpLOONG64MASKNEZ:
		return rewriteValueLOONG64_OpLOONG64MASKNEZ(v)
	case OpLOONG64MOVBUload:
		return rewriteValueLOONG64_OpLOONG64MOVBUload(v)
	case OpLOONG64MOVBUloadidx:
		return rewriteValueLOONG64_OpLOONG64MOVBUloadidx(v)
	case OpLOONG64MOVBUreg:
		return rewriteValueLOONG64_OpLOONG64MOVBUreg(v)
	case OpLOONG64MOVBload:
		return rewriteValueLOONG64_OpLOONG64MOVBload(v)
	case OpLOONG64MOVBloadidx:
		return rewriteValueLOONG64_OpLOONG64MOVBloadidx(v)
	case OpLOONG64MOVBreg:
		return rewriteValueLOONG64_OpLOONG64MOVBreg(v)
	case OpLOONG64MOVBstore:
		return rewriteValueLOONG64_OpLOONG64MOVBstore(v)
	case OpLOONG64MOVBstoreidx:
		return rewriteValueLOONG64_OpLOONG64MOVBstoreidx(v)
	case OpLOONG64MOVBstorezero:
		return rewriteValueLOONG64_OpLOONG64MOVBstorezero(v)
	case OpLOONG64MOVBstorezeroidx:
		return rewriteValueLOONG64_OpLOONG64MOVBstorezeroidx(v)
	case OpLOONG64MOVDload:
		return rewriteValueLOONG64_OpLOONG64MOVDload(v)
	case OpLOONG64MOVDloadidx:
		return rewriteValueLOONG64_OpLOONG64MOVDloadidx(v)
	case OpLOONG64MOVDstore:
		return rewriteValueLOONG64_OpLOONG64MOVDstore(v)
	case OpLOONG64MOVDstoreidx:
		return rewriteValueLOONG64_OpLOONG64MOVDstoreidx(v)
	case OpLOONG64MOVFload:
		return rewriteValueLOONG64_OpLOONG64MOVFload(v)
	case OpLOONG64MOVFloadidx:
		return rewriteValueLOONG64_OpLOONG64MOVFloadidx(v)
	case OpLOONG64MOVFstore:
		return rewriteValueLOONG64_OpLOONG64MOVFstore(v)
	case OpLOONG64MOVFstoreidx:
		return rewriteValueLOONG64_OpLOONG64MOVFstoreidx(v)
	case OpLOONG64MOVHUload:
		return rewriteValueLOONG64_OpLOONG64MOVHUload(v)
	case OpLOONG64MOVHUloadidx:
		return rewriteValueLOONG64_OpLOONG64MOVHUloadidx(v)
	case OpLOONG64MOVHUreg:
		return rewriteValueLOONG64_OpLOONG64MOVHUreg(v)
	case OpLOONG64MOVHload:
		return rewriteValueLOONG64_OpLOONG64MOVHload(v)
	case OpLOONG64MOVHloadidx:
		return rewriteValueLOONG64_OpLOONG64MOVHloadidx(v)
	case OpLOONG64MOVHreg:
		return rewriteValueLOONG64_OpLOONG64MOVHreg(v)
	case OpLOONG64MOVHstore:
		return rewriteValueLOONG64_OpLOONG64MOVHstore(v)
	case OpLOONG64MOVHstoreidx:
		return rewriteValueLOONG64_OpLOONG64MOVHstoreidx(v)
	case OpLOONG64MOVHstorezero:
		return rewriteValueLOONG64_OpLOONG64MOVHstorezero(v)
	case OpLOONG64MOVHstorezeroidx:
		return rewriteValueLOONG64_OpLOONG64MOVHstorezeroidx(v)
	case OpLOONG64MOVVload:
		return rewriteValueLOONG64_OpLOONG64MOVVload(v)
	case OpLOONG64MOVVloadidx:
		return rewriteValueLOONG64_OpLOONG64MOVVloadidx(v)
	case OpLOONG64MOVVnop:
		return rewriteValueLOONG64_OpLOONG64MOVVnop(v)
	case OpLOONG64MOVVreg:
		return rewriteValueLOONG64_OpLOONG64MOVVreg(v)
	case OpLOONG64MOVVstore:
		return rewriteValueLOONG64_OpLOONG64MOVVstore(v)
	case OpLOONG64MOVVstoreidx:
		return rewriteValueLOONG64_OpLOONG64MOVVstoreidx(v)
	case OpLOONG64MOVVstorezero:
		return rewriteValueLOONG64_OpLOONG64MOVVstorezero(v)
	case OpLOONG64MOVVstorezeroidx:
		return rewriteValueLOONG64_OpLOONG64MOVVstorezeroidx(v)
	case OpLOONG64MOVWUload:
		return rewriteValueLOONG64_OpLOONG64MOVWUload(v)
	case OpLOONG64MOVWUloadidx:
		return rewriteValueLOONG64_OpLOONG64MOVWUloadidx(v)
	case OpLOONG64MOVWUreg:
		return rewriteValueLOONG64_OpLOONG64MOVWUreg(v)
	case OpLOONG64MOVWload:
		return rewriteValueLOONG64_OpLOONG64MOVWload(v)
	case OpLOONG64MOVWloadidx:
		return rewriteValueLOONG64_OpLOONG64MOVWloadidx(v)
	case OpLOONG64MOVWreg:
		return rewriteValueLOONG64_OpLOONG64MOVWreg(v)
	case OpLOONG64MOVWstore:
		return rewriteValueLOONG64_OpLOONG64MOVWstore(v)
	case OpLOONG64MOVWstoreidx:
		return rewriteValueLOONG64_OpLOONG64MOVWstoreidx(v)
	case OpLOONG64MOVWstorezero:
		return rewriteValueLOONG64_OpLOONG64MOVWstorezero(v)
	case OpLOONG64MOVWstorezeroidx:
		return rewriteValueLOONG64_OpLOONG64MOVWstorezeroidx(v)
	case OpLOONG64MULV:
		return rewriteValueLOONG64_OpLOONG64MULV(v)
	case OpLOONG64NEGV:
		return rewriteValueLOONG64_OpLOONG64NEGV(v)
	case OpLOONG64NOR:
		return rewriteValueLOONG64_OpLOONG64NOR(v)
	case OpLOONG64NORconst:
		return rewriteValueLOONG64_OpLOONG64NORconst(v)
	case OpLOONG64OR:
		return rewriteValueLOONG64_OpLOONG64OR(v)
	case OpLOONG64ORconst:
		return rewriteValueLOONG64_OpLOONG64ORconst(v)
	case OpLOONG64REMV:
		return rewriteValueLOONG64_OpLOONG64REMV(v)
	case OpLOONG64REMVU:
		return rewriteValueLOONG64_OpLOONG64REMVU(v)
	case OpLOONG64ROTR:
		return rewriteValueLOONG64_OpLOONG64ROTR(v)
	case OpLOONG64ROTRV:
		return rewriteValueLOONG64_OpLOONG64ROTRV(v)
	case OpLOONG64SGT:
		return rewriteValueLOONG64_OpLOONG64SGT(v)
	case OpLOONG64SGTU:
		return rewriteValueLOONG64_OpLOONG64SGTU(v)
	case OpLOONG64SGTUconst:
		return rewriteValueLOONG64_OpLOONG64SGTUconst(v)
	case OpLOONG64SGTconst:
		return rewriteValueLOONG64_OpLOONG64SGTconst(v)
	case OpLOONG64SLLV:
		return rewriteValueLOONG64_OpLOONG64SLLV(v)
	case OpLOONG64SLLVconst:
		return rewriteValueLOONG64_OpLOONG64SLLVconst(v)
	case OpLOONG64SRAV:
		return rewriteValueLOONG64_OpLOONG64SRAV(v)
	case OpLOONG64SRAVconst:
		return rewriteValueLOONG64_OpLOONG64SRAVconst(v)
	case OpLOONG64SRLV:
		return rewriteValueLOONG64_OpLOONG64SRLV(v)
	case OpLOONG64SRLVconst:
		return rewriteValueLOONG64_OpLOONG64SRLVconst(v)
	case OpLOONG64SUBD:
		return rewriteValueLOONG64_OpLOONG64SUBD(v)
	case OpLOONG64SUBF:
		return rewriteValueLOONG64_OpLOONG64SUBF(v)
	case OpLOONG64SUBV:
		return rewriteValueLOONG64_OpLOONG64SUBV(v)
	case OpLOONG64SUBVconst:
		return rewriteValueLOONG64_OpLOONG64SUBVconst(v)
	case OpLOONG64XOR:
		return rewriteValueLOONG64_OpLOONG64XOR(v)
	case OpLOONG64XORconst:
		return rewriteValueLOONG64_OpLOONG64XORconst(v)
	case OpLeq16:
		return rewriteValueLOONG64_OpLeq16(v)
	case OpLeq16U:
		return rewriteValueLOONG64_OpLeq16U(v)
	case OpLeq32:
		return rewriteValueLOONG64_OpLeq32(v)
	case OpLeq32F:
		return rewriteValueLOONG64_OpLeq32F(v)
	case OpLeq32U:
		return rewriteValueLOONG64_OpLeq32U(v)
	case OpLeq64:
		return rewriteValueLOONG64_OpLeq64(v)
	case OpLeq64F:
		return rewriteValueLOONG64_OpLeq64F(v)
	case OpLeq64U:
		return rewriteValueLOONG64_OpLeq64U(v)
	case OpLeq8:
		return rewriteValueLOONG64_OpLeq8(v)
	case OpLeq8U:
		return rewriteValueLOONG64_OpLeq8U(v)
	case OpLess16:
		return rewriteValueLOONG64_OpLess16(v)
	case OpLess16U:
		return rewriteValueLOONG64_OpLess16U(v)
	case OpLess32:
		return rewriteValueLOONG64_OpLess32(v)
	case OpLess32F:
		return rewriteValueLOONG64_OpLess32F(v)
	case OpLess32U:
		return rewriteValueLOONG64_OpLess32U(v)
	case OpLess64:
		return rewriteValueLOONG64_OpLess64(v)
	case OpLess64F:
		return rewriteValueLOONG64_OpLess64F(v)
	case OpLess64U:
		return rewriteValueLOONG64_OpLess64U(v)
	case OpLess8:
		return rewriteValueLOONG64_OpLess8(v)
	case OpLess8U:
		return rewriteValueLOONG64_OpLess8U(v)
	case OpLoad:
		return rewriteValueLOONG64_OpLoad(v)
	case OpLocalAddr:
		return rewriteValueLOONG64_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValueLOONG64_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValueLOONG64_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValueLOONG64_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValueLOONG64_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValueLOONG64_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValueLOONG64_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValueLOONG64_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValueLOONG64_OpLsh32x8(v)
	case OpLsh64x16:
		return rewriteValueLOONG64_OpLsh64x16(v)
	case OpLsh64x32:
		return rewriteValueLOONG64_OpLsh64x32(v)
	case OpLsh64x64:
		return rewriteValueLOONG64_OpLsh64x64(v)
	case OpLsh64x8:
		return rewriteValueLOONG64_OpLsh64x8(v)
	case OpLsh8x16:
		return rewriteValueLOONG64_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValueLOONG64_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValueLOONG64_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValueLOONG64_OpLsh8x8(v)
	case OpMax32F:
		v.Op = OpLOONG64FMAXF
		return true
	case OpMax64F:
		v.Op = OpLOONG64FMAXD
		return true
	case OpMin32F:
		v.Op = OpLOONG64FMINF
		return true
	case OpMin64F:
		v.Op = OpLOONG64FMIND
		return true
	case OpMod16:
		return rewriteValueLOONG64_OpMod16(v)
	case OpMod16u:
		return rewriteValueLOONG64_OpMod16u(v)
	case OpMod32:
		return rewriteValueLOONG64_OpMod32(v)
	case OpMod32u:
		return rewriteValueLOONG64_OpMod32u(v)
	case OpMod64:
		return rewriteValueLOONG64_OpMod64(v)
	case OpMod64u:
		v.Op = OpLOONG64REMVU
		return true
	case OpMod8:
		return rewriteValueLOONG64_OpMod8(v)
	case OpMod8u:
		return rewriteValueLOONG64_OpMod8u(v)
	case OpMove:
		return rewriteValueLOONG64_OpMove(v)
	case OpMul16:
		v.Op = OpLOONG64MULV
		return true
	case OpMul32:
		v.Op = OpLOONG64MULV
		return true
	case OpMul32F:
		v.Op = OpLOONG64MULF
		return true
	case OpMul64:
		v.Op = OpLOONG64MULV
		return true
	case OpMul64F:
		v.Op = OpLOONG64MULD
		return true
	case OpMul8:
		v.Op = OpLOONG64MULV
		return true
	case OpNeg16:
		v.Op = OpLOONG64NEGV
		return true
	case OpNeg32:
		v.Op = OpLOONG64NEGV
		return true
	case OpNeg32F:
		v.Op = OpLOONG64NEGF
		return true
	case OpNeg64:
		v.Op = OpLOONG64NEGV
		return true
	case OpNeg64F:
		v.Op = OpLOONG64NEGD
		return true
	case OpNeg8:
		v.Op = OpLOONG64NEGV
		return true
	case OpNeq16:
		return rewriteValueLOONG64_OpNeq16(v)
	case OpNeq32:
		return rewriteValueLOONG64_OpNeq32(v)
	case OpNeq32F:
		return rewriteValueLOONG64_OpNeq32F(v)
	case OpNeq64:
		return rewriteValueLOONG64_OpNeq64(v)
	case OpNeq64F:
		return rewriteValueLOONG64_OpNeq64F(v)
	case OpNeq8:
		return rewriteValueLOONG64_OpNeq8(v)
	case OpNeqB:
		v.Op = OpLOONG64XOR
		return true
	case OpNeqPtr:
		return rewriteValueLOONG64_OpNeqPtr(v)
	case OpNilCheck:
		v.Op = OpLOONG64LoweredNilCheck
		return true
	case OpNot:
		return rewriteValueLOONG64_OpNot(v)
	case OpOffPtr:
		return rewriteValueLOONG64_OpOffPtr(v)
	case OpOr16:
		v.Op = OpLOONG64OR
		return true
	case OpOr32:
		v.Op = OpLOONG64OR
		return true
	case OpOr64:
		v.Op = OpLOONG64OR
		return true
	case OpOr8:
		v.Op = OpLOONG64OR
		return true
	case OpOrB:
		v.Op = OpLOONG64OR
		return true
	case OpPanicBounds:
		return rewriteValueLOONG64_OpPanicBounds(v)
	case OpPopCount16:
		return rewriteValueLOONG64_OpPopCount16(v)
	case OpPopCount32:
		return rewriteValueLOONG64_OpPopCount32(v)
	case OpPopCount64:
		return rewriteValueLOONG64_OpPopCount64(v)
	case OpPubBarrier:
		v.Op = OpLOONG64LoweredPubBarrier
		return true
	case OpRotateLeft16:
		return rewriteValueLOONG64_OpRotateLeft16(v)
	case OpRotateLeft32:
		return rewriteValueLOONG64_OpRotateLeft32(v)
	case OpRotateLeft64:
		return rewriteValueLOONG64_OpRotateLeft64(v)
	case OpRotateLeft8:
		return rewriteValueLOONG64_OpRotateLeft8(v)
	case OpRound32F:
		v.Op = OpLOONG64LoweredRound32F
		return true
	case OpRound64F:
		v.Op = OpLOONG64LoweredRound64F
		return true
	case OpRsh16Ux16:
		return rewriteValueLOONG64_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValueLOONG64_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValueLOONG64_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValueLOONG64_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValueLOONG64_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValueLOONG64_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValueLOONG64_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValueLOONG64_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValueLOONG64_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValueLOONG64_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValueLOONG64_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValueLOONG64_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValueLOONG64_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValueLOONG64_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValueLOONG64_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValueLOONG64_OpRsh32x8(v)
	case OpRsh64Ux16:
		return rewriteValueLOONG64_OpRsh64Ux16(v)
	case OpRsh64Ux32:
		return rewriteValueLOONG64_OpRsh64Ux32(v)
	case OpRsh64Ux64:
		return rewriteValueLOONG64_OpRsh64Ux64(v)
	case OpRsh64Ux8:
		return rewriteValueLOONG64_OpRsh64Ux8(v)
	case OpRsh64x16:
		return rewriteValueLOONG64_OpRsh64x16(v)
	case OpRsh64x32:
		return rewriteValueLOONG64_OpRsh64x32(v)
	case OpRsh64x64:
		return rewriteValueLOONG64_OpRsh64x64(v)
	case OpRsh64x8:
		return rewriteValueLOONG64_OpRsh64x8(v)
	case OpRsh8Ux16:
		return rewriteValueLOONG64_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValueLOONG64_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValueLOONG64_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValueLOONG64_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValueLOONG64_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValueLOONG64_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValueLOONG64_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValueLOONG64_OpRsh8x8(v)
	case OpSelect0:
		return rewriteValueLOONG64_OpSelect0(v)
	case OpSelect1:
		return rewriteValueLOONG64_OpSelect1(v)
	case OpSelectN:
		return rewriteValueLOONG64_OpSelectN(v)
	case OpSignExt16to32:
		v.Op = OpLOONG64MOVHreg
		return true
	case OpSignExt16to64:
		v.Op = OpLOONG64MOVHreg
		return true
	case OpSignExt32to64:
		v.Op = OpLOONG64MOVWreg
		return true
	case OpSignExt8to16:
		v.Op = OpLOONG64MOVBreg
		return true
	case OpSignExt8to32:
		v.Op = OpLOONG64MOVBreg
		return true
	case OpSignExt8to64:
		v.Op = OpLOONG64MOVBreg
		return true
	case OpSlicemask:
		return rewriteValueLOONG64_OpSlicemask(v)
	case OpSqrt:
		v.Op = OpLOONG64SQRTD
		return true
	case OpSqrt32:
		v.Op = OpLOONG64SQRTF
		return true
	case OpStaticCall:
		v.Op = OpLOONG64CALLstatic
		return true
	case OpStore:
		return rewriteValueLOONG64_OpStore(v)
	case OpSub16:
		v.Op = OpLOONG64SUBV
		return true
	case OpSub32:
		v.Op = OpLOONG64SUBV
		return true
	case OpSub32F:
		v.Op = OpLOONG64SUBF
		return true
	case OpSub64:
		v.Op = OpLOONG64SUBV
		return true
	case OpSub64F:
		v.Op = OpLOONG64SUBD
		return true
	case OpSub8:
		v.Op = OpLOONG64SUBV
		return true
	case OpSubPtr:
		v.Op = OpLOONG64SUBV
		return true
	case OpTailCall:
		v.Op = OpLOONG64CALLtail
		return true
	case OpTrunc16to8:
		v.Op = OpCopy
		return true
	case OpTrunc32to16:
		v.Op = OpCopy
		return true
	case OpTrunc32to8:
		v.Op = OpCopy
		return true
	case OpTrunc64to16:
		v.Op = OpCopy
		return true
	case OpTrunc64to32:
		v.Op = OpCopy
		return true
	case OpTrunc64to8:
		v.Op = OpCopy
		return true
	case OpWB:
		v.Op = OpLOONG64LoweredWB
		return true
	case OpXor16:
		v.Op = OpLOONG64XOR
		return true
	case OpXor32:
		v.Op = OpLOONG64XOR
		return true
	case OpXor64:
		v.Op = OpLOONG64XOR
		return true
	case OpXor8:
		v.Op = OpLOONG64XOR
		return true
	case OpZero:
		return rewriteValueLOONG64_OpZero(v)
	case OpZeroExt16to32:
		v.Op = OpLOONG64MOVHUreg
		return true
	case OpZeroExt16to64:
		v.Op = OpLOONG64MOVHUreg
		return true
	case OpZeroExt32to64:
		v.Op = OpLOONG64MOVWUreg
		return true
	case OpZeroExt8to16:
		v.Op = OpLOONG64MOVBUreg
		return true
	case OpZeroExt8to32:
		v.Op = OpLOONG64MOVBUreg
		return true
	case OpZeroExt8to64:
		v.Op = OpLOONG64MOVBUreg
		return true
	}
	return false
}
func rewriteValueLOONG64_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVVaddr {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpLOONG64MOVVaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueLOONG64_OpAtomicAnd8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicAnd8 ptr val mem)
	// result: (LoweredAtomicAnd32 (AND <typ.Uintptr> (MOVVconst [^3]) ptr) (NORconst [0] <typ.UInt32> (SLLV <typ.UInt32> (XORconst <typ.UInt32> [0xff] (ZeroExt8to32 val)) (SLLVconst <typ.UInt64> [3] (ANDconst <typ.UInt64> [3] ptr)))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpLOONG64LoweredAtomicAnd32)
		v0 := b.NewValue0(v.Pos, OpLOONG64AND, typ.Uintptr)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpLOONG64NORconst, typ.UInt32)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpLOONG64SLLV, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpLOONG64XORconst, typ.UInt32)
		v4.AuxInt = int64ToAuxInt(0xff)
		v5 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v5.AddArg(val)
		v4.AddArg(v5)
		v6 := b.NewValue0(v.Pos, OpLOONG64SLLVconst, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(3)
		v7 := b.NewValue0(v.Pos, OpLOONG64ANDconst, typ.UInt64)
		v7.AuxInt = int64ToAuxInt(3)
		v7.AddArg(ptr)
		v6.AddArg(v7)
		v3.AddArg2(v4, v6)
		v2.AddArg(v3)
		v.AddArg3(v0, v2, mem)
		return true
	}
}
func rewriteValueLOONG64_OpAtomicCompareAndSwap32(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicCompareAndSwap32 ptr old new mem)
	// result: (LoweredAtomicCas32 ptr (SignExt32to64 old) new mem)
	for {
		ptr := v_0
		old := v_1
		new := v_2
		mem := v_3
		v.reset(OpLOONG64LoweredAtomicCas32)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(old)
		v.AddArg4(ptr, v0, new, mem)
		return true
	}
}
func rewriteValueLOONG64_OpAtomicCompareAndSwap32Variant(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicCompareAndSwap32Variant ptr old new mem)
	// result: (LoweredAtomicCas32Variant ptr (SignExt32to64 old) new mem)
	for {
		ptr := v_0
		old := v_1
		new := v_2
		mem := v_3
		v.reset(OpLOONG64LoweredAtomicCas32Variant)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(old)
		v.AddArg4(ptr, v0, new, mem)
		return true
	}
}
func rewriteValueLOONG64_OpAtomicOr8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicOr8 ptr val mem)
	// result: (LoweredAtomicOr32 (AND <typ.Uintptr> (MOVVconst [^3]) ptr) (SLLV <typ.UInt32> (ZeroExt8to32 val) (SLLVconst <typ.UInt64> [3] (ANDconst <typ.UInt64> [3] ptr))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpLOONG64LoweredAtomicOr32)
		v0 := b.NewValue0(v.Pos, OpLOONG64AND, typ.Uintptr)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpLOONG64SLLV, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v3.AddArg(val)
		v4 := b.NewValue0(v.Pos, OpLOONG64SLLVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(3)
		v5 := b.NewValue0(v.Pos, OpLOONG64ANDconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(3)
		v5.AddArg(ptr)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v2, mem)
		return true
	}
}
func rewriteValueLOONG64_OpAvg64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg64u <t> x y)
	// result: (ADDV (SRLVconst <t> (SUBV <t> x y) [1]) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64ADDV)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLVconst, t)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SUBV, t)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueLOONG64_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (BitLen32 <t> x)
	// result: (NEGV <t> (SUBVconst <t> [32] (CLZW <t> x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64NEGV)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64SUBVconst, t)
		v0.AuxInt = int64ToAuxInt(32)
		v1 := b.NewValue0(v.Pos, OpLOONG64CLZW, t)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpBitLen64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (BitLen64 <t> x)
	// result: (NEGV <t> (SUBVconst <t> [64] (CLZV <t> x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64NEGV)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64SUBVconst, t)
		v0.AuxInt = int64ToAuxInt(64)
		v1 := b.NewValue0(v.Pos, OpLOONG64CLZV, t)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpBitRev16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (BitRev16 <t> x)
	// result: (REVB2H (BITREV4B <t> x))
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64REVB2H)
		v0 := b.NewValue0(v.Pos, OpLOONG64BITREV4B, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpCom16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com16 x)
	// result: (NOR (MOVVconst [0]) x)
	for {
		x := v_0
		v.reset(OpLOONG64NOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueLOONG64_OpCom32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com32 x)
	// result: (NOR (MOVVconst [0]) x)
	for {
		x := v_0
		v.reset(OpLOONG64NOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueLOONG64_OpCom64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com64 x)
	// result: (NOR (MOVVconst [0]) x)
	for {
		x := v_0
		v.reset(OpLOONG64NOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueLOONG64_OpCom8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com8 x)
	// result: (NOR (MOVVconst [0]) x)
	for {
		x := v_0
		v.reset(OpLOONG64NOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueLOONG64_OpCondSelect(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CondSelect <t> x y cond)
	// result: (OR (MASKEQZ <t> x cond) (MASKNEZ <t> y cond))
	for {
		t := v.Type
		x := v_0
		y := v_1
		cond := v_2
		v.reset(OpLOONG64OR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MASKEQZ, t)
		v0.AddArg2(x, cond)
		v1 := b.NewValue0(v.Pos, OpLOONG64MASKNEZ, t)
		v1.AddArg2(y, cond)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVVconst [int64(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueLOONG64_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVVconst [int64(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueLOONG64_OpConst32F(v *Value) bool {
	// match: (Const32F [val])
	// result: (MOVFconst [float64(val)])
	for {
		val := auxIntToFloat32(v.AuxInt)
		v.reset(OpLOONG64MOVFconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueLOONG64_OpConst64(v *Value) bool {
	// match: (Const64 [val])
	// result: (MOVVconst [int64(val)])
	for {
		val := auxIntToInt64(v.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueLOONG64_OpConst64F(v *Value) bool {
	// match: (Const64F [val])
	// result: (MOVDconst [float64(val)])
	for {
		val := auxIntToFloat64(v.AuxInt)
		v.reset(OpLOONG64MOVDconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueLOONG64_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVVconst [int64(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueLOONG64_OpConstBool(v *Value) bool {
	// match: (ConstBool [t])
	// result: (MOVVconst [int64(b2i(t))])
	for {
		t := auxIntToBool(v.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(b2i(t)))
		return true
	}
}
func rewriteValueLOONG64_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVVconst [0])
	for {
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValueLOONG64_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 x y)
	// result: (DIVV (SignExt16to64 x) (SignExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64DIVV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (DIVVU (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64DIVVU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32 x y)
	// result: (DIVV (SignExt32to64 x) (SignExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64DIVV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32u x y)
	// result: (DIVVU (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64DIVVU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div64 x y)
	// result: (DIVV x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64DIVV)
		v.AddArg2(x, y)
		return true
	}
}
func rewriteValueLOONG64_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (DIVV (SignExt8to64 x) (SignExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64DIVV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (DIVVU (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64DIVVU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (SGTU (MOVVconst [1]) (XOR (ZeroExt16to64 x) (ZeroExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq32 x y)
	// result: (SGTU (MOVVconst [1]) (XOR (ZeroExt32to64 x) (ZeroExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (FPFlagTrue (CMPEQF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPEQF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq64 x y)
	// result: (SGTU (MOVVconst [1]) (XOR x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (FPFlagTrue (CMPEQD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpLOONG64CMPEQD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (SGTU (MOVVconst [1]) (XOR (ZeroExt8to64 x) (ZeroExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (XOR (MOVVconst [1]) (XOR <typ.Bool> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqPtr x y)
	// result: (SGTU (MOVVconst [1]) (XOR x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64XOR, typ.UInt64)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpHmul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32 x y)
	// result: (SRAVconst (MULV (SignExt32to64 x) (SignExt32to64 y)) [32])
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAVconst)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpLOONG64MULV, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpHmul32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32u x y)
	// result: (SRLVconst (MULV (ZeroExt32to64 x) (ZeroExt32to64 y)) [32])
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRLVconst)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpLOONG64MULV, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (IsInBounds idx len)
	// result: (SGTU len idx)
	for {
		idx := v_0
		len := v_1
		v.reset(OpLOONG64SGTU)
		v.AddArg2(len, idx)
		return true
	}
}
func rewriteValueLOONG64_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsNonNil ptr)
	// result: (SGTU ptr (MOVVconst [0]))
	for {
		ptr := v_0
		v.reset(OpLOONG64SGTU)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(ptr, v0)
		return true
	}
}
func rewriteValueLOONG64_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsSliceInBounds idx len)
	// result: (XOR (MOVVconst [1]) (SGTU idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpLOONG64XOR)
		v0 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v1.AddArg2(idx, len)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpLOONG64ADDD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDD (MULD x y) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FMADDD x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLOONG64MULD {
				continue
			}
			y := v_0.Args[1]
			x := v_0.Args[0]
			z := v_1
			if !(z.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpLOONG64FMADDD)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (ADDD z (NEGD (MULD x y)))
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMSUBD x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			z := v_0
			if v_1.Op != OpLOONG64NEGD {
				continue
			}
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpLOONG64MULD {
				continue
			}
			y := v_1_0.Args[1]
			x := v_1_0.Args[0]
			if !(z.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpLOONG64FNMSUBD)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64ADDF(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDF (MULF x y) z)
	// cond: z.Block.Func.useFMA(v)
	// result: (FMADDF x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLOONG64MULF {
				continue
			}
			y := v_0.Args[1]
			x := v_0.Args[0]
			z := v_1
			if !(z.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpLOONG64FMADDF)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (ADDF z (NEGF (MULF x y)))
	// cond: z.Block.Func.useFMA(v)
	// result: (FNMSUBF x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			z := v_0
			if v_1.Op != OpLOONG64NEGF {
				continue
			}
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpLOONG64MULF {
				continue
			}
			y := v_1_0.Args[1]
			x := v_1_0.Args[0]
			if !(z.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpLOONG64FNMSUBF)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64ADDV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDV x (MOVVconst <t> [c]))
	// cond: is32Bit(c) && !t.IsPtr()
	// result: (ADDVconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64MOVVconst {
				continue
			}
			t := v_1.Type
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c) && !t.IsPtr()) {
				continue
			}
			v.reset(OpLOONG64ADDVconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADDV x (NEGV y))
	// result: (SUBV x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64NEGV {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpLOONG64SUBV)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64ADDVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDVconst [off1] (MOVVaddr [off2] {sym} ptr))
	// cond: is32Bit(off1+int64(off2))
	// result: (MOVVaddr [int32(off1)+int32(off2)] {sym} ptr)
	for {
		off1 := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		if !(is32Bit(off1 + int64(off2))) {
			break
		}
		v.reset(OpLOONG64MOVVaddr)
		v.AuxInt = int32ToAuxInt(int32(off1) + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg(ptr)
		return true
	}
	// match: (ADDVconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ADDVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c+d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c + d)
		return true
	}
	// match: (ADDVconst [c] (ADDVconst [d] x))
	// cond: is32Bit(c+d)
	// result: (ADDVconst [c+d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c + d)) {
			break
		}
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (ADDVconst [c] (SUBVconst [d] x))
	// cond: is32Bit(c-d)
	// result: (ADDVconst [c-d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64SUBVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c - d)) {
			break
		}
		v.reset(OpLOONG64ADDVconst)
		v.AuxInt = int64ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64AND(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AND x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (ANDconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpLOONG64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpLOONG64ANDconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64ANDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDconst [0] _)
	// result: (MOVVconst [0])
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (ANDconst [-1] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ANDconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c&d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c & d)
		return true
	}
	// match: (ANDconst [c] (ANDconst [d] x))
	// result: (ANDconst [c&d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpLOONG64ANDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpLOONG64ANDconst)
		v.AuxInt = int64ToAuxInt(c & d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64DIVV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIVV (MOVVconst [c]) (MOVVconst [d]))
	// cond: d != 0
	// result: (MOVVconst [c/d])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(c / d)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64DIVVU(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIVVU x (MOVVconst [1]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (DIVVU x (MOVVconst [c]))
	// cond: isPowerOfTwo(c)
	// result: (SRLVconst [log64(c)] x)
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(isPowerOfTwo(c)) {
			break
		}
		v.reset(OpLOONG64SRLVconst)
		v.AuxInt = int64ToAuxInt(log64(c))
		v.AddArg(x)
		return true
	}
	// match: (DIVVU (MOVVconst [c]) (MOVVconst [d]))
	// cond: d != 0
	// result: (MOVVconst [int64(uint64(c)/uint64(d))])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) / uint64(d)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MASKEQZ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MASKEQZ (MOVVconst [0]) cond)
	// result: (MOVVconst [0])
	for {
		if v_0.Op != OpLOONG64MOVVconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MASKEQZ x (MOVVconst [c]))
	// cond: c == 0
	// result: (MOVVconst [0])
	for {
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c == 0) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MASKEQZ x (MOVVconst [c]))
	// cond: c != 0
	// result: x
	for {
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c != 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MASKNEZ(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MASKNEZ (MOVVconst [0]) cond)
	// result: (MOVVconst [0])
	for {
		if v_0.Op != OpLOONG64MOVVconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBUload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBUload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBUload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBUloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVBUloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBUloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBUloadidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVBUload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVBUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUloadidx (MOVVconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVBUload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVBUload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBUreg (SRLVconst [rc] x))
	// cond: rc < 8
	// result: (BSTRPICKV [rc + (7+rc)<<6] x)
	for {
		if v_0.Op != OpLOONG64SRLVconst {
			break
		}
		rc := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(rc < 8) {
			break
		}
		v.reset(OpLOONG64BSTRPICKV)
		v.AuxInt = int64ToAuxInt(rc + (7+rc)<<6)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(SGT _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpLOONG64SGT {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(SGTU _ _))
	// result: x
	for {
		x := v_0
		if x.Op != OpLOONG64SGTU {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(XOR (MOVVconst [1]) (SGT _ _)))
	// result: x
	for {
		x := v_0
		if x.Op != OpLOONG64XOR {
			break
		}
		_ = x.Args[1]
		x_0 := x.Args[0]
		x_1 := x.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, x_0, x_1 = _i0+1, x_1, x_0 {
			if x_0.Op != OpLOONG64MOVVconst || auxIntToInt64(x_0.AuxInt) != 1 || x_1.Op != OpLOONG64SGT {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (MOVBUreg x:(XOR (MOVVconst [1]) (SGTU _ _)))
	// result: x
	for {
		x := v_0
		if x.Op != OpLOONG64XOR {
			break
		}
		_ = x.Args[1]
		x_0 := x.Args[0]
		x_1 := x.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, x_0, x_1 = _i0+1, x_1, x_0 {
			if x_0.Op != OpLOONG64MOVVconst || auxIntToInt64(x_0.AuxInt) != 1 || x_1.Op != OpLOONG64SGTU {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (MOVBUreg x:(MOVBUload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(MOVBUreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBUreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (SLLVconst [lc] x))
	// cond: lc >= 8
	// result: (MOVVconst [0])
	for {
		if v_0.Op != OpLOONG64SLLVconst {
			break
		}
		lc := auxIntToInt64(v_0.AuxInt)
		if !(lc >= 8) {
			break
		}
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (MOVBUreg (MOVVconst [c]))
	// result: (MOVVconst [int64(uint8(c))])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		return true
	}
	// match: (MOVBUreg (ANDconst [c] x))
	// result: (ANDconst [c&0xff] x)
	for {
		if v_0.Op != OpLOONG64ANDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpLOONG64ANDconst)
		v.AuxInt = int64ToAuxInt(c & 0xff)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBload [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBload [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVBload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off] {sym} (ADDV ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVBloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBloadidx ptr (MOVVconst [c]) mem)
	// cond: is32Bit(c)
	// result: (MOVBload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVBload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBloadidx (MOVVconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (MOVBload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVBload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBreg x:(MOVBload _ _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBload {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg x:(MOVBreg _))
	// result: (MOVVreg x)
	for {
		x := v_0
		if x.Op != OpLOONG64MOVBreg {
			break
		}
		v.reset(OpLOONG64MOVVreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (MOVVconst [c]))
	// result: (MOVVconst [int64(int8(c))])
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpLOONG64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(int8(c)))
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBstore [off1] {sym} (ADDVconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym1} (MOVVaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstore [off1+int32(off2)] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVBreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBUreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVBUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVHUreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVWreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVWUreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVWUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVVconst [0]) mem)
	// result: (MOVBstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpLOONG64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} (ADDV ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (MOVBstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDV {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpLOONG64MOVBstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstoreidx ptr (MOVVconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (MOVBstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstoreidx (MOVVconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (MOVBstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpLOONG64MOVBstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (MOVBstoreidx ptr idx (MOVVconst [0]) mem)
	// result: (MOVBstorezeroidx ptr idx mem)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpLOONG64MOVVconst || auxIntToInt64(v_2.AuxInt) != 0 {
			break
		}
		mem := v_3
		v.reset(OpLOONG64MOVBstorezeroidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpLOONG64MOVBstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVBstorezero [off1] {sym} (ADDVconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (MOVBstorezero [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpLOONG64ADDVconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpLOONG64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg
"""




```