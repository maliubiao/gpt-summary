Response: My goal is to analyze the provided Go code snippet and extract its functionality, infer its purpose within the Go compiler, provide illustrative examples, and summarize its role as the first part of a larger set.

**Thinking Process:**

1. **Identify the Core Function:** The code defines a function `rewriteValuegeneric(v *Value) bool`. This immediately suggests that this code is part of a rewrite pass in the SSA (Static Single Assignment) optimization pipeline of the Go compiler. The function takes an SSA `Value` as input and returns a boolean, indicating whether the value was rewritten.

2. **Analyze the `switch` Statement:** The `rewriteValuegeneric` function contains a large `switch` statement based on `v.Op`. This strongly suggests that this function handles rewrites for various SSA operations. Each `case` calls another function, like `rewriteValuegeneric_OpAdd16(v)`, indicating a separate handler for each operation.

3. **Infer the Overall Purpose:** Given that this is a rewrite pass, the primary goal is to simplify or optimize the SSA representation. This can involve:
    * **Constant Folding:** Evaluating operations with constant operands at compile time.
    * **Algebraic Simplification:** Applying algebraic identities to reduce the complexity of expressions.
    * **Strength Reduction:** Replacing expensive operations with cheaper ones.
    * **Pattern Matching:** Identifying specific code patterns and replacing them with more efficient alternatives.

4. **Examine Individual `case` Handlers (e.g., `rewriteValuegeneric_OpAdd16`):**
    * **Constant Folding:** The first match in `rewriteValuegeneric_OpAdd16` (`match: (Add16 (Const16 [c]) (Const16 [d])) result: (Const16 [c+d])`) clearly demonstrates constant folding.
    * **Algebraic Simplification:**  Matches like `match: (Add16 <t> (Mul16 x y) (Mul16 x z)) result: (Mul16 x (Add16 <t> y z))` show the application of the distributive property. Another example is `match: (Add16 x (Neg16 y)) result: (Sub16 x y)`.
    * **Identity Laws:** `match: (Add16 (Const16 [0]) x) result: x` illustrates the additive identity.
    * **Inverse Operations:** `match: (Add16 (Com16 x) x) result: (Const16 [-1])` relies on the property of bitwise complement.
    * **Rotation Optimization:** The more complex matches involving `Lsh` and `Rsh` suggest optimizations for bitwise rotations.

5. **Infer the Target Go Language Features:** By observing the types of operations being rewritten (arithmetic, bitwise, comparisons, conversions, memory access, function calls, etc.), I can infer that this code deals with a broad range of Go language features and their low-level representations in SSA.

6. **Construct Example Code:** Based on the identified optimizations, I can create Go code examples that would trigger these rewrites. For instance, adding two constant integers will be folded at compile time.

7. **Consider Command-Line Arguments:** The code itself doesn't directly process command-line arguments. However, the entire compilation process involves numerous flags. I need to consider if any flags might indirectly influence the behavior of this rewrite pass (e.g., optimization level).

8. **Identify Potential User Errors:**  Users don't directly interact with this code. However, understanding its optimizations can help developers write more efficient Go code. For example, knowing that constant expressions are folded might encourage their use where appropriate.

9. **Summarize the Functionality:** Combine all the observations to provide a concise summary of the code's role in the Go compiler.

10. **Address the "Part 1 of 13" Instruction:**  Acknowledge that this is just a segment and its full context lies within the subsequent parts.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the low-level SSA details. I need to step back and think about the higher-level Go language constructs being optimized.
* I need to ensure the example code is clear and directly demonstrates the rewrites being performed.
* I must be precise in describing the compiler's internal workings without making assumptions about the user's knowledge.
* The command-line argument section needs to be framed carefully, as this specific file doesn't handle them directly. It's the overall `go build` process.

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive response addressing all the user's requirements.
`go/src/cmd/compile/internal/ssa/rewritegeneric.go` 的这一部分代码的主要功能是定义了一个名为 `rewriteValuegeneric` 的函数，该函数负责对 SSA（Static Single Assignment）形式的中间代码进行基于操作码 (Opcode) 的重写规则应用。

更具体地说，它是一个大型的 `switch` 语句，根据 `v.Op` (当前 SSA Value 的操作码) 的不同，调用相应的 `rewriteValuegeneric_OpXXX` 函数。每个 `rewriteValuegeneric_OpXXX` 函数都包含了针对特定操作码的优化或简化规则。

**功能归纳:**

* **SSA 值重写调度器:**  `rewriteValuegeneric` 函数充当一个调度器，根据 SSA Value 的操作类型，将重写任务分发到特定的处理函数。
* **通用类型操作的重写规则入口:**  由于文件名包含 "generic"，可以推断这部分代码处理的是与类型无关或者可以应用于多种类型的通用 SSA 操作的重写规则。
* **基于模式匹配的优化:** 每个 `case` 分支和对应的 `rewriteValuegeneric_OpXXX` 函数都实现了一组模式匹配和替换规则，旨在识别特定的 SSA 代码模式并将其替换为更优化或更简洁的形式。

**推理其实现的 Go 语言功能 (及其代码示例):**

从 `switch` 语句中的 `case` 来看，它涵盖了 Go 语言中许多基本操作，例如：

* **算术运算:** `OpAdd16`, `OpAdd32`, `OpSub64`, `OpMul8`, `OpDiv32F` 等，对应 Go 中的加减乘除运算。
* **位运算:** `OpAnd16`, `OpOr64`, `OpXor8`, `OpLsh32x64`, `OpRsh16Ux16` 等，对应 Go 中的按位与、或、异或、左移、右移等运算。
* **比较运算:** `OpEq32`, `OpNeqPtr`, `OpLess16U`, `OpLeq64F` 等，对应 Go 中的等于、不等于、小于、小于等于等比较操作。
* **类型转换:** `OpConvert`, `OpCvt32Fto64`, `OpSignExt8to32`, `OpTrunc64to16` 等，对应 Go 中的类型转换操作。
* **常量:** `OpConst16`, `OpConstString`, `OpConstInterface`，对应 Go 中的常量定义。
* **内存操作:** `OpLoad`, `OpStore`, `OpMove`，对应 Go 中的内存读取、写入和移动操作。
* **切片和数组操作:** `OpSliceLen`, `OpArraySelect`，对应 Go 中的切片长度获取和数组元素选择。
* **函数调用:** `OpStaticCall`, `OpInterLECall`，对应 Go 中的静态函数调用和接口方法调用。

**Go 代码示例 (基于 `OpAdd16` 的推理):**

假设 `rewriteValuegeneric_OpAdd16` 函数实现了以下规则：将两个常量 `int16` 相加的结果替换为一个新的常量。

```go
// 假设的 rewriteValuegeneric_OpAdd16 函数实现
func rewriteValuegeneric_OpAdd16(v *Value) bool {
	if v.Args[0].Op == OpConst16 && v.Args[1].Op == OpConst16 {
		c := auxIntToInt16(v.Args[0].AuxInt)
		d := auxIntToInt16(v.Args[1].AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(c + d)
		return true
	}
	return false
}

// 示例 Go 代码
package main

func main() {
	var a int16 = 5
	var b int16 = 10
	c := a + b //  编译器在 SSA 阶段可能会生成 OpAdd16(Const16[5], Const16[10])
	println(c)
}
```

**假设的输入与输出:**

对于上面的 `OpAdd16` 示例，假设在 SSA 构建阶段，`c := a + b` 被表示为 `OpAdd16` 节点，其输入是两个 `OpConst16` 节点：

* **输入 (SSA Value v):**
    * `v.Op`: `OpAdd16`
    * `v.Args[0].Op`: `OpConst16`, `v.Args[0].AuxInt`: 5 (假设)
    * `v.Args[1].Op`: `OpConst16`, `v.Args[1].AuxInt`: 10 (假设)

* **输出 (经过 `rewriteValuegeneric_OpAdd16` 重写后):**
    * `v.Op`: `OpConst16`
    * `v.AuxInt`: 15

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是 Go 编译器内部 SSA 优化管道的一部分。命令行参数（如 `-gcflags` 中的优化选项）会影响整个编译流程，可能导致不同的 SSA 图的生成，从而间接影响 `rewritegeneric.go` 中的规则是否被触发以及如何被触发。例如，较高的优化级别可能会启用更多的 SSA 重写规则。

**归纳其功能 (第1部分，共13部分):**

作为 13 个部分中的第一部分，`go/src/cmd/compile/internal/ssa/rewritegeneric.go` 的这一段代码定义了 **`rewriteValuegeneric` 函数，它是针对通用类型 SSA 操作进行优化的入口点和调度器。** 它通过一个大的 `switch` 语句，根据不同的 SSA 操作码，将重写任务分发到相应的特定处理函数中。  可以推断，后续的 12 个部分很可能包含了 `rewriteValuegeneric_OpXXX` 函数的具体实现，分别负责处理各种不同的 SSA 操作的重写规则，从而实现更广泛的 SSA 优化。总而言之，**这部分代码是 Go 编译器 SSA 优化中处理通用操作重写规则的核心框架。**

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
// Code generated from _gen/generic.rules using 'go generate'; DO NOT EDIT.

package ssa

import "math"
import "math/bits"
import "cmd/internal/obj"
import "cmd/compile/internal/types"
import "cmd/compile/internal/ir"

func rewriteValuegeneric(v *Value) bool {
	switch v.Op {
	case OpAdd16:
		return rewriteValuegeneric_OpAdd16(v)
	case OpAdd32:
		return rewriteValuegeneric_OpAdd32(v)
	case OpAdd32F:
		return rewriteValuegeneric_OpAdd32F(v)
	case OpAdd64:
		return rewriteValuegeneric_OpAdd64(v)
	case OpAdd64F:
		return rewriteValuegeneric_OpAdd64F(v)
	case OpAdd8:
		return rewriteValuegeneric_OpAdd8(v)
	case OpAddPtr:
		return rewriteValuegeneric_OpAddPtr(v)
	case OpAnd16:
		return rewriteValuegeneric_OpAnd16(v)
	case OpAnd32:
		return rewriteValuegeneric_OpAnd32(v)
	case OpAnd64:
		return rewriteValuegeneric_OpAnd64(v)
	case OpAnd8:
		return rewriteValuegeneric_OpAnd8(v)
	case OpAndB:
		return rewriteValuegeneric_OpAndB(v)
	case OpArraySelect:
		return rewriteValuegeneric_OpArraySelect(v)
	case OpBitLen16:
		return rewriteValuegeneric_OpBitLen16(v)
	case OpBitLen32:
		return rewriteValuegeneric_OpBitLen32(v)
	case OpBitLen64:
		return rewriteValuegeneric_OpBitLen64(v)
	case OpBitLen8:
		return rewriteValuegeneric_OpBitLen8(v)
	case OpCeil:
		return rewriteValuegeneric_OpCeil(v)
	case OpCom16:
		return rewriteValuegeneric_OpCom16(v)
	case OpCom32:
		return rewriteValuegeneric_OpCom32(v)
	case OpCom64:
		return rewriteValuegeneric_OpCom64(v)
	case OpCom8:
		return rewriteValuegeneric_OpCom8(v)
	case OpConstInterface:
		return rewriteValuegeneric_OpConstInterface(v)
	case OpConstSlice:
		return rewriteValuegeneric_OpConstSlice(v)
	case OpConstString:
		return rewriteValuegeneric_OpConstString(v)
	case OpConvert:
		return rewriteValuegeneric_OpConvert(v)
	case OpCtz16:
		return rewriteValuegeneric_OpCtz16(v)
	case OpCtz32:
		return rewriteValuegeneric_OpCtz32(v)
	case OpCtz64:
		return rewriteValuegeneric_OpCtz64(v)
	case OpCtz8:
		return rewriteValuegeneric_OpCtz8(v)
	case OpCvt32Fto32:
		return rewriteValuegeneric_OpCvt32Fto32(v)
	case OpCvt32Fto64:
		return rewriteValuegeneric_OpCvt32Fto64(v)
	case OpCvt32Fto64F:
		return rewriteValuegeneric_OpCvt32Fto64F(v)
	case OpCvt32to32F:
		return rewriteValuegeneric_OpCvt32to32F(v)
	case OpCvt32to64F:
		return rewriteValuegeneric_OpCvt32to64F(v)
	case OpCvt64Fto32:
		return rewriteValuegeneric_OpCvt64Fto32(v)
	case OpCvt64Fto32F:
		return rewriteValuegeneric_OpCvt64Fto32F(v)
	case OpCvt64Fto64:
		return rewriteValuegeneric_OpCvt64Fto64(v)
	case OpCvt64to32F:
		return rewriteValuegeneric_OpCvt64to32F(v)
	case OpCvt64to64F:
		return rewriteValuegeneric_OpCvt64to64F(v)
	case OpCvtBoolToUint8:
		return rewriteValuegeneric_OpCvtBoolToUint8(v)
	case OpDiv16:
		return rewriteValuegeneric_OpDiv16(v)
	case OpDiv16u:
		return rewriteValuegeneric_OpDiv16u(v)
	case OpDiv32:
		return rewriteValuegeneric_OpDiv32(v)
	case OpDiv32F:
		return rewriteValuegeneric_OpDiv32F(v)
	case OpDiv32u:
		return rewriteValuegeneric_OpDiv32u(v)
	case OpDiv64:
		return rewriteValuegeneric_OpDiv64(v)
	case OpDiv64F:
		return rewriteValuegeneric_OpDiv64F(v)
	case OpDiv64u:
		return rewriteValuegeneric_OpDiv64u(v)
	case OpDiv8:
		return rewriteValuegeneric_OpDiv8(v)
	case OpDiv8u:
		return rewriteValuegeneric_OpDiv8u(v)
	case OpEq16:
		return rewriteValuegeneric_OpEq16(v)
	case OpEq32:
		return rewriteValuegeneric_OpEq32(v)
	case OpEq32F:
		return rewriteValuegeneric_OpEq32F(v)
	case OpEq64:
		return rewriteValuegeneric_OpEq64(v)
	case OpEq64F:
		return rewriteValuegeneric_OpEq64F(v)
	case OpEq8:
		return rewriteValuegeneric_OpEq8(v)
	case OpEqB:
		return rewriteValuegeneric_OpEqB(v)
	case OpEqInter:
		return rewriteValuegeneric_OpEqInter(v)
	case OpEqPtr:
		return rewriteValuegeneric_OpEqPtr(v)
	case OpEqSlice:
		return rewriteValuegeneric_OpEqSlice(v)
	case OpFloor:
		return rewriteValuegeneric_OpFloor(v)
	case OpIMake:
		return rewriteValuegeneric_OpIMake(v)
	case OpInterLECall:
		return rewriteValuegeneric_OpInterLECall(v)
	case OpIsInBounds:
		return rewriteValuegeneric_OpIsInBounds(v)
	case OpIsNonNil:
		return rewriteValuegeneric_OpIsNonNil(v)
	case OpIsSliceInBounds:
		return rewriteValuegeneric_OpIsSliceInBounds(v)
	case OpLeq16:
		return rewriteValuegeneric_OpLeq16(v)
	case OpLeq16U:
		return rewriteValuegeneric_OpLeq16U(v)
	case OpLeq32:
		return rewriteValuegeneric_OpLeq32(v)
	case OpLeq32F:
		return rewriteValuegeneric_OpLeq32F(v)
	case OpLeq32U:
		return rewriteValuegeneric_OpLeq32U(v)
	case OpLeq64:
		return rewriteValuegeneric_OpLeq64(v)
	case OpLeq64F:
		return rewriteValuegeneric_OpLeq64F(v)
	case OpLeq64U:
		return rewriteValuegeneric_OpLeq64U(v)
	case OpLeq8:
		return rewriteValuegeneric_OpLeq8(v)
	case OpLeq8U:
		return rewriteValuegeneric_OpLeq8U(v)
	case OpLess16:
		return rewriteValuegeneric_OpLess16(v)
	case OpLess16U:
		return rewriteValuegeneric_OpLess16U(v)
	case OpLess32:
		return rewriteValuegeneric_OpLess32(v)
	case OpLess32F:
		return rewriteValuegeneric_OpLess32F(v)
	case OpLess32U:
		return rewriteValuegeneric_OpLess32U(v)
	case OpLess64:
		return rewriteValuegeneric_OpLess64(v)
	case OpLess64F:
		return rewriteValuegeneric_OpLess64F(v)
	case OpLess64U:
		return rewriteValuegeneric_OpLess64U(v)
	case OpLess8:
		return rewriteValuegeneric_OpLess8(v)
	case OpLess8U:
		return rewriteValuegeneric_OpLess8U(v)
	case OpLoad:
		return rewriteValuegeneric_OpLoad(v)
	case OpLsh16x16:
		return rewriteValuegeneric_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValuegeneric_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValuegeneric_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValuegeneric_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValuegeneric_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValuegeneric_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValuegeneric_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValuegeneric_OpLsh32x8(v)
	case OpLsh64x16:
		return rewriteValuegeneric_OpLsh64x16(v)
	case OpLsh64x32:
		return rewriteValuegeneric_OpLsh64x32(v)
	case OpLsh64x64:
		return rewriteValuegeneric_OpLsh64x64(v)
	case OpLsh64x8:
		return rewriteValuegeneric_OpLsh64x8(v)
	case OpLsh8x16:
		return rewriteValuegeneric_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValuegeneric_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValuegeneric_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValuegeneric_OpLsh8x8(v)
	case OpMod16:
		return rewriteValuegeneric_OpMod16(v)
	case OpMod16u:
		return rewriteValuegeneric_OpMod16u(v)
	case OpMod32:
		return rewriteValuegeneric_OpMod32(v)
	case OpMod32u:
		return rewriteValuegeneric_OpMod32u(v)
	case OpMod64:
		return rewriteValuegeneric_OpMod64(v)
	case OpMod64u:
		return rewriteValuegeneric_OpMod64u(v)
	case OpMod8:
		return rewriteValuegeneric_OpMod8(v)
	case OpMod8u:
		return rewriteValuegeneric_OpMod8u(v)
	case OpMove:
		return rewriteValuegeneric_OpMove(v)
	case OpMul16:
		return rewriteValuegeneric_OpMul16(v)
	case OpMul32:
		return rewriteValuegeneric_OpMul32(v)
	case OpMul32F:
		return rewriteValuegeneric_OpMul32F(v)
	case OpMul64:
		return rewriteValuegeneric_OpMul64(v)
	case OpMul64F:
		return rewriteValuegeneric_OpMul64F(v)
	case OpMul8:
		return rewriteValuegeneric_OpMul8(v)
	case OpNeg16:
		return rewriteValuegeneric_OpNeg16(v)
	case OpNeg32:
		return rewriteValuegeneric_OpNeg32(v)
	case OpNeg32F:
		return rewriteValuegeneric_OpNeg32F(v)
	case OpNeg64:
		return rewriteValuegeneric_OpNeg64(v)
	case OpNeg64F:
		return rewriteValuegeneric_OpNeg64F(v)
	case OpNeg8:
		return rewriteValuegeneric_OpNeg8(v)
	case OpNeq16:
		return rewriteValuegeneric_OpNeq16(v)
	case OpNeq32:
		return rewriteValuegeneric_OpNeq32(v)
	case OpNeq32F:
		return rewriteValuegeneric_OpNeq32F(v)
	case OpNeq64:
		return rewriteValuegeneric_OpNeq64(v)
	case OpNeq64F:
		return rewriteValuegeneric_OpNeq64F(v)
	case OpNeq8:
		return rewriteValuegeneric_OpNeq8(v)
	case OpNeqB:
		return rewriteValuegeneric_OpNeqB(v)
	case OpNeqInter:
		return rewriteValuegeneric_OpNeqInter(v)
	case OpNeqPtr:
		return rewriteValuegeneric_OpNeqPtr(v)
	case OpNeqSlice:
		return rewriteValuegeneric_OpNeqSlice(v)
	case OpNilCheck:
		return rewriteValuegeneric_OpNilCheck(v)
	case OpNot:
		return rewriteValuegeneric_OpNot(v)
	case OpOffPtr:
		return rewriteValuegeneric_OpOffPtr(v)
	case OpOr16:
		return rewriteValuegeneric_OpOr16(v)
	case OpOr32:
		return rewriteValuegeneric_OpOr32(v)
	case OpOr64:
		return rewriteValuegeneric_OpOr64(v)
	case OpOr8:
		return rewriteValuegeneric_OpOr8(v)
	case OpOrB:
		return rewriteValuegeneric_OpOrB(v)
	case OpPhi:
		return rewriteValuegeneric_OpPhi(v)
	case OpPtrIndex:
		return rewriteValuegeneric_OpPtrIndex(v)
	case OpRotateLeft16:
		return rewriteValuegeneric_OpRotateLeft16(v)
	case OpRotateLeft32:
		return rewriteValuegeneric_OpRotateLeft32(v)
	case OpRotateLeft64:
		return rewriteValuegeneric_OpRotateLeft64(v)
	case OpRotateLeft8:
		return rewriteValuegeneric_OpRotateLeft8(v)
	case OpRound32F:
		return rewriteValuegeneric_OpRound32F(v)
	case OpRound64F:
		return rewriteValuegeneric_OpRound64F(v)
	case OpRoundToEven:
		return rewriteValuegeneric_OpRoundToEven(v)
	case OpRsh16Ux16:
		return rewriteValuegeneric_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValuegeneric_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValuegeneric_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValuegeneric_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValuegeneric_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValuegeneric_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValuegeneric_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValuegeneric_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValuegeneric_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValuegeneric_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValuegeneric_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValuegeneric_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValuegeneric_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValuegeneric_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValuegeneric_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValuegeneric_OpRsh32x8(v)
	case OpRsh64Ux16:
		return rewriteValuegeneric_OpRsh64Ux16(v)
	case OpRsh64Ux32:
		return rewriteValuegeneric_OpRsh64Ux32(v)
	case OpRsh64Ux64:
		return rewriteValuegeneric_OpRsh64Ux64(v)
	case OpRsh64Ux8:
		return rewriteValuegeneric_OpRsh64Ux8(v)
	case OpRsh64x16:
		return rewriteValuegeneric_OpRsh64x16(v)
	case OpRsh64x32:
		return rewriteValuegeneric_OpRsh64x32(v)
	case OpRsh64x64:
		return rewriteValuegeneric_OpRsh64x64(v)
	case OpRsh64x8:
		return rewriteValuegeneric_OpRsh64x8(v)
	case OpRsh8Ux16:
		return rewriteValuegeneric_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValuegeneric_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValuegeneric_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValuegeneric_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValuegeneric_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValuegeneric_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValuegeneric_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValuegeneric_OpRsh8x8(v)
	case OpSelect0:
		return rewriteValuegeneric_OpSelect0(v)
	case OpSelect1:
		return rewriteValuegeneric_OpSelect1(v)
	case OpSelectN:
		return rewriteValuegeneric_OpSelectN(v)
	case OpSignExt16to32:
		return rewriteValuegeneric_OpSignExt16to32(v)
	case OpSignExt16to64:
		return rewriteValuegeneric_OpSignExt16to64(v)
	case OpSignExt32to64:
		return rewriteValuegeneric_OpSignExt32to64(v)
	case OpSignExt8to16:
		return rewriteValuegeneric_OpSignExt8to16(v)
	case OpSignExt8to32:
		return rewriteValuegeneric_OpSignExt8to32(v)
	case OpSignExt8to64:
		return rewriteValuegeneric_OpSignExt8to64(v)
	case OpSliceCap:
		return rewriteValuegeneric_OpSliceCap(v)
	case OpSliceLen:
		return rewriteValuegeneric_OpSliceLen(v)
	case OpSlicePtr:
		return rewriteValuegeneric_OpSlicePtr(v)
	case OpSlicemask:
		return rewriteValuegeneric_OpSlicemask(v)
	case OpSqrt:
		return rewriteValuegeneric_OpSqrt(v)
	case OpStaticCall:
		return rewriteValuegeneric_OpStaticCall(v)
	case OpStaticLECall:
		return rewriteValuegeneric_OpStaticLECall(v)
	case OpStore:
		return rewriteValuegeneric_OpStore(v)
	case OpStringLen:
		return rewriteValuegeneric_OpStringLen(v)
	case OpStringPtr:
		return rewriteValuegeneric_OpStringPtr(v)
	case OpStructSelect:
		return rewriteValuegeneric_OpStructSelect(v)
	case OpSub16:
		return rewriteValuegeneric_OpSub16(v)
	case OpSub32:
		return rewriteValuegeneric_OpSub32(v)
	case OpSub32F:
		return rewriteValuegeneric_OpSub32F(v)
	case OpSub64:
		return rewriteValuegeneric_OpSub64(v)
	case OpSub64F:
		return rewriteValuegeneric_OpSub64F(v)
	case OpSub8:
		return rewriteValuegeneric_OpSub8(v)
	case OpTrunc:
		return rewriteValuegeneric_OpTrunc(v)
	case OpTrunc16to8:
		return rewriteValuegeneric_OpTrunc16to8(v)
	case OpTrunc32to16:
		return rewriteValuegeneric_OpTrunc32to16(v)
	case OpTrunc32to8:
		return rewriteValuegeneric_OpTrunc32to8(v)
	case OpTrunc64to16:
		return rewriteValuegeneric_OpTrunc64to16(v)
	case OpTrunc64to32:
		return rewriteValuegeneric_OpTrunc64to32(v)
	case OpTrunc64to8:
		return rewriteValuegeneric_OpTrunc64to8(v)
	case OpXor16:
		return rewriteValuegeneric_OpXor16(v)
	case OpXor32:
		return rewriteValuegeneric_OpXor32(v)
	case OpXor64:
		return rewriteValuegeneric_OpXor64(v)
	case OpXor8:
		return rewriteValuegeneric_OpXor8(v)
	case OpZero:
		return rewriteValuegeneric_OpZero(v)
	case OpZeroExt16to32:
		return rewriteValuegeneric_OpZeroExt16to32(v)
	case OpZeroExt16to64:
		return rewriteValuegeneric_OpZeroExt16to64(v)
	case OpZeroExt32to64:
		return rewriteValuegeneric_OpZeroExt32to64(v)
	case OpZeroExt8to16:
		return rewriteValuegeneric_OpZeroExt8to16(v)
	case OpZeroExt8to32:
		return rewriteValuegeneric_OpZeroExt8to32(v)
	case OpZeroExt8to64:
		return rewriteValuegeneric_OpZeroExt8to64(v)
	}
	return false
}
func rewriteValuegeneric_OpAdd16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Add16 (Const16 [c]) (Const16 [d]))
	// result: (Const16 [c+d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1.AuxInt)
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(c + d)
			return true
		}
		break
	}
	// match: (Add16 <t> (Mul16 x y) (Mul16 x z))
	// result: (Mul16 x (Add16 <t> y z))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul16 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				y := v_0_1
				if v_1.Op != OpMul16 {
					continue
				}
				_ = v_1.Args[1]
				v_1_0 := v_1.Args[0]
				v_1_1 := v_1.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, v_1_0, v_1_1 = _i2+1, v_1_1, v_1_0 {
					if x != v_1_0 {
						continue
					}
					z := v_1_1
					v.reset(OpMul16)
					v0 := b.NewValue0(v.Pos, OpAdd16, t)
					v0.AddArg2(y, z)
					v.AddArg2(x, v0)
					return true
				}
			}
		}
		break
	}
	// match: (Add16 (Const16 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Add16 x (Neg16 y))
	// result: (Sub16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpNeg16 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpSub16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add16 (Com16 x) x)
	// result: (Const16 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom16 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Add16 (Sub16 x t) (Add16 t y))
	// result: (Add16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpSub16 {
				continue
			}
			t := v_0.Args[1]
			x := v_0.Args[0]
			if v_1.Op != OpAdd16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpAdd16)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Add16 (Const16 [1]) (Com16 x))
	// result: (Neg16 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 1 || v_1.Op != OpCom16 {
				continue
			}
			x := v_1.Args[0]
			v.reset(OpNeg16)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Add16 x (Sub16 y x))
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpSub16 {
				continue
			}
			_ = v_1.Args[1]
			y := v_1.Args[0]
			if x != v_1.Args[1] {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Add16 x (Add16 y (Sub16 z x)))
	// result: (Add16 y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAdd16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				y := v_1_0
				if v_1_1.Op != OpSub16 {
					continue
				}
				_ = v_1_1.Args[1]
				z := v_1_1.Args[0]
				if x != v_1_1.Args[1] {
					continue
				}
				v.reset(OpAdd16)
				v.AddArg2(y, z)
				return true
			}
		}
		break
	}
	// match: (Add16 (Add16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Add16 i (Add16 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAdd16 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst16 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst16 && x.Op != OpConst16) {
					continue
				}
				v.reset(OpAdd16)
				v0 := b.NewValue0(v.Pos, OpAdd16, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Add16 (Sub16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Add16 i (Sub16 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpSub16 {
				continue
			}
			z := v_0.Args[1]
			i := v_0.Args[0]
			if i.Op != OpConst16 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst16 && x.Op != OpConst16) {
				continue
			}
			v.reset(OpAdd16)
			v0 := b.NewValue0(v.Pos, OpSub16, t)
			v0.AddArg2(x, z)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Add16 (Const16 <t> [c]) (Add16 (Const16 <t> [d]) x))
	// result: (Add16 (Const16 <t> [c+d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpAdd16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst16 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt16(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpAdd16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c + d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Add16 (Const16 <t> [c]) (Sub16 (Const16 <t> [d]) x))
	// result: (Sub16 (Const16 <t> [c+d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpSub16 {
				continue
			}
			x := v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpConst16 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt16(v_1_0.AuxInt)
			v.reset(OpSub16)
			v0 := b.NewValue0(v.Pos, OpConst16, t)
			v0.AuxInt = int16ToAuxInt(c + d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	// match: (Add16 (Lsh16x64 x z:(Const64 <t> [c])) (Rsh16Ux64 x (Const64 [d])))
	// cond: c < 16 && d == 16-c && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh16x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh16Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 16 && d == 16-c && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add16 left:(Lsh16x64 x y) right:(Rsh16Ux64 x (Sub64 (Const64 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add16 left:(Lsh16x32 x y) right:(Rsh16Ux32 x (Sub32 (Const32 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add16 left:(Lsh16x16 x y) right:(Rsh16Ux16 x (Sub16 (Const16 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add16 left:(Lsh16x8 x y) right:(Rsh16Ux8 x (Sub8 (Const8 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add16 right:(Rsh16Ux64 x y) left:(Lsh16x64 x z:(Sub64 (Const64 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add16 right:(Rsh16Ux32 x y) left:(Lsh16x32 x z:(Sub32 (Const32 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add16 right:(Rsh16Ux16 x y) left:(Lsh16x16 x z:(Sub16 (Const16 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add16 right:(Rsh16Ux8 x y) left:(Lsh16x8 x z:(Sub8 (Const8 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpAdd32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Add32 (Const32 [c]) (Const32 [d]))
	// result: (Const32 [c+d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(c + d)
			return true
		}
		break
	}
	// match: (Add32 <t> (Mul32 x y) (Mul32 x z))
	// result: (Mul32 x (Add32 <t> y z))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul32 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				y := v_0_1
				if v_1.Op != OpMul32 {
					continue
				}
				_ = v_1.Args[1]
				v_1_0 := v_1.Args[0]
				v_1_1 := v_1.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, v_1_0, v_1_1 = _i2+1, v_1_1, v_1_0 {
					if x != v_1_0 {
						continue
					}
					z := v_1_1
					v.reset(OpMul32)
					v0 := b.NewValue0(v.Pos, OpAdd32, t)
					v0.AddArg2(y, z)
					v.AddArg2(x, v0)
					return true
				}
			}
		}
		break
	}
	// match: (Add32 (Const32 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Add32 x (Neg32 y))
	// result: (Sub32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpNeg32 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpSub32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add32 (Com32 x) x)
	// result: (Const32 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom32 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Add32 (Sub32 x t) (Add32 t y))
	// result: (Add32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpSub32 {
				continue
			}
			t := v_0.Args[1]
			x := v_0.Args[0]
			if v_1.Op != OpAdd32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpAdd32)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Add32 (Const32 [1]) (Com32 x))
	// result: (Neg32 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 1 || v_1.Op != OpCom32 {
				continue
			}
			x := v_1.Args[0]
			v.reset(OpNeg32)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Add32 x (Sub32 y x))
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpSub32 {
				continue
			}
			_ = v_1.Args[1]
			y := v_1.Args[0]
			if x != v_1.Args[1] {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Add32 x (Add32 y (Sub32 z x)))
	// result: (Add32 y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAdd32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				y := v_1_0
				if v_1_1.Op != OpSub32 {
					continue
				}
				_ = v_1_1.Args[1]
				z := v_1_1.Args[0]
				if x != v_1_1.Args[1] {
					continue
				}
				v.reset(OpAdd32)
				v.AddArg2(y, z)
				return true
			}
		}
		break
	}
	// match: (Add32 (Add32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Add32 i (Add32 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAdd32 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst32 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst32 && x.Op != OpConst32) {
					continue
				}
				v.reset(OpAdd32)
				v0 := b.NewValue0(v.Pos, OpAdd32, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Add32 (Sub32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Add32 i (Sub32 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpSub32 {
				continue
			}
			z := v_0.Args[1]
			i := v_0.Args[0]
			if i.Op != OpConst32 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst32 && x.Op != OpConst32) {
				continue
			}
			v.reset(OpAdd32)
			v0 := b.NewValue0(v.Pos, OpSub32, t)
			v0.AddArg2(x, z)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Add32 (Const32 <t> [c]) (Add32 (Const32 <t> [d]) x))
	// result: (Add32 (Const32 <t> [c+d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpAdd32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt32(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpAdd32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c + d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Add32 (Const32 <t> [c]) (Sub32 (Const32 <t> [d]) x))
	// result: (Sub32 (Const32 <t> [c+d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpSub32 {
				continue
			}
			x := v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpConst32 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt32(v_1_0.AuxInt)
			v.reset(OpSub32)
			v0 := b.NewValue0(v.Pos, OpConst32, t)
			v0.AuxInt = int32ToAuxInt(c + d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	// match: (Add32 (Lsh32x64 x z:(Const64 <t> [c])) (Rsh32Ux64 x (Const64 [d])))
	// cond: c < 32 && d == 32-c && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh32x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh32Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 32 && d == 32-c && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add32 left:(Lsh32x64 x y) right:(Rsh32Ux64 x (Sub64 (Const64 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add32 left:(Lsh32x32 x y) right:(Rsh32Ux32 x (Sub32 (Const32 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add32 left:(Lsh32x16 x y) right:(Rsh32Ux16 x (Sub16 (Const16 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add32 left:(Lsh32x8 x y) right:(Rsh32Ux8 x (Sub8 (Const8 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add32 right:(Rsh32Ux64 x y) left:(Lsh32x64 x z:(Sub64 (Const64 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add32 right:(Rsh32Ux32 x y) left:(Lsh32x32 x z:(Sub32 (Const32 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add32 right:(Rsh32Ux16 x y) left:(Lsh32x16 x z:(Sub16 (Const16 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add32 right:(Rsh32Ux8 x y) left:(Lsh32x8 x z:(Sub8 (Const8 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpAdd32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Add32F (Const32F [c]) (Const32F [d]))
	// cond: c+d == c+d
	// result: (Const32F [c+d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32F {
				continue
			}
			c := auxIntToFloat32(v_0.AuxInt)
			if v_1.Op != OpConst32F {
				continue
			}
			d := auxIntToFloat32(v_1.AuxInt)
			if !(c+d == c+d) {
				continue
			}
			v.reset(OpConst32F)
			v.AuxInt = float32ToAuxInt(c + d)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpAdd64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Add64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c+d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(c + d)
			return true
		}
		break
	}
	// match: (Add64 <t> (Mul64 x y) (Mul64 x z))
	// result: (Mul64 x (Add64 <t> y z))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul64 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				y := v_0_1
				if v_1.Op != OpMul64 {
					continue
				}
				_ = v_1.Args[1]
				v_1_0 := v_1.Args[0]
				v_1_1 := v_1.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, v_1_0, v_1_1 = _i2+1, v_1_1, v_1_0 {
					if x != v_1_0 {
						continue
					}
					z := v_1_1
					v.reset(OpMul64)
					v0 := b.NewValue0(v.Pos, OpAdd64, t)
					v0.AddArg2(y, z)
					v.AddArg2(x, v0)
					return true
				}
			}
		}
		break
	}
	// match: (Add64 (Const64 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Add64 x (Neg64 y))
	// result: (Sub64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpNeg64 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpSub64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add64 (Com64 x) x)
	// result: (Const64 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom64 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Add64 (Sub64 x t) (Add64 t y))
	// result: (Add64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpSub64 {
				continue
			}
			t := v_0.Args[1]
			x := v_0.Args[0]
			if v_1.Op != OpAdd64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpAdd64)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Add64 (Const64 [1]) (Com64 x))
	// result: (Neg64 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 1 || v_1.Op != OpCom64 {
				continue
			}
			x := v_1.Args[0]
			v.reset(OpNeg64)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Add64 x (Sub64 y x))
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpSub64 {
				continue
			}
			_ = v_1.Args[1]
			y := v_1.Args[0]
			if x != v_1.Args[1] {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Add64 x (Add64 y (Sub64 z x)))
	// result: (Add64 y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAdd64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				y := v_1_0
				if v_1_1.Op != OpSub64 {
					continue
				}
				_ = v_1_1.Args[1]
				z := v_1_1.Args[0]
				if x != v_1_1.Args[1] {
					continue
				}
				v.reset(OpAdd64)
				v.AddArg2(y, z)
				return true
			}
		}
		break
	}
	// match: (Add64 (Add64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Add64 i (Add64 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAdd64 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst64 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst64 && x.Op != OpConst64) {
					continue
				}
				v.reset(OpAdd64)
				v0 := b.NewValue0(v.Pos, OpAdd64, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Add64 (Sub64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Add64 i (Sub64 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpSub64 {
				continue
			}
			z := v_0.Args[1]
			i := v_0.Args[0]
			if i.Op != OpConst64 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst64 && x.Op != OpConst64) {
				continue
			}
			v.reset(OpAdd64)
			v0 := b.NewValue0(v.Pos, OpSub64, t)
			v0.AddArg2(x, z)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Add64 (Const64 <t> [c]) (Add64 (Const64 <t> [d]) x))
	// result: (Add64 (Const64 <t> [c+d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpAdd64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt64(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpAdd64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c + d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Add64 (Const64 <t> [c]) (Sub64 (Const64 <t> [d]) x))
	// result: (Sub64 (Const64 <t> [c+d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpSub64 {
				continue
			}
			x := v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpConst64 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt64(v_1_0.AuxInt)
			v.reset(OpSub64)
			v0 := b.NewValue0(v.Pos, OpConst64, t)
			v0.AuxInt = int64ToAuxInt(c + d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	// match: (Add64 (Lsh64x64 x z:(Const64 <t> [c])) (Rsh64Ux64 x (Const64 [d])))
	// cond: c < 64 && d == 64-c && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh64x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh64Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 64 && d == 64-c && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add64 left:(Lsh64x64 x y) right:(Rsh64Ux64 x (Sub64 (Const64 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add64 left:(Lsh64x32 x y) right:(Rsh64Ux32 x (Sub32 (Const32 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add64 left:(Lsh64x16 x y) right:(Rsh64Ux16 x (Sub16 (Const16 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add64 left:(Lsh64x8 x y) right:(Rsh64Ux8 x (Sub8 (Const8 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add64 right:(Rsh64Ux64 x y) left:(Lsh64x64 x z:(Sub64 (Const64 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add64 right:(Rsh64Ux32 x y) left:(Lsh64x32 x z:(Sub32 (Const32 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add64 right:(Rsh64Ux16 x y) left:(Lsh64x16 x z:(Sub16 (Const16 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add64 right:(Rsh64Ux8 x y) left:(Lsh64x8 x z:(Sub8 (Const8 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpAdd64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Add64F (Const64F [c]) (Const64F [d]))
	// cond: c+d == c+d
	// result: (Const64F [c+d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64F {
				continue
			}
			c := auxIntToFloat64(v_0.AuxInt)
			if v_1.Op != OpConst64F {
				continue
			}
			d := auxIntToFloat64(v_1.AuxInt)
			if !(c+d == c+d) {
				continue
			}
			v.reset(OpConst64F)
			v.AuxInt = float64ToAuxInt(c + d)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpAdd8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Add8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c+d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1.AuxInt)
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(c + d)
			return true
		}
		break
	}
	// match: (Add8 <t> (Mul8 x y) (Mul8 x z))
	// result: (Mul8 x (Add8 <t> y z))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMul8 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				y := v_0_1
				if v_1.Op != OpMul8 {
					continue
				}
				_ = v_1.Args[1]
				v_1_0 := v_1.Args[0]
				v_1_1 := v_1.Args[1]
				for _i2 := 0; _i2 <= 1; _i2, v_1_0, v_1_1 = _i2+1, v_1_1, v_1_0 {
					if x != v_1_0 {
						continue
					}
					z := v_1_1
					v.reset(OpMul8)
					v0 := b.NewValue0(v.Pos, OpAdd8, t)
					v0.AddArg2(y, z)
					v.AddArg2(x, v0)
					return true
				}
			}
		}
		break
	}
	// match: (Add8 (Const8 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Add8 x (Neg8 y))
	// result: (Sub8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpNeg8 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpSub8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Add8 (Com8 x) x)
	// result: (Const8 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom8 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Add8 (Sub8 x t) (Add8 t y))
	// result: (Add8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpSub8 {
				continue
			}
			t := v_0.Args[1]
			x := v_0.Args[0]
			if v_1.Op != OpAdd8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpAdd8)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Add8 (Const8 [1]) (Com8 x))
	// result: (Neg8 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 1 || v_1.Op != OpCom8 {
				continue
			}
			x := v_1.Args[0]
			v.reset(OpNeg8)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Add8 x (Sub8 y x))
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpSub8 {
				continue
			}
			_ = v_1.Args[1]
			y := v_1.Args[0]
			if x != v_1.Args[1] {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Add8 x (Add8 y (Sub8 z x)))
	// result: (Add8 y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAdd8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				y := v_1_0
				if v_1_1.Op != OpSub8 {
					continue
				}
				_ = v_1_1.Args[1]
				z := v_1_1.Args[0]
				if x != v_1_1.Args[1] {
					continue
				}
				v.reset(OpAdd8)
				v.AddArg2(y, z)
				return true
			}
		}
		break
	}
	// match: (Add8 (Add8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Add8 i (Add8 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAdd8 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst8 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst8 && x.Op != OpConst8) {
					continue
				}
				v.reset(OpAdd8)
				v0 := b.NewValue0(v.Pos, OpAdd8, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Add8 (Sub8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Add8 i (Sub8 <t> x z))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpSub8 {
				continue
			}
			z := v_0.Args[1]
			i := v_0.Args[0]
			if i.Op != OpConst8 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst8 && x.Op != OpConst8) {
				continue
			}
			v.reset(OpAdd8)
			v0 := b.NewValue0(v.Pos, OpSub8, t)
			v0.AddArg2(x, z)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Add8 (Const8 <t> [c]) (Add8 (Const8 <t> [d]) x))
	// result: (Add8 (Const8 <t> [c+d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpAdd8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst8 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt8(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpAdd8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c + d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Add8 (Const8 <t> [c]) (Sub8 (Const8 <t> [d]) x))
	// result: (Sub8 (Const8 <t> [c+d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpSub8 {
				continue
			}
			x := v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpConst8 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt8(v_1_0.AuxInt)
			v.reset(OpSub8)
			v0 := b.NewValue0(v.Pos, OpConst8, t)
			v0.AuxInt = int8ToAuxInt(c + d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	// match: (Add8 (Lsh8x64 x z:(Const64 <t> [c])) (Rsh8Ux64 x (Const64 [d])))
	// cond: c < 8 && d == 8-c && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh8x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh8Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 8 && d == 8-c && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Add8 left:(Lsh8x64 x y) right:(Rsh8Ux64 x (Sub64 (Const64 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)
```